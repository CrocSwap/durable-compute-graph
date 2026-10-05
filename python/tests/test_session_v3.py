"""Stateful wire v3 in the Python session client: payloads, the authority slot
on creators, session features (ring streams, declared rejection; DCG design
docs/design/session-reject-and-ring-v1.md) and the v3 session reader."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.session import (
    COUNTER_MANIFEST,
    DEFAULT_PROGRAM_ID,
    FEATURE_REJECTABLE,
    FEATURE_RING_STREAM,
    MIN_RING_CAPACITY,
    KernelRef,
    SessionAddresses,
    SessionInfo,
    SessionSigners,
    account_layout,
    slot_offset,
)
from dcg.session.client import Session
from dcg.session.instructions import create_state, create_stream, initialize_state, open_session

V3_MODE = {"id": 0x434F_4E53, "version": 3}


def kernel(**overrides) -> KernelRef:
    manifest = {**COUNTER_MANIFEST, "mode": V3_MODE, **overrides}
    return KernelRef.from_manifest(manifest)


def keys():
    payer, authority = Keypair.from_seed(bytes([1] * 32)), Keypair.from_seed(bytes([2] * 32))
    return payer, authority


def addresses(k: KernelRef, authority: Pubkey) -> SessionAddresses:
    return SessionAddresses.derive(layout=account_layout(3), program_id=DEFAULT_PROGRAM_ID, authority=authority,
                                   session_id=9, state_span_count=len(k.state_span_lengths))


def program_payload(k: KernelRef, writer: Pubkey, capacity: int, tail: bytes) -> bytes:
    """The program's v3 OPEN_SESSION payload (stateful_v3.rs open_session):
    the 178-byte instruction (tag + 177-byte body: append policy, no resource, headered state), then the
    optional lanes / lanes+features bytes."""
    body = bytes([3]) + (9).to_bytes(8, "little") + bytes([1, k.input_width]) + struct.pack("<I", capacity)
    body += bytes([1]) + k.id + struct.pack("<HHIH", k.semantic_version, k.abi_version, k.mode_id, k.mode_version)
    body += k.stream_root + bytes(writer) + bytes(32) + bytes(6) + bytes(32) + bytes([0])
    assert len(body) == 177  # 178 with the tag byte
    return body + tail


class SessionV3Tests(unittest.TestCase):
    def open_ix(self, k, capacity=8, features=0, lanes=0):
        payer, authority = keys()
        return open_session(program_id=DEFAULT_PROGRAM_ID, addresses=addresses(k, authority.pubkey()), kernel=k,
                            payer=payer.pubkey(), authority=authority.pubkey(), session_id=9, wire_version=3,
                            input_capacity=capacity, max_steps=1, features=features, lanes=lanes)

    def test_open_payload_forms_match_the_program(self):
        k = kernel()
        _payer, authority = keys()
        w = authority.pubkey()
        plain = self.open_ix(k)
        self.assertEqual(plain.data[1:], program_payload(k, w, 8, b""), "178 bytes: no features")
        self.assertEqual(self.open_ix(k, lanes=2).data[1:], program_payload(k, w, 8, bytes([2])), "179: lanes")
        ring = self.open_ix(k, capacity=128, features=FEATURE_RING_STREAM)
        self.assertEqual(ring.data[1:], program_payload(k, w, 128, bytes([0, 1])), "180: lanes 0 + features")
        both = self.open_ix(k, capacity=128, features=FEATURE_RING_STREAM | FEATURE_REJECTABLE, lanes=3)
        self.assertEqual(both.data[1:], program_payload(k, w, 128, bytes([3, 3])))

    def test_open_refuses_what_the_program_refuses(self):
        k = kernel()
        with self.assertRaises(ValueError):
            self.open_ix(k, capacity=MIN_RING_CAPACITY - 1, features=FEATURE_RING_STREAM)
        with self.assertRaises(ValueError):
            self.open_ix(k, features=4)
        with self.assertRaises(ValueError):
            self.open_ix(k, lanes=5)
        payer, authority = keys()
        v2 = KernelRef.from_manifest(COUNTER_MANIFEST)
        with self.assertRaises(ValueError):
            open_session(program_id=DEFAULT_PROGRAM_ID, addresses=addresses(v2, authority.pubkey()), kernel=v2,
                         payer=payer.pubkey(), authority=authority.pubkey(), session_id=9, wire_version=2,
                         features=FEATURE_RING_STREAM, input_capacity=128)

    def test_v3_creators_take_the_signing_authority_at_account_2(self):
        k = kernel()
        payer, authority = keys()
        a = addresses(k, authority.pubkey())
        for built in (
            create_stream(program_id=DEFAULT_PROGRAM_ID, addresses=a, payer=payer.pubkey(), wire_version=3,
                          authority=authority.pubkey()),
            create_state(program_id=DEFAULT_PROGRAM_ID, addresses=a, kernel=k, payer=payer.pubkey(), wire_version=3,
                         authority=authority.pubkey()),
        ):
            meta = built.instruction.accounts[2]
            self.assertEqual((meta.pubkey, meta.is_signer, meta.is_writable), (authority.pubkey(), True, False))
            self.assertIn("authority", built.signer_roles)
        with self.assertRaises(ValueError):
            create_stream(program_id=DEFAULT_PROGRAM_ID, addresses=a, payer=payer.pubkey(), wire_version=3)
        v2 = create_stream(program_id=DEFAULT_PROGRAM_ID, addresses=a, payer=payer.pubkey(), wire_version=2)
        self.assertEqual(len(v2.instruction.accounts), 4, "v2 keeps its account list")
        init = initialize_state(program_id=DEFAULT_PROGRAM_ID, addresses=a, authority=authority.pubkey(), wire_version=3)
        self.assertEqual(init.data[1:3], bytes([3, 0xFF]))

    def test_v3_addresses_use_the_v3_seeds(self):
        _payer, authority = keys()
        a = addresses(kernel(), authority.pubkey())
        want = Pubkey.find_program_address([b"dcg-session-v3", bytes(authority.pubkey()), (9).to_bytes(8, "little")],
                                           DEFAULT_PROGRAM_ID)[0]
        self.assertEqual(a.session, want)
        self.assertEqual(a.stream, Pubkey.find_program_address([b"dcg-input-v3", bytes(want)], DEFAULT_PROGRAM_ID)[0])

    def test_ring_slot_offsets_wrap(self):
        self.assertEqual(slot_offset(5, 128, ring=False), 128 + 5 * 16)
        self.assertEqual(slot_offset(130, 128, ring=True), 128 + 2 * 16)
        with self.assertRaises(ValueError):
            slot_offset(128, 128, ring=False)

    def test_session_features_follow_the_kernel_and_ring_choice(self):
        payer, authority = keys()
        signers = SessionSigners(payer=payer, authority=authority)
        journal = Path(tempfile.mkdtemp()) / "accounts.json"
        plain = Session(kernel=kernel(), transport=None, signers=signers, session_id=9, wire_version=3,
                        journal_path=journal)
        self.assertEqual(plain.features, 0)
        rejecting = Session(kernel=kernel(rejects_input=True), transport=None, signers=signers, session_id=10,
                            wire_version=3, ring=True, input_capacity=128, journal_path=journal.with_name("b.json"))
        self.assertEqual(rejecting.features, FEATURE_RING_STREAM | FEATURE_REJECTABLE)
        self.assertTrue(rejecting.ring and rejecting.rejectable)
        with self.assertRaises(ValueError):
            Session(kernel=kernel(), transport=None, signers=signers, session_id=11, wire_version=3, ring=True,
                    journal_path=journal.with_name("c.json"))
        with self.assertRaises(ValueError):
            KernelRef.from_manifest({**COUNTER_MANIFEST, "rejects_input": True})  # a v2 kernel

    def test_session_info_reads_features_and_rejections(self):
        session = bytearray(1280)
        session[:4], session[4:6], session[6] = b"DSS3", (3).to_bytes(2, "little"), 1
        struct.pack_into("<I", session, 10, 128)
        struct.pack_into("<II", session, 112, 40, 45)
        session[1273] = FEATURE_RING_STREAM | FEATURE_REJECTABLE
        struct.pack_into("<I", session, 1274, 3)
        stream = bytearray(128 + 16 * 128)
        stream[:4] = b"DSB3"
        struct.pack_into("<II", stream, 120, 37, 7)
        info = SessionInfo.decode(bytes(session), bytes(stream))
        self.assertEqual((info.cursor, info.frontier, info.rejected_count), (40, 45, 3))
        self.assertEqual((info.last_reject_sequence, info.last_reject_code), (37, 7))
        self.assertTrue(info.ring and info.rejectable)
        text = info.explain()
        self.assertIn("rejectable: yes", text)
        self.assertIn("ring", text)
        session[1273] = 0
        plain = SessionInfo.decode(bytes(session))
        self.assertIn("rejectable: no", plain.explain())
        session[1273] = 4
        with self.assertRaises(ValueError):
            SessionInfo.decode(bytes(session))


if __name__ == "__main__":
    unittest.main()
