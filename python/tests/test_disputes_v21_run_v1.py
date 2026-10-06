"""Version-1 v2.1 runs (tag 227 sub 28): who receives a convicted executor's
remainder, and the init_run body."""
import struct

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.disputes_v21 import client as CL


def run_bytes(version: int, n_refs: int, payer: bytes, remainder: bytes | None) -> bytes:
    body = bytearray(CL.R_REFS + 52 * n_refs + 4 + (32 if remainder else 0))
    body[0:4] = b"D21R"
    body[CL.R_VERSION] = version
    body[CL.R_PAYER:CL.R_PAYER + 32] = payer
    struct.pack_into("<I", body, CL.R_NEXT, n_refs)
    struct.pack_into("<I", body, CL.R_REFS + 52 * n_refs, 3)  # waiting_E
    if remainder:
        body[-32:] = remainder
    return bytes(body)


@pytest.mark.parametrize("n_refs", [0, 2])
def test_remainder_recipient_by_version(n_refs):
    payer, to = bytes([1]) * 32, bytes([2]) * 32
    assert CL.remainder_recipient(run_bytes(0, n_refs, payer, None)) == payer
    assert CL.remainder_recipient(run_bytes(1, n_refs, payer, to)) == to
    with pytest.raises(ValueError):
        CL.remainder_recipient(run_bytes(2, n_refs, payer, None))


class Recorder:
    def __init__(self):
        self.sent = []

    def pda(self, *seeds):
        return Pubkey.find_program_address(list(seeds), Pubkey.default())[0]

    def _send(self, sub, body, metas, signers):
        self.sent.append((sub, body))


def test_init_run_v1_appends_remainder_to():
    rec = Recorder()
    payer, executor, to = Keypair(), Keypair().pubkey(), Keypair().pubkey()
    CL.DisputeClient.init_run(rec, Pubkey.default(), bytes(32), bytes([5]) * 32, executor, [], payer)
    CL.DisputeClient.init_run(rec, Pubkey.default(), bytes(32), bytes([5]) * 32, executor, [], payer, to)
    (s0, b0), (s1, b1) = rec.sent
    assert (s0, s1) == ("init_run", "init_run_v1")
    assert b1 == b0 + bytes(to) and CL.SUB["init_run_v1"] == 28
