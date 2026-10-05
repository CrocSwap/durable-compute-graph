from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.sequencer import JournalError, ProgramRefused
from dcg.session import (
    ACCOUNT_LAYOUTS,
    AccountInventory,
    COUNTER_MANIFEST,
    DEFAULT_PROGRAM_ID,
    KernelRef,
    SessionAddresses,
    SessionSigners,
    WritableAccountRefused,
    AccountRecord,
    Inventory,
    account_layout,
    explain_refusal,
)
from dcg.session.instructions import (
    advance,
    create_state,
    create_stream,
    grow_state,
    initialize_state,
    open_session,
    write_input,
)


ROOT = Path(__file__).resolve().parents[2]


class SessionGoldenTests(unittest.TestCase):
    def setUp(self):
        self.kernel = KernelRef.from_manifest(COUNTER_MANIFEST)
        self.payer = Keypair.from_seed(bytes([11]) * 32).pubkey()
        self.authority = Keypair.from_seed(bytes([17]) * 32).pubkey()
        self.addresses = SessionAddresses.derive(
            layout=account_layout(1),
            program_id=DEFAULT_PROGRAM_ID,
            authority=self.authority,
            session_id=1,
            state_span_count=2,
        )

    def test_instruction_data_matches_hello_world_v1_bytes(self):
        built = [
            open_session(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=self.addresses,
                kernel=self.kernel,
                payer=self.payer,
                authority=self.authority,
                session_id=1,
                wire_version=1,
                input_capacity=8,
                max_steps=1,
                writer=self.authority,
            ),
            create_stream(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=self.addresses,
                payer=self.payer,
                wire_version=1,
            ),
            create_state(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=self.addresses,
                kernel=self.kernel,
                payer=self.payer,
                wire_version=1,
            ),
            write_input(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=self.addresses,
                writer=self.authority,
                sequence=0,
                value=b"\x07",
                wire_version=1,
            ),
            advance(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=self.addresses,
                authority=self.authority,
                cursor=0,
                steps=1,
                wire_version=1,
            ),
        ]
        expected = [
            "e601010000000000000001010800016463672d636f756e7465722d7631000001000100534e4f430100"
            + "a5" * 32
            + bytes(self.authority).hex(),
            "e701",
            "e801020800000008000000",
            "ea01000000000107",
            "eb010000000001",
        ]
        self.assertEqual([item.data.hex() for item in built], expected)
        expected_accounts = [
            [
                ("payer", str(self.payer), True, True),
                ("authority", str(self.authority), True, False),
                ("session", "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3", False, True),
                ("system_program", str(Pubkey.default()), False, False),
            ],
            [
                ("payer", str(self.payer), True, True),
                ("session", "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3", False, True),
                ("input_stream", "HEFt7UVHfWUDWjTptWv7EsNVGjkuZBAWE8dxnSoxHcES", False, True),
                ("system_program", str(Pubkey.default()), False, False),
            ],
            [
                ("payer", str(self.payer), True, True),
                ("session", "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3", False, True),
                ("state_span_0", "3VVTvFFNQqXUv7Fx7u6BNFkrj9skHpSx1ZoEEqBHrKgK", False, True),
                ("state_span_1", "HCGR1NqzNqHCJqAf9ZFKzzFmVDWYh5dThwf5PKNhga6F", False, True),
                ("system_program", str(Pubkey.default()), False, False),
            ],
            [
                ("writer", str(self.authority), True, False),
                ("session", "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3", False, True),
                ("input_stream", "HEFt7UVHfWUDWjTptWv7EsNVGjkuZBAWE8dxnSoxHcES", False, True),
            ],
            [
                ("authority", str(self.authority), True, False),
                ("session", "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3", False, True),
                ("input_stream", "HEFt7UVHfWUDWjTptWv7EsNVGjkuZBAWE8dxnSoxHcES", False, True),
                ("state_span_0", "3VVTvFFNQqXUv7Fx7u6BNFkrj9skHpSx1ZoEEqBHrKgK", False, True),
                ("state_span_1", "HCGR1NqzNqHCJqAf9ZFKzzFmVDWYh5dThwf5PKNhga6F", False, True),
            ],
        ]
        actual_accounts = [
            [
                (role, str(meta.pubkey), meta.is_signer, meta.is_writable)
                for role, meta in instruction.account_roles
            ]
            for instruction in built
        ]
        self.assertEqual(actual_accounts, expected_accounts)

    def test_pda_vectors_match_rust_seed_derivations(self):
        # The vectors were independently produced by Solana's Rust CLI
        # find-program-derived-address, using the seed expressions in
        # stateful.rs and stateful_v2.rs.
        self.assertEqual(str(self.addresses.session), "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3")
        self.assertEqual(str(self.addresses.stream), "HEFt7UVHfWUDWjTptWv7EsNVGjkuZBAWE8dxnSoxHcES")
        self.assertEqual(str(self.addresses.states[0]), "3VVTvFFNQqXUv7Fx7u6BNFkrj9skHpSx1ZoEEqBHrKgK")
        self.assertEqual(str(self.addresses.states[1]), "HCGR1NqzNqHCJqAf9ZFKzzFmVDWYh5dThwf5PKNhga6F")
        v2 = SessionAddresses.derive(
            layout=account_layout(2),
            program_id=DEFAULT_PROGRAM_ID,
            authority=self.authority,
            session_id=1,
            state_span_count=2,
        )
        self.assertEqual(str(v2.session), "r4VTYZhGs85xYmEM3BkJE6TyXeVTexmtH458U1qbobk")
        self.assertEqual(str(v2.stream), "HEWe3L1pLLYSFRzB58aQ2ackcNd2pgWzzYPHkBwpbDop")
        self.assertEqual(str(v2.states[0]), "AjGgd5q633aqGS82GMeXNEoXuu1rJJLweu4MdgYg21z7")
        self.assertEqual(str(v2.states[1]), "CDEpPH5jfBKVcLMDQfJw8MWcgFNddAeR89Gi2pPxDnk2")

    def test_v2_encoder_keeps_open_growth_and_initialization_in_one_module(self):
        v2_kernel = KernelRef.from_manifest(
            {
                **COUNTER_MANIFEST,
                "id": "dcg-counter-v2\0\0",
                "mode": {"id": 0x434F4E53, "version": 2},
            }
        )
        addresses = SessionAddresses.derive(
            layout=account_layout(2),
            program_id=DEFAULT_PROGRAM_ID,
            authority=self.authority,
            session_id=1,
            state_span_count=2,
        )
        opened = open_session(
            program_id=DEFAULT_PROGRAM_ID,
            addresses=addresses,
            kernel=v2_kernel,
            payer=self.payer,
            authority=self.authority,
            session_id=1,
            wire_version=2,
            input_capacity=8,
            max_steps=1,
            writer=self.authority,
        )
        self.assertEqual(len(opened.data), 177)
        self.assertEqual(opened.data[:3], bytes([230, 2, 1]))
        self.assertEqual(
            create_stream(program_id=DEFAULT_PROGRAM_ID, addresses=addresses, payer=self.payer, wire_version=2).data,
            bytes([231, 2, 0]),
        )
        self.assertEqual(
            grow_state(program_id=DEFAULT_PROGRAM_ID, addresses=addresses, payer=self.payer, index=1).data,
            bytes([232, 2, 254, 1]),
        )
        self.assertEqual(
            initialize_state(program_id=DEFAULT_PROGRAM_ID, addresses=addresses, authority=self.authority).data,
            bytes([232, 2, 255]),
        )

    def test_signer_roles_select_only_keys_required_by_each_transaction(self):
        signers = SessionSigners(
            payer=Keypair.from_seed(bytes([11]) * 32),
            authority=Keypair.from_seed(bytes([17]) * 32),
        )
        self.assertEqual(signers.for_roles({"payer"}).signature_count, 1)
        self.assertEqual(signers.for_roles({"payer", "authority"}).signature_count, 2)
        self.assertEqual(signers.for_roles({"payer", "writer"}).signature_count, 2)

    def test_error_table_tracks_both_rust_constant_bands(self):
        common_names = (
            "REFUSAL_MALFORMED", "REFUSAL_AUTHORITY", "REFUSAL_ALIAS", "REFUSAL_SESSION", "REFUSAL_LIVE",
            "REFUSAL_RESOURCE", "REFUSAL_DUPLICATE_SLOT", "REFUSAL_BACKPRESSURE", "REFUSAL_CURSOR",
            "REFUSAL_INPUT_GAP", "REFUSAL_STATE", "REFUSAL_VIEW", "REFUSAL_REFUND", "REFUSAL_KERNEL",
        )
        expected_by_file = {
            "stateful.rs": {name: code for name, code in zip(common_names, range(2301, 2315))},
            "stateful_v2.rs": {
                **{name: code for name, code in zip(common_names, range(2321, 2335))},
                "REFUSAL_PHASE_CURSOR": 2335,
                "REFUSAL_PHASE_STATE_CHANGED": 2336,
            },
            "stateful_v3.rs": {
                **{name: code for name, code in zip(common_names, range(2321, 2335))},
                "REFUSAL_PHASE_CURSOR": 2335,
                "REFUSAL_PHASE_STATE_CHANGED": 2336,
                "REFUSAL_INITIALIZATION": 2337,
                "REFUSAL_LANE": 2338,
                "REFUSAL_LANE_CURSOR": 2339,
                "REFUSAL_CAPTURE_OPEN": 2340,
                "REFUSAL_STALE_PUBLICATION": 2341,
            },
        }
        for filename, expected in expected_by_file.items():
            source = ROOT / "crates/dcg-program/src" / filename
            observed = {
                name: int(code.replace("_", ""))
                for name, code in re.findall(
                    r"pub const (REFUSAL_[A-Z0-9_]+): u32 = ([0-9_]+);", source.read_text()
                )
            }
            self.assertEqual(observed, expected)
        self.assertEqual(set(ACCOUNT_LAYOUTS), {1, 2, 3})
        from dcg.session.errors import REFUSAL_CLASSES, REFUSAL_TABLE
        self.assertEqual(set(REFUSAL_CLASSES), set(REFUSAL_TABLE))
        self.assertTrue(set(range(2321, 2342)) <= set(REFUSAL_TABLE))

    def test_custom_2304_with_bad_advance_meta_names_writable_role(self):
        built = advance(
            program_id=DEFAULT_PROGRAM_ID,
            addresses=self.addresses,
            authority=self.authority,
            cursor=0,
            steps=1,
            wire_version=1,
            input_stream_writable=False,
        )
        translated = explain_refusal(
            ProgramRefused('{"InstructionError":[0,{"Custom":2304}]}'), built
        )
        self.assertIsInstance(translated, WritableAccountRefused)
        self.assertEqual(translated.account_role, "input_stream")
        self.assertIn("WritableAccountRefused", str(translated))
        self.assertIn("must be writable", str(translated))
        self.assertIn("mark mutated accounts writable", str(translated))

    def test_account_journal_rejects_an_address_outside_derived_session(self):
        # A close operation cannot be redirected by editing an inventory file.
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "accounts.json"
            inventory = Inventory(
                path,
                program_id=str(DEFAULT_PROGRAM_ID),
                metadata={"session_id": 1, "authority": str(self.authority)},
            )
            valid = AccountRecord.derive(
                DEFAULT_PROGRAM_ID,
                kind="session",
                role="session",
                seeds=(b"dcg-session-v1", bytes(self.authority), (1).to_bytes(8, "little")),
            )
            forged = AccountRecord(
                address=str(Pubkey.default()),
                kind="stream",
                role="input_stream",
                seeds=(b"dcg-input-v1", bytes(self.addresses.session)),
                parent=str(self.addresses.session),
            )
            with self.assertRaises(JournalError):
                inventory.plan((valid, forged))

    def test_account_inventory_persists_role_parent_and_lifecycle(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "accounts.json"
            inventory = Inventory(
                path,
                program_id=str(DEFAULT_PROGRAM_ID),
                metadata={"session_id": 1, "authority": str(self.authority)},
            )
            session = AccountRecord.derive(
                DEFAULT_PROGRAM_ID,
                kind="stateful_session_v1",
                role="session",
                seeds=(b"dcg-session-v1", bytes(self.authority), (1).to_bytes(8, "little")),
            )
            stream = AccountRecord.derive(
                DEFAULT_PROGRAM_ID,
                kind="stateful_stream_v1",
                role="input_stream",
                seeds=(b"dcg-input-v1", bytes(self.addresses.session)),
                parent=str(self.addresses.session),
            )
            inventory.plan(
                (
                    session,
                    stream,
                )
            )
            inventory.mark_live(str(self.addresses.session), payer=str(self.payer), rent_lamports=1234)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["accounts"][0]["address"], str(self.addresses.session))
            self.assertEqual(payload["accounts"][0]["lifecycle"], "live")
            self.assertEqual(payload["accounts"][0]["payer"], str(self.payer))
            self.assertEqual(payload["accounts"][0]["rent_lamports"], 1234)
            self.assertEqual(payload["accounts"][0]["seeds"], [b"dcg-session-v1".hex(), bytes(self.authority).hex(), (1).to_bytes(8, "little").hex()])
            self.assertEqual(payload["accounts"][1]["parent"], str(self.addresses.session))
            self.assertEqual(payload["accounts"][1]["lifecycle"], "planned")

    def test_inventory_record_derivation_matches_rust_session_vectors(self):
        session = AccountRecord.derive(
            DEFAULT_PROGRAM_ID,
            kind="stateful_session_v1",
            role="session",
            seeds=(b"dcg-session-v1", bytes(self.authority), (1).to_bytes(8, "little")),
        )
        stream = AccountRecord.derive(
            DEFAULT_PROGRAM_ID,
            kind="stateful_stream_v1",
            role="input_stream",
            seeds=(b"dcg-input-v1", bytes(self.addresses.session)),
            parent=str(self.addresses.session),
        )
        self.assertEqual(session.address, "AR8u9GTAuk93NLAdzm2xJV8CmM3eRduvNoFEY7NFiKh3")
        self.assertEqual(stream.address, "HEFt7UVHfWUDWjTptWv7EsNVGjkuZBAWE8dxnSoxHcES")
        v2_session = AccountRecord.derive(
            DEFAULT_PROGRAM_ID,
            kind="stateful_session_v2",
            role="session",
            seeds=(b"dcg-session-v2", bytes(self.authority), (1).to_bytes(8, "little")),
        )
        v2_stream = AccountRecord.derive(
            DEFAULT_PROGRAM_ID,
            kind="stateful_stream_v2",
            role="input_stream",
            seeds=(b"dcg-input-v2", bytes(Pubkey.from_string(v2_session.address))),
            parent=v2_session.address,
        )
        self.assertEqual(v2_session.address, "r4VTYZhGs85xYmEM3BkJE6TyXeVTexmtH458U1qbobk")
        self.assertEqual(v2_stream.address, "HEWe3L1pLLYSFRzB58aQ2ackcNd2pgWzzYPHkBwpbDop")

    def test_legacy_session_inventory_upgrades_only_after_seed_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "accounts.json"
            payload = {
                "schema_version": 1,
                "session_id": 1,
                "program_id": str(DEFAULT_PROGRAM_ID),
                "authority": str(self.authority),
                "accounts": [
                    {"address": str(self.addresses.session), "role": "session", "parent": None, "lifecycle": "created"},
                    {"address": str(self.addresses.stream), "role": "input_stream", "parent": str(self.addresses.session), "lifecycle": "created"},
                ],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            inventory = AccountInventory(
                path,
                session_id=1,
                program_id=str(DEFAULT_PROGRAM_ID),
                authority=str(self.authority),
            )
            inventory.plan(
                (
                    AccountRecord.derive(
                        DEFAULT_PROGRAM_ID,
                        kind="stateful_session_v1",
                        role="session",
                        seeds=(b"dcg-session-v1", bytes(self.authority), (1).to_bytes(8, "little")),
                    ),
                    AccountRecord.derive(
                        DEFAULT_PROGRAM_ID,
                        kind="stateful_stream_v1",
                        role="input_stream",
                        seeds=(b"dcg-input-v1", bytes(self.addresses.session)),
                        parent=str(self.addresses.session),
                    ),
                )
            )
            upgraded = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(upgraded["schema_version"], 2)
        self.assertEqual([item["lifecycle"] for item in upgraded["accounts"]], ["live", "live"])
        self.assertTrue(all(item["seeds"] for item in upgraded["accounts"]))


if __name__ == "__main__":
    unittest.main()
