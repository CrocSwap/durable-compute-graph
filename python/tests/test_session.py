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
    COUNTER_MANIFEST,
    DEFAULT_PROGRAM_ID,
    KernelRef,
    SessionAddresses,
    SessionSigners,
    WritableAccountRefused,
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
        self.assertEqual(set(ACCOUNT_LAYOUTS), {1, 2})

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
            addresses = [str(self.addresses.session), str(self.addresses.stream), *(str(x) for x in self.addresses.states)]
            payload = {
                "schema_version": 1,
                "session_id": 1,
                "program_id": str(DEFAULT_PROGRAM_ID),
                "authority": str(self.authority),
                "accounts": [
                    {"address": addresses[0], "role": "session", "parent": None, "lifecycle": "planned"},
                    {"address": str(Pubkey.default()), "role": "input_stream", "parent": addresses[0], "lifecycle": "planned"},
                    *[
                        {"address": address, "role": f"state_span_{index}", "parent": addresses[0], "lifecycle": "planned"}
                        for index, address in enumerate(addresses[2:])
                    ],
                ],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(JournalError):
                from dcg.session.journal import AccountInventory

                inventory = AccountInventory(
                    path,
                    session_id=1,
                    program_id=str(DEFAULT_PROGRAM_ID),
                    authority=str(self.authority),
                )
                inventory.plan(
                    (
                        (addresses[0], "session", None),
                        (addresses[1], "input_stream", addresses[0]),
                        (addresses[2], "state_span_0", addresses[0]),
                        (addresses[3], "state_span_1", addresses[0]),
                    )
                )

    def test_account_inventory_persists_role_parent_and_lifecycle(self):
        from dcg.session.journal import AccountInventory
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "accounts.json"
            inventory = AccountInventory(
                path,
                session_id=1,
                program_id=str(DEFAULT_PROGRAM_ID),
                authority=str(self.authority),
            )
            inventory.plan(
                (
                    (str(self.addresses.session), "session", None),
                    (str(self.addresses.stream), "input_stream", str(self.addresses.session)),
                )
            )
            inventory.mark_created(str(self.addresses.session))
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["accounts"],
                [
                    {
                        "address": str(self.addresses.session),
                        "lifecycle": "created",
                        "parent": None,
                        "role": "session",
                    },
                    {
                        "address": str(self.addresses.stream),
                        "lifecycle": "planned",
                        "parent": str(self.addresses.session),
                        "role": "input_stream",
                    },
                ],
            )


if __name__ == "__main__":
    unittest.main()
