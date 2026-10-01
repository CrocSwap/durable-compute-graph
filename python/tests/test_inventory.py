from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from solders.pubkey import Pubkey

from dcg.sequencer import AccountInfo, Commitment, JournalError
from dcg.session import AccountRecord, DEFAULT_PROGRAM_ID, Inventory, stateful_account_codecs


class MockInventoryRpc:
    def __init__(self, program_id: str, accounts: dict[str, AccountInfo]):
        self.program_id = program_id
        self.accounts = accounts
        self.multiple_calls: list[tuple[str, ...]] = []
        self.program_calls: list[tuple[str, int]] = []

    async def get_multiple_accounts(self, addresses, commitment):
        self.assert_commitment(commitment)
        group = tuple(addresses)
        self.multiple_calls.append(group)
        return tuple(self.accounts.get(address) for address in group)

    async def get_program_accounts(self, program_id, *, filters, commitment):
        self.assert_commitment(commitment)
        self.assertEqual(program_id, self.program_id)
        memcmp = filters[0]["memcmp"]
        offset = memcmp["offset"]
        parent = str(Pubkey.from_string(memcmp["bytes"]))
        self.program_calls.append((parent, offset))
        return tuple(
            (address, info)
            for address, info in self.accounts.items()
            if info.owner == program_id
            and len(info.data) >= offset + 32
            and str(Pubkey.from_bytes(info.data[offset : offset + 32])) == parent
        )

    @staticmethod
    def assertEqual(first, second):
        if first != second:
            raise AssertionError(f"{first!r} != {second!r}")

    @staticmethod
    def assert_commitment(commitment):
        if commitment != Commitment.CONFIRMED:
            raise AssertionError(f"unexpected commitment {commitment!r}")


def session_header(status: int, authority: str, child_count: int = 0) -> bytes:
    data = bytearray(672)
    data[:4] = b"DSS1"
    data[6] = status
    data[12:20] = (1).to_bytes(8, "little")
    data[20:52] = bytes(Pubkey.from_string(authority))
    data[120:122] = child_count.to_bytes(2, "little")
    return bytes(data)


def child_header(magic: bytes, parent: str, *, kind: int, index: int | None = None, size: int = 128) -> bytes:
    data = bytearray(size)
    data[:4] = magic
    data[4:6] = (1).to_bytes(2, "little")
    data[6] = kind
    data[8:40] = bytes(Pubkey.from_string(parent))
    if magic == b"DSB1":
        data[72:74] = (2).to_bytes(2, "little")
        data[84:88] = (16).to_bytes(4, "little")
    elif magic == b"DSE1":
        data[84:88] = (size - 128).to_bytes(4, "little")
    if index is not None:
        data[78] = index
    return bytes(data)


class InventoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.program = str(DEFAULT_PROGRAM_ID)
        self.authority = Pubkey.from_bytes(bytes([17]) * 32)
        self.session = AccountRecord.derive(
            self.program,
            kind="stateful_session_v1",
            role="session",
            seeds=(b"dcg-session-v1", bytes(self.authority), (1).to_bytes(8, "little")),
            expected_size=672,
            lifecycle="live",
        )
        self.stream = AccountRecord.derive(
            self.program,
            kind="stateful_stream_v1",
            role="input_stream",
            seeds=(b"dcg-input-v1", bytes(Pubkey.from_string(self.session.address))),
            parent=self.session.address,
            expected_size=160,
            lifecycle="live",
        )
        self.state0 = AccountRecord.derive(
            self.program,
            kind="stateful_state_v1",
            role="state_span_0",
            seeds=(b"dcg-state-v1", bytes(Pubkey.from_string(self.session.address)), b"\x00"),
            parent=self.session.address,
            expected_size=128,
            lifecycle="live",
        )
        self.state2 = AccountRecord.derive(
            self.program,
            kind="stateful_state_v1",
            role="state_span_2",
            seeds=(b"dcg-state-v1", bytes(Pubkey.from_string(self.session.address)), b"\x02"),
            parent=self.session.address,
            expected_size=128,
            lifecycle="live",
        )
        self.extra_state1 = AccountRecord.derive(
            self.program,
            kind="stateful_state_v1",
            role="state_span_1",
            seeds=(b"dcg-state-v1", bytes(Pubkey.from_string(self.session.address)), b"\x01"),
            parent=self.session.address,
            expected_size=128,
            lifecycle="live",
        )
        self.temp = tempfile.TemporaryDirectory(prefix="dcg-inventory-")
        self.addCleanup(self.temp.cleanup)

    def inventory(self, entries):
        inventory = Inventory(
            Path(self.temp.name) / "accounts.json",
            program_id=self.program,
            metadata={"session_id": 1, "authority": str(self.authority)},
            codecs=stateful_account_codecs(1),
        )
        inventory.plan(entries)
        return inventory

    async def test_reconcile_reports_missing_extra_wrong_owner_and_wrong_size(self):
        inventory = self.inventory((self.session, self.stream, self.state0, self.state2))
        rpc = MockInventoryRpc(
            self.program,
            {
                self.session.address: AccountInfo(self.program, 500, False, None, session_header(1, str(self.authority))),
                self.stream.address: AccountInfo("WrongOwner11111111111111111111111111111", 200, False, None, child_header(b"DSB1", self.session.address, kind=1, size=160)),
                self.state0.address: AccountInfo(self.program, 300, False, None, child_header(b"DSE1", self.session.address, kind=2, index=0, size=130)),
                self.extra_state1.address: AccountInfo(self.program, 350, False, None, child_header(b"DSE1", self.session.address, kind=2, index=1, size=129)),
            },
        )

        report = await inventory.reconcile(rpc)

        self.assertEqual([item.address for item in report.missing], [self.state2.address])
        self.assertEqual([item.address for item in report.unexpected], [self.extra_state1.address])
        self.assertTrue(any(self.stream.address in issue.address and "owner" in issue.message for issue in report.wrong_state))
        self.assertTrue(any(self.state0.address == issue.address and "data size" in issue.message for issue in report.wrong_state))
        self.assertIn((self.session.address, 8), rpc.program_calls)

    async def test_reconcile_can_rebuild_unjournaled_parent_bearing_children(self):
        inventory = self.inventory((self.session,))
        rpc = MockInventoryRpc(
            self.program,
            {
                self.session.address: AccountInfo(self.program, 500, False, None, session_header(1, str(self.authority))),
                self.extra_state1.address: AccountInfo(self.program, 350, False, None, child_header(b"DSE1", self.session.address, kind=2, index=1, size=129)),
            },
        )

        report = await inventory.reconcile(rpc, rebuild=True)

        self.assertEqual([item.address for item in report.rebuilt], [self.extra_state1.address])
        self.assertEqual(inventory.record(self.extra_state1.address).lifecycle, "live")
        self.assertEqual(inventory.record(self.extra_state1.address).rent_lamports, 350)
        self.assertFalse(report.unexpected)

    async def test_reconcile_reports_a_locally_edited_address_instead_of_trusting_it(self):
        inventory = self.inventory((self.session,))
        path = Path(self.temp.name) / "accounts.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["accounts"][0]["address"] = str(Pubkey.default())
        path.write_text(json.dumps(payload), encoding="utf-8")
        reloaded = Inventory(
            path,
            program_id=self.program,
            metadata={"session_id": 1, "authority": str(self.authority)},
            codecs=stateful_account_codecs(1),
        )
        rpc = MockInventoryRpc(
            self.program,
            {self.session.address: AccountInfo(self.program, 500, False, None, session_header(1, str(self.authority)))},
        )

        report = await reloaded.reconcile(rpc)

        self.assertTrue(any("seed-derived address" in issue.message for issue in report.wrong_state))

    async def test_close_refuses_a_live_account_before_rpc_or_close_action(self):
        inventory = self.inventory((self.session,))
        rpc = MockInventoryRpc(
            self.program,
            {self.session.address: AccountInfo(self.program, 500, False, None, session_header(1, str(self.authority)))},
        )
        called = False

        async def close_action(_record, _info):
            nonlocal called
            called = True

        with self.assertRaisesRegex(JournalError, "must be retired"):
            await inventory.close(self.session.address, rpc, close_action)

        self.assertFalse(called)
        self.assertFalse(rpc.multiple_calls)

    async def test_retired_close_refuses_a_chain_dependent_account(self):
        session = AccountRecord(**{**self.session.__dict__, "lifecycle": "retired"})
        inventory = self.inventory((session, self.stream))
        rpc = MockInventoryRpc(
            self.program,
            {
                session.address: AccountInfo(self.program, 500, False, None, session_header(2, str(self.authority))),
                self.stream.address: AccountInfo(self.program, 200, False, None, child_header(b"DSB1", session.address, kind=1, size=160)),
            },
        )
        called = False

        async def close_action(_record, _info):
            nonlocal called
            called = True

        with self.assertRaisesRegex(JournalError, "on-chain dependents"):
            await inventory.close(session.address, rpc, close_action)

        self.assertFalse(called)

    async def test_retired_session_close_refuses_nonzero_chain_dependency_count(self):
        session = replace(self.session, lifecycle="retired")
        inventory = self.inventory((session,))
        rpc = MockInventoryRpc(
            self.program,
            {session.address: AccountInfo(self.program, 500, False, None, session_header(2, str(self.authority), 1))},
        )

        async def close_action(_record, _info):
            raise AssertionError("close action must not run")

        with self.assertRaisesRegex(JournalError, "records 1 dependent"):
            await inventory.close(session.address, rpc, close_action)

    async def test_retired_close_rechecks_absence_before_marking_closed(self):
        session = replace(self.session, lifecycle="planned")
        inventory = self.inventory((session,))
        inventory.mark_live(session.address, payer=str(self.authority), rent_lamports=500)
        inventory.retire(session.address)
        rpc = MockInventoryRpc(
            self.program,
            {session.address: AccountInfo(self.program, 500, False, None, session_header(2, str(self.authority)))},
        )

        async def close_action(record, _info):
            rpc.accounts.pop(record.address)

        refunded = await inventory.close(session.address, rpc, close_action)

        self.assertEqual(refunded, 500)
        self.assertEqual(inventory.record(session.address).lifecycle, "closed")
        self.assertEqual(len(rpc.multiple_calls), 3)

    async def test_missing_planned_account_can_be_removed_only_after_chain_read(self):
        inventory = self.inventory((replace(self.state2, lifecycle="planned"),))
        rpc = MockInventoryRpc(self.program, {})

        await inventory.forget_missing_plan(self.state2.address, rpc)

        self.assertFalse(inventory.accounts)
        self.assertEqual(rpc.multiple_calls, [(self.state2.address,)])


if __name__ == "__main__":
    unittest.main()
