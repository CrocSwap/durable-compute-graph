from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
import os
import queue
import resource
import statistics
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.transaction import VersionedTransaction

from dcg.sequencer.stream import (
    StreamClosed,
    StreamError,
    StreamIdentity,
    StreamIntent,
    StreamLimits,
    StreamQuotaExceeded,
    StreamTerminal,
    StreamingPlan,
)
from dcg.sequencer.stream_journal import StreamJournal


_KEYPAIR = Keypair()
_PROGRAM = Keypair().pubkey()
_DESTINATION = Keypair().pubkey()


def identity(
    *,
    genesis_hash: str = "genesis-test-1",
    signer_public_keys: tuple[str, ...] | None = None,
    destination_accounts: tuple[str, ...] | None = None,
    commitment_policy: str = "confirmed",
) -> StreamIdentity:
    return StreamIdentity(
        run_id="app-session-17",
        genesis_hash=genesis_hash,
        program_id=str(_PROGRAM),
        destination_accounts=destination_accounts or (str(_DESTINATION),),
        signer_public_keys=signer_public_keys or (str(_KEYPAIR.pubkey()),),
        route_policy_digest="route-policy-sha256",
        commitment_policy=commitment_policy,
    )


def intent(
    step_id: str,
    *,
    dependencies: tuple[str, ...] = (),
    blob_bytes: int = 0,
    route_group: str = "render",
    route_affinity: str | None = "lane-a",
) -> StreamIntent:
    return StreamIntent(
        step_id=step_id,
        dependencies=dependencies,
        route_group=route_group,
        route_affinity=route_affinity,
        compute_class="range-write",
        compute_unit_limit=180_000,
        intent_digest=f"intent-{step_id}",
        recovery_policy_digest=f"recovery-{step_id}",
        intent_data={"step": step_id, "blob": "x" * blob_bytes},
        max_packet_bytes=1232,
        write_locks=(f"account-{step_id}",),
    )


def signed_packet(step_id: str) -> tuple[str, bytes]:
    recent_blockhash = Hash.from_bytes(hashlib.sha256(step_id.encode()).digest())
    instruction = Instruction(
        _PROGRAM,
        b"\x01",
        [AccountMeta(_DESTINATION, False, True)],
    )
    transaction = VersionedTransaction(
        Message.new_with_blockhash([instruction], _KEYPAIR.pubkey(), recent_blockhash),
        [_KEYPAIR],
    )
    return str(transaction.signatures[0]), bytes(transaction)


async def confirm(stream: StreamingPlan, step_id: str, signature: str | None = None) -> None:
    actual_signature, raw_packet = signed_packet(step_id) if signature is None else signed_packet(step_id)
    assert signature is None or signature == actual_signature
    await stream.record_signed_packet(step_id, actual_signature, raw_packet, str(_KEYPAIR.pubkey()))
    await stream.record_terminal(
        StreamTerminal(
            step_id=step_id,
            outcome="confirmed",
            signature=actual_signature,
            commitment="confirmed",
            postcondition_satisfied=True,
            postcondition_digest=f"state-{step_id}",
            slot=20,
        )
    )


def _long_run_worker(root_text: str, progress: Any) -> None:
    """Run the isolated 100k-step persistence probe and return checkpoint samples."""

    root = Path(root_text)
    limits = StreamLimits(
        max_pending_steps=128,
        max_segment_bytes=4 * 1024 * 1024,
        max_journal_bytes=64 * 1024 * 1024,
        append_reserve_bytes=1024,
        max_intent_bytes=512,
        max_attempts_per_generation=1,
        max_observations_per_generation=1,
        max_generations_per_step=1,
    )
    journal = StreamJournal(root, identity(), limits)
    signature, raw_packet = signed_packet("shared-long-run-packet")
    samples = []
    max_disk_bytes = journal.disk_bytes
    started = time.perf_counter()
    try:
        for index in range(100_000):
            step_id = f"step-{index:06d}"
            journal.append_intent(intent(step_id, route_affinity=None))
            journal.record_signed_packet(step_id, signature, raw_packet, str(_KEYPAIR.pubkey()))
            journal.record_send_attempt(
                step_id,
                0,
                provider_id="tpu",
                endpoint_id="rpc-a",
                route_group="render",
            )
            journal.record_send_result(
                step_id,
                0,
                1,
                acknowledged=True,
                disposition="helper-pipe-written",
            )
            journal.record_observation(
                step_id,
                0,
                status_commitment="confirmed",
                status_error=None,
                slot=1,
                postcondition_satisfied=True,
                postcondition_digest="stable-state",
            )
            journal.record_terminal(
                StreamTerminal(
                    step_id=step_id,
                    outcome="confirmed",
                    signature=signature,
                    commitment="confirmed",
                    postcondition_satisfied=True,
                    postcondition_digest="stable-state",
                )
            )
            max_disk_bytes = max(max_disk_bytes, journal.disk_bytes)
            if (index + 1) % 5_000 == 0:
                journal.checkpoint(index + 1)
                journal.close()
                open_started = time.perf_counter()
                journal = StreamJournal(root, identity(), limits)
                open_seconds = time.perf_counter() - open_started
                checkpoint_paths = list((root / "checkpoints").glob("checkpoint-*.json"))
                sample = {
                    "steps": index + 1,
                    "disk_bytes": journal.disk_bytes,
                    "max_disk_bytes": max_disk_bytes,
                    "file_count": sum(path.is_file() for path in root.rglob("*")),
                    "manifest_bytes": journal.manifest_bytes,
                    "checkpoint_bytes": checkpoint_paths[0].stat().st_size if checkpoint_paths else 0,
                    "open_seconds": open_seconds,
                }
                samples.append(sample)
                progress.put({"progress": sample})
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_bytes = int(peak if sys.platform == "darwin" else peak * 1024)
        progress.put(
            {
                "done": {
                    "elapsed_seconds": time.perf_counter() - started,
                    "peak_rss_bytes": peak_bytes,
                    "samples": samples,
                }
            }
        )
    finally:
        journal.close()


def _complete_journal_step(
    journal: StreamJournal,
    step_id: str,
    *,
    dependencies: tuple[str, ...] = (),
    observe: bool = False,
    acknowledge: bool = False,
) -> tuple[str, bytes]:
    journal.append_intent(intent(step_id, dependencies=dependencies, route_affinity=None))
    signature, raw_packet = signed_packet(step_id)
    journal.record_signed_packet(step_id, signature, raw_packet, str(_KEYPAIR.pubkey()))
    if acknowledge:
        journal.record_send_attempt(
            step_id,
            0,
            provider_id="tpu",
            endpoint_id="rpc-a",
            route_group="render",
        )
        journal.record_send_result(
            step_id,
            0,
            1,
            acknowledged=True,
            disposition="helper-pipe-written",
        )
    if observe:
        journal.record_observation(
            step_id,
            0,
            status_commitment="confirmed",
            status_error=None,
            slot=1,
            postcondition_satisfied=True,
            postcondition_digest="stable-state",
        )
    journal.record_terminal(
        StreamTerminal(
            step_id=step_id,
            outcome="confirmed",
            signature=signature,
            commitment="confirmed",
            postcondition_satisfied=True,
            postcondition_digest="stable-state",
        )
    )
    return signature, raw_packet


class StreamingJournalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="dcg-stream-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.streams: list[StreamingPlan] = []

    async def asyncTearDown(self) -> None:
        for stream in reversed(self.streams):
            await stream.close()

    async def open_stream(
        self,
        name: str = "run",
        *,
        limits: StreamLimits | None = None,
        stream_identity: StreamIdentity | None = None,
    ) -> StreamingPlan:
        stream = await StreamingPlan.open(
            stream_identity or identity(),
            self.root / name,
            limits=limits or StreamLimits(),
        )
        self.streams.append(stream)
        return stream

    async def close_stream(self, stream: StreamingPlan) -> None:
        await stream.close()
        self.streams.remove(stream)

    async def test_restart_repairs_partial_tail_and_duplicate_append_is_idempotent(self):
        stream = await self.open_stream()
        original = intent("step-1")
        first = await stream.append(original)
        active_path = self.root / "run" / "segments" / "segment-00000000.jsonl"
        with active_path.open("ab") as journal_file:
            journal_file.write(b'{"schema_version":3,"event_sequence":999,"event":"partial"')
        await self.close_stream(stream)

        resumed = await self.open_stream()
        self.assertEqual(resumed.pending_count, 1)
        duplicate = await resumed.append(original)
        self.assertTrue(duplicate.already_present)
        self.assertEqual(duplicate.sequence, first.sequence)
        self.assertEqual(duplicate.sequence_digest, first.sequence_digest)
        self.assertTrue(active_path.read_bytes().endswith(b"\n"))
        self.assertNotIn(b"partial", active_path.read_bytes())

        changed = StreamIntent(
            **{
                **original.__dict__,
                "intent_digest": "different-intent",
            }
        )
        with self.assertRaises(StreamError):
            await resumed.append(changed)

    async def test_complete_final_row_without_newline_is_accepted(self):
        stream = await self.open_stream()
        await stream.append(intent("final-row"))
        active_path = self.root / "run" / "segments" / "segment-00000000.jsonl"
        data = active_path.read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        active_path.write_bytes(data[:-1])
        await self.close_stream(stream)

        resumed = await self.open_stream()
        self.assertEqual([step.step_id for _, step in resumed.pending_intents], ["final-row"])
        self.assertTrue(active_path.read_bytes().endswith(b"\n"))

    async def test_single_writer_lock_refuses_second_opener(self):
        first = await self.open_stream()
        with self.assertRaisesRegex(StreamError, "active writer"):
            await StreamingPlan.open(identity(), self.root / "run", limits=StreamLimits())
        await self.close_stream(first)
        second = await self.open_stream()
        self.assertEqual(second.pending_count, 0)

    async def test_pending_limit_backpressures_until_a_terminal_summary(self):
        stream = await self.open_stream(limits=StreamLimits(max_pending_steps=1))
        first = await stream.append(intent("first"))
        blocked = asyncio.create_task(stream.append(intent("second", dependencies=("first",))))
        await asyncio.sleep(0.02)
        self.assertFalse(blocked.done())
        self.assertEqual(stream.pending_count, 1)

        await confirm(stream, "first")
        second = await asyncio.wait_for(blocked, timeout=1)
        self.assertEqual(second.sequence, first.sequence + 1)
        self.assertEqual(stream.pending_count, 1)

    async def test_append_rechecks_dependencies_after_capacity_wait(self):
        limits = StreamLimits(max_pending_steps=1)
        journal = StreamJournal(self.root / "dependency-wait", identity(), limits)
        journal.append_intent(intent("first", route_affinity=None))
        first_signature, first_packet = signed_packet("first")
        journal.record_signed_packet("first", first_signature, first_packet, str(_KEYPAIR.pubkey()))
        stream = StreamingPlan(journal, limits)
        blocked = asyncio.create_task(
            stream.append(intent("blocked", dependencies=("first",), route_affinity=None))
        )
        await asyncio.sleep(0.02)
        self.assertFalse(blocked.done())

        async with stream._condition:
            journal.record_terminal(
                StreamTerminal(
                    step_id="first",
                    outcome="confirmed",
                    signature=first_signature,
                    commitment="confirmed",
                    postcondition_satisfied=True,
                    postcondition_digest="stable-first",
                )
            )
            _complete_journal_step(journal, "unrelated")
            self.assertNotIn("first", journal.intents)
            stream._condition.notify_all()

        with self.assertRaisesRegex(StreamError, "after the capacity wait"):
            await blocked
        await stream.close()

    async def test_quota_reservation_keeps_admitted_work_finishable(self):
        limits = StreamLimits(
            max_pending_steps=8,
            max_segment_bytes=8192,
            max_journal_bytes=40_000,
            append_reserve_bytes=1024,
            max_attempts_per_generation=1,
            max_observations_per_generation=1,
            max_generations_per_step=1,
        )
        stream = await self.open_stream(limits=limits)
        admitted: list[str] = []
        for index in range(8):
            step_id = f"quota-{index}"
            try:
                await stream.append(intent(step_id, blob_bytes=400))
            except StreamQuotaExceeded:
                break
            admitted.append(step_id)
        self.assertGreaterEqual(len(admitted), 1)
        self.assertLess(len(admitted), 8)

        for step_id in admitted:
            signature, raw_packet = signed_packet(step_id)
            await stream.record_signed_packet(step_id, signature, raw_packet, str(_KEYPAIR.pubkey()))
            await stream.record_terminal(
                StreamTerminal(
                    step_id=step_id,
                    outcome="confirmed",
                    signature=signature,
                    commitment="confirmed",
                    postcondition_satisfied=True,
                    postcondition_digest=f"state-{step_id}",
                )
            )
        self.assertEqual(stream.pending_count, 0)
        self.assertEqual(len(stream.terminal_summaries), len(admitted))

    async def test_tight_quota_refuses_rotation_without_poisoning_pending_work(self):
        limits = StreamLimits(
            max_pending_steps=16,
            max_segment_bytes=64 * 1024,
            max_journal_bytes=1400 * 1024,
            append_reserve_bytes=1024,
            max_attempts_per_generation=1,
            max_observations_per_generation=2,
            max_generations_per_step=1,
        )
        journal = StreamJournal(self.root / "tight-quota", identity(), limits)
        pending: list[tuple[str, str]] = []
        next_step = 0
        refused = False
        try:
            for _ in range(300):
                while len(pending) < limits.max_pending_steps:
                    step_id = f"quota-{next_step:05d}"
                    before = (
                        journal.event_high_water_mark,
                        journal.sequence_digest,
                        journal.disk_bytes,
                        journal._active_bytes,
                    )
                    try:
                        journal.append_intent(
                            intent(step_id, blob_bytes=15_000, route_affinity=None)
                        )
                    except StreamQuotaExceeded:
                        refused = True
                        self.assertLess(journal.pending_count, limits.max_pending_steps)
                        self.assertGreater(before[3] + 15_000, limits.max_segment_bytes)
                        self.assertEqual(
                            before,
                            (
                                journal.event_high_water_mark,
                                journal.sequence_digest,
                                journal.disk_bytes,
                                journal._active_bytes,
                            ),
                        )
                        break
                    signature, raw = signed_packet(step_id)
                    journal.record_signed_packet(step_id, signature, raw, str(_KEYPAIR.pubkey()))
                    pending.append((step_id, signature))
                    next_step += 1
                if refused:
                    break
                step_id, signature = pending.pop(0)
                for commitment in ("processed", "confirmed"):
                    journal.record_observation(
                        step_id,
                        0,
                        status_commitment=commitment,
                        status_error=None,
                        slot=1,
                        postcondition_satisfied=None,
                        postcondition_digest=None,
                    )
                journal.record_terminal(
                    StreamTerminal(
                        step_id=step_id,
                        outcome="confirmed",
                        signature=signature,
                        commitment="confirmed",
                        postcondition_satisfied=True,
                        postcondition_digest="stable-quota-state",
                    )
                )

            self.assertTrue(refused, "the configured tight quota should refuse an append")
            self.assertGreater(len(pending), 0)
            self.assertFalse(journal._poisoned)
            for step_id, signature in pending:
                for commitment in ("processed", "confirmed"):
                    journal.record_observation(
                        step_id,
                        0,
                        status_commitment=commitment,
                        status_error=None,
                        slot=1,
                        postcondition_satisfied=None,
                        postcondition_digest=None,
                    )
                journal.record_terminal(
                    StreamTerminal(
                        step_id=step_id,
                        outcome="confirmed",
                        signature=signature,
                        commitment="confirmed",
                        postcondition_satisfied=True,
                        postcondition_digest="stable-quota-state",
                    )
                )
            self.assertEqual(journal.pending_count, 0)
            self.assertFalse(journal._poisoned)
        finally:
            journal.close()

    async def test_signed_packet_identity_and_signature_are_checked(self):
        stream = await self.open_stream()
        await stream.append(intent("verified"))
        signature, raw_packet = signed_packet("verified")
        tampered = bytearray(raw_packet)
        tampered[-1] ^= 1
        with self.assertRaises(StreamError):
            await stream.record_signed_packet(
                "verified", signature, bytes(tampered), str(_KEYPAIR.pubkey())
            )
        accepted = await stream.record_signed_packet(
            "verified", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        self.assertEqual(accepted.raw_bytes, raw_packet)

        wrong_program = Keypair().pubkey()
        wrong_instruction = Instruction(
            wrong_program,
            b"\x02",
            [AccountMeta(_DESTINATION, False, True)],
        )
        other_tx = VersionedTransaction(
            Message.new_with_blockhash(
                [wrong_instruction],
                _KEYPAIR.pubkey(),
                Hash.from_bytes(hashlib.sha256(b"wrong-program").digest()),
            ),
            [_KEYPAIR],
        )
        with self.assertRaises(StreamError):
            await stream.record_signed_packet(
                "verified", str(other_tx.signatures[0]), bytes(other_tx), str(_KEYPAIR.pubkey())
            )

    async def test_stream_instruction_requires_every_account_meta_to_be_bound(self):
        unbound_authority = Keypair().pubkey()
        unbound = (
            AccountMeta(_KEYPAIR.pubkey(), True, True),
            AccountMeta(unbound_authority, False, True),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
        )
        for index, account in enumerate(unbound):
            step_id = f"unbound-{index}"
            stream = await self.open_stream(step_id)
            await stream.append(intent(step_id))
            instruction = Instruction(
                _PROGRAM,
                b"\x01",
                [AccountMeta(_DESTINATION, False, True), account],
            )
            transaction = VersionedTransaction(
                Message.new_with_blockhash(
                    [instruction],
                    _KEYPAIR.pubkey(),
                    Hash.from_bytes(hashlib.sha256(step_id.encode()).digest()),
                ),
                [_KEYPAIR],
            )
            with self.assertRaisesRegex(StreamError, "outside the identity"):
                await stream.record_signed_packet(
                    step_id,
                    str(transaction.signatures[0]),
                    bytes(transaction),
                    str(_KEYPAIR.pubkey()),
                )

        other_program = Keypair().pubkey()
        other_account = Keypair().pubkey()
        step_id = "other-program-account"
        stream = await self.open_stream(step_id)
        await stream.append(intent(step_id))
        transaction = VersionedTransaction(
            Message.new_with_blockhash(
                [
                    Instruction(
                        _PROGRAM,
                        b"\x01",
                        [AccountMeta(_DESTINATION, False, True)],
                    ),
                    Instruction(
                        other_program,
                        b"\x02",
                        [AccountMeta(other_account, False, True)],
                    ),
                ],
                _KEYPAIR.pubkey(),
                Hash.from_bytes(hashlib.sha256(step_id.encode()).digest()),
            ),
            [_KEYPAIR],
        )
        packet = await stream.record_signed_packet(
            step_id,
            str(transaction.signatures[0]),
            bytes(transaction),
            str(_KEYPAIR.pubkey()),
        )
        self.assertEqual(packet.raw_bytes, bytes(transaction))

    async def test_record_signed_packet_is_idempotent_for_latest_generation(self):
        stream = await self.open_stream()
        await stream.append(intent("same-packet"))
        signature, raw_packet = signed_packet("same-packet")
        first = await stream.record_signed_packet(
            "same-packet", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        duplicate = await stream.record_signed_packet(
            "same-packet", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        self.assertEqual(first, duplicate)
        self.assertEqual(len(await stream.unresolved_packets()), 1)

    async def test_unresolved_packet_route_attempts_and_observations_survive_rotation(self):
        limits = StreamLimits(
            max_pending_steps=16,
            max_segment_bytes=4096,
            max_journal_bytes=2_000_000,
            max_attempts_per_generation=20,
            max_observations_per_generation=8,
        )
        stream = await self.open_stream(limits=limits)
        await stream.append(intent("pending", blob_bytes=1000))
        signature, raw_packet = signed_packet("pending")
        first = await stream.record_signed_packet(
            "pending", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        self.assertEqual(first.raw_bytes, raw_packet)
        route = SimpleNamespace(
            endpoint_id="rpc-a",
            route_group="render",
            affinity_key="lane-a",
            is_probe=False,
        )
        for number in range(1, 15):
            attempt = await stream.record_send_attempt(
                "pending",
                0,
                provider_id="tpu-quic",
                route=route,
            )
            self.assertEqual(attempt.number, number)
            await stream.record_send_result(
                "pending",
                0,
                number,
                acknowledged=(number == 14),
                route=route,
                receipt=(
                    SimpleNamespace(
                        signature=signature,
                        provider_id="tpu-quic",
                        endpoint_id="rpc-a",
                        disposition="helper-pipe-written",
                    )
                    if number == 14
                    else None
                ),
                detail=f"transport-{number}",
            )
        await stream.record_observation(
            "pending",
            0,
            status_commitment="processed",
            status_error=None,
            slot=42,
            postcondition_satisfied=None,
            postcondition_digest=None,
        )
        # Boundary zero checkpoints the current prefix without claiming that
        # the unresolved step itself is terminal.
        await stream.checkpoint(through_sequence=0)
        await self.close_stream(stream)

        resumed = await self.open_stream(limits=limits)
        unresolved = await resumed.unresolved_packets()
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].raw_bytes, raw_packet)
        self.assertEqual(unresolved[0].signature, signature)
        self.assertEqual(len(unresolved[0].attempts), 14)
        self.assertEqual(unresolved[0].attempts[-1].provider_id, "tpu-quic")
        self.assertEqual(unresolved[0].attempts[-1].disposition, "helper-pipe-written")
        self.assertEqual(len(resumed.observations), 1)
        self.assertEqual(resumed.observations[0].slot, 42)

        checkpoints = [
            json.loads(path.read_bytes())
            for path in (self.root / "run" / "checkpoints").glob("checkpoint-*.json")
        ]
        self.assertEqual(len(checkpoints), 1)
        self.assertTrue(checkpoints[-1]["unresolved_packet_references"])
        self.assertEqual(
            checkpoints[-1]["unresolved_packet_references"][0]["packet_digest"],
            first.packet_digest,
        )
        self.assertNotIn("journal_events", checkpoints[-1])
        self.assertEqual(
            [row["step_id"] for row in checkpoints[-1]["observations"]], ["pending"]
        )

    async def test_late_provider_failure_and_latency_events_read_back_after_resume(self):
        stream = await self.open_stream()
        await stream.append(intent("late"))
        signature, raw_packet = signed_packet("late")
        await stream.record_signed_packet("late", signature, raw_packet, str(_KEYPAIR.pubkey()))
        await stream.record_send_attempt(
            "late",
            0,
            provider_id="tpu-quic",
            route=SimpleNamespace(
                endpoint_id="rpc-a", route_group="render", affinity_key=None, is_probe=False
            ),
        )
        route = SimpleNamespace(
            endpoint_id="rpc-a", route_group="render", affinity_key=None, is_probe=False
        )
        await stream.record_send_result(
            "late",
            0,
            1,
            acknowledged=True,
            route=route,
            receipt=SimpleNamespace(
                signature=signature,
                provider_id="tpu-quic",
                endpoint_id="rpc-a",
                disposition="helper-pipe-written",
            ),
        )
        await stream.record_late_provider_failure(
            "late",
            0,
            1,
            route=route,
            receipt=SimpleNamespace(
                signature=signature,
                provider_id="tpu-quic",
                endpoint_id="rpc-a",
                disposition="helper-pipe-written",
            ),
            detail="drain_failures reported late error",
        )
        await stream.record_step_dropped("late", 0, detail="processed status disappeared")
        with self.assertRaisesRegex(StreamError, "already recorded"):
            await stream.record_step_dropped("late", 0, detail="duplicate lifecycle event")
        await stream.record_optimistic_branch_invalidated("late", 0, detail="parent branch was dropped")
        await stream.record_reconciliation_required("late", 0, detail="application state readback required")
        await self.close_stream(stream)

        resumed = await self.open_stream()
        self.assertEqual(len(resumed.provider_failures), 1)
        self.assertEqual(resumed.provider_failures[0].data["provider_id"], "tpu-quic")
        self.assertEqual(
            [event.event for event in resumed.lifecycle_events],
            [
                "late_provider_failure",
                "step_dropped",
                "optimistic_branch_invalidated",
                "reconciliation_required",
            ],
        )

    async def test_identity_and_sequence_digest_are_stable_and_bind_genesis_signers(self):
        unsorted = StreamIdentity(
            run_id="app-session-17",
            genesis_hash="genesis-test-1",
            program_id=str(_PROGRAM),
            destination_accounts=(str(_DESTINATION),),
            signer_public_keys=(str(_KEYPAIR.pubkey()),),
            route_policy_digest="route-policy-sha256",
            commitment_policy="confirmed",
        )
        left = await self.open_stream("left", stream_identity=unsorted)
        right = await self.open_stream("right", stream_identity=identity())
        left_one = await left.append(intent("one"))
        right_one = await right.append(intent("one"))
        left_two = await left.append(intent("two", dependencies=("one",)))
        right_two = await right.append(intent("two", dependencies=("one",)))
        self.assertEqual(left.identity.destination_accounts, tuple(sorted(left.identity.destination_accounts)))
        self.assertEqual(left_one.sequence_digest, right_one.sequence_digest)
        self.assertEqual(left_two.sequence_digest, right_two.sequence_digest)
        await self.close_stream(left)

        changed_genesis = identity(genesis_hash="another-genesis")
        with self.assertRaises(StreamError):
            await StreamingPlan.open(changed_genesis, self.root / "left", limits=StreamLimits())
        second_signer = Keypair()
        changed_signers = identity(signer_public_keys=(str(second_signer.pubkey()),))
        with self.assertRaises(StreamError):
            await StreamingPlan.open(changed_signers, self.root / "left", limits=StreamLimits())

    async def test_checkpoint_summarizes_terminal_work_and_compacts_segment(self):
        stream = await self.open_stream()
        await stream.append(intent("done"))
        signature, _ = signed_packet("done")
        await confirm(stream, "done", signature)
        checkpoint = await stream.checkpoint()

        self.assertEqual(set(checkpoint.confirmed_steps), {"done"})
        self.assertEqual(checkpoint.unresolved_packet_references, ())
        self.assertFalse((self.root / "run" / "segments" / "segment-00000000.jsonl").exists())
        await self.close_stream(stream)
        resumed = await self.open_stream()
        self.assertEqual(resumed.pending_count, 0)
        self.assertEqual(resumed.sequence_digest, checkpoint.sequence_digest)
        self.assertIn("done", resumed.terminal_summaries)

    async def test_checkpoint_keeps_only_latest_checkpoint_and_live_state(self):
        stream = await self.open_stream(limits=StreamLimits(max_pending_steps=2))
        await stream.append(intent("one"))
        await confirm(stream, "one")
        first = await stream.checkpoint()
        await stream.append(intent("two"))
        await confirm(stream, "two")
        second = await stream.checkpoint()

        checkpoint_paths = list((self.root / "run" / "checkpoints").glob("checkpoint-*.json"))
        segment_paths = list((self.root / "run" / "segments").glob("segment-*.jsonl"))
        self.assertEqual([path.stem for path in checkpoint_paths], [second.checkpoint_id])
        self.assertEqual([path.stem for path in segment_paths], ["segment-00000002"])
        record = json.loads(checkpoint_paths[0].read_bytes())
        self.assertNotIn("journal_events", record)
        self.assertEqual(set(record["terminal_records"]), {"one", "two"})
        self.assertEqual(record["pending_intents"], {})
        self.assertLess(second.event_high_water_mark, 2**63)
        self.assertNotEqual(first.checkpoint_id, second.checkpoint_id)

    async def test_missing_sealed_segment_index_is_a_stream_error(self):
        stream = await self.open_stream()
        await stream.append(intent("checkpoint-corruption"))
        await confirm(stream, "checkpoint-corruption")
        checkpoint = await stream.checkpoint()
        await self.close_stream(stream)

        checkpoint_path = self.root / "run" / "checkpoints" / f"{checkpoint.checkpoint_id}.json"
        checkpoint_record = json.loads(checkpoint_path.read_bytes())
        del checkpoint_record["sealed_segment_index"]
        checkpoint_bytes = json.dumps(
            checkpoint_record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        checkpoint_digest = hashlib.sha256(checkpoint_bytes).hexdigest()
        checkpoint_path.write_bytes(checkpoint_bytes)
        manifest_path = self.root / "run" / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["checkpoint"]["digest"] = checkpoint_digest
        manifest["previous_checkpoint_digest"] = checkpoint_digest
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
        segment_path = next((self.root / "run" / "segments").glob("segment-*.jsonl"))
        marker = json.loads(segment_path.read_text().splitlines()[0])
        marker["data"]["checkpoint_digest"] = checkpoint_digest
        segment_path.write_text(
            json.dumps(marker, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        )

        with self.assertRaisesRegex(StreamError, "sealed_segment_index is missing"):
            await StreamingPlan.open(identity(), self.root / "run", limits=StreamLimits())

    async def test_dependencies_are_refused_after_deterministic_terminal_window(self):
        limits = StreamLimits(max_pending_steps=1)
        stream = await self.open_stream(limits=limits)
        await stream.append(intent("old"))
        await confirm(stream, "old")
        await stream.append(intent("new", dependencies=("old",)))
        await confirm(stream, "new")
        journal = stream._journal
        self.assertNotIn("old", journal.intents)

        before = (
            journal.event_high_water_mark,
            journal.sequence_digest,
            journal.disk_bytes,
            journal._active_bytes,
        )
        with self.assertRaisesRegex(StreamError, "dependencies"):
            await stream.append(intent("too-old", dependencies=("old",)))
        self.assertEqual(
            before,
            (
                journal.event_high_water_mark,
                journal.sequence_digest,
                journal.disk_bytes,
                journal._active_bytes,
            ),
        )
        self.assertFalse(journal._poisoned)
        await self.close_stream(stream)
        resumed = await self.open_stream(limits=limits)
        self.assertEqual(resumed.pending_count, 0)
        self.assertEqual(resumed.terminal_summaries["new"].outcome, "confirmed")

    async def test_compacted_terminal_late_failure_is_an_orphan_and_reopens(self):
        limits = StreamLimits(max_pending_steps=1)
        stream = await self.open_stream(limits=limits)
        await stream.append(intent("provider-old"))
        signature, raw_packet = signed_packet("provider-old")
        await stream.record_signed_packet(
            "provider-old", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        route = SimpleNamespace(
            endpoint_id="rpc-a", route_group="render", affinity_key=None, is_probe=False
        )
        receipt = SimpleNamespace(
            signature=signature,
            provider_id="tpu",
            endpoint_id="rpc-a",
            disposition="helper-pipe-written",
        )
        await stream.record_send_attempt("provider-old", 0, provider_id="tpu", route=route)
        await stream.record_send_result(
            "provider-old", 0, 1, acknowledged=True, route=route, receipt=receipt
        )
        await stream.record_terminal(
            StreamTerminal(
                step_id="provider-old",
                outcome="confirmed",
                signature=signature,
                commitment="confirmed",
                postcondition_satisfied=True,
                postcondition_digest="stable",
            )
        )
        await stream.append(intent("newer", dependencies=("provider-old",)))
        await confirm(stream, "newer")
        self.assertNotIn("provider-old", stream._journal.intents)

        await stream.record_late_provider_failure(
            "provider-old",
            0,
            1,
            route=route,
            receipt=receipt,
            detail="provider reported delayed error",
        )
        self.assertTrue(stream.provider_failures[-1].data["orphan"])
        await self.close_stream(stream)
        resumed = await self.open_stream(limits=limits)
        self.assertEqual(len(resumed.provider_failures), 1)
        self.assertTrue(resumed.provider_failures[0].data["orphan"])
        self.assertEqual(resumed.pending_count, 0)

    async def test_processed_observation_is_labeled_optimistic_until_stable(self):
        stream = await self.open_stream()
        await stream.append(intent("optimistic"))
        signature, raw_packet = signed_packet("optimistic")
        await stream.record_signed_packet(
            "optimistic", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        await stream.record_observation(
            "optimistic",
            0,
            status_commitment="processed",
            status_error=None,
            slot=10,
            postcondition_satisfied=None,
            postcondition_digest=None,
        )
        self.assertEqual(stream.observations[-1].label, "optimistic")
        self.assertEqual(stream.optimistic_steps, ("optimistic",))
        await stream.record_observation(
            "optimistic",
            0,
            status_commitment="confirmed",
            status_error=None,
            slot=11,
            postcondition_satisfied=True,
            postcondition_digest="stable",
        )
        self.assertEqual(stream.observations[-1].label, "stable")
        self.assertEqual(stream.optimistic_steps, ())
        await stream.record_terminal(
            StreamTerminal(
                step_id="optimistic",
                outcome="confirmed",
                signature=signature,
                commitment="confirmed",
                postcondition_satisfied=True,
                postcondition_digest="stable",
                slot=11,
            )
        )

    async def test_unsigned_descendant_can_be_abandoned_after_journaled_reconciliation(self):
        limits = StreamLimits(max_pending_steps=1)
        final_identity = identity(commitment_policy="finalized")
        stream = await self.open_stream(
            limits=limits, stream_identity=final_identity
        )
        await stream.append(intent("parent"))
        parent_signature, parent_packet = signed_packet("parent")
        await stream.record_signed_packet(
            "parent", parent_signature, parent_packet, str(_KEYPAIR.pubkey())
        )
        await stream.record_terminal(
            StreamTerminal(
                step_id="parent",
                outcome="confirmed",
                signature=parent_signature,
                commitment="finalized",
                postcondition_satisfied=True,
                postcondition_digest="stable-parent",
            )
        )
        await stream.append(intent("unsigned-child", dependencies=("parent",)))
        await stream.record_reconciliation_required(
            "unsigned-child", 0, detail="parent branch was dropped before child signing"
        )
        with self.assertRaisesRegex(StreamError, "journaled adapter decision"):
            await stream.record_terminal(
                StreamTerminal(
                    step_id="unsigned-child",
                    outcome="abandoned",
                    signature=None,
                    commitment=None,
                    postcondition_satisfied=False,
                    postcondition_digest="adapter-decision",
                    reconciliation_decision_event_sequence=0,
                )
            )
        self.assertEqual(stream.pending_count, 1)
        self.assertTrue(stream.lifecycle_events[-1].data["unsigned"])
        decision_sequence = await stream.record_reconciliation_decision(
            "unsigned-child",
            0,
            decision="abandon",
            evidence_digest="adapter-decision",
        )
        await stream.record_terminal(
            StreamTerminal(
                step_id="unsigned-child",
                outcome="abandoned",
                signature=None,
                commitment=None,
                postcondition_satisfied=False,
                postcondition_digest="adapter-decision",
                reconciliation_decision_event_sequence=decision_sequence,
            )
        )
        self.assertEqual(stream.pending_count, 0)
        self.assertIsNone(stream.terminal_summaries["unsigned-child"].commitment)
        await stream.checkpoint(2)
        await self.close_stream(stream)
        resumed = await self.open_stream(limits=limits, stream_identity=final_identity)
        self.assertEqual(resumed.terminal_summaries["unsigned-child"].outcome, "abandoned")

    async def test_rebuilt_step_observations_reopen_with_their_generation_signatures(self):
        limits = StreamLimits(max_pending_steps=4)
        journal = StreamJournal(self.root / "rebuild", identity(), limits)
        journal.append_intent(intent("rebuilt", route_affinity=None))
        signature0, raw0 = signed_packet("rebuilt")
        journal.record_signed_packet("rebuilt", signature0, raw0, str(_KEYPAIR.pubkey()))
        journal.record_observation(
            "rebuilt",
            0,
            status_commitment=None,
            status_error="BlockhashNotFound",
            slot=None,
            postcondition_satisfied=None,
            postcondition_digest=None,
        )
        journal.authorize_rebuild("rebuilt", 0, "expired-blockhash-observation")
        signature1, raw1 = signed_packet("rebuilt-generation-1")
        journal.record_signed_packet("rebuilt", signature1, raw1, str(_KEYPAIR.pubkey()))
        journal.record_observation(
            "rebuilt",
            1,
            status_commitment="confirmed",
            status_error=None,
            slot=3,
            postcondition_satisfied=True,
            postcondition_digest="rebuilt-state",
        )
        journal.record_terminal(
            StreamTerminal(
                step_id="rebuilt",
                outcome="confirmed",
                signature=signature1,
                commitment="confirmed",
                postcondition_satisfied=True,
                postcondition_digest="rebuilt-state",
            )
        )
        journal.checkpoint(1)
        journal.close()

        reopened = StreamJournal(self.root / "rebuild", identity(), limits)
        observations = reopened.observations
        self.assertEqual(
            [(row.generation, row.signature) for row in observations],
            [(0, signature0), (1, signature1)],
        )
        self.assertEqual(
            reopened._terminal_packet_signatures["rebuilt"],
            {0: signature0, 1: signature1},
        )
        reopened.close()

    async def test_signed_and_unsigned_abandonment_variants_reopen(self):
        limits = StreamLimits(max_pending_steps=2)
        for signature_mode in ("none", "packet"):
            with self.subTest(signature_mode=signature_mode):
                root = self.root / f"abandon-{signature_mode}"
                journal = StreamJournal(root, identity(), limits)
                journal.append_intent(intent("abandoned", route_affinity=None))
                signature, raw = signed_packet("abandoned")
                journal.record_signed_packet("abandoned", signature, raw, str(_KEYPAIR.pubkey()))
                journal.record_observation(
                    "abandoned",
                    0,
                    status_commitment="processed",
                    status_error=None,
                    slot=3,
                    postcondition_satisfied=None,
                    postcondition_digest=None,
                )
                journal.record_step_dropped("abandoned", 0, detail="fork")
                journal.record_reconciliation_required("abandoned", 0, detail="fork")
                decision_sequence = journal.record_reconciliation_decision(
                    "abandoned", 0, decision="abandon", evidence_digest="adapter-evidence"
                )
                terminal_signature = None if signature_mode == "none" else signature
                with self.assertRaisesRegex(StreamError, "does not match one of its signed packets"):
                    journal.record_terminal(
                        StreamTerminal(
                            step_id="abandoned",
                            outcome="abandoned",
                            signature="unrelated-signature",
                            commitment=None,
                            postcondition_satisfied=False,
                            postcondition_digest="adapter-evidence",
                            reconciliation_decision_event_sequence=decision_sequence,
                        )
                    )
                journal.record_terminal(
                    StreamTerminal(
                        step_id="abandoned",
                        outcome="abandoned",
                        signature=terminal_signature,
                        commitment=None,
                        postcondition_satisfied=False,
                        postcondition_digest="adapter-evidence",
                        reconciliation_decision_event_sequence=decision_sequence,
                    )
                )
                journal.checkpoint(1)
                journal.close()

                reopened = StreamJournal(root, identity(), limits)
                self.assertEqual(reopened.terminal_summaries["abandoned"].signature, terminal_signature)
                self.assertEqual(reopened.observations[0].signature, signature)
                reopened.close()

    async def test_orphan_provider_failures_survive_compaction_and_reject_unknowns(self):
        limits = StreamLimits(max_pending_steps=1)
        journal = StreamJournal(self.root / "orphans", identity(), limits)
        signature_a, _ = _complete_journal_step(journal, "A", acknowledge=True)
        _complete_journal_step(journal, "B")
        self.assertNotIn("A", journal.intents)
        journal.record_late_provider_failure(
            "A",
            0,
            1,
            provider_id="tpu",
            endpoint_id="rpc-a",
            route_group="render",
            receipt=SimpleNamespace(
                signature=signature_a,
                provider_id="tpu",
                endpoint_id="rpc-a",
                disposition="helper-pipe-written",
            ),
            disposition="helper-pipe-written",
            detail="late provider error",
        )
        self.assertTrue(journal.provider_failures[-1].data["orphan"])
        _complete_journal_step(journal, "C")
        with self.assertRaisesRegex(StreamError, "already recorded"):
            journal.record_late_provider_failure(
                "A",
                0,
                1,
                provider_id="tpu",
                endpoint_id="rpc-a",
                route_group="render",
                disposition="helper-pipe-written",
                detail="duplicate late provider error",
            )
        with self.assertRaisesRegex(StreamError, "never appended"):
            journal.record_late_provider_failure(
                "never-appended",
                7,
                3,
                provider_id="tpu",
                endpoint_id="rpc-a",
                route_group="render",
                disposition="helper-pipe-written",
                detail="unattributed failure",
            )
        journal.checkpoint(3)
        journal.close()

        reopened = StreamJournal(self.root / "orphans", identity(), limits)
        self.assertEqual(len(reopened.provider_failures), 1)
        self.assertTrue(reopened.provider_failures[0].data["orphan"])
        self.assertEqual(reopened.provider_failures[0].data["signature"], signature_a)
        with self.assertRaisesRegex(StreamError, "already recorded"):
            reopened.record_late_provider_failure(
                "A",
                0,
                1,
                provider_id="tpu",
                endpoint_id="rpc-a",
                route_group="render",
                disposition="helper-pipe-written",
                detail="duplicate after reopen",
            )
        reopened.close()

    def test_orphan_checkpoint_window_is_bounded_and_keeps_the_most_recent_failures(self):
        from dcg.sequencer.stream_journal import MAX_RETAINED_ORPHAN_FAILURES

        limits = StreamLimits(max_pending_steps=1)
        root = self.root / "bounded-orphans"
        journal = StreamJournal(root, identity(), limits)
        try:
            for index in range(MAX_RETAINED_ORPHAN_FAILURES + 2):
                _complete_journal_step(journal, f"orphan-step-{index:03d}", acknowledge=True)
                if index > 0:
                    step_id = f"orphan-step-{index - 1:03d}"
                    journal.record_late_provider_failure(
                        step_id,
                        0,
                        1,
                        provider_id="tpu",
                        endpoint_id="rpc-a",
                        route_group="render",
                        disposition="helper-pipe-written",
                        detail=f"late failure for {step_id}",
                    )

            retained_ids = [event.step_id for event in journal.provider_failures]
            expected_ids = [
                f"orphan-step-{index:03d}"
                for index in range(1, MAX_RETAINED_ORPHAN_FAILURES + 1)
            ]
            self.assertEqual(retained_ids, expected_ids)
            journal.checkpoint(MAX_RETAINED_ORPHAN_FAILURES + 2)
        finally:
            journal.close()

        reopened = StreamJournal(root, identity(), limits)
        self.assertEqual([event.step_id for event in reopened.provider_failures], expected_ids)
        reopened.close()

    def test_k1_reduced_segment_sweep_reopens_rebuild_and_signed_abandonment(self):
        def snapshot(journal: StreamJournal) -> tuple[Any, ...]:
            return (
                journal.pending_intents,
                journal.unresolved_packets(),
                dict(journal.terminals),
                tuple(journal.observations),
                tuple(journal.lifecycle_events),
                journal.sequence_digest,
                journal.next_stream_sequence,
                journal.event_high_water_mark,
                journal.input_closed,
            )

        for pending_limit in (1, 2):
            for segment_bytes in (3500, 5000, 7500):
                with self.subTest(pending_limit=pending_limit, segment_bytes=segment_bytes):
                    limits = StreamLimits(
                        max_pending_steps=pending_limit,
                        max_segment_bytes=segment_bytes,
                        max_journal_bytes=8 * 1024 * 1024,
                        append_reserve_bytes=1024,
                        max_intent_bytes=512,
                        max_attempts_per_generation=1,
                        max_observations_per_generation=2,
                        max_generations_per_step=2,
                    )
                    root = self.root / f"k1-{pending_limit}-{segment_bytes}"
                    journal = StreamJournal(root, identity(), limits)
                    journal.append_intent(intent("A", route_affinity=None))
                    signature0, raw0 = signed_packet("A")
                    journal.record_signed_packet("A", signature0, raw0, str(_KEYPAIR.pubkey()))
                    journal.record_observation(
                        "A",
                        0,
                        status_commitment=None,
                        status_error="BlockhashNotFound",
                        slot=None,
                        postcondition_satisfied=None,
                        postcondition_digest=None,
                    )
                    journal.authorize_rebuild("A", 0, "expired-lease")
                    signature1, raw1 = signed_packet("A-generation-1")
                    journal.record_signed_packet("A", signature1, raw1, str(_KEYPAIR.pubkey()))
                    journal.record_send_attempt(
                        "A", 1, provider_id="tpu", endpoint_id="rpc-a", route_group="render"
                    )
                    journal.record_send_result(
                        "A",
                        1,
                        1,
                        acknowledged=True,
                        disposition="helper-pipe-written",
                    )
                    journal.record_observation(
                        "A",
                        1,
                        status_commitment="confirmed",
                        status_error=None,
                        slot=2,
                        postcondition_satisfied=True,
                        postcondition_digest="stable-A",
                    )
                    journal.record_terminal(
                        StreamTerminal(
                            step_id="A",
                            outcome="confirmed",
                            signature=signature1,
                            commitment="confirmed",
                            postcondition_satisfied=True,
                            postcondition_digest="stable-A",
                        )
                    )

                    journal.append_intent(intent("B", dependencies=("A",), route_affinity=None))
                    signature_b, raw_b = signed_packet("B")
                    journal.record_signed_packet("B", signature_b, raw_b, str(_KEYPAIR.pubkey()))
                    journal.record_send_attempt(
                        "B", 0, provider_id="tpu", endpoint_id="rpc-a", route_group="render"
                    )
                    journal.record_send_result(
                        "B",
                        0,
                        1,
                        acknowledged=True,
                        disposition="helper-pipe-written",
                    )
                    journal.record_observation(
                        "B",
                        0,
                        status_commitment="processed",
                        status_error=None,
                        slot=3,
                        postcondition_satisfied=None,
                        postcondition_digest=None,
                    )
                    journal.record_step_dropped("B", 0, detail="adapter observed dropped branch")
                    journal.record_reconciliation_required("B", 0, detail="adapter checked state")
                    decision_sequence = journal.record_reconciliation_decision(
                        "B", 0, decision="abandon", evidence_digest="packet-cannot-land"
                    )
                    journal.record_terminal(
                        StreamTerminal(
                            step_id="B",
                            outcome="abandoned",
                            signature=signature_b,
                            commitment=None,
                            postcondition_satisfied=False,
                            postcondition_digest="packet-cannot-land",
                            reconciliation_decision_event_sequence=decision_sequence,
                        )
                    )
                    journal.record_late_provider_failure(
                        "A",
                        1,
                        1,
                        provider_id="tpu",
                        endpoint_id="rpc-a",
                        route_group="render",
                        disposition="helper-pipe-written",
                        detail="late failure after terminal summary",
                    )
                    journal.checkpoint(2)
                    expected = snapshot(journal)
                    journal.close()

                    reopened = StreamJournal(root, identity(), limits)
                    self.assertEqual(snapshot(reopened), expected)
                    if "A" in reopened.terminals:
                        self.assertEqual(
                            reopened._terminal_packet_signatures["A"],
                            {0: signature0, 1: signature1},
                        )
                    self.assertEqual(reopened.terminals["B"].signature, signature_b)
                    self.assertTrue(reopened.provider_failures[-1].data["orphan"])
                    reopened.close()

    async def test_provider_disposition_type_matches_before_and_after_reopen(self):
        from dcg.sequencer.pool import EndpointRoute
        from dcg.sequencer.providers import ProviderReceipt, SendDisposition

        stream = await self.open_stream()
        await stream.append(intent("typed-disposition"))
        signature, raw_packet = signed_packet("typed-disposition")
        await stream.record_signed_packet(
            "typed-disposition", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        route = EndpointRoute("rpc-a", "render", "lane-a")
        await stream.record_send_attempt("typed-disposition", 0, provider_id="tpu", route=route)
        receipt = ProviderReceipt(
            signature,
            "tpu",
            "rpc-a",
            SendDisposition.HELPER_PIPE_WRITTEN,
            0.0,
        )
        result = await stream.record_send_result(
            "typed-disposition", 0, 1, acknowledged=True, receipt=receipt, route=route
        )
        self.assertIs(type(result.disposition), str)
        await self.close_stream(stream)
        resumed = await self.open_stream()
        restored = (await resumed.unresolved_packets())[0].attempts[-1]
        self.assertIs(type(restored.disposition), str)
        self.assertEqual(restored.disposition, result.disposition)

    async def test_p2_natural_segment_size_sweep_reopens_with_late_failures_and_dependencies(self):
        rotations = 0
        no_rotations = 0
        for max_segment_bytes in range(4_000, 16_000, 37):
            root = self.root / f"natural-{max_segment_bytes}"
            limits = StreamLimits(
                max_pending_steps=1,
                max_segment_bytes=max_segment_bytes,
                max_journal_bytes=4 * 1024 * 1024,
                append_reserve_bytes=1024,
                max_intent_bytes=512,
                max_attempts_per_generation=1,
                max_observations_per_generation=1,
                max_generations_per_step=1,
            )
            journal = StreamJournal(root, identity(), limits)
            try:
                signature, _ = _complete_journal_step(
                    journal, "A", acknowledge=True
                )
                _complete_journal_step(journal, "B", dependencies=("A",))
                if journal._manifest["active_segment"] > 0:
                    rotations += 1
                else:
                    no_rotations += 1

                before = (
                    journal.event_high_water_mark,
                    journal.sequence_digest,
                    journal.disk_bytes,
                    journal._active_bytes,
                )
                with self.assertRaisesRegex(StreamError, "dependencies"):
                    journal.append_intent(intent("C", dependencies=("A",)))
                self.assertEqual(
                    before,
                    (
                        journal.event_high_water_mark,
                        journal.sequence_digest,
                        journal.disk_bytes,
                        journal._active_bytes,
                    ),
                )
                self.assertFalse(journal._poisoned)

                journal.record_late_provider_failure(
                    "A",
                    0,
                    1,
                    provider_id="tpu",
                    endpoint_id="rpc-a",
                    route_group="render",
                    disposition="helper-pipe-written",
                    detail="late provider error after terminal compaction",
                )
                self.assertTrue(journal.provider_failures[-1].data["orphan"])
                expected_digest = journal.sequence_digest
                journal.close()

                reopened = StreamJournal(root, identity(), limits)
                self.assertEqual(reopened.sequence_digest, expected_digest)
                self.assertEqual(reopened.pending_count, 0)
                self.assertEqual(len(reopened.provider_failures), 1)
                self.assertTrue(reopened.provider_failures[0].data["orphan"])
                self.assertLessEqual(
                    len(list((root / "checkpoints").glob("checkpoint-*.json"))), 1
                )
                self.assertLessEqual(
                    len(list((root / "segments").glob("segment-*.jsonl"))), 1
                )
                reopened.close()
            finally:
                journal.close()
        self.assertGreater(rotations, 0)
        self.assertGreater(no_rotations, 0)

    async def test_p2_brick_dependency_refusal_is_clean_when_rotation_is_due(self):
        limits = StreamLimits(max_pending_steps=1)
        journal = StreamJournal(self.root / "brick", identity(), limits)
        _complete_journal_step(journal, "A")
        journal.append_intent(intent("B", dependencies=("A",)))
        journal.checkpoint(1)
        signature, raw_packet = signed_packet("B")
        journal.record_signed_packet("B", signature, raw_packet, str(_KEYPAIR.pubkey()))
        journal.record_terminal(
            StreamTerminal(
                step_id="B",
                outcome="confirmed",
                signature=signature,
                commitment="confirmed",
                postcondition_satisfied=True,
                postcondition_digest="stable",
            )
        )
        self.assertNotIn("A", journal.intents)
        journal._active_bytes = limits.max_segment_bytes
        before = (journal.event_high_water_mark, journal.disk_bytes, journal.sequence_digest)
        with self.assertRaisesRegex(StreamError, "dependencies"):
            journal.append_intent(intent("C", dependencies=("A",)))
        self.assertEqual(
            before,
            (journal.event_high_water_mark, journal.disk_bytes, journal.sequence_digest),
        )
        self.assertFalse(journal._poisoned)
        journal.close()
        reopened = StreamJournal(self.root / "brick", identity(), limits)
        self.assertEqual(reopened.pending_count, 0)
        self.assertEqual(reopened.terminal_summaries["B"].outcome, "confirmed")
        reopened.close()

    async def test_checkpoint_crash_injections_recover_only_committed_live_state(self):
        limits = StreamLimits(max_pending_steps=4)
        phases = (
            ("before-manifest", "_write_manifest_value", None),
            ("before-unlink", "_unlink_if_present", "segment-00000001.jsonl"),
            ("before-new-segment", "_write_new_file", "segment-00000002.jsonl"),
            ("before-checkpoint-directory-sync", "_fsync_directory", "checkpoints"),
        )
        for phase, target, condition in phases:
            root = self.root / phase
            journal = StreamJournal(root, identity(), limits)
            _complete_journal_step(journal, "A", observe=True)
            journal.checkpoint(1)
            _complete_journal_step(journal, "B", observe=True)
            journal.append_intent(intent("P"))
            signature, raw_packet = signed_packet("P")
            journal.record_signed_packet("P", signature, raw_packet, str(_KEYPAIR.pubkey()))
            journal.record_send_attempt(
                "P", 0, provider_id="tpu", endpoint_id="rpc-a", route_group="render"
            )

            original = getattr(journal, target)

            def inject(*args, _original=original, _condition=condition, **kwargs):
                if _condition is None or _condition in str(args[0]):
                    raise StreamError("injected checkpoint crash")
                return _original(*args, **kwargs)

            with patch.object(journal, target, side_effect=inject):
                with self.assertRaises(StreamError):
                    journal.checkpoint(2)
            journal.close()

            resumed = StreamJournal(root, identity(), limits)
            unresolved = resumed.unresolved_packets()
            self.assertEqual([(packet.step_id, packet.raw_bytes) for packet in unresolved], [("P", raw_packet)])
            self.assertEqual(len(unresolved[0].attempts), 1)
            self.assertEqual({row.step_id for row in resumed.observations}, {"A", "B"})
            self.assertTrue({"A", "B"}.issubset(resumed.terminal_summaries))
            resumed.append_intent(intent("Z"))
            resumed.checkpoint(2)
            resumed.close()

    async def test_failed_partial_append_poisons_process_and_recovers_prior_packet(self):
        stream = await self.open_stream()
        await stream.append(intent("pending"))
        signature, raw_packet = signed_packet("pending")
        await stream.record_signed_packet("pending", signature, raw_packet, str(_KEYPAIR.pubkey()))
        journal = stream._journal
        original_write_all = journal._write_all

        def partial_write(descriptor: int, data: bytes) -> None:
            os.write(descriptor, data[: max(1, len(data) // 2)])
            raise OSError("injected partial write")

        with patch.object(journal, "_write_all", side_effect=partial_write):
            with self.assertRaises(StreamError):
                await stream.record_send_attempt(
                    "pending", 0, provider_id="rpc", endpoint_id="rpc-a", route_group="render"
                )
        with self.assertRaises(StreamError):
            await stream.append(intent("after-failure"))
        await self.close_stream(stream)

        resumed = await self.open_stream()
        packets = await resumed.unresolved_packets()
        self.assertEqual([(packet.step_id, packet.raw_bytes) for packet in packets], [("pending", raw_packet)])
        self.assertTrue(original_write_all)

    async def test_fsync_error_poisons_process_and_recovery_keeps_packet(self):
        stream = await self.open_stream()
        await stream.append(intent("pending"))
        signature, raw_packet = signed_packet("pending")
        await stream.record_signed_packet("pending", signature, raw_packet, str(_KEYPAIR.pubkey()))
        journal = stream._journal

        with patch.object(journal, "_fsync_file", side_effect=OSError("injected fsync error")):
            with self.assertRaises(StreamError):
                await stream.record_send_attempt(
                    "pending", 0, provider_id="rpc", endpoint_id="rpc-a", route_group="render"
                )
        with self.assertRaises(StreamError):
            await stream.append(intent("after-fsync-error"))
        await self.close_stream(stream)

        resumed = await self.open_stream()
        packets = await resumed.unresolved_packets()
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].raw_bytes, raw_packet)

    async def test_rotation_crash_before_manifest_commit_cleans_orphan_files(self):
        stream = await self.open_stream()
        await stream.append(intent("pending"))
        journal = stream._journal
        original_write_manifest = journal._write_manifest_value

        def fail_pointer(manifest):
            raise StreamError("injected crash before manifest pointer")

        with patch.object(journal, "_write_manifest_value", side_effect=fail_pointer):
            with self.assertRaises(StreamError):
                await stream.checkpoint(through_sequence=0)
        with self.assertRaises(StreamError):
            await stream.append(intent("while-poisoned"))
        await self.close_stream(stream)
        self.assertTrue((self.root / "run" / "segments" / "segment-00000001.jsonl").exists())

        resumed = await self.open_stream()
        self.assertFalse((self.root / "run" / "segments" / "segment-00000001.jsonl").exists())
        self.assertEqual(list((self.root / "run" / "checkpoints").glob("checkpoint-*.json")), [])
        self.assertEqual(resumed.pending_count, 1)
        self.assertTrue(original_write_manifest)

    async def test_crash_after_checkpoint_pointer_before_compaction_recovers(self):
        stream = await self.open_stream()
        await stream.append(intent("pending"))
        journal = stream._journal
        original_unlink = journal._unlink_if_present

        def fail_compaction(path: Path) -> None:
            if path.name == "segment-00000000.jsonl":
                raise StreamError("injected crash before compaction")
            return original_unlink(path)

        with patch.object(journal, "_unlink_if_present", side_effect=fail_compaction):
            with self.assertRaises(StreamError):
                await stream.checkpoint(through_sequence=0)
        with self.assertRaises(StreamError):
            await stream.append(intent("while-poisoned"))
        await self.close_stream(stream)
        self.assertTrue((self.root / "run" / "segments" / "segment-00000000.jsonl").exists())

        resumed = await self.open_stream()
        self.assertFalse((self.root / "run" / "segments" / "segment-00000000.jsonl").exists())
        self.assertEqual(resumed.pending_count, 1)
        self.assertEqual(resumed.sequence_digest, (await resumed.append(intent("pending"))).sequence_digest)

    async def test_authorize_rebuild_gates_new_generation(self):
        stream = await self.open_stream()
        await stream.append(intent("rebuild"))
        signature, raw_packet = signed_packet("rebuild")
        first = await stream.record_signed_packet(
            "rebuild", signature, raw_packet, str(_KEYPAIR.pubkey())
        )
        new_signature, new_raw_packet = signed_packet("rebuild-next")
        with self.assertRaises(StreamError):
            await stream.record_signed_packet(
                "rebuild", new_signature, new_raw_packet, str(_KEYPAIR.pubkey())
            )
        await stream.authorize_rebuild("rebuild", 0, "reconciled-state-sha256")
        second = await stream.record_signed_packet(
            "rebuild", new_signature, new_raw_packet, str(_KEYPAIR.pubkey())
        )
        self.assertEqual((first.generation, second.generation), (0, 1))
        await self.close_stream(stream)
        resumed = await self.open_stream()
        self.assertEqual([packet.generation for packet in await resumed.unresolved_packets()], [0, 1])

    async def test_close_input_blocks_new_intents_and_can_wait_for_pending(self):
        stream = await self.open_stream()
        await stream.append(intent("pending"))
        draining = asyncio.create_task(stream.close_input(wait_for_pending=True))
        await asyncio.sleep(0.02)
        self.assertFalse(draining.done())
        with self.assertRaises(StreamClosed):
            await stream.append(intent("too-late"))
        await confirm(stream, "pending")
        await asyncio.wait_for(draining, timeout=1)
        self.assertTrue(stream.input_closed)

    async def test_cancellation_during_append_finishes_durable_operation(self):
        stream = await self.open_stream()
        journal = stream._journal
        original_append = journal._append_file
        started = threading.Event()
        release = threading.Event()

        def delayed_append(path: Path, data: bytes) -> None:
            started.set()
            if not release.wait(5):
                raise TimeoutError("test did not release append")
            original_append(path, data)

        with patch.object(journal, "_append_file", side_effect=delayed_append):
            task = asyncio.create_task(stream.append(intent("cancel-append")))
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
            task.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(stream.pending_count, 1)
        receipt = await stream.append(intent("cancel-append"))
        self.assertTrue(receipt.already_present)

    async def test_cancellation_during_sign_finishes_packet_fsync(self):
        stream = await self.open_stream()
        await stream.append(intent("cancel-sign"))
        signature, raw_packet = signed_packet("cancel-sign")
        journal = stream._journal
        original_append = journal._append_file
        started = threading.Event()
        release = threading.Event()

        def delayed_append(path: Path, data: bytes) -> None:
            if b'"event":"step_signed"' in data:
                started.set()
                if not release.wait(5):
                    raise TimeoutError("test did not release signed packet")
            original_append(path, data)

        with patch.object(journal, "_append_file", side_effect=delayed_append):
            task = asyncio.create_task(
                stream.record_signed_packet(
                    "cancel-sign", signature, raw_packet, str(_KEYPAIR.pubkey())
                )
            )
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
            task.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        unresolved = await stream.unresolved_packets()
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].raw_bytes, raw_packet)

    async def test_concurrent_reads_are_consistent_during_journal_writes(self):
        stream = await self.open_stream(limits=StreamLimits(max_pending_steps=4))
        await stream.append(intent("concurrent"))
        signature, raw_packet = signed_packet("concurrent")
        await stream.record_signed_packet("concurrent", signature, raw_packet, str(_KEYPAIR.pubkey()))

        async def reader() -> None:
            for _ in range(100):
                count = stream.pending_count
                pending = stream.pending_intents
                packets = await stream.unresolved_packets()
                self.assertIn(count, {0, 1})
                self.assertLessEqual(len(pending), 1)
                self.assertLessEqual(len(packets), 1)

        readers = [asyncio.create_task(reader()) for _ in range(4)]
        await stream.record_send_attempt(
            "concurrent", 0, provider_id="rpc", endpoint_id="rpc-a", route_group="render"
        )
        await asyncio.gather(*readers)
        self.assertEqual(stream.pending_count, 1)

    async def test_quota_checks_do_not_rescan_the_directory(self):
        stream = await self.open_stream()
        journal = stream._journal
        with patch.object(Path, "rglob", side_effect=AssertionError("quota path rescanned")):
            await stream.append(intent("incremental-quota"))
        self.assertGreater(journal.disk_bytes, 0)

    def test_bounded_growth_with_128_pending_steps_and_2048_completions(self):
        limits = StreamLimits(
            max_pending_steps=128,
            max_segment_bytes=1 * 1024 * 1024,
            max_journal_bytes=64 * 1024 * 1024,
            append_reserve_bytes=1024,
            max_intent_bytes=512,
            max_attempts_per_generation=1,
            max_observations_per_generation=2,
            max_generations_per_step=1,
        )
        root = self.root / "bounded-growth"
        journal = StreamJournal(root, identity(), limits)
        signature, raw_packet = signed_packet("shared-bounded-growth-packet")
        pending: list[tuple[str, str]] = []
        next_step = 0
        peak_disk_bytes = journal.disk_bytes
        file_counts: list[int] = []
        checkpoint_sizes: list[int] = []
        try:
            for completed in range(1, 2049):
                while len(pending) < limits.max_pending_steps and next_step < 2048:
                    step_id = f"growth-{next_step:07d}"
                    dependencies = (pending[-1][0],) if pending else ()
                    journal.append_intent(
                        intent(step_id, dependencies=dependencies, route_affinity=None)
                    )
                    journal.record_signed_packet(
                        step_id, signature, raw_packet, str(_KEYPAIR.pubkey())
                    )
                    pending.append((step_id, signature))
                    next_step += 1

                step_id, step_signature = pending.pop(0)
                journal.record_terminal(
                    StreamTerminal(
                        step_id=step_id,
                        outcome="confirmed",
                        signature=step_signature,
                        commitment="confirmed",
                        postcondition_satisfied=True,
                        postcondition_digest="stable-growth-state",
                    )
                )
                peak_disk_bytes = max(peak_disk_bytes, journal.disk_bytes)

                if completed % 512 == 0:
                    journal.checkpoint(completed)
                    journal.close()
                    journal = StreamJournal(root, identity(), limits)
                    self.assertEqual(
                        [packet.step_id for packet in journal.unresolved_packets()],
                        [step for step, _ in pending],
                    )
                    file_counts.append(sum(path.is_file() for path in root.rglob("*")))
                    checkpoint_paths = list((root / "checkpoints").glob("checkpoint-*.json"))
                    checkpoint_sizes.append(checkpoint_paths[0].stat().st_size)

            self.assertEqual(next_step, 2048)
            self.assertEqual(journal.pending_count, 0)
            self.assertLess(peak_disk_bytes, 8 * 1024 * 1024)
            self.assertEqual(file_counts, [4, 4, 4, 4])
            self.assertLess(max(checkpoint_sizes), 4 * 1024 * 1024)
        finally:
            journal.close()

    @unittest.skipUnless(
        os.environ.get("DCG_RUN_STREAM_100K") == "1",
        "set DCG_RUN_STREAM_100K=1 to run the opt-in 100k-step persistence test",
    )
    async def test_long_run_100k_steps_keeps_journal_and_reopen_cost_bounded(self):
        context = multiprocessing.get_context("spawn")
        progress = context.Queue()
        process = context.Process(
            target=_long_run_worker,
            args=(str(self.root / "long-run"), progress),
        )
        process.start()
        samples = []
        result = None
        while result is None:
            try:
                message = progress.get(timeout=5)
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            if "progress" in message:
                sample = message["progress"]
                samples.append(sample)
                print(
                    f"100k stream progress: {sample['steps']} steps; "
                    f"disk {sample['disk_bytes']} bytes; "
                    f"manifest {sample['manifest_bytes']} bytes; "
                    f"open {sample['open_seconds']:.4f}s",
                    flush=True,
                )
            else:
                result = message["done"]
        process.join()
        exit_code = process.exitcode
        progress.close()
        process.close()
        self.assertEqual(exit_code, 0)
        self.assertIsNotNone(result)
        self.assertEqual(len(samples), 20)

        max_disk = max(sample["max_disk_bytes"] for sample in samples)
        disk_samples = [sample["disk_bytes"] for sample in samples]
        manifest_samples = [sample["manifest_bytes"] for sample in samples]
        checkpoint_samples = [sample["checkpoint_bytes"] for sample in samples]
        file_samples = [sample["file_count"] for sample in samples]
        open_samples = [sample["open_seconds"] for sample in samples]
        early_open = statistics.median(open_samples[:5])
        late_open = statistics.median(open_samples[-5:])

        self.assertLess(max_disk, 16 * 1024 * 1024)
        self.assertLess(max_disk, 64 * 1024 * 1024)
        self.assertLess(max(disk_samples) - min(disk_samples), 1024 * 1024)
        self.assertEqual(set(file_samples), {4})
        self.assertLess(max(manifest_samples), 16 * 1024)
        self.assertLess(max(manifest_samples) - min(manifest_samples), 1024)
        self.assertLess(max(checkpoint_samples), 2 * 1024 * 1024)
        self.assertLess(max(checkpoint_samples) - min(checkpoint_samples), 64 * 1024)
        self.assertLess(max(open_samples), 2.0)
        self.assertLessEqual(late_open, early_open * 5 + 0.05)
        self.assertLess(result["peak_rss_bytes"], 256 * 1024 * 1024)
        print(
            "100k stream persistence: "
            f"{result['elapsed_seconds']:.1f}s total; disk samples {min(disk_samples)}.."
            f"{max(disk_samples)} bytes (peak accounted {max_disk}); files {set(file_samples)}; "
            f"manifest {min(manifest_samples)}..{max(manifest_samples)} bytes; "
            f"checkpoint {min(checkpoint_samples)}..{max(checkpoint_samples)} bytes; "
            f"reopen median early/late {early_open:.4f}/{late_open:.4f}s, max {max(open_samples):.4f}s; "
            f"peak RSS {result['peak_rss_bytes'] / (1024 * 1024):.1f} MiB"
        )


if __name__ == "__main__":
    unittest.main()
