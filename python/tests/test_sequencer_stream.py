from __future__ import annotations

import asyncio
import hashlib
import json
import os
import statistics
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
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
) -> StreamIdentity:
    return StreamIdentity(
        run_id="app-session-17",
        genesis_hash=genesis_hash,
        program_id=str(_PROGRAM),
        destination_accounts=(str(_DESTINATION),),
        signer_public_keys=signer_public_keys or (str(_KEYPAIR.pubkey()),),
        route_policy_digest="route-policy-sha256",
        commitment_policy="confirmed",
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
        self.assertTrue(checkpoints[-1]["unresolved_packet_references"])
        self.assertEqual(
            checkpoints[-1]["unresolved_packet_references"][0]["packet_digest"],
            first.packet_digest,
        )
        sealed_events = {row["event"] for checkpoint in checkpoints for row in checkpoint["journal_events"]}
        self.assertTrue(
            {
                "step_appended",
                "step_signed",
                "send_attempt_started",
                "send_attempt_finished",
                "step_observed",
            }.issubset(sealed_events)
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

    async def test_long_run_20k_steps_keeps_manifest_event_and_disk_cost_bounded(self):
        limits = StreamLimits(
            max_pending_steps=1,
            max_segment_bytes=131_072,
            max_journal_bytes=64 * 1024 * 1024,
            append_reserve_bytes=1024,
            max_intent_bytes=512,
            max_attempts_per_generation=1,
            max_observations_per_generation=1,
            max_generations_per_step=1,
        )
        journal = StreamJournal(self.root / "long-run", identity(), limits)
        self.addCleanup(journal.close)
        signature, raw_packet = signed_packet("shared-long-run-packet")
        append_durations: list[int] = []
        max_manifest = journal.manifest_bytes
        max_disk = journal.disk_bytes
        started = time.perf_counter()
        checkpoints = 0

        for index in range(20_000):
            step_id = f"step-{index:05d}"
            start = time.perf_counter_ns()
            journal.append_intent(intent(step_id, route_affinity=None))
            append_durations.append(time.perf_counter_ns() - start)
            journal.record_signed_packet(step_id, signature, raw_packet, str(_KEYPAIR.pubkey()))
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
            max_manifest = max(max_manifest, journal.manifest_bytes)
            max_disk = max(max_disk, journal.disk_bytes)
            if (index + 1) % 1000 == 0:
                journal.checkpoint(index + 1)
                checkpoints += 1
                max_manifest = max(max_manifest, journal.manifest_bytes)
                max_disk = max(max_disk, journal.disk_bytes)
            if (index + 1) % 5000 == 0:
                print(
                    f"20k stream persistence progress: {index + 1} steps, "
                    f"manifest {journal.manifest_bytes} bytes, disk {journal.disk_bytes} bytes",
                    flush=True,
                )

        elapsed = time.perf_counter() - started
        average_append_ms = statistics.mean(append_durations) / 1_000_000
        disk_bytes_per_step = max_disk / 20_000
        early_median_ms = statistics.median(append_durations[:1000]) / 1_000_000
        late_median_ms = statistics.median(append_durations[-1000:]) / 1_000_000
        self.assertEqual(checkpoints, 20)
        self.assertEqual(journal.pending_count, 0)
        self.assertLess(max_manifest, 64 * 1024)
        self.assertLess(max_disk, limits.max_journal_bytes)
        self.assertLess(disk_bytes_per_step, 4096)
        self.assertLessEqual(late_median_ms, max(early_median_ms * 10, 250.0))
        self.assertLess(average_append_ms, 250.0)
        print(
            "20k stream persistence: "
            f"{elapsed:.2f}s total; append mean {average_append_ms:.3f}ms, "
            f"early/late median {early_median_ms:.3f}/{late_median_ms:.3f}ms; "
            f"manifest max {max_manifest} bytes; disk max {max_disk} bytes "
            f"({disk_bytes_per_step:.1f} bytes/step); checkpoints {checkpoints}"
        )


if __name__ == "__main__":
    unittest.main()
