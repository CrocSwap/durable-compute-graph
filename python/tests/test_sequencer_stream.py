from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.transaction import VersionedTransaction

from dcg.sequencer.stream import (
    StreamError,
    StreamIdentity,
    StreamIntent,
    StreamLimits,
    StreamQuotaExceeded,
    StreamTerminal,
    StreamingPlan,
)


_KEYPAIR = Keypair()


def identity() -> StreamIdentity:
    return StreamIdentity(
        run_id="app-session-17",
        genesis_hash="genesis-test-1",
        program_id="Program1111111111111111111111111111111111",
        destination_accounts=("AccountA", "AccountB"),
        signer_public_keys=(str(_KEYPAIR.pubkey()),),
        route_policy_digest="route-policy-sha256",
        commitment_policy="confirmed",
    )


def intent(step_id: str, *, dependencies: tuple[str, ...] = (), blob_bytes: int = 0) -> StreamIntent:
    return StreamIntent(
        step_id=step_id,
        dependencies=dependencies,
        endpoint_id="rpc-a",
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
    transaction = VersionedTransaction(
        Message.new_with_blockhash([], _KEYPAIR.pubkey(), recent_blockhash),
        [_KEYPAIR],
    )
    return str(transaction.signatures[0]), bytes(transaction)


async def confirm(stream: StreamingPlan, step_id: str, signature: str) -> None:
    actual_signature, raw_packet = signed_packet(step_id)
    assert signature == actual_signature
    await stream.record_signed_packet(step_id, actual_signature, raw_packet, str(_KEYPAIR.pubkey()))
    await stream.record_terminal(
        StreamTerminal(
            step_id=step_id,
            outcome="confirmed",
            signature=signature,
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

    async def open_stream(
        self,
        name: str = "run",
        *,
        limits: StreamLimits | None = None,
        stream_identity: StreamIdentity | None = None,
    ) -> StreamingPlan:
        return await StreamingPlan.open(
            stream_identity or identity(),
            self.root / name,
            limits=limits or StreamLimits(),
        )

    async def test_restart_repairs_partial_tail_and_duplicate_append_is_idempotent(self):
        stream = await self.open_stream()
        original = intent("step-1")
        first = await stream.append(original)
        active_path = self.root / "run" / "segments" / "segment-00000000.jsonl"
        with active_path.open("ab") as journal_file:
            journal_file.write(b'{"schema_version":2,"event_sequence":999,"event":"partial"')

        resumed = await self.open_stream()
        self.assertEqual(resumed.pending_count, 1)
        duplicate = await resumed.append(original)
        self.assertTrue(duplicate.already_present)
        self.assertEqual(duplicate.sequence, first.sequence)
        self.assertEqual(duplicate.sequence_digest, first.sequence_digest)
        self.assertTrue(active_path.read_bytes().endswith(b"\n"))
        self.assertNotIn(b"partial", active_path.read_bytes())

        with self.assertRaises(StreamError):
            await resumed.append(
                StreamIntent(
                    **{
                        **original.__dict__,
                        "intent_digest": "different-intent",
                    }
                )
            )

    async def test_pending_limit_backpressures_until_a_terminal_summary(self):
        stream = await self.open_stream(limits=StreamLimits(max_pending_steps=1))
        first = await stream.append(intent("first"))
        blocked = asyncio.create_task(stream.append(intent("second", dependencies=("first",))))
        await asyncio.sleep(0.02)
        self.assertFalse(blocked.done())
        self.assertEqual(stream.pending_count, 1)

        await confirm(stream, "first", signed_packet("first")[0])
        second = await asyncio.wait_for(blocked, timeout=1)
        self.assertEqual(second.sequence, first.sequence + 1)
        self.assertEqual(stream.pending_count, 1)

    async def test_quota_pressure_refuses_new_intent_and_leaves_stream_resumable(self):
        limits = StreamLimits(max_pending_steps=8, max_segment_bytes=4096, max_journal_bytes=15_000)
        stream = await self.open_stream(limits=limits)
        await stream.append(intent("large-1", blob_bytes=2000))

        with self.assertRaises(StreamQuotaExceeded):
            await stream.append(intent("large-2", blob_bytes=2000))

        resumed = await self.open_stream(limits=limits)
        self.assertEqual([step.step_id for _, step in resumed.pending_intents], ["large-1"])
        self.assertFalse(resumed.input_closed)

    async def test_signed_packet_is_verified_before_it_is_journaled(self):
        stream = await self.open_stream()
        await stream.append(intent("verified"))
        signature, raw_packet = signed_packet("verified")
        tampered_packet = bytearray(raw_packet)
        tampered_packet[1] ^= 1

        with self.assertRaises(StreamError):
            await stream.record_signed_packet(
                "verified", signature, bytes(tampered_packet), str(_KEYPAIR.pubkey())
            )

        accepted = await stream.record_signed_packet("verified", signature, raw_packet, str(_KEYPAIR.pubkey()))
        self.assertEqual(accepted.raw_bytes, raw_packet)

    async def test_unresolved_signed_packet_and_attempt_history_survive_rotation(self):
        limits = StreamLimits(max_pending_steps=16, max_segment_bytes=4096, max_journal_bytes=1_000_000)
        stream = await self.open_stream(limits=limits)
        await stream.append(intent("pending", blob_bytes=1500))
        signature, original_packet = signed_packet("pending")
        packet = await stream.record_signed_packet("pending", signature, original_packet, str(_KEYPAIR.pubkey()))
        self.assertEqual(packet.raw_bytes, original_packet)
        for number in range(1, 15):
            attempt = await stream.record_send_attempt("pending", 0)
            self.assertEqual(attempt.number, number)
            await stream.record_send_result(
                "pending", 0, number, acknowledged=(number == 14), detail=f"transport-{number}"
            )

        resumed = await self.open_stream(limits=limits)
        unresolved = resumed._journal.unresolved_packets()
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].raw_bytes, original_packet)
        self.assertEqual(unresolved[0].signature, signature)
        self.assertEqual(len(unresolved[0].attempts), 14)
        self.assertTrue(all(attempt.finished_event_sequence is not None for attempt in unresolved[0].attempts))

        checkpoint_path = next((self.root / "run" / "checkpoints").glob("checkpoint-*.json"))
        checkpoint = json.loads(checkpoint_path.read_bytes())
        self.assertTrue(checkpoint["unresolved_packet_references"])
        self.assertEqual(checkpoint["unresolved_packet_references"][0]["packet_digest"], packet.packet_digest)

    async def test_identity_and_sequence_digest_are_stable_and_bound(self):
        left = await self.open_stream("left")
        right = await self.open_stream("right", stream_identity=StreamIdentity(
            run_id="app-session-17",
            genesis_hash="genesis-test-1",
            program_id="Program1111111111111111111111111111111111",
            destination_accounts=("AccountA", "AccountB"),
            signer_public_keys=(str(_KEYPAIR.pubkey()),),
            route_policy_digest="route-policy-sha256",
            commitment_policy="confirmed",
        ))
        left_one = await left.append(intent("one"))
        right_one = await right.append(intent("one"))
        left_two = await left.append(intent("two", dependencies=("one",)))
        right_two = await right.append(intent("two", dependencies=("one",)))
        self.assertEqual(left_one.sequence_digest, right_one.sequence_digest)
        self.assertEqual(left_two.sequence_digest, right_two.sequence_digest)

        mismatched = StreamIdentity(
            run_id="another-session",
            genesis_hash="genesis-test-1",
            program_id="Program1111111111111111111111111111111111",
            destination_accounts=("AccountA", "AccountB"),
            signer_public_keys=(str(_KEYPAIR.pubkey()),),
            route_policy_digest="route-policy-sha256",
            commitment_policy="confirmed",
        )
        with self.assertRaises(StreamError):
            await StreamingPlan.open(mismatched, self.root / "left", limits=StreamLimits())

    async def test_checkpoint_summarizes_terminal_work_before_compaction(self):
        stream = await self.open_stream()
        await stream.append(intent("done"))
        signature, _ = signed_packet("done")
        await confirm(stream, "done", signature)
        checkpoint = await stream.checkpoint()

        self.assertEqual(set(checkpoint.confirmed_steps), {"done"})
        self.assertEqual(checkpoint.unresolved_packet_references, ())
        self.assertFalse((self.root / "run" / "segments" / "segment-00000000.jsonl").exists())
        resumed = await self.open_stream()
        self.assertEqual(resumed.pending_count, 0)
        self.assertEqual(resumed.sequence_digest, checkpoint.sequence_digest)


if __name__ == "__main__":
    unittest.main()
