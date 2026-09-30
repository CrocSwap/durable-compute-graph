from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from dcg.sequencer import (
    AmbiguousFate,
    Backoff,
    BlockhashExpired,
    BlockhashLease,
    Commitment,
    EndpointLimits,
    JournalError,
    JournalStore,
    PacketTooLarge,
    PlanError,
    PostconditionResult,
    ProgramRefused,
    RateLimited,
    RetryPolicy,
    RpcUnavailable,
    Sequencer,
    SequencerConfig,
    SendReceipt,
    SignatureObservation,
    SignedTransaction,
    StepTimeCapExceeded,
    TransactionPlan,
    TransactionStep,
)


class SimulatedCrash(Exception):
    pass


class FakeSigner:
    def __init__(self, secret: bytes = b"SECRET_KEY_MUST_NOT_ENTER_THE_JOURNAL"):
        self.secret = secret
        self._public_key = "SignerPublicKey111111111111111111111111111111"
        self.sign_calls = 0

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def signature_count(self) -> int:
        return 1

    @property
    def signature_size_bytes(self) -> int:
        return 64

    async def sign(self, message: bytes, lease: BlockhashLease) -> SignedTransaction:
        self.sign_calls += 1
        signature = hashlib.sha256(self.secret + message + lease.blockhash.encode()).hexdigest()[:48]
        raw = b"\x01" + signature.encode().ljust(64, b"\0") + message
        return SignedTransaction(signature, raw)


class FakeRpc:
    endpoint_id = "rpc-a"

    def __init__(self):
        self.behaviors: list[str] = []
        self.status_behaviors: list[str] = []
        self.statuses: dict[str, SignatureObservation] = {}
        self.packets_by_signature: dict[str, bytes] = {}
        self.send_packets: list[bytes] = []
        self.send_started_times: list[float] = []
        self.effects: set[str] = set()
        self.effect_count = 0
        self.duplicate_count = 0
        self.hide_status = False
        self.metadata_available = True
        self.program_refusal: str | None = None
        self.hang_on_blockhash = False
        self.send_delay = 0.0
        self.active_sends = 0
        self.max_active_sends = 0
        self.blockhash_count = 0
        self.status_calls = 0

    async def latest_blockhash(self, genesis_hash: str, lifetime_seconds: float) -> BlockhashLease:
        if self.hang_on_blockhash:
            await asyncio.Event().wait()
        self.blockhash_count += 1
        return BlockhashLease(
            blockhash=f"blockhash-{self.blockhash_count}",
            genesis_hash=genesis_hash,
            fetched_at_unix=time.time(),
            last_valid_block_height=1000 + self.blockhash_count,
            context_slot=10 + self.blockhash_count,
            lifetime_seconds=lifetime_seconds,
        )

    async def send_raw_transaction(self, raw_bytes: bytes):
        self.active_sends += 1
        self.max_active_sends = max(self.max_active_sends, self.active_sends)
        self.send_started_times.append(time.monotonic())
        try:
            if self.send_delay:
                await asyncio.sleep(self.send_delay)
            self.send_packets.append(raw_bytes)
            behavior = self.behaviors.pop(0) if self.behaviors else "success"
            if behavior == "rate-limit":
                raise RateLimited(retry_after=0)
            if behavior == "drop":
                raise RpcUnavailable("injected response drop before acceptance")
            if behavior == "blockhash-expired":
                raise BlockhashExpired("injected expired blockhash")

            signature = raw_bytes[1:65].rstrip(b"\0").decode()
            already_seen = signature in self.packets_by_signature
            if already_seen:
                self.duplicate_count += 1
            else:
                self.packets_by_signature[signature] = raw_bytes
                if self.program_refusal is None:
                    self.effects.add(raw_bytes[65:].decode())
                    self.effect_count += 1
                self.statuses[signature] = SignatureObservation(
                    signature=signature,
                    commitment=Commitment.FINALIZED if self.program_refusal else Commitment.CONFIRMED,
                    error=self.program_refusal,
                    slot=99,
                    transaction_metadata_available=self.metadata_available,
                    fee_lamports=5000 if self.metadata_available else None,
                    compute_units_consumed=22_000 if self.metadata_available else None,
                )
            if behavior == "drop-response":
                raise RpcUnavailable("injected lost response after acceptance")
            if behavior == "duplicate":
                # A duplicate transport handoff carries the identical packet
                # and signature. The fake cluster applies it only once.
                self.duplicate_count += 1
            return SendReceipt(signature)
        finally:
            self.active_sends -= 1

    async def signature_status(self, signature: str):
        self.status_calls += 1
        behavior = self.status_behaviors.pop(0) if self.status_behaviors else "normal"
        if behavior == "outage":
            raise RpcUnavailable("injected status outage")
        if behavior == "null":
            return None
        if self.hide_status:
            return None
        return self.statuses.get(signature)


async def postcondition(endpoint: FakeRpc, expected_step: str = "write-0") -> PostconditionResult:
    if any(message.startswith(f"message-{expected_step}-") for message in endpoint.effects):
        return PostconditionResult(True, f"state-digest-after-{expected_step}")
    return PostconditionResult(False, "state-digest-before-effect")


def step(
    step_id: str = "write-0",
    *,
    dependencies: tuple[str, ...] = (),
    write_locks: tuple[str, ...] = (),
    retry_policy: RetryPolicy = RetryPolicy.SAME_BYTES,
    authorize_rebuild=None,
    build_message=None,
    postcondition_callback=None,
    intent_digest: str | None = None,
) -> TransactionStep:
    if postcondition_callback is None:
        async def postcondition_for_step(endpoint):
            return await postcondition(endpoint, step_id)

        postcondition_callback = postcondition_for_step
    return TransactionStep(
        step_id=step_id,
        dependencies=dependencies,
        endpoint_id="rpc-a",
        compute_class="range-write",
        compute_unit_limit=180_000,
        intent_digest=intent_digest or f"intent-{step_id}",
        recovery_policy_digest=f"recovery-{step_id}",
        build_message=build_message or (lambda lease: f"message-{step_id}-{lease.blockhash}".encode()),
        postcondition=postcondition_callback,
        write_locks=write_locks,
        retry_policy=retry_policy,
        authorize_rebuild=authorize_rebuild,
    )


def plan(*steps: TransactionStep) -> TransactionPlan:
    return TransactionPlan(
        genesis_hash="genesis-testnet-1",
        program_id="Program1111111111111111111111111111111111",
        destination_accounts=("Destination111111111111111111111111111111",),
        signer_public_key=FakeSigner().public_key,
        steps=tuple(steps),
    )


def config(
    *,
    max_in_flight: int = 8,
    batch_size: int = 16,
    time_cap: float = 1.0,
) -> SequencerConfig:
    return SequencerConfig(
        endpoint_limits={"rpc-a": EndpointLimits(sends_per_second=100_000, max_in_flight=max_in_flight)},
        max_batch_size=batch_size,
        per_step_time_cap_seconds=time_cap,
        confirmation_poll_seconds=0,
        backoff=Backoff(initial_seconds=0, maximum_seconds=0, multiplier=2),
    )


class CrashOnce:
    def __init__(self, event: str, should_crash=lambda: True):
        self.event = event
        self.should_crash = should_crash
        self.did_crash = False

    async def __call__(self, event: str, step_id: str | None) -> None:
        if not self.did_crash and event == self.event and self.should_crash():
            self.did_crash = True
            raise SimulatedCrash(event)


class SequencerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcg-sequencer-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def journal(self, name: str = "run.jsonl") -> JournalStore:
        return JournalStore(self.directory / name)

    def sequencer(self, rpc: FakeRpc, signer: FakeSigner | None = None, *, cfg=None, hook=None) -> Sequencer:
        return Sequencer(
            endpoints={"rpc-a": rpc},
            signer=signer or FakeSigner(),
            config=cfg or config(),
            event_hook=hook,
        )

    async def test_plan_dag_batches_independent_steps_and_gates_dependencies(self):
        rpc = FakeRpc()
        run = await self.sequencer(rpc).submit(plan(step("a"), step("b"), step("c", dependencies=("a", "b"))), self.journal())
        self.assertEqual(set(run.outcomes), {"a", "b", "c"})
        self.assertEqual(len(rpc.packets_by_signature), 3)
        names = [event.name for event in self.journal().events()]
        signed = [event.data["step_id"] for event in self.journal().events() if event.name == "step_signed"]
        self.assertLess(max(signed.index("a"), signed.index("b")), signed.index("c"))
        self.assertIn("run_started", names)

    async def test_shared_write_lock_serializes_independent_ready_steps(self):
        rpc = FakeRpc()
        rpc.send_delay = 0.01
        await self.sequencer(rpc, cfg=config(max_in_flight=8)).submit(
            plan(step("a", write_locks=("same-account",)), step("b", write_locks=("same-account",))), self.journal()
        )
        self.assertEqual(rpc.max_active_sends, 1)

    async def test_endpoint_in_flight_cap_bounds_independent_batch(self):
        rpc = FakeRpc()
        rpc.send_delay = 0.01
        await self.sequencer(rpc, cfg=config(max_in_flight=2)).submit(
            plan(*(step(f"step-{index}") for index in range(6))), self.journal()
        )
        self.assertEqual(rpc.max_active_sends, 2)

    async def test_endpoint_send_rate_spaces_packets(self):
        rpc = FakeRpc()
        limited = SequencerConfig(
            endpoint_limits={"rpc-a": EndpointLimits(sends_per_second=10, max_in_flight=8)},
            max_batch_size=4,
            per_step_time_cap_seconds=2,
            confirmation_poll_seconds=0,
            backoff=Backoff(initial_seconds=0, maximum_seconds=0, multiplier=2),
        )
        await self.sequencer(rpc, cfg=limited).submit(plan(step("a"), step("b"), step("c")), self.journal())
        deltas = [right - left for left, right in zip(rpc.send_started_times, rpc.send_started_times[1:])]
        self.assertEqual(len(deltas), 2)
        self.assertTrue(all(delta >= 0.08 for delta in deltas), deltas)

    async def test_signed_packet_is_fsynced_before_provider_handoff(self):
        class JournalAwareRpc(FakeRpc):
            journal: JournalStore

            async def send_raw_transaction(self, raw_bytes: bytes):
                events = self.journal.events()
                signed = [event for event in events if event.name == "step_signed"][-1]
                attempt = [event for event in events if event.name == "send_attempt_started"][-1]
                self_outer.assertLess(signed.sequence, attempt.sequence)
                self_outer.assertEqual(base64.b64decode(signed.data["raw_transaction"]), raw_bytes)
                return await super().send_raw_transaction(raw_bytes)

        self_outer = self
        rpc = JournalAwareRpc()
        journal = self.journal()
        rpc.journal = journal
        await self.sequencer(rpc).submit(plan(step()), journal)

    async def test_invalid_cycle_fails_before_journal_or_signing(self):
        rpc = FakeRpc()
        signer = FakeSigner()
        journal = self.journal()
        sequencer = self.sequencer(rpc, signer)
        with self.assertRaises(PlanError):
            await sequencer.submit(plan(step("a", dependencies=("b",)), step("b", dependencies=("a",))), journal)
        self.assertEqual(signer.sign_calls, 0)
        self.assertEqual(journal.events(), [])

    async def test_packet_size_is_checked_before_signing(self):
        rpc = FakeRpc()
        signer = FakeSigner()
        journal = self.journal()
        oversized = step("too-large", build_message=lambda lease: b"x" * 1168)
        with self.assertRaises(PacketTooLarge):
            await self.sequencer(rpc, signer).submit(plan(oversized), journal)
        self.assertEqual(signer.sign_calls, 0)
        self.assertEqual(rpc.send_packets, [])

    async def test_429_outage_and_drop_retry_the_same_signed_bytes(self):
        rpc = FakeRpc()
        rpc.behaviors = ["rate-limit", "drop", "success"]
        journal = self.journal()
        result = await self.sequencer(rpc).submit(plan(step()), journal)
        self.assertEqual(len(result.outcomes), 1)
        self.assertEqual(len(rpc.send_packets), 3)
        self.assertTrue(all(packet == rpc.send_packets[0] for packet in rpc.send_packets))
        self.assertEqual(rpc.effect_count, 1)
        self.assertEqual(sum(event.name == "send_error" for event in journal.events()), 2)

    async def test_duplicate_handoff_has_one_application_effect(self):
        rpc = FakeRpc()
        rpc.behaviors = ["duplicate"]
        await self.sequencer(rpc).submit(plan(step()), self.journal())
        self.assertEqual(rpc.duplicate_count, 1)
        self.assertEqual(rpc.effect_count, 1)

    async def test_lost_send_response_recovers_original_signature(self):
        rpc = FakeRpc()
        rpc.behaviors = ["drop-response"]
        result = await self.sequencer(rpc).submit(plan(step()), self.journal())
        self.assertEqual(len(rpc.send_packets), 1)
        self.assertEqual(rpc.effect_count, 1)
        self.assertEqual(result.outcomes["write-0"].confirmed_by, "signature")

    async def test_blockhash_expiry_requires_adapter_approval_before_new_signature(self):
        rpc = FakeRpc()
        rpc.behaviors = ["blockhash-expired", "success"]
        approvals = []

        async def authorize(evidence):
            approvals.append(evidence)
            return evidence.lease_expired and evidence.postcondition.satisfied is False

        target = step(
            retry_policy=RetryPolicy.RECONCILE,
            authorize_rebuild=authorize,
        )
        journal = self.journal()
        result = await self.sequencer(rpc).submit(plan(target), journal)
        signatures = [event.data["signature"] for event in journal.events() if event.name == "step_signed"]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(len(signatures), 2)
        self.assertNotEqual(signatures[0], signatures[1])
        self.assertEqual(result.outcomes["write-0"].signature, signatures[1])

    async def test_blockhash_expiry_without_authorizer_stops_as_ambiguous(self):
        rpc = FakeRpc()
        rpc.behaviors = ["blockhash-expired"]
        journal = self.journal()
        with self.assertRaises(AmbiguousFate):
            await self.sequencer(rpc).submit(plan(step()), journal)
        self.assertEqual(sum(event.name == "step_signed" for event in journal.events()), 1)
        self.assertEqual(sum(event.name == "step_ambiguous" for event in journal.events()), 1)

    async def test_missing_status_uses_postcondition_as_confirmation(self):
        rpc = FakeRpc()
        rpc.hide_status = True
        result = await self.sequencer(rpc).submit(plan(step()), self.journal())
        outcome = result.outcomes["write-0"]
        self.assertEqual(outcome.confirmed_by, "account-state")
        self.assertIsNone(outcome.fee_lamports)
        self.assertIsNone(outcome.compute_units_consumed)

    async def test_signature_confirmation_preserves_missing_metadata_as_null(self):
        rpc = FakeRpc()
        rpc.metadata_available = False
        result = await self.sequencer(rpc).submit(plan(step()), self.journal())
        outcome = result.outcomes["write-0"]
        self.assertEqual(outcome.confirmed_by, "signature")
        self.assertIsNone(outcome.fee_lamports)
        self.assertIsNone(outcome.compute_units_consumed)

    async def test_finalized_program_refusal_is_terminal_and_gates_dependents(self):
        rpc = FakeRpc()
        rpc.program_refusal = "Custom(42)"
        journal = self.journal()
        with self.assertRaises(ProgramRefused):
            await self.sequencer(rpc).submit(plan(step("first"), step("dependent", dependencies=("first",))), journal)
        self.assertEqual(sum(event.name == "step_signed" for event in journal.events()), 1)
        self.assertEqual(sum(event.name == "step_terminal_failure" for event in journal.events()), 1)

    async def test_resume_rejects_plan_drift_before_any_send(self):
        rpc = FakeRpc()
        journal = self.journal()
        original = plan(step())
        await self.sequencer(rpc).submit(original, journal)
        changed = plan(step(intent_digest="different-intent"))
        with self.assertRaises(JournalError):
            await self.sequencer(rpc).resume(changed, journal)
        self.assertEqual(len(rpc.send_packets), 1)

    async def test_journal_never_contains_signer_private_material(self):
        rpc = FakeRpc()
        signer = FakeSigner()
        journal = self.journal()
        await self.sequencer(rpc, signer).submit(plan(step()), journal)
        raw = journal.path.read_bytes()
        self.assertNotIn(signer.secret, raw)
        self.assertNotIn(signer.secret.decode(), raw.decode())
        self.assertIn(signer.public_key.encode(), raw)

    async def test_torn_final_journal_row_is_discarded(self):
        rpc = FakeRpc()
        journal = self.journal()
        await self.sequencer(rpc).submit(plan(step()), journal)
        complete_count = len(journal.events())
        with journal.path.open("ab") as stream:
            stream.write(b'{"schema_version":1,"sequence":999')
        self.assertEqual(len(journal.events()), complete_count)
        self.assertTrue(journal.path.read_bytes().endswith(b"\n"))

    async def test_resume_after_crash_at_each_normal_journal_state(self):
        cases = [
            ("run_started", None),
            ("step_signed", None),
            ("postcondition_observed", None),
            ("send_attempt_started", None),
            ("send_acknowledged", None),
            ("status_observed", None),
            ("step_confirmed", None),
            ("send_error", "rate-limit"),
        ]
        for index, (event, behavior) in enumerate(cases):
            with self.subTest(event=event):
                rpc = FakeRpc()
                if behavior:
                    rpc.behaviors = [behavior, "success"]
                hook = CrashOnce(event)
                journal = self.journal(f"crash-{index}.jsonl")
                with self.assertRaises(SimulatedCrash):
                    await self.sequencer(rpc, hook=hook).submit(plan(step()), journal)
                resumed = await self.sequencer(rpc).resume(plan(step()), journal)
                self.assertEqual(set(resumed.outcomes), {"write-0"})
                self.assertEqual(sum(item.name == "step_confirmed" for item in journal.events()), 1)

    async def test_resume_after_post_send_account_readback_crash(self):
        rpc = FakeRpc()
        rpc.hide_status = True
        hook = CrashOnce("postcondition_observed", should_crash=lambda: bool(rpc.send_packets))
        journal = self.journal()
        with self.assertRaises(SimulatedCrash):
            await self.sequencer(rpc, hook=hook).submit(plan(step()), journal)
        result = await self.sequencer(rpc).resume(plan(step()), journal)
        self.assertEqual(result.outcomes["write-0"].confirmed_by, "account-state")

    async def test_resume_after_rebuild_authorization_crash(self):
        rpc = FakeRpc()
        rpc.behaviors = ["blockhash-expired", "success"]

        async def authorize(evidence):
            return evidence.postcondition.satisfied is False

        target = step(retry_policy=RetryPolicy.RECONCILE, authorize_rebuild=authorize)
        journal = self.journal()
        hook = CrashOnce("step_rebuild_authorized")
        with self.assertRaises(SimulatedCrash):
            await self.sequencer(rpc, hook=hook).submit(plan(target), journal)
        result = await self.sequencer(rpc).resume(plan(target), journal)
        self.assertEqual(len(result.outcomes), 1)
        self.assertEqual(sum(item.name == "step_signed" for item in journal.events()), 2)

    async def test_resume_keeps_finalized_refusal_terminal(self):
        rpc = FakeRpc()
        rpc.program_refusal = "Custom(9)"
        journal = self.journal()
        hook = CrashOnce("step_terminal_failure")
        with self.assertRaises(SimulatedCrash):
            await self.sequencer(rpc, hook=hook).submit(plan(step()), journal)
        with self.assertRaises(ProgramRefused):
            await self.sequencer(rpc).resume(plan(step()), journal)
        self.assertEqual(len(rpc.send_packets), 1)

    async def test_resume_preserves_ambiguous_fate(self):
        rpc = FakeRpc()
        rpc.behaviors = ["blockhash-expired"]
        journal = self.journal()
        hook = CrashOnce("step_ambiguous")
        with self.assertRaises(SimulatedCrash):
            await self.sequencer(rpc, hook=hook).submit(plan(step()), journal)
        with self.assertRaises(AmbiguousFate):
            await self.sequencer(rpc).resume(plan(step()), journal)
        self.assertEqual(sum(item.name == "step_signed" for item in journal.events()), 1)

    async def test_per_step_time_cap_is_journaled_and_resumable(self):
        rpc = FakeRpc()
        rpc.hang_on_blockhash = True
        journal = self.journal()
        hook = CrashOnce("step_time_cap")
        with self.assertRaises(SimulatedCrash):
            await self.sequencer(rpc, cfg=config(time_cap=0.01), hook=hook).submit(plan(step()), journal)
        self.assertEqual(sum(item.name == "step_time_cap" for item in journal.events()), 1)
        rpc.hang_on_blockhash = False
        result = await self.sequencer(rpc).resume(plan(step()), journal)
        self.assertEqual(len(result.outcomes), 1)

    async def test_per_step_time_cap_raises_resumable_failure(self):
        rpc = FakeRpc()
        rpc.hang_on_blockhash = True
        journal = self.journal()
        with self.assertRaises(StepTimeCapExceeded):
            await self.sequencer(rpc, cfg=config(time_cap=0.01)).submit(plan(step()), journal)
        self.assertEqual(sum(item.name == "step_time_cap" for item in journal.events()), 1)


if __name__ == "__main__":
    unittest.main()
