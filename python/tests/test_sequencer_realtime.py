from __future__ import annotations

import asyncio
import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from dcg.sequencer import (
    AmbiguousFate,
    Backoff,
    BlockhashLease,
    Commitment,
    EndpointLimits,
    JournalStore,
    KeypairFileSigner,
    LatencyMode,
    MultiSigner,
    PostconditionResult,
    JournalError,
    ReconciliationRequired,
    RetryPolicy,
    RpcUnavailable,
    RunResult,
    SendReceipt,
    Sequencer,
    SequencerConfig,
    SignatureObservation,
    StreamIdentity,
    StreamIntent,
    StreamLimits,
    StreamTerminal,
    StepTimeCapExceeded,
    TransactionPlan,
    TransactionStep,
)
from dcg.sequencer.pool import EndpointNodeConfig, EndpointPool, EndpointPoolExhausted, RequestKind
from dcg.sequencer.providers import TpuQuicConfig, TpuQuicSendProvider

from test_sequencer_providers import MemoryHelper


GENESIS = "local-cluster-genesis"
PROGRAM = Pubkey.new_unique()
DESTINATION = Pubkey.new_unique()


def _status(signature: str, commitment: Commitment) -> SignatureObservation:
    return SignatureObservation(signature, commitment, slot=12)


class FakeRpc:
    endpoint_id = "rpc-a"

    def __init__(self):
        self.blockhash_count = 0
        self.send_packets: list[bytes] = []
        self.packets_by_signature: dict[str, bytes] = {}
        self.status_resolver = None
        self.status_calls: dict[str, int] = {}
        self.batch_calls = 0
        self.batch_sizes: list[int] = []
        self.send_started_times: list[float] = []
        self.active_sends = 0
        self.max_active_sends = 0
        self.send_delay = 0.0
        self.send_error: BaseException | None = None
        self.reconciliations: list[tuple[str, bool | None]] = []

    async def get_genesis_hash(self) -> str:
        return GENESIS

    async def latest_blockhash(self, genesis_hash: str, lifetime_seconds: float) -> BlockhashLease:
        self.blockhash_count += 1
        return BlockhashLease(
            blockhash=str(Hash.new_unique()),
            genesis_hash=genesis_hash,
            fetched_at_unix=time.time(),
            last_valid_block_height=1000 + self.blockhash_count,
            context_slot=self.blockhash_count,
            lifetime_seconds=lifetime_seconds,
        )

    async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt:
        self.active_sends += 1
        self.max_active_sends = max(self.max_active_sends, self.active_sends)
        self.send_started_times.append(time.monotonic())
        try:
            if self.send_delay:
                await asyncio.sleep(self.send_delay)
            self.send_packets.append(raw_bytes)
            if self.send_error is not None:
                error, self.send_error = self.send_error, None
                raise error
            signature = str(Signature.from_bytes(raw_bytes[1:65]))
            self.packets_by_signature.setdefault(signature, raw_bytes)
            return SendReceipt(signature)
        finally:
            self.active_sends -= 1

    async def signature_status(self, signature: str):
        return (await self.signature_statuses([signature]))[signature]

    async def signature_statuses(self, signatures):
        self.batch_calls += 1
        self.batch_sizes.append(len(signatures))
        result = {}
        for signature in signatures:
            self.status_calls[signature] = self.status_calls.get(signature, 0) + 1
            packet = self.packets_by_signature.get(signature)
            if packet is None:
                result[signature] = None
            elif self.status_resolver is not None:
                result[signature] = self.status_resolver(
                    signature, packet, self.status_calls[signature]
                )
            else:
                result[signature] = _status(signature, Commitment.CONFIRMED)
        return result

    async def get_multiple_accounts(self, addresses, commitment):
        del addresses, commitment
        return ()

    async def get_program_accounts(self, program_id, *, filters, commitment):
        del program_id, filters, commitment
        return ()


def _config(
    *,
    latency_mode=LatencyMode.CONFIRMED,
    max_in_flight=8,
    pool_timeout=2.0,
    per_step_time_cap_seconds=3.0,
    **values,
):
    return SequencerConfig(
        endpoint_limits={
            "rpc-a": EndpointLimits(
                sends_per_second=10_000,
                requests_per_second=100_000,
                max_in_flight=max_in_flight,
                route_group="rpc-a",
            )
        },
        max_batch_size=32,
        per_step_time_cap_seconds=per_step_time_cap_seconds,
        confirmation_poll_seconds=0.001,
        status_batch_window_seconds=0.01,
        backoff=Backoff(initial_seconds=0.001, maximum_seconds=0.01, multiplier=2),
        health_cooldown_seconds=0.001,
        health_max_cooldown_seconds=0.01,
        pool_acquire_timeout_seconds=pool_timeout,
        latency_mode=latency_mode,
        **values,
    )


def _intent(step_id: str, *, dependencies=(), write_locks=(), route_affinity="lane-a") -> StreamIntent:
    return StreamIntent(
        step_id=step_id,
        dependencies=tuple(dependencies),
        route_group="rpc-a",
        route_affinity=route_affinity,
        compute_class="test-write",
        compute_unit_limit=120_000,
        intent_digest=f"intent:{step_id}",
        recovery_policy_digest=f"recovery:{step_id}",
        intent_data={"tag": step_id},
        max_packet_bytes=1232,
        write_locks=tuple(write_locks),
    )


def _step_factory(rpc: FakeRpc, signer: KeypairFileSigner, *, reconcile=True):
    async def postcondition(endpoint, tag):
        marker = f"dcg-step:{tag}".encode()
        satisfied = any(marker in packet for packet in endpoint.send_packets)
        return PostconditionResult(satisfied, hashlib.sha256(marker).hexdigest())

    async def reconcile(endpoint, signature, postcondition):
        del endpoint
        rpc.reconciliations.append((signature, postcondition.satisfied))

    def build(intent: StreamIntent) -> TransactionStep:
        tag = intent.intent_data["tag"]

        def message(lease):
            instruction = Instruction(
                PROGRAM,
                f"dcg-step:{tag}".encode(),
                [AccountMeta(DESTINATION, False, True)],
            )
            return bytes(Message.new_with_blockhash([instruction], _public_key(signer), Hash.from_string(lease.blockhash)))

        async def check(endpoint):
            return await postcondition(endpoint, tag)

        return TransactionStep(
            step_id=intent.step_id,
            dependencies=intent.dependencies,
            endpoint_id="rpc-a",
            route_group=intent.route_group,
            route_affinity=intent.route_affinity,
            compute_class=intent.compute_class,
            compute_unit_limit=intent.compute_unit_limit,
            intent_digest=intent.intent_digest,
            recovery_policy_digest=intent.recovery_policy_digest,
            build_message=message,
            postcondition=check,
            max_packet_bytes=intent.max_packet_bytes,
            write_locks=intent.write_locks,
            retry_policy=RetryPolicy.NEVER,
            reconcile_dropped=reconcile if reconcile else None,
        )

    return build


def _public_key(signer: KeypairFileSigner) -> Pubkey:
    return Pubkey.from_string(signer.public_key)


class RealtimeSequencerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dcg-realtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keypair = Keypair()
        self.signer = KeypairFileSigner(self.keypair)
        self.rpc = FakeRpc()
        self.sequencer = Sequencer(
            endpoints={"rpc-a": self.rpc},
            signer=self.signer,
            config=_config(),
        )
        self.streams = []

    async def asyncTearDown(self):
        for stream in reversed(self.streams):
            await stream.close()

    async def open_stream(self, *, latency_mode=LatencyMode.CONFIRMED, config=None, name="run"):
        if config is None:
            config = _config(latency_mode=latency_mode)
        sequencer = Sequencer(
            endpoints={"rpc-a": self.rpc},
            signer=self.signer,
            config=config,
        )
        identity = StreamIdentity(
            run_id=f"run-{name}",
            genesis_hash=GENESIS,
            program_id=str(PROGRAM),
            destination_accounts=(str(DESTINATION),),
            signer_public_keys=(self.signer.public_key,),
            route_policy_digest=sequencer.route_policy_digest,
            commitment_policy="confirmed",
        )
        stream = await sequencer.open_stream(
            identity,
            str(self.root / name),
            _step_factory(self.rpc, self.signer),
            limits=StreamLimits(max_journal_bytes=config.stream_journal_quota_bytes),
        )
        self.streams.append(stream)
        return stream

    async def test_stream_write_lanes_serialize_conflicts_and_parallelize_independent_lanes(self):
        self.rpc.send_delay = 0.02
        stream = await self.open_stream()
        original_factory = stream.step_factory
        factories_started = 0
        release_factories = asyncio.Event()

        async def synchronized_factory(intent):
            nonlocal factories_started
            factories_started += 1
            if factories_started == 3:
                release_factories.set()
            await asyncio.wait_for(release_factories.wait(), timeout=2)
            return original_factory(intent)

        stream.step_factory = synchronized_factory
        intents = (
            _intent("lane-a-1", write_locks=("account-a",)),
            _intent("lane-a-2", write_locks=("account-a",)),
            _intent("lane-b-1", write_locks=("account-b",)),
        )
        receipts = await asyncio.gather(*(stream.append(intent) for intent in intents))
        result = await stream.wait()
        self.assertIsInstance(result, RunResult)
        self.assertEqual(set(result.outcomes), {"lane-a-1", "lane-a-2", "lane-b-1"})
        self.assertEqual(self.rpc.max_active_sends, 2)
        lane_a_order = [
            step_id
            for _sequence, step_id in sorted(
                (receipt.sequence, intent.step_id) for receipt, intent in zip(receipts, intents)
            )
            if step_id.startswith("lane-a")
        ]
        self.assertEqual(lane_a_order, ["lane-a-1", "lane-a-2"])

    async def test_confirmation_pump_coalesces_status_reads_across_lanes(self):
        stream = await self.open_stream(name="coalesced")
        original_factory = stream.step_factory
        factories_started = 0
        release_factories = asyncio.Event()

        async def synchronized_factory(intent):
            nonlocal factories_started
            factories_started += 1
            if factories_started == 2:
                release_factories.set()
            await asyncio.wait_for(release_factories.wait(), timeout=2)
            return original_factory(intent)

        stream.step_factory = synchronized_factory
        await asyncio.gather(
            stream.append(_intent("first", write_locks=("one",))),
            stream.append(_intent("second", write_locks=("two",))),
        )
        await stream.wait()
        self.assertIn(2, self.rpc.batch_sizes)
        self.assertLess(self.rpc.batch_calls, 4)

    async def test_default_mode_keeps_dependents_behind_confirmed(self):
        parent_stable = False

        def status(signature, packet, count):
            if b"dcg-step:parent" in packet:
                return _status(signature, Commitment.CONFIRMED if parent_stable else Commitment.PROCESSED)
            return _status(signature, Commitment.CONFIRMED)

        self.rpc.status_resolver = status
        stream = await self.open_stream(name="confirmed-gate")
        await stream.append(_intent("parent", write_locks=("same-lane",)))
        await stream.append(_intent("dependent", dependencies=("parent",), write_locks=("same-lane",)))
        for _ in range(100):
            if any(b"dcg-step:parent" in packet for packet in self.rpc.send_packets):
                break
            await asyncio.sleep(0.005)
        self.assertEqual(len(self.rpc.send_packets), 1)
        parent_stable = True
        await asyncio.wait_for(stream.wait(), timeout=2)
        self.assertEqual(len(self.rpc.send_packets), 2)

    async def test_processed_optimism_releases_bounded_dependents_and_marks_result(self):
        parent_stable = False

        def status(signature, packet, count):
            if b"dcg-step:root" in packet:
                return _status(signature, Commitment.CONFIRMED if parent_stable else Commitment.PROCESSED)
            if b"dcg-step:child-2" in packet and not parent_stable:
                return _status(signature, Commitment.PROCESSED)
            return _status(signature, Commitment.CONFIRMED)

        self.rpc.status_resolver = status
        stream = await self.open_stream(
            latency_mode=LatencyMode.PROCESSED,
            config=_config(latency_mode=LatencyMode.PROCESSED, optimistic_max_depth=2),
            name="optimistic",
        )
        await stream.append(_intent("root", write_locks=("lane",)))
        await stream.append(_intent("child-1", dependencies=("root",), write_locks=("lane",)))
        await stream.append(_intent("child-2", dependencies=("child-1",), write_locks=("lane",)))
        await stream.append(_intent("child-3", dependencies=("child-2",), write_locks=("lane",)))
        for _ in range(200):
            tags = [tag for tag in (b"root", b"child-1", b"child-2", b"child-3") if any(f"dcg-step:{tag.decode()}".encode() in p for p in self.rpc.send_packets)]
            if len(tags) >= 3:
                break
            await asyncio.sleep(0.005)
        tags = [tag.decode() for tag in (b"root", b"child-1", b"child-2", b"child-3") if any(f"dcg-step:{tag.decode()}".encode() in p for p in self.rpc.send_packets)]
        self.assertEqual(tags, ["root", "child-1", "child-2"])
        self.assertTrue(stream.result().outcomes["root"].optimistic)
        self.assertEqual(stream.optimistic_steps, ("root",))
        parent_observations = [row for row in stream.observations if row.step_id == "root"]
        self.assertIn("processed", [row.status_commitment for row in parent_observations])
        self.assertTrue(any(row.label == "optimistic" for row in parent_observations))
        parent_stable = True
        await asyncio.wait_for(stream.wait(), timeout=2)
        self.assertIn(b"dcg-step:child-3", b"".join(self.rpc.send_packets))

    async def test_dropped_processed_parent_reconciles_and_invalidates_descendant(self):
        def status(signature, packet, count):
            if b"dcg-step:parent" in packet:
                # One initial status lookup happens before the packet reaches
                # FakeRpc; its next lookup is the first observable status.
                return _status(signature, Commitment.PROCESSED) if count == 2 else None
            return _status(signature, Commitment.PROCESSED)

        self.rpc.status_resolver = status
        stream = await self.open_stream(
            latency_mode=LatencyMode.PROCESSED,
            config=_config(latency_mode=LatencyMode.PROCESSED),
            name="dropped",
        )
        await stream.append(_intent("parent", write_locks=("lane",)))
        await stream.append(_intent("child", dependencies=("parent",), write_locks=("lane",)))
        with self.assertRaises(ReconciliationRequired):
            await asyncio.wait_for(stream.wait(), timeout=2)
        events = stream.plan.lifecycle_events
        self.assertIn("step_dropped", [event.event for event in events])
        self.assertIn("optimistic_branch_invalidated", [event.event for event in events])
        self.assertIn("reconciliation_required", [event.event for event in events])
        self.assertEqual(len(self.rpc.reconciliations), 2, "both signed packets are checked by the app adapter")
        self.assertEqual(len(self.rpc.send_packets), 2, "the invalidated child is never silently replayed")

    async def _dropped_parent_stream(self, name, parent_lands):
        def status(signature, packet, count):
            if b"dcg-step:parent" in packet:
                if parent_lands["now"]:
                    return _status(signature, Commitment.CONFIRMED)
                return _status(signature, Commitment.PROCESSED) if count == 2 else None
            return _status(signature, Commitment.CONFIRMED)

        self.rpc.status_resolver = status
        stream = await self.open_stream(
            latency_mode=LatencyMode.PROCESSED,
            config=_config(latency_mode=LatencyMode.PROCESSED),
            name=name,
        )
        await stream.append(_intent("parent", write_locks=("lane",)))
        await stream.append(_intent("child", dependencies=("parent",), write_locks=("lane",)))
        with self.assertRaises(ReconciliationRequired):
            await asyncio.wait_for(stream.wait(), timeout=2)
        return stream

    async def test_h2_decide_continue_resumes_dropped_parent_and_descendant(self):
        lands = {"now": False}
        stream = await self._dropped_parent_stream("decide-continue", lands)
        lands["now"] = True
        await stream.decide("parent", "continue", "evidence-continue")
        result = await asyncio.wait_for(stream.wait(), timeout=3)
        self.assertEqual(set(result.outcomes), {"parent", "child"})
        decisions = [event for event in stream.plan.lifecycle_events if event.event == "reconciliation_decision"]
        self.assertEqual([(event.step_id, event.data.get("decision")) for event in decisions][:1],
                         [("parent", "continue")])

    async def test_h2_decide_abandon_is_journaled_and_rejects_bad_input(self):
        stream = await self._dropped_parent_stream("decide-abandon", {"now": False})
        with self.assertRaises(ValueError):
            await stream.decide("parent", "retry", "evidence")
        with self.assertRaises(JournalError):
            await stream.decide("child-that-was-not-dropped", "continue", "evidence")
        await stream.decide("parent", "abandon", "evidence-abandon")
        decisions = [event for event in stream.plan.lifecycle_events if event.event == "reconciliation_decision"]
        self.assertEqual(decisions[-1].step_id, "parent")
        self.assertEqual(decisions[-1].data.get("decision"), "abandon")

    async def test_invalidated_unsigned_descendant_is_journaled_and_can_be_abandoned(self):
        def status(signature, packet, count):
            if b"dcg-step:parent" in packet:
                return _status(signature, Commitment.PROCESSED) if count == 2 else None
            if b"dcg-step:child" in packet:
                return _status(signature, Commitment.PROCESSED)
            return None

        self.rpc.status_resolver = status
        stream = await self.open_stream(
            latency_mode=LatencyMode.PROCESSED,
            config=_config(latency_mode=LatencyMode.PROCESSED, optimistic_max_depth=1),
            name="unsigned-descendant",
        )
        await stream.append(_intent("parent", write_locks=("lane",)))
        await stream.append(_intent("child", dependencies=("parent",), write_locks=("lane",)))
        await stream.append(_intent("grandchild", dependencies=("child",), write_locks=("lane",)))

        with self.assertRaises(ReconciliationRequired):
            await asyncio.wait_for(stream.wait(), timeout=2)

        self.assertEqual(len(self.rpc.send_packets), 2, "the depth-limited grandchild stays unsigned")
        required = next(
            event
            for event in stream.plan.lifecycle_events
            if event.event == "reconciliation_required" and event.step_id == "grandchild"
        )
        self.assertTrue(required.data["unsigned"])
        self.assertEqual(required.generation, 0)
        decision_sequence = await stream.plan.record_reconciliation_decision(
            "grandchild",
            0,
            decision="abandon",
            evidence_digest="test-application-reconciliation",
        )
        await stream.plan.record_terminal(
            StreamTerminal(
                step_id="grandchild",
                outcome="abandoned",
                signature=None,
                commitment=None,
                postcondition_satisfied=False,
                postcondition_digest="test-application-reconciliation",
                reconciliation_decision_event_sequence=decision_sequence,
            )
        )
        self.assertEqual(stream.plan.terminal_summaries["grandchild"].outcome, "abandoned")

    async def test_status_transport_outage_does_not_count_as_processed_drop(self):
        def status(signature, packet, count):
            if b"dcg-step:parent" in packet:
                if count == 2:
                    return _status(signature, Commitment.PROCESSED)
                if count in {3, 4}:
                    raise RpcUnavailable("temporary status outage")
            return _status(signature, Commitment.CONFIRMED)

        self.rpc.status_resolver = status
        stream = await self.open_stream(
            latency_mode=LatencyMode.PROCESSED,
            config=_config(latency_mode=LatencyMode.PROCESSED),
            name="status-outage",
        )
        await stream.append(_intent("parent", write_locks=("lane",)))
        await stream.append(_intent("child", dependencies=("parent",), write_locks=("lane",)))
        result = await asyncio.wait_for(stream.wait(), timeout=2)
        self.assertEqual(set(result.outcomes), {"parent", "child"})
        self.assertNotIn("step_dropped", [event.event for event in stream.plan.lifecycle_events])

    async def test_fixed_plan_v1_journal_shape_remains_unchanged(self):
        journal = self.root / "fixed.jsonl"
        message = lambda lease: bytes(
            Message.new_with_blockhash(
                [Instruction(PROGRAM, b"fixed-v1", [AccountMeta(DESTINATION, False, True)])],
                self.keypair.pubkey(),
                Hash.from_string(lease.blockhash),
            )
        )

        async def postcondition(endpoint):
            return PostconditionResult(False, "fixed-state-before-send")

        step = TransactionStep(
            "fixed",
            (),
            "rpc-a",
            "test-write",
            120_000,
            "fixed-intent",
            "fixed-recovery",
            message,
            postcondition,
        )
        plan = TransactionPlan(GENESIS, str(PROGRAM), (str(DESTINATION),), self.signer.public_key, (step,))
        store = JournalStore(journal)
        run = await self.sequencer.submit(plan, store)
        header = store.events()[0].data
        self.assertEqual(header["schema_version"], 1)
        self.assertNotIn("signer_public_keys", header)
        self.assertEqual(set(run.outcomes), {"fixed"})
        send_attempt = next(event for event in store.events() if event.name == "send_attempt_started")
        self.assertEqual(set(send_attempt.data), {"step_id", "generation", "attempt"})

    async def test_multisigner_fixed_plan_uses_only_injected_signers(self):
        authority = Keypair()
        new_account = Keypair()
        signers = (KeypairFileSigner(authority), KeypairFileSigner(new_account))
        multisigner = MultiSigner(signers)
        message = bytes(
            Message.new_with_blockhash(
                [
                    Instruction(
                        PROGRAM,
                        b"setup",
                        [AccountMeta(new_account.pubkey(), True, True)],
                    )
                ],
                authority.pubkey(),
                Hash.new_unique(),
            )
        )
        lease = BlockhashLease(str(Hash.new_unique()), GENESIS, time.time())
        signed = await multisigner.sign(message, lease)
        tx = VersionedTransaction.from_bytes(signed.raw_bytes)
        self.assertEqual(len(tx.signatures), 2)
        tx.verify_and_hash_message()
        self.assertEqual(signed.signature, str(tx.signatures[0]))

    async def test_multisigner_rejects_invalid_injected_signature(self):
        authority = Keypair()
        new_account = Keypair()
        message = bytes(
            Message.new_with_blockhash(
                [Instruction(PROGRAM, b"setup", [AccountMeta(new_account.pubkey(), True, True)])],
                authority.pubkey(),
                Hash.new_unique(),
            )
        )

        class InvalidSigner:
            public_key = str(new_account.pubkey())

            async def sign_message(self, message):
                del message
                return bytes(64)

        multisigner = MultiSigner((KeypairFileSigner(authority), InvalidSigner()))
        with self.assertRaisesRegex(ValueError, "does not verify"):
            await multisigner.sign(message, BlockhashLease(str(Hash.new_unique()), GENESIS, time.time()))

    async def test_pool_exhaustion_and_step_deadline_are_bounded(self):
        lease_configs = _config(max_in_flight=1, pool_timeout=0.01, per_step_time_cap_seconds=0.2)
        exhausted_rpc = FakeRpc()
        exhausted_rpc.get_genesis_hash = None
        exhausted = Sequencer(endpoints={"rpc-a": exhausted_rpc}, signer=self.signer, config=lease_configs)
        # The pool holds 4x the v1 step cap for reads (M3); exhaust every slot.
        held = [await exhausted.pool.acquire(RequestKind.RPC) for _ in range(4)]
        # M3: exhaustion during build/sign waits (bounded by the step cap)
        # instead of aborting the run.
        with self.assertRaises((EndpointPoolExhausted, StepTimeCapExceeded)) as error:
            await exhausted.submit(self._fixed_plan(), JournalStore(self.root / "exhausted.jsonl"))
        if isinstance(error.exception, EndpointPoolExhausted):
            self.assertEqual(getattr(error.exception, "classification", None), "pool-exhausted")
        for lease in held:
            await lease.close()

        deadline_config = _config(max_in_flight=1, pool_timeout=1.0, per_step_time_cap_seconds=0.02)
        deadline_rpc = FakeRpc()
        deadline_rpc.get_genesis_hash = None
        deadline = Sequencer(endpoints={"rpc-a": deadline_rpc}, signer=self.signer, config=deadline_config)
        held = [await deadline.pool.acquire(RequestKind.RPC) for _ in range(4)]
        with self.assertRaises((StepTimeCapExceeded, EndpointPoolExhausted)):
            await deadline.submit(self._fixed_plan(), JournalStore(self.root / "deadline.jsonl"))
        for lease in held:
            await lease.close()

    async def test_tpu_helper_death_during_stream_stays_ambiguous_without_replay(self):
        dead = MemoryHelper(dead=True)
        spawn_count = 0

        def factory():
            nonlocal spawn_count
            spawn_count += 1
            return dead

        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="unused-test-helper", rpc_url="http://127.0.0.1:8899"),
            helper_factory=factory,
        )
        self.addAsyncCleanup(provider.close)
        config = _config()
        sequencer = Sequencer(
            endpoints={"rpc-a": self.rpc},
            signer=self.signer,
            config=config,
            providers={provider.provider_id: provider},
        )
        identity = StreamIdentity(
            run_id="tpu-failure",
            genesis_hash=GENESIS,
            program_id=str(PROGRAM),
            destination_accounts=(str(DESTINATION),),
            signer_public_keys=(self.signer.public_key,),
            route_policy_digest=sequencer.route_policy_digest,
            commitment_policy="confirmed",
        )
        stream = await sequencer.open_stream(
            identity,
            str(self.root / "tpu-failure"),
            _step_factory(self.rpc, self.signer),
        )
        self.streams.append(stream)
        await stream.append(_intent("tpu-parent"))
        await stream.append(_intent("blocked-child", dependencies=("tpu-parent",)))
        with self.assertRaises(AmbiguousFate):
            await asyncio.wait_for(stream.wait(), timeout=2)
        self.assertEqual(spawn_count, 1)
        self.assertEqual(len(dead.sent), 1)
        self.assertEqual(len(self.rpc.send_packets), 0, "a failed parent cannot release its dependent")
        unresolved = await stream.plan.unresolved_packets()
        self.assertEqual(dead.sent[0][0], unresolved[0].raw_bytes)

    async def test_tpu_async_error_is_recorded_against_acknowledged_stream_attempt(self):
        class ObservableMemoryHelper(MemoryHelper):
            async def send_raw(inner_self, raw_bytes, expected_signature):
                await super(ObservableMemoryHelper, inner_self).send_raw(raw_bytes, expected_signature)
                self.rpc.send_packets.append(raw_bytes)
                self.rpc.packets_by_signature[expected_signature] = raw_bytes

        helper = ObservableMemoryHelper()
        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="unused-test-helper", rpc_url="http://127.0.0.1:8899"),
            helper_factory=lambda: helper,
        )
        self.addAsyncCleanup(provider.close)
        self.rpc.status_resolver = lambda signature, packet, count: None
        original_statuses = self.rpc.signature_statuses
        acknowledged_status_read = asyncio.Event()

        async def signal_after_handoff_ack(signatures):
            if all(signature in self.rpc.packets_by_signature for signature in signatures):
                acknowledged_status_read.set()
            return await original_statuses(signatures)

        self.rpc.signature_statuses = signal_after_handoff_ack
        sequencer = Sequencer(
            endpoints={"rpc-a": self.rpc},
            signer=self.signer,
            config=_config(),
            providers={provider.provider_id: provider},
        )
        identity = StreamIdentity(
            run_id="tpu-late-error",
            genesis_hash=GENESIS,
            program_id=str(PROGRAM),
            destination_accounts=(str(DESTINATION),),
            signer_public_keys=(self.signer.public_key,),
            route_policy_digest=sequencer.route_policy_digest,
            commitment_policy="confirmed",
        )
        journal_path = str(self.root / "tpu-late-error")
        stream = await sequencer.open_stream(
            identity,
            journal_path,
            _step_factory(self.rpc, self.signer),
            limits=StreamLimits(max_attempts_per_generation=1),
        )
        self.streams.append(stream)
        await stream.append(_intent("late-error"))
        await asyncio.wait_for(acknowledged_status_read.wait(), timeout=2)
        packets = await stream.plan.unresolved_packets()
        packet = next((item for item in packets if item.attempts and item.attempts[0].outcome == "acknowledged"), None)
        self.assertIsNotNone(packet, "the helper attempt should be durably acknowledged before its async ERR")
        await stream.close()
        stream = await sequencer.open_stream(
            identity,
            journal_path,
            _step_factory(self.rpc, self.signer),
            limits=StreamLimits(max_attempts_per_generation=1),
        )
        self.streams.append(stream)
        await provider._on_helper_failure(packet.signature, "leader returned ERR")
        failure = next(
            (event for event in stream.plan.provider_failures if event.event == "late_provider_failure"),
            None,
        )
        self.assertIsNotNone(failure, "the async provider ERR should reach the stream journal")
        self.assertEqual(failure.step_id, "late-error")
        self.assertEqual(failure.data["attempt"], packet.attempts[0].number)
        self.assertIn("leader returned ERR", failure.data["detail"])

    async def test_tpu_callback_before_handoff_ack_is_journaled_after_ack(self):
        provider_box = {}
        test_case = self
        previous_failures = []

        class CallbackBeforeAckHelper(MemoryHelper):
            async def send_raw(self, raw_bytes, expected_signature):
                self.sent.append((raw_bytes, expected_signature))
                test_case.rpc.send_packets.append(raw_bytes)
                test_case.rpc.packets_by_signature[expected_signature] = raw_bytes
                await provider_box["provider"]._on_helper_failure(
                    expected_signature,
                    "leader returned ERR before the send acknowledgement",
                )

        helper = CallbackBeforeAckHelper()
        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="unused-test-helper", rpc_url="http://127.0.0.1:8899"),
            helper_factory=lambda: helper,
            failure_handler=previous_failures.append,
        )
        provider_box["provider"] = provider
        self.addAsyncCleanup(provider.close)
        sequencer = Sequencer(
            endpoints={"rpc-a": self.rpc},
            signer=self.signer,
            config=_config(),
            providers={provider.provider_id: provider},
        )
        identity = StreamIdentity(
            run_id="tpu-early-error",
            genesis_hash=GENESIS,
            program_id=str(PROGRAM),
            destination_accounts=(str(DESTINATION),),
            signer_public_keys=(self.signer.public_key,),
            route_policy_digest=sequencer.route_policy_digest,
            commitment_policy="confirmed",
        )
        stream = await sequencer.open_stream(
            identity,
            str(self.root / "tpu-early-error"),
            _step_factory(self.rpc, self.signer),
        )
        self.streams.append(stream)
        await stream.append(_intent("early-error"))
        await asyncio.wait_for(stream.wait(), timeout=2)

        failures = [
            event
            for event in stream.plan.provider_failures
            if event.event == "late_provider_failure" and event.step_id == "early-error"
        ]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].data["attempt"], 1)
        self.assertIn("before the send acknowledgement", failures[0].data["detail"])
        self.assertEqual(len(previous_failures), 1, "the provider's existing callback remains chained")

    def _fixed_plan(self):
        async def postcondition(endpoint):
            return PostconditionResult(False, "not-applied")

        return TransactionPlan(
            GENESIS,
            str(PROGRAM),
            (str(DESTINATION),),
            self.signer.public_key,
            (
                TransactionStep(
                    "blocked",
                    (),
                    "rpc-a",
                    "test-write",
                    120_000,
                    "blocked-intent",
                    "blocked-recovery",
                    lambda lease: b"not-reached",
                    postcondition,
                ),
            ),
        )


if __name__ == "__main__":
    unittest.main()
