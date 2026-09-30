"""Async transaction planning, durable send, confirmation, and resume core."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Mapping, Sequence

from .journal import JournalEvent, JournalStore
from .types import (
    AmbiguousFate,
    Backoff,
    BlockhashExpired,
    BlockhashLease,
    Commitment,
    EndpointLimits,
    EventHook,
    JournalError,
    PacketTooLarge,
    PlanError,
    PostconditionResult,
    ProgramRefused,
    RateLimited,
    RecoveryEvidence,
    RetryPolicy,
    RpcEndpoint,
    RpcError,
    RpcUnavailable,
    SequencerConfig,
    SignatureObservation,
    SignedTransaction,
    Signer,
    StepTimeCapExceeded,
    TransactionPlan,
    TransactionStep,
)


@dataclass(frozen=True)
class StepOutcome:
    step_id: str
    signature: str
    confirmed_by: str
    slot: int | None
    fee_lamports: int | None
    compute_units_consumed: int | None


@dataclass(frozen=True)
class RunResult:
    run_id: str
    plan_digest: str
    outcomes: Mapping[str, StepOutcome]


@dataclass
class _PacketState:
    generation: int
    signature: str
    raw_bytes: bytes
    lease: BlockhashLease
    attempts: int = 0
    status: SignatureObservation | None = None
    postcondition: PostconditionResult | None = None
    last_send_error: str | None = None


@dataclass
class _ReplayState:
    run_id: str
    plan_digest: str
    packets: dict[str, list[_PacketState]] = field(default_factory=dict)
    outcomes: dict[str, StepOutcome] = field(default_factory=dict)
    terminal_errors: dict[str, str] = field(default_factory=dict)
    rebuild_authorized_for: set[tuple[str, int]] = field(default_factory=set)
    event_names: list[str] = field(default_factory=list)

    @classmethod
    def from_events(cls, events: Sequence[JournalEvent]) -> _ReplayState:
        if not events or events[0].name != "run_started":
            raise JournalError("journal has no run_started row")
        run_id = events[0].run_id
        header = events[0].data
        plan_digest = header.get("plan_digest")
        if not isinstance(plan_digest, str):
            raise JournalError("journal run header has no plan digest")
        state = cls(run_id=run_id, plan_digest=plan_digest)
        for index, event in enumerate(events):
            if event.run_id != run_id:
                raise JournalError("journal contains more than one run")
            state.event_names.append(event.name)
            data = event.data
            if event.name == "run_started":
                if index != 0:
                    raise JournalError("journal contains more than one run_started row")
                continue
            step_id = data.get("step_id")
            if not isinstance(step_id, str):
                raise JournalError(f"{event.name} row has no step id")
            if step_id in state.outcomes or step_id in state.terminal_errors:
                raise JournalError(f"journal event follows terminal state for {step_id}")
            if event.name == "step_signed":
                if step_id in state.outcomes or step_id in state.terminal_errors:
                    raise JournalError(f"step {step_id} was signed after completion")
                packet = _packet_from_event(data)
                packets = state.packets.setdefault(step_id, [])
                if packet.generation != len(packets):
                    raise JournalError(f"nonconsecutive packet generation for {step_id}")
                packets.append(packet)
            elif event.name in {"send_attempt_started", "send_error", "send_acknowledged"}:
                packet = state._packet(step_id, data)
                if event.name == "send_attempt_started":
                    packet.attempts += 1
                    packet.last_send_error = None
                elif event.name == "send_error":
                    packet.last_send_error = str(data.get("error_class", "rpc-error"))
                elif event.name == "send_acknowledged" and data.get("signature") != packet.signature:
                    raise JournalError("send acknowledgment signature differs from signed packet")
            elif event.name == "status_observed":
                packet = state._packet(step_id, data)
                packet.status = _status_from_json(data.get("status"))
            elif event.name == "postcondition_observed":
                packet = state._packet(step_id, data)
                packet.postcondition = _postcondition_from_json(data.get("postcondition"))
            elif event.name == "step_rebuild_authorized":
                generation = data.get("generation")
                if not isinstance(generation, int):
                    raise JournalError("rebuild authorization has invalid generation")
                packet = state._packet(step_id, data)
                if data.get("signature") != packet.signature:
                    raise JournalError("rebuild authorization signature does not match packet")
                state.rebuild_authorized_for.add((step_id, generation))
            elif event.name == "step_confirmed":
                packet = state._packet(step_id, data)
                if data.get("signature") != packet.signature:
                    raise JournalError("confirmation signature does not match signed packet")
                if step_id in state.outcomes or step_id in state.terminal_errors:
                    raise JournalError(f"step {step_id} has conflicting terminal journal states")
                try:
                    confirmed_by = data["confirmed_by"]
                except KeyError as exc:
                    raise JournalError("confirmation row is missing its source") from exc
                state.outcomes[step_id] = StepOutcome(
                    step_id=step_id,
                    signature=packet.signature,
                    confirmed_by=str(confirmed_by),
                    slot=data.get("slot"),
                    fee_lamports=data.get("fee_lamports"),
                    compute_units_consumed=data.get("compute_units_consumed"),
                )
            elif event.name == "step_terminal_failure":
                packet = state._packet(step_id, data)
                if data.get("signature") != packet.signature:
                    raise JournalError("terminal failure signature does not match signed packet")
                if step_id in state.outcomes or step_id in state.terminal_errors:
                    raise JournalError(f"step {step_id} has conflicting terminal journal states")
                state.terminal_errors[step_id] = str(data.get("error", "program refused transaction"))
            elif event.name == "step_ambiguous":
                state._packet(step_id, data)
            elif event.name == "step_time_cap":
                pass
            else:
                raise JournalError(f"unknown journal event {event.name!r}")
        return state

    def _packet(self, step_id: str, data: dict[str, Any]) -> _PacketState:
        generation = data.get("generation")
        packets = self.packets.get(step_id, [])
        if not isinstance(generation, int) or generation < 0 or generation >= len(packets):
            raise JournalError(f"event references unknown packet generation for {step_id}")
        return packets[generation]


def _packet_from_event(data: dict[str, Any]) -> _PacketState:
    try:
        raw_bytes = base64.b64decode(data["raw_transaction"], validate=True)
        lease_data = data["lease"]
        lease = BlockhashLease(
            blockhash=lease_data["blockhash"],
            genesis_hash=lease_data["genesis_hash"],
            fetched_at_unix=float(lease_data["fetched_at_unix"]),
            last_valid_block_height=lease_data.get("last_valid_block_height"),
            context_slot=lease_data.get("context_slot"),
            lifetime_seconds=float(lease_data["lifetime_seconds"]),
        )
        generation = data["generation"]
        signature = data["signature"]
    except (KeyError, TypeError, ValueError) as exc:
        raise JournalError("invalid signed packet row") from exc
    if not isinstance(raw_bytes, bytes) or not isinstance(generation, int) or not isinstance(signature, str):
        raise JournalError("invalid signed packet row field types")
    return _PacketState(generation, signature, raw_bytes, lease)


def _status_to_json(status: SignatureObservation | None) -> dict[str, Any] | None:
    if status is None:
        return None
    return {
        "signature": status.signature,
        "commitment": status.commitment.value,
        "error": status.error,
        "slot": status.slot,
        "transaction_metadata_available": status.transaction_metadata_available,
        "fee_lamports": status.fee_lamports,
        "compute_units_consumed": status.compute_units_consumed,
    }


def _status_from_json(value: Any) -> SignatureObservation | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise JournalError("invalid signature status row")
    try:
        return SignatureObservation(
            signature=value["signature"],
            commitment=Commitment(value["commitment"]),
            error=value.get("error"),
            slot=value.get("slot"),
            transaction_metadata_available=bool(value.get("transaction_metadata_available", False)),
            fee_lamports=value.get("fee_lamports"),
            compute_units_consumed=value.get("compute_units_consumed"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise JournalError("invalid signature status row") from exc


def _postcondition_to_json(value: PostconditionResult) -> dict[str, Any]:
    return {"satisfied": value.satisfied, "state_digest": value.state_digest}


def _postcondition_from_json(value: Any) -> PostconditionResult | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("satisfied") not in {True, False, None}:
        raise JournalError("invalid postcondition row")
    return PostconditionResult(value.get("satisfied"), value.get("state_digest"))


def _lease_to_json(lease: BlockhashLease) -> dict[str, Any]:
    return {
        "blockhash": lease.blockhash,
        "genesis_hash": lease.genesis_hash,
        "fetched_at_unix": lease.fetched_at_unix,
        "last_valid_block_height": lease.last_valid_block_height,
        "context_slot": lease.context_slot,
        "lifetime_seconds": lease.lifetime_seconds,
    }


class _EndpointPacer:
    def __init__(self, limits: EndpointLimits):
        if limits.sends_per_second <= 0 or limits.max_in_flight <= 0:
            raise PlanError("endpoint send rate and in-flight limit must be positive")
        self._interval = 1.0 / limits.sends_per_second
        self._semaphore = asyncio.Semaphore(limits.max_in_flight)
        self._rate_lock = asyncio.Lock()
        self._next_send_at = 0.0

    @asynccontextmanager
    async def transaction_slot(self) -> AsyncIterator[None]:
        async with self._semaphore:
            yield

    async def wait_send_rate(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._rate_lock:
            now = loop.time()
            delay = max(0.0, self._next_send_at - now)
            self._next_send_at = max(now, self._next_send_at) + self._interval
        if delay:
            await asyncio.sleep(delay)


class Sequencer:
    """Execute dependency-aware transaction plans and resume from a JSONL journal."""

    def __init__(
        self,
        *,
        endpoints: Mapping[str, RpcEndpoint],
        signer: Signer,
        config: SequencerConfig,
        event_hook: EventHook | None = None,
    ):
        self.endpoints = dict(endpoints)
        self.signer = signer
        self.config = config
        self.event_hook = event_hook
        for endpoint_id, endpoint in self.endpoints.items():
            if endpoint.endpoint_id != endpoint_id:
                raise PlanError(f"RPC endpoint mapping key {endpoint_id!r} does not match endpoint identity")
        self._pacers = {
            endpoint_id: _EndpointPacer(config.endpoint_limits[endpoint_id])
            for endpoint_id in self.endpoints
            if endpoint_id in config.endpoint_limits
        }
        self._validate_config()

    def _validate_config(self) -> None:
        if self.config.max_batch_size <= 0:
            raise PlanError("max_batch_size must be positive")
        if self.config.max_packet_bytes <= 0 or self.config.max_packet_bytes > 1232:
            raise PlanError("max_packet_bytes must be between 1 and the 1232-byte packet limit")
        if self.config.blockhash_lifetime_seconds <= 0:
            raise PlanError("blockhash lifetime must be positive")
        if self.config.per_step_time_cap_seconds <= 0:
            raise PlanError("per-step time cap must be positive")
        if self.config.confirmation_poll_seconds < 0:
            raise PlanError("confirmation poll interval cannot be negative")
        if self.config.backoff.initial_seconds < 0 or self.config.backoff.maximum_seconds < 0:
            raise PlanError("backoff values cannot be negative")
        if self.config.backoff.multiplier < 1:
            raise PlanError("backoff multiplier must be at least 1")
        if set(self.endpoints) != set(self.config.endpoint_limits):
            raise PlanError("every configured endpoint limit must match exactly one RPC endpoint")

    async def submit(self, plan: TransactionPlan, journal: JournalStore) -> RunResult:
        """Start a new run. The journal must be empty."""

        self._validate_plan(plan)
        if journal.events():
            raise JournalError("submit requires a fresh empty journal; use resume")
        run_id = str(uuid.uuid4())
        plan_digest = self._plan_digest(plan)
        await self._append(
            journal,
            run_id,
            "run_started",
            {
                "schema_version": 1,
                "plan_digest": plan_digest,
                "genesis_hash": plan.genesis_hash,
                "program_id": plan.program_id,
                "destination_accounts": sorted(plan.destination_accounts),
                "signer_public_key": self.signer.public_key,
                "signer_signature_count": self.signer.signature_count,
                "signer_signature_size_bytes": self.signer.signature_size_bytes,
                "steps": [self._step_manifest(step) for step in sorted(plan.steps, key=lambda s: s.step_id)],
            },
            None,
        )
        return await self._drive(plan, journal, run_id, plan_digest)

    async def resume(self, plan: TransactionPlan, journal: JournalStore) -> RunResult:
        """Validate plan and signer identity, then continue unresolved journal rows."""

        self._validate_plan(plan)
        events = journal.events()
        if not events:
            raise JournalError("resume requires an existing run journal")
        replay = _ReplayState.from_events(events)
        plan_digest = self._plan_digest(plan)
        known_step_ids = {step.step_id for step in plan.steps}
        for event in events[1:]:
            step_id = event.data.get("step_id")
            if not isinstance(step_id, str) or step_id not in known_step_ids:
                raise JournalError(f"journal references a step outside the supplied plan: {step_id!r}")
        if replay.plan_digest != plan_digest:
            raise JournalError("journal plan digest does not match supplied plan")
        expected_steps = [self._step_manifest(step) for step in sorted(plan.steps, key=lambda item: item.step_id)]
        if events[0].data.get("steps") != expected_steps:
            raise JournalError("journal step manifest does not match supplied plan")
        if events[0].data.get("genesis_hash") != plan.genesis_hash:
            raise JournalError("journal genesis hash does not match supplied plan")
        if events[0].data.get("program_id") != plan.program_id:
            raise JournalError("journal program ID does not match supplied plan")
        if events[0].data.get("destination_accounts") != sorted(plan.destination_accounts):
            raise JournalError("journal destination accounts do not match supplied plan")
        if events[0].data.get("signer_public_key") != self.signer.public_key:
            raise JournalError("journal signer public key does not match current signer")
        if events[0].data.get("signer_signature_count") != self.signer.signature_count:
            raise JournalError("journal signer signature count does not match current signer")
        if events[0].data.get("signer_signature_size_bytes") != self.signer.signature_size_bytes:
            raise JournalError("journal signer signature size does not match current signer")
        return await self._drive(plan, journal, replay.run_id, plan_digest)

    def _validate_plan(self, plan: TransactionPlan) -> None:
        if not plan.genesis_hash or not plan.program_id or not plan.signer_public_key:
            raise PlanError("plan must bind genesis, program, and signer public identities")
        if plan.signer_public_key != self.signer.public_key:
            raise PlanError("plan signer public key does not match the signer")
        if not plan.steps:
            raise PlanError("plan must contain at least one transaction step")
        by_id: dict[str, TransactionStep] = {}
        for step in plan.steps:
            if not step.step_id or step.step_id in by_id:
                raise PlanError(f"step ids must be non-empty and unique: {step.step_id!r}")
            by_id[step.step_id] = step
            if step.endpoint_id not in self.endpoints:
                raise PlanError(f"unknown RPC endpoint {step.endpoint_id!r}")
            if step.compute_unit_limit <= 0 or not step.compute_class:
                raise PlanError(f"step {step.step_id} needs a compute class and positive CU limit")
            if not step.intent_digest or not step.recovery_policy_digest:
                raise PlanError(f"step {step.step_id} needs stable intent and recovery-policy digests")
            if not 0 < step.max_packet_bytes <= self.config.max_packet_bytes:
                raise PlanError(f"step {step.step_id} packet limit exceeds the plan maximum")
            if step.retry_policy is RetryPolicy.RECONCILE and step.authorize_rebuild is None:
                raise PlanError(f"step {step.step_id} needs an explicit rebuild authorizer")
            if step.retry_policy is not RetryPolicy.RECONCILE and step.authorize_rebuild is not None:
                raise PlanError(f"step {step.step_id} has a rebuild authorizer without reconcile policy")
            if len(set(step.dependencies)) != len(step.dependencies) or step.step_id in step.dependencies:
                raise PlanError(f"step {step.step_id} has duplicate or self dependencies")
        for step in plan.steps:
            missing = set(step.dependencies) - set(by_id)
            if missing:
                raise PlanError(f"step {step.step_id} depends on unknown steps: {sorted(missing)}")
        # Kahn traversal catches cycles and makes malformed plans fail before signing.
        completed: set[str] = set()
        while len(completed) != len(by_id):
            ready = {sid for sid, step in by_id.items() if sid not in completed and set(step.dependencies) <= completed}
            if not ready:
                raise PlanError("transaction dependency graph contains a cycle")
            completed.update(ready)

    def _step_manifest(self, step: TransactionStep) -> dict[str, Any]:
        return {
            "step_id": step.step_id,
            "dependencies": sorted(step.dependencies),
            "endpoint_id": step.endpoint_id,
            "compute_class": step.compute_class,
            "compute_unit_limit": step.compute_unit_limit,
            "intent_digest": step.intent_digest,
            "recovery_policy_digest": step.recovery_policy_digest,
            "max_packet_bytes": step.max_packet_bytes,
            "write_locks": sorted(step.write_locks),
            "retry_policy": step.retry_policy.value,
        }

    def _plan_digest(self, plan: TransactionPlan) -> str:
        manifest = {
            "schema_version": 1,
            "genesis_hash": plan.genesis_hash,
            "program_id": plan.program_id,
            "destination_accounts": sorted(plan.destination_accounts),
            "signer_public_key": self.signer.public_key,
            "signer_signature_count": self.signer.signature_count,
            "signer_signature_size_bytes": self.signer.signature_size_bytes,
            "steps": [self._step_manifest(step) for step in sorted(plan.steps, key=lambda s: s.step_id)],
        }
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    async def _drive(
        self, plan: TransactionPlan, journal: JournalStore, run_id: str, plan_digest: str
    ) -> RunResult:
        by_id = {step.step_id: step for step in plan.steps}
        while True:
            replay = _ReplayState.from_events(journal.events())
            for step_id, error in replay.terminal_errors.items():
                raise ProgramRefused(f"step {step_id} was finalized with a program error: {error}")
            if len(replay.outcomes) == len(by_id):
                return RunResult(run_id, plan_digest, dict(replay.outcomes))

            ready = [
                step
                for step in sorted(plan.steps, key=lambda item: item.step_id)
                if step.step_id not in replay.outcomes
                and set(step.dependencies) <= set(replay.outcomes)
            ]
            if not ready:
                unresolved = sorted(set(by_id) - set(replay.outcomes))
                raise JournalError(f"no runnable steps remain; unresolved: {unresolved}")
            batch = self._select_batch(ready)
            results = await asyncio.gather(
                *(self._drive_step(step, journal, run_id) for step in batch),
                return_exceptions=True,
            )
            failure = next((result for result in results if isinstance(result, BaseException)), None)
            if failure is not None:
                raise failure

    def _select_batch(self, ready: Sequence[TransactionStep]) -> list[TransactionStep]:
        batch: list[TransactionStep] = []
        locks: set[str] = set()
        for step in ready:
            if len(batch) >= self.config.max_batch_size:
                break
            if locks.intersection(step.write_locks):
                continue
            batch.append(step)
            locks.update(step.write_locks)
        if not batch:
            raise PlanError("ready steps could not be batched")
        return batch

    async def _drive_step(self, step: TransactionStep, journal: JournalStore, run_id: str) -> None:
        try:
            async with asyncio.timeout(self.config.per_step_time_cap_seconds):
                async with self._pacers[step.endpoint_id].transaction_slot():
                    await self._drive_step_inner(step, journal, run_id)
        except TimeoutError as exc:
            await self._append(
                journal,
                run_id,
                "step_time_cap",
                {"step_id": step.step_id, "seconds": self.config.per_step_time_cap_seconds},
                step.step_id,
            )
            raise StepTimeCapExceeded(f"step {step.step_id} exceeded its time cap") from exc

    async def _drive_step_inner(self, step: TransactionStep, journal: JournalStore, run_id: str) -> None:
        backoff_delay = self.config.backoff.initial_seconds
        endpoint = self.endpoints[step.endpoint_id]
        while True:
            replay = _ReplayState.from_events(journal.events())
            if step.step_id in replay.outcomes:
                return
            if step.step_id in replay.terminal_errors:
                raise ProgramRefused(replay.terminal_errors[step.step_id])
            packets = replay.packets.get(step.step_id, [])
            if not packets:
                packet = await self._build_and_sign(step, endpoint, journal, run_id, 0)
            else:
                packet = packets[-1]

            # A signed packet that was never handed to an endpoint cannot have
            # landed. It may safely be replaced after its lease expires.
            if self._packet_lease_expired(packet) and packet.attempts == 0:
                packet = await self._build_and_sign(step, endpoint, journal, run_id, packet.generation + 1)
                continue

            status: SignatureObservation | None = None
            status_error: RpcError | None = None
            try:
                status = await endpoint.signature_status(packet.signature)
            except RpcError as exc:
                status_error = exc
            if status is not None:
                if status.signature != packet.signature:
                    raise JournalError("RPC returned status for a different signature")
                await self._append(
                    journal,
                    run_id,
                    "status_observed",
                    {"step_id": step.step_id, "generation": packet.generation, "status": _status_to_json(status)},
                    step.step_id,
                )
                if status.error is None and status.commitment in {Commitment.CONFIRMED, Commitment.FINALIZED}:
                    await self._confirm(
                        step,
                        packet,
                        journal,
                        run_id,
                        confirmed_by="signature",
                        slot=status.slot,
                        fee_lamports=status.fee_lamports,
                        compute_units_consumed=status.compute_units_consumed,
                    )
                    return
                if status.error is not None and status.commitment is Commitment.FINALIZED:
                    await self._terminal_failure(step, packet, status.error, journal, run_id)

            postcondition = PostconditionResult(None)
            postcondition_error: RpcError | None = None
            if status is None:
                try:
                    postcondition = await step.postcondition(endpoint)
                except RpcError as exc:
                    postcondition_error = exc
                    postcondition = PostconditionResult(None)
                await self._append(
                    journal,
                    run_id,
                    "postcondition_observed",
                    {
                        "step_id": step.step_id,
                        "generation": packet.generation,
                        "postcondition": _postcondition_to_json(postcondition),
                        "error_class": type(postcondition_error).__name__ if postcondition_error else None,
                    },
                    step.step_id,
                )
                if postcondition.satisfied is True:
                    await self._confirm(
                        step,
                        packet,
                        journal,
                        run_id,
                        confirmed_by="account-state",
                        slot=None,
                        fee_lamports=None,
                        compute_units_consumed=None,
                    )
                    return

            expired = self._packet_lease_expired(packet)
            if expired and packet.attempts > 0:
                evidence = RecoveryEvidence(
                    signature=packet.signature,
                    lease=packet.lease,
                    status=status,
                    postcondition=postcondition,
                    lease_expired=True,
                )
                if (step.step_id, packet.generation) in replay.rebuild_authorized_for:
                    packet = await self._build_and_sign(step, endpoint, journal, run_id, packet.generation + 1)
                    backoff_delay = self.config.backoff.initial_seconds
                    continue
                if step.retry_policy is RetryPolicy.RECONCILE and step.authorize_rebuild is not None:
                    allowed = await step.authorize_rebuild(evidence)
                    if allowed:
                        await self._append(
                            journal,
                            run_id,
                            "step_rebuild_authorized",
                            {
                                "step_id": step.step_id,
                                "generation": packet.generation,
                                "signature": packet.signature,
                                "postcondition_satisfied": postcondition.satisfied,
                                "state_digest": postcondition.state_digest,
                            },
                            step.step_id,
                        )
                        packet = await self._build_and_sign(step, endpoint, journal, run_id, packet.generation + 1)
                        backoff_delay = self.config.backoff.initial_seconds
                        continue
                await self._append(
                    journal,
                    run_id,
                    "step_ambiguous",
                    {
                        "step_id": step.step_id,
                        "generation": packet.generation,
                        "signature": packet.signature,
                        "status_known": status is not None,
                        "postcondition_satisfied": postcondition.satisfied,
                        "state_digest": postcondition.state_digest,
                    },
                    step.step_id,
                )
                raise AmbiguousFate(
                    f"step {step.step_id} packet {packet.signature} expired without proof of outcome or safe rebuild"
                )

            should_send = packet.attempts == 0
            if packet.attempts > 0 and status is None and step.retry_policy is not RetryPolicy.NEVER:
                should_send = True
            if status_error is not None or postcondition_error is not None:
                should_send = packet.attempts == 0 or (
                    step.retry_policy is not RetryPolicy.NEVER and not expired
                )

            if should_send and not expired:
                if status_error is not None or postcondition_error is not None:
                    retry_after = max(
                        getattr(status_error, "retry_after", 0.0) or 0.0,
                        getattr(postcondition_error, "retry_after", 0.0) or 0.0,
                    )
                    await self._sleep_backoff(backoff_delay, retry_after)
                    backoff_delay = self._next_backoff(backoff_delay)
                elif packet.attempts > 0:
                    await asyncio.sleep(self.config.confirmation_poll_seconds)
                await self._pacers[step.endpoint_id].wait_send_rate()
                attempt = packet.attempts + 1
                await self._append(
                    journal,
                    run_id,
                    "send_attempt_started",
                    {"step_id": step.step_id, "generation": packet.generation, "attempt": attempt},
                    step.step_id,
                )
                try:
                    receipt = await endpoint.send_raw_transaction(packet.raw_bytes)
                except BlockhashExpired as exc:
                    await self._append(
                        journal,
                        run_id,
                        "send_error",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "error_class": type(exc).__name__,
                            "retry_after": None,
                        },
                        step.step_id,
                    )
                    # Treat provider expiry as a hint, then reconcile status and
                    # application state on the next loop before any fresh sign.
                    continue
                except ProgramRefused as exc:
                    await self._terminal_failure(step, packet, str(exc), journal, run_id)
                except RateLimited as exc:
                    await self._append(
                        journal,
                        run_id,
                        "send_error",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "error_class": type(exc).__name__,
                            "retry_after": exc.retry_after,
                        },
                        step.step_id,
                    )
                    await self._sleep_backoff(backoff_delay, exc.retry_after)
                    backoff_delay = self._next_backoff(backoff_delay)
                    continue
                except RpcUnavailable as exc:
                    await self._append(
                        journal,
                        run_id,
                        "send_error",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "error_class": type(exc).__name__,
                            "retry_after": None,
                        },
                        step.step_id,
                    )
                    await self._sleep_backoff(backoff_delay)
                    backoff_delay = self._next_backoff(backoff_delay)
                    continue
                if receipt.signature != packet.signature:
                    await self._append(
                        journal,
                        run_id,
                        "send_acknowledged",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "signature": packet.signature,
                            "provider_signature": receipt.signature,
                        },
                        step.step_id,
                    )
                    raise AmbiguousFate("RPC accepted bytes but returned a different signature")
                await self._append(
                    journal,
                    run_id,
                    "send_acknowledged",
                    {"step_id": step.step_id, "generation": packet.generation, "signature": receipt.signature},
                    step.step_id,
                )
                backoff_delay = self.config.backoff.initial_seconds
                continue

            if status is not None and status.commitment in {Commitment.PROCESSED, Commitment.CONFIRMED}:
                await self._sleep_backoff(self.config.confirmation_poll_seconds)
            else:
                await self._sleep_backoff(backoff_delay)
                backoff_delay = self._next_backoff(backoff_delay)

    async def _build_and_sign(
        self,
        step: TransactionStep,
        endpoint: RpcEndpoint,
        journal: JournalStore,
        run_id: str,
        generation: int,
    ) -> _PacketState:
        backoff_delay = self.config.backoff.initial_seconds
        while True:
            try:
                lease = await endpoint.latest_blockhash(
                    self._active_genesis_hash(journal), self.config.blockhash_lifetime_seconds
                )
            except (RateLimited, RpcUnavailable) as exc:
                await self._sleep_backoff(backoff_delay, getattr(exc, "retry_after", None))
                backoff_delay = self._next_backoff(backoff_delay)
                continue
            if lease.genesis_hash != self._active_genesis_hash(journal):
                raise PlanError("endpoint returned a blockhash lease for a different genesis")
            if not lease.blockhash or lease.lifetime_seconds <= 0:
                raise PlanError("endpoint returned an invalid blockhash lease")
            if self._lease_expired(lease):
                await self._sleep_backoff(backoff_delay)
                backoff_delay = self._next_backoff(backoff_delay)
                continue
            message = step.build_message(lease)
            if not isinstance(message, bytes):
                raise PlanError(f"step {step.step_id} builder must return bytes")
            signature_count = self.signer.signature_count
            signature_size = self.signer.signature_size_bytes
            if signature_count <= 0 or signature_size <= 0:
                raise PlanError("signer must declare positive signature count and size")
            projected_size = len(message) + _shortvec_size(signature_count) + signature_count * signature_size
            packet_limit = min(step.max_packet_bytes, self.config.max_packet_bytes)
            if projected_size > packet_limit:
                raise PacketTooLarge(
                    f"step {step.step_id} projects {projected_size} bytes, limit is {packet_limit}; signer was not called"
                )
            signed = await self.signer.sign(message, lease)
            if not isinstance(signed, SignedTransaction) or not signed.signature or not signed.raw_bytes:
                raise PlanError("signer returned an invalid signed transaction")
            if len(signed.raw_bytes) > packet_limit:
                raise PacketTooLarge(
                    f"step {step.step_id} signer returned {len(signed.raw_bytes)} bytes, limit is {packet_limit}"
                )
            packet = _PacketState(generation, signed.signature, signed.raw_bytes, lease)
            await self._append(
                journal,
                run_id,
                "step_signed",
                {
                    "step_id": step.step_id,
                    "generation": generation,
                    "signature": signed.signature,
                    "raw_transaction": base64.b64encode(signed.raw_bytes).decode("ascii"),
                    "signer_public_key": self.signer.public_key,
                    "compute_class": step.compute_class,
                    "compute_unit_limit": step.compute_unit_limit,
                    "lease": _lease_to_json(lease),
                },
                step.step_id,
            )
            return packet

    def _active_genesis_hash(self, journal: JournalStore) -> str:
        events = journal.events()
        if not events:
            raise JournalError("cannot build a transaction before the run header")
        genesis_hash = events[0].data.get("genesis_hash")
        if not isinstance(genesis_hash, str):
            raise JournalError("run header has no genesis hash")
        return genesis_hash

    def _lease_expired(self, lease: BlockhashLease) -> bool:
        lifetime = min(lease.lifetime_seconds, self.config.blockhash_lifetime_seconds)
        return time.time() - lease.fetched_at_unix >= lifetime

    def _packet_lease_expired(self, packet: _PacketState) -> bool:
        return packet.last_send_error == BlockhashExpired.__name__ or self._lease_expired(packet.lease)

    async def _confirm(
        self,
        step: TransactionStep,
        packet: _PacketState,
        journal: JournalStore,
        run_id: str,
        *,
        confirmed_by: str,
        slot: int | None,
        fee_lamports: int | None,
        compute_units_consumed: int | None,
    ) -> None:
        await self._append(
            journal,
            run_id,
            "step_confirmed",
            {
                "step_id": step.step_id,
                "generation": packet.generation,
                "signature": packet.signature,
                "confirmed_by": confirmed_by,
                "slot": slot,
                "fee_lamports": fee_lamports,
                "compute_units_consumed": compute_units_consumed,
            },
            step.step_id,
        )

    async def _terminal_failure(
        self, step: TransactionStep, packet: _PacketState, error: str, journal: JournalStore, run_id: str
    ) -> None:
        await self._append(
            journal,
            run_id,
            "step_terminal_failure",
            {"step_id": step.step_id, "generation": packet.generation, "signature": packet.signature, "error": error},
            step.step_id,
        )
        raise ProgramRefused(f"step {step.step_id} finalized with program error: {error}")

    async def _append(
        self,
        journal: JournalStore,
        run_id: str,
        event: str,
        data: dict[str, Any],
        step_id: str | None,
    ) -> None:
        journal.append(run_id, event, data)
        if self.event_hook is not None:
            await self.event_hook(event, step_id)

    async def _sleep_backoff(self, delay: float, retry_after: float | None = None) -> None:
        actual = max(delay, retry_after or 0.0)
        if actual:
            await asyncio.sleep(actual)

    def _next_backoff(self, current: float) -> float:
        backoff: Backoff = self.config.backoff
        if current == 0:
            return 0
        return min(backoff.maximum_seconds, current * backoff.multiplier)


def _shortvec_size(value: int) -> int:
    """Encoded length of Solana's compact-u16 signature-count prefix."""

    if value < 0 or value > 0xFFFF:
        raise PlanError("signature count is outside compact-u16 range")
    if value < 0x80:
        return 1
    if value < 0x4000:
        return 2
    return 3
