"""Async transaction planning, durable send, confirmation, and resume core."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field, is_dataclass
from os import PathLike
from typing import Any, Mapping, Sequence

from . import health
from .journal import JournalEvent, JournalStore
from .pool import (
    EndpointNodeConfig,
    EndpointPool,
    EndpointPoolExhausted,
    EndpointRoute,
    HealthObservation,
    HealthPolicy,
    HealthSignal,
    RequestKind,
)
from .providers import RpcSendProvider, SendProvider
from .signer import MultiSigner
from .stream import StreamingPlan
from .stream_journal import (
    StreamIdentity,
    StreamIntent,
    StreamLimits,
    StreamTerminal,
)
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
    LatencyMode,
    MessageSigner,
    ReconciliationRequired,
)


@dataclass(frozen=True)
class StepOutcome:
    step_id: str
    signature: str
    confirmed_by: str
    slot: int | None
    fee_lamports: int | None
    compute_units_consumed: int | None
    optimistic: bool = False
    commitment: Commitment = Commitment.CONFIRMED


@dataclass(frozen=True)
class RunResult:
    run_id: str
    plan_digest: str
    outcomes: Mapping[str, StepOutcome]
    optimistic_steps: tuple[str, ...] = ()


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


@dataclass
class _StatusWaiter:
    route_group: str
    signature: str
    route_affinity: str | None
    future: asyncio.Future[SignatureObservation | None]


class _ConfirmationPump:
    """One coalescing, batched confirmation poller shared by every send path."""

    def __init__(self, sequencer: Sequencer):
        self._sequencer = sequencer
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[str, str], _StatusWaiter] = {}
        self._waiters: dict[tuple[str, str], list[asyncio.Future[SignatureObservation | None]]] = {}
        self._task: asyncio.Task[None] | None = None
        self._flush_tasks: set[asyncio.Task[None]] = set()

    async def status(
        self, signature: str, *, route_group: str, route_affinity: str | None = None
    ) -> SignatureObservation | None:
        key = (route_group, signature)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[SignatureObservation | None] = loop.create_future()
        async with self._lock:
            if key in self._pending:
                self._waiters[key].append(future)
            else:
                self._pending[key] = _StatusWaiter(route_group, signature, route_affinity, future)
                self._waiters[key] = [future]
            if self._task is None:
                self._schedule_flush(loop)
        return await future

    def _schedule_flush(self, loop: asyncio.AbstractEventLoop) -> None:
        task = loop.create_task(self._flush())
        self._task = task
        self._flush_tasks.add(task)
        task.add_done_callback(self._flush_tasks.discard)

    async def cancel_pending(self) -> None:
        """Cancel idle/read-only status batches when the sequencer has no work."""

        async with self._lock:
            waiters = tuple(future for group in self._waiters.values() for future in group)
            self._pending.clear()
            self._waiters.clear()
            tasks = tuple(self._flush_tasks)
            self._task = None
            for future in waiters:
                if not future.done():
                    future.cancel()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _flush(self) -> None:
        try:
            await self._sequencer.config.sleep(self._sequencer.config.status_batch_window_seconds)
            async with self._lock:
                pending = self._pending
                futures = self._waiters
                self._pending = {}
                self._waiters = {}
                self._task = None
            groups: dict[str, list[tuple[tuple[str, str], _StatusWaiter]]] = {}
            for key, waiter in pending.items():
                groups.setdefault(waiter.route_group, []).append((key, waiter))
            for route_group, entries in groups.items():
                for start in range(0, len(entries), self._sequencer.config.status_batch_size):
                    batch = entries[start : start + self._sequencer.config.status_batch_size]
                    try:
                        observations = await self._sequencer._read_status_batch(
                            [waiter.signature for _key, waiter in batch],
                            route_group=route_group,
                            route_affinity=batch[0][1].route_affinity,
                        )
                    except BaseException as exc:
                        for key, _waiter in batch:
                            for future in futures[key]:
                                if not future.done():
                                    future.set_exception(exc)
                    else:
                        for key, waiter in batch:
                            observation = observations.get(waiter.signature)
                            for future in futures[key]:
                                if not future.done():
                                    future.set_result(observation)
        finally:
            async with self._lock:
                if self._task is asyncio.current_task():
                    self._task = None
                if self._pending and self._task is None:
                    self._schedule_flush(asyncio.get_running_loop())


class Sequencer:
    """Execute dependency-aware transaction plans and resume from a JSONL journal."""

    def __init__(
        self,
        *,
        endpoints: Mapping[str, RpcEndpoint],
        signer: Signer | None = None,
        signers: Sequence[MessageSigner] = (),
        config: SequencerConfig,
        event_hook: EventHook | None = None,
        pool: EndpointPool | None = None,
        providers: Mapping[str, SendProvider] | None = None,
    ):
        self.endpoints = dict(endpoints)
        if signer is not None and signers:
            raise PlanError("inject either one signer or an ordered signer set, not both")
        self.signer = MultiSigner(signers) if signers else signer
        if self.signer is None:
            raise PlanError("at least one injected signer is required")
        self.config = config
        self.event_hook = event_hook
        for endpoint_id, endpoint in self.endpoints.items():
            if endpoint.endpoint_id != endpoint_id:
                raise PlanError(f"RPC endpoint mapping key {endpoint_id!r} does not match endpoint identity")
        nodes = [
            EndpointNodeConfig(
                endpoint=endpoint,
                sends_per_second=config.endpoint_limits[endpoint_id].sends_per_second,
                requests_per_second=config.endpoint_limits[endpoint_id].requests_per_second,
                # M3: v1 max_in_flight caps concurrent steps (enforced in
                # _select_batch); the pool gets headroom for each step's reads.
                max_in_flight=config.endpoint_limits[endpoint_id].max_in_flight * 4,
                weight=config.endpoint_limits[endpoint_id].weight,
                route_group=config.endpoint_limits[endpoint_id].route_group or endpoint_id,
            )
            for endpoint_id, endpoint in self.endpoints.items()
            if endpoint_id in config.endpoint_limits
        ]
        self.pool = pool or EndpointPool(
            nodes,
            health_policy=HealthPolicy(
                score_threshold=config.health_score_threshold,
                cooldown_seconds=config.health_cooldown_seconds,
                max_cooldown_seconds=config.health_max_cooldown_seconds,
                rate_limit_points=config.health_rate_limit_points,
                transport_error_points=config.health_transport_error_points,
            ),
            clock=config.monotonic_clock,
            default_acquire_timeout_seconds=config.pool_acquire_timeout_seconds,
        )
        self.providers = dict(providers or {"rpc": RpcSendProvider(self.endpoints)})
        if not self.providers:
            raise PlanError("at least one send provider is required")
        if any(key != provider.provider_id for key, provider in self.providers.items()):
            raise PlanError("send provider mapping keys must match provider identities")
        self._stream_provider_attempts: dict[tuple[str, str], list[_StreamProviderAttempt]] = {}
        self.unmatched_provider_failures: deque[Any] = deque(maxlen=256)
        self._attach_async_provider_failure_handlers()
        self._active_streams = 0
        self._active_fixed_runs = 0
        self._expected_genesis: str | None = None
        self._confirmation_pump = _ConfirmationPump(self)
        self._validate_config()

    def _attach_async_provider_failure_handlers(self) -> None:
        """Chain TPU-style asynchronous errors into active stream journals."""

        for provider in self.providers.values():
            if not callable(getattr(provider, "drain_failures", None)) or not hasattr(
                provider, "_failure_handler"
            ):
                continue
            # Package A exposes failure_handler at construction but has no
            # registration method; preserve its existing callback while adding
            # this sequencer's stream-journal observer.
            previous = provider._failure_handler

            async def chained(failure, previous=previous):
                try:
                    if previous is not None:
                        result = previous(failure)
                        if inspect.isawaitable(result):
                            await result
                finally:
                    await self._handle_async_provider_failure(failure)

            provider._failure_handler = chained

    def _register_stream_provider_attempt(self, attempt: _StreamProviderAttempt) -> None:
        key = (attempt.provider_id, attempt.signature)
        self._stream_provider_attempts.setdefault(key, []).append(attempt)

    def _forget_stream_provider_attempt(self, attempt: _StreamProviderAttempt) -> None:
        key = (attempt.provider_id, attempt.signature)
        values = self._stream_provider_attempts.get(key, [])
        if attempt in values:
            values.remove(attempt)
        if not values:
            self._stream_provider_attempts.pop(key, None)

    async def _handle_async_provider_failure(self, failure: Any) -> None:
        provider_id = getattr(failure, "provider_id", None)
        signature = getattr(failure, "signature", None)
        attempts = self._stream_provider_attempts.get((provider_id, signature), [])
        attempt = next(
            (item for item in attempts if not item.failure_recorded and item.failure is None),
            None,
        )
        if attempt is None:
            self.unmatched_provider_failures.append(failure)
            return
        attempt.failure = failure
        if attempt.acknowledged:
            await self._record_async_provider_failure(attempt)

    async def _record_async_provider_failure(self, attempt: _StreamProviderAttempt) -> None:
        async with attempt.failure_lock:
            if attempt.failure is None or attempt.failure_recorded or not attempt.acknowledged:
                return
            try:
                await attempt.plan.record_late_provider_failure(
                    attempt.step_id,
                    attempt.generation,
                    attempt.attempt,
                    provider_id=attempt.provider_id,
                    endpoint_id=attempt.endpoint_id,
                    route_group=attempt.route_group,
                    route=attempt.route,
                    disposition=attempt.disposition,
                    route_affinity=attempt.route_affinity,
                    detail=str(getattr(attempt.failure, "reason", "asynchronous provider failure"))[:512],
                )
            except Exception:
                if any(
                    event.step_id == attempt.step_id
                    and event.generation == attempt.generation
                    and event.data.get("attempt") == attempt.attempt
                    for event in attempt.plan.provider_failures
                ):
                    attempt.failure_recorded = True
                    return
                raise
            attempt.failure_recorded = True

    async def _release_stream_provider_attempts(self, plan: StreamingPlan) -> None:
        for attempts in tuple(self._stream_provider_attempts.values()):
            for attempt in tuple(attempts):
                if attempt.plan is plan:
                    await self._record_async_provider_failure(attempt)
                    self._forget_stream_provider_attempt(attempt)

    async def _maybe_cancel_confirmation_pump(self) -> None:
        if self._active_streams == 0 and self._active_fixed_runs == 0:
            await self._confirmation_pump.cancel_pending()

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
        if self.config.pool_acquire_timeout_seconds <= 0:
            raise PlanError("pool acquire timeout must be positive")
        if self.config.health_score_threshold <= 0 or self.config.health_cooldown_seconds <= 0:
            raise PlanError("health threshold and base cooldown must be positive")
        if self.config.health_max_cooldown_seconds < self.config.health_cooldown_seconds:
            raise PlanError("maximum cooldown must be at least the base cooldown")
        if self.config.status_batch_window_seconds < 0 or self.config.status_batch_size <= 0:
            raise PlanError("status batch window and size must be non-negative and positive")
        if (
            self.config.optimistic_max_depth <= 0
            or self.config.optimistic_max_seconds <= 0
            or self.config.optimistic_drop_status_misses <= 0
        ):
            raise PlanError("optimistic depth and age bounds must be positive")
        if self.config.stream_journal_quota_bytes < 4096 or self.config.stream_checkpoint_retention <= 0:
            raise PlanError("stream quota and checkpoint retention must be positive")
        if self.config.backoff.initial_seconds < 0 or self.config.backoff.maximum_seconds < 0:
            raise PlanError("backoff values cannot be negative")
        if self.config.backoff.multiplier < 1:
            raise PlanError("backoff multiplier must be at least 1")
        if set(self.endpoints) != set(self.config.endpoint_limits):
            raise PlanError("every configured endpoint limit must match exactly one RPC endpoint")
        snapshots = self.pool._nodes
        if set(snapshots) != set(self.endpoints):
            raise PlanError("endpoint pool nodes must match the supplied RPC endpoint set")

    async def submit(self, plan: TransactionPlan, journal: JournalStore) -> RunResult:
        """Start a new run. The journal must be empty."""

        self._validate_plan(plan)
        self._expected_genesis = plan.genesis_hash
        await self._validate_cluster_genesis(plan.genesis_hash)
        if journal.events():
            raise JournalError("submit requires a fresh empty journal; use resume")
        run_id = str(uuid.uuid4())
        plan_digest = self._plan_digest(plan)
        header = {
            "schema_version": 1,
            "plan_digest": plan_digest,
            "genesis_hash": plan.genesis_hash,
            "program_id": plan.program_id,
            "destination_accounts": sorted(plan.destination_accounts),
            "signer_public_key": self.signer.public_key,
            "signer_signature_count": self.signer.signature_count,
            "signer_signature_size_bytes": self.signer.signature_size_bytes,
            "steps": [self._step_manifest(step) for step in sorted(plan.steps, key=lambda s: s.step_id)],
        }
        signer_public_keys = self._plan_signer_public_keys(plan)
        if len(signer_public_keys) > 1:
            header["signer_public_keys"] = list(signer_public_keys)
        await self._append(
            journal,
            run_id,
            "run_started",
            header,
            None,
        )
        self._active_fixed_runs += 1
        try:
            return await self._drive(plan, journal, run_id, plan_digest)
        finally:
            self._active_fixed_runs -= 1
            await self._maybe_cancel_confirmation_pump()

    async def resume(self, plan: TransactionPlan, journal: JournalStore) -> RunResult:
        """Validate plan and signer identity, then continue unresolved journal rows."""

        self._validate_plan(plan)
        self._expected_genesis = plan.genesis_hash
        await self._validate_cluster_genesis(plan.genesis_hash)
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
        signer_public_keys = self._plan_signer_public_keys(plan)
        if len(signer_public_keys) > 1 and events[0].data.get("signer_public_keys") != list(signer_public_keys):
            raise JournalError("journal signer set does not match the injected signer set")
        self._active_fixed_runs += 1
        try:
            return await self._drive(plan, journal, replay.run_id, plan_digest)
        finally:
            self._active_fixed_runs -= 1
            await self._maybe_cancel_confirmation_pump()

    @property
    def route_policy_digest(self) -> str:
        """Canonical digest for the pool caps, routing groups, and provider kinds."""

        nodes = [
            {
                "endpoint_id": node.config.endpoint_id,
                "route_group": node.config.route_group,
                "sends_per_second": node.config.sends_per_second,
                "requests_per_second": node.config.requests_per_second,
                "max_in_flight": node.config.max_in_flight,
                "weight": node.config.weight,
            }
            for node in sorted(self.pool._nodes.values(), key=lambda item: item.config.endpoint_id)
        ]
        providers = [
            {
                "provider_id": provider_id,
                "type": f"{provider.__class__.__module__}.{provider.__class__.__qualname__}",
                "config": _plain_value(getattr(provider, "config", None)),
            }
            for provider_id, provider in sorted(self.providers.items())
        ]
        encoded = json.dumps(
            {"nodes": nodes, "providers": providers},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    async def _validate_cluster_genesis(self, genesis_hash: str, *, force: bool = False) -> None:
        if not force and len(self.endpoints) == 1 and all(
            not callable(getattr(endpoint, "get_genesis_hash", None))
            for endpoint in self.endpoints.values()
        ) and all(isinstance(provider, RpcSendProvider) for provider in self.providers.values()):
            return
        for endpoint_id, endpoint in sorted(self.endpoints.items()):
            get_genesis = getattr(endpoint, "get_genesis_hash", None)
            if callable(get_genesis):
                actual = await self._rpc_call("get_genesis_hash", endpoint_id=endpoint_id)
            else:
                lease = await self._rpc_call(
                    "latest_blockhash",
                    genesis_hash,
                    self.config.blockhash_lifetime_seconds,
                    endpoint_id=endpoint_id,
                )
                actual = lease.genesis_hash
            if actual != genesis_hash:
                raise PlanError(
                    f"RPC endpoint {endpoint_id!r} belongs to genesis {actual!r}, expected {genesis_hash!r}"
                )

    async def open_stream(
        self,
        identity: StreamIdentity,
        journal_path: str,
        step_factory,
        *,
        limits: StreamLimits | None = None,
    ) -> SequencerStream:
        """Open a durable stream and immediately reconcile its pending intents."""

        self._expected_genesis = identity.genesis_hash
        configured_signers = tuple(getattr(self.signer, "public_keys", (self.signer.public_key,)))
        if set(configured_signers) != set(identity.signer_public_keys):
            raise PlanError("stream signer identity does not match the injected signer set")
        if identity.route_policy_digest != self.route_policy_digest:
            raise PlanError("stream route policy digest does not match the configured pool and providers")
        await self._validate_cluster_genesis(identity.genesis_hash, force=True)
        stream_limits = limits or StreamLimits(max_journal_bytes=self.config.stream_journal_quota_bytes)
        plan = await StreamingPlan.open(identity, journal_path, limits=stream_limits)
        session = SequencerStream(self, plan, step_factory)
        self._active_streams += 1
        try:
            await session._start()
        except BaseException:
            self._active_streams -= 1
            await plan.close()
            await self._maybe_cancel_confirmation_pump()
            raise
        return session

    def _validate_plan(self, plan: TransactionPlan) -> None:
        if not plan.genesis_hash or not plan.program_id or not plan.signer_public_key:
            raise PlanError("plan must bind genesis, program, and signer public identities")
        signer_public_keys = self._plan_signer_public_keys(plan)
        injected_signers = tuple(getattr(self.signer, "public_keys", (self.signer.public_key,)))
        if plan.signer_public_key != self.signer.public_key or signer_public_keys != injected_signers:
            raise PlanError("plan signer public keys do not match the injected signer set and order")
        if not plan.steps:
            raise PlanError("plan must contain at least one transaction step")
        by_id: dict[str, TransactionStep] = {}
        for step in plan.steps:
            if not step.step_id or step.step_id in by_id:
                raise PlanError(f"step ids must be non-empty and unique: {step.step_id!r}")
            by_id[step.step_id] = step
            if step.endpoint_id not in self.endpoints:
                raise PlanError(f"unknown RPC endpoint {step.endpoint_id!r}")
            if step.provider_id is not None and step.provider_id not in self.providers:
                raise PlanError(f"unknown send provider {step.provider_id!r}")
            if step.route_group is not None and not any(
                node.config.route_group == step.route_group for node in self.pool._nodes.values()
            ):
                raise PlanError(f"unknown route group {step.route_group!r}")
            if step.route_affinity is not None and not step.route_affinity:
                raise PlanError("route affinity must be non-empty when provided")
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
        manifest = {
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
        if step.route_group is not None:
            manifest["route_group"] = step.route_group
        if step.route_affinity is not None:
            manifest["route_affinity"] = step.route_affinity
        if step.provider_id is not None:
            manifest["provider_id"] = step.provider_id
        return manifest

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
        signer_public_keys = self._plan_signer_public_keys(plan)
        if len(signer_public_keys) > 1:
            manifest["signer_public_keys"] = list(signer_public_keys)
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _plan_signer_public_keys(plan: TransactionPlan) -> tuple[str, ...]:
        return plan.signer_public_keys or (plan.signer_public_key,)

    def _route_group(self, step: TransactionStep) -> str:
        if step.route_group is not None:
            return step.route_group
        limits = self.config.endpoint_limits[step.endpoint_id]
        return limits.route_group or step.endpoint_id

    async def _report_exception(self, lease, error: Exception) -> None:
        try:
            observation = health.classify(error)
        except TypeError:
            return
        await lease.observe(observation)

    async def _acquire_lease(
        self,
        kind: RequestKind,
        *,
        route_group: str | None = None,
        endpoint_id: str | None = None,
        route_affinity: str | None = None,
    ):
        while True:
            lease = await self.pool.acquire(
                kind,
                route_group=route_group,
                endpoint_id=endpoint_id,
                route_affinity=route_affinity,
            )
            if not lease.route.is_probe:
                return lease
            try:
                get_health = getattr(lease.endpoint, "get_health", None)
                if callable(get_health):
                    await get_health()
                else:
                    if self._expected_genesis is None:
                        raise PlanError("cannot probe an endpoint before binding a genesis hash")
                    probe_lease = await lease.endpoint.latest_blockhash(
                        self._expected_genesis, self.config.blockhash_lifetime_seconds
                    )
                    if probe_lease.genesis_hash != self._expected_genesis:
                        raise PlanError("endpoint probe returned a lease for a different genesis")
            except Exception as exc:
                try:
                    observation = health.classify(exc)
                except TypeError:
                    observation = HealthObservation(HealthSignal.UNHEALTHY)
                await lease.observe(observation)
                await lease.close()
                continue
            else:
                await lease.observe(HealthObservation(HealthSignal.SUCCESS))
                await lease.close()

    async def _rpc_call(
        self,
        method_name: str,
        *args: Any,
        endpoint_id: str | None = None,
        route_group: str | None = None,
        route_affinity: str | None = None,
        **kwargs: Any,
    ) -> Any:
        lease = await self._acquire_lease(
            RequestKind.RPC,
            route_group=route_group,
            endpoint_id=endpoint_id,
            route_affinity=route_affinity,
        )
        started = self.config.monotonic_clock()
        try:
            result = await getattr(lease.endpoint, method_name)(*args, **kwargs)
        except Exception as exc:
            await self._report_exception(lease, exc)
            raise
        else:
            await lease.observe(
                HealthObservation(
                    HealthSignal.SUCCESS,
                    latency_seconds=max(0.0, self.config.monotonic_clock() - started),
                )
            )
            return result
        finally:
            await lease.close()

    def _pooled_endpoint(self, *, route_group: str, route_affinity: str | None = None):
        return _PooledRpcEndpoint(self, route_group, route_affinity)

    async def _read_status_batch(
        self,
        signatures: Sequence[str],
        *,
        route_group: str,
        route_affinity: str | None = None,
    ) -> dict[str, SignatureObservation | None]:
        lease = await self._acquire_lease(
            RequestKind.RPC,
            route_group=route_group,
            route_affinity=route_affinity,
        )
        started = self.config.monotonic_clock()
        try:
            batch_reader = getattr(lease.endpoint, "signature_statuses", None)
            if callable(batch_reader):
                result = await batch_reader(signatures)
            else:
                values = await asyncio.gather(
                    *(lease.endpoint.signature_status(signature) for signature in signatures)
                )
                result = dict(zip(signatures, values, strict=True))
        except Exception as exc:
            await self._report_exception(lease, exc)
            raise
        else:
            if not isinstance(result, Mapping) or any(signature not in result for signature in signatures):
                raise JournalError("RPC returned an incomplete batched signature status result")
            await lease.observe(
                HealthObservation(
                    HealthSignal.SUCCESS,
                    latency_seconds=max(0.0, self.config.monotonic_clock() - started),
                )
            )
            return dict(result)
        finally:
            await lease.close()

    async def _send_packet(self, step: TransactionStep, packet: _PacketState, lease=None):
        provider_id = step.provider_id or ("rpc" if "rpc" in self.providers else next(iter(self.providers)))
        provider = self.providers[provider_id]
        route_group = self._route_group(step)
        if lease is None:
            lease = await self._acquire_lease(
                RequestKind.SEND,
                route_group=route_group,
                route_affinity=step.route_affinity or step.step_id,
            )
        started = self.config.monotonic_clock()
        try:
            receipt = await provider.send_raw(packet.raw_bytes, packet.signature, lease.route)
        except Exception as exc:
            await self._report_exception(lease, exc)
            raise
        else:
            await lease.observe(
                HealthObservation(
                    HealthSignal.SUCCESS,
                    latency_seconds=max(0.0, self.config.monotonic_clock() - started),
                )
            )
            self.pool.remember_affinity(step.route_affinity or step.step_id, lease.endpoint_id)
            return receipt
        finally:
            await lease.close()

    @staticmethod
    def _is_transport_exception(error: Exception) -> bool:
        try:
            health.classify(error)
        except TypeError:
            return False
        return True

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
        step_cap = min(
            self.config.max_batch_size,
            sum(limits.max_in_flight for limits in self.config.endpoint_limits.values()) or self.config.max_batch_size,
        )
        for step in ready:
            if len(batch) >= step_cap:
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
        route_group = self._route_group(step)
        endpoint = self._pooled_endpoint(route_group=route_group, route_affinity=step.route_affinity or step.step_id)
        while True:
            replay = _ReplayState.from_events(journal.events())
            if step.step_id in replay.outcomes:
                return
            if step.step_id in replay.terminal_errors:
                raise ProgramRefused(replay.terminal_errors[step.step_id])
            packets = replay.packets.get(step.step_id, [])
            if not packets:
                packet = await self._build_and_sign(step, journal, run_id, 0)
            else:
                packet = packets[-1]

            # A signed packet that was never handed to an endpoint cannot have
            # landed. It may safely be replaced after its lease expires.
            if self._packet_lease_expired(packet) and packet.attempts == 0:
                packet = await self._build_and_sign(step, journal, run_id, packet.generation + 1)
                continue

            status: SignatureObservation | None = None
            status_error: RpcError | None = None
            try:
                status = await self._confirmation_pump.status(
                    packet.signature,
                    route_group=route_group,
                    route_affinity=step.route_affinity or step.step_id,
                )
            except Exception as exc:
                if not self._is_transport_exception(exc):
                    raise
                status_error = exc  # type: ignore[assignment]
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
                landed = {Commitment.CONFIRMED, Commitment.FINALIZED}
                if self.config.latency_mode is LatencyMode.PROCESSED:
                    # Latency mode: a clean processed status completes the step
                    # and releases its dependents (rollback risk accepted).
                    landed = landed | {Commitment.PROCESSED}
                if status.error is None and status.commitment in landed:
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
                except Exception as exc:
                    if not self._is_transport_exception(exc):
                        raise
                    postcondition_error = exc  # type: ignore[assignment]
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
                    packet = await self._build_and_sign(step, journal, run_id, packet.generation + 1)
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
                        packet = await self._build_and_sign(step, journal, run_id, packet.generation + 1)
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
                # M3: the pool lease comes before the attempt row, so a pool
                # timeout is never counted as a send attempt.
                try:
                    send_lease = await self._acquire_lease(
                        RequestKind.SEND,
                        route_group=self._route_group(step),
                        route_affinity=step.route_affinity or step.step_id,
                    )
                except EndpointPoolExhausted:
                    await self._sleep_backoff(backoff_delay)
                    backoff_delay = self._next_backoff(backoff_delay)
                    continue
                attempt = packet.attempts + 1
                await self._append(
                    journal,
                    run_id,
                    "send_attempt_started",
                    {"step_id": step.step_id, "generation": packet.generation, "attempt": attempt},
                    step.step_id,
                )
                try:
                    # The intent, signature, and attempt row are durable before
                    # acquiring the final send lease. The lease then crosses
                    # directly into the selected provider, for RPC and TPU alike.
                    receipt = await self._send_packet(step, packet, send_lease)
                except BlockhashExpired as exc:
                    await self._append(
                        journal,
                        run_id,
                        "send_error",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "error_class": type(exc).__name__,
                            "message": str(exc)[:500],
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
                            "message": str(exc)[:500],
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
                            "message": str(exc)[:500],
                            "retry_after": None,
                        },
                        step.step_id,
                    )
                    await self._sleep_backoff(backoff_delay)
                    backoff_delay = self._next_backoff(backoff_delay)
                    continue
                except EndpointPoolExhausted as exc:
                    await self._append(
                        journal,
                        run_id,
                        "send_error",
                        {
                            "step_id": step.step_id,
                            "generation": packet.generation,
                            "error_class": type(exc).__name__,
                            "message": str(exc)[:500],
                            "retry_after": None,
                        },
                        step.step_id,
                    )
                    await self._sleep_backoff(backoff_delay)
                    backoff_delay = self._next_backoff(backoff_delay)
                    continue
                except AmbiguousFate as exc:
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
                            "reason": str(exc),
                        },
                        step.step_id,
                    )
                    raise
                except Exception as exc:
                    if self._is_transport_exception(exc):
                        await self._append(
                            journal,
                            run_id,
                            "send_error",
                            {
                                "step_id": step.step_id,
                                "generation": packet.generation,
                                "error_class": type(exc).__name__,
                            "message": str(exc)[:500],
                                "retry_after": getattr(exc, "retry_after", None),
                            },
                            step.step_id,
                        )
                        await self._sleep_backoff(backoff_delay, getattr(exc, "retry_after", None))
                        backoff_delay = self._next_backoff(backoff_delay)
                        continue
                    failure_class = getattr(getattr(exc, "failure_class", None), "value", None)
                    if failure_class == "ambiguous":
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
                                "reason": str(exc),
                            },
                            step.step_id,
                        )
                    raise
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
        journal: JournalStore,
        run_id: str,
        generation: int,
    ) -> _PacketState:
        backoff_delay = self.config.backoff.initial_seconds
        while True:
            try:
                lease = await self._rpc_call(
                    "latest_blockhash",
                    self._active_genesis_hash(journal),
                    self.config.blockhash_lifetime_seconds,
                    route_group=self._route_group(step),
                    route_affinity=step.route_affinity or step.step_id,
                )
            except Exception as exc:
                # M3: pool exhaustion while fetching the build blockhash is a
                # wait, not a run abort.
                if not (isinstance(exc, EndpointPoolExhausted) or self._is_transport_exception(exc)):
                    raise
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
        # M2 (open): a lagging load-balanced node can report BlockhashExpired
        # for a fresh blockhash; the tests still treat the report as proof.
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
            await self.config.sleep(actual)

    def _next_backoff(self, current: float) -> float:
        backoff: Backoff = self.config.backoff
        if current == 0:
            return 0
        return min(backoff.maximum_seconds, current * backoff.multiplier)


@dataclass(frozen=True)
class _OptimisticState:
    lane: tuple[str, ...]
    since: float
    depth: int
    signature: str
    generation: int


@dataclass
class _StreamProviderAttempt:
    plan: StreamingPlan
    step_id: str
    generation: int
    signature: str
    attempt: int
    provider_id: str
    endpoint_id: str
    route_group: str
    route_affinity: str | None
    route: Any
    disposition: str | None = None
    acknowledged: bool = False
    failure: Any | None = None
    failure_recorded: bool = False
    failure_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)


class SequencerStream:
    """Live scheduler over Package B's durable ``StreamingPlan`` API."""

    def __init__(self, sequencer: Sequencer, plan: StreamingPlan, step_factory):
        self.sequencer = sequencer
        self.plan = plan
        self.step_factory = step_factory
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._intents: dict[str, tuple[int, StreamIntent]] = {}
        self._steps: dict[str, TransactionStep] = {}
        self._lanes: dict[str, tuple[str, ...]] = {}
        self._optimistic: dict[str, _OptimisticState] = {}
        self._permissions: dict[str, tuple[float, int, str, int, frozenset[str]]] = {}
        self._causal: dict[str, tuple[float, int, frozenset[str]]] = {}
        self._dropped: set[str] = set()
        self._invalidated: set[str] = set()
        self._failures: dict[str, BaseException] = {}
        self._reconciliation_recorded: set[str] = set()
        # C1: lane predecessors are fixed at registration; completed steps stay
        # satisfied after the journal prunes their terminal summaries.
        self._latest_by_lock: dict[str, tuple[int, str]] = {}
        self._lane_prev: dict[str, frozenset[str]] = {}
        self._completed: set[str] = set()
        self._resumed_seen: dict[tuple[str, int], float] = {}
        self._last_observations: dict[tuple[str, int], tuple[Any, ...]] = {}
        self._leases: dict[tuple[str, int], BlockhashLease] = {}
        self._conditions = asyncio.Condition()
        self._backoff = sequencer.config.backoff.initial_seconds
        self._closed = False
        self._released = False

    @property
    def identity(self) -> StreamIdentity:
        return self.plan.identity

    @property
    def pending_count(self) -> int:
        return self.plan.pending_count

    @property
    def observations(self):
        return self.plan.observations

    @property
    def optimistic_steps(self) -> tuple[str, ...]:
        """Pending steps whose latest journaled observation is only processed."""

        return self.plan.optimistic_steps

    async def _start(self) -> None:
        for sequence, intent in self.plan.pending_intents:
            self._intents[intent.step_id] = (sequence, intent)
            self._register(sequence, intent)
        for packet in await self.plan.unresolved_packets():
            for prior_attempt in packet.attempts:
                if (
                    prior_attempt.outcome != "acknowledged"
                    or not prior_attempt.provider_id
                    or not prior_attempt.endpoint_id
                    or not prior_attempt.route_group
                ):
                    continue
                self.sequencer._register_stream_provider_attempt(
                    _StreamProviderAttempt(
                        self.plan,
                        packet.step_id,
                        packet.generation,
                        packet.signature,
                        prior_attempt.number,
                        prior_attempt.provider_id,
                        prior_attempt.endpoint_id,
                        prior_attempt.route_group,
                        prior_attempt.route_affinity,
                        EndpointRoute(
                            prior_attempt.endpoint_id,
                            prior_attempt.route_group,
                            prior_attempt.route_affinity,
                        ),
                        disposition=prior_attempt.disposition,
                        acknowledged=True,
                    )
                )
        for event in self.plan.lifecycle_events:
            if event.event == "step_dropped":
                self._dropped.add(event.step_id)
            elif event.event == "reconciliation_required":
                self._reconciliation_recorded.add(event.step_id)
        for row in self.plan.observations:
            self._last_observations[(row.step_id, row.generation)] = (
                row.status_commitment,
                row.status_error,
                row.slot,
                row.postcondition_satisfied,
                row.postcondition_digest,
            )
        self._rebuild_invalidated()
        for sequence, intent in self.plan.pending_intents:
            self._schedule(sequence, intent)

    async def append(self, intent: StreamIntent):
        if self._closed:
            raise JournalError("stream scheduler is closed")
        if self._failures:
            raise next(iter(self._failures.values()))
        # H2: a failed step never frees its pending slot, so a full pending
        # window must surface the failure instead of waiting forever.
        append_task = asyncio.ensure_future(self.plan.append(intent))
        while not append_task.done():
            await asyncio.wait({append_task}, timeout=0.25)
            if self._failures and not append_task.done():
                append_task.cancel()
                raise next(iter(self._failures.values()))
        receipt = append_task.result()
        self._intents[intent.step_id] = (receipt.sequence, intent)
        self._register(receipt.sequence, intent)
        if not receipt.already_present or intent.step_id not in self._tasks:
            if intent.step_id not in self.plan.terminal_summaries:
                self._schedule(receipt.sequence, intent)
        async with self._conditions:
            self._conditions.notify_all()
        return receipt

    async def checkpoint(self, through_sequence: int | None = None):
        return await self.plan.checkpoint(through_sequence)

    async def decide(
        self,
        step_id: str,
        decision: str,
        evidence_digest: str,
    ) -> None:
        """H2: act on the application's reconciliation choice for a dropped parent.

        ``continue`` keeps the original signed bytes authoritative and resumes
        polling them; ``rebuild`` authorizes a fresh generation; ``abandon``
        leaves the branch failed. The choice is journaled before any state
        changes, then the dropped parent and its invalidated descendants are
        cleared and rescheduled.
        """

        if decision not in ("abandon", "continue", "rebuild"):
            raise ValueError("decision must be abandon, continue, or rebuild")
        if step_id not in self._dropped:
            raise JournalError(f"step {step_id} is not a dropped stream parent")
        packets = [packet for packet in await self.plan.unresolved_packets() if packet.step_id == step_id]
        generation = max((packet.generation for packet in packets), default=0)
        await self.plan.record_reconciliation_decision(
            step_id, generation, decision=decision, evidence_digest=evidence_digest
        )
        if decision == "abandon":
            return
        if decision == "rebuild" and packets:
            await self.plan.authorize_rebuild(step_id, generation, evidence_digest)
        affected = {step_id, *self._invalidated}
        self._dropped.discard(step_id)
        self._rebuild_invalidated()
        for affected_id in affected:
            self._failures.pop(affected_id, None)
            self._reconciliation_recorded.discard(affected_id)
            entry = self._intents.get(affected_id)
            if entry is not None and affected_id not in self.plan.terminal_summaries:
                self._schedule(entry[0], entry[1])
        async with self._conditions:
            self._conditions.notify_all()

    async def close_input(self, *, wait_for_pending: bool = False) -> None:
        await self.plan.close_input(wait_for_pending=wait_for_pending)

    async def wait(self) -> RunResult:
        """Wait for current work to reach stable outcomes or surface reconciliation."""

        tasks = tuple(self._tasks.values())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        failure = next((result for result in results if isinstance(result, BaseException)), None)
        if failure is not None:
            raise failure
        return self.result()

    def result(self) -> RunResult:
        outcomes: dict[str, StepOutcome] = {}
        for step_id, terminal in self.plan.terminal_summaries.items():
            if terminal.outcome == "confirmed":
                outcomes[step_id] = StepOutcome(
                    step_id,
                    terminal.signature,
                    "signature",
                    terminal.slot,
                    None,
                    None,
                    optimistic=False,
                    commitment=Commitment(terminal.commitment),
                )
        observations = self.plan.observations
        for step_id in self.optimistic_steps:
            if step_id in outcomes:
                continue
            observation = next(
                (
                    row
                    for row in reversed(observations)
                    if row.step_id == step_id and row.label == "optimistic"
                ),
                None,
            )
            if observation is None:
                continue
            outcomes[step_id] = StepOutcome(
                step_id,
                observation.signature,
                "signature",
                observation.slot,
                None,
                None,
                optimistic=True,
                commitment=Commitment.PROCESSED,
            )
        optimistic_steps = tuple(sorted(step_id for step_id, outcome in outcomes.items() if outcome.optimistic))
        return RunResult(self.identity.run_id, self.plan.sequence_digest, outcomes, optimistic_steps)

    async def close(self) -> None:
        if self._released:
            return
        self._closed = True
        current = asyncio.current_task()
        tasks = [task for task in self._tasks.values() if task is not current and not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.sequencer._release_stream_provider_attempts(self.plan)
        await self.plan.close()
        self._released = True
        self.sequencer._active_streams -= 1
        await self.sequencer._maybe_cancel_confirmation_pump()

    def _schedule(self, sequence: int, intent: StreamIntent) -> None:
        current = self._tasks.get(intent.step_id)
        if current is None or current.done():
            self._tasks[intent.step_id] = asyncio.create_task(self._run_step(sequence, intent))

    async def _make_step(self, intent: StreamIntent) -> TransactionStep:
        step = self.step_factory(intent)
        if inspect.isawaitable(step):
            step = await step
        if not isinstance(step, TransactionStep):
            raise PlanError("stream step factory must return a TransactionStep")
        if (
            step.step_id != intent.step_id
            or set(step.dependencies) != set(intent.dependencies)
            or tuple(sorted(step.write_locks)) != tuple(sorted(intent.write_locks))
            or step.compute_class != intent.compute_class
            or step.compute_unit_limit != intent.compute_unit_limit
            or step.intent_digest != intent.intent_digest
            or step.recovery_policy_digest != intent.recovery_policy_digest
            or step.max_packet_bytes != intent.max_packet_bytes
        ):
            raise PlanError("stream callback step differs from its fsynced intent")
        route_group = step.route_group or intent.route_group
        if route_group != intent.route_group:
            raise PlanError("stream callback route group differs from its intent")
        if step.endpoint_id not in self.sequencer.endpoints:
            raise PlanError(f"stream step names unknown endpoint {step.endpoint_id!r}")
        configured_group = self.sequencer._route_group(step)
        if configured_group != intent.route_group:
            raise PlanError("stream step endpoint is not in the intent route group")
        if step.route_affinity != intent.route_affinity and step.route_affinity is not None:
            raise PlanError("stream callback route affinity differs from its intent")
        if self.sequencer.config.latency_mode is LatencyMode.PROCESSED and step.reconcile_dropped is None:
            raise PlanError("processed stream steps require an application reconciliation callback")
        if step.route_group is None or step.route_affinity is None:
            from dataclasses import replace

            step = replace(
                step,
                route_group=route_group,
                route_affinity=step.route_affinity or intent.route_affinity,
            )
        return step

    def _lane_for(self, step: TransactionStep) -> tuple[str, ...]:
        if step.write_locks:
            return tuple(sorted(step.write_locks))
        for dependency in step.dependencies:
            if dependency in self._lanes:
                return self._lanes[dependency]
        return (f"step:{step.step_id}",)

    def _register(self, sequence: int, intent: StreamIntent) -> None:
        if intent.step_id in self._lane_prev:
            return
        prev = set()
        for lock in intent.write_locks:
            latest = self._latest_by_lock.get(lock)
            if latest is not None and latest[0] < sequence:
                prev.add(latest[1])
            if latest is None or latest[0] < sequence:
                self._latest_by_lock[lock] = (sequence, intent.step_id)
        self._lane_prev[intent.step_id] = frozenset(prev)

    def _dependencies_for(self, sequence: int, intent: StreamIntent) -> tuple[str, ...]:
        dependencies = set(intent.dependencies)
        dependencies.update(self._lane_prev.get(intent.step_id, ()))
        return tuple(sorted(dependencies))

    def _forget(self, step_id: str) -> None:
        # M4: bounded memory; keep only what a later step can still reference.
        self._completed.add(step_id)
        if len(self._completed) > 4 * max(1, getattr(self.plan, "max_pending_steps", 128)):
            keep = {sid for _, sid in self._latest_by_lock.values()}
            for old in list(self._completed):
                if old in keep:
                    continue
                if not any(old in prev for prev in self._lane_prev.values()):
                    for table in (self._intents, self._steps, self._lanes, self._lane_prev, self._causal):
                        table.pop(old, None)

    async def _wait_dependencies(self, sequence: int, intent: StreamIntent, step: TransactionStep):
        dependencies = self._dependencies_for(sequence, intent)
        while True:
            terminals = self.plan.terminal_summaries
            if any(
                dep in self._dropped or dep in self._invalidated or dep in self._failures
                for dep in dependencies
            ):
                return False, dependencies
            if any(dep in terminals and terminals[dep].outcome == "failed" for dep in dependencies):
                return False, dependencies
            unresolved = [dep for dep in dependencies if dep not in terminals and dep not in self._completed]
            causes: list[tuple[float, int, str, int, frozenset[str]]] = []
            waiting_for_parent = False
            for dependency in dependencies:
                causal = self._causal.get(dependency)
                if causal is not None:
                    since, depth, roots = causal
                    active_roots = frozenset(root for root in roots if root not in terminals)
                    if active_roots:
                        state = self._optimistic.get(dependency)
                        causes.append(
                            (
                                since,
                                depth,
                                state.signature if state else dependency,
                                state.generation if state else 0,
                                active_roots,
                            )
                        )
                if dependency in terminals or dependency in self._completed:
                    continue
                optimistic = self._optimistic.get(dependency)
                if optimistic is None:
                    waiting_for_parent = True
                elif causal is None:
                    roots = frozenset({dependency})
                    causes.append((optimistic.since, optimistic.depth, optimistic.signature, optimistic.generation, roots))
            if waiting_for_parent:
                pass
            elif causes and self.sequencer.config.latency_mode is LatencyMode.PROCESSED:
                since = min(item[0] for item in causes)
                depth = max(item[1] + 1 for item in causes)
                roots = frozenset(root for item in causes for root in item[4])
                if (
                    depth <= self.sequencer.config.optimistic_max_depth
                    and self.sequencer.config.monotonic_clock() - since
                    <= self.sequencer.config.optimistic_max_seconds
                ):
                    source = max(causes, key=lambda item: item[1])
                    permission = (since, depth, source[2], source[3], roots)
                    self._permissions[step.step_id] = permission
                    self._causal[step.step_id] = (since, depth, roots)
                    return True, dependencies
            elif not causes and not waiting_for_parent:
                self._causal.pop(step.step_id, None)
                return True, dependencies
            async with self._conditions:
                try:
                    await asyncio.wait_for(
                        self._conditions.wait(),
                        timeout=max(self.sequencer.config.confirmation_poll_seconds, 0.01),
                    )
                except TimeoutError:
                    pass

    async def _run_step(self, sequence: int, intent: StreamIntent) -> None:
        try:
            if intent.step_id in self.plan.terminal_summaries:
                return
            step = await self._make_step(intent)
            self._steps[step.step_id] = step
            self._lanes[step.step_id] = self._lane_for(step)
            ready, dependencies = await self._wait_dependencies(sequence, intent, step)
            if not ready:
                await self._record_reconciliation_required(step, intent, "an upstream step failed or invalidated this lane")
                packets = [packet for packet in await self.plan.unresolved_packets() if packet.step_id == step.step_id]
                if packets:
                    packet = max(packets, key=lambda item: item.generation)
                    postcondition = await self._reconcile_existing_packet(step, packet)
                    if step.reconcile_dropped is not None:
                        endpoint = self.sequencer._pooled_endpoint(
                            route_group=intent.route_group, route_affinity=intent.route_affinity
                        )
                        await step.reconcile_dropped(endpoint, packet.signature, postcondition)
                raise ReconciliationRequired(f"step {step.step_id} requires application reconciliation")
            try:
                async with asyncio.timeout(self.sequencer.config.per_step_time_cap_seconds):
                    await self._drive_stream_step(sequence, intent, step, dependencies)
            except TimeoutError as exc:
                # H3: the cap surfaces as a journaled reconciliation, never a bare TimeoutError.
                await self._record_reconciliation_required(
                    step, intent, f"step exceeded its {self.sequencer.config.per_step_time_cap_seconds}s time cap"
                )
                raise StepTimeCapExceeded(f"stream step {step.step_id} exceeded its time cap") from exc
            self._forget(intent.step_id)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._failures[intent.step_id] = exc
            raise
        finally:
            async with self._conditions:
                self._conditions.notify_all()

    async def _drive_stream_step(
        self,
        sequence: int,
        intent: StreamIntent,
        step: TransactionStep,
        dependencies: Sequence[str],
    ) -> None:
        route_group = intent.route_group
        route_affinity = intent.route_affinity
        prior = [packet for packet in await self.plan.unresolved_packets() if packet.step_id == step.step_id]
        packet_record = max(prior, key=lambda item: item.generation) if prior else None
        if packet_record is None:
            packet_record = await self._build_stream_packet(intent, step)
        processed_observed = any(
            row.step_id == step.step_id
            and row.generation == packet_record.generation
            and row.label == "optimistic"
            for row in self.plan.observations
        )
        missing_processed = 0
        missing_since: float | None = None
        while True:
            if step.step_id in self._invalidated:
                await self._record_reconciliation_required(step, intent, "an optimistic ancestor was dropped")
                postcondition = await self._reconcile_existing_packet(step, packet_record)
                if step.reconcile_dropped is not None:
                    endpoint = self.sequencer._pooled_endpoint(
                        route_group=route_group, route_affinity=route_affinity
                    )
                    await step.reconcile_dropped(endpoint, packet_record.signature, postcondition)
                raise ReconciliationRequired(f"step {step.step_id} requires application reconciliation")
            status = None
            status_query_succeeded = False
            try:
                status = await self.sequencer._confirmation_pump.status(
                    packet_record.signature,
                    route_group=route_group,
                    route_affinity=route_affinity,
                )
                status_query_succeeded = True
            except Exception as exc:
                if not self.sequencer._is_transport_exception(exc):
                    raise
            postcondition = PostconditionResult(None)
            endpoint = self.sequencer._pooled_endpoint(
                route_group=route_group, route_affinity=route_affinity
            )
            try:
                postcondition = await step.postcondition(endpoint)
            except Exception as exc:
                if not self.sequencer._is_transport_exception(exc):
                    raise
            await self._record_observation(step, packet_record, status, postcondition)
            if status is not None and status.commitment in {Commitment.CONFIRMED, Commitment.FINALIZED}:
                if status.error is not None:
                    if status.commitment is Commitment.FINALIZED:
                        digest = postcondition.state_digest or hashlib.sha256(
                            ("finalized-error\0" + status.error).encode()
                        ).hexdigest()
                        await self.plan.record_terminal(
                            StreamTerminal(
                                step.step_id,
                                "failed",
                                packet_record.signature,
                                Commitment.FINALIZED.value,
                                False,
                                digest,
                                status.slot,
                                status.error,
                            )
                        )
                        raise ProgramRefused(f"step {step.step_id} finalized with program error: {status.error}")
                elif postcondition.satisfied is True and postcondition.state_digest:
                    await self.plan.record_terminal(
                        StreamTerminal(
                            step.step_id,
                            "confirmed",
                            packet_record.signature,
                            status.commitment.value,
                            True,
                            postcondition.state_digest,
                            status.slot,
                        )
                    )
                    self._optimistic.pop(step.step_id, None)
                    self._prune_causal()
                    return
            if status is not None and status.commitment is Commitment.PROCESSED and status.error is None:
                processed_observed = True
                if self.sequencer.config.latency_mode is LatencyMode.PROCESSED:
                    current = self._optimistic.get(step.step_id)
                    if current is None:
                        permission = self._permissions.pop(step.step_id, None)
                        parent_depths = [self._optimistic[dep].depth + 1 for dep in dependencies if dep in self._optimistic]
                        self._optimistic[step.step_id] = _OptimisticState(
                            self._lanes[step.step_id],
                            permission[0] if permission else min(
                                (self._optimistic[dep].since for dep in dependencies if dep in self._optimistic),
                                default=self.sequencer.config.monotonic_clock(),
                            ),
                            permission[1] if permission else max(parent_depths, default=0),
                            packet_record.signature,
                            packet_record.generation,
                        )
                        if permission is None:
                            self._causal[step.step_id] = (
                                self.sequencer.config.monotonic_clock(),
                                max(parent_depths, default=0),
                                frozenset({step.step_id}),
                            )
                        async with self._conditions:
                            self._conditions.notify_all()
            elif (
                status is None
                and processed_observed
                and status_query_succeeded
                and self.sequencer.config.latency_mode is LatencyMode.PROCESSED
            ):
                # H1: only latency mode may infer a drop, only after a bounded
                # window, and never against a satisfied postcondition.
                missing_processed += 1
                if missing_since is None:
                    missing_since = self.sequencer.config.monotonic_clock()
                if (
                    missing_processed >= self.sequencer.config.optimistic_drop_status_misses
                    and self.sequencer.config.monotonic_clock() - missing_since
                    >= self.sequencer.config.optimistic_drop_window_seconds
                ):
                    await self._drop_branch(step, intent, packet_record, postcondition)
                    return
            elif status is not None:
                missing_processed = 0
                missing_since = None

            permission = self._permissions.get(step.step_id)
            if (
                permission is not None
                and self.sequencer.config.monotonic_clock() - permission[0]
                > self.sequencer.config.optimistic_max_seconds
            ):
                self._permissions.pop(step.step_id, None)
                ready, _dependencies = await self._wait_dependencies(sequence, intent, step)
                if not ready:
                    await self._record_reconciliation_required(step, intent, "optimistic window expired after branch invalidation")
                    raise ReconciliationRequired(f"step {step.step_id} requires application reconciliation")
                continue

            lease = self._leases.get((step.step_id, packet_record.generation))
            if lease is not None:
                expired = self.sequencer._lease_expired(lease)
            else:
                # H3: a packet resumed from the journal has no in-memory lease.
                # Its blockhash was fetched before this process saw it, so one
                # full lifetime after first sight is a safe upper bound.
                first_seen = self._resumed_seen.setdefault(
                    (step.step_id, packet_record.generation), self.sequencer.config.monotonic_clock()
                )
                expired = (
                    self.sequencer.config.monotonic_clock() - first_seen
                    > self.sequencer.config.blockhash_lifetime_seconds
                )
            if expired and status is None and postcondition.satisfied is not True:
                evidence = RecoveryEvidence(
                    packet_record.signature,
                    lease,
                    status,
                    postcondition,
                    True,
                )
                if step.retry_policy is RetryPolicy.RECONCILE and step.authorize_rebuild is not None:
                    if await step.authorize_rebuild(evidence):
                        evidence_digest = hashlib.sha256(
                            json.dumps(
                                {
                                    "signature": packet_record.signature,
                                    "postcondition": _postcondition_to_json(postcondition),
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode()
                        ).hexdigest()
                        await self.plan.authorize_rebuild(step.step_id, packet_record.generation, evidence_digest)
                        packet_record = await self._build_stream_packet(intent, step, packet_record.generation + 1)
                        processed_observed = False
                        continue
                await self._record_reconciliation_required(step, intent, "signed packet expired without safe application rebuild authorization")
                raise AmbiguousFate(f"stream step {step.step_id} has ambiguous fate after blockhash expiry")

            attempts = packet_record.attempts
            unfinished = next((item for item in reversed(attempts) if item.finished_event_sequence is None), None)
            if unfinished is not None:
                await self.plan.record_send_result(
                    step.step_id,
                    packet_record.generation,
                    unfinished.number,
                    acknowledged=False,
                    provider_id=unfinished.provider_id,
                    endpoint_id=unfinished.endpoint_id,
                    route_group=unfinished.route_group,
                    route_affinity=unfinished.route_affinity,
                    detail="recovered an interrupted handoff; the original packet remains authoritative",
                )
                packet_record = next(
                    item for item in await self.plan.unresolved_packets()
                    if item.step_id == step.step_id and item.generation == packet_record.generation
                )
                attempts = packet_record.attempts
            # M1: RetryPolicy.NEVER sends a stream packet exactly once.
            retry_allowed = step.retry_policy is not RetryPolicy.NEVER or not attempts
            if (status is None and not processed_observed and retry_allowed
                    and len(attempts) < self.plan.limits.max_attempts_per_generation):
                receipt = await self._send_stream_packet(step, intent, packet_record)
                if receipt is not None and receipt.signature != packet_record.signature:
                    raise AmbiguousFate("provider acknowledged a signature different from the journaled packet")
                packet_record = next(
                    item for item in await self.plan.unresolved_packets()
                    if item.step_id == step.step_id and item.generation == packet_record.generation
                )
            await self.sequencer.config.sleep(self.sequencer.config.confirmation_poll_seconds or 0.01)

    async def _build_stream_packet(
        self, intent: StreamIntent, step: TransactionStep, generation: int = 0
    ):
        lease = await self.sequencer._rpc_call(
            "latest_blockhash",
            self.identity.genesis_hash,
            self.sequencer.config.blockhash_lifetime_seconds,
            route_group=intent.route_group,
            route_affinity=intent.route_affinity,
        )
        if lease.genesis_hash != self.identity.genesis_hash:
            raise PlanError("stream blockhash source has a different genesis")
        message = step.build_message(lease)
        if not isinstance(message, bytes):
            raise PlanError("stream message builder must return bytes")
        packet_limit = min(intent.max_packet_bytes, self.sequencer.config.max_packet_bytes)
        projected = len(message) + _shortvec_size(self.sequencer.signer.signature_count) + (
            self.sequencer.signer.signature_count * self.sequencer.signer.signature_size_bytes
        )
        if projected > packet_limit:
            raise PacketTooLarge(f"stream step {step.step_id} projects {projected} bytes, limit is {packet_limit}")
        signed = await self.sequencer.signer.sign(message, lease)
        if len(signed.raw_bytes) > packet_limit:
            raise PacketTooLarge(f"stream step {step.step_id} exceeds its packet limit")
        record = await self.plan.record_signed_packet(
            step.step_id, signed.signature, signed.raw_bytes, self.sequencer.signer.public_key
        )
        self._leases[(step.step_id, generation)] = lease
        if record.generation != generation:
            raise JournalError("stream journal assigned an unexpected packet generation")
        return record

    async def _send_stream_packet(self, step: TransactionStep, intent: StreamIntent, packet):
        provider_id = step.provider_id or ("rpc" if "rpc" in self.sequencer.providers else next(iter(self.sequencer.providers)))
        provider = self.sequencer.providers[provider_id]
        # M5: take the pool lease before journaling the attempt, so pool
        # exhaustion never consumes attempt budget, and fail over within the
        # route group when the pinned endpoint cannot admit the send. The
        # attempt row is still durable before the packet crosses to the provider.
        try:
            try:
                lease = await self.sequencer._acquire_lease(
                    RequestKind.SEND,
                    endpoint_id=step.endpoint_id,
                    route_group=intent.route_group,
                    route_affinity=intent.route_affinity,
                )
            except EndpointPoolExhausted:
                if intent.route_group is None:
                    raise
                lease = await self.sequencer._acquire_lease(
                    RequestKind.SEND,
                    endpoint_id=None,
                    route_group=intent.route_group,
                    route_affinity=intent.route_affinity,
                )
        except EndpointPoolExhausted:
            await self.sequencer._sleep_backoff(self._backoff)
            self._backoff = self.sequencer._next_backoff(self._backoff)
            return None
        try:
            attempt = await self.plan.record_send_attempt(
                step.step_id,
                packet.generation,
                provider_id=provider_id,
                endpoint_id=lease.endpoint_id,
                route_group=intent.route_group,
                route_affinity=intent.route_affinity,
            )
        except BaseException:
            await lease.close()
            raise
        provider_attempt = _StreamProviderAttempt(
            self.plan,
            step.step_id,
            packet.generation,
            packet.signature,
            attempt.number,
            provider_id,
            lease.endpoint_id,
            lease.route.route_group,
            intent.route_affinity,
            lease.route,
        )
        self.sequencer._register_stream_provider_attempt(provider_attempt)
        started = self.sequencer.config.monotonic_clock()
        try:
            receipt = await provider.send_raw(packet.raw_bytes, packet.signature, lease.route)
        except Exception as exc:
            await self.sequencer._report_exception(lease, exc)
            await self.plan.record_send_result(
                step.step_id,
                packet.generation,
                attempt.number,
                acknowledged=False,
                provider_id=provider_id,
                endpoint_id=lease.endpoint_id,
                route_group=lease.route.route_group,
                route=lease.route,
                route_affinity=intent.route_affinity,
                detail=str(exc)[:512],
            )
            if provider_attempt.failure is not None:
                self.sequencer.unmatched_provider_failures.append(provider_attempt.failure)
            self.sequencer._forget_stream_provider_attempt(provider_attempt)
            # M2: BlockhashExpired is a hint (a lagging node may not know the
            # blockhash yet); the lease clock and status reconciliation decide.
            if isinstance(exc, (RateLimited, RpcUnavailable, EndpointPoolExhausted, BlockhashExpired)):
                await self.sequencer._sleep_backoff(self._backoff, getattr(exc, "retry_after", None))
                self._backoff = self.sequencer._next_backoff(self._backoff)
                return None
            raise AmbiguousFate(f"provider handoff for {packet.signature} is unresolved: {exc}") from exc
        else:
            await lease.observe(
                HealthObservation(
                    HealthSignal.SUCCESS,
                    latency_seconds=max(0.0, self.sequencer.config.monotonic_clock() - started),
                )
            )
            await self.plan.record_send_result(
                step.step_id,
                packet.generation,
                attempt.number,
                acknowledged=True,
                provider_id=provider_id,
                endpoint_id=lease.endpoint_id,
                route_group=lease.route.route_group,
                route=lease.route,
                receipt=receipt,
                route_affinity=intent.route_affinity,
            )
            provider_attempt.disposition = getattr(receipt.disposition, "value", str(receipt.disposition))
            provider_attempt.acknowledged = True
            await self.sequencer._record_async_provider_failure(provider_attempt)
            self.sequencer.pool.remember_affinity(intent.route_affinity or step.step_id, lease.endpoint_id)
            self._backoff = self.sequencer.config.backoff.initial_seconds
            return receipt
        finally:
            await lease.close()

    async def _drop_branch(self, step: TransactionStep, intent: StreamIntent, packet, postcondition) -> None:
        detail = "processed signature disappeared before stable confirmation"
        await self.plan.record_step_dropped(step.step_id, packet.generation, detail=detail)
        await self.plan.record_optimistic_branch_invalidated(step.step_id, packet.generation, detail=detail)
        self._dropped.add(step.step_id)
        self._optimistic.pop(step.step_id, None)
        self._rebuild_invalidated()
        for step_id in self._invalidated:
            self._optimistic.pop(step_id, None)
            self._causal.pop(step_id, None)
        self._causal.pop(step.step_id, None)
        await self._record_reconciliation_required(step, intent, detail)
        if step.reconcile_dropped is None:
            raise ReconciliationRequired(f"dropped stream parent {step.step_id} has no application reconciler")
        endpoint = self.sequencer._pooled_endpoint(
            route_group=intent.route_group, route_affinity=intent.route_affinity
        )
        await step.reconcile_dropped(endpoint, packet.signature, postcondition)
        async with self._conditions:
            self._conditions.notify_all()
        raise ReconciliationRequired(f"dropped stream parent {step.step_id} was reconciled by the application")

    async def _record_reconciliation_required(
        self, step: TransactionStep, intent: StreamIntent, detail: str
    ) -> None:
        if step.step_id in self._reconciliation_recorded:
            return
        packets = [packet for packet in await self.plan.unresolved_packets() if packet.step_id == step.step_id]
        if packets:
            packet = max(packets, key=lambda item: item.generation)
            generation = packet.generation
        else:
            # Package B supports reconciliation records for descendants that
            # were invalidated before they received a signed packet.
            generation = 0
        await self.plan.record_reconciliation_required(step.step_id, generation, detail=detail)
        self._reconciliation_recorded.add(step.step_id)

    async def _reconcile_existing_packet(self, step: TransactionStep, packet) -> PostconditionResult:
        intent = self._intents[step.step_id][1]
        status = await self.sequencer._confirmation_pump.status(
            packet.signature,
            route_group=intent.route_group,
            route_affinity=intent.route_affinity,
        )
        postcondition = PostconditionResult(None)
        endpoint = self.sequencer._pooled_endpoint(route_group=intent.route_group, route_affinity=intent.route_affinity)
        try:
            postcondition = await step.postcondition(endpoint)
        except Exception as exc:
            if not self.sequencer._is_transport_exception(exc):
                raise
        await self._record_observation(step, packet, status, postcondition)
        return postcondition

    async def _record_observation(self, step, packet, status, postcondition) -> None:
        values = (
            status.commitment.value if status else None,
            status.error if status else None,
            status.slot if status else None,
            postcondition.satisfied,
            postcondition.state_digest,
        )
        key = (step.step_id, packet.generation)
        if self._last_observations.get(key) == values:
            return
        await self.plan.record_observation(
            step.step_id,
            packet.generation,
            status_commitment=values[0],
            status_error=values[1],
            slot=values[2],
            postcondition_satisfied=values[3],
            postcondition_digest=values[4],
        )
        self._last_observations[key] = values

    def _rebuild_invalidated(self) -> None:
        invalidated = set(self._dropped)
        pending = sorted(self._intents.items(), key=lambda item: item[1][0])
        changed = True
        while changed:
            changed = False
            invalidated_locks = {
                lock
                for step_id, (_sequence, intent) in pending
                if step_id in invalidated
                for lock in intent.write_locks
            }
            for step_id, (_sequence, intent) in pending:
                if step_id in invalidated:
                    continue
                if set(intent.dependencies).intersection(invalidated) or set(intent.write_locks).intersection(invalidated_locks):
                    invalidated.add(step_id)
                    changed = True
        self._invalidated = invalidated - self._dropped

    def _prune_causal(self) -> None:
        terminals = self.plan.terminal_summaries
        for step_id, (since, depth, roots) in tuple(self._causal.items()):
            active_roots = frozenset(root for root in roots if root not in terminals)
            if not active_roots:
                self._causal.pop(step_id, None)
            elif active_roots != roots:
                self._causal[step_id] = (since, depth, active_roots)


def _shortvec_size(value: int) -> int:
    """Encoded length of Solana's compact-u16 signature-count prefix."""

    if value < 0 or value > 0xFFFF:
        raise PlanError("signature count is outside compact-u16 range")
    if value < 0x80:
        return 1
    if value < 0x4000:
        return 2
    return 3


class _PooledRpcEndpoint:
    """RpcEndpoint facade that keeps adapter reads inside the shared pool."""

    def __init__(self, sequencer: Sequencer, route_group: str, route_affinity: str | None):
        self._sequencer = sequencer
        self._route_group = route_group
        self._route_affinity = route_affinity
        candidates = sorted(
            endpoint_id
            for endpoint_id, limits in sequencer.config.endpoint_limits.items()
            if (limits.route_group or endpoint_id) == route_group
        )
        self.endpoint_id = candidates[0] if candidates else "pooled"

    def __getattr__(self, name: str) -> Any:
        # Retain local adapter conveniences (such as an in-memory state view),
        # but never expose a callable that could issue an unpooled RPC request.
        endpoint = self._sequencer.endpoints.get(self.endpoint_id)
        if endpoint is None:
            raise AttributeError(name)
        value = getattr(endpoint, name)
        if callable(value):
            raise AttributeError(f"RPC method {name!r} is not exposed by the pooled adapter")
        return value

    async def get_genesis_hash(self) -> str:
        return await self._sequencer._rpc_call(
            "get_genesis_hash",
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def get_health(self) -> str:
        return await self._sequencer._rpc_call(
            "get_health",
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def latest_blockhash(self, genesis_hash: str, lifetime_seconds: float) -> BlockhashLease:
        return await self._sequencer._rpc_call(
            "latest_blockhash",
            genesis_hash,
            lifetime_seconds,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def send_raw_transaction(self, raw_bytes: bytes):
        raise RuntimeError("pooled adapter reads cannot submit signed transactions")

    async def signature_status(self, signature: str) -> SignatureObservation | None:
        return await self._sequencer._confirmation_pump.status(
            signature, route_group=self._route_group, route_affinity=self._route_affinity
        )

    async def signature_statuses(
        self, signatures: Sequence[str]
    ) -> Mapping[str, SignatureObservation | None]:
        observations = await asyncio.gather(
            *(
                self._sequencer._confirmation_pump.status(
                    signature, route_group=self._route_group, route_affinity=self._route_affinity
                )
                for signature in signatures
            )
        )
        return dict(zip(signatures, observations, strict=True))

    async def get_account_info(self, address, commitment):
        return await self._sequencer._rpc_call(
            "get_account_info",
            address,
            commitment,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def request_airdrop(self, address, lamports):
        return await self._sequencer._rpc_call(
            "request_airdrop",
            address,
            lamports,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def get_multiple_accounts(self, addresses, commitment):
        return await self._sequencer._rpc_call(
            "get_multiple_accounts",
            addresses,
            commitment,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def get_program_accounts(self, program_id, *, filters, commitment):
        return await self._sequencer._rpc_call(
            "get_program_accounts",
            program_id,
            filters=filters,
            commitment=commitment,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )

    async def simulate_transaction(
        self,
        raw_transaction: bytes,
        *,
        commitment: Commitment = Commitment.CONFIRMED,
        sig_verify: bool = False,
        replace_recent_blockhash: bool = False,
    ):
        return await self._sequencer._rpc_call(
            "simulate_transaction",
            raw_transaction,
            commitment=commitment,
            sig_verify=sig_verify,
            replace_recent_blockhash=replace_recent_blockhash,
            route_group=self._route_group,
            route_affinity=self._route_affinity,
        )


def _plain_value(value: Any) -> Any:
    """Convert provider configuration to deterministic JSON-safe primitives."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, PathLike):
        return str(value)
    if is_dataclass(value):
        return _plain_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _plain_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list)):
        return [_plain_value(item) for item in value]
    return f"{value.__class__.__module__}.{value.__class__.__qualname__}"
