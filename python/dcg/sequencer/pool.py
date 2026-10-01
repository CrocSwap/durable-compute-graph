"""Typed per-node pacing, routing, and health management.

Integration contract
--------------------
Package C should construct :class:`EndpointPool` with one
:class:`EndpointNodeConfig` for every RPC endpoint eligible for sends or
observation. Callers must wrap every outbound RPC operation in
``pool.request(kind, ...)``. The pool is the authoritative pacing and
admission limiter; configure a ``SolanaRpcEndpoint``'s own limiter so it does
not impose a lower, competing rate. Use ``RequestKind.SEND`` for signed packet
submission, including TPU sends, so the selected observer node's send and
total-request budgets are enforced. ``EndpointRoute.endpoint_id`` is that
selected observer identity and is recorded in the send receipt even when a
shared TPU helper carries the packet.

The yielded lease exposes the chosen ``RpcEndpoint`` and immutable
``EndpointRoute``. Report classified health through ``lease.observe`` and call
``pool.remember_affinity`` after selecting the node for a prior step/lane. If
``lease.route.is_probe`` is true, the first eligible caller has acquired a
probe lease: perform one bounded health probe, report it, close the lease, and
acquire again before normal work. Every configured acquisition has a bounded
deadline; an explicit ``deadline`` is an absolute value from the pool's
monotonic clock.

The caller supplies the endpoint implementations and decides what endpoint
health means. In particular, account/cursor postconditions remain app policy.
When ``probe_due`` names an endpoint, Package C may acquire an explicit
``RequestKind.PROBE`` lease and must report its result before normal work can
use that node again. If all matching nodes are unavailable, the first normal
acquirer after a cooldown is instead given a probe lease.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator, Callable, Sequence

from .types import FailureClass, RpcEndpoint, SequencerError


class RequestKind(str, Enum):
    """Which per-node pacing budgets an operation consumes."""

    SEND = "send"
    RPC = "rpc"
    PROBE = "probe"


class HealthSignal(str, Enum):
    """Classified input for the endpoint circuit breaker."""

    SUCCESS = "success"
    RATE_LIMITED = "rate-limited"
    TRANSPORT_ERROR = "transport-error"
    TIMEOUT = "timeout"
    UNHEALTHY = "unhealthy"


class EndpointPoolExhausted(SequencerError):
    """No endpoint could be admitted before the caller's pool deadline."""

    failure_class = FailureClass.RESUMABLE
    classification = "pool-exhausted"


@dataclass(frozen=True)
class EndpointNodeConfig:
    """One endpoint and its configured local pacing and route policy."""

    endpoint: RpcEndpoint
    sends_per_second: float
    requests_per_second: float
    max_in_flight: int
    weight: float = 1.0
    route_group: str = "default"

    def __post_init__(self) -> None:
        if not self.endpoint.endpoint_id:
            raise ValueError("endpoint ID must be non-empty")
        if not math.isfinite(self.sends_per_second) or self.sends_per_second <= 0:
            raise ValueError("sends_per_second must be finite and positive")
        if not math.isfinite(self.requests_per_second) or self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be finite and positive")
        if self.max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        if not math.isfinite(self.weight) or self.weight <= 0:
            raise ValueError("weight must be finite and positive")
        if not self.route_group:
            raise ValueError("route_group must be non-empty")

    @property
    def endpoint_id(self) -> str:
        return self.endpoint.endpoint_id


@dataclass(frozen=True)
class HealthPolicy:
    """Local circuit-breaker thresholds; values are configuration, not capacity claims."""

    score_threshold: float = 4.0
    cooldown_seconds: float = 1.0
    max_cooldown_seconds: float = 60.0
    decay_half_life_seconds: float = 30.0
    recovery_points: float = 1.0
    rate_limit_points: float = 3.0
    transport_error_points: float = 2.0
    timeout_points: float = 2.0
    unhealthy_points: float = 4.0
    slow_request_seconds: float | None = 1.0
    slow_request_points: float = 0.5
    max_slot_lag: int | None = 8
    slot_lag_points: float = 1.5

    def __post_init__(self) -> None:
        positive = (
            self.score_threshold,
            self.cooldown_seconds,
            self.max_cooldown_seconds,
            self.decay_half_life_seconds,
        )
        if any(not math.isfinite(value) or value <= 0 for value in positive):
            raise ValueError("health thresholds and cooldowns must be finite and positive")
        if self.max_cooldown_seconds < self.cooldown_seconds:
            raise ValueError("max_cooldown_seconds must be at least cooldown_seconds")
        nonnegative = (
            self.recovery_points,
            self.rate_limit_points,
            self.transport_error_points,
            self.timeout_points,
            self.unhealthy_points,
            self.slow_request_points,
            self.slot_lag_points,
        )
        if any(not math.isfinite(value) or value < 0 for value in nonnegative):
            raise ValueError("health score changes must be finite and non-negative")
        if self.slow_request_seconds is not None and (
            not math.isfinite(self.slow_request_seconds) or self.slow_request_seconds <= 0
        ):
            raise ValueError("slow_request_seconds must be finite and positive")
        if self.max_slot_lag is not None and self.max_slot_lag < 0:
            raise ValueError("max_slot_lag cannot be negative")


@dataclass(frozen=True)
class HealthObservation:
    """A provider or observer's classified result for one endpoint operation."""

    signal: HealthSignal
    retry_after_seconds: float | None = None
    latency_seconds: float | None = None
    slot_lag: int | None = None

    def __post_init__(self) -> None:
        if self.retry_after_seconds is not None and (
            not math.isfinite(self.retry_after_seconds) or self.retry_after_seconds < 0
        ):
            raise ValueError("retry_after_seconds must be finite and non-negative")
        if self.latency_seconds is not None and (
            not math.isfinite(self.latency_seconds) or self.latency_seconds < 0
        ):
            raise ValueError("latency_seconds must be finite and non-negative")
        if self.slot_lag is not None and self.slot_lag < 0:
            raise ValueError("slot_lag cannot be negative")


@dataclass(frozen=True)
class EndpointRoute:
    """A selected node identity suitable for provider routing and journaling."""

    endpoint_id: str
    route_group: str
    affinity_key: str | None = None
    is_probe: bool = False


@dataclass(frozen=True)
class EndpointSnapshot:
    """Read-only state; ``waiter_count`` counts blocked routes including this node."""

    endpoint_id: str
    route_group: str
    in_flight: int
    health_score: float
    cooldown_until: float
    probe_required: bool
    probe_in_flight: bool
    waiter_count: int


@dataclass
class _NodeState:
    config: EndpointNodeConfig
    in_flight: int = 0
    next_send_at: float = 0.0
    next_request_at: float = 0.0
    health_score: float = 0.0
    health_updated_at: float = 0.0
    cooldown_until: float = 0.0
    probe_required: bool = False
    probe_in_flight: bool = False
    cooldown_count: int = 0
    smooth_weight: float = 0.0
    waiters: int = 0


class EndpointLease:
    """One reserved endpoint request slot; always close it after the operation."""

    def __init__(
        self,
        pool: EndpointPool,
        state: _NodeState,
        kind: RequestKind,
        affinity_key: str | None,
    ):
        self._pool = pool
        self._state = state
        self.kind = kind
        self.route = EndpointRoute(
            endpoint_id=state.config.endpoint_id,
            route_group=state.config.route_group,
            affinity_key=affinity_key,
            is_probe=kind is RequestKind.PROBE,
        )
        self._closed = False
        self._observed = False

    @property
    def endpoint(self) -> RpcEndpoint:
        return self._state.config.endpoint

    @property
    def endpoint_id(self) -> str:
        return self._state.config.endpoint_id

    async def observe(self, observation: HealthObservation) -> None:
        """Report one result before release; a probe must report success or failure."""

        if self._closed:
            raise RuntimeError("cannot report health for a closed endpoint lease")
        if self._observed:
            raise RuntimeError("endpoint lease already has a health observation")
        await self._pool._observe(self._state, observation, is_probe=self.kind is RequestKind.PROBE)
        self._observed = True

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self._pool._release(self._state, is_probe=self.kind is RequestKind.PROBE, observed=self._observed)

    async def __aenter__(self) -> EndpointLease:
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()


class EndpointPool:
    """Weighted endpoint router with shared request budgets and health cooling."""

    def __init__(
        self,
        nodes: Sequence[EndpointNodeConfig],
        *,
        health_policy: HealthPolicy = HealthPolicy(),
        clock: Callable[[], float] = time.monotonic,
        default_acquire_timeout_seconds: float = 30.0,
        max_affinity_entries: int = 4096,
    ):
        if not nodes:
            raise ValueError("endpoint pool requires at least one node")
        ids = [node.endpoint_id for node in nodes]
        if len(set(ids)) != len(ids):
            raise ValueError("endpoint IDs in a pool must be unique")
        if (
            not math.isfinite(default_acquire_timeout_seconds)
            or default_acquire_timeout_seconds <= 0
        ):
            raise ValueError("default_acquire_timeout_seconds must be finite and positive")
        if max_affinity_entries <= 0:
            raise ValueError("max_affinity_entries must be positive")
        self.health_policy = health_policy
        self._clock = clock
        self._default_acquire_timeout_seconds = default_acquire_timeout_seconds
        self._max_affinity_entries = max_affinity_entries
        now = clock()
        self._nodes = {
            node.endpoint_id: _NodeState(node, health_updated_at=now) for node in nodes
        }
        self._affinity: OrderedDict[str, str] = OrderedDict()
        self._condition = asyncio.Condition()

    async def acquire(
        self,
        kind: RequestKind,
        *,
        route_group: str | None = None,
        endpoint_id: str | None = None,
        route_affinity: str | None = None,
        deadline: float | None = None,
    ) -> EndpointLease:
        """Reserve an endpoint before an absolute monotonic ``deadline``.

        Calls without an explicit deadline use the configured bounded default.
        When every matching node is cooling, the first caller eligible after a
        cooldown receives a probe lease (``lease.kind == PROBE``); it must
        perform a health check and acquire again before doing normal work.
        """

        if not isinstance(kind, RequestKind):
            kind = RequestKind(kind)
        if endpoint_id is not None and endpoint_id not in self._nodes:
            raise ValueError(f"unknown RPC endpoint {endpoint_id!r}")
        if not any(
            (endpoint_id is None or state.config.endpoint_id == endpoint_id)
            and (route_group is None or state.config.route_group == route_group)
            for state in self._nodes.values()
        ):
            raise ValueError("no endpoint matches the requested route group and endpoint")
        if route_affinity is not None and not route_affinity:
            raise ValueError("route_affinity must be non-empty when provided")
        if deadline is not None and not math.isfinite(deadline):
            raise ValueError("deadline must be finite when provided")
        async with self._condition:
            matching = tuple(
                state
                for state in self._nodes.values()
                if (endpoint_id is None or state.config.endpoint_id == endpoint_id)
                and (route_group is None or state.config.route_group == route_group)
            )
            expires_at = (
                deadline
                if deadline is not None
                else self._clock() + self._default_acquire_timeout_seconds
            )
            while True:
                now = self._clock()
                timed: list[float] = []
                healthy: list[_NodeState] = []
                probes: list[_NodeState] = []
                for state in matching:
                    if kind is RequestKind.PROBE:
                        if not state.probe_required or state.probe_in_flight:
                            continue
                        if state.cooldown_until > now:
                            timed.append(state.cooldown_until - now)
                            continue
                        if state.in_flight >= state.config.max_in_flight:
                            continue
                        probes.append(state)
                        continue
                    if state.probe_required:
                        if not state.probe_in_flight:
                            if state.cooldown_until > now:
                                timed.append(state.cooldown_until - now)
                            elif state.in_flight < state.config.max_in_flight:
                                probes.append(state)
                        continue
                    if state.cooldown_until > now:
                        timed.append(state.cooldown_until - now)
                        continue
                    if state.in_flight >= state.config.max_in_flight:
                        continue
                    healthy.append(state)

                if kind is RequestKind.PROBE:
                    candidates = probes
                    effective_kind = RequestKind.PROBE
                else:
                    # A probe is an escape hatch only when no healthy matching
                    # endpoint can admit this request now. In particular, do
                    # not let a cooled node steal traffic from a due healthy node.
                    due_healthy = [
                        state
                        for state in healthy
                        if self._rate_due(state, kind) <= now
                    ]
                    if due_healthy:
                        candidates = due_healthy
                        effective_kind = kind
                    elif not healthy:
                        candidates = [
                            state
                            for state in probes
                            if state.in_flight < state.config.max_in_flight
                        ]
                        effective_kind = RequestKind.PROBE
                    else:
                        candidates = []
                        effective_kind = kind
                    for state in healthy:
                        due = self._rate_due(state, kind)
                        if due > now:
                            timed.append(due - now)

                for state in candidates:
                    due = self._rate_due(state, effective_kind)
                    if due > now:
                        timed.append(due - now)
                if candidates:
                    ready = [
                        state
                        for state in candidates
                        if self._rate_due(state, effective_kind) <= now
                    ]
                    if ready:
                        selected, weighted = self._choose(ready, route_affinity)
                        if weighted:
                            self._commit_weighted_choice(ready, selected)
                        selected.in_flight += 1
                        if effective_kind is RequestKind.SEND:
                            selected.next_send_at = max(now, selected.next_send_at) + 1.0 / selected.config.sends_per_second
                        selected.next_request_at = max(now, selected.next_request_at) + 1.0 / selected.config.requests_per_second
                        if effective_kind is RequestKind.PROBE:
                            selected.probe_in_flight = True
                        return EndpointLease(self, selected, effective_kind, route_affinity)

                remaining = expires_at - now
                if remaining <= 0:
                    raise EndpointPoolExhausted(
                        "endpoint pool exhausted before the acquisition deadline"
                    )
                timeout = min(timed + [remaining]) if timed else remaining
                waiting_on = matching
                for state in waiting_on:
                    state.waiters += 1
                try:
                    await asyncio.wait_for(self._condition.wait(), timeout=max(timeout, 0.0001))
                except TimeoutError:
                    pass
                finally:
                    for state in waiting_on:
                        state.waiters -= 1

    @asynccontextmanager
    async def request(
        self,
        kind: RequestKind,
        *,
        route_group: str | None = None,
        endpoint_id: str | None = None,
        route_affinity: str | None = None,
        deadline: float | None = None,
    ) -> AsyncIterator[EndpointLease]:
        """Context-managed form of :meth:`acquire`."""

        lease = await self.acquire(
            kind,
            route_group=route_group,
            endpoint_id=endpoint_id,
            route_affinity=route_affinity,
            deadline=deadline,
        )
        async with lease:
            yield lease

    def remember_affinity(self, route_affinity: str, endpoint_id: str) -> None:
        """Prefer the endpoint used by a prior step/lane while it remains healthy."""

        if not route_affinity:
            raise ValueError("route_affinity must be non-empty")
        if endpoint_id not in self._nodes:
            raise ValueError(f"unknown RPC endpoint {endpoint_id!r}")
        self._affinity[route_affinity] = endpoint_id
        self._affinity.move_to_end(route_affinity)
        while len(self._affinity) > self._max_affinity_entries:
            self._affinity.popitem(last=False)

    def forget_affinity(self, route_affinity: str) -> None:
        self._affinity.pop(route_affinity, None)

    async def probe_due(self) -> tuple[str, ...]:
        """Return cooled nodes that need a bounded health probe before reuse."""

        async with self._condition:
            now = self._clock()
            return tuple(
                state.config.endpoint_id
                for state in self._nodes.values()
                if state.probe_required and not state.probe_in_flight and state.cooldown_until <= now
            )

    async def snapshots(self) -> tuple[EndpointSnapshot, ...]:
        async with self._condition:
            now = self._clock()
            result = []
            for state in self._nodes.values():
                self._decay(state, now)
                result.append(
                    EndpointSnapshot(
                        endpoint_id=state.config.endpoint_id,
                        route_group=state.config.route_group,
                        in_flight=state.in_flight,
                        health_score=state.health_score,
                        cooldown_until=state.cooldown_until,
                        probe_required=state.probe_required,
                        probe_in_flight=state.probe_in_flight,
                        waiter_count=state.waiters,
                    )
                )
            return tuple(result)

    def _choose(
        self, eligible: Sequence[_NodeState], route_affinity: str | None
    ) -> tuple[_NodeState, bool]:
        if route_affinity is not None:
            preferred_id = self._affinity.get(route_affinity)
            preferred = next((state for state in eligible if state.config.endpoint_id == preferred_id), None)
            if preferred is not None:
                self._affinity.move_to_end(route_affinity)
                return preferred, False
        # Peek at smooth weighted round-robin state. Commit the counters only
        # when the selected node can actually admit this request, so a delayed
        # route does not skew later choices toward whichever node is currently
        # paced and ready.
        selected = max(
            eligible,
            key=lambda state: state.smooth_weight + state.config.weight,
        )
        return selected, True

    @staticmethod
    def _rate_due(state: _NodeState, kind: RequestKind) -> float:
        due = state.next_request_at
        if kind is RequestKind.SEND:
            due = max(due, state.next_send_at)
        return due

    @staticmethod
    def _commit_weighted_choice(eligible: Sequence[_NodeState], selected: _NodeState) -> None:
        total_weight = sum(state.config.weight for state in eligible)
        for state in eligible:
            state.smooth_weight += state.config.weight
        selected.smooth_weight -= total_weight

    def _decay(self, state: _NodeState, now: float) -> None:
        elapsed = max(0.0, now - state.health_updated_at)
        if elapsed:
            state.health_score *= 0.5 ** (elapsed / self.health_policy.decay_half_life_seconds)
            state.health_updated_at = now

    async def _observe(
        self, state: _NodeState, observation: HealthObservation, *, is_probe: bool
    ) -> None:
        async with self._condition:
            now = self._clock()
            self._decay(state, now)
            policy = self.health_policy
            points = {
                HealthSignal.SUCCESS: -policy.recovery_points,
                HealthSignal.RATE_LIMITED: policy.rate_limit_points,
                HealthSignal.TRANSPORT_ERROR: policy.transport_error_points,
                HealthSignal.TIMEOUT: policy.timeout_points,
                HealthSignal.UNHEALTHY: policy.unhealthy_points,
            }[observation.signal]
            if (
                observation.latency_seconds is not None
                and policy.slow_request_seconds is not None
                and observation.latency_seconds > policy.slow_request_seconds
            ):
                points += policy.slow_request_points
            if (
                observation.slot_lag is not None
                and policy.max_slot_lag is not None
                and observation.slot_lag > policy.max_slot_lag
            ):
                points += policy.slot_lag_points
            state.health_score = max(0.0, state.health_score + points)

            failed = observation.signal is not HealthSignal.SUCCESS or points > 0
            if is_probe:
                if failed:
                    state.probe_required = True
                    self._cool(state, now, observation.retry_after_seconds)
                else:
                    state.probe_required = False
                    state.cooldown_until = 0.0
                    state.cooldown_count = 0
                    state.health_score = 0.0
            elif state.health_score >= policy.score_threshold:
                state.probe_required = True
                self._cool(state, now, observation.retry_after_seconds)
            elif observation.retry_after_seconds is not None and observation.retry_after_seconds > 0:
                state.probe_required = True
                self._cool(state, now, observation.retry_after_seconds)
            self._condition.notify_all()

    def _cool(self, state: _NodeState, now: float, retry_after_seconds: float | None) -> None:
        already_cooling = state.cooldown_until > now
        if not already_cooling:
            state.cooldown_count += 1
        backoff = min(
            self.health_policy.max_cooldown_seconds,
            self.health_policy.cooldown_seconds * (2 ** min(max(state.cooldown_count - 1, 0), 30)),
        )
        requested = retry_after_seconds or 0.0
        state.cooldown_until = max(state.cooldown_until, now + backoff, now + requested)

    async def _release(self, state: _NodeState, *, is_probe: bool, observed: bool) -> None:
        async with self._condition:
            if state.in_flight <= 0:
                raise RuntimeError("endpoint in-flight counter underflow")
            state.in_flight -= 1
            if is_probe:
                state.probe_in_flight = False
                if not observed and state.probe_required:
                    # An abandoned probe must not implicitly rehabilitate a node.
                    state.cooldown_until = max(
                        state.cooldown_until,
                        self._clock() + self.health_policy.cooldown_seconds,
                    )
            self._condition.notify_all()
