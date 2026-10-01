"""Open-ended, backpressured streams for the DCG transaction sequencer.

Integration contract for Package C
-----------------------------------
Package C constructs a :class:`StreamIdentity` from the checked cluster,
application run/session, program and destinations, signer set, and caller-owned
route/commitment policy. It opens this API with ``await StreamingPlan.open``
and appends :class:`StreamIntent` records. Package C must provide stable intent
and recovery-policy digests plus JSON-safe ``intent_data`` that lets its
application adapter reconstruct runtime callbacks after restart. It must call
``record_signed_packet`` and ``record_send_attempt`` before provider handoff,
record each send result/observation, and call ``record_terminal`` only after
the configured stable commitment and app postcondition are established. A new
signature generation requires ``authorize_rebuild`` with app reconciliation
evidence. ``checkpoint`` waits for an app-selected terminal boundary, and
``close_input`` stops further appends while allowing the scheduler to drain or
leave work resumable. Pending plus in-flight steps count against the bound
until Package C records a terminal summary.

An observation at ``processed`` is labeled ``optimistic`` until a stable
observation or terminal result is recorded. After a dropped branch, the adapter
may mark even never-signed descendants ``reconciliation_required``. It releases
their pending slots only by journaling a reconciliation decision of ``abandon``
and then a terminal ``abandoned`` summary; this outcome does not claim finalized
commitment.

After resume, the adapter must reconcile unresolved packets before signing new
work. route_policy_digest must be the canonical digest of the configured
endpoint pool and provider configuration. observations exposes observations
restored from both active segments and sealed checkpoints.

This module is intentionally not exported from ``dcg.sequencer.__init__`` in
this package: Package C owns that integration surface.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Literal, Protocol, TypeVar

from .stream_journal import (
    PacketAttempt,
    SignedPacketRecord,
    StreamAppendReceipt,
    StreamCheckpoint,
    StreamClosed,
    StreamError,
    StreamIdentity,
    StreamIntent,
    StreamJournal,
    StreamJournalProtocol,
    StreamLifecycleEvent,
    StreamLimits,
    StreamObservation,
    StreamQuotaExceeded,
    StreamTerminal,
)

_T = TypeVar("_T")


class StreamingPlanProtocol(Protocol):
    """Typed stream surface with Package C recovery duties.

    After resume, Package C must reconcile unresolved packets before signing
    new work. route_policy_digest is a canonical digest of the endpoint-pool
    and provider configuration.
    """

    @property
    def identity(self) -> StreamIdentity: ...

    @property
    def pending_intents(self) -> tuple[tuple[int, StreamIntent], ...]: ...

    @property
    def pending_count(self) -> int: ...

    @property
    def sequence_digest(self) -> str: ...

    @property
    def terminal_summaries(self) -> dict[str, StreamTerminal]: ...

    @property
    def observations(self) -> tuple[StreamObservation, ...]: ...

    @property
    def optimistic_steps(self) -> tuple[str, ...]: ...

    async def append(self, intent: StreamIntent) -> StreamAppendReceipt: ...

    async def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint: ...

    async def close_input(self, *, wait_for_pending: bool = False) -> None: ...

    async def record_signed_packet(
        self, step_id: str, signature: str, raw_bytes: bytes, signer_public_key: str
    ) -> SignedPacketRecord: ...

    async def record_send_attempt(
        self, step_id: str, generation: int, *, provider_id: str, endpoint_id: str | None = None,
        route_group: str | None = None, route: Any | None = None,
        route_affinity: str | None = None, disposition: str | None = None
    ) -> PacketAttempt: ...

    async def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]: ...

    async def record_send_result(
        self, step_id: str, generation: int, attempt: int, *, acknowledged: bool,
        provider_id: str | None = None, endpoint_id: str | None = None,
        route_group: str | None = None, route: Any | None = None, receipt: Any | None = None,
        route_affinity: str | None = None,
        disposition: str | None = None, detail: str | None = None
    ) -> PacketAttempt: ...

    async def record_observation(
        self,
        step_id: str,
        generation: int,
        *,
        status_commitment: str | None,
        status_error: str | None,
        slot: int | None,
        postcondition_satisfied: bool | None,
        postcondition_digest: str | None,
    ) -> None: ...

    async def record_late_provider_failure(
        self, step_id: str, generation: int, attempt: int, *, provider_id: str | None = None,
        endpoint_id: str | None = None, route_group: str | None = None, route: Any | None = None,
        receipt: Any | None = None, disposition: str | None = None, detail: str,
        route_affinity: str | None = None
    ) -> None: ...

    async def record_step_dropped(self, step_id: str, generation: int, *, detail: str) -> None: ...

    async def record_optimistic_branch_invalidated(
        self, step_id: str, generation: int, *, detail: str
    ) -> None: ...

    async def record_reconciliation_required(
        self, step_id: str, generation: int, *, detail: str
    ) -> None: ...

    async def record_reconciliation_decision(
        self,
        step_id: str,
        generation: int,
        *,
        decision: Literal["abandon", "continue", "rebuild"],
        evidence_digest: str,
    ) -> int: ...

    async def record_terminal(self, terminal: StreamTerminal) -> None: ...


class StreamingPlan:
    """Async stream facade with package-level reconciliation duties.

    After resume, the application adapter must reconcile unresolved packets
    before signing new work. StreamIdentity.route_policy_digest must be the
    canonical digest of the configured endpoint pool and send providers.
    """

    def __init__(self, journal: StreamJournalProtocol, limits: StreamLimits):
        self._journal = journal
        self.limits = limits
        self._condition = asyncio.Condition()

    @classmethod
    async def open(
        cls,
        identity: StreamIdentity,
        path: str | Path,
        *,
        limits: StreamLimits,
    ) -> StreamingPlan:
        """Open or resume a stream after exact identity validation."""

        journal = await _run_thread(StreamJournal, path, identity, limits)
        return cls(journal, limits)

    @property
    def identity(self) -> StreamIdentity:
        return self._journal.identity

    @property
    def pending_count(self) -> int:
        return self._journal.pending_count

    @property
    def pending_intents(self) -> tuple[tuple[int, StreamIntent], ...]:
        return self._journal.pending_intents

    @property
    def sequence_digest(self) -> str:
        return self._journal.sequence_digest

    @property
    def terminal_summaries(self) -> dict[str, StreamTerminal]:
        return dict(self._journal.terminal_summaries)

    @property
    def observations(self) -> tuple[StreamObservation, ...]:
        return self._journal.observations

    @property
    def optimistic_steps(self) -> tuple[str, ...]:
        """Steps released at ``processed`` that have not reached stable status."""

        return self._journal.optimistic_steps

    @property
    def lifecycle_events(self) -> tuple[StreamLifecycleEvent, ...]:
        return self._journal.lifecycle_events

    @property
    def provider_failures(self) -> tuple[StreamLifecycleEvent, ...]:
        return self._journal.provider_failures

    @property
    def input_closed(self) -> bool:
        return self._journal.input_closed

    async def append(self, intent: StreamIntent) -> StreamAppendReceipt:
        """Durably append an intent, waiting while the outstanding bound is full."""

        async with self._condition:
            prior = self._journal.intents.get(intent.step_id)
            if prior is None:
                if self._journal.input_closed:
                    raise StreamClosed("stream input is closed")
                known = set(self._journal.intents)
                if any(dependency not in known for dependency in intent.dependencies):
                    raise StreamError(
                        "stream dependencies must name pending steps or the deterministic retained terminal window"
                    )
                while self.pending_count >= self.limits.max_pending_steps:
                    if self._journal.input_closed:
                        raise StreamClosed("stream input closed while append waited for capacity")
                    await self._condition.wait()
                if self._journal.input_closed:
                    raise StreamClosed("stream input is closed")
            return await _run_thread(self._journal.append_intent, intent)

    async def record_signed_packet(
        self,
        step_id: str,
        signature: str,
        raw_bytes: bytes,
        signer_public_key: str,
    ) -> SignedPacketRecord:
        """Fsync exact signed bytes before a provider can receive them."""

        return await _run_thread(
            self._journal.record_signed_packet, step_id, signature, raw_bytes, signer_public_key
        )

    async def authorize_rebuild(self, step_id: str, generation: int, evidence_digest: str) -> None:
        await _run_thread(self._journal.authorize_rebuild, step_id, generation, evidence_digest)

    async def record_send_attempt(
        self, step_id: str, generation: int, *, provider_id: str,
        endpoint_id: str | None = None, route_group: str | None = None,
        route: Any | None = None, route_affinity: str | None = None,
        disposition: str | None = None
    ) -> PacketAttempt:
        return await _run_thread(
            self._journal.record_send_attempt, step_id, generation,
            provider_id=provider_id, endpoint_id=endpoint_id, route_group=route_group, route=route,
            route_affinity=route_affinity, disposition=disposition,
        )

    async def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]:
        return await asyncio.to_thread(self._journal.unresolved_packets)

    async def record_send_result(
        self,
        step_id: str,
        generation: int,
        attempt: int,
        *,
        acknowledged: bool,
        provider_id: str | None = None,
        endpoint_id: str | None = None,
        route_group: str | None = None,
        route: Any | None = None,
        receipt: Any | None = None,
        route_affinity: str | None = None,
        disposition: str | None = None,
        detail: str | None = None,
    ) -> PacketAttempt:
        return await _run_thread(
            self._journal.record_send_result,
            step_id,
            generation,
            attempt,
            acknowledged=acknowledged,
            provider_id=provider_id,
            endpoint_id=endpoint_id,
            route_group=route_group,
            route=route,
            receipt=receipt,
            route_affinity=route_affinity,
            disposition=disposition,
            detail=detail,
        )

    async def record_observation(
        self,
        step_id: str,
        generation: int,
        *,
        status_commitment: str | None,
        status_error: str | None,
        slot: int | None,
        postcondition_satisfied: bool | None,
        postcondition_digest: str | None,
    ) -> None:
        await _run_thread(
            self._journal.record_observation,
            step_id,
            generation,
            status_commitment=status_commitment,
            status_error=status_error,
            slot=slot,
            postcondition_satisfied=postcondition_satisfied,
            postcondition_digest=postcondition_digest,
        )

    async def record_late_provider_failure(
        self, step_id: str, generation: int, attempt: int, *, provider_id: str | None = None,
        endpoint_id: str | None = None, route_group: str | None = None, route: Any | None = None,
        receipt: Any | None = None, disposition: str | None = None, detail: str,
        route_affinity: str | None = None
    ) -> None:
        await _run_thread(
            self._journal.record_late_provider_failure, step_id, generation, attempt,
            provider_id=provider_id, endpoint_id=endpoint_id, route_group=route_group,
            route=route, receipt=receipt, route_affinity=route_affinity,
            disposition=disposition, detail=detail,
        )

    async def record_step_dropped(self, step_id: str, generation: int, *, detail: str) -> None:
        await _run_thread(self._journal.record_step_dropped, step_id, generation, detail=detail)

    async def record_optimistic_branch_invalidated(
        self, step_id: str, generation: int, *, detail: str
    ) -> None:
        await _run_thread(
            self._journal.record_optimistic_branch_invalidated, step_id, generation, detail=detail
        )

    async def record_reconciliation_required(
        self, step_id: str, generation: int, *, detail: str
    ) -> None:
        await _run_thread(
            self._journal.record_reconciliation_required, step_id, generation, detail=detail
        )

    async def record_reconciliation_decision(
        self,
        step_id: str,
        generation: int,
        *,
        decision: Literal["abandon", "continue", "rebuild"],
        evidence_digest: str,
    ) -> int:
        return await _run_thread(
            self._journal.record_reconciliation_decision,
            step_id,
            generation,
            decision=decision,
            evidence_digest=evidence_digest,
        )

    async def record_terminal(self, terminal: StreamTerminal) -> None:
        async with self._condition:
            try:
                await _run_thread(self._journal.record_terminal, terminal)
            finally:
                self._condition.notify_all()

    async def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint:
        """Wait for the selected prefix to become terminal, then rotate safely."""

        async with self._condition:
            boundary = self._journal.next_stream_sequence - 1 if through_sequence is None else through_sequence
            if boundary < 0 or boundary >= self._journal.next_stream_sequence:
                raise StreamError("checkpoint boundary is outside the appended stream")
            while any(sequence <= boundary for sequence, _ in self.pending_intents):
                await self._condition.wait()
            return await _run_thread(self._journal.checkpoint, boundary)

    async def close_input(self, *, wait_for_pending: bool = False) -> None:
        """Stop admitting intents; optionally wait for the scheduler to drain."""

        async with self._condition:
            try:
                await _run_thread(self._journal.close_input)
            finally:
                self._condition.notify_all()
            if wait_for_pending:
                while self.pending_count:
                    await self._condition.wait()

    async def wait_for_capacity(self) -> None:
        """Wait until an outstanding slot is available to a producer."""

        async with self._condition:
            while self.pending_count >= self.limits.max_pending_steps and not self._journal.input_closed:
                await self._condition.wait()

    async def close(self) -> None:
        """Release the process-wide single-writer lock."""

        await asyncio.to_thread(self._journal.close)


async def _run_thread(function: Callable[..., _T], /, *args: Any, **kwargs: Any) -> _T:
    """Keep the async admission lock until an fsync operation really finishes."""

    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await asyncio.shield(task)
        except Exception:
            # Cancellation is the caller-visible result; the journal operation
            # has nevertheless finished and remains recoverable on disk.
            pass
        raise


__all__ = [
    "PacketAttempt",
    "SignedPacketRecord",
    "StreamAppendReceipt",
    "StreamCheckpoint",
    "StreamClosed",
    "StreamError",
    "StreamIdentity",
    "StreamIntent",
    "StreamJournalProtocol",
    "StreamLifecycleEvent",
    "StreamLimits",
    "StreamObservation",
    "StreamQuotaExceeded",
    "StreamTerminal",
    "StreamingPlan",
    "StreamingPlanProtocol",
]
