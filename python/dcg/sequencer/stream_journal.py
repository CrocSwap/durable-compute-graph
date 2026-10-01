"""Versioned durable journal primitives for open-ended transaction streams.

The stream WAL is append-only between checkpoints. A checkpoint stores pending
work, a deterministic terminal window with each retained generation's
signature, observations/lifecycle rows for those steps, a bounded recent step-ID
window, and recent orphan provider failures. It never copies segment history.
Once its manifest pointer commits, older checkpoints and covered segments are
deleted. Fixed-plan journal v1 remains implemented by journal.py and is
unchanged. A complete final WAL row without a trailing newline is accepted and
repaired when the stream resumes.

An append may depend only on pending steps or one of the last
``max_pending_steps`` terminal steps by stream sequence. Older dependencies are
refused before writing, independent of segment rotation timing. Checkpoint
layout changes are stream schema 4; schema 3 journals are refused rather than
silently migrated. Applications
must also use globally unique step IDs for the stream lifetime and map late
provider failures to their original step, generation, and attempt. Compacted
late failures are stored as orphan events because their packet records are gone.
At most 64 orphan failures and 512 recent appended step IDs are retained across
checkpoint compaction; duplicate checks cover the retained orphan window.

For packets that invoke this stream program, every instruction account meta
must appear in ``destination_accounts``. That includes the payer, authority,
and system program when they are instruction accounts. The stream program ID is
checked separately against ``program_id``. Instructions to other programs are
not checked by this destination rule.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import sys
import threading
from enum import Enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol

from .types import JournalError


STREAM_SCHEMA_VERSION = 4
MAX_RETAINED_ORPHAN_FAILURES = 64
MAX_RECENT_APPENDED_STEP_IDS = 512
_ZERO_DIGEST = "0" * 64
_SEQUENCE_DOMAIN = b"dcg-stream-sequence-v1\0"
_INTENT_DOMAIN = b"dcg-stream-intent-v1\0"
_HISTORY_EVENTS = frozenset(
    {
        "step_observed",
        "step_confirmed",
        "step_terminal_failure",
        "late_provider_failure",
        "step_dropped",
        "optimistic_branch_invalidated",
        "reconciliation_required",
        "reconciliation_decision",
        "step_abandoned_after_reconciliation",
    }
)


class StreamError(JournalError):
    """Base class for stream journal and lifecycle errors."""


class StreamQuotaExceeded(StreamError):
    """The journal cannot safely persist another event within its hard quota."""


class StreamClosed(StreamError):
    """Input has been closed and cannot accept another new intent."""


@dataclass(frozen=True)
class StreamIdentity:
    """Stable application, cluster, program, account, signer, and route identity."""

    run_id: str
    genesis_hash: str
    program_id: str
    destination_accounts: tuple[str, ...]
    signer_public_keys: tuple[str, ...]
    route_policy_digest: str
    commitment_policy: str = "confirmed"

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "genesis_hash",
            "program_id",
            "route_policy_digest",
            "commitment_policy",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty text")
        for name in ("destination_accounts", "signer_public_keys"):
            values = getattr(self, name)
            if not values or any(not isinstance(value, str) or not value for value in values):
                raise ValueError(f"{name} must contain non-empty identities")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        # Both identity sets use lexical ordering as their canonical encoding.
        object.__setattr__(self, "destination_accounts", tuple(sorted(self.destination_accounts)))
        object.__setattr__(self, "signer_public_keys", tuple(sorted(self.signer_public_keys)))

    def to_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "genesis_hash": self.genesis_hash,
            "program_id": self.program_id,
            "destination_accounts": list(self.destination_accounts),
            "signer_public_keys": list(self.signer_public_keys),
            "route_policy_digest": self.route_policy_digest,
            "commitment_policy": self.commitment_policy,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> StreamIdentity:
        try:
            return cls(
                run_id=value["run_id"],
                genesis_hash=value["genesis_hash"],
                program_id=value["program_id"],
                destination_accounts=tuple(value["destination_accounts"]),
                signer_public_keys=tuple(value["signer_public_keys"]),
                route_policy_digest=value["route_policy_digest"],
                commitment_policy=value["commitment_policy"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StreamError("invalid stream identity record") from exc

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_record())).hexdigest()


@dataclass(frozen=True)
class StreamIntent:
    """Serializable facts needed to durably admit one application step."""

    step_id: str
    dependencies: tuple[str, ...]
    route_group: str
    compute_class: str
    compute_unit_limit: int
    intent_digest: str
    recovery_policy_digest: str
    intent_data: Mapping[str, Any] = field(default_factory=dict)
    max_packet_bytes: int = 1232
    write_locks: tuple[str, ...] = ()
    route_affinity: str | None = None

    def __post_init__(self) -> None:
        for name in ("step_id", "route_group", "compute_class", "intent_digest", "recovery_policy_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty text")
        if self.route_affinity is not None and (
            not isinstance(self.route_affinity, str) or not self.route_affinity
        ):
            raise ValueError("route_affinity must be non-empty text or null")
        if len(self.step_id.encode("utf-8")) > 256:
            raise ValueError("step_id is too long")
        if (
            not isinstance(self.compute_unit_limit, int)
            or isinstance(self.compute_unit_limit, bool)
            or not isinstance(self.max_packet_bytes, int)
            or isinstance(self.max_packet_bytes, bool)
            or self.compute_unit_limit <= 0
            or not 0 < self.max_packet_bytes <= 1232
        ):
            raise ValueError("compute and packet limits must be positive and packet size at most 1232")
        if any(not isinstance(value, str) or not value for value in (*self.dependencies, *self.write_locks)):
            raise ValueError("dependencies and write_locks must contain non-empty text")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("dependencies must not contain duplicates")
        if len(set(self.write_locks)) != len(self.write_locks):
            raise ValueError("write_locks must not contain duplicates")
        if self.step_id in self.dependencies:
            raise ValueError("an intent cannot depend on itself")
        if not isinstance(self.intent_data, Mapping):
            raise ValueError("intent_data must be a JSON object")
        object.__setattr__(self, "intent_data", json.loads(_canonical_json(self.intent_data)))

    def to_record(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "dependencies": list(self.dependencies),
            "route_group": self.route_group,
            "route_affinity": self.route_affinity,
            "compute_class": self.compute_class,
            "compute_unit_limit": self.compute_unit_limit,
            "intent_digest": self.intent_digest,
            "recovery_policy_digest": self.recovery_policy_digest,
            "intent_data": json.loads(_canonical_json(self.intent_data)),
            "max_packet_bytes": self.max_packet_bytes,
            "write_locks": list(self.write_locks),
        }

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> StreamIntent:
        try:
            return cls(
                step_id=value["step_id"],
                dependencies=tuple(value["dependencies"]),
                route_group=value["route_group"],
                route_affinity=value.get("route_affinity"),
                compute_class=value["compute_class"],
                compute_unit_limit=value["compute_unit_limit"],
                intent_digest=value["intent_digest"],
                recovery_policy_digest=value["recovery_policy_digest"],
                intent_data=value.get("intent_data", {}),
                max_packet_bytes=value["max_packet_bytes"],
                write_locks=tuple(value["write_locks"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StreamError("invalid stream intent record") from exc


@dataclass(frozen=True)
class StreamLimits:
    """Caller-selected memory, attempt, and disk bounds for one open stream."""

    max_pending_steps: int = 128
    max_segment_bytes: int = 1_048_576
    max_journal_bytes: int = 67_108_864
    append_reserve_bytes: int = 4096
    max_intent_bytes: int = 16_384
    max_attempts_per_generation: int = 8
    max_observations_per_generation: int = 8
    max_generations_per_step: int = 2

    def __post_init__(self) -> None:
        if self.max_pending_steps <= 0:
            raise ValueError("max_pending_steps must be positive")
        if self.max_segment_bytes < 512:
            raise ValueError("max_segment_bytes must be at least 512")
        if self.max_journal_bytes < max(self.max_segment_bytes, 4096):
            raise ValueError("max_journal_bytes must be at least max_segment_bytes and 4096")
        if self.append_reserve_bytes < 0 or self.append_reserve_bytes >= self.max_journal_bytes:
            raise ValueError("append_reserve_bytes must be non-negative and smaller than the journal quota")
        for name in (
            "max_intent_bytes",
            "max_attempts_per_generation",
            "max_observations_per_generation",
            "max_generations_per_step",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_generations_per_step > 8:
            raise ValueError("max_generations_per_step cannot exceed 8")


@dataclass(frozen=True)
class StreamAppendReceipt:
    step_id: str
    sequence: int
    sequence_digest: str
    already_present: bool


@dataclass(frozen=True)
class StreamTerminal:
    """Durable stable result or adapter-authorized abandonment summary."""

    step_id: str
    outcome: Literal["confirmed", "failed", "abandoned"]
    signature: str | None
    commitment: str | None
    postcondition_satisfied: bool
    postcondition_digest: str
    slot: int | None = None
    error: str | None = None
    reconciliation_decision_event_sequence: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.step_id, str) or not self.step_id:
            raise ValueError("terminal step identity must be non-empty text")
        if not isinstance(self.outcome, str) or self.outcome not in {"confirmed", "failed", "abandoned"}:
            raise ValueError("terminal outcome must be confirmed, failed, or abandoned")
        if self.signature is not None and (not isinstance(self.signature, str) or not self.signature):
            raise ValueError("terminal signature must be non-empty text or null")
        if self.commitment is not None and not isinstance(self.commitment, str):
            raise ValueError("terminal commitment must be text or null")
        if not isinstance(self.postcondition_satisfied, bool):
            raise ValueError("terminal postcondition result must be boolean")
        if not isinstance(self.postcondition_digest, str) or not self.postcondition_digest:
            raise ValueError("terminal summary must bind a postcondition digest")
        if len(self.postcondition_digest) > 256 or (
            self.commitment is not None and len(self.commitment) > 64
        ):
            raise ValueError("terminal commitment and postcondition digest exceed their bounds")
        if self.error is not None and (not isinstance(self.error, str) or len(self.error) > 512):
            raise ValueError("terminal error must be at most 512 characters or null")
        if self.outcome == "confirmed" and not self.postcondition_satisfied:
            raise ValueError("a confirmed terminal step requires a satisfied postcondition")
        if self.outcome == "failed" and self.postcondition_satisfied:
            raise ValueError("a failed terminal step cannot have a satisfied postcondition")
        if self.outcome in {"confirmed", "failed"} and (not self.signature or not self.commitment):
            raise ValueError("signed terminal outcomes require a signature and commitment")
        if self.outcome == "confirmed" and self.commitment not in {"confirmed", "finalized"}:
            raise ValueError("a confirmed terminal step requires stable commitment")
        if self.outcome == "failed" and self.commitment != "finalized":
            raise ValueError("a terminal failure requires finalized commitment")
        if self.outcome == "abandoned" and (
            self.commitment is not None
            or self.postcondition_satisfied
            or self.reconciliation_decision_event_sequence is None
        ):
            raise ValueError("abandonment requires a journaled reconciliation decision, no commitment, and a false postcondition")
        if self.reconciliation_decision_event_sequence is not None and (
            not isinstance(self.reconciliation_decision_event_sequence, int)
            or isinstance(self.reconciliation_decision_event_sequence, bool)
            or self.reconciliation_decision_event_sequence < 0
        ):
            raise ValueError("reconciliation decision event sequence must be non-negative")
        if self.slot is not None and (
            not isinstance(self.slot, int) or isinstance(self.slot, bool) or self.slot < 0
        ):
            raise ValueError("slot must be non-negative")

    def to_record(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "outcome": self.outcome,
            "signature": self.signature,
            "commitment": self.commitment,
            "postcondition_satisfied": self.postcondition_satisfied,
            "postcondition_digest": self.postcondition_digest,
            "slot": self.slot,
            "error": self.error,
            "reconciliation_decision_event_sequence": self.reconciliation_decision_event_sequence,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> StreamTerminal:
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise StreamError("invalid terminal summary") from exc


@dataclass(frozen=True)
class PacketAttempt:
    number: int
    started_event_sequence: int
    finished_event_sequence: int | None = None
    outcome: Literal["acknowledged", "error"] | None = None
    detail: str | None = None
    provider_id: str = ""
    endpoint_id: str = ""
    route_group: str = ""
    route_affinity: str | None = None
    disposition: str | None = None


@dataclass(frozen=True)
class SignedPacketRecord:
    step_id: str
    generation: int
    signature: str
    raw_bytes: bytes
    packet_digest: str
    signer_public_key: str
    signed_event_sequence: int
    segment_index: int
    attempts: tuple[PacketAttempt, ...] = ()


@dataclass(frozen=True)
class StreamObservation:
    step_id: str
    generation: int
    signature: str
    status_commitment: str | None
    status_error: str | None
    slot: int | None
    postcondition_satisfied: bool | None
    postcondition_digest: str | None
    event_sequence: int

    @property
    def label(self) -> Literal["optimistic", "stable", "unresolved"]:
        """Classify progress released at processed without calling it confirmed."""

        if self.status_commitment == "processed":
            return "optimistic"
        if self.status_commitment in {"confirmed", "finalized"}:
            return "stable"
        return "unresolved"


@dataclass(frozen=True)
class StreamLifecycleEvent:
    event: str
    step_id: str
    generation: int
    event_sequence: int
    data: Mapping[str, Any]


@dataclass(frozen=True)
class StreamCheckpoint:
    checkpoint_id: str
    through_sequence: int
    stream_sequence_high_water_mark: int
    sequence_digest: str
    confirmed_steps: Mapping[str, Mapping[str, Any]]
    terminal_steps: Mapping[str, Mapping[str, Any]]
    unresolved_packet_references: tuple[Mapping[str, Any], ...]
    checkpoint_digest: str
    event_high_water_mark: int = -1


class StreamJournalProtocol(Protocol):
    @property
    def identity(self) -> StreamIdentity: ...
    @property
    def intents(self) -> Mapping[str, tuple[int, StreamIntent, str]]: ...
    @property
    def terminals(self) -> Mapping[str, StreamTerminal]: ...

    @property
    def terminal_summaries(self) -> Mapping[str, StreamTerminal]: ...

    @property
    def pending_count(self) -> int: ...

    @property
    def pending_intents(self) -> tuple[tuple[int, StreamIntent], ...]: ...

    @property
    def observations(self) -> tuple[StreamObservation, ...]: ...

    @property
    def optimistic_steps(self) -> tuple[str, ...]: ...

    @property
    def lifecycle_events(self) -> tuple[StreamLifecycleEvent, ...]: ...

    @property
    def provider_failures(self) -> tuple[StreamLifecycleEvent, ...]: ...
    @property
    def input_closed(self) -> bool: ...
    @property
    def next_stream_sequence(self) -> int: ...
    @property
    def sequence_digest(self) -> str: ...
    def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]: ...
    def append_intent(self, intent: StreamIntent) -> StreamAppendReceipt: ...
    def record_signed_packet(self, step_id: str, signature: str, raw_bytes: bytes, signer_public_key: str) -> SignedPacketRecord: ...
    def record_send_attempt(self, step_id: str, generation: int, **route: Any) -> PacketAttempt: ...
    def record_send_result(self, step_id: str, generation: int, attempt: int, *, acknowledged: bool, **route: Any) -> PacketAttempt: ...
    def record_observation(self, step_id: str, generation: int, **observation: Any) -> None: ...
    def record_late_provider_failure(self, step_id: str, generation: int, attempt: int, **failure: Any) -> None: ...
    def record_reconciliation_required(self, step_id: str, generation: int, *, detail: str) -> None: ...
    def record_reconciliation_decision(self, step_id: str, generation: int, **decision: Any) -> int: ...
    def record_terminal(self, terminal: StreamTerminal) -> None: ...
    def close_input(self) -> None: ...
    def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint: ...

    def close(self) -> None: ...


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("stream records must contain canonical JSON values") from exc


def _intent_digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_INTENT_DOMAIN + _canonical_json(record)).hexdigest()


def _advance_sequence_digest(previous_hex: str, sequence: int, record_digest: str) -> str:
    return hashlib.sha256(
        _SEQUENCE_DOMAIN
        + bytes.fromhex(previous_hex)
        + sequence.to_bytes(8, "big")
        + bytes.fromhex(record_digest)
    ).hexdigest()


def _initial_sequence_digest(identity_digest: str) -> str:
    return hashlib.sha256(_SEQUENCE_DOMAIN + bytes.fromhex(identity_digest)).hexdigest()


def _verify_signed_transaction(
    raw_bytes: bytes,
    expected_signature: str,
    declared_signer: str,
    identity: StreamIdentity,
) -> None:
    """Verify bytes, signer membership, and statically verifiable stream targets.

    Packets using address-table lookups are rejected because the journal cannot
    verify loaded addresses without the adapter's lookup-table snapshot.
    """

    try:
        from solders.transaction import VersionedTransaction

        transaction = VersionedTransaction.from_bytes(raw_bytes)
        if bytes(transaction) != raw_bytes:
            raise StreamError("signed transaction is not canonically encoded")
        message = transaction.message
        required_signatures = message.header.num_required_signatures
        signer_keys = tuple(str(key) for key in message.account_keys[:required_signatures])
        if not required_signatures or len(transaction.signatures) != required_signatures:
            raise StreamError("signed transaction signature count does not match its message")
        if str(transaction.signatures[0]) != expected_signature:
            raise StreamError("signed transaction signature does not match its packet record")
        if declared_signer not in signer_keys or any(key not in identity.signer_public_keys for key in signer_keys):
            raise StreamError("signed transaction required signer is outside the bound signer set")
        if not all(transaction.verify_with_results()):
            raise StreamError("signed transaction contains an invalid signature")
        lookups = getattr(message, "address_table_lookups", ())
        if lookups:
            raise StreamError("address-table packets require adapter verification of loaded destinations")
        keys = tuple(str(key) for key in message.account_keys)
        destination_set = set(identity.destination_accounts)
        touched_destinations: set[str] = set()
        invoked_stream_program = False
        for instruction in message.instructions:
            program_id = keys[instruction.program_id_index]
            if program_id != identity.program_id:
                continue
            invoked_stream_program = True
            for account_index in instruction.accounts:
                account = keys[account_index]
                if account not in destination_set:
                    raise StreamError("stream program instruction touches an account outside the identity")
                touched_destinations.add(account)
        if not invoked_stream_program or not touched_destinations:
            raise StreamError("signed packet does not invoke the stream program on a bound destination")
    except StreamError:
        raise
    except Exception as exc:
        raise StreamError("signed transaction packet is invalid") from exc




class StreamJournal:
    """Single-writer stream WAL with checkpoint recovery and quota reservations."""

    def __init__(self, path: str | os.PathLike[str], identity: StreamIdentity, limits: StreamLimits):
        self.path = Path(path)
        self.limits = limits
        self._append_reserve_bytes = max(
            limits.append_reserve_bytes,
            min(limits.max_segment_bytes, limits.max_journal_bytes // 16),
        )
        self._lock = threading.RLock()
        self._poisoned = False
        self._lock_fd: int | None = None
        self._disk_bytes = 0
        self._bytes_written = 0
        self._identity = identity
        self._intents: dict[str, tuple[int, StreamIntent, str]] = {}
        self._intent_chain_digests: dict[str, str] = {}
        self._known_step_ids: set[str] = set()
        self._known_step_order: list[str] = []
        self._pending: dict[str, tuple[int, StreamIntent, str]] = {}
        self._terminals: dict[str, StreamTerminal] = {}
        self._terminal_packet_signatures: dict[str, dict[int, str]] = {}
        self._reserve_left: dict[str, int] = {}
        self._terminal_reserve_left: dict[str, int] = {}
        self._packet_index: dict[tuple[str, int], SignedPacketRecord] = {}
        self._attempt_index: dict[tuple[str, int], list[PacketAttempt]] = {}
        self._rebuild_authorizations: list[dict[str, Any]] = []
        self._observations_by_step: dict[str, list[StreamObservation]] = {}
        self._lifecycle_events_by_step: dict[str, list[StreamLifecycleEvent]] = {}
        self._orphan_provider_failures: dict[tuple[str, int, int], StreamLifecycleEvent] = {}
        self._reconciliation_decisions: dict[tuple[str, int], tuple[int, str, str]] = {}
        self._next_event_sequence = 0
        self._next_stream_sequence = 1
        self._sequence_digest = _initial_sequence_digest(identity.digest)
        self._input_closed = False
        self._active_bytes = 0
        self._manifest: dict[str, Any] = {}
        try:
            self._open(identity)
        except Exception:
            self.close()
            raise

    @property
    def identity(self) -> StreamIdentity:
        return self._identity

    @property
    def intents(self) -> Mapping[str, tuple[int, StreamIntent, str]]:
        with self._lock:
            return dict(self._intents)

    @property
    def terminals(self) -> Mapping[str, StreamTerminal]:
        with self._lock:
            return dict(self._terminals)

    @property
    def terminal_summaries(self) -> Mapping[str, StreamTerminal]:
        return self.terminals

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def pending_intents(self) -> tuple[tuple[int, StreamIntent], ...]:
        with self._lock:
            return tuple(
                (sequence, intent)
                for sequence, intent, _ in sorted(
                    self._pending.values(), key=lambda row: row[0]
                )
            )

    @property
    def input_closed(self) -> bool:
        with self._lock:
            return self._input_closed

    @property
    def next_stream_sequence(self) -> int:
        with self._lock:
            return self._next_stream_sequence

    @property
    def sequence_digest(self) -> str:
        with self._lock:
            return self._sequence_digest

    @property
    def observations(self) -> tuple[StreamObservation, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (row for rows in self._observations_by_step.values() for row in rows),
                    key=lambda row: row.event_sequence,
                )
            )

    @property
    def optimistic_steps(self) -> tuple[str, ...]:
        """Pending steps whose latest recorded status is only ``processed``."""

        with self._lock:
            optimistic = []
            for step_id, (sequence, _intent, _digest) in sorted(
                self._pending.items(), key=lambda item: item[1][0]
            ):
                rows = self._observations_by_step.get(step_id, ())
                processed = [
                    row for row in rows if row.status_commitment == "processed"
                ]
                stable_sequences = {
                    row.event_sequence
                    for row in rows
                    if row.status_commitment in {"confirmed", "finalized"}
                }
                if processed:
                    latest_processed = max(row.event_sequence for row in processed)
                    if not any(event_sequence > latest_processed for event_sequence in stable_sequences):
                        optimistic.append((sequence, step_id))
            return tuple(step_id for _sequence, step_id in optimistic)

    @property
    def lifecycle_events(self) -> tuple[StreamLifecycleEvent, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        row
                        for row in (
                            [event for rows in self._lifecycle_events_by_step.values() for event in rows]
                            + list(self._orphan_provider_failures.values())
                        )
                    ),
                    key=lambda row: row.event_sequence,
                )
            )

    @property
    def provider_failures(self) -> tuple[StreamLifecycleEvent, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        row
                        for row in (
                            [event for rows in self._lifecycle_events_by_step.values() for event in rows]
                            + list(self._orphan_provider_failures.values())
                        )
                        if row.event == "late_provider_failure"
                    ),
                    key=lambda row: row.event_sequence,
                )
            )

    @property
    def disk_bytes(self) -> int:
        with self._lock:
            return self._disk_bytes

    @property
    def bytes_written(self) -> int:
        with self._lock:
            return self._bytes_written

    @property
    def manifest_bytes(self) -> int:
        with self._lock:
            try:
                return (self.path / "manifest.json").stat().st_size
            except OSError:
                return 0

    @property
    def event_high_water_mark(self) -> int:
        with self._lock:
            return self._next_event_sequence - 1

    def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]:
        with self._lock:
            unresolved_ids = set(self._pending)
            return tuple(
                SignedPacketRecord(
                    step_id=record.step_id,
                    generation=record.generation,
                    signature=record.signature,
                    raw_bytes=record.raw_bytes,
                    packet_digest=record.packet_digest,
                    signer_public_key=record.signer_public_key,
                    signed_event_sequence=record.signed_event_sequence,
                    segment_index=record.segment_index,
                    attempts=tuple(self._attempt_index[(record.step_id, record.generation)]),
                )
                for (step_id, _), record in sorted(
                    self._packet_index.items(),
                    key=lambda item: (item[1].signed_event_sequence, item[0][1]),
                )
                if step_id in unresolved_ids
            )

    def append_intent(self, intent: StreamIntent) -> StreamAppendReceipt:
        with self._lock:
            self._ensure_usable()
            record = intent.to_record()
            encoded_intent = _canonical_json(record)
            if len(encoded_intent) > self.limits.max_intent_bytes:
                raise StreamQuotaExceeded("stream intent exceeds max_intent_bytes")
            digest = _intent_digest(record)
            prior = self._intents.get(intent.step_id)
            if prior is not None:
                sequence, prior_intent, prior_digest = prior
                if prior_digest != digest or prior_intent.to_record() != record:
                    raise StreamError(f"step {intent.step_id!r} was already appended with different intent")
                return StreamAppendReceipt(
                    intent.step_id,
                    sequence,
                    self._intent_chain_digests[intent.step_id],
                    True,
                )
            if intent.step_id in self._known_step_ids:
                raise StreamError(f"step {intent.step_id!r} was already appended in the retained stream history")
            if self._input_closed:
                raise StreamClosed("stream input is closed")
            if len(self._pending) >= self.limits.max_pending_steps:
                raise StreamQuotaExceeded("pending stream-step limit reached")
            retained_terminals = self._terminal_keep_ids()
            if any(
                dependency not in self._pending and dependency not in retained_terminals
                for dependency in intent.dependencies
            ):
                raise StreamError(
                    "stream dependencies must name pending steps or the deterministic retained terminal window"
                )
            sequence = self._next_stream_sequence
            if any(self._intents[dependency][0] >= sequence for dependency in intent.dependencies):
                raise StreamError("stream dependency does not precede the appended step")
            prior_digest = self._sequence_digest
            chain_digest = _advance_sequence_digest(prior_digest, sequence, digest)
            self._append_event(
                "step_appended",
                {
                    "stream_sequence": sequence,
                    "intent": record,
                    "intent_record_digest": digest,
                    "previous_sequence_digest": prior_digest,
                    "sequence_digest": chain_digest,
                },
                admission_reserve=self._step_reserve(intent) + self._terminal_step_reserve(intent),
            )
            return StreamAppendReceipt(intent.step_id, sequence, chain_digest, False)

    def record_signed_packet(
        self, step_id: str, signature: str, raw_bytes: bytes, signer_public_key: str
    ) -> SignedPacketRecord:
        with self._lock:
            self._ensure_usable()
            intent_entry = self._pending.get(step_id)
            if intent_entry is None:
                raise StreamError(f"cannot sign unknown or terminal stream step {step_id!r}")
            if not isinstance(signature, str) or not signature or not isinstance(raw_bytes, bytes) or not raw_bytes:
                raise StreamError("signed packet signature and bytes must be non-empty")
            if not isinstance(signer_public_key, str) or not signer_public_key:
                raise StreamError("signed packet signer identity must be non-empty text")
            latest_generation = max(
                (generation for candidate, generation in self._packet_index if candidate == step_id),
                default=-1,
            )
            if latest_generation >= 0:
                latest = self._packet_index[(step_id, latest_generation)]
                if (
                    latest.signature == signature
                    and latest.raw_bytes == raw_bytes
                    and latest.signer_public_key == signer_public_key
                ):
                    return latest
            intent = intent_entry[1]
            if len(raw_bytes) > intent.max_packet_bytes:
                raise StreamError("signed packet exceeds the appended step packet limit")
            if signer_public_key not in self.identity.signer_public_keys:
                raise StreamError("signed packet signer is outside the bound signer set")
            _verify_signed_transaction(raw_bytes, signature, signer_public_key, self.identity)
            generation = latest_generation + 1
            if generation >= self.limits.max_generations_per_step:
                raise StreamError("signed generation limit reached for stream step")
            authorized = any(
                row["step_id"] == step_id and row["next_generation"] == generation
                for row in self._rebuild_authorizations
            )
            if generation > 0 and not authorized:
                raise StreamError("a new signed generation requires journaled adapter authorization")
            packet_digest = hashlib.sha256(raw_bytes).hexdigest()
            self._append_event(
                "step_signed",
                {
                    "step_id": step_id,
                    "stream_sequence": intent_entry[0],
                    "generation": generation,
                    "signature": signature,
                    "raw_transaction": base64.b64encode(raw_bytes).decode("ascii"),
                    "packet_digest": packet_digest,
                    "signer_public_key": signer_public_key,
                },
                reservation_step=step_id if step_id in self._pending else None,
            )
            return self._packet_index[(step_id, generation)]

    def authorize_rebuild(self, step_id: str, generation: int, evidence_digest: str) -> None:
        with self._lock:
            self._ensure_usable()
            if not isinstance(step_id, str) or not step_id:
                raise StreamError("step identity must be non-empty text")
            packet = self._packet_index.get((step_id, generation))
            latest_generation = max(
                (candidate for candidate_step, candidate in self._packet_index if candidate_step == step_id),
                default=-1,
            )
            if (
                packet is None
                or step_id not in self._pending
                or generation != latest_generation
                or not isinstance(evidence_digest, str)
                or not evidence_digest
                or len(evidence_digest) > 256
            ):
                raise StreamError("rebuild authorization must reference a pending latest packet and evidence digest")
            next_generation = generation + 1
            if next_generation >= self.limits.max_generations_per_step:
                raise StreamError("signed generation limit reached for stream step")
            if any(row["step_id"] == step_id and row["next_generation"] == next_generation for row in self._rebuild_authorizations):
                raise StreamError("replacement generation is already authorized")
            self._append_event(
                "step_rebuild_authorized",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": packet.signature,
                    "next_generation": next_generation,
                    "evidence_digest": evidence_digest,
                },
                reservation_step=step_id,
            )

    def record_send_attempt(
        self,
        step_id: str,
        generation: int,
        *,
        provider_id: str,
        endpoint_id: str | None = None,
        route_group: str | None = None,
        route: Any | None = None,
        route_affinity: str | None = None,
        disposition: str | None = None,
    ) -> PacketAttempt:
        with self._lock:
            packet = self._require_packet(step_id, generation)
            route_record = self._resolve_route(
                provider_id,
                endpoint_id,
                route_group,
                route_affinity,
                disposition,
                route=route,
                allow_no_disposition=True,
            )
            attempts = self._attempt_index[(step_id, generation)]
            if len(attempts) >= self.limits.max_attempts_per_generation:
                raise StreamError("send attempt limit reached for signed generation")
            self._append_event(
                "send_attempt_started",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": packet.signature,
                    "attempt": len(attempts) + 1,
                    **route_record,
                },
                reservation_step=step_id,
            )
            return self._attempt_index[(step_id, generation)][-1]

    def record_send_result(
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
        with self._lock:
            packet = self._require_packet(step_id, generation)
            if not isinstance(acknowledged, bool):
                raise StreamError("send acknowledgment flag must be boolean")
            if detail is not None and (not isinstance(detail, str) or len(detail) > 512):
                raise StreamError("send result detail must be at most 512 characters or null")
            attempts = self._attempt_index[(step_id, generation)]
            if not 0 < attempt <= len(attempts):
                raise StreamError("send result references an unknown attempt")
            current = attempts[attempt - 1]
            if current.finished_event_sequence is not None or current.number != attempt:
                raise StreamError("send attempt already has a result or is out of order")
            provider_id, endpoint_id, disposition = self._receipt_values(
                receipt, provider_id, endpoint_id, disposition, packet.signature
            )
            endpoint_id = current.endpoint_id if endpoint_id is None else endpoint_id
            route_group = current.route_group if route_group is None and route is None else route_group
            route_affinity = (
                current.route_affinity
                if route_affinity is None and route is None
                else route_affinity
            )
            route_record = self._resolve_route(
                provider_id or current.provider_id,
                endpoint_id,
                route_group,
                route_affinity,
                disposition,
                route=route,
                allow_no_disposition=not acknowledged,
            )
            values = {
                "provider_id": route_record["provider_id"],
                "endpoint_id": route_record["endpoint_id"],
                "route_group": route_record["route_group"],
                "route_affinity": route_record["route_affinity"],
                "disposition": route_record["disposition"],
            }
            normalized = self._validate_route(**values, allow_no_disposition=not acknowledged)
            for field_name in ("provider_id", "endpoint_id", "route_group", "route_affinity"):
                if normalized[field_name] != getattr(current, field_name):
                    raise StreamError(f"send result {field_name} differs from its route reservation")
            outcome: Literal["acknowledged", "error"] = "acknowledged" if acknowledged else "error"
            self._append_event(
                "send_attempt_finished",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": packet.signature,
                    "attempt": attempt,
                    "outcome": outcome,
                    "detail": detail,
                    **normalized,
                },
                reservation_step=step_id,
            )
            return self._attempt_index[(step_id, generation)][attempt - 1]

    def record_late_provider_failure(
        self,
        step_id: str,
        generation: int,
        attempt: int,
        *,
        provider_id: str | None = None,
        endpoint_id: str | None = None,
        route_group: str | None = None,
        route: Any | None = None,
        receipt: Any | None = None,
        disposition: str | None = None,
        detail: str,
        route_affinity: str | None = None,
    ) -> None:
        """Record a delayed provider error, orphaning it after packet compaction.

        The adapter must map provider output to the original step, generation,
        and attempt. A compacted or terminal step has no packet lookup; the
        supplied receipt/route data is the provider's attestation.
        """

        with self._lock:
            self._ensure_usable()
            if not isinstance(step_id, str) or not step_id:
                raise StreamError("late provider failure step identity must be non-empty text")
            if not isinstance(detail, str) or not detail or len(detail) > 512:
                raise StreamError("late provider failure detail must be 1 to 512 characters")
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
                or not isinstance(attempt, int)
                or isinstance(attempt, bool)
                or attempt <= 0
            ):
                raise StreamError("late failure generation and attempt must be non-negative/positive integers")
            if step_id not in self._known_step_ids:
                raise StreamError("late provider failure references a step id that was never appended or is no longer retained")
            packet = self._packet_index.get((step_id, generation))
            orphan = step_id not in self._pending
            if packet is None and not orphan:
                raise StreamError("late failure references an unsigned pending step")
            expected_signature = None if orphan else packet.signature
            provider_id, endpoint_id, disposition = self._receipt_values(
                receipt, provider_id, endpoint_id, disposition, expected_signature
            )
            receipt_signature = self._route_attribute(receipt, "signature")
            if receipt_signature is not None and not isinstance(receipt_signature, str):
                raise StreamError("late provider failure receipt signature must be text or null")
            route_record = self._resolve_route(
                provider_id,
                endpoint_id,
                route_group,
                route_affinity,
                disposition,
                route=route,
            )
            if not orphan:
                attempts = self._attempt_index[(step_id, generation)]
                if not 0 < attempt <= len(attempts):
                    raise StreamError("late failure references an unknown attempt")
                current = attempts[attempt - 1]
                if current.outcome != "acknowledged":
                    raise StreamError("late provider failure requires an acknowledged send attempt")
                if any(
                    route_record[field] != getattr(current, field)
                    for field in ("provider_id", "endpoint_id", "route_group", "route_affinity", "disposition")
                ):
                    raise StreamError("late provider failure differs from the acknowledged provider receipt")
            failure_key = (step_id, generation, attempt)
            if failure_key in self._orphan_provider_failures or any(
                event.step_id == step_id
                and event.generation == generation
                and event.data.get("attempt") == attempt
                for event in self._lifecycle_events_by_step.get(step_id, ())
                if event.event == "late_provider_failure"
            ):
                raise StreamError("late provider failure was already recorded for this attempt")
            self._append_event(
                "late_provider_failure",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "attempt": attempt,
                    "signature": packet.signature if packet is not None else receipt_signature,
                    "orphan": orphan,
                    "detail": detail,
                    **route_record,
                },
                reservation_step=step_id if step_id in self._pending else None,
            )

    def record_observation(
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
        with self._lock:
            packet = self._require_packet(step_id, generation)
            self._validate_observation_fields(
                status_commitment,
                status_error,
                slot,
                postcondition_satisfied,
                postcondition_digest,
            )
            count = sum(
                observation.generation == generation
                for observation in self._observations_by_step.get(step_id, ())
            )
            if count >= self.limits.max_observations_per_generation:
                raise StreamError("observation limit reached for signed generation")
            self._append_event(
                "step_observed",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": packet.signature,
                    "status_commitment": status_commitment,
                    "status_error": status_error,
                    "slot": slot,
                    "postcondition_satisfied": postcondition_satisfied,
                    "postcondition_digest": postcondition_digest,
                },
                reservation_step=step_id,
            )

    def observations_for(self, step_id: str) -> tuple[StreamObservation, ...]:
        with self._lock:
            return tuple(self._observations_by_step.get(step_id, ()))

    def record_step_dropped(self, step_id: str, generation: int, *, detail: str) -> None:
        self._record_lifecycle("step_dropped", step_id, generation, detail=detail)

    def record_optimistic_branch_invalidated(
        self, step_id: str, generation: int, *, detail: str
    ) -> None:
        self._record_lifecycle("optimistic_branch_invalidated", step_id, generation, detail=detail)

    def record_reconciliation_required(
        self, step_id: str, generation: int, *, detail: str
    ) -> None:
        self._record_lifecycle(
            "reconciliation_required", step_id, generation, detail=detail, allow_unsigned=True
        )

    def record_reconciliation_decision(
        self,
        step_id: str,
        generation: int,
        *,
        decision: Literal["abandon", "continue", "rebuild"],
        evidence_digest: str,
    ) -> int:
        """Journal the adapter's choice before it changes a dropped branch."""

        with self._lock:
            self._ensure_usable()
            if not isinstance(step_id, str) or not step_id:
                raise StreamError("reconciliation step identity must be non-empty text")
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
            ):
                raise StreamError("reconciliation generation must be a non-negative integer")
            if step_id not in self._pending:
                raise StreamError("reconciliation decision requires a pending stream step")
            if not any(
                event.event == "reconciliation_required" and event.generation == generation
                for event in self._lifecycle_events_by_step.get(step_id, ())
            ):
                raise StreamError("reconciliation decision requires a prior reconciliation_required event")
            if not isinstance(decision, str) or decision not in {"abandon", "continue", "rebuild"}:
                raise StreamError("reconciliation decision must be abandon, continue, or rebuild")
            if not isinstance(evidence_digest, str) or not evidence_digest or len(evidence_digest) > 256:
                raise StreamError("reconciliation evidence digest must be 1 to 256 characters")
            key = (step_id, generation)
            if key in self._reconciliation_decisions:
                raise StreamError("reconciliation decision was already recorded")
            row = self._append_event(
                "reconciliation_decision",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "decision": decision,
                    "evidence_digest": evidence_digest,
                },
                reservation_step=step_id,
            )
            return row["event_sequence"]

    def _record_lifecycle(
        self,
        name: str,
        step_id: str,
        generation: int,
        *,
        detail: str,
        allow_unsigned: bool = False,
    ) -> None:
        with self._lock:
            self._ensure_usable()
            if not isinstance(step_id, str) or not step_id:
                raise StreamError(f"{name} step identity must be non-empty text")
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
            ):
                raise StreamError(f"{name} generation must be a non-negative integer")
            packet = self._packet_index.get((step_id, generation))
            if packet is None:
                if not allow_unsigned or generation != 0 or step_id not in self._pending:
                    raise StreamError("stream event references an unknown signed packet")
            elif step_id not in self._pending:
                raise StreamError("cannot add lifecycle events after step terminal state")
            if not isinstance(detail, str) or not detail or len(detail) > 512:
                raise StreamError(f"{name} detail must be 1 to 512 characters")
            if any(
                event.event == name
                and event.generation == generation
                for event in self._lifecycle_events_by_step.get(step_id, ())
            ):
                raise StreamError(f"{name} was already recorded for this packet generation")
            self._append_event(
                name,
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": None if packet is None else packet.signature,
                    "unsigned": packet is None,
                    "detail": detail,
                },
                reservation_step=step_id,
            )

    def record_terminal(self, terminal: StreamTerminal) -> None:
        with self._lock:
            self._ensure_usable()
            if terminal.step_id not in self._pending:
                raise StreamError(f"cannot finish unknown or already terminal stream step {terminal.step_id!r}")
            if terminal.outcome == "abandoned":
                decision = next(
                    (
                        value
                        for (candidate, _generation), value in self._reconciliation_decisions.items()
                        if candidate == terminal.step_id
                        and value[0] == terminal.reconciliation_decision_event_sequence
                    ),
                    None,
                )
                if decision is None or decision[1] != "abandon":
                    raise StreamError("abandonment requires a journaled adapter decision to abandon")
                if terminal.reconciliation_decision_event_sequence != decision[0]:
                    raise StreamError("abandonment does not reference the journaled reconciliation decision")
                packet_signatures = {
                    packet.signature
                    for (candidate, _generation), packet in self._packet_index.items()
                    if candidate == terminal.step_id
                }
                if terminal.signature is not None and terminal.signature not in packet_signatures:
                    raise StreamError("abandoned terminal signature does not match one of its signed packets")
            else:
                if not any(
                    key[0] == terminal.step_id and packet.signature == terminal.signature
                    for key, packet in self._packet_index.items()
                ):
                    raise StreamError("terminal summary signature does not match a retained signed packet")
                self._validate_terminal_policy(terminal)
            self._append_event(
                {
                    "confirmed": "step_confirmed",
                    "failed": "step_terminal_failure",
                    "abandoned": "step_abandoned_after_reconciliation",
                }[terminal.outcome],
                terminal.to_record(),
                reservation_step=terminal.step_id,
            )

    def close_input(self) -> None:
        with self._lock:
            self._ensure_usable()
            if self._input_closed:
                return
            self._append_event(
                "input_closed",
                {"stream_sequence_high_water_mark": self._next_stream_sequence - 1},
            )

    def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint:
        with self._lock:
            self._ensure_usable()
            high_water = self._next_stream_sequence - 1
            boundary = high_water if through_sequence is None else through_sequence
            if (
                not isinstance(boundary, int)
                or isinstance(boundary, bool)
                or boundary < 0
                or boundary > high_water
            ):
                raise StreamError("checkpoint boundary is outside the appended stream")
            for step_id, (sequence, _, _) in self._pending.items():
                if sequence <= boundary:
                    raise StreamError("checkpoint boundary includes a nonterminal step")
            return self._rotate_checkpoint(boundary)

    def close(self) -> None:
        with self._lock:
            if self._lock_fd is None:
                return
            descriptor = self._lock_fd
            self._lock_fd = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _open(self, identity: StreamIdentity) -> None:
        try:
            self._ensure_directory(self.path)
            self._ensure_directory(self.path / "segments")
            self._ensure_directory(self.path / "checkpoints")
            lock_path = self.path / "stream.lock"
            self._lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                os.close(self._lock_fd)
                self._lock_fd = None
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise StreamError("stream directory already has an active writer") from exc
                raise
            self._disk_bytes = sum(
                path.stat().st_size
                for path in self.path.rglob("*")
                if path.is_file()
            )
        except StreamError:
            raise
        except OSError as exc:
            raise StreamError(f"cannot create or lock stream journal directory {self.path}") from exc

        manifest_path = self.path / "manifest.json"
        if not manifest_path.exists():
            self._cleanup_orphans(None)
            self._identity = identity
            self._sequence_digest = _initial_sequence_digest(identity.digest)
            self._manifest = {
                "schema_version": STREAM_SCHEMA_VERSION,
                "identity": identity.to_record(),
                "identity_digest": identity.digest,
                "active_segment": 0,
                "previous_segment_digest": _ZERO_DIGEST,
                "previous_checkpoint_digest": _ZERO_DIGEST,
                "event_high_water_mark": -1,
                "next_stream_sequence": 1,
                "sequence_digest": self._sequence_digest,
                "pending_intents": {},
                "terminal_records": {},
                "input_closed": False,
                "checkpoint": None,
            }
            self._persist_manifest(initial=True)
            self._write_new_file(self._segment_path(0), b"")
            self._active_bytes = 0
            self._append_event(
                "stream_started",
                {
                    "journal_version": STREAM_SCHEMA_VERSION,
                    "identity_digest": identity.digest,
                    "identity": identity.to_record(),
                },
            )
            return

        try:
            raw_manifest = json.loads(manifest_path.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StreamError("stream manifest is unreadable or invalid JSON") from exc
        if not isinstance(raw_manifest, dict) or raw_manifest.get("schema_version") != STREAM_SCHEMA_VERSION:
            raise StreamError("unsupported stream journal version")
        stored_identity = StreamIdentity.from_record(raw_manifest.get("identity", {}))
        if stored_identity.digest != raw_manifest.get("identity_digest"):
            raise StreamError("stream identity digest mismatch")
        if stored_identity != identity:
            raise StreamError("stream identity does not match the existing journal")
        self._identity = stored_identity
        self._manifest = raw_manifest
        self._validate_manifest_shape()
        checkpoint = raw_manifest.get("checkpoint")
        checkpoint_record = self._load_checkpoint_chain(checkpoint)
        if checkpoint_record is not None:
            self._restore_checkpoint(checkpoint_record)
        else:
            self._restore_manifest_state(raw_manifest)
        self._cleanup_orphans(checkpoint)
        self._scan_active_segment(checkpoint_record)
        self._validate_recovered_state()
        self._active_bytes = self._segment_path(self._manifest["active_segment"]).stat().st_size

    def _validate_manifest_shape(self) -> None:
        try:
            if self._manifest.get("identity_digest") != self.identity.digest:
                raise StreamError("stream manifest identity changed")
            if not isinstance(self._manifest["active_segment"], int) or self._manifest["active_segment"] < 0:
                raise StreamError("stream manifest active segment is invalid")
            if not isinstance(self._manifest["event_high_water_mark"], int):
                raise StreamError("stream manifest event high-water mark is invalid")
            if not isinstance(self._manifest["next_stream_sequence"], int) or self._manifest["next_stream_sequence"] <= 0:
                raise StreamError("stream manifest stream sequence is invalid")
            if self._manifest.get("checkpoint") is None:
                if not isinstance(self._manifest.get("pending_intents", {}), dict):
                    raise StreamError("stream manifest pending intents are invalid")
                if not isinstance(self._manifest.get("terminal_records", {}), dict):
                    raise StreamError("stream manifest terminal records are invalid")
            if not isinstance(self._manifest["sequence_digest"], str) or len(self._manifest["sequence_digest"]) != 64:
                raise StreamError("stream manifest sequence digest is invalid")
            bytes.fromhex(self._manifest["sequence_digest"])
            if not isinstance(self._manifest["input_closed"], bool):
                raise StreamError("stream manifest input state is invalid")
            previous = self._manifest.get("previous_segment_digest")
            if not isinstance(previous, str) or len(previous) != 64:
                raise StreamError("stream previous-segment digest is invalid")
            bytes.fromhex(previous)
            previous_checkpoint = self._manifest.get("previous_checkpoint_digest")
            if not isinstance(previous_checkpoint, str) or len(previous_checkpoint) != 64:
                raise StreamError("stream checkpoint-chain digest is invalid")
            bytes.fromhex(previous_checkpoint)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StreamError):
                raise
            raise StreamError("stream manifest has invalid fields") from exc

    def _load_checkpoint_chain(self, pointer: Mapping[str, Any] | None) -> dict[str, Any] | None:
        """Load and validate only the checkpoint named by the manifest pointer."""

        if pointer is None:
            if self._manifest["active_segment"] != 0:
                raise StreamError("stream manifest has no checkpoint for a rotated segment")
            return None
        try:
            relative_path = Path(pointer["file"])
            if relative_path.parent != Path("checkpoints") or len(relative_path.parts) != 2:
                raise StreamError("stream checkpoint pointer path is invalid")
            latest_path = self.path / relative_path
            expected_digest = pointer["digest"]
            marker_sequence = pointer["marker_event_sequence"]
            raw = latest_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_digest:
                raise StreamError("active stream checkpoint digest mismatch")
            latest = json.loads(raw)
        except StreamError:
            raise
        except (KeyError, OSError, json.JSONDecodeError, TypeError) as exc:
            raise StreamError("active stream checkpoint is unreadable") from exc
        if not isinstance(latest, dict):
            raise StreamError("active stream checkpoint is invalid")
        sealed_index = latest.get("sealed_segment_index")
        if (
            not isinstance(sealed_index, int)
            or isinstance(sealed_index, bool)
            or sealed_index < 0
        ):
            raise StreamError("checkpoint sealed_segment_index is missing or invalid")
        previous_checkpoint_digest = latest.get("previous_checkpoint_digest")
        previous_segment_digest = latest.get("previous_segment_digest")
        sealed_digest = latest.get("sealed_segment_digest")
        try:
            for digest in (previous_checkpoint_digest, previous_segment_digest, sealed_digest):
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ValueError
                bytes.fromhex(digest)
        except ValueError as exc:
            raise StreamError("checkpoint digest-chain fields are invalid") from exc
        if (
            latest.get("schema_version") != STREAM_SCHEMA_VERSION
            or latest.get("checkpoint_id") != latest_path.stem
            or latest_path.stem != f"checkpoint-{sealed_index + 1:08d}"
            or latest.get("identity_digest") != self.identity.digest
            or latest.get("next_active_segment") != sealed_index + 1
            or latest.get("event_high_water_mark") != marker_sequence
            or marker_sequence != self._manifest["event_high_water_mark"]
            or latest.get("next_active_segment") != self._manifest["active_segment"]
            or sealed_digest != self._manifest["previous_segment_digest"]
            or expected_digest != self._manifest["previous_checkpoint_digest"]
            or latest.get("next_stream_sequence") != self._manifest["next_stream_sequence"]
            or latest.get("sequence_digest") != self._manifest["sequence_digest"]
            or latest.get("input_closed") != self._manifest["input_closed"]
        ):
            raise StreamError("checkpoint pointer does not match the stream manifest")
        return latest

    def _restore_manifest_state(self, manifest: Mapping[str, Any]) -> None:
        self._pending.clear()
        self._intents.clear()
        self._known_step_ids.clear()
        self._known_step_order.clear()
        self._terminals.clear()
        self._terminal_packet_signatures.clear()
        self._reserve_left.clear()
        self._terminal_reserve_left.clear()
        self._intent_chain_digests.clear()
        for step_id, row in manifest.get("pending_intents", {}).items():
            self._restore_intent_row(step_id, row, pending=True)
            self._terminal_reserve_left[step_id] = self._terminal_step_reserve(self._pending[step_id][1])
        for step_id, row in manifest.get("terminal_records", {}).items():
            self._restore_intent_row(step_id, row["intent_row"], pending=False)
            terminal = StreamTerminal.from_record(row["terminal"])
            self._terminals[step_id] = terminal
            self._terminal_reserve_left[step_id] = self._terminal_step_reserve(self._intents[step_id][1])
            signatures = row.get("packet_signatures")
            if signatures is not None:
                validated = self._validated_generation_signatures(signatures)
                if terminal.signature is not None and terminal.signature not in validated.values():
                    raise StreamError("checkpoint terminal signature has no retained signed packet")
                self._terminal_packet_signatures[step_id] = validated
        self._known_step_ids.update(self._pending)
        self._known_step_ids.update(self._terminals)
        self._known_step_order = [
            step_id
            for step_id, _record in sorted(
                self._intents.items(), key=lambda item: item[1][0]
            )
        ]
        self._next_stream_sequence = manifest["next_stream_sequence"]
        self._sequence_digest = manifest["sequence_digest"]
        self._next_event_sequence = manifest["event_high_water_mark"] + 1
        self._input_closed = manifest["input_closed"]

    def _restore_checkpoint(self, checkpoint: Mapping[str, Any]) -> None:
        if (
            not isinstance(checkpoint.get("pending_intents"), dict)
            or not isinstance(checkpoint.get("terminal_records"), dict)
            or not isinstance(checkpoint.get("unresolved_packets"), list)
            or not isinstance(checkpoint.get("observations"), list)
            or not isinstance(checkpoint.get("lifecycle_events"), list)
        ):
            raise StreamError("checkpoint state is invalid")
        state = {
            "pending_intents": checkpoint["pending_intents"],
            "terminal_records": checkpoint["terminal_records"],
            "next_stream_sequence": checkpoint["next_stream_sequence"],
            "sequence_digest": checkpoint["sequence_digest"],
            "event_high_water_mark": checkpoint["event_high_water_mark"],
            "input_closed": checkpoint["input_closed"],
        }
        self._restore_manifest_state(state)
        known_step_ids = checkpoint.get("known_step_ids")
        recent_step_ids = checkpoint.get("recent_step_ids")
        if known_step_ids is not None:
            if (
                not isinstance(known_step_ids, list)
                or any(not isinstance(step_id, str) or not step_id for step_id in known_step_ids)
                or known_step_ids != sorted(set(known_step_ids))
            ):
                raise StreamError("checkpoint known step IDs are invalid")
            self._known_step_ids = set(known_step_ids)
            if not (set(self._pending) | set(self._terminals)).issubset(self._known_step_ids):
                raise StreamError("checkpoint known step IDs omit pending or retained terminal work")
        else:
            self._known_step_ids.update(self._pending)
            self._known_step_ids.update(self._terminals)
        if recent_step_ids is not None:
            if (
                not isinstance(recent_step_ids, list)
                or len(recent_step_ids) > MAX_RECENT_APPENDED_STEP_IDS
                or any(not isinstance(step_id, str) or not step_id for step_id in recent_step_ids)
                or len(recent_step_ids) != len(set(recent_step_ids))
                or not set(recent_step_ids).issubset(self._known_step_ids)
            ):
                raise StreamError("checkpoint recent step IDs are invalid")
            self._known_step_order = list(recent_step_ids)
        if (
            self._next_stream_sequence != self._manifest["next_stream_sequence"]
            or self._sequence_digest != self._manifest["sequence_digest"]
            or self._input_closed != self._manifest["input_closed"]
            or checkpoint["event_high_water_mark"] != self._manifest["event_high_water_mark"]
        ):
            raise StreamError("checkpoint state does not match manifest state")
        self._next_event_sequence = checkpoint["event_high_water_mark"] + 1
        self._rebuild_authorizations = list(checkpoint.get("rebuild_authorizations", []))
        self._packet_index.clear()
        self._attempt_index.clear()
        self._orphan_provider_failures.clear()
        for row in checkpoint["unresolved_packets"]:
            self._restore_packet_row(row)
        for step_id, row in checkpoint["terminal_records"].items():
            signatures = row.get("packet_signatures")
            if signatures is not None:
                validated = self._validated_generation_signatures(signatures)
                terminal = self._terminals[step_id]
                if terminal.signature is not None and terminal.signature not in validated.values():
                    raise StreamError("checkpoint terminal signature has no retained signed packet")
                self._terminal_packet_signatures[step_id] = validated
        orphan_rows = checkpoint.get("orphan_provider_failures", [])
        if not isinstance(orphan_rows, list) or len(orphan_rows) > MAX_RETAINED_ORPHAN_FAILURES:
            raise StreamError("checkpoint orphan provider failures are invalid")
        orphan_sequences: set[int] = set()
        for row in orphan_rows:
            try:
                event = StreamLifecycleEvent(
                    row["event"],
                    row["step_id"],
                    row["generation"],
                    row["event_sequence"],
                    row["data"],
                )
                if event.event_sequence in orphan_sequences:
                    raise ValueError
                orphan_sequences.add(event.event_sequence)
                self._remember_orphan_provider_failure(event)
            except (KeyError, TypeError, ValueError) as exc:
                raise StreamError("checkpoint orphan provider failure is invalid") from exc
        self._validate_checkpoint_packet_refs(checkpoint)
        self._restore_checkpoint_event_state(checkpoint)
        expected_known_ids = (
            set(self._pending)
            | set(self._terminals)
            | set(self._known_step_order)
            | {event.step_id for event in self._orphan_provider_failures.values()}
        )
        if expected_known_ids != self._known_step_ids:
            raise StreamError("checkpoint known step IDs do not match retained journal state")
        self._validate_restored_intents()

    def _restore_intent_row(self, step_id: str, row: Mapping[str, Any], *, pending: bool) -> None:
        try:
            intent = StreamIntent.from_record(row["intent"])
            sequence = row["sequence"]
            record_digest = row["intent_record_digest"]
            chain_digest = row["sequence_digest"]
            reserve_left = row.get("reserve_left", 0)
            if (
                intent.step_id != step_id
                or not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or not isinstance(record_digest, str)
                or not isinstance(chain_digest, str)
                or not isinstance(reserve_left, int)
                or reserve_left < 0
                or reserve_left > max(self._step_reserve(intent), self._legacy_step_reserve(intent))
                or _intent_digest(intent.to_record()) != record_digest
            ):
                raise ValueError
            record = (sequence, intent, record_digest)
        except (KeyError, TypeError, ValueError) as exc:
            raise StreamError("checkpoint or manifest intent entry is invalid") from exc
        self._intents[step_id] = record
        self._intent_chain_digests[step_id] = chain_digest
        if pending:
            self._pending[step_id] = record
            self._reserve_left[step_id] = reserve_left

    @staticmethod
    def _validated_generation_signatures(value: Any) -> dict[int, str]:
        if not isinstance(value, dict):
            raise StreamError("checkpoint terminal packet signatures are invalid")
        signatures: dict[int, str] = {}
        try:
            for raw_generation, signature in value.items():
                if not isinstance(raw_generation, str) or not raw_generation.isdecimal():
                    raise ValueError
                generation = int(raw_generation)
                if (
                    generation < 0
                    or not isinstance(signature, str)
                    or not signature
                    or generation in signatures
                ):
                    raise ValueError
                signatures[generation] = signature
        except (TypeError, ValueError) as exc:
            raise StreamError("checkpoint terminal packet signatures are invalid") from exc
        return signatures

    def _validate_restored_intents(self) -> None:
        # A checkpoint intentionally prunes old terminal IDs, so the stream
        # high-water mark cannot be derived from the retained intent subset.
        if self._next_stream_sequence <= max((row[0] for row in self._intents.values()), default=0):
            raise StreamError("checkpoint stream high-water mark precedes a retained intent")
        for step_id, (sequence, intent, digest) in self._intents.items():
            if sequence <= 0 or sequence >= self._next_stream_sequence:
                raise StreamError("retained intent sequence is outside the stream high-water mark")
            if _intent_digest(intent.to_record()) != digest:
                raise StreamError("retained intent digest changed")
            if any(
                dependency in self._intents and self._intents[dependency][0] >= sequence
                for dependency in intent.dependencies
            ):
                raise StreamError("retained intent has a future or same-sequence dependency")

    def _restore_packet_row(self, value: Mapping[str, Any]) -> None:
        try:
            step_id = value["step_id"]
            generation = value["generation"]
            signature = value["signature"]
            raw_bytes = base64.b64decode(value["raw_transaction"], validate=True)
            packet_digest = value["packet_digest"]
            signer = value["signer_public_key"]
            signed_sequence = value["signed_event_sequence"]
            segment_index = value["segment_index"]
            if (
                step_id not in self._pending
                or not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
                or hashlib.sha256(raw_bytes).hexdigest() != packet_digest
                or len(raw_bytes) > self._intents[step_id][1].max_packet_bytes
                or signer not in self.identity.signer_public_keys
            ):
                raise ValueError
            _verify_signed_transaction(raw_bytes, signature, signer, self.identity)
            key = (step_id, generation)
            if key in self._packet_index:
                raise ValueError
            record = SignedPacketRecord(
                step_id,
                generation,
                signature,
                raw_bytes,
                packet_digest,
                signer,
                signed_sequence,
                segment_index,
            )
            attempts = [self._attempt_from_record(row) for row in value.get("attempts", [])]
            if [row.number for row in attempts] != list(range(1, len(attempts) + 1)):
                raise ValueError
            self._packet_index[key] = record
            self._attempt_index[key] = attempts
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StreamError):
                raise
            raise StreamError("checkpoint contains an invalid signed packet") from exc

    def _validate_checkpoint_packet_refs(self, checkpoint: Mapping[str, Any]) -> None:
        references = checkpoint.get("unresolved_packet_references")
        if not isinstance(references, list):
            raise StreamError("checkpoint unresolved packet references are invalid")
        actual = {
            (packet.step_id, packet.generation): packet
            for packet in self.unresolved_packets()
        }
        reference_keys = []
        for reference in references:
            if not isinstance(reference, dict):
                raise StreamError("checkpoint unresolved packet reference is invalid")
            key = (reference.get("step_id"), reference.get("generation"))
            if (
                not isinstance(key[0], str)
                or not key[0]
                or not isinstance(key[1], int)
                or isinstance(key[1], bool)
                or key[1] < 0
                or key in reference_keys
            ):
                raise StreamError("checkpoint unresolved packet reference identity is invalid")
            reference_keys.append(key)
            packet = actual.get(key)
            if (
                packet is None
                or packet.signature != reference.get("signature")
                or packet.packet_digest != reference.get("packet_digest")
                or packet.signed_event_sequence != reference.get("signed_event_sequence")
            ):
                raise StreamError("checkpoint references a missing or changed unresolved packet")
            event_sequences = []
            for attempt in packet.attempts:
                event_sequences.append(attempt.started_event_sequence)
                if attempt.finished_event_sequence is not None:
                    event_sequences.append(attempt.finished_event_sequence)
            if event_sequences != reference.get("attempt_event_sequences"):
                raise StreamError("checkpoint attempt references do not match packet history")
        if set(reference_keys) != set(actual):
            raise StreamError("checkpoint unresolved packet references do not cover pending packets")

    def _restore_checkpoint_event_state(self, checkpoint: Mapping[str, Any]) -> None:
        live_ids = set(self._pending) | set(self._terminals)
        high_water = checkpoint["event_high_water_mark"]
        seen_event_sequences: set[int] = {
            event.event_sequence for event in self._orphan_provider_failures.values()
        }
        for row in checkpoint["observations"]:
            try:
                if not isinstance(row, dict):
                    raise ValueError
                observation = StreamObservation(**row)
                if (
                    observation.step_id not in live_ids
                    or not isinstance(observation.generation, int)
                    or isinstance(observation.generation, bool)
                    or observation.generation < 0
                    or not 0 <= observation.event_sequence <= high_water
                    or observation.event_sequence in seen_event_sequences
                ):
                    raise ValueError
                terminal = self._terminals.get(observation.step_id)
                packet = self._packet_index.get((observation.step_id, observation.generation))
                if terminal is None:
                    if packet is None or observation.signature != packet.signature:
                        raise ValueError
                else:
                    generation_signatures = self._terminal_packet_signatures.get(observation.step_id)
                    # Older schema-4 checkpoints did not retain terminal packet
                    # signatures. Their checkpoint digest still binds the rows,
                    # so keep them readable while validating new checkpoints by
                    # the observation's own generation.
                    if (
                        generation_signatures is not None
                        and generation_signatures.get(observation.generation) != observation.signature
                    ):
                        raise ValueError
                seen_event_sequences.add(observation.event_sequence)
            except (TypeError, ValueError) as exc:
                raise StreamError("checkpoint contains an invalid live observation") from exc
            self._observations_by_step.setdefault(observation.step_id, []).append(observation)

        for row in checkpoint["lifecycle_events"]:
            try:
                event = row["event"]
                step_id = row["step_id"]
                generation = row["generation"]
                event_sequence = row["event_sequence"]
                data = row["data"]
                if (
                    event not in _HISTORY_EVENTS
                    or step_id not in live_ids
                    or not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation < 0
                    or not isinstance(event_sequence, int)
                    or isinstance(event_sequence, bool)
                    or not 0 <= event_sequence <= high_water
                    or event_sequence in seen_event_sequences
                    or not isinstance(data, dict)
                    or data.get("step_id") != step_id
                ):
                    raise ValueError
                lifecycle = StreamLifecycleEvent(
                    event, step_id, generation, event_sequence, dict(data)
                )
                if event == "reconciliation_decision":
                    decision = data.get("decision")
                    evidence_digest = data.get("evidence_digest")
                    if (
                        decision not in {"abandon", "continue", "rebuild"}
                        or not isinstance(evidence_digest, str)
                        or not evidence_digest
                    ):
                        raise ValueError
                    key = (step_id, generation)
                    if key in self._reconciliation_decisions:
                        raise ValueError
                    self._reconciliation_decisions[key] = (
                        event_sequence,
                        decision,
                        evidence_digest,
                    )
                if event == "late_provider_failure" and data.get("orphan") is True:
                    self._remember_orphan_provider_failure(lifecycle)
                else:
                    self._lifecycle_events_by_step.setdefault(step_id, []).append(lifecycle)
                seen_event_sequences.add(event_sequence)
            except (KeyError, TypeError, ValueError) as exc:
                raise StreamError("checkpoint contains an invalid live lifecycle event") from exc

    def _scan_active_segment(self, checkpoint: Mapping[str, Any] | None) -> None:
        active_index = self._manifest["active_segment"]
        path = self._segment_path(active_index)
        if not path.exists():
            if checkpoint is None and active_index == 0:
                self._write_new_file(path, b"")
            else:
                raise StreamError(f"active stream segment {active_index} is missing")
        raw = path.read_bytes()
        raw = self._repair_active_tail(path, raw)
        rows = self._decode_segment_rows(raw, active_index)
        if checkpoint is not None:
            marker_sequence = checkpoint["event_high_water_mark"]
            if not rows:
                raise StreamError("active segment lost its checkpoint marker")
            marker = rows[0]
            if (
                marker["event"] != "checkpoint"
                or marker["event_sequence"] != marker_sequence
                or marker["data"].get("checkpoint_id") != checkpoint["checkpoint_id"]
                or marker["data"].get("checkpoint_digest") != self._manifest["checkpoint"]["digest"]
            ):
                raise StreamError("active segment does not match its checkpoint pointer")
            self._next_event_sequence = marker_sequence + 1
            rows = rows[1:]
        else:
            self._next_event_sequence = 0
        for row in rows:
            if row["event_sequence"] != self._next_event_sequence:
                raise StreamError("active stream event sequence has a gap")
            self._index_packet_event(row, active_index)
            self._consume_replayed_reservation(row)
            self._apply_event(row, active_index)
        self._active_bytes = len(raw)

    def _validate_recovered_state(self) -> None:
        if self._next_stream_sequence <= 0:
            raise StreamError("stream sequence high-water mark is invalid")
        if self._sequence_digest == _ZERO_DIGEST:
            raise StreamError("stream sequence digest is invalid")
        if set(self._pending) & set(self._terminals):
            raise StreamError("stream step is both pending and terminal")
        if len(self._pending) > self.limits.max_pending_steps:
            raise StreamError("recovered stream exceeds the configured pending-step limit")
        if any(sequence >= self._next_stream_sequence for sequence, _, _ in self._pending.values()):
            raise StreamError("pending intent exceeds stream high-water mark")
        for step_id, remaining in self._reserve_left.items():
            if step_id not in self._pending or remaining < 0:
                raise StreamError("pending-step quota reservation is invalid")
        if set(self._terminal_reserve_left) != (set(self._pending) | set(self._terminals)):
            raise StreamError("retained terminal-window quota reservation is invalid")

    def _apply_event(self, row: Mapping[str, Any], segment_index: int) -> None:
        self._ensure_usable()
        self._validate_event_row(row)
        name = row["event"]
        data = row["data"]
        sequence = row["event_sequence"]
        if sequence != self._next_event_sequence:
            raise StreamError("stream event is not the next durable event")
        if name == "stream_started":
            if sequence != 0 or data.get("identity_digest") != self.identity.digest:
                raise StreamError("invalid stream journal header")
        elif name == "step_appended":
            intent = StreamIntent.from_record(data["intent"])
            stream_sequence = data["stream_sequence"]
            record_digest = _intent_digest(intent.to_record())
            if (
                stream_sequence != self._next_stream_sequence
                or data.get("previous_sequence_digest") != self._sequence_digest
                or data.get("intent_record_digest") != record_digest
                or data.get("sequence_digest")
                != _advance_sequence_digest(self._sequence_digest, stream_sequence, record_digest)
                or intent.step_id in self._intents
                or intent.step_id in self._known_step_ids
                or any(
                    dependency not in self._pending
                    and dependency not in self._terminal_keep_ids()
                    for dependency in intent.dependencies
                )
            ):
                raise StreamError("appended intent digest, sequence, or dependency is invalid")
            if len(_canonical_json(intent.to_record())) > self.limits.max_intent_bytes:
                raise StreamError("appended intent exceeds max_intent_bytes")
            row_value = (stream_sequence, intent, record_digest)
            self._intents[intent.step_id] = row_value
            self._pending[intent.step_id] = row_value
            self._intent_chain_digests[intent.step_id] = data["sequence_digest"]
            self._reserve_left[intent.step_id] = self._step_reserve(intent)
            self._terminal_reserve_left[intent.step_id] = self._terminal_step_reserve(intent)
            self._known_step_ids.add(intent.step_id)
            self._known_step_order.append(intent.step_id)
            self._next_stream_sequence += 1
            self._sequence_digest = data["sequence_digest"]
        elif name == "step_signed":
            pass
        elif name == "step_rebuild_authorized":
            step_id = data.get("step_id")
            generation = data.get("generation")
            packet = self._packet_index.get((step_id, generation))
            if (
                packet is None
                or step_id not in self._pending
                or data.get("signature") != packet.signature
                or data.get("next_generation") != generation + 1
                or not isinstance(data.get("evidence_digest"), str)
                or not data.get("evidence_digest")
            ):
                raise StreamError("invalid rebuild authorization row")
            self._rebuild_authorizations.append(dict(data))
        elif name == "send_attempt_started":
            pass
        elif name == "send_attempt_finished":
            pass
        elif name == "late_provider_failure":
            lifecycle = StreamLifecycleEvent(name, data["step_id"], data["generation"], sequence, dict(data))
            if data.get("orphan") is True:
                self._remember_orphan_provider_failure(lifecycle)
            else:
                self._lifecycle_events_by_step.setdefault(lifecycle.step_id, []).append(lifecycle)
        elif name == "step_observed":
            observation = self._observation_from_event(data, sequence)
            self._observations_by_step.setdefault(observation.step_id, []).append(observation)
        elif name in {"step_dropped", "optimistic_branch_invalidated", "reconciliation_required"}:
            if any(
                event.event == name
                and event.generation == data["generation"]
                for event in self._lifecycle_events_by_step.get(data["step_id"], ())
            ):
                raise StreamError(f"{name} was recorded more than once for one packet generation")
            lifecycle = StreamLifecycleEvent(
                name, data["step_id"], data["generation"], sequence, dict(data)
            )
            self._lifecycle_events_by_step.setdefault(lifecycle.step_id, []).append(lifecycle)
        elif name == "reconciliation_decision":
            step_id = data.get("step_id")
            generation = data.get("generation")
            decision = data.get("decision")
            evidence_digest = data.get("evidence_digest")
            if (
                step_id not in self._pending
                or not any(
                    event.event == "reconciliation_required" and event.generation == generation
                    for event in self._lifecycle_events_by_step.get(step_id, ())
                )
                or decision not in {"abandon", "continue", "rebuild"}
                or not isinstance(evidence_digest, str)
                or not evidence_digest
                or (step_id, generation) in self._reconciliation_decisions
            ):
                raise StreamError("invalid or duplicate reconciliation decision row")
            self._reconciliation_decisions[(step_id, generation)] = (
                sequence,
                decision,
                evidence_digest,
            )
            lifecycle = StreamLifecycleEvent(
                name, step_id, generation, sequence, dict(data)
            )
            self._lifecycle_events_by_step.setdefault(step_id, []).append(lifecycle)
        elif name in {
            "step_confirmed",
            "step_terminal_failure",
            "step_abandoned_after_reconciliation",
        }:
            terminal = StreamTerminal.from_record(data)
            if terminal.step_id not in self._pending:
                raise StreamError("terminal event references unknown or already terminal step")
            if terminal.outcome == "abandoned":
                decision = next(
                    (
                        value
                        for (candidate, _generation), value in self._reconciliation_decisions.items()
                        if candidate == terminal.step_id
                        and value[0] == terminal.reconciliation_decision_event_sequence
                    ),
                    None,
                )
                if decision is None or decision[1] != "abandon":
                    raise StreamError("abandonment has no preceding adapter decision")
                packet_signatures = {
                    packet.signature
                    for (candidate, _generation), packet in self._packet_index.items()
                    if candidate == terminal.step_id
                }
                if terminal.signature is not None and terminal.signature not in packet_signatures:
                    raise StreamError("abandoned terminal signature does not match one of its signed packets")
            else:
                self._validate_terminal_policy(terminal)
                if not any(
                    key[0] == terminal.step_id and packet.signature == terminal.signature
                    for key, packet in self._packet_index.items()
                ):
                    raise StreamError("terminal event signature has no retained packet")
            if name == "step_confirmed" and terminal.outcome != "confirmed":
                raise StreamError("step_confirmed row has non-confirmed outcome")
            if name == "step_terminal_failure" and terminal.outcome != "failed":
                raise StreamError("step_terminal_failure row has non-failed outcome")
            if name == "step_abandoned_after_reconciliation" and terminal.outcome != "abandoned":
                raise StreamError("step_abandoned row has non-abandoned outcome")
            self._terminals[terminal.step_id] = terminal
            self._terminal_packet_signatures[terminal.step_id] = {
                generation: packet.signature
                for (candidate, generation), packet in self._packet_index.items()
                if candidate == terminal.step_id
            }
            self._pending.pop(terminal.step_id)
            self._reserve_left.pop(terminal.step_id, None)
            lifecycle = StreamLifecycleEvent(
                name,
                terminal.step_id,
                0,
                sequence,
                dict(data),
            )
            self._lifecycle_events_by_step.setdefault(terminal.step_id, []).append(lifecycle)
            self._prune_memory_state(self._terminal_keep_ids())
        elif name == "input_closed":
            if data.get("stream_sequence_high_water_mark") != self._next_stream_sequence - 1:
                raise StreamError("input_closed row has a mismatched stream high-water mark")
            self._input_closed = True
        elif name == "checkpoint":
            pass
        else:
            raise StreamError(f"unknown stream journal event {name!r}")
        self._next_event_sequence = sequence + 1
        self._manifest["event_high_water_mark"] = sequence

    def _consume_replayed_reservation(self, row: Mapping[str, Any]) -> None:
        if row["event"] not in {
            "step_signed",
            "step_rebuild_authorized",
            "send_attempt_started",
            "send_attempt_finished",
            "step_observed",
            "late_provider_failure",
            "step_dropped",
            "optimistic_branch_invalidated",
            "reconciliation_required",
            "step_confirmed",
            "step_terminal_failure",
            "reconciliation_decision",
            "step_abandoned_after_reconciliation",
        }:
            return
        step_id = row["data"].get("step_id")
        if step_id not in self._reserve_left:
            return
        charge = len(_canonical_json(row)) + 1
        if charge > self._reserve_left[step_id]:
            raise StreamError("journal event exceeds its admitted-step quota reservation")
        self._reserve_left[step_id] -= charge

    def _index_packet_event(self, row: Mapping[str, Any], segment_index: int) -> None:
        name = row["event"]
        data = row["data"]
        sequence = row["event_sequence"]
        if name == "step_signed":
            try:
                step_id = data["step_id"]
                generation = data["generation"]
                signature = data["signature"]
                raw_bytes = base64.b64decode(data["raw_transaction"], validate=True)
                signer = data["signer_public_key"]
                intent = self._pending[step_id][1]
                digest = hashlib.sha256(raw_bytes).hexdigest()
                if (
                    not isinstance(generation, int)
                    or generation < 0
                    or digest != data["packet_digest"]
                    or len(raw_bytes) > intent.max_packet_bytes
                    or signer not in self.identity.signer_public_keys
                ):
                    raise StreamError("signed packet digest, limit, or signer is invalid")
                _verify_signed_transaction(raw_bytes, signature, signer, self.identity)
                expected_generation = max(
                    (candidate_generation for candidate_step, candidate_generation in self._packet_index if candidate_step == step_id),
                    default=-1,
                ) + 1
                if generation != expected_generation:
                    raise StreamError("signed packet generation is not consecutive")
                if generation > 0 and not any(
                    item["step_id"] == step_id and item["next_generation"] == generation
                    for item in self._rebuild_authorizations
                ):
                    raise StreamError("new packet generation has no prior adapter authorization")
                key = (step_id, generation)
                if key in self._packet_index:
                    raise StreamError("duplicate signed packet generation")
                self._packet_index[key] = SignedPacketRecord(
                    step_id,
                    generation,
                    signature,
                    raw_bytes,
                    digest,
                    signer,
                    sequence,
                    segment_index,
                )
                self._attempt_index[key] = []
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, StreamError):
                    raise
                raise StreamError("invalid signed stream packet row") from exc
        elif name == "send_attempt_started":
            key = (data.get("step_id"), data.get("generation"))
            packet = self._packet_index.get(key)
            attempts = self._attempt_index.get(key)
            if packet is None or attempts is None or data.get("signature") != packet.signature:
                raise StreamError("send attempt references an unknown packet")
            number = data.get("attempt")
            if number != len(attempts) + 1 or number > self.limits.max_attempts_per_generation:
                raise StreamError("send attempt sequence or limit is invalid")
            route = self._validate_route(
                data.get("provider_id"),
                data.get("endpoint_id"),
                data.get("route_group"),
                data.get("route_affinity"),
                data.get("disposition"),
                allow_no_disposition=True,
            )
            attempts.append(
                PacketAttempt(
                    number,
                    sequence,
                    provider_id=route["provider_id"],
                    endpoint_id=route["endpoint_id"],
                    route_group=route["route_group"],
                    route_affinity=route["route_affinity"],
                    disposition=route["disposition"],
                )
            )
        elif name == "send_attempt_finished":
            key = (data.get("step_id"), data.get("generation"))
            packet = self._packet_index.get(key)
            attempts = self._attempt_index.get(key)
            number = data.get("attempt")
            if packet is None or attempts is None or not isinstance(number, int) or not 0 < number <= len(attempts):
                raise StreamError("send result references an unknown packet attempt")
            old = attempts[number - 1]
            if old.finished_event_sequence is not None or number != len(attempts):
                raise StreamError("send result is duplicated or out of order")
            if data.get("signature") != packet.signature:
                raise StreamError("send result signature differs from packet")
            if any(
                data.get(field) != getattr(old, field)
                for field in ("provider_id", "endpoint_id", "route_group", "route_affinity")
            ):
                raise StreamError("send result route differs from attempt reservation")
            route = self._validate_route(
                old.provider_id,
                old.endpoint_id,
                old.route_group,
                old.route_affinity,
                data.get("disposition"),
                allow_no_disposition=data.get("outcome") == "error",
            )
            outcome = data.get("outcome")
            if outcome not in {"acknowledged", "error"}:
                raise StreamError("send result has invalid outcome")
            detail = data.get("detail")
            if detail is not None and (not isinstance(detail, str) or len(detail) > 512):
                raise StreamError("send result detail is invalid")
            attempts[number - 1] = PacketAttempt(
                number,
                old.started_event_sequence,
                sequence,
                outcome,
                detail,
                route["provider_id"],
                route["endpoint_id"],
                route["route_group"],
                route["route_affinity"],
                route["disposition"],
            )
        elif name == "step_observed":
            packet = self._packet_index.get((data.get("step_id"), data.get("generation")))
            if packet is None or data.get("signature") != packet.signature:
                raise StreamError("observation references an unknown signed packet")
        elif name == "late_provider_failure" and data.get("orphan") is True:
            step_id = data.get("step_id")
            generation = data.get("generation")
            number = data.get("attempt")
            detail = data.get("detail")
            signature = data.get("signature")
            if (
                not isinstance(step_id, str)
                or not step_id
                or not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
                or not isinstance(number, int)
                or isinstance(number, bool)
                or number <= 0
                or not isinstance(detail, str)
                or not detail
                or (signature is not None and not isinstance(signature, str))
            ):
                raise StreamError("orphan late provider failure has invalid identity fields")
            self._validate_route(
                data.get("provider_id"),
                data.get("endpoint_id"),
                data.get("route_group"),
                data.get("route_affinity"),
                data.get("disposition"),
            )
        elif name == "reconciliation_required" and data.get("unsigned") is True:
            if (
                data.get("generation") != 0
                or data.get("signature") is not None
                or data.get("step_id") not in self._pending
                or not isinstance(data.get("detail"), str)
                or not data.get("detail")
            ):
                raise StreamError("unsigned reconciliation event does not reference a pending descendant")
        elif name in {"late_provider_failure", "step_dropped", "optimistic_branch_invalidated", "reconciliation_required"}:
            packet = self._packet_index.get((data.get("step_id"), data.get("generation")))
            if packet is None or data.get("signature") != packet.signature or data.get("step_id") not in self._pending:
                raise StreamError(f"{name} references an unknown signed packet")
            if name == "late_provider_failure":
                attempts = self._attempt_index[(packet.step_id, packet.generation)]
                number = data.get("attempt")
                if not isinstance(number, int) or not 0 < number <= len(attempts):
                    raise StreamError("late provider failure references an unknown attempt")
                attempt = attempts[number - 1]
                route = self._validate_route(
                    data.get("provider_id"),
                    data.get("endpoint_id"),
                    data.get("route_group"),
                    data.get("route_affinity"),
                    data.get("disposition"),
                )
                if attempt.outcome != "acknowledged" or any(
                    route[field] != getattr(attempt, field)
                    for field in ("provider_id", "endpoint_id", "route_group", "route_affinity", "disposition")
                ):
                    raise StreamError("late failure does not match an acknowledged provider attempt")

    def _require_packet(self, step_id: str, generation: int) -> SignedPacketRecord:
        self._ensure_usable()
        packet = self._packet_index.get((step_id, generation))
        if packet is None:
            raise StreamError("stream event references an unknown signed packet")
        if step_id not in self._pending:
            raise StreamError("cannot add transport events after step terminal state")
        return packet

    def _append_event(
        self,
        name: str,
        data: dict[str, Any],
        *,
        admission_reserve: int = 0,
        reservation_step: str | None = None,
    ) -> dict[str, Any]:
        self._ensure_usable()
        row = self._event_row(name, data, self._next_event_sequence)
        encoded = _canonical_json(row) + b"\n"
        if len(encoded) > self.limits.max_segment_bytes:
            raise StreamQuotaExceeded("one stream event exceeds the configured segment bound")
        if self._active_bytes + len(encoded) > self.limits.max_segment_bytes and name != "stream_started":
            next_row = self._event_row(name, data, self._next_event_sequence + 1)
            next_encoded = _canonical_json(next_row) + b"\n"
            if len(next_encoded) > self.limits.max_segment_bytes:
                raise StreamQuotaExceeded("one stream event exceeds the configured segment bound")
            after_reserve, extra_preserve = self._event_quota_reserve(
                name, len(next_encoded), admission_reserve, reservation_step
            )
            try:
                self._rotate_checkpoint(
                    self._terminal_prefix_sequence(),
                    following_event_required=(len(next_encoded) + after_reserve + extra_preserve),
                    following_event_bytes=len(next_encoded),
                )
            except StreamQuotaExceeded:
                raise
            except Exception:
                self._poisoned = True
                raise
            row = self._event_row(name, data, self._next_event_sequence)
            encoded = _canonical_json(row) + b"\n"
            if self._active_bytes + len(encoded) > self.limits.max_segment_bytes:
                raise StreamQuotaExceeded("stream event cannot fit after a safe segment rotation")

        after_reserve, extra_preserve = self._event_quota_reserve(
            name, len(encoded), admission_reserve, reservation_step
        )
        self._ensure_quota(len(encoded) + after_reserve + extra_preserve)
        try:
            self._append_file(self._segment_path(self._manifest["active_segment"]), encoded)
            self._active_bytes += len(encoded)
            self._bytes_written += len(encoded)
            self._index_packet_event(row, self._manifest["active_segment"])
            if reservation_step is not None and name not in {"step_confirmed", "step_terminal_failure"}:
                self._reserve_left[reservation_step] -= len(encoded)
            self._apply_event(row, self._manifest["active_segment"])
        except Exception:
            self._poisoned = True
            raise
        return row

    def _event_quota_reserve(
        self,
        name: str,
        encoded_bytes: int,
        admission_reserve: int,
        reservation_step: str | None,
    ) -> tuple[int, int]:
        reserve_total = sum(self._reserve_left.values()) + sum(self._terminal_reserve_left.values())
        after_reserve = reserve_total
        if name == "step_appended":
            after_reserve += admission_reserve
            extra_preserve = self._append_reserve_bytes
        elif reservation_step is not None:
            available = self._reserve_left.get(reservation_step)
            if available is None or encoded_bytes > available:
                raise StreamQuotaExceeded("event exceeds the reserved finish bytes for its admitted step")
            after_reserve -= encoded_bytes
            if name in {
                "step_confirmed",
                "step_terminal_failure",
                "step_abandoned_after_reconciliation",
            }:
                after_reserve -= available - encoded_bytes
            extra_preserve = 0
        else:
            extra_preserve = self._append_reserve_bytes
        return after_reserve, extra_preserve

    def _event_row(self, name: str, data: Mapping[str, Any], sequence: int) -> dict[str, Any]:
        return {
            "schema_version": STREAM_SCHEMA_VERSION,
            "event_sequence": sequence,
            "event": name,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "data": dict(data),
        }

    def _rotate_checkpoint(
        self,
        through_sequence: int,
        *,
        following_event_required: int | None = None,
        following_event_bytes: int | None = None,
    ) -> StreamCheckpoint:
        self._ensure_usable()
        high_water = self._next_stream_sequence - 1
        if through_sequence < 0 or through_sequence > high_water:
            raise StreamError("checkpoint terminal boundary is outside the appended stream")
        if any(sequence <= through_sequence for sequence, _, _ in self._pending.values()):
            raise StreamError("checkpoint terminal boundary includes nonterminal work")
        old_index = self._manifest["active_segment"]
        old_path = self._segment_path(old_index)
        try:
            old_raw = old_path.read_bytes()
        except OSError as exc:
            self._poisoned = True
            raise StreamError("cannot read active segment for checkpoint") from exc
        old_digest = hashlib.sha256(old_raw).hexdigest()
        new_index = old_index + 1
        checkpoint_id = f"checkpoint-{new_index:08d}"
        marker_sequence = self._next_event_sequence
        terminal_keep = self._terminal_keep_ids()
        checkpoint_record = self._checkpoint_record(
            checkpoint_id,
            through_sequence,
            marker_sequence,
            old_index,
            old_digest,
            terminal_keep,
        )
        checkpoint_bytes = _canonical_json(checkpoint_record)
        checkpoint_digest = hashlib.sha256(checkpoint_bytes).hexdigest()
        marker = self._event_row(
            "checkpoint",
            {
                "checkpoint_id": checkpoint_id,
                "checkpoint_digest": checkpoint_digest,
                "through_sequence": through_sequence,
                "stream_sequence_high_water_mark": high_water,
                "sequence_digest": self._sequence_digest,
            },
            marker_sequence,
        )
        marker_bytes = _canonical_json(marker) + b"\n"
        if (
            following_event_bytes is not None
            and len(marker_bytes) + following_event_bytes > self.limits.max_segment_bytes
        ):
            raise StreamQuotaExceeded("stream event cannot fit after a safe segment rotation")
        candidate = self._manifest_value_for_checkpoint(
            checkpoint_id,
            checkpoint_digest,
            marker_sequence,
            new_index,
            old_digest,
            terminal_keep,
            checkpoint_record["previous_checkpoint_digest"],
        )
        manifest_bytes = _canonical_json(candidate)
        checkpoint_path = self.path / "checkpoints" / f"{checkpoint_id}.json"
        new_segment_path = self._segment_path(new_index)
        # The temporary peak includes the still-live segment and manifest. The
        # per-step reservation remains untouched until all admitted work is done.
        peak_extra = len(checkpoint_bytes) + len(marker_bytes) + len(manifest_bytes)
        pending_terminal_reserve = sum(
            self._terminal_reserve_left.get(step_id, 0) for step_id in self._pending
        )
        self._ensure_quota(
            peak_extra + sum(self._reserve_left.values()) + pending_terminal_reserve
        )
        if following_event_required is not None:
            manifest_path = self.path / "manifest.json"
            old_manifest_bytes = manifest_path.stat().st_size if manifest_path.exists() else 0
            cleanup_paths = [
                path
                for path in (self.path / "segments").glob("segment-*.jsonl")
                if path != new_segment_path
            ] + [
                path
                for path in (self.path / "checkpoints").glob("checkpoint-*.json")
                if path != checkpoint_path
            ]
            cleanup_bytes = sum(path.stat().st_size for path in cleanup_paths)
            projected_disk_bytes = (
                self._disk_bytes
                + len(checkpoint_bytes)
                + len(marker_bytes)
                + len(manifest_bytes)
                - old_manifest_bytes
                - cleanup_bytes
            )
            if projected_disk_bytes + following_event_required > self.limits.max_journal_bytes:
                raise StreamQuotaExceeded(
                    f"stream journal quota exceeded after safe rotation: "
                    f"{projected_disk_bytes} bytes projected before append, "
                    f"{following_event_required} bytes required, "
                    f"{self.limits.max_journal_bytes} byte limit"
                )
        try:
            self._write_new_file(checkpoint_path.with_suffix(".json.tmp"), checkpoint_bytes)
            os.replace(checkpoint_path.with_suffix(".json.tmp"), checkpoint_path)
            self._fsync_directory(checkpoint_path.parent)
            self._write_new_file(new_segment_path, marker_bytes)
            self._write_manifest_value(candidate)
        except Exception as exc:
            self._poisoned = True
            if isinstance(exc, StreamError):
                raise
            raise StreamError("cannot durably rotate stream journal") from exc

        self._manifest = candidate
        self._active_bytes = len(marker_bytes)
        self._next_event_sequence = marker_sequence + 1
        self._prune_memory_state(terminal_keep)
        self._known_step_ids = set(checkpoint_record["known_step_ids"])
        self._known_step_order = list(checkpoint_record["recent_step_ids"])
        try:
            latest_checkpoint = self.path / "checkpoints" / f"{checkpoint_id}.json"
            for path in (self.path / "segments").glob("segment-*.jsonl"):
                if path != new_segment_path:
                    self._unlink_if_present(path)
            self._fsync_directory(self.path / "segments")
            for path in (self.path / "checkpoints").glob("checkpoint-*.json"):
                if path != latest_checkpoint:
                    self._unlink_if_present(path)
            self._fsync_directory(self.path / "checkpoints")
        except Exception:
            self._poisoned = True
            raise
        terminal_rows = {step_id: terminal.to_record() for step_id, terminal in self._terminals.items()}
        confirmed = {
            step_id: row for step_id, row in terminal_rows.items() if row.get("outcome") == "confirmed"
        }
        refs = tuple(checkpoint_record["unresolved_packet_references"])
        return StreamCheckpoint(
            checkpoint_id=checkpoint_id,
            through_sequence=through_sequence,
            stream_sequence_high_water_mark=high_water,
            sequence_digest=self._sequence_digest,
            confirmed_steps=confirmed,
            terminal_steps=terminal_rows,
            unresolved_packet_references=refs,
            checkpoint_digest=checkpoint_digest,
            event_high_water_mark=marker_sequence,
        )

    def _checkpoint_record(
        self,
        checkpoint_id: str,
        through_sequence: int,
        marker_sequence: int,
        sealed_index: int,
        sealed_digest: str,
        terminal_keep: set[str],
    ) -> dict[str, Any]:
        pending_rows = self._serialize_intent_rows(self._pending, pending=True)
        retained = {
            step_id: {
                "intent_row": self._serialize_one_intent(step_id),
                "terminal": terminal.to_record(),
                "packet_signatures": {
                    str(generation): signature
                    for generation, signature in sorted(
                        self._terminal_packet_signatures.get(step_id, {}).items()
                    )
                },
            }
            for step_id, terminal in sorted(self._terminals.items())
            if step_id in terminal_keep
        }
        pending_ids = set(self._pending)
        recent_step_ids = self._known_step_order[-MAX_RECENT_APPENDED_STEP_IDS:]
        known_step_ids = pending_ids | terminal_keep | set(recent_step_ids) | {
            event.step_id for event in self._orphan_provider_failures.values()
        }
        packet_rows = [
            self._packet_record(packet)
            for packet in sorted(
                self._packet_index.values(),
                key=lambda item: (item.signed_event_sequence, item.generation),
            )
            if packet.step_id in pending_ids
        ]
        refs = []
        for packet in self.unresolved_packets():
            sequences = []
            for attempt in packet.attempts:
                sequences.append(attempt.started_event_sequence)
                if attempt.finished_event_sequence is not None:
                    sequences.append(attempt.finished_event_sequence)
            refs.append(
                {
                    "step_id": packet.step_id,
                    "generation": packet.generation,
                    "signature": packet.signature,
                    "packet_digest": packet.packet_digest,
                    "signed_event_sequence": packet.signed_event_sequence,
                    "segment_index": packet.segment_index,
                    "attempt_event_sequences": sequences,
                }
            )
        prior_checkpoint = self._manifest.get("checkpoint")
        prior_digest = _ZERO_DIGEST if prior_checkpoint is None else prior_checkpoint["digest"]
        previous_segment_digest = self._manifest.get("previous_segment_digest", _ZERO_DIGEST)
        return {
            "schema_version": STREAM_SCHEMA_VERSION,
            "checkpoint_id": checkpoint_id,
            "identity_digest": self.identity.digest,
            "previous_checkpoint_digest": prior_digest,
            "sealed_segment_index": sealed_index,
            "sealed_segment_digest": sealed_digest,
            "previous_segment_digest": previous_segment_digest,
            "next_active_segment": sealed_index + 1,
            "through_sequence": through_sequence,
            "stream_sequence_high_water_mark": self._next_stream_sequence - 1,
            "next_stream_sequence": self._next_stream_sequence,
            "sequence_digest": self._sequence_digest,
            "event_high_water_mark": marker_sequence,
            "input_closed": self._input_closed,
            "pending_intents": pending_rows,
            "terminal_records": retained,
            "known_step_ids": sorted(known_step_ids),
            "recent_step_ids": recent_step_ids,
            "unresolved_packets": packet_rows,
            "unresolved_packet_references": refs,
            "observations": [
                self._observation_to_record(observation)
                for observation in self.observations
                if observation.step_id in (pending_ids | terminal_keep)
            ],
            "lifecycle_events": [
                self._lifecycle_to_record(event)
                for event in sorted(
                    (
                        event
                        for rows in self._lifecycle_events_by_step.values()
                        for event in rows
                    ),
                    key=lambda item: item.event_sequence,
                )
                if event.step_id in (pending_ids | terminal_keep)
            ],
            "orphan_provider_failures": [
                self._lifecycle_to_record(event)
                for event in sorted(
                    self._orphan_provider_failures.values(),
                    key=lambda item: item.event_sequence,
                )
            ],
            "rebuild_authorizations": [
                row for row in self._rebuild_authorizations if row["step_id"] in self._pending
            ],
        }

    def _manifest_value_for_checkpoint(
        self,
        checkpoint_id: str,
        checkpoint_digest: str,
        marker_sequence: int,
        new_index: int,
        sealed_digest: str,
        terminal_keep: set[str],
        previous_checkpoint_digest: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": STREAM_SCHEMA_VERSION,
            "identity": self.identity.to_record(),
            "identity_digest": self.identity.digest,
            "active_segment": new_index,
            "previous_segment_digest": sealed_digest,
            "previous_checkpoint_digest": checkpoint_digest,
            "event_high_water_mark": marker_sequence,
            "next_stream_sequence": self._next_stream_sequence,
            "sequence_digest": self._sequence_digest,
            "input_closed": self._input_closed,
            "checkpoint": {
                "file": f"checkpoints/{checkpoint_id}.json",
                "digest": checkpoint_digest,
                "marker_event_sequence": marker_sequence,
            },
        }

    def _serialize_intent_rows(
        self,
        values: Mapping[str, tuple[int, StreamIntent, str]],
        *,
        pending: bool,
    ) -> dict[str, Any]:
        return {
            step_id: self._serialize_one_intent(step_id, pending=pending)
            for step_id in sorted(values)
        }

    def _serialize_one_intent(self, step_id: str, *, pending: bool = False) -> dict[str, Any]:
        sequence, intent, record_digest = self._intents[step_id]
        row = {
            "sequence": sequence,
            "intent": intent.to_record(),
            "intent_record_digest": record_digest,
            "sequence_digest": self._intent_chain_digests[step_id],
        }
        if pending:
            row["reserve_left"] = self._reserve_left[step_id]
        return row

    def _packet_record(self, packet: SignedPacketRecord) -> dict[str, Any]:
        return {
            "step_id": packet.step_id,
            "generation": packet.generation,
            "signature": packet.signature,
            "raw_transaction": base64.b64encode(packet.raw_bytes).decode("ascii"),
            "packet_digest": packet.packet_digest,
            "signer_public_key": packet.signer_public_key,
            "signed_event_sequence": packet.signed_event_sequence,
            "segment_index": packet.segment_index,
            "attempts": [
                self._attempt_to_record(attempt)
                for attempt in self._attempt_index[(packet.step_id, packet.generation)]
            ],
        }

    @staticmethod
    def _observation_to_record(observation: StreamObservation) -> dict[str, Any]:
        return asdict(observation)

    @staticmethod
    def _lifecycle_to_record(event: StreamLifecycleEvent) -> dict[str, Any]:
        return {
            "event": event.event,
            "step_id": event.step_id,
            "generation": event.generation,
            "event_sequence": event.event_sequence,
            "data": dict(event.data),
        }

    def _remember_orphan_provider_failure(self, event: StreamLifecycleEvent) -> None:
        data = event.data
        step_id = event.step_id
        generation = event.generation
        attempt = data.get("attempt") if isinstance(data, dict) else None
        if (
            event.event != "late_provider_failure"
            or not isinstance(step_id, str)
            or not step_id
            or step_id not in self._known_step_ids
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt <= 0
            or not isinstance(data, dict)
            or data.get("orphan") is not True
            or data.get("step_id") != step_id
        ):
            raise StreamError("orphan late provider failure has invalid identity fields")
        self._validate_route(
            data.get("provider_id"),
            data.get("endpoint_id"),
            data.get("route_group"),
            data.get("route_affinity"),
            data.get("disposition"),
        )
        key = (step_id, generation, attempt)
        if key in self._orphan_provider_failures:
            raise StreamError("orphan late provider failure was already recorded for this attempt")
        self._orphan_provider_failures[key] = event
        if len(self._orphan_provider_failures) > MAX_RETAINED_ORPHAN_FAILURES:
            oldest_key = min(
                self._orphan_provider_failures,
                key=lambda candidate: self._orphan_provider_failures[candidate].event_sequence,
            )
            del self._orphan_provider_failures[oldest_key]

    @staticmethod
    def _attempt_to_record(attempt: PacketAttempt) -> dict[str, Any]:
        return {
            "number": attempt.number,
            "started_event_sequence": attempt.started_event_sequence,
            "finished_event_sequence": attempt.finished_event_sequence,
            "outcome": attempt.outcome,
            "detail": attempt.detail,
            "provider_id": attempt.provider_id,
            "endpoint_id": attempt.endpoint_id,
            "route_group": attempt.route_group,
            "route_affinity": attempt.route_affinity,
            "disposition": attempt.disposition,
        }

    @staticmethod
    def _attempt_from_record(row: Mapping[str, Any]) -> PacketAttempt:
        try:
            return PacketAttempt(**row)
        except (TypeError, ValueError) as exc:
            raise StreamError("checkpoint attempt record is invalid") from exc

    def _terminal_keep_ids(self) -> set[str]:
        ordered = sorted(
            self._terminals,
            key=lambda step_id: self._intents.get(step_id, (0, None, ""))[0],
            reverse=True,
        )
        return set(ordered[: self.limits.max_pending_steps])

    def _prune_memory_state(self, terminal_keep: set[str]) -> None:
        for step_id in tuple(self._terminals):
            if step_id not in terminal_keep:
                self._terminals.pop(step_id, None)
                self._terminal_packet_signatures.pop(step_id, None)
                self._intents.pop(step_id, None)
                self._intent_chain_digests.pop(step_id, None)
        for key in tuple(self._packet_index):
            if key[0] not in self._pending:
                self._packet_index.pop(key, None)
                self._attempt_index.pop(key, None)
        live_ids = set(self._pending) | terminal_keep
        self._observations_by_step = {
            step_id: rows
            for step_id, rows in self._observations_by_step.items()
            if step_id in live_ids
        }
        self._lifecycle_events_by_step = {
            step_id: rows
            for step_id, rows in self._lifecycle_events_by_step.items()
            if step_id in live_ids
        }
        self._reconciliation_decisions = {
            key: value
            for key, value in self._reconciliation_decisions.items()
            if key[0] in live_ids
        }
        self._terminal_reserve_left = {
            step_id: reserve
            for step_id, reserve in self._terminal_reserve_left.items()
            if step_id in live_ids
        }
        self._rebuild_authorizations = [
            row for row in self._rebuild_authorizations if row["step_id"] in self._pending
        ]

    def _terminal_prefix_sequence(self) -> int:
        terminal_ids = set(self._terminals)
        boundary = 0
        for step_id, (sequence, _, _) in sorted(self._intents.items(), key=lambda item: item[1][0]):
            if step_id not in terminal_ids:
                break
            boundary = sequence
        return boundary

    def _step_reserve(self, intent: StreamIntent) -> int:
        packet_row = ((intent.max_packet_bytes + 2) // 3) * 4 + 1200
        per_generation = (
            packet_row
            + self.limits.max_attempts_per_generation * 5000
            + self.limits.max_observations_per_generation * 1200
            + 1500
            + 3 * 1400
        )
        terminal = 1400
        return self.limits.max_generations_per_step * per_generation + terminal

    def _terminal_step_reserve(self, intent: StreamIntent) -> int:
        """Reserve one retained terminal's bounded checkpoint representation."""

        intent_bytes = len(_canonical_json(intent.to_record()))
        observations = (
            self.limits.max_generations_per_step
            * self.limits.max_observations_per_generation
            * 1200
        )
        late_failures = (
            self.limits.max_generations_per_step
            * self.limits.max_attempts_per_generation
            * 1400
        )
        lifecycle = self.limits.max_generations_per_step * 3 * 1400
        return intent_bytes + 1400 + observations + late_failures + lifecycle + 1024

    def _legacy_step_reserve(self, intent: StreamIntent) -> int:
        """Upper bound for reserve values written by earlier schema-4 builds."""

        packet_row = ((intent.max_packet_bytes + 2) // 3) * 4 + 1200
        return (
            self._step_reserve(intent)
            + len(_canonical_json(intent.to_record()))
            + self.limits.max_generations_per_step
            * (
                packet_row
                + self.limits.max_attempts_per_generation * 1200
                + self.limits.max_observations_per_generation * 1200
            )
            + 4096
        )

    def _validate_route(
        self,
        provider_id: Any,
        endpoint_id: Any,
        route_group: Any,
        route_affinity: Any,
        disposition: Any,
        *,
        allow_no_disposition: bool = False,
    ) -> dict[str, Any]:
        values = {
            "provider_id": provider_id,
            "endpoint_id": endpoint_id,
            "route_group": route_group,
            "route_affinity": route_affinity,
            "disposition": disposition,
        }
        for name in ("provider_id", "endpoint_id", "route_group"):
            value = values[name]
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
                raise StreamError(f"{name} must be 1 to 128 UTF-8 bytes")
        if route_affinity is not None and (
            not isinstance(route_affinity, str)
            or not route_affinity
            or len(route_affinity.encode("utf-8")) > 128
        ):
            raise StreamError("route_affinity must be null or 1 to 128 UTF-8 bytes")
        if isinstance(disposition, Enum):
            disposition = disposition.value
            values["disposition"] = disposition
        if disposition is None and allow_no_disposition:
            pass
        elif not isinstance(disposition, str) or not disposition or len(disposition) > 64:
            raise StreamError("provider disposition must be non-empty text")
        return values

    def _resolve_route(
        self,
        provider_id: Any,
        endpoint_id: Any,
        route_group: Any,
        route_affinity: Any,
        disposition: Any,
        *,
        route: Any | None = None,
        allow_no_disposition: bool = False,
    ) -> dict[str, Any]:
        if route is not None:
            route_endpoint = self._route_attribute(route, "endpoint_id")
            route_group_value = self._route_attribute(route, "route_group")
            route_affinity_value = self._route_attribute(
                route, "affinity_key", self._route_attribute(route, "route_affinity")
            )
            for name, supplied, routed in (
                ("endpoint_id", endpoint_id, route_endpoint),
                ("route_group", route_group, route_group_value),
                ("route_affinity", route_affinity, route_affinity_value),
            ):
                if supplied is not None and supplied != routed:
                    raise StreamError(f"{name} differs from the selected endpoint route")
            endpoint_id = route_endpoint if endpoint_id is None else endpoint_id
            route_group = route_group_value if route_group is None else route_group
            route_affinity = route_affinity_value if route_affinity is None else route_affinity
            if self._route_attribute(route, "is_probe", False):
                raise StreamError("health-probe routes cannot be recorded as packet sends")
        return self._validate_route(
            provider_id,
            endpoint_id,
            route_group,
            route_affinity,
            disposition,
            allow_no_disposition=allow_no_disposition,
        )

    @staticmethod
    def _route_attribute(route: Any, name: str, default: Any = None) -> Any:
        if isinstance(route, Mapping):
            return route.get(name, default)
        return getattr(route, name, default)

    def _receipt_values(
        self,
        receipt: Any | None,
        provider_id: str | None,
        endpoint_id: str | None,
        disposition: str | None,
        expected_signature: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        if receipt is None:
            return provider_id, endpoint_id, disposition
        receipt_signature = self._route_attribute(receipt, "signature")
        if expected_signature is not None and receipt_signature != expected_signature:
            raise StreamError("provider receipt signature differs from the signed packet")
        received = (
            self._route_attribute(receipt, "provider_id"),
            self._route_attribute(receipt, "endpoint_id"),
            self._route_attribute(receipt, "disposition"),
        )
        for name, supplied, actual in zip(
            ("provider_id", "endpoint_id", "disposition"),
            (provider_id, endpoint_id, disposition),
            received,
        ):
            if supplied is not None and supplied != actual:
                raise StreamError(f"provider receipt {name} differs from the recorded value")
        return tuple(
            actual if supplied is None else supplied
            for supplied, actual in zip((provider_id, endpoint_id, disposition), received)
        )

    @staticmethod
    def _validate_observation_fields(
        status_commitment: str | None,
        status_error: str | None,
        slot: int | None,
        postcondition_satisfied: bool | None,
        postcondition_digest: str | None,
    ) -> None:
        if status_commitment is not None and (
            not isinstance(status_commitment, str) or len(status_commitment) > 64
        ):
            raise StreamError("observed commitment must be at most 64 characters or null")
        if status_error is not None and (not isinstance(status_error, str) or len(status_error) > 512):
            raise StreamError("observed status error must be at most 512 characters or null")
        if slot is not None and (not isinstance(slot, int) or isinstance(slot, bool) or slot < 0):
            raise StreamError("observed slot must be a non-negative integer or null")
        if postcondition_satisfied is not None and not isinstance(postcondition_satisfied, bool):
            raise StreamError("observed postcondition result must be boolean or null")
        if postcondition_digest is not None and (
            not isinstance(postcondition_digest, str) or len(postcondition_digest) > 256
        ):
            raise StreamError("observed postcondition digest must be at most 256 characters or null")

    @staticmethod
    def _observation_from_event(data: Mapping[str, Any], sequence: int) -> StreamObservation:
        return StreamObservation(
            step_id=data["step_id"],
            generation=data["generation"],
            signature=data["signature"],
            status_commitment=data.get("status_commitment"),
            status_error=data.get("status_error"),
            slot=data.get("slot"),
            postcondition_satisfied=data.get("postcondition_satisfied"),
            postcondition_digest=data.get("postcondition_digest"),
            event_sequence=sequence,
        )

    def _validate_terminal_policy(self, terminal: StreamTerminal) -> None:
        if (
            terminal.outcome != "abandoned"
            and self.identity.commitment_policy == "finalized"
            and terminal.commitment != "finalized"
        ):
            raise StreamError("terminal summary is weaker than the stream commitment policy")

    def _ensure_usable(self) -> None:
        if self._poisoned:
            raise StreamError("stream journal is unusable after an incomplete durable update; reopen it")

    def _ensure_quota(self, extra_bytes: int) -> None:
        if extra_bytes < 0:
            raise StreamError("internal quota reservation became negative")
        if self._disk_bytes + extra_bytes > self.limits.max_journal_bytes:
            raise StreamQuotaExceeded(
                f"stream journal quota exceeded: {self._disk_bytes} bytes used, "
                f"{extra_bytes} bytes required, {self.limits.max_journal_bytes} byte limit"
            )

    def _persist_manifest(self, *, initial: bool = False) -> None:
        encoded = _canonical_json(self._manifest)
        path = self.path / "manifest.json"
        self._atomic_write(path, encoded)

    def _write_manifest_value(self, manifest: Mapping[str, Any]) -> None:
        encoded = _canonical_json(manifest)
        path = self.path / "manifest.json"
        try:
            self._atomic_write(path, encoded)
        except Exception:
            self._poisoned = True
            raise
        self._bytes_written += len(encoded)

    def _atomic_write(self, path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp")
        old_size = path.stat().st_size if path.exists() else 0
        temp_old = temporary.stat().st_size if temporary.exists() else 0
        self._ensure_quota(max(0, len(data) - temp_old))
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            try:
                self._write_all(descriptor, data)
                self._fsync_file(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        except OSError as exc:
            self._poisoned = True
            raise StreamError(f"cannot atomically persist {path.name}") from exc
        # Atomic replace removes the old target and temporary file together.
        self._disk_bytes += len(data) - old_size - temp_old

    def _write_new_file(self, path: Path, data: bytes) -> None:
        self._ensure_quota(len(data))
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                self._write_all(descriptor, data)
                self._fsync_file(descriptor)
            finally:
                os.close(descriptor)
            self._fsync_directory(path.parent)
        except FileExistsError:
            raise
        except OSError as exc:
            self._poisoned = True
            raise StreamError(f"cannot create stream file {path.name}") from exc
        self._disk_bytes += len(data)
        self._bytes_written += len(data)

    def _append_file(self, path: Path, data: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_APPEND | os.O_WRONLY)
            try:
                self._write_all(descriptor, data)
                self._fsync_file(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            self._poisoned = True
            raise StreamError("cannot append and fsync stream event") from exc
        self._disk_bytes += len(data)
        self._bytes_written += len(data)

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short stream journal write")
            view = view[written:]

    @staticmethod
    def _fsync_file(descriptor: int) -> None:
        if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
            try:
                fcntl.fcntl(descriptor, fcntl.F_FULLFSYNC)
                return
            except OSError as exc:
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                    raise
        os.fsync(descriptor)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise StreamError(f"cannot fsync stream directory {directory}") from exc

    @classmethod
    def _ensure_directory(cls, directory: Path) -> None:
        missing: list[Path] = []
        current = directory
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                break
            current = current.parent
        for entry in reversed(missing):
            entry.mkdir(mode=0o700)
            cls._fsync_directory(entry.parent)

    def _cleanup_orphans(self, checkpoint: Mapping[str, Any] | None) -> None:
        changed_segments = False
        changed_checkpoints = False
        for path in self.path.rglob("*.tmp"):
            self._unlink_if_present(path)
        active = self._manifest.get("active_segment", 0)
        for path in (self.path / "segments").glob("segment-*.jsonl"):
            try:
                index = int(path.stem.removeprefix("segment-"))
            except ValueError:
                self._unlink_if_present(path)
                changed_segments = True
                continue
            if index != active:
                self._unlink_if_present(path)
                changed_segments = True
        latest = (
            None
            if checkpoint is None
            else int(Path(checkpoint["file"]).stem.removeprefix("checkpoint-"))
        )
        for path in (self.path / "checkpoints").glob("checkpoint-*.json"):
            try:
                index = int(path.stem.removeprefix("checkpoint-"))
            except ValueError:
                self._unlink_if_present(path)
                changed_checkpoints = True
                continue
            if index != latest:
                self._unlink_if_present(path)
                changed_checkpoints = True
        if changed_segments:
            self._fsync_directory(self.path / "segments")
        if changed_checkpoints:
            self._fsync_directory(self.path / "checkpoints")

    def _unlink_if_present(self, path: Path) -> None:
        try:
            size = path.stat().st_size
            path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StreamError(f"cannot remove stream file {path.name}") from exc
        self._disk_bytes = max(0, self._disk_bytes - size)
        self._fsync_directory(path.parent)

    def _repair_active_tail(self, path: Path, raw: bytes) -> bytes:
        if not raw or raw.endswith(b"\n"):
            return raw
        tail_start = raw.rfind(b"\n") + 1
        tail = raw[tail_start:]
        try:
            row = json.loads(tail)
            self._validate_event_row(row)
        except (UnicodeDecodeError, json.JSONDecodeError, StreamError):
            try:
                with path.open("r+b") as stream:
                    stream.truncate(tail_start)
                    stream.flush()
                    self._fsync_file(stream.fileno())
            except OSError as exc:
                raise StreamError("cannot truncate incomplete active stream tail") from exc
            self._disk_bytes -= len(raw) - tail_start
            return raw[:tail_start]
        self._append_file(path, b"\n")
        return raw + b"\n"

    def _decode_segment_rows(self, raw: bytes, segment_index: int) -> list[dict[str, Any]]:
        result = []
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line:
                raise StreamError(f"empty stream journal row in segment {segment_index} line {line_number}")
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StreamError(f"invalid JSON in stream segment {segment_index}") from exc
            self._validate_event_row(row)
            result.append(row)
        return result

    @staticmethod
    def _validate_event_row(row: Any) -> None:
        if (
            not isinstance(row, dict)
            or row.get("schema_version") != STREAM_SCHEMA_VERSION
            or not isinstance(row.get("event_sequence"), int)
            or isinstance(row.get("event_sequence"), bool)
            or not isinstance(row.get("event"), str)
            or not isinstance(row.get("data"), dict)
            or not isinstance(row.get("recorded_at"), str)
        ):
            raise StreamError("invalid stream journal event row")

    def _segment_path(self, index: int) -> Path:
        return self.path / "segments" / f"segment-{index:08d}.jsonl"
