"""Version-2 journal primitives for open-ended transaction streams.

This store is deliberately separate from :mod:`dcg.sequencer.journal`.  It
does not read, rewrite, or migrate fixed-plan v1 JSONL journals.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol

from .types import JournalError


STREAM_SCHEMA_VERSION = 2
_ZERO_DIGEST = "0" * 64
_SEQUENCE_DOMAIN = b"dcg-stream-sequence-v1\0"
_INTENT_DOMAIN = b"dcg-stream-intent-v1\0"


class StreamError(JournalError):
    """Base class for stream journal and lifecycle errors."""


class StreamQuotaExceeded(StreamError):
    """The journal cannot safely persist another event within its hard quota."""


class StreamClosed(StreamError):
    """Input has been closed and cannot accept another new intent."""


@dataclass(frozen=True)
class StreamIdentity:
    """Stable identity bound by every stream journal.

    ``run_id`` is the application run/session identity.  The route and
    commitment policy digests are opaque caller-computed commitments; DCG does
    not infer endpoint allowlists or application policy from them.
    """

    run_id: str
    genesis_hash: str
    program_id: str
    destination_accounts: tuple[str, ...]
    signer_public_keys: tuple[str, ...]
    route_policy_digest: str
    commitment_policy: str = "confirmed"

    def __post_init__(self) -> None:
        for name in ("run_id", "genesis_hash", "program_id", "route_policy_digest", "commitment_policy"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty text")
        if not self.destination_accounts or any(not isinstance(value, str) or not value for value in self.destination_accounts):
            raise ValueError("destination_accounts must contain non-empty identities")
        if not self.signer_public_keys or any(
            not isinstance(value, str) or not value for value in self.signer_public_keys
        ):
            raise ValueError("signer_public_keys must contain non-empty identities")
        if len(set(self.signer_public_keys)) != len(self.signer_public_keys):
            raise ValueError("signer_public_keys must not contain duplicates")
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
    endpoint_id: str
    compute_class: str
    compute_unit_limit: int
    intent_digest: str
    recovery_policy_digest: str
    intent_data: Mapping[str, Any] = field(default_factory=dict)
    max_packet_bytes: int = 1232
    write_locks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value
            for value in (self.step_id, self.endpoint_id, self.compute_class)
        ):
            raise ValueError("step_id, endpoint_id, and compute_class must be non-empty")
        if any(
            not isinstance(value, str) or not value for value in (self.intent_digest, self.recovery_policy_digest)
        ):
            raise ValueError("intent and recovery-policy digests must be non-empty")
        if (
            not isinstance(self.compute_unit_limit, int)
            or isinstance(self.compute_unit_limit, bool)
            or not isinstance(self.max_packet_bytes, int)
            or isinstance(self.max_packet_bytes, bool)
            or self.compute_unit_limit <= 0
            or self.max_packet_bytes <= 0
        ):
            raise ValueError("compute and packet limits must be positive")
        if any(not isinstance(value, str) or not value for value in self.dependencies):
            raise ValueError("dependencies must contain non-empty step IDs")
        if any(not isinstance(value, str) or not value for value in self.write_locks):
            raise ValueError("write_locks must contain non-empty lock IDs")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("dependencies must not contain duplicates")
        if len(set(self.write_locks)) != len(self.write_locks):
            raise ValueError("write_locks must not contain duplicates")
        # Validate and detach the mapping at the serialization boundary.
        if not isinstance(self.intent_data, Mapping):
            raise ValueError("intent_data must be a JSON object")
        object.__setattr__(self, "intent_data", json.loads(_canonical_json(self.intent_data)))

    def to_record(self) -> dict[str, Any]:
        intent_data = json.loads(_canonical_json(self.intent_data))
        return {
            "step_id": self.step_id,
            "dependencies": list(self.dependencies),
            "endpoint_id": self.endpoint_id,
            "compute_class": self.compute_class,
            "compute_unit_limit": self.compute_unit_limit,
            "intent_digest": self.intent_digest,
            "recovery_policy_digest": self.recovery_policy_digest,
            "intent_data": intent_data,
            "max_packet_bytes": self.max_packet_bytes,
            "write_locks": list(self.write_locks),
        }

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> StreamIntent:
        try:
            return cls(
                step_id=value["step_id"],
                dependencies=tuple(value["dependencies"]),
                endpoint_id=value["endpoint_id"],
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
    """Caller-selected memory and disk bounds for one open stream."""

    max_pending_steps: int = 128
    max_segment_bytes: int = 1_048_576
    max_journal_bytes: int = 67_108_864
    append_reserve_bytes: int = 4096

    def __post_init__(self) -> None:
        if self.max_pending_steps <= 0:
            raise ValueError("max_pending_steps must be positive")
        if self.max_segment_bytes < 512:
            raise ValueError("max_segment_bytes must be at least 512")
        if self.max_journal_bytes < max(self.max_segment_bytes, 4096):
            raise ValueError("max_journal_bytes must be at least max_segment_bytes and 4096")
        if self.append_reserve_bytes < 0 or self.append_reserve_bytes >= self.max_journal_bytes:
            raise ValueError("append_reserve_bytes must be non-negative and smaller than the journal quota")


@dataclass(frozen=True)
class StreamAppendReceipt:
    step_id: str
    sequence: int
    sequence_digest: str
    already_present: bool


@dataclass(frozen=True)
class StreamTerminal:
    """Durable summary of a step after stable signature and state checks."""

    step_id: str
    outcome: Literal["confirmed", "failed"]
    signature: str
    commitment: str
    postcondition_satisfied: bool
    postcondition_digest: str
    slot: int | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if not self.step_id or not self.signature or not self.commitment:
            raise ValueError("terminal step identity, signature, and commitment are required")
        if self.outcome not in {"confirmed", "failed"}:
            raise ValueError("terminal outcome must be confirmed or failed")
        if not isinstance(self.postcondition_satisfied, bool):
            raise ValueError("terminal postcondition result must be boolean")
        if not isinstance(self.postcondition_digest, str) or not self.postcondition_digest:
            raise ValueError("terminal summary must bind a postcondition digest")
        if not isinstance(self.commitment, str) or not self.commitment:
            raise ValueError("terminal commitment must be non-empty text")
        if self.error is not None and not isinstance(self.error, str):
            raise ValueError("terminal error must be text or null")
        if self.outcome == "confirmed" and not self.postcondition_satisfied:
            raise ValueError("a confirmed terminal step requires a satisfied postcondition")
        if self.outcome == "failed" and self.postcondition_satisfied:
            raise ValueError("a failed terminal step cannot have a satisfied postcondition")
        if self.outcome == "confirmed" and self.commitment not in {"confirmed", "finalized"}:
            raise ValueError("a confirmed terminal step requires stable commitment")
        if self.outcome == "failed" and self.commitment != "finalized":
            raise ValueError("a terminal failure requires finalized commitment")
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
class StreamCheckpoint:
    checkpoint_id: str
    through_sequence: int
    stream_sequence_high_water_mark: int
    sequence_digest: str
    confirmed_steps: Mapping[str, Mapping[str, Any]]
    terminal_steps: Mapping[str, Mapping[str, Any]]
    unresolved_packet_references: tuple[Mapping[str, Any], ...]
    checkpoint_digest: str


class StreamJournalProtocol(Protocol):
    """Synchronous fsync boundary used by the async :class:`StreamingPlan`."""

    @property
    def identity(self) -> StreamIdentity: ...

    @property
    def intents(self) -> Mapping[str, tuple[int, StreamIntent, str]]: ...

    @property
    def terminals(self) -> Mapping[str, StreamTerminal]: ...

    @property
    def input_closed(self) -> bool: ...

    @property
    def next_stream_sequence(self) -> int: ...

    @property
    def sequence_digest(self) -> str: ...

    def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]: ...

    def append_intent(self, intent: StreamIntent) -> StreamAppendReceipt: ...

    def record_signed_packet(
        self, step_id: str, signature: str, raw_bytes: bytes, signer_public_key: str
    ) -> SignedPacketRecord: ...

    def record_send_attempt(self, step_id: str, generation: int) -> PacketAttempt: ...

    def record_send_result(
        self, step_id: str, generation: int, attempt: int, *, acknowledged: bool, detail: str | None = None
    ) -> PacketAttempt: ...

    def authorize_rebuild(self, step_id: str, generation: int, evidence_digest: str) -> None: ...

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
    ) -> None: ...

    def record_terminal(self, terminal: StreamTerminal) -> None: ...

    def close_input(self) -> None: ...

    def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint: ...


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
    allowed_signers: tuple[str, ...],
) -> None:
    """Validate the canonical Solana packet, its signatures, and signer set."""

    try:
        from solders.transaction import VersionedTransaction

        transaction = VersionedTransaction.from_bytes(raw_bytes)
        if bytes(transaction) != raw_bytes:
            raise StreamError("signed transaction is not canonically encoded")
        required_signatures = transaction.message.header.num_required_signatures
        transaction_signers = tuple(
            str(pubkey) for pubkey in transaction.message.account_keys[:required_signatures]
        )
        if not required_signatures or len(transaction.signatures) != required_signatures:
            raise StreamError("signed transaction signature count does not match its message")
        if str(transaction.signatures[0]) != expected_signature:
            raise StreamError("signed transaction signature does not match its packet record")
        if declared_signer not in transaction_signers or any(
            signer not in allowed_signers for signer in transaction_signers
        ):
            raise StreamError("signed transaction required signer is outside the bound signer set")
        if not all(transaction.verify_with_results()):
            raise StreamError("signed transaction contains an invalid signature")
    except StreamError:
        raise
    except Exception as exc:
        raise StreamError("signed transaction packet is invalid") from exc


class StreamJournal:
    """Versioned directory journal with bounded JSONL segments and checkpoints."""

    def __init__(self, path: str | os.PathLike[str], identity: StreamIdentity, limits: StreamLimits):
        self.path = Path(path)
        self.limits = limits
        self._lock = threading.RLock()
        self._poisoned = False
        self._packet_index: dict[tuple[str, int], SignedPacketRecord] = {}
        self._attempt_index: dict[tuple[str, int], list[PacketAttempt]] = {}
        self._open(identity)

    @property
    def identity(self) -> StreamIdentity:
        return self._identity

    @property
    def intents(self) -> Mapping[str, tuple[int, StreamIntent, str]]:
        return self._intents

    @property
    def terminals(self) -> Mapping[str, StreamTerminal]:
        return self._terminals

    @property
    def input_closed(self) -> bool:
        return bool(self._manifest["input_closed"])

    @property
    def pending_count(self) -> int:
        return len(self._intents) - len(self._terminals)

    @property
    def next_stream_sequence(self) -> int:
        return int(self._manifest["next_stream_sequence"])

    @property
    def sequence_digest(self) -> str:
        return str(self._manifest["sequence_digest"])

    def unresolved_packets(self) -> tuple[SignedPacketRecord, ...]:
        unresolved = set(self._intents) - set(self._terminals)
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
                self._packet_index.items(), key=lambda item: (item[1].signed_event_sequence, item[0][1])
            )
            if step_id in unresolved
        )

    def append_intent(self, intent: StreamIntent) -> StreamAppendReceipt:
        with self._lock:
            self._ensure_usable()
            prior = self._intents.get(intent.step_id)
            record = intent.to_record()
            digest = _intent_digest(record)
            if prior is not None:
                sequence, prior_intent, prior_digest = prior
                if prior_digest != digest or prior_intent.to_record() != record:
                    raise StreamError(f"step {intent.step_id!r} was already appended with different intent")
                old_chain_digest = self._manifest["intent_index"][intent.step_id]["sequence_digest"]
                return StreamAppendReceipt(intent.step_id, sequence, old_chain_digest, True)
            if self.input_closed:
                raise StreamClosed("stream input is closed")
            known = set(self._intents)
            next_sequence = self.next_stream_sequence
            if any(dependency not in known for dependency in intent.dependencies):
                raise StreamError("stream dependencies must name earlier appended steps")
            if any(self._intents[dependency][0] >= next_sequence for dependency in intent.dependencies):
                raise StreamError("stream dependency does not precede the appended step")
            previous_digest = self.sequence_digest
            next_digest = _advance_sequence_digest(previous_digest, next_sequence, digest)
            self._append_event(
                "step_appended",
                {
                    "stream_sequence": next_sequence,
                    "intent": record,
                    "intent_record_digest": digest,
                    "previous_sequence_digest": previous_digest,
                    "sequence_digest": next_digest,
                },
            )
            return StreamAppendReceipt(intent.step_id, next_sequence, next_digest, False)

    def record_signed_packet(
        self, step_id: str, signature: str, raw_bytes: bytes, signer_public_key: str
    ) -> SignedPacketRecord:
        with self._lock:
            self._ensure_usable()
            intent_entry = self._intents.get(step_id)
            if intent_entry is None:
                raise StreamError(f"cannot sign unknown stream step {step_id!r}")
            if step_id in self._terminals:
                raise StreamError(f"cannot sign terminal stream step {step_id!r}")
            if not signature or not raw_bytes:
                raise StreamError("signed packet signature and bytes must be non-empty")
            if not isinstance(signature, str) or not isinstance(raw_bytes, bytes):
                raise StreamError("signed packet signature and bytes have invalid types")
            if not isinstance(signer_public_key, str) or not signer_public_key:
                raise StreamError("signed packet signer identity must be non-empty text")
            intent = intent_entry[1]
            if len(raw_bytes) > intent.max_packet_bytes:
                raise StreamError("signed packet exceeds the appended step packet limit")
            if signer_public_key not in self.identity.signer_public_keys:
                raise StreamError("signed packet signer is outside the bound signer set")
            _verify_signed_transaction(raw_bytes, signature, signer_public_key, self.identity.signer_public_keys)
            generations = [generation for (candidate, generation) in self._packet_index if candidate == step_id]
            generation = max(generations, default=-1) + 1
            authorization = next(
                (
                    row
                    for row in reversed(self._manifest["rebuild_authorizations"])
                    if row["step_id"] == step_id and row["next_generation"] == generation
                ),
                None,
            )
            if generation > 0 and authorization is None:
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
            )
            return self._packet_index[(step_id, generation)]

    def authorize_rebuild(self, step_id: str, generation: int, evidence_digest: str) -> None:
        """Record explicit application authorization before a replacement signature."""

        with self._lock:
            self._ensure_usable()
            record = self._packet_index.get((step_id, generation))
            generations = [candidate for candidate_step, candidate in self._packet_index if candidate_step == step_id]
            if (
                record is None
                or step_id in self._terminals
                or generation != max(generations, default=-1)
                or not isinstance(evidence_digest, str)
                or not evidence_digest
            ):
                raise StreamError("rebuild authorization must reference a packet and evidence digest")
            next_generation = generation + 1
            if any(
                row["step_id"] == step_id and row["next_generation"] == next_generation
                for row in self._manifest["rebuild_authorizations"]
            ):
                raise StreamError("replacement generation is already authorized")
            self._append_event(
                "step_rebuild_authorized",
                {
                    "step_id": step_id,
                    "generation": generation,
                    "signature": record.signature,
                    "next_generation": next_generation,
                    "evidence_digest": evidence_digest,
                },
            )

    def record_send_attempt(self, step_id: str, generation: int) -> PacketAttempt:
        with self._lock:
            packet = self._require_packet(step_id, generation)
            attempts = self._attempt_index[(step_id, generation)]
            number = len(attempts) + 1
            self._append_event(
                "send_attempt_started",
                {"step_id": step_id, "generation": generation, "signature": packet.signature, "attempt": number},
            )
            return self._attempt_index[(step_id, generation)][-1]

    def record_send_result(
        self,
        step_id: str,
        generation: int,
        attempt: int,
        *,
        acknowledged: bool,
        detail: str | None = None,
    ) -> PacketAttempt:
        with self._lock:
            packet = self._require_packet(step_id, generation)
            if not isinstance(acknowledged, bool):
                raise StreamError("send acknowledgment flag must be boolean")
            if detail is not None and not isinstance(detail, str):
                raise StreamError("send result detail must be text")
            attempts = self._attempt_index[(step_id, generation)]
            if attempt <= 0 or attempt > len(attempts):
                raise StreamError("send result references an unknown attempt")
            current = attempts[attempt - 1]
            if current.finished_event_sequence is not None:
                raise StreamError("send attempt already has a result")
            if current.number != attempt:
                raise StreamError("send attempt sequence mismatch")
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
                },
            )
            return self._attempt_index[(step_id, generation)][attempt - 1]

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
            if status_commitment is not None and not isinstance(status_commitment, str):
                raise StreamError("observed commitment must be text or null")
            if status_error is not None and not isinstance(status_error, str):
                raise StreamError("observed status error must be text or null")
            if slot is not None and (not isinstance(slot, int) or isinstance(slot, bool) or slot < 0):
                raise StreamError("observed slot must be a non-negative integer or null")
            if postcondition_satisfied is not None and not isinstance(postcondition_satisfied, bool):
                raise StreamError("observed postcondition result must be boolean or null")
            if postcondition_digest is not None and not isinstance(postcondition_digest, str):
                raise StreamError("observed postcondition digest must be text or null")
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
            )

    def record_terminal(self, terminal: StreamTerminal) -> None:
        with self._lock:
            self._ensure_usable()
            if terminal.step_id not in self._intents:
                raise StreamError(f"cannot finish unknown stream step {terminal.step_id!r}")
            if terminal.step_id in self._terminals:
                if self._terminals[terminal.step_id] == terminal:
                    return
                raise StreamError(f"stream step {terminal.step_id!r} already has a terminal summary")
            generations = [
                self._packet_index[key]
                for key in self._packet_index
                if key[0] == terminal.step_id
            ]
            if not any(packet.signature == terminal.signature for packet in generations):
                raise StreamError("terminal summary signature does not match a retained signed packet")
            if terminal.outcome == "confirmed" and terminal.commitment not in {"confirmed", "finalized"}:
                raise StreamError("confirmed step requires confirmed or finalized commitment")
            if terminal.outcome == "failed" and terminal.commitment != "finalized":
                raise StreamError("terminal failure requires finalized commitment")
            self._validate_terminal_policy(terminal)
            self._append_event(
                "step_confirmed" if terminal.outcome == "confirmed" else "step_terminal_failure",
                terminal.to_record(),
            )

    def close_input(self) -> None:
        with self._lock:
            self._ensure_usable()
            if self.input_closed:
                return
            self._append_event("input_closed", {"stream_sequence_high_water_mark": self.next_stream_sequence - 1})

    def checkpoint(self, through_sequence: int | None = None) -> StreamCheckpoint:
        with self._lock:
            self._ensure_usable()
            high_water = self.next_stream_sequence - 1
            boundary = high_water if through_sequence is None else through_sequence
            if boundary < 0 or boundary > high_water:
                raise StreamError("checkpoint boundary is outside the appended stream")
            for step_id, (sequence, _, _) in self._intents.items():
                if sequence <= boundary and step_id not in self._terminals:
                    raise StreamError("checkpoint boundary includes a nonterminal step")
            return self._rotate_checkpoint(boundary)

    def _open(self, identity: StreamIdentity) -> None:
        identity_record = identity.to_record()
        identity_digest = identity.digest
        try:
            for directory in (self.path, self.path / "segments", self.path / "checkpoints"):
                self._ensure_directory(directory)
        except OSError as exc:
            raise StreamError(f"cannot create stream journal directory {self.path}") from exc
        manifest_path = self.path / "manifest.json"
        if not manifest_path.exists():
            self._identity = identity
            self._intents: dict[str, tuple[int, StreamIntent, str]] = {}
            self._terminals: dict[str, StreamTerminal] = {}
            initial_digest = _initial_sequence_digest(identity_digest)
            segment = self._segment_meta(0, _ZERO_DIGEST, "active", 0, None, [])
            self._manifest: dict[str, Any] = {
                "schema_version": STREAM_SCHEMA_VERSION,
                "identity": identity_record,
                "identity_digest": identity_digest,
                "segments": [segment],
                "active_segment": 0,
                "next_event_sequence": 0,
                "next_stream_sequence": 1,
                "sequence_digest": initial_digest,
                "intent_index": {},
                "terminal_summaries": {},
                "rebuild_authorizations": [],
                "checkpoint": None,
                "input_closed": False,
            }
            self._ensure_quota(
                2 * len(_canonical_json(self._manifest))
                + 2 * len(_canonical_json(identity_record))
                + 1024
            )
            self._persist_manifest()
            segment_path = self._segment_path(0)
            self._write_new_file(segment_path, b"")
            self._append_event(
                "stream_started",
                {"journal_version": STREAM_SCHEMA_VERSION, "identity_digest": identity_digest, "identity": identity_record},
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
        self._intents = self._decode_intent_index(raw_manifest.get("intent_index"))
        self._terminals = self._decode_terminal_index(raw_manifest.get("terminal_summaries"))
        self._validate_manifest_state()
        self._cleanup_orphans()
        self._scan_segments_and_recover_tail()
        if self._manifest["next_event_sequence"] == 0:
            self._append_event(
                "stream_started",
                {
                    "journal_version": STREAM_SCHEMA_VERSION,
                    "identity_digest": self.identity.digest,
                    "identity": self.identity.to_record(),
                },
            )
        self._validate_checkpoint_refs()
        self._ensure_quota((self.path / "manifest.json").stat().st_size)
        self._persist_manifest()

    def _validate_manifest_state(self) -> None:
        try:
            segments = self._manifest["segments"]
            active = self._manifest["active_segment"]
            if not isinstance(segments, list) or not segments or active != segments[-1]["index"]:
                raise StreamError("stream manifest has an invalid active segment")
            if segments[-1]["status"] != "active":
                raise StreamError("stream manifest active segment is not active")
            previous = _ZERO_DIGEST
            previous_last_event: int | None = None
            expected_index = 0
            for segment in segments:
                if segment["index"] != expected_index or segment["previous_digest"] != previous:
                    raise StreamError("stream segment digest links are inconsistent")
                if segment["name"] != f"segments/segment-{expected_index:08d}.jsonl":
                    raise StreamError("stream segment name does not match its index")
                if segment["status"] not in {"active", "sealed", "compacted"}:
                    raise StreamError("stream segment has an invalid state")
                if segment["status"] == "active" and segment is not segments[-1]:
                    raise StreamError("only the last segment can be active")
                first = segment.get("first_event_sequence")
                last = segment.get("last_event_sequence")
                if first is None or last is None:
                    if segment is not segments[-1] or self._manifest["next_event_sequence"] != 0:
                        raise StreamError("only a new empty stream segment may omit event bounds")
                else:
                    if not isinstance(first, int) or not isinstance(last, int) or first > last:
                        raise StreamError("stream segment event bounds are invalid")
                    if previous_last_event is not None and first != previous_last_event + 1:
                        raise StreamError("stream segment event sequence links are inconsistent")
                    previous_last_event = last
                if segment["status"] != "active":
                    digest = segment.get("digest")
                    if not isinstance(digest, str) or len(digest) != 64:
                        raise StreamError("sealed segment is missing its content digest")
                    bytes.fromhex(digest)
                    previous = digest
                expected_index += 1
            if previous_last_event is not None and previous_last_event + 1 != self._manifest["next_event_sequence"]:
                raise StreamError("stream event high-water mark does not match segment metadata")
            if self._manifest["identity_digest"] != self.identity.digest:
                raise StreamError("stream manifest identity changed")
            if self._manifest["next_stream_sequence"] != len(self._intents) + 1:
                raise StreamError("stream manifest sequence high-water mark is inconsistent")
            digest = _initial_sequence_digest(self.identity.digest)
            ordered = sorted(self._intents.items(), key=lambda item: item[1][0])
            for expected, (step_id, (sequence, intent, record_digest)) in enumerate(ordered, start=1):
                if sequence != expected or intent.step_id != step_id:
                    raise StreamError("stream manifest has a sequence gap or duplicate step")
                if any(
                    dependency not in self._intents or self._intents[dependency][0] >= sequence
                    for dependency in intent.dependencies
                ):
                    raise StreamError("stream manifest contains a missing or future dependency")
                record = intent.to_record()
                actual_intent_digest = _intent_digest(record)
                if actual_intent_digest != record_digest:
                    raise StreamError("stream intent digest mismatch in manifest")
                expected_row_digest = _advance_sequence_digest(digest, sequence, actual_intent_digest)
                if self._manifest["intent_index"][step_id].get("sequence_digest") != expected_row_digest:
                    raise StreamError("stream intent sequence digest mismatch in manifest")
                digest = expected_row_digest
            if digest != self._manifest["sequence_digest"]:
                raise StreamError("stream sequence digest mismatch in manifest")
            if set(self._terminals) - set(self._intents):
                raise StreamError("stream terminal summary references an unknown intent")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StreamError):
                raise
            raise StreamError("stream manifest has invalid fields") from exc

    def _scan_segments_and_recover_tail(self) -> None:
        self._packet_index.clear()
        self._attempt_index.clear()
        expected_uncommitted = int(self._manifest["next_event_sequence"])
        active_index = int(self._manifest["active_segment"])
        for meta in self._manifest["segments"]:
            index = meta["index"]
            segment_path = self._segment_path(index)
            if meta["status"] == "compacted":
                continue
            if not segment_path.exists():
                if index == active_index and self._manifest["next_event_sequence"] == 0:
                    self._write_new_file(segment_path, b"")
                else:
                    raise StreamError(f"retained stream segment {index} is missing")
            raw = segment_path.read_bytes()
            if index == active_index:
                raw = self._repair_active_tail(segment_path, raw)
            elif hashlib.sha256(raw).hexdigest() != meta["digest"]:
                raise StreamError(f"sealed stream segment {index} digest mismatch")
            rows = self._decode_segment_rows(raw, index)
            if index == active_index:
                if not rows and self._manifest["next_event_sequence"] > 0:
                    raise StreamError("active stream segment lost committed journal rows")
                if rows and meta["first_event_sequence"] is not None:
                    if rows[0]["event_sequence"] != meta["first_event_sequence"]:
                        raise StreamError("active stream segment first event sequence mismatch")
                if rows and meta["last_event_sequence"] is not None:
                    if rows[-1]["event_sequence"] < meta["last_event_sequence"]:
                        raise StreamError("active stream segment lost committed journal rows")
            if index != active_index and rows:
                if rows[0]["event_sequence"] != meta["first_event_sequence"]:
                    raise StreamError(f"stream segment {index} first event sequence mismatch")
                if rows[-1]["event_sequence"] != meta["last_event_sequence"]:
                    raise StreamError(f"stream segment {index} last event sequence mismatch")
            previous_row_sequence: int | None = None
            for row in rows:
                sequence = row["event_sequence"]
                if row["event"] == "stream_started" and (
                    sequence != 0 or row["data"].get("identity_digest") != self.identity.digest
                ):
                    raise StreamError("invalid stream journal header")
                if previous_row_sequence is not None and sequence != previous_row_sequence + 1:
                    raise StreamError(f"event sequence gap inside segment {index}")
                previous_row_sequence = sequence
                self._index_packet_event(row, index)
                if sequence >= expected_uncommitted:
                    if sequence != expected_uncommitted:
                        raise StreamError("uncommitted stream event sequence has a gap")
                    self._apply_event(row, index)
                    expected_uncommitted += 1
            if index == active_index:
                meta["bytes"] = len(raw)
                if rows:
                    meta["last_event_sequence"] = rows[-1]["event_sequence"]
                    meta["first_event_sequence"] = rows[0]["event_sequence"]
            if rows:
                recorded_step_id_set = set()
                for row in rows:
                    step_id = row["data"].get("step_id")
                    intent_data = row["data"].get("intent")
                    if step_id is None and isinstance(intent_data, dict):
                        step_id = intent_data.get("step_id")
                    if isinstance(step_id, str):
                        recorded_step_id_set.add(step_id)
                recorded_step_ids = sorted(recorded_step_id_set)
                if index == active_index:
                    meta["step_ids"] = recorded_step_ids
                elif meta["status"] == "sealed" and sorted(meta["step_ids"]) != recorded_step_ids:
                    raise StreamError(f"stream segment {index} step index mismatch")
        self._manifest["next_event_sequence"] = expected_uncommitted

    def _decode_segment_rows(self, raw: bytes, segment_index: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line:
                raise StreamError(f"empty stream journal row in segment {segment_index} line {line_number}")
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StreamError(f"invalid JSON in stream segment {segment_index}") from exc
            if (
                not isinstance(row, dict)
                or row.get("schema_version") != STREAM_SCHEMA_VERSION
                or not isinstance(row.get("event_sequence"), int)
                or not isinstance(row.get("event"), str)
                or not isinstance(row.get("data"), dict)
                or not isinstance(row.get("recorded_at"), str)
            ):
                raise StreamError(f"invalid stream row in segment {segment_index}")
            result.append(row)
        return result

    def _repair_active_tail(self, path: Path, raw: bytes) -> bytes:
        if not raw or raw.endswith(b"\n"):
            return raw
        tail_start = raw.rfind(b"\n") + 1
        tail = raw[tail_start:]
        try:
            row = json.loads(tail)
        except (UnicodeDecodeError, json.JSONDecodeError):
            repaired = raw[:tail_start]
            try:
                with path.open("r+b") as stream:
                    stream.truncate(tail_start)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise StreamError("cannot truncate incomplete active stream tail") from exc
            return repaired
        self._decode_segment_rows(tail + b"\n", int(self._manifest["active_segment"]))
        self._append_file(path, b"\n")
        return raw + b"\n"

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
                digest = hashlib.sha256(raw_bytes).hexdigest()
                if digest != data["packet_digest"]:
                    raise StreamError("signed packet digest mismatch")
                if len(raw_bytes) > self._intents[step_id][1].max_packet_bytes:
                    raise StreamError("signed packet exceeds its intent packet limit")
                if signer not in self.identity.signer_public_keys:
                    raise StreamError("signed packet signer is outside stream identity")
                _verify_signed_transaction(raw_bytes, signature, signer, self.identity.signer_public_keys)
                expected_generation = max(
                    (candidate_generation for candidate_step, candidate_generation in self._packet_index if candidate_step == step_id),
                    default=-1,
                ) + 1
                if generation != expected_generation:
                    raise StreamError("signed packet generation is not consecutive")
                if generation > 0 and not any(
                    auth["step_id"] == step_id and auth["next_generation"] == generation
                    for auth in self._manifest["rebuild_authorizations"]
                ):
                    raise StreamError("new packet generation has no prior adapter authorization")
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, StreamError):
                    raise
                raise StreamError("invalid signed stream packet row") from exc
            record = SignedPacketRecord(
                step_id=step_id,
                generation=generation,
                signature=signature,
                raw_bytes=raw_bytes,
                packet_digest=digest,
                signer_public_key=signer,
                signed_event_sequence=sequence,
                segment_index=segment_index,
            )
            if (step_id, generation) in self._packet_index:
                raise StreamError("duplicate signed packet generation")
            self._packet_index[(step_id, generation)] = record
            self._attempt_index[(step_id, generation)] = []
            return
        if name == "send_attempt_started":
            key = (data.get("step_id"), data.get("generation"))
            packet = self._packet_index.get(key)
            attempts = self._attempt_index.get(key)
            if packet is None or attempts is None or data.get("signature") != packet.signature:
                raise StreamError("send attempt references an unknown packet")
            number = data.get("attempt")
            if number != len(attempts) + 1:
                raise StreamError("send attempt sequence is not consecutive")
            attempts.append(PacketAttempt(number, sequence))
            return
        if name == "send_attempt_finished":
            key = (data.get("step_id"), data.get("generation"))
            packet = self._packet_index.get(key)
            attempts = self._attempt_index.get(key)
            number = data.get("attempt")
            if (
                packet is None
                or attempts is None
                or data.get("signature") != packet.signature
                or not isinstance(number, int)
                or number <= 0
                or number > len(attempts)
            ):
                raise StreamError("send result references an unknown packet attempt")
            old = attempts[number - 1]
            if old.finished_event_sequence is not None or number != len(attempts):
                raise StreamError("send result is duplicated or out of order")
            outcome = data.get("outcome")
            if outcome not in {"acknowledged", "error"}:
                raise StreamError("send result has invalid outcome")
            attempts[number - 1] = PacketAttempt(number, old.started_event_sequence, sequence, outcome, data.get("detail"))
            return
        if name == "step_observed":
            key = (data.get("step_id"), data.get("generation"))
            packet = self._packet_index.get(key)
            if packet is None or data.get("signature") != packet.signature:
                raise StreamError("observation references an unknown signed packet")

    def _apply_event(self, row: Mapping[str, Any], segment_index: int) -> None:
        name = row["event"]
        data = row["data"]
        sequence = row["event_sequence"]
        if sequence != self._manifest["next_event_sequence"]:
            raise StreamError("stream event is not the next durable event")
        if name == "step_appended":
            try:
                stream_sequence = data["stream_sequence"]
                intent = StreamIntent.from_record(data["intent"])
                record_digest = _intent_digest(intent.to_record())
                previous = data["previous_sequence_digest"]
                chain_digest = data["sequence_digest"]
                if record_digest != data["intent_record_digest"]:
                    raise StreamError("appended intent digest mismatch")
                if stream_sequence != self.next_stream_sequence or previous != self.sequence_digest:
                    raise StreamError("appended intent sequence does not continue the stream")
                expected_chain = _advance_sequence_digest(previous, stream_sequence, record_digest)
                if chain_digest != expected_chain:
                    raise StreamError("appended sequence digest mismatch")
                if intent.step_id in self._intents or any(dep not in self._intents for dep in intent.dependencies):
                    raise StreamError("appended intent duplicates an ID or has a future dependency")
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, StreamError):
                    raise
                raise StreamError("invalid step_appended row") from exc
            self._intents[intent.step_id] = (stream_sequence, intent, record_digest)
            self._manifest["intent_index"][intent.step_id] = {
                "sequence": stream_sequence,
                "intent": intent.to_record(),
                "intent_record_digest": record_digest,
                "sequence_digest": chain_digest,
            }
            self._manifest["next_stream_sequence"] = stream_sequence + 1
            self._manifest["sequence_digest"] = chain_digest
        elif name in {"step_confirmed", "step_terminal_failure"}:
            terminal = StreamTerminal.from_record(data)
            self._validate_terminal_policy(terminal)
            if terminal.step_id not in self._intents or terminal.step_id in self._terminals:
                raise StreamError("terminal event references unknown or already terminal step")
            if not any(
                key[0] == terminal.step_id and packet.signature == terminal.signature
                for key, packet in self._packet_index.items()
            ):
                raise StreamError("terminal event signature has no retained packet")
            if name == "step_confirmed" and terminal.outcome != "confirmed":
                raise StreamError("step_confirmed row has non-confirmed outcome")
            if name == "step_terminal_failure" and terminal.outcome != "failed":
                raise StreamError("step_terminal_failure row has non-failed outcome")
            if terminal.outcome == "confirmed" and terminal.commitment not in {"confirmed", "finalized"}:
                raise StreamError("confirmed terminal row has an unstable commitment")
            if terminal.outcome == "failed" and terminal.commitment != "finalized":
                raise StreamError("terminal failure row is not finalized")
            self._terminals[terminal.step_id] = terminal
            self._manifest["terminal_summaries"][terminal.step_id] = terminal.to_record()
        elif name == "step_rebuild_authorized":
            step_id = data.get("step_id")
            generation = data.get("generation")
            packet = self._packet_index.get((step_id, generation))
            generations = [candidate for candidate_step, candidate in self._packet_index if candidate_step == step_id]
            if (
                packet is None
                or step_id in self._terminals
                or generation != max(generations, default=-1)
                or data.get("signature") != packet.signature
                or data.get("next_generation") != generation + 1
                or not isinstance(data.get("evidence_digest"), str)
                or not data.get("evidence_digest")
            ):
                raise StreamError("invalid rebuild authorization row")
            self._manifest["rebuild_authorizations"].append(dict(data))
        elif name == "input_closed":
            if data.get("stream_sequence_high_water_mark") != self.next_stream_sequence - 1:
                raise StreamError("input_closed row has a mismatched stream high-water mark")
            self._manifest["input_closed"] = True
        elif name == "stream_started":
            if sequence != 0 or data.get("identity_digest") != self.identity.digest:
                raise StreamError("invalid stream header row")
        elif name == "checkpoint":
            pass
        elif name in {"step_signed", "send_attempt_started", "send_attempt_finished", "step_observed"}:
            pass  # Packet references were validated and indexed before replay.
        else:
            raise StreamError(f"unknown stream journal event {name!r}")
        self._manifest["next_event_sequence"] = sequence + 1
        active = self._manifest["segments"][-1]
        if active["index"] == segment_index:
            active["last_event_sequence"] = sequence
            if active["first_event_sequence"] is None:
                active["first_event_sequence"] = sequence
            step_id = data.get("step_id")
            if step_id is None and isinstance(data.get("intent"), dict):
                step_id = data["intent"].get("step_id")
            if isinstance(step_id, str) and step_id not in active["step_ids"]:
                active["step_ids"].append(step_id)

    def _append_event(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        self._ensure_usable()
        event_sequence = int(self._manifest["next_event_sequence"])
        row = {
            "schema_version": STREAM_SCHEMA_VERSION,
            "event_sequence": event_sequence,
            "event": name,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        encoded = _canonical_json(row) + b"\n"
        active = self._manifest["segments"][-1]
        if active["bytes"] + len(encoded) > self.limits.max_segment_bytes:
            if len(encoded) + 256 > self.limits.max_segment_bytes:
                raise StreamQuotaExceeded("one stream event exceeds the configured segment bound")
            reserve = self.limits.append_reserve_bytes if name == "step_appended" else 0
            self._rotate_checkpoint(self._terminal_prefix_sequence(), quota_reserve=reserve)
            active = self._manifest["segments"][-1]
            row["event_sequence"] = int(self._manifest["next_event_sequence"])
            encoded = _canonical_json(row) + b"\n"
            if active["bytes"] + len(encoded) > self.limits.max_segment_bytes:
                raise StreamQuotaExceeded("stream event cannot fit after a safe segment rotation")
        segment_path = self._segment_path(active["index"])
        reserve = self.limits.append_reserve_bytes if name == "step_appended" else 0
        self._ensure_quota(len(encoded) + self._manifest_peak_size(len(encoded)) + reserve)
        self._append_file(segment_path, encoded)
        try:
            self._index_packet_event(row, active["index"])
            self._apply_event(row, active["index"])
            active["bytes"] += len(encoded)
            self._persist_manifest()
        except Exception:
            self._poisoned = True
            raise
        return row

    def _rotate_checkpoint(self, through_sequence: int, *, quota_reserve: int = 0) -> StreamCheckpoint:
        active = self._manifest["segments"][-1]
        current_path = self._segment_path(active["index"])
        current_bytes = current_path.read_bytes()
        segment_digest = hashlib.sha256(current_bytes).hexdigest()
        checkpoint_id = f"checkpoint-{len(self._manifest['segments']):08d}"
        checkpoint_path = self.path / "checkpoints" / f"{checkpoint_id}.json"
        snapshot = self._checkpoint_record(checkpoint_id, through_sequence)
        checkpoint_bytes = _canonical_json(snapshot)
        checkpoint_digest = hashlib.sha256(checkpoint_bytes).hexdigest()
        checkpoint_path_tmp = checkpoint_path.with_suffix(".json.tmp")
        new_index = int(active["index"]) + 1
        marker_sequence = int(self._manifest["next_event_sequence"])
        marker = {
            "schema_version": STREAM_SCHEMA_VERSION,
            "event_sequence": marker_sequence,
            "event": "checkpoint",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "checkpoint_id": checkpoint_id,
                "checkpoint_digest": checkpoint_digest,
                "through_sequence": through_sequence,
                "stream_sequence_high_water_mark": self.next_stream_sequence - 1,
                "sequence_digest": self.sequence_digest,
            },
        }
        marker_bytes = _canonical_json(marker) + b"\n"
        candidate = copy.deepcopy(self._manifest)
        candidate_active = candidate["segments"][-1]
        candidate_active["status"] = "sealed"
        candidate_active["digest"] = segment_digest
        candidate_active["bytes"] = len(current_bytes)
        candidate["segments"].append(
            self._segment_meta(new_index, segment_digest, "active", len(marker_bytes), marker_sequence, [])
        )
        candidate["active_segment"] = new_index
        candidate["next_event_sequence"] = marker_sequence + 1
        candidate["checkpoint"] = {
            "file": f"checkpoints/{checkpoint_id}.json",
            "digest": checkpoint_digest,
            "base_segment": active["index"],
            "marker_event_sequence": marker_sequence,
        }
        manifest_bytes = _canonical_json(candidate)
        compacted_candidate = copy.deepcopy(candidate)
        for meta in compacted_candidate["segments"]:
            if meta["index"] != new_index and meta["status"] == "sealed":
                if all(step_id in self._terminals for step_id in meta["step_ids"]):
                    meta["status"] = "compacted"
        compaction_manifest_bytes = (
            _canonical_json(compacted_candidate) if compacted_candidate != candidate else b""
        )
        # The checkpoint and new segment are written before the pointer. If
        # compaction is safe, reserve the second atomic manifest write as well.
        extra = len(checkpoint_bytes) + len(marker_bytes) + len(manifest_bytes) + len(compaction_manifest_bytes)
        self._ensure_quota(extra + quota_reserve)
        try:
            self._write_new_file(checkpoint_path_tmp, checkpoint_bytes)
            os.replace(checkpoint_path_tmp, checkpoint_path)
            self._fsync_directory(checkpoint_path.parent)
            new_segment_path = self._segment_path(new_index)
            self._write_new_file(new_segment_path, marker_bytes)
            self._write_manifest_value(candidate)
        except OSError as exc:
            raise StreamError("cannot durably rotate stream journal") from exc
        previous_checkpoint = self._manifest.get("checkpoint")
        self._manifest = candidate
        # The checkpoint marker is a journal event, but does not change stream state.
        self._compact_terminal_segments()
        if previous_checkpoint and previous_checkpoint.get("file") != candidate["checkpoint"]["file"]:
            self._unlink_if_present(self.path / previous_checkpoint["file"])
        return self._checkpoint_from_record(snapshot, checkpoint_digest)

    def _checkpoint_record(self, checkpoint_id: str, through_sequence: int) -> dict[str, Any]:
        high_water = self.next_stream_sequence - 1
        if through_sequence < 0 or through_sequence > high_water:
            raise StreamError("checkpoint terminal boundary is outside the appended stream")
        if any(
            sequence <= through_sequence and step_id not in self._terminals
            for step_id, (sequence, _, _) in self._intents.items()
        ):
            raise StreamError("checkpoint terminal boundary includes nonterminal work")
        references: list[dict[str, Any]] = []
        for packet in self.unresolved_packets():
            attempt_sequences = []
            for attempt in packet.attempts:
                attempt_sequences.append(attempt.started_event_sequence)
                if attempt.finished_event_sequence is not None:
                    attempt_sequences.append(attempt.finished_event_sequence)
            references.append(
                {
                    "step_id": packet.step_id,
                    "generation": packet.generation,
                    "signature": packet.signature,
                    "packet_digest": packet.packet_digest,
                    "signed_event_sequence": packet.signed_event_sequence,
                    "segment_index": packet.segment_index,
                    "attempt_event_sequences": attempt_sequences,
                }
            )
        intent_summaries = [
            {
                "sequence": sequence,
                "step_id": step_id,
                "intent": intent.to_record(),
                "intent_record_digest": digest,
            }
            for step_id, (sequence, intent, digest) in sorted(self._intents.items(), key=lambda item: item[1][0])
        ]
        terminal_rows = {step_id: terminal.to_record() for step_id, terminal in sorted(self._terminals.items())}
        return {
            "schema_version": STREAM_SCHEMA_VERSION,
            "checkpoint_id": checkpoint_id,
            "identity_digest": self.identity.digest,
            "through_sequence": through_sequence,
            "stream_sequence_high_water_mark": self.next_stream_sequence - 1,
            "sequence_digest": self.sequence_digest,
            "intent_summaries": intent_summaries,
            "confirmed_steps": {
                step_id: value for step_id, value in terminal_rows.items() if value["outcome"] == "confirmed"
            },
            "terminal_steps": terminal_rows,
            "unresolved_packet_references": references,
        }

    def _checkpoint_from_record(self, value: Mapping[str, Any], digest: str) -> StreamCheckpoint:
        return StreamCheckpoint(
            checkpoint_id=value["checkpoint_id"],
            through_sequence=value["through_sequence"],
            stream_sequence_high_water_mark=value["stream_sequence_high_water_mark"],
            sequence_digest=value["sequence_digest"],
            confirmed_steps=value["confirmed_steps"],
            terminal_steps=value["terminal_steps"],
            unresolved_packet_references=tuple(value["unresolved_packet_references"]),
            checkpoint_digest=digest,
        )

    def _terminal_prefix_sequence(self) -> int:
        boundary = 0
        for step_id, (sequence, _, _) in sorted(self._intents.items(), key=lambda item: item[1][0]):
            if step_id not in self._terminals:
                break
            boundary = sequence
        return boundary

    def _validate_checkpoint_refs(self) -> None:
        checkpoint = self._manifest.get("checkpoint")
        if checkpoint is None:
            return
        if checkpoint["base_segment"] + 1 != self._manifest["active_segment"]:
            raise StreamError("active stream checkpoint does not point to the current segment boundary")
        checkpoint_path = self.path / checkpoint["file"]
        try:
            raw = checkpoint_path.read_bytes()
        except OSError as exc:
            raise StreamError("active stream checkpoint is missing") from exc
        if hashlib.sha256(raw).hexdigest() != checkpoint["digest"]:
            raise StreamError("active stream checkpoint digest mismatch")
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StreamError("active stream checkpoint is invalid JSON") from exc
        if (
            record.get("schema_version") != STREAM_SCHEMA_VERSION
            or record.get("checkpoint_id") != checkpoint_path.stem
            or record.get("identity_digest") != self.identity.digest
        ):
            raise StreamError("checkpoint identity does not match stream")
        sequence_digest = _initial_sequence_digest(self.identity.digest)
        summaries = record.get("intent_summaries")
        if not isinstance(summaries, list):
            raise StreamError("checkpoint intent summaries are invalid")
        for expected_sequence, summary in enumerate(summaries, start=1):
            try:
                intent = StreamIntent.from_record(summary["intent"])
                sequence = summary["sequence"]
                summary_step_id = summary["step_id"]
                record_digest = summary["intent_record_digest"]
                current = self._intents[intent.step_id]
            except (KeyError, TypeError, ValueError) as exc:
                raise StreamError("checkpoint contains an invalid intent summary") from exc
            actual_record_digest = _intent_digest(intent.to_record())
            if (
                sequence != expected_sequence
                or summary_step_id != intent.step_id
                or record_digest != actual_record_digest
                or current[0] != sequence
                or current[1].to_record() != intent.to_record()
                or current[2] != record_digest
            ):
                raise StreamError("checkpoint intent summary does not match the stream")
            if any(
                dependency not in self._intents or self._intents[dependency][0] >= sequence
                for dependency in intent.dependencies
            ):
                raise StreamError("checkpoint contains a missing or future dependency")
            sequence_digest = _advance_sequence_digest(sequence_digest, sequence, actual_record_digest)
        high_water = record.get("stream_sequence_high_water_mark")
        if high_water != len(summaries) or record.get("sequence_digest") != sequence_digest:
            raise StreamError("checkpoint stream sequence digest is inconsistent")
        terminal_rows = record.get("terminal_steps")
        if not isinstance(terminal_rows, dict):
            raise StreamError("checkpoint terminal summaries are invalid")
        terminal_boundary = record.get("through_sequence")
        if (
            not isinstance(terminal_boundary, int)
            or isinstance(terminal_boundary, bool)
            or terminal_boundary < 0
            or terminal_boundary > high_water
        ):
            raise StreamError("checkpoint terminal boundary is invalid")
        if any(
            summary["sequence"] <= terminal_boundary and summary["step_id"] not in terminal_rows
            for summary in summaries
        ):
            raise StreamError("checkpoint terminal boundary includes an unresolved step")
        for step_id, terminal_row in terminal_rows.items():
            terminal = StreamTerminal.from_record(terminal_row)
            if self._terminals.get(step_id) != terminal:
                raise StreamError("checkpoint terminal summary is absent or changed")
        expected_confirmed = {
            step_id: row for step_id, row in terminal_rows.items() if row.get("outcome") == "confirmed"
        }
        if record.get("confirmed_steps") != expected_confirmed:
            raise StreamError("checkpoint confirmed-step summary does not match terminal summaries")
        active_rows = self._decode_segment_rows(self._segment_path(self._manifest["active_segment"]).read_bytes(), self._manifest["active_segment"])
        if (
            not active_rows
            or active_rows[0]["event_sequence"] != checkpoint["marker_event_sequence"]
            or active_rows[0]["event"] != "checkpoint"
            or active_rows[0]["data"].get("checkpoint_id") != checkpoint_path.stem
            or active_rows[0]["data"].get("checkpoint_digest") != checkpoint["digest"]
        ):
            raise StreamError("active segment does not contain the manifest checkpoint marker")
        references = record.get("unresolved_packet_references")
        if not isinstance(references, list):
            raise StreamError("checkpoint unresolved-packet references are invalid")
        for reference in references:
            if not isinstance(reference, dict):
                raise StreamError("checkpoint unresolved-packet reference is invalid")
            key = (reference.get("step_id"), reference.get("generation"))
            packet = self._packet_index.get(key)
            if (
                packet is None
                or packet.signature != reference.get("signature")
                or packet.packet_digest != reference.get("packet_digest")
                or packet.segment_index != reference.get("segment_index")
                or packet.signed_event_sequence != reference.get("signed_event_sequence")
            ):
                raise StreamError("checkpoint references a missing or changed unresolved packet")
            actual_attempt_sequences = []
            for attempt in self._attempt_index.get(key, []):
                actual_attempt_sequences.append(attempt.started_event_sequence)
                if attempt.finished_event_sequence is not None:
                    actual_attempt_sequences.append(attempt.finished_event_sequence)
            checkpoint_attempt_sequences = reference.get("attempt_event_sequences")
            if not isinstance(checkpoint_attempt_sequences, list):
                raise StreamError("checkpoint attempt references are invalid")
            if actual_attempt_sequences[: len(checkpoint_attempt_sequences)] != checkpoint_attempt_sequences:
                raise StreamError("checkpoint attempt references do not match retained packet history")

    def _compact_terminal_segments(self) -> None:
        changed = False
        active_index = self._manifest["active_segment"]
        for meta in self._manifest["segments"]:
            if meta["index"] == active_index or meta["status"] != "sealed":
                continue
            if all(step_id in self._terminals for step_id in meta["step_ids"]):
                meta["status"] = "compacted"
                changed = True
        if not changed:
            return
        # The new checkpoint pointer is already durable. Persist compaction state
        # before unlinking files, so a crash can only leave harmless old bytes.
        self._persist_manifest()
        for meta in self._manifest["segments"]:
            if meta["status"] == "compacted":
                self._unlink_if_present(self._segment_path(meta["index"]))
        self._fsync_directory(self.path / "segments")

    def _segment_meta(
        self,
        index: int,
        previous_digest: str,
        status: str,
        byte_count: int,
        first_event_sequence: int | None,
        step_ids: list[str],
    ) -> dict[str, Any]:
        return {
            "index": index,
            "name": f"segments/segment-{index:08d}.jsonl",
            "previous_digest": previous_digest,
            "digest": None,
            "status": status,
            "bytes": byte_count,
            "first_event_sequence": first_event_sequence,
            "last_event_sequence": None if first_event_sequence is None else first_event_sequence,
            "step_ids": list(step_ids),
        }

    def _decode_intent_index(self, value: Any) -> dict[str, tuple[int, StreamIntent, str]]:
        if not isinstance(value, dict):
            raise StreamError("stream manifest intent index is invalid")
        result = {}
        for step_id, row in value.items():
            try:
                intent = StreamIntent.from_record(row["intent"])
                sequence = row["sequence"]
                digest = row["intent_record_digest"]
                if intent.step_id != step_id or not isinstance(sequence, int) or not isinstance(digest, str):
                    raise ValueError
                result[step_id] = (sequence, intent, digest)
            except (KeyError, TypeError, ValueError) as exc:
                raise StreamError("stream manifest intent row is invalid") from exc
        return result

    def _decode_terminal_index(self, value: Any) -> dict[str, StreamTerminal]:
        if not isinstance(value, dict):
            raise StreamError("stream manifest terminal index is invalid")
        result = {step_id: StreamTerminal.from_record(row) for step_id, row in value.items()}
        if any(step_id != terminal.step_id for step_id, terminal in result.items()):
            raise StreamError("stream manifest terminal index key mismatch")
        for terminal in result.values():
            self._validate_terminal_policy(terminal)
        return result

    def _validate_terminal_policy(self, terminal: StreamTerminal) -> None:
        if self.identity.commitment_policy == "finalized" and terminal.commitment != "finalized":
            raise StreamError("terminal summary is weaker than the stream commitment policy")

    def _require_packet(self, step_id: str, generation: int) -> SignedPacketRecord:
        self._ensure_usable()
        packet = self._packet_index.get((step_id, generation))
        if packet is None:
            raise StreamError("stream event references an unknown signed packet")
        if step_id in self._terminals:
            raise StreamError("cannot add transport events after step terminal state")
        return packet

    def _ensure_usable(self) -> None:
        if self._poisoned:
            raise StreamError("stream journal needs reopen after an incomplete durable update")

    def _ensure_quota(self, extra_bytes: int) -> None:
        used = sum(path.stat().st_size for path in self.path.rglob("*") if path.is_file() and not path.name.endswith(".tmp"))
        if used + extra_bytes > self.limits.max_journal_bytes:
            raise StreamQuotaExceeded(
                f"stream journal quota exceeded: {used} bytes used, {extra_bytes} bytes required, "
                f"{self.limits.max_journal_bytes} byte limit"
            )

    def _manifest_peak_size(self, event_size: int) -> int:
        # An appended intent is duplicated in the manifest index. Other events
        # add at most their row size to manifest state; leave a small structural
        # allowance for segment metadata and JSON punctuation.
        current_size = (self.path / "manifest.json").stat().st_size
        return current_size + event_size + 2048

    def _persist_manifest(self) -> None:
        self._write_manifest_value(self._manifest)

    def _write_manifest_value(self, manifest: Mapping[str, Any]) -> None:
        encoded = _canonical_json(manifest)
        self._atomic_write(self.path / "manifest.json", encoded)

    def _atomic_write(self, path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp")
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            try:
                self._write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        except OSError as exc:
            raise StreamError(f"cannot atomically persist {path.name}") from exc

    def _write_new_file(self, path: Path, data: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                self._write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._fsync_directory(path.parent)
        except FileExistsError:
            raise
        except OSError as exc:
            raise StreamError(f"cannot create stream file {path.name}") from exc

    @classmethod
    def _ensure_directory(cls, directory: Path) -> None:
        missing = []
        current = directory
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                break
            current = current.parent
        for entry in reversed(missing):
            entry.mkdir(mode=0o700)
            cls._fsync_directory(entry.parent)

    def _append_file(self, path: Path, data: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_APPEND | os.O_WRONLY)
            try:
                self._write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise StreamError("cannot append and fsync stream event") from exc

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short stream journal write")
            view = view[written:]

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

    def _cleanup_orphans(self) -> None:
        referenced_checkpoints = {self._manifest["checkpoint"]["file"]} if self._manifest.get("checkpoint") else set()
        for path in self.path.rglob("*.tmp"):
            self._unlink_if_present(path)
        for path in (self.path / "segments").glob("segment-*.jsonl"):
            relative = path.relative_to(self.path).as_posix()
            known = any(meta["name"] == relative for meta in self._manifest["segments"])
            if not known:
                self._unlink_if_present(path)
        for path in (self.path / "checkpoints").glob("checkpoint-*.json"):
            relative = path.relative_to(self.path).as_posix()
            if relative not in referenced_checkpoints:
                self._unlink_if_present(path)
        # A compacted segment may remain if a crash happened after the manifest
        # update and before unlink. Its digest stays in the chain metadata.
        for meta in self._manifest["segments"]:
            if meta["status"] == "compacted":
                self._unlink_if_present(self._segment_path(meta["index"]))

    @staticmethod
    def _unlink_if_present(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StreamError(f"cannot remove compacted stream file {path.name}") from exc
        StreamJournal._fsync_directory(path.parent)

    def _segment_path(self, index: int) -> Path:
        return self.path / "segments" / f"segment-{index:08d}.jsonl"
