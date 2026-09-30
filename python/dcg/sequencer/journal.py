"""Versioned, append-only JSONL journal with fsync-before-return semantics."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .types import JournalError


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class JournalEvent:
    sequence: int
    run_id: str
    name: str
    data: dict[str, Any]
    recorded_at: str


class JournalStore:
    """Durable JSONL journal. Each returned append has been flushed and fsynced.

    Packet bytes are base64-encoded in ``step_signed`` rows. The journal never
    receives a signer object or private key; it stores only the signer's public
    identity and the signed transaction that must be retransmitted verbatim.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._next_sequence: int | None = None

    def events(self) -> list[JournalEvent]:
        """Read and validate the journal, discarding only an incomplete tail."""

        with self._lock:
            if not self.path.exists():
                return []
            try:
                raw = self.path.read_bytes()
            except OSError as exc:
                raise JournalError(f"cannot read journal {self.path}") from exc

            if raw and not raw.endswith(b"\n"):
                tail_start = raw.rfind(b"\n") + 1
                tail = raw[tail_start:]
                try:
                    json.loads(tail)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._truncate(tail_start)
                else:
                    # Valid JSON with an unsupported schema or bad fields is
                    # corruption, not a torn write to silently discard.
                    self._decode_line(tail)
                    self._append_bytes(b"\n")
                raw = self.path.read_bytes()

            result: list[JournalEvent] = []
            expected_sequence = 0
            for line_number, line in enumerate(raw.splitlines(), start=1):
                if not line:
                    raise JournalError(f"empty journal row at line {line_number}")
                event = self._decode_line(line)
                if event.sequence != expected_sequence:
                    raise JournalError(
                        f"journal sequence mismatch at line {line_number}: "
                        f"expected {expected_sequence}, got {event.sequence}"
                    )
                expected_sequence += 1
                result.append(event)
            self._next_sequence = expected_sequence
            return result

    def append(self, run_id: str, name: str, data: dict[str, Any]) -> JournalEvent:
        """Append one event and fsync the row and newly created directory entry."""

        with self._lock:
            if self._next_sequence is None:
                self.events()
            self._ensure_parent()
            created = not self.path.exists()
            event = JournalEvent(
                sequence=self._next_sequence or 0,
                run_id=run_id,
                name=name,
                data=data,
                recorded_at=datetime.now(timezone.utc).isoformat(),
            )
            row = {
                "schema_version": SCHEMA_VERSION,
                "sequence": event.sequence,
                "run_id": event.run_id,
                "event": event.name,
                "recorded_at": event.recorded_at,
                "data": event.data,
            }
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            self._append_bytes(encoded + b"\n")
            if created:
                self._fsync_directory(self.path.parent)
            self._next_sequence = event.sequence + 1
            return event

    def _decode_line(self, line: bytes) -> JournalEvent:
        try:
            payload = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JournalError("invalid JSON in journal") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
            raise JournalError("unsupported journal schema version")
        try:
            sequence = payload["sequence"]
            run_id = payload["run_id"]
            name = payload["event"]
            data = payload["data"]
            recorded_at = payload["recorded_at"]
        except KeyError as exc:
            raise JournalError("journal row is missing a required field") from exc
        if (
            not isinstance(sequence, int)
            or not isinstance(run_id, str)
            or not isinstance(name, str)
            or not isinstance(data, dict)
            or not isinstance(recorded_at, str)
        ):
            raise JournalError("journal row has an invalid field type")
        return JournalEvent(sequence, run_id, name, data, recorded_at)

    def _truncate(self, size: int) -> None:
        try:
            with self.path.open("r+b") as stream:
                stream.truncate(size)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise JournalError("cannot repair incomplete journal tail") from exc

    def _append_bytes(self, data: bytes) -> None:
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        try:
            descriptor = os.open(self.path, flags, 0o600)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short journal write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise JournalError("cannot append and fsync journal") from exc

    def _ensure_parent(self) -> None:
        missing: list[Path] = []
        parent = self.path.parent
        while not parent.exists():
            missing.append(parent)
            if parent.parent == parent:
                break
            parent = parent.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
                self._fsync_directory(directory.parent)
            except OSError as exc:
                raise JournalError(f"cannot create journal directory {directory}") from exc

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise JournalError(f"cannot fsync journal directory {directory}") from exc
