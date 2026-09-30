"""Tiny local account inventory; it is the authority for session cleanup."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dcg.sequencer import JournalError


@dataclass(frozen=True)
class AccountRecord:
    address: str
    role: str
    parent: str | None
    lifecycle: str


class AccountInventory:
    """Atomic JSON snapshot of accounts this client intends to create/close."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        session_id: int,
        program_id: str,
        authority: str,
    ):
        self.path = Path(path)
        self.session_id = session_id
        self.program_id = program_id
        self.authority = authority
        self._accounts: list[AccountRecord] = []
        self._load()

    @property
    def accounts(self) -> tuple[AccountRecord, ...]:
        return tuple(self._accounts)

    def plan(self, entries: Iterable[tuple[str, str, str | None]]) -> None:
        proposed = [AccountRecord(address, role, parent, "planned") for address, role, parent in entries]
        if len({item.address for item in proposed}) != len(proposed):
            raise JournalError("account inventory contains duplicate addresses")
        if self._accounts:
            existing = [(item.address, item.role, item.parent) for item in self._accounts]
            expected = [(item.address, item.role, item.parent) for item in proposed]
            if existing != expected:
                raise JournalError("account inventory does not match this session's derived addresses")
            return
        self._accounts = proposed
        self._save()

    def mark_created(self, address: str) -> None:
        self._transition(address, "planned", "created")

    def mark_closed(self, address: str) -> None:
        self._transition(address, "created", "closed")

    def record(self, address: str) -> AccountRecord:
        for item in self._accounts:
            if item.address == address:
                return item
        raise JournalError(f"account {address} is absent from this session's inventory")

    def created(self) -> tuple[AccountRecord, ...]:
        return tuple(item for item in self._accounts if item.lifecycle == "created")

    def _transition(self, address: str, source: str, target: str) -> None:
        for index, item in enumerate(self._accounts):
            if item.address == address:
                if item.lifecycle == target:
                    return
                if item.lifecycle != source:
                    raise JournalError(
                        f"account {address} lifecycle cannot move from {item.lifecycle} to {target}"
                    )
                self._accounts[index] = AccountRecord(item.address, item.role, item.parent, target)
                self._save()
                return
        raise JournalError(f"account {address} is absent from this session's inventory")

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            records = payload["accounts"]
            if (
                payload.get("schema_version") != self.SCHEMA_VERSION
                or payload.get("session_id") != self.session_id
                or payload.get("program_id") != self.program_id
                or payload.get("authority") != self.authority
                or not isinstance(records, list)
            ):
                raise ValueError
            parsed = [
                AccountRecord(
                    address=item["address"],
                    role=item["role"],
                    parent=item.get("parent"),
                    lifecycle=item["lifecycle"],
                )
                for item in records
            ]
            if any(item.lifecycle not in {"planned", "created", "closed"} for item in parsed):
                raise ValueError
            if len({item.address for item in parsed}) != len(parsed):
                raise ValueError
            self._accounts = parsed
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise JournalError(f"account inventory is malformed or belongs to another session: {self.path}") from exc

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "session_id": self.session_id,
            "program_id": self.program_id,
            "authority": self.authority,
            "accounts": [
                {
                    "address": item.address,
                    "role": item.role,
                    "parent": item.parent,
                    "lifecycle": item.lifecycle,
                }
                for item in self._accounts
            ],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        descriptor, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
