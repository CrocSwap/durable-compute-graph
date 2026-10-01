"""Seed-backed account inventory with chain reconciliation and close guards.

The JSON file is a cache of operator intent. Addresses are re-derived from
their seeds and chain reads decide whether an account exists, is well formed,
or still has children.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Mapping, Sequence

from solders.pubkey import Pubkey

from dcg.sequencer import AccountInfo, Commitment, JournalError


LIFECYCLES = frozenset({"planned", "live", "retired", "closed"})
MAX_MULTIPLE_ACCOUNTS = 100


@dataclass(frozen=True)
class AccountRecord:
    """One account intent, with its address bound to the PDA seeds."""

    address: str
    kind: str
    role: str
    seeds: tuple[bytes, ...]
    parent: str | None
    lifecycle: str = "planned"
    payer: str | None = None
    rent_lamports: int | None = None
    expected_size: int | None = None

    @classmethod
    def derive(
        cls,
        program_id: str | Pubkey,
        *,
        kind: str,
        role: str,
        seeds: Iterable[bytes],
        parent: str | None = None,
        lifecycle: str = "planned",
        payer: str | None = None,
        rent_lamports: int | None = None,
        expected_size: int | None = None,
    ) -> AccountRecord:
        seed_tuple = tuple(seeds)
        _validate_seeds(seed_tuple)
        program = Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id
        address = str(Pubkey.find_program_address(list(seed_tuple), program)[0])
        return cls(
            address=address,
            kind=kind,
            role=role,
            seeds=seed_tuple,
            parent=parent,
            lifecycle=lifecycle,
            payer=payer,
            rent_lamports=rent_lamports,
            expected_size=expected_size,
        )

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value for value in (self.address, self.kind, self.role)):
            raise ValueError("account address, kind, and role must be non-empty")
        if self.parent is not None and not isinstance(self.parent, str):
            raise ValueError("account parent must be a public key string or None")
        if self.payer is not None and not isinstance(self.payer, str):
            raise ValueError("account payer must be a public key string or None")
        _validate_seeds(self.seeds)
        if self.lifecycle not in LIFECYCLES:
            raise ValueError(f"unsupported account lifecycle {self.lifecycle!r}")
        if self.rent_lamports is not None and (
            not isinstance(self.rent_lamports, int)
            or isinstance(self.rent_lamports, bool)
            or self.rent_lamports < 0
        ):
            raise ValueError("rent_lamports must be a non-negative integer or None")
        if self.expected_size is not None and (
            not isinstance(self.expected_size, int)
            or isinstance(self.expected_size, bool)
            or self.expected_size < 0
        ):
            raise ValueError("expected_size must be a non-negative integer or None")


@dataclass(frozen=True)
class AccountKindCodec:
    """Optional header rules for validating and rebuilding a DCG account kind.

    A codec that has ``parent_offset`` participates in filtered
    ``getProgramAccounts`` discovery. ``seeds_from_data`` makes that kind
    rebuildable from its on-chain header. Codecs are executable client rules;
    they are deliberately supplied by the caller rather than serialized into
    the inventory file.
    """

    kind: str
    magic: bytes
    parent_offset: int | None = None
    may_have_children: bool = True
    seeds_from_data: Callable[[bytes], tuple[bytes, ...]] | None = None
    role_from_data: Callable[[bytes], str] | None = None
    size_from_data: Callable[[bytes], int | None] | None = None
    state_from_data: Callable[[bytes], str | None] | None = None
    dependency_count_from_data: Callable[[bytes], int | None] | None = None
    expected_state: Mapping[str, str] | None = None
    validate_data: Callable[[bytes], str | None] | None = None

    def __post_init__(self) -> None:
        if not self.kind or not self.magic:
            raise ValueError("account codec kind and magic must be non-empty")
        if self.parent_offset is not None and self.parent_offset < 0:
            raise ValueError("parent header offset cannot be negative")

    def parent_from_data(self, data: bytes) -> str | None:
        if self.parent_offset is None:
            return None
        end = self.parent_offset + 32
        if len(data) < end:
            raise ValueError("account header is too short to contain its parent")
        return str(Pubkey.from_bytes(data[self.parent_offset:end]))

    def rebuild(
        self, *, address: str, program_id: str, info: AccountInfo, parent: str
    ) -> AccountRecord | None:
        if not info.data.startswith(self.magic) or self.seeds_from_data is None:
            return None
        try:
            if self.validate_data is not None and self.validate_data(info.data) is not None:
                return None
            if self.parent_from_data(info.data) != parent:
                return None
            seeds = self.seeds_from_data(info.data)
            role = self.role_from_data(info.data) if self.role_from_data is not None else self.kind
            expected_size = self.size_from_data(info.data) if self.size_from_data is not None else len(info.data)
        except (IndexError, TypeError, ValueError):
            return None
        record = AccountRecord.derive(
            program_id,
            kind=self.kind,
            role=role,
            seeds=seeds,
            parent=parent,
            lifecycle="live",
            rent_lamports=info.lamports,
            expected_size=expected_size,
        )
        if record.address != address:
            return None
        return record


@dataclass(frozen=True)
class StateIssue:
    address: str
    message: str


@dataclass(frozen=True)
class UnexpectedAccount:
    address: str
    parent: str | None
    kind: str | None
    message: str


@dataclass(frozen=True)
class ReconciliationReport:
    missing: tuple[AccountRecord, ...]
    unexpected: tuple[UnexpectedAccount, ...]
    wrong_state: tuple[StateIssue, ...]
    chain_children: tuple[UnexpectedAccount, ...]
    rebuilt: tuple[AccountRecord, ...]
    discovery_complete: bool
    discovery_issue: str | None = None

    @property
    def ok(self) -> bool:
        return not (self.missing or self.unexpected or self.wrong_state) and self.discovery_complete

    def issues_for(self, address: str) -> tuple[StateIssue, ...]:
        return tuple(issue for issue in self.wrong_state if issue.address == address)

    def children_of(self, address: str) -> tuple[UnexpectedAccount, ...]:
        return tuple(child for child in self.chain_children if child.parent == address)


CloseAction = Callable[[AccountRecord, AccountInfo], Awaitable[object]]


class Inventory:
    """Atomic local snapshot reconciled against program-owned chain accounts."""

    SCHEMA_VERSION = 2

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        program_id: str | Pubkey,
        metadata: Mapping[str, object] | None = None,
        codecs: Iterable[AccountKindCodec] = (),
    ):
        self.path = Path(path)
        self.program_id = str(Pubkey.from_string(program_id) if isinstance(program_id, str) else program_id)
        self.metadata = dict(metadata or {})
        codec_list = tuple(codecs)
        self.codecs = {codec.kind: codec for codec in codec_list}
        if len(self.codecs) != len(codec_list):
            raise ValueError("account codec kinds must be unique")
        self._accounts: list[AccountRecord] = []
        self._legacy_metadata: dict[str, object] | None = None
        self._load()

    @property
    def accounts(self) -> tuple[AccountRecord, ...]:
        return tuple(self._accounts)

    def plan(self, entries: Iterable[AccountRecord]) -> None:
        proposed = list(entries)
        if len({item.address for item in proposed}) != len(proposed):
            raise JournalError("account inventory contains duplicate addresses")
        for item in proposed:
            self._validate_derived(item)

        if self._legacy_metadata is not None:
            for legacy in self._accounts:
                matches = [
                    item
                    for item in proposed
                    if (item.role, item.parent) == (legacy.role, legacy.parent)
                ]
                if len(matches) != 1 or matches[0].address != legacy.address:
                    raise JournalError("legacy account inventory does not match the new seed-derived plan")

        existing_by_address = {item.address: item for item in self._accounts}
        for item in proposed:
            existing = existing_by_address.get(item.address)
            if existing is None:
                conflicts = [
                    record
                    for record in self._accounts
                    if (record.kind, record.role, record.parent) == (item.kind, item.role, item.parent)
                ]
                if conflicts:
                    raise JournalError("account role and parent already exist with a different seed-derived address")
                self._accounts.append(item)
                continue
            if self._legacy_metadata is not None:
                if (existing.role, existing.parent) != (item.role, item.parent):
                    raise JournalError("legacy account inventory does not match derived account roles")
                upgraded = AccountRecord(
                    **{
                        **_record_dict(item),
                        "lifecycle": existing.lifecycle,
                        "payer": item.payer or existing.payer,
                        "rent_lamports": existing.rent_lamports,
                    }
                )
                self._accounts[self._accounts.index(existing)] = upgraded
                continue
            if _identity(existing) != _identity(item):
                raise JournalError("account inventory does not match the derived address, role, seeds, or parent")
        if proposed:
            self._legacy_metadata = None
            self._save()

    def add(self, record: AccountRecord) -> None:
        self.plan((record,))

    def mark_live(self, address: str, *, payer: str | None = None, rent_lamports: int | None = None) -> None:
        self._transition(address, {"planned"}, "live", payer=payer, rent_lamports=rent_lamports)

    def mark_created(self, address: str) -> None:
        """Compatibility alias for the former ``created`` lifecycle state."""

        self.mark_live(address)

    def retire(self, address: str) -> None:
        self._transition(address, {"live"}, "retired")

    def mark_closed(self, address: str) -> None:
        """Mark a retired record closed after an external, verified close."""

        self._transition(address, {"retired"}, "closed")

    async def forget_missing_plan(
        self, address: str, rpc, *, commitment: Commitment = Commitment.CONFIRMED
    ) -> None:
        """Drop a planned entry only after chain confirms its PDA was never created."""

        record = self.record(address)
        if record.lifecycle != "planned":
            raise JournalError(f"account {address} is not a planned entry")
        derived = _derive(self.program_id, record.seeds)
        if derived != address:
            raise JournalError(f"account {address} differs from its seed-derived address {derived}")
        info = (await _get_multiple(rpc, (derived,), commitment))[0]
        if info is not None:
            raise JournalError(f"planned account {address} exists on chain; reconcile it before removing the plan")
        self._accounts.remove(record)
        self._save()

    def record(self, address: str) -> AccountRecord:
        for item in self._accounts:
            if item.address == address:
                return item
        raise JournalError(f"account {address} is absent from the inventory")

    def created(self) -> tuple[AccountRecord, ...]:
        """Compatibility accessor; new code should use ``accounts`` or ``live``."""

        return self.live()

    def live(self) -> tuple[AccountRecord, ...]:
        return tuple(item for item in self._accounts if item.lifecycle == "live")

    async def reconcile(
        self,
        rpc,
        *,
        discover: bool = True,
        rebuild: bool = False,
        commitment: Commitment = Commitment.CONFIRMED,
        parents_to_check: Iterable[str] | None = None,
    ) -> ReconciliationReport:
        """Re-derive expected PDAs and compare them with batched chain reads.

        Discovery uses parent offsets declared by account codecs. It can find
        unjournaled children only for registered, parent-bearing header kinds.
        """

        derived: dict[str, str] = {}
        issues: list[StateIssue] = []
        for record in self._accounts:
            try:
                actual = _derive(self.program_id, record.seeds)
            except (TypeError, ValueError) as exc:
                issues.append(StateIssue(record.address, f"stored seeds cannot derive a PDA: {exc}"))
                continue
            if actual != record.address:
                issues.append(StateIssue(record.address, f"stored address differs from seed-derived address {actual}"))
            if actual in derived:
                issues.append(StateIssue(record.address, f"duplicate derived address also used by {derived[actual]}"))
            derived[actual] = record.address

        actual_addresses = tuple(derived)
        infos = await _get_multiple(rpc, actual_addresses, commitment)
        missing: list[AccountRecord] = []
        unexpected: list[UnexpectedAccount] = []
        rebuilt: list[AccountRecord] = []
        local_state_changed = False
        record_by_derived = {derived_addr: self.record(stored_addr) for derived_addr, stored_addr in derived.items()}
        for address, info in zip(actual_addresses, infos, strict=True):
            record = record_by_derived[address]
            if info is None:
                if record.lifecycle != "closed":
                    missing.append(record)
                continue
            inspection = self._inspect(record, info)
            if record.lifecycle == "closed":
                unexpected.append(UnexpectedAccount(address, record.parent, record.kind, "closed account still exists on chain"))
                issues.extend(inspection)
            elif rebuild:
                structural = [item for item in inspection if not item.message.startswith("chain state is ")]
                if record.address != address or structural:
                    issues.extend(inspection)
                else:
                    recovered = self._lifecycle_from_chain(record, info)
                    if recovered is None:
                        issues.extend(inspection)
                        issues.append(StateIssue(address, "account exists on chain but its lifecycle cannot be rebuilt from its header"))
                    else:
                        if record.lifecycle != recovered or record.rent_lamports != info.lamports:
                            record = self._replace_record(
                                record,
                                lifecycle=recovered,
                                payer=record.payer,
                                rent_lamports=info.lamports,
                            )
                            local_state_changed = True
                        issues.extend(self._inspect(record, info))
            elif record.lifecycle == "planned":
                issues.append(StateIssue(address, "account exists on chain but inventory still says planned"))
                issues.extend(inspection)
            else:
                issues.extend(inspection)

        chain_children: list[UnexpectedAccount] = []
        discovery_complete = True
        discovery_issue: str | None = None
        if discover:
            offsets = sorted({codec.parent_offset for codec in self.codecs.values() if codec.parent_offset is not None})
            if parents_to_check is None:
                parent_queue = sorted(
                    address
                    for address, stored in derived.items()
                    if (self.codecs.get(self.record(stored).kind) is None)
                    or self.codecs[self.record(stored).kind].may_have_children
                )
            else:
                parent_queue = sorted(set(parents_to_check))
            get_program_accounts = getattr(rpc, "get_program_accounts", None)
            if not offsets:
                discovery_complete = False
                discovery_issue = "no parent-header codecs are registered to verify account dependencies"
            elif get_program_accounts is None:
                discovery_complete = False
                discovery_issue = "RPC adapter does not provide getProgramAccounts parent discovery"
            else:
                seen: set[tuple[str, str]] = set()
                discovered_parents = set(parent_queue)
                while parent_queue:
                    parent = parent_queue.pop(0)
                    for offset in offsets:
                        matches = await get_program_accounts(
                            self.program_id,
                            filters=({"memcmp": {"offset": offset, "bytes": parent}},),
                            commitment=commitment,
                        )
                        for child_address, info in matches:
                            identity = (parent, child_address)
                            if identity in seen:
                                continue
                            seen.add(identity)
                            codec = next(
                                (
                                    candidate
                                    for candidate in self.codecs.values()
                                    if candidate.parent_offset == offset
                                    and info.data.startswith(candidate.magic)
                                ),
                                None,
                            )
                            try:
                                header_parent = (
                                    codec.parent_from_data(info.data)
                                    if codec is not None
                                    else str(Pubkey.from_bytes(info.data[offset : offset + 32]))
                                )
                            except (ValueError, IndexError):
                                continue
                            if header_parent != parent:
                                continue
                            child = UnexpectedAccount(
                                child_address,
                                parent,
                                codec.kind if codec is not None else None,
                                "untracked on-chain child with a parent header",
                            )
                            chain_children.append(child)
                            if child_address in derived:
                                continue
                            if codec is not None and codec.validate_data is not None:
                                codec_issue = codec.validate_data(info.data)
                                if codec_issue:
                                    unexpected.append(
                                        UnexpectedAccount(child_address, parent, codec.kind, f"cannot rebuild malformed child: {codec_issue}")
                                    )
                                    continue
                            try:
                                rebuilt_record = codec.rebuild(
                                    address=child_address,
                                    program_id=self.program_id,
                                    info=info,
                                    parent=parent,
                                ) if codec is not None else None
                            except (IndexError, TypeError, ValueError):
                                rebuilt_record = None
                            if rebuild and rebuilt_record is not None:
                                if info.owner != self.program_id or info.executable:
                                    issues.append(StateIssue(child_address, "cannot rebuild account with unexpected owner or executable flag"))
                                    unexpected.append(child)
                                    continue
                                self._validate_derived(rebuilt_record)
                                self._accounts.append(rebuilt_record)
                                rebuilt.append(rebuilt_record)
                                if codec.may_have_children and child_address not in discovered_parents:
                                    discovered_parents.add(child_address)
                                    parent_queue.append(child_address)
                                continue
                            unexpected.append(child)

        if rebuilt or local_state_changed:
            self._save()
        return ReconciliationReport(
            missing=tuple(missing),
            unexpected=tuple(unexpected),
            wrong_state=tuple(issues),
            chain_children=tuple(chain_children),
            rebuilt=tuple(rebuilt),
            discovery_complete=discovery_complete,
            discovery_issue=discovery_issue,
        )

    async def close(
        self,
        address: str,
        rpc,
        close_action: CloseAction,
        *,
        commitment: Commitment = Commitment.CONFIRMED,
    ) -> int:
        """Close one retired account after rechecking it and its dependents.

        ``close_action`` performs the kind-specific protocol instruction. The
        inventory verifies disappearance before recording ``closed`` and
        returns the account's last observed lamports.
        """

        record = self.record(address)
        if record.lifecycle != "retired":
            raise JournalError(f"account {address} must be retired before it can be closed")
        report = await self.reconcile(
            rpc,
            discover=True,
            commitment=commitment,
            parents_to_check=(address,),
        )
        if not report.discovery_complete:
            raise JournalError(report.discovery_issue or "cannot verify on-chain dependents")
        if report.children_of(address):
            child_addresses = ", ".join(child.address for child in report.children_of(address))
            raise JournalError(f"account {address} still has on-chain dependents: {child_addresses}")
        issues = report.issues_for(address)
        if issues:
            raise JournalError(f"account {address} has wrong chain state: {issues[0].message}")
        derived = _derive(self.program_id, record.seeds)
        if derived != address:
            raise JournalError(f"account {address} differs from its seed-derived address {derived}")
        info = (await _get_multiple(rpc, (derived,), commitment))[0]
        if info is None:
            self.mark_closed(address)
            return 0
        inspection = self._inspect(record, info)
        if inspection:
            raise JournalError(f"account {address} has wrong chain state: {inspection[0].message}")
        codec = self.codecs.get(record.kind)
        if codec is not None and codec.dependency_count_from_data is not None:
            try:
                dependency_count = codec.dependency_count_from_data(info.data)
            except (IndexError, TypeError, ValueError) as exc:
                raise JournalError(f"account {address} has a malformed dependency count: {exc}") from exc
            if dependency_count is None:
                raise JournalError(f"account {address} does not expose a readable dependency count")
            if dependency_count:
                raise JournalError(f"account {address} still records {dependency_count} dependent account(s)")
        await close_action(record, info)
        remaining = (await _get_multiple(rpc, (derived,), commitment))[0]
        if remaining is not None:
            raise JournalError(f"close action returned but account {address} still exists on chain")
        self.mark_closed(address)
        self._set_rent(address, info.lamports)
        return info.lamports

    def _inspect(self, record: AccountRecord, info: AccountInfo) -> list[StateIssue]:
        issues: list[StateIssue] = []
        if info.owner != self.program_id:
            issues.append(StateIssue(record.address, f"owner is {info.owner}, expected {self.program_id}"))
        if info.executable:
            issues.append(StateIssue(record.address, "account is executable, expected a data account"))
        if record.expected_size is not None and len(info.data) != record.expected_size:
            issues.append(StateIssue(record.address, f"data size is {len(info.data)}, expected {record.expected_size}"))
        codec = self.codecs.get(record.kind)
        if codec is not None:
            if not info.data.startswith(codec.magic):
                issues.append(StateIssue(record.address, f"header magic does not match {record.kind}"))
            else:
                if codec.seeds_from_data is not None:
                    try:
                        header_seeds = codec.seeds_from_data(info.data)
                    except (IndexError, TypeError, ValueError) as exc:
                        issues.append(StateIssue(record.address, f"header seed fields are malformed: {exc}"))
                    else:
                        if header_seeds != record.seeds:
                            issues.append(StateIssue(record.address, "header seeds differ from the inventory derivation"))
                if codec.role_from_data is not None:
                    try:
                        header_role = codec.role_from_data(info.data)
                    except (IndexError, TypeError, ValueError) as exc:
                        issues.append(StateIssue(record.address, f"header role field is malformed: {exc}"))
                    else:
                        if header_role != record.role:
                            issues.append(StateIssue(record.address, f"header role is {header_role!r}, expected {record.role!r}"))
                if codec.parent_offset is not None:
                    try:
                        actual_parent = codec.parent_from_data(info.data)
                    except ValueError as exc:
                        issues.append(StateIssue(record.address, str(exc)))
                    else:
                        if actual_parent != record.parent:
                            issues.append(StateIssue(record.address, f"header parent is {actual_parent}, expected {record.parent}"))
                if codec.validate_data is not None:
                    try:
                        issue = codec.validate_data(info.data)
                    except (IndexError, TypeError, ValueError) as exc:
                        issue = f"account header is malformed: {exc}"
                    if issue:
                        issues.append(StateIssue(record.address, issue))
                if codec.state_from_data is not None:
                    actual_state = codec.state_from_data(info.data)
                    expected_state = (codec.expected_state or {}).get(record.lifecycle)
                    if expected_state is not None and actual_state != expected_state:
                        issues.append(StateIssue(record.address, f"chain state is {actual_state!r}, expected {expected_state!r} for {record.lifecycle}"))
        return issues

    def _lifecycle_from_chain(self, record: AccountRecord, info: AccountInfo) -> str | None:
        codec = self.codecs.get(record.kind)
        if codec is None:
            return record.lifecycle if record.lifecycle in {"live", "retired"} else "live"
        if not info.data.startswith(codec.magic):
            return None
        if codec.state_from_data is None:
            return "live"
        observed = codec.state_from_data(info.data)
        for lifecycle, state in (codec.expected_state or {}).items():
            if state == observed and lifecycle in {"live", "retired"}:
                return lifecycle
        return None

    def _replace_record(
        self,
        record: AccountRecord,
        *,
        lifecycle: str,
        payer: str | None,
        rent_lamports: int | None,
    ) -> AccountRecord:
        replacement = AccountRecord(
            **{
                **_record_dict(record),
                "lifecycle": lifecycle,
                "payer": payer if payer is not None else record.payer,
                "rent_lamports": rent_lamports if rent_lamports is not None else record.rent_lamports,
            }
        )
        self._accounts[self._accounts.index(record)] = replacement
        return replacement

    def _validate_derived(self, record: AccountRecord) -> None:
        if _derive(self.program_id, record.seeds) != record.address:
            raise JournalError(f"account {record.address} does not match its supplied derivation seeds")
        if record.parent is not None:
            try:
                Pubkey.from_string(record.parent)
            except ValueError as exc:
                raise JournalError(f"account {record.address} has an invalid parent address") from exc

    def _transition(
        self,
        address: str,
        sources: set[str],
        target: str,
        *,
        payer: str | None = None,
        rent_lamports: int | None = None,
    ) -> None:
        for index, item in enumerate(self._accounts):
            if item.address != address:
                continue
            if item.lifecycle == target:
                return
            if item.lifecycle not in sources:
                raise JournalError(f"account {address} lifecycle cannot move from {item.lifecycle} to {target}")
            self._accounts[index] = AccountRecord(
                **{
                    **_record_dict(item),
                    "lifecycle": target,
                    "payer": payer if payer is not None else item.payer,
                    "rent_lamports": rent_lamports if rent_lamports is not None else item.rent_lamports,
                }
            )
            self._save()
            return
        raise JournalError(f"account {address} is absent from the inventory")

    def _set_rent(self, address: str, rent_lamports: int) -> None:
        for index, item in enumerate(self._accounts):
            if item.address == address:
                self._accounts[index] = AccountRecord(
                    **{**_record_dict(item), "rent_lamports": rent_lamports}
                )
                self._save()
                return

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            version = payload.get("schema_version")
            if version == 1:
                if payload.get("program_id") != self.program_id:
                    raise ValueError
                legacy = {key: payload.get(key) for key in ("session_id", "authority") if key in payload}
                if any(self.metadata.get(key) != value for key, value in legacy.items()):
                    raise ValueError
                records = payload["accounts"]
                if not isinstance(records, list):
                    raise ValueError
                self._accounts = [
                    AccountRecord(
                        address=item["address"],
                        kind=item.get("role", "legacy"),
                        role=item["role"],
                        seeds=(b"legacy-unbound",),
                        parent=item.get("parent"),
                        lifecycle={"created": "live"}.get(item["lifecycle"], item["lifecycle"]),
                    )
                    for item in records
                ]
                self._legacy_metadata = legacy
                return
            if (
                version != self.SCHEMA_VERSION
                or payload.get("program_id") != self.program_id
                or payload.get("metadata", {}) != self.metadata
                or not isinstance(payload.get("accounts"), list)
            ):
                raise ValueError
            self._accounts = [_record_from_json(item) for item in payload["accounts"]]
            if len({item.address for item in self._accounts}) != len(self._accounts):
                raise ValueError
        except (OSError, AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise JournalError(f"account inventory is malformed or belongs to another program/session: {self.path}") from exc

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "program_id": self.program_id,
            "metadata": self.metadata,
            "accounts": [_record_json(item) for item in self._accounts],
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


class AccountInventory(Inventory):
    """Compatibility constructor for loading and migrating v1 session journals."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        session_id: int,
        program_id: str,
        authority: str,
        codecs: Iterable[AccountKindCodec] = (),
    ):
        self.session_id = session_id
        self.authority = authority
        super().__init__(
            path,
            program_id=program_id,
            metadata={"session_id": session_id, "authority": authority},
            codecs=codecs,
        )


def stateful_account_codecs(wire_version: int) -> tuple[AccountKindCodec, ...]:
    """Header codecs for stateful v1/v2 sessions and parent-bearing children."""

    if wire_version not in {1, 2}:
        raise ValueError("stateful inventory codecs support wire versions 1 and 2")
    version = str(wire_version).encode("ascii")
    session_kind = f"stateful_session_v{wire_version}"

    def session_state(data: bytes) -> str | None:
        if len(data) <= 6:
            return None
        return {1: "active", 2: "halted"}.get(data[6], "invalid")

    def read_uint(data: bytes, offset: int, width: int) -> int:
        return int.from_bytes(data[offset : offset + width], "little")

    def stream_size(data: bytes) -> int | None:
        width = 2 if wire_version == 1 else 4
        if len(data) < 72 + width:
            return None
        return 128 + read_uint(data, 72, width) * 16

    def validate_stream(data: bytes) -> str | None:
        expected = stream_size(data)
        if (
            len(data) < 128
            or data[4:6] != wire_version.to_bytes(2, "little")
            or data[6] != 1
            or data[7] != 1
        ):
            return "stream account header is malformed"
        if data[84:88] != (16).to_bytes(4, "little") or expected != len(data):
            return "stream account size or slot width disagrees with its header"
        return None

    def state_size(data: bytes) -> int | None:
        if len(data) < 128:
            return None
        allocated = read_uint(data, 84 if wire_version == 1 else 100, 4)
        return 128 + allocated

    def validate_state(data: bytes) -> str | None:
        if (
            len(data) < 128
            or data[4:6] != wire_version.to_bytes(2, "little")
            or data[6] != 2
            or data[7] != 0
        ):
            return "state account header is malformed"
        desired = read_uint(data, 84, 4)
        allocated = desired if wire_version == 1 else read_uint(data, 100, 4)
        if desired == 0 or allocated > desired or len(data) != 128 + allocated:
            return "state account size disagrees with its declared allocation"
        if wire_version == 1 and any(data[100:128]):
            return "state account reserved header bytes are nonzero"
        return None

    def view_size(data: bytes) -> int | None:
        if len(data) < 112:
            return None
        return 128 + read_uint(data, 108, 4)

    def validate_view(data: bytes) -> str | None:
        if len(data) < 128 or data[4:6] != wire_version.to_bytes(2, "little") or data[6] not in {3, 4, 5}:
            return "view account header is malformed"
        length = read_uint(data, 108, 4)
        if length == 0 or len(data) != 128 + length or any(data[120:128]):
            return "view account size or reserved header bytes are invalid"
        return None

    codecs: list[AccountKindCodec] = [
        AccountKindCodec(
            kind=session_kind,
            magic=b"DSS" + version,
            may_have_children=True,
            seeds_from_data=(
                lambda data: (b"dcg-session-v1", data[20:52], data[12:20])
                if wire_version == 1
                else (b"dcg-session-v2", data[22:54], data[14:22])
            ),
            role_from_data=lambda _data: "session",
            state_from_data=session_state,
            dependency_count_from_data=lambda data: read_uint(data, 120, 2) if len(data) >= 122 else None,
            expected_state={"live": "active", "retired": "halted"},
            validate_data=lambda data, size=(672 if wire_version == 1 else 1280): (
                None if len(data) == size else f"session account header has size {len(data)}, expected {size}"
            ),
        )
    ]

    codecs.extend(
        (
            AccountKindCodec(
                kind=f"stateful_stream_v{wire_version}",
                magic=b"DSB" + version,
                parent_offset=8,
                may_have_children=False,
                seeds_from_data=lambda data, seed=b"dcg-input-v" + version: (seed, data[8:40]),
                role_from_data=lambda _data: "input_stream",
                size_from_data=stream_size,
                validate_data=validate_stream,
            ),
            AccountKindCodec(
                kind=f"stateful_state_v{wire_version}",
                magic=b"DSE" + version,
                parent_offset=8,
                may_have_children=False,
                seeds_from_data=lambda data, seed=b"dcg-state-v" + version: (seed, data[8:40], data[78:79]),
                role_from_data=lambda data: f"state_span_{data[78]}" if len(data) > 78 else "state_span_invalid",
                size_from_data=state_size,
                validate_data=validate_state,
            ),
            AccountKindCodec(
                kind=f"stateful_view_v{wire_version}",
                magic=b"DVW" + version,
                parent_offset=8,
                may_have_children=False,
                seeds_from_data=lambda data, seed=b"dcg-view-v" + version: (seed, data[8:40], data[6:7]),
                role_from_data=lambda data: {
                    3: "view_counter",
                    4: "view_total",
                    5: "view_scratch",
                }.get(data[6], f"view_kind_{data[6]}"),
                size_from_data=view_size,
                validate_data=validate_view,
            ),
        )
    )
    return tuple(codecs)


def _validate_seeds(seeds: tuple[bytes, ...]) -> None:
    if (
        not isinstance(seeds, tuple)
        or not seeds
        or len(seeds) > 16
        or any(not isinstance(seed, bytes) or len(seed) > 32 for seed in seeds)
    ):
        raise ValueError("PDA seeds must contain 1 to 16 byte strings of at most 32 bytes")


def _derive(program_id: str, seeds: tuple[bytes, ...]) -> str:
    _validate_seeds(seeds)
    return str(Pubkey.find_program_address(list(seeds), Pubkey.from_string(program_id))[0])


def _identity(record: AccountRecord) -> tuple[object, ...]:
    return (record.address, record.kind, record.role, record.seeds, record.parent, record.expected_size)


def _record_dict(record: AccountRecord) -> dict[str, object]:
    return {
        "address": record.address,
        "kind": record.kind,
        "role": record.role,
        "seeds": record.seeds,
        "parent": record.parent,
        "lifecycle": record.lifecycle,
        "payer": record.payer,
        "rent_lamports": record.rent_lamports,
        "expected_size": record.expected_size,
    }


def _record_json(record: AccountRecord) -> dict[str, object]:
    values = _record_dict(record)
    values["seeds"] = [seed.hex() for seed in record.seeds]
    return values


def _record_from_json(item: object) -> AccountRecord:
    if not isinstance(item, dict):
        raise ValueError("account record must be an object")
    raw_seeds = item["seeds"]
    if not isinstance(raw_seeds, list) or any(not isinstance(seed, str) for seed in raw_seeds):
        raise ValueError("account seeds must be an array of hexadecimal strings")
    return AccountRecord(
        address=item["address"],
        kind=item["kind"],
        role=item["role"],
        seeds=tuple(bytes.fromhex(seed) for seed in raw_seeds),
        parent=item.get("parent"),
        lifecycle=item["lifecycle"],
        payer=item.get("payer"),
        rent_lamports=item.get("rent_lamports"),
        expected_size=item.get("expected_size"),
    )


async def _get_multiple(rpc, addresses: Sequence[str], commitment: Commitment) -> tuple[AccountInfo | None, ...]:
    get_multiple = getattr(rpc, "get_multiple_accounts", None)
    if get_multiple is None:
        raise JournalError("RPC adapter does not provide getMultipleAccounts")
    result: list[AccountInfo | None] = []
    for start in range(0, len(addresses), MAX_MULTIPLE_ACCOUNTS):
        group = tuple(addresses[start : start + MAX_MULTIPLE_ACCOUNTS])
        values = await get_multiple(group, commitment)
        if not isinstance(values, Sequence) or len(values) != len(group):
            raise JournalError("getMultipleAccounts returned a result with the wrong number of accounts")
        result.extend(values)
    return tuple(result)
