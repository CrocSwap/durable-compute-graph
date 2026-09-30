"""Typed stateful session client backed by DCG's existing transaction sequencer."""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from solders.hash import Hash
from solders.message import Message
from solders.pubkey import Pubkey

from dcg.sequencer import (
    Backoff,
    Commitment,
    EndpointLimits,
    JournalStore,
    PostconditionResult,
    ProgramRefused,
    RetryPolicy,
    RpcConfig,
    Sequencer,
    SequencerConfig,
    SolanaRpcEndpoint,
    TransactionPlan,
    TransactionStep,
)

from .errors import explain_refusal
from .instructions import (
    BuiltInstruction,
    KIND_SESSION,
    KIND_STATE,
    KIND_STREAM,
    advance as encode_advance,
    close_child,
    close_session as encode_close_session,
    create_state,
    create_stream,
    grow_state,
    halt_session,
    initialize_state,
    open_session,
    write_input as encode_write_input,
)
from .journal import AccountInventory, AccountRecord
from .layout import SessionAddresses, account_layout
from .manifest import KernelRef
from .signers import SessionSigners


DEFAULT_PROGRAM_ID = Pubkey.from_bytes(bytes([0xD9]) * 32)
CHILD_HEADER_BYTES = 128


def _account_fingerprint(info) -> str | None:
    if info is None:
        return None
    digest = hashlib.sha256()
    digest.update(info.owner.encode("ascii"))
    digest.update(info.lamports.to_bytes(8, "little"))
    digest.update(bytes([info.executable]))
    digest.update(info.data)
    return digest.hexdigest()


@dataclass(frozen=True)
class CounterState:
    value: int
    total: int


@dataclass(frozen=True)
class CloseReceipt:
    rent_lamports: int
    accounts_closed: tuple[str, ...]


class SequencedInstructionTransport:
    """Adapt one encoded instruction at a time to the durable sequencer."""

    def __init__(
        self,
        *,
        endpoint: SolanaRpcEndpoint,
        signers: SessionSigners,
        journal_dir: str | os.PathLike[str],
        per_step_time_cap_seconds: float = 90.0,
    ):
        self.endpoint = endpoint
        self.signers = signers
        self.journal_dir = Path(journal_dir)
        self.per_step_time_cap_seconds = per_step_time_cap_seconds
        self._operation = 0
        self._genesis_hash: str | None = None
        self._sequencer_config = SequencerConfig(
            endpoint_limits={endpoint.endpoint_id: EndpointLimits(20, 1)},
            max_batch_size=1,
            max_packet_bytes=1232,
            blockhash_lifetime_seconds=30,
            per_step_time_cap_seconds=per_step_time_cap_seconds,
            confirmation_poll_seconds=0.15,
            backoff=Backoff(initial_seconds=0.1, maximum_seconds=1),
        )

    async def send(
        self,
        built: BuiltInstruction,
        *,
        program_id: Pubkey,
        expected_accounts: Iterable[tuple[Pubkey, bool]],
    ) -> None:
        if self._genesis_hash is None:
            self._genesis_hash = await self.endpoint.get_genesis_hash()
        expected = tuple(expected_accounts)
        before: dict[str, str | None] = {}
        for address, _should_exist in expected:
            info = await self.endpoint.get_account_info(str(address), Commitment.CONFIRMED)
            before[str(address)] = _account_fingerprint(info)
        ix = built.instruction
        payer = self.signers.payer.pubkey()
        operation_signers = self.signers.for_roles({"payer", *built.signer_roles})
        intent_digest = hashlib.sha256(
            bytes(program_id)
            + built.data
            + b"".join(
                bytes(meta.pubkey) + bytes([meta.is_signer, meta.is_writable])
                for _role, meta in built.account_roles
            )
        ).hexdigest()
        step_id = f"{self._operation:04d}-{built.name}-{secrets.token_hex(4)}"
        self._operation += 1
        journal_path = self.journal_dir / f"{step_id}.jsonl"

        def build_message(lease):
            return bytes(Message.new_with_blockhash([ix], payer, Hash.from_string(lease.blockhash)))

        async def postcondition(endpoint):
            digest = hashlib.sha256()
            changed = False
            for address, should_exist in expected:
                info = await endpoint.get_account_info(str(address), Commitment.CONFIRMED)
                if (info is not None) != should_exist:
                    return PostconditionResult(False)
                if info is not None:
                    if info.owner != str(program_id):
                        return PostconditionResult(False)
                    fingerprint = _account_fingerprint(info)
                    changed = changed or fingerprint != before[str(address)]
                    digest.update(bytes(address))
                    digest.update(bytes.fromhex(fingerprint))
                else:
                    changed = changed or before[str(address)] is not None
                    digest.update(bytes(address))
                    digest.update(b"absent")
            return PostconditionResult(changed, digest.hexdigest() if changed else None)

        step = TransactionStep(
            step_id=step_id,
            dependencies=(),
            endpoint_id=self.endpoint.endpoint_id,
            compute_class=f"dcg-stateful-tag-{built.tag}",
            compute_unit_limit=1_400_000,
            intent_digest=intent_digest,
            recovery_policy_digest=f"stateful-session:{built.name}:account-delta-postcondition-v1",
            build_message=build_message,
            postcondition=postcondition,
            max_packet_bytes=1232,
            write_locks=tuple(
                sorted(str(meta.pubkey) for _role, meta in built.account_roles if meta.is_writable)
            ),
            retry_policy=RetryPolicy.SAME_BYTES,
        )
        plan = TransactionPlan(
            genesis_hash=self._genesis_hash,
            program_id=str(program_id),
            destination_accounts=tuple(sorted({str(meta.pubkey) for _role, meta in built.account_roles})),
            signer_public_key=operation_signers.public_key,
            steps=(step,),
        )
        try:
            sequencer = Sequencer(
                endpoints={self.endpoint.endpoint_id: self.endpoint},
                signer=operation_signers,
                config=self._sequencer_config,
            )
            await sequencer.submit(plan, JournalStore(journal_path))
        except ProgramRefused as error:
            translated = explain_refusal(error, built)
            if translated is error:
                raise
            raise translated from error


class Session:
    """A typed stateful workload with derived accounts and journaled cleanup."""

    def __init__(
        self,
        *,
        kernel: KernelRef,
        transport: SequencedInstructionTransport,
        signers: SessionSigners,
        program_id: Pubkey = DEFAULT_PROGRAM_ID,
        session_id: int | None = None,
        journal_path: str | os.PathLike[str] = "/private/tmp/dcg-session-accounts.json",
        wire_version: int | None = None,
        input_capacity: int = 8,
        max_steps: int = 1,
    ):
        self.kernel = kernel
        self.transport = transport
        self.signers = signers
        self.program_id = program_id
        self.session_id = secrets.randbits(64) if session_id is None else session_id
        if not 0 <= self.session_id < 1 << 64:
            raise ValueError("session_id must fit in an unsigned 64-bit integer")
        self.wire_version = kernel.mode_version if wire_version is None else wire_version
        if self.wire_version not in {1, 2}:
            raise ValueError("stateful session wire_version must be 1 or 2")
        if kernel.mode_version != self.wire_version:
            raise ValueError("kernel mode version must match the selected stateful wire version")
        if not 2 <= input_capacity <= (64 if self.wire_version == 1 else ((10 * 1024 * 1024 - 128) // 16)):
            raise ValueError("input_capacity is outside the selected wire-version bounds")
        if not 1 <= max_steps <= 8:
            raise ValueError("max_steps must be between 1 and 8")
        if sum(kernel.state_span_lengths) > 10_000_000:
            raise ValueError("state spans exceed the stateful 10,000,000-byte aggregate bound")
        self.input_capacity = input_capacity
        self.max_steps = max_steps
        self.layout = account_layout(self.wire_version)
        self.addresses = SessionAddresses.derive(
            layout=self.layout,
            program_id=program_id,
            authority=signers.authority.pubkey(),
            session_id=self.session_id,
            state_span_count=len(kernel.state_span_lengths),
        )
        self.inventory = AccountInventory(
            journal_path,
            session_id=self.session_id,
            program_id=str(program_id),
            authority=signers.authority_public_key,
        )
        self.inventory.plan(
            (
                (str(self.addresses.session), "session", None),
                (str(self.addresses.stream), "input_stream", str(self.addresses.session)),
                *(
                    (str(address), f"state_span_{index}", str(self.addresses.session))
                    for index, address in enumerate(self.addresses.states)
                ),
            )
        )
        self.cursor = 0
        self._write_cursor = 0
        self._opened = False
        self._closed = False

    @classmethod
    def from_environment(
        cls,
        kernel: KernelRef,
        *,
        session_id: int | None = None,
        wire_version: int | None = None,
        input_capacity: int = 8,
        max_steps: int = 1,
    ) -> Session:
        payer_path = os.environ.get("DCG_PAYER_KEYPAIR")
        authority_path = os.environ.get("DCG_AUTHORITY_KEYPAIR")
        if not payer_path or not authority_path:
            raise ValueError("set DCG_PAYER_KEYPAIR and DCG_AUTHORITY_KEYPAIR to local keypair JSON files")
        signers = SessionSigners.from_files(
            payer=payer_path,
            authority=authority_path,
            writer=os.environ.get("DCG_WRITER_KEYPAIR"),
        )
        program_id = Pubkey.from_string(os.environ.get("DCG_PROGRAM_ID", str(DEFAULT_PROGRAM_ID)))
        journal_path = Path(
            os.environ.get(
                "DCG_SESSION_JOURNAL",
                f"/private/tmp/dcg-session-{session_id if session_id is not None else secrets.token_hex(6)}.json",
            )
        )
        endpoint = SolanaRpcEndpoint(
            os.environ.get("DCG_ENDPOINT_ID", "dcg-local-validator"),
            os.environ.get("DCG_RPC_URL", "http://127.0.0.1:8899"),
            config=RpcConfig(
                timeout_seconds=float(os.environ.get("DCG_RPC_TIMEOUT", "10")),
                requests_per_second=float(os.environ.get("DCG_RPC_RATE", "20")),
                max_in_flight=1,
                commitment=Commitment.CONFIRMED,
            ),
        )
        transport = SequencedInstructionTransport(
            endpoint=endpoint,
            signers=signers,
            journal_dir=os.environ.get("DCG_SEQUENCER_JOURNAL_DIR", f"{journal_path}.transactions"),
        )
        return cls(
            kernel=kernel,
            transport=transport,
            signers=signers,
            program_id=program_id,
            session_id=session_id,
            journal_path=journal_path,
            wire_version=wire_version,
            input_capacity=input_capacity,
            max_steps=max_steps,
        )

    async def open(self) -> Session:
        if self._opened:
            return self
        if self.signers.payer.pubkey() == self.signers.authority.pubkey():
            raise ValueError("payer and session authority must be distinct signer roles")
        await self._send(
            open_session(
                program_id=self.program_id,
                addresses=self.addresses,
                kernel=self.kernel,
                payer=self.signers.payer.pubkey(),
                authority=self.signers.authority.pubkey(),
                session_id=self.session_id,
                wire_version=self.wire_version,
                input_capacity=self.input_capacity,
                max_steps=self.max_steps,
                writer=self.signers.writer.pubkey(),
            ),
            expected=((self.addresses.session, True),),
        )
        self.inventory.mark_created(str(self.addresses.session))
        await self._send(
            create_stream(
                program_id=self.program_id,
                addresses=self.addresses,
                payer=self.signers.payer.pubkey(),
                wire_version=self.wire_version,
            ),
            expected=((self.addresses.stream, True),),
        )
        self.inventory.mark_created(str(self.addresses.stream))
        await self._send(
            create_state(
                program_id=self.program_id,
                addresses=self.addresses,
                kernel=self.kernel,
                payer=self.signers.payer.pubkey(),
                wire_version=self.wire_version,
            ),
            expected=tuple((address, True) for address in self.addresses.states),
        )
        for address in self.addresses.states:
            self.inventory.mark_created(str(address))
        if self.wire_version == 2:
            for index, length in enumerate(self.kernel.state_span_lengths):
                for _offset in range(min(length, 8192), length, 8192):
                    await self._send(
                        grow_state(
                            program_id=self.program_id,
                            addresses=self.addresses,
                            payer=self.signers.payer.pubkey(),
                            index=index,
                        ),
                        expected=((self.addresses.states[index], True),),
                    )
            await self._send(
                initialize_state(
                    program_id=self.program_id,
                    addresses=self.addresses,
                    authority=self.signers.authority.pubkey(),
                ),
                expected=tuple((address, True) for address in self.addresses.states),
            )
        self._opened = True
        return self

    async def write_input(self, value: int | bytes) -> int:
        self._require_open()
        if self._write_cursor >= self.input_capacity:
            raise ValueError("input stream is full; choose a larger input_capacity before opening")
        if self.kernel.input_codec == "u8":
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
                raise ValueError("this kernel accepts an integer input from 0 through 255")
            command = bytes([value])
        else:
            if not isinstance(value, bytes) or len(value) != self.kernel.input_width:
                raise ValueError(f"input must be exactly {self.kernel.input_width} bytes")
            command = value
        await self._send(
            encode_write_input(
                program_id=self.program_id,
                addresses=self.addresses,
                writer=self.signers.writer.pubkey(),
                sequence=self._write_cursor,
                value=command,
                wire_version=self.wire_version,
            ),
            expected=((self.addresses.stream, True),),
        )
        written_sequence = self._write_cursor
        self._write_cursor += 1
        return written_sequence

    async def advance(self, n: int) -> int:
        self._require_open()
        if not 1 <= n <= self.max_steps:
            raise ValueError(f"advance step count must be between 1 and {self.max_steps}")
        if self.cursor + n > self.input_capacity:
            raise ValueError("advance would move beyond the declared input-stream capacity")
        if self._write_cursor < self.cursor + n:
            raise ValueError(f"write {self.cursor + n - self._write_cursor} more input value(s) before advancing")
        start = self.cursor
        await self._send(
            encode_advance(
                program_id=self.program_id,
                addresses=self.addresses,
                authority=self.signers.authority.pubkey(),
                cursor=self.cursor,
                steps=n,
                wire_version=self.wire_version,
            ),
            expected=((self.addresses.session, True), (self.addresses.stream, True))
            + tuple((address, True) for address in self.addresses.states),
        )
        self.cursor += n
        return start

    async def read_state(self) -> CounterState | bytes:
        self._require_open()
        chunks = []
        for address in self.addresses.states:
            info = await self.transport.endpoint.get_account_info(str(address), Commitment.CONFIRMED)
            if info is None:
                raise RuntimeError(f"state span {address} does not exist")
            if info.owner != str(self.program_id) or len(info.data) < CHILD_HEADER_BYTES:
                raise RuntimeError(f"state span {address} has the wrong owner or truncated header")
            chunks.append(info.data[CHILD_HEADER_BYTES:])
        state_bytes = b"".join(chunks)
        if self.kernel.state_codec == "counter-u64-pair":
            if len(state_bytes) != 16:
                raise RuntimeError("counter state must contain exactly two little-endian u64 values")
            return CounterState(
                int.from_bytes(state_bytes[:8], "little"),
                int.from_bytes(state_bytes[8:16], "little"),
            )
        return state_bytes

    async def close(self) -> CloseReceipt:
        if self._closed:
            return CloseReceipt(0, ())
        self._validate_inventory()
        created = self.inventory.created()
        session_record = next((item for item in created if item.role == "session"), None)
        if session_record is None:
            raise RuntimeError("session account is not recorded as created; refusing to close anything")

        session_info = await self.transport.endpoint.get_account_info(
            str(self.addresses.session), Commitment.CONFIRMED
        )
        closed: list[str] = []
        refunded = 0
        if session_info is not None:
            status = session_info.data[6] if len(session_info.data) > 6 else None
            if status == 1:
                await self._send(
                    halt_session(
                        program_id=self.program_id,
                        addresses=self.addresses,
                        authority=self.signers.authority.pubkey(),
                        cursor=self.cursor,
                        wire_version=self.wire_version,
                    ),
                    expected=((self.addresses.session, True),),
                )

        child_records = [item for item in created if item.role != "session"]
        for item in reversed(child_records):
            address = Pubkey.from_string(item.address)
            info = await self.transport.endpoint.get_account_info(item.address, Commitment.CONFIRMED)
            if info is None:
                self.inventory.mark_closed(item.address)
                continue
            refunded += info.lamports
            kind = KIND_STREAM if item.role == "input_stream" else KIND_STATE
            await self._send(
                close_child(
                    program_id=self.program_id,
                    addresses=self.addresses,
                    authority=self.signers.authority.pubkey(),
                    target=address,
                    kind=kind,
                    role=item.role,
                    wire_version=self.wire_version,
                ),
                expected=((address, False),),
            )
            self.inventory.mark_closed(item.address)
            closed.append(item.address)

        current_session = await self.transport.endpoint.get_account_info(
            str(self.addresses.session), Commitment.CONFIRMED
        )
        if current_session is not None:
            refunded += current_session.lamports
            await self._send(
                encode_close_session(
                    program_id=self.program_id,
                    addresses=self.addresses,
                    authority=self.signers.authority.pubkey(),
                    wire_version=self.wire_version,
                ),
                expected=((self.addresses.session, False),),
            )
            self.inventory.mark_closed(session_record.address)
            closed.append(session_record.address)
        self._closed = True
        return CloseReceipt(refunded, tuple(closed))

    async def aclose(self) -> None:
        await self.transport.endpoint.aclose()

    async def _send(self, built: BuiltInstruction, *, expected: Iterable[tuple[Pubkey, bool]]) -> None:
        try:
            await self.transport.send(
                built,
                program_id=self.program_id,
                expected_accounts=expected,
            )
        except ProgramRefused as error:
            translated = explain_refusal(error, built)
            if translated is error:
                raise
            raise translated from error

    def _validate_inventory(self) -> None:
        expected = {
            str(self.addresses.session): ("session", None),
            str(self.addresses.stream): ("input_stream", str(self.addresses.session)),
            **{
                str(address): (f"state_span_{index}", str(self.addresses.session))
                for index, address in enumerate(self.addresses.states)
            },
        }
        for record in self.inventory.accounts:
            if expected.get(record.address) != (record.role, record.parent):
                raise RuntimeError("account journal lists an address or parent outside this derived session")
        if set(item.address for item in self.inventory.accounts) != set(expected):
            raise RuntimeError("account journal is missing one or more derived session accounts")

    def _require_open(self) -> None:
        if not self._opened or self._closed:
            raise RuntimeError("call open() before session operations and do not use a closed session")
