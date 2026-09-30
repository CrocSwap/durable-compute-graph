"""One canonical encoder for stateful v1/v2 Solana instructions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey

from .layout import SessionAddresses
from .manifest import KernelRef


SYSTEM_PROGRAM_ID = Pubkey.default()
TAG_OPEN_SESSION = 230
TAG_CREATE_STREAM = 231
TAG_CREATE_STATE = 232
TAG_WRITE_INPUT = 234
TAG_ADVANCE = 235
TAG_HALT_SESSION = 237
TAG_CLOSE_ACCOUNT = 238
KIND_SESSION = 0
KIND_STREAM = 1
KIND_STATE = 2
STATE_OP_INITIALIZE = 0xFF
STATE_OP_GROW = 0xFE
POLICY_APPEND = 1


@dataclass(frozen=True)
class BuiltInstruction:
    """An encoded handler call plus role names used for diagnostics/policy."""

    name: str
    tag: int
    instruction: Instruction
    account_roles: tuple[tuple[str, AccountMeta], ...]
    signer_roles: frozenset[str]
    writable_roles: frozenset[str]

    @property
    def data(self) -> bytes:
        return bytes(self.instruction.data)

    @property
    def account_keys(self) -> tuple[Pubkey, ...]:
        return tuple(meta.pubkey for _role, meta in self.account_roles)


def _build(
    *,
    program_id: Pubkey,
    name: str,
    tag: int,
    body: bytes,
    accounts: Iterable[tuple[str, Pubkey, bool, bool]],
    required_writable_roles: frozenset[str] | None = None,
) -> BuiltInstruction:
    roles = tuple(
        (role, AccountMeta(pubkey, is_signer, is_writable))
        for role, pubkey, is_signer, is_writable in accounts
    )
    return BuiltInstruction(
        name=name,
        tag=tag,
        instruction=Instruction(program_id, bytes([tag]) + body, [meta for _role, meta in roles]),
        account_roles=roles,
        signer_roles=frozenset(role for role, meta in roles if meta.is_signer),
        writable_roles=required_writable_roles
        if required_writable_roles is not None
        else frozenset(role for role, meta in roles if meta.is_writable),
    )


def open_session(
    *,
    program_id: Pubkey,
    addresses: SessionAddresses,
    kernel: KernelRef,
    payer: Pubkey,
    authority: Pubkey,
    session_id: int,
    wire_version: int,
    input_capacity: int = 8,
    max_steps: int = 1,
    writer: Pubkey | None = None,
) -> BuiltInstruction:
    if not 0 <= session_id < 1 << 64:
        raise ValueError("session_id must fit in an unsigned 64-bit integer")
    if not 2 <= input_capacity <= (64 if wire_version == 1 else ((10 * 1024 * 1024 - 128) // 16)):
        raise ValueError("input_capacity is outside the selected wire-version bounds")
    if not 1 <= max_steps <= 8:
        raise ValueError("max_steps must be between 1 and 8")
    requested_writer = writer or authority
    body = bytearray([wire_version])
    body.extend(session_id.to_bytes(8, "little"))
    body.extend((POLICY_APPEND, kernel.input_width))
    if wire_version == 1:
        if input_capacity > 0xFFFF:
            raise ValueError("v1 input_capacity must fit in u16")
        body.extend(input_capacity.to_bytes(2, "little"))
        body.append(max_steps)
        body.extend(kernel.id)
        body.extend(kernel.semantic_version.to_bytes(2, "little"))
        body.extend(kernel.abi_version.to_bytes(2, "little"))
        body.extend(kernel.mode_id.to_bytes(4, "little"))
        body.extend(kernel.mode_version.to_bytes(2, "little"))
        body.extend(kernel.stream_root)
        body.extend(bytes(requested_writer))
    elif wire_version == 2:
        body.extend(input_capacity.to_bytes(4, "little"))
        body.append(max_steps)
        body.extend(kernel.id)
        body.extend(kernel.semantic_version.to_bytes(2, "little"))
        body.extend(kernel.abi_version.to_bytes(2, "little"))
        body.extend(kernel.mode_id.to_bytes(4, "little"))
        body.extend(kernel.mode_version.to_bytes(2, "little"))
        body.extend(kernel.stream_root)
        body.extend(bytes(requested_writer))
        body.extend(bytes(32))  # no optional resource account
        body.extend(bytes(6))   # no resource schema
        body.extend(bytes(32))  # no resource commitment
    else:
        raise ValueError(f"unsupported stateful wire version {wire_version}")
    return _build(
        program_id=program_id,
        name="open_session",
        tag=TAG_OPEN_SESSION,
        body=bytes(body),
        accounts=(
            ("payer", payer, True, True),
            ("authority", authority, True, False),
            ("session", addresses.session, False, True),
            ("system_program", SYSTEM_PROGRAM_ID, False, False),
        ),
    )


def create_stream(
    *, program_id: Pubkey, addresses: SessionAddresses, payer: Pubkey, wire_version: int
) -> BuiltInstruction:
    body = bytes([wire_version]) if wire_version == 1 else bytes([wire_version, 0])
    return _build(
        program_id=program_id,
        name="create_stream",
        tag=TAG_CREATE_STREAM,
        body=body,
        accounts=(
            ("payer", payer, True, True),
            ("session", addresses.session, False, True),
            ("input_stream", addresses.stream, False, True),
            ("system_program", SYSTEM_PROGRAM_ID, False, False),
        ),
    )


def create_state(
    *, program_id: Pubkey, addresses: SessionAddresses, kernel: KernelRef, payer: Pubkey, wire_version: int
) -> BuiltInstruction:
    body = bytearray([wire_version, len(kernel.state_span_lengths)])
    for length in kernel.state_span_lengths:
        body.extend(length.to_bytes(4, "little"))
    return _build(
        program_id=program_id,
        name="create_state",
        tag=TAG_CREATE_STATE,
        body=bytes(body),
        accounts=(
            ("payer", payer, True, True),
            ("session", addresses.session, False, True),
            *((f"state_span_{index}", address, False, True) for index, address in enumerate(addresses.states)),
            ("system_program", SYSTEM_PROGRAM_ID, False, False),
        ),
    )


def initialize_state(
    *, program_id: Pubkey, addresses: SessionAddresses, authority: Pubkey
) -> BuiltInstruction:
    """Initialize the v2 state spans after their bounded account allocation."""

    return _build(
        program_id=program_id,
        name="initialize_state",
        tag=TAG_CREATE_STATE,
        body=bytes([2, STATE_OP_INITIALIZE]),
        accounts=(
            ("authority", authority, True, False),
            ("session", addresses.session, False, True),
            *((f"state_span_{index}", address, False, True) for index, address in enumerate(addresses.states)),
        ),
    )


def grow_state(
    *, program_id: Pubkey, addresses: SessionAddresses, payer: Pubkey, index: int
) -> BuiltInstruction:
    """Grow one v2 span by the handler's fixed maximum of 8,192 bytes."""

    if not 0 <= index < len(addresses.states):
        raise ValueError("state span index is outside this session")
    return _build(
        program_id=program_id,
        name=f"grow_state_{index}",
        tag=TAG_CREATE_STATE,
        body=bytes([2, STATE_OP_GROW, index]),
        accounts=(
            ("payer", payer, True, True),
            ("session", addresses.session, False, True),
            (f"state_span_{index}", addresses.states[index], False, True),
            ("system_program", SYSTEM_PROGRAM_ID, False, False),
        ),
    )


def write_input(
    *, program_id: Pubkey, addresses: SessionAddresses, writer: Pubkey, sequence: int, value: bytes, wire_version: int
) -> BuiltInstruction:
    if not 0 <= sequence < 1 << 32 or not 1 <= len(value) <= 8:
        raise ValueError("input sequence or command width is outside the stateful bounds")
    body = bytes([wire_version]) + sequence.to_bytes(4, "little") + bytes([len(value)]) + value
    return _build(
        program_id=program_id,
        name="write_input",
        tag=TAG_WRITE_INPUT,
        body=body,
        accounts=(
            ("writer", writer, True, False),
            ("session", addresses.session, False, True),
            ("input_stream", addresses.stream, False, True),
        ),
    )


def advance(
    *,
    program_id: Pubkey,
    addresses: SessionAddresses,
    authority: Pubkey,
    cursor: int,
    steps: int,
    wire_version: int,
    input_stream_writable: bool = True,
) -> BuiltInstruction:
    if not 0 <= cursor < 1 << 32 or not 1 <= steps <= 8:
        raise ValueError("advance cursor or step count is outside the stateful bounds")
    body = bytes([wire_version]) + cursor.to_bytes(4, "little") + bytes([steps])
    return _build(
        program_id=program_id,
        name="advance",
        tag=TAG_ADVANCE,
        body=body,
        accounts=(
            ("authority", authority, True, False),
            ("session", addresses.session, False, True),
            ("input_stream", addresses.stream, False, input_stream_writable),
            *((f"state_span_{index}", address, False, True) for index, address in enumerate(addresses.states)),
        ),
        required_writable_roles=frozenset(
            {"session", "input_stream", *(f"state_span_{index}" for index in range(len(addresses.states)))}
        ),
    )


def halt_session(
    *, program_id: Pubkey, addresses: SessionAddresses, authority: Pubkey, cursor: int, wire_version: int
) -> BuiltInstruction:
    if not 0 <= cursor < 1 << 32:
        raise ValueError("halt cursor must fit in an unsigned 32-bit integer")
    return _build(
        program_id=program_id,
        name="halt_session",
        tag=TAG_HALT_SESSION,
        body=bytes([wire_version]) + cursor.to_bytes(4, "little"),
        accounts=(("authority", authority, True, False), ("session", addresses.session, False, True)),
    )


def close_child(
    *, program_id: Pubkey, addresses: SessionAddresses, authority: Pubkey, target: Pubkey, kind: int, role: str, wire_version: int
) -> BuiltInstruction:
    return _build(
        program_id=program_id,
        name=f"close_{role}",
        tag=TAG_CLOSE_ACCOUNT,
        body=bytes([wire_version, kind]),
        accounts=(
            ("session", addresses.session, False, True),
            (role, target, False, True),
            ("refund", authority, False, True),
        ),
    )


def close_session(
    *, program_id: Pubkey, addresses: SessionAddresses, authority: Pubkey, wire_version: int
) -> BuiltInstruction:
    return _build(
        program_id=program_id,
        name="close_session",
        tag=TAG_CLOSE_ACCOUNT,
        body=bytes([wire_version, KIND_SESSION]),
        accounts=(("session", addresses.session, False, True), ("refund", authority, False, True)),
    )
