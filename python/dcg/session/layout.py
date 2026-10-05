"""Versioned PDA and account-layout identities for stateful workloads."""

from __future__ import annotations

from dataclasses import dataclass

from solders.pubkey import Pubkey


@dataclass(frozen=True)
class AccountLayout:
    """The complete seed namespace for one stateful account-wire version."""

    wire_version: int
    session_seed: bytes
    stream_seed: bytes
    state_seed: bytes
    view_seed: bytes
    child_header_bytes: int = 128

    def session(self, program_id: Pubkey, authority: Pubkey, session_id: int) -> Pubkey:
        address, _bump = Pubkey.find_program_address(
            [self.session_seed, bytes(authority), session_id.to_bytes(8, "little")], program_id
        )
        return address

    def stream(self, program_id: Pubkey, session: Pubkey) -> Pubkey:
        return Pubkey.find_program_address([self.stream_seed, bytes(session)], program_id)[0]

    def state(self, program_id: Pubkey, session: Pubkey, index: int) -> Pubkey:
        if not 0 <= index <= 255:
            raise ValueError("state span index must fit in one byte")
        return Pubkey.find_program_address([self.state_seed, bytes(session), bytes([index])], program_id)[0]

    def view(self, program_id: Pubkey, session: Pubkey, role: int) -> Pubkey:
        if not 0 <= role <= 255:
            raise ValueError("view role must fit in one byte")
        return Pubkey.find_program_address([self.view_seed, bytes(session), bytes([role])], program_id)[0]


ACCOUNT_LAYOUTS: dict[int, AccountLayout] = {
    1: AccountLayout(1, b"dcg-session-v1", b"dcg-input-v1", b"dcg-state-v1", b"dcg-view-v1"),
    2: AccountLayout(2, b"dcg-session-v2", b"dcg-input-v2", b"dcg-state-v2", b"dcg-view-v2"),
    3: AccountLayout(3, b"dcg-session-v3", b"dcg-input-v3", b"dcg-state-v3", b"dcg-view-v3"),
}


def account_layout(wire_version: int) -> AccountLayout:
    """Return the frozen account namespace for v1, v2 or v3.

    A future wire version must add its seed set here instead of scattering
    version branches across the session builder.
    """

    try:
        return ACCOUNT_LAYOUTS[wire_version]
    except KeyError as exc:
        raise ValueError(f"unsupported stateful account layout v{wire_version}") from exc


@dataclass(frozen=True)
class SessionAddresses:
    session: Pubkey
    stream: Pubkey
    states: tuple[Pubkey, ...]

    @classmethod
    def derive(
        cls,
        *,
        layout: AccountLayout,
        program_id: Pubkey,
        authority: Pubkey,
        session_id: int,
        state_span_count: int,
    ) -> SessionAddresses:
        session = layout.session(program_id, authority, session_id)
        return cls(
            session=session,
            stream=layout.stream(program_id, session),
            states=tuple(
                layout.state(program_id, session, index) for index in range(state_span_count)
            ),
        )


# --- v3 session features (DCG docs/design/session-reject-and-ring-v1.md) -----

#: OPEN_SESSION ``features`` bits (v3, 180-byte payload).
FEATURE_RING_STREAM = 1
FEATURE_REJECTABLE = 2
FEATURES_KNOWN = FEATURE_RING_STREAM | FEATURE_REJECTABLE
MAX_STREAM_WINDOW = 64
MIN_RING_CAPACITY = 2 * MAX_STREAM_WINDOW
RING_SEQUENCE_CEILING = (1 << 32) - 1 - MAX_STREAM_WINDOW
SLOT_BYTES = 16


def slot_offset(sequence: int, capacity: int, ring: bool) -> int:
    """Byte offset of ``sequence``'s 16-byte slot in a stream account: the
    sequence itself on a linear stream, ``sequence mod capacity`` on a ring."""
    index = sequence % capacity if ring else sequence
    if not ring and not 0 <= sequence < capacity:
        raise ValueError("sequence is outside a linear stream's capacity")
    return 128 + index * SLOT_BYTES


@dataclass(frozen=True)
class SessionInfo:
    """The public fields of a v3 session record (``DSS3``) and its stream."""

    status: str
    capacity: int
    cursor: int
    frontier: int
    features: int
    rejected_count: int
    halt_reason: int
    halt_cursor: int
    last_reject_sequence: int | None = None
    last_reject_code: int | None = None

    @property
    def ring(self) -> bool:
        return bool(self.features & FEATURE_RING_STREAM)

    @property
    def rejectable(self) -> bool:
        return bool(self.features & FEATURE_REJECTABLE)

    @classmethod
    def decode(cls, session: bytes, stream: bytes | None = None) -> SessionInfo:
        if len(session) != 1280 or session[:4] != b"DSS3" or int.from_bytes(session[4:6], "little") != 3:
            raise ValueError("not a v3 session record")
        u32 = lambda d, at: int.from_bytes(d[at:at + 4], "little")  # noqa: E731
        features = session[1273]
        if features & ~FEATURES_KNOWN:
            raise ValueError("unknown session feature bits")
        last_seq = last_code = None
        if stream is not None:
            if len(stream) < 128 or stream[:4] != b"DSB3":
                raise ValueError("not a v3 stream record")
            if features & FEATURE_REJECTABLE and u32(stream, 124):
                last_seq, last_code = u32(stream, 120), u32(stream, 124)
        return cls(
            status={1: "active", 2: "halted"}.get(session[6], "invalid"),
            capacity=u32(session, 10), cursor=u32(session, 112), frontier=u32(session, 116),
            features=features, rejected_count=u32(session, 1274),
            halt_reason=u32(session, 1254), halt_cursor=u32(session, 1258),
            last_reject_sequence=last_seq, last_reject_code=last_code,
        )

    def explain(self) -> str:
        """Plain-language summary, including whether rejection is possible."""
        lines = [
            f"status: {self.status}",
            f"rejectable: {'yes' if self.rejectable else 'no'}"
            + (" (the kernel may consume an input without applying it)" if self.rejectable else ""),
            f"stream: {'ring' if self.ring else 'linear'}, capacity {self.capacity}"
            + (" (keeps only the last lap of inputs; the input chain is the archive)" if self.ring else ""),
            f"cursor {self.cursor}, frontier {self.frontier}",
        ]
        if self.rejectable:
            last = (f"; last at sequence {self.last_reject_sequence}, code {self.last_reject_code}"
                    if self.last_reject_code else "")
            lines.append(f"rejected inputs: {self.rejected_count}{last}")
        if self.status == "halted":
            lines.append(f"halted at cursor {self.halt_cursor}, reason {self.halt_reason:#x}")
        return "\n".join(lines)
