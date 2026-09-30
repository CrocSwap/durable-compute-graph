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
}


def account_layout(wire_version: int) -> AccountLayout:
    """Return the frozen account namespace for v1 or v2.

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
