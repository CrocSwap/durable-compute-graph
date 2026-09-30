"""Human-readable names and remedies for stateful handler refusal codes."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from dcg.sequencer import ProgramRefused

if TYPE_CHECKING:
    from .instructions import BuiltInstruction


class StatefulRefusal(ProgramRefused):
    """A named custom refusal with an actionable explanation."""

    name = "StatefulRefusal"

    def __init__(self, code: int, detail: str | None = None):
        self.code = code
        info = REFUSAL_TABLE[code]
        self.name, explanation, action = info
        self.explanation = explanation
        self.action = action
        self.account_role: str | None = None
        message = f"DCG {self.name} (Custom({code})): {explanation} Fix: {action}"
        if detail:
            message += f" {detail}"
        super().__init__(message)


class MalformedInstruction(StatefulRefusal):
    pass


class AuthorityRefused(StatefulRefusal):
    pass


class AccountAliasRefused(StatefulRefusal):
    pass


class SessionAccountRefused(StatefulRefusal):
    pass


class LiveSessionRefused(StatefulRefusal):
    pass


class ResourceRefused(StatefulRefusal):
    pass


class DuplicateInputRefused(StatefulRefusal):
    pass


class BackpressureRefused(StatefulRefusal):
    pass


class CursorRefused(StatefulRefusal):
    pass


class InputGapRefused(StatefulRefusal):
    pass


class StateRefused(StatefulRefusal):
    pass


class ViewRefused(StatefulRefusal):
    pass


class RefundRefused(StatefulRefusal):
    pass


class KernelRefused(StatefulRefusal):
    pass


class PhaseCursorRefused(StatefulRefusal):
    pass


class PhaseStateChangedRefused(StatefulRefusal):
    pass


class WritableAccountRefused(SessionAccountRefused):
    """The refusal table's account check found a read-only required role."""

    def __init__(self, code: int, role: str):
        super().__init__(code, detail=f"Account {role!r} must be writable.")
        self.account_role = role
        self.name = "WritableAccountRefused"
        self.args = (
            f"DCG {self.name} (Custom({code})): {self.explanation} "
            f"Fix: {self.action} Account {role!r} must be writable.",
        )


REFUSAL_CLASSES: dict[int, type[StatefulRefusal]] = {
    2301: MalformedInstruction,
    2302: AuthorityRefused,
    2303: AccountAliasRefused,
    2304: SessionAccountRefused,
    2305: LiveSessionRefused,
    2306: ResourceRefused,
    2307: DuplicateInputRefused,
    2308: BackpressureRefused,
    2309: CursorRefused,
    2310: InputGapRefused,
    2311: StateRefused,
    2312: ViewRefused,
    2313: RefundRefused,
    2314: KernelRefused,
    2321: MalformedInstruction,
    2322: AuthorityRefused,
    2323: AccountAliasRefused,
    2324: SessionAccountRefused,
    2325: LiveSessionRefused,
    2326: ResourceRefused,
    2327: DuplicateInputRefused,
    2328: BackpressureRefused,
    2329: CursorRefused,
    2330: InputGapRefused,
    2331: StateRefused,
    2332: ViewRefused,
    2333: RefundRefused,
    2334: KernelRefused,
    2335: PhaseCursorRefused,
    2336: PhaseStateChangedRefused,
}

REFUSAL_TABLE: dict[int, tuple[str, str, str]] = {
    2301: ("MalformedInstruction", "the stateful instruction body is invalid", "use the encoder for the selected wire version"),
    2302: ("AuthorityRefused", "a required signer or configured authority is wrong", "sign with the session authority and use the configured writer role"),
    2303: ("AccountAliasRefused", "two account roles resolve to the same address", "derive each role from its own documented PDA seed"),
    2304: ("SessionAccountRefused", "a session or child account has the wrong owner, link, PDA, or writable flag", "check the derived address, owner and parent link, and mark mutated accounts writable"),
    2305: ("LiveSessionRefused", "the session is still active or has live children", "halt the session and close its journaled child accounts first"),
    2306: ("ResourceRefused", "the kernel, resource, width, capacity, or resource limit does not match", "compare the session manifest and bounded resource declaration with the linked kernel"),
    2307: ("DuplicateInputRefused", "the write-once input slot already contains a command", "write each input cursor once"),
    2308: ("BackpressureRefused", "the input cursor is outside the allowed buffer window", "advance the session or increase capacity before writing farther ahead"),
    2309: ("CursorRefused", "the instruction cursor differs from the session cursor", "read the current cursor and rebuild the instruction with that value"),
    2310: ("InputGapRefused", "one or more commands required by advance are missing", "write every input slot in the requested range before advancing"),
    2311: ("StateRefused", "the state account set or state cursor does not match the kernel schema", "use the session's derived state spans in manifest order"),
    2312: ("ViewRefused", "the view declaration or publication state is invalid", "match the linked view ABI and declared output range"),
    2313: ("RefundRefused", "the refund account is not the session authority or the refund would overflow", "use the authority recorded by the session as the writable refund account"),
    2314: ("KernelRefused", "the statically linked kernel rejected its input or state", "check the kernel's declared input and state shape"),
    2321: ("MalformedInstruction", "the stateful v2 instruction body is invalid", "use the v2 encoder and exact v2 account ordering"),
    2322: ("AuthorityRefused", "a required signer or configured authority is wrong", "sign with the session authority and use the configured writer role"),
    2323: ("AccountAliasRefused", "two account roles resolve to the same address", "derive each role from its own documented v2 PDA seed"),
    2324: ("SessionAccountRefused", "a session or child account has the wrong owner, link, PDA, or writable flag", "check the derived address, owner and parent link, and mark mutated accounts writable"),
    2325: ("LiveSessionRefused", "the session is still active or has live children", "halt the session and close its journaled child accounts first"),
    2326: ("ResourceRefused", "the kernel, resource, width, capacity, or resource limit does not match", "compare the session manifest and bounded resource declaration with the linked kernel"),
    2327: ("DuplicateInputRefused", "the write-once input slot already contains a command", "write each input cursor once"),
    2328: ("BackpressureRefused", "the input cursor is outside the allowed buffer window", "advance the session or increase capacity before writing farther ahead"),
    2329: ("CursorRefused", "the instruction cursor differs from the session cursor", "read the current cursor and rebuild the instruction with that value"),
    2330: ("InputGapRefused", "one or more commands required by advance are missing", "write every input slot in the requested range before advancing"),
    2331: ("StateRefused", "the state account set or state cursor does not match the kernel schema", "use the session's derived state spans in manifest order"),
    2332: ("ViewRefused", "the view declaration or publication state is invalid", "match the linked view ABI and declared output range"),
    2333: ("RefundRefused", "the refund account is not the session authority or the refund would overflow", "use the authority recorded by the session as the writable refund account"),
    2334: ("KernelRefused", "the statically linked kernel rejected its input or state", "check the kernel's declared input and state shape"),
    2335: ("PhaseCursorRefused", "the publication phase cursor is stale", "read the exact next phase cursor and resume there"),
    2336: ("PhaseStateChangedRefused", "state changed while a resumable publication phase was open", "abort that phase and start a fresh publication from the current state cursor"),
}


def _find_custom_code(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value in REFUSAL_CLASSES else None
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() == "custom" and isinstance(child, int) and child in REFUSAL_CLASSES:
                return child
            found = _find_custom_code(child)
            if found is not None:
                return found
    if isinstance(value, (list, tuple)):
        for child in value:
            found = _find_custom_code(child)
            if found is not None:
                return found
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            parsed = None
        found = _find_custom_code(parsed)
        if found is not None:
            return found
        match = re.search(r"Custom\((\d+)\)|custom program error:\s*0x([0-9a-f]+)", value, re.IGNORECASE)
        if match:
            raw = match.group(1) or match.group(2)
            code = int(raw, 16) if match.group(2) else int(raw)
            return code if code in REFUSAL_CLASSES else None
    return None


def explain_refusal(error: ProgramRefused, instruction: BuiltInstruction | None = None) -> ProgramRefused:
    """Translate a sequencer/RPC refusal to a named, actionable DCG exception."""

    code = _find_custom_code(str(error))
    if code is None:
        return error
    if code in {2304, 2324} and instruction is not None:
        readonly = next(
            (role for role, meta in instruction.account_roles if role in instruction.writable_roles and not meta.is_writable),
            None,
        )
        if readonly is not None:
            return WritableAccountRefused(code, readonly)
    return REFUSAL_CLASSES[code](code)
