"""Python mirrors of DCG's v3 test counters (``stateful_test.rs``), checked
against the Rust kernels by the kernel kit:

    cargo build -p dcg-kernel-conform
    python -m dcg.kernel_kit check --bin target/debug/dcg-kernel-conform \\
        examples/kernel-kit/counter_mirrors.py

The counter's state is two u64 values (value, running total) in two 8-byte
spans; a 1-byte command adds to the value, then the value to the total, and
refuses on overflow. The rejecting counters add special commands.
"""

from __future__ import annotations

import struct

from dcg.kernel_kit import MODE_CONSENSUS_V3, KernelDecl, KernelRefused, Outcome, StatefulMirror

MASK = (1 << 64) - 1


def counter_decl(name: str, rejects_input: bool = False) -> KernelDecl:
    return KernelDecl(
        name=name,
        max_input_bytes=8,
        max_output_bytes=16,
        max_state_bytes=16,
        max_compute_units=80_000,
        max_operations=8,
        modes=(MODE_CONSENSUS_V3,),
        rejects_input=rejects_input,
    )


def count(command: bytes, state: bytes) -> Outcome:
    if len(command) != 1 or len(state) != 16:
        raise KernelRefused("InvalidInput")
    value, total = struct.unpack("<QQ", state)
    value += command[0]
    total += value
    if value > MASK or total > MASK:
        raise KernelRefused("Refused", "overflow")
    nxt = struct.pack("<QQ", value, total)
    return Outcome(output=nxt, state=nxt)


class Counter(StatefulMirror):
    decl = counter_decl("dcg-counter-v1")
    state_spans = (8, 8)

    def initial_state(self, spans: tuple[int, ...]) -> bytes:
        if spans != (8, 8):
            raise KernelRefused("InvalidInput")
        return bytes(16)

    def transition(self, command: bytes, state: bytes) -> Outcome:
        return count(command, state)


#: Commands of the rejecting counters (``V3_REJECT_*_COMMAND``).
REJECT, REJECT_DIRTY, REJECT_ZERO, HALT_BEFORE, HALT_AFTER = 0xEE, 0xED, 0xEC, 0xEB, 0xEA
REJECT_CODE, HALT_REASON = 7, 0xBEEF


class RejectCounter(Counter):
    """The counter that may reject: ``REJECT`` rejects with code 7,
    ``REJECT_DIRTY`` adds 1 and then rejects (the runtime refuses it),
    ``REJECT_ZERO`` rejects with code 0 (refused), and the halt commands halt
    before or after adding 1."""

    decl = counter_decl("dcg-rejctr-v1", rejects_input=True)
    special_inputs = tuple(bytes([c]) for c in (REJECT, REJECT_DIRTY, REJECT_ZERO, HALT_BEFORE, HALT_AFTER))

    def transition(self, command: bytes, state: bytes) -> Outcome:
        first = command[0] if command else None
        if first == REJECT:
            return Outcome(b"", state, "reject", REJECT_CODE)
        if first == REJECT_ZERO:
            return Outcome(b"", state, "reject", 0)
        if first == REJECT_DIRTY:
            return Outcome(b"", count(b"\x01", state).state, "reject", REJECT_CODE)
        if first == HALT_BEFORE:
            return Outcome(b"", state, "halt_before", HALT_REASON)
        if first == HALT_AFTER:
            after = count(b"\x01", state)
            return Outcome(after.output, after.state, "halt_after", HALT_REASON)
        return count(command, state)


class UndeclaredRejectCounter(RejectCounter):
    """The same transitions without the capability: every reject is refused."""

    decl = counter_decl("dcg-undrej-v1")


class LaneCounter(Counter):
    decl = counter_decl("dcg-lanectr-v1")


COUNTER = Counter()
REJECT_COUNTER = RejectCounter()
UNDECLARED_REJECT = UndeclaredRejectCounter()
LANE_COUNTER = LaneCounter()
