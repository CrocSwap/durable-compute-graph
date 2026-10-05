"""The Python mirror of `dcg-tally-v1` (src/lib.rs), checked against the
Rust kernel with the kernel kit:

    cargo build --features conform,no-entrypoint --bin tally-conform
    python -m dcg.kernel_kit check --bin target/debug/tally-conform mirror.py
"""

from __future__ import annotations

import struct

from dcg.kernel_kit import MODE_CONSENSUS_V3, KernelDecl, KernelRefused, Outcome, StatefulMirror

REJECT_ZERO = 1
MASK = (1 << 64) - 1


class Tally(StatefulMirror):
    decl = KernelDecl(
        name="dcg-tally-v1",
        max_input_bytes=1,
        max_output_bytes=16,
        max_state_bytes=16,
        max_compute_units=50_000,
        max_operations=8,
        modes=(MODE_CONSENSUS_V3,),
        rejects_input=True,
    )
    state_spans = (16,)

    def initial_state(self, spans: tuple[int, ...]) -> bytes:
        if sum(spans) != 16:
            raise KernelRefused("StateTooLarge")
        return bytes(16)

    def transition(self, command: bytes, state: bytes) -> Outcome:
        if len(command) != 1:
            raise KernelRefused("InvalidInput")
        if command[0] == 0:
            return Outcome(b"", state, "reject", REJECT_ZERO)
        count, total = struct.unpack("<QQ", state)
        count, total = count + 1, total + command[0]
        if count > MASK or total > MASK:
            raise KernelRefused("Refused", "overflow")
        nxt = struct.pack("<QQ", count, total)
        return Outcome(nxt, nxt)


TALLY = Tally()
