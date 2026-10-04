"""A toy LX1 machine with the shape of a model document (test-only).

Each position p:
- `start`: a = 3·h + p + 1 into position scratch;
- a decomposed step over the log of earlier positions, in windows of W
  entries and two phases, as attention's two global reductions:
  - phase 1 (max): m = max(m, log[i]) over the window;
  - phase 2 (sum): s = s + (m - log[i]) over the window;
- `finish`: h' = (a + s - m) mod 2^31; append log[p] = h'; clear the
  scratch slots.

Carried slots: h, then log[0..P). Scratch slots: a, m, s. All values are i64
little-endian.

With `weights=True` (design §13), `start` also reads two template constant
chunks, in order: chunk `p mod 4` of constant 0 (16-byte chunks) and chunk
`p mod 3` of constant 2 (8-byte chunks; id 1 is unused), and adds the first
i64 of the first minus the first i64 of the second.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .lx import ConstantTable, Transition

MOD = 1 << 31


def enc(v: int) -> bytes:
    return struct.pack("<q", v)


def dec(b: bytes | None) -> int | None:
    return None if b is None else struct.unpack("<q", b)[0]


@dataclass
class ToyMachine:
    positions_count: int = 9
    window: int = 3
    h0: int = 7
    weights: bool = False
    by_value: bool = False  # the start's constant-0 chunk is chosen by h (data-dependent read)

    WEIGHTS0 = (5, -3, 11, 2, 7, 0, -9, 4)
    WEIGHTS2 = (13, 1, 6)

    def constant_table(self) -> ConstantTable | None:
        if not self.weights:
            return None
        pack = lambda xs: b"".join(enc(x) for x in xs)  # noqa: E731
        return ConstantTable({0: pack(self.WEIGHTS0), 2: pack(self.WEIGHTS2)}, {0: 4, 2: 3})

    # Slot layout.
    H = 0

    @property
    def log0(self) -> int:
        return 1

    @property
    def A(self) -> int:
        return 1 + self.positions_count

    @property
    def M(self) -> int:
        return self.A + 1

    @property
    def S(self) -> int:
        return self.A + 2

    @property
    def slot_count(self) -> int:
        return self.A + 3

    def positions(self) -> int:
        return self.positions_count

    def windows(self, p: int) -> int:
        return -(-p // self.window)  # ceil(p / W) windows over log[0..p)

    def transitions_in(self, p: int) -> int:
        return 2 + 2 * self.windows(p)

    def initial_state(self) -> dict[int, bytes]:
        return {self.H: enc(self.h0)}

    def output_slots(self) -> tuple[int, ...]:
        return (self.H,)

    def transition(self, p: int, i: int) -> Transition:
        from .lx import Schedule  # noqa: F401  (coordinates come from the schedule below)
        base = sum(self.transitions_in(q) for q in range(p))
        c = base + i
        nw = self.windows(p)
        if i == 0:
            if self.weights:
                def start_w(r, chunks, p=p):
                    w = dec(chunks[0][:8]) - dec(chunks[1][:8])
                    return {self.A: enc((3 * dec(r[self.H]) + p + 1 + w) % MOD)}
                if self.by_value:
                    def reads(r, p=p):
                        return ((0, dec(r[self.H]) % 4), (2, p % 3))
                    return Transition(c, f"p{p}.start", (self.H,), (self.A,), start_w, reads)
                return Transition(c, f"p{p}.start", (self.H,), (self.A,), start_w,
                                  ((0, p % 4), (2, p % 3)))

            def start(r, p=p):
                return {self.A: enc((3 * dec(r[self.H]) + p + 1) % MOD)}
            return Transition(c, f"p{p}.start", (self.H,), (self.A,), start)
        if 1 <= i <= 2 * nw:
            phase, w = (1, i - 1) if i <= nw else (2, i - 1 - nw)
            lo, hi = w * self.window, min(p, (w + 1) * self.window)
            logs = tuple(self.log0 + j for j in range(lo, hi))
            if phase == 1:
                def maxw(r, logs=logs):
                    m = dec(r[self.M])
                    for s in logs:
                        v = dec(r[s])
                        m = v if m is None else max(m, v)
                    return {self.M: enc(m)}
                return Transition(c, f"p{p}.max{w}", (self.M,) + logs, (self.M,), maxw)

            def sumw(r, logs=logs):
                m, acc = dec(r[self.M]), dec(r[self.S]) or 0
                for s in logs:
                    acc += m - dec(r[s])
                return {self.S: enc(acc)}
            return Transition(c, f"p{p}.sum{w}", (self.M, self.S) + logs, (self.S,), sumw)
        if i == 2 * nw + 1:
            def finish(r, p=p):
                a, m, s = dec(r[self.A]), dec(r[self.M]) or 0, dec(r[self.S]) or 0
                h = (a + s - m) % MOD
                return {self.H: enc(h), self.log0 + p: enc(h), self.A: None, self.M: None, self.S: None}
            return Transition(c, f"p{p}.finish", (self.H, self.A, self.M, self.S),
                              (self.H, self.log0 + p, self.A, self.M, self.S), finish)
        raise IndexError("no such transition")
