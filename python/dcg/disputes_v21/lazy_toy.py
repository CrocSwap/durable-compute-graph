"""Test-only chunked dot product demonstrating the generic lazy interface."""

from __future__ import annotations

import struct
from typing import Sequence

from .lazy import AccumulatorScheme, ParentStep, SubstepWitness, REGISTRY

KERNEL_ID = b"dcg-lazy-dot/v1".ljust(16, b"\x00")
DECOMPOSITION_ID = 0xD071
DECOMPOSITION_VERSION = 1
ACCUMULATOR = AccumulatorScheme(1, 1, 8)
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1


class ChunkedDot:
    kernel_id = KERNEL_ID
    semantic_version = 1
    abi_version = 1
    decomposition_id = DECOMPOSITION_ID
    decomposition_version = DECOMPOSITION_VERSION

    def count(self, parent: ParentStep) -> int:
        width = int(parent.shape["chunk_pairs"])
        pairs = int(parent.shape["pairs"])
        if width <= 0 or pairs <= 0 or len(parent.inputs) != 1 or len(parent.inputs[0]) != pairs * 8:
            raise ValueError("dot shape/input mismatch")
        return (pairs + width - 1) // width

    def accumulator_scheme(self, _parent: ParentStep) -> AccumulatorScheme:
        return ACCUMULATOR

    def phase(self, _parent: ParentStep, _index: int) -> int:
        return 1

    def initial_accumulator(self, _parent: ParentStep) -> bytes:
        return struct.pack("<q", 0)

    def inputs(self, parent: ParentStep, index: int,
               _prior_witnesses: Sequence[SubstepWitness]) -> tuple[bytes, ...]:
        width = int(parent.shape["chunk_pairs"])
        start = index * width * 8
        end = min(start + width * 8, len(parent.inputs[0]))
        return (parent.inputs[0][start:end],)

    def replay(self, _parent: ParentStep, _index: int, inputs: tuple[bytes, ...],
               prior_accumulator: bytes) -> tuple[tuple[bytes, ...], bytes]:
        if len(inputs) != 1 or len(inputs[0]) % 8 or len(prior_accumulator) != 8:
            raise ValueError("dot sub-step witness shape")
        acc = struct.unpack("<q", prior_accumulator)[0]
        for left, right in struct.iter_unpack("<ii", inputs[0]):
            acc += left * right
            if not I64_MIN <= acc <= I64_MAX:
                raise ValueError("i64 accumulator overflow")
        raw = struct.pack("<q", acc)
        return (raw,), raw


DOT = ChunkedDot()


def register() -> None:
    """Called by the DCG test harness; production app kernels register separately."""
    if not REGISTRY._items:
        REGISTRY.register(DOT)


def parent_step(pairs: Sequence[tuple[int, int]], *, chunk_pairs: int = 2,
                output: int | None = None) -> ParentStep:
    raw = b"".join(struct.pack("<ii", a, b) for a, b in pairs)
    true = sum(a * b for a, b in pairs)
    claimed = true if output is None else output
    # The leaf hash is a test commitment to the canonical parent statement.
    from .lazy import values_digest
    from . import run as R
    leaf_hash = R.leaf_hash(KERNEL_ID + values_digest((raw,)) + R.value_digest(struct.pack("<q", claimed)))
    return ParentStep(leaf_hash, KERNEL_ID, 1, 1, DECOMPOSITION_ID,
                      DECOMPOSITION_VERSION, {"pairs": len(pairs), "chunk_pairs": chunk_pairs},
                      (raw,), (struct.pack("<q", claimed),))
