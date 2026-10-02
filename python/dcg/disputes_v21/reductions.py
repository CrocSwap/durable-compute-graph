"""Chunked reduction kernels: stateful steps over one chunk at a time.

A chunked kernel is a repeated block whose body step reads one chunk of a
chunked input (producer kind 5), carries a running partial as SMALL state,
exports that state on port 0 and drives the block's gate on port 1. A
dispute replays one chunk-step, never the whole reduction.

All arithmetic is integer-exact with fixed widths; an overflow is a kernel
refusal. These are generic DCG kernels; model kernels stay in applications.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1


@dataclass(frozen=True)
class StatefulKernel:
    name: str
    state_bytes: int
    arity: int
    # (inputs, prior state) -> (outputs by port, next state); raises ValueError to refuse
    fn: Callable[[list[bytes], bytes], tuple[list[bytes], bytes]]


def _words(chunk: bytes) -> list[int]:
    if len(chunk) % 4:
        raise ValueError("chunk is not whole i32 words")
    return list(struct.unpack(f"<{len(chunk) // 4}i", chunk))


def _gate(on: bool) -> bytes:
    return struct.pack("<i", 1 if on else 0)


def _sum(inputs: list[bytes], prior: bytes) -> tuple[list[bytes], bytes]:
    (acc,) = struct.unpack("<q", prior)
    acc += sum(_words(inputs[0]))
    if not I64_MIN <= acc <= I64_MAX:
        raise ValueError("i64 overflow")
    nxt = struct.pack("<q", acc)
    return [nxt, _gate(True)], nxt


def _argmax(inputs: list[bytes], prior: bytes) -> tuple[list[bytes], bytes]:
    """State (seen:u32, best:i32, index:u32). Ties keep the lowest index."""
    seen, best, index = struct.unpack("<IiI", prior)
    words = _words(inputs[0])
    (iteration,) = struct.unpack("<I", inputs[1])
    for j, v in enumerate(words):
        if not seen or v > best:
            seen, best, index = 1, v, iteration * len(words) + j
    nxt = struct.pack("<IiI", seen, best, index)
    return [nxt, _gate(True)], nxt


def _scan(inputs: list[bytes], prior: bytes) -> tuple[list[bytes], bytes]:
    """First index of `needle`; state (found:u32, index:u32). The gate turns
    off once found, so later iterations do not run."""
    found, index = struct.unpack("<II", prior)
    words = _words(inputs[0])
    (iteration,) = struct.unpack("<I", inputs[1])
    (needle,) = struct.unpack("<i", inputs[2])
    if not found:
        for j, v in enumerate(words):
            if v == needle:
                found, index = 1, iteration * len(words) + j
                break
    nxt = struct.pack("<II", found, index)
    return [nxt, _gate(not found)], nxt


ROWDOT_ROWS = 64


def _rowdot(inputs: list[bytes], prior: bytes) -> tuple[list[bytes], bytes]:
    """One row of a matrix-vector product: y[i] = sum_j w[j] * x[j] in i64,
    for weight row w (a constant chunk), vector x and row index i < 64.
    State: y as 64 i64 entries."""
    w, x = _words(inputs[0]), _words(inputs[1])
    (i,) = struct.unpack("<I", inputs[2])
    if len(w) != len(x) or i >= ROWDOT_ROWS:
        raise ValueError("shape")
    y = list(struct.unpack(f"<{ROWDOT_ROWS}q", prior))
    acc = 0
    for a, b in zip(w, x):
        acc += a * b
        if not I64_MIN <= acc <= I64_MAX:
            raise ValueError("i64 overflow")
    y[i] = acc
    nxt = struct.pack(f"<{ROWDOT_ROWS}q", *y)
    return [nxt, _gate(True)], nxt


def _head(inputs: list[bytes], _prior: bytes) -> tuple[list[bytes], bytes]:
    """Stateless: the first i32 word of a value (reads a reduction's result)."""
    if len(inputs[0]) < 4:
        raise ValueError("value shorter than one word")
    return [inputs[0][:4]], b""


REGISTRY = {k.name: k for k in (
    StatefulKernel("sumchunk_i32", 8, 1, _sum),
    StatefulKernel("argmax_i32c", 12, 2, _argmax),
    StatefulKernel("scan_i32c", 8, 3, _scan),
    StatefulKernel("head_i32", 0, 1, _head),
    StatefulKernel("rowdot_i32c", 8 * ROWDOT_ROWS, 3, _rowdot),
)}


def kernel_id(name: str) -> bytes:
    raw = f"{name}/v1".encode()
    assert len(raw) <= 16
    return raw + bytes(16 - len(raw))


def lookup(kernel: bytes) -> StatefulKernel | None:
    return REGISTRY.get(kernel.rstrip(b"\x00").decode(errors="replace").split("/")[0])
