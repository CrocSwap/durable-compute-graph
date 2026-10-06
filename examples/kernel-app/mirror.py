"""The Python mirror of `ex-polyhash-v1` (src/lib.rs). The v2.1 referee and
executor use it to replay the kernel off chain; the kernel kit checks it
against the Rust kernel:

    cargo build --features conform,no-entrypoint --bin polyhash-conform
    python -m dcg.kernel_kit check --bin target/debug/polyhash-conform mirror.py
"""

from __future__ import annotations

import struct

from dcg.kernel_kit import KernelRefused, step_kernel

MODULUS = (1 << 61) - 1
MAX_INPUT_BYTES = 4_096


@step_kernel("ex-polyhash-v1", max_input_bytes=MAX_INPUT_BYTES, max_output_bytes=8, max_compute_units=200_000)
def polyhash(inputs: list[bytes]) -> bytes:
    data = b"".join(inputs)
    if not inputs or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise KernelRefused("InvalidInput")
    h = 0
    for b in data:
        h = (h * 257 + b + 1) % MODULUS
    return struct.pack("<Q", h)
