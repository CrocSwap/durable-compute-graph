"""Application kernels for STEP replay, by exact 16-byte kernel id.

The program resolves a step's kernel from the image's application manifest
(id, semantic and ABI versions); this registry is the Python reference's
mirror. Kernels here are stateless with one output (this slice). Mirrors are
declared with the kernel kit (``dcg.kernel_kit.step_kernel``) and checked
against the Rust kernels with ``python -m dcg.kernel_kit check``.
"""

from __future__ import annotations

import hashlib

from dcg.kernel_kit import STEP_REGISTRY, KernelRefused, step_kernel

# Keyed by (16-byte kernel id, semantic version, ABI version), exactly as the
# program resolves a manifest kernel (review 10-03, F2).
REGISTRY = STEP_REGISTRY


@step_kernel("dcg-test-sha-v1", max_input_bytes=65_536, max_output_bytes=32, max_compute_units=100_000)
def sha256_concat(inputs: list[bytes]) -> bytes:
    """`dcg-test-sha-v1`: SHA-256 over the inputs in order (the semantics of
    Basanos form 22, `window_leaf`)."""
    total = sum(len(v) for v in inputs)
    if not inputs or total == 0 or total > 65_536:
        raise KernelRefused("InvalidInput", "input size")
    return hashlib.sha256(b"".join(inputs)).digest()
