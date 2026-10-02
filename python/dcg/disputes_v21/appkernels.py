"""Application kernels for STEP replay, by exact 16-byte kernel id.

The program resolves a step's kernel from the image's application manifest
(id, semantic and ABI versions); this registry is the Python reference's
mirror. Kernels here are stateless with one output (this slice).
"""

from __future__ import annotations

import hashlib
from typing import Callable


def _sha256_concat(inputs: list[bytes]) -> list[bytes]:
    """`dcg-test-sha-v1`: SHA-256 over the inputs in order (the semantics of
    Basanos form 22, `window_leaf`)."""
    total = sum(len(v) for v in inputs)
    if not inputs or total == 0 or total > 65_536:
        raise ValueError("input size")
    return [hashlib.sha256(b"".join(inputs)).digest()]


REGISTRY: dict[bytes, Callable[[list[bytes]], list[bytes]]] = {
    b"dcg-test-sha-v1\x00": _sha256_concat,
}
