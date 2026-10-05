"""Small, validated Python description of a statically linked kernel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def _uint(value: object, bits: int, label: str, *, nonzero: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << bits):
        raise ValueError(f"{label} must be an unsigned {bits}-bit integer")
    if nonzero and value == 0:
        raise ValueError(f"{label} must be nonzero")
    return value


def _identity(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must contain id and version")
    return (
        _uint(value.get("id"), 32, f"{label}.id", nonzero=True),
        _uint(value.get("version"), 16, f"{label}.version", nonzero=True),
    )


@dataclass(frozen=True)
class KernelRef:
    """Versioned kernel identity and the small shape needed to open a session."""

    id: bytes
    semantic_version: int
    abi_version: int
    mode_id: int
    mode_version: int
    schema_id: int
    schema_version: int
    input_width: int
    state_span_lengths: tuple[int, ...]
    stream_root: bytes
    input_codec: str = "u8"
    state_codec: str = "counter-u64-pair"
    #: The kernel declares KernelCapabilities::REJECTS_INPUT (v3 only): its
    #: sessions must open rejectable and may consume an input without applying it.
    rejects_input: bool = False

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> KernelRef:
        """Build a kernel reference from a declarative mapping, not Rust code."""

        if not isinstance(manifest, Mapping):
            raise ValueError("kernel manifest must be a mapping")
        raw_id = manifest.get("id")
        if isinstance(raw_id, str):
            # A name shorter than 16 bytes is padded with NULs, as KernelDecl
            # pads it in Rust.
            kernel_id = raw_id.encode("utf-8")
            if 0 < len(kernel_id) < 16 and b"\x00" not in kernel_id:
                kernel_id = kernel_id.ljust(16, b"\x00")
        elif isinstance(raw_id, bytes):
            kernel_id = raw_id
        else:
            raise ValueError("kernel id must be UTF-8 text or 16 bytes")
        if len(kernel_id) != 16:
            raise ValueError("kernel id must encode to exactly 16 bytes")

        mode_id, mode_version = _identity(manifest.get("mode"), "mode")
        schema_id, schema_version = _identity(manifest.get("schema"), "schema")
        spans = manifest.get("state_spans")
        if not isinstance(spans, (list, tuple)) or not spans or len(spans) > 8:
            raise ValueError("state_spans must contain between 1 and 8 lengths")
        lengths = tuple(_uint(n, 32, f"state_spans[{i}]", nonzero=True) for i, n in enumerate(spans))
        if sum(lengths) > 10_000_000:
            raise ValueError("state_spans exceed the stateful 10,000,000-byte aggregate bound")
        root_value = manifest.get("stream_root", "a5" * 32)
        if isinstance(root_value, str):
            try:
                stream_root = bytes.fromhex(root_value)
            except ValueError as exc:
                raise ValueError("stream_root must be 64 hexadecimal characters") from exc
        elif isinstance(root_value, bytes):
            stream_root = root_value
        else:
            raise ValueError("stream_root must be hexadecimal text or bytes")
        if len(stream_root) != 32:
            raise ValueError("stream_root must be exactly 32 bytes")

        input_codec = manifest.get("input_codec", "u8")
        state_codec = manifest.get("state_codec", "counter-u64-pair")
        if input_codec not in {"u8", "bytes"}:
            raise ValueError("supported input_codec values are 'u8' and 'bytes'")
        if state_codec not in {"counter-u64-pair", "bytes"}:
            raise ValueError("supported state_codec values are 'counter-u64-pair' and 'bytes'")
        rejects_input = manifest.get("rejects_input", False)
        if not isinstance(rejects_input, bool):
            raise ValueError("rejects_input must be true or false")
        if rejects_input and mode_version != 3:
            raise ValueError("rejects_input needs a stateful v3 kernel")
        input_width = _uint(manifest.get("input_width"), 8, "input_width", nonzero=True)
        if input_width > 8:
            raise ValueError("input_width must not exceed the stateful 8-byte command limit")
        return cls(
            id=kernel_id,
            semantic_version=_uint(manifest.get("semantic_version"), 16, "semantic_version", nonzero=True),
            abi_version=_uint(manifest.get("abi_version"), 16, "abi_version", nonzero=True),
            mode_id=mode_id,
            mode_version=mode_version,
            schema_id=schema_id,
            schema_version=schema_version,
            input_width=input_width,
            state_span_lengths=lengths,
            stream_root=stream_root,
            input_codec=input_codec,
            rejects_input=rejects_input,
            state_codec=state_codec,
        )


COUNTER_MANIFEST: dict[str, Any] = {
    "id": "dcg-counter-v1\0\0",
    "semantic_version": 1,
    "abi_version": 1,
    "mode": {"id": 0x434F4E53, "version": 1},
    "schema": {"id": 0x434E5452, "version": 1},
    "input_width": 1,
    "state_spans": [8, 8],
    "stream_root": "a5" * 32,
    "input_codec": "u8",
    "state_codec": "counter-u64-pair",
}
