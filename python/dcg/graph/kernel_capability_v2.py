"""Canonical offline test-vector envelope for kernel capability v2.

This codec carries test material; it does not execute or validate a kernel.
Manifest bytes and roots are implemented in :mod:`dcg.graph.v2` so graph/plan
and capability references share the same canonical DCKC encoder.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class VectorError(ValueError):
    """A DCTV encoding or structural refusal with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class PortValueV1:
    port_id: int
    value: bytes


@dataclass(frozen=True)
class KernelTestVectorV1:
    vector_id: bytes
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    manifest_root: bytes
    source_kind: int
    source_identity: bytes
    generator_id: bytes
    generator_version: int
    seed: bytes
    parameters: bytes
    inputs: tuple[PortValueV1, ...]
    prior_state: bytes
    expected_outputs: tuple[PortValueV1, ...] | None
    next_state: bytes = b""
    stable_error_code: int = 0


_U32_MAX = (1 << 32) - 1
_ZERO16 = bytes(16)
_ZERO32 = bytes(32)


class _Writer:
    def __init__(self) -> None:
        self.data = bytearray()

    def uint(self, value: int, width: int, field: str) -> None:
        maximum = (1 << (width * 8)) - 1
        if type(value) is not int or not 0 <= value <= maximum:
            raise VectorError("INTEGER_RANGE", f"{field} does not fit u{width * 8}")
        self.data.extend(value.to_bytes(width, "little"))

    def fixed(self, value: bytes, width: int, field: str) -> None:
        if not isinstance(value, bytes) or len(value) != width:
            raise VectorError("FIXED_WIDTH", f"{field} must be exactly {width} bytes")
        self.data.extend(value)

    def blob(self, value: bytes, field: str) -> None:
        if not isinstance(value, bytes):
            raise VectorError("TYPE", f"{field} must be bytes")
        self.uint(len(value), 4, f"{field}.length")
        self.data.extend(value)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def uint(self, width: int, field: str) -> int:
        return int.from_bytes(self.fixed(width, field), "little")

    def fixed(self, width: int, field: str) -> bytes:
        if width < 0 or self.remaining < width:
            raise VectorError("TRUNCATED", field)
        start = self.pos
        self.pos += width
        return self.data[start : self.pos]

    def blob(self, field: str) -> bytes:
        length = self.uint(4, f"{field}.length")
        return self.fixed(length, field)

    def record(self, field: str) -> _Reader:
        length = self.uint(4, f"{field}.record_length")
        return _Reader(self.fixed(length, field))

    def finish(self, field: str) -> None:
        if self.remaining:
            raise VectorError("TRAILING_BYTES", f"{field} has {self.remaining} trailing bytes")


def _ordered(values: Iterable[PortValueV1], field: str) -> tuple[PortValueV1, ...]:
    if not isinstance(values, tuple):
        raise VectorError("TYPE", f"{field} must be a tuple")
    result = values
    keys = tuple(value.port_id for value in result)
    if keys != tuple(sorted(keys)):
        raise VectorError("ORDER", f"{field} must be sorted by port_id")
    if len(set(keys)) != len(keys):
        raise VectorError("DUPLICATE", f"{field} contains duplicate port_id")
    for value in result:
        if type(value.port_id) is not int or not 0 <= value.port_id <= 0xFFFF:
            raise VectorError("INTEGER_RANGE", f"{field}.port_id does not fit u16")
        if not isinstance(value.value, bytes):
            raise VectorError("TYPE", f"{field}.value must be bytes")
        if len(value.value) > _U32_MAX:
            raise VectorError("INTEGER_RANGE", f"{field}.value is too long")
    return result


def _validate_vector(vector: KernelTestVectorV1) -> None:
    if not isinstance(vector, KernelTestVectorV1):
        raise VectorError("TYPE", "vector must be KernelTestVectorV1")
    for value, width, field in (
        (vector.vector_id, 16, "vector_id"),
        (vector.kernel_id, 16, "kernel_id"),
        (vector.manifest_root, 32, "manifest_root"),
        (vector.source_identity, 32, "source_identity"),
        (vector.generator_id, 16, "generator_id"),
        (vector.seed, 32, "seed"),
    ):
        if not isinstance(value, bytes) or len(value) != width:
            raise VectorError("FIXED_WIDTH", f"{field} must be exactly {width} bytes")
    for value, field in (
        (vector.semantic_version, "semantic_version"),
        (vector.abi_version, "abi_version"),
        (vector.generator_version, "generator_version"),
    ):
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise VectorError("INTEGER_RANGE", f"{field} does not fit u16")
    if not vector.semantic_version or not vector.abi_version:
        raise VectorError("VERSION", "kernel semantic and ABI versions must be nonzero")
    if type(vector.source_kind) is not int or vector.source_kind not in (0, 1, 2):
        raise VectorError("SOURCE_KIND", "source_kind must be captured=0, normative=1, or derived=2")
    if vector.source_kind in (0, 1):
        if vector.generator_id != _ZERO16 or vector.generator_version != 0 or vector.seed != _ZERO32:
            raise VectorError("SOURCE_METADATA", "captured and normative vectors have zero generator and seed fields")
    elif vector.generator_id == _ZERO16 or vector.generator_version == 0:
        raise VectorError("SOURCE_METADATA", "derived vectors require a generator ID and version")
    if not isinstance(vector.parameters, bytes) or not isinstance(vector.prior_state, bytes) or not isinstance(vector.next_state, bytes):
        raise VectorError("TYPE", "parameters, prior_state, and next_state must be bytes")
    if len(vector.parameters) > _U32_MAX or len(vector.prior_state) > _U32_MAX or len(vector.next_state) > _U32_MAX:
        raise VectorError("INTEGER_RANGE", "parameter or state bytes exceed u32 length")
    if type(vector.stable_error_code) is not int or not 0 <= vector.stable_error_code <= 0xFFFF:
        raise VectorError("INTEGER_RANGE", "stable_error_code does not fit u16")
    _ordered(vector.inputs, "inputs")
    if vector.expected_outputs is None:
        if vector.stable_error_code == 0:
            raise VectorError("ERROR_CODE", "a refusal vector needs a nonzero stable u16 error code")
        if vector.next_state:
            raise VectorError("OUTCOME_FIELDS", "a refusal vector cannot have next-state bytes")
    else:
        _ordered(vector.expected_outputs, "expected_outputs")
        if vector.stable_error_code != 0:
            raise VectorError("OUTCOME_FIELDS", "an output vector must have zero stable_error_code")


def _port_values_write(writer: _Writer, values: tuple[PortValueV1, ...], field: str) -> None:
    writer.uint(len(values), 2, f"{field}.count")
    for index, value in enumerate(values):
        writer.uint(value.port_id, 2, f"{field}[{index}].port_id")
        writer.blob(value.value, f"{field}[{index}].value")


def encode_test_vectors(vectors: tuple[KernelTestVectorV1, ...]) -> bytes:
    """Encode a canonical DCTV v1 envelope."""
    if not isinstance(vectors, tuple) or not vectors:
        raise VectorError("VECTOR_COUNT", "test-vector envelope needs at least one vector")
    if len(vectors) > _U32_MAX:
        raise VectorError("VECTOR_COUNT", "test-vector count exceeds u32")
    for vector in vectors:
        _validate_vector(vector)
    ids = tuple(vector.vector_id for vector in vectors)
    if ids != tuple(sorted(ids)):
        raise VectorError("ORDER", "vectors must be sorted by vector_id")
    if len(set(ids)) != len(ids):
        raise VectorError("DUPLICATE", "duplicate vector_id")

    body = _Writer()
    for vector in vectors:
        record = _Writer()
        record.fixed(vector.vector_id, 16, "vector.vector_id")
        record.fixed(vector.kernel_id, 16, "vector.kernel_id")
        record.uint(vector.semantic_version, 2, "vector.semantic_version")
        record.uint(vector.abi_version, 2, "vector.abi_version")
        record.fixed(vector.manifest_root, 32, "vector.manifest_root")
        record.uint(vector.source_kind, 1, "vector.source_kind")
        record.fixed(vector.source_identity, 32, "vector.source_identity")
        record.fixed(vector.generator_id, 16, "vector.generator_id")
        record.uint(vector.generator_version, 2, "vector.generator_version")
        record.fixed(vector.seed, 32, "vector.seed")
        record.blob(vector.parameters, "vector.parameters")
        _port_values_write(record, vector.inputs, "vector.inputs")
        record.blob(vector.prior_state, "vector.prior_state")
        if vector.expected_outputs is None:
            record.uint(1, 1, "vector.expected_outcome")
            record.uint(vector.stable_error_code, 2, "vector.stable_error_code")
        else:
            record.uint(0, 1, "vector.expected_outcome")
            _port_values_write(record, vector.expected_outputs, "vector.expected_outputs")
            record.blob(vector.next_state, "vector.next_state")
        body.uint(len(record.data), 4, "vector.record_length")
        body.data.extend(record.data)

    envelope = _Writer()
    envelope.data.extend(b"DCTV")
    envelope.uint(1, 2, "format_version")
    envelope.uint(0, 2, "flags")
    envelope.uint(len(body.data), 4, "body_length")
    envelope.uint(len(vectors), 4, "vector_count")
    envelope.data.extend(body.data)
    return bytes(envelope.data)


def _read_port_values(reader: _Reader, field: str) -> tuple[PortValueV1, ...]:
    count = reader.uint(2, f"{field}.count")
    if count > reader.remaining // 6:
        raise VectorError("PORT_COUNT", f"{field} record count cannot fit in the remaining bytes")
    values = tuple(
        PortValueV1(reader.uint(2, f"{field}[{index}].port_id"), reader.blob(f"{field}[{index}].value"))
        for index in range(count)
    )
    return _ordered(values, field)


def _decode_vector(reader: _Reader) -> KernelTestVectorV1:
    record = reader.record("vector")
    vector_id = record.fixed(16, "vector.vector_id")
    kernel_id = record.fixed(16, "vector.kernel_id")
    semantic_version = record.uint(2, "vector.semantic_version")
    abi_version = record.uint(2, "vector.abi_version")
    manifest_root = record.fixed(32, "vector.manifest_root")
    source_kind = record.uint(1, "vector.source_kind")
    source_identity = record.fixed(32, "vector.source_identity")
    generator_id = record.fixed(16, "vector.generator_id")
    generator_version = record.uint(2, "vector.generator_version")
    seed = record.fixed(32, "vector.seed")
    parameters = record.blob("vector.parameters")
    inputs = _read_port_values(record, "vector.inputs")
    prior_state = record.blob("vector.prior_state")
    outcome = record.uint(1, "vector.expected_outcome")
    if outcome == 0:
        outputs = _read_port_values(record, "vector.expected_outputs")
        next_state = record.blob("vector.next_state")
        error_code = 0
    elif outcome == 1:
        outputs = None
        next_state = b""
        error_code = record.uint(2, "vector.stable_error_code")
    else:
        raise VectorError("OUTCOME", f"unknown expected_outcome {outcome}")
    record.finish("vector record")
    vector = KernelTestVectorV1(
        vector_id,
        kernel_id,
        semantic_version,
        abi_version,
        manifest_root,
        source_kind,
        source_identity,
        generator_id,
        generator_version,
        seed,
        parameters,
        inputs,
        prior_state,
        outputs,
        next_state,
        error_code,
    )
    _validate_vector(vector)
    return vector


def decode_test_vectors(data: bytes) -> tuple[KernelTestVectorV1, ...]:
    """Decode DCTV v1 and refuse any noncanonical or trailing bytes."""
    if not isinstance(data, bytes):
        raise VectorError("TYPE", "DCTV input must be bytes")
    reader = _Reader(data)
    if reader.fixed(4, "magic") != b"DCTV":
        raise VectorError("MAGIC", "expected DCTV")
    version = reader.uint(2, "format_version")
    if version != 1:
        raise VectorError("VERSION", f"unsupported DCTV version {version}")
    if reader.uint(2, "flags") != 0:
        raise VectorError("FLAGS", "DCTV flags must be zero")
    body_length = reader.uint(4, "body_length")
    count = reader.uint(4, "vector_count")
    if count == 0:
        raise VectorError("VECTOR_COUNT", "test-vector envelope needs at least one vector")
    if body_length != reader.remaining:
        raise VectorError("BODY_LENGTH", "body length must equal bytes after the 16-byte header")
    if count > reader.remaining // 4:
        raise VectorError("VECTOR_COUNT", "record count cannot fit in the declared body")
    vectors = tuple(_decode_vector(reader) for _ in range(count))
    reader.finish("DCTV")
    ids = tuple(vector.vector_id for vector in vectors)
    if ids != tuple(sorted(ids)):
        raise VectorError("ORDER", "vectors must be sorted by vector_id")
    if len(set(ids)) != len(ids):
        raise VectorError("DUPLICATE", "duplicate vector_id")
    return vectors
