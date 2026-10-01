"""Reference codecs for DCGG/DCPL v1.

The module intentionally has no RPC, chain, or Rust dependencies.  Its byte
codecs are the Python side of the graph/plan consensus-byte contract; a
successful decode proves canonical structure only, not kernel behavior.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, TypeVar


MAX_GRAPH_BYTES = 4 * 1024 * 1024
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_NODES = 4096
MAX_REGIONS = 256
MAX_EDGES = 16_384
MAX_PORTS = 16_384
MAX_RANK = 8
MAX_PORT_BYTES = 1024 * 1024
MAX_KERNEL_PARAMETER_BYTES = 64 * 1024
MAX_PLAN_STEPS = 16_384
MAX_OPENING_BYTES = 4096
ROOT_PARENT = 0xFFFF_FFFF

MODE_CONSENSUS = 0x434F_4E53
MODE_OPTIMISTIC = 0x4F50_5449
SCHEME_SHA256_MERKLE = 2
LAYOUT_FULL_TRACE = 1
LAYOUT_CHECKPOINTED_STATE = 2

_GRAPH_DOMAIN = b"dcg.graph.id.v2\x00"
_PLAN_DOMAIN = b"dcg.plan.id.v2\x00"
_TEMPLATE_DOMAIN = b"dcg.template.id.v2\x00"
_RUN_DOMAIN = b"dcg.run.id.v2\x00"
_MANIFEST_DOMAIN = b"dcg.kernel.manifest.id.v2\x00"
_LEAF_DOMAIN = b"dcg.region.leaf.v2\x00"
_NODE_DOMAIN = b"dcg.region.node.v2\x00"
_ROOT_DOMAIN = b"dcg.region.root.v2\x00"

_SCALAR_WIDTHS = {1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 8, 8: 8, 9: 1}
_U16_MAX = (1 << 16) - 1
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1


class GraphError(ValueError):
    """A graph encoding or semantic refusal with a stable machine code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class PlanError(ValueError):
    """A plan encoding or semantic refusal with a stable machine code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class NodeV1:
    node_id: int
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    region_id: int
    state_schema_id: int = 0
    state_schema_version: int = 0
    max_state_bytes: int = 0
    parameter_layout_id: int = 0
    parameter_layout_version: int = 0
    parameters: bytes = b""


@dataclass(frozen=True)
class PortV1:
    node_id: int
    direction: int
    port_id: int
    layout_id: int
    layout_version: int
    scalar_type: int
    dimensions: tuple[int, ...]
    alignment: int
    byte_length: int
    max_byte_length: int


@dataclass(frozen=True)
class EdgeV1:
    source_node: int
    source_port: int
    destination_node: int
    destination_port: int


@dataclass(frozen=True)
class RegionV1:
    region_id: int
    parent_region_id: int
    mode_id: int
    mode_version: int
    scheme_id: int
    scheme_version: int
    layout_id: int
    layout_version: int
    mode_parameters: bytes = b""
    scheme_parameters: bytes = b""
    layout_parameters: bytes = b""


@dataclass(frozen=True)
class GraphInputV1:
    external_id: int
    destination_node: int
    destination_port: int


@dataclass(frozen=True)
class GraphOutputV1:
    external_id: int
    source_node: int
    source_port: int


@dataclass(frozen=True)
class GraphV2:
    nodes: tuple[NodeV1, ...]
    ports: tuple[PortV1, ...]
    edges: tuple[EdgeV1, ...]
    regions: tuple[RegionV1, ...]
    inputs: tuple[GraphInputV1, ...]
    outputs: tuple[GraphOutputV1, ...]


@dataclass(frozen=True)
class PortRefV1:
    node_id: int
    direction: int
    port_id: int


@dataclass(frozen=True)
class RegionPlanV1:
    region_id: int
    parent_region_id: int
    mode_id: int
    mode_version: int
    scheme_id: int
    scheme_version: int
    layout_id: int
    layout_version: int
    direct_step_count: int
    segment_count: int
    mode_parameters: bytes = b""
    scheme_parameters: bytes = b""
    layout_parameters: bytes = b""


@dataclass(frozen=True)
class StepV1:
    ordinal: int
    region_id: int
    segment_id: int
    node_id: int
    kernel_step: int
    decomposition_id: int
    decomposition_version: int
    inputs: tuple[PortRefV1, ...]
    outputs: tuple[PortRefV1, ...]


@dataclass(frozen=True)
class SegmentV1:
    region_id: int
    segment_id: int
    first_step: int
    step_count: int
    root_scheme_id: int
    root_scheme_version: int


@dataclass(frozen=True)
class BoundaryV1:
    source_region: int
    destination_region: int
    source: PortRefV1
    destination: PortRefV1
    layout_id: int
    layout_version: int
    scheme_id: int
    scheme_version: int
    cursor_schema_id: int = 0
    cursor_schema_version: int = 0


@dataclass(frozen=True)
class TranslationV1:
    source_scheme_id: int
    source_version: int
    target_scheme_id: int
    target_version: int
    relation_or_kernel_id: bytes
    semantic_version: int
    abi_version: int
    input_layout_id: int
    input_layout_version: int
    output_layout_id: int
    output_layout_version: int
    max_input_bytes: int
    max_output_bytes: int
    max_cu: int
    max_accounts: int
    max_opening_bytes: int


@dataclass(frozen=True)
class CostAdmissionV1:
    scope_kind: int
    region_id: int
    step_ordinal: int
    max_cu: int
    max_accounts: int
    max_read_bytes: int
    max_write_bytes: int
    max_operations: int
    max_heap_bytes: int
    max_stack_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    max_state_bytes: int
    max_opening_bytes: int


@dataclass(frozen=True)
class PlanV2:
    graph_id: bytes
    compiler_id: bytes
    compiler_version: int
    frontend_version: int
    lowering_version: int
    admission_ruleset_id: int
    admission_ruleset_version: int
    app_image_id: bytes
    kernel_manifest_root: bytes
    compiler_parameters: bytes
    regions: tuple[RegionPlanV1, ...]
    steps: tuple[StepV1, ...]
    segments: tuple[SegmentV1, ...]
    boundaries: tuple[BoundaryV1, ...]
    translations: tuple[TranslationV1, ...]
    costs: tuple[CostAdmissionV1, ...]


@dataclass(frozen=True)
class CapabilityPortV1:
    direction: int
    port_id: int
    layout_id: int
    layout_version: int
    scalar_type: int
    dimensions: tuple[int, ...]
    byte_order: int
    alignment: int
    mutability: int
    alias_rule: int
    max_byte_length: int


@dataclass(frozen=True)
class StateComponentV1:
    component_id: int
    layout_id: int
    layout_version: int
    max_read_bytes: int
    max_write_bytes: int
    initial_bytes: bytes = b""


@dataclass(frozen=True)
class ReplayCapabilityV1:
    abi_id: int
    abi_version: int
    max_input_spans: int
    max_prior_state_bytes: int
    max_output_bytes: int
    max_next_state_bytes: int
    max_authentication_path_nodes: int
    max_opening_bytes: int
    allowed_account_roles: int
    max_svm_cu: int


@dataclass(frozen=True)
class ModeCapabilityV1:
    mode_id: int
    version: int
    required_capabilities: tuple[tuple[bytes, int], ...]
    schemes: tuple[tuple[int, int], ...]
    replay: ReplayCapabilityV1 | None = None


@dataclass(frozen=True)
class ErrorMappingV1:
    condition_id: int
    stable_error_code: int


@dataclass(frozen=True)
class KernelCapabilityV1:
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    implementation_id: bytes
    parameter_layout_id: int
    parameter_layout_version: int
    max_parameter_bytes: int
    ports: tuple[CapabilityPortV1, ...]
    state_present: bool
    state_schema_id: int
    state_schema_version: int
    max_state_bytes: int
    cursor_schema_id: int
    cursor_schema_version: int
    initial_state: bytes
    complete_state_commitment: bool
    state_components: tuple[StateComponentV1, ...]
    step_abi_id: int
    step_abi_version: int
    decomposition_id: int
    decomposition_version: int
    max_step_count: int
    whole_sweep_supported: bool
    modes: tuple[ModeCapabilityV1, ...]
    max_input_bytes: int
    max_output_bytes: int
    max_operations: int
    max_accounts: int
    max_cu: int
    max_heap_bytes: int
    max_stack_bytes: int
    max_concurrent_live_states: int
    max_live_state_bytes: int
    error_mappings: tuple[ErrorMappingV1, ...]


@dataclass(frozen=True)
class KernelManifestV1:
    kernels: tuple[KernelCapabilityV1, ...]


@dataclass(frozen=True)
class ExternalInputRefV1:
    external_id: int
    layout_id: int
    layout_version: int
    scheme_id: int
    scheme_version: int
    byte_length: int
    value_digest: bytes


@dataclass(frozen=True)
class ValueRefV1:
    node_id: int
    direction: int
    port_id: int
    layout_id: int
    layout_version: int
    scheme_id: int
    scheme_version: int
    byte_length: int
    value_digest: bytes


@dataclass(frozen=True)
class ChildRootV1:
    child_region_id: int
    mode_id: int
    mode_version: int
    scheme_id: int
    scheme_version: int
    layout_id: int
    layout_version: int
    child_root: bytes


@dataclass(frozen=True)
class RegionRootV1:
    plan_id: bytes
    run_id: bytes
    region_id: int
    mode_id: int
    mode_version: int
    scheme_id: int
    scheme_version: int
    layout_id: int
    layout_version: int
    inputs: tuple[ValueRefV1, ...]
    step_tree_root: bytes
    children: tuple[ChildRootV1, ...]
    outputs: tuple[ValueRefV1, ...]
    final_state_digest: bytes


class _Writer:
    def __init__(self, error_type: type[ValueError]) -> None:
        self.data = bytearray()
        self.error_type = error_type

    def uint(self, value: int, width: int, field: str) -> None:
        limit = (1 << (8 * width)) - 1
        if type(value) is not int or value < 0 or value > limit:
            self.fail("INTEGER_RANGE", f"{field} does not fit u{width * 8}")
        self.data.extend(value.to_bytes(width, "little"))

    def fixed(self, value: bytes, width: int, field: str) -> None:
        if not isinstance(value, bytes) or len(value) != width:
            self.fail("FIXED_WIDTH", f"{field} must be exactly {width} bytes")
        self.data.extend(value)

    def blob(self, value: bytes, field: str) -> None:
        if not isinstance(value, bytes):
            self.fail("TYPE", f"{field} must be bytes")
        self.uint(len(value), 4, f"{field}.length")
        self.data.extend(value)

    def fail(self, code: str, detail: str = "") -> None:
        raise self.error_type(code, detail)


class _Reader:
    def __init__(self, data: bytes, error_type: type[ValueError]) -> None:
        self.data = data
        self.pos = 0
        self.error_type = error_type

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def uint(self, width: int, field: str) -> int:
        return int.from_bytes(self.fixed(width, field), "little")

    def fixed(self, width: int, field: str) -> bytes:
        if width < 0 or self.remaining < width:
            self.fail("TRUNCATED", field)
        start = self.pos
        self.pos += width
        return self.data[start : self.pos]

    def blob(self, field: str) -> bytes:
        size = self.uint(4, f"{field}.length")
        return self.fixed(size, field)

    def record(self, field: str) -> _Reader:
        size = self.uint(4, f"{field}.record_length")
        return _Reader(self.fixed(size, field), self.error_type)

    def finish(self, field: str = "record") -> None:
        if self.remaining:
            self.fail("TRAILING_BYTES", f"{field} has {self.remaining} trailing bytes")

    def fail(self, code: str, detail: str = "") -> None:
        raise self.error_type(code, detail)


T = TypeVar("T")


def _strictly_sorted(items: Iterable[T], key, code: str, error_type: type[ValueError]) -> None:
    values = tuple(items)
    keys = tuple(key(item) for item in values)
    if keys != tuple(sorted(keys)):
        raise error_type(code, "records are not in canonical order")
    if len(set(keys)) != len(keys):
        raise error_type("DUPLICATE", "duplicate canonical record key")


def _mode_ok(mode_id: int, version: int, error_type: type[ValueError]) -> None:
    if (mode_id, version) not in ((MODE_CONSENSUS, 1), (MODE_OPTIMISTIC, 1)):
        raise error_type("UNKNOWN_MODE", f"unsupported mode {mode_id:#x}/{version}")


def _scheme_ok(scheme_id: int, version: int, error_type: type[ValueError]) -> None:
    if (scheme_id, version) != (SCHEME_SHA256_MERKLE, 1):
        raise error_type("UNKNOWN_SCHEME", f"unsupported scheme {scheme_id}/{version}")


def _layout_ok(layout_id: int, version: int, error_type: type[ValueError]) -> None:
    if (layout_id, version) not in ((LAYOUT_FULL_TRACE, 1), (LAYOUT_CHECKPOINTED_STATE, 1)):
        raise error_type("UNKNOWN_LAYOUT", f"unsupported layout {layout_id}/{version}")


def _port_shape(port: PortV1, error_type: type[ValueError]) -> None:
    if port.direction not in (0, 1):
        raise error_type("DIRECTION", "port direction must be input=0 or output=1")
    if port.scalar_type not in _SCALAR_WIDTHS:
        raise error_type("SCALAR_TYPE", f"unknown scalar type {port.scalar_type}")
    if len(port.dimensions) > MAX_RANK:
        raise error_type("RANK_LIMIT", f"rank exceeds {MAX_RANK}")
    if type(port.alignment) is not int or port.alignment <= 0 or port.alignment & (port.alignment - 1):
        raise error_type("ALIGNMENT", "alignment must be a nonzero power of two")
    if port.alignment > _U16_MAX:
        raise error_type("ALIGNMENT", "alignment does not fit u16")
    product = 1
    for dim in port.dimensions:
        if type(dim) is not int or dim <= 0 or dim > _U32_MAX:
            raise error_type("DIMENSION", "dimensions must be positive u32 values")
        product *= dim
        if product > _U32_MAX:
            raise error_type("OVERFLOW", "dimension product exceeds u32")
    expected = product * _SCALAR_WIDTHS[port.scalar_type]
    if expected > _U32_MAX or expected != port.byte_length:
        raise error_type("PORT_BYTE_LENGTH", "byte_length must equal checked shape product times scalar width")
    if port.byte_length > MAX_PORT_BYTES or port.max_byte_length > MAX_PORT_BYTES:
        raise error_type("PORT_BYTE_LIMIT", f"port bytes exceed {MAX_PORT_BYTES}")
    if type(port.byte_length) is not int or type(port.max_byte_length) is not int:
        raise error_type("INTEGER_RANGE", "port byte lengths must be integers")
    if port.byte_length < 0 or port.max_byte_length < 0:
        raise error_type("INTEGER_RANGE", "port byte lengths must be nonnegative")
    if port.max_byte_length < port.byte_length:
        raise error_type("PORT_MAX_TOO_SMALL", "max_byte_length must cover byte_length")


def _encode_record(body: bytes) -> bytes:
    w = _Writer(GraphError)
    w.uint(len(body), 4, "record_length")
    w.data.extend(body)
    return bytes(w.data)


def _graph_record(error_type: type[ValueError], emit) -> bytes:
    w = _Writer(error_type)
    emit(w)
    return bytes(w.data)


def _write_node(w: _Writer, node: NodeV1) -> None:
    body = _graph_record(w.error_type, lambda b: _node_fields(b, node))
    w.uint(len(body), 4, "node.record_length")
    w.data.extend(body)


def _node_fields(w: _Writer, node: NodeV1) -> None:
    if not isinstance(node.parameters, bytes):
        w.fail("TYPE", "node parameters must be bytes")
    if not node.semantic_version or not node.abi_version:
        w.fail("VERSION", "kernel semantic and ABI versions must be nonzero")
    state_present = any((node.state_schema_id, node.state_schema_version, node.max_state_bytes))
    parameter_present = bool(node.parameters)
    if state_present and not (node.state_schema_id and node.state_schema_version and node.max_state_bytes):
        w.fail("STATE_FIELDS", "state-present node requires schema id/version and a positive maximum")
    if not state_present and (node.state_schema_id or node.state_schema_version or node.max_state_bytes):
        w.fail("STATE_FIELDS", "stateless node state fields must all be zero")
    if parameter_present and not (node.parameter_layout_id and node.parameter_layout_version):
        w.fail("PARAMETER_FIELDS", "parameter bytes require layout id and version")
    if not parameter_present and (node.parameter_layout_id or node.parameter_layout_version):
        w.fail("PARAMETER_FIELDS", "empty parameter block requires zero layout id/version")
    if len(node.parameters) > MAX_KERNEL_PARAMETER_BYTES:
        w.fail("PARAMETER_LIMIT", f"kernel parameters exceed {MAX_KERNEL_PARAMETER_BYTES}")
    w.uint(node.node_id, 4, "node.node_id")
    w.fixed(node.kernel_id, 16, "node.kernel_id")
    w.uint(node.semantic_version, 2, "node.semantic_version")
    w.uint(node.abi_version, 2, "node.abi_version")
    w.uint(node.region_id, 4, "node.region_id")
    w.uint(1 if state_present else 0, 1, "node.state_present")
    w.uint(node.state_schema_id, 4, "node.state_schema_id")
    w.uint(node.state_schema_version, 2, "node.state_schema_version")
    w.uint(node.max_state_bytes, 4, "node.max_state_bytes")
    w.uint(node.parameter_layout_id, 4, "node.parameter_layout_id")
    w.uint(node.parameter_layout_version, 2, "node.parameter_layout_version")
    w.uint(len(node.parameters), 4, "node.parameter_length")
    w.data.extend(node.parameters)


def _write_port(w: _Writer, port: PortV1) -> None:
    _port_shape(port, w.error_type)
    body = _graph_record(w.error_type, lambda b: _port_fields(b, port))
    w.uint(len(body), 4, "port.record_length")
    w.data.extend(body)


def _port_fields(w: _Writer, port: PortV1) -> None:
    w.uint(port.node_id, 4, "port.node_id")
    w.uint(port.direction, 1, "port.direction")
    w.uint(port.port_id, 2, "port.port_id")
    w.uint(port.layout_id, 4, "port.layout_id")
    w.uint(port.layout_version, 2, "port.layout_version")
    w.uint(port.scalar_type, 1, "port.scalar_type")
    w.uint(len(port.dimensions), 1, "port.rank")
    w.uint(port.alignment, 2, "port.alignment")
    w.uint(0, 2, "port.reserved")
    w.uint(port.byte_length, 4, "port.byte_length")
    w.uint(port.max_byte_length, 4, "port.max_byte_length")
    for index, dimension in enumerate(port.dimensions):
        w.uint(dimension, 4, f"port.dimensions[{index}]")


def _write_edge(w: _Writer, edge: EdgeV1) -> None:
    body = _graph_record(
        w.error_type,
        lambda b: (
            b.uint(edge.source_node, 4, "edge.source_node"),
            b.uint(edge.source_port, 2, "edge.source_port"),
            b.uint(edge.destination_node, 4, "edge.destination_node"),
            b.uint(edge.destination_port, 2, "edge.destination_port"),
        ),
    )
    w.uint(len(body), 4, "edge.record_length")
    w.data.extend(body)


def _write_region(w: _Writer, region: RegionV1) -> None:
    _mode_ok(region.mode_id, region.mode_version, w.error_type)
    _scheme_ok(region.scheme_id, region.scheme_version, w.error_type)
    _layout_ok(region.layout_id, region.layout_version, w.error_type)

    def fields(b: _Writer) -> None:
        for value, width, name in (
            (region.region_id, 4, "region_id"),
            (region.parent_region_id, 4, "parent_region_id"),
            (region.mode_id, 4, "mode_id"),
            (region.mode_version, 2, "mode_version"),
            (region.scheme_id, 4, "scheme_id"),
            (region.scheme_version, 2, "scheme_version"),
            (region.layout_id, 4, "layout_id"),
            (region.layout_version, 2, "layout_version"),
        ):
            b.uint(value, width, f"region.{name}")
        for name, payload in (
            ("mode", region.mode_parameters),
            ("scheme", region.scheme_parameters),
            ("layout", region.layout_parameters),
        ):
            b.uint(len(payload), 4, f"region.{name}_parameter_length")
            b.data.extend(payload)

    body = _graph_record(w.error_type, fields)
    w.uint(len(body), 4, "region.record_length")
    w.data.extend(body)


def _write_graph_endpoint(w: _Writer, item: GraphInputV1 | GraphOutputV1, input_side: bool) -> None:
    def fields(b: _Writer) -> None:
        b.uint(item.external_id, 4, "endpoint.external_id")
        if input_side:
            b.uint(item.destination_node, 4, "input.destination_node")  # type: ignore[attr-defined]
            b.uint(item.destination_port, 2, "input.destination_port")  # type: ignore[attr-defined]
        else:
            b.uint(item.source_node, 4, "output.source_node")  # type: ignore[attr-defined]
            b.uint(item.source_port, 2, "output.source_port")  # type: ignore[attr-defined]
        b.uint(0, 2, "endpoint.reserved")

    body = _graph_record(w.error_type, fields)
    w.uint(len(body), 4, "endpoint.record_length")
    w.data.extend(body)


def _validate_graph(graph: GraphV2, error_type: type[ValueError]) -> None:
    if not graph.nodes or len(graph.nodes) > MAX_NODES:
        raise error_type("NODE_COUNT", f"node count must be in 1..{MAX_NODES}")
    if len(graph.ports) > MAX_PORTS:
        raise error_type("PORT_COUNT", f"port count exceeds {MAX_PORTS}")
    if len(graph.edges) > MAX_EDGES:
        raise error_type("EDGE_COUNT", f"edge count exceeds {MAX_EDGES}")
    if not graph.regions or len(graph.regions) > MAX_REGIONS:
        raise error_type("REGION_COUNT", f"region count must be in 1..{MAX_REGIONS}")
    if len(graph.inputs) > _U16_MAX or len(graph.outputs) > _U16_MAX:
        raise error_type("ENDPOINT_COUNT", "graph input/output count exceeds u16")

    _strictly_sorted(graph.nodes, lambda n: n.node_id, "ORDER", error_type)
    _strictly_sorted(graph.ports, lambda p: (p.node_id, p.direction, p.port_id), "ORDER", error_type)
    _strictly_sorted(
        graph.edges,
        lambda e: (e.destination_node, e.destination_port, e.source_node, e.source_port),
        "ORDER",
        error_type,
    )
    _strictly_sorted(graph.regions, lambda r: r.region_id, "ORDER", error_type)
    _strictly_sorted(graph.inputs, lambda i: i.external_id, "ORDER", error_type)
    _strictly_sorted(graph.outputs, lambda o: o.external_id, "ORDER", error_type)

    node_by_id = {node.node_id: node for node in graph.nodes}
    region_by_id = {region.region_id: region for region in graph.regions}
    if 0 not in region_by_id or region_by_id[0].parent_region_id != ROOT_PARENT:
        raise error_type("REGION_ROOT", "region zero must be the unique root")
    if sum(region.parent_region_id == ROOT_PARENT for region in graph.regions) != 1:
        raise error_type("REGION_ROOT", "exactly one root parent sentinel is required")
    for region in graph.regions:
        if region.region_id == ROOT_PARENT:
            raise error_type("REGION_ID_RESERVED", "0xffffffff is reserved as the root-parent sentinel")
        if region.region_id != 0 and region.parent_region_id not in region_by_id:
            raise error_type("REGION_PARENT", f"region {region.region_id} has unknown parent")
        if region.region_id != 0 and region.parent_region_id == region.region_id:
            raise error_type("REGION_CYCLE", "region cannot parent itself")
        _mode_ok(region.mode_id, region.mode_version, error_type)
        _scheme_ok(region.scheme_id, region.scheme_version, error_type)
        _layout_ok(region.layout_id, region.layout_version, error_type)
    for region in graph.regions:
        seen: set[int] = set()
        current = region
        depth = 1
        while current.region_id != 0:
            if current.region_id in seen:
                raise error_type("REGION_CYCLE", "region tree contains a cycle")
            seen.add(current.region_id)
            current = region_by_id[current.parent_region_id]
            depth += 1
            if depth > 8:
                raise error_type("REGION_DEPTH", "region-tree depth exceeds 8 including root")

    for node in graph.nodes:
        if node.region_id not in region_by_id:
            raise error_type("NODE_REGION", f"node {node.node_id} names unknown region")
        if len(node.parameters) > MAX_KERNEL_PARAMETER_BYTES:
            raise error_type("PARAMETER_LIMIT", f"node {node.node_id} parameters exceed {MAX_KERNEL_PARAMETER_BYTES}")
        _node_fields(_Writer(error_type), node)
    port_by_key: dict[tuple[int, int, int], PortV1] = {}
    children: dict[int, set[int]] = {rid: set() for rid in region_by_id}
    for region in graph.regions:
        if region.region_id:
            children[region.parent_region_id].add(region.region_id)
    for region in graph.regions:
        if not any(node.region_id == region.region_id for node in graph.nodes) and not children[region.region_id]:
            raise error_type("EMPTY_REGION", f"region {region.region_id} has no node or child region")
    for port in graph.ports:
        if port.node_id not in node_by_id:
            raise error_type("PORT_NODE", f"port names unknown node {port.node_id}")
        _port_shape(port, error_type)
        if not port.layout_id or not port.layout_version:
            raise error_type("PORT_LAYOUT", "port layout id and version must be nonzero")
        port_by_key[(port.node_id, port.direction, port.port_id)] = port

    supplied_inputs: dict[tuple[int, int], int] = {}
    used_outputs: set[tuple[int, int]] = set()
    declared_outputs = {(out.source_node, out.source_port) for out in graph.outputs}
    adjacency: dict[int, set[int]] = {node.node_id: set() for node in graph.nodes}
    indegree = {node.node_id: 0 for node in graph.nodes}
    for edge in graph.edges:
        source = port_by_key.get((edge.source_node, 1, edge.source_port))
        destination = port_by_key.get((edge.destination_node, 0, edge.destination_port))
        if source is None or destination is None:
            raise error_type("EDGE_PORT", "edge must connect an existing output port to an input port")
        if (
            source.layout_id,
            source.layout_version,
            source.scalar_type,
            source.dimensions,
            source.byte_length,
            source.alignment,
        ) != (
            destination.layout_id,
            destination.layout_version,
            destination.scalar_type,
            destination.dimensions,
            destination.byte_length,
            destination.alignment,
        ):
            raise error_type("EDGE_LAYOUT", "whole-port edge layouts do not match exactly")
        destination_key = (edge.destination_node, edge.destination_port)
        if destination_key in supplied_inputs:
            raise error_type("INPUT_MULTIPLE_SOURCES", "an input port is supplied more than once")
        supplied_inputs[destination_key] = 1
        used_outputs.add((edge.source_node, edge.source_port))
        if edge.destination_node not in adjacency[edge.source_node]:
            adjacency[edge.source_node].add(edge.destination_node)
            indegree[edge.destination_node] += 1

    input_external: set[tuple[int, int]] = set()
    for item in graph.inputs:
        key = (item.destination_node, item.destination_port)
        port = port_by_key.get((item.destination_node, 0, item.destination_port))
        if port is None:
            raise error_type("INPUT_PORT", "graph input must name an existing input port")
        if key in supplied_inputs or key in input_external:
            raise error_type("INPUT_MULTIPLE_SOURCES", "an input port is supplied more than once")
        input_external.add(key)
        supplied_inputs[key] = 1
    for key, port in port_by_key.items():
        node_id, direction, port_id = key
        if direction == 0 and (node_id, port_id) not in supplied_inputs:
            raise error_type("INPUT_UNBOUND", f"input port {key} has no source")
        if direction == 1 and (node_id, port_id) not in used_outputs and (node_id, port_id) not in declared_outputs:
            raise error_type("OUTPUT_UNDECLARED", f"output port {key} is unused and undeclared")
    external_input_ids: set[int] = set()
    for item in graph.inputs:
        if item.external_id in external_input_ids:
            raise error_type("DUPLICATE", "duplicate external input id")
        external_input_ids.add(item.external_id)
    external_output_ids: set[int] = set()
    for item in graph.outputs:
        if (item.source_node, 1, item.source_port) not in port_by_key:
            raise error_type("OUTPUT_PORT", "graph output must name an existing output port")
        if item.external_id in external_output_ids:
            raise error_type("DUPLICATE", "duplicate external output id")
        external_output_ids.add(item.external_id)

    ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
    visited = 0
    while ready:
        node_id = ready.pop(0)
        visited += 1
        for destination in sorted(adjacency[node_id]):
            indegree[destination] -= 1
            if indegree[destination] == 0:
                ready.append(destination)
                ready.sort()
    if visited != len(graph.nodes):
        raise error_type("GRAPH_CYCLE", "DCGG v1 admits no in-graph loops")


def encode_graph(graph: GraphV2) -> bytes:
    _validate_graph(graph, GraphError)
    w = _Writer(GraphError)
    w.data.extend(b"DCGG")
    w.uint(1, 2, "format_version")
    w.uint(0, 2, "flags")
    w.uint(0, 4, "body_length")
    w.uint(len(graph.nodes), 4, "node_count")
    w.uint(len(graph.ports), 4, "port_count")
    w.uint(len(graph.edges), 4, "edge_count")
    w.uint(len(graph.regions), 2, "region_count")
    w.uint(len(graph.inputs), 2, "input_count")
    w.uint(len(graph.outputs), 2, "output_count")
    w.uint(0, 2, "reserved")
    header_size = len(w.data)
    for node in graph.nodes:
        _write_node(w, node)
    for port in graph.ports:
        _write_port(w, port)
    for edge in graph.edges:
        _write_edge(w, edge)
    for region in graph.regions:
        _write_region(w, region)
    for item in graph.inputs:
        _write_graph_endpoint(w, item, True)
    for item in graph.outputs:
        _write_graph_endpoint(w, item, False)
    body_length = len(w.data) - header_size
    w.data[8:12] = body_length.to_bytes(4, "little")
    if len(w.data) > MAX_GRAPH_BYTES:
        raise GraphError("GRAPH_BYTE_LIMIT", f"DCGG exceeds {MAX_GRAPH_BYTES} bytes")
    return bytes(w.data)


def _decode_node(r: _Reader) -> NodeV1:
    q = r.record("node")
    node_id = q.uint(4, "node.node_id")
    kernel_id = q.fixed(16, "node.kernel_id")
    semantic_version = q.uint(2, "node.semantic_version")
    abi_version = q.uint(2, "node.abi_version")
    region_id = q.uint(4, "node.region_id")
    state_present = q.uint(1, "node.state_present")
    if state_present not in (0, 1):
        q.fail("PRESENCE", "state_present must be 0 or 1")
    state_schema_id = q.uint(4, "node.state_schema_id")
    state_schema_version = q.uint(2, "node.state_schema_version")
    max_state_bytes = q.uint(4, "node.max_state_bytes")
    parameter_layout_id = q.uint(4, "node.parameter_layout_id")
    parameter_layout_version = q.uint(2, "node.parameter_layout_version")
    parameters = q.fixed(q.uint(4, "node.parameter_length"), "node.parameter_bytes")
    q.finish("node")
    if not state_present and (state_schema_id or state_schema_version or max_state_bytes):
        q.fail("STATE_FIELDS", "absent state has nonzero fields")
    if state_present and not (state_schema_id and state_schema_version and max_state_bytes):
        q.fail("STATE_FIELDS", "present state needs nonzero schema/version/maximum")
    if len(parameters) > MAX_KERNEL_PARAMETER_BYTES:
        q.fail("PARAMETER_LIMIT", f"kernel parameters exceed {MAX_KERNEL_PARAMETER_BYTES}")
    if bool(parameters) != bool(parameter_layout_id and parameter_layout_version):
        q.fail("PARAMETER_FIELDS", "parameter bytes and layout id/version presence disagree")
    if not parameters and (parameter_layout_id or parameter_layout_version):
        q.fail("PARAMETER_FIELDS", "absent parameter block has nonzero layout fields")
    return NodeV1(
        node_id,
        kernel_id,
        semantic_version,
        abi_version,
        region_id,
        state_schema_id,
        state_schema_version,
        max_state_bytes,
        parameter_layout_id,
        parameter_layout_version,
        parameters,
    )


def _decode_port(r: _Reader) -> PortV1:
    q = r.record("port")
    node_id = q.uint(4, "port.node_id")
    direction = q.uint(1, "port.direction")
    port_id = q.uint(2, "port.port_id")
    layout_id = q.uint(4, "port.layout_id")
    layout_version = q.uint(2, "port.layout_version")
    scalar_type = q.uint(1, "port.scalar_type")
    rank = q.uint(1, "port.rank")
    alignment = q.uint(2, "port.alignment")
    reserved = q.uint(2, "port.reserved")
    byte_length = q.uint(4, "port.byte_length")
    max_byte_length = q.uint(4, "port.max_byte_length")
    if reserved:
        q.fail("RESERVED", "port reserved field must be zero")
    if rank > MAX_RANK:
        q.fail("RANK_LIMIT", f"rank exceeds {MAX_RANK}")
    dimensions = tuple(q.uint(4, f"port.dimensions[{index}]") for index in range(rank))
    q.finish("port")
    port = PortV1(node_id, direction, port_id, layout_id, layout_version, scalar_type, dimensions, alignment, byte_length, max_byte_length)
    _port_shape(port, GraphError)
    return port


def _decode_edge(r: _Reader) -> EdgeV1:
    q = r.record("edge")
    edge = EdgeV1(q.uint(4, "edge.source_node"), q.uint(2, "edge.source_port"), q.uint(4, "edge.destination_node"), q.uint(2, "edge.destination_port"))
    q.finish("edge")
    return edge


def _decode_region(r: _Reader) -> RegionV1:
    q = r.record("region")
    fixed = [q.uint(width, name) for width, name in (
        (4, "region.region_id"),
        (4, "region.parent_region_id"),
        (4, "region.mode_id"),
        (2, "region.mode_version"),
        (4, "region.scheme_id"),
        (2, "region.scheme_version"),
        (4, "region.layout_id"),
        (2, "region.layout_version"),
    )]
    payloads = [q.fixed(q.uint(4, f"region.{name}_parameter_length"), f"region.{name}_parameters") for name in ("mode", "scheme", "layout")]
    q.finish("region")
    return RegionV1(*fixed, *payloads)


def _decode_endpoint(r: _Reader, input_side: bool) -> GraphInputV1 | GraphOutputV1:
    q = r.record("graph endpoint")
    external_id = q.uint(4, "endpoint.external_id")
    node_id = q.uint(4, "endpoint.node_id")
    port_id = q.uint(2, "endpoint.port_id")
    reserved = q.uint(2, "endpoint.reserved")
    q.finish("graph endpoint")
    if reserved:
        q.fail("RESERVED", "graph endpoint reserved field must be zero")
    return GraphInputV1(external_id, node_id, port_id) if input_side else GraphOutputV1(external_id, node_id, port_id)


def decode_graph(data: bytes) -> GraphV2:
    if not isinstance(data, bytes):
        raise GraphError("TYPE", "DCGG input must be bytes")
    if len(data) > MAX_GRAPH_BYTES:
        raise GraphError("GRAPH_BYTE_LIMIT", f"DCGG exceeds {MAX_GRAPH_BYTES} bytes")
    r = _Reader(data, GraphError)
    if r.fixed(4, "magic") != b"DCGG":
        r.fail("MAGIC", "expected DCGG")
    version = r.uint(2, "format_version")
    if version != 1:
        r.fail("VERSION", f"unsupported DCGG version {version}")
    if r.uint(2, "flags") != 0:
        r.fail("FLAGS", "DCGG flags must be zero")
    body_length = r.uint(4, "body_length")
    node_count = r.uint(4, "node_count")
    port_count = r.uint(4, "port_count")
    edge_count = r.uint(4, "edge_count")
    region_count = r.uint(2, "region_count")
    input_count = r.uint(2, "input_count")
    output_count = r.uint(2, "output_count")
    if r.uint(2, "reserved") != 0:
        r.fail("RESERVED", "DCGG reserved field must be zero")
    if body_length != r.remaining:
        r.fail("BODY_LENGTH", "body length must equal bytes following the fixed header")
    if not 1 <= node_count <= MAX_NODES:
        r.fail("NODE_COUNT", f"node count must be in 1..{MAX_NODES}")
    if port_count > MAX_PORTS:
        r.fail("PORT_COUNT", f"port count exceeds {MAX_PORTS}")
    if edge_count > MAX_EDGES:
        r.fail("EDGE_COUNT", f"edge count exceeds {MAX_EDGES}")
    if not 1 <= region_count <= MAX_REGIONS:
        r.fail("REGION_COUNT", f"region count must be in 1..{MAX_REGIONS}")
    nodes = tuple(_decode_node(r) for _ in range(node_count))
    ports = tuple(_decode_port(r) for _ in range(port_count))
    edges = tuple(_decode_edge(r) for _ in range(edge_count))
    regions = tuple(_decode_region(r) for _ in range(region_count))
    inputs = tuple(_decode_endpoint(r, True) for _ in range(input_count))
    outputs = tuple(_decode_endpoint(r, False) for _ in range(output_count))
    r.finish("DCGG")
    graph = GraphV2(nodes, ports, edges, regions, inputs, outputs)
    _validate_graph(graph, GraphError)
    return graph


def _write_ref(w: _Writer, ref: PortRefV1) -> None:
    w.uint(ref.node_id, 4, "port_ref.node_id")
    w.uint(ref.direction, 1, "port_ref.direction")
    w.uint(ref.port_id, 2, "port_ref.port_id")


def _ref_key(ref: PortRefV1) -> tuple[int, int, int]:
    return ref.node_id, ref.direction, ref.port_id


def _write_plan_record(w: _Writer, error_type: type[ValueError], emit, field: str) -> None:
    local = _Writer(error_type)
    emit(local)
    w.uint(len(local.data), 4, f"{field}.record_length")
    w.data.extend(local.data)


def _validate_plan(plan: PlanV2, error_type: type[ValueError]) -> None:
    for value, width, name in (
        (plan.graph_id, 32, "graph_id"),
        (plan.compiler_id, 16, "compiler_id"),
        (plan.app_image_id, 32, "app_image_id"),
        (plan.kernel_manifest_root, 32, "kernel_manifest_root"),
    ):
        if not isinstance(value, bytes) or len(value) != width:
            raise error_type("FIXED_WIDTH", f"{name} must be exactly {width} bytes")
    if not plan.regions or len(plan.regions) > MAX_REGIONS:
        raise error_type("REGION_COUNT", f"plan region count must be in 1..{MAX_REGIONS}")
    if not plan.steps or len(plan.steps) > MAX_PLAN_STEPS:
        raise error_type("STEP_COUNT", f"plan step count must be in 1..{MAX_PLAN_STEPS}")
    if len(plan.segments) > MAX_PLAN_STEPS:
        raise error_type("SEGMENT_COUNT", f"segment count exceeds {MAX_PLAN_STEPS}")
    if len(plan.compiler_parameters) > MAX_PLAN_BYTES:
        raise error_type("PLAN_BYTE_LIMIT", "compiler parameters alone exceed plan byte ceiling")

    _strictly_sorted(plan.regions, lambda r: r.region_id, "ORDER", error_type)
    _strictly_sorted(plan.steps, lambda s: s.ordinal, "ORDER", error_type)
    _strictly_sorted(plan.segments, lambda s: (s.region_id, s.segment_id), "ORDER", error_type)
    _strictly_sorted(
        plan.boundaries,
        lambda b: (b.source_region, b.destination_region, _ref_key(b.source), _ref_key(b.destination)),
        "ORDER",
        error_type,
    )
    _strictly_sorted(
        plan.translations,
        lambda t: (
            t.source_scheme_id,
            t.source_version,
            t.target_scheme_id,
            t.target_version,
            t.relation_or_kernel_id,
            t.semantic_version,
            t.abi_version,
            t.input_layout_id,
            t.input_layout_version,
            t.output_layout_id,
            t.output_layout_version,
        ),
        "ORDER",
        error_type,
    )
    _strictly_sorted(plan.costs, lambda c: (c.scope_kind, c.region_id, c.step_ordinal), "ORDER", error_type)

    region_by_id = {item.region_id: item for item in plan.regions}
    if 0 not in region_by_id or region_by_id[0].parent_region_id != ROOT_PARENT:
        raise error_type("REGION_ROOT", "plan region zero must be the unique root")
    if sum(item.parent_region_id == ROOT_PARENT for item in plan.regions) != 1:
        raise error_type("REGION_ROOT", "plan requires exactly one root")
    for item in plan.regions:
        if item.region_id == ROOT_PARENT:
            raise error_type("REGION_ID_RESERVED", "0xffffffff is reserved")
        if item.region_id and item.parent_region_id not in region_by_id:
            raise error_type("REGION_PARENT", f"plan region {item.region_id} has unknown parent")
        _mode_ok(item.mode_id, item.mode_version, error_type)
        _scheme_ok(item.scheme_id, item.scheme_version, error_type)
        _layout_ok(item.layout_id, item.layout_version, error_type)
    for item in plan.regions:
        current = item
        seen: set[int] = set()
        depth = 1
        while current.region_id != 0:
            if current.region_id in seen:
                raise error_type("REGION_CYCLE", "plan region tree contains a cycle")
            seen.add(current.region_id)
            current = region_by_id[current.parent_region_id]
            depth += 1
            if depth > 8:
                raise error_type("REGION_DEPTH", "region-tree depth exceeds 8 including root")

    if tuple(step.ordinal for step in plan.steps) != tuple(range(len(plan.steps))):
        raise error_type("ORDINALS", "global step ordinals must be contiguous starting at zero")
    step_by_ordinal: dict[int, StepV1] = {}
    node_kernel_steps: set[tuple[int, int]] = set()
    for step in plan.steps:
        if step.region_id not in region_by_id:
            raise error_type("STEP_REGION", "step names unknown region")
        if not step.decomposition_id or not step.decomposition_version:
            raise error_type("STEP_ABI", "step decomposition ID/version must be nonzero")
        if type(step.node_id) is not int or not 0 <= step.node_id <= _U32_MAX:
            raise error_type("INTEGER_RANGE", "step node_id does not fit u32")
        if (step.node_id, step.kernel_step) in node_kernel_steps:
            raise error_type("DUPLICATE", "duplicate (node_id, kernel_step)")
        node_kernel_steps.add((step.node_id, step.kernel_step))
        _strictly_sorted(step.inputs, _ref_key, "ORDER", error_type)
        _strictly_sorted(step.outputs, _ref_key, "ORDER", error_type)
        if any(ref.direction != 0 for ref in step.inputs):
            raise error_type("DIRECTION", "step input references must use direction 0")
        if any(ref.direction != 1 for ref in step.outputs):
            raise error_type("DIRECTION", "step output references must use direction 1")
        step_by_ordinal[step.ordinal] = step
    step_counts = {region_id: 0 for region_id in region_by_id}
    for step in plan.steps:
        step_counts[step.region_id] += 1
    for item in plan.regions:
        if item.direct_step_count != step_counts[item.region_id]:
            raise error_type("REGION_STEP_COUNT", f"region {item.region_id} direct step count mismatch")

    segment_counts = {region_id: 0 for region_id in region_by_id}
    covered: list[tuple[int, int, int]] = []
    for segment in plan.segments:
        if segment.region_id not in region_by_id:
            raise error_type("SEGMENT_REGION", "segment names unknown region")
        if segment.step_count <= 0:
            raise error_type("SEGMENT_EMPTY", "segment step_count must be positive")
        region_plan = region_by_id[segment.region_id]
        if (segment.root_scheme_id, segment.root_scheme_version) != (region_plan.scheme_id, region_plan.scheme_version):
            raise error_type("SEGMENT_SCHEME", "segment root scheme differs from its region plan")
        if segment.first_step + segment.step_count > len(plan.steps):
            raise error_type("SEGMENT_RANGE", "segment range exceeds plan step count")
        segment_counts[segment.region_id] += 1
        for ordinal in range(segment.first_step, segment.first_step + segment.step_count):
            step = step_by_ordinal[ordinal]
            if (step.region_id, step.segment_id) != (segment.region_id, segment.segment_id):
                raise error_type("SEGMENT_MEMBERSHIP", "segment range and step coordinates disagree")
            covered.append((ordinal, segment.region_id, segment.segment_id))
    for item in plan.regions:
        if item.segment_count != segment_counts[item.region_id]:
            raise error_type("REGION_SEGMENT_COUNT", f"region {item.region_id} segment count mismatch")
        local_ids = tuple(segment.segment_id for segment in plan.segments if segment.region_id == item.region_id)
        if local_ids != tuple(range(len(local_ids))):
            raise error_type("SEGMENT_IDS", f"region {item.region_id} segment IDs must start at zero without gaps")
    if tuple(item[0] for item in sorted(covered)) != tuple(range(len(plan.steps))):
        raise error_type("SEGMENT_COVERAGE", "segments must cover each global ordinal exactly once")
    for step in plan.steps:
        if not any(
            segment.region_id == step.region_id
            and segment.segment_id == step.segment_id
            and segment.first_step <= step.ordinal < segment.first_step + segment.step_count
            for segment in plan.segments
        ):
            raise error_type("SEGMENT_MEMBERSHIP", "step does not belong to a declared segment")

    boundary_keys = set()
    for boundary in plan.boundaries:
        if boundary.source_region not in region_by_id or boundary.destination_region not in region_by_id:
            raise error_type("BOUNDARY_REGION", "boundary names unknown region")
        if boundary.source_region == boundary.destination_region:
            raise error_type("BOUNDARY_REGION", "boundary must cross region scopes")
        if boundary.source.direction != 1 or boundary.destination.direction != 0:
            raise error_type("BOUNDARY_DIRECTION", "boundary must connect output to input")
        _layout_ok(boundary.layout_id, boundary.layout_version, error_type)
        _scheme_ok(boundary.scheme_id, boundary.scheme_version, error_type)
        if bool(boundary.cursor_schema_id) != bool(boundary.cursor_schema_version):
            raise error_type("CURSOR_SCHEMA", "cursor schema id and version must be both zero or both nonzero")
        key = (boundary.source_region, boundary.destination_region, _ref_key(boundary.source), _ref_key(boundary.destination))
        if key in boundary_keys:
            raise error_type("DUPLICATE", "duplicate boundary")
        boundary_keys.add(key)
    if plan.translations:
        raise error_type("TRANSLATION_UNSUPPORTED", "profile 1 admits only one commitment scheme")
    for translation in plan.translations:
        if len(translation.relation_or_kernel_id) != 16:
            raise error_type("FIXED_WIDTH", "translation relation/kernel id must be 16 bytes")
        if translation.max_opening_bytes > MAX_OPENING_BYTES:
            raise error_type("OPENING_LIMIT", f"translation opening exceeds {MAX_OPENING_BYTES}")

    cost_keys = set()
    cost_steps: set[int] = set()
    cost_regions: set[int] = set()
    run_costs = 0
    for cost in plan.costs:
        if cost.scope_kind not in (1, 2, 3):
            raise error_type("COST_SCOPE", "scope_kind must be step=1, region=2, or run=3")
        key = (cost.scope_kind, cost.region_id, cost.step_ordinal)
        if key in cost_keys:
            raise error_type("DUPLICATE", "duplicate cost admission key")
        cost_keys.add(key)
        if cost.scope_kind == 1:
            if cost.region_id not in region_by_id or cost.step_ordinal not in step_by_ordinal:
                raise error_type("COST_REFERENCE", "step cost names unknown region/ordinal")
            if step_by_ordinal[cost.step_ordinal].region_id != cost.region_id:
                raise error_type("COST_REFERENCE", "step cost region does not match its step")
            cost_steps.add(cost.step_ordinal)
        elif cost.scope_kind == 2:
            if cost.region_id not in region_by_id or cost.step_ordinal != 0:
                raise error_type("COST_REFERENCE", "region cost uses unknown region or nonzero unused ordinal")
            cost_regions.add(cost.region_id)
        else:
            if cost.region_id != 0 or cost.step_ordinal != 0:
                raise error_type("COST_REFERENCE", "run cost unused keys must be zero")
            run_costs += 1
        if cost.max_opening_bytes > MAX_OPENING_BYTES:
            raise error_type("OPENING_LIMIT", f"cost opening exceeds {MAX_OPENING_BYTES}")
    if cost_steps != set(step_by_ordinal) or cost_regions != set(region_by_id) or run_costs != 1:
        raise error_type("COST_COVERAGE", "plan needs one cost record per step, region, and exactly one run")


def _encode_region_plan(w: _Writer, item: RegionPlanV1) -> None:
    _mode_ok(item.mode_id, item.mode_version, w.error_type)
    _scheme_ok(item.scheme_id, item.scheme_version, w.error_type)
    _layout_ok(item.layout_id, item.layout_version, w.error_type)

    def emit(b: _Writer) -> None:
        for value, width, name in (
            (item.region_id, 4, "region_id"),
            (item.parent_region_id, 4, "parent_region_id"),
            (item.mode_id, 4, "mode_id"),
            (item.mode_version, 2, "mode_version"),
            (item.scheme_id, 4, "scheme_id"),
            (item.scheme_version, 2, "scheme_version"),
            (item.layout_id, 4, "layout_id"),
            (item.layout_version, 2, "layout_version"),
            (item.direct_step_count, 4, "direct_step_count"),
            (item.segment_count, 4, "segment_count"),
        ):
            b.uint(value, width, f"region_plan.{name}")
        for name, payload in (("mode", item.mode_parameters), ("scheme", item.scheme_parameters), ("layout", item.layout_parameters)):
            b.blob(payload, f"region_plan.{name}_parameters")

    _write_plan_record(w, w.error_type, emit, "region_plan")


def _encode_step(w: _Writer, step: StepV1) -> None:
    def emit(b: _Writer) -> None:
        for value, width, name in (
            (step.ordinal, 8, "ordinal"),
            (step.region_id, 4, "region_id"),
            (step.segment_id, 4, "segment_id"),
            (step.node_id, 4, "node_id"),
            (step.kernel_step, 4, "kernel_step"),
            (step.decomposition_id, 4, "decomposition_id"),
            (step.decomposition_version, 2, "decomposition_version"),
        ):
            b.uint(value, width, f"step.{name}")
        b.uint(len(step.inputs), 2, "step.input_count")
        for ref in step.inputs:
            _write_ref(b, ref)
        b.uint(len(step.outputs), 2, "step.output_count")
        for ref in step.outputs:
            _write_ref(b, ref)

    _write_plan_record(w, w.error_type, emit, "step")


def _encode_segment(w: _Writer, item: SegmentV1) -> None:
    def emit(b: _Writer) -> None:
        for value, width, name in (
            (item.region_id, 4, "region_id"),
            (item.segment_id, 4, "segment_id"),
            (item.first_step, 8, "first_step"),
            (item.step_count, 4, "step_count"),
            (item.root_scheme_id, 4, "root_scheme_id"),
            (item.root_scheme_version, 2, "root_scheme_version"),
        ):
            b.uint(value, width, f"segment.{name}")

    _write_plan_record(w, w.error_type, emit, "segment")


def _encode_boundary(w: _Writer, item: BoundaryV1) -> None:
    def emit(b: _Writer) -> None:
        b.uint(item.source_region, 4, "boundary.source_region")
        b.uint(item.destination_region, 4, "boundary.destination_region")
        _write_ref(b, item.source)
        _write_ref(b, item.destination)
        for value, width, name in (
            (item.layout_id, 4, "layout_id"),
            (item.layout_version, 2, "layout_version"),
            (item.scheme_id, 4, "scheme_id"),
            (item.scheme_version, 2, "scheme_version"),
            (item.cursor_schema_id, 4, "cursor_schema_id"),
            (item.cursor_schema_version, 2, "cursor_schema_version"),
        ):
            b.uint(value, width, f"boundary.{name}")

    _write_plan_record(w, w.error_type, emit, "boundary")


def _encode_translation(w: _Writer, item: TranslationV1) -> None:
    def emit(b: _Writer) -> None:
        for value, width, name in (
            (item.source_scheme_id, 4, "source_scheme_id"),
            (item.source_version, 2, "source_version"),
            (item.target_scheme_id, 4, "target_scheme_id"),
            (item.target_version, 2, "target_version"),
        ):
            b.uint(value, width, f"translation.{name}")
        b.fixed(item.relation_or_kernel_id, 16, "translation.relation_or_kernel_id")
        for value, width, name in (
            (item.semantic_version, 2, "semantic_version"),
            (item.abi_version, 2, "abi_version"),
            (item.input_layout_id, 4, "input_layout_id"),
            (item.input_layout_version, 2, "input_layout_version"),
            (item.output_layout_id, 4, "output_layout_id"),
            (item.output_layout_version, 2, "output_layout_version"),
            (item.max_input_bytes, 4, "max_input_bytes"),
            (item.max_output_bytes, 4, "max_output_bytes"),
            (item.max_cu, 8, "max_cu"),
            (item.max_accounts, 2, "max_accounts"),
            (item.max_opening_bytes, 4, "max_opening_bytes"),
        ):
            b.uint(value, width, f"translation.{name}")

    _write_plan_record(w, w.error_type, emit, "translation")


def _encode_cost(w: _Writer, item: CostAdmissionV1) -> None:
    def emit(b: _Writer) -> None:
        b.uint(item.scope_kind, 1, "cost.scope_kind")
        b.uint(item.region_id, 4, "cost.region_id")
        b.uint(item.step_ordinal, 8, "cost.step_ordinal")
        b.uint(item.max_cu, 8, "cost.max_cu")
        b.uint(item.max_accounts, 2, "cost.max_accounts")
        for name in (
            "max_read_bytes",
            "max_write_bytes",
            "max_operations",
            "max_heap_bytes",
            "max_stack_bytes",
            "max_input_bytes",
            "max_output_bytes",
            "max_state_bytes",
            "max_opening_bytes",
        ):
            b.uint(getattr(item, name), 4, f"cost.{name}")

    _write_plan_record(w, w.error_type, emit, "cost")


def encode_plan(plan: PlanV2) -> bytes:
    _validate_plan(plan, PlanError)
    w = _Writer(PlanError)
    w.data.extend(b"DCPL")
    w.uint(1, 2, "format_version")
    w.uint(0, 2, "flags")
    w.uint(0, 4, "body_length")
    w.fixed(plan.graph_id, 32, "graph_id")
    w.fixed(plan.compiler_id, 16, "compiler_id")
    w.uint(plan.compiler_version, 2, "compiler_version")
    w.uint(plan.frontend_version, 2, "frontend_version")
    w.uint(plan.lowering_version, 2, "lowering_version")
    w.uint(plan.admission_ruleset_id, 4, "admission_ruleset_id")
    w.uint(plan.admission_ruleset_version, 2, "admission_ruleset_version")
    w.fixed(plan.app_image_id, 32, "app_image_id")
    w.fixed(plan.kernel_manifest_root, 32, "kernel_manifest_root")
    w.uint(len(plan.regions), 2, "region_count")
    for value, name in (
        (len(plan.steps), "step_count"),
        (len(plan.segments), "segment_count"),
        (len(plan.boundaries), "boundary_count"),
        (len(plan.translations), "translation_count"),
        (len(plan.costs), "cost_count"),
        (len(plan.compiler_parameters), "compiler_parameter_length"),
    ):
        w.uint(value, 4, name)
    w.data.extend(plan.compiler_parameters)
    records_start = 162 + len(plan.compiler_parameters)
    for item in plan.regions:
        _encode_region_plan(w, item)
    for item in plan.steps:
        _encode_step(w, item)
    for item in plan.segments:
        _encode_segment(w, item)
    for item in plan.boundaries:
        _encode_boundary(w, item)
    for item in plan.translations:
        _encode_translation(w, item)
    for item in plan.costs:
        _encode_cost(w, item)
    w.data[8:12] = (len(w.data) - 162).to_bytes(4, "little")
    if len(w.data) > MAX_PLAN_BYTES:
        raise PlanError("PLAN_BYTE_LIMIT", f"DCPL exceeds {MAX_PLAN_BYTES} bytes")
    return bytes(w.data)


def _decode_port_ref(r: _Reader, field: str) -> PortRefV1:
    return PortRefV1(r.uint(4, f"{field}.node_id"), r.uint(1, f"{field}.direction"), r.uint(2, f"{field}.port_id"))


def _decode_record(r: _Reader, field: str, decode):
    q = r.record(field)
    result = decode(q)
    q.finish(field)
    return result


def _decode_region_plan(r: _Reader) -> RegionPlanV1:
    def parse(q: _Reader) -> RegionPlanV1:
        values = [q.uint(width, name) for width, name in (
            (4, "region_plan.region_id"),
            (4, "region_plan.parent_region_id"),
            (4, "region_plan.mode_id"),
            (2, "region_plan.mode_version"),
            (4, "region_plan.scheme_id"),
            (2, "region_plan.scheme_version"),
            (4, "region_plan.layout_id"),
            (2, "region_plan.layout_version"),
            (4, "region_plan.direct_step_count"),
            (4, "region_plan.segment_count"),
        )]
        params = [q.blob(f"region_plan.{name}_parameters") for name in ("mode", "scheme", "layout")]
        return RegionPlanV1(*values, *params)

    return _decode_record(r, "region_plan", parse)


def _decode_step(r: _Reader) -> StepV1:
    def parse(q: _Reader) -> StepV1:
        ordinal = q.uint(8, "step.ordinal")
        region_id = q.uint(4, "step.region_id")
        segment_id = q.uint(4, "step.segment_id")
        node_id = q.uint(4, "step.node_id")
        kernel_step = q.uint(4, "step.kernel_step")
        decomposition_id = q.uint(4, "step.decomposition_id")
        decomposition_version = q.uint(2, "step.decomposition_version")
        inputs = tuple(_decode_port_ref(q, f"step.inputs[{index}]") for index in range(q.uint(2, "step.input_count")))
        outputs = tuple(_decode_port_ref(q, f"step.outputs[{index}]") for index in range(q.uint(2, "step.output_count")))
        return StepV1(ordinal, region_id, segment_id, node_id, kernel_step, decomposition_id, decomposition_version, inputs, outputs)

    return _decode_record(r, "step", parse)


def _decode_segment(r: _Reader) -> SegmentV1:
    def parse(q: _Reader) -> SegmentV1:
        return SegmentV1(q.uint(4, "segment.region_id"), q.uint(4, "segment.segment_id"), q.uint(8, "segment.first_step"), q.uint(4, "segment.step_count"), q.uint(4, "segment.root_scheme_id"), q.uint(2, "segment.root_scheme_version"))

    return _decode_record(r, "segment", parse)


def _decode_boundary(r: _Reader) -> BoundaryV1:
    def parse(q: _Reader) -> BoundaryV1:
        source_region = q.uint(4, "boundary.source_region")
        destination_region = q.uint(4, "boundary.destination_region")
        source = _decode_port_ref(q, "boundary.source")
        destination = _decode_port_ref(q, "boundary.destination")
        return BoundaryV1(source_region, destination_region, source, destination, q.uint(4, "boundary.layout_id"), q.uint(2, "boundary.layout_version"), q.uint(4, "boundary.scheme_id"), q.uint(2, "boundary.scheme_version"), q.uint(4, "boundary.cursor_schema_id"), q.uint(2, "boundary.cursor_schema_version"))

    return _decode_record(r, "boundary", parse)


def _decode_translation(r: _Reader) -> TranslationV1:
    def parse(q: _Reader) -> TranslationV1:
        source_scheme_id = q.uint(4, "translation.source_scheme_id")
        source_version = q.uint(2, "translation.source_version")
        target_scheme_id = q.uint(4, "translation.target_scheme_id")
        target_version = q.uint(2, "translation.target_version")
        relation_id = q.fixed(16, "translation.relation_or_kernel_id")
        rest = [q.uint(width, name) for width, name in (
            (2, "translation.semantic_version"),
            (2, "translation.abi_version"),
            (4, "translation.input_layout_id"),
            (2, "translation.input_layout_version"),
            (4, "translation.output_layout_id"),
            (2, "translation.output_layout_version"),
            (4, "translation.max_input_bytes"),
            (4, "translation.max_output_bytes"),
            (8, "translation.max_cu"),
            (2, "translation.max_accounts"),
            (4, "translation.max_opening_bytes"),
        )]
        return TranslationV1(source_scheme_id, source_version, target_scheme_id, target_version, relation_id, *rest)

    return _decode_record(r, "translation", parse)


def _decode_cost(r: _Reader) -> CostAdmissionV1:
    def parse(q: _Reader) -> CostAdmissionV1:
        head = [q.uint(width, name) for width, name in ((1, "cost.scope_kind"), (4, "cost.region_id"), (8, "cost.step_ordinal"), (8, "cost.max_cu"), (2, "cost.max_accounts"))]
        rest = [q.uint(4, f"cost.{name}") for name in ("max_read_bytes", "max_write_bytes", "max_operations", "max_heap_bytes", "max_stack_bytes", "max_input_bytes", "max_output_bytes", "max_state_bytes", "max_opening_bytes")]
        return CostAdmissionV1(*head, *rest)

    return _decode_record(r, "cost", parse)


def decode_plan(data: bytes) -> PlanV2:
    if not isinstance(data, bytes):
        raise PlanError("TYPE", "DCPL input must be bytes")
    if len(data) > MAX_PLAN_BYTES:
        raise PlanError("PLAN_BYTE_LIMIT", f"DCPL exceeds {MAX_PLAN_BYTES} bytes")
    r = _Reader(data, PlanError)
    if r.fixed(4, "magic") != b"DCPL":
        r.fail("MAGIC", "expected DCPL")
    version = r.uint(2, "format_version")
    if version != 1:
        r.fail("VERSION", f"unsupported DCPL version {version}")
    if r.uint(2, "flags") != 0:
        r.fail("FLAGS", "DCPL flags must be zero")
    body_length = r.uint(4, "body_length")
    graph = r.fixed(32, "graph_id")
    compiler = r.fixed(16, "compiler_id")
    compiler_version = r.uint(2, "compiler_version")
    frontend_version = r.uint(2, "frontend_version")
    lowering_version = r.uint(2, "lowering_version")
    ruleset_id = r.uint(4, "admission_ruleset_id")
    ruleset_version = r.uint(2, "admission_ruleset_version")
    image_id = r.fixed(32, "app_image_id")
    manifest_root = r.fixed(32, "kernel_manifest_root")
    region_count = r.uint(2, "region_count")
    step_count = r.uint(4, "step_count")
    segment_count = r.uint(4, "segment_count")
    boundary_count = r.uint(4, "boundary_count")
    translation_count = r.uint(4, "translation_count")
    cost_count = r.uint(4, "cost_count")
    compiler_parameter_length = r.uint(4, "compiler_parameter_length")
    if not 1 <= region_count <= MAX_REGIONS:
        r.fail("REGION_COUNT", f"region count must be in 1..{MAX_REGIONS}")
    if not 1 <= step_count <= MAX_PLAN_STEPS:
        r.fail("STEP_COUNT", f"step count must be in 1..{MAX_PLAN_STEPS}")
    if segment_count > MAX_PLAN_STEPS:
        r.fail("SEGMENT_COUNT", f"segment count exceeds {MAX_PLAN_STEPS}")
    if body_length != r.remaining:
        r.fail("BODY_LENGTH", "body length must equal bytes following the fixed header")
    params = r.fixed(compiler_parameter_length, "compiler_parameters")
    regions = tuple(_decode_region_plan(r) for _ in range(region_count))
    steps = tuple(_decode_step(r) for _ in range(step_count))
    segments = tuple(_decode_segment(r) for _ in range(segment_count))
    boundaries = tuple(_decode_boundary(r) for _ in range(boundary_count))
    translations = tuple(_decode_translation(r) for _ in range(translation_count))
    costs = tuple(_decode_cost(r) for _ in range(cost_count))
    r.finish("DCPL")
    plan = PlanV2(graph, compiler, compiler_version, frontend_version, lowering_version, ruleset_id, ruleset_version, image_id, manifest_root, params, regions, steps, segments, boundaries, translations, costs)
    _validate_plan(plan, PlanError)
    return plan


def _manifest_record(w: _Writer, emit) -> None:
    body = _Writer(GraphError)
    emit(body)
    w.uint(len(body.data), 4, "manifest.record_length")
    w.data.extend(body.data)


def _validate_manifest(manifest: KernelManifestV1) -> None:
    if not manifest.kernels or len(manifest.kernels) > MAX_NODES:
        raise GraphError("KERNEL_COUNT", f"kernel count must be in 1..{MAX_NODES}")
    _strictly_sorted(
        manifest.kernels,
        lambda k: (k.kernel_id, k.semantic_version, k.abi_version),
        "ORDER",
        GraphError,
    )
    for kernel in manifest.kernels:
        if len(kernel.kernel_id) != 16 or len(kernel.implementation_id) != 32:
            raise GraphError("FIXED_WIDTH", "kernel ID/image identity has the wrong width")
        if not kernel.semantic_version or not kernel.abi_version:
            raise GraphError("VERSION", "kernel semantic and ABI versions must be nonzero")
        if kernel.max_parameter_bytes > MAX_KERNEL_PARAMETER_BYTES:
            raise GraphError("PARAMETER_LIMIT", "kernel maximum parameter bytes exceed 64 KiB")
        if bool(kernel.max_parameter_bytes) != bool(kernel.parameter_layout_id and kernel.parameter_layout_version):
            raise GraphError("PARAMETER_FIELDS", "parameter maximum and layout presence disagree")
        _strictly_sorted(kernel.ports, lambda p: (p.direction, p.port_id), "ORDER", GraphError)
        if any(port.direction not in (0, 1) for port in kernel.ports):
            raise GraphError("DIRECTION", "capability port direction must be 0 or 1")
        for port in kernel.ports:
            if not port.layout_id or not port.layout_version:
                raise GraphError("PORT_LAYOUT", "capability port layout id/version must be nonzero")
            if port.byte_order != (0 if port.scalar_type == 9 else 1):
                raise GraphError("BYTE_ORDER", "integer ports are little-endian and opaque ports use byte_order=0")
            if port.mutability != port.direction:
                raise GraphError("MUTABILITY", "input is read-only and output is kernel-written")
            if port.alias_rule not in (0, 1, 2):
                raise GraphError("ALIAS_RULE", "unknown alias rule")
            shape_bytes = 1
            for dim in port.dimensions:
                shape_bytes *= dim
                if shape_bytes > _U32_MAX:
                    raise GraphError("OVERFLOW", "capability port shape product exceeds u32")
            shape_bytes *= _SCALAR_WIDTHS.get(port.scalar_type, 0)
            shape = PortV1(0, port.direction, port.port_id, port.layout_id, port.layout_version, port.scalar_type, port.dimensions, port.alignment, shape_bytes, port.max_byte_length)
            _port_shape(shape, GraphError)
        _strictly_sorted(kernel.state_components, lambda c: c.component_id, "ORDER", GraphError)
        if kernel.state_present:
            if not (kernel.state_schema_id and kernel.state_schema_version and kernel.max_state_bytes):
                raise GraphError("STATE_FIELDS", "state capability needs schema id/version and maximum")
            if len(kernel.initial_state) > kernel.max_state_bytes:
                raise GraphError("STATE_INITIAL", "initial state exceeds maximum")
            if bool(kernel.cursor_schema_id) != bool(kernel.cursor_schema_version):
                raise GraphError("CURSOR_SCHEMA", "cursor schema ID/version must both be zero or nonzero")
        elif any((kernel.state_schema_id, kernel.state_schema_version, kernel.max_state_bytes, kernel.cursor_schema_id, kernel.cursor_schema_version, kernel.initial_state, kernel.complete_state_commitment, kernel.state_components)):
            raise GraphError("STATE_FIELDS", "absent state fields must all be zero or empty")
        for component in kernel.state_components:
            if not (component.layout_id and component.layout_version):
                raise GraphError("STATE_LAYOUT", "state component layout id/version must be nonzero")
            if len(component.initial_bytes) > component.max_write_bytes:
                raise GraphError("STATE_INITIAL", "component initial bytes exceed max_write_bytes")
        if not (kernel.step_abi_id and kernel.step_abi_version and kernel.decomposition_id and kernel.decomposition_version):
            raise GraphError("STEP_ABI", "step ABI and decomposition identities/versions must be nonzero")
        if not 1 <= kernel.max_step_count <= MAX_PLAN_STEPS:
            raise GraphError("STEP_COUNT", f"kernel max_step_count must be in 1..{MAX_PLAN_STEPS}")
        if type(kernel.whole_sweep_supported) is not bool or type(kernel.state_present) is not bool or type(kernel.complete_state_commitment) is not bool:
            raise GraphError("BOOLEAN", "manifest Boolean fields must be bool")
        _strictly_sorted(kernel.modes, lambda m: (m.mode_id, m.version), "ORDER", GraphError)
        for mode in kernel.modes:
            if not mode.version:
                raise GraphError("VERSION", "mode version must be nonzero")
            _strictly_sorted(mode.required_capabilities, lambda c: (c[0], c[1]), "ORDER", GraphError)
            if any(len(cap_id) != 16 or not cap_version for cap_id, cap_version in mode.required_capabilities):
                raise GraphError("CAPABILITY_ID", "capability references need 16-byte IDs and nonzero versions")
            _strictly_sorted(mode.schemes, lambda scheme: scheme, "ORDER", GraphError)
            for scheme_id, scheme_version in mode.schemes:
                _scheme_ok(scheme_id, scheme_version, GraphError)
            replay = mode.replay
            if replay is not None:
                if not replay.abi_id or not replay.abi_version:
                    raise GraphError("REPLAY_ABI", "replay ABI ID/version must be nonzero")
                if replay.max_opening_bytes > MAX_OPENING_BYTES:
                    raise GraphError("OPENING_LIMIT", f"replay opening exceeds {MAX_OPENING_BYTES}")
        _strictly_sorted(kernel.error_mappings, lambda e: e.condition_id, "ORDER", GraphError)
        if any(not item.condition_id or not item.stable_error_code for item in kernel.error_mappings):
            raise GraphError("ERROR_MAPPING", "condition and stable error IDs must be nonzero")


def encode_kernel_manifest(manifest: KernelManifestV1) -> bytes:
    """Encode a canonical DCKC v1 kernel capability manifest."""
    _validate_manifest(manifest)
    w = _Writer(GraphError)
    w.data.extend(b"DCKC")
    w.uint(1, 2, "manifest.format_version")
    w.uint(0, 2, "manifest.flags")
    w.uint(0, 4, "manifest.body_length")
    w.uint(len(manifest.kernels), 4, "manifest.kernel_count")
    header_size = len(w.data)
    for kernel in manifest.kernels:
        def emit(b: _Writer, kernel=kernel) -> None:
            b.fixed(kernel.kernel_id, 16, "kernel.kernel_id")
            b.uint(kernel.semantic_version, 2, "kernel.semantic_version")
            b.uint(kernel.abi_version, 2, "kernel.abi_version")
            b.fixed(kernel.implementation_id, 32, "kernel.implementation_id")
            b.uint(kernel.parameter_layout_id, 4, "kernel.parameter_layout_id")
            b.uint(kernel.parameter_layout_version, 2, "kernel.parameter_layout_version")
            b.uint(kernel.max_parameter_bytes, 4, "kernel.max_parameter_bytes")
            inputs = tuple(port for port in kernel.ports if port.direction == 0)
            outputs = tuple(port for port in kernel.ports if port.direction == 1)
            b.uint(len(inputs), 2, "kernel.input_port_count")
            b.uint(len(outputs), 2, "kernel.output_port_count")
            for port in kernel.ports:
                b.uint(port.port_id, 2, "port.port_id")
                b.uint(port.layout_id, 4, "port.layout_id")
                b.uint(port.layout_version, 2, "port.layout_version")
                b.uint(port.scalar_type, 1, "port.scalar_type")
                b.uint(len(port.dimensions), 1, "port.rank")
                b.uint(port.byte_order, 1, "port.byte_order")
                b.uint(port.alignment, 2, "port.alignment")
                b.uint(port.mutability, 1, "port.mutability")
                b.uint(port.alias_rule, 1, "port.alias_rule")
                b.uint(port.max_byte_length, 4, "port.max_byte_length")
                for dim in port.dimensions:
                    b.uint(dim, 4, "port.dimension")
            b.uint(1 if kernel.state_present else 0, 1, "kernel.state_present")
            b.uint(kernel.state_schema_id, 4, "kernel.state_schema_id")
            b.uint(kernel.state_schema_version, 2, "kernel.state_schema_version")
            b.uint(kernel.max_state_bytes, 4, "kernel.max_state_bytes")
            b.uint(kernel.cursor_schema_id, 4, "kernel.cursor_schema_id")
            b.uint(kernel.cursor_schema_version, 2, "kernel.cursor_schema_version")
            b.blob(kernel.initial_state, "kernel.initial_state")
            b.uint(1 if kernel.complete_state_commitment else 0, 1, "kernel.complete_state_commitment")
            b.uint(len(kernel.state_components), 2, "kernel.state_component_count")
            for component in kernel.state_components:
                b.uint(component.component_id, 2, "state_component.component_id")
                b.uint(component.layout_id, 4, "state_component.layout_id")
                b.uint(component.layout_version, 2, "state_component.layout_version")
                b.uint(component.max_read_bytes, 4, "state_component.max_read_bytes")
                b.uint(component.max_write_bytes, 4, "state_component.max_write_bytes")
                b.blob(component.initial_bytes, "state_component.initial_bytes")
            b.uint(kernel.step_abi_id, 4, "kernel.step_abi_id")
            b.uint(kernel.step_abi_version, 2, "kernel.step_abi_version")
            b.uint(kernel.decomposition_id, 4, "kernel.decomposition_id")
            b.uint(kernel.decomposition_version, 2, "kernel.decomposition_version")
            b.uint(kernel.max_step_count, 4, "kernel.max_step_count")
            b.uint(1 if kernel.whole_sweep_supported else 0, 1, "kernel.whole_sweep_supported")
            b.uint(len(kernel.modes), 2, "kernel.mode_count")
            for mode in kernel.modes:
                b.uint(mode.mode_id, 4, "mode.mode_id")
                b.uint(mode.version, 2, "mode.version")
                b.uint(len(mode.required_capabilities), 2, "mode.required_capability_count")
                for capability_id, capability_version in mode.required_capabilities:
                    b.fixed(capability_id, 16, "mode.capability_id")
                    b.uint(capability_version, 2, "mode.capability_version")
                b.uint(len(mode.schemes), 2, "mode.scheme_count")
                for scheme_id, scheme_version in mode.schemes:
                    b.uint(scheme_id, 4, "mode.scheme_id")
                    b.uint(scheme_version, 2, "mode.scheme_version")
                replay = mode.replay
                b.uint(1 if replay is not None else 0, 1, "mode.replay_present")
                replay_values = replay or ReplayCapabilityV1(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                for value, width, name in (
                    (replay_values.abi_id, 4, "replay.abi_id"),
                    (replay_values.abi_version, 2, "replay.abi_version"),
                    (replay_values.max_input_spans, 2, "replay.max_input_spans"),
                    (replay_values.max_prior_state_bytes, 4, "replay.max_prior_state_bytes"),
                    (replay_values.max_output_bytes, 4, "replay.max_output_bytes"),
                    (replay_values.max_next_state_bytes, 4, "replay.max_next_state_bytes"),
                    (replay_values.max_authentication_path_nodes, 2, "replay.max_authentication_path_nodes"),
                    (replay_values.max_opening_bytes, 4, "replay.max_opening_bytes"),
                    (replay_values.allowed_account_roles, 4, "replay.allowed_account_roles"),
                    (replay_values.max_svm_cu, 8, "replay.max_svm_cu"),
                ):
                    b.uint(value, width, name)
            for value, width, name in (
                (kernel.max_input_bytes, 4, "kernel.max_input_bytes"),
                (kernel.max_output_bytes, 4, "kernel.max_output_bytes"),
                (kernel.max_operations, 4, "kernel.max_operations"),
                (kernel.max_accounts, 2, "kernel.max_accounts"),
                (kernel.max_cu, 8, "kernel.max_cu"),
                (kernel.max_heap_bytes, 4, "kernel.max_heap_bytes"),
                (kernel.max_stack_bytes, 4, "kernel.max_stack_bytes"),
                (kernel.max_concurrent_live_states, 4, "kernel.max_concurrent_live_states"),
                (kernel.max_live_state_bytes, 4, "kernel.max_live_state_bytes"),
            ):
                b.uint(value, width, name)
            b.uint(len(kernel.error_mappings), 2, "kernel.error_mapping_count")
            for mapping in kernel.error_mappings:
                b.uint(mapping.condition_id, 2, "error_mapping.condition_id")
                b.uint(mapping.stable_error_code, 2, "error_mapping.stable_error_code")

        _manifest_record(w, emit)
    w.data[8:12] = (len(w.data) - header_size).to_bytes(4, "little")
    if len(w.data) > MAX_MANIFEST_BYTES:
        raise GraphError("MANIFEST_BYTE_LIMIT", f"DCKC exceeds {MAX_MANIFEST_BYTES} bytes")
    return bytes(w.data)


def _decode_manifest_record(r: _Reader) -> KernelCapabilityV1:
    q = r.record("kernel")
    kernel_id = q.fixed(16, "kernel.kernel_id")
    semantic_version = q.uint(2, "kernel.semantic_version")
    abi_version = q.uint(2, "kernel.abi_version")
    implementation_id = q.fixed(32, "kernel.implementation_id")
    parameter_layout_id = q.uint(4, "kernel.parameter_layout_id")
    parameter_layout_version = q.uint(2, "kernel.parameter_layout_version")
    max_parameter_bytes = q.uint(4, "kernel.max_parameter_bytes")
    input_count = q.uint(2, "kernel.input_port_count")
    output_count = q.uint(2, "kernel.output_port_count")
    ports: list[CapabilityPortV1] = []
    for direction, count in ((0, input_count), (1, output_count)):
        for index in range(count):
            port_id = q.uint(2, f"port[{direction},{index}].port_id")
            layout_id = q.uint(4, "port.layout_id")
            layout_version = q.uint(2, "port.layout_version")
            scalar_type = q.uint(1, "port.scalar_type")
            rank = q.uint(1, "port.rank")
            byte_order = q.uint(1, "port.byte_order")
            alignment = q.uint(2, "port.alignment")
            mutability = q.uint(1, "port.mutability")
            alias_rule = q.uint(1, "port.alias_rule")
            max_byte_length = q.uint(4, "port.max_byte_length")
            if rank > MAX_RANK:
                q.fail("RANK_LIMIT", f"capability port rank exceeds {MAX_RANK}")
            dimensions = tuple(q.uint(4, "port.dimension") for _ in range(rank))
            ports.append(CapabilityPortV1(direction, port_id, layout_id, layout_version, scalar_type, dimensions, byte_order, alignment, mutability, alias_rule, max_byte_length))
    state_present = q.uint(1, "kernel.state_present")
    if state_present not in (0, 1):
        q.fail("PRESENCE", "state_present must be 0 or 1")
    state_schema_id = q.uint(4, "kernel.state_schema_id")
    state_schema_version = q.uint(2, "kernel.state_schema_version")
    max_state_bytes = q.uint(4, "kernel.max_state_bytes")
    cursor_schema_id = q.uint(4, "kernel.cursor_schema_id")
    cursor_schema_version = q.uint(2, "kernel.cursor_schema_version")
    initial_state = q.blob("kernel.initial_state")
    complete_state_commitment = q.uint(1, "kernel.complete_state_commitment")
    if complete_state_commitment not in (0, 1):
        q.fail("BOOLEAN", "complete_state_commitment must be 0 or 1")
    state_components = []
    for _ in range(q.uint(2, "kernel.state_component_count")):
        state_components.append(StateComponentV1(q.uint(2, "state_component.component_id"), q.uint(4, "state_component.layout_id"), q.uint(2, "state_component.layout_version"), q.uint(4, "state_component.max_read_bytes"), q.uint(4, "state_component.max_write_bytes"), q.blob("state_component.initial_bytes")))
    step_abi_id = q.uint(4, "kernel.step_abi_id")
    step_abi_version = q.uint(2, "kernel.step_abi_version")
    decomposition_id = q.uint(4, "kernel.decomposition_id")
    decomposition_version = q.uint(2, "kernel.decomposition_version")
    max_step_count = q.uint(4, "kernel.max_step_count")
    whole_sweep_supported = q.uint(1, "kernel.whole_sweep_supported")
    if whole_sweep_supported not in (0, 1):
        q.fail("BOOLEAN", "whole_sweep_supported must be 0 or 1")
    modes = []
    for _ in range(q.uint(2, "kernel.mode_count")):
        mode_id = q.uint(4, "mode.mode_id")
        mode_version = q.uint(2, "mode.version")
        caps = tuple((q.fixed(16, "mode.capability_id"), q.uint(2, "mode.capability_version")) for _ in range(q.uint(2, "mode.required_capability_count")))
        schemes = tuple((q.uint(4, "mode.scheme_id"), q.uint(2, "mode.scheme_version")) for _ in range(q.uint(2, "mode.scheme_count")))
        replay_present = q.uint(1, "mode.replay_present")
        if replay_present not in (0, 1):
            q.fail("PRESENCE", "replay_present must be 0 or 1")
        replay_values = [q.uint(width, name) for width, name in (
            (4, "replay.abi_id"),
            (2, "replay.abi_version"),
            (2, "replay.max_input_spans"),
            (4, "replay.max_prior_state_bytes"),
            (4, "replay.max_output_bytes"),
            (4, "replay.max_next_state_bytes"),
            (2, "replay.max_authentication_path_nodes"),
            (4, "replay.max_opening_bytes"),
            (4, "replay.allowed_account_roles"),
            (8, "replay.max_svm_cu"),
        )]
        replay = ReplayCapabilityV1(*replay_values) if replay_present else None
        if not replay_present and any(replay_values):
            q.fail("PRESENCE_FIELDS", "absent replay declaration has nonzero fields")
        modes.append(ModeCapabilityV1(mode_id, mode_version, caps, schemes, replay))
    resources = [q.uint(width, name) for width, name in (
        (4, "kernel.max_input_bytes"),
        (4, "kernel.max_output_bytes"),
        (4, "kernel.max_operations"),
        (2, "kernel.max_accounts"),
        (8, "kernel.max_cu"),
        (4, "kernel.max_heap_bytes"),
        (4, "kernel.max_stack_bytes"),
        (4, "kernel.max_concurrent_live_states"),
        (4, "kernel.max_live_state_bytes"),
    )]
    error_mappings = tuple(ErrorMappingV1(q.uint(2, "error_mapping.condition_id"), q.uint(2, "error_mapping.stable_error_code")) for _ in range(q.uint(2, "kernel.error_mapping_count")))
    q.finish("kernel")
    return KernelCapabilityV1(kernel_id, semantic_version, abi_version, implementation_id, parameter_layout_id, parameter_layout_version, max_parameter_bytes, tuple(ports), bool(state_present), state_schema_id, state_schema_version, max_state_bytes, cursor_schema_id, cursor_schema_version, initial_state, bool(complete_state_commitment), tuple(state_components), step_abi_id, step_abi_version, decomposition_id, decomposition_version, max_step_count, bool(whole_sweep_supported), tuple(modes), *resources, error_mappings)


def decode_kernel_manifest(data: bytes) -> KernelManifestV1:
    if not isinstance(data, bytes):
        raise GraphError("TYPE", "DCKC input must be bytes")
    if len(data) > MAX_MANIFEST_BYTES:
        raise GraphError("MANIFEST_BYTE_LIMIT", f"DCKC exceeds {MAX_MANIFEST_BYTES} bytes")
    r = _Reader(data, GraphError)
    if r.fixed(4, "magic") != b"DCKC":
        r.fail("MAGIC", "expected DCKC")
    version = r.uint(2, "format_version")
    if version != 1:
        r.fail("VERSION", f"unsupported DCKC version {version}")
    if r.uint(2, "flags") != 0:
        r.fail("FLAGS", "DCKC flags must be zero")
    body_length = r.uint(4, "body_length")
    count = r.uint(4, "kernel_count")
    if body_length != r.remaining:
        r.fail("BODY_LENGTH", "DCKC body length mismatch")
    if not 1 <= count <= MAX_NODES:
        r.fail("KERNEL_COUNT", f"kernel count must be in 1..{MAX_NODES}")
    manifest = KernelManifestV1(tuple(_decode_manifest_record(r) for _ in range(count)))
    r.finish("DCKC")
    _validate_manifest(manifest)
    return manifest


def graph_id(canonical_graph_bytes: bytes) -> bytes:
    decode_graph(canonical_graph_bytes)
    return hashlib.sha256(_GRAPH_DOMAIN + canonical_graph_bytes).digest()


def plan_id(canonical_plan_bytes: bytes) -> bytes:
    decode_plan(canonical_plan_bytes)
    return hashlib.sha256(_PLAN_DOMAIN + canonical_plan_bytes).digest()


def kernel_manifest_root(canonical_manifest_bytes: bytes) -> bytes:
    decode_kernel_manifest(canonical_manifest_bytes)
    return hashlib.sha256(_MANIFEST_DOMAIN + canonical_manifest_bytes).digest()


def template_id(graph: bytes, plan: bytes, app_image_id: bytes, manifest_root: bytes) -> bytes:
    if len(graph) != 32 or len(plan) != 32 or len(app_image_id) != 32 or len(manifest_root) != 32:
        raise GraphError("FIXED_WIDTH", "template identity components must each be 32 bytes")
    return hashlib.sha256(_TEMPLATE_DOMAIN + graph + plan + app_image_id + manifest_root).digest()


def _encode_external_input_ref(ref: ExternalInputRefV1, w: _Writer) -> None:
    _layout_ok(ref.layout_id, ref.layout_version, GraphError)
    _scheme_ok(ref.scheme_id, ref.scheme_version, GraphError)
    if ref.byte_length > MAX_PORT_BYTES:
        w.fail("PORT_BYTE_LIMIT", f"external input exceeds {MAX_PORT_BYTES}")
    w.uint(ref.external_id, 4, "external_input.external_id")
    w.uint(ref.layout_id, 4, "external_input.layout_id")
    w.uint(ref.layout_version, 2, "external_input.layout_version")
    w.uint(ref.scheme_id, 4, "external_input.scheme_id")
    w.uint(ref.scheme_version, 2, "external_input.scheme_version")
    w.uint(ref.byte_length, 4, "external_input.byte_length")
    w.fixed(ref.value_digest, 32, "external_input.value_digest")


def run_id(template: bytes, nonce: bytes, refs: tuple[ExternalInputRefV1, ...]) -> bytes:
    if len(template) != 32 or len(nonce) != 32:
        raise GraphError("FIXED_WIDTH", "template id and client nonce must each be 32 bytes")
    _strictly_sorted(refs, lambda item: item.external_id, "ORDER", GraphError)
    w = _Writer(GraphError)
    w.uint(len(refs), 4, "external_input_count")
    for ref in refs:
        _encode_external_input_ref(ref, w)
    return hashlib.sha256(_RUN_DOMAIN + template + nonce + bytes(w.data)).digest()


def encode_value_ref(value: ValueRefV1) -> bytes:
    if value.direction not in (0, 1):
        raise GraphError("DIRECTION", "value reference direction must be input=0 or output=1")
    _layout_ok(value.layout_id, value.layout_version, GraphError)
    _scheme_ok(value.scheme_id, value.scheme_version, GraphError)
    if value.byte_length > MAX_PORT_BYTES:
        raise GraphError("PORT_BYTE_LIMIT", f"value reference exceeds {MAX_PORT_BYTES}")
    w = _Writer(GraphError)
    for item, width, name in (
        (value.node_id, 4, "node_id"),
        (value.direction, 1, "direction"),
        (value.port_id, 2, "port_id"),
        (value.layout_id, 4, "layout_id"),
        (value.layout_version, 2, "layout_version"),
        (value.scheme_id, 4, "scheme_id"),
        (value.scheme_version, 2, "scheme_version"),
        (value.byte_length, 4, "byte_length"),
    ):
        w.uint(item, width, f"value_ref.{name}")
    w.fixed(value.value_digest, 32, "value_ref.value_digest")
    return bytes(w.data)


def step_leaf_digest(
    plan_digest: bytes,
    run_digest: bytes,
    region_id: int,
    segment_id: int,
    ordinal: int,
    node_id: int,
    kernel_step: int,
    inputs: tuple[ValueRefV1, ...],
    outputs: tuple[ValueRefV1, ...],
    prior_state_digest: bytes = bytes(32),
    next_state_digest: bytes = bytes(32),
) -> bytes:
    if len(plan_digest) != 32 or len(run_digest) != 32 or len(prior_state_digest) != 32 or len(next_state_digest) != 32:
        raise GraphError("FIXED_WIDTH", "leaf hashes and state digests must be 32 bytes")
    _strictly_sorted(inputs, lambda value: (value.node_id, value.direction, value.port_id), "ORDER", GraphError)
    _strictly_sorted(outputs, lambda value: (value.node_id, value.direction, value.port_id), "ORDER", GraphError)
    if any(value.direction != 0 for value in inputs) or any(value.direction != 1 for value in outputs):
        raise GraphError("DIRECTION", "leaf input/output refs use direction 0/1 respectively")
    w = _Writer(GraphError)
    w.fixed(plan_digest, 32, "plan_id")
    w.fixed(run_digest, 32, "run_id")
    w.uint(region_id, 4, "region_id")
    w.uint(region_id, 4, "coordinate.region_id")
    w.uint(segment_id, 4, "coordinate.segment_id")
    w.uint(ordinal, 8, "coordinate.ordinal")
    w.uint(node_id, 4, "coordinate.node_id")
    w.uint(kernel_step, 4, "coordinate.kernel_step")
    w.uint(len(inputs), 2, "input_count")
    for value in inputs:
        w.data.extend(encode_value_ref(value))
    w.uint(len(outputs), 2, "output_count")
    for value in outputs:
        w.data.extend(encode_value_ref(value))
    w.fixed(prior_state_digest, 32, "prior_state_digest")
    w.fixed(next_state_digest, 32, "next_state_digest")
    return hashlib.sha256(_LEAF_DOMAIN + bytes(w.data)).digest()


def merkle_root(leaf_hashes: tuple[bytes, ...]) -> bytes:
    if not leaf_hashes:
        raise GraphError("EMPTY_TREE", "region step tree must contain at least one leaf")
    level = list(leaf_hashes)
    if any(not isinstance(item, bytes) or len(item) != 32 for item in level):
        raise GraphError("FIXED_WIDTH", "Merkle leaves must be 32-byte digests")
    depth = 0
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            w = _Writer(GraphError)
            w.uint(depth, 2, "merkle.level")
            w.fixed(left, 32, "merkle.left")
            w.fixed(right, 32, "merkle.right")
            next_level.append(hashlib.sha256(_NODE_DOMAIN + bytes(w.data)).digest())
        level = next_level
        depth += 1
        if depth > _U16_MAX:
            raise GraphError("TREE_DEPTH", "Merkle tree exceeds u16 depth")
    return level[0]


def encode_region_root(root: RegionRootV1) -> bytes:
    _mode_ok(root.mode_id, root.mode_version, GraphError)
    _scheme_ok(root.scheme_id, root.scheme_version, GraphError)
    _layout_ok(root.layout_id, root.layout_version, GraphError)
    _strictly_sorted(root.inputs, lambda value: (value.node_id, value.direction, value.port_id), "ORDER", GraphError)
    _strictly_sorted(root.outputs, lambda value: (value.node_id, value.direction, value.port_id), "ORDER", GraphError)
    _strictly_sorted(root.children, lambda child: child.child_region_id, "ORDER", GraphError)
    if any(value.direction != 0 for value in root.inputs) or any(value.direction != 1 for value in root.outputs):
        raise GraphError("DIRECTION", "region-root input/output refs use direction 0/1 respectively")
    if len(root.inputs) > _U16_MAX or len(root.outputs) > _U16_MAX or len(root.children) > _U16_MAX:
        raise GraphError("COUNT_RANGE", "region-root lists must fit u16")
    w = _Writer(GraphError)
    w.fixed(root.plan_id, 32, "region_root.plan_id")
    w.fixed(root.run_id, 32, "region_root.run_id")
    for value, width, name in (
        (root.region_id, 4, "region_id"),
        (root.mode_id, 4, "mode_id"),
        (root.mode_version, 2, "mode_version"),
        (root.scheme_id, 4, "scheme_id"),
        (root.scheme_version, 2, "scheme_version"),
        (root.layout_id, 4, "layout_id"),
        (root.layout_version, 2, "layout_version"),
    ):
        w.uint(value, width, f"region_root.{name}")
    w.uint(len(root.inputs), 2, "region_root.input_count")
    for value in root.inputs:
        w.data.extend(encode_value_ref(value))
    w.fixed(root.step_tree_root, 32, "region_root.step_tree_root")
    w.uint(len(root.children), 2, "region_root.child_count")
    for child in root.children:
        _mode_ok(child.mode_id, child.mode_version, GraphError)
        _scheme_ok(child.scheme_id, child.scheme_version, GraphError)
        _layout_ok(child.layout_id, child.layout_version, GraphError)
        for value, width, name in (
            (child.child_region_id, 4, "child_region_id"),
            (child.mode_id, 4, "mode_id"),
            (child.mode_version, 2, "mode_version"),
            (child.scheme_id, 4, "scheme_id"),
            (child.scheme_version, 2, "scheme_version"),
            (child.layout_id, 4, "layout_id"),
            (child.layout_version, 2, "layout_version"),
        ):
            w.uint(value, width, f"child_root.{name}")
        w.fixed(child.child_root, 32, "child_root.root")
    w.uint(len(root.outputs), 2, "region_root.output_count")
    for value in root.outputs:
        w.data.extend(encode_value_ref(value))
    w.fixed(root.final_state_digest, 32, "region_root.final_state_digest")
    return bytes(w.data)


def region_root_digest(root: RegionRootV1) -> bytes:
    return hashlib.sha256(_ROOT_DOMAIN + encode_region_root(root)).digest()
