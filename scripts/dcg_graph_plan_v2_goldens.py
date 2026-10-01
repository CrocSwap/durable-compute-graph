#!/usr/bin/env python3
"""Generate or verify the DCGG/DCPL v1 reference vectors."""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from dcg.graph import v2 as wire  # noqa: E402


OUT = ROOT / "tests" / "golden" / "dcg" / "graph_plan_v2"
MIB = 1024 * 1024


def kid(label: bytes) -> bytes:
    return label.ljust(16, b"\x00")


def _cap_kernel(kernel_id: bytes, impl_byte: bytes, *, input_count: int, input_bytes: int, output_bytes: int) -> wire.KernelCapabilityV1:
    ports = tuple(
        wire.CapabilityPortV1(0, index, 1, 1, 5, (), 1, 4, 0, 0, 4)
        for index in range(input_count)
    ) + (wire.CapabilityPortV1(1, 0, 1, 1, 5, (), 1, 4, 1, 0, 4),)
    replay = wire.ReplayCapabilityV1(1, 1, input_count, 0, output_bytes, 0, 16, 4096, 1, 100_000)
    mode = wire.ModeCapabilityV1(
        wire.MODE_OPTIMISTIC,
        1,
        ((kid(b"step-replay-v1"), 1),),
        ((wire.SCHEME_SHA256_MERKLE, 1),),
        replay,
    )
    errors = tuple(wire.ErrorMappingV1(condition, 100 + condition) for condition in range(1, 6))
    return wire.KernelCapabilityV1(
        kernel_id,
        1,
        1,
        impl_byte * 32,
        0,
        0,
        0,
        ports,
        False,
        0,
        0,
        0,
        0,
        0,
        b"",
        False,
        (),
        1,
        1,
        1,
        1,
        1,
        False,
        (mode,),
        input_bytes,
        output_bytes,
        4,
        2,
        100_000,
        4096,
        4096,
        0,
        0,
        errors,
    )


def first_slice() -> tuple[wire.GraphV2, wire.KernelManifestV1, wire.PlanV2]:
    add_id = kid(b"add_i32/v1")
    identity_id = kid(b"identity_i32/v1")
    graph = wire.GraphV2(
        nodes=(
            wire.NodeV1(1, add_id, 1, 1, 1),
            wire.NodeV1(2, identity_id, 1, 1, 0),
        ),
        ports=(
            wire.PortV1(1, 0, 0, 1, 1, 5, (), 4, 4, 4),
            wire.PortV1(1, 0, 1, 1, 1, 5, (), 4, 4, 4),
            wire.PortV1(1, 1, 0, 1, 1, 5, (), 4, 4, 4),
            wire.PortV1(2, 0, 0, 1, 1, 5, (), 4, 4, 4),
            wire.PortV1(2, 1, 0, 1, 1, 5, (), 4, 4, 4),
        ),
        edges=(wire.EdgeV1(1, 0, 2, 0),),
        regions=(
            wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),
            wire.RegionV1(1, 0, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),
        ),
        inputs=(wire.GraphInputV1(0, 1, 0), wire.GraphInputV1(1, 1, 1)),
        outputs=(wire.GraphOutputV1(0, 2, 0),),
    )
    manifest = wire.KernelManifestV1(
        (
            _cap_kernel(add_id, b"A", input_count=2, input_bytes=8, output_bytes=4),
            _cap_kernel(identity_id, b"I", input_count=1, input_bytes=4, output_bytes=4),
        )
    )
    graph_bytes = wire.encode_graph(graph)
    manifest_bytes = wire.encode_kernel_manifest(manifest)
    root_steps = (
        wire.StepV1(0, 1, 0, 1, 0, 1, 1, (wire.PortRefV1(1, 0, 0), wire.PortRefV1(1, 0, 1)), (wire.PortRefV1(1, 1, 0),)),
        wire.StepV1(1, 0, 0, 2, 0, 1, 1, (wire.PortRefV1(2, 0, 0),), (wire.PortRefV1(2, 1, 0),)),
    )
    costs = (
        wire.CostAdmissionV1(1, 0, 1, 100_000, 2, 4, 4, 4, 4096, 4096, 4, 4, 0, 4096),
        wire.CostAdmissionV1(1, 1, 0, 100_000, 2, 8, 4, 4, 4096, 4096, 8, 4, 0, 4096),
        wire.CostAdmissionV1(2, 0, 0, 100_000, 4, 8, 4, 8, 4096, 4096, 8, 4, 0, 4096),
        wire.CostAdmissionV1(2, 1, 0, 100_000, 2, 8, 4, 4, 4096, 4096, 8, 4, 0, 4096),
        wire.CostAdmissionV1(3, 0, 0, 200_000, 6, 16, 8, 12, 8192, 8192, 12, 8, 0, 4096),
    )
    plan = wire.PlanV2(
        wire.graph_id(graph_bytes),
        b"compiler-v2-id!!",
        1,
        1,
        1,
        1,
        1,
        b"I" * 32,
        wire.kernel_manifest_root(manifest_bytes),
        b"",
        (
            wire.RegionPlanV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1, 1, 1),
            wire.RegionPlanV1(1, 0, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1, 1, 1),
        ),
        root_steps,
        (wire.SegmentV1(0, 0, 1, 1, 2, 1), wire.SegmentV1(1, 0, 0, 1, 2, 1)),
        (wire.BoundaryV1(1, 0, wire.PortRefV1(1, 1, 0), wire.PortRefV1(2, 0, 0), 1, 1, 2, 1),),
        (),
        costs,
    )
    return graph, manifest, plan


def graph_no_ports(
    nodes: int,
    regions: tuple[wire.RegionV1, ...] | None = None,
    node_regions: tuple[int, ...] | None = None,
) -> wire.GraphV2:
    if regions is None:
        regions = (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),)
    if node_regions is None:
        node_regions = (0,) * nodes
    if len(node_regions) != nodes:
        raise ValueError("node_regions must contain one region ID per node")
    return wire.GraphV2(
        tuple(wire.NodeV1(index, kid(b"empty-kernel"), 1, 1, node_regions[index]) for index in range(nodes)),
        (),
        (),
        regions,
        (),
        (),
    )


def graph_boundary_vectors(base_graph: wire.GraphV2) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    regions8 = tuple(
        wire.RegionV1(index, wire.ROOT_PARENT if index == 0 else index - 1, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1)
        for index in range(8)
    )
    result.append(("region_tree_depth_8", wire.encode_graph(graph_no_ports(8, regions8, tuple(range(8))))))
    regions256 = tuple(
        wire.RegionV1(index, wire.ROOT_PARENT if index == 0 else 0, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1)
        for index in range(256)
    )
    result.append(("region_count_256", wire.encode_graph(graph_no_ports(256, regions256, tuple(range(256))))))
    result.append(("node_count_4096", wire.encode_graph(graph_no_ports(4096))))

    many_ports = tuple(
        wire.PortV1(0, direction, port_id, 1, 1, 5, (), 4, 4, 4)
        for direction in (0, 1)
        for port_id in range(8192)
    )
    all_external = tuple(wire.GraphInputV1(i, 0, i) for i in range(8192))
    all_outputs = tuple(wire.GraphOutputV1(i, 0, i) for i in range(8192))
    port_graph = wire.GraphV2(
        (wire.NodeV1(0, kid(b"ports-kernel"), 1, 1, 0),),
        many_ports,
        (),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        all_external,
        all_outputs,
    )
    result.append(("port_count_16384", wire.encode_graph(port_graph)))

    max_edges = 16_383
    edge_graph = wire.GraphV2(
        (wire.NodeV1(0, kid(b"fanout-kernel"), 1, 1, 0), wire.NodeV1(1, kid(b"fanin-kernel"), 1, 1, 0)),
        (wire.PortV1(0, 1, 0, 1, 1, 5, (), 4, 4, 4),)
        + tuple(wire.PortV1(1, 0, port_id, 1, 1, 5, (), 4, 4, 4) for port_id in range(max_edges)),
        tuple(wire.EdgeV1(0, 0, 1, port_id) for port_id in range(max_edges)),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        (),
        (wire.GraphOutputV1(0, 0, 0),),
    )
    result.append(("edge_count_max_port_compatible_16383", wire.encode_graph(edge_graph)))

    megabyte = MIB
    port_bytes = wire.GraphV2(
        (wire.NodeV1(0, kid(b"wide-kernel"), 1, 1, 0),),
        (
            wire.PortV1(0, 0, 0, 1, 1, 5, (megabyte // 4,), 4, megabyte, megabyte),
            wire.PortV1(0, 1, 0, 1, 1, 5, (megabyte // 4,), 4, megabyte, megabyte),
        ),
        (),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        (wire.GraphInputV1(0, 0, 0),),
        (wire.GraphOutputV1(0, 0, 0),),
    )
    result.append(("port_max_bytes_1048576", wire.encode_graph(port_bytes)))
    rank8 = wire.GraphV2(
        (wire.NodeV1(0, kid(b"rank-kernel"), 1, 1, 0),),
        (wire.PortV1(0, 0, 0, 1, 1, 5, (1,) * 8, 4, 4, 4), wire.PortV1(0, 1, 0, 1, 1, 5, (1,) * 8, 4, 4, 4)),
        (),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        (wire.GraphInputV1(0, 0, 0),),
        (wire.GraphOutputV1(0, 0, 0),),
    )
    result.append(("port_rank_8", wire.encode_graph(rank8)))

    param = wire.NodeV1(0, kid(b"params-kernel"), 1, 1, 0, parameter_layout_id=1, parameter_layout_version=1, parameters=b"p" * (64 * 1024))
    param_graph = replace(graph_no_ports(1), nodes=(param,))
    result.append(("kernel_parameters_65536", wire.encode_graph(param_graph)))

    max_graph_target = wire.MAX_GRAPH_BYTES
    empty_graph = graph_no_ports(64)
    empty_bytes = wire.encode_graph(empty_graph)
    remaining = max_graph_target - len(empty_bytes)
    sized_nodes = []
    for index in range(64):
        size = min(64 * 1024, remaining)
        remaining -= size
        if size:
            sized_nodes.append(wire.NodeV1(index, kid(b"graph-size"), 1, 1, 0, parameter_layout_id=1, parameter_layout_version=1, parameters=b"g" * size))
        else:
            sized_nodes.append(wire.NodeV1(index, kid(b"graph-size"), 1, 1, 0))
    if remaining:
        raise AssertionError("graph byte ceiling does not fit node parameter bounds")
    max_graph = replace(empty_graph, nodes=tuple(sized_nodes))
    encoded_max_graph = wire.encode_graph(max_graph)
    assert len(encoded_max_graph) == max_graph_target
    result.append(("canonical_graph_bytes_4194304", encoded_max_graph))

    return result


def plan_regions(count: int, graph_digest: bytes, manifest_root: bytes) -> wire.PlanV2:
    regions = tuple(
        wire.RegionPlanV1(index, wire.ROOT_PARENT if index == 0 else 0, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1, 1, 1)
        for index in range(count)
    )
    steps = tuple(wire.StepV1(index, index, 0, index, 0, 1, 1, (), ()) for index in range(count))
    segments = tuple(wire.SegmentV1(index, 0, index, 1, 2, 1) for index in range(count))
    costs = [wire.CostAdmissionV1(1, index, index, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) for index in range(count)]
    costs.extend(wire.CostAdmissionV1(2, index, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) for index in range(count))
    costs.append(wire.CostAdmissionV1(3, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    return wire.PlanV2(graph_digest, b"compiler-v2-id!!", 1, 1, 1, 1, 1, b"I" * 32, manifest_root, b"", regions, steps, segments, (), (), tuple(costs))


def plan_boundary_vectors(graph_digest: bytes, manifest_root: bytes, minimal: wire.PlanV2) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    result.append(("region_count_256", wire.encode_plan(plan_regions(256, graph_digest, manifest_root))))
    depth8 = plan_regions(8, graph_digest, manifest_root)
    depth8_regions = tuple(
        replace(item, parent_region_id=wire.ROOT_PARENT if item.region_id == 0 else item.region_id - 1)
        for item in depth8.regions
    )
    result.append(("region_tree_depth_8", wire.encode_plan(replace(depth8, regions=depth8_regions))))

    max_steps = wire.MAX_PLAN_STEPS
    steps = tuple(wire.StepV1(index, 0, 0, 0, index, 1, 1, (), ()) for index in range(max_steps))
    costs = tuple(wire.CostAdmissionV1(1, 0, index, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) for index in range(max_steps)) + (
        wire.CostAdmissionV1(2, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
        wire.CostAdmissionV1(3, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    )
    plan_steps = replace(
        minimal,
        regions=(wire.RegionPlanV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1, max_steps, 1),),
        steps=steps,
        segments=(wire.SegmentV1(0, 0, 0, max_steps, 2, 1),),
        boundaries=(),
        costs=costs,
    )
    result.append(("plan_steps_16384", wire.encode_plan(plan_steps)))
    opening_costs = tuple(replace(cost, max_opening_bytes=wire.MAX_OPENING_BYTES) for cost in minimal.costs)
    result.append(("replay_opening_bytes_4096", wire.encode_plan(replace(minimal, costs=opening_costs))))

    empty = wire.encode_plan(minimal)
    compiler_parameter_length = wire.MAX_PLAN_BYTES - len(empty)
    max_plan = wire.encode_plan(replace(minimal, compiler_parameters=b"c" * compiler_parameter_length))
    assert len(max_plan) == wire.MAX_PLAN_BYTES
    result.append(("canonical_plan_bytes_4194304", max_plan))
    return result


def raw_graph(graph: wire.GraphV2) -> bytes:
    """Serialize structurally shaped data while intentionally skipping graph validation."""
    w = wire._Writer(wire.GraphError)
    w.data.extend(b"DCGG")
    for value, width in ((1, 2), (0, 2), (0, 4), (len(graph.nodes), 4), (len(graph.ports), 4), (len(graph.edges), 4), (len(graph.regions), 2), (len(graph.inputs), 2), (len(graph.outputs), 2), (0, 2)):
        w.uint(value, width, "raw.header")
    start = len(w.data)
    for node in graph.nodes:
        wire._write_node(w, node)
    for port in graph.ports:
        wire._write_port(w, port)
    for edge in graph.edges:
        wire._write_edge(w, edge)
    for region in graph.regions:
        wire._write_region(w, region)
    for item in graph.inputs:
        wire._write_graph_endpoint(w, item, True)
    for item in graph.outputs:
        wire._write_graph_endpoint(w, item, False)
    w.data[8:12] = (len(w.data) - start).to_bytes(4, "little")
    return bytes(w.data)


def raw_plan(plan: wire.PlanV2) -> bytes:
    """Serialize a plan-shaped object while intentionally skipping plan validation."""
    w = wire._Writer(wire.PlanError)
    w.data.extend(b"DCPL")
    for value, width in ((1, 2), (0, 2), (0, 4)):
        w.uint(value, width, "raw.header")
    w.fixed(plan.graph_id, 32, "graph_id")
    w.fixed(plan.compiler_id, 16, "compiler_id")
    for value, width in ((plan.compiler_version, 2), (plan.frontend_version, 2), (plan.lowering_version, 2), (plan.admission_ruleset_id, 4), (plan.admission_ruleset_version, 2)):
        w.uint(value, width, "raw.version")
    w.fixed(plan.app_image_id, 32, "app_image_id")
    w.fixed(plan.kernel_manifest_root, 32, "kernel_manifest_root")
    for value, width in ((len(plan.regions), 2), (len(plan.steps), 4), (len(plan.segments), 4), (len(plan.boundaries), 4), (len(plan.translations), 4), (len(plan.costs), 4), (len(plan.compiler_parameters), 4)):
        w.uint(value, width, "raw.count")
    w.data.extend(plan.compiler_parameters)
    for item in plan.regions:
        wire._encode_region_plan(w, item)
    for item in plan.steps:
        wire._encode_step(w, item)
    for item in plan.segments:
        wire._encode_segment(w, item)
    for item in plan.boundaries:
        wire._encode_boundary(w, item)
    for item in plan.translations:
        wire._encode_translation(w, item)
    for item in plan.costs:
        wire._encode_cost(w, item)
    w.data[8:12] = (len(w.data) - 162).to_bytes(4, "little")
    return bytes(w.data)


def malformed_vectors(graph: wire.GraphV2, plan: wire.PlanV2) -> list[tuple[str, str, str, bytes]]:
    gb = wire.encode_graph(graph)
    pb = wire.encode_plan(plan)
    result: list[tuple[str, str, str, bytes]] = []

    def add(name: str, kind: str, code: str, data: bytes) -> None:
        result.append((name, kind, code, data))

    def gmut(name: str, code: str, offset: int, value: int, width: int = 1) -> None:
        data = bytearray(gb)
        data[offset : offset + width] = value.to_bytes(width, "little")
        add(name, "graph", code, bytes(data))

    add("graph_bad_magic", "graph", "MAGIC", b"XXXX" + gb[4:])
    gmut("graph_bad_version", "VERSION", 4, 2, 2)
    gmut("graph_nonzero_flags", "FLAGS", 6, 1, 2)
    gmut("graph_wrong_body_length", "BODY_LENGTH", 8, len(gb), 4)
    gmut("graph_nonzero_reserved", "RESERVED", 30, 1, 2)
    gmut("graph_node_count_over_limit", "NODE_COUNT", 12, wire.MAX_NODES + 1, 4)
    gmut("graph_edge_count_over_limit", "EDGE_COUNT", 20, wire.MAX_EDGES + 1, 4)
    gmut("graph_unknown_scalar", "SCALAR_TYPE", 32 + 53 + 53 + 4 + 13, 10)
    gmut("graph_bad_alignment", "ALIGNMENT", 32 + 106 + 4 + 15, 3, 2)
    gmut("graph_nonzero_port_reserved", "RESERVED", 32 + 106 + 4 + 17, 1, 2)
    gmut("graph_shape_mismatch", "PORT_BYTE_LENGTH", 32 + 106 + 4 + 19, 3, 4)
    region0_start = 32 + 2 * 53 + 5 * 31 + 16
    gmut("graph_unknown_mode", "UNKNOWN_MODE", region0_start + 4 + 8, 7, 4)
    gmut("graph_bad_region_parent", "REGION_PARENT", region0_start + 42 + 4 + 4, 77, 4)
    graph_record_length = bytearray(gb)
    graph_record_length[32:36] = (54).to_bytes(4, "little")
    add("graph_node_record_trailing_byte", "graph", "TRAILING_BYTES", bytes(graph_record_length))
    graph_trailing = bytearray(gb + b"x")
    graph_trailing[8:12] = (len(graph_trailing) - 32).to_bytes(4, "little")
    add("graph_trailing_bytes", "graph", "TRAILING_BYTES", bytes(graph_trailing))
    input_reserved = bytearray(gb)
    input0_start = region0_start + 2 * 42
    input_reserved[input0_start + 14 : input0_start + 16] = (1).to_bytes(2, "little")
    add("graph_input_reserved_nonzero", "graph", "RESERVED", bytes(input_reserved))

    unsorted_nodes = bytearray(gb)
    first = bytes(unsorted_nodes[32:85])
    second = bytes(unsorted_nodes[85:138])
    unsorted_nodes[32:85] = second
    unsorted_nodes[85:138] = first
    add("graph_unsorted_nodes", "graph", "ORDER", bytes(unsorted_nodes))
    duplicate_node = bytearray(gb)
    duplicate_node[85 + 4 : 85 + 8] = (1).to_bytes(4, "little")
    add("graph_duplicate_node", "graph", "DUPLICATE", bytes(duplicate_node))

    duplicate_input_graph = replace(
        graph,
        inputs=graph.inputs + (wire.GraphInputV1(2, 2, 0),),
    )
    add("graph_input_multiple_sources", "graph", "INPUT_MULTIPLE_SOURCES", raw_graph(duplicate_input_graph))

    bad_edge_layout = bytearray(gb)
    second_node_first_port = 32 + 106 + 3 * 31
    bad_edge_layout[second_node_first_port + 4 + 7 : second_node_first_port + 4 + 11] = (2).to_bytes(4, "little")
    add("graph_edge_layout_mismatch", "graph", "EDGE_LAYOUT", bytes(bad_edge_layout))

    dimensioned = wire.GraphV2(
        (wire.NodeV1(0, kid(b"dimension-kernel"), 1, 1, 0),),
        (wire.PortV1(0, 0, 0, 1, 1, 5, (1,), 4, 4, 4), wire.PortV1(0, 1, 0, 1, 1, 5, (1,), 4, 4, 4)),
        (),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        (wire.GraphInputV1(0, 0, 0),),
        (wire.GraphOutputV1(0, 0, 0),),
    )
    dimensional_bytes = bytearray(wire.encode_graph(dimensioned))
    dimensional_bytes[32 + 53 + 4 + 27] = 0
    add("graph_zero_dimension", "graph", "DIMENSION", bytes(dimensional_bytes))

    missing_parent = replace(graph, regions=(graph.regions[0], replace(graph.regions[1], parent_region_id=99)))
    add("graph_unknown_region_parent", "graph", "REGION_PARENT", raw_graph(missing_parent))
    region_cycle = bytearray(gb)
    second_region_start = region0_start + 42
    region_cycle[second_region_start + 4 + 4 : second_region_start + 4 + 8] = (1).to_bytes(4, "little")
    add("graph_region_cycle", "graph", "REGION_CYCLE", bytes(region_cycle))
    depth9_regions = tuple(
        wire.RegionV1(index, wire.ROOT_PARENT if index == 0 else index - 1, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1)
        for index in range(9)
    )
    add("graph_region_depth_over_limit", "graph", "REGION_DEPTH", raw_graph(graph_no_ports(9, depth9_regions, tuple(range(9)))))
    cycle = wire.GraphV2(
        (wire.NodeV1(1, kid(b"cycle-a"), 1, 1, 0), wire.NodeV1(2, kid(b"cycle-b"), 1, 1, 0)),
        (wire.PortV1(1, 0, 0, 1, 1, 5, (), 4, 4, 4), wire.PortV1(1, 1, 0, 1, 1, 5, (), 4, 4, 4), wire.PortV1(2, 0, 0, 1, 1, 5, (), 4, 4, 4), wire.PortV1(2, 1, 0, 1, 1, 5, (), 4, 4, 4)),
        (wire.EdgeV1(2, 0, 1, 0), wire.EdgeV1(1, 0, 2, 0)),
        (wire.RegionV1(0, wire.ROOT_PARENT, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1),),
        (),
        (wire.GraphOutputV1(0, 1, 0), wire.GraphOutputV1(1, 2, 0)),
    )
    add("graph_cycle", "graph", "GRAPH_CYCLE", raw_graph(cycle))

    parameter_node = wire.NodeV1(0, kid(b"parameter-kernel"), 1, 1, 0, parameter_layout_id=1, parameter_layout_version=1, parameters=b"p" * (64 * 1024))
    parameter_graph = replace(graph_no_ports(1), nodes=(parameter_node,))
    oversized_param = bytearray(wire.encode_graph(parameter_graph))
    oversized_param[32:36] = (int.from_bytes(oversized_param[32:36], "little") + 1).to_bytes(4, "little")
    oversized_param[81:85] = (64 * 1024 + 1).to_bytes(4, "little")
    oversized_param.insert(32 + 4 + 49 + 64 * 1024, ord("p"))
    oversized_param[8:12] = (len(oversized_param) - 32).to_bytes(4, "little")
    add("graph_kernel_parameter_over_limit", "graph", "PARAMETER_LIMIT", bytes(oversized_param))

    def pmut(name: str, code: str, offset: int, value: int, width: int = 1) -> None:
        data = bytearray(pb)
        data[offset : offset + width] = value.to_bytes(width, "little")
        add(name, "plan", code, bytes(data))

    add("plan_bad_magic", "plan", "MAGIC", b"XXXX" + pb[4:])
    pmut("plan_bad_version", "VERSION", 4, 2, 2)
    pmut("plan_nonzero_flags", "FLAGS", 6, 1, 2)
    pmut("plan_wrong_body_length", "BODY_LENGTH", 8, len(pb), 4)
    pmut("plan_step_count_over_limit", "STEP_COUNT", 138, wire.MAX_PLAN_STEPS + 1, 4)
    pmut("plan_unknown_mode", "UNKNOWN_MODE", 162 + 4 + 8, 9, 4)
    opening_offset = 162 + 100 + (59 + 52) + 60 + 44 + 59
    pmut("plan_opening_over_limit", "OPENING_LIMIT", opening_offset, wire.MAX_OPENING_BYTES + 1, 4)
    plan_trailing = bytearray(pb + b"x")
    plan_trailing[8:12] = (len(plan_trailing) - 162).to_bytes(4, "little")
    add("plan_trailing_bytes", "plan", "TRAILING_BYTES", bytes(plan_trailing))

    unsorted_plan = bytearray(pb)
    r0 = bytes(unsorted_plan[162:212])
    r1 = bytes(unsorted_plan[212:262])
    unsorted_plan[162:212] = r1
    unsorted_plan[212:262] = r0
    add("plan_unsorted_regions", "plan", "ORDER", bytes(unsorted_plan))
    gap = bytearray(pb)
    second_step_start = 162 + 100 + 59
    gap[second_step_start + 4 : second_step_start + 12] = (2).to_bytes(8, "little")
    add("plan_ordinal_gap", "plan", "ORDINALS", bytes(gap))
    bad_direction = bytearray(pb)
    bad_direction[309] = 2
    add("plan_bad_input_direction", "plan", "DIRECTION", bytes(bad_direction))
    bad_segment = bytearray(pb)
    segment0 = 162 + 100 + 59 + 52
    bad_segment[segment0 + 4 + 8 : segment0 + 4 + 16] = (0).to_bytes(8, "little")
    add("plan_segment_membership", "plan", "SEGMENT_MEMBERSHIP", bytes(bad_segment))
    plan_record_length = bytearray(pb)
    plan_record_length[162:166] = (47).to_bytes(4, "little")
    add("plan_region_record_trailing_byte", "plan", "TRAILING_BYTES", bytes(plan_record_length))
    missing_cost_plan = replace(plan, costs=plan.costs[:-1])
    add("plan_missing_run_cost", "plan", "COST_COVERAGE", raw_plan(missing_cost_plan))
    bad_boundary_plan = replace(
        plan,
        boundaries=(replace(plan.boundaries[0], source_region=99),),
    )
    add("plan_unknown_boundary_region", "plan", "BOUNDARY_REGION", raw_plan(bad_boundary_plan))
    depth9_plan = plan_regions(9, plan.graph_id, plan.kernel_manifest_root)
    depth9_plan = replace(
        depth9_plan,
        regions=tuple(replace(item, parent_region_id=wire.ROOT_PARENT if item.region_id == 0 else item.region_id - 1) for item in depth9_plan.regions),
    )
    add("plan_region_depth_over_limit", "plan", "REGION_DEPTH", raw_plan(depth9_plan))

    manifest = first_slice()[1]
    mb = wire.encode_kernel_manifest(manifest)
    add("manifest_bad_magic", "manifest", "MAGIC", b"XXXX" + mb[4:])
    manifest_version = bytearray(mb)
    manifest_version[4:6] = (2).to_bytes(2, "little")
    add("manifest_bad_version", "manifest", "VERSION", bytes(manifest_version))
    manifest_flags = bytearray(mb)
    manifest_flags[6:8] = (1).to_bytes(2, "little")
    add("manifest_nonzero_flags", "manifest", "FLAGS", bytes(manifest_flags))
    manifest_body_length = bytearray(mb)
    manifest_body_length[8:12] = len(mb).to_bytes(4, "little")
    add("manifest_wrong_body_length", "manifest", "BODY_LENGTH", bytes(manifest_body_length))
    manifest_presence = bytearray(mb)
    first_kernel_body = 16 + 4
    first_kernel = manifest.kernels[0]
    state_offset = first_kernel_body + 16 + 2 + 2 + 32 + 4 + 2 + 4 + 2 + 2 + len(first_kernel.ports) * 19
    manifest_presence[state_offset] = 2
    add("manifest_invalid_presence", "manifest", "PRESENCE", bytes(manifest_presence))

    return result


def hash_vectors(graph_bytes: bytes, manifest_bytes: bytes, plan_bytes: bytes) -> bytes:
    graph_digest = wire.graph_id(graph_bytes)
    manifest_root = wire.kernel_manifest_root(manifest_bytes)
    plan_digest = wire.plan_id(plan_bytes)
    app_image_id = b"I" * 32
    template = wire.template_id(graph_digest, plan_digest, app_image_id, manifest_root)
    nonce = b"N" * 32
    external_refs = (
        wire.ExternalInputRefV1(0, 1, 1, 2, 1, 4, hashlib.sha256(b"input-zero").digest()),
        wire.ExternalInputRefV1(1, 1, 1, 2, 1, 4, hashlib.sha256(b"input-one").digest()),
    )
    run = wire.run_id(template, nonce, external_refs)

    def value_ref(node: int, direction: int, port: int, label: bytes) -> wire.ValueRefV1:
        return wire.ValueRefV1(node, direction, port, 1, 1, 2, 1, 4, hashlib.sha256(label).digest())

    leaf_inputs = (value_ref(1, 0, 0, b"input-zero"), value_ref(1, 0, 1, b"input-one"))
    leaf_outputs = (value_ref(1, 1, 0, b"add-output"),)
    leaf_preimage = bytearray(b"dcg.region.leaf.v2\x00")
    leaf_preimage.extend(plan_digest)
    leaf_preimage.extend(run)
    leaf_preimage.extend((1).to_bytes(4, "little"))
    leaf_preimage.extend((1).to_bytes(4, "little"))  # coordinate region id
    leaf_preimage.extend((0).to_bytes(4, "little"))  # segment id
    leaf_preimage.extend((0).to_bytes(8, "little"))  # global ordinal
    leaf_preimage.extend((1).to_bytes(4, "little"))  # node id
    leaf_preimage.extend((0).to_bytes(4, "little"))  # kernel step
    leaf_preimage.extend(len(leaf_inputs).to_bytes(2, "little"))
    for value in leaf_inputs:
        leaf_preimage.extend(wire.encode_value_ref(value))
    leaf_preimage.extend(len(leaf_outputs).to_bytes(2, "little"))
    for value in leaf_outputs:
        leaf_preimage.extend(wire.encode_value_ref(value))
    leaf_preimage.extend(bytes(32))
    leaf_preimage.extend(bytes(32))
    leaf_digest = wire.step_leaf_digest(plan_digest, run, 1, 0, 0, 1, 0, leaf_inputs, leaf_outputs)
    if hashlib.sha256(leaf_preimage).digest() != leaf_digest:
        raise AssertionError("step leaf preimage differs from reference encoder")

    left = hashlib.sha256(b"left-child").digest()
    right = hashlib.sha256(b"right-child").digest()
    node_preimage = b"dcg.region.node.v2\x00" + (0).to_bytes(2, "little") + left + right
    node_digest = hashlib.sha256(node_preimage).digest()
    root_model = wire.RegionRootV1(
        plan_digest,
        run,
        0,
        wire.MODE_OPTIMISTIC,
        1,
        2,
        1,
        1,
        1,
        (value_ref(2, 0, 0, b"boundary-add-result"),),
        wire.merkle_root((leaf_digest,)),
        (wire.ChildRootV1(1, wire.MODE_OPTIMISTIC, 1, 2, 1, 1, 1, leaf_digest),),
        (value_ref(2, 1, 0, b"identity-result"),),
        bytes(32),
    )
    root_preimage = b"dcg.region.root.v2\x00" + wire.encode_region_root(root_model)
    root_digest = wire.region_root_digest(root_model)

    rows = [
        ("graph_id", b"dcg.graph.id.v2\x00" + graph_bytes, graph_digest),
        ("plan_id", b"dcg.plan.id.v2\x00" + plan_bytes, plan_digest),
        ("template_id", b"dcg.template.id.v2\x00" + graph_digest + plan_digest + app_image_id + manifest_root, template),
        ("kernel_manifest_root", b"dcg.kernel.manifest.id.v2\x00" + manifest_bytes, manifest_root),
        ("run_id", b"dcg.run.id.v2\x00" + template + nonce + (len(external_refs)).to_bytes(4, "little") + b"".join(
            ref.external_id.to_bytes(4, "little")
            + ref.layout_id.to_bytes(4, "little")
            + ref.layout_version.to_bytes(2, "little")
            + ref.scheme_id.to_bytes(4, "little")
            + ref.scheme_version.to_bytes(2, "little")
            + ref.byte_length.to_bytes(4, "little")
            + ref.value_digest
            for ref in external_refs
        ), run),
        ("step_leaf", bytes(leaf_preimage), leaf_digest),
        ("merkle_node_level_0", node_preimage, node_digest),
        ("region_root", root_preimage, root_digest),
    ]
    lines = ["name\tpreimage_base64\tsha256\n"]
    for name, preimage, digest in rows:
        if hashlib.sha256(preimage).digest() != digest:
            raise AssertionError(f"{name} reference hash mismatch")
        lines.append(f"{name}\t{base64.b64encode(preimage).decode('ascii')}\t{digest.hex()}\n")
    return "".join(lines).encode("ascii")


def _valid_tsv(rows: list[tuple[str, bytes, bytes]]) -> bytes:
    lines = ["name\tbytes_base64\tsha256\n"]
    for name, payload, digest in rows:
        lines.append(f"{name}\t{base64.b64encode(payload).decode('ascii')}\t{digest.hex()}\n")
    return "".join(lines).encode("ascii")


def generate() -> dict[Path, bytes]:
    graph, manifest, plan = first_slice()
    graph_bytes = wire.encode_graph(graph)
    manifest_bytes = wire.encode_kernel_manifest(manifest)
    plan_bytes = wire.encode_plan(plan)

    graph_rows: list[tuple[str, bytes, bytes]] = [("minimal_two_level_add_identity", graph_bytes, wire.graph_id(graph_bytes))]
    graph_rows.extend((name, payload, wire.graph_id(payload)) for name, payload in graph_boundary_vectors(graph))

    plan_rows: list[tuple[str, bytes, bytes]] = [("minimal_two_level_add_identity", plan_bytes, wire.plan_id(plan_bytes))]
    plan_rows.extend((name, payload, wire.plan_id(payload)) for name, payload in plan_boundary_vectors(wire.graph_id(graph_bytes), wire.kernel_manifest_root(manifest_bytes), plan))

    manifest_rows = [("minimal_add_identity_capabilities", manifest_bytes, wire.kernel_manifest_root(manifest_bytes))]
    refusal_rows = malformed_vectors(graph, plan)
    refusal_lines = ["name\tcodec\texpected_code\tmalformed_bytes_base64\n"]
    for name, codec, code, payload in refusal_rows:
        refusal_lines.append(f"{name}\t{codec}\t{code}\t{base64.b64encode(payload).decode('ascii')}\n")

    return {
        OUT / "graphs_v1.tsv": _valid_tsv(graph_rows),
        OUT / "plans_v1.tsv": _valid_tsv(plan_rows),
        OUT / "kernel_manifests_v1.tsv": _valid_tsv(manifest_rows),
        OUT / "refusals_v1.tsv": "".join(refusal_lines).encode("ascii"),
        OUT / "hashes_v1.tsv": hash_vectors(graph_bytes, manifest_bytes, plan_bytes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write generated TSV files")
    args = parser.parse_args()
    generated = generate()
    mismatches = []
    for path, data in generated.items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            print(f"wrote {path.relative_to(ROOT)} ({len(data)} bytes)")
        elif not path.exists() or path.read_bytes() != data:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        print("golden mismatch: " + ", ".join(mismatches), file=sys.stderr)
        print("run scripts/dcg_graph_plan_v2_goldens.py --write", file=sys.stderr)
        return 1
    if not args.write:
        print(f"verified {len(generated)} DCG graph/plan v2 golden files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
