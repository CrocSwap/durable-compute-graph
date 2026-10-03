"""Dispute spec (DCDS) records and derivation (design §5).

`derive` lowers a canonical DCGG/DCPL to one enumerated block. `plans.py`
builds multi-block specs with repeated blocks (gates, producer kinds 4 to 7),
SMALL state and chunked inputs: the chunked-kernel slice. The record encoders
cover every type so goldens can pin their bytes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from dcg.graph import v2 as wire

from . import trees

SPEC_LEAF_DOMAIN = b"dcg.spec.leaf.v2.1\x00"
PARAMS_DOMAIN = b"dcg.params.v2.1\x00"
PORTS_DOMAIN = b"dcg.ports.v2.1\x00"

TYPE_HEADER, TYPE_BLOCK, TYPE_CONST, TYPE_IN, TYPE_OUT, TYPE_OUT_BLOCK, TYPE_REGION, TYPE_STEP, TYPE_BODY = range(1, 10)


class SpecError(ValueError):
    pass


def port_header(node: int, direction: int, port: int, layout_id: int, layout_version: int,
                scheme_id: int, scheme_version: int, byte_length: int) -> bytes:
    return struct.pack("<IBHIHIHI", node, direction, port, layout_id, layout_version, scheme_id,
                       scheme_version, byte_length)


assert len(port_header(0, 0, 0, 0, 0, 0, 0, 0)) == 23


def producer(kind: int, a: int = 0, b: int = 0, c: int = 0, d: int = 0) -> bytes:
    return struct.pack("<B3xQIII", kind, a, b, c, d)


assert len(producer(0)) == 24

NO_PRODUCER = producer(0)


@dataclass(frozen=True)
class StepInput:
    header: bytes  # 23
    producer: bytes  # 24
    initial: bytes = NO_PRODUCER  # 24 (kind 4 only)


@dataclass(frozen=True)
class StepSpec:
    region_id: int
    dcpl_segment_id: int
    node_id: int
    kernel_step: int
    kernel_id: bytes  # 16
    semantic_version: int
    abi_version: int
    decomposition_id: int
    decomposition_version: int
    max_cu: int
    parameter_digest: bytes
    port_shapes_digest: bytes
    inputs: tuple[StepInput, ...]
    outputs: tuple[bytes, ...]  # 23-byte headers
    state_scheme: int = 0
    state_export_port: int = 0xFF
    state_unit: int = 0
    state_size: int = 0
    state_predecessor: bytes = NO_PRODUCER
    state_initial: bytes = NO_PRODUCER
    magic: bytes = b"DSS1"

    def encode(self) -> bytes:
        if len(self.inputs) > 8 or len(self.outputs) > 8:
            raise SpecError("a step has at most 8 inputs and 8 outputs")
        head = (self.magic + struct.pack("<IIII", self.region_id, self.dcpl_segment_id, self.node_id,
                                          self.kernel_step)
                + self.kernel_id + struct.pack("<HHIH2xQ", self.semantic_version, self.abi_version,
                                               self.decomposition_id, self.decomposition_version, self.max_cu)
                + self.parameter_digest + self.port_shapes_digest
                + struct.pack("<BB2xIQ", self.state_scheme, self.state_export_port, self.state_unit,
                              self.state_size)
                + self.state_predecessor + self.state_initial
                + struct.pack("<BB6x", len(self.inputs), len(self.outputs)))
        assert len(head) == 192, len(head)
        body = b"".join(i.header + i.producer + i.initial + b"\x00" for i in self.inputs)
        body += b"".join(o + b"\x00" for o in self.outputs)
        return head + body


def decode_step_spec(raw: bytes) -> dict:
    """Parse a StepSpec for the referee (the fields claims compare)."""
    n_in, n_out = raw[184], raw[185]
    at = 192
    ins = []
    for _ in range(n_in):
        ins.append((raw[at:at + 23], raw[at + 23:at + 47], raw[at + 47:at + 71]))
        at += 72
    outs = []
    for _ in range(n_out):
        outs.append(raw[at:at + 23])
        at += 24
    region, segment, node, kernel_step = struct.unpack_from("<IIII", raw, 4)
    return {"magic": raw[:4], "region": region, "state_export": raw[121],
            "state_unit": struct.unpack_from("<I", raw, 124)[0],
            "state_size": struct.unpack_from("<Q", raw, 128)[0], "state_predecessor": raw[136:160],
            "state_initial": raw[160:184], "segment": segment, "node": node, "kernel_step": kernel_step,
            "kernel_id": raw[20:36], "semantic_version": struct.unpack_from("<H", raw, 36)[0],
            "abi_version": struct.unpack_from("<H", raw, 38)[0],
            "max_cu": struct.unpack_from("<Q", raw, 48)[0], "parameter_digest": raw[56:88],
            "port_shapes_digest": raw[88:120], "state_scheme": raw[120], "inputs": ins, "outputs": outs}


def decode_producer(raw: bytes) -> tuple[int, int, int, int, int]:
    kind, a, b, c, d = struct.unpack("<B3xQIII", raw)
    return kind, a, b, c, d


def block_spec(kind: int, base: int, step_count: int, k: int, body_len: int, gate_entry: int, gate_port: int,
               first_record: int, record_count: int, address_base: int, address_height: int,
               body_graph_id: bytes = bytes(32)) -> bytes:
    raw = (b"DBK1" + struct.pack("<B3xQQIIIH2xQQQB7x", kind, base, step_count, k, body_len, gate_entry,
                                  gate_port, first_record, record_count, address_base, address_height)
           + body_graph_id)
    assert len(raw) == 104, len(raw)
    return raw


def in_spec(external_id: int, header: bytes, chunk_log2: int = 0) -> bytes:
    raw = b"DIN1" + struct.pack("<I", external_id) + header + b"\x00" + bytes([chunk_log2]) + bytes(7)
    assert len(raw) == 40
    return raw


def const_spec(constant_id: int, header: bytes, residency: int, source_kind: int, digest: bytes,
               locator: bytes = bytes(32)) -> bytes:
    raw = (b"DCN1" + struct.pack("<I", constant_id) + header + bytes([residency, source_kind]) + bytes(7)
           + digest + locator)
    assert len(raw) == 104
    return raw


def out_spec(header: bytes, prod: bytes) -> bytes:
    raw = b"DOU1" + bytes(4) + header + b"\x00" + prod
    assert len(raw) == 56
    return raw


def out_block_spec(block: int, entry: int, port: int, header: bytes, first_out_index: int) -> bytes:
    raw = (b"DOB1" + struct.pack("<IIH2x", block, entry, port) + header + b"\x00"
           + struct.pack("<Q", first_out_index) + bytes(8))
    assert len(raw) == 56, len(raw)
    return raw


def region_spec(region: wire.RegionV1) -> bytes:
    raw = b"DRG1" + struct.pack("<IIIHIHIH2x", region.region_id, region.parent_region_id, region.mode_id,
                                 region.mode_version, region.scheme_id, region.scheme_version,
                                 region.layout_id, region.layout_version)
    assert len(raw) == 32
    return raw


def spec_header(block_count: int, const_count: int, in_count: int, out_count: int, out_block_count: int,
                region_count: int, total_steps: int, total_outputs: int) -> bytes:
    raw = b"DCS1" + struct.pack("<H2xIIIIIIQQ", 1, block_count, const_count, in_count, out_count,
                                 out_block_count, region_count, total_steps, total_outputs)
    assert len(raw) == 48
    return raw


def spec_leaf(type_code: int, record: bytes) -> bytes:
    return hashlib.sha256(SPEC_LEAF_DOMAIN + bytes([type_code]) + record).digest()


def parameter_digest(node: wire.NodeV1) -> bytes:
    if not node.parameters and not node.parameter_layout_id:
        return bytes(32)
    return hashlib.sha256(PARAMS_DOMAIN + struct.pack("<IHI", node.parameter_layout_id,
                                                      node.parameter_layout_version, len(node.parameters))
                          + node.parameters).digest()


def port_shapes_digest(ports: list[wire.PortV1]) -> bytes:
    body = b"".join(wire._graph_record(wire.GraphError, lambda w, p=p: wire._port_fields(w, p))
                    for p in sorted(ports, key=lambda p: (p.direction, p.port_id)))
    return hashlib.sha256(PORTS_DOMAIN + body).digest()


@dataclass(frozen=True)
class Block:
    """One BlockSpec, with its place in the step tree's address map (§6.2)."""

    kind: int  # 1 enumerated, 2 repeated
    base: int
    step_count: int
    k: int  # iterations (repeated)
    body_len: int
    gate_entry: int
    gate_port: int
    first_record: int
    record_count: int
    address_base: int
    address_height: int

    @property
    def hb(self) -> int:
        return trees.height_for(self.body_len) if self.kind == 2 else 0

    def record(self) -> bytes:
        return block_spec(self.kind, self.base, self.step_count, self.k, self.body_len, self.gate_entry,
                          self.gate_port, self.first_record, self.record_count, self.address_base,
                          self.address_height)


def place_blocks(shapes: list[tuple[int, int, int]]) -> tuple[list[tuple[int, int]], int]:
    """Address map (§6.2): for (kind, step_count or body_len, K) per block, the
    (address_base, address_height) of each, and the global tree height."""
    out, end = [], 0
    for kind, n, k in shapes:
        height = trees.height_for(n) if kind == 1 else trees.height_for(k) + trees.height_for(n)
        size = 1 << height
        base = -(-end // size) * size
        out.append((base, height))
        end = base + size
    return out, trees.height_for(end)


def chunk_header(scheme_id: int, scheme_version: int, chunk_bytes: int) -> bytes:
    """The derived header of one chunk read as a plain value (§3.3, R3-B3)."""
    return port_header(0, 0, 0, LAYOUT_RAW, 1, scheme_id, scheme_version, chunk_bytes)


LAYOUT_SCALAR, LAYOUT_CHUNKED, LAYOUT_LOG, LAYOUT_RAW = 1, 3, 4, 5


@dataclass
class Spec:
    """A derived DCDS: records in spec-tree order, the blocks and the indices the referee needs."""

    records: list[tuple[int, bytes]]  # (type code, record bytes), in leaf order
    blocks: list[Block]
    block_records: list[list[bytes]]  # per block: its StepSpec records or body entries
    in_specs: dict[int, bytes]  # by external id
    out_specs: list[bytes]  # by out index
    total_steps: int
    total_outputs: int
    address_height: int
    first_out_record: int
    const_specs: dict[int, bytes] = field(default_factory=dict)  # by constant id
    # Off-chain availability of committed constants (not part of any record):
    # the bytes an executor and challenger fetch by locator.
    constant_values: dict[int, bytes] = field(default_factory=dict)
    tree: trees.Tree = field(init=False)

    def __post_init__(self):
        self.tree = trees.build("spec", [spec_leaf(t, r) for t, r in self.records])

    @property
    def root(self) -> bytes:
        return self.tree.root

    def opening(self, leaf_index: int) -> tuple[int, bytes, list[bytes]]:
        t, r = self.records[leaf_index]
        return t, r, self.tree.path(leaf_index)

    # --- ordinals, records and addresses ------------------------------------------------
    def locate(self, ordinal: int) -> tuple[int, Block, int, int]:
        """(block index, block, iteration, entry) of a step ordinal."""
        for bi, b in enumerate(self.blocks):
            if b.base <= ordinal < b.base + b.step_count:
                r = ordinal - b.base
                if b.kind == 1:
                    return bi, b, 0, r
                return bi, b, r // b.body_len, r % b.body_len
        raise SpecError("ordinal out of range")

    def ordinal_of(self, block: int, iteration: int, entry: int) -> int:
        b = self.blocks[block]
        return b.base + (iteration * b.body_len + entry if b.kind == 2 else entry)

    def step_leaf_index(self, ordinal: int) -> int:
        _bi, b, _i, e = self.locate(ordinal)
        return b.first_record + e

    def position_of(self, ordinal: int) -> int:
        _bi, b, i, e = self.locate(ordinal)
        return b.address_base + ((i << b.hb) + e if b.kind == 2 else e)

    def ordinal_at(self, position: int) -> int | None:
        for b in self.blocks:
            r = position - b.address_base
            if not 0 <= r < (1 << b.address_height):
                continue
            if b.kind == 1:
                return b.base + r if r < b.step_count else None
            i, e = r >> b.hb, r & ((1 << b.hb) - 1)
            return b.base + i * b.body_len + e if i < b.k and e < b.body_len else None
        return None

    def gated(self, ordinal: int) -> bool:
        """A step whose presence depends on a gate: iteration >= 1 of a repeated block."""
        _bi, b, i, _e = self.locate(ordinal)
        return b.kind == 2 and i >= 1

    def step_spec(self, ordinal: int) -> bytes:
        """StepSpec(k): stored, or generated from its body entry (§5.2)."""
        bi, b, i, e = self.locate(ordinal)
        raw = self.block_records[bi][e]
        if b.kind == 1:
            return raw
        return generate(raw, b, i)

    @property
    def step_specs(self) -> list[bytes]:
        return [self.step_spec(k) for k in range(self.total_steps)]

    @property
    def first_step_record(self) -> int:
        return self.blocks[0].first_record

    def out_leaf_index(self, j: int) -> int:
        return self.first_out_record + j

    def const_leaf_index(self, constant_id: int) -> int:
        """ConstSpec records follow the BlockSpecs, by constant id."""
        return 1 + len(self.blocks) + sorted(self.const_specs).index(constant_id)

    def pickable(self, level: int, position: int) -> bool:
        """Structural (§7.1): the subtree at (level, position) holds a step position."""
        lo, hi = position << level, (position + 1) << level
        for b in self.blocks:
            blo = max(lo, b.address_base) - b.address_base
            bhi = min(hi, b.address_base + (1 << b.address_height)) - b.address_base
            if blo >= bhi:
                continue
            if b.kind == 1:
                if blo < b.step_count:
                    return True
                continue
            i = blo >> b.hb
            if i < b.k and (i << b.hb) + b.body_len > blo:
                return True
            if i + 1 < b.k and ((i + 1) << b.hb) < bhi:
                return True
        return False


def _resolve(prod: bytes, initial: bytes, b: Block, i: int) -> bytes:
    kind, a, pb, c, d = decode_producer(prod)
    if kind == 4:
        lag = c
        if i >= lag:
            return producer(1, b.base + (i - lag) * b.body_len + a, pb)
        return initial
    if kind == 5:
        return producer(5, a, pb, 0, i * c + d)
    if kind == 7:
        return producer(7, i)
    return prod


def generate(body_entry: bytes, b: Block, i: int) -> bytes:
    """Resolve a body entry's relative producers for iteration i (§5.2)."""
    if body_entry[:4] != b"DSB1":
        raise SpecError("not a body entry")
    out = bytearray(b"DSS1" + body_entry[4:])
    initial_state = body_entry[160:184]
    out[136:160] = _resolve(body_entry[136:160], initial_state, b, i)
    at = 192
    for _ in range(body_entry[184]):
        out[at + 23:at + 47] = _resolve(body_entry[at + 23:at + 47], body_entry[at + 47:at + 71], b, i)
        out[at + 47:at + 71] = NO_PRODUCER
        at += 72
    return bytes(out)


def derive(graph_bytes: bytes, plan_bytes: bytes, max_cu: int = 200_000) -> Spec:
    """DCDS for one enumerated block from canonical DCGG and DCPL."""
    graph = wire.decode_graph(graph_bytes)
    plan = wire.decode_plan(plan_bytes)
    nodes = {n.node_id: n for n in graph.nodes}
    ports = {(p.node_id, p.direction, p.port_id): p for p in graph.ports}
    node_ports: dict[int, list[wire.PortV1]] = {}
    for p in graph.ports:
        node_ports.setdefault(p.node_id, []).append(p)
    regions = {r.region_id: r for r in graph.regions}
    root = next(r for r in graph.regions if r.parent_region_id == wire.ROOT_PARENT)
    steps = sorted(plan.steps, key=lambda s: s.ordinal)
    if [s.ordinal for s in steps] != list(range(len(steps))):
        raise SpecError("plan ordinals are not 0..n")
    produced: dict[tuple[int, int], int] = {}
    for s in steps:
        for o in s.outputs:
            if (o.node_id, o.port_id) in produced:
                raise SpecError("an output port is produced by more than one step")
            produced[(o.node_id, o.port_id)] = s.ordinal
    edge_source = {(e.destination_node, e.destination_port): (e.source_node, e.source_port) for e in graph.edges}
    external = {(i.destination_node, i.destination_port): i.external_id for i in graph.inputs}

    def header_of(port: wire.PortV1, scheme_region: wire.RegionV1) -> bytes:
        return port_header(port.node_id, port.direction, port.port_id, port.layout_id, port.layout_version,
                           scheme_region.scheme_id, scheme_region.scheme_version, port.byte_length)

    in_headers: dict[int, bytes] = {}
    step_specs = []
    for s in steps:
        node = nodes[s.node_id]
        inputs = []
        for r in sorted(s.inputs, key=lambda r: (r.node_id, r.direction, r.port_id)):
            key = (r.node_id, r.port_id)
            port = ports[(r.node_id, 0, r.port_id)]
            if key in external:
                eid = external[key]
                h = header_of(port, root)
                in_headers[eid] = h
                inputs.append(StepInput(h, producer(2, eid)))
            else:
                src = edge_source[key]
                p = produced.get(src)
                if p is None or p >= s.ordinal:
                    raise SpecError("plan order is not topological")
                producer_region = regions[nodes[src[0]].region_id]
                inputs.append(StepInput(header_of(port, producer_region), producer(1, p, src[1])))
        outputs = tuple(header_of(ports[(o.node_id, 1, o.port_id)], regions[node.region_id])
                        for o in sorted(s.outputs, key=lambda r: (r.node_id, r.direction, r.port_id)))
        step_specs.append(StepSpec(
            region_id=s.region_id, dcpl_segment_id=s.segment_id, node_id=s.node_id, kernel_step=s.kernel_step,
            kernel_id=node.kernel_id, semantic_version=node.semantic_version, abi_version=node.abi_version,
            decomposition_id=s.decomposition_id, decomposition_version=s.decomposition_version, max_cu=max_cu,
            parameter_digest=parameter_digest(node), port_shapes_digest=port_shapes_digest(node_ports[s.node_id]),
            inputs=tuple(inputs), outputs=outputs).encode())
    outs = []
    for o in sorted(graph.outputs, key=lambda o: o.external_id):
        port = ports[(o.source_node, 1, o.source_port)]
        outs.append(out_spec(header_of(port, regions[nodes[o.source_node].region_id]),
                             producer(1, produced[(o.source_node, o.source_port)], o.source_port)))
    n = len(steps)
    [(address_base, block_height)], height = place_blocks([(1, n, 0)])
    in_records = [in_spec(eid, in_headers[eid]) for eid in sorted(in_headers)]
    first_out = 1 + 1 + len(in_records)
    first_step = first_out + len(outs) + len(graph.regions)
    block = Block(1, 0, n, 0, 0, 0, 0, first_step, n, address_base, block_height)
    records = [(TYPE_HEADER, spec_header(1, 0, len(in_records), len(outs), 0, len(graph.regions), n, len(outs))),
               (TYPE_BLOCK, block.record())]
    records += [(TYPE_IN, r) for r in in_records]
    records += [(TYPE_OUT, r) for r in outs]
    records += [(TYPE_REGION, region_spec(r)) for r in sorted(graph.regions, key=lambda r: r.region_id)]
    records += [(TYPE_STEP, r) for r in step_specs]
    return Spec(records, [block], [step_specs], {eid: r for eid, r in zip(sorted(in_headers), in_records)}, outs,
                n, len(outs), height, first_out)
