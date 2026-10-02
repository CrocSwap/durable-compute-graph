"""Root-committed optimistic runs and the root → region → step descent.

The executor commits one RegionRootV1 digest for the root region (spec §5).
A dispute walks the region tree: the executor reveals a region's RegionRootV1,
the challenger picks a child region or a leaf of that region's step tree, the
executor reveals the leaf and its Merkle path, and the challenger replays it on
chain with every input authenticated against its source.

Encodings are the frozen §5 ones from ``dcg.graph.v2``. The value digest is
PROVISIONAL (the spec does not fix it): SHA256("dcg.value.v2.provisional\\0" ||
value bytes), matching the program's ``VALUE_DOMAIN``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.graph import v2 as wire
from dcg.graph_client import SYSTEM, GraphClient
from dcg.tracing import Graph, PLAN_DOMAIN

VALUE_DOMAIN = b"dcg.value.v2.provisional\x00"
LEAF_DOMAIN = b"dcg.region.leaf.v2\x00"
NODE_DOMAIN = b"dcg.region.node.v2\x00"


def value_digest(value: bytes) -> bytes:
    return hashlib.sha256(VALUE_DOMAIN + value).digest()


def _blob16(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


def merkle_path(leaves: list[bytes], index: int) -> list[bytes]:
    """Sibling digests from leaf to root (§5: odd layers duplicate the last)."""
    path, level, depth = [], list(leaves), 0
    while len(level) > 1:
        sibling = index ^ 1
        path.append(level[sibling] if sibling < len(level) else level[index])
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(NODE_DOMAIN + struct.pack("<H", depth) + left + right).digest())
        level, index, depth = nxt, index // 2, depth + 1
    return path


@dataclass
class Commitment:
    """Every region root, leaf and value of one executed run."""

    plan_id: bytes
    run_id: bytes
    root: bytes
    region_bytes: dict[int, bytes]
    region_leaves: dict[int, list[bytes]]  # leaf digests in ordinal order
    region_ordinals: dict[int, list[int]]
    leaf_bytes: dict[int, bytes]  # ordinal -> leaf preimage (without domain)
    values: dict[tuple[int, int, int], bytes]  # (node, direction, port) -> value bytes


def build(graph: Graph, run_id: bytes, inputs: list[int], trace: list[int],
          forge: dict[tuple[int, int, int], bytes] | None = None) -> Commitment:
    """The §5 commitment of ``graph`` run on ``inputs`` with the executor's ``trace``
    (one i32 cell per step, possibly dishonest). ``forge`` overrides individual
    port values after propagation, to build inconsistent commitments in tests."""
    g = wire.decode_graph(graph.graph_bytes())
    p = wire.decode_plan(graph.plan_bytes())
    plan_id = hashlib.sha256(PLAN_DOMAIN + graph.plan_bytes()).digest()
    port = {(q.node_id, q.direction, q.port_id): q for q in g.ports}
    regions = {r.region_id: r for r in p.regions}

    values: dict[tuple[int, int, int], bytes] = {}
    for index, item in enumerate(g.inputs):
        values[(item.destination_node, 0, item.destination_port)] = struct.pack("<i", inputs[index])
    for step in p.steps:
        (out,) = step.outputs
        values[(out.node_id, 1, out.port_id)] = struct.pack("<i", trace[step.ordinal])
    for edge in g.edges:
        values[(edge.destination_node, 0, edge.destination_port)] = values[(edge.source_node, 1, edge.source_port)]
    values.update(forge or {})

    def ref(node: int, direction: int, port_id: int) -> wire.ValueRefV1:
        q = port[(node, direction, port_id)]
        v = values[(node, direction, port_id)]
        return wire.ValueRefV1(node, direction, port_id, q.layout_id, q.layout_version, 2, 1, q.byte_length,
                               value_digest(v))

    leaf_bytes: dict[int, bytes] = {}
    leaf_digest: dict[int, bytes] = {}
    for s in p.steps:
        ins = tuple(ref(r.node_id, 0, r.port_id) for r in s.inputs)
        outs = tuple(ref(r.node_id, 1, r.port_id) for r in s.outputs)
        body = (plan_id + run_id + struct.pack("<IIIQII", s.region_id, s.region_id, s.segment_id, s.ordinal, s.node_id,
                                                 s.kernel_step)
                + struct.pack("<H", len(ins)) + b"".join(wire.encode_value_ref(v) for v in ins)
                + struct.pack("<H", len(outs)) + b"".join(wire.encode_value_ref(v) for v in outs)
                + bytes(64))
        leaf_bytes[s.ordinal] = body
        leaf_digest[s.ordinal] = wire.step_leaf_digest(plan_id, run_id, s.region_id, s.segment_id, s.ordinal,
                                                       s.node_id, s.kernel_step, ins, outs)
        assert hashlib.sha256(LEAF_DOMAIN + body).digest() == leaf_digest[s.ordinal]

    node_region = {n.node_id: n.region_id for n in g.nodes}
    consumers: dict[tuple[int, int], list[int]] = {}
    for edge in g.edges:
        consumers.setdefault((edge.source_node, edge.source_port), []).append(node_region[edge.destination_node])
    graph_outputs = {(o.source_node, o.source_port) for o in g.outputs}

    region_bytes: dict[int, bytes] = {}
    region_root: dict[int, bytes] = {}
    region_leaves: dict[int, list[bytes]] = {}
    region_ordinals: dict[int, list[int]] = {}

    def depth(rid: int) -> int:
        return 0 if rid == 0 else 1 + depth(regions[rid].parent_region_id)

    for rid in sorted(regions, key=depth, reverse=True):  # children first
        r = regions[rid]
        own = [s for s in p.steps if s.region_id == rid]
        region_ordinals[rid] = [s.ordinal for s in own]
        region_leaves[rid] = [leaf_digest[s.ordinal] for s in own]
        own_nodes = {s.node_id for s in own}
        ins = sorted({(i.node_id, 0, i.port_id) for s in own for i in s.inputs
                      if not any(e.destination_node == i.node_id and e.destination_port == i.port_id
                                 and e.source_node in own_nodes for e in g.edges)})
        outs = sorted({(o.node_id, 1, o.port_id) for s in own for o in s.outputs
                       if (o.node_id, o.port_id) in graph_outputs
                       or any(c != rid for c in consumers.get((o.node_id, o.port_id), []))})
        children = tuple(
            wire.ChildRootV1(c.region_id, c.mode_id, c.mode_version, c.scheme_id, c.scheme_version, c.layout_id,
                             c.layout_version, region_root[c.region_id])
            for c in sorted(regions.values(), key=lambda x: x.region_id) if c.region_id != 0 and c.parent_region_id == rid)
        model = wire.RegionRootV1(plan_id, run_id, rid, r.mode_id, r.mode_version, r.scheme_id, r.scheme_version,
                                  r.layout_id, r.layout_version, tuple(ref(*k) for k in ins),
                                  wire.merkle_root(tuple(region_leaves[rid])), children,
                                  tuple(ref(*k) for k in outs), bytes(32))
        region_bytes[rid] = wire.encode_region_root(model)
        region_root[rid] = wire.region_root_digest(model)
    return Commitment(plan_id, run_id, region_root[0], region_bytes, region_leaves, region_ordinals, leaf_bytes,
                      values)


class DescentClient:
    """Tags 220..226 over a ``GraphClient``."""

    def __init__(self, client: GraphClient):
        self.c = client

    def dispute(self, run: Pubkey) -> Pubkey:
        return self.c.pda(b"dcg2disp", bytes(run))

    def read(self, run: Pubkey) -> dict:
        d = self.c.account(self.dispute(run))
        return {"phase": d[4], "winner": d[5], "region": struct.unpack_from("<I", d, 80)[0],
                "deadline": struct.unpack_from("<Q", d, 8)[0]}

    def _metas(self, admitted, run, signer: Keypair, writable: bool = False):
        return [AccountMeta(signer.pubkey(), True, writable), AccountMeta(run, False, True),
                AccountMeta(admitted["template"], False, False), AccountMeta(self.dispute(run), False, True)]

    def commit_root(self, admitted, run, commitment: Commitment, trace: list[int], executor: Keypair):
        data = bytes([220]) + commitment.root + b"".join(struct.pack("<i", v) for v in trace)
        return self.c.send(data, self._metas(admitted, run, executor, True) + [AccountMeta(SYSTEM, False, False)],
                           [executor])

    def open(self, admitted, run, challenger: Keypair):
        return self.c.send(bytes([221]), self._metas(admitted, run, challenger, True), [challenger])

    def reveal_region(self, admitted, run, commitment: Commitment, region: int, executor: Keypair):
        return self.c.send(bytes([222]) + commitment.region_bytes[region], self._metas(admitted, run, executor),
                           [executor])

    def choose(self, admitted, run, kind: int, value: int, challenger: Keypair):
        return self.c.send(bytes([223, kind]) + struct.pack("<I", value), self._metas(admitted, run, challenger),
                           [challenger])

    def reveal_leaf(self, admitted, run, commitment: Commitment, region: int, index: int, executor: Keypair):
        ordinal = commitment.region_ordinals[region][index]
        path = merkle_path(commitment.region_leaves[region], index)
        return self.c.send(bytes([224]) + _blob16(commitment.leaf_bytes[ordinal]) + _blob16(b"".join(path)),
                           self._metas(admitted, run, executor), [executor])

    def replay(self, admitted, run, graph: Graph, commitment: Commitment, region: int, index: int,
               challenger: Keypair):
        """Replay leaf ``index`` of ``region`` with the executor's own committed values
        and the authentication the program requires for each input."""
        g = wire.decode_graph(graph.graph_bytes())
        p = wire.decode_plan(graph.plan_bytes())
        ordinal = commitment.region_ordinals[region][index]
        step = p.steps[ordinal]
        data = bytes([225]) + _blob16(commitment.leaf_bytes[ordinal])
        external = {(i.destination_node, i.destination_port) for i in g.inputs}
        producer_step = {(s.outputs[0].node_id, s.outputs[0].port_id): s for s in p.steps}
        for r in step.inputs:
            data += _blob16(commitment.values[(r.node_id, 0, r.port_id)])
            if (r.node_id, r.port_id) in external:
                data += bytes([0])
                continue
            edge = next(e for e in g.edges if (e.destination_node, e.destination_port) == (r.node_id, r.port_id))
            src = producer_step[(edge.source_node, edge.source_port)]
            parent = next(r.parent_region_id for r in p.regions if r.region_id == region)
            if src.region_id in (region, parent):
                # 1: a producer in this region; 3: in the parent region the
                # descent came from (authenticated under its step root).
                k = commitment.region_ordinals[src.region_id].index(src.ordinal)
                data += (bytes([1 if src.region_id == region else 3]) + _blob16(commitment.leaf_bytes[src.ordinal])
                         + struct.pack("<I", k)
                         + _blob16(b"".join(merkle_path(commitment.region_leaves[src.region_id], k))))
            else:
                data += bytes([2]) + _blob16(commitment.region_bytes[src.region_id])
        metas = self._metas(admitted, run, challenger, True) + [
            AccountMeta(admitted["graph"], False, False), AccountMeta(admitted["plan"], False, False)]
        return self.c.send(data, metas, [challenger], cu=1_400_000)

    def settle(self, admitted, run, executor: Pubkey, challenger: Pubkey):
        metas = [AccountMeta(self.c.payer.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(admitted["template"], False, False), AccountMeta(self.dispute(run), False, True),
                 AccountMeta(executor, False, True), AccountMeta(challenger, False, True)]
        return self.c.send(bytes([226]), metas)
