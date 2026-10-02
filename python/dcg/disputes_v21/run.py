"""Run identity, step leaves, honest execution and commitments (design §6), step-1 scope."""

from __future__ import annotations

import copy
import hashlib
import struct
from dataclasses import dataclass, field

from dcg.graph import v2 as wire

from . import spec as S
from . import trees

VALUE_DOMAIN = b"dcg.value.v2\x00"
LEAF_DOMAIN = b"dcg.region.leaf.v2\x00"  # frozen v2.0 step-leaf domain
RUN_ID_DOMAIN = b"dcg.run.id.v2.1\x00"
RUN_ROOT_DOMAIN = b"dcg.run.root.v2.1\x00"
OUT_LEAF_DOMAIN = b"dcg.out.leaf.v2.1\x00"


def value_digest(value: bytes) -> bytes:
    return hashlib.sha256(VALUE_DOMAIN + value).digest()


def external_ref(external_id: int, header: bytes, digest: bytes) -> bytes:
    """The frozen 52-byte external input ref, from an InSpec header (bytes 7..23)."""
    layout_id, layout_version, scheme_id, scheme_version, byte_length = struct.unpack("<IHIHI", header[7:23])
    return struct.pack("<IIHIHI", external_id, layout_id, layout_version, scheme_id, scheme_version,
                       byte_length) + digest


def run_id(template_id: bytes, nonce: bytes, external_refs: list[bytes], executor: bytes) -> bytes:
    refs = sorted(external_refs, key=lambda r: struct.unpack_from("<I", r)[0])
    return hashlib.sha256(RUN_ID_DOMAIN + template_id + nonce + struct.pack("<I", len(refs)) + b"".join(refs)
                          + executor).digest()


# --- step leaves (frozen preimage, graph-plan-v2 §5) ----------------------------------------

def leaf_preimage(plan_id: bytes, run: bytes, region: int, segment: int, ordinal: int, node: int,
                  kernel_step: int, inputs: list[bytes], outputs: list[bytes],
                  prior: bytes = bytes(32), nxt: bytes = bytes(32)) -> bytes:
    """`inputs` and `outputs` are 55-byte ValueRefV1 encodings, already sorted."""
    return (plan_id + run + struct.pack("<IIIQII", region, region, segment, ordinal, node, kernel_step)
            + struct.pack("<H", len(inputs)) + b"".join(inputs) + struct.pack("<H", len(outputs))
            + b"".join(outputs) + prior + nxt)


def leaf_hash(preimage: bytes | None) -> bytes:
    return trees.EMPTY_LEAF if preimage is None else hashlib.sha256(LEAF_DOMAIN + preimage).digest()


@dataclass(frozen=True)
class Leaf:
    plan_id: bytes
    run_id: bytes
    region: int
    coord_region: int
    segment: int
    ordinal: int
    node: int
    kernel_step: int
    inputs: tuple[bytes, ...]
    outputs: tuple[bytes, ...]
    prior: bytes
    next: bytes


def parse_leaf(raw: bytes) -> Leaf | None:
    """Strict parse; None for anything malformed (the malformed-data rule, §7.3)."""
    try:
        if len(raw) < 64 + 28 + 2:
            return None
        plan_id, run = raw[:32], raw[32:64]
        region, coord_region, segment, ordinal, node, kernel_step = struct.unpack_from("<IIIQII", raw, 64)
        at = 92
        (n_in,) = struct.unpack_from("<H", raw, at)
        at += 2
        ins = [raw[at + 55 * i:at + 55 * (i + 1)] for i in range(n_in)]
        at += 55 * n_in
        (n_out,) = struct.unpack_from("<H", raw, at)
        at += 2
        outs = [raw[at + 55 * i:at + 55 * (i + 1)] for i in range(n_out)]
        at += 55 * n_out
        if len(raw) != at + 64 or any(len(r) != 55 for r in ins + outs):
            return None
        return Leaf(plan_id, run, region, coord_region, segment, ordinal, node, kernel_step, tuple(ins),
                    tuple(outs), raw[at:at + 32], raw[at + 32:at + 64])
    except struct.error:
        return None


def out_leaf(index: int, entry: bytes | None) -> bytes:
    return trees.EMPTY_OUT if entry is None else hashlib.sha256(OUT_LEAF_DOMAIN + struct.pack("<Q", index)
                                                                 + entry).digest()


def run_root_bytes(plan_id: bytes, run: bytes, spec_root: bytes, total_steps: int, step_root: bytes,
                   total_outputs: int, out_root: bytes) -> bytes:
    raw = plan_id + run + spec_root + struct.pack("<Q", total_steps) + step_root + struct.pack("<Q", total_outputs) + out_root
    assert len(raw) == 176
    return raw


def run_root(raw: bytes) -> bytes:
    return hashlib.sha256(RUN_ROOT_DOMAIN + raw).digest()


# --- kernels ----------------------------------------------------------------------------------

def replay(kernel_id: bytes, inputs: list[bytes]) -> list[bytes] | None:
    """Host replay of the registered kernels on i32 cells; None on a kernel refusal."""
    from dcg import kernels

    name = kernel_id.rstrip(b"\x00").decode().split("/")[0]
    spec = next((k for k in kernels.REGISTRY.values() if k.name == name), None)
    if spec is None or len(inputs) != spec.arity or any(len(v) != 4 for v in inputs):
        return None
    try:
        out = kernels.host(spec, [struct.unpack("<i", v)[0] for v in inputs])
    except OverflowError:
        return None
    return [struct.pack("<i", out)]


# --- execution and commitment ---------------------------------------------------------------

@dataclass
class Commitment:
    """What an executor commits: leaves by ordinal (None = empty), out entries, and the trees."""

    plan_id: bytes
    run_id: bytes
    spec: S.Spec
    leaves: list[bytes | None]
    out_entries: list[bytes | None]
    values: dict[tuple[int, int], bytes] = field(default_factory=dict)  # (ordinal, port) -> output bytes
    step_tree: trees.Tree = field(init=False)
    out_tree: trees.Tree = field(init=False)
    node_overrides: dict[tuple[int, int], bytes] = field(default_factory=dict)  # (level, position) -> hash

    def __post_init__(self):
        self.rebuild()

    def rebuild(self) -> None:
        leaves = [leaf_hash(x) for x in self.leaves]
        self.step_tree = trees.build("step", leaves, self.spec.address_height)
        for (level, position), h in sorted(self.node_overrides.items()):
            # A forged internal node: replace it and re-fold above it.
            self.step_tree.levels[level][position] = h
            for l in range(level, self.step_tree.height):
                p = position >> (l - level)
                left, right = self.step_tree.levels[l][p & ~1], self.step_tree.levels[l][p | 1]
                self.step_tree.levels[l + 1][p >> 1] = trees.node("step", l, left, right)
        self.out_tree = trees.build("out", [out_leaf(j, e) for j, e in enumerate(self.out_entries)])

    @property
    def root_bytes(self) -> bytes:
        return run_root_bytes(self.plan_id, self.run_id, self.spec.root, self.spec.total_steps,
                              self.step_tree.root, self.spec.total_outputs, self.out_tree.root)

    @property
    def root(self) -> bytes:
        return run_root(self.root_bytes)

    def clone(self) -> "Commitment":
        c = copy.copy(self)
        c.leaves = list(self.leaves)
        c.out_entries = list(self.out_entries)
        c.values = dict(self.values)
        c.node_overrides = dict(self.node_overrides)
        c.rebuild()
        return c


def value_ref(header: bytes, digest: bytes) -> bytes:
    return header + digest


def execute(spec: S.Spec, plan_id: bytes, run: bytes, external_values: dict[int, bytes]) -> Commitment:
    """The honest execution H of one enumerated block."""
    values: dict = {("ext", eid): v for eid, v in external_values.items()}
    leaves: list[bytes | None] = []
    for ordinal, raw in enumerate(spec.step_specs):
        d = S.decode_step_spec(raw)
        in_values, in_refs = [], []
        for header, prod, _initial in d["inputs"]:
            kind, a, b, _c, _d = S.decode_producer(prod)
            v = external_values[a] if kind == 2 else values[(a, b)]
            in_values.append(v)
            in_refs.append(value_ref(header, value_digest(v)))
        outs = replay(d["kernel_id"], in_values)
        if outs is None:
            raise ValueError(f"step {ordinal} refused by its kernel")
        out_refs = []
        for header, v in zip(d["outputs"], outs):
            port = struct.unpack_from("<H", header, 5)[0]
            values[(ordinal, port)] = v
            out_refs.append(value_ref(header, value_digest(v)))
        leaves.append(leaf_preimage(plan_id, run, d["region"], d["segment"], ordinal, d["node"], d["kernel_step"],
                                    in_refs, out_refs))
    entries = []
    for raw in spec.out_specs:
        header, prod = raw[8:31], raw[32:56]
        _k, a, b, _c, _d = S.decode_producer(prod)
        entries.append(value_ref(header, value_digest(values[(a, b)])))
    return Commitment(plan_id, run, spec, leaves, entries, values)
