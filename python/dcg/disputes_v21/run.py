"""Run identity, step leaves, honest execution and commitments (design §6)."""

from __future__ import annotations

import copy
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable

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

def canonical_kernel_name(kernel_id: bytes) -> str | None:
    """A kernel id's name: the bytes before its NUL padding, which must be
    valid UTF-8 and followed only by NULs (the program's rule). None otherwise."""
    raw = bytes(kernel_id)
    name = raw.rstrip(b"\x00")
    if b"\x00" in name:
        return None
    try:
        return name.decode()
    except UnicodeDecodeError:
        return None


def replay(kernel_id: bytes, inputs: list[bytes]) -> list[bytes] | None:
    """Host replay of the registered kernels on i32 cells; None on a kernel
    refusal or an unknown id. The id must be exactly `name/v<semantic>`."""
    from dcg import kernels

    name = canonical_kernel_name(kernel_id)
    spec = next((k for k in kernels.REGISTRY.values() if f"{k.name}/v{k.semantic_version}" == name), None)
    if spec is None or len(inputs) != spec.arity or any(len(v) != 4 for v in inputs):
        return None
    try:
        out = kernels.host(spec, [struct.unpack("<i", v)[0] for v in inputs])
    except OverflowError:
        return None
    return [struct.pack("<i", out)]


def replay_step(kernel_id: bytes, inputs: list[bytes], prior: bytes | None, semantic_version: int = 1,
                abi_version: int = 1) -> tuple[list[bytes], bytes | None] | None:
    """Replay one step: (outputs by port order, next state or None); None on
    refusal. Application kernels resolve by (id, semantic, ABI) exactly, as
    the program resolves them from the image's manifest."""
    from . import appkernels, reductions

    k = reductions.lookup(kernel_id)
    if k is None:
        if prior is not None:
            return None
        app = appkernels.REGISTRY.get((bytes(kernel_id), semantic_version, abi_version))
        if app is not None:
            try:
                return app(inputs), None
            except ValueError:
                return None
        outs = replay(kernel_id, inputs)
        return None if outs is None else (outs, None)
    if len(inputs) != k.arity or (prior is None) != (k.state_bytes == 0):
        return None
    if prior is not None and len(prior) != k.state_bytes:
        return None
    try:
        outs, nxt = k.fn(inputs, prior if prior is not None else b"")
    except (ValueError, struct.error):
        return None
    return outs, (nxt if k.state_bytes else None)


def replay_log_step(d: dict, inputs: list[bytes], entries: list[bytes]) -> tuple[list[bytes], list[bytes]] | None:
    """Replay a LOG step: the kernel reads every entry and appends one."""
    from . import reductions

    k = reductions.lookup_log(d["kernel_id"])
    if k is None or len(inputs) != k.arity or d["state_unit"] != k.entry_bytes or len(entries) >= d["state_size"]:
        return None
    try:
        outs, new = k.fn(inputs, entries)
    except (ValueError, struct.error):
        return None
    if len(new) != k.entry_bytes:
        return None
    return outs, entries + [new]


# --- chunked values (§4.2) ------------------------------------------------------------------

CHUNK_LEAF_DOMAIN = b"dcg.chunk.leaf.v2.1\x00"


def chunks(value: bytes, chunk_bytes: int) -> list[bytes]:
    return [value[i:i + chunk_bytes] for i in range(0, len(value), chunk_bytes)] or [b""]


def chunk_leaf(index: int, chunk: bytes) -> bytes:
    return hashlib.sha256(CHUNK_LEAF_DOMAIN + struct.pack("<Q", index) + chunk).digest()


def chunk_tree(value: bytes, chunk_bytes: int) -> trees.Tree:
    return trees.build("chunk", [chunk_leaf(i, c) for i, c in enumerate(chunks(value, chunk_bytes))])


def chunked_digest(value: bytes, chunk_bytes: int) -> bytes:
    return chunk_tree(value, chunk_bytes).root


def input_digest(in_spec_record: bytes, value: bytes) -> bytes:
    """The digest an external ref carries: plain, or the chunk-tree root."""
    chunk_log2 = in_spec_record[32]
    return chunked_digest(value, 1 << chunk_log2) if chunk_log2 else value_digest(value)


def const_chunk_log2(const_spec_record: bytes) -> int:
    """A chunked constant's chunk_log2: its header's layout_version (layout 3)."""
    header = const_spec_record[8:31]
    return struct.unpack_from("<H", header, 11)[0] if struct.unpack_from("<I", header, 7)[0] == 3 else 0


LIST_DOMAIN = b"dcg.list.v2.1\x00"
LIST_LEAF_DOMAIN = b"dcg.list.leaf.v2.1\x00"


def list_leaf(index: int, element_ref: bytes) -> bytes:
    """One list element: its 55-byte value ref (ListSpec header, value digest)."""
    assert len(element_ref) == 55
    return hashlib.sha256(LIST_LEAF_DOMAIN + struct.pack("<I", index) + element_ref).digest()


def list_tree(element_refs: list[bytes]) -> trees.Tree:
    return trees.build("list", [list_leaf(j, r) for j, r in enumerate(element_refs)])


def list_digest(element_refs: list[bytes]) -> bytes:
    """A list input's digest: H(count || root of the element tree)."""
    return hashlib.sha256(LIST_DOMAIN + struct.pack("<I", len(element_refs)) + list_tree(element_refs).root).digest()


def flatten(values: list) -> list[bytes]:
    """Kernel inputs: a list input contributes its elements in order."""
    out = []
    for v in values:
        out.extend(v if isinstance(v, list) else [v])
    return out


LOG_DOMAIN = b"dcg.log.v2.1\x00"
LOG_ENTRY_DOMAIN = b"dcg.log.entry.v2.1\x00"


def log_entry_leaf(index: int, entry: bytes) -> bytes:
    return hashlib.sha256(LOG_ENTRY_DOMAIN + struct.pack("<Q", index) + entry).digest()


def log_tree(entries: list[bytes], capacity: int) -> trees.Tree:
    """The fixed-capacity LOG tree: `capacity` slots, empty ones EMPTY_LOG."""
    if len(entries) > capacity:
        raise ValueError("log over capacity")
    leaves = [log_entry_leaf(i, e) for i, e in enumerate(entries)]
    return trees.build("log", leaves, trees.height_for(capacity))


def log_digest_from_root(length: int, root: bytes) -> bytes:
    return hashlib.sha256(LOG_DOMAIN + struct.pack("<Q", length) + root).digest()


def log_digest(entries: list[bytes], capacity: int) -> bytes:
    return log_digest_from_root(len(entries), log_tree(entries, capacity).root)


def state_digest(d: dict, state) -> bytes:
    """A state's digest by scheme: SMALL is the value digest of its bytes;
    LOG is H(length || root) over `state_size` slots."""
    if d["state_scheme"] == 2:
        return log_digest(state, d["state_size"])
    return value_digest(state)


def small_state_digest(state: bytes) -> bytes:
    return value_digest(state)


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
    states: dict[int, bytes] = field(default_factory=dict)  # ordinal -> next state bytes
    last_running: dict[int, int] = field(default_factory=dict)  # repeated block -> last running iteration
    # (ordinal, input index) -> the list input's element refs, revealed with the leaf
    lists: dict[tuple[int, int], list[bytes]] = field(default_factory=dict)

    def __post_init__(self):
        self.rebuild()

    def rebuild(self) -> None:
        positioned = [trees.EMPTY_LEAF] * (1 << self.spec.address_height)
        for ordinal, x in enumerate(self.leaves):
            positioned[self.spec.position_of(ordinal)] = leaf_hash(x)
        self.step_tree = trees.build("step", positioned, self.spec.address_height)
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
        c.states = dict(self.states)
        c.lists = {k: list(v) for k, v in self.lists.items()}
        c.rebuild()
        return c


def value_ref(header: bytes, digest: bytes) -> bytes:
    return header + digest


def execute(spec: S.Spec, plan_id: bytes, run: bytes, external_values: dict[int, bytes],
            fault: Callable[[int, list[bytes], bytes | None], tuple[list[bytes], bytes | None]] | None = None,
            input_fault: Callable[[int, int, bytes], bytes] | None = None,
            prior_fault: Callable[[int, bytes], bytes] | None = None,
            constants: dict[int, bytes] | None = None,
            list_fault: Callable[[int, int, int, bytes], bytes] | None = None) -> Commitment:
    """The honest execution H (or, with `fault`, an executor that corrupts one
    step's results and then continues consistently from them).

    `fault(ordinal, outputs, next_state)` may return altered results;
    `input_fault(ordinal, index, value)` an altered input value and
    `prior_fault(ordinal, prior)` an altered prior state, both before replay;
    `list_fault(ordinal, index, element, value)` an altered list element."""
    constants = spec.constant_values if constants is None else constants
    values: dict = {("ext", eid): v for eid, v in external_values.items()}
    values.update({("const", cid): v for cid, v in constants.items()})
    states: dict[int, bytes] = {}
    leaves: list[bytes | None] = [None] * spec.total_steps
    last_running: dict[int, int] = {}
    lists: dict[tuple[int, int], list[bytes]] = {}

    def fetch(prod: bytes) -> bytes:
        kind, a, b, _c, d = S.decode_producer(prod)
        if kind == 1:
            return values[(a, b)]
        if kind == 2:
            return external_values[a]
        if kind == 3:
            return constants[a]
        if kind == 5:
            if b == 3:
                return chunks(constants[a], 1 << const_chunk_log2(spec.const_specs[a]))[d]
            chunk_bytes = 1 << spec.in_specs[a][32]
            return chunks(external_values[a], chunk_bytes)[d]
        if kind == 6:
            blk = spec.blocks[a]
            t = last_running[a]
            return values[(blk.base + t * blk.body_len + _c, b)]
        if kind == 7:
            return struct.pack("<I", a)
        if kind == S.PRODUCER_LIST:
            _lid, elements = S.decode_list_spec(spec.list_specs[a])
            return [fetch(prod) for _h, prod in elements]
        raise ValueError(f"producer kind {kind}")

    def state_of(d: dict) -> bytes | None:
        if not d["state_scheme"]:
            return None
        kind, a, *_ = S.decode_producer(d["state_predecessor"])
        if kind == 1:
            return states[a]
        if kind == 2:
            return external_values[a]
        return [] if d["state_scheme"] == 2 else bytes(d["state_size"])  # EMPTY_STATE

    def run_step(ordinal: int) -> None:
        d = S.decode_step_spec(spec.step_spec(ordinal))
        in_values = [fetch(prod) for _h, prod, _i in d["inputs"]]
        if input_fault is not None:
            in_values = [v if isinstance(v, list) else input_fault(ordinal, i, v) for i, v in enumerate(in_values)]
        in_refs = []
        for i, ((h, prod, _i), v) in enumerate(zip(d["inputs"], in_values)):
            if not isinstance(v, list):
                in_refs.append(value_ref(h, value_digest(v)))
                continue
            if list_fault is not None:
                v = in_values[i] = [list_fault(ordinal, i, j, e) for j, e in enumerate(v)]
            _lid, elements = S.decode_list_spec(spec.list_specs[S.decode_producer(prod)[1]])
            refs = [value_ref(eh, value_digest(e)) for (eh, _p), e in zip(elements, v)]
            lists[(ordinal, i)] = refs
            in_refs.append(value_ref(h, list_digest(refs)))
        prior = state_of(d)
        if prior_fault is not None and prior is not None and d["state_scheme"] == 1:
            prior = prior_fault(ordinal, prior)
        if d["state_scheme"] == 2:
            result = replay_log_step(d, in_values, prior)
        else:
            result = replay_step(d["kernel_id"], flatten(in_values), prior,
                                 d["semantic_version"], d["abi_version"])
        if result is None:
            raise ValueError(f"step {ordinal} refused by its kernel")
        outs, nxt = result
        if fault is not None:
            outs, nxt = fault(ordinal, list(outs), nxt)
        out_refs = []
        for header, v in zip(d["outputs"], outs):
            port = struct.unpack_from("<H", header, 5)[0]
            values[(ordinal, port)] = v
            out_refs.append(value_ref(header, value_digest(v)))
        if nxt is not None:
            states[ordinal] = nxt
        z = bytes(32)
        leaves[ordinal] = leaf_preimage(
            plan_id, run, d["region"], d["segment"], ordinal, d["node"], d["kernel_step"], in_refs, out_refs,
            state_digest(d, prior) if prior is not None else z,
            state_digest(d, nxt) if nxt is not None else z)

    for bi, blk in enumerate(spec.blocks):
        if blk.kind == 1:
            for ordinal in range(blk.base, blk.base + blk.step_count):
                run_step(ordinal)
            continue
        for i in range(blk.k):
            for e in range(blk.body_len):
                run_step(blk.base + i * blk.body_len + e)
            last_running[bi] = i
            gate = values.get((blk.base + i * blk.body_len + blk.gate_entry, blk.gate_port))
            if gate is None or struct.unpack("<i", gate)[0] == 0:
                break
    entries = []
    for raw in spec.out_specs:
        header, prod = raw[8:31], raw[32:56]
        entries.append(value_ref(header, value_digest(fetch(prod))))
    c = Commitment(plan_id, run, spec, leaves, entries, values)
    c.states, c.last_running, c.lists = states, last_running, lists
    return c
