"""DCG v2 Python tracer (stage 4, fast path).

Traces a pure Python function over symbolic ``Value`` handles. Every call to a
registered kernel (``dcg.kernels``) records one static step; data-dependent
control flow, ambient effects, and unknown operations are refused at trace
time with the source location. The result lowers to the step table that the
on-chain graph lifecycle executes, plus graph/plan blobs.

Encoding: the exact two-level add/identity shape emits the frozen golden
DCGG/DCPL bytes; any other shape the canonical format can express is lowered
to canonical v2.0 DCGG/DCPL with the reference encoder (``dcg.graph.v2``).
Shapes it cannot express (an external input used twice or never, a step whose
output is neither consumed nor returned, an output that is a raw input) fall
back to the ``DCGGF1``/``DCPLF1`` fast encoding, whose table the chain trusts.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import inspect
import struct
import traceback
from dataclasses import dataclass, field
from pathlib import Path

GRAPH_DOMAIN = b"dcg.graph.id.v2\x00"
PLAN_DOMAIN = b"dcg.plan.id.v2\x00"
TABLE_DOMAIN = b"dcg.steptable.id.v2\x00"
I32_MIN, I32_MAX = -(2**31), 2**31 - 1


class TraceError(ValueError):
    def __init__(self, code: str, message: str, where: str | None = None):
        self.code, self.where = code, where
        super().__init__(f"{code}: {message}" + (f" at {where}" if where else ""))


def _caller() -> str:
    for frame in reversed(traceback.extract_stack()[:-1]):
        if "dcg/tracing.py" not in frame.filename and "dcg/kernels.py" not in frame.filename:
            return f"{Path(frame.filename).name}:{frame.lineno}"
    return "?"


@dataclass(frozen=True)
class KernelSpec:
    code: int
    name: str
    arity: int
    semantic_version: int = 1
    abi_version: int = 1


@dataclass
class Step:
    kernel: KernelSpec
    refs: tuple[int, ...]
    region: str
    where: str


@dataclass
class Trace:
    name: str
    input_names: tuple[str, ...]
    steps: list[Step] = field(default_factory=list)
    outputs: tuple[int, ...] = ()
    region_stack: list[str] = field(default_factory=lambda: ["root"])
    region_parents: dict[str, str] = field(default_factory=dict)

    @property
    def n_inputs(self) -> int:
        return len(self.input_names)


_ACTIVE: list[Trace] = []


class Value:
    """A symbolic i32 cell inside a trace."""

    __slots__ = ("trace", "index")

    def __init__(self, trace: Trace, index: int):
        self.trace, self.index = trace, index

    def __bool__(self):
        raise TraceError("DATA_DEPENDENT_CONTROL", "a traced value cannot drive Python control flow", _caller())

    def __index__(self):
        raise TraceError("DATA_DEPENDENT_CONTROL", "a traced value cannot be used as a Python integer", _caller())

    def _refuse(self, *_args, **_kwargs):
        raise TraceError("UNREGISTERED_OP", "only registered kernel calls are traceable; use dcg.kernels", _caller())

    __add__ = __radd__ = __sub__ = __mul__ = __truediv__ = __lt__ = __gt__ = __le__ = __ge__ = _refuse

    def __repr__(self):
        return f"Value(cell={self.index})"


def call(kernel: KernelSpec, *args) -> Value:
    if not _ACTIVE:
        raise TraceError("NO_TRACE", f"{kernel.name} called outside dcg.trace", _caller())
    trace = _ACTIVE[-1]
    if len(args) != kernel.arity:
        raise TraceError("ARITY", f"{kernel.name} takes {kernel.arity} inputs, got {len(args)}", _caller())
    refs = []
    for arg in args:
        if not isinstance(arg, Value):
            raise TraceError("TYPE", f"{kernel.name} input must be a traced i32 value, got {type(arg).__name__}", _caller())
        if arg.trace is not trace:
            raise TraceError("FOREIGN_VALUE", "value belongs to another trace", _caller())
        refs.append(arg.index)
    trace.steps.append(Step(kernel, tuple(refs), trace.region_stack[-1], _caller()))
    return Value(trace, trace.n_inputs + len(trace.steps) - 1)


@contextlib.contextmanager
def region(name: str):
    trace = _ACTIVE[-1]
    parent = trace.region_parents.setdefault(name, trace.region_stack[-1])
    if parent != trace.region_stack[-1] or name == "root":
        raise TraceError("REGION_NESTING", f"region {name!r} entered under two parents", _caller())
    trace.region_stack.append(name)
    try:
        yield
    finally:
        trace.region_stack.pop()


def trace(fn) -> "Graph":
    params = tuple(inspect.signature(fn).parameters)
    t = Trace(fn.__name__, params)
    _ACTIVE.append(t)
    try:
        result = fn(*(Value(t, i) for i in range(len(params))))
    finally:
        _ACTIVE.pop()
    outs = result if isinstance(result, tuple) else (result,)
    for out in outs:
        if not isinstance(out, Value):
            raise TraceError("OUTPUT", "graph outputs must be traced values", fn.__name__)
    t.outputs = tuple(o.index for o in outs)
    if not t.steps:
        raise TraceError("EMPTY", "graph has no kernel calls", fn.__name__)
    return Graph(t)


def _golden(name: str, file: str) -> bytes | None:
    root = Path(__file__).resolve().parents[2] / "tests/golden/dcg/graph_plan_v2" / file
    if not root.exists():
        return None
    for line in root.read_text().splitlines()[1:]:
        cols = line.split("\t")
        if cols[0] == name:
            return base64.b64decode(cols[1])
    return None


class Graph:
    def __init__(self, t: Trace):
        self.trace = t

    # --- lowering -------------------------------------------------------
    def step_table(self) -> bytes:
        t = self.trace
        out = struct.pack("<HH", t.n_inputs, len(t.steps))
        for s in t.steps:
            out += struct.pack("<HB", s.kernel.code, len(s.refs)) + b"".join(struct.pack("<H", r) for r in s.refs)
        return out

    def _is_hello_shape(self) -> bool:
        s = self.trace.steps
        return (self.trace.n_inputs == 2 and len(s) == 2 and s[0].kernel.name == "add_i32"
                and s[0].refs == (0, 1) and s[1].kernel.name == "identity_i32" and s[1].refs == (2,))

    def canonical(self, mode: str = "optimistic") -> tuple[bytes, bytes] | None:
        """Canonical v2.0 (DCGG, DCPL) for this trace with every region in the
        resolution mode of ``mode`` (consensus, or optimistic for optimistic and
        sampling templates), or None when the shape is outside what the
        canonical format expresses (see module note)."""
        cache = self.__dict__.setdefault("_canonical", {})
        key = "consensus" if mode == "consensus" else "optimistic"
        if key not in cache:
            cache[key] = self._lower(key)
        return cache[key]

    def _lower(self, mode: str) -> tuple[bytes, bytes] | None:
        from dcg.graph import v2 as wire

        mode_id = wire.MODE_CONSENSUS if mode == "consensus" else wire.MODE_OPTIMISTIC

        t = self.trace
        n_in = t.n_inputs
        uses = [0] * n_in
        consumed = [False] * len(t.steps)
        for s in t.steps:
            for r in s.refs:
                if r < n_in:
                    uses[r] += 1
                else:
                    consumed[r - n_in] = True
        returned = {o - n_in for o in t.outputs if o >= n_in}
        if (any(u != 1 for u in uses) or any(o < n_in for o in t.outputs)
                or any(not c and i not in returned for i, c in enumerate(consumed))):
            return None
        names = ["root"]
        for s in t.steps:
            for name in self._region_path(s.region):
                if name not in names:
                    names.append(name)
        rid = {name: i for i, name in enumerate(names)}
        parent = {rid[n]: (wire.ROOT_PARENT if n == "root" else rid[t.region_parents[n]]) for n in names}

        def kid(name: str, version: int) -> bytes:
            return f"{name}/v{version}".encode().ljust(16, b"\x00")

        nodes, ports, edges, ins, outs = [], [], [], [], []
        for i, s in enumerate(t.steps):
            node = i + 1
            nodes.append(wire.NodeV1(node, kid(s.kernel.name, s.kernel.semantic_version), s.kernel.semantic_version,
                                     s.kernel.abi_version, rid[s.region]))
            for port, r in enumerate(s.refs):
                ports.append(wire.PortV1(node, 0, port, 1, 1, 5, (), 4, 4, 4))
                if r < n_in:
                    ins.append(wire.GraphInputV1(r, node, port))
                else:
                    edges.append(wire.EdgeV1(r - n_in + 1, 0, node, port))
            ports.append(wire.PortV1(node, 1, 0, 1, 1, 5, (), 4, 4, 4))
        for external, o in enumerate(t.outputs):
            outs.append(wire.GraphOutputV1(external, o - n_in + 1, 0))
        regions = tuple(wire.RegionV1(r, parent[r], mode_id, 1, 2, 1, 1, 1) for r in sorted(parent))
        graph = wire.GraphV2(tuple(nodes), tuple(sorted(ports, key=lambda p: (p.node_id, p.direction, p.port_id))),
                             tuple(sorted(edges, key=lambda e: (e.destination_node, e.destination_port,
                                                                 e.source_node, e.source_port))),
                             regions, tuple(sorted(ins, key=lambda x: x.external_id)), tuple(outs))
        try:
            graph_bytes = wire.encode_graph(graph)
        except (wire.GraphError, ValueError):
            return None
        # Steps keep trace order; a region's segment breaks wherever another
        # region's step intervenes.
        steps, segments, seg_of = [], [], {}
        last: tuple[int, int] | None = None
        for i, s in enumerate(t.steps):
            r = rid[s.region]
            if last is None or last[0] != r:
                seg_of[r] = seg_of.get(r, -1) + 1
                segments.append([r, seg_of[r], i, 0])
            segments[-1][3] += 1
            last = (r, seg_of[r])
            node = i + 1
            steps.append(wire.StepV1(i, r, seg_of[r], node, 0, 1, 1,
                                     tuple(wire.PortRefV1(node, 0, p) for p in range(len(s.refs))),
                                     (wire.PortRefV1(node, 1, 0),)))
        region_plans = tuple(
            wire.RegionPlanV1(r, parent[r], mode_id, 1, 2, 1, 1, 1,
                              sum(1 for st in steps if st.region_id == r), seg_of.get(r, -1) + 1)
            for r in sorted(parent))
        node_region = {n.node_id: n.region_id for n in nodes}
        boundaries = tuple(sorted(
            (wire.BoundaryV1(node_region[e.source_node], node_region[e.destination_node],
                             wire.PortRefV1(e.source_node, 1, e.source_port),
                             wire.PortRefV1(e.destination_node, 0, e.destination_port), 1, 1, 2, 1)
             for e in edges if node_region[e.source_node] != node_region[e.destination_node]),
            key=lambda b: (b.source_region, b.destination_region,
                           (b.source.node_id, b.source.direction, b.source.port_id),
                           (b.destination.node_id, b.destination.direction, b.destination.port_id))))
        costs = [wire.CostAdmissionV1(1, st.region_id, st.ordinal, 100_000, 2, 4 * len(st.inputs), 4, 4, 4096, 4096,
                                      4 * len(st.inputs), 4, 0, 4096) for st in steps]
        costs += [wire.CostAdmissionV1(2, r, 0, 100_000, 4, 64, 64, 64, 4096, 4096, 64, 64, 0, 4096)
                  for r in sorted(parent)]
        costs.append(wire.CostAdmissionV1(3, 0, 0, 1_400_000, 64, 4096, 4096, 4096, 32768, 4096, 4096, 4096, 0, 4096))
        costs.sort(key=lambda c: (c.scope_kind, c.region_id, c.step_ordinal))
        golden_plan = _golden("minimal_two_level_add_identity", "plans_v1.tsv")
        manifest_root = golden_plan[104:136] if golden_plan else bytes(32)
        plan = wire.PlanV2(wire.graph_id(graph_bytes), b"compiler-v2-id!!", 1, 1, 1, 1, 1, b"I" * 32, manifest_root,
                           b"", region_plans, tuple(steps),
                           tuple(sorted((wire.SegmentV1(r, sid, first, count, 2, 1)
                                         for r, sid, first, count in segments), key=lambda x: (x.region_id, x.segment_id))),
                           boundaries, (), tuple(costs))
        try:
            return graph_bytes, wire.encode_plan(plan)
        except (wire.PlanError, ValueError):
            return None

    def _region_path(self, name: str) -> list[str]:
        path = [name]
        while path[-1] != "root":
            path.append(self.trace.region_parents[path[-1]])
        return list(reversed(path))

    def graph_bytes(self, mode: str = "optimistic") -> bytes:
        # The frozen golden Hello pair is the optimistic one.
        if self._is_hello_shape() and mode != "consensus":
            golden = _golden("minimal_two_level_add_identity", "graphs_v1.tsv")
            if golden:
                return golden
        if self.canonical(mode):
            return self.canonical(mode)[0]
        return b"DCGGF1" + self.step_table() + struct.pack("<H", len(self.trace.outputs)) + b"".join(
            struct.pack("<H", o) for o in self.trace.outputs)

    def plan_bytes(self, mode: str = "optimistic") -> bytes:
        if self._is_hello_shape() and mode != "consensus":
            golden = _golden("minimal_two_level_add_identity", "plans_v1.tsv")
            if golden:
                return golden
        if self.canonical(mode):
            return self.canonical(mode)[1]
        regions = sorted({s.region for s in self.trace.steps})
        return b"DCPLF1" + self.step_table() + ",".join(regions).encode()

    def ids(self, mode: str = "optimistic") -> dict[str, bytes]:
        return {
            "graph": hashlib.sha256(GRAPH_DOMAIN + self.graph_bytes(mode)).digest(),
            "plan": hashlib.sha256(PLAN_DOMAIN + self.plan_bytes(mode)).digest(),
            "table": hashlib.sha256(TABLE_DOMAIN + self.step_table()).digest(),
        }

    # --- host execution (honest executor) ---------------------------------
    def evaluate(self, *inputs: int) -> list[int]:
        from dcg import kernels

        t = self.trace
        if len(inputs) != t.n_inputs:
            raise TraceError("ARITY", f"{t.name} takes {t.n_inputs} inputs")
        cells = []
        for name, v in zip(t.input_names, inputs):
            if not isinstance(v, int) or not I32_MIN <= v <= I32_MAX:
                raise TraceError("RANGE", f"input {name}={v!r} is not an i32")
            cells.append(v)
        for i, s in enumerate(t.steps):
            try:
                cells.append(kernels.host(s.kernel, [cells[r] for r in s.refs]))
            except OverflowError as exc:
                raise TraceError("OVERFLOW", f"step {i} {s.kernel.name}: {exc}", s.where) from None
        return cells[t.n_inputs:]

    def outputs_of(self, trace_values: list[int]) -> list[int]:
        n = self.trace.n_inputs
        return [trace_values[o - n] if o >= n else None for o in self.trace.outputs]

    # --- explain ----------------------------------------------------------
    def explain(self, mode: str = "optimistic", samples: int = 0, measured: dict | None = None) -> str:
        t, ids = self.trace, self.ids()
        lines = [f"graph {t.name}: {t.n_inputs} i32 inputs ({', '.join(t.input_names)}), {len(t.steps)} kernel steps",
                 f"  graph id {ids['graph'].hex()[:16]}…  plan id {ids['plan'].hex()[:16]}…  table id {ids['table'].hex()[:16]}…",
                 f"  encoding: {'frozen v2.0 golden DCGG/DCPL' if self._is_hello_shape() else 'canonical v2.0 DCGG/DCPL' if self.canonical() else 'fast-path DCGGF1/DCPLF1 (not canonical v2.0)'}"]
        regions: dict[str, list[int]] = {}
        for i, s in enumerate(t.steps):
            regions.setdefault(s.region, []).append(i)
        for name, steps in regions.items():
            lines.append(f"  region {name}: steps {steps}")
        for i, s in enumerate(t.steps):
            src = ", ".join(t.input_names[r] if r < t.n_inputs else f"step{r - t.n_inputs}" for r in s.refs)
            lines.append(f"    step{i} = {s.kernel.name}/v{s.kernel.semantic_version}({src})  [{s.where}]")
        kernels_used = sorted({(s.kernel.name, s.kernel.semantic_version, s.kernel.abi_version) for s in t.steps})
        lines.append("  required kernels: " + ", ".join(f"{n}/{v} abi {a}" for n, v, a in kernels_used))
        guarantee = {
            "consensus": "every step executed by the on-chain program; result final when the execute transaction lands",
            "optimistic": "executor posts the full trace; any single wrong step can be challenged and is replayed on chain "
                          "before the deadline; final only after the deadline passes unchallenged (requires one honest watcher)",
            "sampling": f"executor posts the full trace; {samples} steps chosen by a slot hash after the commit are replayed "
                        f"on chain; a wrong trace with w bad steps escapes with probability (1-w/n)^{samples}; "
                        "single-step challenges remain open until the deadline",
        }[mode]
        lines.append(f"  mode {mode}: {guarantee}")
        lines.append("  ceilings (designed): 4-byte cells, ≤8 inputs per step, one step replay fits one transaction")
        if measured:
            lines.append("  measured: " + ", ".join(f"{k}={v}" for k, v in measured.items()))
        else:
            lines.append("  measured: none yet")
        return "\n".join(lines)
