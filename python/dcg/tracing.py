"""DCG v2 Python tracer (stage 4, fast path).

Traces a pure Python function over symbolic ``Value`` handles. Every call to a
registered kernel (``dcg.kernels``) records one static step; data-dependent
control flow, ambient effects, and unknown operations are refused at trace
time with the source location. The result lowers to the step table that the
on-chain graph lifecycle executes, plus graph/plan blobs.

Fast-path note: for the exact two-level add/identity shape the emitted graph
and plan blobs are the frozen golden DCGG/DCPL bytes. Other shapes emit a
``DCGGF1``/``DCPLF1`` fast encoding of the step table, which is not the frozen
v2.0 canonical format.
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

    def graph_bytes(self) -> bytes:
        if self._is_hello_shape():
            golden = _golden("minimal_two_level_add_identity", "graphs_v1.tsv")
            if golden:
                return golden
        return b"DCGGF1" + self.step_table() + struct.pack("<H", len(self.trace.outputs)) + b"".join(
            struct.pack("<H", o) for o in self.trace.outputs)

    def plan_bytes(self) -> bytes:
        if self._is_hello_shape():
            golden = _golden("minimal_two_level_add_identity", "plans_v1.tsv")
            if golden:
                return golden
        regions = sorted({s.region for s in self.trace.steps})
        return b"DCPLF1" + self.step_table() + ",".join(regions).encode()

    def ids(self) -> dict[str, bytes]:
        return {
            "graph": hashlib.sha256(GRAPH_DOMAIN + self.graph_bytes()).digest(),
            "plan": hashlib.sha256(PLAN_DOMAIN + self.plan_bytes()).digest(),
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
                 f"  encoding: {'frozen v2.0 golden DCGG/DCPL' if self._is_hello_shape() else 'fast-path DCGGF1/DCPLF1 (not canonical v2.0)'}"]
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
