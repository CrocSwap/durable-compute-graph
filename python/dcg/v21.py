"""Trace Python functions to v2.1 dispute plans (DCG alpha E1).

Design: ``docs/design/tracing-v21-frontend.md``. A traced function receives
symbolic handles for its external inputs and calls kernels through this
module; the trace lowers to ``dcg.disputes_v21.plans.PlanBuilder`` calls, so
every plan it produces is one the builder, the Python referee and the program
already accept.

    from dcg import v21

    @v21.trace
    def total(data: v21.Chunked(bytes=256, chunk=64)):
        acc = v21.reduce("sumchunk_i32", data)     # one repeated block
        return v21.call("head_i32", acc)           # read through kind 6

    spec = total.plan()
    print(total.explain())

Straight-line calls form enumerated blocks; ``reduce`` emits a repeated block
(one stateful step per chunk) and its result is read through kind 6;
``constant`` declares a committed constant; ``list`` passes up to 128 values to
one step. Data-dependent Python control flow and operators on handles are
refused at trace time.
"""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, field
from typing import Callable, Sequence

from dcg import kernels as _builtin
from dcg.disputes_v21 import plans as P
from dcg.disputes_v21 import reductions as _red
from dcg.disputes_v21 import spec as S
from dcg.disputes_v21 import wire as W
from dcg.tracing import TraceError, _caller


# --- input declarations -------------------------------------------------------------

@dataclass(frozen=True)
class Scalar:
    """An external i32 (4 bytes, scalar layout)."""


@dataclass(frozen=True)
class Raw:
    """An external value of exactly ``bytes`` raw bytes."""

    bytes: int


@dataclass(frozen=True)
class Chunked:
    """An external value of ``bytes`` raw bytes in chunks of ``chunk`` bytes
    (a power of two, 64..65,536); read whole chunks with ``reduce``."""

    bytes: int
    chunk: int


Scalar = Scalar()  # usable as a bare annotation: `x: v21.Scalar`


# --- handles ------------------------------------------------------------------------

@dataclass(frozen=True)
class Value:
    """A traced value: its producer, byte length and whether it is an i32 scalar."""

    trace: "_Trace"
    producer: bytes
    length: int
    scalar: bool

    def _input(self) -> P.Input:
        return P.Input(self.producer, self.length, self.scalar)

    def __bool__(self):
        raise TraceError("DATA_DEPENDENT_CONTROL", "a traced value cannot drive Python control flow", _caller())

    def __index__(self):
        raise TraceError("DATA_DEPENDENT_CONTROL", "a traced value cannot be used as a Python integer", _caller())

    def _refuse(self, *_a, **_k):
        raise TraceError("UNREGISTERED_OP", "operators are not traceable; call a kernel with v21.call", _caller())

    __add__ = __radd__ = __sub__ = __mul__ = __truediv__ = __lt__ = __gt__ = __le__ = __ge__ = _refuse


@dataclass(frozen=True)
class ChunkedValue:
    """A chunked external input or constant: only ``reduce`` may read it."""

    trace: "_Trace"
    ident: int
    source: str  # "input" | "constant"
    bytes: int
    chunk: int


@dataclass(frozen=True)
class ListValue:
    trace: "_Trace"
    input: P.Input


# --- kernel shapes --------------------------------------------------------------------

# Output ports of the built-in kernels a trace may call directly: (length, scalar).
_BUILTIN_OUTPUTS: dict[str, tuple[tuple[int, bool], ...]] = {
    **{k.name: ((4, True),) for k in _builtin.REGISTRY.values()},
    "head_i32": ((4, True),),
}


def _kernel_ref(kernel: str | bytes) -> str | bytes:
    """A built-in name (``add_i32`` or ``add_i32/v1``) or a 16-byte app kernel id
    (bytes, or ``name/vN`` text that is not a built-in)."""
    if isinstance(kernel, bytes):
        if len(kernel) != 16:
            raise TraceError("KERNEL", "an application kernel id is exactly 16 bytes", _caller())
        return kernel
    name = kernel[:-3] if kernel.endswith("/v1") else kernel
    if name in _BUILTIN_OUTPUTS or name in _red.REGISTRY:
        return name
    raw = kernel.encode()
    if len(raw) > 16:
        raise TraceError("KERNEL", f"kernel id {kernel!r} is longer than 16 bytes", _caller())
    return raw.ljust(16, b"\x00")


# --- the trace --------------------------------------------------------------------------

@dataclass
class _Trace:
    name: str
    builder: P.PlanBuilder = field(default_factory=P.PlanBuilder)
    pending: list[P.Step] = field(default_factory=list)  # the open enumerated block
    base: int = 0  # ordinal of the first step of the open enumerated block
    next_constant: int = 0
    next_list: int = 0
    notes: list[str] = field(default_factory=list)

    def flush(self) -> None:
        if self.pending:
            self.builder.enumerated(self.pending)
            self.base += len(self.pending)
            self.pending = []

    def check(self, *values) -> None:
        for v in values:
            if getattr(v, "trace", None) is not self:
                raise TraceError("FOREIGN_VALUE", "value belongs to another trace (or is not traced)", _caller())


_ACTIVE: list[_Trace] = []


def _current() -> _Trace:
    if not _ACTIVE:
        raise TraceError("NO_TRACE", "v21 calls must run inside a v21.trace function", _caller())
    return _ACTIVE[-1]


def call(kernel: str | bytes, *args: Value | ListValue, out: Sequence[tuple[int, bool]] | None = None):
    """One step of ``kernel`` over ``args``. Built-in kernels know their output
    shape; an application kernel needs ``out=[(length, scalar), ...]``. Returns
    one ``Value`` per output port (a single ``Value`` for one port)."""
    t = _current()
    t.check(*args)
    ref = _kernel_ref(kernel)
    if out is None:
        if not isinstance(ref, str) or ref not in _BUILTIN_OUTPUTS:
            raise TraceError("SHAPE", f"pass out=[(length, scalar), ...] for application kernel {kernel!r}", _caller())
        out = _BUILTIN_OUTPUTS[ref]
    if not 1 <= len(out) <= 8 or len(args) > 8:
        raise TraceError("ARITY", "a step has 1..8 outputs and at most 8 inputs", _caller())
    inputs = tuple(a.input if isinstance(a, ListValue) else a._input() for a in args)
    t.pending.append(P.Step(ref, inputs, tuple((p, n, sc) for p, (n, sc) in enumerate(out))))
    ordinal = t.base + len(t.pending) - 1
    values = tuple(Value(t, S.producer(1, ordinal, p), n, sc) for p, (n, sc) in enumerate(out))
    return values[0] if len(values) == 1 else values


class _Iteration:
    """``v21.ITERATION``: the iteration index ``i`` (a u32 scalar, kind 7), as an
    extra input of ``reduce``."""

    def __repr__(self):
        return "v21.ITERATION"


ITERATION = _Iteration()


def reduce(kernel: str, data: ChunkedValue, *extra: Value | _Iteration) -> Value:
    """A chunked kernel: a repeated block whose iteration ``i`` reads chunk ``i``
    of ``data`` (with ``extra`` plain inputs), its running state exported on
    port 0. Returns the final state, read through kind 6."""
    t = _current()
    t.check(data, *(e for e in extra if e is not ITERATION))
    if not isinstance(data, ChunkedValue):
        raise TraceError("TYPE", "reduce reads a v21.Chunked input or a chunked v21.constant", _caller())
    if kernel not in _red.REGISTRY or not _red.REGISTRY[kernel].state_bytes:
        raise TraceError("KERNEL", f"{kernel!r} is not a registered stateful reduction", _caller())
    t.flush()
    ex = tuple(P.Input(S.producer(7), 4, scalar=True) if e is ITERATION else e._input() for e in extra)
    if data.source == "input":
        block = t.builder.chunked_reduce(kernel, data.ident, ex)
    else:
        block = t.builder.chunked_reduce_const(kernel, data.ident, ex)
    t.base += data.bytes // data.chunk
    state = _red.REGISTRY[kernel].state_bytes
    return Value(t, S.producer(6, block, 0, 0), state, False)


def constant(value: bytes, chunk: int = 0) -> Value | ChunkedValue:
    """A committed constant: plain (read whole), or chunked (``chunk`` a power of
    two 64..65,536, read with ``reduce``)."""
    t = _current()
    cid = t.next_constant
    t.next_constant += 1
    log2 = chunk.bit_length() - 1 if chunk else 0
    if chunk and (chunk != 1 << log2):
        raise TraceError("CHUNK", "chunk must be a power of two", _caller())
    t.builder.committed_constant(cid, bytes(value), log2)
    if chunk:
        return ChunkedValue(t, cid, "constant", len(value), chunk)
    return Value(t, S.producer(3, cid), len(value), False)


def list(values: Sequence[Value]) -> ListValue:  # noqa: A001 - mirrors the design's v21.list
    """1..128 values as one list input (a wide read)."""
    t = _current()
    t.check(*values)
    lid = t.next_list
    t.next_list += 1
    return ListValue(t, t.builder.list_input(lid, tuple(v._input() for v in values)))


# --- the traced function --------------------------------------------------------------

class Traced:
    """The result of ``@v21.trace``: lazily traced and built."""

    def __init__(self, fn: Callable, inputs: Sequence[object] | None):
        self.fn = fn
        self.inputs = inputs
        self._spec: S.Spec | None = None
        self._trace: _Trace | None = None

    def _declarations(self) -> list[object]:
        if self.inputs is not None:
            return [*self.inputs]
        # eval_str: annotations are strings under `from __future__ import annotations`;
        # they are evaluated in the function's module, not its enclosing scope.
        try:
            params = inspect.signature(self.fn, eval_str=True).parameters.values()
        except NameError as exc:
            raise TraceError("INPUT", f"an input annotation names something outside the module ({exc}); "
                                      "use module-level sizes or pass inputs=[...] to v21.trace", self.fn.__name__) from exc
        out = []
        for p in params:
            if p.annotation is inspect.Parameter.empty:
                raise TraceError("INPUT", f"parameter {p.name!r} needs a v21.Scalar / Raw / Chunked annotation", self.fn.__name__)
            out.append(p.annotation)
        return out

    def plan(self) -> S.Spec:
        if self._spec is None:
            t = _Trace(self.fn.__name__)
            args = []
            for eid, decl in enumerate(self._declarations()):
                if decl is Scalar or isinstance(decl, type(Scalar)):
                    args.append(Value(t, t.builder.scalar_input(eid), 4, True))
                elif isinstance(decl, Raw):
                    args.append(Value(t, t.builder.raw_input(eid, decl.bytes), decl.bytes, False))
                elif isinstance(decl, Chunked):
                    log2 = decl.chunk.bit_length() - 1
                    t.builder.chunked_input(eid, decl.bytes, log2)
                    args.append(ChunkedValue(t, eid, "input", decl.bytes, decl.chunk))
                else:
                    raise TraceError("INPUT", f"input {eid} is not a v21.Scalar / Raw / Chunked declaration", self.fn.__name__)
            _ACTIVE.append(t)
            try:
                result = self.fn(*args)
            finally:
                _ACTIVE.pop()
            outs = result if isinstance(result, tuple) else (result,)
            for o in outs:
                if not isinstance(o, Value) or o.trace is not t:
                    raise TraceError("OUTPUT", "outputs must be traced values (read a reduce result before returning it)", self.fn.__name__)
            t.flush()
            if not t.builder.blocks:
                raise TraceError("EMPTY", "the plan has no steps", self.fn.__name__)
            for o in outs:
                t.builder.output(o.producer, o.length, o.scalar)
            self._trace = t
            self._spec = t.builder.build()
        return self._spec

    def execute(self, values: dict[int, bytes] | Sequence[bytes | int], *, plan_id: bytes = bytes(32),
                run_id: bytes = bytes(32)):
        """Run the plan with the Python reference executor (what an honest
        executor commits). ``values`` maps input index to bytes (an int is
        packed as an i32); the plan's constants are supplied automatically.
        Returns ``dcg.disputes_v21.run.Commitment``."""
        from dcg.disputes_v21 import run as R
        import struct as _struct

        sp = self.plan()
        items = values.items() if isinstance(values, dict) else enumerate(values)
        ext = {k: (_struct.pack("<i", v) if isinstance(v, int) else bytes(v)) for k, v in items}
        consts = {cid: value for cid, (value, _log2) in self._trace.builder.constants.items()}
        return R.execute(sp, plan_id, run_id, ext, constants=consts or None)

    def template(self, *, depth: int = 3, plan_id: bytes = bytes(32), **windows) -> bytes:
        """Canonical v2.1 template creation data (sub 1) for this plan. Keyword
        arguments are ``challenge_window``, ``phase_window``, ``executor_bond``,
        ``challenger_bond`` and ``slasher_bps`` (``wire.template_data``)."""
        return W.template_data(self.plan(), depth, plan_id, **windows)

    def template_id(self, **kw) -> bytes:
        return hashlib.sha256(W.TEMPLATE_DOMAIN + self.template(**kw)).digest()

    def explain(self) -> str:
        """What the plan commits to: blocks, steps, kernels, inputs, constants
        and outputs. Cost estimates are the later E8 item."""
        sp = self.plan()
        b = self._trace.builder
        lines = [f"v2.1 plan {self.fn.__name__!r}: {sp.total_steps} steps in {len(b.blocks)} blocks"]
        for i, blk in enumerate(b.blocks):
            if blk[0] == "enum":
                names = sorted({_kname(st.kernel) for st in blk[1]})
                lines.append(f"  block {i}: enumerated, {len(blk[1])} steps ({', '.join(names)})")
            else:
                lines.append(f"  block {i}: repeated {blk[2]} times, body {len(blk[1])} "
                             f"({', '.join(_kname(st.kernel) for st in blk[1])}), gate entry {blk[3][0]} port {blk[3][1]}")
        for eid, (length, log2) in sorted(b.inputs.items()):
            kind = "chunked" if log2 > 0 else "raw" if log2 < 0 else "i32 scalar"
            extra = f", chunks of {1 << log2} bytes" if log2 > 0 else ""
            lines.append(f"  input {eid}: {kind}, {length} bytes{extra}")
        for cid, (value, log2) in sorted(b.constants.items()):
            lines.append(f"  constant {cid}: {len(value)} bytes{', chunked' if log2 else ''}, committed in the template")
        for n, (prod, length, scalar) in enumerate(b.outputs):
            lines.append(f"  output {n}: {'i32' if scalar else f'{length} bytes'}")
        apps = sorted({st.kernel for blk in b.blocks for st in blk[1] if isinstance(st.kernel, bytes)})
        if apps:
            lines.append("  application kernels (the program image must provide them, with the STEP mode): "
                         + ", ".join(k.rstrip(b"\x00").decode(errors="replace") for k in apps))
        return "\n".join(lines)


def _kname(k: str | bytes) -> str:
    return k.rstrip(b"\x00").decode(errors="replace") if isinstance(k, bytes) else k


def trace(fn: Callable | None = None, *, inputs: Sequence[object] | None = None):
    """Decorate a function whose parameters are annotated with ``v21.Scalar``,
    ``v21.Raw(n)`` or ``v21.Chunked(bytes, chunk)``; or pass ``inputs=[...]``
    and take ``*args``."""
    if fn is None:
        return lambda f: Traced(f, inputs)
    return Traced(fn, inputs)
