# Tracing frontend for v2.1 (alpha E1) — API proposal

**Status: proposal (2026-10-05), not implemented.** Alpha plan item E1: write a
Python function with loops, constants and wide reads, and get a v2.1 plan
(repeated blocks, gates, constants, chunked and list inputs). Today a v2.1 plan
is assembled by hand with `dcg.disputes_v21.plans.PlanBuilder` and packed
producer tuples (`examples/hello-graph/chunked_dispute.py`).

## What a user writes

```python
from dcg import v21

@v21.trace
def checksum(data: v21.Chunked(bytes=4096, chunk=64),   # external, chunked
             salt: v21.Scalar):                           # external i32
    table = v21.constant(TABLE_BYTES, chunk=64)           # committed constant
    acc = v21.reduce("sumchunk_i32", data)                # chunked kernel: one
                                                          # repeated block, kind-6 result
    mixed = v21.reduce("sumchunk_i32", table)             # same over a constant
    parts = [v21.call("head_i32", acc), v21.call("head_i32", mixed), salt]
    wide = v21.call("my_app_kernel/v1", v21.list(parts))  # list input (wide read)
    return v21.call("add_i32", wide, salt)

plan = checksum.plan()          # dcg.disputes_v21.spec.Spec, via PlanBuilder
print(checksum.explain())       # blocks, kernels, inputs, constants, sizes
tdata = checksum.template(challenge_window=1_500, ...)   # canonical template bytes
```

- **Straight-line calls** become one enumerated block, in call order.
- **`v21.reduce(kernel, chunked)`** becomes a repeated block of one stateful
  step per chunk (the existing `chunked_reduce` / `chunked_reduce_const`), and
  its result is read through kind 6.
- **`for i in v21.repeat(k): ...`** traces the body once and emits a repeated
  block with K = k and the gate the body returns (`v21.gate(value)`), for
  loops whose body is identical per iteration. Python `for` loops over
  constants are unrolled into the enumerated block, as today.
- **`v21.constant(bytes, chunk=...)`** declares a committed constant (plain, or
  chunked for kind-5 reads).
- **`v21.list([...])`** passes 1..128 values to one step as a list input.
- **Application kernels** are named by their 16-byte id (or `name/vN`) and must
  advertise the STEP mode in the image's manifest; `explain()` says which
  kernels the template needs and refuses a name that is a built-in.
- Data-dependent Python control flow, unknown ops and foreign values are
  refused at trace time with the source line, as in the v2.0 tracer.

## Lowering

The tracer records a small IR (calls, reduces, repeats, constants, lists),
then emits `PlanBuilder` calls in topological order, so every plan it produces
is one the builder, the Python referee and the program already accept. The
existing goldens give equivalence checks: the traced versions of the
chunked, list and constant scenarios must build byte-identical specs and
template ids.

## Not in the first cut

LOG-state kernels (refused until LOG is on chain), nested repeats, kind-7
iteration reads beyond the last running iteration, and v2.0 graphs (the v2.0
tracer stays as it is).

## Open questions for the owner

1. Module name and entry point: `dcg.v21.trace` (proposed) or extend
   `dcg.trace` with a `mode="v2.1"` switch.
2. Whether `explain()` should also estimate costs (transactions, rent) from the
   template, as E8 suggests, in the first cut.
