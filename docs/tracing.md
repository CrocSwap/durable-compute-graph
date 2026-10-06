# Tracing reference: Python functions to v2.1 plans

`dcg.v21` turns a Python function into a v2.1 plan. You write straight-line
code that calls kernels; tracing records the calls and builds the plan that
templates, executors, watchtowers and the program all use. Examples:
`examples/optimistic-quickstart/quickstart.py` and the tests in
`python/tests/test_v21_tracing.py`.

```python
from dcg import v21

@v21.trace
def checksum(data: v21.Chunked(bytes=256, chunk=64), salt: v21.Scalar):
    acc = v21.reduce("sumchunk_i32", data)     # one step per 64-byte chunk
    h = v21.call("head_i32", acc)              # the first word of the result
    return v21.call("add_i32", h, salt)

spec = checksum.plan()        # the plan (S.Spec), ready for a template
print(checksum.explain())     # steps, blocks, inputs and outputs
```

## Inputs

Each parameter of the traced function is one external input, numbered from
0 in order. The run commits each input as a digest, and the application must
publish the bytes for watchers ([`guarantees.md`](guarantees.md)).

| Annotation | Value |
|---|---|
| `v21.Scalar` | one i32 (4 bytes) |
| `v21.Raw(bytes=n)` | exactly `n` raw bytes, read whole |
| `v21.Chunked(bytes=n, chunk=c)` | `n` bytes in chunks of `c` (a power of two, 64 to 65,536), read one chunk per step with `reduce` |

## Operations

- **`v21.call(kernel, *args)`:** one step of a kernel over values. It returns
  the step's output. An application kernel needs
  `out=[(length, scalar), ...]`, because DCG does not know its output shape.
- **`v21.reduce(kernel, data, *extra)`:** a repeated block. Iteration `i`
  reads chunk `i` of `data` and carries a running state. It returns the final
  state. Pass `v21.ITERATION` where the kernel takes the iteration number.
- **`v21.constant(value, chunk=0)`:** bytes committed in the template. Plain
  constants are read whole; with `chunk`, read them with `reduce`.
- **`v21.list(values)`:** 1 to 128 values passed to one step as a single
  list input (a wide read).

Each step has at most 8 inputs and 1 to 8 outputs. Tracing refuses, at trace
time and with the line that caused it:
- Python control flow on traced values (`if acc > 0:`);
- operators on traced values (`acc + 1`; use a kernel);
- unknown kernels and wrong shapes.

## Built-in kernels

Every program image has these. The program replays them directly in a
dispute.

| Kernel | Use | Inputs | Output |
|---|---|---|---|
| `add_i32` | `call` | two i32 | i32 (overflow refuses) |
| `identity_i32` | `call` | one i32 | the same i32 |
| `head_i32` | `call` | any value of at least 4 bytes | its first i32 word |
| `sumchunk_i32` | `reduce` | a chunked input of i32 words | i64 running sum (8 bytes) |
| `argmax_i32c` | `reduce` | a chunked input, `v21.ITERATION` | (seen u32, best i32, index u32); ties keep the lowest index |
| `scan_i32c` | `reduce` | a chunked input, `v21.ITERATION`, a needle i32 | (found u32, index u32); stops at the first match |
| `rowdot_i32c` | `reduce` | a chunked constant of weight rows, a vector, `v21.ITERATION` | 64 i64 entries: row `i`'s dot product with the vector |

All arithmetic is integer-exact with fixed widths. An overflow makes the
kernel refuse. An executor cannot commit such a step honestly, so a
watchtower convicts it.

For anything else, write your own kernel in Rust with a Python mirror, and
build an application image that carries it ([`kernel-app.md`](kernel-app.md)).
Call it with `v21.call("my-kernel-v1", ..., out=[(8, False)])`.

## Not supported yet

- **Loops whose count depends on data.** A `reduce` runs once per chunk, and
  only a reduction's gate can stop it early (`scan_i32c` does).
- **`v21.repeat`** (a repeated block over an application kernel). It is
  planned; see the design proposal,
  [`design/tracing-v21-frontend.md`](design/tracing-v21-frontend.md).
- **LOG state.** It is not supported in the alpha. Use LX1 checkpoints for
  long state chains ([`design/v2.1-lazy-expansion.md`](design/v2.1-lazy-expansion.md)).
