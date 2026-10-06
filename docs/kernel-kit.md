# The kernel kit

The kernel kit is how an application declares a kernel and checks that the
kernel's Python mirror agrees with it. It covers alpha plan items E2
(optimistic mode, STEP kernels) and C3 (consensus mode, stateful kernels).

To start a whole application, copy a template: `examples/kernel-app` for a
custom STEP kernel (`docs/kernel-app.md`) or `examples/session-app` for a
stateful kernel (`docs/session-quickstart.md`).

**Why it exists.** The Python client stands in for the program wherever the
program would run a kernel:
- the v2.1 referee replays STEP claims with the mirror;
- session clients predict state with it.

If the mirror and the kernel differ at any input, edge limit or refusal, the
client's predictions are wrong at that input. Review finding F2 (10-03) was
this kind of bug. The kit runs both on generated inputs and fails on any
disagreement.

## 1. Declare the kernel in Rust

`KernelDecl` (`crates/dcg-program/src/kernel_kit.rs`) builds a
`KernelManifest`:
- each port's limit is stated once and becomes the resource limit too;
- the declaration is checked at compile time when used in a `static`. The checks are: the name is 1 to 16 bytes with no NUL, the versions are nonzero, both layouts are declared, there is at least one mode, and the compute ceiling fits one transaction.

```rust
use dcg_program::kernel::{KernelManifest, VersionedId, MODE_STEP_V21};
use dcg_program::kernel_kit::KernelDecl;

static MANIFEST: KernelManifest = KernelDecl::new("my-hash-v1", 1, 1)
    .input(VersionedId { id: 1, version: 1 }, 4096)
    .output(VersionedId { id: 2, version: 1 }, 32)
    .compute(60_000, 1)
    .modes(&[MODE_STEP_V21])
    .build();
```

- A stateful kernel adds `.state(schema, max_bytes)`.
- A kernel that may reject inputs adds `.rejects_input()` (design
  `session-reject-and-ring-v1.md`).

`KernelDecl` produces exactly the hand-written manifests. The test
`crates/dcg-kernel-conform/tests/kit.rs` reproduces the alpha manifest's
SHA-256 and byte-sum kernels and the rejecting counter with it.

## 2. Write the mirror in Python

A STEP kernel's mirror is a function from its inputs to its one output. It
raises `KernelRefused` (a `ValueError`) to refuse. The decorator registers it
for the v2.1 referee under (id, semantic version, ABI version), the same key
the program resolves:

```python
import hashlib

from dcg.kernel_kit import KernelRefused, step_kernel

@step_kernel("my-hash-v1", max_input_bytes=4096, max_output_bytes=32, max_compute_units=60_000)
def my_hash(inputs: list[bytes]) -> bytes:
    data = b"".join(inputs)
    if not inputs or not 0 < len(data) <= 4096:
        raise KernelRefused("InvalidInput")
    return hashlib.sha256(data).digest()
```

A stateful kernel's mirror subclasses `StatefulMirror`. It sets:
- `decl`, the same limits as the Rust declaration;
- `state_spans`, the span lengths sessions open with;
- optionally `special_inputs`, commands the generator should always try.

It implements:
- `initial_state(spans) -> bytes`;
- `transition(command, state) -> Outcome`.

An `Outcome` carries the output, the state after the call, and the disposition (`continue`, `halt_before`, `halt_after` or `reject`) with its reason or code. A mirror models the kernel only. The kit applies the runtime's own rules on top, which the next section lists.
`examples/kernel-kit/counter_mirrors.py` mirrors DCG's v3 test counters,
including the rejecting ones.

## 3. Check them against each other

An application builds a small conformance server that names its kernels. It
is a copy of `crates/dcg-kernel-conform/src/main.rs`, about ten lines:

```rust
let registry = Registry { app: Some(&MY_MANIFEST_APP), stateful: &[&MY_STATEFUL_KERNEL] };
serve(&registry, std::io::stdin().lock(), std::io::stdout().lock())
```

Then run:

```sh
cargo build -p dcg-kernel-conform
python -m dcg.kernel_kit check --bin target/debug/dcg-kernel-conform \
    dcg.disputes_v21.appkernels examples/kernel-kit/counter_mirrors.py
```

The command prints one line per kernel: the number of cases, the number of
disagreements, and which outcomes the cases reached. It exits nonzero on any
disagreement.

**What the server runs.** It makes the program's own calls, shared with the
program in `kernel_kit.rs`, so it tests the program's judgement of the kernel
and not a copy of it:
- **STEP:** `step_kernel_call`. The kernel must match the exact id and
  versions and advertise `MODE_STEP_V21`. Each input is one span, and the
  output buffer is the output port's limit.
- **Stateful:** the v3 runtime's transition.
  - State spans sit at consecutive offsets.
  - The output buffer is from `v3_output_len`.
  - `judge_outcome` applies the runtime's checks:
    - output within the buffer;
    - nonzero halt reasons;
    - HaltBefore leaves state unchanged;
    - Reject is accepted only in a rejectable session of a kernel that declares the capability, with a nonzero code, no output and unchanged state.
  - The unchanged-state checks apply only at or below the runtime's 8 KiB snapshot cap, as in the program.

**What is compared:**
- The declared limits, against the built manifest. A mirror cannot quietly
  assume a different limit.
- For STEP: the output bytes, or that both refuse.
- For stateful kernels: the initial state for the declared spans, and
  refusal for other splits.
- For each transition: whether the runtime accepts it, and if it does, the
  disposition, code and next state, plus the output for `continue` and
  `halt_after`.
- A STEP kernel whose name is a built-in kernel or reduction is reported as a
  disagreement: the referee rules on the built-in first and never runs the app
  kernel. `step_kernel` refuses such names.

Error kinds are reported but not compared, because the program treats every
kernel error alike.

**The generated cases:**
- **STEP:**
  - Inputs of 0, 1, max−1, max and max+1 total bytes, as zeros, 0xFF and
    random bytes, each split into 1 to 3 spans (some empty).
  - No spans at all.
  - Seeded random sizes up to 25% past the limit.
- **Stateful:**
  - Every generated command from each of these states: the initial state,
    all zeros, all 0xFF, all 0x7F and random states, each at the full state
    size. The commands are the edge lengths, the special inputs and random
    bytes.
  - Each in both a plain and a rejectable session.
  - Then a seeded walk of accepted transitions.

`python/tests/test_kernel_kit.py` checks that the kit catches six deliberate
mirror bugs:
1. a limit one byte short;
2. a declared limit that differs from the kernel's;
3. different hashing;
4. a counter that wraps where the kernel refuses;
5. a dirty reject modelled as clean;
6. a missing capability.

## What the kit does not check

- The server passes zero account keys and owners, binds invocation state per
  call (the program binds once per multi-step advance), and initialises with
  no resource accounts. A kernel that reads keys, caches across the steps of
  one advance, or uses resources is checked only partly.
- `@step_kernel` registers into one process-wide registry; import only the
  mirrors of kernels your image has.
- Set `DCG_REQUIRE_KERNEL_CONFORM=1` in CI so a missing server fails the kit
  tests instead of skipping them.

- Account plumbing, session admission, the per-advance compute budget and the
  STEP template's arity are not checked. They belong to the program and are
  tested by running it (native, SBF and live).
- Kernels with views, lanes or resource accounts are checked only on their
  transitions.
- LX1 machines are not covered; the LX conformance tests stay in
  `tests/disputes_v21_lx.rs`.
- The kit compares the mirror with the kernel. It cannot tell you that both
  are wrong in the same way.
