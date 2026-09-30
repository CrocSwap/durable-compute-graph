# Hello World friction report

This report describes the first runnable counter path at this checkout. The
example is a local ProgramTest mechanics demo. It is not an SBF or validator
run, and the example does not define a new kernel.

## Most painful first

1. **The first compile is longer than the stated 10-minute target.** Measured
   from an empty Cargo target, `cargo build --locked` took 12 minutes 26
   seconds on this Apple Silicon workstation and left a 1.1 GB target. The
   Cargo registry source/cache was already populated; a genuinely clean
   machine may take longer to download dependencies. ProgramTest brings in
   much of Solana's runtime and RPC dependency graph for this one-byte example.
   The smallest fix is a lightweight supported local runner, or a warm,
   pinned example build artifact for first use. **Owner: program/tooling.**

2. **A developer cannot define the kernel in this example.** The `CounterKernel`
   and its static `KernelManifest` are in the core's feature-gated
   `stateful_test.rs`; the example links that test app. The input is dynamic,
   but the actual kernel is not. A newcomer has to find the right core feature
   and understand that the manifest is compiled into the program. The smallest
   fix is an app-owned kernel crate/template with a supported manifest builder
   and a one-command local runner. **Owner: program/client.**

3. **Most of the example is account and instruction plumbing.** The driver
   spells out the session PDA, input-stream PDA, two state PDAs, versioned
   kernel identity, byte layouts, signer roles and five transactions. The
   transaction sequencer sends caller-built messages; it does not build DCG
   instructions or know session policy. A user looking for “increment this”
   must first translate it into DCG's account protocol. It also reads the
   output by slicing raw account bytes; there is no typed output object. The
   smallest fix is a typed Python counter/session builder that owns this
   boilerplate and exposes a single `run(input)` call. **Owner:
   client/sequencer.**

4. **The working path is the native Rust handler, not SBF.** This uses
   `ProgramTest` with `processor!(dcg_program::process_instruction)`. It proves
   the handler accepted the input and wrote state in ProgramTest's bank; it
   does not prove the built SBF image or a validator deployment behaves the
   same way. The smallest fix is a maintained ProgramTest SBF target for this
   example, with the pinned SDK and image build hidden behind one documented
   command. **Owner: program/tooling/docs.**

5. **Several protocol concepts come before the first result.** Even this
   counter binds a kernel ID, semantic version, ABI version, state schema and
   consensus mode. The input stream has a fixed byte width and cursor; the
   state is split across authenticated spans; the writer and advance authority
   sign different operations. The general kernel contract also expects
   deterministic integer work, fixed bounds and no ambient state. The smallest
   fix is a guided “copy this app, change this function” example that introduces
   each concept only when it is needed. **Owner: docs/client.**

6. **The first build produces a large warning stream.** Measured compilation
   emitted 60 warnings from `dcg-program`, including target-specific cfg,
   deprecated account APIs and dead-code warnings. The output runs to hundreds
   of lines and obscures the example's own build status. The smallest fix is to
   clear the core warning baseline or gate warnings for code paths not built by
   the selected image. **Owner: program.**

7. **Program refusals are hard to diagnose.** During the first attempt, the
   advance instruction had a read-only input stream. The program returned
   `Custom(2304)`; the number did not say that the account's writable role was
   wrong or how to fix it. The example now labels each transaction, but the
   caller still needs source knowledge to map the numeric refusal. The smallest
   fix is a stable refusal-code table and client errors that name the failed
   account role and expected signer/writable flags. **Owner: program/client.**

8. **The current getting-started guide is a contract tour, not a short first
   run.** It begins with implementing a Rust `Kernel`, writing a static app
   manifest, building feature-specific tests, then optionally setting up an
   SBF image. That is useful reference material but does not get a Python user
   to the first result quickly. The smallest fix is to put this runnable example
   first, then link the contract and SBF details as follow-up steps. **Owner:
   docs.**

9. **Some lifecycle examples depend on Basanos-local artifacts.** The full
   revision-8 path in the existing guide needs a retained compiler-v1 PT2P
   bundle supplied via `BASANOS_PT2P_ROOT`; a fresh DCG clone does not include
   those large artifacts. This counter path has no Basanos dependency. The
   smallest fix is a standalone, checked-in tiny input fixture for each
   documented lifecycle example, or a clearly separated runbook for the
   Basanos artifact path. **Owner: docs/fixture tooling.**

10. **A testnet app currently carries a deployment step.** The repository says
   each application links its manifest and kernel into its program image, so
   a testnet first run must build and deploy an app image before sending input.
   This example avoids that cost because ProgramTest registers a native
   processor. A shared pre-deployed program with a small allowlist of general
   kernels would remove the image build and deployment step for those kernels;
   apps with custom kernels or custom handlers would still need their own image.
   This is a designed option, not current behavior. The smallest first version
   is a shared testnet image with a few versioned general kernels and an
   explicit app/kernel allowlist. **Owner: program/product design.**

11. **Hello, Dispute is not ready to add here.** The optimistic replay seam is
    being changed by the separate `dcg-seam-fix-2` work. This example does not
    build around an in-flight interface. The next step is to pin that seam,
    then add a false executor output and an on-chain challenger path against
    the same app kernel. **Owner: program/client.**

## Newcomer path measurement

The brief's fresh clone was made locally from revision `4d1446f` with
`git clone --no-hardlinks`; this does not measure a remote network clone. The
Python environment and Cargo target were fresh. Cargo's downloaded source/cache
was already present, so the build number is not a fully cold-network estimate.

| Step | Result | Evidence label |
|---|---:|---|
| Local clone | 0.258 s | measured |
| Fresh `uv venv` creation | 0.313 s; no Python packages needed | measured |
| `cargo build` with an empty `/private/tmp/dcg-hello-world-target` | 12 min 26 s; 1.1 GB target | measured |
| Final Python invocation after build | 19.765 s including an incremental rebuild after the final source tweak; printed `input=7 value=7 total=7` | measured |
| Repeat from a fresh Python venv and warm Cargo target | 4.866 s; same output | measured |
| Fresh clone, cold Cargo registry, and first successful result together | Not measured | open |

That successful result was produced by five ProgramTest transactions:
open session, create stream, create state, write input, and advance. It then
read the value and running-total bytes from the two program-owned state
accounts. The sample takes three commands after clone: `uv venv`, `cargo build`,
and the venv's Python running `examples/hello-world/run.py 7`.

Tools present in the measurement environment were Rust/Cargo 1.92.0 (the
checked-in toolchain), CPython 3.12, `uv`, `solana-test-validator`, and
`cargo-build-sbf`; the pinned platform-tools SDK path was also present. Only
Rust/Cargo, Python 3.12 and `uv` were needed by this ProgramTest route. The
validator, SBF builder and SDK were not used. A validator-backed testnet path
would need the SBF toolchain, a wallet, program deployment and the current
per-app image flow.

## Lines of code

Physical line counts, including comments and blank lines:

| Part | Lines | Note |
|---|---:|---|
| Shell setup | 3 commands after clone | install, build, run |
| Python wrapper | 44 | argument check and Cargo launch |
| Rust example driver | 254 | mostly PDA, account, transaction and ProgramTest setup |
| New kernel implementation in the example | 0 | it reuses the core's test-only kernel |
| Reused counter kernel and manifest | 173 | `stateful_test.rs` lines 1–173 |

The 254-line Rust driver is mostly fixed-protocol boilerplate for one byte of
useful input. An estimated 218 lines cover instruction bodies, PDAs, account
metas, signers, ProgramTest setup and account reads; the example-specific
behavior is parsing the increment, submitting it, and checking the two output
values. This is a line-count estimate, not a semantic code-size metric.
