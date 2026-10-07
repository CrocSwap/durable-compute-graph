# Session quickstart: your own stateful program

This guide takes you from a kernel to a session running in your own program. It covers alpha plan items C0 (the embedding contract) and C1 (the session quickstart). The worked example is `examples/session-app`, a tally kernel embedded in its own program.

DCG's consensus mode is a library that you link into your own program; the shared alpha program does not route sessions (owner decision, 2026-10-03). You write the kernel, and DCG supplies:
- the session, stream and state accounts;
- the input stream;
- the advance loop, with its checks;
- rejects and halts;
- the close path.

## 1. Write the kernel

`examples/session-app/src/lib.rs` defines `dcg-tally-v1`. Each 1-byte input adds its value to a running sum and counts it. The input 0 is rejected: it is consumed, state is unchanged, and the reject carries code 1.

The kernel has three parts:

- **A manifest,** declared once with `KernelDecl` (see `docs/kernel-kit.md`):

  ```rust
  pub static MANIFEST: KernelManifest = KernelDecl::new("dcg-tally-v1", 1, 1)
      .input(INPUT_LAYOUT, 1)
      .output(OUTPUT_LAYOUT, 16)
      .state(STATE_SCHEMA, 16)
      .compute(50_000, 8)
      .modes(&[MODE_CONSENSUS_V3])
      .rejects_input()
      .build();
  ```

- **`StatefulKernel`:**
  - `initial_state_spans` writes the starting state.
  - `transition_spans_with_outcome` applies one input. It returns `Continue`, `HaltBefore`, `HaltAfter` or `Reject`, or a `KernelError` to refuse the whole advance.
  - The state is handed over as spans (account slices) at consecutive offsets.
  - A kernel must be deterministic and must not read anything except its input and state.
- **The flat `initial_state` and `transition` methods,** which the trait requires. A v3-only kernel can implement them over one buffer, as the tally does.

## 2. Mirror it in Python and check the mirror

`examples/session-app/mirror.py` is the tally's Python mirror. Clients use it to predict state. The kernel kit checks it against the Rust kernel at every edge: inputs of every length, states at their limits, rejects in plain and rejectable sessions, and overflow.

```sh
cd examples/session-app
cargo build --features conform,no-entrypoint --bin tally-conform
PYTHONPATH=../../python python -m dcg.kernel_kit check --bin target/debug/tally-conform mirror.py
# dcg-tally-v1 v1/1 (stateful): 221 cases, 0 disagreements (continue 128, init state 3, refused 67, reject 23)
```

The conformance server, `src/bin/tally-conform.rs`, is four lines that name the app's kernels.

## 3. Embed the runtime (the embedding contract)

Your program's entrypoint hands every instruction to the DCG runtime, together with your kernel:

```rust
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    dcg_program::stateful::v3::process_with_kernel(program_id, accounts, data, &TALLY)
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
```

The contract:

- **Dependency.** Depend on `dcg-program` with `default-features = false` and
  `features = ["no-entrypoint"]`, so DCG's own entrypoint and allocator stay out of your program. Pin DCG by git revision; the example uses a path.
- **Patch.** Add `[patch.crates-io] curve25519-dalek` pointing at DCG's vendored copy, `crates/dcg-program/vendor`. DCG's pinned dependency set needs it.
- **Toolchain.** Build with `cargo build-sbf --tools-version v1.51 -- --locked` and commit your `Cargo.lock`. `examples/session-app/build.sh OUT` builds the image and writes a receipt with its sha256 and runtime version.
- **The runtime owns the wire.** Every instruction tag your program receives is DCG's stateful v3 wire. To add instructions of your own, dispatch them before calling `process_with_kernel`, on tags DCG does not use.
- **Runtime version.** Every image that links DCG's entry points carries a marker of the form `dcg-runtime/1 <version> stateful-v3 v21`. Anyone can read it without sending a transaction:
  - from a built image: `python -m dcg.runtime out/dcg_session_app.so`;
  - from a deployed program: `python -m dcg.runtime RPC_URL PROGRAM_ID`, which reads the program's ProgramData account.

  DCG security advisories name affected versions by this marker. The version is the `dcg-program` crate version, bumped with each runtime release.

## 4. Run a session

`examples/session-app/quickstart.py` does the whole loop on a local validator. Nothing leaves your machine.

```sh
./build.sh out
PYTHONPATH=../../python python quickstart.py out/dcg_session_app.so
```

Its steps:

1. Start `solana-test-validator` with the program loaded at a fresh address.
2. Read the program's runtime version from the chain.
3. Open a session through `dcg.session.Session`. The session manifest gives:
   - the kernel's identity, mode and schema;
   - the session's input width and state spans.

   Because the kernel declares `rejects_input`, the session opens rejectable.
4. Write the inputs 5, 0, 7 and 3, and advance four steps in one transaction.
5. Read the state (count 3, sum 15) and the session's info (cursor 4; one input rejected, at sequence 1 with code 1).
6. Check that the mirror predicts the same state.
7. Close the session, its stream and its state, and get the rent back.

Measured on 2026-10-05 on a MacBook with solana-test-validator 3.0.15: all steps passed in 11 s. The opt-in test `python/tests/test_session_app_local.py` repeats this run (`DCG_RUN_LOCAL_VALIDATOR=1 DCG_APP_IMAGE=...`).

To use testnet instead, deploy the image with the usual Solana tools, then point `SolanaRpcEndpoint` at the RPC and pass the program id. The session code is the same.

## What this does not show yet

- Views, lanes, resource accounts and phased initialization through the high-level `Session`. These are built and tested in Rust (`stateful-workloads-v3.md`, `stateful-session-lanes-v1.md`), but the Python `Session` does not drive them yet.
- A deployment to testnet or mainnet. The quickstart is a local run; it shows that the mechanics work, not network performance.
- A long session. [`session-tutorial.md`](session-tutorial.md) runs one
  through the sequencer, with batching, a dropped and resent transaction,
  and measured costs; [`sequencer.md`](sequencer.md) gives throughput
  guidance.
