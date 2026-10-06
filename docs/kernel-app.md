# An application image with a custom kernel

`examples/kernel-app` is a complete optimistic-mode application. It is one
custom STEP kernel, `ex-polyhash-v1`, in a program that runs DCG's v2.1
disputes (tag 227). Copy it to start your own. For consensus mode (sessions),
start from `examples/session-app` (`docs/session-quickstart.md`).

## What is in it

| File | What it is |
|---|---|
| `src/lib.rs` | the kernel, its `KernelDecl`, the `ApplicationManifest`, and the entrypoint |
| `src/bin/polyhash-conform.rs` | the kernel-kit conformance server for this crate's kernels |
| `mirror.py` | the Python mirror. The off-chain referee and executor use it to replay the kernel |
| `dispute.py` | a lying run and an honest run, each disputed, then settled and closed |

The entrypoint routes only tag 227:

```rust
Some(227) => dcg_program::disputes_v21::process(program_id, accounts, data, &APPLICATION),
```

The program resolves a step's kernel id against `APPLICATION` when it rules a
STEP claim. A kernel replays a STEP claim only if its declaration lists
`MODE_STEP_V21`.

## The steps

1. **Write the kernel and its declaration.** The declaration states the limits:
   `KernelDecl::new("ex-polyhash-v1", 1, 1)` with input 4,096 bytes, output 8
   bytes, a compute ceiling of 200,000 CU, and the STEP mode. Declaration
   errors fail at compile time (`docs/kernel-kit.md`).
2. **Write the mirror** with the same limits. Use `@step_kernel(name,
   max_input_bytes=..., max_output_bytes=..., max_compute_units=...)`, and
   raise `KernelRefused` wherever the Rust kernel refuses.
3. **Check that the two agree:**

   ```sh
   cd examples/kernel-app
   cargo build --features conform,no-entrypoint --bin polyhash-conform
   python -m dcg.kernel_kit check --bin target/debug/polyhash-conform mirror.py
   ```

   *Measured 2026-10-05:* 112 cases, 0 disagreements (81 outputs, 31
   refusals). The build took 82 s from cold on an M-series Mac.
4. **Build the image:** `dcg build --crate examples/kernel-app out/kapp`. This
   writes the `.so` and a build receipt (commit, toolchain, SHA-256, runtime
   marker).
5. **Run it.** Locally, start `dcg dev --crate examples/kernel-app` in one
   terminal (it runs until Ctrl-C) and source the env file it prints in
   another. On testnet, deploy the `.so` at your own program address and set
   `DCG_RPC_URL`, `DCG_PROGRAM_ID` and `DCG_PAYER_KEYPAIR` yourself. Then:

   ```sh
   source /private/tmp/dcg-dev-…/dcg-dev.env
   PYTHONPATH=python python examples/kernel-app/dispute.py --settle
   ```

## What the example shows (measured, testnet, 2026-10-05)

The image was built from commit `595cd04` (341,008 bytes, SHA-256
`9426291282e957bd…`). It was deployed at a fresh testnet address,
`FWVem35SZKZx3rHghTX4ZoPqunbs24nCpzMq3xyT5x6`. The deploy took 8 s and
`dispute.py --settle` took 69 s, using 27 transactions:

- **Lying run:** the executor committed a corrupted hash. The challenger's STEP
  claim replayed the kernel on chain, and the program ruled **C** (the
  challenger wins).
- **Honest run:** the same claim against a correct commitment was ruled **E**
  (the executor wins).
- Every run was settled and closed down to its receipt, and the template was
  closed. The payer's net cost was 167,240 lamports.
- Every ruling matched the Python oracle.

This is alpha exit criterion 5. The receipts are in Basanos
`out/runs/dcg-kernel-app-testnet-2026-10-05/` and evidence row M1385.

## Rules for your own kernel

- **Do not change a deployed kernel while its runs are live.** STEP claims
  resolve against the image that is live when the dispute is ruled
  (`docs/release-terms.md`).
- **The mirror must match the kernel exactly,** including every limit and
  refusal. Rerun the kit after every change to either one.
- **Plans should check limits:** at plan time, check that every step fits its
  kernel's declared limits.
- **Do not use LOG state.** It is not supported in the alpha. Use SMALL state,
  or LX1 checkpoints for large state.
