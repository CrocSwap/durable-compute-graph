# DCG Hello World

## Typed Python session client

[`run_session.py`](run_session.py) uses `dcg.session.Session` to derive the
session, input-stream and state-span PDAs; build and submit instructions; read
the counter as a typed `CounterState`; and reclaim accounts listed in its local
JSON inventory. It targets the same static counter kernel in a local
validator. The local-validator integration test is written but was not run in
this worktree: the pinned SBF build reduced free space to 5.3 GiB after 30
seconds, so it was stopped before crossing the dispatch's 5 GB floor. This is
an SBF mechanics path, not a capability or performance result.

The existing counter manifest and Hello World use stateful wire v1, so the
client preserves those instruction bytes and v1 PDA seeds. The account-layout
module also carries the v2 seed namespace and the encoder has v2 forms for the
shared session operations. The current v2 scaled workload has a different
static kernel and is not claimed by this counter example.

Build the test-only SBF image using the pinned tools, then start a local
validator with the example's fixed program ID:

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-python-session-target
DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920 \
DCG_SBF_TOOLS_VERSION=v1.51 \
DCG_SBF_STAGING_NAME=dcg-python-session-staging \
crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-python-session-sbf

solana-test-validator --reset \
  --bpf-program FfQ94M4DKiTAGeH8epnP8xUXyTeg9nywFYdPeUj18HzQ \
  /private/tmp/dcg-python-session-sbf/dcg_program.so
```

In another shell, create disposable local payer and authority keypairs, fund
the payer from the validator faucet, install the pinned Python dependencies,
then run the short example:

```sh
solana-keygen new --no-bip39-passphrase --silent --force -o /private/tmp/dcg-session-payer.json
solana-keygen new --no-bip39-passphrase --silent --force -o /private/tmp/dcg-session-authority.json
solana airdrop 5 "$(solana address -k /private/tmp/dcg-session-payer.json)" --url http://127.0.0.1:8899

UV_PROJECT_ENVIRONMENT=/private/tmp/dcg-python-session-venv \
UV_CACHE_DIR=/private/tmp/dcg-python-session-uv-cache \
uv sync --locked --project python --python 3.12
DCG_PAYER_KEYPAIR=/private/tmp/dcg-session-payer.json \
DCG_AUTHORITY_KEYPAIR=/private/tmp/dcg-session-authority.json \
PYTHONPATH=python /private/tmp/dcg-python-session-venv/bin/python \
  examples/hello-world/run_session.py 7
```

The client defaults to `http://127.0.0.1:8899` and the fixed example program
ID above. The account inventory records each PDA's seed derivation, kind, role,
parent, lifecycle, payer and observed rent. Before cleanup, `Session.close()`
reconciles the inventory with batched RPC reads, discovers parent-bearing
children, then retires and closes the session accounts. Its default inventory
path is unique per session; if `DCG_SESSION_JOURNAL` is set, choose a fresh path
for each new session. See [the Python session guide](../../docs/python-session.md)
for drift reports and recovery. The original [`run.py`](run.py) remains the
in-process ProgramTest path for comparison.

This runs one counter transition against DCG's stateful instruction handler in
an in-process Solana `ProgramTest` bank. It creates a session, deposits one
input byte, submits an `ADVANCE`, then reads the resulting program-owned state
account. Try an input of `7`; the bank should report `input=7 value=7 total=7`.

This is a local mechanics example. It runs the Rust handler through
`ProgramTest`'s native processor, not an SBF image or a validator. The static
`CounterKernel` and its manifest are currently in
`crates/dcg-program/src/stateful_test.rs`, behind the
`sbf-real-lifecycle-test` feature. The original `run.py` remains a command
wrapper around the Rust ProgramTest driver; `run_session.py` is the separate
Python transaction client described above. Remaining core limitations are
listed in [FRICTION.md](FRICTION.md).

## Requirements

- Rust and Cargo from the pinned `rust-toolchain.toml` (Rust 1.92.0).
- Python 3.12.
- `uv` to create the Python 3.12 virtual environment.
- No Solana CLI, SBF toolchain, or separately running validator for this
  ProgramTest path.

## Commands

From the repository root, create a fresh Python environment. The wrapper uses
only Python's standard library, so it has no Python package dependencies:

```sh
uv venv --python 3.12 /private/tmp/dcg-hello-world-venv
```

Build the example into a temporary target directory, then run it:

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-hello-world-target
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
cargo build --locked --manifest-path examples/hello-world/Cargo.toml
/private/tmp/dcg-hello-world-venv/bin/python examples/hello-world/run.py 7
```

The first build downloads and compiles the Rust/ProgramTest dependency graph.
Later runs reuse it. To choose another one-byte input, replace `7` with an
integer from 0 through 255.

The kernel increments `value` by the input and adds the new value to `total`.
Both values start at zero. This first example runs one transition, so they both
equal the input. DCG's account adapter binds the session to the kernel's
semantic version, ABI version, state schema and consensus mode before accepting
the input or transition.

## Cleanup

After the run, remove temporary targets and the Python environment:

```sh
mv /private/tmp/dcg-hello-world-target /private/tmp/trash-dcg-hello-world
rm -rf /private/tmp/dcg-hello-world-venv
```

## Extension

The next rung would use the same kernel in optimistic mode and show a challenger
catching a false result. That path is not included in this example because the
optimistic replay seam is under active repair; see the [friction report](FRICTION.md).
