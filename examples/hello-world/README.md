# DCG Hello World

This runs one counter transition against DCG's stateful instruction handler in
an in-process Solana `ProgramTest` bank. It creates a session, deposits one
input byte, submits an `ADVANCE`, then reads the resulting program-owned state
account. Try an input of `7`; the bank should report `input=7 value=7 total=7`.

This is a local mechanics example. It runs the Rust handler through
`ProgramTest`'s native processor, not an SBF image or a validator. The static
`CounterKernel` and its manifest are currently in
`crates/dcg-program/src/stateful_test.rs`, behind the
`sbf-real-lifecycle-test` feature. The Python file is a command wrapper around
the Rust ProgramTest driver; it is not yet a Python kernel or transaction
client. These are current core limitations, listed in [FRICTION.md](FRICTION.md).

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
