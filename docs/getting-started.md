# Getting started with DCG

DCG runs computations on chain in one of two modes. Pick the one that fits,
then follow its quickstart. Each takes a few minutes on a local chain.

| | Consensus mode (sessions) | Optimistic mode (v2.1 runs and disputes) |
|---|---|---|
| **What runs on chain** | every step, one transaction each | nothing, unless a run is disputed; then one step |
| **Trust** | none beyond the chain | at least one honest watcher per run, inside its window |
| **Finality** | each step, at once | after the challenge window |
| **Good for** | long interactive state machines (a game, an agent loop) | big computations that are rarely wrong |
| **Start here** | [`session-tutorial.md`](session-tutorial.md) | [`optimistic-quickstart.md`](optimistic-quickstart.md) |

Both modes run kernels: small, deterministic, integer-exact functions.
Built-in kernels cover simple reductions. You can add your own in Rust, with
a Python mirror that the kernel kit checks against them
([`kernel-kit.md`](kernel-kit.md)).

## Setup

You need:
- Python 3.12. Install the `python/` package with `cd python && uv sync`,
  then `source python/.venv/bin/activate` (from the repository root). That
  puts the `dcg` command, and a `python` with DCG installed, on PATH.
- The Solana CLI tools (`solana-test-validator`, `cargo build-sbf`), for
  local chains and program builds.

Start a local chain with DCG on it:

```sh
dcg dev
```

The first start builds the alpha program image, which takes about 4 to 5
minutes on a fresh checkout with no output. It then prints an env file to
source in another terminal ([`dev-commands.md`](dev-commands.md)).

## Next steps

- **Your own kernel in optimistic mode:** [`kernel-app.md`](kernel-app.md),
  a template application with one custom STEP kernel.
- **Your own stateful program in consensus mode:**
  [`session-tutorial.md`](session-tutorial.md), from an empty directory to
  a long session with costs; [`session-quickstart.md`](session-quickstart.md)
  explains each piece, and [`sequencer.md`](sequencer.md) how to go faster.
- **Tracing a graph, and the built-in kernels:** [`tracing.md`](tracing.md).
- **What each mode guarantees, and how to check it:**
  [`guarantees.md`](guarantees.md).
- **Running the executor service and a watchtower:**
  [`services.md`](services.md).
- **The shared testnet program:** `J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9`
  on Fogo testnet runs the reviewed alpha image (optimistic mode). Consensus
  mode runs in your own program ([`session-quickstart.md`](session-quickstart.md)).
- **Terms:** testnet only; formats may change before beta
  ([`release-terms.md`](release-terms.md)).

The older revision-8 handler walkthrough, which Basanos uses, is in
[`revision-8-handlers.md`](revision-8-handlers.md).
