# durable-compute-graph

DCG puts long computations on chain. It has two modes:
- **Consensus mode (sessions):** every step of a stateful kernel runs on
  chain, one transaction at a time, in your own program with DCG's runtime
  embedded. Nothing needs to be watched, and each step is final when it lands.
- **Optimistic mode (v2.1 runs and disputes):** an executor runs a plan off
  chain and commits to the result. Anyone can check it, and a wrong
  commitment is refuted on chain by replaying a single step.

In both modes the computation is made of kernels: small, deterministic,
integer-exact functions. DCG shows that a computation was done as stated. It
does not show that the computation is the right one.

## Start here

- [`docs/getting-started.md`](docs/getting-started.md): the two modes side
  by side, setup, and a local chain with `dcg dev`.
- [`docs/session-tutorial.md`](docs/session-tutorial.md): from an empty
  directory to a long session in your own program, with costs.
- [`docs/optimistic-quickstart.md`](docs/optimistic-quickstart.md): trace a
  graph, commit an honest and a lying run, and watch a watchtower convict
  the lie.
- [`docs/guarantees.md`](docs/guarantees.md): what each mode guarantees, and
  how to check a template or session with `explain`.
- [`docs/overview.md`](docs/overview.md): how it works.

## Status

**Alpha, testnet only.** Formats may change before beta. See
[`docs/release-terms.md`](docs/release-terms.md),
[`CHANGELOG.md`](CHANGELOG.md) and [`SECURITY.md`](SECURITY.md).

The shared alpha program for optimistic mode on Fogo testnet is
`J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9`. It runs the reviewed image
`8d39d440…`; `dcg verify` checks it ([`docs/dev-commands.md`](docs/dev-commands.md)).
Consensus mode runs in each application's own program.

## Repository map

| Path | What it is |
|---|---|
| `crates/dcg-program` | the on-chain program: the stateful (consensus) runtime, v2.1 disputes (tag 227), the kernel kit, and the revision-8 lifecycle |
| `crates/dcg-disputes` | v2.1 consensus bytes: trees, leaves, run roots, spec records (`no_std`) |
| `crates/dcg-kernels` | built-in kernels, the same source on the host and in the program |
| `crates/dcg-wire` | DCGG/DCPL v2 wire decoding and step lowering |
| `crates/dcg-test-support` | builds test states through real instructions |
| `crates/dcg-kernel-conform` | the kernel kit's conformance server for the example kernels |
| `python/dcg` | the Python client: `dcg.session`, `dcg.sequencer`, `dcg.v21` (tracing), `dcg.disputes_v21`, `dcg.services` (executor and watchtower), `dcg.kernel_kit`, `dcg.explain`, and the `dcg` command |
| `examples/` | `session-app` and `kernel-app` (templates for your own program), `optimistic-quickstart`, `hello-graph`, `services`, `kernel-kit` |
| `docs/` | guides, `design/` (normative designs), `experiments/` (measured evidence), `plans/` |

## Checks

```sh
cargo test --locked --profile fasttest --all-targets     # Rust, offline
cd python && uv run --with pytest pytest                   # Python, offline
```

Tests that need a local validator or a network are opt-in and say so.

## Revision-8 material

DCG began as an extraction of the revision-8 lifecycle mechanics from
Basanos, which still uses them through the application seam. That history,
the seam, and the older checks are in
[`docs/revision-8-extraction.md`](docs/revision-8-extraction.md) and
[`docs/revision-8-handlers.md`](docs/revision-8-handlers.md).

## License

Rust implementation code is GPL-3.0-only. Specifications and portable goldens
are MIT. The vendored `curve25519-dalek` source keeps its original BSD 3-Clause
license and attribution; see [NOTICE.md](NOTICE.md).
