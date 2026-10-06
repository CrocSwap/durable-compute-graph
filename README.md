# durable-compute-graph

DCG (Durable Compute Graph) is a framework for orchestrating massively multi-transactional workloads in a blockchain context. Well suited applications include AI/ML models, complex derivative pricing and risk engines, clearing large batch auctions, and rich onchain gaming. DCG currently targets SVM based blockchains like Fogo and Solana. 

Modern blockchains have abundant compute in aggregate, but expose only thin transactions with limited compute and data budgets. In that context, scaling compute beyond non-trivial workloads has required manual and low-level coordination of intermediate data between atomic transactions. Traditionally scaling workloads beyond single transactions introduce a steep escalation of developer frictions and error and security risks. DCG solves this by abstracting the multi-transactional coordination into a single highly optimized, highly verified orchestration layer.

To write a DCG application, you break down your workload into *kernels* and assemble those kernels into *templates*. Kernels are small, deterministic integer-exact functions that must always execute within a single transaction. The DCG library provides a library of pre-written and validated kernels, but developing new kernels is easily supported by the framework. Templates are written as directed-acyclic-graphs where each node is a kernel. Each workload executes as a run through a pre-defined template. DCG handles both the onchain coalescing of intermediate data, as well as the off chain transport layer to orchestrate interdependent execution transactions at low latency and high throughput.  

DCG has two modes:

- **Consensus mode:** every step of a stateful kernel runs on
  chain, one transaction at a time, in your own program with DCG's runtime
  embedded. Nothing needs to be watched, and each step is final when it lands.
- **Optimistic mode:** an executor runs a plan off
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

**Alpha.** Formats may change before beta. See
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

## License

Rust implementation code is GPL-3.0-only. Specifications and portable goldens
are MIT. The vendored `curve25519-dalek` source keeps its original BSD 3-Clause
license and attribution; see [NOTICE.md](NOTICE.md).
