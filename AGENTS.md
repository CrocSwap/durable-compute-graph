# AGENTS.md

## Project

DCG (Durable Compute Graph) runs computations too big for one transaction on
Fogo (an SVM chain), in two modes: **consensus** (stateful sessions embedded
in the application's own program, every step on chain) and **optimistic**
(v2.1 runs committed off chain and refuted on chain by a single-step dispute,
with LX1 checkpoints for large state). Start at `README.md` and
`docs/overview.md`; what each mode guarantees is in `docs/guarantees.md`.

DCG is a library and a shared program, not an application. It stays
unopinionated: dispute economics are application hooks, and model kernels
belong to applications (Basanos, Doom), never to DCG.

## Read first

- `docs/project-rules.md`: standing rules.
- `DIRECTOR_HANDOFF.md`: in-flight state (ephemeral).
- `docs/plans/`: the roadmap (`post-alpha-roadmap.md`) and plans in progress.
- Before changing protocol behavior: the design under `docs/design/` (v2.1:
  `optimistic-descent-v2.1.md`, laws in `docs/spec/referee-laws-v21.md`;
  sessions: `stateful-workloads-v3.md`, lanes `stateful-session-lanes-v1.md`)
  and the experiment notes under `docs/experiments/`.

If code, designs, laws and experiment notes disagree, surface the
inconsistency instead of silently choosing one.

## Repository map

| Path | What it is |
|---|---|
| `crates/dcg-program` | the on-chain program: sessions (consensus runtime), v2.1 disputes (tag 227), the kernel kit, and the revision-8 lifecycle (being retired: `docs/plans/retire-revision-8.md`) |
| `crates/dcg-disputes` | v2.1 consensus bytes (`no_std`): trees, leaves, run roots, LX1 |
| `crates/dcg-kernels` | built-in kernels, the same source on host and in the program |
| `crates/dcg-wire` | DCGG/DCPL wire decoding and step lowering |
| `crates/dcg-test-support` | builds test states through real instructions |
| `python/dcg` | the client: `dcg.session`, `dcg.sequencer`, `dcg.v21`, `dcg.disputes_v21`, `dcg.services`, `dcg.kernel_kit`, `dcg.explain`, the `dcg` command |
| `examples/` | templates for applications and quickstarts |
| `docs/` | guides, `design/` (normative), `spec/`, `experiments/` (measured evidence), `plans/` |

## Development

```sh
cargo test --locked --profile fasttest --all-targets       # Rust, offline
cargo test -p dcg-program --features graph-v21,example-kernels   # the alpha image's features
cd python && uv run --with pytest pytest                     # Python, offline
```

SBF images are built reproducibly (`scripts/build-alpha-image.sh`); never
assume a host build equals the SBF build. Tests that need a validator or a
network are opt-in and say so.

## Protocol changes

Anything that changes consensus bytes, rulings, endings or payouts is
consensus-sensitive:
- version it explicitly (a new sub-instruction, layout version or spec
  version); old behavior stays reproducible;
- add golden vectors or cross-implementation tests (Python mirrors cover
  consensus bytes; program behavior is tested by running the program, native
  and SBF);
- test honest and adversarial role orders, and every ending (rule 7);
- update the design, the referee laws and `CHANGELOG.md` in the same change.

## Consumers

Basanos and Doom on DCG consume DCG. They pin **tagged releases**. Do not edit
a consumer's repository from here; a change that breaks a consumer is marked
**breaking** in `CHANGELOG.md` with its migration.

## Completion checklist

1. The touched area's quick suite (and the alpha-image features when the
   program changes).
2. Goldens and cross-implementation checks where they apply.
3. Failure, timeout, malformed-input and adversarial paths.
4. Report what was not tested, especially SBF and live networks.
