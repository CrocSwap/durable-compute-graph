# DCG after the alpha: roadmap (2026-10-06)

**Status: proposed for owner review.** v0.1.0-alpha is tagged; the alpha plan is
`alpha-release-plan.md` (all exit criteria met), and the milestone history is
`v2-roadmap.md`. Durations are estimates.

## Separation (agreed 2026-10-06)

1. **Tagged releases for consumers.** Basanos and Doom pin tags instead of a
   sibling checkout (Cargo git dependencies, the `dcg` Python package from the
   tag). About a day.
2. **Retire revision 8** (`retire-revision-8.md`). 2 to 4 days plus review.
3. **Doom moves to its own repository** (`dcg-doom`), depending on a DCG tag.
   The pre-DCG Doom program is removed; the shareware WAD is fetched, never
   committed.

## Capabilities

- **On-chain input posting** (v2.1 design §4.4, `INPUTS_COMPLETE`): required
  before non-LX templates with external inputs are offered on mainnet.
- **LX watchtower:** checking LX1 runs needs a full re-execution; it follows
  faster executors (GPU work in Basanos).
- **Version-1 runs on the shared program:** `J9Eje…` predates sub 28; the
  next alpha image carries it.
- **Mixed modes in one graph** (per-region guarantees, `explain()` per
  region): designed in `docs/design/` as the long-term direction; not started.
- **TypeScript client:** a thin layer over the Python reference.
- **Hosted sessions:** post-alpha by the 10-03 decision.

## Hygiene

- The release terms say "testnet only"; Basanos's mainnet deployment is an
  owner decision for our own application. The terms need the owner's
  wording for consumers who deploy DCG-based programs themselves.
- `disputes_v21_chunked_oracle` needs the `example-kernels` feature; gate it
  so a plain `graph-v21` run does not report a false failure.
