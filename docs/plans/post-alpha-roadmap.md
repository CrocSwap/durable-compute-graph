# DCG after the alpha: roadmap (2026-10-06)

**Status: accepted by the owner 2026-10-14.** v0.1.0-alpha is tagged; the alpha plan is
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
- **Version-1 runs on the shared program:** done 2026-10-13; `J9Eje…` runs
  the v0.2.0-alpha image `7acbce49…`, which carries sub 28.
- **Mixed modes in one graph** (per-region guarantees, `explain()` per
  region): designed in `docs/design/` as the long-term direction; not started.
- **TypeScript client:** a thin layer over the Python reference.
- **Hosted sessions:** post-alpha by the 10-03 decision.

## Hygiene

- Done (owner 2026-10-06): the release terms say mainnet at the deployer's
  own risk (`docs/release-terms.md`).
- Done (2026-10-09): `disputes_v21_chunked_oracle` is gated on
  `graph-v21` and `example-kernels`; a plain `graph-v21` run compiles it to
  no tests (measured), and with both features its 2 tests pass.
