# Changelog

Breaking changes are marked **breaking**, with who is affected and how to
migrate. Formats may change before beta (see `docs/release-terms.md`).

## v0.1.0-alpha (2026-10-06)

The first tagged release: the alpha exit criteria are met (`docs/plans/alpha-release-plan.md`),
and consumers (Basanos, Doom on DCG) pin this tag instead of a sibling checkout.
The shared testnet alpha program `J9Eje…` runs image `8d39d440…` (built from
466e55d); version-1 runs (sub 28) are in this source but not yet in that image.
Basanos's own mainnet program (owner decision 2026-10-06) is built from 7d1aac5.

### Python client

- **`Session.write_and_advance(values)`** writes up to `max_steps` inputs and
  advances over them in one transaction; the transport's `send_many` sends
  several instructions in one transaction. One transaction per batch instead
  of one per input.
- **`dcg dev`** keeps its run directory when the validator fails to start, so
  its `validator.log` can be read.

### Program (shared alpha image `8d39d440…`, runtime `dcg-runtime/1 0.1.0`)

- **Version-1 v2.1 runs** (tag 227 sub 28, `init_run_v1`): the run records
  `remainder_to`, which receives a convicted executor's bond remainder in
  place of the payer; it may not be the executor, and the payer may then be
  the executor. The layout version is byte 5 of the run, and `remainder_to`
  follows `waiting_E`. Version-0 runs (sub 2) are unchanged. Python:
  `DisputeClient.init_run(..., remainder_to=...)`, `LxClient.init_lx_run(...,
  remainder_to=...)`, and `client.remainder_recipient(run)`. Not yet in the
  deployed alpha image.

- **The runtime version marker** (`dcg-runtime/1 <version> stateful-v3
  v21`) is in every image. Read it with `python -m dcg.runtime`.
- **Kernel kit:** the STEP replay and the v3 transition judgement are shared
  with the conformance harness. Behavior is unchanged (reviewed).
- **Rejectable sessions and ring streams** (session features; sessions v3).
  **Breaking for v3 clients:** child creators now take the session authority,
  signing, as account 2; the open payload may carry `lanes` and `features`.
  Migrate with the current Python client (`dcg.session`), or follow
  `docs/stateful-workloads-v3.md`.
- **Removed features (R4):** `weight-witness-probe`, `v7-cu-probe`,
  `a16-kernel-probe`, `decision-kernel-probe`, `pt2p-seal-profile`,
  `legacy-basanos-fixtures` and `legacy-hclosure-handlers` (the legacy
  HClosure dispatch, about 1,150 lines, and 41 fixture-dependent tests that
  could not run in DCG; their Basanos counterparts pass in Basanos). None
  gated default or alpha-image behavior. **Breaking** only for a build that
  names them: drop them from its feature list.
- **LOG state is reserved, not supported** (alpha decision 2026-10-05).
  **Breaking for plan builders:** `PlanBuilder.build` refuses LOG steps
  unless `allow_log=True`. The program is unchanged and still rules LOG
  claims moot. Use LX1 checkpoints for large state.
- **Tag 227 admission:** the window floors, canonical template ids,
  built-in kernels bound at version (1, 1), and staging-growth refunds.
  **Breaking:** templates that broke these rules are refused; re-encode them
  with the current client.

### Client and tools

- `dcg dev`, `dcg build`, `dcg verify`, `dcg explain`.
- `dcg.services`: the executor service and the watchtower.
- `settle_and_reclaim`, named tag-227 errors, `dcg.v21` tracing, and the
  kernel kit (`dcg.kernel_kit`).
- The template session app (`examples/session-app`) and the session
  quickstart.
