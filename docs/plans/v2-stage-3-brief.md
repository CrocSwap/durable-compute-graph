# DCG v2 stage 3 brief: graph/plan compiler and on-chain lifecycle

## Goal

Implement deterministic graph validation/lowering, frozen graph and plan
bytes, and the v2 template/run/dispute lifecycle. The first slice is a static
two-region `add_i32/1` then `identity_i32/1` graph. It is a mechanics gate, not
useful-model-quality evidence.

## Exact file ownership

The exact stage-3 file set agreed in the shared v2 contract is:

- new `crates/dcg-program/src/graph/{codec,validate,plan,guarantee}.rs`;
- new `crates/dcg-program/src/dispute_v2/{template,run,descent,replay,settlement}.rs`;
- `tests/golden/dcg/graph_v2/`;
- the actual ProgramTest/SBF lifecycle tests.

Do not own stage 2 kernel arithmetic/registry or stage 4 Python tracing,
source maps, and diagnostics. The shared specs and existing Python codec
corpora are frozen inputs; a change to their bytes or refusal semantics requires
all three packages to update together.

## Frozen inputs

- `docs/spec/graph-plan-v2.md` v2.0-frozen, including static DAG validation,
  finality-gated imports, and fixed-index on-chain template shards.
- `docs/spec/kernel-capability-v2.md` v2.0-frozen, including DCKC/DCTV layouts
  and the OPEN registry boundary.
- `tests/golden/dcg/graph_plan_v2/` and
  `tests/golden/dcg/kernel_capability_v2/`.
- Stage 2's exact registered callback IDs and capability manifest; stage 4's
  compiler-free Python trace and Hello Graph example once its local bytes
  match these inputs.
- Owner answers for the v2 profile: shared pre-deployed testnet image, no
  in-graph loops, finality-gated imports without rollback, and on-chain
  fixed-index plan shards.

The owner decision about a shared program does not mean one program image may
be replaced while an admitted template or dispute still depends on it.

Stage 3 may launch in parallel with stages 2 and 4 as soon as DCG stage 1
releases capacity; the shared contract gate is frozen in this kickoff.

## First milestone

In ProgramTest, admit the minimal graph, lower it deterministically, store its
graph/plan once in immutable fixed-index shards, initialize a run, execute the
honest result, and expose a plan that stage 4 can reproduce exactly. The
lifecycle uses stage 2 registered callbacks and binds the exact compiler,
application image, and manifest identities.

## Acceptance tests

- Rust graph and plan bytes, IDs, and roots equal the checked-in Python golden
  vectors. Sorting, odd-tree rules, widths, overflows, and refusal codes match
  the frozen spec.
- Reject a self-edge/cycle, unbounded or dynamic graph expansion, missing
  capability/callback, wrong port layout, invalid account provenance, mutable
  template shard, and graph/plan identity mismatch.
- Prove that a consumer cannot execute from a provisional source-region
  output; it becomes eligible only after source finality. V2.0 never rolls back
  an imported value.
- Exercise the honest executor and a dishonest executor that commits a wrong
  `add_i32` result. An honest challenger descends root → child region → step,
  opens authenticated inputs, and receives the challenger ruling from actual
  SVM replay.
- Also exercise a matching opening, both role timeout outcomes, a wrong-half
  challenger, malformed opening, account/identity mismatch, exact deadline
  boundaries, and immutable terminal ruling/settlement behavior.
- Keep ProgramTest/native results distinct from the later shared-testnet gate.
  The shared-program deployment and exact-image testnet receipt are a separate
  integration milestone.

## Time-boxed first round and report

**First-round time box: estimated 5 engineer-days.** Stop at the first complete
local ProgramTest run lifecycle or the time-box boundary. Report at that first
measurement: compiler/source identities, graph/plan roots, final result,
measured runtime/CU and account costs when the harness exposes them, exercised
failure paths, and gaps. If the first lifecycle does not complete in the
round, report the last reproducible failure and mark the gate unverified. This
is a planning cap, not a measured delivery estimate.

## Coordination points

- Stage 2 publishes capability IDs, exact DCKC root, callback registry, and
  generated vectors before stage 3 locks lifecycle account validation.
- Stage 4 consumes stage 3's canonical graph/plan goldens; stage 3 must not
  create a second convenient Python-specific format.
- Any change to DCKC/DCTV, DCGG/DCPL, composition rules, refusal codes, or the
  initial vector seed requires a coordinated update from stages 2, 3, and 4.
- Keep the shared testnet deployment decisions in
  `docs/design/shared-testnet-program-decisions.md`; do not treat local
  ProgramTest acceptance as a deployed capability.
