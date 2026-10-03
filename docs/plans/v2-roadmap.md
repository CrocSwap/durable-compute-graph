# DCG v2 milestone roadmap

**Status (2026-10-03): milestones 1, 2 and 4 are done for the v2.0 trace
path. Milestone 3, disputes, moved to v2.1 (optimistic first-divergence
descent, tag 227), which now runs on testnet with real Basanos kernels but
is not yet independently reviewed (a review is running).** The table at the
end is the original designed sequence; its durations are **estimates** from
the kickoff and must not be summed as elapsed time.

## Status by milestone (2026-10-03)

| # | Milestone | Status |
|---|---|---|
| 1 | Hello Graph locally | **Done** (2026-10-01). `dcg.tracing` lowers traced graphs to canonical v2.0 graph and plan bytes; `crates/dcg-wire` decodes them against goldens; admission checks uploads against the canonical lowering. |
| 2 | Hello Graph on the shared program | **Done on testnet** (*measured* 2026-10-01, `docs/hello-graph.md`), a mechanics demonstration. The shared program runs image `7b04f8d5` (2026-10-02). |
| 3 | Hello Dispute | **v2.0 descent and sampling are retired in favour of v2.1** (`docs/design/optimistic-descent-v2.1.md`), after the 2026-10-02 review's eight v2.0 blockers. v2.1 status is below. |
| 4 | `explain()` with a composed guarantee | **Done for the trace-committed v2.0 profile** (offline, 2026-10-02); it refuses root commitments and sampling. Not yet extended to v2.1 templates. |
| 5 | Doom consumer | **Runs on stateful v3, below target:** 1.63–1.67 frames/s on testnet against the 3.0/s goal (*measured* 10-02). Lanes (`docs/design/stateful-session-lanes-v1.md`) have owner decisions; the sequencer's `OrderedLane` exists; the program-side lanes are not implemented. |
| 6–8 | Sampling, Freivalds, ZK | Not started. Their place in v2.1 is a per-region mode (design §11). |

## v2.1 (tag 227) status

All *measured* items are on Fogo testnet or in ProgramTest as named; none is
independently reviewed yet.

| Capability | Status |
|---|---|
| Descent, claims (SHAPE, EDGE, STATE, STEP, GATE, OUT), repeated blocks, gates, kind 6 | Done: native and SBF oracle suites agree with the Python referee (687+ chunked scenarios). |
| Chunked kernels, committed constants (plain and chunked) | Done (10-02): oracle-checked natively, on SBF and on testnet (26/26 replay scenarios, forged ConstSpec openings refused). |
| Staging buffers (128 KiB), reveal cache | Done. |
| Application kernels from the embedding image's manifest | Done (8680be8, 10-03). Basanos's test image runs form 4 (`basanos-f4-v1`, weight rows as committed constants) and form 22 (`basanos-f22-v1`): 31/31 oracle cases natively and on SBF, and 31 live disputes on testnet rule as the oracle. |
| Rent reclaim | Done (bc4e391, 10-03): disputes with their staging buffers, runs (shrunk to a receipt that keeps status and root), caches. Live on testnet: a 64 KiB dispute returns about 0.48 FOGO. **Open:** template closes (in progress). |
| LOG state (KV cache) | Python reference only (d2d9f51). |
| List inputs (wide steps, more than 8 producers) | Python reference done and owner-approved (10-03); crate, wire and program in progress. |
| Attested admission | Done for revision 8 (9cad0d3). |
| Admission cursor | Parked (10-02): templates are trusted subjectively and verified off-chain. |

**What Basanos still needs before migrating documents to v2.1** (design §13):
1. Attention witness growth at late positions: being measured (10-03).
2. LOG state in the program.
3. Typed decisions as a v2.1 template.
4. Per-form decompositions and CU.

## Next, in order

1. The independent v2.1 review: done 10-03; F1–F5 and F9 fixed (0862470),
   re-reviewed and kept. Follow-ups A (narrow LOG neutrality) and B (§8.3's
   additive load extension, counted only while waiting on the executor) are
   queued with their own review; until LOG is on chain, admitters refuse
   LOG-state templates.
2. List inputs and template closes in the program (in progress).
3. A run-level dispute model in the Python reference (several disputes, ruled
   prefix, best win, bonds), fuzzed against the program with random
   interleavings and per-step invariant checks: conservation, no bond to the
   executor after the best win, every dispute ends. It follows the F1 bond
   theft, which the per-dispute oracle could not see.
4. LOG state in the crate and program.
5. The attention decomposition, chosen from the 10-03 measurement.
6. A v2.1 Basanos document template (one repeated block per position), end to end on testnet.
7. Lanes in the program, for Doom.
8. Sampling and Freivalds as v2.1 region modes.

## Original sequence (kickoff estimates)

| Milestone | Dependencies | Acceptance | Estimate |
|---|---|---|---|
| **1. Hello Graph locally** | Gate 1 frozen; stage 2 registers `add_i32/1` and `identity_i32/1`; stage 3 emits/validates DCGG/DCPL; stage 4 traces the supported Python example. | Python trace → exact shared graph/plan bytes and roots → local SVM ProgramTest honest run. The first `explain()` report names calls, regions, limits, image, manifest, and plan IDs, without claiming a composed guarantee that stage 3 has not implemented. | **Estimated 4–8 engineer-weeks** on the stage-3 critical path (low confidence), plus **estimated 1–2 engineer-weeks** for cross-package integration. Stage budgets: stage 2 **1–2 weeks**, stage 3 **4–8 weeks**, stage 4 frontend **3–6 weeks**; parallel work overlaps. |
| **2. Hello Graph on the shared program** | Hello Graph locally passes; owner records upgrade authority, starter kernels, version policy, fees/rent, and abuse limits; exact shared testnet program/image and manifest are admitted. | On the shared testnet image, upload immutable fixed-index graph/plan shards once, initialize a run, execute the honest add/identity graph, read back the final result, and retain exact image/root/run/fee/rent receipts. | **Estimated 1–2 additional engineer-weeks**, excluding deployment wait and testnet scheduling. This is a new planning estimate, not measured. |
| **3. Hello Dispute on v2** | Shared-program honest run passes; stage 2's replay callback and stage 3's nested optimistic lifecycle use the same registered manifest and image. | Commit a wrong `add_i32` result, then have an honest challenger descend root → child → step and win through actual SVM replay. Also pass honest matching, executor/challenger timeout, wrong-half, malformed-opening, neutral identity mismatch, and deadline-boundary controls. | **Estimated 2–4 engineer-weeks after Hello Graph on the shared program**, low confidence. This is incremental integration/run work; implementation overlaps stage 3's **estimated 4–8 week** package. |
| **4. `explain()` with a composed guarantee** | Hello Dispute establishes the mode lifecycle; stage 2 capabilities, stage 3 composition rules, and stage 4 source mapping are all versioned and aligned. | `explain()` names which regions use which modes, how guarantees compose across finality-gated imports, the exact required kernel capabilities, and which ceilings are designed versus measured. It refuses to state a guarantee for an OPEN capability or unsupported mode. | **Estimated 1–2 engineer-weeks** after the relevant stage outputs stabilize. |
| **5. Doom consumer integration** | Composed guarantee is available; Doom's state/cursor ABI is pointer-free and registered; local Doom kernel behavior and throughput gates pass; the existing sequencer public stream API is stable. | Build a static Doom adapter on DCG v2, pass standalone SBF one-tic and bounded-sweep gates, then compare on a fresh testnet program/image with byte-exact frame outputs and no unresolved fates. Keep session, input ordering, workspace pool, snapshot identity/hash, rendering, rent, and fees in Doom/application code. | **Estimated 4–8 engineer-weeks**, low confidence, from the Doom port design; excludes graph runtime, testnet operation, and renderer redesign. |
| **6. Sampling audit backend** | Doom is not a prerequisite for the backend, but stage 3's optimistic dispute gate is; owner selects a chain-verifiable future randomness source/delay and the backend's public commitment/opening ABI. | Commit before randomness; verify sampled openings; route mismatch/withholding to all-step dispute; measure random verification, sample CU, packet sizes, and adversarial withholding. | **Estimated 2–4 engineer-weeks** after randomness and witness choices. |
| **7. Freivalds backend** | A representative batched matrix workload, field/range rules, accumulator commitments/openings, and exact requantization contract are fixed. | Compare full verifier-graph cost against direct replay after all openings; accept only if the measured batch is cheaper and exact output checks pass. | **Estimated 3–6 engineer-weeks** after workload and field decisions. |
| **8. ZK backend** | Relation, proof system, public/private boundary, commitment translation, verifier key, and SVM cost target are selected. | A bounded SBF verifier accepts the exact versioned relation and malformed-proof controls; no privacy claim exceeds the chosen proof system. | **Open; no estimate** until the prerequisites are chosen. |

## Integration order and guardrails

The order is deliberate: first prove an offline/local graph, then the shared
program run, then an actual dispute, then explain the composed guarantee. Doom
and the deferred proof modes consume those shared interfaces after the first
vertical slice is understood. A small kernel mechanics pass does not establish
useful model quality, general compiler correctness, or full-profile capacity.

D8 has selected a shared pre-deployed testnet program as the target; its release
and first use are later than the local Hello Graph gate. Follow `docs/design/shared-testnet-program-decisions.md`
before its first template is admitted. Record image SHA on each permitted
testnet upgrade and keep templates/disputes bound to the exact image they
admitted against.

Real-time transport is its own DCG sequencer workstream. The A/B/C sequencer work in `docs/design/realtime-transport-v1.md` owns the
generic transport integration; stage 4 and Doom consume its public API and do
not create a second sequencer. The current tree contains sequencer modules,
but the transport design still marks implementation/live behavior OPEN. The
earlier `dcg-modes-and-compiler` roadmap's **estimated** transport-reference
effort (8–12 person-days) came from a separate TypeScript-first proposal and is not a stage-4 estimate. Current
Python transport scope and open decisions live in
`docs/design/realtime-transport-v1.md`; do not infer that the testnet transport
comparison has run from the presence of code or docs.
