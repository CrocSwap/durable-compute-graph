# DCG v2 milestone roadmap

**Status: designed sequence.** Every duration below is an **estimate**, not a
measurement. The kickoff produced offline specs and codec vectors only; no Rust
or SBF build, ProgramTest lifecycle, shared-program deployment, or testnet
transaction was run here. Estimates overlap across stage 2/3/4 and must not be
summed as elapsed time.

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
