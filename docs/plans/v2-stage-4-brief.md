# DCG v2 stage 4 brief: Python tracing, explain, and examples

## Goal

Build the supported pure-Python front end for the frozen graph/plan contract.
It traces static kernel calls with early type, shape, state, and range checks,
emits bytes identical to stage 3, explains the resulting plan/guarantee, and
provides Hello Graph and dishonest-executor examples.

## Exact file ownership

The exact stage-4 file set agreed in the shared v2 contract is:

- new `python/dcg/{tracing,ir,codec,explain}.py` and package metadata;
- new `examples/hello-graph/`, including the dishonest executor;
- optionally update `docs/python-session.md` only to clarify that the existing
  typed stateful session client is distinct from the graph tracer.

Do not choose wire fields, mode rules, kernel equations, on-chain handlers, or
lifecycle economics. The shared Python reference codec and golden test support
added during kickoff is an integration input; package work must not fork its
encoding.

## Frozen inputs

- `docs/spec/kernel-capability-v2.md` v2.0-frozen: DCKC manifest root, DCTV
  vector envelope, ordering, versions, and explicit OPEN registry items.
- `docs/spec/graph-plan-v2.md` v2.0-frozen: DCGG/DCPL bytes, DAG-only graph,
  finality-gated imports, and graph/plan identity rules.
- Both golden corpora under `tests/golden/dcg/`.
- Stage 2's registered kernel calls and manifest; stage 3's canonical
  graph/plan roots, refusal codes, and composition rules.
- The Python-first frontend decision and the restricted static subset from the
  shared v2 design.

## First milestone

Stage 4 may launch in parallel with stages 2 and 3 as soon as DCG stage 1
releases capacity; the shared contract gate is frozen in this kickoff.


Trace a small pure function that binds two signed `i32` inputs, calls the
registered `add_i32/1`, then passes its child-region result through
`identity_i32/1` in the parent region. Emit the frozen `DCGG` bytes and a
stage-3-compatible `DCPL`, then show `explain()` with source locations,
kernel calls, region boundaries, admitted ceilings, and any guarantee
composition stage 3 has actually specified.

## Acceptance tests

The shared §10 ownership list does not name Python test-module paths. Stage 4
must coordinate any new `python/tests/` files with the other package leads
before adding them; keep tests focused on the exact shared goldens and do not
silently expand the package ownership boundary.

- `DCGG`, `DCPL`, IDs, and roots reproduce the checked-in golden bytes
  byte-for-byte. DCKC/DCTV references bind the exact staged manifest and vector
  corpus.
- Type, rank, fixed shape, integer range, and state-cursor mismatches fail at
  trace/compile time with the source span and offending call.
- Dynamic graph expansion, in-graph loops, ambient reads, unsupported Python
  effects, and undeclared aliases are refused with stable diagnostics; bounded
  loops must be expressed inside a registered kernel or as a repeated graph
  call.
- `explain()` reports only guarantees and costs justified by the selected
  versioned mode, stage-2 capabilities, and stage-3 composition result. It
  labels designed ceilings separately from measured runtime results.
- The Hello Graph fixture includes a deliberately dishonest executor for
  stage 3 to consume; the example does not simulate a successful chain dispute
  or claim that Python tracing proves on-chain execution.

## Sequencer coordination

Use the existing `dcg.sequencer` transport path for any example submission.
The current DCG tree contains sequencer pool/provider, streaming-journal,
and scheduler modules, while packages A, B, and C in
`docs/design/realtime-transport-v1.md` define their integration contract.
Stage 4 does not rebuild those modules or own
`python/dcg/sequencer/`, its tests, or its transport docs. Consume the stable
public `Sequencer`/stream API once package C publishes it; keep graph meaning,
tracing, and application postconditions in this package. If the transport API
is still in integration, continue the offline tracer and record that runtime
submission awaits the existing transport gate.

## Time-boxed first round and report

**First-round time box: estimated 5 engineer-days.** Stop at the first
Hello Graph trace whose emitted bytes and roots match the shared goldens, or at
the time-box boundary. Report after that first parity measurement with the
source example, emitted graph/plan IDs, trace diagnostics exercised, and which
`explain()` fields remain unavailable because stage 3 has not frozen them. If
no parity measurement completes in the round, report the exact mismatch and
mark the front-end acceptance unverified. This is a planning cap, not a
measured delivery estimate.

## Coordination points

- Stage 2 publishes the kernel call bindings and exact manifest before tracing
  examples are accepted.
- Stage 3 publishes canonical graph/plan goldens and refusal codes before
  Python/Rust parity is claimed.
- Keep the Hello Graph and dishonest-executor fixtures on the shared frozen
  identities. Do not create a Python-only wire shortcut.
- The sequencer remains its own A/B/C integration path. Coordinate only its
  public API needs and example adapter; do not duplicate the transport roadmap.
- Any shared contract change requires stages 2, 3, and 4 to update together
  and regenerate all affected golden corpora.
