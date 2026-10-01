# DCG v2 stage 2 brief: kernel capabilities and single-source kernels

## Goal

Implement the frozen capability contract and the minimal `no_std` kernel
library. This stage proves the shared manifest can name exact typed callbacks
and that host and SBF handler executions agree on the vectors they consume.
It does not compile graphs, own plan bytes, trace Python, or claim useful-model
quality.

## Exact file ownership

The exact stage-2 file set agreed in the shared v2 contract is:

- `crates/dcg-program/src/kernel.rs` capability ABI and validation;
- new `crates/dcg-kernels/src/{lib.rs,add_i32.rs,identity_i32.rs}` and its
  manifest;
- new `crates/dcg-kernels/tests/vectors/` generator and output.

The shared spec/golden corpus and its Python reference codec are integration
gate inputs. Do not change them from this package alone. Do not edit graph
lowering, plan bytes, region lifecycle, Python names, or the tracer. A contract
change goes through all three packages together.

## Frozen inputs

- `docs/spec/kernel-capability-v2.md` v2.0-frozen: `DCKC/1`, `DCTV/1`, root
  domain, ordering, bounds, and refusal behavior.
- `docs/spec/graph-plan-v2.md` v2.0-frozen: graph/plan profile and exact
  profile-1 mode, scheme, and layout identities.
- `tests/golden/dcg/kernel_capability_v2/` and
  `tests/golden/dcg/graph_plan_v2/`.
- Kernel IDs and first-slice scope: checked stateless `add_i32/1` in the child
  region and `identity_i32/1` in the parent region.

Open registries in the capability spec remain open. A package must refuse an
unknown capability or account-role bit; it must not assign meanings to the
placeholder stable-error values in the codec fixture.

Stage 2 may launch in parallel with stages 3 and 4 as soon as DCG stage 1
releases capacity; the shared contract gate is frozen in this kickoff.

## First milestone

Register the two kernels in one static image; emit/validate its DCKC manifest;
execute the add and identity callbacks from the same portable `no_std` source
on host and through their actual SBF instruction handlers. Consume the checked-in
DCTV bytes. Add mechanically derived boundary and malformed-input cases only
when each expected output/refusal is established by the normative equation or
captured handler output.

## Acceptance tests

- Rust emits the exact checked-in DCKC bytes and manifest root; its test-vector
  reader consumes the exact DCTV envelope.
- `add_i32/1` returns canonical signed little-endian `i32` bytes and refuses
  signed overflow with the kernel's assigned stable code; `identity_i32/1`
  copies the canonical input exactly.
- Host and actual SBF handler agree byte-for-byte on outputs and kernel
  refusal codes for ordinary, range-edge, overflow, and malformed input cases.
  A wrong claimed output fails the registered optimistic replay check; stage 3
  owns the dispute ruling. Manifest validation rejects nonzero state/cursor
  fields for these stateless kernels, whose replay state bytes are empty.
- Unknown manifest version, capability, mode, scheme, or callback is refused
  before execution. DCKC alias rule `2` is refused while its paired-port ABI
  remains OPEN.
- Program handler behavior is tested through the SBF path; Python codec tests
  are not used as a substitute for handler execution.

The two first-slice kernels demonstrate mechanics only. They do not establish
model fidelity or broad kernel-library quality.

## Time-boxed first round and report

**First-round time box: estimated 5 engineer-days.** Stop the round at the
first host/SBF parity measurement or at the end of the time box, whichever
comes first. Report immediately after the first measurement with the exact
source/image, toolchain, vector IDs, outputs/refusals, measured CU if available,
remaining cases, and anything that could not run. If no SBF measurement is
available at the time-box boundary, report that as unverified; do not replace
it with a host-only pass. This is a planning cap, not a measured delivery
estimate.

## Coordination points

- Start only after shared integration gate 1 is acknowledged. Stages 3 and 4
  may proceed in parallel against these exact frozen files and goldens.
- Publish the static kernel registry and generated Rust vector bytes to stage 3
  before its first SVM lifecycle gate.
- Coordinate any new capability, error, account-role, or state-schema registry
  values with stage 3 and stage 4. If bytes or meanings change, issue a new
  shared version and update all three tracks together.
- Stage 3 calls only registered callbacks; stage 4 binds calls by the exact
  `(kernel_id, semantic_version, abi_version)` tuple.
