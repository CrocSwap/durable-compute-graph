# durable-compute-graph

`durable-compute-graph` is a standalone Rust/SVM home for reusable byte
commitments, records, and optimistic-resolution mechanics. This repository
contains no neural model implementation, typed-decision producer, or graph or
sweep wire format.

## Extraction status

The current cut carries the revision-8 lifecycle mechanics and their SVM
account adapters:

- canonical record codecs and portable v8 vectors;
- registry admission, document initialization, root landing, finalization,
  challenge descent, response verification, and result resolution;
- bond escrow, settlement, retry, document/result close, and rent refunds;
- PT1/PT2 upload and seal mechanics, SHA-256/Merkle support, and bounded
  response storage.

The 37 historical machine/form rows are retained as metadata in
[`compatibility.rs`](crates/dcg-program/src/compatibility.rs). The profile
adapter preserves the existing form limits and wire checks, but does not link
model execution. HClosure tree commitments now live in
[`closure_v2_tree.rs`](crates/dcg-program/src/closure_v2_tree.rs), while account
and PDA helpers live in
[`closure_v2_accounts.rs`](crates/dcg-program/src/closure_v2_accounts.rs).
Legacy HClosure handlers compile only with the non-default
`legacy-hclosure-handlers` feature; the default entrypoint does not dispatch
them.

Measured current source inventory, using `wc -l` on Rust files: 13,071 lines
under `unified/`; 23,689 under the other program source modules; and 6,539 in
tests. These counts include comments and inline tests. The Basanos model
kernels, argmax and typed-decision producers, claim lifecycle, Tier C request
programs, and bond policy remain in Basanos. The generic escrow and transfer
mechanics are in this crate.

Revision-8 terms, template limits, and registry-class admission now go through
the `ApplicationHooks` interface. The default
[`Revision8CompatibilityAdapter`](crates/dcg-program/src/compatibility.rs)
preserves the existing checks and encodings. PT2P route selection has an
explicit `DecisionRouteSelector` app seam; the standalone default selector
returns `None` because no typed-decision producer is linked. The default test
image therefore refuses tags 120–124 and 126–129 and is not a replacement for
Basanos's revision-8 image.

For a first-hour path through the kernel contract, app manifest, replay witness,
and the extracted revision-8 handler tests, see
[`docs/getting-started.md`](docs/getting-started.md). The separate
`bytesum_sbf_lifecycle` target is an isolated canary, not the revision-8
lifecycle.

## Application instruction seam

Application crates can add statically linked instruction handlers through
[`dcg_program::app_api`](crates/dcg-program/src/app_api.rs). A const-validated
`ApplicationProgramManifest` pairs the existing kernel/form manifest with a
tag-sorted table of handler ids, semantic versions, preflight callbacks, and
handlers. `process_instruction_with_application` sends the revision-8 core tag
set through DCG first, then checks the application table, and rejects
everything else. Tag 125 stays DCG-owned; the application dispute/replay tags
are the non-core members of 120–129.

Each app instruction declares a static rule for every ordered account.
`process_instruction_with_application` validates the key or PDA derivation,
owner, account shape, roles, and writable aliases before calling preflight;
the handler then receives the ordered account view only after preflight passes.
The app-manifest digest commits the app identity, its form-to-kernel admission
identity, canonical `(tag, handler id, handler version)` rows, and account
rules.

Pure region-content folds are available from
[`dcg_program::region_commitment`](crates/dcg-program/src/region_commitment.rs).
They preserve Basanos's v1 domain and little-endian encoding; the shared
`region_content_v1.tsv` vectors live under `tests/golden/dcg/lifecycle/`.
The DRS1 record and tags 14–15 remain outside this small commitment module.
See [`docs/application-api.md`](docs/application-api.md) for the exact public
surface and callback contract.

## Kernel contract: what a developer implements

Each application defines a static `ApplicationManifest` whose kernel entries
implement `Kernel`. A kernel manifest declares:

1. a stable `KernelId`, semantic version, and independent ABI version;
2. versioned input/output layouts, optional state schema, and resource limits;
3. the versioned `ModeId` values the application enables for that kernel.

Declare the manifest with `KernelDecl` and check the kernel against its Python
mirror with the kernel kit ([`docs/kernel-kit.md`](docs/kernel-kit.md)).

`Kernel::execute` accepts authenticated canonical bytes and writes canonical
output bytes. Stateful kernels may additionally implement `StatefulKernel`;
optimistically replayable kernels may implement `OptimisticReplay`. An
application binds an old revision-8 form row to an exact kernel semantic
version, ABI version, and mode in its static manifest. Required form bindings
are checked during class admission; a missing mapping refuses with code 799.
The app supplies `ApplicationHooks` and a `DecisionRouteSelector` through
separate manifest fields; revision-8 policy uses the hooks, and tags 146, 199,
and 200 use the app's selector.

For a bound form, the committed ROOT_ONLY leaf is an `app-replay-leaf/2`
digest over the descriptor, exact `(position, segment, local)` coordinate,
app/kernel/mode identity, and canonical `ARW1` witness. The witness contains
the coordinate's versioned input slices and claimed output. Tags 166, 168, and
169 carry it to the fix-point. An app-bound fix-point that is not convicted
immediately remains in RESPOND until the executor opens the committed leaf
through tags 183 and 184. A mismatched claimed output rules against the
executor with code 800. Committed inputs the selected kernel cannot replay
rule against the executor with code 799. A successful replay rules for the
executor. For a routed input, descend to the first divergent leaf: if a
consumer correctly used a fabricated producer output, the consumer wins and
the producer is the challenge target. A binding may select one plan read even
when the instance has other reads. Those other reads are not authenticated as
inputs to this kernel replay; challenging their producers does not verify how
this consumer used them. A zero-span binding at an instance with plan reads
must opt in through `accepts_empty_input_spans()`; the application then declares
that replay accepts no opened plan input there. Admission rejects unsupported
producer provenance and any opening that cannot fit the bounded witness.
App-bound documents record an `ARI1` manifest identity; a changed saved
identity, or a saved identity with no current manifest, ends the challenge
neutrally even if the current image removed the form binding. Without a saved
identity, neutrality applies only when the current image still binds the
coordinate. The app path uses
DCR1 version 6 while it is in RESPOND; the version-5 compatibility record
remains unchanged when no app binding is selected.

The application separately supplies a `ResolutionBackend` that owns
admission, challenge transitions, and resolution status. Commitment-scheme
versions are independent of kernel, ABI, and mode versions. The core has no
dynamic loading path; `AccountInfo` is confined to the SVM adapter.

The included `ByteSum` test kernel exercises manifest validation, bounded
`ARW1` parsing, and committed-input replay in focused tests. The optional
`sbf-real-lifecycle-test` feature adds a test-only Form-256 binding and a
small stateful counter app. Its ProgramTest targets run against the feature
SBF image; they are mechanics tests, not model-capability demonstrations. The
feature must not be used for a production image.

The separate `sbf-unbound-form-test` image contains one sentinel mapping and
uses the same revision-8 driver to verify that an unbound registry form refuses
at admission tag 160 with code 799.

## Stateful workloads

The versioned local prototype in
[`docs/stateful-workloads-v1.md`](docs/stateful-workloads-v1.md) adds a
session-owned indexed/append input stream, schema-bound state spans, output
views and scratch spans, explicit optional anchors, bounded step resources,
and authority-directed account close. The adapter supports split state without
serializing runtime pointers. Tags 230–239 are only dispatched by the
feature-built test application; the default revision-8 entrypoint and goldens
are unchanged.

The SBF counter test advances multiple one-byte commands per transaction,
publishes two outputs from one state cursor, exercises refusal atomicity, and
closes all session accounts with rent refunds. The real revision-8
ProgramTest driver, including the round-5 patch, is also retained in the
repository behind `sbf-real-lifecycle-test`; reproducing its retained K=80
and K=10,240 cases still needs the documented local compiler-v1 artifacts.

## Checks and standalone SBF image

Run the offline suite with:

```sh
cargo test --locked --profile fasttest --all-targets
```

The suite includes the lifecycle property harness and ported v8 record,
resolve-check, and bond tests. Tests gated by the optional
`legacy-basanos-fixtures` feature require historical Basanos v7/rung-D fixtures
that are not included here.

Measured before the app-dispatch change on 2026-09-30: 87 tests passed with the
default command above. The SBF-only lifecycle canary is a separate ProgramTest
invocation and passed one test; its measured CU by instruction and image identity are in
[`docs/experiments/bytesum-sbf-lifecycle-2026-09-30.md`](docs/experiments/bytesum-sbf-lifecycle-2026-09-30.md).

The canary uses bespoke test-only tags 240–250 and its own compact account
layout. It does not exercise registry/admission, document init/roots/finalize,
attest/resolve, challenge descent, or the extracted close handlers. Round 5
also ran those real revision-8 stages against the standalone SBF image with
ByteSum replay through the feature-gated Form-256 manifest binding. Its
retained-fixture ProgramTest source and harness patch are now permanent
feature-gated targets in this repository. The fixtures remain local inputs.
The exact tags, CU measurements, image digest, test counts, and artifact
requirements are recorded in the experiment note linked above.

The earlier canary image, built with `cargo-build-sbf 3.0.15` and platform-tools
v1.51, was 792,056 bytes with SHA-256
`860a3cb1a97555ac1fcbd423cb3a0f6188e2bc9a2233c45c2e21fc92df098b5b`. This is
the standalone DCG test image with `ByteSum` and a feature-gated lifecycle
canary; it does not reproduce the Basanos revision-8 image. The portable v8
TSV contents match the Basanos copies byte-for-byte.

Rust implementation code is GPL-3.0-only. Specifications and portable goldens
are MIT. The vendored `curve25519-dalek` source keeps its original BSD 3-Clause
license and attribution; see [NOTICE.md](NOTICE.md).
