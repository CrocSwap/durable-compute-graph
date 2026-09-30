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

For a first-hour path through the kernel contract, app manifest, authenticated
account spans, and the extracted revision-8 handler tests, see
[`docs/getting-started.md`](docs/getting-started.md). The separate
`bytesum_sbf_lifecycle` target is an isolated canary, not the revision-8
lifecycle.

## Kernel contract: what a developer implements

Each application defines a static `ApplicationManifest` whose kernel entries
implement `Kernel`. A kernel manifest declares:

1. a stable `KernelId`, semantic version, and independent ABI version;
2. versioned input/output layouts, optional state schema, and resource limits;
3. the versioned `ModeId` values the application enables for that kernel.

`Kernel::execute` accepts authenticated canonical bytes and writes canonical
output bytes. Stateful kernels may additionally implement `StatefulKernel`;
optimistically replayable kernels may implement `OptimisticReplay`. An
application can bind an old revision-8 form row to an exact kernel semantic
version, ABI version, and mode in its static manifest. At the challenge
fix-point, the SVM adapter checks account identity, owner, signer/writable
roles, schema, region bounds, and aliases before it forms the kernel's span
view. A byte-only kernel such as `ByteSum` continues to use its single-slice
method. No revision-8 instruction or document bytes change.

The application separately supplies a `ResolutionBackend` that owns
admission, challenge transitions, and resolution status. Commitment-scheme
versions are independent of kernel, ABI, and mode versions. The core has no
dynamic loading path; `AccountInfo` is confined to the SVM adapter.

The included `ByteSum` test kernel exercises the compiled manifest and
authenticated-span replay in focused tests. The optional
`sbf-real-lifecycle-test` feature adds a test-only Form-256 binding and a
small stateful counter app. Its ProgramTest targets run against the feature
SBF image; they are mechanics tests, not model-capability demonstrations. The
feature must not be used for a production image.

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
