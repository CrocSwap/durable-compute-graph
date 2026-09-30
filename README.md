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

For a first-hour path through the kernel contract, manifest, SBF build, and
lifecycle canary, see [`docs/getting-started.md`](docs/getting-started.md).

## Kernel contract: what a developer implements

Each application defines a static `ApplicationManifest` whose kernel entries
implement `Kernel`. A kernel manifest declares:

1. a stable `KernelId`, semantic version, and independent ABI version;
2. versioned input/output layouts, optional state schema, and resource limits;
3. the versioned `ModeId` values the application enables for that kernel.

`Kernel::execute` accepts authenticated canonical bytes and writes canonical
output bytes. Stateful kernels may additionally implement `StatefulKernel`;
optimistically replayable kernels may implement `OptimisticReplay`. The
application separately supplies a `ResolutionBackend` that owns admission,
challenge transitions, and resolution status. Commitment-scheme versions are
independent of kernel, ABI, and mode versions. The core performs exact static
registry lookup and has no dynamic loading path or `AccountInfo` in its byte
contract.

The included `ByteSum` test kernel exercises the compiled manifest, byte
execution, SHA-256 commitment, and an optimistic lifecycle backend in the
lifecycle harness. It is a seam test, not a model-capability demonstration.

## Checks and standalone SBF image

Run the offline suite with:

```sh
cargo test --locked --profile fasttest --all-targets
```

The suite includes the lifecycle property harness and ported v8 record,
resolve-check, and bond tests. Tests gated by the optional
`legacy-basanos-fixtures` feature require historical Basanos v7/rung-D fixtures
that are not included here.

Measured on 2026-09-30: 87 tests passed with the default command above. The
SBF-only lifecycle canary is a separate ProgramTest invocation and passed one
test; its measured CU by instruction and image identity are in
[`docs/experiments/bytesum-sbf-lifecycle-2026-09-30.md`](docs/experiments/bytesum-sbf-lifecycle-2026-09-30.md).

Measured lifecycle test image built with `cargo-build-sbf 3.0.15` and
platform-tools v1.51: 792,056 bytes, SHA-256
`860a3cb1a97555ac1fcbd423cb3a0f6188e2bc9a2233c45c2e21fc92df098b5b`. This is
the standalone DCG test image with `ByteSum` and a feature-gated lifecycle
canary; it does not reproduce the Basanos revision-8 image. The portable v8
TSV contents match the Basanos copies byte-for-byte.

Rust implementation code is GPL-3.0-only. Specifications and portable goldens
are MIT. The vendored `curve25519-dalek` source keeps its original BSD 3-Clause
license and attribution; see [NOTICE.md](NOTICE.md).
