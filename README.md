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
model execution. The test image rejects legacy claim-dispute tags; the private
HClosure support modules still combine reusable tree/account helpers with old
handlers and remain a mixed area for a later extraction pass. The compiled
entrypoint does not dispatch those handlers.

Measured source inventory, using `wc -l` on the changed Rust files: 13,123
lines across `unified/`; 22,461 lines across the other changed program modules;
and 6,101 lines of tests. These counts include comments and inline tests. Of the
non-`unified` program count, 3,431 lines remain in the private mixed HClosure
support modules. The Basanos model kernels, argmax and typed-decision
producers, claim lifecycle, Tier C request programs, and bond policy remain in
Basanos. The generic escrow and transfer mechanics are in this crate.

The compatibility boundary is still incomplete in three places: the old
HClosure helpers and handlers share source files; v8 record/config modules
retain fixed application terms and class checks for byte compatibility; and
the decision route-selection hook returns `None` until an application links
its compiled selector. The standalone test image therefore refuses tags
120–124 and 126–129 and is not a replacement for Basanos's revision-8 image.

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

Measured on 2026-09-30: 87 tests passed with the command above.

Measured test image built with `cargo-build-sbf 3.0.15` and platform-tools
v1.53: 684,984 bytes, SHA-256
`8350fa2dda93734f4212c9dc3424b7e2a7a1f40804ac400e6216a1d6f1cc0416`. This is
the standalone DCG core plus `ByteSum`; it does not reproduce the Basanos
revision-8 image. The portable v8 TSV contents match the Basanos copies
byte-for-byte.

Rust implementation code is GPL-3.0-only. Specifications and portable goldens
are MIT. The vendored `curve25519-dalek` source keeps its original BSD 3-Clause
license and attribution; see [NOTICE.md](NOTICE.md).
