# durable-compute-graph

`durable-compute-graph` is the standalone repository for reusable commitment,
hashing, Merkle, and lifecycle protocol components. DCG is a general framework;
it does not include neural network kernels or a typed-decision producer.

## Licensing

Rust implementation code is GPL-3.0-only. Specifications and portable golden
vectors are MIT. The vendored `curve25519-dalek` source keeps its original
BSD 3-Clause license and attribution; see [NOTICE.md](NOTICE.md).

## Current extraction slice

This first local cut contains byte-identical copies of the generic SHA-256
module, the generic commit Merkle fold, their offline tests, the revision-8
portable golden TSVs, and the lifecycle property harness. Its focused SVM
processor implements PT1X creation (tag 140) and unpublished PT1X close
(tag 197), which are the handler-produced transitions in that harness.

It is not a replacement for Basanos's complete revision-8 program. The
revision-8 unified document and dispute handlers still mix reusable lifecycle
logic with Basanos machine/form registration, typed-decision validation,
execution hooks, and application bond policy. Those modules remain in Basanos
until the generic interfaces are split and the complete allowlist can be
tested here. The PT1X output, PT2S upload/seal, PT1O reserve/instantiate/close,
DEA2 admission, document, challenge, resolution, and settlement handlers have
not been copied. The portable revision-8 record vectors are present, but this
cut does not include the `DDT2`, `DRB1`, `DPD2`, `DCM2`, and `DCR2` codecs or
their record round-trip tests; their current implementations share the mixed
unified modules. Claim lifecycle, Tier C request/oracle programs, model
kernels, argmax and typed-decision producers are excluded by design.

The lifecycle harness's generated malformed operations exercise atomic refusal
and account safety for this cut. They do not validate the omitted document,
admission, challenge-response, settlement, or output-producer handlers.
The portable-golden check confirms the pinned file bytes and does not establish
codec equivalence for record types whose implementations remain in Basanos.

## Local checks

The default offline harness is:

```sh
cargo test --profile fasttest --all-targets
```

It requires only the checked-in vectors and Rust dependencies. The test
processor is not a deployable revision-8 replacement image.
