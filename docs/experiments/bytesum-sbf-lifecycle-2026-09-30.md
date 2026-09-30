# ByteSum optimistic lifecycle on SBF (2026-09-30)

**Result: measured mechanics demonstration.** The `bytesum_sbf_lifecycle`
ProgramTest ran the feature-gated DCG SBF image. It completed an honest
resolution and rent-refund close, then caught a wrong claimed output, bisected
to one step, replayed that step through the compiled ByteSum kernel, settled
against the cheater, and closed the document. One malformed instruction was
refused at each stage (tags 240 through 250).

This is not evidence of useful model quality, faithful inference, or a
production graph/sweep protocol. The four-entry trace and tags are local test
mechanics.

## Reproduction

The image was built with `cargo-build-sbf 3.0.15`, platform-tools v1.51, and
rustc 1.84.1 from the pinned SDK root:

```sh
DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920 \
DCG_SBF_TOOLS_VERSION=v1.51 \
DCG_SBF_STAGING_NAME=dcg-extract-3-sbf-staging-final \
CARGO_TARGET_DIR=/private/tmp/dcg-extract-3-target \
crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-extract-3-sbf-final

SBF_OUT_DIR=/private/tmp/dcg-extract-3-sbf-final \
CARGO_TARGET_DIR=/private/tmp/dcg-extract-3-target \
cargo test --locked --profile fasttest -p dcg-program \
  --features sbf-lifecycle-test \
  --test bytesum_sbf_lifecycle -- --nocapture
```

The measured image was 792,056 bytes with SHA-256
`860a3cb1a97555ac1fcbd423cb3a0f6188e2bc9a2233c45c2e21fc92df098b5b`.
ProgramTest reported one passed test. CU values below are from
`BanksTransactionResultWithMetadata.compute_units_consumed`; every labeled
transaction had one DCG lifecycle instruction. The test uses deterministic
fixed-seed payer, challenger, and refund keypairs. Two consecutive runs
reported the same CU values below.

## Malformed input by stage

Each tag is intentionally malformed for its named instruction, and each
instruction refused it:

| Stage tag | Stage | CU |
| ---: | --- | ---: |
| 240 | Register template | 186 |
| 241 | Admit template | 187 |
| 242 | Initialize document | 186 |
| 243 | Land roots | 187 |
| 244 | Finalize | 188 |
| 245 | Resolve | 186 |
| 246 | Challenge | 187 |
| 247 | Bisect | 188 |
| 248 | Replay | 186 |
| 249 | Settle | 187 |
| 250 | Close | 188 |

## Honest lifecycle

| Instruction | CU |
| --- | ---: |
| Register template | 6,158 |
| Admit template | 2,378 |
| Initialize document | 16,038 |
| Land roots | 8,788 |
| Finalize | 7,321 |
| Resolve | 8,374 |
| Close and refund rent | 11,586 |

## Cheating lifecycle

| Instruction | CU |
| --- | ---: |
| Register template | 6,158 |
| Admit template | 2,378 |
| Initialize document with a wrong claimed output | 14,538 |
| Land roots | 5,788 |
| Finalize | 4,321 |
| Challenge | 4,438 |
| Bisect, round 0 | 2,726 |
| Bisect, round 1 | 2,698 |
| Replay disputed step | 5,052 |
| Settle against cheater | 5,719 |
| Close | 10,088 |

## What remains before Basanos switches over

This extraction changes only the standalone DCG repository. Basanos still
needs to depend on a reviewed DCG revision and supply adapters for its compiled
kernels, typed-decision route selector, and app-owned bond policy. Its existing
revision-8 paths need cross-implementation tests against the crate before
switch-over. Graph and sweep wire formats remain unspecified. Historical
Basanos HClosure fixtures are also absent here, so the optional
`legacy-basanos-fixtures` suite was not run.
