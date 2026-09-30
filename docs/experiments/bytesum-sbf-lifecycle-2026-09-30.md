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

## Round 4 extraction attempt (2026-09-30)

**The real revision-8 SBF lifecycle remains open.** The round-4 app-dispatch
and account-span code has native unit coverage, but this attempt did not
produce the requested honest and cheating documents through the real
revision-8 handlers. The existing real-handler `unified_v8_bond` ProgramTest
uses five small native settlement programs under fixture-only names. A trial
with `prefer_bpf(true)` loaded `dcg_program.so`, then stopped before test
execution because ProgramTest looked for `settler_honest.so` and reported
`Program file data not available for settler_honest`. No SBF lifecycle CU is
claimed from that attempt.

The separate `bytesum_sbf_lifecycle` canary remains behind the
`sbf-lifecycle-test` feature and still passes on the round-4 SBF image. This is
a repeat of the bespoke tags 240–250 mechanics demonstration, not evidence
that the app manifest is reached by a real revision-8 challenge. Its measured
SBF image SHA-256 was
`af45c579cb18a763b5e33e3edc5c63bc104e3553647accbf4939601a04b48a6e`. The
reproduction command is the one above with `dcg-extract-4` substituted for
`dcg-extract-3` in the target, staging, and output paths.

| Instruction | Round 3 CU | Round 4 canary CU | Change |
| --- | ---: | ---: | ---: |
| Malformed tag 240–250, each | 186–188 | 188–190 | +2 each |
| Register template | 6,158 | 6,489 | +331 |
| Admit template | 2,378 | 2,380 | +2 |
| Initialize honest document | 16,038 | 16,040 | +2 |
| Land honest roots | 8,788 | 8,790 | +2 |
| Finalize honest document | 7,321 | 7,323 | +2 |
| Honest resolve | 8,374 | 8,376 | +2 |
| Honest close and refund | 11,586 | 11,588 | +2 |
| Initialize cheating document | 14,538 | 14,540 | +2 |
| Land cheating roots | 5,788 | 5,790 | +2 |
| Finalize cheating document | 4,321 | 4,323 | +2 |
| Challenge | 4,438 | 4,440 | +2 |
| Bisect, round 0 | 2,726 | 2,728 | +2 |
| Bisect, round 1 | 2,698 | 2,700 | +2 |
| Replay disputed step | 5,052 | 5,054 | +2 |
| Settle against cheater | 5,719 | 5,721 | +2 |
| Cheating close | 10,088 | 10,090 | +2 |

The 11 malformed CU values in order were 188, 189, 188, 189, 190, 188, 189,
190, 188, 189, and 190. The round-4 canary retest passed 1/1. These are
measured mechanics values from the canary image; they do not estimate the CU
cost of the app-manifest replay path.

The remaining stateful design includes the input stream, engine-state
accounts, views, and session close. No wire format was introduced for these
features.
