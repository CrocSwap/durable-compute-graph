# ByteSum optimistic lifecycle on SBF (2026-09-30)

## Round 5: real revision-8 handlers

**Result: measured mechanics demonstration.** A ProgramTest bank executed the
standalone DCG SBF image through real revision-8 registry/admission, document,
challenge, replay, settlement, resolve, and close instructions. The disputed
Form-256 fix-point ran through the image's static application manifest and
ByteSum kernel with authenticated account spans. The SBF ELF was 751,280 bytes,
built by the pinned cargo-build-sbf 3.0.15 / platform-tools v1.51 wrapper;
its SHA-256 was
80cbc43ba99da10cabf071fa4d6769b546dad73f8431f7bcce9a32a2e6fad2bf.

The test image uses the sbf-real-lifecycle-test feature. It adds a test-only
machine selector 1 / Form 256 manifest binding at semantic version 1, ABI
version 1, optimistic mode 1. The binding reads three zero bytes at PT2S
offset 184 and eight zero bytes at geometry offset 9 through authenticated,
read-only spans. Existing revision-8 instruction bytes and retained fixtures
were not changed. The default image does not include this Form-256 binding.

The transaction driver was a temporary copy of Basanos's existing
unified_v8_document ProgramTest harness with retained fixtures. It loaded the
standalone ELF through BPF_OUT_DIR; the direct DCG calls were executed by SBF
in ProgramTest, not by the native Rust processor. The K=10,240 test built the
PT2P/PT2S fixture using tags 140–145, then reached registry/admission tags
156–160 and template seal 176 before continuing through document tags 161,
162, 165, 177, 178, and close tag 172. A separate K=80 challenge path used
tags 167, 163, 164, 168, and 169 to reach a ByteSum fix-point replay. The
executor then timed out at tag 132, was settled by tag 131 under the standard
bond policy, and the document was closed with tag 172. The successful tag-169
replay admitted the honest ByteSum output.

The inherited broad K=10,240 test first stopped at tag 150, an envelope
instruction not implemented by the extracted DCG image. The focused temporary
driver omitted that Basanos-only envelope step and exercised the following DCG
admission and lifecycle instructions directly. The standalone image therefore
has not demonstrated Basanos envelope handling. The test driver was kept
outside both source repositories; the actual Basanos checkout was not changed.

### Measured SBF compute units

Values are from ProgramTest's BanksTransactionResultWithMetadata and the
per-instruction CU logs. PT2P/PT2S setup handlers may be called many times;
counts and ranges below describe the K=10,240 focused run.

| Tag | Stage | Calls | CU per call |
| ---: | --- | ---: | ---: |
| 140 | PT2P base init | 1 | 628,620 |
| 141 | PT2P base upload | 9,336 | 966–1,137 |
| 142 | PT2P base seal | 1,930 | 1,586–418,641 |
| 143 | PT2S init | 2 | 1,114–5,404 |
| 144 | PT2S hash | 757 | 1,370–1,194,743 |
| 145 | PT2S seal | 2 | 1,561–496,390 |
| 156 | Registry initialize | 1 | 8,730 |
| 157 | Registry row chunk | 29 | 4,377–4,388 |
| 158 | Registry seal | 1 | 5,446 |
| 159 | Template admission check | 1 | 28,463 |
| 160 | Template admission step | 1,801 | 51,930–719,610 |
| 176 | Template seal | 1 | 27,368 |

| Tag | K=10,240 honest lifecycle stage | CU |
| ---: | --- | ---: |
| 161 | Document init | 306,271 |
| 162 | Land roots | 24,462 |
| 165 | Finalize | 10,822 |
| 177 | Attest output | 36,900 |
| 178 | Resolve final result | 5,773 |
| 172 | Close and refund rent | 13,404 |

The separate K=80 challenge/cheat path measured 145,926 CU for tag 161,
20,250–21,703 for four tag-162 root chunks, 92,761 for tag 163, 23,837 for tag
164, 8,615 for tag 168, and 32,693 for the successful tag-169 ByteSum replay.
Making the geometry account writable caused tag 169 to refuse the wrong role
(30,788 CU; program error 731). The subsequent correct-role replay succeeded.
The executor timeout, standard settlement, and close used 15,023 CU (tag 132),
20,819 CU (tag 131), and 13,234 CU (tag 172), respectively.

| Tag | K=80 challenge path stage | CU |
| ---: | --- | ---: |
| 167 | Open position challenge | 20,481 |
| 163 | Reveal position | 92,761 |
| 164 | Select segment | 23,837 |
| 168 | Reveal segment | 8,615 |
| 169 | Descend to fix-point and replay via ByteSum manifest | 32,693 |
| 132 | Timeout against silent executor | 15,023 |
| 131 | Standard bond settlement | 20,819 |
| 172 | Close and refund rent | 13,234 |

### Adversarial controls and test counts

- Wrong root: tag 162 refused the wrong root in 10,556 CU.
- Late challenge: tag 167 refused after the production deadline in 12,688 CU.
  Separate phase/role challenge controls also refused.
- Wrong manifest/account identity: host manifest tests refused an unknown
  kernel ID and wrong semantic/ABI version; host span tests refused wrong
  account roles and overlapping aliases. These compile-time/host checks have
  no SBF CU measurement. The writable-geometry role refusal above was an SBF
  instruction-level control.
- Focused host tests passed 3 kernel tests and 3 kernel-SVM span tests with
  sbf-real-lifecycle-test enabled.
- Ten isolated ProgramTest cases passed against the SBF image: seven existing
  revision-8 cases and three temporary focused tests for K=10,240 admission,
  K=10,240 resolve/close, and the ByteSum timeout/settlement path.

The full offline suite and live network services were not run. These are
execution and account-mechanics results only. They do not demonstrate useful
model quality, faithful inference, or production deployment. The input stream,
engine-state accounts, views, and session close remain open stateful features.

For reproduction, use the pinned SBF build command below with feature
sbf-real-lifecycle-test. The retained-fixture ProgramTest source was a
temporary harness copy and is not part of this repository; it must be supplied
from a Basanos checkout with the retained K=80 or K=10,240 fixture. The build
ELF digest and raw CU logs were retained in the dcg-extract-5 run receipts.

The standalone image build for round 5 is:

```sh
export DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-extract-5-sbf-staging
export CARGO_TARGET_DIR=/private/tmp/dcg-extract-5-target

crates/dcg-program/scripts/build-sbf-reproducible.sh --features sbf-real-lifecycle-test --sbf-out-dir /private/tmp/dcg-extract-5-sbf
```

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
