# Stateful workload SBF mechanics (2026-09-30)

**Result: measured mechanics demonstration.** One local ProgramTest case ran the
versioned stateful adapter from the actual `dcg_program.so` SBF image. The
statically linked counter kernel advanced indexed and append inputs, wrote two
split state spans, published two output views from one cursor, explicitly
anchored inputs and state, halted, and refunded every created account. The
program contains no Doom adapter. This measures account and transaction
mechanics only.

The image was built with `build-sbf-reproducible.sh`, cargo-build-sbf 3.0.15,
and platform-tools v1.51, feature `sbf-real-lifecycle-test`. Its measured
length is 826,352 bytes and SHA-256 is
`17d3e01c9af69fa8b2b8e8b724bdbe1565e327166b4e2a945de77497c4e22353`. CU values
come from ProgramTest's transaction metadata; they include the complete SBF
instruction, including System Program account creation where applicable.

## Measured compute units

| Tag | Operation | Successful CU | Refusal controls (CU) |
| ---: | --- | ---: | --- |
| 230 | Open session | indexed 7,594; append 7,588 | operation limit 1,155 |
| 231 | Create input stream | indexed 24,343; append 9,343 | — |
| 232 | Create two state spans | indexed 15,207; append 24,207 | — |
| 233 | Declare two views and scratch | 6,501; 6,505; 9,432 | — |
| 234 | Write an indexed/append command | 1,973–1,976 | duplicate 1,590; append gap 1,543; wrong writer 1,272 |
| 235 | Advance | three indexed steps 5,001; two append steps 4,701 | stale cursor 1,574; wrong authority 1,560; alias 2,022 |
| 236 | Publish both views | 4,339 | stale view cursor 1,704 |
| 237 | Halt session | 1,414 | — |
| 238 | Close child/session | child 1,901–1,923; session 1,198 | live close 1,308; wrong refund 1,316 |
| 239 | Explicit input/state anchor | 4,598 | — |

The values are measurements for this small test kernel and this SBF toolchain.
The 80,000-CU per-transition manifest ceiling and 1.4M transaction ceiling
are designed bounds, not measured cost claims. Normal ADVANCE performed no
stream/state commitment hashing; the explicit ANCHOR did.

## Verification

The stateful ProgramTest passed 1 test with 41 logged SBF instructions. It
checked state values, both published views, cursor binding, all-or-nothing
refusal behavior, and authority refunds. Its controls cover invalid resource
declarations, duplicate input slots, stale and unauthorized advance, aliased
state accounts, wrong append sequence/writer, stale view cursor, close while
live, and wrong refund authority.

The focused `kernel`/`kernel_svm` host target passed 7 manifest and span tests,
including refusal of a compute declaration above the designed ceiling.
`cargo fmt --all -- --check` also passed.

The retained revision-8 ProgramTest target compiled and four focused SBF
cases passed: the K=80 position challenge to an admitted ByteSum fixpoint, the
K=80 timeout/settlement/close path, K=10,240 PT1X registry/admission, and
K=10,240 real admission through resolve and rent close. These cases execute
revision-8 instructions from the final SBF image; they do not change the
revision-8 records or goldens. The `rev8_pt1x_` filter also selected the
broader optional `rev8_pt1x_full_honest_path_reaches_challenge_ruling` test,
which returned `needs_local_artifacts` because `BASANOS_PT1X_FULL_E2E` was not
set. The copied test's typed-decision fixture builder uses a checked-in
host-only LUT fixture and is not linked into the program image.

Commands used (with the build output and retained artifact roots set as in the
getting-started guide):

```sh
cargo fmt --all -- --check
CARGO_TARGET_DIR=/private/tmp/dcg-stateful-1-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test unified_v8_document --no-run
SBF_OUT_DIR=/private/tmp/dcg-stateful-1-sbf \
CARGO_TARGET_DIR=/private/tmp/dcg-stateful-1-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test stateful_sbf_workload -- --nocapture
```

Raw local receipts are under
`out/runs/dcg-stateful-1-2026-09-30/` in the Basanos workspace. No validator,
live service, network test, or full offline suite was run. The warm-target
helper found no cached target for this standalone clone; the cold target
peaked at 1.7 GB, below the 5 GB limit.
