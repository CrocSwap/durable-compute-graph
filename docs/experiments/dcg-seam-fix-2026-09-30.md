# Coordinate-bound optimistic replay seam (2026-09-30)

## Result

**Measured mechanics demonstration.** The revision-8 ProgramTest driver ran the
standalone DCG SBF image and exercised the app-bound replay path through the
real challenge handlers. The test app was the statically linked ByteSum
manifest. These runs demonstrate dispute-record mechanics for a tiny byte
kernel; they do not establish useful model quality, faithful inference, or
production behavior.

The replay preimage is a bounded `ARW1` witness: version, span count, claimed
output length, then versioned input slices and exactly that many output bytes.
Its digest commits to the document descriptor, exact `(position, segment,
local)` coordinate, application/kernel/mode/form identity, and full witness
under `app-replay-leaf/1`. The digest is the ROOT_ONLY leaf opened through the
document's segment and position proofs. At the fix-point, the challenge handler
recomputes that digest against DCR1 `raw[104..136]`, parses the opened witness,
selects the statically bound kernel, and replays the committed input. No
template-account byte range is used as a substitute for the committed input.

The ruling rule is deterministic: if the challenger preimage does not open the
committed leaf, the challenger loses with proof code 734. If the committed
input is malformed or the selected kernel cannot replay it, the executor loses
with code 799. If replay succeeds but its output differs from the committed
claimed output, the executor loses with code 800. A form required to have an
app binding is rejected earlier at admission tag 160 with code 799.

App-replay rulings use DCR1 version 6 and carry an `ARI1` block after the DEV2
area. It fills bytes 7104 through 7167, including the old path-length byte;
version 6 is written only at the terminal fix-point after the path is no
longer needed. The block includes the application-manifest digest, kernel ID
and semantic/ABI versions, replay mode, and form. DCR1 version 5 bytes remain
the compatibility record when no app binding is selected.

## SBF images

Both images were built by `build-sbf-reproducible.sh` with
`cargo-build-sbf 3.0.15`, platform-tools v1.51, and the pinned SDK at
`/private/tmp/basanos-sbf-sdk-v151-20260920`.

| Image | Feature | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Replay lifecycle | `sbf-real-lifecycle-test` | 829,984 | `b7c4c000fdc326ba3937a322de8810fc38d63c4e041768532096c11a07e99915` |
| Unbound admission | `sbf-unbound-form-test` | 829,912 | `bd52992313cf2b99de1efd14fbe8e99e9d6382dabf37e9285d4da12c720931f4` |

The K=80 ProgramTest fixture used the retained compiler-v1 PT2P bundle at
`out/runs/dcg-pt2-parametric-window-routes-20260923/pt2p`. The unbound image
uses a valid sentinel binding for Form 65,535 while requiring a binding for
every selected form.

## Measured ProgramTest results

CU figures are `BanksTransactionResultWithMetadata.compute_units_consumed`
from the SBF ProgramTest runs, with the test's Compute Budget instruction
included. The image identity above was printed by each run.

| Scenario | Tag | CU | Ruling observed |
| --- | ---: | ---: | --- |
| Honest replay | 169 | 43,677 | Challenger loses; winner 1, code 0 |
| Malicious challenger against honest committed output | 169 | 41,800 | Challenger loses; winner 1, proof code 734 |
| Wrong committed ByteSum output | 169 | 40,703 | Executor loses; winner 2, code 800 |
| Wrong-output standard bond settlement | 131 | 13,339 | Settlement succeeds against executor |
| Refuted document close | 172 | 13,276 | Close succeeds after settlement |
| Malformed committed input schema | 169 | 46,563 | Executor loses; winner 2, code 799 |
| Required but unbound form | 160 | 24,021 | Admission refuses with code 799 |

The wrong-output, malicious-challenger, and malformed-input tests passed
against the replay lifecycle SBF image (3 passed). The honest-replay test
passed separately (1 passed). The unbound-form test passed against its
sentinel-only SBF image (1 passed). Across the runs, the exact tags exercised
were 131, 145, 156, 157, 158, 160, 161, 162, 163, 164, 165, 167, 168, 169,
172, and 176. Tag 131 settled the wrong-output ruling; tag 172 closed the
refuted document; tag 160 refused the required but unbound form.

## Other focused checks

- `cargo fmt --all -- --check` passed.
- The focused kernel unit tests passed with both lifecycle and unbound
  manifests, including `ApplicationManifest::validate()` and form-admission
  assertions.
- The admission refusal unit test and all three kernel-SVM span checks passed.
- The golden files `unified_v7.json`, `closure_v2_real_rev7.json`, and
  `root_only_real_rev7.json` were compared byte-for-byte with the Basanos test
  fixtures; they match.

The full offline suite and live chain, audit-box, and network checks were not
run. All chain-like execution was local ProgramTest only.

## Reproduction outline

```sh
export DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920
export DCG_SBF_TOOLS_VERSION=v1.51
export CARGO_TARGET_DIR=/private/tmp/basanos-dcg-seam-fix-target

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-seam-fix-sbf

BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-seam-fix-sbf \
  BASANOS_PT2P_ROOT=/path/to/retained/k80/pt2p \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test unified_v8_document \
    rev8_bytesum_ -- --nocapture --test-threads=1

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-unbound-form-test \
  --sbf-out-dir /private/tmp/dcg-seam-fix-unbound-sbf

BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-seam-fix-unbound-sbf \
  BASANOS_PT2P_ROOT=/path/to/retained/k80/pt2p \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-unbound-form-test --test unified_v8_document \
    rev8_unbound_form_refuses_admission_on_sbf -- --nocapture --test-threads=1
```

## Round 2 retest: executor opens through RESPOND

This section supersedes the ruling rules and ProgramTest measurements above;
those figures describe the previous challenger-only replay path.

The challenger witness is now an optional fast path. A matching, route-valid
opening that demonstrates a wrong output convicts the executor immediately
(800). A missing, mismatching, malformed, or route-unproven fast-path opening
leaves the fix-point in RESPOND. The executor uploads the preimage in ordered
tag-183 chunks and tag 184 checks its coordinate-bound digest, DCR1 v6 app
identity, predecessor route opening, and the selected kernel replay. An
incomplete or non-matching response is refused (730), so the executor must
provide the correct opening before timeout. A digest-matching decode/kernel
failure or input that differs from the proved predecessor output convicts the
executor (799); a matching successful replay rules for the executor.

The route adapter currently supports one declared input route whose producer
is earlier in the same position and segment. Its RWP1 path proves the
producer's ARW1 output leaf into the saved segment root and compares the exact
route slice with the consumer input. Unsupported provenance and malformed
route paths are neutral refusals (730). Cross-position, cross-segment, and
document-input route adapters remain open.

`ApplicationManifest::validate()` now checks the declared per-kernel CU ceiling
and route bindings during every admission step. The reproducible SBF wrapper
also runs a host test of the exact feature-selected static application
manifest before linking the SBF image, including `EMPTY_APPLICATION`. The
declared ceiling is designed to be at most 1.4 million CU per kernel; this is a
manifest bound, not a measured proof of every kernel's worst-case runtime.

### Measured SBF images and ProgramTest results

Images were built with cargo-build-sbf 3.0.15, platform-tools v1.51, and the
pinned SDK at `/private/tmp/basanos-sbf-sdk-v151-20260920`. CU totals include
the test's Compute Budget instruction.

| Image | Features | Size (bytes) | SHA-256 |
| --- | --- | ---: | --- |
| Replay lifecycle | `sbf-real-lifecycle-test` | 863,744 | `ceb685a5b2aa11b7259efcb7959e4adf1287f080c9c889119811c3b5586054fd` |
| Empty compatibility | `revision-8` | 786,376 | `5cf11c2552613627f5fd1ae9d67ba8feaa9775334f4d5f656dcd27c81dae96e6` |
| Unbound admission | `sbf-unbound-form-test` | 863,672 | `28b1ef2d8848bda11fb3dde0175a5c08c33357e376e3da3003b0e2cc680316ed` |

| Scenario | Tags | Measured payload sizes | Measured CU / result |
| --- | --- | --- | --- |
| Wrong-output optional fast path | 169 | 635 bytes | 218,143; executor loses with 800 |
| Matching honest fast path | 169, 183, 184 | tag 169: 635 bytes; 405 + 238 byte stage instructions; 633-byte witness total | tag 169: 220,672 enters RESPOND; tag 184: 79,792, executor wins |
| Honest executor defeats non-matching malicious challenger | 169, 183, 184 | tag 169: 635 bytes; 405 + 238 byte stage instructions; 633-byte witness total | tag 169: 170,293 enters RESPOND; tag 184: 64,792, executor wins |
| Fake `[4,5,6]` input with its correct sum against proved `[1,2,3]` predecessor bytes | 169, 183, 184 | 405 + 238 byte stage instructions; 633-byte witness total | tag 169: 172,550 enters RESPOND; tag 184: 70,468; executor loses with 799 |
| Schema-invalid committed input | 169, 183, 184 | tag 169: 635 bytes; 405 + 238 byte stage instructions; 633-byte witness total | tag 169: 223,291; tag 184: 85,433, executor loses with 799 |
| Oversize executor witness | 169, 183 | 906-byte instruction carrying a declared 901-byte witness | tag 183: 3,972; refused with 730 |
| Random and wrong-coordinate openings | 169, 183, 184, 132 | 20 and 638 byte stage instructions | tag 184: 27,572 and 53,541; both refused with 730; tag 132 timeout awards challenger (13,539 CU) |
| Random opening against a committed non-ARW1 leaf | 169, 183, 184, 132 | 27-byte tag-183 instruction carrying 23 bytes; tag 184 has 1 byte | tag 169: 172,550 enters RESPOND; tag 183: 3,534; tag 184: 29,073 refused with 730; tag 132: 19,539, challenger wins on timeout |
| Empty app: appended data at tag 166 | 166 | 723 bytes | 89,381; refused with 730 |
| Empty app: tag-168 k=0 length guard | 168 | 65 bytes | 27,974; refused with 730 |
| Empty app: appended data then exact tag-169 retry | 169 | 635 bytes then 2 bytes | 169,955 refused with 730; 170,791 enters RESPOND |
| Required but unbound form | 160 | 7 bytes | 24,643; admission refuses with 799 |
| Previously admitted DCM2 fixture under an image that now requires a missing binding | 169 | 2 bytes | 37,357; refused with 730, DCR1 unchanged and DCM2 unrefuted |

The **measured** executor witness in the route tests is 633 bytes, uploaded in
two tag-183 transactions. The **designed** staged witness cap is 900 bytes;
each chunked instruction stays independently bounded. The **measured** test
suite results were five `rev8_bytesum_` tests, two malformed-opening/timeout
tests, one empty-application compatibility test, and two unbound-form tests
(admission refusal and late-binding neutrality), all passing on their named
SBF images. Kernel manifest tests passed in the `test-kernel` (5 tests),
`sbf-real-lifecycle-test` (6 tests), and `sbf-unbound-form-test` (5 tests)
feature sets; one admission test passed in each feature set. All three
reproducible SBF builds passed the exact-feature manifest preflight.

Raw build, preflight, and ProgramTest logs are retained at
`/Users/colkitt/sith/toys/crypto/basanos/.fadeno/local/worktrees/dcg-seam-fix-2/out/runs/dcg-seam-fix-2-20260930/`;
its README lists each log's image and feature configuration.

Across the Round 2 SBF runs, the exact tags sent were 131, 132, 145, 156,
157, 158, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 172, 176,
177, 183, and 184. Tags 183/184 stage and verify the executor opening; tag 132 is
the RESPOND timeout handler.

The retained K=80 plan has no singleton segment. A synthetic tag-168 k=0
attempt against a multi-entry segment was refused by the existing path-height
check (586), so a valid singleton tag-168 fix-point with no witness remains
**unverified**. The compatibility test verifies its empty-app trailing-data
guard before proof processing, but does not replace that missing singleton
fixture. Cross-position/document-input route proofs, a validator run, and the
full offline suite were also not tested.

## Round 3 source status (2026-09-30)

This round adds admission checks for every app-bound coordinate, the DCM2
admission identity, the versioned `/2` leaf, and executor-owned tag-183/184
RESPOND openings. Route declarations must now account for every plan read on
the selected form: a route-free form has no plan reads, and a routed form has
exactly one. The documented CU bound is 1,289,567 declared kernel CU
(1,400,000 ceiling minus 85,433 measured tag-184 overhead minus a designed
25,000-CU margin). This limit is a manifest constraint, not a measured bound
for arbitrary kernels. Terminal app DCR1 records restore `t:u32 | form:u16`
from DEV2 after using bytes 170..174 as staging counters. Revision 8 excludes
tag 182 from its dispatcher, matching Basanos' `InvalidInstructionData` result.

No fresh SBF image or SBF ProgramTest result was produced for this round. The
previous image was built before the final test manifest was reduced to the
single ByteSum kernel, so it is stale for this source and is not evidence for
Round 3. The pinned SBF wrapper was stopped before its SBF link stage to keep
the filesystem above the required 5-GiB free-space floor. Subsequent checks
found less than 5 GiB free, and no build was run below that floor.

The native ProgramTest run of
`rev8_bytesum_matching_honest_fastpath_enters_respond_sbf` reached tag 184,
ruled for the executor, rejected a duplicate tag 184, and settled tag 131.
It then failed the old tag-172 balance assertion by 500,000 lamports: that
fixture is not fully attested, so close correctly applies the withheld-document
bond disposition to the incinerator. The assertion was changed to account for
the executor refund and incinerator credit exactly, but the corrected test was
not rerun because free space had crossed the stop threshold. New unit checks
for multiple manifest routes and tag 182's revision-8 refusal were added but
also remain unrun.

The requested fresh SBF cases remain open: unsupported cross-segment,
cross-position, document-input, multi-route, and non-app-producer admission;
RWP1 path-height admission refusal; and app-bound singleton-segment tag-168
k=0. A same-leaf two-challenger ProgramTest was added but not run.
Exact-deadline staging/response/timeout, staging order/restart/signer, duplicate
response, post-timeout response, first-divergent-leaf guidance, identity
change, and the existing winner paths have source-test coverage, but Round 3
SBF execution has not verified them.

## Round 4 SBF follow-up (2026-09-30)

Round 4 corrects the selected-route rule: a manifest's one declared route
selects one plan read ordinal that becomes the replay kernel's input span. A
plan may contain additional reads; they are not inputs to this app replay
contract and remain independently challengeable at their own coordinates.
Admission and fix-point support both check that the selected ordinal exists at
every instance of the bound form. This change is needed by the retained
K=10,240 Form-22 route, whose selected ordinal is 7 in a multi-read form.

The focused app-bound SBF image was rebuilt with
`cargo-build-sbf 3.0.15` / platform-tools v1.51 and the pinned SDK:

| Image | Features | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| App lifecycle v2 | `sbf-real-lifecycle-test` | 1,233,600 | `3d2839d2fa193a3a002f5c98152a07215a9fa6203fc9a14cbca6239c04a3c406` |
| Empty application final | `revision-8` | 801,128 | `055565c48f27461a3ca5e84cb78b5165b5b2ba56f69b19068b5e0b1e2457a1af` |
| Unbound form | `sbf-unbound-form-test` | 1,233,456 | `fe2838b6a41711b3f23aaf930d2acc547264a50f8b22344aeb01efcee9203552` |

The focused SBF results are:

| Scenario | Image / fixture | Result |
| --- | --- | --- |
| `rev8_bytesum_` lifecycle, mismatch, malformed input, malicious challenger, and timeout identity checks | App lifecycle v2; K=80 retained plan | 5 passed; both a challenger ruling and an executor ruling survive an identity mutation attempt at tag 132, with settlement paid to the recorded winner |
| `rev8_app_respond_full_900_witness_k10240_sbf` | App lifecycle v2; K=10,240 PT2S and 900-byte routed ARW1/RWP1 witness | 1 passed; tag 184 measured 45,573 CU |
| `rev8_pt1x_registry_and_admission_sbf` | Empty application image; retained K=10,240 fixture | 1 passed; real tag-159/160 admission completed, with the largest observed tag-160 chunk at 720,384 CU |
| `rev8_multi_read_form_admits_selected_route_tag160_sbf` | App lifecycle v2; K=80 retained plan, Form 22 reads ordinal 7 | 1 passed; tag 160 admitted the class at 744,559 CU |
| `rev8_stale_manifest_does_not_neutralize_non_app_fixpoint_on_sbf` | Unbound-form image; non-app DCR1 v5 | 1 passed; tag 169 stayed on the v5 RESPOND path and ordinary tag-132 timeout ruled the challenger (18,450 CU) |
| `rev8_empty_application_refuses_witness_tails_for_166_168_169_sbf` | Empty application image | 1 passed; legacy trailing-data and phase-first refusal behavior remained intact |

The tag-184 CU figure includes the test's Compute Budget instruction. The
manifest cap is now `1,400,000 - 45,573 - 25,000 = 1,329,427` CU; the 25,000
CU margin is designed. The K=10,240 adapter test uses the retained plan and
its full 10,240-position geometry, while the committed completion lands the
retained executor's 80 available position roots. The separate real admission
test uses `EMPTY_APPLICATION`; full application-aware K=10,240 tag-160
admission remains unverified because the first app-image attempt exhausted its
transaction budget during tag 160 before reaching tag 184.

The K=10,240 measurement uses a pre-admitted DEA2 fixture to isolate the
tag-184 adapter cost from tag-160 admission. It measures routed replay and the
single PT2S bind/view performed by the adapter, not general kernel runtime.
It does not show that every application kernel fits its declared budget.

Receipts are retained at
`/Users/colkitt/sith/toys/crypto/basanos/out/runs/dcg-seam-fix-4-2026-09-30/`.
That directory includes the successful logs and earlier failed measurement
attempts (app-image admission reached the CU limit; pre-measurement harness
iterations exposed and corrected witness sizing, plan-position, and selected
route-bound checks). The revision-7 feature build still fails before tests
because this source tree imports `crate::rs1_summary` without containing that
module. The default offline `dcg-program` suite passed, including 48 library
tests and the revision-8 portable golden check; `unified_v8_records` also
passed all 11 tests. The stale-manifest test confirmed that a non-app v5
record enters ordinary RESPOND and receives the ordinary challenger timeout
ruling; an earlier assertion expecting DESCEND was corrected to match that
observed transition. A K=10,240 app-image attempt at full application-aware
tag-160 admission still hit the transaction CU ceiling before tag 184; the
successful tag-160 run used the empty application image, and the 900-byte
adapter test used a pre-admitted K=10,240 DEA2 fixture. Full app-aware
K=10,240 admission is therefore **unverified**.
