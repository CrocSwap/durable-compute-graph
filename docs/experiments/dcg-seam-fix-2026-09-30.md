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
