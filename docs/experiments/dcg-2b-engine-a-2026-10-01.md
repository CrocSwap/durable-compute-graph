# DCG generic dispute engine, part A — 2026-10-01

Status: partial implementation and local SBF measurement. This is not a source
parity result and is not ready to merge into a qualified image. No live chain
transaction was submitted.

## Port boundary

`app_api` now defines `ApplicationDisputeHooks` and
`ArtifactWitnessVerifier`. DCG routes 120, 121, 126, and 128 to the generic
revision-8 handler. Tags 122, 123, 124, 127, and 129 return
`InvalidInstructionData`. Source tag 129 is `VERIFY_RANGE_SLOTS`: a bounded
range-read proof continuation; it remains refused in this part.

The handler currently implements the unified revision-8 DCR1 v5 / DCM2 v7
path. The source file at Basanos dispatch base `8bfdfbb7e121` also accepts
DCR1 v2/v4 and DCM2 v6. Those source formats are not ported here. Source
`live()` also rejects unsupported forms with custom 740; DCG has no equivalent
form-catalog check and does not emit 740. Both are unintentional parity gaps.

## Refusal-code audit

These are the custom refusal codes reachable from each source tag and the DCG
counterpart. Tags 120/121 can also bubble the shared PT parser/route codes
`580, 585, 598, 600–604` in both trees. The source owner-only checks may return
runtime `IncorrectProgramId`, which is not a custom program code.

| Tag | Basanos source custom codes | DCG custom codes | Audit |
|---:|---|---|---|
| 120 | `730, 731, 733, 734, 736, 738, 740` plus PT codes above | `730, 731*, 733, 734, 736, 738` plus PT codes above | Direct DCR1/DRU1 identity-gate failures map source `IncorrectProgramId`/`731` to `734`. `740` is missing. `731*` can still arise only if the second canonical DRU1 check in `sealed_view` rejects a noncanonical bump that passed the stored-bump gate; normal program creation stores the canonical bump. |
| 121 | `730, 731, 733, 734, 736, 738, 740, 741` plus PT codes above | `730, 731*, 733, 734, 736, 738, 741` plus PT codes above | Same provenance and unsupported-form differences as tag 120. `741` remains the incomplete range-family refusal. A custom code returned by `ArtifactWitnessVerifier::supplied_read_hash` can also bubble through; the current fail-closed default returns `734`. |
| 126 | `730, 733, 734, 736, 740` | `730, 733, 734, 736` | Source owner checks may return `IncorrectProgramId`; DCG maps stored-bump identity failures to `734`. `740` is missing. |
| 128 | `730, 731, 733, 734, 736, 740` | `730, 731*, 733, 734, 736` | Same response-identity and unsupported-form differences as tag 120. |

The intentional provenance seam is limited to identity validation: the fresh
DCG record uses stored canonical bumps and maps its gate failures to 734.
The missing 740 behavior and older source-format acceptance are not provenance
seams, so the code and acceptance behavior do not yet match the source.

## SBF build and CU measurements

Measured on the local SBF ProgramTest image built with
`crates/dcg-program/scripts/build-sbf-reproducible.sh`, release profile,
`sbf-real-lifecycle-test`, `cargo-build-sbf 3.0.15`, platform-tools v1.51, and
`rustc 1.84.1-dev`. The image is
`out/runs/dcg-2b-engine-a-2026-10-01/sbf-image/dcg_program.so`, 1,389,376
bytes, SHA-256
`00de5eaabb5edd22766c429195c3c55b1af3ffad47fc4fefd883ca637d099727`.
Build log: `out/runs/dcg-2b-engine-a-2026-10-01/sbf-build.log`.

The table reports measured `compute_units_consumed` from that exact image.
For tags 120 and 121 only the malformed account-list path ran; it does not
measure their honest or disputed handler path.

| Tag | Measured SBF path and CU |
|---:|---|
| 120 | Malformed account list: 209 CU |
| 121 | Malformed account list: 210 CU |
| 126 | Malformed account list: 216 CU; honest restage: 5,879 CU; executor substitution refusal: 2,979 CU |
| 128 | Malformed account list: 217 CU; honest output verification: 11,066 CU; write mismatch refusal: 10,296 CU; retained fixture mismatch: 9,903 CU in the standalone fixture test and 11,403 CU in the combined output test |

Measured reserved-tag refusals on the same image: tag 122, 123, and 124 used
211 CU each; tags 127 and 129 used 214 CU each. Each returned
`InvalidInstructionData`.

The retained `tests/fixtures/closure_v2_generic/entry-119.dgr1` envelope
rejected the wrong descriptor with 734. The valid synthetic DGR1 used by the
tag-128 test passed; an altered committed write was refused with 734.

## Tag 120/121 setup blocker

Both attempted SBF integration tests stopped before reaching tag 120 or 121.
Their retained Form-47 setup failed at the prior tag-145 template seal with
custom 813 (`ERR_OPTION_RANGE`), consuming 492,732 CU including the
ComputeBudget instruction. The same Form-47 tag-145 refusal is recorded as
reproduced on the baseline lifecycle image in
`docs/experiments/dcg-seam-fix-2026-09-30.md`. The seal implementation is
outside this dispatch's permitted edit set, so the tag-120 forged-target and
tag-121 honest Form-47/F48 SBF cases remain unverified.

Retained artifacts are compiler-v1 fixtures; this dispatch did not invoke a
compiler. The full captured test output is in:

- `out/runs/dcg-2b-engine-a-2026-10-01/generic-sbf-test-receipt.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f47-sbf-test-receipt.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f48-sbf-test-receipt.log`

The generic SBF suite passed 5/5, and the focused `app_api::tests` unit suite
passed 15/15. The focused F47 and F48 setup tests each failed before the
ported handler ran. The host check, retained DGR1 parser fixture, and
formatting checks also passed. No evidence-register row was added.
