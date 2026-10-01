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

## Final SBF build and CU measurements

Measured on the final local SBF ProgramTest image built with
`crates/dcg-program/scripts/build-sbf-reproducible.sh`, release profile,
`sbf-real-lifecycle-test`, `cargo-build-sbf 3.0.15`, platform-tools v1.51, and
`rustc 1.84.1-dev`. The final image is
`out/runs/dcg-2b-engine-a-2026-10-01/sbf-image-final/dcg_program.so`,
1,389,048 bytes, SHA-256
`bcc2671e62eba0e68f41a94069e47209864ade3e014b39de119085d5147947a2`.
Build log: `out/runs/dcg-2b-engine-a-2026-10-01/sbf-build-final.log`.

All figures below are measured from this image in local ProgramTest. The
malformed-account and part-B refusal figures are transaction CU. F47 tag
figures are transaction CU, including the ComputeBudget instructions. F48
reports both instruction and transaction CU for its 128-read tag-121 case.

| Tag | Measured SBF path and CU |
|---:|---|
| 120 | Malformed accounts: 209; honest F47 K=80: 293,972 default roles / 290,972 swapped roles; forged-target refusal (734): 268,328 / 263,828 |
| 121 | Malformed accounts: 210; honest F47 K=80: 282,235 / 279,235; honest F48 128-read K=80: 818,476 / 816,976 instruction CU, 818,832 / 817,332 transaction CU |
| 126 | Malformed accounts: 216; honest restage: 5,879; executor substitution refusal (733): 2,979 |
| 128 | Malformed accounts: 217; honest output verification: 11,075; committed-write mismatch refusal (734): 10,305; retained fixture descriptor mismatch (734): 9,912 standalone and 11,412 combined |

The F47 run exercised tags 120 and 121 in both honest role orders, rejected a
forged tag-120 target with 734, and confirmed deferred tag 124 still returns
`InvalidInstructionData` (1,507 transaction CU). The F48 run also exercised
tag 120 followed by a complete 128-read tag 121 in both role orders, rejected
out-of-range mappings and segment ordinals atomically, and confirmed tag 124
remains refused (1,507 CU). The generic SBF suite passed 5/5, including the
malformed inputs, tag-126 substitution, tag-128 mismatch, and retained
`tests/fixtures/closure_v2_generic/entry-119.dgr1` descriptor-mismatch paths.

Measured reserved-tag refusals on the final image: tag 122, 123, and 124 used
211 CU each; tags 127 and 129 used 214 CU each. Each returned
`InvalidInstructionData`. Tag 129 is source `VERIFY_RANGE_SLOTS`, the bounded
range-read proof continuation, and remains intentionally refused in this
part.

The focused `app_api::tests` unit suite passed 15/15. The focused host F47
test also passed both role orders. Formatting and `git diff --check` passed.
No evidence-register row was requested or added; no live chain transaction
was submitted. Retained artifacts are compiler-v1 fixtures; this dispatch did
not invoke a compiler.

## Earlier attempts and retained receipts

The pre-merge image at
`out/runs/dcg-2b-engine-a-2026-10-01/sbf-image/dcg_program.so` (1,389,376
bytes, SHA-256
`00de5eaabb5edd22766c429195c3c55b1af3ffad47fc4fefd883ca637d099727`)
recorded the initial generic-tag measurements. Its F47/F48 setup reached the
prior tag-145 template seal, then failed with 813 (`ERR_OPTION_RANGE`). Merging
current `main` supplied the Form-47 geometry fix; the post-merge rerun reached
the generic tags. During that rerun, tag 121 exposed the overlap between the
routes key at bytes 216..248 and the stored response bump at byte 219. The
final implementation preserves the response bump at byte 481 with marker 1
at byte 480 before staging the route key, then the final SBF runs above passed.

The failed and intermediate outputs remain preserved alongside the final
receipts:

- `out/runs/dcg-2b-engine-a-2026-10-01/generic-sbf-test-receipt.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f47-sbf-test-receipt.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f48-sbf-test-receipt.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f47-sbf-post-merge.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f47-sbf-post-merge-rerun.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f47-sbf-final.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/f48-sbf-final.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/generic-sbf-final.log`
- `out/runs/dcg-2b-engine-a-2026-10-01/app-api-final.log`

The source-format and unsupported-form parity gaps listed above remain open.
This is not a source-parity result and is not ready for a qualified image.
