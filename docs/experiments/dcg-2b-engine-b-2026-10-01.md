# DCG generic dispute engine, part B — 2026-10-01

Status: hook-backed tags 122, 123, 124, 127 and unified-v5 tag 129 are
implemented and locally measured. This is an application-mechanics result,
not a model-quality or source-parity claim. No chain transaction was
submitted.

## Implementation boundary

The generic dispatcher routes tags 120–124 and 126–129 through the static
application manifest. `ArtifactWitnessVerifier` owns descriptor rows, weight
rows and artifact blocks; `ApplicationDisputeHooks` owns form admission and
PT1 replay. The test application uses the existing ByteSum test kernel. Its
successful SBF dispute demonstrates the hook and account-transition mechanics
only.

The added record/document validators accept the tested DCR1 v2/v4 and DCM2
v6 shapes on hook-backed paths, and unsupported forms return 740. The v2/v4
acceptance test covers tags 122/123, not a complete v2/v4 tag-120/121 dispute.
The implementation does not yet match the full Basanos source surface:

- tag 124's replay hook is called once with `output_range: None`; the source's
  chunked and windowed output continuation is not ported;
- tag 129 supports unified DCR1 v5 range-slot proofs without page picks; the
  source's legacy DCR1 v2/v4 page-pick continuation is not ported;
- DCR1 v2/v4 full tag-120/121 target/read replay is not ported;
- no positive tag-129 continuation was exercised in this dispatch.

## Refusal-code parity audit

This is a static call-path comparison with Basanos
`chain/dcg-program/src/closure_v2_generic.rs`. The table names the tag-specific
refusal classes relevant to these hooks; shared live-record validation can
also return 731/736 and lower-level route/template readers can bubble their
own codes. Adapter-returned custom errors remain application-owned.

| Tag | Basanos source behavior | DCG hook-backed behavior | Parity evidence/status |
|---:|---|---|---|
| 122 | `730, 731, 733, 734, 735, 736, 740` | `730, 733, 734, 736, 740` plus verifier-returned codes | Malformed/740 refusals, positive verifier path and DCR1 v2/v4 acceptance measured. Negative verifier witness not exercised. |
| 123 | `730, 731, 733, 734, 735, 736, 740, 741` | `730, 733, 734, 736, 740, 741` plus verifier-returned codes | Malformed/740 and positive row path measured. Negative row witness not exercised. |
| 124 | `730, 731, 733, 734, 735, 736, 738, 740, 741` plus replay/kernel errors | `730, 733, 734, 736, 738, 740, 741` plus replay-hook-returned codes | Malformed/740 measured; honest and deliberate-cheat verdicts measured through tag 131. Chunked/windowed execution is a known gap. |
| 127 | `730, 731, 733, 734, 735, 736, 740` | `730, 733, 734, 736, 740` plus verifier-returned codes | Malformed/740 and a positive artifact-marker hook path measured. Negative artifact-witness refusal not exercised. |
| 129 | `730, 731, 733, 734, 736, 738, 740, 741` | `730, 733, 734, 736, 738, 740, 741` on unified v5; no page-pick bytes accepted | Malformed/740 measured. Positive unified range proof and legacy page-pick parity remain unverified; legacy v2/v4 path is absent. |

Cross-cutting DCR1/DRU1 identity failures intentionally map through DCG's
provenance gate to 734, while some Basanos owner/address paths return 731 or
runtime `IncorrectProgramId`. This is the documented account-provenance seam,
not byte-for-byte refusal parity. Hook errors are returned unchanged, so a
production application's negative verifier tests must pin its own codes.

## Final SBF image and measurements

The final image was built from this branch with the pinned SDK and
platform-tools v1.51, `cargo-build-sbf` 3.0.15, and Rust 1.84.1-dev.
Build log:
`out/runs/dcg-2b-engine-b-2026-10-01/sbf-build-final8.log`.

Image: `out/runs/dcg-2b-engine-b-2026-10-01/sbf-image-final8/dcg_program.so`,
1,424,896 bytes, SHA-256
`0c0328a2f9b96ff07bad7a6fe7e22c57cb5cd77e7890adaeeb00192d022366e4`.
The generated keypair file was deleted. CU values below are measured local
ProgramTest transaction CU, including ComputeBudget instructions where those
instructions are present.

| Path | Measured result |
|---|---|
| Generic SBF suite | 8/8 passed. Malformed tags 120/121/122/123/124/126/127/128/129: 180/181/180/181/180/181/180/181/182 CU. |
| Unsupported-form refusal 740 | Tags 122/123/124/127/129: 768/617/1,222/768/1,527 CU. |
| Positive app hooks | Tag 127 artifact hook: 15,775 CU. DCR1v2/DCM2v2 accepted at tag 122: 16,486 CU; DCR1v4/DCM2v4 accepted: 13,487 CU. |
| F47 full path, K=80, both role orders | Tag 120: 291,064; 121: 279,335; 122: 10,733; 123: 8,387; honest 124: 106,514; tag 131 settlement: 10,909 CU. |
| F47 deliberate tag-124 cheats | Both wrong-mapping and wrong-duplicate-probability cases convicted in both role orders. Tag 124: 103,723–106,723 CU; tag 131 settlement: 13,073 CU. |

Receipts: `closure-v2-generic-sbf-final8.log`,
`f47-full-path-sbf-final8-settles.log`, `app-api-tests-final8.log`, and
`unified-v8-document-sbf-final8.log` under the receipt directory above. The
focused F47 test passes in both identity-role orders and includes the complete
120 → 121 → 122/123 → 124 → 131 sequence. Its direct-account fixture models
the opener's DCM2 open-count increment before exercising settlement.

## Suite result and Part A comparison

`app_api::tests`: 15/15 passed, matching Part A's 15/15. The generic SBF suite
grew from Part A's 5/5 to 8/8 and now includes tag 127 positive hook coverage,
v2/v4 acceptance, and the requested tag-124 verdict path. The full
`unified_v8_document` SBF suite finished with 67 passed and 2 failed in
255.34 seconds. Both failures are
`rev8_pt1x_real_admission_to_resolve_sbf` and
`rev8_pt1x_registry_and_admission_sbf`; each exhausts the 1,400,000-CU limit
at tag 160 with `ProgramFailedToComplete`. Part A did not retain a comparable
full-suite result, so no full-suite delta is available.

Formatting and `git diff --check` pass. This work did not change the evidence
register or promote a protocol capability claim. The remaining parity gaps
above must be closed and the failing tag-160 admission paths investigated
before treating this branch as ready for a qualified image.
