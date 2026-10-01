# Form-47 geometry version fix (2026-10-01)

The revision-8 program accepts Form-47 geometry version 2 only. During DCG
extraction, `decode_form_geometry` was copied with a version-1 check, and no
test fed real compiler output to the extracted decoder. The compiler-v1 golden
`02008000ffff07001000000000000000` therefore failed at tag 145 with custom
error 813.

The regression guard is
`form47_geometry_v2_compiler_golden_guard` in
`crates/dcg-program/src/kernels/mod.rs`. It feeds that compiler-v1 golden to
the decoder and also checks rejection of version 1, capacity 80, an option
region other than `0xffff`, and a short buffer.

**Measured local SBF check.** With the retained K=10,240 fixture
`f47-k10240-v1` and SBF image SHA-256
`1b27d27a50feee96046338d0260717dcdcb04747493e1ceb2ab517b8605a9f67`, all four
fixture-driven cases recorded tag 145 at 894,824 transaction CU. The
`unified_init_rejects_prompt_shorter_than_template_producer_delta` test passed.
`f47_compiler_v1_unified_init_accepts_option_counts_1_47_48_80` continued to
tag 146 and then refused with `IncorrectProgramId`; the Form-47 dispute and
Form-48 gather tests continued to tag 120 and then refused with
`InvalidInstructionData`. Their stdout receipts are in Basanos at
`out/runs/dcg-f47-geometry-fix-2026-10-01/`. No chain transactions were sent.

Parity-fix-2 follow-up receipt: Basanos
`out/runs/dcg-r8-parity-fix-2-2026-10-01/`.
