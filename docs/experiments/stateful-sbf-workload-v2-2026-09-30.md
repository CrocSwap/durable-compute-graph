# Stateful workload v2 SBF mechanics (2026-09-30)

**Result: measured mechanics demonstration.** One local ProgramTest ran the
v2 stateful adapter from an SBF ELF and passed its 1,001-step stream workload,
large resource-bound state initialization, 1 MB snapshot plus eight-strip
staging, phase controls, atomic publication, halt, and rent recovery. It also
made one extra state transition while a publication was suspended and verified
that the stale publication refused. The workload uses the default view-copy
callback; this is not a Doom renderer or an application capability result.

The feature ELF was built with `build-sbf-reproducible.sh`, cargo-build-sbf
3.0.15, platform-tools v1.51, and `sbf-real-lifecycle-test`. Its length is
1,097,408 bytes and SHA-256 is
`7d96af326e925cba9ecb82be1b77a44e2cc79af282024a50ea2560467bd805f1`.
ProgramTest transaction metadata supplied the CU values below. For batched
transactions, the test extracted the SBF program's CU log for every
instruction; ranges are per instruction, not total transaction costs.

## Measured compute units

| Tag | Successful operation(s) | Refusal/control measurements |
| ---: | --- | --- |
| 230 | Open session: 8,197 | — |
| 231 | Create 64-slot stream: 9,234; grow 64→576: 5,716; grow 576→1,024: 5,741 | — |
| 232 | Create two-span state: 14,866; 135 state growth instructions: 6,958–11,348; authenticated initialization: 5,363 | Wrong resource: 3,220 |
| 233 | Nine output creations: 7,873–13,893; scratch creation: 7,709; 263 output/scratch growth instructions: 5,219–9,609 | — |
| 234 | 1,002 successful writes: 3,259–3,264 (most: 3,262) | Duplicate slot: 2,648 |
| 235 | 126 advances for the initial 1,001 steps: 5,652 for the one-step call and 7,759 for an eight-step call; extra mid-phase step: 5,654 | Input gap: 5,682 |
| 236 | Begin: 11,344; successful 65,536-byte phases: 12,383–12,384; final partial phase: 13,757; commit: 16,326; abort: 2,719 | Stale phase cursor: 5,255; state changed mid-phase: 5,250 |
| 237 | Halt: 2,703 | — |
| 238 | Child closes: 3,233–3,311; session close: 2,390 | Close while live: 2,464 |
| 239 | Not exercised | — |

The successful view publication used 17 fresh phase instructions, each with a
declared limit of 1,000,000 CU and a 65,536-byte maximum chunk. The final
partial phase crossed several output boundaries and consumed 13,757 CU. The
runtime's existing 1,400,000-CU transaction ceiling was not changed. The
declared phase limit and byte limit are designed protocol bounds; the values
in the table are measured costs for this test kernel and toolchain.

## Verification

The focused SBF ProgramTest passed one test: `stateful_v2_windows_resources_phased_views_and_lifecycle` (1 passed, 0 failed, 74.99 seconds). It checked 1,001 steps before publication, then an extra state change and successful publication at cursor 1,002. It verified state values, authenticated resource bytes, all nine output contents and cursors, unchanged outputs before commit, unchanged scratch on stale-cursor/state refusals, gap and duplicate-write atomicity, same stream root after each growth, close-while-live refusal, and account closure/refunds.

The run covers v2 tags 230–238 and does not exercise v2 tag 239 (explicit
anchor). The stream-root commitment was checked across both capacity changes;
the explicit input-chain/state anchor remains unverified here. No live
validator, on-chain program, Doom engine, or full offline suite was run.
The 5,363-CU initialization measurement writes only the small test resource
prefix into already-zeroed state accounts; it does not measure importing the
Doom context. V2 has no phased initialization operation today, so Doom's full
WAD-to-context import must first be measured against the runtime ceiling and
may require a resumable initialization extension.

Commands used from the standalone `dcg-repo` checkout (the SBF SDK path is the
local pinned platform-tools SDK):

```sh
export CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-2-target
export DCG_SBF_SDK=/path/to/pinned/platform-tools-sdk
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-stateful-2-staging

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-stateful-2-sbf

# cargo-build-sbf emitted the fresh ELF under CARGO_TARGET_DIR; copy that
# exact build output into the ProgramTest lookup directory.
cp "$CARGO_TARGET_DIR/sbpf-solana-solana/release/dcg_program.so" \
  /private/tmp/dcg-stateful-2-sbf/dcg_program.so

RUST_LOG=error \
BPF_OUT_DIR=/private/tmp/dcg-stateful-2-sbf \
SBF_OUT_DIR=/private/tmp/dcg-stateful-2-sbf \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-2-target \
cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test \
  --test stateful_v2_sbf_workload -- --nocapture
```

The warm-target helper found no retained warm build for this standalone clone;
the cold SBF target reached 1.4 GB, below the 5 GB dispatch limit. The binary,
build log, test log, and result manifest are retained in
`out/runs/dcg-stateful-2-2026-09-30/`. The temporary target and SBF output
directories were moved under `/private/tmp/trash-dcg-stateful-2` after the
check.
