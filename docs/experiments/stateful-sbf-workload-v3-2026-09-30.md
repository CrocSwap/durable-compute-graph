# Stateful workload v3 SBF mechanics (2026-09-30)

**Result: measured mechanics demonstration.** Two local ProgramTest tests ran
the v3 stateful adapter from the feature-built SBF image (2 passed, 0 failed,
63.52 seconds). The workload covered a fixed-address primary state account,
10 MB phased initialization, resource-aware rendering with writable
workspace, adversarial refusals, and a committed two-step prefix halt. It is
not a Doom engine or application capability result.

The SBF image was built with `cargo-build-sbf` 3.0.15, platform-tools v1.51,
rustc 1.84.1, and the `sbf-real-lifecycle-test` feature. The built image is
1,298,712 bytes; SHA-256:
`eaf70b0abf1032646fcc8142d43f83e5379d8b28180f85f641bd5ee5d4542d7d`.
ProgramTest transaction metadata measured individual instructions. For
batched growth, the test extracted one SBF CU log per instruction. The
initialization phase range includes the first and last partial/edge phases.

## Measured compute units

| Instruction / phase | Measured CU |
|---|---:|
| `OPEN_SESSION`, headerless primary | 10,439 |
| `OPEN_SESSION`, default headered control | See control group below |
| `CREATE_STREAM` | 8,248 |
| `WRITE_INPUT`, four writes | 3,859 each |
| `CREATE_STATE`, 10 MB headerless | 16,412 |
| `GROW_STATE`, 1,220 calls | 14,340–54,276 each |
| `BEGIN_INITIALIZE` | 3,370 |
| `RUN_INITIALIZE`, 153 phases | 7,692–7,850 each; first 65,536-byte phase: 7,850; final 38,528-byte phase: 7,692 |
| Wrong session schema refusal | 2,869 |
| `ADVANCE` before initialization completion refusal | 3,543 |
| Stale initialization phase refusal | 2,950 |
| `CREATE_VIEW`, output | 9,916 |
| `CREATE_VIEW`, renderer workspace | 8,283 |
| `CREATE_VIEW`, publication scratch | 8,292 |
| `BEGIN_PHASE` for rendering | 7,050 |
| `RUN_PHASE`, resource and workspace callback | 9,983 |
| `COMMIT_PHASE` | 7,178 |
| `ADVANCE`, primary-account substitution refusal | 3,681 |
| `ADVANCE`, stale cursor refusal | 3,116 |
| `ADVANCE`, four requested steps with halt-before at step 3 | 6,504 |
| `ANCHOR`, 10 MB headerless primary | 200,000 consumed, then default-budget failure |

The halting `ADVANCE` committed exactly the first two commands. The session
recorded the test reason `0xD00D` and cursor 2; the state and input stream
cursors both reflected the same prefix. Substitution, wrong schema, use before
initialization, and stale initialization/cursor paths left the relevant
accounts unchanged.

The default headered control test measured: `OPEN_SESSION` 7,276 CU,
`CREATE_STREAM` 8,273 CU, `CREATE_STATE` 15,202 CU, each of two `WRITE_INPUT`
calls 3,920 CU, one-call `INITIALIZE_STATE` 5,656 CU, and `ADVANCE` 6,983 CU.

All values are measured for this local SBF image and test fixture. The
1,400,000-CU runtime bound remains a designed ceiling. The 10 MB anchor only
ran under ProgramTest's default 200,000-CU transaction budget; it failed at
that limit and left the anchor fields unchanged. Whether it succeeds at the
runtime ceiling is open and was not tested.

## Verification and scope

The focused tests were:

- `stateful_v3_primary_prefix_halt_resource_views_and_phased_init`
- `stateful_v3_default_layout_remains_headered`

The primary test ran these exact operation families: `OPEN_SESSION`,
`CREATE_STREAM`, four `WRITE_INPUT`s, `CREATE_STATE`, 1,220 `GROW_STATE`s,
`BEGIN_INITIALIZE`, 153 `RUN_INITIALIZE`s, three `CREATE_VIEW`s,
`BEGIN_PHASE`, `RUN_PHASE`, `COMMIT_PHASE`, three `ADVANCE` refusal/success
paths, and `ANCHOR` (expected budget failure). The refusal paths were wrong
session schema, `ADVANCE` before initialization was complete, stale init
cursor, substituted primary account, and stale transition cursor. Account
contents were checked around each adversarial case.

The resource fixture is a committed 4,096-byte buffer, and the test kernel
copies its prefix into the 10 MB state. This does not measure a full 4.4 MB
WAD import, Doom's 9.7 MB context initialization, or an actual renderer. The
view test establishes that a callback can read the authenticated resource and
write its workspace while output remains unchanged until publication commit.
It does not measure Doom rendering cost. No validator or deployed chain was
used. No evidence-register row was requested or added.

The standalone checkout used the pinned local SBF SDK at
`/private/tmp/basanos-sbf-sdk-v151-20260920` and this build command:

```sh
DCG_CARGO_BUILD_SBF=/Users/colkitt/.local/share/solana/install/active_release/bin/cargo-build-sbf \
DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920 \
DCG_SBF_TOOLS_VERSION=v1.51 \
DCG_SBF_STAGING_NAME=dcg-stateful-3-staging \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-target \
  crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-stateful-3-sbf
```

The exact focused ProgramTest command was:

```sh
RUST_LOG=error \
BPF_OUT_DIR=/private/tmp/dcg-stateful-3-sbf \
SBF_OUT_DIR=/private/tmp/dcg-stateful-3-sbf \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test \
  --test stateful_v3_sbf_workload -- --nocapture --test-threads=1
```

The cold build target remained below the dispatch's 5 GB ceiling. Build target,
SBF image, and logs were moved to `/private/tmp/trash-dcg-stateful-3` after
verification.
