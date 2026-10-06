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
DCG_CARGO_BUILD_SBF=~/.local/share/solana/install/active_release/bin/cargo-build-sbf \
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

## Follow-up fixes and measurements (2026-09-30)

**Result: measured mechanics demonstration.** The expanded focused SBF
ProgramTest run passed 8 tests, 0 failed, in 142.30 seconds. It uses the
`sbf-real-lifecycle-test` image built with `cargo-build-sbf` 3.0.15,
platform-tools v1.51, and rustc 1.84.1. The image is 1,180,240 bytes with
SHA-256
`18f2030484494e6961cd71493fb755d916dbd7ade60734d37ba53bf15b1d339c`.

The run covers the previous primary-state and default-headered workloads plus
forged-session rejection, failed-initialization recovery, cross-session
account rejection, workspace and scratch provenance, phase cursor rejection,
halt outcomes, and anchor cleanup. `HaltBefore` mutation is refused with
state/session/stream unchanged for bounded state; larger state still relies on
the kernel's documented obligation. `BEGIN_PHASE` zeroes workspace. Resource
identity is proved by chunk and copied once into a sealed program-owned
account. Anchor work uses the phase-locked `dcg/state-anchor/3` commitment;
`ADVANCE` is refused while that phase is open. The feature-only test kernels
advertise v1, v2, and v3 mode identifiers through separate manifests.

### Measured scaled paths

| Workload | Measured result |
|---|---:|
| 4,400,000-byte resource allocation | 537 calls; 13,361–30,892 CU/call; 11,890,538 CU total |
| 4,400,000-byte resource upload | 68 proof-checked chunks; 17,137–45,672 CU/chunk; 3,076,724 CU total |
| 10,000,000-byte state anchor | 153 chunks; 38,518–52,024 CU/chunk; 7,946,015 CU chunk total |
| Anchor begin and finish | 22,199 + 7,535 CU; lifecycle total 7,975,750 CU across separate instructions |
| Close finished anchor after halt | 21,375 CU |

The resource test changes the source account after upload and verifies that
initialization still reads the committed bytes from the sealed copy. The 4.4
MB input is synthetic, not the Doom WAD. The anchor is a multi-transaction
mechanics path; these measurements do not establish deployed-chain fit or
Doom correctness.

### Focused test names

- `stateful_v3_default_layout_remains_headered`
- `stateful_v3_failed_initialization_can_halt_and_recover_rent`
- `stateful_v3_forged_session_and_other_primary_are_refused`
- `stateful_v3_halt_outcomes_are_atomic_and_close_input_after_halt`
- `stateful_v3_halt_with_view_phase_open_still_allows_closing_children`
- `stateful_v3_primary_and_headered_spans_advance_twice`
- `stateful_v3_primary_prefix_halt_resource_views_and_phased_init`
- `stateful_v3_sealed_resource_accepts_4_4mb_chunks_once`

The forged-session test attempts `CLOSE_ACCOUNT`, `ADVANCE`, and
`RUN_INITIALIZE` through session-shaped primary bytes and expects refusal. It
also substitutes another session's program-owned primary at index zero and
checks that state remains unchanged. Cross-session workspace and scratch
accounts, closing a primary through another session, and a correctly ordered
primary plus headered span are exercised.

### Compatibility build

The default revision-8 image built from this tree is SHA-256
`eb578084cf1947b1c53c3dbf7f494dd2bc213cbd685736a2cb9dc7b6068aaa4a`.
The requested `9bd8fe5c` prefix did not match. A clean archive of the stated
base commit `22bb914a2c49adc64682b5c5372e8288f4e3d210`, built with the same
pinned SDK/toolchain, produced the same 752,656-byte image and exact hash. This
confirms the branch leaves the revision-8 image unchanged under this build;
the requested prefix is not reproducible from the stated base and toolchain.

The focused commands were:

```sh
DCG_CARGO_BUILD_SBF=~/.local/share/solana/install/active_release/bin/cargo-build-sbf \
DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920 \
DCG_SBF_TOOLS_VERSION=v1.51 \
DCG_SBF_STAGING_NAME=dcg-stateful-3-fix-staging \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-fix-target \
  crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-stateful-3-fix-sbf

RUST_LOG=error \
BPF_OUT_DIR=/private/tmp/dcg-stateful-3-fix-sbf \
SBF_OUT_DIR=/private/tmp/dcg-stateful-3-fix-sbf \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-fix-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test \
  --test stateful_v3_sbf_workload -- --nocapture --test-threads=1
```

The brief also cited `docs/spec/settlement-pilot-contract.md` (including the
“Address provenance gate”) and `docs/spec/referee-laws.md`, law 3. Those files
are absent from this DCG checkout and its sibling source checkout, so the
implementation used the supplied review and brief; it re-derives session
addresses from an independent authority signer or supplied refund destination
where available, and from the session's stored authority where the instruction
has no independent source. Authority-bearing handlers also validate signer
status.

The feature SBF image, default revision-8 images, clean base archive, target,
and ProgramTest logs were moved under `/private/tmp/trash-dcg-stateful-3-fix`
after verification. No validator or deployed chain was used.

## Follow-up fixes and measurements (2026-09-30, dispatch dcg-stateful-3-fix2)

**Measured mechanics demonstration.** The full focused v3 SBF workload passed
12 tests, 0 failed, in 154.58 seconds. The feature image was built with the
pinned `cargo-build-sbf` and platform-tools v1.51 setup below. Its size was
1,184,136 bytes and its SHA-256 was
`e7f94cec2baf9cb351cddf5d6fa5dfa118cf127bb30f1fc64b97c7c9be321184`. The
Rust target directory was 1.5 GiB after the runs, below the 4 GiB limit.

The follow-up tests close both spans of a primary-plus-headered session and of
the default two-span layout, then close the session and verify that all rent
returns. They also exercise `HaltBefore` at the 8,192-byte snapshot cap with
eight-step `ADVANCE`, reject initialization before the named resource copy is
sealed, and verify the one-shot anchor authority, status, and distinct domain
checks. The implementation closes state spans highest-index first and
subtracts each closed span's length; it reuses one capped snapshot buffer. For
state above 8,192 bytes, `HaltBefore` immutability remains the kernel's
obligation.

The v1 and v2 compatibility SBF workloads also passed, one test each. They
exercise the unchanged wire formats with session address re-derivation added
to the v1 and v2 session checks.

### Follow-up focused test names

- `stateful_v3_closes_two_spans_in_order_and_recovers_all_rent`
- `stateful_v3_halt_before_at_snapshot_cap_with_eight_step_advance`
- `stateful_v3_begin_initialization_requires_sealed_resource`
- `stateful_v3_one_shot_anchor_requires_authority_and_active_session`
- `stateful_v3_sbf_workload::stateful_consensus_stream_views_close_and_refusal_atomicity` (v1)
- `stateful_v2_sbf_workload::stateful_v2_windows_resources_phased_views_and_lifecycle` (v2)

The complete v3 workload also reran the eight tests listed above under
“Focused test names.” These results are SBF ProgramTest mechanics evidence;
they do not establish validator or deployed-chain behavior.

### Follow-up commands

```sh
DCG_CARGO_BUILD_SBF=~/.local/share/solana/install/active_release/bin/cargo-build-sbf \
DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920 \
DCG_SBF_TOOLS_VERSION=v1.51 \
DCG_SBF_STAGING_NAME=dcg-stateful-3-fix2-staging \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-fix2-target \
  crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-stateful-3-fix2-sbf

RUST_LOG=error BPF_OUT_DIR=/private/tmp/dcg-stateful-3-fix2-sbf \
SBF_OUT_DIR=/private/tmp/dcg-stateful-3-fix2-sbf \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-fix2-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test --test stateful_v3_sbf_workload \
  -- --nocapture --test-threads=1

RUST_LOG=error BPF_OUT_DIR=/private/tmp/dcg-stateful-3-fix2-sbf \
SBF_OUT_DIR=/private/tmp/dcg-stateful-3-fix2-sbf \
CARGO_TARGET_DIR=/private/tmp/basanos-dcg-stateful-3-fix2-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test --test stateful_sbf_workload \
  --test stateful_v2_sbf_workload -- --nocapture --test-threads=1
```

The target and SBF output directories were moved to
`/private/tmp/trash-dcg-stateful-3-fix2` after verification. No validator,
deployed chain, network, or remote was used.
