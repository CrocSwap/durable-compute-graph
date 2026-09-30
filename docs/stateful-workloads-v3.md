# Stateful workloads v3 (local prototype)

Status: designed and implemented as an additive stateful wire version. V1 and
v2 remain available, and their wire bytes are unchanged. V3 changes
stateful-layer semantics and uses distinct account discriminators and PDA
seeds; it does not change revision-8 instructions or goldens. The default
revision-8 entrypoint does not dispatch app-owned stateful tags. The SBF
ProgramTest evidence is a mechanics demonstration, not an engine capability
claim.

V3 is selected by wire version byte `3`. The existing tag range 230–239 is
retained. Existing session, stream, state, view, scratch, and workspace
accounts use `DSS3`, `DSB3`, `DSE3`, `DVW3`, and versioned v3 PDA seeds. The
stateful processor routes only those tags to a selected static kernel; the
application composes the helper with its existing instruction handler.

## V3 additions

| Tag | Operation | V3 contract |
|---:|---|---|
| 230 | `OPEN_SESSION` | Adds a layout selector. `0` keeps headered state as the default; `1` selects a headerless primary state span at state index 0. The session records and authenticates that span's schema and declared length. |
| 231 | `CREATE_STREAM`, `GROW_STREAM` | Retains v2 stream behavior and versioned v3 accounts. |
| 232 | `CREATE_STATE`, `GROW_STATE`, initialization | Adds `BEGIN_INITIALIZE` (`0xFC`) and cursor-bound `RUN_INITIALIZE` (`0xFD`) subtypes, plus the existing growth and one-call initialization paths. State use refuses until phased initialization completes. |
| 233 | `CREATE_VIEW`, `CREATE_WORKSPACE`, `GROW_VIEW` | Adds a separately declared writable renderer workspace, bound to a session. Publication scratch remains a separate account and role. |
| 234 | `WRITE_INPUT` | Retains the v2 indexed/append and write-once policies. |
| 235 | `ADVANCE` | Supports a kernel outcome that continues, halts before a step, or halts after a step. A halt commits the exact successful prefix and records reason and cursor. A refusal remains transaction-atomic. |
| 236 | `BEGIN_PHASE`, `RUN_PHASE`, `COMMIT_PHASE`, `ABORT_PHASE` | The renderer receives the authenticated resource read-only, the state at the bound state version, and the writable renderer workspace. Output staging remains separately committed atomically. |
| 237 | `HALT_SESSION` | Retains explicit session halt. |
| 238 | `CLOSE_ACCOUNT` | Retains child/session account closure and refund behavior. |
| 239 | `ANCHOR` | Supports the primary layout when constructing a state/input anchor. Whole-state hashing may exceed the default transaction compute budget for large state. |

Stateful tag payloads begin with the v3 version byte. V3 preserves v2's
existing bounds: at most eight state spans, 10,000,000 aggregate engine-state
bytes, at most eight transitions per `ADVANCE`, at most 64 input slots in the
active write window, and state growth in 8,192-byte increments. Views support
up to 16 outputs; publication scratch is capped at 4,000,000 bytes. A renderer
workspace has a kernel-declared maximum. Kernel phase declarations are checked
against the 1,400,000-CU runtime declaration bound. These are designed limits,
not measured cost promises.

### Primary state and instruction account order

The layout selector is the last byte of the v3 `OPEN_SESSION` payload. With
selector `0`, state spans retain the 128-byte child header. With selector `1`,
state span 0 has no child header. Its schema, version, and length are recorded
in the authenticated session; later spans keep their child headers. On
`ADVANCE`, the primary data account is account 0, so an engine callback sees
its data address at the expected fixed location. For example, the tested order
is `[state0, authority, session, stream]`. The account address is checked
against the session's registered state key before any transition callback.

Read and mutable state spans omit the header only for this first primary
span. The callback-local `StateSpanMut::data_address()` therefore points at
the first application byte. Application code still must bind and clear any
engine context around every callback; no pointer is serialized.

### Prefix halt semantics

The v3 transition callback returns `Continue`, `HaltBefore { reason }`, or
`HaltAfter { reason }`. The stateful processor runs steps in order and commits
only successful transitions. `HaltBefore` leaves the triggering command
unconsumed; `HaltAfter` consumes and commits that command. In either case, the
session enters the halted state and records the reason and resulting cursor.
Thus the stream cursor agrees with the committed prefix. Ordinary refusal
paths continue to use transaction rollback, so state, stream, and session
remain unchanged on refusal.

### Phased initialization and rendering

`BEGIN_INITIALIZE` binds an initialization declaration to the current session,
state layout, exact aggregate state size, kernel-declared maximum phase bytes,
and compute units. Each `RUN_INITIALIZE` supplies the exact next byte cursor.
The callback receives the committed resource identity/schema/digest and the
phase range and writes only the declared state range. The phase cursor moves
forward until every declared byte has been initialized. Transition and render
state use refuse before completion. A stale phase cursor or mismatched session
schema refuses without changing state, session, or cursor.

For rendering, the kernel receives read-only resource bytes that are checked
against the session-bound key/schema/commitment, read-only state spans, and a
separate writable workspace account. The workspace is session-bound and
versioned alongside the state cursor. The view output remains staged in the
existing publication scratch until `COMMIT_PHASE`; workspace changes alone do
not publish output.

## Scaled SBF mechanics demonstration

`tests/stateful_v3_sbf_workload.rs` runs the feature-built SBF image in
ProgramTest. One test confirms that layout selector `0` keeps a headered
state. The primary-layout workload declares a 10,000,000-byte headerless
state and grows it in 1,220 bounded instructions, initializes it in 153
phases, and uses a 4,096-byte committed test resource plus separate renderer
workspace and publication scratch. A small fixed-address guard in the test
kernel checks that primary state begins at the expected account-0 data
address. The workload then performs a four-step `ADVANCE` whose third command
halts before execution: it commits two steps, records the halt reason and
cursor 2, and leaves the third command unconsumed.

The SBF test covers these exact instructions and controls:

- `OPEN_SESSION` (both primary and default layout), `CREATE_STREAM`,
  `WRITE_INPUT` (four primary-layout slots), `CREATE_STATE`, and 1,220
  `GROW_STATE` calls.
- `BEGIN_INITIALIZE` and 153 `RUN_INITIALIZE` phases, including wrong session
  schema, advance before initialization completes, and stale phase cursor
  refusals.
- `CREATE_VIEW` for output, renderer workspace, and publication scratch;
  `BEGIN_PHASE`, `RUN_PHASE`, and `COMMIT_PHASE` for a view that reads the
  authenticated resource and writes the workspace.
- `ADVANCE` with a substituted primary account, stale cursor, and a
  halt-before command after two committed steps.
- `ANCHOR` on the 10 MB primary state, which reaches the default ProgramTest
  200,000-CU budget and fails with `ComputationalBudgetExceeded`; the test
  confirms the anchor cursor and hash remain unchanged.

This test is a mechanics demonstration. The 4 KB resource and fixed test
kernel do not implement a WAD importer, Doom renderer, or useful engine
capability. In particular, rechecking the entire committed resource in each
initialization callback does not measure importing Doom's 4.4 MB WAD into its
9.7 MB context. The 10 MB state is exercised through initialization and
transition; the whole-state anchor is not successful at the default 200,000
CU ProgramTest budget. The test did not raise the compute budget to the runtime
ceiling, so the higher-budget anchor result remains open.

Per-instruction and per-phase measurements and reproduction commands are in
[`experiments/stateful-sbf-workload-v3-2026-09-30.md`](experiments/stateful-sbf-workload-v3-2026-09-30.md).

## Doom adapter work remaining

The Doom adapter still needs to select v3 explicitly, bind its actual state
schema and 9,734,160-byte context, and verify each transition against the
retained SIM/2 boundaries. It must pass the real WAD resource and authenticate
it efficiently across initialization phases, then implement deterministic
renderer chunks using the new workspace and measure each phase on the final
SBF image. The 4 KB fixture says nothing about WAD-to-context throughput or
render quality. If Doom requires a successful whole-context anchor, the
adapter also needs a measured anchor strategy or a state commitment design
that fits the relevant compute budget.
