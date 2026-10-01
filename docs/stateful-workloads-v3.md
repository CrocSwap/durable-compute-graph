# Stateful workloads v3 (local prototype)

Status: designed and implemented as an additive stateful wire version. V1 and
v2 remain available, and their wire bytes are unchanged. V3 changes
stateful-layer semantics and uses distinct account discriminators and PDA
seeds; it does not change revision-8 instructions or goldens. The default
revision-8 entrypoint does not dispatch app-owned stateful tags. The SBF
ProgramTest evidence is a mechanics demonstration, not an engine capability
claim.

V3 is selected by wire version byte `3`. Tags 230–239 retain the stateful
session surface; tag 240 carries resource-copy growth and chunk upload. Session,
stream, state, view, scratch, workspace, resource, and anchor accounts use
`DSS3`, `DSB3`, `DSE3`, `DVW3`, `DRS3`, and `DAN3` records with versioned v3
PDA seeds. The stateful processor routes these instructions to a selected
static kernel; the application composes the helper with its existing
instruction handler.

**Composition constraint:** do not compose the headerless primary layout
(selector `1`) into an image that also dispatches revision 8 or stateful v1/v2
handlers. A headerless primary can be sized to resemble a legacy session
record. V1 and v2 now re-derive their session addresses; revision-8 handlers
still authenticate some records by owner and contents alone. Keep this layout
in a v3-only dispatch image or enforce an equivalent routing boundary.

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
| 239 | `ANCHOR` | Supports one-shot anchors up to 65,536 bytes under `dcg/state-anchor-one-shot/3` and phase-locked chunked anchors for larger state under `dcg/state-anchor-chunked/3`. |
| 240 | `RESOURCE_COPY` | `RESOURCE_GROW` increases the program-owned copy by at most 8,192 bytes. `RESOURCE_CHUNK` verifies one Merkle proof and copies one source chunk; the copy is sealed once every chunk is present. |

Stateful tag payloads begin with the v3 version byte. V3 preserves v2's
existing bounds: at most eight state spans, 10,000,000 aggregate engine-state
bytes, at most eight transitions per `ADVANCE`, at most 64 input slots in the
active write window, and state growth in 8,192-byte increments. Views support
up to 16 outputs; publication scratch is capped at 4,000,000 bytes. A renderer
workspace has a kernel-declared maximum, bounded by the 10 MiB SVM account-data
limit separately from publication scratch. Kernel phase declarations are
checked against the shared `MAX_DECLARED_KERNEL_COMPUTE_UNITS` constant. The test
kernel declares initialization at 90% of that constant, below the
1,289,567-CU compatibility target for the seam-fix work. These are designed
limits, not measured cost promises.

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

Every checked session decodes its stored `(authority, id, bump)` and
re-derives the PDA under `dcg-session-v3`, then checks that the derived address
matches both the account key and stored `self_key`. Instructions with an
independent authority signer or refund destination use that supplied key as
the authority seed; instructions without one derive from the session's stored
authority. State,
stream, resource, view, workspace, scratch, and anchor readers also check the
PDA derived from the session account key. The headerless primary must be the
derived state PDA at index zero in both state access and close. The v1 and v2
session checks also re-derive their PDA from the stored authority and id without
changing either wire format. This does not relax the composition constraint
above for revision-8 handlers.

### Prefix halt semantics

The v3 transition callback returns `Continue`, `HaltBefore { reason }`, or
`HaltAfter { reason }`. The stateful processor runs steps in order and commits
only successful transitions. `HaltBefore` leaves the triggering command
unconsumed; `HaltAfter` consumes and commits that command. In either case, the
session enters the halted state and records the reason and resulting cursor.
Thus the stream cursor agrees with the committed prefix. Ordinary refusal
paths continue to use transaction rollback, so state, stream, and session
remain unchanged on refusal. For aggregate state at or below 8,192 bytes the
adapter uses one reusable snapshot buffer and refuses a `HaltBefore` callback
that changed state. Above that cap, leaving state unchanged on `HaltBefore`
remains a kernel obligation.

### Phased initialization and rendering

`BEGIN_INITIALIZE` binds an initialization declaration to the current session,
state layout, exact aggregate state size, kernel-declared maximum phase bytes,
and compute units. If the session names a resource, `BEGIN_INITIALIZE` also
requires its program-owned copy to be sealed, with every committed chunk
present. Each `RUN_INITIALIZE` supplies the exact next byte cursor.
The callback receives the committed resource identity/schema/digest and the
phase range and writes only the declared state range. The phase cursor moves
forward until every declared byte has been initialized. Transition and render
state use refuse before completion. A stale phase cursor or mismatched session
schema refuses without changing state, session, or cursor.

`HALT_SESSION` is allowed during initialization and clears any open phase, so
a permanently failing phase can be halted and its children closed for rent
recovery. A one-call initializer cannot run after phased initialization has
started or completed.

For rendering, the kernel receives read-only resource bytes that are checked
against the session-bound key/schema/commitment, read-only state spans, and a
separate writable workspace account. The workspace is session-bound and
versioned alongside the state cursor. The view output remains staged in the
existing publication scratch until `COMMIT_PHASE`; workspace changes alone do
not publish output.

The ordinary `RUN_PHASE` account order keeps a headerless primary state span
first. A fixed-address engine may opt into the additive workspace-first order
for `RUN_PHASE` only: `[workspace, authority, session, resource?, state spans,
view outputs, publication scratch]`. This makes the workspace account the
invocation's first data region. It validates the same session, state, view,
resource, workspace, and scratch PDAs as the ordinary order, then normalizes
the spans for the kernel callback. A view may receive writable transaction
privileges on state accounts; each application kernel must enforce its own
state-write contract. For example, Doom refuses writable state spans in its
renderer.
`BEGIN_PHASE`, `COMMIT_PHASE`, and `ABORT_PHASE` keep
the ordinary account order. A kernel that opts into this path may temporarily
use the authenticated 128-byte workspace child header as fixed-address engine
bytes during its callback; the processor snapshots the header before each
callback and refuses if any of its 128 bytes differ when the callback returns.

By default, `BEGIN_PHASE` clears the workspace payload. A kernel may opt out
when it overwrites every byte it relies on before reading the workspace in a
new publication. The view cursor still starts at zero, outputs remain staged,
and transaction rollback still covers callback changes.

At `OPEN_SESSION`, the caller names a read-only source account and commits a
Merkle root over its 65,536-byte chunks. The program creates a `DRS3`
program-owned copy, initially allocating at most 8,192 data bytes. Tag 240
grows it in at most 8,192-byte steps; each step is a separate instruction.
`RESOURCE_CHUNK` verifies a proof under `dcg/resource-chunk/1`, copies the
proved chunk, and sets its one-time bitmap bit. Leaves bind chunk index, total
resource length, and bytes; internal nodes use `dcg/resource-node/1` and
duplicate the last node at odd widths. Initialization and rendering use the
sealed copy and check its program ownership, structure, and bitmap count
without re-hashing the entire resource on each callback. The copy is immutable
through the stateful API after it is sealed.

`BEGIN_PHASE` zeros the workspace payload before each publication. `ANCHOR`
creates a session-bound `DAN3` account and processes 65,536-byte state slices
under the phase lock. Chunked anchors use the
`dcg/state-anchor-chunked/3` domain; the one-shot path uses the distinct
`dcg/state-anchor-one-shot/3` domain and requires the active session authority
to sign. `ADVANCE` refuses while the anchor phase is open. A small state can
still use the one-shot v3 anchor path. After the session halts, a finished or
abandoned anchor can be closed as a child account to recover its rent.

State spans are closed from the highest index down. Each close subtracts that
span's declared length and then reduces the live span count, keeping the
remaining session record decodable until the final span and session are closed.

## Scaled SBF mechanics demonstration

`tests/stateful_v3_sbf_workload.rs` runs the feature-built SBF image in
ProgramTest. The measured workload grows a 10,000,000-byte headerless primary
state in 1,220 bounded instructions and initializes it in 153 phases. A
chunked anchor over all 10 MB completes in 153 slices. The suite also covers a
4.4 MB synthetic resource, a permanently failing initialization, forged
session-shaped primary bytes, another session's primary at index zero,
two-advance primary-plus-headered spans, view cleanup, and prefix halt cases.
A small fixed-address test kernel still says nothing about Doom engine quality.

The 4.4 MB synthetic resource required 537 separate 8,192-byte allocation
steps and 68 proof-checked upload chunks. Measured resource growth cost was
13,361–30,892 CU per step; chunk upload cost was 17,137–45,672 CU per chunk.
The source account was changed after upload, and initialization still read the
original bytes from the sealed program-owned copy. This is mechanics evidence
for content binding and storage scale, not a Doom WAD importer result.

The 10 MB anchor completed with 153 chunk calls at 38,518–52,024 CU each.
Chunk work totaled 7,946,015 CU; begin and finish brought the lifecycle total
to 7,975,750 CU across separate instructions. Closing the finished anchor cost
21,375 CU. These are measured SBF
transactions, not one transaction and not a claim about Doom's 9.7 MB state
cost or chain compute limits.

Per-instruction and per-phase measurements and reproduction commands are in
[`experiments/stateful-sbf-workload-v3-2026-09-30.md`](experiments/stateful-sbf-workload-v3-2026-09-30.md).

## Doom adapter work remaining

The Doom adapter still needs to select v3 explicitly, bind its actual state
schema and 9,734,160-byte context, and verify each transition against the
retained SIM/2 boundaries. The 4.4 MB synthetic resource does not contain or
validate the actual WAD, and this test kernel does not import it into Doom's
context or render Doom frames. The adapter must measure those operations on
the final SBF image. The chunked 10 MB anchor is a mechanics path; it does not
establish chain fit, Doom correctness, or renderer quality.
