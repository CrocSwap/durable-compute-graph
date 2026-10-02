# Design: tag-124 bounded replay interface v2

**Status:** proposed interface; no code changed and no protocol choice is frozen here.
Every undecided item is marked **OPEN**. The proposal targets revision-8 A16
PT2P forms and requires a new DCR1 version before it can change a ruling.

## 1. Problem and boundary

The reviewed DCG hook calls `replay_pt1` once with `output_range: None` and a
2,048-byte buffer. Its request has no validated M4 context or DCG-owned replay
cursor. Tag 128 can verify a complete DGR1 output stream and set its existing
verified flag, but the current tag-124 path does not require that flag or
compare `body.outputs`. The Basanos source has per-form chunk routines and
window routines; those routines are not yet represented by the generic hook
contract. An executor can therefore be unable to answer a legitimate A16
challenge and lose by timeout.

The intended split remains: **DCG** authenticates the challenge, owns all
progress and timeout state, compares every replay byte with the authenticated
claimed stream, and makes the ruling. **Basanos** supplies the frozen form
catalog, kernel implementation, and a byte-range adapter. It returns bytes and
cannot write progress, mark outputs verified, or select the verdict.

This is a design for a new versioned path. It does not turn local mechanics or
CU measurements into evidence of useful inference quality.

## 2. A16 form inventory

“Output bytes” is the frozen row's maximum concatenated DGR1 write length; an
instance's actual length is the sum of its authenticated write-row lengths.
The source CU column is **measured**: for forms 1–46 it is the frozen registry
`execute_cu` field, populated from local SBF measurements at the recorded
representative shape. It is not a measured cost for every A16 instance, a
worst-case guarantee, or a projected v2 chunk cost. Forms 47–48 use measured
tag-124 totals from the K=10,240, 80-read fixture. Chunk costs for the proposed
interface remain **unmeasured**.

| Form | Maximum output bytes | Current source replay pattern | Measured source CU | Proposed hook-v2 treatment |
|---:|---:|---|---:|---|
| 1 | 20,480 | single response | 248,727 | byte-range stream |
| 2 | 4,096 | unit-chunked | 510,636 | preserve unit boundaries; byte-range stream |
| 3 | 5,128 | single response | 517,981 | byte-range stream |
| 4 | 640 | row-chunked | 1,184,174 | preserve row chunks |
| 5 | 32,768 | single response | 410,507 | byte-range stream; pass M4 position-table root |
| 6 | 8,192 | single response | 42,589 | byte-range stream |
| 10 | 16,384 | unit-chunked | 366,577 | preserve unit boundaries; byte-range stream |
| 11 | 10,240 | single response | 139,182 | byte-range stream |
| 12 | 16 | single response | 316,872 | one bounded call |
| 13 | 16,384 | single response | 705,869 | byte-range stream |
| 16 | 8,192 | channel-chunked | 369,927 | preserve channel boundaries; byte-range stream |
| 17 | 16,384 | unit-chunked | 348,591 | preserve unit boundaries; byte-range stream |
| 18 | 512 | single response | 491,787 | one bounded call |
| 19 | 32,768 | unit-chunked | 358,318 | preserve unit boundaries; byte-range stream |
| 21 | 8,192 | unit-chunked | 346,571 | preserve unit boundaries; byte-range stream |
| 22 | 32 | single response | 306,581 | one bounded call |
| 27 | 560 | single response | 531,197 | one bounded call |
| 28 | 1,120 | single response | 101,360 | one bounded call |
| 29 | 2,048 | unit-chunked | 507,783 | preserve unit boundaries; byte-range stream |
| 30 | 263,168 | column-chunked, multiple writes | 906,530 | preserve column/write boundaries; byte-range stream |
| 40 | 1,040 | windowed | 1,332,804 | ordered window units; subdivide to meet CU target |
| 41 | 32 | windowed | 69,358 | ordered window units |
| 42 | 2,048 | windowed | 104,804 | ordered window units |
| 43 | 2,048 | windowed | 595,387 | ordered window units |
| 44 | 2,048 | windowed | 604,422 | ordered window units |
| 45 | 8 | windowed | 124,287 | ordered window units |
| 46 | 8 | windowed | 139,858 | ordered window units |
| 47 | 1,024 | single decision gather | 1,063,097 | one bounded call; pass instantiated PT1 entry |
| 48 | 1,024 | single decision gather | 502,550 | one bounded call; pass option table and PXR1 directory |

The 27 values for forms 1–46 come from retained revision-8 registry rows and
the local SBF census reports; those reports explicitly distinguish a measured
representative shape from a guarantee. Form 47/48 tag-124 measurements are
from the compiler-v1 K=10,240, 80-read G1 run. The Form 47/48 measurement is a
mechanics result for that fixture, not a form-wide maximum.

### Inventory gap

The named chunk/window set in the current engine review is 2, 4, 10, 16, 17,
19, 21, 29, 30, and 40–46. But the frozen rows also declare outputs above
2,048 bytes for forms 1, 3, 5, 6, 11, and 13. Those forms cannot fit the
reviewed hook's existing whole-output buffer either. They are included in the
byte-range proposal rather than silently omitted.

**OPEN:** reconcile the single-response classification for forms 1, 5, 6, 11,
and 13 against the exact A16 source revision and instance output lengths before
implementation. Also confirm whether form 3's 5,128-byte shape is the maximum
for every admitted A16 instance. If any declared form can emit more than its
row's `max_write_bytes`, fix admission or the source row before this interface
ships.

## 3. Proposed wire and DCG-owned progress

### Version boundary

Retain the current tag-124 dispatch and hook semantics for existing DCR1
versions, including any app-specific continuation payloads already in use.
The proposed bounded path requires a new DCR1 v7 record. The new v2 wire is
accepted only on v7; v5/v6 keep the old handler. This keeps old single-call
leaves, byte encodings, and verdict paths reproducible.

**OPEN:** whether the v7 path is selected for every A16 challenge or only
forms whose current response cannot fit one call. The default proposal is to
use it for all A16 forms, with a one-step completion for small outputs; this
keeps one well-defined tag-128 gate and one progress state machine.

### DCR1 tail record

The app-bound DCR1 v6 layout documents bytes `8100..8192` as unused. Prefer
using this 92-byte tail in DCR1 v7, rather than adding a progress PDA and rent,
address, and account-meta dependencies. The fixed record is:

```text
8100..8104  "RPR2"
8104..8106  version:u16 = 2
8106..8108  flags:u16       // bit 0 active, bit 1 tag128-complete, bit 2 complete
8108..8112  sequence:u32
8112..8116  total_output_bytes:u32
8116..8120  next_output_offset:u32
8120..8124  completed_chunk_count:u32
8124        mismatch:u8     // canonical 0 or 1; v2 treats mismatch as terminal
8125..8128  zero[3]
8128..8160  replay_digest[32]
8160..8192  claimed_digest[32]
```

DCG initializes this record only after tag 120 has authenticated the challenged
entry and its total output length has been computed from authenticated DGR1
write rows. Initialize `sequence`, `next_output_offset`, and
`completed_chunk_count` to zero and `mismatch` to zero. Seed both rolling
digests from the authenticated replay context. The adapter never sees a
mutable account slice. Each call checks
magic, version, reserved zeros, allowed flags, bounds, expected sequence,
expected offset, and the output-verification bit before invoking the adapter.
All offset addition is checked; offset and length are little-endian integers.

**OPEN:** use of the DCR1 tail depends on confirming that no later app-bound
extension owns these bytes. The alternative is a separately derived,
challenge-scoped progress PDA with an explicit close/refund policy.

### Tag 124 continuation

Proposed v7 instruction bytes are:

```text
tag:u8 = 124 | replay_version:u8 = 2 | sequence:u32le | expected_offset:u32le
```

The caller echoes the DCG-owned sequence and byte cursor to make stale,
duplicate, skipped, or reordered submissions fail explicitly. The caller does
not choose an arbitrary range or verdict. DCG derives the next range from the
authenticated total, ordered DGR1 write rows, and the selected form's
deterministic chunk schedule. For forms without native chunk units, choose
`min(1,024, bytes-to-next-write-boundary, bytes-remaining)`. For other forms,
the static application form descriptor may declare canonical row, channel,
unit, column, and window boundaries; DCG validates and advances that schedule.
The form descriptor and schedule must be covered by the selected application
identity. **OPEN:** settle the descriptor representation and its identity
encoding before freezing the API. Each range is contiguous in the
canonical output stream formed by concatenating DGR1 write rows in row order.

DCG passes the adapter `output_range = Some((offset, length))` and a buffer of
exactly `length` bytes. The adapter must return exactly that many bytes. A
short result, overlong result, unsupported range, or invalid form context is
a refusal with no progress update. The result is compared directly, byte by
byte, with `body.outputs[offset..offset+length]`; the app does not compare or
hash claimed output on DCG's behalf.

If any byte differs after tag 128 has authenticated the claim, DCG rules for
the challenger in that call and marks the mismatch terminal. If all bytes
match, DCG advances the cursor and sequence, updates both digests, and stores
the state atomically. The final range must end exactly at the derived total;
then the two rolling digests must match and DCG rules for the executor. No
caller-supplied progress can skip the final check.

Timeout before completion follows the existing DCR1 deadline and tag-132
timeout law: an abandoned live sequence is ruled against the executor. It
cannot turn incomplete replay into an executor win. Terminal tag-124 rulings
cannot be changed by timeout.

### Output digest accumulation

The per-chunk byte comparison is authoritative. A rolling digest provides a
compact consistency check over the exact ordered transcript and catches an
internal cursor/digest-state inconsistency at completion; it is not a
replacement for the DGR1 write digests and is not itself an inference claim.

Let `ordered_write_rows_digest = SHA256("dcg/tag124/write-rows/2" ||
write_count:u16le || ordered_raw_write_rows)`, where each row is the exact
48-byte DGR1 row in canonical order. Let `context =
SHA256("dcg/tag124/replay-context/2" || descriptor[32] || position:u32le ||
segment:u16le || entry:u32le || form:u16le || total_output_bytes:u32le ||
ordered_write_rows_digest[32])`. Seed:

```text
R0 = SHA256("dcg/tag124/replay-seed/2"  || context)
C0 = SHA256("dcg/tag124/claimed-seed/2" || context)
```

For an accepted range `(offset, length)` and its replay bytes `r` and claimed
bytes `c`:

```text
Rnext = SHA256("dcg/tag124/replay-step/2"  || Rprev || offset:u32le || length:u16le || r)
Cnext = SHA256("dcg/tag124/claimed-step/2" || Cprev || offset:u32le || length:u16le || c)
```

The context and step domains are distinct. A mismatch is terminal before a
successful final digest comparison. The byte encodings, domain strings,
version, and state offsets require golden vectors before adoption.

### Tag 128 gate

For v7, tag 128 must authenticate the *entire* claimed `body.outputs` stream
against every committed DGR1 write row, including exact concatenated length,
before it sets `tag128-complete` in RPR2. Tag 124 refuses until that bit is
set. This prevents a claimant from changing the compared stream between
replay calls and makes each tag-124 range comparison evidence about bytes
already bound to the leaf. The tag-128 flag and cursor are written by DCG only;
the adapter receives neither as mutable state.

The current one-call tag 128 can hash the borrowed body without copying the
whole output into the DCR1 scratch area. Its cost for the 263,168-byte Form 30
maximum has not been established here.

**OPEN:** measure tag 128 at maximum admitted output and under the actual
transaction meter. If it does not fit, specify a separately versioned,
DCG-owned tag-128 continuation that streams each DGR1 write digest and only
opens tag 124 after every write digest and total length are complete. Do not
set the flag from the application adapter.

## 4. M4 request context

Add immutable, borrowed validated views to `ApplicationReplayRequest`:

| Field | DCG source and validation | Consumer |
|---|---|---|
| `position_table_root: Option<&[u8; 32]>` | DCM2 `doc[296..328]`, exposed only after DCG validates the document and the form-5 artifact path | Form 5 |
| `option_table: Option<&[u8]>` | bounded option-table slice from validated DCM2 lengths and offsets | Form 48 |
| `pxr1_directory: Option<&[u8]>` | PXR1 directory/trailer view bounded by the validated route account and offsets | Form 48 |
| `instantiated_pt1_entry: Option<&ValidatedPt1Entry>` | DCG-owned PT1 instance after validating form, coordinates, and route metadata against DCM2/PT2S/PT1 | Form 47 |

These fields are `None` when irrelevant and are borrowed for the duration of
the call. Do not pass an unchecked byte offset for an adapter to resolve. For
PXR1, DCG must validate both the routes-account offset and the directory's
internal lengths before constructing the slice. The adapter may interpret
the validated view to compute kernel bytes; it cannot replace DCG's leaf,
route, read, write, or final-output checks.

**OPEN:** settle the exact public Rust types and whether the option/PXR1 views
are slices or parsed borrowed structs. Keep the wire representation and
validated semantics identical across implementations.

## 5. Resource limits

Proposed limits for the v2 tag-124 path:

| Resource | Proposed limit | Status |
|---|---:|---|
| Returned replay bytes per call | at most 1,024 bytes | **Designed**, needs SBF measurement |
| Per-call heap attributable to replay | no whole-stream allocation; output buffer at most 1,024 bytes; incremental adapter working set target at most 64 KiB | **Designed target**, needs heap instrumentation |
| Requested Solana heap frame | 256 KiB ceiling for qualification | **OPEN**, confirm assembly/runtime baseline |
| Total stream | authenticated DGR1 write sum; A16 frozen maximum is 263,168 bytes | **Measured row bound**, confirm every admitted instance |
| CU per tag-124 replay chunk | at most 1.2M CU | **Designed target**, not measured |

The 1.2M target leaves roughly 200K below the 1.4M transaction ceiling for
dispatch, validation, comparisons, hashing, and measurement margin. The
frozen Form 40 execute field is 1,332,804 CU, already above the chunk target;
its window schedule must split the kernel work further or the form cannot
qualify. The registry execute field is not the cost of the proposed v2 chunk.
Measure each maximum admitted form/shape, including the larger DGR1 writes,
M4 parsing, DCR1 updates, and both digest folds. Do not use a favorable average
chunk to qualify a heavier final chunk.

**OPEN:** approve the 1,024-byte cap and 64-KiB adapter working-set target only
after SBF measurements show that the range schedule actually stays under
1.2M CU and the full handler stays within the selected heap frame. A form with
no such bounded schedule must be excluded from the new manifest until fixed.

## 6. Compatibility and protocol versioning

- Existing DCR1 v5/v6 tag-124 calls keep the current handler, payloads, and
  comparison behavior byte-for-byte. No new cursor, tag-128 requirement,
  output ordering, or digest fold is applied to these records.
- DCR1 v7 is the opt-in boundary for the new tag-124 wire and RPR2 state.
- The adapter's one-call forms still return their same canonical result bytes;
  v2 simply requests bounded slices when the output exceeds the per-call cap.
- A new digest domain, wire version, DCR1 version, range schedule, or ruling
  timing change is consensus-sensitive. Publish it with golden vectors and an
  explicit DCG protocol/spec version. Keep the old route reproducible.

**OPEN:** confirm the owner-approved DCR1 v7 and DCG revision-8 versioning
scheme before implementation. This note alone does not authorize a protocol
change.

## 7. Required tests

These are implementation gates, not results claimed by this design:

1. **Honest chunked leaf:** for a representative multi-write A16 form, verify
   target, reads, required artifacts, and tag 128; submit every range in order
   in both honest role orders; assert exact cursor/digest progression and an
   executor win only after the last range.
2. **Cheat at chunk k:** use an authenticated claimed stream and an adapter
   fixture that changes one replay byte at a selected middle chunk. Assert
   that DCG compares the bytes itself, rules for the challenger at chunk k,
   and cannot be overridden by later calls or tag 132.
3. **Abandoned sequence:** submit a valid prefix, advance beyond the
   challenge deadline, and exercise tag 132. Assert a timeout ruling against
   the executor, no executor win from a partial digest, and no ability to
   resume the terminal record.
4. **Forged progress:** submit skipped, repeated, reordered, overflowing, and
   out-of-range offsets/sequences; assert refusal before the app hook and no
   state change. In the program test harness, mutate RPR2 magic/version,
   flags, reserved bytes, cursor, count, and digest fields to malformed
   combinations and assert fail-closed behavior. On chain, DCR1 owner checks
   prevent a caller from writing this program-owned state directly.
5. **Compatibility:** retain old v5/v6 tag-124 golden cases and
   assert identical handler inputs and ruling/state bytes. Assert those
   records never enter the v2 RPR2 state machine.

Add golden vectors for RPR2 encoding, all digest seeds/folds, empty/small/full
stream boundaries, odd write counts, and a final partial range. Exercise both
role orders and a malformed or deliberate-cheat path. These are required
before a protocol version is frozen.

## 8. Implementation plan and effort

The switchover must keep Basanos forms and model meanings app-local. This is
the replay-adapter slice of switchover package A (the kernel ABI/replay adapter
work, referred to here as package A2); it must preserve tag-124 PT1 semantics.

| Workstream | Scope | Estimated effort |
|---|---|---:|
| DCG core | Define DCR1 v7/RPR2 and version gate; add v2 wire parsing; derive ranges from authenticated rows and a fixed schedule; add M4 validated views to the hook request; make tag 128 gate tag 124; compare ranges, update state and digests, and apply terminal/timeout laws; add golden and adversarial tests. | **Estimated 3–5 engineer-days** |
| Basanos adapter (switchover package A2) | Implement the new request fields and byte-range bridge; map every one of the 29 A16 forms, preserve native row/unit/channel/column/window boundaries, resolve the oversized single-response inventory, and add form parity fixtures. Keep kernels, registry, artifacts, and decision semantics local. | **Estimated 4–7 engineer-days** |
| Integration and qualification | Reconcile source inventory, measure each worst-shape chunk and tag 128, calibrate heap/CU limits, exercise the five gates above on-chain/local SBF harnesses, and update the protocol/evidence records for the chosen version. | **Estimated 2–4 engineer-days**, excluding testnet scheduling |

Core API and DCR1 state shape are prerequisites for adapter implementation.
Do not let the adapter invent cursor rules or parse raw DCM2/PXR1 offsets. The
integration owner must update the relevant DCG spec, Basanos terminology,
decisions, evidence row, and CLI help only when a new protocol version is
actually selected.

## 9. Source basis and limits

Reviewed DCG hook/API source: `fadeno/dcg-2b-engine-b` at `214c16e`, especially
`crates/dcg-program/src/closure_v2_generic.rs`,
`crates/dcg-program/src/app_api.rs`, `docs/application-api.md`, and
`docs/spec/app-bound-replay-v1.md`. This is a review checkout, not the fresh
clone receiving this design. Fresh clone baseline is standalone DCG `main` at
`e039b48`.

Reviewed Basanos source: `fadeno/dcg-2b-engine-b` at `73febc528`,
`chain/dcg-program/src/closure_v2_generic.rs`, plus the revision-8 frozen row
and testnet experiment records. Relevant reports include
`docs/experiments/rev8-f-census-part3-2026-09-27.md`,
`docs/experiments/rev8-g1-f47-48-dispute-cost-2026-09-29.md`, and
`docs/experiments/rev8-a16-full-document-testnet-2026-10-01.md`. The A16
full-document report is explicitly mechanics evidence; it does not establish
faithful inference, cross-machine determinism, or useful model quality.

No build, test, SBF run, or chain transaction was performed for this design.
All proposed interface/resource values are design targets until the stated
measurements and protocol decisions are complete.
