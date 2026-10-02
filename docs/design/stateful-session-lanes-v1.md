# Stateful session lanes v1 (draft)

Status: **draft design for review, 2026-10-02.** Nothing here is implemented.
It proposes an additive extension of stateful v3 so one session can keep
several publications in flight. Numbers are labeled *measured* (with a source)
or *estimated*; estimates are not capability claims.

## 1. Problem

A v3 stateful session is a total order. Three rules in `stateful_v3.rs` make it
one:

1. **One cursor.** Every input, transition and publication is bound to the
   session's single `cursor`, and a step for any other cursor refuses with
   `REFUSAL_CURSOR` (2329) or `REFUSAL_PHASE_CURSOR` (2335).
2. **One phase lock.** The session holds one `phase` (`NONE`, view
   publication, initialization or anchor). `ADVANCE`, `BEGIN_PHASE` and the
   other phase openers refuse unless it is `NONE`. A publication therefore
   blocks the next transition from the moment it begins until it commits or
   aborts.
3. **One write set.** Every stateful instruction writes the session record,
   and every publication writes the same workspace and scratch. The leader
   must run them one after another, and a step that arrives early is refused
   rather than queued.

So a session's rate is bounded by one round of dependent work per published
output: the chain time of the whole round plus the time before its last step
is visible, regardless of how much of that work is independent.

**Measured on Fogo testnet (Doom on DCG, 2026-10-01/02, status page
`fast-path-status-2026-10-01.md`):**
- a packed frame is 17 transactions over 7–8 slots, about 0.32 s on chain,
  visible about 0.57 s after sending;
- 1.66 frames/s, 45/45 clean, from a host 1.6 ms from the RPC node;
- overlapping two frames was refused (`2329`) in every form tried, including
  a 0.5 s delay, because the next frame's steps land while the previous
  frame's phase is still open.

The pre-DCG Doom program reached 3.35 pictures/s (measured 09-28) with four
render buffers: frame N rendered into buffer k while frame N+1 advanced, and
the chain used about 14M CU/s at peak, below the block budget. The difference
is not compute; it is that DCG cannot express the independence.

This is a general limitation, not a Doom one: any session that produces a
published output per transition (games, simulations, order-book snapshots,
any "publish N while computing N+1" shape) is held to one round per output.

## 2. Goals and non-goals

Goals:
- Let a session keep up to L publications in flight while transitions
  continue, with the heavy rendering work outside the session's write set.
- Keep every existing guarantee: inputs are consumed exactly once in cursor
  order; a published output is bound to the exact committed state version it
  was rendered from; refusals stay transaction-atomic; halt and close recover
  rent.
- Be additive: a session opened without lanes behaves byte-for-byte as v3
  today, and v1/v2/v3 wire bytes and goldens do not change.

Non-goals:
- Concurrent transitions. The transition chain stays strictly ordered; it is
  inherently serial.
- Reordering or queueing early arrivals on chain. A step that is not yet
  admissible still refuses; lanes shrink what must be ordered, they do not
  make the program tolerate disorder.
- Copy-on-write state. Section 7 lists it as a later option.

## 3. Model

A session declares `L` **render lanes** (1 ≤ L ≤ 4) at open. Lane `k` owns:
- a lane record `DLN3` at PDA `["dcg-lane-v3", session, k]`;
- its own renderer workspace and publication scratch (PDAs as today, with the
  lane index in the role seed);
- its own view outputs, or a share of the session's views (open question 2).

The session keeps the transition chain: stream, state spans, `cursor`. It
gains one field, `capture_mask: u8`, a bit per lane that is currently
capturing state.

A publication on lane `k` has three stages:

1. **Capture** (`LANE_CAPTURE_BEGIN`, `LANE_CAPTURE_RUN`×m,
   `LANE_CAPTURE_END`). Copies the state the renderer needs from the state
   spans (read-only) into the lane workspace, at the session's current cursor
   `c`. Begin sets the lane's bit in `capture_mask` and records `c` in the lane
   record; end clears the bit. **`ADVANCE` refuses while `capture_mask != 0`**,
   so the state cannot move under a capture. This is the only cross-lane
   exclusion.
2. **Render** (`LANE_RUN_PHASE`×n). Reads the lane workspace, the
   session-bound resource and the session record **read-only**, and writes
   only the lane's own workspace and scratch. It does not touch the state
   spans or the session record, so it does not conflict with `ADVANCE` or with
   other lanes.
3. **Commit** (`LANE_COMMIT`). Publishes the staged output with its source
   cursor `c`. It refuses if `c` is older than the newest cursor already
   published (a lane that finishes late is dropped, see 4.4), then frees the
   lane.

The transition chain only waits for captures. A frame's critical path becomes
`ADVANCE → CAPTURE`; rendering of frame N overlaps the advance and capture of
frame N+1 on another lane.

## 4. Rules

### 4.1 Account write sets

| Instruction | Writes | Reads |
|---|---|---|
| `ADVANCE` (unchanged) | session, stream, state spans | resource |
| `LANE_CAPTURE_BEGIN/END` | session (`capture_mask`), lane record | — |
| `LANE_CAPTURE_RUN` | lane workspace, lane record | session, state spans, resource |
| `LANE_RUN_PHASE` | lane workspace, lane scratch, lane record | session, resource |
| `LANE_COMMIT` | lane record, lane views, publication index | session |
| v3 `BEGIN/RUN/COMMIT_PHASE` (lanes off) | as today | as today |

Render steps on different lanes share no writable account, and none shares
one with `ADVANCE`. `LANE_CAPTURE_RUN` writes only its lane but reads the
state spans that `ADVANCE` writes; the `capture_mask` gate makes that
ordering explicit instead of relying on the leader.

### 4.2 Lane state machine

`IDLE → CAPTURING(c) → RENDERING(c) → IDLE` per lane, with `ABORT` from
`CAPTURING` or `RENDERING` back to `IDLE` (clearing the capture bit if set).
Every lane step carries `(lane, c, phase_cursor)` and refuses on any mismatch
with the lane record, with new codes:

| Code | Meaning |
|---:|---|
| 2338 | `REFUSAL_LANE` — unknown lane, lane not declared, or lane busy |
| 2339 | `REFUSAL_LANE_CURSOR` — `c` or the lane phase cursor does not match |
| 2340 | `REFUSAL_CAPTURE_OPEN` — `ADVANCE` while a capture is open |
| 2341 | `REFUSAL_STALE_PUBLICATION` — commit older than the newest published cursor |

`LANE_CAPTURE_BEGIN` requires `session.cursor == c`, an initialized state,
session phase `NONE` (lanes do not use the session phase lock), and the lane
`IDLE`.

### 4.3 What the renderer may read

The renderer sees only its lane workspace (the captured state), the
committed resource, and read-only session fields. It never sees the live
state spans, which may already be at a later cursor. The captured bytes are
bound by recording `c` and the kernel-declared capture range in the lane
record; the commit carries `c` into the publication so a reader can tie the
output to state version `c`.

### 4.4 Publication order

Views carry a publication index `(cursor, lane)`. `LANE_COMMIT` refuses a
cursor below the newest published one, so outputs are monotonic for readers.
A lane that loses that race aborts (or its commit refuses and the client
aborts it); its render work is wasted but nothing is published out of order.
Two lanes may never capture the same cursor.

### 4.5 Halt, close and rent

`HALT_SESSION` is allowed with lanes in any state; it clears `capture_mask`
and marks every lane closable. Lane records, workspaces and scratch close as
session children (highest lane first) with the existing refund rules. Rent
scales with L: each Doom lane adds a 10.46 MB workspace (*measured* rent for
one workspace on testnet: 72.8 FOGO).

## 5. Compatibility and wire

- `OPEN_SESSION` v3 gains an optional trailing `lanes: u8`; absent or `0`
  means no lanes and today's exact behavior. A session with lanes refuses the
  single-workspace `BEGIN_PHASE` path.
- New subtypes under tag 236 (`LANE_*`), with the existing v3 version byte;
  no new top-level tag. `DLN3` is a new discriminator; existing record layouts
  are unchanged except the session's `capture_mask` byte. It should come from
  unused bytes of the 1,280-byte `DSS3` record so v3 sessions without lanes decode
  identically; that the space is free is **not yet checked**.
- The kernel interface gains a capture declaration (which state ranges a
  render needs, and its compute) alongside the existing phase declaration.

## 6. Doom mapping and estimate

Today's packed frame: inputs and two advance pairs, snapshot copies into the
single workspace, view strips, commit — all on one write set.

With lanes, frame N on lane `N mod L`:
- serial: `WRITE_INPUT`/`ADVANCE` (≈0.6M CU), then the capture of the
  renderer's state (Doom's existing snapshot-copy work, today 10 copies
  folded into multi-phase instructions);
- parallel: the strips (about 600k–960k CU each) and the commit, on lane-only
  accounts.

*Estimated:* the serial path is the advance plus capture, about 3–4 slots
(0.12–0.16 s) if capture costs what today's snapshot copies cost, which
would allow about 3–4 frames/s from the chain side with L = 3, before the
per-frame client overhead. Visibility latency (about 0.25 s) no longer limits
throughput because the client does not wait for frame N's commit before
sending frame N+1's advance. **Open:** whether Fogo's leader actually runs
the lane renders in parallel within a slot; the 10 ms-per-instruction load of
Doom's 26 MB account set still applies per instruction; capture may dominate
and need copy-on-write (7.1).

## 7. Alternatives and later options

1. **Copy-on-write / double-buffered state.** Two state buffers alternate per
   cursor, so a render reads buffer A while `ADVANCE` writes B, with no copy.
   Removes capture cost; doubles state rent and changes the state-span model.
   Worth doing if capture is the measured bottleneck.
2. **Multiple sessions.** One session per frame lane, with an off-chain
   hand-off of state, is possible today but breaks the single committed state
   chain and its input-exactly-once guarantee. Rejected.
3. **Queueing early arrivals on chain.** Accepting a step for cursor c+1 and
   parking it until c commits needs per-step storage and still serializes the
   work. Rejected.

## 8. Test plan

- ProgramTest (SBF), lanes off: the full v3 suite unchanged, and v3 goldens
  identical.
- Lanes on:
  - capture/advance exclusion (2340);
  - lane cursor mismatches (2339);
  - render steps never write session or state (account-privilege check);
  - two lanes rendering interleaved;
  - a late commit refused (2341) and then aborted;
  - halt with lanes in each state;
  - close order and rent reclaim;
  - a forged lane record from another session;
  - an output's bound cursor matching the state it was captured from.
- Adversarial: a renderer that tries to read live state, a capture that tries
  to write state, a commit for a cursor never captured.
- Doom on testnet: frames/s and frame-hash equality against the local golden
  at L = 1, 2, 3, against the 1.66 frames/s single-lane baseline and the 3.35
  reference.

## 9. Decisions for the owner

1. Capture-copy (this draft) or copy-on-write state first.
2. Per-lane views with a publication index (this draft), or shared views
   committed in order.
3. Maximum lanes per session (draft: 4) and whether rent for lane workspaces
   is acceptable for the Doom demo.
4. Whether render steps may read the session record at all (for binding), or
   only the lane record, to keep their write and read sets minimal.
5. Version: subtypes under v3 (this draft) or a new stateful wire version.
