# Real-time transaction transport v1

**Status: designed; implementation and live behavior are open.** This note is
based on DCG `main` at `057f088` (which already contains the Python
`dcg.sequencer`) and the Basanos source snapshot at `8bfdfbb7e121`. The Doom
adapter reference is Basanos branch `fadeno/doom-dcg-r7b`, commit `8f082eac6`.
No implementation, build, test, chain transaction, Doom relayer run, or Tokyo
access was part of this design task.

## Decision and scope

The owner decision dated 2026-10-01 is to move generic real-time transaction
transport from the Basanos Doom senders into DCG's Python `dcg.sequencer`. Doom
on DCG testnet part 2 will use that client. The application keeps Doom sessions
and idle handoff, the provisioned slot and workspace pool, snapshot hashing,
input and cursor order, rent and fees, and Doom's state and rendering rules.

This selects the Python package that already exists on DCG `main`. The
2026-09-30 Basanos client census still recommends a TypeScript-first client in
its “Proposed DCG client experience” section. That recommendation is
superseded for this work by the owner decision and by DCG's current Python
sequencer; retain the census as historical analysis and reconcile its future
recommendation when that source note is next edited. The separate Doom port
plan already records the owner's Python-first choice and identifies this
disagreement as needing reconciliation.

The current API is a finite `TransactionPlan` of dependency-aware steps. Each
step has explicit write locks, packet and compute limits, an intent digest,
postcondition, and retry policy. The sequencer bounds in-flight work and
resends the journaled signed bytes; the RPC adapter checks genesis before
leasing a blockhash. The proposal below adds a streaming plan alongside that
API, and makes routing and sending provider-pluggable. It does not move
instruction construction, account semantics, state recovery decisions, or
application economics into DCG.

## 1. Real-time transport inventory

The line references name the checked-in Basanos snapshot listed above.
“Generic” means the transport mechanism moves to `dcg.sequencer`; it does not
make the Doom account or retry policy generic. “Application” means the decision
remains in Doom's adapter or relayer.

| Technique | Classification | Source and disposition |
|---|---|---|
| Per-node RPC pacing, 429 classification, round-robin send selection, and bounded RPC work | **Generic mechanism** | `scripts/doom_r8b_tokyo_pipeline.py:432–505, 555–697`; analogous weighted routing and same-byte failover in `chain/high_throughput_sender.py:103–182`. Move the scheduler and per-node counters/caps. Rates and endpoint allowlists remain caller configuration. |
| Endpoint health, lag checks, cooldown, removal and resynchronization | **Generic mechanism; app supplies health meaning** | `scripts/doom_relayer_server.py:831–999, 1035–1116`; health-aware uploader precedent `chain/driver_upload.py:89–202`. DCG should score nodes, cool them, and probe them back in. Doom continues to decide which cursor/account observations establish useful session progress. |
| Shared confirmation queue and batched status polling for render work | **Generic** | `scripts/doom_r8b_tokyo_pipeline.py:1863–2002` (`StatusCollector`). One status pump should cover every lane and stream, not one poller per frame or lane. Preserve batching, a poll floor, and bounded outstanding work. |
| Blockhash cache/lease and signed packet submission | **Generic mechanism; rebuild authorization is app policy** | `scripts/doom_r8b_tokyo_pipeline.py:823` and `:1180–1213`; sequencer precedent is [blockhash and packet handling](../../python/dcg/sequencer/core.py#L752). Keep the lease's genesis/source/expiry facts. A blockhash refresh never implies permission to re-sign an unresolved step. |
| Multi-frame and multi-buffer pipeline | **Generic dependency scheduler plus app graph** | `scripts/doom_r8b_tokyo_pipeline.py:2016–2075, 2296–2315, 2449–2529, 2988–3018`; lane precedent `chain/stepc_engine.py:105–114, 365–402`. DCG schedules ready steps across independent write-lock sets. Doom declares which cursor, snapshot, workspace and strip steps depend on each other. |
| Readback, cursor resync, and recovery after uncertain sends | **Generic journal/reconcile mechanism; app supplies postconditions and recovery policy** | `scripts/doom_r8b_tokyo_pipeline.py:3751` and `scripts/doom_relayer_server.py:1035–1116`. A signature observation is not a Doom cursor. The adapter reads the relevant session/context/workspace state and decides whether a new intent is safe. |
| Python-to-Rust TPU/QUIC send path | **Generic provider implementation** | `chain/tpu_transport.py:132–194`; `chain/tpu_sender.py:385–438, 647–658, 714–720, 1146–1192`; `chain/tpu-sender/src/main.rs:1547–1634`; framing contract `chain/tpu-sender/README.md:82–103`. Reuse the signed-byte pipe as a send-only provider; keep confirmation in the shared RPC observer. |
| Doom session admission, slot pool, public-player arbitration, idle pause/handoff, and public frame stream | **Application** | `stunts/doom-relayer/pool.mjs:34–180`, `public-mode.mjs:50–75, 317–357, 378–448`, `sender.mjs:329–365, 767–770`, `server.mjs:148–282, 994–1004, 1127–1261`. Keep these policies in the Doom service. The bounded browser frame stream is not the transaction journal. |
| Doom command mapping, player/input ordering, cursor thresholds, RESET/rollover, snapshot identity/hash, render-buffer reuse, strip assembly, and pixel validation | **Application** | `scripts/doom_relayer_server.py:198–329, 1035–1165, 1641–1807, 2203–2473`; `scripts/doom_r8b_tokyo_pipeline.py:286, 2016–2075, 2296–2529`; DCG Doom workspace behavior at `stunts/doom-dcg/src/lib.rs:527–823, 1118–1216`. None belongs in the sequencer's generic step executor. |
| Slot count, per-node configured rate, compute budgets, rent, fees, spending caps, and endpoint credentials | **Application/operator configuration** | Doom flags and checks include `scripts/doom_relayer_server.py:350–380, 680–721, 831–979`; testnet relay setup is in `stunts/doom-relayer/server.mjs:1348–1469`. DCG validates that a configured cap is positive; it must not invent a universal network rate, CU budget, payer, or spend limit. |

The general helpers are evidence of reusable patterns, not modules to copy
wholesale. `high_throughput_sender.py` and `driver_upload.py` encode Fogo- and
caller-specific assumptions; `stepc_engine.py` carries a lane engine but not
the durable plan identity and ambiguous-fate contract already present in DCG.
The DCG core remains the safety boundary.

## 2. `dcg.sequencer` API changes

### Endpoint pool and routing

Add an `EndpointPool` over named RPC nodes, retaining an `RpcEndpoint` per
node. Each node configuration has its own configured send rate, total RPC
request rate, in-flight cap, weight, and route group. Admission, status polling,
blockhash fetches, account reads, and health probes share that node's request
budget so a render readback cannot bypass the limiter that protects sends.
Configured values are local caps, not measured chain capacity.

Track a decaying health score from classified 429s and `Retry-After`, transport
errors, timeouts, request latency, `getHealth`, and observed slot/status lag.
When a node crosses the configured threshold, set a cooldown and route around
it. After cooldown, send a bounded probe before admitting normal work again;
do not permanently discard a node merely because a public endpoint briefly
throttled. If all eligible nodes are cooling or at their in-flight cap, apply
backpressure and expose the wait instead of creating an unbounded queue.

An optional `route_affinity` names a prior step or lane. Prefer its node for a
dependent step while it is healthy, which can reduce endpoint skew and keep
related traffic on a consistent RPC view. Affinity is best effort: fallback
may send the *same signed bytes* elsewhere. It does not promise landing order,
shared cache state, or commitment. The dependency graph and postcondition still
decide when downstream work may proceed.

The plan identity binds the eligible pool and route policy; each attempt records
the selected node and provider. On startup/resume, check `getGenesisHash` for
every RPC endpoint eligible to build leases or observe state and fail closed on
a mismatch. A TPU provider is bound to a checked RPC observer/cluster identity.
Store which endpoint supplied each lease; do not let a stale or cross-genesis
lease silently enter the pool.

### Send providers: RPC and TPU/QUIC

Separate the send interface from status and account observation. A proposed
`SendProvider.send_raw(raw_bytes, expected_signature, route)` returns only a
transport receipt or a classified send error. `RpcSendProvider` wraps
`sendTransaction`; `TpuQuicSendProvider` wraps the Rust TPU sender. The RPC
observer remains responsible for signature statuses, genesis, blockhashes,
account reads, and postconditions because the existing Rust helper is a
fire-and-forget sender.

Python reaches the Rust sender through the existing persistent subprocess
wrapper: `TpuSender` writes a little-endian length followed by the signed wire
packet to helper stdin and reads transport errors/statistics from stdout. The
Rust process forwards the bytes to leader QUIC endpoints. The sequencer signs
using its injected Python `Signer`, appends and fsyncs `step_signed` with the
exact bytes, then hands that byte string to either provider. Rust receives no
key, signing callback, unsigned message, or authority to rebuild a transaction.
The journal is the durable custody boundary; helper queues and acknowledgments
are not a second source of truth. On helper restart, only the Python journal
can authorize re-sending, and it resends the saved bytes.

This wrapper design reuses the existing signed-wire interface and preserves
the 1,232-byte cap. Build and package the Rust helper as an explicit DCG runtime
dependency rather than importing Basanos private modules. Keep helper version,
bind addresses, QUIC fanout, and per-helper rate as provider configuration.
None of those values is a global default or a measured DCG promise.

### Open-ended streaming plans

Keep `TransactionPlan` and `submit`/`resume` for finite jobs. Add a separate
`StreamingPlan` for an application that appends work while the sequencer is
running:

```python
stream = await sequencer.open_stream(identity, journal, limits=stream_limits)
await stream.append(step)       # fsynced intent; waits when the queue is full
await stream.checkpoint()       # waits for and records an app-selected boundary
await stream.close_input()      # no more steps; drain or leave resumable work
```

`identity` fixes genesis, program, destinations, signers, app run/session ID,
and the allowed route/commitment policy. Each appended step has a monotonic
stream sequence, stable step ID, dependencies on earlier steps, an intent and
recovery-policy digest, packet/CU limits, and write locks. Re-appending a
retained ID with the same digest is idempotent; the same ID with a different
digest is a plan error. New work cannot depend on an undeclared future step.

Use a bounded in-memory ready queue and a configured maximum for pending plus
in-flight steps. `append` blocks at the high-water mark; the app then slows or
pauses input/frame production according to its own policy. Do not silently drop
signed work to keep an interactive queue fresh. Stream journal storage has a
hard quota and rotates before the limit. A rotation writes and fsyncs a
checkpoint containing the stream sequence/high-water mark, canonical intent
digest chain, confirmed-step summary and unresolved packet references before
switching segments. Each sealed segment carries its content digest and the
previous segment digest; atomically persist the new manifest pointer before
compacting an older segment. Retain the exact packet and every attempt for each
unresolved step. Compact terminal event detail only after its postcondition and
confirmation have been durably summarized; archive closed segments if the
operator needs a full audit trail. If the quota is reached before safe
compaction/rotation, stop accepting appended work and leave the stream
resumable. Never evict an unresolved signed packet.

Streaming needs a versioned journal header and event set; existing fixed-plan
v1 journals remain readable and unchanged. Resume validates the stable identity,
segment links, append sequence, intent digests, signer set, and every pending
signature/packet. It restores scheduler state from the checkpoint and reconciles
pending steps against signature status and app postconditions before more
steps are signed. Appending is acknowledged only after the intent is durable,
so the application can recover at the returned sequence after a crash.

### Shared confirmation and latency modes

Run one confirmation pump for the entire stream, shared by all work-lock lanes
and both send providers. It coalesces duplicate signature watches, polls bounded
groups (at most the endpoint's supported batch size), and journals each
observation once. A send acknowledgment is never treated as a landing. When
several independent steps are ready, status collection batches them rather than
creating one polling task per frame.

Default continuation waits for `confirmed` (or a stronger caller-selected
commitment) before a dependency is released, matching today's conservative
behavior. Add an explicit low-latency mode that may release a dependency after
the parent reaches `processed`; the journal and `RunResult` must label such a
step `optimistic` until the chosen stable commitment is observed. Bound the
optimistic depth and age per lane. Do not report it as confirmed progress.

If a processed parent later disappears or is reported dropped, append a
`step_dropped`/`optimistic_branch_invalidated` event, stop extending that lane,
and reconcile its app-supplied postcondition at the configured stable
commitment. Keep and poll the parent's original signed bytes. Any already-signed
descendants also keep their original signatures and bytes; do not silently
replace or replay them. Mark affected descendants `reconciliation_required`,
check their signatures and state, then ask the application adapter to choose a
new safe plan from the actual cursor/state. A dropped transaction is not proof
that dependent transactions did not land. The adapter owns that recovery
decision. Before abandoning a signed step, the adapter must have evidence that
its packet can no longer land. A timeout, missing status, provider error, or
height observation alone is not sufficient evidence.

### Pipelining across write-lock lanes

Continue to use `dependencies` and `write_locks` as the scheduling contract,
now across appended stream steps. The scheduler may build/send ready steps from
independent lanes concurrently while respecting each node's rate and
in-flight caps and a stream-wide cap. Steps sharing any declared write lock
remain serialized. A configured send window does not override actual runtime
account locks, and transport order does not imply chain landing order.

For Doom, each render workspace is one writable lane. A frame's workspace
snapshot phases depend on the advance that produced its target cursor and are
serialized on that workspace; its strip phases depend on the snapshot and
remain in that workspace lane. Reserve another workspace for the next frame so
its snapshot can be a separate lane. Once the previous snapshot has copied the
state into its workspace, strips that only mutate that workspace may overlap
the next session advance and another workspace's snapshot, subject to their
declared account locks. Workspace reuse waits until its prior frame has been
read back and the app releases it. This keeps the scheduler generic while
making the Doom dependency edges explicit.

The `r7b` reference currently documents one dedicated view workspace. Multiple
workspaces are an adapter-level provisioned ring required for multiple render
lanes; the single-workspace reference does not establish multi-workspace
throughput or lock behavior. Verify that account shape and concurrency in the
local handler gate before relying on the pipeline.

## 3. Current sequencer invariants in streaming mode

| Invariant | Existing finite-plan behavior | Streaming requirement |
|---|---|---|
| Exact-byte resend | Journal stores the signed raw packet; retries call `send_raw_transaction` with those bytes. | `step_signed` is fsynced before either provider handoff. The provider gets immutable bytes; cross-node/provider retry reuses that exact buffer. Segment rotation pins unresolved packets and attempt history. |
| No silent re-sign | A new packet requires expired lease, queried status, checked postcondition, and explicit adapter authorization. | Stream append cannot replace a live step ID or mutate its intent. Expiry, processed-drop, or provider switch never creates a generation automatically. A new generation needs journaled `step_rebuild_authorized` evidence from the adapter after reconciliation. |
| Journal and resume | Fixed-plan v1 binds plan and signer identity; JSONL fsyncs events and repairs only an incomplete tail. | Versioned stream header binds stable run identity; ordered append events and checkpoints bind every segment. Resume reconciles unresolved exact packet bytes before consuming newly appended work. Compaction is only for durably terminal steps, and quota exhaustion backpressures the producer. |
| Genesis check | RPC verifies actual genesis against `TransactionPlan` before its first lease. | Validate all eligible RPC observers/lease sources before opening the stream and again for newly introduced endpoints. Bind a TPU route to that checked cluster. Refuse the stream on mixed or changed genesis. |
| Packet limits | Projected serialized size is checked before signing; signed size is checked after signing, capped at 1,232 bytes. | Apply both checks to every appended step before it enters the ready queue/signing path. Provider framing adds no transaction bytes. Oversize is terminal for that intent, not a cue to truncate or silently split it. |

The current implementation anchors are [step/plan and limits](../../python/dcg/sequencer/types.py#L168), [fixed-plan resume and scheduling](../../python/dcg/sequencer/core.py#L324), [pre-send signing/journaling and post-sign packet check](../../python/dcg/sequencer/core.py#L752), and [fsynced JSONL](../../python/dcg/sequencer/journal.py#L28). The stream mode should add these capabilities without changing the meaning of a v1 fixed-plan journal.

## 4. Doom testnet adapter sketch

Add a Python testnet driver under `stunts/doom-dcg/` that builds Doom's
application steps and streams them to DCG. The testnet workload profile in the
dispatch brief calls for about nine input/advance transactions and 20 render
transactions per frame. These are **designed profile counts**, not measured
rates or confirmed transaction counts. The current `r7b` kernel documents a
dedicated writable workspace, bounded snapshot-copy phases, and eight strip
views (`stunts/doom-dcg/README.md:9–20`; `src/lib.rs:73–98, 527–823`).

1. Construct the Doom manifest/kernel reference, new program/session identity,
and application inventory for the session, input stream, state spans, and a
ring of snapshot/render workspaces. Verify genesis and the program/resource
image identity before admitting work. Create/close and rent amounts remain
application operations. `dcg.session` currently documents stateful v1/v2
layouts; using it for this v3 Doom kernel requires v3 session/layout support or
an app adapter that encodes the v3 forms. The design does not assume that
support already exists.
2. Translate each keyboard event into Doom's four-byte command and assign its
input sequence/cursor in the app. The corresponding app-built ADVANCE packet
carries that cursor's input payload and state advance in the protocol's
permitted order, so the app need not make a standalone generic input decision.
The step intent digest binds session, input sequence, command bytes, and
expected before/after cursor; its postcondition reads the typed session/context
cursor. The adapter must verify in local handler tests that input plus advance
can be included atomically in one transaction before relying on this shape.
If a given instruction profile cannot do so, represent input write and advance
as two explicit dependent steps; never claim they are one transaction without
handler evidence.
3. Append the roughly nine input/advance packets per frame as cursor-ordered
steps on the state lane. Each one depends on the prior transition. The sequencer
only moves them when the selected commitment mode permits; it does not
interpret keys, choose tic batch size, choose cursor thresholds, or decide how
to recover a Doom refusal.
4. When Doom's render policy selects a cursor, reserve a free workspace and
append its snapshot phases after the matching advance. Append the 20 configured
render transactions in their tested workspace order: snapshot/copy phases,
then the required render phases and eight strip outputs. The workspace write
lock serializes those phases; other free workspaces can pipeline independently.
The app reads back the complete output, validates snapshot hash and cursor,
assembles strips, verifies the expected frame hash, then releases the workspace
for reuse. Those hashes and release rules stay in Doom.
5. Keep Doom's HTTP/player service, session pool, idle pause and handoff,
input ordering, snapshot identity, browser frame stream, cursor resync, spend
limits, and fee/rent accounting as application code. The new sequencer owns
transport attempts, route and confirmation observations, exact packet journal,
backpressure, dependency scheduling, and resumable run state.

Until the driver passes local handler/golden gates and the new-address testnet
comparison, it is an adapter sketch only. The 2026-09-30 Doom port plan already
requires local program behavior and throughput gates before testnet, and says
to migrate the Doom sender last.

## 5. Revision 8 template uploader migration

The first Basanos migration remains `scripts/rev8_template.py`, as stated in
[DCG's sequencer guide](../sequencer.md#L316). Its setup, independent writes,
seal boundaries, cursor recovery, and account postconditions exercise bulk
transport without moving template meaning into DCG. It should use the same
endpoint pool, provider interface, journal, exact-byte resend, and scheduler as
Doom; bulk and low-latency clients should be configurations of one transport.

For large uploads, generate fixed-plan steps in bounded dependency windows or
append range steps to `StreamingPlan` as the template artifact is read. Keep a
stable intent digest per template/range, CU class/limit, packet limit,
destination account and write lock. Independent destination accounts may fill
the send window; writes to the same writable account remain serialized even if
their byte ranges do not overlap. Verify stored bytes/cursors from chain state
before sealing or authorizing a new signed generation. A high-throughput bulk
profile can favor bounded send windows and account readback, while the low-
latency Doom profile can release confirmed dependencies promptly and cap
optimistic depth.

The Basanos adapter still builds revision-8 instructions, template/account
identities, range/cursor postconditions, and setup dependencies, and owns
template bytes, allocation, rent, payer selection, fees, cursor policy, and
fresh-sign authorization. The existing DCG guide calls out a multisigner
adapter as an open prerequisite for setup transactions requiring both the
authority and newly allocated account keypairs. Add a composite signer
capability before migrating those steps; the Rust TPU sidecar continues to
receive signed bytes only.

## 6. Testnet part 2 measurement plan

The retained comparison is the 2026-09-28 Fogo testnet
`advance-cu-1m4` receipt at `Basanos/out/runs/doom-send-pipeline-2026-09-28/advance-cu-1m4/`.
Its run note records 3.354 **measured active new pictures/s** during 68.580
seconds of input, 29.377 **measured tics/s**, and 3.533 **measured frames/s**
over 75.297 seconds. It has 37 measured key-to-next-picture samples (193.4 ms median,
709.8 ms p95), zero measured HTTP 429s, and no 286/297/308 refusals or
compute-budget exhaustion. The run used four render buffers, prediction off,
`ADVANCE_CU_LIMIT=1,400,000`, `SEND_RATE=60`, and `MIN_CURSOR_STEP=6`; those
are **configured settings**, not network capacity. Measurement source:
`Basanos/docs/experiments/doom-send-pipeline-2026-09-28.md:64–77`; the note
identifies the retained receipt and image/source pins at lines 3–13.

After local gates, run the new DCG program/session at a fresh address on the
same testnet with the same WAD/resource and captured input tape. Keep the
comparison window, input-active accounting, renderer output, send profile and
operator caps fixed where the programs permit. Preserve the baseline receipt;
record each candidate receipt and program/resource hash. The existing Doom
port plan gives a **designed** initial gate of at least 90% of baseline active
new-picture and tic rates, byte-exact frames, and no unresolved fates. Report
that gate separately from raw results; it is not evidence until measured.

For every run, report:

- **Measured pictures/s:** distinct complete frame hashes for expected new
  cursors, both over the whole run and during active input. Report frame
  duplicates, skips and stalls separately.
- **Measured tics/s:** committed session cursor delta divided by elapsed time;
  include the actual cursor range and requested/consumed CU by advance.
- **Measured key latency:** client key event to first returned byte-exact picture
  at or after its target cursor; include sample count, median, p95 and timeout
  count. Capture it at the same visible client boundary as the baseline.
- **Measured transactions/s per node:** attempted sends, unique signed packets,
  provider acknowledgments and observed landed signatures by RPC node or TPU
  helper/source route, divided by the same active window. Keep RPC status/read
  traffic as a separate count.
- **Measured 429 and drop rates:** per-node 429 responses divided by requests,
  throttle/cooldown duration, and unique signed packets that expire without
  target commitment and whose app postcondition remains unsatisfied after
  reconciliation. Report unresolved ambiguous fates separately from proven
  drops; count processed-then-dropped signatures and affected descendants.

Run at least three paired baseline/candidate active-input windows of 60–90
seconds (**designed sample plan**), and report each result plus median and
range. Do not claim the transport caused any change unless program CU, account
locks, runtime/provider configuration, and app rendering work are separately
reported. This measurement is authorized as a future testnet plan only; no
transactions are part of the current design task.

## 7. Implementation work packages

Effort ranges below are **estimates**, not measured durations. The first three
packages can be developed in parallel after the small public API contract is
agreed; their file ownership is disjoint. The application migration can proceed
against that contract in its own files, with testnet acceptance gated on the
sequencer integration.

| Package | Exclusive file ownership | Deliverable and gate | Estimate |
|---|---|---|---|
| A. Endpoint pool and provider adapters | New `python/dcg/sequencer/pool.py`, `providers.py`; new `python/tests/test_sequencer_pool.py`, `test_sequencer_providers.py` | Configured per-node rate/in-flight caps, weighted route selection, health/cooldown/probe lifecycle, affinity, RPC send adapter, Python wrapper for Rust TPU, provider error tests including same-byte retry and helper death. | **Estimated 3–5 engineer-days.** |
| B. Streaming journal and bounded rotation | New `python/dcg/sequencer/stream.py`, `stream_journal.py`; new `python/tests/test_sequencer_stream.py` | Append/close/checkpoint API, stable identity and sequence digest, bounded queue, segment rotation/compaction, restart tests for partial tails, duplicate append, quota pressure, and unresolved signed packets. | **Estimated 4–6 engineer-days.** |
| C. Scheduler, shared confirmation and latency modes | Existing `python/dcg/sequencer/core.py`, `types.py`, `__init__.py`; `docs/sequencer.md`; new `python/tests/test_sequencer_realtime.py` | Integrate the pool/providers and stream behind one sequencer, preserve fixed-plan v1 behavior, enforce write-lock lanes, one batched status pump, confirmed default, processed optimism and dropped-parent reconciliation tests. | **Estimated 5–8 engineer-days.** |
| D. Caller migrations and comparison harness | Basanos `scripts/rev8_template.py`, new `stunts/doom-dcg/testnet_driver.py`, `tests/test_dcg_realtime_transport_adapter.py`, `docs/design/realtime-transport-testnet-part2.md`, and its testnet receipts | Migrate the rev 8 uploader first using bulk mode, then build the Doom adapter against the stable stream API. Exercise restart and account-state reconciliation locally before the separately gated fresh-address testnet comparison. | **Estimated 5–8 engineer-days**, excluding open local kernel/API work and testnet scheduling. |

Packages A–C own only the files listed for each package; Package D owns only
the Basanos caller files and its new testnet driver/adapter tests. Package C is
the integration point and can merge A/B's new modules once their protocols are
frozen. The testnet run is a later owner-scheduled measurement, not part of the
parallel implementation estimate.

## Owner decisions

- **Recorded decision (2026-10-01):** implement generic real-time transport in
  DCG's Python `dcg.sequencer`; Doom part 2 uses it. Keep session/idle/player
  handoff, provisioned slot and workspace pools, snapshot hashing, input and
  cursor ordering, rent, and fees in the application.
- **Existing sequencing decision:** migrate the rev 8 template uploader first
  to validate bulk work; migrate Doom last, after the new-address testnet gate.
- **Existing measurement gate:** the Doom port plan sets a **designed** minimum
  of 90% of baseline active picture and tic rates, byte-exact frames, and no
  unresolved fates. This note carries that gate forward.
- **Recommended API decision for owner review:** preserve finite plans and
  their v1 journal contract; add a versioned streaming mode, a separate send
  provider protocol, stable `confirmed` continuation by default, and explicit
  bounded `processed` optimism as the opt-in latency mode.
- **Open owner choices:** the default pool health thresholds/cooldowns, stream
  disk quota and segment retention policy, maximum optimistic depth, and whether
  RPC or TPU/QUIC is enabled in the first DCG testnet part 2 profile. All rates
  and caps must be recorded as configured or measured per run; no global
  throughput target is inferred here.
