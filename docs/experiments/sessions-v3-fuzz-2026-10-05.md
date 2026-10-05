# Sessions v3 and lanes run-level fuzz campaign (2026-10-05)

**Status: built and run (alpha R2 item); one low finding (F1), no invariant,
liveness or closability failure.** Test-only: no program source changed. Spec:
"Fuzzer scope" in
[`sessions-v3-review-2026-10-05.md`](sessions-v3-review-2026-10-05.md).
Program at DCG `d8108bc` (after the H1–H3 fixes); branch
`fast/sessions-v3-fuzzer`.

## Harness

`crates/dcg-program/tests/stateful_v3_fuzz.rs` (feature
`sbf-real-lifecycle-test`). The generator and the reference model are in Rust
inside the test (not Python as the review suggested): the generator is
state-dependent, so keeping it next to the model avoids a play-file format.
Sequence `i` of seed `s` depends only on `(s, i)` and the program's answers,
which are deterministic.

- **Sequence.** Each sequence gets its own ProgramTest bank and one session:
  either the lane counter (headered 16-byte state, lanes 0–4, width 1, or width
  2 so the kernel refuses every input) or the workspace-first fixed engine
  (headerless primary of 1,280, 8,192 or 20,000 bytes, a sealed resource of
  32–17,000 bytes, phased initialization). Indexed or APPEND policy, capacity
  2–10 (10%: 65–80, to reach the 64-slot window), 1–8 steps per advance.
  25–140 steps, then the two oracles.
- **Actors.** Fee payer, session authority, APPEND writer, bystander, lamport
  pre-funder. Payers of creations and grows are drawn from all of them.
- **Operations.** Open (also re-open after a full close), stream create and
  grow, state create and grow, one-call and phased initialization, resource
  grow and chunk upload (good and bad proof), view, workspace and scratch
  creation, view/workspace/scratch grow, input writes, single and batched
  advances, BEGIN/RUN/COMMIT/ABORT_PHASE, lane create, grow, capture
  begin/run/end, render, commit, abort, halt, one-shot anchor, chunked anchor
  begin/chunk/finish/abort, every child close and the session close, and
  pre-funding transfers to any session-derived address. About 72% of steps
  pick a model-valid op (weighted toward progress); the rest pick any op kind,
  65% of the time perturbed (another actor, cursor or offset off by one,
  another lane, wrong kind byte, wrong role or ABI, unsigned authority slot,
  lengths out of range). Per step: 6% resend of an earlier transaction (stale
  duplicates and replays), 5% a reordered pair (generated in order, sent
  swapped), 6% a 2–3 instruction bundle (atomic as a whole); on SBF 4% of
  single steps carry a 1,000–25,000 CU limit (injected compute failure).
- **Injected kernel refusals** (all existing test-kernel behavior): fixed
  engine input 0xED (state change before `HaltBefore`, refused by the runtime
  snapshot check), 0xEE (halt before) and 0xEF (halt after); a resource
  starting with 0xEE (initialization refuses for good); renders past the first
  16 view bytes; the lane counter's non-lane render (always refused); width-2
  lane-counter sessions; a 20,000-byte primary the engine cannot initialize.
- **Reference model.** For every transaction the model predicts acceptance or
  refusal and, on acceptance, the effect. Every mismatch fails the run:
  "unexpected acceptance" or "unexpected refusal" (except a refusal caused by an
  injected compute limit).
- **Run.** `V3_FUZZ_SEED`, `V3_FUZZ_COUNT`, `V3_FUZZ_FROM`, `V3_FUZZ_JOBS`
  (8 banks at once), `V3_FUZZ_ONLY=<i>` (one sequence, verbose),
  `V3_FUZZ_SBF=1` with `BPF_OUT_DIR`/`SBF_OUT_DIR`:

```sh
V3_FUZZ_SEED=1000 V3_FUZZ_COUNT=1000 V3_FUZZ_JOBS=8 RUST_LOG=error \
  cargo test -p dcg-program --features sbf-real-lifecycle-test \
  --test stateful_v3_fuzz -- --ignored fuzz_campaign --nocapture
```

  Each transaction reuses the latest blockhash and carries a unique compute
  unit limit (no price, so the fee stays the signature fee), so resends are
  distinct transactions.
- **Default suite.** `fuzz_smoke` (6 native sequences) and three planted
  checks run in the default suite: a wrong host input-chain domain, a model
  that forbids the authority's halt and a host counter that adds one per input
  are each caught ("input root differs", "unexpected acceptance", "state
  digest"). All pass in about 1 s.

## Invariants checked after every transaction

1. Counters: `cursor <= frontier <= capacity`, `frontier - cursor <= 64`.
2. The stream header mirrors the session (capacity, cursor, frontier, writer,
   stream root, kind, length).
3. Input root equals the host SHA-256 chain (`dcg/input-chain/2`) over the
   consumed inputs.
4. Written slots never change: every slot equals the bytes the model wrote
   (or zero), so a rewrite or a lost slot fails.
5. State equals a host replay of the test kernel: the counter's value and
   total, or the fixed engine's resource-initialized primary plus the input
   sum (the allocated prefix for a partly grown primary). Headered spans'
   before/after cursors match.
6. Every refused transaction leaves every tracked account (session, all
   children, all actors, the resource source) byte-identical, the fee payer
   losing only the fee.
7. Capture bits equal the set of capturing lanes while active, zero after
   halt; lane records (status, captured cursor, capture and render cursors and
   totals) match the model.
8. View stamps: equal across published views, never ahead of the cursor,
   monotone (the model's), and each view's bytes equal the host render at its
   stamp (lane commits: the state at the captured cursor; fixed-engine commits:
   the resource bytes).
9. Captured cursors: distinct across busy lanes, below `last_captured`, which
   matches the model (strictly increasing captures; an aborted capture
   forfeits its cursor).
10. Child count equals the number of live program-owned children, and every
    child's existence matches the model; no child exists without its session.
11. Lamport conservation: the tracked set loses exactly the transaction fee.
12. Session fields: status, halt reason and cursor (0xD00D, 0xD00E or 0),
    phase kind and cursors, initialized flag, lanes, span and view counts,
    last advance start, anchor cursor, and the state anchor equal to the host
    hash (one-shot and chunked domains, including the chunk accumulator in the
    anchor account).

Oracles at the end of every sequence:

- **Liveness** (lane counter, width 1, session still active): from the reached
  state the authority and writer abort any open phase, anchor or lane, create
  missing children, grow the stream if full, write and advance one input and,
  with lanes, capture, render and commit it. Every step must be accepted.
- **Closability** (any open session): halt if active, close every child (any
  order except states highest first) and the session; every session-derived
  address ends empty and system-owned, and the authority gains exactly the
  lamports those accounts held (pre-funding included).

## Results (measured)

| Campaign | Seeds | Sequences | Transactions (accepted / refused) | Wall (8 jobs) | Failures |
|---|---|---|---|---|---|
| Native | 1000–1009 | 10,000 | 794,902 (576,413 / 218,489) | 1,328 s (0.13 s per sequence) | 0 |
| SBF image | 2000–2002 | 3,000 | 236,072 (169,286 / 66,786) | 536 s (0.18 s per sequence) | 0 |

SBF image: `cargo-build-sbf` 3.0.15, platform-tools v1.51, feature
`sbf-real-lifecycle-test`, from `d8108bc` via
`crates/dcg-program/scripts/build-sbf-reproducible.sh`; `dcg_program.so`
SHA-256
`b1c9c03107654d9b22f45a37a3c28e01d8c07037cc5a106aac539b41f4d3ba7c`.

Coverage (native / SBF): 6,116 / 1,804 lane-counter and 3,884 / 1,196
fixed-engine sessions; resends 40,096 / 11,675; reordered pairs 34,181 /
10,335; bundles 40,485 / 11,881; injected compute failures 0 / 2,104;
pre-funding transfers 95,600 / 25,245 accepted; sessions reopened at a closed
address 717 / 161; accepted advances 34,982 / 10,390 (cursor up to 42 / 43);
lane commits 4,761 / 1,417; non-lane view commits 0 / 1,058 (the fixed engine
renders only at the SBF fixed address); chunked anchors finished 13,057 /
3,849 and one-shot anchors 12,393 / 3,564; primary grows 377 / 126; resource
grows 1,775 / 507; liveness oracle 2,742 / 812 runs (publishing on a lane in
2,040 / 614); closability oracle 6,488 / 1,915 runs.

Halts by state at the halt (native): view phase open 1,032, initialization
open 428, anchor open 1,060 (with one or more lanes busy in 210), lanes
capturing or rendering with no phase 436, kernel halt-before 447, kernel
halt-after 437, idle 1,237. SBF is similar (1,472 halts).

Liveness skips (native): session halted or closed 5,533, fixed engine (not an
accepting kernel; covered by H4) 1,393, width-2 refusing kernel 256, authority
began phased initialization on the one-call kernel 76 (self-wedge until halt),
every lane created with a too-small scratch 50 (publish skipped, advance
checked).

Before the campaign, about 4,000 shake-out sequences fixed harness gaps (tx-
level signer and writability, account lists inside bundles, compute-failure
detection); none was a program fault.

## Finding F1 (low): close kind byte not enforced for two account kinds

Observed at native seed 1001 index 316. `close_account` (tag 238) checks the
instruction's kind byte against the target's byte 6, and `close_child` then
identifies the anchor and the headerless primary by their addresses. Byte 6 of
the anchor is its open flag, and byte 6 of the headerless primary is
application state. So a halted session's open anchor closes under kind 1
(`KIND_STREAM`), and a headerless primary whose byte 6 equals some kind
`k != 0` closes under `k`. The effect equals the correct close (rent to the
authority, child count decremented, order rules kept), so no lamports or
records are at risk; the wire's kind byte is simply not authoritative for these
two accounts. Reproducer (ignored, fails today):

```sh
cargo test -p dcg-program --features sbf-real-lifecycle-test \
  --test stateful_v3_fuzz -- --ignored finding_f1
```

The anchor case is measured (native reproducer); the primary case is from the
code path and the model (the model accepts both so the campaign could
continue). A fix would check the kind against the address-derived kind before
`close_child`; it changes refusal behavior, so it needs a version decision.

## Not covered

- **Kernel coverage.** Only the two test kernels; Doom's adapter is not
  fuzzed. Accepted grows exist only for the stream, the resource copy and the
  fixed engine's 20,000-byte primary; headered state, view, workspace and lane
  grows are exercised only as refusals (the test kernels' children are
  created at full length).
- **Fixed-engine liveness.** Not checked: it is not an accepting kernel (0xED
  wedges the session, the H4 class). The liveness oracle covers the lane
  counter only, and only sessions that end active.
- **Workspace contents.** Lane and non-lane workspace bytes are not compared
  with a host copy (the lane render output is, through the views).
- **Kernel compute failures natively.** Native ProgramTest does not meter the
  program, so injected compute limits run only on SBF.
- **Independence.** The model was written from the code and design docs; where
  the program's intended semantics were unclear (renders and aborts after halt,
  forfeited capture cursors) it encodes the documented behavior, so a bug
  shared by the code and its documentation would not show. Invariants 1–11 and
  both oracles do not depend on the model's acceptance rules.
- Live validators, testnet, the v1/v2 stateful paths, the revision-8 image
  composition constraint, and sequences longer than 140 steps or cursors past
  43 (M2's 655,352-input ceiling is not approached).

## What remains for R2 sign-off

- Owner decision on F1 (fix with a version note, or document that the anchor
  and headerless primary are closed by address).
- H4 and M2 owner decisions (unchanged by this campaign; the fuzzer shows the
  fixed engine's 0xED wedge and recovers only by halt and close).
- An independent rule-10 review of this harness and note.
