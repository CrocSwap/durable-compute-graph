# Stateful sessions v3 and lanes: independent review (alpha R2) — 2026-10-05

**Status: reviewed; not ready for sign-off (4 high).** Rule-10 adversarial
review of `stateful_v3.rs` (tags 230–240) and `stateful_v3_lanes.rs` (lane
ops 4–11) at DCG c0afbc9, for the alpha's R2 item
(`docs/plans/alpha-release-plan.md`). Five findings were confirmed by native
ProgramTest probes (not SBF), kept at
`scratchpad/r2-dcg/crates/dcg-program/tests/r2_probe.rs` (5 pass; run with
`--features sbf-real-lifecycle-test --test r2_probe`). No code changed.

## High

- **H1. Child creators are open to anyone** (measured, probes P1–P3).
  `create_stream`, `create_state`, `create_view`, `create_scratch` and
  `create_workspace` need only a fee payer, who picks the lengths, the view
  role and its source range. A bystander's tiny state span or workspace makes
  the session unrunnable (2331/2334, 2332 forever); an extra `TOTAL` view on a
  lane session publishes the value bytes under the wrong meaning. Fix: the
  session authority signs every create; grows may stay open.
- **H2. Pre-funding an address blocks its creation forever** (measured, P5).
  `open_session` requires zero lamports at the session address and
  `create_derived_account` refuses pre-funded targets; every child address
  derives from the session key, so one rent-sized transfer kills a stream,
  view, lane or anchor (2324/2326). Fix: `allocate_derived_account` and drop
  the zero-lamport check.
- **H3. A halted, partly grown headerless primary can never close**
  (measured, P4: 124,723,200 lamports stranded). `close_child` requires the
  declared length; growth requires an active session. Fix: a halted session
  closes a primary of any length up to the declared one.
- **H4. A refused input wedges the session for good.** A kernel refusal in
  `ADVANCE` rolls back; inputs are write-once; so a refused input at the
  cursor can never be consumed (the Doom lanes session at tic 5,310 on
  2026-10-05). Only halt and close remain, losing progress; under the APPEND
  policy a non-authority writer can do it. The kernel contract does not say
  kernels must accept every well-formed command. Proposed: document that
  obligation; an optional, per-session, versioned "reject" outcome that
  consumes the input without changing state and records it in the input
  chain; later, a new session seeded from an anchor. **Needs an owner
  decision.**

## Medium

- **M1.** Every close refunds the authority, not the payer; separate fee
  payers and sponsors never get rent back (record the payer, or document it).
- **M2.** A session's life is at most 655,352 inputs (absolute slots, growth
  only at cursor == capacity, ~10 MB of stream rent at the maximum): about
  5.2 h of Doom at one input per tic (estimated), short of a week-long public
  demo. A ring buffer removes it.
- **M3.** "A render sees only the state captured at its cursor" is a kernel
  obligation: `capture_run` does not check the kernel wrote its range, and
  renders get the captured workspace writable. Zeroing each capture phase's
  range before the kernel call makes it a program guarantee.

## Low

L1 anyone may close a halted session's children (views and anchor can vanish
before readers fetch them; rent still to the authority). L2 the resource
source's owner is unchecked and need not be (uploads are proven), but its
length is read from the account, so its owner can resize it to block sealing;
take the length from the instruction. L3 the `HaltBefore` unchanged-state
check covers only state up to 8 KiB. L4 capturing before the lane workspace
is fully grown leaves only abort. L5 predictable session ids let H2 burn an
id; a fully closed session can reopen at the same address. L6
`account-provenance.md` does not list the self-seeded lane record or the open
creators.

## What held

Cursor, frontier, the 64-slot window and write-once inputs; exact-cursor
advance; phase and lane cursors as idempotency keys; newest-only commit
(2341); capture blocking ADVANCE (2340); halt clearing masks and open phases;
closing a lane mid-render. No handler in scope accepts an account by owner
and magic alone.

## Fuzzer scope (for R2)

A Python reference-model generator replayed through ProgramTest (as the LX1
campaign does), with actors authority, writer, bystander and pre-funder; every
tag and lane op plus resends, duplicates, reordering, injected kernel
refusals and compute failures, halts in every phase, closes in any order; and
invariants after every step: counters and window, the input chain, host-replay
state digests, refused transactions byte-identical, capture bits, view stamps
monotone and equal to a host render, captured cursors increasing, child count,
lamport conservation, a closability oracle and a liveness oracle (the last two
would have caught H1–H3).

## Next

Fix H1–H3 (creation and close semantics change: version them; rule-10
re-review), owner decision on H4 (and M2 for the public demo), then the
fuzzer, then R2 sign-off.
