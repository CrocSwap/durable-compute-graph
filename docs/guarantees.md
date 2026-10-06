# What DCG guarantees, and what it does not

This page states what each mode guarantees in the alpha, what you must do
for the guarantee to hold, and how to check a given template or session with
`explain`. The alpha's terms and known gaps are in
[`release-terms.md`](release-terms.md).

## Consensus mode (sessions)

**The guarantee.** Every transition of a session ran on chain, in your
program, with the kernel your program's manifest declares. The state the
session holds is exactly what the transitions produced from its inputs, in
order:
- each step applies once, and in order;
- a duplicated, failed or reordered transaction cannot skip ahead or corrupt
  state;
- a kernel that declares rejectable inputs refuses a bad input without
  changing state, and the session goes on.

Nobody needs to watch, and nothing waits for a challenge window.

**What you must do:**
- **Keep the kernel deterministic and integer-exact.** The kernel kit checks
  it against its host reference ([`kernel-kit.md`](kernel-kit.md)).
- **Fit each step in one transaction.** Size the work so a step fits the
  compute ceiling you declare, and the declared ceiling fits the chain's
  per-transaction limit.
- **Keep submitting.** The chain does not advance a session by itself. The
  sequencer submits, resends and resumes from its journal
  ([`sequencer.md`](sequencer.md)).

**Check a session:**

```python
print(await session.explain(decl=MANIFEST))
```

It states the guarantee, the kernel with its per-step and per-transaction
compute bounds, and the session's live state: its cursor, its rejections,
and whether it halted.

## Optimistic mode (v2.1 runs and disputes)

**The guarantee.** A committed run that anyone disputes inside its challenge
window is either upheld or refuted on chain. A refuted run's executor loses
its bond. The program decides by replaying at most one step. A run that
nobody disputes becomes final after the window.

The guarantee holds when all of these are true:
- **Someone checks every run you care about,** inside its challenge window.
  The watchtower service does this ([`services.md`](services.md)).
- **The checker can get the run's inputs.** The alpha commits inputs as
  digests only, so the application must publish them. On-chain input posting
  is planned before any mainnet use.
- **Each party moves before its phase deadlines.** A party that misses one
  loses that dispute. Run services close to their RPC node, and size the
  windows (see below).
- **The plan behind the template is the plan you meant.** The program trusts
  the template's spec root. Check the plan off chain with
  `dcg explain template --plan`.
- **Every application kernel agrees with its Python mirror.** The off-chain
  referee and executor use the mirror. The kernel kit checks that they agree
  ([`kernel-app.md`](kernel-app.md)).
- **An application kernel does not change while its runs are live.** STEP
  claims resolve against the image that is live when the dispute is ruled.

**Who profits from acting first.** These rules hold for every ending; the
run-level fuzzer checks them after every transaction
([`experiments/v21-run-fuzz-2026-10-05.md`](experiments/v21-run-fuzz-2026-10-05.md)):
- The pot (the slasher share of the executor's bond) goes to the
  lowest-sequence dispute that wins, not to the fastest one.
- A dispute opened after that win is ruled moot, and its bond comes back.
- Anyone may settle: time out a late party, advance, pay the pot, finalize,
  and close accounts. Bonds and rent go only to the parties the accounts
  record, whoever sends the transaction.

**Check a template:**

```sh
dcg explain template --rpc URL --template T --plan my_app.py:my_graph
```

For the quickstart's template on a local chain it prints (abridged):

```text
status:
  open for runs, 0 live run(s)
  guarantee: optimistic. A wrong commitment is refuted only if a watcher challenges it inside the challenge window; the program then replays the disputed step.
plan check:
  the given plan matches the template's spec root and counts
kernels:
  sumchunk_i32/v1 v1/1 (4 steps): built-in reduction, replayed by the program
  head_i32/v1 v1/1 (1 step): built-in reduction, replayed by the program
dispute path:
  descent over the step tree (height 3) or the output tree (height 0), 3 level(s) per round: at most 1 / 0 round(s), then a claim
windows:
  challenge: 1,000 slots (~40 s at 40 ms/slot) after commit
  each phase: 750 slots (~30 s at 40 ms/slot); a party that misses a phase loses that dispute
bonds:
  executor: 0.002 FOGO (2,000,000 lamports); challenger: 0.001 FOGO (1,000,000 lamports) per dispute
  a winning challenger gets 50% of the executor bond; the rest goes to the run's payer
warnings:
  ! the challenge window (~40 s) is shorter than twice a remote watcher's slowest tick (~33 s measured on testnet): a lie may finalize before a remote watcher checks it
```

Read the warnings first. Each one names a condition from the list above that
this template does not make easy.

**Sizing windows.** The program's minimum window is 750 slots (about 30 s on
Fogo). That is enough for a service next to its RPC node, but not for one
whose RPC calls take about 350 ms. `examples/optimistic-quickstart` and the
services' testnet runs use a 3,000-slot challenge window and 1,500-slot
phases. [`services.md`](services.md) has the measured guidance.

## Both modes

- **Faithful execution, not usefulness.** DCG shows that a computation was
  done as stated. It does not show that the computation is the right one.
- **Exact integer arithmetic only.** A floating-point model must first be
  quantized into an integer-exact form.
- **Not private.** Checkers must be able to read the inputs and the
  intermediate values.
- **Alpha.** Testnet only, and formats may change before beta
  ([`release-terms.md`](release-terms.md)).
