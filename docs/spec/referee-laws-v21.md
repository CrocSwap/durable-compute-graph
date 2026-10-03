# Referee laws for v2.1 disputes (tag 227)

Status: **designed contract**, written 2026-10-03 against DCG main `3df716d`
and the queued follow-up fix round. It states what every accepted tag 227
transition must satisfy. It is not a proof that the program satisfies it. Each
law lists the evidence that exists today and the known violations still open.

This document succeeds [`referee-laws.md`](referee-laws.md) for v2.1. That
page covers the revision-8 document lifecycle, which is being retired. The
seven law headings are kept so the two can be compared; v2.1 adds two
(neutrality, and admission bounds) and an LX1 section.

Uses:
- **Tests.** The every-ending matrix (`disputes_v21_skeleton.rs`), the dispute
  oracles, and the planned run-level fuzzer check these laws. A new ending or
  payout path is not complete until it is covered here (Basanos project
  rule 10).
- **Review.** An independent review of an ending or payout change checks the
  change against each law and fills in the "who profits by calling first"
  table (§6.3).
- **bendSVM.** The settlement subset in §11 is the proposed target for the
  bendSVM pilot, replacing the revision-8 tags 132, 131 and 172.

## Model

**Accounts.** Every v2.1 record is accepted only at its derived address.

| Record | Address | Created by | Rent payer |
|---|---|---|---|
| Template | `["dcg21tmpl", template_id, payer]` | admitter (sub 1) | the admitter |
| Run | `["dcg21run", run_id, payer]` | payer (sub 2) | the run payer |
| Receipt | the run's own address, after sub 19 | the run, shrunk | the run payer |
| Dispute | `["dcg2dsp", run, challenger, nonce]` | challenger (sub 4) | the challenger |
| Staging buffer | per dispute and party | challenger at open for both (sub 4), each party for growth (subs 14, 17) | recorded creator, byte 5 |
| Reveal cache | keyed by the run, the parent position and hash | executor (sub 16) | the executor, recorded in the cache |

**Parties.** `A` is a template's admitter, `P` a run's payer, `E` the run's
executor, `C` a dispute's challenger, and `X` anyone at all, including any of
the others under another key.

**Run status.** `OPEN → COMMITTED → FINAL`, or `COMMITTED → REFUTED`.
An `OPEN` run with no commit can be cancelled after its commit deadline. A
`FINAL` or paid `REFUTED` run with every dispute closed shrinks to a receipt.

**Dispute phases.** `NODES` (E owes) and `PICK` (C owes) alternate down the
tree. Then come `LEAF` (E owes) and `CLAIM` (C owes, with the openings and
witness staged), and finally `RULED`. A ruling is `EXECUTOR`, `CHALLENGER` or
`MOOT`. The party a phase waits on is said to **owe** it.

**Time.** `now` is the Clock slot. An action is allowed while
`now <= deadline`. A timeout is allowed only when `now > deadline`. Every
deadline is computed with checked `u64` arithmetic, and windows are bounded at
admission (`MIN_PHASE_WINDOW ≤ window ≤ MAX_WINDOW`).

**Refusal.** A refused instruction changes no program-owned bytes or
lamports. The transaction fee is still charged by the runtime, and is outside
the ledger in §2.

**Adversary.** The adversary may:
- hold any number of keys, and act as several parties at once, including a
  challenger against its own run (a "puppet" dispute);
- order its own transactions freely within a slot and front-run others;
- pre-fund any address, and write or grow its own staging buffers at any
  time the rules allow;
- choose any timing up to a deadline, and stay silent.

The adversary cannot break SHA-256, forge a signature, or censor the other
party for a whole phase window. Censorship-resistance for one window is the
inclusion assumption; the windows are sized for it (design §8.3).

## 1. Honest party wins

**Plain English.** A party that tells the truth and makes every move it owes
on time never ends a dispute as the loser. Lies, silence or malformed data
from the other side cannot change that.

**Law.** Let `good(d)` mean the executor's commitment is correct at the
position dispute `d` descends to: every revealed node, leaf and opening
matches what the honest execution of the admitted template produces.
- If E is honest and makes every move it owes, every complete path of `d`
  ends `EXECUTOR` or `MOOT`. It never ends `CHALLENGER`.
- If E's commitment is wrong anywhere and C is honest and makes every move it
  owes, C can always reach `CHALLENGER` by following first divergence (design
  §7).
- A timeout rules against the party that owes the phase. It never rules
  against the party that does not owe it.
- A refusal is not a ruling. If an honest move is refused, the same honest
  party must still have a legal move that leads to its win.

**Catches.** An honest executor convicted because the reference executor and
the rule disagree on a state digest (A1, 2026-10-03: a LOG chain that changes
capacity). A malformed leaf that cannot be convicted. A claim the honest
challenger cannot make because its witness exceeds a buffer.

**Status.**
- Measured for the scenario sets: the base oracle (84 scenarios), the chunked
  oracle (687), the list oracle (12) and the LOG goldens, native and SBF. The
  12 list rulings were also replayed from the real client's instruction
  stream.
- **Open violation:** A1, on branch `review/v21-followups-ab` only, not on
  main. The fix round refuses capacity-changing LOG chains at admission.

## 2. Conservation

**Plain English.** Every lamport that moves has a named source, a named
destination and an exact amount. Nothing appears, disappears, or lands with
the caller by default.

**Law.** For every successful transition and every touched account `a`:

```text
L'(a) = L(a) + credits(a) - debits(a)
```

Here every credit and debit is one of the movements below. The sum over all
touched accounts is unchanged.

| Sub | Movement |
|---|---|
| 1 create template | A → template: rent. An adopted pre-fund stays in the template and is A's at close. |
| 2 init run | P → run: rent. |
| 3 commit | E → run: the executor bond. |
| 4 open | C → dispute: rent and the challenger bond. C → both staging buffers: rent at their admitted sizes. |
| 14, 17 stage create, grow | the writing party → its own buffer: rent. |
| 16 cache answer | E → cache: rent. |
| ruling (CLAIM resolution or 9 timeout) | the dispute's lamports above its rent floor (C's bond) → E on an executor win, → C on a challenger win or a neutral (moot) outcome. |
| 12 moot | C's bond → C. E gains nothing. |
| 10 finalize | E's bond → E, from the run, on a run that ends `FINAL`. |
| 13 pay pot | from the run: `bond_slasher_bps` of E's bond → the `best_win` challenger, and the remainder → P. Once only (`R_PAID`). |
| 18 close dispute | bonds have already moved. The dispute's rent → C. Each buffer's whole balance → its recorded creator (byte 5): E's buffer → E only if E created it, otherwise → C. |
| 19 close run | the run's lamports above the receipt's rent → P. |
| 20 close cache | the cache's rent → its recorded executor. |
| 21 close template | the template's whole balance → A. |
| cancel (sub 19 on an `OPEN` run) | the run's whole balance → P. |

**Design and code differ (surfaced, not resolved).** Design §10.3 says the
pot's remainder goes to "the committed destination, the payer or the
incinerator". The program pays the run's payer only, and `init_run` refuses a
payer equal to the named executor. Design §10.2 also describes a zero-key
executor ("anyone may commit"). The program's commit requires the signer to
equal the recorded executor key, so that mode is not built. The program is
what this table states.

**Catches.** A bond paid twice or to the caller. Rent returned to the closer.
A pot paid before the ruled prefix passes `best_win`. A growth funder's rent
silently absorbed.

**Status.**
- Measured: exact lamport conservation in the skeleton tests and in every
  cell of the every-ending matrix (`2dfb0e0`), in both role orders.
- Not checked: a sum over all accounts across a long random run. That is the
  run-level fuzzer's job.
- Known, accepted: growth funders are refunded through the buffer's creator
  (design §9, `CLOSE_DISPUTE`).

## 3. Authority and provenance

**Plain English.** Only the right party can make a move, and an account is
trusted only at its derived address. Owning the right bytes is not enough.

**Law.** Before its first write, every transition checks:
- every account it reads or writes is at the exact address derived for its
  role (§Model), with the right owner, magic, length and phase;
- every signer the rule requires is the key recorded for that role (A, P, E
  or C), and an unrelated signer or the fee payer has no authority by being
  there;
- aliases (the same account in two roles) are refused unless the rule names
  them.

**Catches.** A record forged into a program-owned account that is not a PDA,
then accepted by owner and bytes. This is the 2026-10-03 legacy DCR1 finding
(low severity, outside tag 227). Template squatting at another payer's address.
A third party ruling a dispute it is not party to.

**Status.**
- Measured: `account_provenance_lint` covers every tag 227 writer, 18 of
  them, each reviewed with file and line in
  `docs/account-provenance-v21-audit-2026-10-03.md`.
- The template-squatting probes passed in the list r3 re-review.

## 4. Binding

**Plain English.** A claim is about the committed data at the committed place,
and nothing can change that data once a claim depends on it.

**Law.**
- Every revealed node, leaf, spec record and opening verifies against an
  authenticated parent, ending at the committed run root and the admitted
  spec root.
- A run is bound to one template and one run id. Every later instruction
  checks the run's stored template key.
- From the moment a dispute enters `CLAIM`, E can no longer write or grow
  its staging buffer. The bytes a claim reads are frozen.
- A cached answer is inserted only after it verified against an
  authenticated parent. A node has one valid child set, so one dispute's
  answer cannot poison another.

**Catches.** E rewriting its buffer after the reveal to make an honest claim
fail (list r2, 2026-10-03, critical). A run driven by a look-alike template at
another address.

**Status.** Measured by the list oracle's rewrite-after-reveal and
grow-after-reveal regressions, native and SBF, and by the r3 template-binding
probe.

## 5. Deadlines and termination

**Plain English.** Every dispute and run reaches an end in bounded time. Each
phase's deadline is fixed when the phase begins. Nobody can extend it later,
and nobody can revive a phase once it has expired.

**Law.**
- When a phase begins, its deadline is computed once and stored:

  ```text
  base window + extension at that moment
  ```

  Later transitions on this or any other dispute never change it.
- The extension for a phase the executor owes may depend on how many disputes
  are waiting on the executor when the phase begins. It is capped per phase
  (`MAX_WINDOW`). It never depends on disputes waiting on the challenger.
- When `now > deadline`, anyone may time the phase out, and no other
  transition can make that timeout fail.
- Each dispute has at most `2 × (ceil(h/d) + 3)` phases. A run is final at
  most `challenge_window + D(N)` after commit (design §10.2), where `N` counts
  the opens.
- Every rent-bearing account has a permissionless route to close once its
  run settles (§7).

**Catches.**
- **B1** (2026-10-03, high): E banks extension through puppet disputes. Every
  later executor phase then inherits it.
- **B2** (2026-10-03, medium): E opens a puppet just before a timeout and
  revives a phase that had already expired.
- The F4 version on main has a related gap: puppets waiting on their
  challenger count toward E's extension, up to `MAX_WINDOW`.

**Status.**
- **Open violations.** On main: the F4 puppet stretch, bounded by
  `MAX_WINDOW`. On `review/v21-followups-ab`: B1 and B2.
- The fix round stores each phase's deadline at phase start. Its
  regressions must fail on `21e530c` and pass after the fix.

## 6. Determinism and order

**Plain English.** The outcome depends on the committed data and on time,
not on who submits a move or which legal transaction lands first.

**Law.**
- A transition reads only committed records, validated account state, the
  slot (for deadlines) and its instruction bytes. It never branches on the fee
  payer or on an unrelated signer.
- **Ruled prefix.** Disputes are ordered by `sequence`. `best_win` is the
  lowest sequence with a challenger ruling. A dispute with a higher sequence
  is moot on a refuted run, whatever order its own ruling lands in (F1). The
  pot is paid only after `ruled_prefix > best_win`, so its recipient does not
  depend on landing order.
- Independent transitions commute. Two disputes' moves on different dispute
  accounts give the same final state in either order.

### 6.3 Who profits by calling first

Every permissionless instruction, and every instruction a party can race, has
an answer here. A new instruction is not complete without one.

| Instruction | Caller | Gains by calling first |
|---|---|---|
| 9 timeout | anyone | nothing; the ruling is fixed by who owes the phase |
| 10 finalize | anyone | nothing; needs zero open disputes past the deadline |
| 11 advance prefix | anyone | nothing; moves over already-ruled disputes |
| 12 moot | anyone | nothing; returns C's bond |
| 13 pay pot | anyone | nothing; recipients are recorded |
| 18–20 closes | anyone | nothing; rent goes to recorded payers |
| 1 create template | any admitter | its own address only; no control of another payer's template |
| 4 open | any challenger | a place in the sequence order; the first win becomes `best_win`. This is the intended reward for finding the first divergence |
| 21, 22 retire, close template | the recorded admitter only | — |

**Catches.** A pot paid to whoever settles first. A ruling that changes with
landing order (the revision-8 `record_winner_if_unset` gap).

**Status.** Measured for the dispute order in the skeleton suite's
alternate-order tests and the matrix. Permuting many disputes is the
run-level fuzzer's job and is not yet measured.

## 7. Terminality and close safety

**Plain English.** Once a dispute is ruled, only closes may touch it. An
account stays open while something still needs it. Its rent then goes to the
party that paid it, never to the closer.

**Law.**
- After `RULED`, every dispute instruction except the closes is refused.
  That includes staging create, write and grow on its buffers.
- `CLOSE_DISPUTE` needs a ruled or moot dispute that the ruled prefix has
  passed. A winning challenger's dispute also waits until its pot is paid.
- `CLOSE_RUN` needs a settled run with every dispute closed. It leaves the
  receipt at the run address, so a run id cannot be committed twice.
- `CLOSE_TEMPLATE` needs zero active runs and the recorded admitter's
  signature.
- Every close pays the recorded payer (§2), and a second close is refused.

**Catches.** Staging writes accepted after a ruling (matrix finding,
2026-10-03, on main). A template closed under a live run. A run re-committed
after its receipt was closed.

**Status.**
- Measured: the skeleton suite covers cancel, retire, final and refuted
  receipts, claim and timeout rulings, moot, legacy read-only templates,
  pre-funded adoption and front-run creation. Nine planted guard bugs were
  each caught.
- **Open violation:** post-ruling staging. The ignored reproducer is in
  `2dfb0e0`, and the fix round refuses it.

## 8. Neutrality

**Plain English.** A moot ruling is the protocol admitting it cannot decide.
It returns every bond and gives nobody anything. It must be rare and
declared in advance, so that nobody can steer a dispute into it for free.

**Law.**
- A dispute ends `MOOT` only in these cases:
  - it was opened after `best_win` on a refuted run (F1);
  - its claim falls in a case this spec declares undecidable. Today that is
    LOG STEP claims; LOG STATE claims whose predecessor is the initial state
    (kinds 0 and 3); and, pending a reference model, kind 2.
- On an admitted template, a challenger cannot reach a declared-undecidable
  case. Admitters must refuse LOG-state templates until LOG is judged on chain
  (re-review condition, design §9). The program cannot check this, because it
  trusts the spec root.

**Catches.** A challenger steering any dispute to a LOG step for a free moot
that delays finality. An undecidable case that rules against either party.

**Status.**
- Designed. The admitter rule is a documented condition, not something the
  program enforces.
- Python and the program disagree on state scheme 3 and above (`game.py`
  checks `!= 2`, the program `> 1`). The fix round aligns them.

## 9. Admission bounds

**Plain English.** A template can only be admitted with economics and limits
under which the other laws can hold.

**Law.** Admission refuses a template unless:
- the executor and challenger bonds are nonzero (F4);
- `bond_slasher_bps < 10,000`, so the remainder is nonzero (design §10.3),
  and `init_run` refuses a payer equal to the named executor, since the payer
  receives the remainder. An executor can still pay through a key it controls
  under another name; the deterrent then rests on the payer being a real
  watcher (F11, accepted);
- every window is within `[MIN_PHASE_WINDOW, MAX_WINDOW]`;
- `extend_slots` is at least the measured `answer_slots` (§8.3);
- the largest opening, leaf, spec record, reveal and witness each fit the
  staging cap (1 MiB), and each STEP claim fits the challenger's 128 KiB
  claim buffer;
- every kernel resolves by its exact id and advertises the mode its claims
  need (F2, F9);
- a list step has at most 1,024 elements;
- LOG chains keep one state scheme and capacity (A1, after the fix round).

**Status.** Measured for the planner and program refusals in the list and
skeleton suites. The `answer_slots` measurement under pick spam (R3-S5) is
still open.

## 10. LX1 additions (designed)

LX1 (`docs/design/v2.1-lazy-expansion.md`) adds checkpointed state chains. The
laws above apply unchanged. LX1 adds these:
- **Commit binding.** The checkpoint coordinates are derived from `k` and the
  schedule; the executor supplies only roots. `R_0` must equal the admitted
  initial state's root.
- **Fixed midpoints.** Midpoint coordinates are fixed by the interval and the
  arity. E supplies only their roots.
- **Opening.** The opening must cover exactly the transition's read and write
  slots and verify against the agreed lower root (canonical multi-proof). A
  kernel failure on a verified opening rules `CHALLENGER`, because a
  committed state that cannot step cannot lead to the committed upper root.
- **Outputs.** An OUTPUT claim opens the output slots against `R_T`. C wins
  exactly when an opened value differs from the claimed output.
- **Accepted property, not a violation.** A wrong intermediate state that
  heals before the next checkpoint cannot be disputed. Only checkpoint states
  and outputs are claims.

Status: the Python reference and the pure Rust functions (slot leaves, the
proof fold, coordinates, `pick_interval`) are measured against golden vectors.
The program handlers are not built yet.

## 11. The bendSVM settlement subset

These transitions decide winners, amounts, recipients and deadlines, and are
small in compute:
- 9 timeout;
- 12 moot;
- 13 pay pot;
- 10 finalize;
- 18 close dispute;
- 19 close run, including cancel;
- 20 close cache;
- 21 close template.

They are the proposed target for the bendSVM pilot. The design is a Bend core
that decides, checked against §§1, 2, 5, 6.3, 7 and 8, with a Rust shell
that keeps §3's account checks and executes the core's plan.

Out of scope for bendSVM:
- the descent and claim replay (`REVEAL_*`, `PICK`, `CLAIM`): kernels,
  hashing and proof folds, which are compute-tight and checked by golden
  vectors;
- staging writes.

## Evidence summary

| Law | Main `3df716d` | After the follow-up fix round |
|---|---|---|
| 1 Honest wins | measured for the scenario sets | A1 must be refused at admission |
| 2 Conservation | measured per matrix cell | unchanged |
| 3 Authority | lint green for tag 227 writers | unchanged |
| 4 Binding | measured (buffer freeze, template binding) | unchanged |
| 5 Deadlines | **F4 puppet stretch, bounded by `MAX_WINDOW`** | B1/B2 regressions must pass |
| 6 Order | measured for two-dispute orders | fuzzer pending |
| 7 Terminality | **post-ruling staging accepted** | refusal must pass |
| 8 Neutrality | designed; admitter rule documented | scheme check aligned |
| 9 Admission | measured for current refusals | LOG chain rule added |
