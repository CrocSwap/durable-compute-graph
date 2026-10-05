# Referee laws for v2.1 disputes (tag 227)

Status: **designed contract**, written 2026-10-03 against DCG main `3df716d`
plus the follow-up fix round (`fast/v21-followups-ab-fix2`), and corrected
after that round's independent re-review. It states what every accepted tag 227
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
| Dispute | `["dcg21dsp", run, challenger, nonce]` | challenger (sub 4) | the challenger |
| Staging buffer | `["dcg21stg", dispute, role]` | sub 14: C may create either role; E may create its own if C has not. Any signer may fund growth (sub 17). Sub 27 (LX1 staged open): C may create its role-2 buffer before the dispute exists, for the address `["dcg21dsp", run, C, nonce]` | the recorded creator, byte 5 |
| Reveal cache | `["dcg21rc", run, kind, level, position]` | the executor, at REVEAL_NODES (sub 5) | the executor, recorded in the cache |

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
deadline is computed with checked `u64` arithmetic. Admission bounds the
challenge window to `[MIN_WINDOW, MAX_WINDOW]` (`MIN_WINDOW` is 1 slot) and
the phase window to `[MIN_PHASE_WINDOW, MAX_WINDOW]` (750 slots minimum).

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
- A1 is avoided, not judged. The program sees only the spec root, so it
  cannot refuse a LOG chain that changes scheme or capacity. It therefore rules
  every LOG STATE and STEP claim moot (§8), as main already did. The Python
  plan builder refuses such chains, including LOG → SMALL; the program does
  not.

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
| 4 open | C → dispute: rent and the challenger bond. |
| 5 reveal nodes | E → reveal cache: rent, when it creates a cache entry. |
| 14 stage create | the creator (C for either role, or E for its own) → the buffer: creation rent. |
| 17 stage grow | any signer → the buffer: rent for the growth; refunded through the buffer's recorded creator at close. |
| 16 cache answer | none; anyone may call it. |
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
- Every dispute, run, cache and staging account has a permissionless route
  to close once its run settles (§7). A buffer staged for a dispute that
  never opened (sub 27) closes by sub 27 op 2: by its challenger at any time,
  or by anyone once its run is final, refuted, a receipt or gone; its rent
  returns to the challenger. A template closes only with its
  admitter's signature, once its active-run count is zero; until then its
  rent is the admitter's own choice to leave in place.

**Catches.**
- **B1** (2026-10-03, high): E banks extension through puppet disputes. Every
  later executor phase then inherits it.
- **B2** (2026-10-03, medium): E opens a puppet just before a timeout and
  revives a phase that had already expired.
- The F4 version on main has a related gap: puppets waiting on their
  challenger count toward E's extension, up to `MAX_WINDOW`.

**Status.**
- **Main (`3df716d`): open violation.** F4 counts puppets that are waiting
  on their own challenger toward E's extension, bounded by `MAX_WINDOW`.
- **After the fix round:** each phase's deadline is stored at its start
  (open, pick, `next_phase`), and nothing else writes it. The re-review
  measured this with probes RR-P1, RR-P2 and RR-N1 to RR-N3: no revival, no
  banking, invariance under puppet bursts, and the wait count balanced over
  every exit. Those probes are kept as regressions in the skeleton suite.
- **Accepted cost:** under a burst of N picks, the k-th wait gets k windows,
  not N each (RR-N7). An honest executor answering in order still meets every
  deadline. The answer time under pick spam (R3-S5) is unmeasured.
- **Upgrade:** runs created before the wait trailer are refused with
  error 40, so an in-place upgrade needs a full drain first (design §9).

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
| 16 cache answer | anyone | nothing; it ends one executor wait with an already-verified answer, at most once per dispute and node |
| 17 stage grow | any funder | nothing; the funder pays rent that is refunded to the buffer's recorded creator, not to the funder |
| 13 pay pot | anyone | nothing; recipients are recorded |
| 18–20 closes | anyone | nothing; rent goes to recorded payers |
| 1 create template | any admitter | its own address only; no control of another payer's template |
| 4 open | any challenger | a place in the sequence order; the first win becomes `best_win`. This is the intended reward for finding the first divergence |
| 27 pre-open staging (create, write) | the challenger only (the dispute address is derived from the signer) | nothing: no dispute, bond, sequence or deadline exists until the open. The staged body is masked by a secret that only the open carries, so a watcher learns nothing it could open with first; front-running the open itself is the same race as an inline open |
| 27 op 2 close of an unopened buffer | the challenger any time; anyone once the run cannot be disputed | nothing; the rent goes to the challenger |
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
- After `RULED`, the only instructions that may act on the dispute are:
  - advance prefix (11) and pay pot (13), which read its ruling;
  - the closes (18–20).

  Every other dispute instruction is refused, including staging create,
  write and grow on both of its buffers.
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
- **Main (`3df716d`): open violation.** Staging is accepted after a ruling.
- **After the fix round:** it is refused. Probe RR-N4 creates both buffers
  before the ruling, then tries create, write and grow (by the owner and by
  a third-party funder), all refused, with balances and sizes unchanged.
  Close then still pays the recorded creators.

## 8. Neutrality

**Plain English.** A moot ruling is the protocol admitting it cannot decide.
It returns every bond and gives nobody anything. It must be rare and
declared in advance, so that nobody can steer a dispute into it for free.

**Law.**
- A dispute ends `MOOT` only in these cases:
  - it was opened after `best_win` on a refuted run (F1);
  - its claim falls in a case this spec declares undecidable. Today that is
    every LOG STATE and LOG STEP claim (state scheme 2 or above), whatever
    its predecessor kind. The program cannot check LOG chain shapes, so it
    does not judge any of them (A1).
- On an admitted template, a challenger cannot reach a declared-undecidable
  case. Admitters must refuse LOG-state templates until LOG is judged on chain
  (re-review condition, design §9). The program cannot check this, because it
  trusts the spec root.

**Catches.** A challenger steering any dispute to a LOG step for a free moot
that delays finality. An undecidable case that rules against either party.

**Status.**
- Designed. The admitter rule is a documented condition, not something the
  program enforces.
- Python and the program agree on the neutral cases after the fix round:
  both treat scheme 2 and above as neutral.

## 9. Admission bounds

**Plain English.** A template can only be admitted with economics and limits
under which the other laws can hold.

**Law.** These bounds are enforced in three places.

*The program, at template admission (sub 1) and `init_run` (sub 2):*
- the executor and challenger bonds are nonzero (F4);
- `bond_slasher_bps < 10,000`, so the remainder is nonzero (design §10.3);
- `init_run` refuses a payer equal to the named executor, since the payer
  receives the remainder. An executor can still pay through a key it
  controls under another name; the deterrent then rests on the payer being a
  real watcher (F11, accepted);
- the challenge window is within `[MIN_WINDOW, MAX_WINDOW]`, and the phase
  window within `[MIN_PHASE_WINDOW, MAX_WINDOW]`.

*The program, at claim time (not at admission):*
- a kernel resolves only by its exact id and must advertise the mode the
  claim needs (F2, F9); otherwise the claim rules as the spec says;
- a list step has at most 1,024 elements.

*The planner (Python `PlanBuilder`) and the admitter, which the program
trusts through the spec root:*
- every opening, leaf, spec record, reveal and witness fits the 1 MiB staging
  cap, and every STEP claim fits the challenger's 128 KiB claim buffer;
- a kind-1 state link that touches LOG on either side keeps one scheme and
  capacity, which also refuses LOG → SMALL (A1);
- LOG-state templates are refused while LOG is neutral (§8).

There is no `extend_slots` parameter. The executor's extension is one phase
window per other live executor wait (§5).

*The admitter, for LX1 templates:* `phase_window` covers the worst
first-round recompute plus the answer (the executor recomputes up to
`(a-1)/a` of a checkpoint interval from its nearest snapshot), and the
challenger's pick window covers its own recompute; the challenge window covers
one full re-execution of the run. The program does not scale windows by `k`
or by the interval (LX1 program review M2).

**Status.** Measured for the program refusals in the skeleton suite, and for
the planner refusals in the Python suite. A template admitted without the
planner is trusted subjectively, as the admission-cursor decision allows.

## 10. LX1 additions

LX1 (`docs/design/v2.1-lazy-expansion.md`) adds checkpointed state chains. The
laws above apply unchanged. LX1 adds these:
- **Commit binding.** The checkpoint coordinates are derived from `k` and the
  schedule; the executor supplies only roots. The machine parameters
  (inputs, length) are admitted by the payer: their digest is the run's
  input id. `R_0` must equal the root of the initial state those parameters
  define.
- **Fixed midpoints.** Midpoint coordinates are fixed by the interval and the
  arity. E supplies only their roots.
- **Opening.** The opening must cover exactly the transition's read and write
  slots and verify against the agreed lower root (canonical multi-proof). A
  kernel failure on a verified opening rules `CHALLENGER`, because a
  committed state that cannot step cannot lead to the committed upper root.
- **Constants.** The constant chunks a transition reads are a function of
  the transition and its read values, which are verified against the agreed
  lower root first; they are never chosen by the opening. A read function
  that cannot name its reads for a verified state rules `CHALLENGER`, as a
  kernel failure does. Each must verify against the
  template's `constants_root` (design §13). A wrong, missing, extra or
  reordered constant is a refusal, so a run computed with other constants
  loses at the first transition that reads a changed chunk.
- **Outputs.** The run commits a digest of its claimed outputs. An OUTPUT
  claim opens the true output slots against `R_T`; C wins exactly when their
  digest differs from the committed one. No preimage of the claim is needed,
  so withholding the claimed values does not protect a lie.
- **Machine contract.** Every position has at least one transition, so every
  checkpoint pair can be disputed; a transition that touches no slot is the
  identity. Admitters check the contract; the program cannot.
- **Accepted property, not a violation.** A wrong intermediate state that
  heals before the next checkpoint cannot be disputed. Only checkpoint states
  and outputs are claims.

Status: implemented (tag 227 subs 23 to 26). Native ProgramTests (SBF before
the review fixes) with
the registered toy machine replay 16 played Python disputes in both role
orders, the OUTPUT claim, refusals, timeouts and every ending through the
shared settlement; the independent program review's findings are fixed
(design §12). Not yet measured: an application machine's compute and heap.

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
| 1 Honest wins | measured for the scenario sets | A1 avoided by LOG neutrality; planner refuses the chains |
| 2 Conservation | measured per matrix cell | unchanged |
| 3 Authority | lint green for tag 227 writers | unchanged |
| 4 Binding | measured (buffer freeze, template binding) | unchanged |
| 5 Deadlines | **F4 puppet stretch, bounded by `MAX_WINDOW`** | fixed at phase start; RR probes kept as regressions; full drain before upgrade |
| 6 Order | measured for two-dispute orders | fuzzer pending |
| 7 Terminality | **post-ruling staging accepted** | refused (RR-N4) |
| 8 Neutrality | all LOG claims moot; admitter rule documented | unchanged; Python aligned |
| 9 Admission | program bonds and windows; planner fits | planner refuses LOG chain changes, including LOG → SMALL |
