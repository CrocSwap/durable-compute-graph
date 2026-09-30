# Referee laws

Status: **designed contract**, assessed against `durable-compute-graph` commit
`4d1446f` (2026-09-30). This document adds no instruction or wire behavior.
The `dcg-repo/docs/spec/` directory at that commit contains only its license;
the README and Rust comments refer to `docs/spec/dcg-unified-v1.md`, which is
not present in the DCG checkout. The Basanos copy describes older revision-7
semantics. Treat this page as a proposed invariant list for the revision-8
referee, and reconcile it with a checked-in, versioned machine spec before
claiming the laws are normative.

`pending seam-fix-2` marks a law whose current status or testability depends on
the in-flight change that moves application replay into an executor `RESPOND`
step. No such core change is included in this checkout.

## Model and notation

Scope is the revision-8 unified document and its referee/account lifecycle:
registry and template admission, document initialization and root landing,
challenge opening and descent, ruling, bond settlement, and close. The separate
feature-only stateful tags 230–239 are outside this referee model.

Let chain state `S` map every address `a` to
`A[a] = (owner, data, lamports, executable)`, and include the current slot.
An instruction transition is `T(S, ix, fee_payer) -> S'` or a refusal. Its
instruction tag names the rule that may write. `PDAs(program, descriptor, …)`
means the exact derivation in `unified/address.rs`; a record's magic, version,
length, and fields must also match its account kind. A refusal is atomic for
program state: all instruction and CPI writes roll back. The Solana transaction
fee is still charged by the runtime and is accounted separately.

Challenge records (DCR1) have phases `RESPOND`, `SEALED`, `RULED`, `SETTLED`,
`REVEAL`, `DESCEND`, `POSITION_REVEAL`, and `SELECT`. A DCM2 document records
its descriptor, executor/payer, admitted PT2S address and digest, finalization
and abandonment deadlines, open-challenge count, ruling flags/counter, and
bond state. DPR2 contains landed position roots; DFS2 contains the admitted
family table; DCR2 retains the durable result/tombstone. Revision-8 handlers
are in `crates/dcg-program/src/unified/`; tags 156–169 and 172–187 dispatch
through `unified/mod.rs`.

The laws below are requirements over *all accepted transitions*, not claims
that the present implementation has been proved correct. “Existing harness”
refers to Basanos `chain/dcg-program/tests/lifecycle_property_harness.rs`,
which is also present in this clone. The current Rust assessment is scoped to
the revision-8 Rust source at the commit above, not to a deployed image.

| Law | Current Rust | Bugs this law catches | Existing harness coverage |
|---|---|---|---|
| Honest party wins | **No** — pending seam-fix-2 | Executor wins without opening; unprovable leaf; malformed challenge that strands an honest party | No honest app-replay role-order or silence case |
| Conservation | **Unknown** | Unexplained bond, escrow, fee, or rent delta | Partial setup/close and malformed-refusal balance checks |
| Authority | **Yes**, for the reviewed revision-8 paths | Tag 98/146 writable-account takeover | Malformed tag-146 attempts, wrong-authority close, and unsupported-tag refusal |
| Binding | **No** — pending seam-fix-2 | Missing predecessor binding; stale RUN_BINDING/package digest | No predecessor substitution or stale-digest adversarial lifecycle |
| Termination | **No** | Timeout-wins rule missing at app replay; unreachable final leaf; unbounded bond retry | Only terminal close/replay refusals; no referee timeout completion |
| Determinism | **No** for document bond winner; pending seam-fix-2 for replay | Caller/order-dependent ruling or settlement | Does not permute competing valid challenges or submitter order |
| Close safety | **Yes** on the reviewed revision-8 close paths | Closing a live dependency; rent paid to closer instead of named payer | PT1X rent refund, wrong-authority refusal, double-close, and reinitialization refusal |

## 1. Honest party wins — pending seam-fix-2

**Plain English.** A party that supplies the correct protocol data and takes
every required turn on time never loses because the other party lies, omits an
opening, or goes silent. A bad proof supplied by a challenger may lose that
challenge, but it must not turn correct executor data into a conviction. A
party's signature on the turn it owes cannot be replaced by the other party's
silence.

**Law.** For a committed leaf `l` at document `d` and coordinate
`q = (position, segment, local)`, let `K` be the statically selected kernel
identity and `x` the canonical inputs committed for that step. Define
`good(d,q) := output_leaf(d,q) = K(x)` and `bad(d,q) := !good(d,q)` after
successful authentication of the committed leaf and inputs. For each dispute
state `c`:

- if `good(d,q)`, every legal complete challenge path ends with
  `winner(c) = EXECUTOR`;
- if `bad(d,q)` or the executor's committed input cannot be decoded/replayed,
  an honest challenger with a valid coordinate proof can reach
  `winner(c) = CHALLENGER`;
- if the required executor turn is silent past its deadline, the permissionless
  timeout transition sets `winner(c) = CHALLENGER`; if the required challenger
  turn is silent, timeout sets `winner(c) = EXECUTOR`;
- no absent/invalid witness supplied by the party that does *not* own the
  response turn may make that party lose.

All terminal rules set DCR1 winner/phase/cause and the document's refutation
counter/flag atomically. In this law, a refusal is not a ruling: the same
honest party must still have a legal route to a terminal ruling or timeout.

**Bugs caught.** This catches the seam re-review's executor-signed `k=0`
fix-point that lets the executor omit its witness and make the challenger lose
with 734. It also catches a non-ARW1, oversized, or otherwise undecodable leaf
whose preimage the challenger cannot provide: a required opening must be made
by the executor, and a matching but invalid committed opening convicts the
executor (799). It catches the earlier case where malformed replay input
refuses instead of deciding, leaving a timeout route that rewards the
executor.

**Current Rust: No.** `challenge.rs::reveal_with_manifest` accepts a `k=0`
opening with no witness bytes; `fix_point` treats absent or malformed
challenger-supplied preimage as proof failure 734 and records an executor win.
The executor is the signer on tag 168. The seam re-review identifies this
case as critical and says no SBF scenario covers it. The same review identifies
leaves that cannot be convicted without a decodable preimage. These branches
break the law directly.

**Existing harness.** The lifecycle property harness sends malformed
instructions and confirms atomic refusal. The artifact-backed
`unified_v8_document.rs` exercises honest and malicious ByteSum examples, but
neither harness tests an executor that withholds the opening, a correct
challenger against an undecodable leaf, or both role orders with silence.
Those app-replay cases are **pending seam-fix-2**.

## 2. Conservation

**Plain English.** Every lamport movement has one named source, one named
destination, and an exact amount. Bonds, rent, escrow balances, and runtime
fees cannot appear, disappear, or be redirected silently. Every touched
account's resulting balance follows from its prior balance and those movements.

**Law.** For every successful transition and every touched account `a`,

```text
L'(a) = L(a) + sum(credits_to(a)) - sum(debits_from(a)) - runtime_fee(a)
```

where each credit/debit is a System Program transfer, a checked program
transfer, a settlement payout, or an explicit transfer to the named
incinerator. `runtime_fee(a)` is nonzero only for the transaction fee payer
and is the runtime-reported fee. Across the chain account set, the only net
decrease is the runtime's burned fee component; the remaining fee credit is
the runtime's fee-recipient movement. Rent exemption is a balance held by an
account, not a protocol fee. A refusal changes no program-owned bytes or
lamports, though the runtime fee payer still pays the transaction fee.

The transition ledger must account for, at minimum:

1. **Init (161):** the recorded executor funds DCM2/DPR2/DFS2/DCR2 account
   creation rent and the committed executor bond. The DCM2 balance is at least
   its rent floor plus any live bond.
2. **Challenge open (166/167):** the challenger funds the DCR1 rent shortfall
   and its committed challenge bond; DCM2's open count increments. A
   pre-funded PDA's prior balance remains part of the same equation.
3. **Settle (131):** the DCR1 challenge bond is credited to the ruling winner;
   remaining DCR1 lamports return to the challenger; a DRU1 response account
   returns to the recorded executor. A live executor bond follows exactly the
   committed STANDARD split or enters the descriptor-derived bond escrow for
   the committed CUSTOM settlement program. No caller-selected destination
   receives a share.
4. **Document close (172):** every remaining DCM2/DPR2/DFS2 lamport is
   distributed by the committed bond disposition and the recorded payer
   refund rule. The DCR2 result rent is retained only at its specified floor;
   tag 185 sends excess rent to its recorded executor. A live custom escrow is
   its own separately balanced account.
5. **Template/output close (186/197/198/200):** each allocation's complete
   balance is either kept at its own address by the specified System reassign,
   or drained to the owner/payer recorded when it was created.

**Bugs caught.** Conservation surfaces a stolen or missing bond, rent not
returned, a settlement escrow that retains a pot after success, or an
unaccounted fee. The tag 98/146 takeover is primarily an authority failure;
it is also visible here if it changes balances.

**Current Rust: Unknown.** `terms.rs` uses checked `u64` deadline arithmetic
and `u128` bond splitting; `bond.rs`, `result.rs`, and `challenge.rs` name
settlement and drain paths. The lifecycle property harness checks conservation
for setup and close transfers, and checks non-fee balances on malformed
refusals. It does not reconcile every account delta across every valid
admission, dispute, standard/custom settlement, retention close, and runtime
fee path. The current evidence is partial, not a proof of the universal law.

**Existing harness.** The positive PT1X init/close path checks total tracked
lamports and the authority's exact refund; malformed generated operations
check that non-fee accounts and lamport totals are unchanged. It does not
include the fee payer in the balance equation or account for protocol bonds.

## 3. Authority

**Plain English.** Only a handler with a named rule may write an account. A
writable account supplied by a caller is not authority to change it.

**Law.** For a transition `T` with write set `W(T)`, every `a ∈ W(T)` must
first satisfy all of the following before the first mutation:

1. the instruction rule names `a`'s role and whether it is writable;
2. `a.key` is the exact PDA or recorded key for that role;
3. `a.owner`, magic, version, data length, and lifecycle phase match that role;
4. required signer keys equal the account's recorded authority, executor,
   challenger, or payer; unrelated transaction signers and the fee payer have
   no authority by implication;
5. aliases are rejected unless the named rule explicitly permits them.

Every CPI write is covered by the same rule: the System Program may create,
assign, or transfer only the validated address and amount; the bond settlement
program receives only the committed destinations and must satisfy the
postconditions in the committed settlement rule. A refusal leaves all
program-owned account bytes and balances unchanged.

**Bugs caught.** This catches the historical tag 98/146 bug where a fee payer
could point an output at and overwrite a program-owned account. It also catches
wrong-authority rent close and account-substitution attacks.

**Current Rust: Yes for the reviewed revision-8 entrypoints.** The revision-8
dispatcher does not route legacy tag 98. Tag 146's `instantiate_with_mode`
checks PT1X state/template ownership and binding, requires the PT1X-recorded
authority as the writable signer paying rent, derives the PT1O address from
the input tuple, and rejects aliases. The close paths validate the stored
authority/payer and derived account kinds. The property harness probes
malformed tag 146 and wrong-authority tag 197; the added `referee_laws.rs`
also passes a writable program-owned sentinel to tag 98 and checks that it is
unchanged. This is a source-and-handler assessment for revision 8, not a
claim about the retired revision-7 dispatcher or every future app image.

**Existing harness.** It checks required signer/writable roles, substituted
accounts, bad owners/kinds, and atomic refusal across the lifecycle allowlist;
it includes a wrong-authority PT1X close and scans unsupported tags. It does
not vary the transaction fee payer across every successful handler or prove
all write sets by generated source analysis.

## 4. Binding — pending seam-fix-2

**Plain English.** A step opening proves the exact committed leaf at the exact
coordinate, and its inputs are the outputs that the committed graph says feed
that step. A record's claimed package and template are exactly the ones
admitted and sealed for that document.

**Law.** Let `D` be the descriptor; `q=(p,s,i)` the position, segment, and
local leaf; `R_D` the committed document root; `P` the sealed PT2S package
bytes; and `B=(routes, geometry, payloads)` the base template accounts. Then:

```text
leaf_path(D, q, opened_leaf) = R_D
replay_leaf = H("app-replay-leaf/1", D, q, app/kernel/mode/form identity,
                canonical_inputs, claimed_output)
canonical_inputs(q) = ordered predecessor outputs named by the sealed graph
package_digest = SHA256(P)
template_base_digests = SHA256(routes), SHA256(geometry), SHA256(payloads)
```

The descriptor, DCM2, admission record, DTA1/DTU1 approval/use records, DCR1,
and any terminal DCR2 identity must all name the same `D`, `package_digest`,
and base digests. At init, the exact sealed package digest must match both its
admission and approval/use PDAs. A caller may not substitute a same-shaped
package, a stale digest, a neighboring coordinate, a different app/kernel
version, or an input copied from another step. Every hash uses the versioned
canonical encoding and domain named by the applicable machine spec.

**Bugs caught.** This catches the missing binding from an opened step to its
predecessor output, the `RUN_BINDING`/stale package digest failure, and reuse
of a valid witness at another coordinate or document.

**Current Rust: No overall.** The exact-coordinate app leaf digest includes
the descriptor, `(p,s,i)`, app/kernel/mode/form identity, and ARW1 witness;
`init_v8` hashes the sealed PT2S and compares it to the admission and the
digest-keyed DTA1/DTU1 records, and checks the PT2S base digests. Those checks
address the package/template sublaw in the inspected source. The higher-level
step law still fails: the seam re-review found no binding of opened inputs to
predecessor outputs/routes, allowing an executor to commit `X'` and the
correct `K(X')`. That finding is marked **pending seam-fix-2**. The checked-in
DCG checkout has no versioned spec or golden that independently settles the
stale-digest question; the source checks are evidence, not a cross-version
conformance result.

**Existing harness.** The lifecycle property harness exercises wrong account
addresses/owners and malformed inputs, but it does not substitute predecessor
outputs while keeping an otherwise valid step opening, nor mutate an admitted
package digest in a complete document. The app-replay SBF scenarios listed in
the seam experiment do not cover findings 1–4. Predecessor binding remains
**pending seam-fix-2**.

## 5. Termination — pending seam-fix-2

**Plain English.** Every open dispute and document has a finite path to a
terminal status. After a response deadline passes, any signer can submit the
timeout/settlement/close instruction that completes the path. No silent party,
unreachable proof, or failed callback can hold protocol state or rent forever.

**Law.** At finalize, the challenge-open deadline is fixed from the committed
challenge window. Each response phase writes its own deadline as
`phase_slot + response_window_slots`; terms validation checks bounded windows
and checked addition. For every open DCR1 there must be a finite bound
`N(c)` on accepted transitions: each nonterminal transition strictly advances
a bounded phase/cursor measure (remaining position roots, segment selection,
tree height, and bounded response bytes), and cannot restart an earlier
measure. After its current deadline `d`, `now > d` enables a permissionless
timeout. A timeout fixes a winner, tag 131 settles the challenge bond and
closes DCR1, tag 172 closes DCM2/DPR2/DFS2 after the dispute window and
`open_challenges = 0`, and tag 185 closes the result after retention. Template
close is then enabled after its dependent-document/reservation counters reach
zero. Under chain progress and transaction inclusion, the completion time is
bounded by the committed open window plus `N(c) * response_window_slots`,
settlement, retention, and the runtime inclusion allowance.

The bound covers the entire committed lifecycle, including any external bond
callback or a documented escrow tombstone. An explicit exception is allowed
only if the protocol states that the exception is not part of finality and
proves it cannot block any dependent close or user balance.

**Bugs caught.** This catches the app-replay refusal/timeout path that lets a
cheating executor win, an undecodable leaf that cannot be convicted, and any
transition whose failure leaves no permissionless next step. It also catches
an unbounded bond retry if that escrow is included in the claimed final state.

**Current Rust: No for full account finality.** Ordinary revision-8 challenge
rounds write deadlines and tags 132/131/172/185 provide permissionless timeout,
settle, and close paths. But `bond.rs` explicitly gives tag 187 no deadline:
a custom settlement program can refuse forever, leaving the bond escrow live
and the result tombstone unable to finish its retention close. Also, the app
replay witness-withholding path gives the executor a winning fix-point instead
of the timeout-required by this law. The replay part is **pending
seam-fix-2**. The liveness claim must either bound tag 187 with a deterministic
fallback or explicitly narrow “final state” to the already-fixed ruling and
document close.

**Existing harness.** The lifecycle harness checks that a successfully closed
unpublished PT1X cannot be double-closed or reinitialized at the same account
state. It does not drive a valid DCR1 through deadline timeout, settlement,
document close, result retention, and custom escrow retry. The seam review says
none of the SBF scenarios reaches the disputed omission/input cases.

## 6. Determinism

**Plain English.** Given the same committed bytes, account state, slot, and
instruction, the referee reaches the same ruling no matter which relayer pays
the fee or which legal independent transaction lands first.

**Law.** The transition function may read only committed protocol data, the
validated current account state, the current slot when a deadline rule needs
it, and explicit instruction bytes. It must not branch on fee payer, unrelated
signer, RPC arrival order, host state, or uncommitted caller-supplied values.
For the same prestate and semantic input, role-equivalent submitters produce
the same `(winner, cause, code, bond disposition)`. Any two legal transitions
declared independent by the state machine must commute:
`T1(T2(S)) = T2(T1(S))`, including the durable ruling and payout record.
Where transitions share a scarce resource, the spec must define a committed
tie-break independent of landing order.

**Bugs caught.** This catches order-dependent verdicts, user-selected or
caller-selected replay inputs, and first-submitter-wins payout state.

**Current Rust: No for the full document payout record; app replay is also
pending seam-fix-2.** A single DCR1 fix-point uses committed bytes and the
selected static kernel, but the seam re-review shows its executor/challenger
opening distinction can change who gets to supply the witness. At document
settlement, `record_winner_if_unset` records the first settled conviction
winner. With multiple valid challenger wins, reordering tag 131 settlements
can change the DCM2 recorded bond winner and thus the bond split recipient.
That is an explicit first-write rule, not an order-independent tie-break.

**Existing harness.** The lifecycle property harness uses deterministic
malformed input seeds and checks refusal atomicity. It does not permute the
same honest/malicious dispute through both role orders, change fee payer, or
settle multiple winning challenges in opposite orders. The replay-order
requirement is **pending seam-fix-2**.

## 7. Close safety

**Plain English.** An account stays open while a live document, dispute,
template admission, result retention, or settlement needs it. When a close is
allowed, its remaining rent goes to the payer recorded for that allocation,
not to whoever submits the close.

**Law.** Let `refs(a)` be all live protocol records that read account `a` or
whose legal next transition requires `a`. A close of `a` is accepted only if
`refs(a) = 0`, except where it atomically closes the dependent record in the
same transition. Examples:

- settle consumes one open DCR1 and decrements DCM2's open count; DCR1's
  challenge bond goes to the ruling winner and its residual rent to the
  recorded challenger;
- tag 172 requires the challenge deadline to have passed and zero open
  challenges, decrements the DTU1 document count, returns DCM2/DPR2/DFS2
  lamports to the DCM2-recorded payer, and leaves DCR2's retention record;
- tag 185 requires document close and retention expiry, leaves the defined
  tombstone rent floor, and refunds excess to the recorded executor;
- tag 186 requires no dependent live documents/reservations and pays the
  PT1X owner, PT2S owner, and seal payer their recorded allocations;
- an unpublished tag-197 close is allowed only for its exact unbound setup
  shape; a zero-data allocation keeps its rent at its own address rather than
  accepting a caller-selected payee.

For every rent-bearing account `a` with recorded refund recipient `p`, close
must prove `p` from the account record and apply either
`L'(p) = L(p) + L(a); L'(a) = 0` with cleared data/System ownership, or the
specified same-key reassignment. It may not refund the closer by default.

**Bugs caught.** This catches early close while a challenge/template still
depends on the account and rent redirected to an arbitrary closer.

**Current Rust: Yes on the reviewed revision-8 close paths.** `close_v8`
requires no open challenge and a passed final/abandon deadline, verifies the
recorded payer, releases the template use count, and drains document working
accounts to that payer. Result/template/output close handlers validate their
recorded recipients and dependency counters. The lifecycle property harness
checks the exact PT1X rent refund, attacker balance, wrong-authority refusal,
double close, and closed-state replay refusal. Artifact-backed document tests
exercise the revision-8 close/retention edges. This is source plus focused
handler evidence, not a formal proof of every account kind.

**Existing harness.** The lifecycle harness's handler-produced PT1X path
measures the authority refund as the sum of state/base balances, verifies the
attacker receives none, and requires a second close and setup replay to refuse
atomically. Its malformed generated attempts also snapshot touched accounts.
It does not construct all published-template and DCR2 retention dependencies;
those are in the artifact-backed document tests.

## Harness gap summary

`lifecycle_property_harness.rs` is a useful native handler property probe, not
a proof of dispute capability. It checks the real revision-8 dispatcher,
malformed role/account mutations, atomic refusal, tracked-lamport
conservation on setup/close, recorded rent recipient, and terminal unpublished
close. It does not currently establish honest-wins, predecessor binding,
full dispute termination, settlement order independence, or the complete
bond/fee/rent equation across a successful published document lifecycle. The
new `tests/referee_laws.rs` adds focused native checks for tag-98 refusal and
the PT1X close laws without changing the existing harness.
