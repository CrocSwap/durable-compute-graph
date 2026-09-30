# Dispute economics v2

**Status:** designed proposal for the next DCG program version (revision 9). It is
not implemented or measured. Revision 8 remains unchanged, including its
first-settled-challenger payout and unbounded tag 187 retry behavior. This file
specifies settlement economics and the records needed to implement them; it
does not claim that the current Rust handlers or the bendSVM pilot conform.

The run commits one bond policy. The standard policy uses the existing
`bond_slasher_bps` and `bond_remainder` split, but selects the **earliest-opened
challenger whose ruling is a win** as its winner. A custom policy remains an
input to settlement. Every custom run commits a finite fallback deadline and a
standard-policy fallback parameter set. DCG validates the facts and enforces
money conservation, rent release, terminal state, and the fallback deadline
for either policy.

All integer fields below are unsigned little-endian. Reserved bytes must be
zero. `slot` always means the runtime Clock slot. Any `u64` addition is checked;
overflow refuses the instruction without changing program-owned state.

## 1. Opening order and authenticated facts

Each document starts with `next_challenge_sequence = 0`. At a successful
challenge open, DCG reads that value from the validated DCM2, checks it equals
the DPA1 policy-facts record's next value, checks the committed per-run
`challenge_limit`, and assigns the value to the new challenge. In the same
atomic instruction it increments both stored counters and writes the outcome
row. A failed open changes none of these fields and consumes no sequence.

The assigned sequence is a `u64`; `u64::MAX` is never assigned because the
increment must also fit. The run's committed `challenge_limit` is 1 through
1,024, so a successful document cannot exhaust storage or wrap the counter.
The caller's existing challenge nonce remains only a challenge-PDA uniqueness
input. It is not the sequence and does not choose or alter the sequence.

Ties cannot occur: every successful open serially consumes one value from the
single document counter, and the counter increment, DCR1 write, and DPA1 row
write commit or roll back together. Two competing opens can therefore receive
successive values, but never the same value. They may share an `open_slot`; the
slot is recorded as a fact but is not an ordering tie-break. A duplicate
challenge PDA, full challenge table, mismatch between the DCM2 and DPA1
counters, or checked counter overflow refuses.

A policy never accepts a sequence number from instruction data or from a
caller-supplied fact. It receives the sequence in a DCG-owned DCR1 v7 record
and the matching DCG-owned DPA1 row. The handler independently anchors the
record set with the descriptor in the instruction, derives the DCM2, DCR1,
DPA1, and (where used) DCR2/escrow addresses, checks owner, version, parent
identity, and writable roles, then requires all copies of the sequence and
counter to agree. A raw DCR1 sequence field alone is not authenticated. If a
handler cannot validate the descriptor and these parent bindings, it must
refuse before calling the policy.

The DPA1 outcome table is ordered by sequence and has no gaps: row `i` is
sequence `i`; only a successful open can increment `next_challenge_sequence`.
This makes the set of earlier challenges complete and auditable. The policy is
given the row values from validated DPA1 data, not a caller-provided list.

## 2. Winner finality and document-pot selection

A DCR1 ruling has one immutable result: `EXECUTOR`, `CHALLENGER`, or `NEUTRAL`.
The ruling transition writes the same winner, cause, and ruling slot into DCR1
and its DPA1 row. Every transition that can rule a challenge, including
permissionless tag 132 timeout and successful terminal/fix-point paths, must
perform this paired write atomically. Later settlement cannot revise it.

A challenger-win row at sequence `s` is eligible for the document pot only
when **every row with sequence less than `s` is RULED or SETTLED**. Neutral and
executor rulings satisfy that ordering condition; an OPEN lower row does not.
The first document-pot winner is the lowest sequence whose final winner is
CHALLENGER. A later challenger win is never allowed to displace that winner.
The DPA1 ledger lets a settlement check this condition even if an earlier
challenge has already been settled and its large DCR1 account closed.

Tag 131 refuses to settle sequence `s` while any lower sequence is OPEN. This
keeps a later DCR1 available until its eligibility is decidable. Once all lower
rows are ruled, tag 131 may settle any sequence in any order:

- A **challenger win** receives its own challenge bond. If it is the lowest
  challenger-win sequence and the document bond is still HELD, it is the
  document-pot winner. STANDARD applies the committed split to that winner;
  CUSTOM moves the document bond to its escrow and records this winner and
  sequence for the later policy call. If a lower challenger-win row exists, a
  later win receives only its own challenge bond.
- An **executor win** receives its own challenge bond and never receives the
  document pot. It is a ruled lower row, so it does not block a later
  challenger win.
- A **neutral ruling** returns that challenge's bond to its challenger. It
  receives no document pot and counts as ruled for later sequences.

An earlier challenger win remains the pot winner even if a later winner's
settlement lands first. That later settlement sees the earlier DPA1 row, pays
only its own challenge bond, and leaves the document bond HELD. The earlier
winner's permissionless tag 131 then applies the document policy. If all
challenges finish without a challenger win, a no-fault terminal close
(`CAUSE_NONE`) returns the still-held document bond to the executor. A
close-time conviction or WITHHELD disposition without a winning challenger
does not invent a challenger sequence or pay a challenger share; the full pot
goes to the committed remainder, with any uncreditable residual sent to the
incinerator. A custom run may call its custom policy at terminal close; its
standard fallback follows the same no-winner rule for the recorded close cause.

The eligible winner is determined from immutable opening sequence and ruling
facts, not from tag 131 landing order. A later settlement cannot alter the
lowest winning sequence. Thus any permutation of successful settlements has
the same document-pot recipient and amount; independent challenge-bond
settlements commute apart from the transaction fee. This is the settlement
property required by referee law 6. An earlier OPEN challenge cannot block
forever: each challenge phase has a committed deadline and permissionless
timeout/ruling; after those rulings, anyone may settle. This is the liveness
condition required by referee law 5, subject to chain progress and transaction
inclusion.

The standard split preserves revision 8's arithmetic and credit rule. For pot
`P` and committed basis points `b`, the challenger share is
`floor(P*b/10,000)` using checked `u128` multiplication; the remainder receives
the balance. If the winner cannot accept its share under the rent-credit rule,
that share is added to the remainder credit. Any amount still uncreditable is
sent to the fixed incinerator. The sum of credits and burn is exactly `P`.
When there is no challenger-win row, the no-win rule above returns `P` to the
executor for `CAUSE_NONE`; a conviction or WITHHELD close pays no challenger
share and sends the pot to the committed remainder/incinerator route.

## 3. Custom fallback encoding and state transition

### 3.1 DDT2 v3 fields

Revision 9 keeps the `DDT2` magic and the existing v2 field offsets through byte
135. It uses a 144-byte version-3 record embedded in DCM2 and DCR2. Bytes
`80..88`, previously an unused v8 custom-settle-window field, become the
explicit fallback delay. The exact fields are:

| DDT2 v3 bytes | Field | Rule |
|---|---|---|
| `0..4` | `DDT2` magic | Exact bytes. |
| `4..6` | version | Little-endian `3`. |
| `6..8` | reserved | Zero. |
| `8..40` | challenge/response windows and challenge/executor bond amounts | Same meanings as v2. |
| `40..42` | legacy executor reward bps | Preserved for record compatibility; unused by v9 settlement. |
| `42` | bond policy | `1` STANDARD, `2` CUSTOM. |
| `43` | reserved | Zero. |
| `44..46` | `bond_slasher_bps` | STANDARD split parameter; CUSTOM fallback challenger-share parameter, `0..=10,000`. |
| `46..48` | reserved | Zero. |
| `48..80` | settlement program | Zero for STANDARD; committed executable program key for CUSTOM. |
| `80..88` | `fallback_delay_slots` | CUSTOM only; `1..=WINDOW_CAP`. STANDARD requires zero. |
| `88..96` | result retention slots | Same meaning as v2. |
| `96..128` | `bond_remainder` | STANDARD remainder key; CUSTOM fallback remainder key. Nonzero and not the recorded executor. |
| `128..136` | abandon window | Same meaning as v2. |
| `136..140` | `challenge_limit` | `u32`, `1..=1,024`; capacity of DPA1's outcome table. |
| `140` | `fallback_anchor_kind` | STANDARD: zero. CUSTOM: `1` trigger-ruling/terminal-disposition slot, `2` challenge-window close slot. |
| `141..144` | reserved | Zero. |

For CUSTOM, `fallback_anchor_kind = 1` anchors to the winning challenge's
ruling slot when that win first escrows the pot. If tag 172 escrows a still-held
pot without a winning challenge, it anchors to tag 172's terminal disposition
slot. `fallback_anchor_kind = 2` anchors to DCM2's committed
`dispute_deadline`, the challenge-window close slot. DPA1 stores both the chosen
anchor slot and `fallback_deadline_slot = anchor_slot + fallback_delay_slots`
when the pot first enters CUSTOM escrow. A later close or custom retry does not
restart the timer. The deadline computation is checked and is done in the same
transaction that escrows the pot.

For CUSTOM, bytes `44..46` and `96..128` are not parameters for the custom
program's primary payout; they are the committed standard-policy fallback
parameter set. The custom program may apply its own rule before the fallback
deadline. For STANDARD, those same bytes are the primary standard split. The
full DDT2 v3 bytes are committed in the document descriptor and copied into
DPA1 so a policy can read them after DCM2 has closed.

### 3.2 DPA1 policy-facts record

Revision 9 creates one DCG-owned DPA1 account per document at init. Its PDA is
derived from `dcg-hcl-policy-facts | descriptor`; it is funded by the recorded
payer and preallocated to the exact committed challenge capacity. The account
remains live only while challenge facts or a CUSTOM escrow need it. Its layout
is:

| DPA1 bytes | Field |
|---|---|
| `0..4` | `DPA1` magic. |
| `4..6` | version `1`. |
| `6` | state: `0` ACTIVE, `1` CUSTOM_ESCROWED. |
| `7` | reserved zero. |
| `8..40` | document descriptor. |
| `40..44` | challenge capacity, equal to DDT2 v3 `challenge_limit`. |
| `44..48` | outcome-entry size, exactly `80`. |
| `48..56` | next challenge sequence; must equal DCM2's counter. |
| `56..64` | fallback anchor slot; zero until escrow. |
| `64..72` | fallback deadline slot; zero until escrow. |
| `72..80` | earliest eligible challenger-win sequence, or `u64::MAX` if none. |
| `80..88` | escrowed document-pot amount; zero unless CUSTOM_ESCROWED. |
| `88..96` | pot-trigger slot (ruling or terminal disposition). |
| `96..128` | earliest eligible winning challenger key; zero if none is final yet. |
| `128..272` | byte-for-byte DDT2 v3 copy. |
| `272..272 + 80*challenge_limit` | outcome table, one 80-byte row per sequence. |

Each outcome row is:

| Row bytes | Field |
|---|---|
| `0..8` | sequence, equal to the row index. |
| `8` | state: `0` UNUSED, `1` OPEN, `2` RULED, `3` SETTLED. |
| `9` | winner: `0` unset, `1` EXECUTOR, `2` CHALLENGER, `3` NEUTRAL. |
| `10` | ruling cause; zero until ruled. |
| `11..16` | reserved zero. |
| `16..24` | challenge bond amount. |
| `24..32` | open slot. |
| `32..40` | ruling slot; zero until ruled. |
| `40..48` | settlement slot; zero until settled. |
| `48..80` | challenger public key. |

At open, DCG writes the sequence, OPEN state, bond, open slot and challenger
key. At ruling, it atomically writes the DCR1 and DPA1 winner, cause and ruling
slot, changing OPEN to RULED. At tag 131, it writes the settlement slot and
changes RULED to SETTLED before closing DCR1. These transitions are one-way;
settlement cannot modify a ruling. DPA1 is complete and immutable after tag 172
because the challenge window is closed, `open_challenges == 0`, and tag 172
requires every row below `next_challenge_sequence` to be SETTLED.

After every ruling, DCG scans rows in sequence order and caches the first
challenger-win row whose entire lower prefix is RULED or SETTLED in bytes
`72..80` and `96..128`. Until such a prefix exists, the cache remains
`u64::MAX`/zero. The cache is checked against the ordered table before use; the
table, not the cache, is authoritative. Once set, this eligible winner cannot
be displaced by a later sequence.

### 3.3 Deadline and payout behavior

The custom callback and fallback share tag 187 but are mutually exclusive
branches. Before or at the stored deadline (`now <= fallback_deadline_slot`),
any signer may trigger the custom policy. A refusing or malformed custom call
rolls back atomically: the escrow balance, DPA1 facts, DCR2/DCRZ marker, and
all destinations remain unchanged, so another call is possible before the
deadline. At the deadline itself fallback is not yet enabled.

After the deadline (`now > fallback_deadline_slot`), any signer may trigger the
fallback. DCG does not call the custom program in this branch. It applies the
standard split directly from DDT2 v3: the earliest winning challenger receives
the configured slasher share; the configured remainder receives the rest; an
uncreditable share is redirected under the standard credit rule and any
residual is burned at the fixed incinerator. If no challenger-win row exists,
the fallback returns the full pot to the executor for `CAUSE_NONE`. For
`CAUSE_CONVICTION` or `CAUSE_WITHHELD`, it pays no challenger share and sends
the full pot to the committed remainder, with any uncreditable residual sent
to the incinerator. The arithmetic is checked and the escrow is debited for
exactly the full pot.

A successful custom payout or fallback must leave the escrow at zero and mark
the bond settled. The same transition closes DPA1 and refunds its complete
balance to the recorded payer. A custom invocation arriving after the deadline
is refused as fallback-due, even if no one has yet submitted fallback. After
fallback has run, the cleared bond marker/escrow and closed DPA1 cause any late
custom invocation to refuse before CPI; it cannot reopen the policy or claim
the pot. At exactly the deadline only the custom branch is legal; after it,
only the fallback branch is legal. This removes a landing-order race over the
shared pot.

If STANDARD is selected, tag 172 returns or pays the held bond according to
section 2 and closes DPA1 to the recorded payer. If CUSTOM is selected, tag
131 or tag 172 moves the bond to the per-document escrow, records the winner
(or the no-winner sentinel), anchor, deadline and pot in DPA1, and leaves DPA1
live. Tag 172 remains permissionless after the dispute deadline and does not
wait for the custom program. The DPA1 rent is therefore needed only until
custom success or the bounded fallback; it is not a permanent escrow. DCR2's
retention close may write the DCRZ v3 tombstone while DPA1 remains live. Tag
187 can use the tombstone plus DPA1 until either policy branch settles, then
refunds the DPA1 rent.

## 4. Facts given to policies and DCG-enforced invariants

### 4.1 Policy fact set

The versioned settlement-v2 ABI receives only independently validated values.
For a tag 131 decision, the facts include:

- descriptor, instruction tag, ABI/program version, current Clock slot, and
  validated role metadata (key, owner, lamports, data length, writable,
  signer, executable);
- current DCR1 sequence, phase and phase deadline, ruling winner/cause/slot,
  challenge bond and challenger/executor identities;
- DCM2 bond amount and state, challenge-window close slot, open-challenge
  count, and the exact DDT2 v3 bytes;
- the ordered DPA1 outcome rows, including each sequence, state, winner, cause,
  challenger bond, challenger key, open slot, ruling slot and settlement slot;
- DPA1's next sequence, earliest winning sequence/key, escrow pot amount, and
  fallback anchor/deadline where already set;
- validated rent-exemption floors and the account balances/data lengths used
  by creditability checks.

The ABI does not receive fee-payer identity, transaction arrival order, a host
clock, raw AccountInfo pointers, or unchecked instruction-provided recipients.

At tag 187, a custom policy receives the same immutable DPA1 record as a
read-only account, together with the current slot, escrow amount, executor,
earliest winner (or no-winner sentinel), trigger cause/slot, fallback anchor
and deadline, and the exact DDT2 v3 fallback parameters. The BSS2 request header
is exactly 144 bytes:

| BSS2 bytes | Field |
|---|---|
| `0..4` | `BSS2` magic. |
| `4..6` | version `2`. |
| `6` | source: `1` eligible challenge win, `2` terminal document disposition. |
| `7` | trigger cause. |
| `8..40` | descriptor. |
| `40..72` | earliest winning challenger key, zero if none. |
| `72..80` | earliest winning sequence, `u64::MAX` if none. |
| `80..88` | executor-bond pot in the escrow. |
| `88..96` | pot-trigger slot. |
| `96..104` | current Clock slot. |
| `104..136` | DPA1 public key. |
| `136..140` | DPA1 outcome count, equal to its next sequence. |
| `140..144` | reserved zero. |

DPA1 contains the complete DDT2 v3 policy parameters and outcome rows; the
custom program must be passed the matching DPA1 account read-only and may not
substitute caller-supplied facts. The CUSTOM CPI may debit only the escrow and
may credit only the validated winner, remainder, executor, or fixed
incinerator accounts named by the committed policy facts. Its output is checked
for escrow-zero, no loss from any other account, unchanged DPA1/DCR2 data, and
unchanged account lengths. The DCG wrapper owns the single terminal marker
write and the DPA1 rent refund.

### 4.2 Invariants enforced regardless of policy

DCG enforces these rules around STANDARD, CUSTOM and fallback execution:

1. **Authenticated state.** DCR1, DCM2, DCR2/DCRZ, DPA1 and escrow have the
   expected owners, versions, descriptor bindings, addresses, exact shapes,
   and privilege flags. Sequence, winner, bond and slot facts come from those
   records and Clock, never from policy or caller payloads.
2. **Monotone outcomes.** One open sequence gets one ruling and at most one
   settlement. The DPA1 row's sequence, challenge bond, challenger, open slot,
   ruling and settlement slots are checked against DCR1/DCM2 before use.
3. **Conservation.** Every successful transition's checked debits equal its
   credits plus an explicit incinerator transfer. No policy can debit more than
   the escrowed pot, alter the recorded executor bond, or transfer funds from
   DPA1, DCR2/DCRZ, or unrelated accounts. Runtime transaction fees remain the
   fee payer's separate runtime movement.
4. **Rent and closure.** DCR1 residual rent returns to its recorded challenger;
   DCM2/DPR2/DFS2 and DPA1 rent returns to their recorded payer when their last
   dependent transition is complete. DCR2 retains only its specified floor;
   closing DPA1 is part of both custom success and fallback. No caller-selected
   closer receives rent.
5. **Atomic custom callback.** A CPI refusal or failed postcondition rolls
   back all account writes and transfers. The funded escrow and its facts remain
   available until fallback. A successful callback must empty the escrow and
   cannot mutate policy facts or the result/tombstone except for the DCG-owned
   terminal marker.
6. **Exclusive finality.** Custom success and fallback are mutually exclusive.
   The deadline selects the legal branch; the terminal marker prevents a later
   callback or repeated fallback from paying twice.
7. **Finite progress.** Challenge phase deadlines, bounded challenge capacity,
   permissionless timeout/settlement/close instructions and the finite custom
   fallback together bound every policy-controlled balance and rent-bearing
   record. A custom program cannot keep DPA1 or the bond escrow live forever.

The policy decides only the distribution allowed by its committed rule. It
cannot decide sequence assignment, challenge ruling, eligibility, deadline,
record shape, balance conservation, allowed destinations, or close authority.

## 5. Revision 8 to revision 9 changes

All changes below are versioned. Revision-8 handlers continue to read/write
revision-8 records byte-for-byte and refuse revision-9 records; revision-9
handlers refuse revision-8 records unless an explicit compatibility reader is
specified. No v8 field is silently reinterpreted by a v8 program.

| Area | Revision 8 | Revision 9 proposal |
|---|---|---|
| Challenge open | Caller supplies a nonce used as DCR1 PDA identity; no per-document opening order. | Keep the nonce only for PDA uniqueness; append writable DPA1 to every challenge-open account list. DCG assigns the next `u64` sequence atomically from DCM2 and DPA1; no instruction sequence field exists. |
| Tag 161 init | Four document working accounts; no outcome ledger account. | Append writable DPA1 at account index 14; create it at `272 + 80*challenge_limit` bytes, copy DDT2 v3, and fund rent from the recorded payer. The init payload carries DDT2 v3's 144 bytes. |
| DCR1 | v5/v6, 8,192 bytes; `140..144` challenge nonce; `184..192` reserved/unused. | v7, same size and old fields; `184..192` is the DCG-assigned sequence. v5/v6 bytes and meanings stay frozen. |
| DCM2 | v7, base length `2,182 + 4*option_count`; DDT2 v2 at `1,842..1,978`, DRB1 at `1,978..2,174`, abandon deadline at `2,174..2,182`. | v8; DDT2 v3 at `1,842..1,986`; DRB1 v2 moves to `1,986..2,182`; abandon deadline to `2,182..2,190`; next sequence at `2,190..2,198`; options start at `2,198`; base length `2,198 + 4*option_count`. The existing winner field at `530..562` means the earliest eligible challenger, not the first ruling/settlement to land. |
| DDT2 | v2, 136 bytes; bytes `80..88` unused by v8 tag 131; no fallback contract. | v3, 144 bytes. Bytes `80..88` are fallback delay; `136..140` challenge limit; `140` fallback anchor kind; `141..144` zero. For CUSTOM, `44..46` and `96..128` are the fallback STANDARD parameters. |
| Policy facts | No ordered challenge outcome record; custom tag 187 sees one conviction winner and a pot, without a deadline. | New DPA1 v1 account with exact DDT2 v3 copy, sequence counters, fallback anchor/deadline and 80-byte ordered challenge outcome rows. It is allocated at init and refunded at the terminal policy transition. |
| DPD2 commitment | Revision-8 descriptor domain `/5`, unified version 3, 755-byte preimage. | Domain `/6`, unified version 4, same field order with DDT2 v3's 144 bytes; preimage is 763 bytes. The new capacity and fallback terms are committed. |
| Tag 131 | One-byte data, nine accounts; first settled challenger win may consume the pot. | Data is `0x83 || descriptor[32]`; append writable DPA1 at index 9. Requires the challenge be ruled and no lower sequence be OPEN. Pays the document pot only to the lowest challenger-win sequence. Executor/neutral/later wins move no pot. |
| Tag 132 and all terminal ruling paths | One-byte timeout; DCR1 ruling only, no ordered policy facts. | Data is `0x84 || descriptor[32]`; append writable DPA1 at account index 2 to tag 132's DCR1/DCM2 pair. Every path that writes RULED must atomically record winner/cause/ruling slot in its DPA1 row. |
| Tag 172 | Descriptor data, ten accounts; drains DCM2/DPR2/DFS2 and leaves DCR2 v6. | Descriptor data, append writable DPA1 at index 10. STANDARD closes/refunds DPA1. CUSTOM stores trigger/anchor/deadline and leaves DPA1 with its escrow; document close does not wait for the custom program. DCR2 becomes v7. |
| DCR2 | v6, 416-byte fixed header; DDT2 v2 at `216..352`; output cells start at 416. | v7, 424-byte fixed header; DDT2 v3 at `216..360`; winner at `360..392`; retention fields at `392..416`; bond state at 416, cause 417, bump 418, zero `419..424`; output cells start at 424. Maximum result size is checked against the same 10 MiB account cap. |
| Tag 185 tombstone | DCRZ v1 ordinary / v2 while custom escrow remains. | DCRZ v3 for revision 9. Keep the 200-byte v2 settlement fields and status/retention prefix; DPA1 is the authenticated source of the full DDT2 v3 and outcome facts until tag 187 terminates. |
| Tag 187 | One-byte data; custom CPI can retry forever; no fallback. | Data is `0xbb || descriptor[32]`; append writable DPA1 at outer index 8 (nine accounts total). It calls CUSTOM only at `now <= deadline`; at `now > deadline` it performs the DCG STANDARD fallback without CPI. Custom success/fallback closes DPA1 and clears the escrow marker. |
| Challenge bond/rent | Tag 131 pays the ruled winner and returns challenge rent to challenger. | Preserve this for EXECUTOR/CHALLENGER wins; NEUTRAL returns the challenge bond to the challenger. DPA1's own rent follows the close rules above. |

DDT2 v3 is included in the new descriptor preimage and copied to DPA1 before
any challenge opens. DPA1 must be a validated account in every open/ruling/
settlement path that reads or writes a sequence outcome. The relevant
settlement-v2 Bend fact codec and BSS2 request are new versioned interfaces;
the pilot's v1 codec is not reinterpreted.

## 6. Required implementation tests

The implementation must add focused tests before revision 9 is treated as
implemented. These tests are requirements, not results from this docs-only
change:

1. **Wire and compatibility vectors:** DDT2 v3, DPA1 header/rows, DCR1 v7,
   DCM2 v8, DCR2 v7, DCRZ v3, BSS2 and DPD2 v9 golden bytes; zero-reserved,
   endian, exact-length, descriptor-hash, capacity and account-size boundaries.
   Confirm revision-8 vectors and handlers remain byte-for-byte unchanged, and
   cross-version records refuse atomically.
2. **Sequence allocation/authentication:** first open gets zero; interleaved
   challengers get distinct increasing values; caller-supplied or forged
   sequences are impossible/rejected; mismatched DCM2/DPA1 counters, row,
   descriptor, owner, PDA, nonce reuse, full capacity and `u64` overflow all
   refuse without consuming a sequence. Exercise two competing opens and show
   only the transaction using the current counter commits.
3. **Ruling ledger coverage:** every terminal success and timeout path records
   the exact winner, cause and Clock ruling slot once. Exercise EXECUTOR,
   CHALLENGER and NEUTRAL; reject a second/different ruling and malformed DPA1
   rows. Check open, ruling and settlement slots against DCR1 state.
4. **Winner finality/order:** create at least two challenger wins and permute
   successful tag 131 order; the lowest sequence receives the document policy
   exactly once. Settle a later win while a lower challenge is OPEN and require
   refusal/no bond movement; rule the lower challenge by honest resolution and
   by timeout, then settle in both orders. Cover lower executor and neutral
   rulings, higher later wins, same winner/remainder alias, and no challenger
   win at no-fault, conviction and WITHHELD closes. Compare final per-account
   balances and DCM2/DPA1/DCR2 bytes across legal orderings, excluding runtime
   transaction fees.
5. **Economics and conservation:** STANDARD split with creditable/uncreditable
   winner and remainder, skipped winner share, incinerator residual, zero
   executor bond, neutral refund, no-winner return/remainder route, and exact
   challenge-bond plus rent credits. Assert every successful movement sums to
   the pot and every refusal leaves all non-fee balances and program-owned
   bytes unchanged.
6. **Fallback encoding and timing:** both anchor modes; trigger ruling anchor,
   no-winner tag-172 disposition anchor, and window-close anchor; exact
   `anchor + delay`; `now == deadline` custom-only and `now == deadline + 1`
   fallback-only; delay/addition overflow and invalid basis/zero delay refuse.
   Check DPA1's persisted anchor/deadline never restarts at close or retry.
7. **Custom callback and fallback:** refusing custom CPI rolls back and can be
   retried; a successful CPI is accepted only when escrow reaches zero and no
   unrelated account loses lamports or policy/result bytes change. Fallback
   after deadline pays the configured standard parameter set without calling
   custom. A late custom call before fallback is refused; after fallback and a
   repeated fallback both refuse without CPI or payout.
8. **Full liveness/rent path:** from challenge open through timeout/ruling,
   settlement, document close, custom retry refusal, fallback and result
   tombstone close, show every state has a permissionless next step after its
   committed deadline. Verify DCM2/DPR2/DFS2/DPA1 refunds go to the recorded
   payer, DCR1 rent goes to the recorded challenger, DCR2 keeps only its
   required floor, and the custom escrow is zero at terminal completion.
9. **Adversarial roles and atomicity:** substitute descriptor, DCR1/DPA1,
   winner, remainder, executor, escrow, system program, writable/signer flag,
   and executable program; corrupt outcome rows and callback writes; test both
   honest role orders and at least one deliberate malformed/custom-policy
   cheat. All refusals leave protocol state and balances unchanged except the
   runtime fee.

The revision-9 implementation must also update the settlement pilot contract,
referee-law assessment, CLI/account help and any revisioned machine spec before
claiming conformance. These follow-on edits are outside this specification-only
brief.
