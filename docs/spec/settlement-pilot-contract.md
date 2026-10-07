# DCG settlement pilot contract

**Deferred (owner 2026-10-07):** the bendSVM settlement pilot is not part of
the DCG program. Its work is kept unchanged on branch
`wip/bend-settlement-pilot` (c6816ab, based on 272ccf7, which still has
revision 8). The revision-8 tags it targets (131, 132, 172) were retired from
main after v0.1.0-alpha, so resuming it needs a decision on what it settles.

**Status:** integration proposal for a local-only bendSVM pilot. This document
is documentation only; the settlement executor remains designed, not
implemented. Existing account bytes below were
observed in `durable-compute-graph` commit
`170712bb93c1c251fd1906182fd2ff7ef88dc5d3`; the DCR1 reserved-byte additions
at 146, 147, 181, and 219 describe the fresh-image implementation in this change.
The Rust-validator/Bend-core split and settlement-plan executor below are
**designed**, not implemented or measured. Deployed images remain frozen.

The pilot order is **tag 132 timeout, tag 131 settle, tag 172 close**. Tag 132
is the canary; tag 131 first moves a challenge bond and may dispose of the
document bond; tag 172 closes the working document accounts and returns rent.
The in-flight `dcg-seam-fix-2` RESPOND change is not a dependency of this
contract.

The proposed C entry point is `dcg_settlement_eval_v1(facts, facts_len,
plan_out, plan_capacity, plan_len)`. All pointers are call-local; the Bend core
cannot retain a pointer or mutate the input. `facts` and `plan_out` use the
generated bendSVM canonical wire encoding (one-byte constructor tags, U32
little-endian, U64 as low/high U32 limbs, exact lengths and zero padding), with
ABI version 1 included in each envelope. A core-level `Rejected { code }` is a
valid encoded business refusal; a nonzero C return means malformed ABI or
internal execution failure. The DCR2 read-only window fold is part of the same
versioned root contract and must remain pure. The generated schema, byte
offsets, and golden request/plan vectors must be frozen before any code is
written; this document fixes the semantic fields and operations below.

## 1. Integration boundary

The public DCG instruction and record encodings remain the inputs to a new,
versioned internal interface. The proposed boundary is:

1. A Rust account validator reads Solana account metadata, the Clock slot, and
   the listed record bytes. It validates account count, ownership, writable and
   signer facts, record shape, parent relationships, allowed aliases, address
   provenance, and every byte range before calling Bend.
2. The Rust-to-Bend call is explicitly versioned (`settlement_v1`). It supplies
   typed, validated facts and any read-only record windows needed by the rule.
   Bend chooses eligibility, winner, amounts, recipients, deadlines, status,
   and closure eligibility. Bend cannot read `AccountInfo`, sysvars, or caller
   memory directly.
3. Bend returns a bounded plan. Rust checks that every plan operation fits the
   validated roles and the static write/close allowlist, validates the complete
   plan against a simulated balance/data-length overlay, then executes it.
4. A nonzero return before or during execution aborts the instruction. Whole
   transaction rollback, including rollback of earlier successful operations,
   relies on the Solana runtime. The fee payer still pays the transaction fee.

The ABI must name its version in the exported symbol and in the fact/plan
headers. A generated Bend codec is not the DCG record codec: bendSVM's current
codec derives offsets from Bend types and does not import DCR1/DCM2/DCR2 layouts.
The pilot needs an external-layout codec and byte goldens against these DCG
records. The current Bend storage adapters also do not expose arbitrary borrowed
account spans, account close/realloc, or generic lamport effects; their
state/actor/effect account layout tops out at 12 accounts and reserves adapter
slots. A dedicated settlement adapter is required for the nine-account tag 131
and ten-account tag 172 lists.

Tag 172 may re-evaluate the result's FINAL condition at close. If DCR2 is not
already FINAL, that rule scans the result bitmap and, for some bindings, up to
`L` output cells. The core must receive those bytes as bounded read-only windows
(for example, repeated pure fold calls over at most eight cells per window).
Rust may transport and bounds-check windows but must not decide the stop rule.
The current bendSVM collection ABI supports typed windows only and does not
expose arbitrary account byte spans or the required DCG byte codecs; the window
bridge and its SBF cost are open prerequisites. No Bend CU result is claimed.

The scout's mixed-language probe measured that a compatible Bend-generated C
object and Rust kernel can be linked into one SBF ELF. That probe did not execute
the ELF in LiteSVM. The production mixed-SBF build, stable root export, raw
record views, and local SBF execution remain unimplemented. The pilot is local
ProgramTest or LiteSVM only.

### Record layouts read by this contract

All integer fields below are little-endian. Program-owned records are owned by
the DCG program and are non-executable unless stated otherwise.

| Record | Layout relevant to settlement | Parent binding and close behavior |
|---|---|---|
| **DCR1 v5/v6**, 8,192 bytes | `0..4` magic; `4` phase; `5` winner (`1` executor, `2` challenger); `6..8` version (`5` or app-replay `6`); `8..40` challenger; `40..72` executor; `72..104` descriptor; `140..144` challenge nonce; `144` source/mode (`1` PT2P); `145` machine; `146` canonical challenge PDA bump; `147` marker `1` required by the fresh revision-8 image; `148..156` current deadline; `162..170` challenge bond; `170..178` rule deadline (zeroed on v8 ruling); `178` cause; `181` canonical DRU1 response PDA bump staged at open; `219` stable canonical response bump written at open and refreshed by tag 164 after it consumes position roots or by a tag 132 ruling from POSITION_REVEAL/SELECT. | Descriptor binds to DCM2. The challenge PDA seeds are `dcg-unified-challenge`, descriptor, challenger, nonce; DRU1 seeds are `dcg-hcl-response`, DCR1 address. Revision-8 tag 131 uses the stored DCR1 and DRU1 bumps for fixed-cost address checks; tag 132's timeout RULE uses the stored DCR1 bump (its account list has no DRU1). Marker-0 records are refused at this fresh program address. Tag 131 drains DCR1 to zero data/lamports and assigns it to System Program. Revision-7 settlement retains its canonical DRU1 search; revision-7 writers leave these reserved bytes zero. |
| **DCM2 v7**, `2,182 + 4*option_count` bytes | `0..4` magic; `4..6` version `7`; `6..8` flags; `8..40` descriptor; `40..72` recorded executor/payer; `72..76` position capacity; `84..88` landed positions; `128..132` open challenge count; `132..136` refuted count; `136..144` finalize slot; `144..152` dispute deadline; `184..192` challenge window; `200..232` PT2S; `232..264` PT2S SHA-256; `456..488` DFS2 key; `528` peak count; `529` executor bond state (`0 none, 1 held, 2 paid, 3 returned, 4 escrowed`); `530..562` write-once conviction winner; peaks from `562`; DDT2 v2 at `1,842..1,978`; DRB1 v2 binding at `1,978..2,174`; abandon deadline `2,174..2,182`; option IDs follow. | Document PDA seeds are `dcg-hcl-document`, descriptor. It stores the payer/executor and the child PDA bumps at bytes `78..82` (DCM2, DPR2, DFS2, bond escrow). Tag 131 updates open count, winner and bond state. Tag 172 drains the whole account. |
| **DDT2 v2**, 136 bytes inside DCM2 | `0..4` magic; `4..6` version `2`; `8..16` challenge window; `16..24` response window; `24..32` challenger bond; `32..40` executor bond; `40..42` legacy reward bps (unused by v8 settlement); `42` bond policy (`1` STANDARD, `2` CUSTOM); `44..46` slasher bps; `48..80` custom settlement program; `80..88` custom settle window (not used by v8 tag 131); `88..96` result retention; `96..128` bond remainder; `128..136` abandon window. | Embedded in the already initialized DCM2; this is the source of bond amounts, policy and remainder address. |
| **DRB1 v2**, 196 bytes at DCM2 `1,978..2,174` | `0..4` magic; `4..6` version `2`; `6..8` zero; `8..40` executor; `40..72` request id; `72..104` consumer digest; `104..136` seed; `136..140` first output position; `140..144` output count; `144..148` output base entry; `148` output write; `149` output width; `150` decision flags; `151` option count; `152..156` prompt positions; `156..160` stop-plus-one; `160..162` option-table offset; `162..164` zero; `164..196` option-table SHA-256. | Embedded run binding used by tag 172's result/final-condition validation; decoder checks shape and record-only relations before plan-dependent checks. |
| **DRU1 v1**, 128-byte header plus response body | `0..4` magic; `4..6` version `1`; `6..8` phase; `8..40` DCR1 key; `40..72` executor; `72..76` declared body length; `76..80` cursor; `80..112` body digest; `112..120` response deadline; `120..128` zero. | PDA seeds are `dcg-hcl-response`, DCR1 address. Current tag 131 accepts either program-owned response data or a System-owned empty account; it does not decode a program-owned DRU1 header before draining it. |
| **DPR2 v1**, 48-byte header plus landed roots | `0..4` magic; `4..6` version `1`; `6..8` zero; `8..40` descriptor; `40..44` capacity; `44..48` landed count; roots begin at `48`, 32 bytes each. Allocation can be shorter than full capacity while roots are being landed. | PDA seeds are `dcg-hcl-positions`, descriptor. Tag 172 drains it. |
| **DFS2 v1**, 48-byte header plus family body | `0..4` magic; `4..6` version `1`; `6..8` zero; `8..40` descriptor; `40..42` family count; `42` height; `43` reserved; `44..48` body length; canonical family body begins at `48`. | PDA seeds are `dcg-hcl-family-slots`, descriptor. Tag 172 currently checks owner/key/writable, but does not decode this header before draining it. |
| **DCR2 v6**, full size `416 + output_count*width + ceil(output_count/8)` bytes; allocated data may be shorter during staged growth but is at least 416 and no longer than the full size | `0..4` magic; `4..6` version `6`; `6` status; `7` closed; `8..40` descriptor; `40..72` document root; `72..104` request id; `104..136` consumer digest; `136..168` executor; `168..176` finalize slot; `176..184` dispute deadline; `184..192` status slot; `192..196` refuted count; `196..200` output count; `200..204` first output position; `204..208` attested count; `208` width; `209..212` zero; `212..216` position count; DDT2 v2 at `216..352`; `352..384` conviction winner; `384..392` retention slots; `392..400` retention start; `400..408` retention deadline; `408` bond state; `409` cause; `410` result PDA bump; `411..416` zero; output cells at `416`, then bitmap. | PDA seeds are `dcg-hcl-result`, descriptor. Tag 172 updates status/closed/retention/bond facts and leaves the DCR2 rent-bearing account alive. |
| **DTU1 v2**, 168 bytes | `0..4` magic; `4..6` version `2`; `6` state; `7` use bump; `8..12` live document count; `12..16` zero; `16..48` authority; `48..80` registry; `80..88` seal slot; `88..128` five template limits; `128..160` payer; `160` seal bump; `161` zero; `162` admission bump; `163..168` zero. | PDA seeds are `dcg-template-use`, PT2S key, PT2S digest. Tag 172 decrements `documents` at `8..12`; it does not move DTU1 lamports. |

The record schemas above are code-derived. The DCG checkout has no
`docs/spec/dcg-unified-v8.md`; `docs/spec/referee-laws.md` labels itself a
designed law set assessed at `4d1446f`, not a normative machine spec. The
source/spec gap must be reconciled before this proposal is treated as protocol
law.

## 2. Tag 132 — timeout against a silent executor (first canary)

**Instruction bytes:** exactly `[0x84]` (one byte, tag 132, no payload).

**Account list:** exactly two accounts, both writable and neither required to
sign. No caller identity or fee-payer identity is a timeout authority.

| Index / role | Owner, kind, flags | Address and parent source |
|---|---|---|
| 0 DCR1 challenge | DCG-owned DCR1 v5 or v6, 8,192 bytes; writable; signer not required. | Current code reads `dcg-unified-challenge | descriptor | challenger | nonce` from DCR1 bytes `72..104`, `8..40`, and `140..144`. The fresh revision-8 image requires marker `1` at byte 147 and uses the stored challenge bump at byte 146. Marker-0 records from an older image are refused. Its parent is DCM2 for that descriptor; DCM2 executor `40..72` must equal DCR1 executor. These current self-sourced PDA fields do not satisfy §5's independent-seed rule. |
| 1 DCM2 document | DCG-owned DCM2 v7; writable; signer not required. | `dcg-hcl-document | descriptor`. Current `document_v8` checks the canonical bump stored at DCM2 byte 78 against the address derived from DCM2 bytes `8..40`, then checks that descriptor against DCR1 `72..104` and checks executor equality. The descriptor seed is therefore self-sourced and cross-bound to DCR1, not independently anchored. |

**Read/write and decision.** The handler accepts only DCR1 v5/v6, phase 1, 2, 5, 6, 7 or 8, and mode/source 1. At timeout the code's winner table is: phases `RESPOND(1)`, `SEALED(2)`, `REVEAL(5)`, `POSITION_REVEAL(7)` => challenger; `DESCEND(6)`, `SELECT(8)` => executor. It writes DCR1 phase `RULED(3)`, winner byte 5, clears `170..178`, and writes cause `TIMEOUT(3)` at 178. A challenger win also increments DCM2 refuted count at 132 and sets flag 4; DCM2's first conviction winner at 530 is written if still zero. There is no lamport movement and no account close.

**Deadline convention:** current code refuses while `now <= DCR1[148..156]`; acceptance is strictly `now > deadline`. `now` is the runtime Clock slot.

**Current custom refusal codes:** `730` malformed data/count/short fields; `731` DCR1 owner/writable/size/PDA or DCM2 binding; `733` wrong DCR1 shape/version/phase; `736` deadline not passed; `598` checked refuted-count overflow. Clock/sysvar/runtime failures can also abort without one of those custom codes.

**Measured CU:** **measured 15,023 CU** for the K=80 executor-timeout ProgramTest against the extracted SBF image in `docs/experiments/bytesum-sbf-lifecycle-2026-09-30.md`. A Bend implementation has no CU measurement.

**Existing tests:** `unified_v8_document.rs::rev8_position_challenge_rounds_convict_executor_and_burn_uncreditable_bond` exercises executor silence and timeout ruling; `::rev8_timeout_refutes_a_challenger_who_stalls_in_descent` exercises challenger silence and executor ruling; `::rev8_challenge_opener_refuses_wrong_phase_role_and_deadlines` includes the early-timeout refusal. `unified_v8_bond.rs::revision8_refuses_legacy_timeout_record_before_bad_document` checks that the v8 dispatcher refuses a legacy record. These do not independently establish a full-game win/termination law.

## 3. Tag 131 — settle and move the challenge bond

**Instruction bytes:** exactly `[0x83]` (one byte, tag 131, no payload).

**Account list:** exactly nine accounts. No role must sign. All writable flags below
are required by the proposed validator. `system` is shown read-only in CUSTOM;
the current handler checks its key but not its read-only flag.

| Index / role | Owner, kind, flags | Address and parent source |
|---|---|---|
| 0 DCR1 | DCG-owned v5/v6 challenge, 8,192 bytes; writable. | Same challenge PDA and self-seed caveat as tag 132. Must be phase RULED, with ruling winner byte 1 or 2 and cause `1..=CAUSE_APP_REPLAY`. |
| 1 DRU1 response | Either DCG-owned DRU1 or System-owned empty data; writable. | `dcg-hcl-response | DCR1 account key`. Its parent identity is DRU1 bytes `8..40` (DCR1 key) and executor `40..72`. Current tag 131 checks derived key and owner/empty shape, but does not validate those DRU1 header fields before closing program-owned DRU1. |
| 2 ruling winner | Any lamport recipient; writable. | Key is DCR1 executor `40..72` when winner byte is 1, otherwise challenger `8..40`. It may alias index 3 or 6 according to the ruled winner. |
| 3 executor | Any lamport recipient; writable. | Exact DCR1 executor bytes `40..72`; this is where a program-owned DRU1 refund goes. May alias index 2 on executor win. |
| 4 DCM2 | DCG-owned DCM2 v7; writable. | `dcg-hcl-document | descriptor`. Current `document_v8` checks the canonical bump stored at DCM2 byte 78 against the address derived from bytes `8..40`, then checks equality with DCR1 `72..104` and checks executor binding. The descriptor seed is self-sourced and cross-bound, not independently anchored. |
| 5 incinerator | Lamport recipient at `incinerator::ID`; writable. | Fixed program constant, not caller-selected. Receives an uncreditable STANDARD residual. Current check is key-only. |
| 6 challenger | Any lamport recipient; writable. | Exact DCR1 challenger bytes `8..40`; receives all remaining DCR1 lamports after the bond payment. |
| 7 policy winner / bond escrow | Writable. STANDARD: any lamport recipient whose key must equal DCM2 conviction winner at `530..562`, or incinerator if that field is zero after this call's write-once step. CUSTOM: System-owned, empty-data bond-escrow PDA. | STANDARD key comes from validated DCM2 state. CUSTOM PDA seeds are `dcg-hcl-bond-escrow | DCR1 descriptor`; tag 131 uses the canonical bump at DCM2 byte 81 with a fixed-cost address check, while tag 187 retains canonical search from DCR2's settlement block. Tag 172 also uses the DCM2 bump at byte 81. The escrow is only fully checked when the bond is live. |
| 8 remainder / System Program | Writable for STANDARD; CUSTOM must be the System Program and read-only by contract. | STANDARD key comes from DDT2 v2 `bond_remainder` at DCM2 `1,938..1,970` (DDT2 offset `96..128`). CUSTOM key is the fixed System Program id. |

**Read/write and decision.** DCR1's own challenge bond is `B_c = DCR1[162..170]`.
The handler credits `B_c` to index 2, decrements DCM2 open count at `128..132`,
sets DCR1 phase to SETTLED, then drains DCR1's full remaining balance and data
to challenger index 6. If index 1 is program-owned DRU1, all its lamports and
data are drained to executor index 3. If it is a System-owned empty account,
current code does not drain it.

The document bond moves only when the challenge ruling is for the challenger
and DCM2 bond state is HELD. On that first such settle, the code records the
ruling challenger at DCM2 `530..562` if the field is zero. STANDARD moves the
committed executor bond from DCM2 according to DDT2 `bond_slasher_bps` and
`bond_remainder`; CUSTOM moves the whole bond to the document's bond escrow and
sets DCM2 state 4. An executor win, later win after disposition, or already
paid/escrowed bond moves no document pot. Tag 131 makes **no call** to the
custom settlement program and has no timed fallback. The historical
`executor_reward_bps` is still encoded but is unused by v8 settlement.

**Deadline convention:** no slot/deadline check; settlement is permissionless
once DCR1 is RULED. It does not require the signer to be the executor,
challenger, winner, or fee payer.

**Current custom refusal codes:** `730` instruction/account count; `731` role
flags, DCR1/DRU1 identity, incinerator/System key; `733` DCR1 not RULED,
missing open count, or insufficient DCR1/DCM2 rent-plus-bond balance; `598`
checked lamport arithmetic; `582` substituted STANDARD recipient/remainder;
`599` wrong escrow PDA; `798` malformed escrow ownership/writability/data;
`791` malformed DDT2 policy. Runtime transfer/borrow failures may propagate as
runtime errors. DCR1 balance must cover its rent floor plus `B_c`; DCM2 must
cover its rent floor plus the live executor bond.

**Measured CU:** **measured 20,819 CU** on the K=80 standard-settlement path
and **measured 13,339 CU** on the separate wrong-output standard-settlement
SBF ProgramTest path. Sources are the bytesum lifecycle note and
`docs/experiments/dcg-seam-fix-2026-09-30.md`; the latter records transaction
CU including its Compute Budget instruction. These are fixture-path measurements,
not a Bend estimate or a worst-case bound.

**Existing tests:** `unified_v8_bond.rs::the_settle_pays_the_standard_policy_split`,
`::the_first_settled_challenger_win_names_its_own_ruling_winner`,
`::a_skipped_share_is_redirected_and_uncreditable_residual_is_burned_at_settle`,
`::the_settle_escrows_the_pot_under_a_custom_policy_and_calls_nothing`,
`::no_pot_moves_without_a_first_settled_challenger_win`,
`::a_substituted_destination_is_refused_at_the_settle`, and
`::every_settle_refusal_on_a_revision_eight_document` exercise the route and
refusals in a native handler fixture. The SBF lifecycle tests
`unified_v8_document.rs::rev8_position_challenge_rounds_convict_executor_and_burn_uncreditable_bond`,
`::rev8_timeout_refutes_a_challenger_who_stalls_in_descent`, and
`::rev8_bytesum_wrong_output_rules_and_settles_sbf` cover integration flows.

## 4. Tag 172 — close and refund

**Instruction bytes:** exactly `0xac || descriptor[32]` (33 bytes). Descriptor
is the raw 32-byte document descriptor; no additional version or length field.

**Account list:** exactly ten accounts. Index 0 must sign; its key is not
otherwise authorized or read. Indexes 1–6 are required writable. The last three
roles are conditional on policy and bond state.

| Index / role | Owner, kind, flags | Address and parent source |
|---|---|---|
| 0 any signer | Any owner/kind; signer required; writable not required. | No protocol key expectation. It can be the recorded payer. Current close is permissionless to any signer. |
| 1 DCM2 | DCG-owned DCM2 v7; writable. | Descriptor is currently read from instruction bytes and the stored DCM2 bump at byte 78 is used to check its PDA. The account's descriptor at `8..40` must match. |
| 2 DPR2 | DCG-owned DPR2 v1; writable. | `dcg-hcl-positions | descriptor`, using bump stored in DCM2 byte 79. DPR2 descriptor/capacity bind to DCM2. |
| 3 DFS2 | DCG-owned DFS2 v1; writable. | `dcg-hcl-family-slots | descriptor`, using bump stored in DCM2 byte 80. Current close checks owner/key/writable but does not decode DFS2 header/body. |
| 4 DCR2 | DCG-owned DCR2 v6; writable. | `dcg-hcl-result | descriptor`; current code takes the result bump from DCR2 byte 410 and checks the PDA with that same record value. DCR2 descriptor at `8..40` must match. |
| 5 recorded payer | Any writable lamport recipient. | Exact DCM2 bytes `40..72`; current code checks this before close. This is the refund recipient, not the closer. |
| 6 DTU1 | DCG-owned DTU1 v2, 168 bytes; writable. | `dcg-template-use | DCM2 PT2S[200..232] | PT2S digest[232..264]`; current `template_record` reads the use bump from DTU1 byte 7. Parent template identity comes from DCM2. |
| 7 aux | Writable when used. STANDARD: any recipient at DCM2 conviction winner `530..562`, or incinerator if absent. CUSTOM: System-owned empty-data bond escrow PDA. | STANDARD source is DCM2. CUSTOM seeds are `dcg-hcl-bond-escrow | DCM2 descriptor`; current close uses DCM2 byte 81 as bump. Not validated/used when no held convicted pot is disposed. |
| 8 tail | STANDARD: writable recipient at DDT2 `bond_remainder`; CUSTOM: fixed System Program id, read-only by contract. | Source is committed DDT2 bytes. Conditional on a held convicted bond. Current code checks the CUSTOM key but does not require this meta to be read-only. |
| 9 incinerator | Writable recipient at `incinerator::ID`. | Fixed program constant. Required when a held convicted bond is disposed; otherwise unused by current code. |

**Read/write and decision.** Close validates document/result records, checks
payer binding and the DTU1 use-count record, decides one of three rows, releases
the template document count, disposes of a held executor bond, writes DCR2, then
drains DCM2/DPR2/DFS2 to index 5. DCR2 remains open as a retention record.

- Finalized document: require `now > DCM2 dispute_deadline` and `open_challenges
  == 0`. A refuted document closes REFUTED. Otherwise a completed result is
  rechecked against the FINAL/stop rule; a violation is convicted here. A
  partially attested result becomes WITHHELD only once the abandon deadline has
  been reached.
- Unfinalized document: close at or after the abandon deadline and retain the
  existing result status.
- DCR2 writes status/status slot/refuted count when status changes; always writes
  closed byte 7, the DCM2 conviction winner at `352..384`, retention start at
  `392..400`, retention deadline at `400..408`, bond state at 408, and bond cause
  at 409. DTU1 decrements `documents` at `8..12`.
- DCM2, DPR2 and DFS2 are drained: all their lamports go to the recorded payer,
  their data is zeroed and shrunk to zero bytes, and their owner is set to System
  Program. A second close while DCR2 remains v6 refuses with 599.

**Deadline equality:** for finalized documents, `now <= dispute_deadline` refuses,
so closing is strictly after it. The incomplete/withheld path additionally
requires `now >= abandon_deadline`. For unfinalized documents, `now <
abandon_deadline` refuses, so close is inclusive at equality. All slots come
from Clock. Tag 172 starts DCR2 retention at the accepted close slot.

**Current custom refusal codes:** `580` malformed list/data or DCM2/DPR2/DFS2/
DCR2 record; `582` wrong payer or substituted bond destination; `598` checked
overflow/underflow; `599` already closed, early close, or open challenge;
`791` malformed DDT2 policy; `793` invalid DTU1; `794` malformed DRB1 binding;
`796` invalid result/final-condition state; `798` malformed custom escrow.
Underlying Clock, rent, borrow, realloc, and runtime errors can also abort.

**Measured CU:** **measured 13,234 CU** for K=80 close after settlement,
**13,404 CU** for K=10,240 honest lifecycle close, and **13,276 CU** for the
refuted close path. Sources are the bytesum lifecycle and seam-fix experiment
notes. These paths do not bound the non-FINAL close branch that scans result
cells/bitmap, nor any Bend implementation; worst-case close cost must be
re-measured.

**Existing tests:** `unified_v8_document.rs::rev8_close_pays_the_payer_and_drops_the_counter_on_every_row`,
`::rev8_close_skips_a_record_that_is_already_final`,
`::rev8_close_splits_a_standard_pot_and_skips_a_sub_floor_share`,
`::rev8_custom_close_refund_is_the_exact_post_escrow_drain`,
`::rev8_standard_close_burns_an_uncreditable_remainder`,
`::rev8_standard_close_burns_every_uncreditable_share_away_from_the_convict`,
and `::rev8_close_refusals` cover close rows, recipients, bond disposition and
refusal behavior. `::rev8_bytesum_wrong_output_rules_and_settles_sbf` covers an
SBF close after refutation. `crates/dcg-program/tests/referee_laws.rs` does not
exercise tags 131/132/172; it tests legacy tag 98 refusal and the PT1X tag 197
rent/authority close.

## 5. Independent account validation and Bend facts

The Rust validator owns facts that require Solana/runtime access:

- Exact account count, runtime account key/owner/writable/signer/executable
  metadata, data length, lamports, and account alias map.
- Executable-kind constraints for every role: DCG state and data accounts,
  recipient accounts, and escrow are non-executable; the System Program role
  is the executable System Program account. These are validator requirements,
  including where the current handler checks only a key or owner.
- Clock slot from the Clock sysvar; no wall-clock time.
- Record magic/version/reserved bytes, fixed/variable length bounds, canonical
  little-endian fields, supported DCR1 version, and parent-instance equality.
- Account address derivation, program-owned vs System-owned shape, and all
  writes/close targets. It emits only validated typed facts to Bend.
- It provides read-only byte windows into DCR2 cells/bitmap for the close FINAL
  check; it does not decide what those cells mean.

The Bend core receives exactly the following for each call: ABI version and
handler tag; each fixed role's 32-byte key and owner key, initial lamports,
data length, and runtime writable/signer/executable booleans; the Clock slot as
U64; and the handler-specific facts below. Fixed-width integers use unsigned
little-endian values in the wire schema. Variable byte sequences are supplied
as bounded windows with explicit offsets and lengths, never as pointers.

- **Tag 132:** DCR1 version, phase, winner, challenger, executor, descriptor,
  nonce, source/mode, deadline, ruling deadline, and cause; DCM2 descriptor,
  executor, flags, open-challenge count, refuted count, and conviction winner.
- **Tag 131:** DCR1 version, phase, winner, challenger, executor, descriptor,
  challenge bond, cause, and response kind (`program-owned DRU1 with a
  validated header` or `System-owned empty`); DCM2 descriptor, executor,
  open-challenge count, bond state, conviction winner, executor bond amount,
  bond policy, slasher bps, committed remainder key, and escrow identity; plus
  the validated account balances, data lengths, owner/privilege facts, and
  rent-exemption floors used by the credit rule.
- **Tag 172:** the instruction descriptor; DCM2 descriptor, payer, flags,
  position capacity, landed count, open/refuted counts, finalize/dispute/
  abandon slots, PT2S key and digest, bond state/winner, DDT2 v2 policy and
  retention fields, DRB1 v2 binding fields, DPR2 descriptor/capacity/landed
  count, and DFS2 descriptor/family-count/height/body-length facts; DCR2
  status, closed flag, descriptor, executor, finalize/dispute and
  status slots, refuted/output/attested/position counts, output width, DDT2 v2,
  winner, retention fields, and bond state/cause; DTU1 state,
  document count, authority, registry, and payer. For the FINAL/stop check it
  also receives the ordered DCR2 result cells and bitmap windows needed by the
  rule, with each window's absolute byte offset and bounded length.

Instruction bytes beyond the fixed tag/descriptor are not facts because these
instructions have no other payload. The signer bitset is exactly the runtime
signer flag for each fixed index: tag 172 requires bit 0 set; tags 131 and 132
require no signer. Bend receives no raw `AccountInfo`, transaction fee-payer
identity, RPC order, host clock, writable pointer, or unchecked
instruction-provided recipient. PDA checks and any bump values remain in Rust's
structural validation; a bump read from a target record still does not prove
independent address provenance.

Bend decides: timeout phase-to-winner and deadline; DCR1 winner and challenge
bond amount/recipient; whether DCM2 bond is live and STANDARD vs CUSTOM; the
write-once document winner; credit/skip/burn amounts and exact destinations;
close row/status/conviction, template release eligibility and retention window;
and all plan values. Rust may reject a plan that exceeds prevalidated role
capabilities or static byte ranges, but must not substitute a different winner,
recipient or amount after Bend has selected one.

### Address provenance gate

The required rule is: **an account cannot establish its own expected address**.
A seed may come from a separately validated parent record or an independently
validated instruction identity, but not solely from the target account or the
instruction currently being checked. Recipient keys must come from the
validated DCR1/DCM2/DDT2 fields or fixed program ids, never from caller-chosen
recipient metas.

The current code does not meet that stricter rule for every account: `record_v8`
derives DCR1 from its own descriptor/challenger/nonce fields; tag 172 takes the
descriptor from its own instruction; close reads DCM2 child bumps from DCM2,
the DCR2 bump from DCR2, and the DTU1 use bump from DTU1. These behaviors are
recorded above, not adopted as satisfying the proposed rule. The existing
131/132 account sets contain no independent challenge identity record, and the
172 account list has no independently validated document-identity anchor. An
implementation preserving every public account/data byte therefore needs an
independent identity source or a documented, versioned change to the account
protocol before it can claim this invariant. Do not label current PDA checks
“independent” until that gap is resolved.

## 6. Settlement plan and executor contract

The plan is a bounded, versioned list of operations addressed only by role
indices from the validated account list:

- **Lamport transfer** `{from, to, amount:u64}`. Both roles must be in the
  handler's transfer capability set; amount is unsigned; source debit and
  destination addition use checked arithmetic. Every transfer source is a
  writable DCG-owned account named in that handler's static capability set;
  System-owned accounts are destinations only.
  The plan cannot use a caller-selected account outside the validated roles.
- **Record write** `{role, offset, bytes}`. Writes are allowed only within a
  static per-handler range allowlist: tag 132, DCR1 ruling fields and (on a
  challenger win) DCM2 flags/count/winner; tag 131, DCR1 settled byte, DCM2
  open-count/winner/bond-state fields; tag 172, DCR2 status/closed/winner/
  retention/bond fields and DTU1 document count. Validate integer widths,
  current old value and exact new-value length before mutation. DCM2/DPR2/DFS2
  drain-time clearing is performed only by Close, not a broad record write.
- **Close and refund** `{role, recipient, final_owner=System, final_len=0}`.
  The role must be designated closable by this handler; the refund recipient is
  named from validated state. Close copies its full current lamport balance to
  that recipient, zeros data, shrinks to zero, and reassigns to System. It is a
  terminal operation for that role.
- **No generic CPI operation** is admitted for 131/132/172. Tag 131 CUSTOM
  moves the document bond directly to the system-owned escrow; the settlement
  program is invoked only by later tag 187. The executor must not call a
  settlement program during either close or settle.

Before the first write or transfer, validate the *whole* plan: operation count,
role indices, write ranges and lengths, expected prior bytes, all unique-close
rules, all recipient relationships, writable privileges, aliases, and an
ordered overlay of checked lamport deltas (including repeated credits to the
same account). Repeated transfers to one destination are applied in plan order
against the overlay, so rent-credit decisions see earlier planned credits.
Reject source/destination self-transfers and any transfer or write after that
role's Close. All operations involving an account, including reads needed for
preflight, finish before it is closed. Close operations execute last, in a
prevalidated order; no later executor access may touch a closed account.

The proposed validator allows duplicate recipient roles when their independently
validated committed keys are equal; these are intentional sequential credits
to one balance. On tag 131 this covers roles 2, 3, 5, 6 and 7, plus role 8 on
STANDARD, when their recipient rules resolve to the same key. In particular,
ruling winner is the executor or challenger, a first live challenger settle can
make policy winner the challenger, the no-winner STANDARD policy recipient is
the incinerator, and the committed remainder can equal any other recipient.
On tag 172 the recorded payer, STANDARD winner, remainder, incinerator, and
anonymous signer may share a key when the role constraints and signer bit both
hold; the CUSTOM tail is the read-only System Program, not a recipient. No
duplicate is allowed among state/source roles, or between a state/source role
and a recipient role, except a signer key may also be a recipient key. A Close
source may not equal its refund recipient. The current handlers do not apply a
global duplicate-account check; this is the proposed executor's explicit alias
policy and must be checked against live handler behavior before adoption.

All explicit failures after execution begins return an error and rely on Solana
transaction atomicity to undo the earlier mutations. Failure-injection coverage
must fail after each possible first/late mutation: after tag 132's DCR1 write
and each DCM2 write; after tag 131's challenge-bond payout, open-count update,
write-once winner update, STANDARD payout or escrow funding, bond-state update,
DCR1 settled write, and each response/challenge close; after tag 172's DTU1
decrement, bond disposition, DCR2 write, first close, and second close. Also
inject source underflow, destination overflow, invalid write range,
repeated-alias credit overflow, late invalid role, and attempted access after
close. Snapshots include every
role account and fee payer; expected rollback excludes the transaction fee.

## 7. Conservation boundary

For each account `a`, successful execution satisfies
`L'(a) = L(a) + credits(a) - debits(a) - fee(a)`. `fee(a)` is the
runtime-reported transaction fee only for the transaction fee payer; it is
separate from the settlement plan. Program refusal/abort rolls back program and
CPI account changes but does not refund the runtime fee. Moving lamports to the
incinerator is an explicit account credit, not an immediate removal from the
ledger. Rent is a balance held by an account, not a protocol expense.

- **Tag 132:** no account lamports move. Only the fee payer's runtime fee can
  reduce a transaction balance.
- **Tag 131:** let `C` be DCR1 lamports and `B_c` its committed challenge bond.
  Require `C >= RentFloor(DCR1)+B_c`; credit `B_c` to the DCR1 ruling winner,
  then credit `C-B_c` (rent plus any excess) to the recorded challenger and
  close DCR1. If DRU1 is DCG-owned, credit all its balance to the recorded
  executor and close it; a System-owned empty DRU1 is currently left untouched.
  If a live challenger win has a held document bond `B_e`, STANDARD books
  `pot=B_e`, `slasher=floor(B_e*slasher_bps/10,000)` in U128 when a winner is
  recorded, and `slasher=0` otherwise. A credit is paid only if the destination
  reaches the code's minimum balance `(128+data_len)*6,960`; a skipped winner
  share is added to the remainder credit. Any amount the remainder cannot
  accept goes to incinerator. CUSTOM instead credits exactly `B_e` to escrow.
  If the document bond is not live, no document-bond movement occurs.
- **Tag 172:** let `D`, `P`, and `F` be the pre-close balances of DCM2, DPR2,
  and DFS2. If a held convicted bond is paid/escrowed at close, let `B_e` be
  the exact moved pot; otherwise `B_e=0` (a held but unconvicted bond is
  returned as part of the payer drain). The recorded payer receives
  `D+P+F-B_e`. STANDARD destinations and the incinerator receive all of `B_e`
  under the same credit/skip rule; CUSTOM escrow receives `B_e`. DCM2/DPR2/DFS2
  end at zero lamports/data and System ownership. DCR2 and DTU1 lamports do not
  move at tag 172; DCR2's rent remains for retention.

**Unsolicited lamports:** today, a donation to a soon-drained DCR1 goes to the
recorded challenger; a program-owned DRU1 donation goes to its recorded
executor; DCM2/DPR2/DFS2 excess goes to DCM2's recorded payer after any committed
bond is disposed. DCR2 excess stays until tag 185, which retains its required
tombstone rent and refunds excess to its recorded executor. DTU1 donations stay
in DTU1 during tag 172. A pre-funded System-owned empty DRU1 address is accepted
but not drained today, so any donated lamports there remain. The System-owned
bond escrow can also be pre-funded; tag 131 tops it up, and tag 187 reads its
whole balance at retry time, so a donation becomes part of the next settlement
pot. The proposed executor preserves these account-local rules and rejects any
plan whose named recipient is not the recipient committed by the associated
record; it does not refund a donor by tracing the transfer's origin.

## 8. Settlement-only statements and submission assumptions

These statements cover only the listed settlement transitions. The adversary
may choose arbitrary instruction bytes, account metas, unrelated signers, fee
payer, submission slot, and donations to any public account/PDA. They cannot
forge a required signature or mutate DCG-owned record bytes except through an
accepted program transition. The validator must reject wrong owners, keys,
record bytes, aliases, privileges, and bounds before invoking Bend. Caller
identity or transaction arrival order is never a protocol input except where
the current first-settled-winner rule explicitly makes order observable.

1. **Timeout ruling.** Given a validated DCR1 in one of the six supported
   nonterminal phases and its validated DCM2 parent, an accepted tag 132 at
   `now > DCR1.deadline` writes the phase-table winner and timeout cause; no
   caller-selected account changes the winner. At `now == deadline` it refuses.
   Conditional on the slot advancing and a valid permissionless transaction
   being included, the timeout transition is available. It does not promise
   censorship resistance or eventual inclusion.
2. **Challenge settlement.** Given a validated RULED DCR1 and its DCM2, tag 131
   sends the challenge bond to the ruling winner from DCR1 and the residual
   record balance to the stored challenger. A document-bond movement can only
   use the committed DCM2 terms and policy accounts; no caller-selected
   recipient receives it. Tag 131 has no deadline equality condition. Identical
   validated pre-state and role-equivalent inputs produce identical plans,
   but distinct challenge settlements sharing DCM2 do not commute under the
   current write-once winner rule.
3. **Document close and refund.** Given a valid DCM2/DPR2/DFS2/DCR2/DTU1 set,
   close requires no open challenge. Finalized rows require `now > dispute_deadline`;
   unfinalized close and the withheld branch use inclusive `now >=
   abandon_deadline`. Successful close sends working-account lamports to the
   DCM2-recorded payer and leaves DCR2 at its versioned retention state. The
   any-signer submitter cannot redirect rent. Conditional on slot progression
   and transaction inclusion, the close is submitable once its exact row's
   conditions hold; inclusion remains an external assumption.
4. **Atomic accounting.** For the successful operations above, account balances
   follow §7 plus the runtime fee. On a returned error or runtime abort, no
   program-account bytes or lamports remain changed after transaction
   rollback; the fee payer still pays its transaction fee. This atomicity claim
   depends on Solana transaction semantics and must be tested with injected
   failure after earlier operations in the actual local SBF image.

These are settlement-only properties. “Honest party wins,” faithful replay,
termination of the whole dispute, and universal finality are out of scope. In
particular the law file marks honest-wins and predecessor binding pending the
RESPOND seam review, and custom tag 187 remains an unbounded liveness exception.

## 9. Two settlement findings retained without choosing policy

### First settled conviction determines the document-bond recipient

**Current behavior:** `record_winner_if_unset` is called on the first settled
challenger win while the DCM2 bond is still HELD. It records that challenge's
ruling challenger and later STANDARD settlement pays the slasher share to the
recorded winner. Therefore settlement order can change who receives the document
bond share. Stop-rule convictions at close leave the winner field zero. The
field is not overwritten by later settlements.

**Options, not a decision:** keep first-settled-wins and state its order
sensitivity as protocol behavior; use an order-independent reducer such as a
fixed minimum over settled winner identities and pay at a later finalized
boundary; or send the entire slashed share to a fixed committed destination.
Any change to the payout rule needs an explicit version and tests that permute
settlement order.

### Tag 187 custom settlement can refuse forever

**Current behavior:** v8 tag 131/tag 172 places a CUSTOM bond in a
system-owned, zero-data bond escrow. Tag 187 assigns that PDA to the committed
custom program and invokes it. If the program refuses, Solana rolls the
transaction back, leaving the escrow System-owned and funded so it can be
retried. Tag 187 has no deadline and no deterministic fallback; the custom
program can therefore refuse indefinitely. The document close can still drain
DCM2/DPR2/DFS2, but escrow/tombstone settlement finality remains open.

**Options, not a decision:** add a committed retry deadline and deterministic
fallback recipient/disposition; remove CUSTOM and use only the STANDARD rule;
or explicitly exclude uncleared custom escrow from the protocol's finality
claim and leave permissionless retry unbounded. Choosing a fallback changes
bond semantics and needs a versioned rule and adversarial tests.

## 10. Evidence and open work

- **Measured:** DCG tags 132/131/172 use the local SBF ProgramTest CU cases
  cited above. These are mechanics measurements, not live-chain results, not
  Bend costs, and not worst-case close bounds.
- **Designed:** this Rust/Bend split, fact set, plan language, close ordering,
  conservation equations, and settlement-only statements.
- **Open:** independent identity/seed provenance for existing account sets;
  the revision-8 machine spec and its reconciliation with `referee-laws.md`;
  external fixed-layout Bend codecs; borrowed-byte streaming for DCR2; mixed SBF
  runtime execution; generic plan preflight/rollback in a real handler; tag 172
  worst-case close CU under Bend; and tag 187 liveness policy.

`crates/dcg-program/tests/referee_laws.rs` is useful law-oriented coverage but
does not test these three tags. The settlement tests listed above preserve
standard/custom payout and close mechanics, but they do not prove the intended
protocol rule, independent seed provenance, all role-order permutations, or
failure atomicity for a future multi-operation Bend executor. No DCG tests or
builds were run while preparing this documentation-only contract.
