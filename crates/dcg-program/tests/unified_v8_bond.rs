#![cfg(feature = "revision-8")]

//! Revision 8's **bond**: the per-document escrow, the challenge route paying
//! the document's own policy (spec `docs/spec/dcg-unified-v8.md` §1.4 and §1.6's
//! tag-131 row) and **tag 187 `RetryBondSettlementV5`**, the only caller of a
//! settlement program anywhere in the revision.
//!
//! Everything here is driven from **real instructions** over accounts the
//! program itself derived, and the records are **crafted** and labelled as such:
//! a DCR1 v5 needs a real 8,192-byte record with a real phase and a real
//! descriptor, but no part of this slice reads the template, the plan or a
//! proof, so nothing here needs `BASANOS_PT2P_ROOT` and **this file runs in the
//! default offline suite**.
//!
//! What is real: the escrow address is the program's own derivation; the terms
//! are a `Terms2` the program's own decoder accepts (and several it refuses,
//! 791); the split is `terms::bond_split`; the credits are `terms::credit`; the
//! BSS1 record is built from the record's own fields; the CPIs are the system
//! program's `transfer` and `assign` and **five real programs loaded into the
//! test bank** as settlement programs, which is what makes the honest, refusing
//! and misbehaving cases three real callees rather than three mocks.
//!
//! Crafted, and labelled where each is used: the **escrow's balance** where a
//! settlement needs one. Tag 187 requires an escrow that exists and holds
//! lamports, and the honest route that creates one is the CUSTOM settle (the
//! other half of this slice) or `CloseDocumentV5` (stream C4's), so a retry test
//! lays the escrow down at exactly the pot it expects; and the *griefing* case
//! lays it down at pot + 1, which is a third party's one-lamport deposit at an
//! address anyone can derive from a public descriptor (spec §1.4's "why the pot
//! field is read at call time"). **Where a test needs the escrow to exist at
//! all, the fixture lays it down**; that is the only state a test writes by hand
//! on this route.
//!
//! **The DLE1 event bodies are not asserted in this file, and the reason is the
//! harness rather than the design:** `sol_log_data` is a **stub in a native
//! program**, so under `solana-program-test` with `prefer_bpf(false)` a DLE1
//! event produces no log line at all. The bodies are pinned where they can be --
//! `tests/golden/dcg/unified_v8/vectors_v1.tsv` carries the kind-12 `bond_retry`
//! body and the 72-byte `close` body, `events::BODY_V3` carries the lengths, and
//! the SBF path (C1's `BASANOS_DCG_V8_SBF` census) is where the bytes are
//! observed on chain. What *is* asserted here is everything a state reader can
//! see: balances, the bond state, the recorded winner, the escrow, and every
//! refusal code.
//!
//! **Three things this harness cannot show, each found by these tests and each
//! recorded rather than papered over.** (i) A **native** callee can write the
//! buffer of a read-only meta, and the syscall stub copies only *writable* inner
//! accounts back to the caller, so a program that scribbled on the result record
//! would be invisible here instead of refused. On chain it cannot: DCG passes
//! that account read-only, and the loader refuses a privilege escalation in a
//! further CPI. So the marker check in `bond::retry` is belt-and-braces and has
//! no test case. (ii) A native callee that **debits a destination it does not
//! own** is caught by the harness's own stub ("instruction spent from the
//! balance of an account it does not own") before DCG's post-check runs, so that
//! case asserts *a refusal* rather than the code 798. (iii) A settlement
//! program's own credits are the **runtime's** business, not DCG's credit rule:
//! crediting a sub-floor amount to a new account is refused by the runtime, so
//! the honest programs here pay funded accounts. §1.4's credit rule governs DCG's
//! own credits -- the STANDARD route and the close's drain -- and those are
//! tested on their own.
//!
//! Two mechanical notes for anyone extending this file. **Fee payers rotate**
//! through a pool of eight: two byte-identical transactions in one slot are the
//! same signature and the bank answers the second with `AlreadyProcessed`. And
//! the **escrow is laid down by the fixture** wherever a settlement needs one that
//! already holds lamports, because the route that creates it for real is the
//! CUSTOM settle above or `CloseDocumentV5`, which is stream C4's slice.
//!
//! `cu` figures printed here are **measured-local, native**
//! (`solana-program-test` with `prefer_bpf(false)`). The honest retry's total
//! includes a **native** callee, so it is not an SBF figure and is not quoted as
//! one; the rows worth quoting are the refusals, which never reach a callee.
use dcg_program::unified::{
    address, bond, document, events, result,
    terms::{self, Terms2, BOND_POLICY_CUSTOM, BOND_POLICY_STANDARD, TERMS_BYTES_V2},
    TAG_RETRY_BOND_SETTLEMENT,
};
use solana_account::{Account, AccountSharedData};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const SYSTEM: Pubkey = solana_program::system_program::ID;
const INCINERATOR: Pubkey = solana_program::incinerator::ID;
const TAG_SETTLE: u8 = 131;
const TAG_TIMEOUT: u8 = 132;
const CL_MALFORMED: u32 = 580;
const CL_AUTHORITY: u32 = 582;
const CL_CLOSE: u32 = 599;
const DCR1_BAD: u32 = 730;
const DCR1_AUTH: u32 = 731;
const DCR1_PHASE: u32 = 733;
const DISPUTE_TERMS: u32 = 791;
const SETTLEMENT_PROGRAM: u32 = 798;
const BOND_NONE: u8 = 0;
const BOND_HELD: u8 = 1;
const BOND_PAID: u8 = 2;
const BOND_ESCROWED: u8 = 4;
const REC_BYTES: usize = 8_192;
/// `minimum_balance(len) = (128 + len) x 6,960` (spec §1.4's one rent model).
const PER_BYTE: u64 = 6_960;
/// The pot every settle test pays out: `split.tsv`'s dust row is
/// `5,000,001` at `bps = 1`, so the smallest share the credit rule can skip
/// appears in a real vector rather than a synthetic one.
const POT: u64 = 5_000_001;
/// §1.1 check 11's floor, and the reason a 1-lamport bond cannot fund the
/// account it is escrowed in.
const ESCROW_FLOOR: u64 = 128 * PER_BYTE;

fn rent_exempt(len: usize) -> u64 {
    (128 + len) as u64 * PER_BYTE
}

fn dcm2_bytes() -> usize {
    document::OPTION_REGION_AT
}

fn system_funded(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: SYSTEM,
        executable: false,
        rent_epoch: 0,
    }
}

fn owned(program: &Pubkey, data: Vec<u8>, lamports: u64) -> Account {
    Account {
        lamports,
        data,
        owner: *program,
        executable: false,
        rent_epoch: 0,
    }
}

fn put(ctx: &mut ProgramTestContext, key: &Pubkey, account: Account) {
    ctx.set_account(key, &AccountSharedData::from(account));
}

// ---------------------------------------------------------------- the terms

/// A DDT2 v2 the program's own decoder accepts: `kind = 1` (STANDARD) with a
/// `bond_slasher_bps` and a `bond_remainder`, `kind = 2` (CUSTOM) with a zero
/// share, a nonzero program and window, and a bond of `ESCROW_FLOOR` because
/// check 11 admits nothing between 0 and the escrow's rent-exempt minimum.
fn policy(kind: u8, slasher_bps: u16, bond: u64, remainder: Pubkey, settlement: Pubkey) -> Terms2 {
    Terms2 {
        challenge_window_slots: 90_000,
        response_window_slots: 45_000,
        challenger_bond_lamports: 1_000_000,
        executor_bond_lamports: bond,
        executor_reward_bps: 5_000,
        bond_policy_kind: kind,
        bond_slasher_bps: slasher_bps,
        settlement_program: settlement.to_bytes(),
        custom_settle_window_slots: if kind == BOND_POLICY_CUSTOM {
            604_800
        } else {
            0
        },
        result_retention_slots: 2_592_000,
        bond_remainder: remainder.to_bytes(),
        // **The grace is the template's, not a constant**: `Terms2::decode` keeps
        // only the structural floor (one slot) since the `rev8-window-limits`
        // merge, and the window itself is bounded by the template's DTU1 limits
        // at init. Nothing on the settle or the retry route reads it, so any legal
        // value will do here.
        abandon_after_slots: 2_592_000,
    }
}

fn standard(remainder: Pubkey, bps: u16) -> Terms2 {
    policy(BOND_POLICY_STANDARD, bps, POT, remainder, Pubkey::default())
}
fn custom(remainder: Pubkey, settlement: Pubkey) -> Terms2 {
    policy(BOND_POLICY_CUSTOM, 0, ESCROW_FLOOR, remainder, settlement)
}

// -------------------------------------------------------------- the records

/// A DCM2 v7 at the program's own derived address: the header fields the settle
/// and the retry read, and nothing else. The DRB1 v2 block is left zeroed with
/// `option_count = 0` (byte 2,129), which is all `document_v8` asks of it -- the
/// length check -- so this is a record of the shape the program would accept at
/// init and nothing more.
fn dcm2_v7(
    program: &Pubkey,
    descriptor: &[u8; 32],
    executor: &Pubkey,
    t: &Terms2,
    open: u32,
    bond_state: u8,
    winner: Option<Pubkey>,
) -> Vec<u8> {
    let mut out = vec![0u8; dcm2_bytes()];
    out[..4].copy_from_slice(b"DCM2");
    out[4..6].copy_from_slice(&7u16.to_le_bytes());
    out[6..8].copy_from_slice(
        &(document::FLAG_ARMED
            | document::FLAG_FINAL
            | document::FLAG_ROOT_ONLY
            | document::FLAG_SEALED)
            .to_le_bytes(),
    );
    out[8..40].copy_from_slice(descriptor);
    out[40..72].copy_from_slice(executor.as_ref());
    out[72..76].copy_from_slice(&80u32.to_le_bytes());
    out[76..78].copy_from_slice(&34u16.to_le_bytes());
    out[document::DCM2_BUMP_AT] = address::document(program, descriptor).1.value();
    out[document::DPR2_BUMP_AT] = address::positions(program, descriptor).1.value();
    out[document::DFS2_BUMP_AT] = address::family_slots(program, descriptor).1.value();
    out[document::BOND_ESCROW_BUMP_AT] = address::bond_escrow(program, descriptor).1;
    out[84..88].copy_from_slice(&40u32.to_le_bytes());
    out[88..96].copy_from_slice(&504_606_552u64.to_le_bytes());
    out[128..132].copy_from_slice(&open.to_le_bytes());
    out[144..152].copy_from_slice(&t.challenge_window_slots.to_le_bytes());
    out[184..192].copy_from_slice(&t.challenge_window_slots.to_le_bytes());
    out[192..200].copy_from_slice(&504_606_552u64.to_le_bytes());
    out[264..296].copy_from_slice(&[1u8; 32]);
    out[296..328].copy_from_slice(&[2u8; 32]);
    out[328..360].copy_from_slice(&[3u8; 32]);
    out[456..488].copy_from_slice(&[4u8; 32]);
    out[527] = 3;
    out[529] = bond_state;
    if let Some(w) = winner {
        out[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32].copy_from_slice(w.as_ref());
    }
    out[document::TERMS_AT_V8..document::TERMS_AT_V8 + TERMS_BYTES_V2].copy_from_slice(&t.encode());
    out
}

/// A DCR2 v6 at its own derived address, in the state a **CUSTOM close** leaves
/// behind: closed, `bond_state = 4`, the cause, the recorded winner, the
/// retention clock and the mirrored terms. `count = 1` and `width = 1`, so the
/// record is 418 bytes and `view_v8_status`'s own size check passes.
fn dcr2_v6(
    descriptor: &[u8; 32],
    executor: &Pubkey,
    t: &Terms2,
    cause: u8,
    winner: Option<Pubkey>,
    status: u8,
) -> Vec<u8> {
    let mut out = vec![0u8; 418];
    out[..4].copy_from_slice(b"DCR2");
    out[4..6].copy_from_slice(&result::VERSION_V6.to_le_bytes());
    out[6] = status;
    out[7] = 1;
    out[8..40].copy_from_slice(descriptor);
    out[40..72].copy_from_slice(&[9u8; 32]);
    out[136..168].copy_from_slice(executor.as_ref());
    out[196..200].copy_from_slice(&1u32.to_le_bytes());
    out[208] = 1;
    out[result::RESULT_TERMS_AT_V6..result::RESULT_TERMS_AT_V6 + TERMS_BYTES_V2]
        .copy_from_slice(&t.encode());
    if let Some(w) = winner {
        out[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32].copy_from_slice(w.as_ref());
    }
    out[result::RETENTION_SLOTS_AT_V6..result::RETENTION_SLOTS_AT_V6 + 8]
        .copy_from_slice(&t.result_retention_slots.to_le_bytes());
    out[result::BOND_STATE_AT_V6] = BOND_ESCROWED;
    out[result::BOND_CAUSE_AT_V6] = cause;
    out
}

/// A **DCRZ v2** tombstone (spec §1.5): what `CloseResultV6` writes at the
/// retention deadline while a bond is still escrowed, and the only record tag
/// 187 can read after DCR2 is gone. `status = 4` (WITHHELD) with a zero winner
/// is the withheld case; `status = 2` (REFUTED) with the challenger's key is the
/// conviction one.
fn dcrz_v2(
    descriptor: &[u8; 32],
    executor: &Pubkey,
    t: &Terms2,
    cause: u8,
    winner: Option<Pubkey>,
    status: u8,
) -> Vec<u8> {
    let mut out = vec![0u8; result::TOMBSTONE_V2_BYTES];
    out[..4].copy_from_slice(b"DCRZ");
    out[4..6].copy_from_slice(&2u16.to_le_bytes());
    out[6] = status;
    out[7] = 1;
    out[8..40].copy_from_slice(descriptor);
    out[40..72].copy_from_slice(executor.as_ref());
    out[72..80].copy_from_slice(&100_000u64.to_le_bytes());
    out[80..88].copy_from_slice(&(100_000 + t.result_retention_slots).to_le_bytes());
    out[88..96].copy_from_slice(&(100_000 + t.result_retention_slots).to_le_bytes());
    out[result::TOMBSTONE_V2_CAUSE_AT] = cause;
    out[result::TOMBSTONE_V2_PROGRAM_AT..result::TOMBSTONE_V2_PROGRAM_AT + 32]
        .copy_from_slice(&t.settlement_program);
    out[result::TOMBSTONE_V2_REMAINDER_AT..result::TOMBSTONE_V2_REMAINDER_AT + 32]
        .copy_from_slice(&t.bond_remainder);
    if let Some(w) = winner {
        out[result::TOMBSTONE_V2_WINNER_AT..result::TOMBSTONE_V2_WINNER_AT + 32]
            .copy_from_slice(w.as_ref());
    }
    out
}

/// A DCR1 v5 challenge record in phase 3 (ruled) with a challenger win, bound to
/// `descriptor` and to `executor`, carrying `record_bond` at 162. Every other
/// byte is zero, which the settle does not read: the round walk, the proofs and
/// the trees belong to instructions this slice is not driving.
fn dcr1_ruled(
    program: &Pubkey,
    descriptor: &[u8; 32],
    challenger: &Pubkey,
    executor: &Pubkey,
    record_bond: u64,
    cause: u8,
    ruled_for_challenger: bool,
) -> Vec<u8> {
    let mut out = vec![0u8; REC_BYTES];
    out[..4].copy_from_slice(b"DCR1");
    out[4] = 3;
    out[5] = if ruled_for_challenger { 2 } else { 1 };
    out[6..8].copy_from_slice(&5u16.to_le_bytes());
    out[8..40].copy_from_slice(challenger.as_ref());
    out[40..72].copy_from_slice(executor.as_ref());
    out[72..104].copy_from_slice(descriptor);
    // A fresh revision-8 image requires the canonical DCR1 and DRU1 bumps.
    out[140..144].copy_from_slice(&0u32.to_le_bytes());
    out[144] = 1;
    let nonce = 0u32.to_le_bytes();
    let (challenge_key, challenge_bump) = Pubkey::find_program_address(
        &[
            b"dcg-unified-challenge",
            descriptor,
            challenger.as_ref(),
            &nonce,
        ],
        program,
    );
    out[146] = challenge_bump;
    out[147] = 1;
    out[148..156].copy_from_slice(&1u64.to_le_bytes());
    out[162..170].copy_from_slice(&record_bond.to_le_bytes());
    out[178] = cause;
    let response_bump =
        Pubkey::find_program_address(&[b"dcg-hcl-response", challenge_key.as_ref()], program).1;
    // The lifecycle moves the staged byte at 181 to the stable slot at 219
    // after position-root staging completes. Settlement fixtures model that
    // post-open state directly.
    out[181] = response_bump;
    out[dcg_program::unified::challenge::RESPONSE_BUMP_AT] = response_bump;
    out
}

// ------------------------------------------------- the settlement programs

fn pay(from: &AccountInfo, to: &AccountInfo, amount: u64) -> Result<(), ProgramError> {
    let mut lamports = from.try_borrow_mut_lamports()?;
    let have = **lamports;
    **lamports = have
        .checked_sub(amount)
        .ok_or(ProgramError::Custom(9_001))?;
    drop(lamports);
    **to.try_borrow_mut_lamports()? = to
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::Custom(9_002))?;
    Ok(())
}

/// The one check §1.9 says a callee must make against the record: the `winner`
/// meta is the record's `winner[32]`, **or** the record's winner is thirty-two
/// zero bytes and the meta is the incinerator. Every program below makes it, so
/// a program that cannot read its own record fails loudly instead of paying out.
fn wire(accounts: &[AccountInfo], data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() != 200 || &data[..4] != b"BSS1" || u16::from_le_bytes([data[4], data[5]]) != 1 {
        return Err(ProgramError::Custom(9_004));
    }
    if accounts.len() != 7 {
        return Err(ProgramError::Custom(9_005));
    }
    if *accounts[6].key != SYSTEM {
        return Err(ProgramError::Custom(9_007));
    }
    // **Only an account's owner may debit it**, so the program asserts it was
    // handed the escrow rather than asking for lamports it cannot take.
    if accounts[1].owner != accounts[0].key {
        return Err(ProgramError::Custom(9_008));
    }
    let want: [u8; 32] = data[8..40].try_into().unwrap();
    let named = if want == [0u8; 32] {
        *accounts[2].key == INCINERATOR
    } else {
        accounts[2].key.as_ref() == want
    };
    if !named {
        return Err(ProgramError::Custom(9_003));
    }
    Ok(u64::from_le_bytes(data[168..176].try_into().unwrap()))
}

/// **The honest settlement program**: it empties the escrow and pays half of the
/// pot to the winner and half to the committed remainder, and it takes nothing
/// from anywhere else. `pot` is the escrow's balance at call time, so a
/// pre-funded escrow is paid out in full.
fn settler(_program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let pot = wire(accounts, data)?;
    let half = pot / 2;
    pay(&accounts[1], &accounts[2], half)?;
    pay(&accounts[1], &accounts[3], pot - half)
}

/// **A misbehaving one**: it empties the escrow but keeps a lamport, which is the
/// named non-case the post-check exists for (798).
fn settler_thief(_program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let pot = wire(accounts, data)?;
    pay(&accounts[1], &accounts[3], pot - 1)
}

/// **A refusing one**: it errors before touching anything, which is the case the
/// split of the work makes survivable -- the transaction aborts, the escrow keeps
/// every lamport, and anyone may call again.
fn settler_refuses(_program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let _ = wire(accounts, data)?;
    Err(ProgramError::Custom(9_011))
}

/// **A greedy one**: it empties the escrow exactly as it should and then takes a
/// lamport out of a **destination**, which is the other post-check -- "no other
/// account lost lamports" -- and the only one a callee can reach with the metas
/// it is given, since every meta it has is either writable-and-there or
/// read-only.
///
/// **A callee cannot reach the result record at all**, so there is deliberately
/// no case for it: DCG passes that account **read-only**, and on chain a callee
/// cannot write a read-only account (nor escalate it in a further CPI, which the
/// loader refuses). Under `solana-program-test` a *native* callee can in fact
/// write the buffer it is handed, and the harness's syscall stub copies only
/// writable inner accounts back to the caller, so such a case would be invisible
/// here rather than refused -- which is why it is not in this file and the
/// marker check is documented as belt-and-braces in `bond.rs`.
fn settler_greedy(_program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let pot = wire(accounts, data)?;
    pay(&accounts[1], &accounts[3], pot)?;
    let mut lamports = accounts[2].try_borrow_mut_lamports()?;
    **lamports = lamports.checked_sub(1).ok_or(ProgramError::Custom(9_012))?;
    Ok(())
}

/// **A lazy one**: it moves nothing at all, so the escrow does not end at zero.
fn settler_idle(_program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let _ = wire(accounts, data)?;
    Ok(())
}

// -------------------------------------------------------------- the fixture

/// The keys, cheap to make: a test that needs a *second* bank (to borrow another
/// behaviour's program id, say) makes its own set rather than starting one.
struct Ids {
    program: Pubkey,
    honest: Pubkey,
    thief: Pubkey,
    refuser: Pubkey,
    greedy: Pubkey,
    idle: Pubkey,
    executor: Pubkey,
    challenger: Pubkey,
    /// A **second** challenger: the recorded conviction winner of some earlier
    /// challenge, which is not this challenge's ruling winner (§1.4's row 131:
    /// "the recorded winner need not be the ruling winner of *this* challenge").
    convict: Pubkey,
    remainder: Pubkey,
    impostor: Pubkey,
    /// A **pool** of fee payers, one per send: two byte-identical transactions in
    /// one slot are the same signature, and the bank answers the second with
    /// `AlreadyProcessed`. The pool is larger than the largest number of sends in
    /// any one test here (about twenty), so every message in a test is distinct,
    /// and `Fx::payer` panics rather than repeating a key -- a flake becomes a
    /// loud failure.
    signers: Vec<Keypair>,
}

fn ids() -> Ids {
    Ids {
        program: Pubkey::new_unique(),
        honest: Pubkey::new_unique(),
        thief: Pubkey::new_unique(),
        refuser: Pubkey::new_unique(),
        greedy: Pubkey::new_unique(),
        idle: Pubkey::new_unique(),
        executor: Pubkey::new_unique(),
        challenger: Pubkey::new_unique(),
        convict: Pubkey::new_unique(),
        remainder: Pubkey::new_unique(),
        impostor: Pubkey::new_unique(),
        signers: (0..32).map(|_| Keypair::new()).collect(),
    }
}

struct Fx {
    ctx: ProgramTestContext,
    ids: Ids,
    turn: usize,
    used: Vec<Pubkey>,
}

impl Fx {
    /// The next fee payer, and **never the same one twice in one fixture**: two
    /// identical messages signed by one payer in one slot are one signature, and
    /// the bank answers the second with `AlreadyProcessed`. The pool is larger
    /// than any test's send count, so this never has to wrap; the assert is here
    /// so that a test which grows past the pool fails loudly instead of
    /// flakily.
    fn payer(&mut self) -> Pubkey {
        let key = self.ids.signers[self.turn].pubkey();
        assert!(
            self.turn < self.ids.signers.len(),
            "the fee-payer pool is exhausted"
        );
        assert!(
            !self.used.contains(&key),
            "a fee payer is used twice in one fixture"
        );
        self.used.push(key);
        self.turn += 1;
        key
    }
}

impl Fx {
    async fn account(&mut self, key: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(key).await.unwrap()
    }
    async fn data(&mut self, key: Pubkey) -> Vec<u8> {
        self.account(key)
            .await
            .unwrap_or_else(|| panic!("{key} exists"))
            .data
    }
    async fn lamports(&mut self, key: Pubkey) -> u64 {
        self.account(key).await.map(|a| a.lamports).unwrap_or(0)
    }
    fn descriptor(&self) -> [u8; 32] {
        [0x42; 32]
    }
    fn dcm2(&self) -> Pubkey {
        address::document(&self.ids.program, &self.descriptor()).0
    }
    fn dcr2(&self) -> Pubkey {
        address::result(&self.ids.program, &self.descriptor()).0
    }
    fn escrow(&self) -> Pubkey {
        address::bond_escrow(&self.ids.program, &self.descriptor()).0
    }
    fn record(&self) -> Pubkey {
        address::challenge(
            &self.ids.program,
            &self.descriptor(),
            &self.ids.challenger,
            0,
        )
        .0
    }
    fn response(&self) -> Pubkey {
        dcg_program::closure_v2_response::address(&self.ids.program, &self.record()).0
    }
    /// The nine metas of tag 131 on a revision-8 record: revision 7's seven plus
    /// two. `extra_a` is the `policy_winner` under `kind = 1` and the escrow
    /// under `kind = 2`; `extra_b` is the remainder or the system program.
    fn settle_metas(&mut self, extra_a: Pubkey, extra_b: Pubkey) -> Vec<AccountMeta> {
        let payer = self.payer();
        let i = &self.ids;
        vec![
            AccountMeta::new(self.record(), false),
            AccountMeta::new(self.response(), false),
            AccountMeta::new(i.challenger, false),
            AccountMeta::new(i.executor, false),
            AccountMeta::new(self.dcm2(), false),
            AccountMeta::new(INCINERATOR, false),
            AccountMeta::new(i.challenger, false),
            AccountMeta::new(extra_a, false),
            AccountMeta::new(extra_b, false),
        ]
    }
    /// Install a result image at the result address, and an escrow balance at
    /// the escrow address. Both own the borrow, so a call site never holds the
    /// fixture's `&mut` and its `&` at once.
    fn install_result(&mut self, mut image: Vec<u8>, lamports: u64) {
        let (key, program) = (self.dcr2(), self.ids.program);
        if image.starts_with(b"DCR2") && image.len() > result::RESULT_PDA_BUMP_AT_V6 {
            let descriptor: [u8; 32] = image[8..40].try_into().expect("DCR2 descriptor");
            image[result::RESULT_PDA_BUMP_AT_V6] = address::result(&program, &descriptor).1.value();
        }
        put(&mut self.ctx, &key, owned(&program, image, lamports));
    }
    fn install_escrow(&mut self, lamports: u64) {
        let key = self.escrow();
        put(&mut self.ctx, &key, system_funded(lamports));
    }
    fn install_at(&mut self, key: Pubkey, account: Account) {
        put(&mut self.ctx, &key, account);
    }
    /// The eight metas of tag 187: any signer, then the seven of the cause-4
    /// BSS1 list, of which the result account is writable.
    fn retry_metas(
        &mut self,
        settlement: Pubkey,
        winner: Pubkey,
        remainder: Pubkey,
    ) -> Vec<AccountMeta> {
        let payer = self.payer();
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(settlement, false),
            AccountMeta::new(self.escrow(), false),
            AccountMeta::new(winner, false),
            AccountMeta::new(remainder, false),
            AccountMeta::new(self.ids.executor, false),
            AccountMeta::new(self.dcr2(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]
    }
}

async fn start(ids: Ids) -> Fx {
    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    test.add_program(
        "dcg_program",
        ids.program,
        processor!(dcg_program::process_instruction),
    );
    test.add_program("settler_honest", ids.honest, processor!(settler));
    test.add_program("settler_thief", ids.thief, processor!(settler_thief));
    test.add_program("settler_refuses", ids.refuser, processor!(settler_refuses));
    test.add_program("settler_greedy", ids.greedy, processor!(settler_greedy));
    test.add_program("settler_idle", ids.idle, processor!(settler_idle));
    for key in [
        ids.executor,
        ids.challenger,
        ids.convict,
        ids.remainder,
        ids.impostor,
    ] {
        test.add_account(key, system_funded(10_000_000_000));
    }
    for signer in &ids.signers {
        test.add_account(signer.pubkey(), system_funded(10_000_000_000));
    }
    Fx {
        ctx: test.start_with_context().await,
        ids,
        turn: 0,
        used: Vec::new(),
    }
}

async fn build() -> Fx {
    start(ids()).await
}

/// Lay down a ruled challenge record, the response account, the document, and --
/// where the test says so -- the escrow.
async fn stage(
    f: &mut Fx,
    t: &Terms2,
    bond_state: u8,
    winner: Option<Pubkey>,
    escrow: Option<u64>,
    ruled_for_challenger: bool,
) {
    let d = f.descriptor();
    let (program, record_key, dcm2_key, escrow_key, response_key) = (
        f.ids.program,
        f.record(),
        f.dcm2(),
        f.escrow(),
        f.response(),
    );
    let record = dcr1_ruled(
        &program,
        &d,
        &f.ids.challenger,
        &f.ids.executor,
        1_000_000,
        1,
        ruled_for_challenger,
    );
    put(
        &mut f.ctx,
        &record_key,
        owned(&program, record, rent_exempt(REC_BYTES) + 1_000_000),
    );
    // The response account at its derived address, system-owned and empty: an
    // executor that never sealed a response. The settle's own check admits it
    // and drains nothing.
    put(&mut f.ctx, &response_key, system_funded(1));
    let doc = dcm2_v7(
        &f.ids.program,
        &d,
        &f.ids.executor,
        t,
        1,
        bond_state,
        winner,
    );
    put(
        &mut f.ctx,
        &dcm2_key,
        owned(
            &program,
            doc,
            rent_exempt(dcm2_bytes()) + t.executor_bond_lamports,
        ),
    );
    if let Some(lamports) = escrow {
        put(&mut f.ctx, &escrow_key, system_funded(lamports));
    }
}

// ------------------------------------------------------------------ plumbing

/// Why a transaction did not succeed. A **custom code** is one of ours; anything
/// else is the client, the bank, or -- the case D12 is about -- a settlement
/// program that errored, which must be visible as *not* being a DCG refusal.
#[derive(Debug)]
enum Fail {
    Custom(u32),
    Other(String),
}

async fn send(f: &mut Fx, data: Vec<u8>, metas: Vec<AccountMeta>) -> Result<Vec<String>, Fail> {
    let (tag, len) = (data.first().copied().unwrap_or(0), data.len());
    let payer = f.payer();
    let mut metas = metas;
    if metas
        .first()
        .is_some_and(|m| f.ids.signers.iter().any(|s| s.pubkey() == m.pubkey))
    {
        // A meta 0 that is one of the pool is the instruction's signer, and it is
        // the *next* pool key, so two byte-identical transactions in one slot --
        // the same signature, which the bank answers with `AlreadyProcessed` --
        // cannot happen.
        metas[0] = AccountMeta::new(payer, true);
    }
    let ixs = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        Instruction {
            program_id: f.ids.program,
            accounts: metas,
            data,
        },
    ];
    let blockhash = f.ctx.banks_client.get_latest_blockhash().await.unwrap();
    let signer = f
        .ids
        .signers
        .iter()
        .find(|k| k.pubkey() == payer)
        .expect("a pool signer pays");
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer), &[signer], blockhash);
    let out = f
        .ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await;
    if let Ok(inner) = &out {
        if let Some(meta) = &inner.metadata {
            eprintln!("CU tag {tag} data {len} cu {}", meta.compute_units_consumed);
        }
    }
    match out {
        Ok(inner) => match inner.result {
            Ok(()) => Ok(inner.metadata.map(|m| m.log_messages).unwrap_or_default()),
            Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
                Err(Fail::Custom(code))
            }
            Err(other) => Err(Fail::Other(format!("{other:?}"))),
        },
        Err(error) => Err(Fail::Other(format!(
            "the banks client refused the transaction: {error:?}"
        ))),
    }
}

/// The settle and the retry, each taking its **already-built** meta list: the
/// list is built from the fixture (an immutable borrow) and then sent (a mutable
/// one), which is why no call site can spell both in one expression.
async fn settle(f: &mut Fx, metas: Vec<AccountMeta>) -> Result<Vec<String>, Fail> {
    send(f, vec![TAG_SETTLE], metas).await
}
async fn settle_ok(f: &mut Fx, metas: Vec<AccountMeta>) -> Vec<String> {
    match settle(f, metas).await {
        Ok(logs) => logs,
        Err(error) => panic!("expected the settle to succeed, got {error:?}"),
    }
}
async fn settle_refuse(f: &mut Fx, metas: Vec<AccountMeta>) -> u32 {
    match settle(f, metas).await {
        Err(Fail::Custom(code)) => code,
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}
async fn retry(f: &mut Fx, metas: Vec<AccountMeta>) -> Result<Vec<String>, Fail> {
    send(f, vec![TAG_RETRY_BOND_SETTLEMENT], metas).await
}
async fn retry_ok(f: &mut Fx, metas: Vec<AccountMeta>) -> Vec<String> {
    match retry(f, metas).await {
        Ok(logs) => logs,
        Err(error) => panic!("expected the retry to succeed, got {error:?}"),
    }
}
async fn retry_refuse(f: &mut Fx, metas: Vec<AccountMeta>) -> u32 {
    match retry(f, metas).await {
        Err(Fail::Custom(code)) => code,
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}

async fn ok(f: &mut Fx, data: Vec<u8>, metas: Vec<AccountMeta>) -> Vec<String> {
    match send(f, data, metas).await {
        Ok(logs) => logs,
        Err(error) => panic!("expected success, got {error:?}"),
    }
}

async fn refuse(f: &mut Fx, data: Vec<u8>, metas: Vec<AccountMeta>) -> u32 {
    match send(f, data, metas).await {
        Err(Fail::Custom(code)) => code,
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}

// ------------------------------------------------------------------- the tests

/// **The STANDARD policy, paid at a settle** (spec §1.4's third row, `kind = 1`).
/// `bps = 2,500` over `pot = 5,000,001`: the slasher share takes
/// `floor(1,250,000.25) = 1,250,000` and the remainder share the exact rest, the
/// dust included.
///
/// **The two destinations are the recorded winner and the committed
/// `bond_remainder`** -- not the ruling winner and not the incinerator -- and the
/// recorded winner here is a *different* challenger from this challenge's, which
/// is the case §1.4's row 131 exists for: the field is write-once, so the second
/// settle's own ruling winner is **not** recorded and is paid nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_settle_pays_the_standard_policy_split() {
    let mut f = build().await;
    let t = standard(f.ids.remainder, 2_500);
    assert_eq!(
        Terms2::decode(&t.encode()),
        Ok(t),
        "the terms the program decodes"
    );
    let convict = f.ids.convict;
    stage(&mut f, &t, BOND_HELD, Some(convict), None, true).await;
    let (slasher, rest) = terms::bond_split(POT, 2_500, true);
    assert_eq!(
        (slasher, rest),
        (1_250_000, 3_750_001),
        "floor, and the remainder takes the dust"
    );
    let before = (
        f.lamports(convict).await,
        f.lamports(f.ids.remainder).await,
        f.lamports(f.ids.executor).await,
    );
    let metas = f.settle_metas(convict, f.ids.remainder);
    settle_ok(&mut f, metas).await;
    assert_eq!(
        f.lamports(convict).await,
        before.0 + slasher,
        "the recorded winner's share"
    );
    assert_eq!(
        f.lamports(f.ids.remainder).await,
        before.1 + rest,
        "the committed remainder's share"
    );
    // **Neither the executor nor this challenge's own ruling winner is paid the
    // pot**, and the field is not overwritten.
    assert_eq!(
        f.lamports(f.ids.executor).await,
        before.2,
        "the convict is paid nothing"
    );
    let doc = f.data(f.dcm2()).await;
    assert_eq!(
        &doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        convict.as_ref(),
        "write-once: a later settle does not overwrite the recorded winner"
    );
    assert_eq!(doc[529], BOND_PAID, "the STANDARD seizure");
    assert_eq!(
        u32::from_le_bytes(doc[128..132].try_into().unwrap()),
        0,
        "open_challenges fell"
    );
    // The document account gave up exactly the pot and kept its rent.
    assert_eq!(f.lamports(f.dcm2()).await, rent_exempt(dcm2_bytes()));
    // The record: **drained to the challenger in full and removed by the
    // runtime**, so there is no phase left to read and a second settle is
    // impossible rather than refused. Its own bond went to the ruling winner
    // first, and the rest is the record's rent.
    assert!(
        f.account(f.record()).await.is_none(),
        "the record is drained and removed"
    );
    assert_eq!(f.lamports(f.ids.challenger).await,
        10_000_000_000 + 1_000_000 + rent_exempt(REC_BYTES),
        "the record bond and the drained record -- the *recorded* winner took the slasher share instead");
    // The `settle` event's 112 bytes carry the two policy shares and the route
    // byte, and **are not asserted here**: `sol_log_data` is a stub in a native
    // program, so a DLE1 event is invisible under `solana-program-test` and only
    // appears against an SBF image. The body is pinned by
    // `tests/golden/dcg/unified_v8/vectors_v1.tsv` (the settle, close and
    // kind-12 rows) and by `events::BODY_V3`; see this file's header.
    assert_eq!(
        events::BODY_V3[events::SETTLE as usize],
        112,
        "the revision-8 settle body length"
    );
}

/// **A first settled challenger win names its own ruling winner** (D11's
/// write-once, and the reason the split is computed *after* the write): with no
/// winner recorded, the settle records this challenge's ruling winner and pays
/// that account, so **the incinerator meta is refused** even though §1.4's
/// refusals row mentions it in the abstract. The row's parenthetical is reachable
/// on the close and on tag 187, where nothing writes the field first; on a
/// settle the field is never zero after the write, and paying a share to a meta
/// the record does not name would break D11's one rule. A refusal rolls the
/// write back, so the retry with the right meta settles the same pot.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_settled_challenger_win_names_its_own_ruling_winner() {
    let mut f = build().await;
    let t = standard(f.ids.remainder, 2_500);
    stage(&mut f, &t, BOND_HELD, None, None, true).await;
    let metas = f.settle_metas(INCINERATOR, f.ids.remainder);
    assert_eq!(
        settle_refuse(&mut f, metas).await,
        CL_AUTHORITY,
        "the incinerator, once the field is written"
    );
    let doc = f.data(f.dcm2()).await;
    assert_eq!(
        &doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        &[0u8; 32][..],
        "the refused attempt rolled the write back"
    );
    let executor_before = f.lamports(f.ids.executor).await;
    let slasher = terms::bond_split(POT, 2_500, true).0;
    let metas = f.settle_metas(f.ids.challenger, f.ids.remainder);
    settle_ok(&mut f, metas).await;
    assert_eq!(
        &f.data(f.dcm2()).await[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        f.ids.challenger.as_ref(),
        "and the retry records the winner it paid"
    );
    assert_eq!(
        f.lamports(f.ids.challenger).await,
        10_000_000_000 + slasher + 1_000_000 + rent_exempt(REC_BYTES)
    );
    assert_eq!(
        f.lamports(INCINERATOR).await,
        0,
        "no residual remained to burn"
    );
    assert_eq!(
        f.lamports(f.ids.executor).await,
        executor_before,
        "the convicted executor receives zero"
    );
}

/// **A skipped share goes to the remainder, never to the convict** (spec §1.4's
/// "where a skipped share goes"): an empty winner account cannot hold a
/// sub-floor share, so the share is **skipped** and the remainder credit is
/// `rest + slasher`. If the remainder cannot hold the combined amount either,
/// the residual is sent to the incinerator rather than left for the close to
/// pay to the convicted executor.
#[tokio::test(flavor = "multi_thread")]
async fn a_skipped_share_is_redirected_and_uncreditable_residual_is_burned_at_settle() {
    let (slasher, rest) = terms::bond_split(POT, 1, true);
    assert_eq!(
        (slasher, rest),
        (500, 4_999_501),
        "the dust row of split.tsv"
    );
    // A **recorded winner** who emptied its own wallet to dodge the share. The
    // share is skipped, and the credit rule *is* applied to the balance as it
    // stands: a destination that this instruction credits *earlier* -- the ruling
    // winner, which receives the record's own bond back a few statements before
    // the payout -- can hold the share afterwards, and is paid. The only
    // destination that can dodge a share is one this instruction pays nothing
    // else to, and that is the one this test empties.
    let mut f = build().await;
    let t = standard(f.ids.remainder, 1);
    let empty = f.ids.convict;
    f.install_at(empty, system_funded(0));
    stage(&mut f, &t, BOND_HELD, Some(empty), None, true).await;
    let rem_before = f.lamports(f.ids.remainder).await;
    let metas = f.settle_metas(empty, f.ids.remainder);
    settle_ok(&mut f, metas).await;
    assert_eq!(f.lamports(empty).await, 0, "the skip is not a payment");
    // The record's own challenger receives the record bond and the drained record.
    assert_eq!(
        f.lamports(f.ids.challenger).await,
        10_000_000_000 + 1_000_000 + rent_exempt(REC_BYTES)
    );
    assert_eq!(
        f.lamports(f.ids.remainder).await,
        rem_before + rest + slasher,
        "the remainder takes the skipped share as well"
    );
    assert_eq!(
        f.lamports(f.dcm2()).await,
        rent_exempt(dcm2_bytes()),
        "DCM2 was debited only what was paid"
    );

    // A sub-floor remainder credit is burned, not retained in DCM2 where a
    // later close would send it to the convicted executor.
    let mut g = build().await;
    let t2 = policy(
        BOND_POLICY_STANDARD,
        1,
        500_000,
        g.ids.remainder,
        Pubkey::default(),
    );
    let empty = g.ids.convict;
    g.install_at(empty, system_funded(0));
    g.install_at(g.ids.remainder, system_funded(0));
    stage(&mut g, &t2, BOND_HELD, Some(empty), None, true).await;
    let executor_before = g.lamports(g.ids.executor).await;
    let incinerator_before = g.lamports(INCINERATOR).await;
    let metas = g.settle_metas(empty, g.ids.remainder);
    settle_ok(&mut g, metas).await;
    assert_eq!(
        g.lamports(g.ids.remainder).await,
        0,
        "the redirect is itself subject to the rule"
    );
    assert_eq!(
        g.lamports(empty).await,
        0,
        "and the winner's share was paid nowhere"
    );
    assert_eq!(
        g.lamports(g.ids.executor).await,
        executor_before,
        "the convicted executor receives zero on the residual-burn path"
    );
    assert_eq!(
        g.lamports(INCINERATOR).await,
        incinerator_before + 500_000,
        "the convict never receives the uncreditable residual"
    );
    assert_eq!(
        g.lamports(g.dcm2()).await,
        rent_exempt(dcm2_bytes()),
        "no bond residual remains for close"
    );
    assert!(
        500_000 < ESCROW_FLOOR,
        "the residual is under one minimum balance"
    );
}

/// **The CUSTOM policy at a settle** (spec §1.4's third row, `kind = 2`): the pot
/// moves into the document's own bond escrow by direct lamport writes,
/// `executor_bond_state = 4`, both payouts are 0, and **no program is called**.
/// The read-only system-program meta stays in the fixed account list so STANDARD
/// and CUSTOM have the same positions. The no-CPI claim is checked the only way it can be
/// without trusting a log: the escrow is still owned by the **system program**
/// afterwards, and a callee can only have debited it if this instruction had
/// first assigned it, so an escrow owned by the policy program would have proved
/// the CPI happened.
#[tokio::test(flavor = "multi_thread")]
async fn the_settle_escrows_the_pot_under_a_custom_policy_and_calls_nothing() {
    let mut f = build().await;
    let t = custom(f.ids.remainder, f.ids.honest);
    stage(&mut f, &t, BOND_HELD, None, None, true).await;
    let metas = f.settle_metas(f.escrow(), SYSTEM);
    settle_ok(&mut f, metas).await;
    let doc = f.data(f.dcm2()).await;
    assert_eq!(
        doc[529], BOND_ESCROWED,
        "the only writers of 4 are the two escrowing routes"
    );
    assert_eq!(
        &doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        f.ids.challenger.as_ref()
    );
    // The escrow holds exactly the pot, and it is still the system program's.
    let escrow = f
        .account(f.escrow())
        .await
        .expect("the transfer created and funded the account");
    assert_eq!(
        escrow.lamports, ESCROW_FLOOR,
        "check 11's bond is the whole pot under kind 2"
    );
    assert!(escrow.data.is_empty());
    assert_eq!(
        escrow.owner, SYSTEM,
        "still system-owned: the policy program was never called"
    );
    assert_eq!(
        f.lamports(f.ids.remainder).await,
        10_000_000_000,
        "the remainder is paid nothing"
    );
    assert_eq!(
        f.lamports(f.ids.challenger).await,
        10_000_000_000 + 1_000_000 + rent_exempt(REC_BYTES),
        "the pot is escrowed, not paid: the record bond and the drained record only"
    );
    assert_eq!(
        f.lamports(f.dcm2()).await,
        rent_exempt(dcm2_bytes()),
        "the document kept its rent"
    );
    assert_eq!(
        events::BODY_V3[events::SETTLE as usize],
        112,
        "the revision-8 settle body length"
    );
}

/// **The pot is live on exactly one transition.** An executor win, a second
/// settle, and an already-escrowed pot move nothing, and the event says route 1
/// with a zero pot -- the same "no pot moved" shape revision 7 has.
#[tokio::test(flavor = "multi_thread")]
async fn no_pot_moves_without_a_first_settled_challenger_win() {
    for (label, state, for_challenger) in [
        ("an executor win", BOND_HELD, false),
        ("a second settle", BOND_PAID, true),
        ("an escrowed pot", BOND_ESCROWED, true),
    ] {
        let mut f = build().await;
        let t = standard(f.ids.remainder, 2_500);
        stage(&mut f, &t, state, None, None, for_challenger).await;
        // The record's own bond always goes to the ruling winner, which is the
        // executor on an executor's win.
        let payee = if for_challenger {
            f.ids.challenger
        } else {
            f.ids.executor
        };
        let before = (
            f.lamports(payee).await,
            f.lamports(f.ids.remainder).await,
            f.lamports(f.ids.challenger).await,
        );
        // With no winner recorded the `policy_winner` meta is the **incinerator**
        // -- the one address the protocol may name -- because this route moves no
        // pot and therefore records no winner.
        let mut metas = f.settle_metas(INCINERATOR, f.ids.remainder);
        metas[2] = AccountMeta::new(payee, false);
        let logs = ok(&mut f, vec![TAG_SETTLE], metas).await;
        // The record's own bond always goes to the **ruling winner** and what is
        // left of the record -- its rent -- is then drained to the **record's
        // challenger**. On a challenger's win the two are the same account, so
        // its delta is the whole record; on an executor's win they are two
        // accounts and each gets one part.
        let payee_delta = 1_000_000
            + if for_challenger {
                rent_exempt(REC_BYTES)
            } else {
                0
            };
        assert_eq!(
            f.lamports(payee).await,
            before.0 + payee_delta,
            "{label}: the record bond, and on a challenger's win the drained record too"
        );
        if !for_challenger {
            assert_eq!(
                f.lamports(f.ids.challenger).await,
                before.2 + rent_exempt(REC_BYTES),
                "{label}: the drained record, and no share of the pot"
            );
        }
        assert_eq!(
            f.lamports(f.ids.remainder).await,
            before.1,
            "{label}: no share of the pot"
        );
        assert_eq!(
            f.lamports(INCINERATOR).await,
            0,
            "{label}: nobody is paid the pot"
        );
        assert_eq!(
            f.data(f.dcm2()).await[529],
            state,
            "{label}: the bond state is unchanged"
        );
        assert_eq!(
            f.data(f.dcm2()).await[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
            [0u8; 32],
            "{label}: and no winner is recorded"
        );
    }
}

/// **A substituted destination is refused, not paid** (582, the code the
/// refusals row names for this route): the `policy_winner` meta must be the
/// recorded winner -- or the incinerator when no winner is recorded -- and the
/// `remainder` meta must be `terms.bond_remainder`. Four refusals, and the pot
/// does not move in any of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_substituted_destination_is_refused_at_the_settle() {
    let mut f = build().await;
    let t = standard(f.ids.remainder, 2_500);
    stage(&mut f, &t, BOND_HELD, None, None, true).await;
    let metas = f.settle_metas(f.ids.impostor, f.ids.remainder);
    assert_eq!(
        settle_refuse(&mut f, metas).await,
        CL_AUTHORITY,
        "an impostor where the recorded winner belongs"
    );
    let metas = f.settle_metas(f.ids.challenger, f.ids.impostor);
    assert_eq!(
        settle_refuse(&mut f, metas).await,
        CL_AUTHORITY,
        "an impostor where the committed remainder belongs"
    );
    // The record's own executor where the ruling winner belongs: revision 7's
    // check, unchanged.
    let mut metas = f.settle_metas(f.ids.challenger, f.ids.remainder);
    metas[2] = AccountMeta::new(f.ids.impostor, false);
    assert_eq!(refuse(&mut f, vec![TAG_SETTLE], metas).await, DCR1_AUTH);
    // Nothing moved and the state is untouched.
    assert_eq!(f.lamports(f.ids.impostor).await, 10_000_000_000);
    assert_eq!(f.lamports(f.ids.remainder).await, 10_000_000_000);
    assert_eq!(f.data(f.dcm2()).await[529], BOND_HELD);
}

/// **A griefing deposit into the escrow address is a gift, not a lock** (spec
/// §1.4's "why the pot field is read at call time"). Anyone can derive the
/// escrow from a public descriptor, so a third party sends it one lamport before
/// the settlement. The retry reads `pot` from the **escrow's balance at call
/// time**, so the pot is the bond plus the gift and the post-check "the escrow
/// ends at zero" stays achievable -- where a route that read the committed bond
/// and then demanded zero would be un-settleable on demand, at a cost of one
/// lamport.
#[tokio::test(flavor = "multi_thread")]
async fn a_deposit_into_the_escrow_address_is_a_gift_and_not_a_lock() {
    let mut f = build().await;
    let t = custom(f.ids.remainder, f.ids.honest);
    // The one-lamport deposit, at the address the program itself derives, before
    // anything else happens. **The fixture lays the account down**; on chain a
    // third party would send it a system transfer.
    stage(&mut f, &t, BOND_HELD, None, Some(1), true).await;
    let metas = f.settle_metas(f.escrow(), SYSTEM);
    settle_ok(&mut f, metas).await;
    let pot = ESCROW_FLOOR + 1;
    assert_eq!(
        f.account(f.escrow()).await.unwrap().lamports,
        pot,
        "the transfer and the gift add"
    );
    let d = f.descriptor();
    let dcr2 = dcr2_v6(
        &d,
        &f.ids.executor,
        &t,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    f.install_result(dcr2, rent_exempt(418));
    let before = (
        f.lamports(f.ids.challenger).await,
        f.lamports(f.ids.remainder).await,
    );
    let metas = f.retry_metas(f.ids.honest, f.ids.challenger, f.ids.remainder);
    retry_ok(&mut f, metas).await;
    let half = pot / 2;
    assert_eq!(f.lamports(f.ids.challenger).await, before.0 + half);
    assert_eq!(f.lamports(f.ids.remainder).await, before.1 + pot - half);
    assert!(
        f.account(f.escrow()).await.is_none(),
        "the escrow is gone: 0 lamports is removed by the runtime"
    );
    assert_eq!(
        events::BODY_V3[events::BOND_RETRY as usize],
        96,
        "the kind-12 body length"
    );
}

/// **Tag 187 pays the pot out, from a DCR2 v6 and from a DCRZ v2** -- the same
/// instruction over the two record versions, which is the whole point of §1.5's
/// "tag 187 reads either": the escrowed pot is reachable before *and* after the
/// retention close, so the wait is forever and not until the next close. The
/// **withheld** case rides along in both: `status = 4`, `cause = 5`, no recorded
/// winner, and therefore the `winner` meta is the incinerator.
#[tokio::test(flavor = "multi_thread")]
async fn the_retry_settles_from_either_record_version() {
    for (label, withheld) in [
        ("a conviction, REFUTED", false),
        ("a withheld attestation, WITHHELD", true),
    ] {
        // The recorded winner is a **funded** account: the settlement program's own
        // credits are the runtime's business, not DCG's credit rule, and the
        // runtime refuses a credit that leaves a new account below its
        // rent-exempt minimum. A policy program pays its destinations from
        // accounts that can hold them; §1.4's credit rule governs DCG's own
        // credits, which is the STANDARD route and the close's drain.
        let status = if withheld {
            result::STATUS_WITHHELD
        } else {
            result::STATUS_REFUTED
        };
        let cause = if withheld {
            bond::CAUSE_WITHHELD
        } else {
            bond::CAUSE_CONVICTION
        };
        // (a) The DCR2 v6, which is what a close leaves behind.
        let mut f = build().await;
        let winner = if withheld { None } else { Some(f.ids.convict) };
        let t = custom(f.ids.remainder, f.ids.honest);
        stage(&mut f, &t, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
        let d = f.descriptor();
        let dcr2 = dcr2_v6(&d, &f.ids.executor, &t, cause, winner, status);
        f.install_result(dcr2, rent_exempt(418));
        let meta_winner = winner.unwrap_or(INCINERATOR);
        let before = (
            f.lamports(meta_winner).await,
            f.lamports(f.ids.remainder).await,
        );
        let metas = f.retry_metas(f.ids.honest, meta_winner, f.ids.remainder);
        retry_ok(&mut f, metas).await;
        let half = ESCROW_FLOOR / 2;
        assert_eq!(f.lamports(meta_winner).await, before.0 + half, "{label}");
        assert_eq!(
            f.lamports(f.ids.remainder).await,
            before.1 + ESCROW_FLOOR - half,
            "{label}"
        );
        assert!(
            f.account(f.escrow()).await.is_none(),
            "{label}: the escrow is gone"
        );
        let after = f.data(f.dcr2()).await;
        assert_eq!(
            after[result::BOND_STATE_AT_V6],
            BOND_NONE,
            "{label}: a settled pot stops being escrowed"
        );

        // (b) The DCRZ v2, after the retention close: the DCR2 is gone and the
        // tombstone carries the settlement block at the same address, so the
        // retry is the same instruction with the same eight metas.
        let mut g = build().await;
        let t2 = custom(g.ids.remainder, g.ids.honest);
        stage(&mut g, &t2, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
        // **This bank's own recorded winner**: a tombstone written with the other
        // bank's key would name an account that does not exist here, and the
        // settlement program's credit to it would leave a new account below its
        // rent-exempt minimum -- which the runtime refuses, and which is the
        // runtime's rule rather than DCG's.
        let recorded = if withheld { None } else { Some(g.ids.convict) };
        let tomb = dcrz_v2(
            &g.descriptor(),
            &g.ids.executor,
            &t2,
            cause,
            recorded,
            status,
        );
        g.install_result(tomb, rent_exempt(result::TOMBSTONE_V2_BYTES));
        let meta_winner = recorded.unwrap_or(INCINERATOR);
        let before = (
            g.lamports(meta_winner).await,
            g.lamports(g.ids.remainder).await,
            g.lamports(g.ids.executor).await,
        );
        let metas = g.retry_metas(g.ids.honest, meta_winner, g.ids.remainder);
        retry_ok(&mut g, metas).await;
        assert_eq!(
            g.lamports(meta_winner).await,
            before.0 + half,
            "{label}: settled from the tombstone"
        );
        assert_eq!(
            g.lamports(g.ids.remainder).await,
            before.1 + ESCROW_FLOOR - half
        );
        assert!(g.account(g.escrow()).await.is_none());
        let shrunk = g.account(g.dcr2()).await.unwrap();
        assert_eq!(
            shrunk.data.len(),
            result::TOMBSTONE_BYTES,
            "{label}: v2 tombstone shrinks to v1"
        );
        assert_eq!(&shrunk.data[..4], b"DCRZ");
        assert_eq!(
            u16::from_le_bytes(shrunk.data[4..6].try_into().unwrap()),
            1,
            "{label}: v1 version"
        );
        assert_eq!(&shrunk.data[6..8], &[0; 2]);
        assert_eq!(
            shrunk.lamports,
            rent_exempt(result::TOMBSTONE_BYTES),
            "{label}: v1 rent floor retained"
        );
        assert_eq!(
            g.lamports(g.ids.executor).await,
            before.2 + rent_exempt(result::TOMBSTONE_V2_BYTES)
                - rent_exempt(result::TOMBSTONE_BYTES),
            "{label}: the executor, who paid the DCR2 rent, receives the freed tombstone rent"
        );
    }
}

/// **A settlement program that fails** (spec §1.4's outcome table). Three real
/// programs, three outcomes: one that **refuses**, so the transaction aborts with
/// the escrow intact and system-owned again and the next attempt free to try
/// again; one that **passes and keeps a lamport**, which is 798; one that
/// **passes and writes the result record**, which is 798 as well. Nothing is
/// stranded in any of them but the one transaction that was going to fail
/// anyway, which is the whole of D12's argument for splitting the settlement out
/// of the close.
#[tokio::test(flavor = "multi_thread")]
async fn a_settlement_program_that_fails_costs_one_transaction_and_nothing_else() {
    // (i) A refusing program: the callee errors, so the transaction aborts --
    // with the callee's own error, not one of ours -- and the escrow keeps every
    // lamport and stays system-owned, because the assignment rolled back too.
    let mut f = build().await;
    let t = custom(f.ids.remainder, f.ids.refuser);
    stage(&mut f, &t, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
    let dcr2 = dcr2_v6(
        &f.descriptor(),
        &f.ids.executor,
        &t,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    f.install_result(dcr2.clone(), rent_exempt(418));
    let metas = f.retry_metas(f.ids.refuser, f.ids.challenger, f.ids.remainder);
    let outcome = send(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], metas).await;
    assert!(
        outcome.is_err(),
        "a refusing program aborts the transaction"
    );
    let escrow = f.account(f.escrow()).await.expect("the escrow survives");
    assert_eq!(
        escrow.lamports, ESCROW_FLOOR,
        "every lamport is still there"
    );
    assert_eq!(
        escrow.owner, SYSTEM,
        "and the assignment rolled back with it"
    );
    assert_eq!(
        f.data(f.dcr2()).await[result::BOND_STATE_AT_V6],
        BOND_ESCROWED,
        "still escrowed"
    );
    assert_eq!(
        f.lamports(f.ids.challenger).await,
        10_000_000_000,
        "nobody was paid"
    );
    assert_eq!(f.lamports(f.ids.remainder).await, 10_000_000_000);
    // **Anyone may call again**, against a program the document's terms name --
    // the program is pinned *by key*, so a document cannot simply be pointed at a
    // different one, and this attempt is a different document's terms.
    let t_ok = custom(f.ids.remainder, f.ids.honest);
    stage(&mut f, &t_ok, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
    let ok_image = dcr2_v6(
        &f.descriptor(),
        &f.ids.executor,
        &t_ok,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    f.install_result(ok_image, rent_exempt(418));
    let metas = f.retry_metas(f.ids.honest, f.ids.challenger, f.ids.remainder);
    retry_ok(&mut f, metas).await;
    assert!(
        f.account(f.escrow()).await.is_none(),
        "the retry that works settles the whole pot"
    );

    // (ii) and (iii): two misbehaving programs, each 798, each rolled back whole.
    // Both were added to this bank, and the terms name the one under test.
    let cases = [
        ("keeps a lamport", f.ids.thief),
        ("takes from a destination", f.ids.greedy),
        ("moves nothing", f.ids.idle),
    ];
    for (label, program) in cases {
        let t2 = custom(f.ids.remainder, program);
        stage(&mut f, &t2, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
        let dcr2 = dcr2_v6(
            &f.descriptor(),
            &f.ids.executor,
            &t2,
            bond::CAUSE_CONVICTION,
            Some(f.ids.challenger),
            result::STATUS_REFUTED,
        );
        f.install_result(dcr2, rent_exempt(418));
        let before = (
            f.lamports(f.ids.challenger).await,
            f.lamports(f.ids.remainder).await,
        );
        let metas = f.retry_metas(program, f.ids.challenger, f.ids.remainder);
        // **Either 798 or the harness's own refusal**: a native callee that
        // debits a destination it does not own is caught by the harness's syscall
        // stub before DCG's post-check runs, and on chain it is DCG's "no other
        // account lost lamports" that catches it. Both are refusals, and neither
        // is a settlement.
        assert!(
            retry(&mut f, metas).await.is_err(),
            "{label}: not a settlement"
        );
        assert_eq!(
            f.account(f.escrow()).await.unwrap().lamports,
            ESCROW_FLOOR,
            "{label}: rolled back"
        );
        assert_eq!(
            f.data(f.dcr2()).await[result::BOND_STATE_AT_V6],
            BOND_ESCROWED,
            "{label}"
        );
        assert_eq!(
            (
                f.lamports(f.ids.challenger).await,
                f.lamports(f.ids.remainder).await
            ),
            before,
            "{label}: and the callee's credits rolled back with it"
        );
    }
}

/// **Every refusal tag 187 has, with its code.** The codes are the ones §1.4's
/// account table and `refusals_v1.tsv` name; the two placements that table does
/// not spell out -- the escrow's **key** and its **lamports** at 599, its
/// writability, ownership and emptiness at 598 -- are the ones `bond.rs`
/// documents and are asserted here so the choice is pinned.
#[tokio::test(flavor = "multi_thread")]
async fn every_retry_refusal() {
    let mut f = build().await;
    let t = custom(f.ids.remainder, f.ids.honest);
    stage(&mut f, &t, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
    let d = f.descriptor();
    let dcr2 = dcr2_v6(
        &d,
        &f.ids.executor,
        &t,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    let install = |f: &mut Fx, image: Vec<u8>| f.install_result(image, rent_exempt(418));
    let good = f.retry_metas(f.ids.honest, f.ids.challenger, f.ids.remainder);
    // The live record is in place before the first assertion, so a refusal below
    // is the one under test and not "there is no result account at all".
    install(&mut f, dcr2.clone());
    // 580: the instruction's own shape. The data is the tag alone and the list
    // is eight metas, and the first meta is a signer.
    let mut no_signer = good.clone();
    no_signer[0] = AccountMeta::new(f.ids.impostor, false);
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], no_signer).await,
        CL_MALFORMED,
        "no signer"
    );
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT, 0], good.clone()).await,
        CL_MALFORMED,
        "one byte of data is not instruction data"
    );
    let mut seven = good.clone();
    seven.pop();
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], seven).await,
        CL_MALFORMED,
        "seven metas"
    );
    let mut ten = good.clone();
    ten.push(AccountMeta::new(f.ids.impostor, false));
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], ten).await,
        CL_MALFORMED,
        "nine metas"
    );
    // 798: the program is pinned **by key**, so a document's program cannot be
    // swapped for another one, and it must be executable, so a *closed* program
    // (its account drained, hence not executable) is refused rather than called.
    let mut wrong_program = good.clone();
    wrong_program[1] = AccountMeta::new_readonly(f.ids.thief, false);
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], wrong_program).await,
        SETTLEMENT_PROGRAM,
        "a program that is not the committed one"
    );
    // 599: the escrow is this document's and it holds lamports.
    let mut wrong_escrow = good.clone();
    wrong_escrow[2] = AccountMeta::new(f.ids.impostor, false);
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], wrong_escrow).await,
        CL_CLOSE,
        "an escrow that is not the document's"
    );
    let mut wrong_read_only_escrow = good.clone();
    wrong_read_only_escrow[2] = AccountMeta::new_readonly(f.ids.impostor, false);
    assert_eq!(
        refuse(
            &mut f,
            vec![TAG_RETRY_BOND_SETTLEMENT],
            wrong_read_only_escrow,
        )
        .await,
        CL_CLOSE,
        "wrong escrow key is refused before its read-only role"
    );
    let second_descriptor = [0xA7; 32];
    let second_escrow = address::bond_escrow(&f.ids.program, &second_descriptor).0;
    f.install_at(second_escrow, system_funded(ESCROW_FLOOR));
    let mut other_document_escrow = good.clone();
    other_document_escrow[2] = AccountMeta::new(second_escrow, false);
    assert_eq!(
        refuse(
            &mut f,
            vec![TAG_RETRY_BOND_SETTLEMENT],
            other_document_escrow
        )
        .await,
        CL_CLOSE,
        "an escrow derived for a different descriptor"
    );
    // A DCG-owned or non-empty escrow at the expected address is a state no
    // caller can make (only DCG signs for the PDA): the escrow validator's
    // unit test (bond::escrow_gate_tests; owner decision 2026-10-02).
    f.install_escrow(0);
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], good.clone()).await,
        CL_CLOSE,
        "an empty escrow: already settled, or never escrowed"
    );
    f.install_escrow(ESCROW_FLOOR);
    // 598: the escrow meta's shape as a writable target.
    let mut read_only = good.clone();
    read_only[2] = AccountMeta::new_readonly(f.escrow(), false);
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], read_only).await,
        SETTLEMENT_PROGRAM,
        "a read-only escrow meta"
    );
    // 582: every destination is committed or derived, so a substitution is a
    // refusal and never a mispayment.
    for (at, what) in [
        (3usize, "the winner"),
        (4, "the remainder"),
        (5, "the executor"),
    ] {
        let mut metas = good.clone();
        metas[at] = AccountMeta::new(f.ids.impostor, false);
        assert_eq!(
            refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], metas).await,
            CL_AUTHORITY,
            "a substituted {what}"
        );
    }
    // The record's non-live and malformed shapes (a paid bond, an unclosed
    // document, a STANDARD document, a revision-7 DCR2 v5, a DCRZ v1, a DCR2 at
    // a non-derived key, cause 0, a withheld record with a winner, tombstone
    // padding) are states only a program bug could write: tag 187's reader
    // unit test (bond::settlement_reader_tests; owner decision 2026-10-02).
    // A DCG-owned 200-byte account elsewhere (for example, a descriptor-upload
    // chunk) cannot impersonate the derived DCRZ v2 address. The old reader
    // accepted this valid-looking tombstone and would have settled the victim's
    // escrow using its descriptor. The derived-address check refuses 580 before
    // the policy CPI, leaving the victim's entire pot untouched.
    let forged_v2 = dcrz_v2(
        &d,
        &f.ids.executor,
        &t,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    assert_eq!(forged_v2.len(), result::TOMBSTONE_V2_BYTES);
    let descriptor_chunk = f.ids.impostor;
    f.install_at(
        descriptor_chunk,
        owned(
            &f.ids.program,
            forged_v2,
            rent_exempt(result::TOMBSTONE_V2_BYTES),
        ),
    );
    let mut forged_metas = good.clone();
    forged_metas[6] = AccountMeta::new(descriptor_chunk, false);
    let victim_escrow_before = f.lamports(f.escrow()).await;
    let victim_winner_before = f.lamports(f.ids.challenger).await;
    let victim_remainder_before = f.lamports(f.ids.remainder).await;
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], forged_metas).await,
        CL_MALFORMED,
        "a forged v2 tombstone at a non-derived address"
    );
    assert_eq!(
        f.lamports(f.escrow()).await,
        victim_escrow_before,
        "the victim's escrow remains untouched"
    );
    assert_eq!(f.lamports(f.ids.challenger).await, victim_winner_before);
    assert_eq!(f.lamports(f.ids.remainder).await, victim_remainder_before);
    // **A closed program**: the committed key with an account that is no longer
    // a program (its account drained, hence not executable). This is the last row
    // of the table because the harness cannot restore a builtin programme's
    // account once it has been replaced, and every row after it would then be
    // answering this one instead.
    let dead = f.ids.honest;
    f.install_at(dead, system_funded(1));
    install(&mut f, dcr2.clone());
    assert_eq!(
        refuse(&mut f, vec![TAG_RETRY_BOND_SETTLEMENT], good.clone()).await,
        SETTLEMENT_PROGRAM,
        "the committed key, but the account is no longer a program"
    );
    // And the positive, which is the round-3 High 1's whole point: **the status
    // byte is not part of the check**, so a `WITHHELD` record is live and the
    // same eight metas settle it.
    let mut g = build().await;
    let t2 = custom(g.ids.remainder, g.ids.honest);
    stage(&mut g, &t2, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
    let withheld = dcr2_v6(
        &g.descriptor(),
        &g.ids.executor,
        &t2,
        bond::CAUSE_WITHHELD,
        None,
        result::STATUS_WITHHELD,
    );
    g.install_result(withheld, rent_exempt(418));
    let metas = g.retry_metas(g.ids.honest, INCINERATOR, g.ids.remainder);
    retry_ok(&mut g, metas).await;
    assert!(
        g.account(g.escrow()).await.is_none(),
        "the withheld pot settled: its pot had an exit"
    );
}

/// **The settle's own refusals, and the terms the decoder refuses**, so the
/// route's codes are pinned where a client meets them: 730 for the
/// instruction's shape, 731 for the list's shape, 733 for a record that is not
/// ruled or a document that cannot cover its own pot, and 791 for the five terms
/// clauses this route depends on.
#[tokio::test(flavor = "multi_thread")]
async fn every_settle_refusal_on_a_revision_eight_document() {
    let mut f = build().await;
    let t = standard(f.ids.remainder, 2_500);
    stage(&mut f, &t, BOND_HELD, None, None, true).await;
    let good = f.settle_metas(f.ids.challenger, f.ids.remainder);
    assert_eq!(
        refuse(&mut f, vec![TAG_SETTLE, 0], good.clone()).await,
        DCR1_BAD,
        "the data is the tag alone"
    );
    let mut eight = good.clone();
    eight.pop();
    assert_eq!(
        refuse(&mut f, vec![TAG_SETTLE], eight).await,
        DCR1_BAD,
        "eight metas"
    );
    let mut eleven = good.clone();
    eleven.push(AccountMeta::new_readonly(SYSTEM, false));
    eleven.push(AccountMeta::new_readonly(SYSTEM, false));
    // **Eleven metas is revision 7's own list length**, so a revision-8 document
    // with eleven metas takes revision 7's body and is refused by *its* checks.
    // The point of the reader split is that this is a refusal and not a
    // mispayment, and the code is the one revision 7 would have given.
    assert!(
        settle_refuse(&mut f, eleven).await != 0,
        "eleven metas on a revision-8 record"
    );
    assert_eq!(f.data(f.dcm2()).await[529], BOND_HELD, "and no pot moved");
    // 731: the list's shape. **The incinerator is in the list on a revision-8
    // settle** -- it receives any uncreditable STANDARD residual, and the list is
    // revision 7's seven plus two -- so a list without it is refused rather than
    // quietly mispaying.
    let mut no_incinerator = good.clone();
    no_incinerator[5] = AccountMeta::new(f.ids.impostor, false);
    assert_eq!(
        refuse(&mut f, vec![TAG_SETTLE], no_incinerator).await,
        DCR1_AUTH
    );
    let wrong_record = f.ids.impostor;
    let forged_record = dcr1_ruled(
        &f.ids.program,
        &f.descriptor(),
        &f.ids.challenger,
        &f.ids.executor,
        1_000_000,
        1,
        true,
    );
    f.install_at(
        wrong_record,
        owned(
            &f.ids.program,
            forged_record,
            rent_exempt(REC_BYTES) + 1_000_000,
        ),
    );
    let mut nonderived_record = good.clone();
    nonderived_record[0] = AccountMeta::new(wrong_record, false);
    nonderived_record[1] = AccountMeta::new(
        dcg_program::closure_v2_response::address(&f.ids.program, &wrong_record).0,
        false,
    );
    assert_eq!(
        settle_refuse(&mut f, nonderived_record).await,
        DCR1_AUTH,
        "a DCR1 record at a non-derived challenge address"
    );
    assert_eq!(
        f.data(f.dcm2()).await[529],
        BOND_HELD,
        "the malformed DCR1 read moved no pot"
    );
    let mut readonly_remainder = good.clone();
    readonly_remainder[8] = AccountMeta::new_readonly(f.ids.remainder, false);
    assert_eq!(
        settle_refuse(&mut f, readonly_remainder).await,
        DCR1_AUTH,
        "STANDARD requires its remainder meta writable (731)"
    );
    assert_eq!(
        f.data(f.dcm2()).await[529],
        BOND_HELD,
        "readonly remainder refusal moved no pot"
    );
    // Under a CUSTOM policy the ninth meta is the system program, and anything
    // else is 731 rather than a CPI to a program the document did not name; and a
    // STANDARD list on a CUSTOM document is caught by the escrow's own key check
    // (599), not by the list's length.
    let mut g = build().await;
    let t2 = custom(g.ids.remainder, g.ids.honest);
    stage(&mut g, &t2, BOND_HELD, None, None, true).await;
    let metas = g.settle_metas(g.escrow(), g.ids.impostor);
    assert_eq!(
        settle_refuse(&mut g, metas).await,
        DCR1_AUTH,
        "the system program meta"
    );
    let metas = g.settle_metas(g.ids.challenger, SYSTEM);
    assert_eq!(settle_refuse(&mut g, metas).await, CL_CLOSE,
        "a STANDARD destination where the escrow belongs: the escrow's own key check, not the list's length");
    let metas = g.settle_metas(g.ids.challenger, g.ids.remainder);
    assert_eq!(
        settle_refuse(&mut g, metas).await,
        DCR1_AUTH,
        "and the ninth meta is not the system program"
    );
    let escrow_key = g.escrow();
    let mut other_escrow = g.settle_metas(escrow_key, SYSTEM);
    let second_descriptor = [0x5C; 32];
    let second_escrow = address::bond_escrow(&g.ids.program, &second_descriptor).0;
    g.install_at(second_escrow, system_funded(ESCROW_FLOOR));
    other_escrow[7] = AccountMeta::new(second_escrow, false);
    assert_eq!(
        settle_refuse(&mut g, other_escrow).await,
        CL_CLOSE,
        "CUSTOM tag 131 refuses a second document's escrow"
    );
    // A DCG-owned or non-empty escrow, and a stale stored escrow bump, are
    // states no caller can make: bond::escrow_gate_tests.
    // 733: the record is not in phase 3.
    let mut h = build().await;
    let t3 = standard(h.ids.remainder, 2_500);
    stage(&mut h, &t3, BOND_HELD, None, None, true).await;
    let mut record = dcr1_ruled(
        &h.ids.program,
        &h.descriptor(),
        &h.ids.challenger,
        &h.ids.executor,
        1_000_000,
        1,
        true,
    );
    record[4] = 1;
    h.install_at(
        h.record(),
        owned(&h.ids.program, record, rent_exempt(REC_BYTES) + 1_000_000),
    );
    let metas = h.settle_metas(h.ids.challenger, h.ids.remainder);
    assert_eq!(
        settle_refuse(&mut h, metas).await,
        DCR1_PHASE,
        "a record in phase 1"
    );
    // 733: the document cannot cover its own pot, which is the one line §1.4's
    // STANDARD step 1 refers to.
    let mut i = build().await;
    let t4 = standard(i.ids.remainder, 2_500);
    let d = i.descriptor();
    let doc = dcm2_v7(&i.ids.program, &d, &i.ids.executor, &t4, 1, BOND_HELD, None);
    i.install_at(
        i.dcm2(),
        owned(&i.ids.program, doc, rent_exempt(dcm2_bytes())),
    );
    let record = dcr1_ruled(
        &i.ids.program,
        &d,
        &i.ids.challenger,
        &i.ids.executor,
        1_000_000,
        1,
        true,
    );
    i.install_at(
        i.record(),
        owned(&i.ids.program, record, rent_exempt(REC_BYTES) + 1_000_000),
    );
    i.install_at(i.response(), system_funded(1));
    let metas = i.settle_metas(i.ids.challenger, i.ids.remainder);
    assert_eq!(
        settle_refuse(&mut i, metas).await,
        DCR1_PHASE,
        "the pot is not there"
    );
    // And the terms: the clauses this route's two branches depend on.
    let mut short = custom(i.ids.remainder, i.ids.honest);
    short.executor_bond_lamports = ESCROW_FLOOR - 1;
    assert_eq!(
        Terms2::decode(&short.encode()),
        Err(DISPUTE_TERMS),
        "check 11: a bond that cannot fund its escrow"
    );
    let mut no_remainder = custom(i.ids.remainder, i.ids.honest);
    no_remainder.bond_remainder = [0; 32];
    assert_eq!(
        Terms2::decode(&no_remainder.encode()),
        Err(DISPUTE_TERMS),
        "check 9: a zero remainder"
    );
    let mut no_policy = standard(i.ids.remainder, 2_500);
    no_policy.bond_policy_kind = 0;
    assert_eq!(
        Terms2::decode(&no_policy.encode()),
        Err(DISPUTE_TERMS),
        "check 7: a policy must exist"
    );
    let mut standard_with_program = standard(i.ids.remainder, 2_500);
    standard_with_program.settlement_program = i.ids.honest.to_bytes();
    assert_eq!(
        Terms2::decode(&standard_with_program.encode()),
        Err(DISPUTE_TERMS),
        "check 10"
    );
    let mut custom_with_share = custom(i.ids.remainder, i.ids.honest);
    custom_with_share.bond_slasher_bps = 1;
    assert_eq!(
        Terms2::decode(&custom_with_share.encode()),
        Err(DISPUTE_TERMS),
        "check 10: kind 2 has no share"
    );
    // And the positive: a STANDARD policy needs no bond floor, which is why the
    // 5,000,001-lamport pot above decodes where a CUSTOM one of the same size
    // would also have to clear the floor.
    let mut floor_free = standard(i.ids.remainder, 10_000);
    floor_free.executor_bond_lamports = 1;
    assert_eq!(
        Terms2::decode(&floor_free.encode()),
        Ok(floor_free),
        "no floor on a STANDARD bond"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revision8_refuses_legacy_timeout_record_before_bad_document() {
    let mut f = build().await;
    let record_key = f.record();
    let dcm2_key = f.dcm2();
    let record = dcr1_ruled(
        &f.ids.program,
        &f.descriptor(),
        &f.ids.challenger,
        &f.ids.executor,
        1_000_000,
        1,
        true,
    );
    f.install_at(
        record_key,
        owned(&f.ids.program, record, rent_exempt(REC_BYTES) + 1_000_000),
    );

    // A revision-7 DCM2 version hint in an invalid system-owned account. The
    // revision-8 image refuses the legacy DCR1 at dispatch and never examines
    // this DCM2 or routes the call to a revision-7 timeout handler.
    let mut malformed_dcm2 = vec![0u8; 6];
    malformed_dcm2[..4].copy_from_slice(b"DCM2");
    malformed_dcm2[4..6].copy_from_slice(&6u16.to_le_bytes());
    f.install_at(
        dcm2_key,
        Account {
            lamports: rent_exempt(malformed_dcm2.len()),
            data: malformed_dcm2,
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        },
    );

    let code = match send(
        &mut f,
        vec![TAG_TIMEOUT],
        vec![
            AccountMeta::new(record_key, false),
            AccountMeta::new(dcm2_key, false),
        ],
    )
    .await
    {
        Err(Fail::Custom(code)) => code,
        other => panic!("expected a revision-8 legacy-record refusal, got {other:?}"),
    };
    assert_eq!(
        code, DCR1_BAD,
        "the legacy DCR1 is refused before reading DCM2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_revision8_image_refuses_marker_zero_dcr1_at_settlement() {
    let mut f = build().await;
    let terms = standard(f.ids.remainder, 2_500);
    stage(&mut f, &terms, BOND_HELD, None, None, true).await;
    let key = f.record();
    let mut record = f.data(key).await;
    assert_eq!(record[147], 1, "the fixture models the revision-8 opener");
    record[147] = 0;
    f.install_at(
        key,
        owned(&f.ids.program, record, rent_exempt(REC_BYTES) + 1_000_000),
    );
    let metas = f.settle_metas(f.ids.challenger, f.ids.remainder);
    assert_eq!(
        settle_refuse(&mut f, metas).await,
        DCR1_AUTH,
        "marker zero belongs to an older program address"
    );
}

/// **One retry, end to end**, with the CU printed. **Measured-local, native.**
/// The honest path's total includes a **native** callee and so is not an SBF
/// figure; the DCG-side cost of a retry that reaches no callee is the refusal
/// rows, which `every_retry_refusal` prints.
#[tokio::test(flavor = "multi_thread")]
async fn a_retry_is_one_instruction() {
    let mut f = build().await;
    let t = custom(f.ids.remainder, f.ids.honest);
    stage(&mut f, &t, BOND_ESCROWED, None, Some(ESCROW_FLOOR), true).await;
    let d = f.descriptor();
    let dcr2 = dcr2_v6(
        &d,
        &f.ids.executor,
        &t,
        bond::CAUSE_CONVICTION,
        Some(f.ids.challenger),
        result::STATUS_REFUTED,
    );
    f.install_result(dcr2, rent_exempt(418));
    let before = f.lamports(f.escrow()).await;
    let metas = f.retry_metas(f.ids.honest, f.ids.challenger, f.ids.remainder);
    retry_ok(&mut f, metas).await;
    eprintln!("RETRY-CU pot={before} record=418 metas=8 mode=native");
    assert!(f.account(f.escrow()).await.is_none());
}
