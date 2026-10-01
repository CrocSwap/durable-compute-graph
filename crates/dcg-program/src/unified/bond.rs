//! Revision 8's **per-document bond escrow** and **tag 187
//! `RetryBondSettlementV5`** (spec `docs/spec/dcg-unified-v8.md` §1.4, §1.9 and
//! D12 of `docs/design/dcg-revision-8-2026-09-25.md`).
//!
//! Three things live here, and they are the whole of the bond's half of
//! revision 8 outside the close:
//!
//! 1. **the escrow** -- one account per document at
//!    `["dcg-hcl-bond-escrow", descriptor]`, system-owned, 0 data bytes, holding
//!    the seized pot and nothing else. Two routes fund it (a CUSTOM
//!    `ChallengeSettleV5` here, a CUSTOM `CloseDocumentV5` in `result.rs`), and
//!    one instruction empties it ([`retry`]). There is no `CloseBondEscrowV5`,
//!    because there is nothing to reclaim and nothing to decide: the escrow
//!    closes when its balance reaches 0 and the runtime removes it.
//! 2. **the policy payout** -- §1.4's STANDARD split with its credit rule
//!    ([`standard_payout`]) and the escrow funding ([`escrow_pot`]), both shared
//!    with the close.
//! 3. **tag 187**, the only caller of the settlement program anywhere in
//!    revision 8.
//!
//! **The split of the work is what makes a refusing program survivable.** On
//! Solana a callee that errors aborts the whole transaction, so a close that
//! had already moved lamports could not "attempt the CPI and catch the error";
//! every inner transfer rolls back with it. D12 therefore splits the two steps:
//! the close (or the settle) moves the pot into the escrow and ends the
//! transaction with **no `invoke` on the settlement program at all**, and the
//! program is called from exactly one instruction whose only work is the
//! settlement. A refusal costs that one transaction, which was going to fail
//! anyway, and the escrow keeps every lamport -- **no fallback and no clock**,
//! because a fallback is a destination DCG chose and a deadline is a forfeiture
//! rule DCG wrote (D10).
//!
//! ```text
//! the 200-byte BSS1 record tag 187 sends (spec §1.9, revision 7's record with
//! two bytes of new meaning and no new byte)
//!   0 magic "BSS1" | 4 version:u16 = 1 | 6 source:u8 (2 challenge, 3 conviction)
//!   7 cause:u8 (4 CAUSE_CONVICTION, 5 CAUSE_WITHHELD)
//!   8 winner[32]   40 loser[32]  72 record[32] (the ESCROW on source 3)
//! 104 result[32]  136 descriptor[32] | 168 pot:u64 | 176 record_bond:u64
//! 184 built_winner:u64 | 192 built_burn:u64 | 200 end
//! ```
//!
//! **`pot` is the escrow's balance at call time, never the committed bond**
//! (§1.4's "why the pot field is read at call time"): anyone can derive the
//! escrow address from a public descriptor and send it a lamport before the
//! close, so a route that moved `terms.executor_bond_lamports` in and then
//! demanded "the escrow ends at zero" would be un-closeable on demand. Reading
//! the balance instead makes a pre-funded escrow a **gift to the next
//! settlement** rather than a lock, and it is what makes the post-check
//! achievable whatever anyone did to the account in between.
//!
//! **Refusal codes.** The spec's §1.4 account table names **798**
//! (`SETTLEMENT_PROGRAM`) for the escrow meta's shape and the post-CPI
//! checks, **599** (`CL_CLOSE`) for "this is not a settlement that can run now",
//! **582** (`CL_AUTHORITY`) for a substituted destination, **580** for a
//! malformed record or instruction. Two placements the spec does not name
//! outright are taken from the codes its table does name and are recorded here
//! rather than invented: the escrow's **key** and its **lamports** are 599
//! (the table's own wording is "the document's escrow ... holding lamports;
//! 599 if it holds none"), and the escrow's writability, system ownership and
//! data-emptiness are 798 (revision 7's `validate_settlement_escrow` already
//! answers exactly that question with that code).

use super::address;
use super::document::{BOND_ESCROWED, BOND_HELD, BOND_NONE, BOND_PAID, WINNER_AT_V8};
use super::events::{self, Body};
use super::result::{
    self, BOND_CAUSE_AT_V6, BOND_STATE_AT_V6, CL_CLOSE, RESULT_TERMS_AT_V6, STATUS_WITHHELD,
    TOMBSTONE_V2_BYTES, TOMBSTONE_V2_CAUSE_AT, TOMBSTONE_V2_PROGRAM_AT, TOMBSTONE_V2_REMAINDER_AT,
    TOMBSTONE_V2_WINNER_AT, WINNER_AT_V6,
};
use super::terms::{self, Terms2, TERMS_BYTES_V2};
use super::{d32, no, CL_AUTHORITY, CL_MALFORMED, CL_OVERFLOW, SETTLEMENT_PROGRAM};
use crate::account_provenance::{
    expect_derived, expect_system_account_shape, AccountKind, RoleFlags,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    incinerator,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

/// BSS1 at `cause = 4` (spec §1.9): revision 7's 200-byte record, `version = 1`.
pub const BSS1_BYTES: usize = 200;
/// Byte 6 keeps its offset and changes its name: revision 7's `ruling` is
/// revision 8's `source`, with one new value.
pub const BSS1_SOURCE_CHALLENGE: u8 = 2;
pub const BSS1_SOURCE_CONVICTION: u8 = 3;
/// The cause vocabulary of §1.9 and of DCR2 409 / the tombstone's 96: the
/// dispute path uses 1..=3, the conviction route 4 and 5.
pub const CAUSE_CONVICTION: u8 = 4;
pub const CAUSE_WITHHELD: u8 = 5;

// ---------------------------------------------------------------- the escrow

/// The document's bond escrow must be this address, writable, system-owned and
/// data-empty. Returns the PDA bump, which is the last seed of the `assign` in
/// [`assign_to_program`]. **The owner check is the load-bearing one:** only an
/// account's owner may debit it, and the escrow is the system program's until
/// tag 187 hands it to the callee.
pub fn validate_escrow(
    program: &Pubkey,
    escrow: &AccountInfo,
    descriptor: &[u8; 32],
) -> Result<u8, ProgramError> {
    let (expected, bump) = address::bond_escrow(program, descriptor);
    if escrow.key != &expected {
        return Err(no(CL_CLOSE));
    }
    expect_system_account_shape(
        escrow,
        RoleFlags {
            writable: true,
            signer: false,
        },
        true,
    )
    .map_err(|_| no(SETTLEMENT_PROGRAM))?;
    Ok(bump)
}

/// Validate a close-time escrow using the bump committed at DCM2 creation.
/// This keeps the close path linear and avoids a variable-cost bump search.
pub fn validate_escrow_with_bump(
    program: &Pubkey,
    escrow: &AccountInfo,
    descriptor: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    let expected =
        Pubkey::create_program_address(&[address::BOND_ESCROW_SEED, descriptor, &[bump]], program)
            .map_err(|_| no(CL_CLOSE))?;
    if escrow.key != &expected {
        return Err(no(CL_CLOSE));
    }
    expect_system_account_shape(
        escrow,
        RoleFlags {
            writable: true,
            signer: false,
        },
        true,
    )
    .map_err(|_| no(SETTLEMENT_PROGRAM))
}

/// **Fund the escrow** (spec §1.4's CUSTOM route step 1): DCG directly debits
/// DCM2 and credits the escrow. There is no CPI because the system program cannot
/// debit a DCG-owned DCM2 account, even when DCG signed for it. The escrow remains
/// **system-owned, 0 data bytes, holding the seized pot**; a pre-funded balance
/// is topped up and becomes a gift to the next settlement rather than a lock.
/// Tag 131 keeps the read-only system-program meta in its fixed list to preserve
/// the account count and position across STANDARD and CUSTOM, and checks the
/// key without invoking the program.
///
/// `amount` is the **whole** `terms.executor_bond_lamports`, not a rent-exempt
/// top-up: check 11 already refuses `0 < bond < minimum_balance(0)` under
/// `kind = 2`, so the pot can fund the account it is escrowed in.
pub fn escrow_pot<'a>(
    from: &AccountInfo<'a>,
    escrow: &AccountInfo<'a>,
    amount: u64,
) -> ProgramResult {
    if !from.is_writable || !escrow.is_writable {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    // **Read first, write second.** The two borrows are of the same `RefCell`, so
    // holding the mutable one across a read of the balance is a panic and not a
    // refusal; every lamport movement in this file is written that way.
    let left = from.lamports().checked_sub(amount).ok_or(no(CL_OVERFLOW))?;
    let right = escrow
        .lamports()
        .checked_add(amount)
        .ok_or(no(CL_OVERFLOW))?;
    **escrow.try_borrow_mut_lamports()? = right;
    **from.try_borrow_mut_lamports()? = left;
    Ok(())
}

/// **Hand the escrow to the callee for the callback** (spec §1.9's "how the
/// callee is allowed to debit the escrow at all"). Only an account's owner may
/// debit it and the callee holds no seeds, so DCG signs for its own PDA and
/// `assign`s the escrow under `["dcg-hcl-bond-escrow", descriptor]` -- the system
/// `assign`, no data, the same shape revision 7's custom settle uses. The
/// assignment happens **inside tag 187's transaction and is rolled back with
/// it**, so a callee that refuses leaves the escrow system-owned and its balance
/// intact, and the next attempt repeats the assignment.
pub fn assign_to_program<'a>(
    descriptor: &[u8; 32],
    settlement_program: &AccountInfo<'a>,
    escrow: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    bump: u8,
) -> ProgramResult {
    invoke_signed(
        &system_instruction::assign(escrow.key, settlement_program.key),
        &[escrow.clone(), system.clone()],
        &[&[address::BOND_ESCROW_SEED, descriptor.as_ref(), &[bump]]],
    )
}

// ---------------------------------------------------------------- the payout

/// **§1.4's STANDARD split on a live document**, with the credit rule, and
/// nothing else: no escrow, no CPI, no clock.
///
/// The pot's presence is discharged by the caller's own rent-plus-bond floor
/// check. `slasher` is `floor(pot · bps / 10,000)` in `u128` and the remainder
/// takes the dust, so `slasher + remainder == pot` in every case; a **skipped**
/// share is **credited to `remainder` rather than left in `from`** (the round-3
/// Low 2), because this route has no drain -- an amount left in the document
/// account would be handed to the convict by the close that eventually comes,
/// which is the transfer the credit rule exists to stop happening. So
/// `winner_payout + remainder_payout ≤ pot`; any still-unpayable residual is
/// credited to the incinerator, never left in DCM2 for a later close to send to
/// the convicted executor.
///
/// The two credits are made **in this order**, and each is tested against its
/// destination's balance as it stands, so an application whose winner and
/// remainder are the same account is handled by construction rather than by a
/// clause. The residual after both credits is burned, and `from` is debited for
/// the full pot.
pub fn standard_payout(
    from: &AccountInfo,
    winner: &AccountInfo,
    remainder: &AccountInfo,
    incinerator: &AccountInfo,
    pot: u64,
    slasher_bps: u16,
    winner_recorded: bool,
) -> Result<(u64, u64, u64), ProgramError> {
    let (slasher, _) = terms::bond_split(pot, slasher_bps, winner_recorded);
    // Each credit is decided on the destination's balance **as it stands** -- and
    // the decision is taken before the borrow, so an account that is both the
    // winner and the remainder is credited against its own first credit.
    let winner_total = terms::credit(winner.lamports(), winner.data_len(), slasher);
    let mut paid_winner = 0u64;
    if let Some(total) = winner_total {
        **winner.try_borrow_mut_lamports()? = total;
        paid_winner = slasher;
    }
    // The skipped share joins the remainder credit, and that credit is itself
    // subject to the rule. Any still-unpaid amount is sent to the incinerator.
    // `rest + (slasher - paid_winner)` is `pot - paid_winner`: with the winner
    // paid it is the remainder share alone, and with the winner skipped it is
    // **the whole pot**, which is what keeps `paid_winner + paid_remainder <=
    // pot` true and the pot conserved.
    let combined = pot.checked_sub(paid_winner).ok_or(no(CL_OVERFLOW))?;
    let remainder_total = terms::credit(remainder.lamports(), remainder.data_len(), combined);
    let mut paid_remainder = 0u64;
    if let Some(total) = remainder_total {
        **remainder.try_borrow_mut_lamports()? = total;
        paid_remainder = combined;
    }
    let paid = paid_winner
        .checked_add(paid_remainder)
        .ok_or(no(CL_OVERFLOW))?;
    let burned = pot.checked_sub(paid).ok_or(no(CL_OVERFLOW))?;
    if burned != 0 {
        let total = incinerator
            .lamports()
            .checked_add(burned)
            .ok_or(no(CL_OVERFLOW))?;
        **incinerator.try_borrow_mut_lamports()? = total;
    }
    let moved = paid.checked_add(burned).ok_or(no(CL_OVERFLOW))?;
    let left = from.lamports().checked_sub(moved).ok_or(no(CL_OVERFLOW))?;
    **from.try_borrow_mut_lamports()? = left;
    Ok((paid_winner, paid_remainder, burned))
}

// ------------------------------------------------- the record tag 187 reads

/// Everything tag 187 needs, read out of **whichever record is there** (spec
/// §1.4's account 6 and §1.5's "tag 187 reads either"): one address, two record
/// versions, and the per-account offsets in the two field tables are the union
/// of the two.
#[derive(Clone, Copy, Debug)]
pub struct Settlement {
    pub descriptor: [u8; 32],
    /// DCR2 136, or the tombstone's 40.
    pub executor: [u8; 32],
    /// The committed policy program, from DCR2's mirrored terms or the
    /// tombstone's 104.
    pub settlement_program: [u8; 32],
    /// The committed remainder destination: DCR2's mirrored terms or the
    /// tombstone's 136.
    pub bond_remainder: [u8; 32],
    /// DCR2 352, or the tombstone's 168. Thirty-two zero bytes when no
    /// challenger was recorded -- a withheld document was never convicted, and a
    /// stop-rule conviction names nobody.
    pub conviction_winner: [u8; 32],
    /// DCR2 409, or the tombstone's 96. 4 or 5, never 0: a record with a live
    /// escrow is one the close or the settle wrote with a cause.
    pub cause: u8,
    /// §1.9's "for reference" fields, built from the term. Check 10 requires
    /// `bond_slasher_bps = 0` under `kind = 2`, so on a record tag 187 can read
    /// they are always `(0, pot)`; they are computed from the field anyway
    /// because that is the expression the goldens pin.
    pub bond_slasher_bps: u16,
    /// True when the record is a **DCRZ v2** tombstone, so the byte to clear on
    /// success is `bond_escrowed` at 7 rather than DCR2's `bond_state` at 408.
    pub tombstone: bool,
}

/// Read the settlement block out of the result account. **599** for anything
/// that is not one of the two live shapes -- a DCR2 v6 with
/// `document_closed = 1` and `bond_state = 4`, or a DCRZ v2 with
/// `bond_escrowed = 1` -- and **580** for a record of one of those shapes whose
/// own fields are malformed.
///
/// **The `status` byte is not part of the test, on either shape** (spec §1.4's
/// "why the status byte is not in account 6's check", round-3 High 1): `4` on a
/// closed result account is already the whole condition and is *stronger* than
/// the status was, because the two routes that write it are the only two that
/// escrow, and a withheld close -- which writes `status = 4 WITHHELD` -- is one
/// of them. The status is recorded for readers; the state byte is enforced.
///
/// **The record is read before every other account is checked**, because it
/// names the descriptor that the escrow's key check and the BSS1 record need.
/// The codes are §1.4's; the order is the program's, and it is the only order
/// that can check anything.
pub fn read_settlement(program: &Pubkey, record: &AccountInfo) -> Result<Settlement, ProgramError> {
    read_settlement_with_hooks(
        program,
        record,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn read_settlement_with_hooks(
    program: &Pubkey,
    record: &AccountInfo,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> Result<Settlement, ProgramError> {
    if record.owner != program || !record.is_writable {
        return Err(no(CL_MALFORMED));
    }
    let head = {
        let raw = record.try_borrow_data()?;
        if raw.len() < 6 {
            return Err(no(CL_CLOSE));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&raw[..4]);
        (magic, u16::from_le_bytes([raw[4], raw[5]]))
    };
    if head.0 != *b"DCR2" || head.1 != result::VERSION_V6 {
        // The tombstone, and only the v2: a v1 is 96 bytes with no settlement
        // block, which is what "a revision-8 image reads version = 1 as
        // 'no settlement block, retry refused 599'" means.
        let raw = record.try_borrow_data()?;
        if head.0 != *b"DCRZ"
            || head.1 != 2
            || raw.len() != result::TOMBSTONE_V2_BYTES
            || raw[7] != 1
            || raw[97..TOMBSTONE_V2_PROGRAM_AT] != [0; 7]
        {
            return Err(no(CL_CLOSE));
        }
        let descriptor = d32(&raw, 8, CL_MALFORMED)?;
        expect_derived(
            record,
            program,
            &[address::RESULT_SEED, &descriptor],
            AccountKind::exact(b"DCRZ", TOMBSTONE_V2_BYTES).with_version(4, 2),
            RoleFlags {
                writable: true,
                signer: false,
            },
        )
        .map_err(|_| no(CL_MALFORMED))?;
        let cause = raw[TOMBSTONE_V2_CAUSE_AT];
        let settlement_program = d32(&raw, TOMBSTONE_V2_PROGRAM_AT, CL_MALFORMED)?;
        let bond_remainder = d32(&raw, TOMBSTONE_V2_REMAINDER_AT, CL_MALFORMED)?;
        let conviction_winner = d32(&raw, TOMBSTONE_V2_WINNER_AT, CL_MALFORMED)?;
        if !matches!(cause, CAUSE_CONVICTION | CAUSE_WITHHELD) {
            return Err(no(CL_MALFORMED));
        }
        // A withheld document names nobody, and a DCRZ v2 always carries a
        // settlement program: both are properties of the record the close wrote.
        if cause == CAUSE_WITHHELD && conviction_winner != [0; 32] {
            return Err(no(CL_MALFORMED));
        }
        // `settlement_program != 0` **is** `kind = 2` (§1.1 check 10), and
        // without it this instruction would be reachable on a STANDARD document
        // where every destination meta is the all-zero key -- the system
        // program, which the runtime will not grant as a writable settlement
        // destination. It is one compare on a field the record already carries.
        if settlement_program == [0; 32] {
            return Err(no(CL_CLOSE));
        }
        return Ok(Settlement {
            descriptor,
            executor: d32(&raw, 40, CL_MALFORMED)?,
            settlement_program,
            bond_remainder,
            conviction_winner,
            cause,
            bond_slasher_bps: 0,
            tombstone: true,
        });
    }
    // A DCR2 v6: every structural check `view_v8` makes, with the status
    // ceiling the close's own fifth value needs.
    let descriptor = {
        let raw = record.try_borrow_data()?;
        d32(&raw, 8, CL_MALFORMED)?
    };
    let v = result::view_v8_status_with_hooks(
        program,
        record,
        &descriptor,
        true,
        STATUS_WITHHELD,
        hooks,
    )?;
    let raw = record.try_borrow_data()?;
    if !v.closed || raw[BOND_STATE_AT_V6] != BOND_ESCROWED {
        return Err(no(CL_CLOSE));
    }
    let terms = Terms2::decode_with(
        &raw[RESULT_TERMS_AT_V6..RESULT_TERMS_AT_V6 + TERMS_BYTES_V2],
        hooks,
    )
    .map_err(no)?;
    if terms.settlement_program == [0; 32] {
        return Err(no(CL_CLOSE));
    }
    let cause = raw[BOND_CAUSE_AT_V6];
    if !matches!(cause, CAUSE_CONVICTION | CAUSE_WITHHELD) {
        return Err(no(CL_MALFORMED));
    }
    let conviction_winner = d32(&raw, WINNER_AT_V6, CL_MALFORMED)?;
    if cause == CAUSE_WITHHELD && conviction_winner != [0; 32] {
        return Err(no(CL_MALFORMED));
    }
    Ok(Settlement {
        descriptor,
        executor: d32(&raw, 136, CL_MALFORMED)?,
        settlement_program: terms.settlement_program,
        bond_remainder: terms.bond_remainder,
        conviction_winner,
        cause,
        bond_slasher_bps: terms.bond_slasher_bps,
        tombstone: false,
    })
}

/// The one byte of the record this instruction owns, and the value it holds
/// while the escrow is live: DCR2's `bond_state` at 408, which the two routes
/// that escrow set to `BOND_ESCROWED` (4), or the tombstone's `bond_escrowed` at
/// 7, which is 1 on a DCRZ v2 by construction. A settled pot must stop being
/// "escrowed", or a DCR2 keeps insisting on a DCRZ v2 tombstone at the retention
/// close and a tombstone already written as v2 keeps extra rent with nothing
/// left to settle (spec §1.4's "why account 6 is writable").
fn live_marker(s: &Settlement) -> (usize, u8) {
    if s.tombstone {
        (7, 1)
    } else {
        (BOND_STATE_AT_V6, BOND_ESCROWED)
    }
}

/// The **200-byte BSS1 record** of §1.9 at `source = 3`, built entirely from
/// committed state and the escrow's balance at call time, so a callee needs no
/// new logic, cannot tell a retry from a first attempt, and cannot be handed a
/// pot that is not there. `record_bond` is 0 on this route: there is no
/// challenge record. `record` is the **escrow** -- the account the pot is
/// escrowed in and the account the callee must empty -- which is why the slot is
/// reused rather than a new field added.
pub fn encode_cause4(
    s: &Settlement,
    escrow: &Pubkey,
    result: &Pubkey,
    pot: u64,
) -> [u8; BSS1_BYTES] {
    let mut out = [0u8; BSS1_BYTES];
    out[..4].copy_from_slice(b"BSS1");
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6] = BSS1_SOURCE_CONVICTION;
    out[7] = s.cause;
    out[8..40].copy_from_slice(&s.conviction_winner);
    out[40..72].copy_from_slice(&s.executor);
    out[72..104].copy_from_slice(escrow.as_ref());
    out[104..136].copy_from_slice(result.as_ref());
    out[136..168].copy_from_slice(&s.descriptor);
    out[168..176].copy_from_slice(&pot.to_le_bytes());
    let (built_winner, _) = terms::executor_bond_split(pot, s.bond_slasher_bps);
    out[184..192].copy_from_slice(&built_winner.to_le_bytes());
    out[192..200].copy_from_slice(&(pot - built_winner).to_le_bytes());
    out
}

// -------------------------------------------------------------- tag 187

/// tag 187 `RetryBondSettlementV5`: **the only caller of the settlement program
/// in revision 8** (spec §1.4). Data: the tag alone. Accounts, eight: any
/// signer, then the seven of the cause-4 BSS1 meta list, of which the result
/// account is writable.
///
/// **Permissionless, and why that is safe:** the pot has exactly one legal exit
/// -- the policy program's own CPI -- and every destination is committed or
/// derived from a public descriptor, so a caller can trigger a settlement but
/// cannot steer one. There is **no deadline**: a deadline is an economic rule (it
/// says when a pot is forfeited) and D10's whole argument is that the protocol
/// does not get to say that. The bond waits; the rent never does, and after the
/// retention deadline the tombstone carries the settlement block, so the wait is
/// until the policy settles; a successful retry also reclaims extra DCRZ v2 rent.
///
/// The three outcomes, from §1.4's table: the program pays the pot out and the
/// escrow ends at 0; the program **refuses**, the transaction aborts, the escrow
/// keeps every lamport and anyone may call again; the program passes and
/// **violates a post-check**, the transaction aborts 798 -- a *misbehaving*
/// program, and the only case the escrow does not survive.
pub fn retry(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    retry_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn retry_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let [signer, settlement_program, escrow, winner, remainder, executor, record_acc, system] =
        accounts
    else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 1 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    // 0. The record, which names the descriptor everything else needs.
    let s = read_settlement_with_hooks(program, record_acc, hooks)?;
    // 1. The escrow: this document's, a writable system-owned 0-byte account,
    //    and holding lamports. **599** if it holds none -- already settled, or
    //    never escrowed -- because "nothing to do" is a refusal and not a no-op
    //    (`outcome = 0` is unassigned and can never be emitted).
    // Validate the committed escrow address before its writable/signer shape;
    // this preserves the baseline public refusal order.
    let bump = validate_escrow(program, escrow, &s.descriptor)?;
    let pot = escrow.lamports();
    if pot == 0 {
        return Err(no(CL_CLOSE));
    }
    // 2. The program is pinned **by key, not by code**, and must be executable:
    //    an upgrade can change what the pot is paid out to within the two
    //    post-checks, and a closed program fails here. The application's trust.
    if settlement_program.key.as_ref() != s.settlement_program.as_slice()
        || !settlement_program.executable
        || *system.key != system_program::ID
    {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    // 3. The two destinations and the loser. Every one is committed or derived,
    //    so a substitution is a refusal and never a mispayment. The winner is
    //    the recorded conviction winner, **or the incinerator when that field is
    //    zero** -- the one address the protocol may name, and a compile-time
    //    constant, so it is not a steering vector (spec §1.9).
    let want_winner = if s.conviction_winner == [0; 32] {
        incinerator::ID.to_bytes()
    } else {
        s.conviction_winner
    };
    if !winner.is_writable
        || winner.key.as_ref() != want_winner.as_slice()
        || !remainder.is_writable
        || remainder.key.as_ref() != s.bond_remainder.as_slice()
        || !executor.is_writable
        || executor.key.as_ref() != s.executor.as_slice()
    {
        return Err(no(CL_AUTHORITY));
    }
    let record = encode_cause4(&s, escrow.key, record_acc.key, pot);
    let (marker_at, marker) = live_marker(&s);
    // 4. Hand the escrow to the callee (it holds no seeds, and only an account's
    //    owner may debit it), then call it with the seven metas. The result
    //    account is passed **read-only**: the one byte this instruction owns is
    //    written afterwards, and a callee that could make the record writable
    //    in a further CPI is exactly what the post-check below is about.
    assign_to_program(&s.descriptor, settlement_program, escrow, system, bump)?;
    let (start_winner, start_remainder, start_executor) =
        (winner.lamports(), remainder.lamports(), executor.lamports());
    let (start_len, start_marker) = (
        record_acc.data_len(),
        record_acc.try_borrow_data()?[marker_at],
    );
    invoke(
        &Instruction::new_with_bytes(
            *settlement_program.key,
            &record,
            vec![
                AccountMeta::new_readonly(*settlement_program.key, false),
                AccountMeta::new(*escrow.key, false),
                AccountMeta::new(*winner.key, false),
                AccountMeta::new(*remainder.key, false),
                AccountMeta::new(*executor.key, false),
                AccountMeta::new_readonly(*record_acc.key, false),
                AccountMeta::new_readonly(*system.key, false),
            ],
        ),
        &[
            settlement_program.clone(),
            escrow.clone(),
            winner.clone(),
            remainder.clone(),
            executor.clone(),
            record_acc.clone(),
            system.clone(),
        ],
    )?;
    // 5. The post-checks: **the escrow ends at zero, no other account lost
    //    lamports, and the result account's only change is the one byte this
    //    instruction owns** -- still the live marker after the CPI, so the
    //    record was not touched at all. The record's *data* is not hashed:
    //    a v6 result may legally hold 10,485,760 bytes, and the callee is given
    //    the account read-only, which on chain is enforced by the loader's
    //    privilege check on any further CPI. What is checked here is the byte
    //    the post-check is about, plus the length, and every lamport.
    let after = record_acc.try_borrow_data()?;
    if escrow.lamports() != 0
        || winner.lamports() < start_winner
        || remainder.lamports() < start_remainder
        || executor.lamports() < start_executor
        || record_acc.data_len() != start_len
        || after.len() <= marker_at
        || after[marker_at] != start_marker
        || start_marker != marker
    {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    drop(after);
    // 6. The pot is settled. A DCR2 only loses its live marker. A DCRZ v2 is
    //    rewritten as the 96-byte v1 prefix and shrunk; every lamport above the
    //    v1 rent floor goes back to its recorded payer.
    if s.tombstone {
        {
            let mut raw = record_acc.try_borrow_mut_data()?;
            raw[4..6].copy_from_slice(&1u16.to_le_bytes());
            raw[6..8].fill(0);
        }
        record_acc.realloc(result::TOMBSTONE_BYTES, true)?;
        let retained = Rent::get()?.minimum_balance(result::TOMBSTONE_BYTES);
        let refund = record_acc
            .lamports()
            .checked_sub(retained)
            .ok_or(no(CL_CLOSE))?;
        let payer_total = executor
            .lamports()
            .checked_add(refund)
            .ok_or(no(CL_OVERFLOW))?;
        **executor.try_borrow_mut_lamports()? = payer_total;
        **record_acc.try_borrow_mut_lamports()? = retained;
    } else {
        record_acc.try_borrow_mut_data()?[marker_at] = BOND_NONE;
    }
    let (winner_payout, remainder_payout) = retry_event_payouts(
        winner.key,
        remainder.key,
        start_winner,
        start_remainder,
        winner.lamports(),
        remainder.lamports(),
    );
    events::emit_v8(
        events::BOND_RETRY,
        &s.descriptor,
        Body::new()
            .key(escrow.key.as_ref())
            .key(&s.conviction_winner)
            .u64(pot)
            .u64(winner_payout)
            .u64(remainder_payout)
            .u8(events::OUTCOME_SETTLED)
            .pad(7),
    );
    Ok(())
}

fn retry_event_payouts(
    winner: &Pubkey,
    remainder: &Pubkey,
    start_winner: u64,
    start_remainder: u64,
    end_winner: u64,
    end_remainder: u64,
) -> (u64, u64) {
    let winner_payout = end_winner.saturating_sub(start_winner);
    let remainder_payout = if winner == remainder {
        0
    } else {
        end_remainder.saturating_sub(start_remainder)
    };
    (winner_payout, remainder_payout)
}

// ------------------------------------------------------ the settle's two routes

/// The route byte of the `settle` event on a revision-8 record. The body is
/// revision 7's 112 bytes and the number is the same numbering: **1** the
/// built-in split, **2** the pot is escrowed for tag 187, **3 unreachable** --
/// revision 8 withdraws the timed fallback that gave it a meaning. What changed
/// is the *meaning* of 2, and DLE1 `version = 3` is the reader split that says
/// so.
pub const ROUTE_STANDARD: u8 = 1;
pub const ROUTE_ESCROWED: u8 = 2;

/// §1.4's write-once `conviction_winner` at a settle (D11). The **first**
/// settled challenger win names its own ruling winner when the field is still
/// zero, so "the person the record names is the person the slasher share goes
/// to" holds on this route as well as the close's -- a document that took a
/// stop-rule conviction first and then had a challenge *win* would otherwise
/// hand the challenge winner's share to the remainder, which is the defect §1.3
/// names. A later settle, and any `RULE`, leave the field alone.
pub fn record_winner_if_unset(doc: &mut [u8], ruling_winner: &[u8; 32]) {
    if doc[WINNER_AT_V8..WINNER_AT_V8 + 32] == [0u8; 32] {
        doc[WINNER_AT_V8..WINNER_AT_V8 + 32].copy_from_slice(ruling_winner);
    }
}

/// Set `executor_bond_state` to 4 (`BOND_ESCROWED`), the only writers of which
/// are the two routes that escrow (spec §1.3's invariant).
pub fn mark_escrowed(doc: &mut [u8]) {
    doc[529] = BOND_ESCROWED;
}

/// Set `executor_bond_state` to 2 (`BOND_PAID`): the STANDARD seizure.
pub fn mark_paid(doc: &mut [u8]) {
    doc[529] = BOND_PAID;
}

/// The record's own byte the two paying routes write, one line each so the
/// meaning is named where it is set.
pub const BOND_STATE_AT_DCM2: usize = 529;

/// The pot exists only on a **first settled challenger win** with the bond still
/// held; anything else moves no pot (spec §1.4's route table, and revision 7's
/// `route == 0`).
pub fn pot_is_live(challenger_won: bool, bond_state: u8) -> bool {
    challenger_won && bond_state == BOND_HELD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(winner: [u8; 32], cause: u8, bps: u16) -> Settlement {
        Settlement {
            descriptor: [1; 32],
            executor: [2; 32],
            settlement_program: [3; 32],
            bond_remainder: [4; 32],
            conviction_winner: winner,
            cause,
            bond_slasher_bps: bps,
            tombstone: false,
        }
    }

    /// The BSS1 record is byte for byte the emitter's `encode_bss1`, and the
    /// `built_winner`/`built_burn` pair is the STANDARD split of the *pot at
    /// call time* with the record's own share.
    #[test]
    fn the_cause4_record_is_the_wire_the_goldens_pin() {
        let result = Pubkey::new_from_array([9; 32]);
        let pot = 5_000_001u64;
        let escrow = Pubkey::new_from_array([8; 32]);
        let out = encode_cause4(&s([7; 32], CAUSE_CONVICTION, 0), &escrow, &result, pot);
        assert_eq!(&out[..4], b"BSS1");
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), 1);
        assert_eq!((out[6], out[7]), (BSS1_SOURCE_CONVICTION, CAUSE_CONVICTION));
        assert_eq!(&out[8..40], &[7u8; 32]);
        assert_eq!(&out[40..72], &[2u8; 32]);
        // `record` is reused for the escrow and `result` is the DCR2 address.
        assert_eq!(&out[72..104], escrow.as_ref());
        assert_eq!(&out[104..136], result.as_ref());
        assert_eq!(&out[136..168], &[1u8; 32]);
        assert_eq!(u64::from_le_bytes(out[168..176].try_into().unwrap()), pot);
        assert_eq!(
            u64::from_le_bytes(out[176..184].try_into().unwrap()),
            0,
            "no record bond"
        );
        assert_eq!(
            u64::from_le_bytes(out[184..192].try_into().unwrap()),
            0,
            "bps = 0 under kind 2"
        );
        assert_eq!(u64::from_le_bytes(out[192..200].try_into().unwrap()), pot);
        // A withheld document names nobody: thirty-two zero bytes, cause 5.
        let withheld = encode_cause4(&s([0; 32], CAUSE_WITHHELD, 0), &escrow, &result, pot);
        assert_eq!(&withheld[8..40], &[0u8; 32]);
        assert_eq!(withheld[7], CAUSE_WITHHELD);
        // The two outcomes of `source`, and nothing else.
        assert_ne!(BSS1_SOURCE_CONVICTION, BSS1_SOURCE_CHALLENGE);
        assert_eq!(BSS1_SOURCE_CHALLENGE, 2);
    }

    /// The credit rule's redirect, as pure arithmetic: a skipped share joins the
    /// remainder, the residual is the subtraction and never a field, and the pot
    /// is conserved either way. `terms::credit` answers `Some(new balance)` when
    /// the credit is executed and `None` when it is **skipped**.
    #[test]
    fn a_skipped_share_goes_to_the_remainder_and_the_residual_is_the_subtraction() {
        let (pot, bps) = (5_000_001u64, 1u16);
        let (slasher, rest) = terms::bond_split(pot, bps, true);
        assert_eq!(
            (slasher, rest),
            (500, 4_999_501),
            "the dust row of split.tsv"
        );
        // An empty winner cannot hold 500 lamports: skipped, and redirected.
        assert_eq!(
            terms::credit(0, 0, slasher),
            None,
            "sub-floor to an empty account"
        );
        // The combined credit is `rest + slasher` = the whole pot, and a pot that
        // size is paid even to an empty destination, so the pot is conserved.
        let combined = pot - 0;
        assert_eq!(
            terms::credit(0, 0, combined),
            Some(5_000_001),
            "the whole pot clears the floor"
        );
        // The bounded residual needs a pot that is itself sub-floor.
        assert_eq!(
            terms::credit(0, 0, 500_000),
            None,
            "an uncreditable amount is burned by STANDARD payout"
        );
        // A share above the floor is always paid, so the grief has a price.
        assert_eq!(
            terms::credit(0, 0, 2_500_000),
            Some(2_500_000),
            "the credit creates the account"
        );
        // Exactly at the floor is a no-op and one lamport under it is a skip.
        assert_eq!(terms::credit(890_880, 0, 0), Some(890_880));
        assert_eq!(
            terms::credit(890_879, 0, 1),
            Some(890_880),
            "the test is on the result"
        );
        // No recorded winner is the whole pot to the remainder (D11).
        assert_eq!(terms::bond_split(pot, bps, false), (0, pot));
    }

    #[test]
    fn retry_event_does_not_count_an_aliased_destination_twice() {
        let same = Pubkey::new_unique();
        assert_eq!(
            retry_event_payouts(&same, &same, 100, 100, 600, 600),
            (500, 0)
        );
        let winner = Pubkey::new_unique();
        let remainder = Pubkey::new_unique();
        assert_eq!(
            retry_event_payouts(&winner, &remainder, 100, 200, 600, 900),
            (500, 700)
        );
    }

    /// The pot is live on exactly one transition, and the marker byte is the
    /// one the record's own version names.
    #[test]
    fn the_pot_is_live_only_on_a_first_settled_challenger_win() {
        assert!(pot_is_live(true, BOND_HELD));
        assert!(
            !pot_is_live(false, BOND_HELD),
            "an executor win moves no pot"
        );
        assert!(
            !pot_is_live(true, BOND_PAID),
            "a second settle moves no pot"
        );
        assert!(
            !pot_is_live(true, BOND_ESCROWED),
            "an escrowed pot moves no pot"
        );
        let mut doc = [0u8; 600];
        assert_eq!(&doc[WINNER_AT_V8..WINNER_AT_V8 + 32], &[0u8; 32]);
        record_winner_if_unset(&mut doc, &[5; 32]);
        assert_eq!(&doc[WINNER_AT_V8..WINNER_AT_V8 + 32], &[5u8; 32]);
        record_winner_if_unset(&mut doc, &[6; 32]);
        assert_eq!(
            &doc[WINNER_AT_V8..WINNER_AT_V8 + 32],
            &[5u8; 32],
            "write-once"
        );
        mark_escrowed(&mut doc);
        assert_eq!(doc[529], BOND_ESCROWED);
        mark_paid(&mut doc);
        assert_eq!(doc[529], BOND_PAID);
    }
}
