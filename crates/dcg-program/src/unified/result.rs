//! DCR2 version 5, the stable result record (spec revision 7, §6.9), and the
//! instructions that write it after UnifiedInit: AttestOutputV5 (177),
//! ResolveResultV5 (178), CloseDocumentV5 (172, §6.12, which starts the
//! retention clock) and CloseResultV6 (185, which writes the DCRZ tombstone).
//!
//! ```text
//!   0 "DCR2" | 4 version:u16 = 5 | 6 status:u8 (0 PENDING, 1 FINAL, 2 REFUTED,
//!     3 SETTLED) | 7 closed:u8 | 8 descriptor[32] | 40 document_root[32]
//!  72 request_id[32] | 104 consumer_digest[32] | 136 executor[32]
//! 168 finalize_slot:u64 | 176 dispute_deadline:u64 | 184 status_slot:u64
//! 192 challenger_wins:u32 | 196 output_count:u32 | 200 output_first_position:u32
//! 204 outputs_attested:u32 | 208 output_width:u8 | 209 zero[7]
//! 216 run_terms[96] (DDT2) | 312 retention_slots:u64 | 320 retention_start_slot:u64
//! 328 retention_deadline:u64 | 336 outputs[count][width] | attested bitmap
//! ```
//!
//! DCRZ (96 bytes): `"DCRZ" | version:u16 = 1 | zero:u16 | descriptor[32] |
//! executor[32] | retention_start_slot:u64 | retention_deadline:u64 |
//! closed_slot:u64`.
//!
//! **Growth (implementation framing).** UnifiedInit creates the record
//! through CPI, which allocates at most 10,240 bytes, funded for its full
//! size. A record above that (about 600 outputs of 16 bytes; a 10,000-token
//! run is 160,264 bytes) is grown toward its full size by AttestOutputV5,
//! at most 10,240 bytes per call; a call that finds the record short only
//! grows it. The spec's one-shot creation assumes the full size (reported).

use super::address;
use super::bond;
pub use super::bond::{CAUSE_CONVICTION, CAUSE_WITHHELD};
use super::document::{
    self, Binding2, ABANDON_DEADLINE_AT, BINDING_AT, BINDING_AT_V8, BINDING_BYTES_V8,
    BOND_ESCROWED, BOND_HELD, BOND_PAID, BOND_RETURNED, FLAG_FINAL, FLAG_REFUTED, TERMS_AT,
    TERMS_AT_V8,
};
use super::events::{self, Body};
use super::terms::{Terms, Terms2, TERMS_BYTES, TERMS_BYTES_V2};
use super::{
    d32, no, plan, u16_at, u32_at, u64_at, CL_COORDINATE, CL_MALFORMED, CL_MISSING, CL_OVERFLOW,
    DCR1_PHASE, PLAN_BINDING,
};
use crate::account_provenance::{expect_derived, expect_derived_with_bump, AccountKind, RoleFlags};
use crate::closure_v2::{self as h, Coordinate};
use crate::hash;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, incinerator,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent, system_program, sysvar::Sysvar,
};

pub const VERSION: u16 = 5;
pub const HEADER: usize = 336;
pub const RESULT_TERMS_AT: usize = 216;
pub const RETENTION_SLOTS_AT: usize = 312;
pub const RETENTION_START_AT: usize = 320;
pub const RETENTION_DEADLINE_AT: usize = 328;

/// **Revision 8's** DCR2 v6 (spec §1.5): a 416-byte header whose bytes
/// `0..216` keep their meaning, so a consumer reading the old layout sees the
/// same fields.
pub const VERSION_V6: u16 = 6;
pub const HEADER_V6: usize = 416;
pub const RESULT_TERMS_AT_V6: usize = 216;
pub const POSITION_LENGTH_AT_V6: usize = 212;
pub const WINNER_AT_V6: usize = 352;
pub const RETENTION_SLOTS_AT_V6: usize = 384;
pub const RETENTION_START_AT_V6: usize = 392;
pub const RETENTION_DEADLINE_AT_V6: usize = 400;
pub const BOND_STATE_AT_V6: usize = 408;
pub const BOND_CAUSE_AT_V6: usize = 409;
/// DCR2 v6 stores its canonical result-PDA bump here for the revision-8 close.
pub const RESULT_PDA_BUMP_AT_V6: usize = 410;
pub const TOMBSTONE_BYTES: usize = 96;
/// **DCRZ v2**, the 200-byte tombstone a revision-8 close writes while a bond is
/// still escrowed (spec §1.5). The three settlement fields at 104/136/168 are
/// what keeps tag 187 able to settle the pot after the retention deadline, and
/// the cause rides in v1's padding at 96, so the tombstone is 200 and not 208.
pub const TOMBSTONE_V2_BYTES: usize = 200;
pub const TOMBSTONE_V2_CAUSE_AT: usize = 96;
pub const TOMBSTONE_V2_PROGRAM_AT: usize = 104;
pub const TOMBSTONE_V2_REMAINDER_AT: usize = 136;
pub const TOMBSTONE_V2_WINNER_AT: usize = 168;
pub const STATUS_PENDING: u8 = 0;
pub const STATUS_FINAL: u8 = 1;
pub const STATUS_REFUTED: u8 = 2;
pub const STATUS_SETTLED: u8 = 3;
/// **`WITHHELD`**, revision 8's fifth status (spec §1.3's vocabulary, §1.5's
/// byte 6). Written by the close's **row 3 only** — finalized, flag 4 clear and
/// `outputs_attested < L` — and it is what makes "SETTLED means the document met
/// the FINAL condition" true again: a never-attested document is never recorded
/// as SETTLED. **4 is a free value** and the coincidence with
/// `BOND_ESCROWED` is harmless (different field, different record, each named in
/// its own table).
pub const STATUS_WITHHELD: u8 = 4;
/// The policy did not run and the bond had no conviction or withheld cause.
pub const CAUSE_NONE: u8 = 0;
/// **The `bond_disposition` enumeration of §1.8**: what happened to the pot, as
/// a renumbering of `executor_bond_state`'s non-zero values. The event byte and
/// the state byte are the same fact read twice, and the pair
/// (`disposition`, `cause`) is the whole of the close's economics in two bytes.
pub const DISPOSITION_NONE: u8 = 0;
pub const DISPOSITION_RETURNED: u8 = 1;
pub const DISPOSITION_SPLIT: u8 = 2;
pub const DISPOSITION_ESCROWED: u8 = 3;
pub const MAX_WIDTH: u8 = 32;
pub const MAX_ACCOUNT: usize = 10_485_760;
pub const OUTPUT_PROOF: u32 = 795;
pub const RESULT_STATE: u32 = 796;
pub const CL_CLOSE: u32 = 599;
pub const TAG_ATTEST_OUTPUT: u8 = 177;
pub const TAG_RESOLVE_RESULT: u8 = 178;
const CPI_ALLOC: usize = 10_240;
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";
/// The leaf-preimage prefix the handler derives (domain, descriptor, coordinate).
const LEAF_TAIL_AT: usize = 69;
const LEAF_WRITE_COUNT_AT: usize = 143;
const LEAF_WRITES_AT: usize = 147;

/// Full size of a revision-7 record with `count` outputs of `width` bytes.
pub fn bytes(count: u32, width: u8) -> Option<usize> {
    (count as usize)
        .checked_mul(width as usize)?
        .checked_add(HEADER)?
        .checked_add((count as usize).div_ceil(8))
        .filter(|&n| n <= MAX_ACCOUNT)
}

/// Full size of a revision-8 record: `416 + count*width + ceil(count/8)`,
/// which spec §1.5 bounds at 10,485,760 bytes and UnifiedInit checks at 794
/// through this function.
pub fn bytes_v8(count: u32, width: u8) -> Option<usize> {
    (count as usize)
        .checked_mul(width as usize)?
        .checked_add(HEADER_V6)?
        .checked_add((count as usize).div_ceil(8))
        .filter(|&n| n <= MAX_ACCOUNT)
}

/// Header facts of a DCR2 v4 at the descriptor's PDA (580 otherwise).
#[derive(Clone, Copy, Debug)]
pub struct View {
    pub status: u8,
    pub closed: bool,
    pub count: u32,
    pub width: u8,
    pub first: u32,
    pub attested: u32,
    pub full: usize,
}

pub fn view(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
) -> Result<View, ProgramError> {
    expect_derived(
        account,
        program,
        &[address::RESULT_SEED, descriptor],
        AccountKind::variable(b"DCR2", HEADER, MAX_ACCOUNT).with_version(4, VERSION),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| no(CL_MALFORMED))?;
    let raw = account.try_borrow_data()?;
    if account.owner != program
        || (writable && !account.is_writable)
        || raw.len() < HEADER
        || raw[..4] != *b"DCR2"
        || u16_at(&raw, 4, CL_MALFORMED)? != VERSION
        || raw[6] > STATUS_SETTLED
        || raw[7] > 1
        || raw[8..40] != *descriptor
        || raw[209..216] != [0; 7]
    {
        return Err(no(CL_MALFORMED));
    }
    let (count, width) = (u32_at(&raw, 196, CL_MALFORMED)?, raw[208]);
    let full = bytes(count, width).ok_or(no(CL_MALFORMED))?;
    if raw.len() > full || !(1..=MAX_WIDTH).contains(&width) {
        return Err(no(CL_MALFORMED));
    }
    let terms = Terms::decode(&raw[RESULT_TERMS_AT..RESULT_TERMS_AT + TERMS_BYTES]).map_err(no)?;
    let retention = u64_at(&raw, RETENTION_SLOTS_AT, CL_MALFORMED)?;
    let start = u64_at(&raw, RETENTION_START_AT, CL_MALFORMED)?;
    let deadline = u64_at(&raw, RETENTION_DEADLINE_AT, CL_MALFORMED)?;
    if retention != terms.result_retention_slots
        || (start == 0) != (deadline == 0)
        || (start != 0 && deadline != start.checked_add(retention).ok_or(no(CL_OVERFLOW))?)
    {
        return Err(no(CL_MALFORMED));
    }
    Ok(View {
        status: raw[6],
        closed: raw[7] == 1,
        count,
        width,
        first: u32_at(&raw, 200, CL_MALFORMED)?,
        attested: u32_at(&raw, 204, CL_MALFORMED)?,
        full,
    })
}

/// The same header facts of a **DCR2 v6** (spec §1.5), 580 otherwise. Every
/// field before 209 keeps its offset, so the returned `View` is the same
/// shape; only the zero run, the terms mirror, the retention clock and the
/// account size move.
///
/// The status ceiling is `SETTLED`, so a `WITHHELD` record is refused here: the
/// only writer of status 4 is `CloseDocumentV5` on row 3, and the handlers that
/// call this one have no use for a closed-and-withheld record. Tag 187 does --
/// an escrowed pot is live on **both** CUSTOM routes and a withheld close is one
/// of them -- so it calls [`view_v8_status`] with [`STATUS_WITHHELD`].
pub fn view_v8(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
) -> Result<View, ProgramError> {
    view_v8_status(program, account, descriptor, writable, STATUS_SETTLED)
}

/// [`view_v8`] with the caller's own status ceiling. `max_status` is the
/// highest `status` byte the caller can reason about; every other check is
/// identical, so this is one parameter and not a second reader.
pub fn view_v8_status(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
    max_status: u8,
) -> Result<View, ProgramError> {
    let bump = stored_result_bump(account)?;
    view_v8_status_inner(
        program,
        account,
        descriptor,
        writable,
        max_status,
        Some(bump),
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn view_v8_status_with_hooks(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
    max_status: u8,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> Result<View, ProgramError> {
    let bump = stored_result_bump(account)?;
    view_v8_status_inner(
        program,
        account,
        descriptor,
        writable,
        max_status,
        Some(bump),
        hooks,
    )
}

fn stored_result_bump(account: &AccountInfo) -> Result<u8, ProgramError> {
    let data = account.try_borrow_data().map_err(|_| no(CL_MALFORMED))?;
    data.get(RESULT_PDA_BUMP_AT_V6)
        .copied()
        .ok_or(no(CL_MALFORMED))
}

/// Revision-8 readers check the DCR2 PDA using the bump stored at creation.
pub fn view_v8_status_with_bump(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
    max_status: u8,
    bump: u8,
) -> Result<View, ProgramError> {
    view_v8_status_inner(
        program,
        account,
        descriptor,
        writable,
        max_status,
        Some(bump),
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn view_v8_status_with_bump_and_hooks(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
    max_status: u8,
    bump: u8,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> Result<View, ProgramError> {
    view_v8_status_inner(
        program,
        account,
        descriptor,
        writable,
        max_status,
        Some(bump),
        hooks,
    )
}

fn view_v8_status_inner(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    writable: bool,
    max_status: u8,
    bump: Option<u8>,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> Result<View, ProgramError> {
    let mut kind =
        AccountKind::variable(b"DCR2", HEADER_V6, MAX_ACCOUNT).with_version(4, VERSION_V6);
    if bump.is_some() {
        kind = kind.with_bump(RESULT_PDA_BUMP_AT_V6);
    }
    let role = RoleFlags {
        writable,
        signer: false,
    };
    if let Some(bump) = bump {
        expect_derived_with_bump(
            account,
            program,
            &[address::RESULT_SEED, descriptor],
            bump,
            kind,
            role,
        )
        .map(|_| ())
    } else {
        expect_derived(
            account,
            program,
            &[address::RESULT_SEED, descriptor],
            kind,
            role,
        )
        .map(|_| ())
    }
    .map_err(|_| no(CL_MALFORMED))?;
    let raw = account.try_borrow_data()?;
    if account.owner != program
        || (writable && !account.is_writable)
        || raw.len() < HEADER_V6
        || raw[..4] != *b"DCR2"
        || u16_at(&raw, 4, CL_MALFORMED)? != VERSION_V6
        || raw[6] > max_status
        || raw[7] > 1
        || raw[8..40] != *descriptor
        || raw[209..212] != [0; 3]
        || raw[411..416] != [0; 5]
    {
        return Err(no(CL_MALFORMED));
    }
    let (count, width) = (u32_at(&raw, 196, CL_MALFORMED)?, raw[208]);
    let full = bytes_v8(count, width).ok_or(no(CL_MALFORMED))?;
    if raw.len() > full || !(1..=MAX_WIDTH).contains(&width) {
        return Err(no(CL_MALFORMED));
    }
    let terms = Terms2::decode_with(
        &raw[RESULT_TERMS_AT_V6..RESULT_TERMS_AT_V6 + TERMS_BYTES_V2],
        hooks,
    )
    .map_err(no)?;
    let retention = u64_at(&raw, RETENTION_SLOTS_AT_V6, CL_MALFORMED)?;
    let start = u64_at(&raw, RETENTION_START_AT_V6, CL_MALFORMED)?;
    let deadline = u64_at(&raw, RETENTION_DEADLINE_AT_V6, CL_MALFORMED)?;
    if retention != terms.result_retention_slots
        || (start == 0) != (deadline == 0)
        || (start != 0 && deadline != start.checked_add(retention).ok_or(no(CL_OVERFLOW))?)
    {
        return Err(no(CL_MALFORMED));
    }
    Ok(View {
        status: raw[6],
        closed: raw[7] == 1,
        count,
        width,
        first: u32_at(&raw, 200, CL_MALFORMED)?,
        attested: u32_at(&raw, 204, CL_MALFORMED)?,
        full,
    })
}

/// UnifiedInit step 9: create the PENDING record from DCM2's DDT1 and DRB1.
pub fn create<'a>(
    program: &Pubkey,
    executor: &AccountInfo<'a>,
    dcr2: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    descriptor: &[u8; 32],
    terms: &[u8],
    binding: &document::Binding,
) -> ProgramResult {
    let full = bytes(binding.output_count, binding.output_width).ok_or(no(super::RUN_BINDING))?;
    let (key, bump) = address::result(program, descriptor);
    if *dcr2.key != key {
        return Err(no(CL_MALFORMED));
    }
    super::registry::create_pda(
        program,
        executor,
        dcr2,
        system,
        &[address::RESULT_SEED, descriptor],
        bump,
        full.min(CPI_ALLOC),
        full,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    let mut raw = dcr2.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DCR2");
    raw[4..6].copy_from_slice(&VERSION.to_le_bytes());
    raw[8..40].copy_from_slice(descriptor);
    raw[72..104].copy_from_slice(&binding.request_id);
    raw[104..136].copy_from_slice(&binding.consumer_digest);
    raw[136..168].copy_from_slice(&binding.executor);
    raw[196..200].copy_from_slice(&binding.output_count.to_le_bytes());
    raw[200..204].copy_from_slice(&binding.output_first_position.to_le_bytes());
    raw[208] = binding.output_width;
    raw[RESULT_TERMS_AT..RESULT_TERMS_AT + TERMS_BYTES].copy_from_slice(terms);
    let decoded = Terms::decode(terms).map_err(no)?;
    raw[RETENTION_SLOTS_AT..RETENTION_SLOTS_AT + 8]
        .copy_from_slice(&decoded.result_retention_slots.to_le_bytes());
    Ok(())
}

/// UnifiedInit step 9 for revision 8: the PENDING DCR2 v6, whose first 216
/// bytes carry the same fields as revision 7's, from the DDT2 v2 and the
/// DRB1 v2. `position_length` (212) stays 0 until finalize, which writes it.
pub fn create_v8<'a>(
    program: &Pubkey,
    executor: &AccountInfo<'a>,
    dcr2: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    descriptor: &[u8; 32],
    terms: &[u8],
    binding: &Binding2,
) -> ProgramResult {
    create_v8_with_hooks(
        program,
        executor,
        dcr2,
        system,
        descriptor,
        terms,
        binding,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn create_v8_with_hooks<'a>(
    program: &Pubkey,
    executor: &AccountInfo<'a>,
    dcr2: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    descriptor: &[u8; 32],
    terms: &[u8],
    binding: &Binding2,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let full =
        bytes_v8(binding.output_count, binding.output_width).ok_or(no(super::RUN_BINDING))?;
    let (key, bump) = address::result(program, descriptor);
    if *dcr2.key != key {
        return Err(no(CL_MALFORMED));
    }
    super::registry::create_pda(
        program,
        executor,
        dcr2,
        system,
        &[address::RESULT_SEED, descriptor],
        bump,
        full.min(CPI_ALLOC),
        full,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    let mut raw = dcr2.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DCR2");
    raw[4..6].copy_from_slice(&VERSION_V6.to_le_bytes());
    raw[8..40].copy_from_slice(descriptor);
    raw[72..104].copy_from_slice(&binding.request_id);
    raw[104..136].copy_from_slice(&binding.consumer_digest);
    raw[136..168].copy_from_slice(&binding.executor);
    raw[196..200].copy_from_slice(&binding.output_count.to_le_bytes());
    raw[200..204].copy_from_slice(&binding.output_first_position.to_le_bytes());
    raw[208] = binding.output_width;
    raw[RESULT_TERMS_AT_V6..RESULT_TERMS_AT_V6 + TERMS_BYTES_V2].copy_from_slice(terms);
    let decoded = Terms2::decode_with(terms, hooks).map_err(no)?;
    raw[RETENTION_SLOTS_AT_V6..RETENTION_SLOTS_AT_V6 + 8]
        .copy_from_slice(&decoded.result_retention_slots.to_le_bytes());
    raw[RESULT_PDA_BUMP_AT_V6] = bump.value();
    Ok(())
}

fn now() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

/// FinalizeDocumentV5's result checks (spec §6.6, 580): PENDING, not closed,
/// and every field it copies from DCM2 equal.
pub fn check_for_finalize(
    program: &Pubkey,
    dcr2: &AccountInfo,
    doc: &[u8],
    descriptor: &[u8; 32],
) -> ProgramResult {
    let v = view(program, dcr2, descriptor, true)?;
    let raw = dcr2.try_borrow_data()?;
    let b = &doc[BINDING_AT..BINDING_AT + document::BINDING_BYTES];
    if v.status != STATUS_PENDING
        || v.closed
        || raw[136..168] != doc[40..72]
        || raw[72..104] != b[40..72]
        || raw[104..136] != b[72..104]
        || raw[200..204] != b[136..140]
        || raw[196..200] != b[140..144]
        || raw[208] != b[149]
        || raw[RESULT_TERMS_AT..RESULT_TERMS_AT + TERMS_BYTES]
            != doc[TERMS_AT..TERMS_AT + TERMS_BYTES]
    {
        return Err(no(CL_MALFORMED));
    }
    Ok(())
}

/// The same checks for a DCR2 v6 against a DCM2 v7, with the same byte
/// comparisons at the same offsets (the first 216 bytes of the header are
/// unchanged) and the widened terms mirror.
pub fn check_for_finalize_v8(
    program: &Pubkey,
    dcr2: &AccountInfo,
    doc: &[u8],
    descriptor: &[u8; 32],
    b: &Binding2,
) -> ProgramResult {
    check_for_finalize_v8_with_hooks(
        program,
        dcr2,
        doc,
        descriptor,
        b,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn check_for_finalize_v8_with_hooks(
    program: &Pubkey,
    dcr2: &AccountInfo,
    doc: &[u8],
    descriptor: &[u8; 32],
    b: &Binding2,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let v = view_v8_status_with_hooks(program, dcr2, descriptor, true, STATUS_SETTLED, hooks)?;
    let raw = dcr2.try_borrow_data()?;
    if v.status != STATUS_PENDING
        || v.closed
        || raw[136..168] != doc[40..72]
        || raw[72..104] != b.request_id
        || raw[104..136] != b.consumer_digest
        || raw[200..204] != b.output_first_position.to_le_bytes()
        || raw[196..200] != b.output_count.to_le_bytes()
        || raw[208] != b.output_width
        || raw[RESULT_TERMS_AT_V6..RESULT_TERMS_AT_V6 + TERMS_BYTES_V2]
            != doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]
    {
        return Err(no(CL_MALFORMED));
    }
    Ok(())
}

/// tag 177 AttestOutputV5 (permissionless): `descriptor[32] | index:u32 |
/// value[w] | tail_len:u16 | leaf_tail | height:u8 | sibling[height][32] |
/// SPP1`. Accounts: signer (s), DCM2, DPR2, DCR2 (w), PT2S, base routes,
/// base geometry. Proves output `index` against the landed DPR2 root of its
/// position at the coordinate the handler derives from the PT2S.
///
/// The reader split is the DCM2 version (spec §0), and revision 8 adds the
/// three things §1.6 names: **attest after finalize** (flag 2 clear is 591),
/// the two-case `L` at the index test (also 591), and the decision locator
/// (output `i` is write `output_write + i` at position `output_first_position`
/// under `decision_flags` bit 0).
pub fn attest(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        attest_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        attest_v8(program, accounts, data)
    }
}

pub fn attest_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = hooks;
        attest_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        attest_v8_with_hooks(program, accounts, data, hooks)
    }
}

/// tag 177 AttestOutputV5 (revision 7).
#[cfg(feature = "revision-7")]
pub fn attest_v7(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [signer, dcm2, dpr2, dcr2, pt2s, routes, geometry] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() < 37 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    let index = u32_at(data, 33, CL_MALFORMED)?;
    document::document(program, dcm2, Some(&descriptor), false, CL_MALFORMED)?;
    let v = view(program, dcr2, &descriptor, true)?;
    // 1. Exact parse at the document's width.
    let w = v.width as usize;
    let value = data.get(37..37 + w).ok_or(no(CL_MALFORMED))?;
    let tail_len = u16_at(data, 37 + w, CL_MALFORMED)? as usize;
    let tail_at = 39 + w;
    let tail = data
        .get(tail_at..tail_at + tail_len)
        .ok_or(no(CL_MALFORMED))?;
    let height = *data.get(tail_at + tail_len).ok_or(no(CL_MALFORMED))? as usize;
    let path_at = tail_at + tail_len + 1;
    let path_bytes = data
        .get(path_at..path_at + 32 * height)
        .ok_or(no(CL_MALFORMED))?;
    let spp1_at = path_at + 32 * height;
    let (ordinal, table, spp1_path, used) =
        super::challenge::decode_spp1(data.get(spp1_at..).ok_or(no(CL_MALFORMED))?)
            .map_err(|_| no(CL_MALFORMED))?;
    if spp1_at + used != data.len() {
        return Err(no(CL_MALFORMED));
    }
    if v.full > dcr2.data_len() {
        // Growth toward the full size (module doc); nothing else changes.
        let next = v.full.min(dcr2.data_len() + CPI_ALLOC);
        dcr2.realloc(next, true)?;
        return Ok(());
    }
    let doc = dcm2.try_borrow_data()?;
    let p_count = u32_at(&doc, 72, CL_MALFORMED)?;
    document::positions(program, dpr2, &descriptor, p_count, false, CL_MALFORMED)?;
    if pt2s.key.as_ref() != &doc[200..232]
        || hash::sha256(&[&pt2s.try_borrow_data()?]) != doc[232..264]
    {
        return Err(no(PLAN_BINDING));
    }
    plan::bind_pt2s(program, pt2s, routes, geometry, None)?;
    // 2-3. Index, repeat, landed position.
    if index >= v.count {
        return Err(no(CL_COORDINATE));
    }
    let (bitmap_at, bit) = (
        HEADER + v.count as usize * w + index as usize / 8,
        1u8 << (index % 8),
    );
    if v.closed || dcr2.try_borrow_data()?[bitmap_at] & bit != 0 {
        return Err(no(OUTPUT_PROOF));
    }
    let p = v.first.checked_add(index).ok_or(no(CL_OVERFLOW))?;
    if p >= u32_at(&doc, 84, CL_MALFORMED)? {
        return Err(no(CL_MISSING));
    }
    // 4. The coordinate and write route from the PT2S.
    let b = document::Binding::decode(&doc[BINDING_AT..BINDING_AT + document::BINDING_BYTES])
        .map_err(no)?;
    let (segment, local, entries, seg_ordinal, segments, table_root, region, offset, length) = {
        let s = pt2s.try_borrow_data()?;
        let (rb, gb) = (routes.try_borrow_data()?, geometry.try_borrow_data()?);
        let x = plan::view(&s, &rb, &gb, &[], None)?;
        let t = x
            .old_to_new(b.output_base_entry, p)
            .map_err(|_| no(OUTPUT_PROOF))?
            .ok_or(no(OUTPUT_PROOF))?;
        let e = x.entry(p, t).map_err(|_| no(OUTPUT_PROOF))?;
        let route = x
            .route(&e, e.read_count + b.output_write as u16)
            .map_err(|_| no(OUTPUT_PROOF))?;
        let c = x.coordinate(p, t).map_err(|_| no(OUTPUT_PROOF))?;
        let mut found = None;
        for s_ord in 0..x.segment_count as usize {
            let (id, n) = x.segment_row(p, s_ord).map_err(|_| no(OUTPUT_PROOF))?;
            if id == c.segment {
                found = Some((s_ord as u16, n));
            }
        }
        let (so, n) = found.ok_or(no(OUTPUT_PROOF))?;
        (
            c.segment,
            c.local,
            n,
            so,
            x.segment_count,
            x.segment_table_root(p).map_err(|_| no(OUTPUT_PROOF))?,
            route.region_id,
            route.effective_offset,
            route.byte_length,
        )
    };
    if length as usize != w {
        return Err(no(OUTPUT_PROOF));
    }
    // 5. The leaf preimage holds the output's write row.
    let mut leaf = Vec::with_capacity(LEAF_TAIL_AT + tail.len());
    leaf.extend_from_slice(LEAF_DOMAIN);
    leaf.extend_from_slice(&descriptor);
    leaf.extend_from_slice(&p.to_le_bytes());
    leaf.extend_from_slice(&segment.to_le_bytes());
    leaf.extend_from_slice(&local.to_le_bytes());
    leaf.extend_from_slice(tail);
    if leaf.len() < LEAF_WRITES_AT || leaf[LEAF_WRITE_COUNT_AT + 2..LEAF_WRITES_AT] != [0; 2] {
        return Err(no(OUTPUT_PROOF));
    }
    let writes =
        u16::from_le_bytes([leaf[LEAF_WRITE_COUNT_AT], leaf[LEAF_WRITE_COUNT_AT + 1]]) as usize;
    if leaf.len() != LEAF_WRITES_AT + 48 * writes {
        return Err(no(OUTPUT_PROOF));
    }
    let coordinate = Coordinate {
        position: p,
        segment,
        entry: local,
    };
    let digest = h::write_digest(&descriptor, coordinate, region, offset, value)?;
    let mut row = [0u8; 48];
    row[0..2].copy_from_slice(&region.to_le_bytes());
    row[4..8].copy_from_slice(&length.to_le_bytes());
    row[8..16].copy_from_slice(&offset.to_le_bytes());
    row[16..48].copy_from_slice(&digest);
    if !leaf[LEAF_WRITES_AT..].chunks_exact(48).any(|r| r == row) {
        return Err(no(OUTPUT_PROOF));
    }
    // 6. Leaf path to the segment root, SPP1 to the landed position root.
    let path: Vec<[u8; 32]> = path_bytes
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let tree = super::challenge::dl_fold(
        &descriptor,
        1,
        p,
        entries,
        local,
        &hash::sha256(&[&leaf]),
        &path,
    )
    .ok_or(no(OUTPUT_PROOF))?;
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            &descriptor,
            &p.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    if ordinal != seg_ordinal {
        return Err(no(OUTPUT_PROOF));
    }
    let proven = super::challenge::spp1_position_root(
        &descriptor,
        p,
        segments,
        &segment_root,
        ordinal,
        &table,
        &spp1_path,
        &table_root,
    )
    .map_err(|_| no(OUTPUT_PROOF))?;
    if proven != Some(document::landed_root(dpr2, p, OUTPUT_PROOF)?) {
        return Err(no(OUTPUT_PROOF));
    }
    drop(doc);
    let mut raw = dcr2.try_borrow_mut_data()?;
    let at = HEADER + index as usize * w;
    raw[at..at + w].copy_from_slice(value);
    raw[bitmap_at] |= bit;
    let attested = v.attested + 1;
    raw[204..208].copy_from_slice(&attested.to_le_bytes());
    events::emit(
        events::OUTPUT,
        &descriptor,
        Body::new()
            .u32(index)
            .u32(attested)
            .u32(p)
            .u8(v.width)
            .pad(3)
            .key(value),
    );
    Ok(())
}

/// tag 177 AttestOutputV5 (revision 8). Identical to revision 7's proof, with
/// four differences and no new account and no new proof format:
/// 1. **flag 2 must be set** (591 when clear): `FinalizeDocumentV5` writes it in
///    the same write that records `n`, and nothing is attestable before it;
/// 2. the index test is against the two-case `L`, not `count` (591);
/// 3. the cell's `(position, write)` comes from `Binding2::cell`, so a decision
///    attests write `output_write + i` at `output_first_position`;
/// 4. the value's byte range and the DCR2 output region are the v6 ones.
#[cfg(feature = "revision-8")]
pub fn attest_v8(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    attest_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn attest_v8_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let [signer, dcm2, dpr2, dcr2, pt2s, routes, geometry] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() < 37 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    let index = u32_at(data, 33, CL_MALFORMED)?;
    document::document_v8_stored(program, dcm2, Some(&descriptor), false, CL_MALFORMED)?;
    // 0. Attest after finalize.
    if u16_at(&dcm2.try_borrow_data()?, 6, CL_MALFORMED)? & document::FLAG_FINAL == 0 {
        return Err(no(CL_MISSING));
    }
    let v = view_v8_status_with_hooks(program, dcr2, &descriptor, true, STATUS_SETTLED, hooks)?;
    // 1. Exact parse at the document's width.
    let w = v.width as usize;
    let value = data.get(37..37 + w).ok_or(no(CL_MALFORMED))?;
    let tail_len = u16_at(data, 37 + w, CL_MALFORMED)? as usize;
    let tail_at = 39 + w;
    let tail = data
        .get(tail_at..tail_at + tail_len)
        .ok_or(no(CL_MALFORMED))?;
    let height = *data.get(tail_at + tail_len).ok_or(no(CL_MALFORMED))? as usize;
    let path_at = tail_at + tail_len + 1;
    let path_bytes = data
        .get(path_at..path_at + 32 * height)
        .ok_or(no(CL_MALFORMED))?;
    let spp1_at = path_at + 32 * height;
    let (ordinal, table, spp1_path, used) =
        super::challenge::decode_spp1(data.get(spp1_at..).ok_or(no(CL_MALFORMED))?)
            .map_err(|_| no(CL_MALFORMED))?;
    if spp1_at + used != data.len() {
        return Err(no(CL_MALFORMED));
    }
    if v.full > dcr2.data_len() {
        // Growth toward the full size (module doc); nothing else changes.
        let next = v.full.min(dcr2.data_len() + CPI_ALLOC);
        dcr2.realloc(next, true)?;
        return Ok(());
    }
    let (binding, n, p_count) = {
        let doc = dcm2.try_borrow_data()?;
        let binding =
            Binding2::decode(&doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8]).map_err(no)?;
        (
            binding,
            u32_at(&doc, 84, CL_MALFORMED)?,
            u32_at(&doc, 72, CL_MALFORMED)?,
        )
    };
    document::positions_from_document(
        program,
        dpr2,
        dcm2,
        &descriptor,
        p_count,
        false,
        CL_MALFORMED,
    )?;
    if pt2s.key.as_ref() != &dcm2.try_borrow_data()?[200..232]
        || hash::sha256(&[&pt2s.try_borrow_data()?]) != dcm2.try_borrow_data()?[232..264]
    {
        return Err(no(PLAN_BINDING));
    }
    plan::bind_pt2s(program, pt2s, routes, geometry, None)?;
    // 2. The two-case `L`: `1 + option_count` for a decision, `n - 1 - first`
    // for a completion, and `1 <= L <= count` at FINAL.
    let span = binding.output_span(n);
    if index >= span || span == 0 || span > v.count {
        return Err(no(CL_MISSING));
    }
    // 3. Repeat, closed.
    let (bitmap_at, bit) = (
        HEADER_V6 + v.count as usize * w + index as usize / 8,
        1u8 << (index % 8),
    );
    if v.closed || dcr2.try_borrow_data()?[bitmap_at] & bit != 0 {
        return Err(no(OUTPUT_PROOF));
    }
    // 4. The cell's coordinate and write route: one position and consecutive
    // lanes under the mode flag, one lane and consecutive positions otherwise.
    let (p, write) = binding.cell(index);
    if p >= n {
        return Err(no(CL_MISSING));
    }
    let (segment, local, entries, seg_ordinal, segments, table_root, region, offset, length) = {
        let s = pt2s.try_borrow_data()?;
        let (rb, gb) = (routes.try_borrow_data()?, geometry.try_borrow_data()?);
        let x = plan::view(&s, &rb, &gb, &[], None)?;
        let t = x
            .old_to_new(binding.output_base_entry, p)
            .map_err(|_| no(OUTPUT_PROOF))?
            .ok_or(no(OUTPUT_PROOF))?;
        let e = x.entry(p, t).map_err(|_| no(OUTPUT_PROOF))?;
        let route = x
            .route(&e, e.read_count + write)
            .map_err(|_| no(OUTPUT_PROOF))?;
        let c = x.coordinate(p, t).map_err(|_| no(OUTPUT_PROOF))?;
        let mut found = None;
        for s_ord in 0..x.segment_count as usize {
            let (id, n) = x.segment_row(p, s_ord).map_err(|_| no(OUTPUT_PROOF))?;
            if id == c.segment {
                found = Some((s_ord as u16, n));
            }
        }
        let (so, n) = found.ok_or(no(OUTPUT_PROOF))?;
        (
            c.segment,
            c.local,
            n,
            so,
            x.segment_count,
            x.segment_table_root(p).map_err(|_| no(OUTPUT_PROOF))?,
            route.region_id,
            route.effective_offset,
            route.byte_length,
        )
    };
    if length as usize != w {
        return Err(no(OUTPUT_PROOF));
    }
    // 5. The leaf preimage holds the output's write row.
    let mut leaf = Vec::with_capacity(LEAF_TAIL_AT + tail.len());
    leaf.extend_from_slice(LEAF_DOMAIN);
    leaf.extend_from_slice(&descriptor);
    leaf.extend_from_slice(&p.to_le_bytes());
    leaf.extend_from_slice(&segment.to_le_bytes());
    leaf.extend_from_slice(&local.to_le_bytes());
    leaf.extend_from_slice(tail);
    if leaf.len() < LEAF_WRITES_AT || leaf[LEAF_WRITE_COUNT_AT + 2..LEAF_WRITES_AT] != [0; 2] {
        return Err(no(OUTPUT_PROOF));
    }
    let writes =
        u16::from_le_bytes([leaf[LEAF_WRITE_COUNT_AT], leaf[LEAF_WRITE_COUNT_AT + 1]]) as usize;
    if leaf.len() != LEAF_WRITES_AT + 48 * writes {
        return Err(no(OUTPUT_PROOF));
    }
    let coordinate = Coordinate {
        position: p,
        segment,
        entry: local,
    };
    let digest = h::write_digest(&descriptor, coordinate, region, offset, value)?;
    let mut row = [0u8; 48];
    row[0..2].copy_from_slice(&region.to_le_bytes());
    row[4..8].copy_from_slice(&length.to_le_bytes());
    row[8..16].copy_from_slice(&offset.to_le_bytes());
    row[16..48].copy_from_slice(&digest);
    if !leaf[LEAF_WRITES_AT..].chunks_exact(48).any(|r| r == row) {
        return Err(no(OUTPUT_PROOF));
    }
    // 6. Leaf path to the segment root, SPP1 to the landed position root.
    let path: Vec<[u8; 32]> = path_bytes
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let tree = super::challenge::dl_fold(
        &descriptor,
        1,
        p,
        entries,
        local,
        &hash::sha256(&[&leaf]),
        &path,
    )
    .ok_or(no(OUTPUT_PROOF))?;
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            &descriptor,
            &p.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    if ordinal != seg_ordinal {
        return Err(no(OUTPUT_PROOF));
    }
    let proven = super::challenge::spp1_position_root(
        &descriptor,
        p,
        segments,
        &segment_root,
        ordinal,
        &table,
        &spp1_path,
        &table_root,
    )
    .map_err(|_| no(OUTPUT_PROOF))?;
    if proven != Some(document::landed_root(dpr2, p, OUTPUT_PROOF)?) {
        return Err(no(OUTPUT_PROOF));
    }
    let mut raw = dcr2.try_borrow_mut_data()?;
    let at = HEADER_V6 + index as usize * w;
    raw[at..at + w].copy_from_slice(value);
    raw[bitmap_at] |= bit;
    let attested = v.attested + 1;
    raw[204..208].copy_from_slice(&attested.to_le_bytes());
    events::emit_v8(
        events::OUTPUT,
        &descriptor,
        Body::new()
            .u32(index)
            .u32(attested)
            .u32(p)
            .u8(v.width)
            .pad(3)
            .key(value),
    );
    Ok(())
}

/// tag 178 ResolveResultV5 (permissionless): `descriptor[32]`. Accounts:
/// DCM2, DCR2 (w). REFUTED if DCM2 flag 4; FINAL under the FINAL condition;
/// else 796 (also 796 when not PENDING or closed).
///
/// The reader split is the DCM2 version (spec §0), exactly as at tag 177, so a
/// revision-7 record keeps the byte-for-byte revision-7 body and a revision-8
/// record takes [`resolve_v8`].
pub fn resolve(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        resolve_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        resolve_v8(program, accounts, data)
    }
}

pub fn resolve_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = hooks;
        resolve_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        resolve_v8_with_hooks(program, accounts, data, hooks)
    }
}

/// tag 178 ResolveResultV5 (revision 7), unchanged byte for byte: `outputs_
/// attested = output_count` is the whole of the FINAL condition there, because
/// revision 7 has no two-case `L` and no stop rule.
#[cfg(feature = "revision-7")]
pub fn resolve_v7(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [dcm2, dcr2] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    document::document(program, dcm2, Some(&descriptor), false, CL_MALFORMED)?;
    let v = view(program, dcr2, &descriptor, true)?;
    if v.status != STATUS_PENDING || v.closed || dcr2.data_len() != v.full {
        return Err(no(RESULT_STATE));
    }
    let doc = dcm2.try_borrow_data()?;
    let flags = u16_at(&doc, 6, CL_MALFORMED)?;
    let now = now()?;
    let status = if flags & FLAG_REFUTED != 0 {
        STATUS_REFUTED
    } else if flags & FLAG_FINAL != 0
        && now > u64_at(&doc, 144, CL_MALFORMED)?
        && u32_at(&doc, 128, CL_MALFORMED)? == 0
        && v.attested == v.count
    {
        STATUS_FINAL
    } else {
        return Err(no(RESULT_STATE));
    };
    let wins = u32_at(&doc, 132, CL_MALFORMED)?;
    let mut raw = dcr2.try_borrow_mut_data()?;
    raw[6] = status;
    raw[184..192].copy_from_slice(&now.to_le_bytes());
    raw[192..196].copy_from_slice(&wins.to_le_bytes());
    events::emit(
        events::RESOLVE,
        &descriptor,
        Body::new()
            .u8(status)
            .pad(3)
            .u32(wins)
            .u32(v.attested)
            .pad(4),
    );
    Ok(())
}

// ------------------------------------------------ revision 8: the resolve check

/// What the revision-8 FINAL condition says about a record (spec §1.6's tag-178
/// row, §1.2's stop rule, and §1.3 (iv) for the close's re-use of it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// **The FINAL condition is met**: `outputs_attested = L`, the bitmap is
    /// exactly `[0, L)`, and -- for a completion with a declared stop value --
    /// the stop rule holds over the attested outputs. `ResolveResultV5` writes
    /// `status = 1`; the close writes SETTLED.
    Final,
    /// **A stop-rule violation**, which is a conviction and not a refusal
    /// (spec §1.6: "A stop-rule violation is a conviction, not a refusal").
    /// Clause 1 fired (a stop value at an output in `[0, L-2)`) or clause 2 did
    /// (output `L-1` is not the stop value with `L < count`). The caller sets
    /// DCM2 flag 4 and `challenger_wins + 1`, and writes `status = 2`.
    Violated,
    /// **The status is already `FINAL`**, so this exact check has already run
    /// and its answer cannot change, and the close skips it (spec §1.3 (iv);
    /// the uncosted-check Medium that §9.10 hands to stream C). The caller
    /// treats it as `Final`; it is a separate value so a reader can see that no
    /// cell and no bitmap byte was read.
    AlreadyFinal,
}

/// The bytes of a cell that carry the token id under the stop rule: an output
/// cell is the 16-byte `(best, token)` pair and bytes `8..16` are the token
/// (spec §1.2). The comparison is on the raw little-endian **u64** and stays
/// workload-neutral -- DCG does not decode a cell as a token.
const STOP_TOKEN_AT: usize = 8;
const STOP_TOKEN_BYTES: usize = 8;

/// A cell is **the stop value** iff the little-endian u64 at its bytes `8..16`,
/// plus one, equals `stop_plus_one` (spec §1.2). u64 arithmetic on the low
/// eight bytes is deliberate: a cell whose value exceeds `2^32 - 1`, or whose
/// high bit is set, can never match, which is the right answer, since such a
/// token cannot be the model's stop token. `stop + 1` is what makes token id 0
/// expressible.
#[inline]
fn is_stop_value(cell: &[u8], stop_plus_one: u32) -> bool {
    let Some(bytes) = cell.get(STOP_TOKEN_AT..STOP_TOKEN_AT + STOP_TOKEN_BYTES) else {
        return false;
    };
    u64::from_le_bytes(bytes.try_into().unwrap()).checked_add(1) == Some(stop_plus_one as u64)
}

/// The revision-8 FINAL condition, as one clause over the DCR2 bytes and the
/// DRB1 v2 block `CloseDocumentV5` re-uses (spec §1.6's tag-178 row and §1.3
/// (iv)). **No account is read here and nothing is written**, so
/// `ResolveResultV5` and the close evaluate the same clause over the same
/// fields, one transaction apart at worst.
///
/// `binding` is the DRB1 v2 block from DCM2 (spec §1.6's four extra reads: DCM2
/// `2,114` `first`, `2,118` `count`, `2,129` `option_count`, `2,134`
/// `stop_plus_one`, all inside the block UnifiedInit wrote once), `n` is DCM2
/// 84 (`positions_complete`, which **is** `n` after finalize), `count` and
/// `attested` are DCR2 196 and 204, `status` is DCR2 6, and `raw` is the whole
/// DCR2 account.
///
/// **796 is a refusal, not a verdict.** It means the record is not in a state
/// where the question has an answer: no `L`, a `L` past `count`, an
/// incompletely attested output set, or a bitmap that is not exactly `[0, L)`.
pub fn resolve_check(
    binding: &Binding2,
    n: u32,
    count: u32,
    attested: u32,
    status: u8,
    raw: &[u8],
) -> Result<Verdict, ProgramError> {
    // (0) **The already-FINAL skip** (spec §1.3 (iv), and the Medium §9.10
    // hands to stream C). `L` is a function of `n` and of the binding, both of
    // which are immutable once flag 2 is set -- finalize is refused 592 after
    // it and the attest only sets bits below `L` -- so a record that reached
    // FINAL can never stop satisfying the condition, and re-evaluating it is
    // the cost a close should not pay. This is the whole of the skip: one
    // compare, and no cell and no bitmap byte is read.
    if status == STATUS_FINAL {
        return Ok(Verdict::AlreadyFinal);
    }
    let l = binding.output_span(n);
    // DCR2 196 and 200 are the copies finalize proved equal to the binding's
    // `output_count` and `output_first_position` (spec §1.6's tag-165 row), so
    // the geometry below is the binding's; this keeps the check self-contained
    // in one compare. Unreachable on program-written state.
    if l == 0 || l > count || count != binding.output_count {
        return Err(no(RESULT_STATE));
    }
    // (1) **The partial bitmap.** Revision 7's condition was `outputs_attested =
    // output_count`; revision 8's is `outputs_attested = L`, and `L` may be
    // below `count` -- a document that stopped early is FINAL with a *partly*
    // filled bitmap. The counting clause is the load-bearing one: the stop rule
    // below reads the cells of `[0, L)` and would otherwise read an
    // **unattested** cell as if it were attested, which for `stop_plus_one = 1`
    // is a cell of zeros and therefore a false conviction. So the bitmap is
    // required to be exactly `[0, L)`: every bit of `[0, L)` set, every bit of
    // `[L, count)` clear, and the padding bits of the last byte clear as well,
    // since nothing ever sets them. The trailing **cells** `[L, count)` are the
    // consumer's zero-byte check (design §2.6, and `tierc-oracle`'s
    // `request_program.rs` "an unset bit requires 16 zero bytes"); no verdict
    // reads them, so they are not scanned here, and the test asserts the
    // property instead of paying for it on chain.
    if attested != l {
        return Err(no(RESULT_STATE));
    }
    let (bitmap_at, bitmap_bytes) = (
        HEADER_V6 + count as usize * binding.output_width as usize,
        (count as usize).div_ceil(8),
    );
    let bitmap = raw
        .get(bitmap_at..bitmap_at + bitmap_bytes)
        .ok_or(no(CL_MALFORMED))?;
    for (b, &byte) in bitmap.iter().enumerate() {
        let lo = 8 * b as u32;
        let want = if lo >= l {
            0
        } else {
            (0xffu32 >> (8 - (l - lo).min(8))) as u8
        };
        if byte != want {
            return Err(no(RESULT_STATE));
        }
    }
    // (2) **The stop rule**, in output indices, on a completion only. A decision
    // document generates nothing (§1.2) so there is nothing to stop, and
    // `outputs_attested = 1 + option_count` is the whole of its condition.
    // `stop_plus_one = 0` is the opt-out and disables the rule.
    if !binding.decision() && binding.stop_plus_one != 0 {
        let w = binding.output_width as usize;
        let cells = raw
            .get(HEADER_V6..HEADER_V6 + count as usize * w)
            .ok_or(no(CL_MALFORMED))?;
        let stop = binding.stop_plus_one;
        // Clause 1, **ran long**: no output in `[0, L-2]` is the stop value.
        // Vacuous at `L = 1`, so a document whose first generated token is the
        // stop value is legal.
        if cells[..(l as usize - 1) * w]
            .chunks_exact(w)
            .any(|c| is_stop_value(c, stop))
        {
            return Ok(Verdict::Violated);
        }
        // Clause 2, **stopped early**: output `L-1` is the stop value, unless
        // `L = count` -- which is the document that used every output it asked
        // for, and is never obliged to have stopped.
        if l < count && !is_stop_value(&cells[(l as usize - 1) * w..l as usize * w], stop) {
            return Ok(Verdict::Violated);
        }
    }
    Ok(Verdict::Final)
}

/// tag 178 ResolveResultV5 (revision 8). The account list is revision 7's, the
/// data is revision 7's `descriptor[32]`, and the DLE1 `resolve` body is
/// unchanged at 16 bytes (spec §1.8) -- the four differences are the reader
/// split, the two-case `L` with the stop rule, the **conviction** branch and the
/// record's own versioned view.
///
/// **A stop-rule violation is a conviction, not a refusal** (spec §1.6): the
/// failing branch sets DCM2 flag 4 and `challenger_wins + 1` (checked, **598**
/// on overflow) exactly as `RULE` does, writes `status = 2` REFUTED, and leaves
/// **`conviction_winner` untouched** -- a stop-rule conviction names nobody, so
/// the field stays 32 zero bytes and the document takes §1.4's disposition with
/// `cause = 4` at the close. `bond_cause` is the close's byte, not this one's.
///
/// **One account-list note, which is a spec inconsistency and not a choice.**
/// §1.6's tag-178 row says "accounts unchanged (DCM2, DCR2)", and revision 7's
/// list is DCM2 read-only with DCR2 writable. The conviction branch writes
/// DCM2, exactly as `RULE` does, so a **read-only** DCM2 on a *violating*
/// record cannot convict: the branch is the one place this instruction needs
/// the meta writable, and it refuses **580** there (the same code `view_v8` and
/// `view` use for a non-writable meta) rather than weakening the account list
/// for the honest paths, which accept either. Every other instruction that
/// names DCM2 as writable means it.
#[cfg(feature = "revision-8")]
pub fn resolve_v8(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    resolve_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn resolve_v8_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let [dcm2, dcr2] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    document::document_v8_stored(program, dcm2, Some(&descriptor), false, CL_MALFORMED)?;
    let v = view_v8_status_with_hooks(program, dcr2, &descriptor, true, STATUS_SETTLED, hooks)?;
    if v.status != STATUS_PENDING || v.closed || dcr2.data_len() != v.full {
        return Err(no(RESULT_STATE));
    }
    // The four reads §1.6 names inside the DRB1 v2 block, and DCM2 84.
    let (flags, binding, n, open) = {
        let doc = dcm2.try_borrow_data()?;
        (
            u16_at(&doc, 6, CL_MALFORMED)?,
            Binding2::decode(&doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8]).map_err(no)?,
            u32_at(&doc, 84, CL_MALFORMED)?,
            u32_at(&doc, 128, CL_MALFORMED)?,
        )
    };
    let now = now()?;
    let status = if flags & FLAG_REFUTED != 0 {
        STATUS_REFUTED
    } else if flags & FLAG_FINAL != 0
        && now > u64_at(&dcm2.try_borrow_data()?, 144, CL_MALFORMED)?
        && open == 0
    {
        // The FINAL condition: the two-case `L`, the partial bitmap and the
        // stop rule, over the same bytes the close re-reads.
        let raw = dcr2.try_borrow_data()?;
        match resolve_check(&binding, n, v.count, v.attested, v.status, &raw)? {
            Verdict::Final | Verdict::AlreadyFinal => STATUS_FINAL,
            Verdict::Violated => conviction(dcm2)?,
        }
    } else {
        return Err(no(RESULT_STATE));
    };
    let wins = u32_at(&dcm2.try_borrow_data()?, 132, CL_MALFORMED)?;
    let mut raw = dcr2.try_borrow_mut_data()?;
    raw[6] = status;
    raw[184..192].copy_from_slice(&now.to_le_bytes());
    raw[192..196].copy_from_slice(&wins.to_le_bytes());
    drop(raw);
    events::emit_v8(
        events::RESOLVE,
        &descriptor,
        Body::new()
            .u8(status)
            .pad(3)
            .u32(wins)
            .u32(v.attested)
            .pad(4),
    );
    Ok(())
}

/// The stop-rule conviction's two writes on **DCM2** (spec §1.6 and §1.3
/// (iv)): flag 4 and `challenger_wins + 1` as a **checked** add, 598 on
/// overflow, exactly as `RULE` does. DCR2's `status = 2`, `status_slot := now`
/// and the new `challenger_wins` are the caller's common tail, and
/// `conviction_winner` (DCR2 352) is deliberately not written -- see
/// [`resolve_v8`]. Returns the status to log.
fn conviction(dcm2: &AccountInfo) -> Result<u8, ProgramError> {
    if !dcm2.is_writable {
        return Err(no(CL_MALFORMED));
    }
    let mut doc = dcm2.try_borrow_mut_data()?;
    let wins = u32_at(&doc, 132, CL_MALFORMED)?
        .checked_add(1)
        .ok_or(no(CL_OVERFLOW))?;
    doc[132..136].copy_from_slice(&wins.to_le_bytes());
    let flags = u16_at(&doc, 6, CL_MALFORMED)? | FLAG_REFUTED;
    doc[6..8].copy_from_slice(&flags.to_le_bytes());
    Ok(STATUS_REFUTED)
}

/// Move every lamport of `from` to `to`, zero and shrink it, give it back to
/// the system program.
pub(crate) fn drain<'a>(from: &AccountInfo<'a>, to: &AccountInfo<'a>) -> Result<u64, ProgramError> {
    if from.key == to.key {
        return Err(no(CL_MALFORMED));
    }
    drain_unchecked(from, to)
}

/// Reproduces the pre-fix behavior for the native payer-alias regression test.
#[cfg(feature = "test-rev8-before-payer-alias-fix")]
pub(crate) fn drain_before_payer_alias_fix<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
) -> Result<u64, ProgramError> {
    drain_unchecked(from, to)
}

fn drain_unchecked<'a>(from: &AccountInfo<'a>, to: &AccountInfo<'a>) -> Result<u64, ProgramError> {
    let amount = from.lamports();
    **to.try_borrow_mut_lamports()? = to.lamports().checked_add(amount).ok_or(no(CL_OVERFLOW))?;
    **from.try_borrow_mut_lamports()? = 0;
    from.try_borrow_mut_data()?.fill(0);
    from.realloc(0, false)?;
    from.assign(&system_program::id());
    Ok(amount)
}

/// tag 172 CloseDocumentV5: `descriptor[32]`. Accounts: signer (s), DCM2 (w),
/// DPR2 (w), DFS2 (w), DCR2 (w), executor (w). After the challenge deadline
/// with no open challenge anyone may close (REFUTED or SETTLED); before
/// finalize only the executor may abandon. Every DCM2/DPR2/DFS2 lamport goes
/// to the executor, a held executor bond with them.
///
/// **The reader split is the DCR2 version**, because the result record survives
/// the close and makes a second close answer 599 after DCM2 has been drained.
/// A revision-7 call presents six metas and takes [`close_v7`] byte for byte,
/// and a revision-8 call presents the ten of §1.6 and takes [`close_v8`]. A
/// revision-7 document therefore keeps the revision-7 handler body, its six
/// metas, its six close rows' worth of behaviour and every refusal code it
/// answered with before this branch existed.
pub fn close<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        close_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        close_v8(program, accounts, data)
    }
}

pub fn close_with_hooks<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = hooks;
        close_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        close_v8_with_hooks(program, accounts, data, hooks)
    }
}

/// tag 172 CloseDocumentV5 (revision 7), unchanged byte for byte. After the
/// challenge deadline with no open challenge anyone may close (REFUTED or
/// SETTLED); before finalize only the executor may abandon. Every
/// DCM2/DPR2/DFS2 lamport goes to the executor, a held executor bond with them.
#[cfg(feature = "revision-7")]
pub fn close_v7<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    let [signer, dcm2, dpr2, dfs2, dcr2, executor] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    // DCR2 outlives the close (spec §6.12): a second close is 599 even though
    // DCM2/DPR2/DFS2 are already drained.
    let v = view(program, dcr2, &descriptor, true)?;
    if v.closed {
        return Err(no(CL_CLOSE));
    }
    document::document(program, dcm2, Some(&descriptor), true, CL_MALFORMED)?;
    let (flags, p_count, bond_state, bond, deadline, open, wins, retention) = {
        let doc = dcm2.try_borrow_data()?;
        let terms = Terms::decode(&doc[TERMS_AT..TERMS_AT + TERMS_BYTES]).map_err(no)?;
        (
            u16_at(&doc, 6, CL_MALFORMED)?,
            u32_at(&doc, 72, CL_MALFORMED)?,
            doc[529],
            terms.executor_bond_lamports,
            u64_at(&doc, 144, CL_MALFORMED)?,
            u32_at(&doc, 128, CL_MALFORMED)?,
            u32_at(&doc, 132, CL_MALFORMED)?,
            terms.result_retention_slots,
        )
    };
    document::positions(program, dpr2, &descriptor, p_count, true, CL_MALFORMED)?;
    expect_derived(
        dfs2,
        program,
        &[address::FAMILY_SLOTS_SEED, &descriptor],
        AccountKind::variable(
            b"DFS2",
            document::DFS2_HEADER,
            document::DFS2_HEADER + 10 * 1024 * 1024,
        ),
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| no(CL_MALFORMED))?;
    if !executor.is_writable || executor.key.as_ref() != &dcm2.try_borrow_data()?[40..72] {
        return Err(no(super::CL_AUTHORITY));
    }
    let finalized = flags & FLAG_FINAL != 0;
    let now = now()?;
    let status = if finalized {
        if now <= deadline || open != 0 {
            return Err(no(CL_CLOSE));
        }
        if flags & FLAG_REFUTED != 0 {
            STATUS_REFUTED
        } else if v.attested != v.count {
            return Err(no(RESULT_STATE));
        } else {
            STATUS_SETTLED
        }
    } else {
        if signer.key != executor.key {
            return Err(no(super::CL_AUTHORITY));
        }
        v.status
    };
    let returned = if bond_state == BOND_HELD { bond } else { 0 };
    let retention_deadline = now.checked_add(retention).ok_or(no(CL_OVERFLOW))?;
    {
        let mut raw = dcr2.try_borrow_mut_data()?;
        if status != raw[6] {
            raw[6] = status;
            raw[184..192].copy_from_slice(&now.to_le_bytes());
            raw[192..196].copy_from_slice(&wins.to_le_bytes());
        }
        raw[7] = 1;
        raw[RETENTION_START_AT..RETENTION_START_AT + 8].copy_from_slice(&now.to_le_bytes());
        raw[RETENTION_DEADLINE_AT..RETENTION_DEADLINE_AT + 8]
            .copy_from_slice(&retention_deadline.to_le_bytes());
    }
    if bond_state == BOND_HELD {
        dcm2.try_borrow_mut_data()?[529] = BOND_RETURNED;
    }
    let mut refund = drain(dcm2, executor)?;
    refund = refund
        .checked_add(drain(dpr2, executor)?)
        .ok_or(no(CL_OVERFLOW))?;
    refund = refund
        .checked_add(drain(dfs2, executor)?)
        .ok_or(no(CL_OVERFLOW))?;
    events::emit(
        events::CLOSE,
        &descriptor,
        Body::new()
            .key(executor.key.as_ref())
            .u64(refund)
            .u64(returned)
            .u8(status)
            .u8(finalized as u8)
            .pad(6),
    );
    Ok(())
}

/// **tag 172 `CloseDocumentV5` (revision 8)**, spec §1.3's three rows, §1.4's
/// disposition and §1.5's DCR2 write. The reader split is the surviving DCR2
/// version, so a second close reaches 599 after DCM2 is gone. **Ten metas**:
///
/// ```text
///   0 signer (s)      1 DCM2 (w)   2 DPR2 (w)   3 DFS2 (w)   4 DCR2 (w)
///   5 payer  (w)      6 DTU1 (w)
///   7 STANDARD: winner (w)   8 STANDARD: remainder (w)
///     CUSTOM:   bond_escrow (w) | 8 CUSTOM: system (ro)
///   9 incinerator (w)
/// ```
///
/// The **kind is read from `terms.bond_policy_kind` and enforced by the two key
/// checks**, not by the count, so a client that hands a STANDARD list to a
/// CUSTOM document is caught by the escrow-key check (582) and not by a length
/// (the re-review's Medium 6).
///
/// **What is new, and why each piece is here.**
///
/// * **The rent refund is unconditional** (D12). Every DCM2, DPR2 and DFS2
///   lamport goes to `payer` on all three rows, whatever the bond policy does,
///   and whatever state the document is in. DCG never strands rent: that is the
///   invariant R2 states and the reason the bond's slow path (tag 187) is a
///   separate instruction.
/// * **`payer` is DCM2 40..72, the recorded payer** — the `UnifiedInit` signer
///   that instruction debited to create the four accounts. So the permissionless
///   rows pay whoever paid, by construction rather than by a new check, and the
///   test "a close with the wrong rent recipient" is one 32-byte compare (582).
/// * **The resolve check runs on row 1 when flag 4 is clear** (§1.3 (iv)), with
///   [`resolve_check`] — the same clause `ResolveResultV5` evaluates, one
///   transaction apart at worst. A violation is a **conviction in this
///   transaction**: flag 4, `challenger_wins + 1` (checked, 598), status REFUTED.
///   The already-FINAL **skip** is inside that clause and costs one compare.
/// * **The DTU1 counter falls by one**, which is what makes the template
///   closable at all (tag 186 refuses at `documents != 0`) and what stops an
///   executor that never closes from holding the template's rent.
/// * **The bond never blocks the close.** The disposition is a movement of
///   lamports plus one byte; there is no callee, no deadline and no fallback.
#[cfg(feature = "revision-8")]
pub fn close_v8<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    close_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn close_v8_with_hooks<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let [signer, dcm2, dpr2, dfs2, dcr2, payer, use_record, aux, tail, burn] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    // DCR2 outlives the close (spec §6.12): a second close is 599 even though
    // DCM2/DPR2/DFS2 are already drained.
    let result_bump = dcr2
        .try_borrow_data()?
        .get(RESULT_PDA_BUMP_AT_V6)
        .copied()
        .ok_or(no(CL_MALFORMED))?;
    let v = view_v8_status_with_bump_and_hooks(
        program,
        dcr2,
        &descriptor,
        true,
        STATUS_WITHHELD,
        result_bump,
        hooks,
    )?;
    if v.closed {
        return Err(no(CL_CLOSE));
    }
    let (document_bump, position_bump, family_bump, escrow_bump) = {
        let raw = dcm2.try_borrow_data()?;
        if raw.len() < document::PDA_BUMPS_RESERVED_AT + 2 {
            return Err(no(CL_MALFORMED));
        }
        (
            raw[document::DCM2_BUMP_AT],
            raw[document::DPR2_BUMP_AT],
            raw[document::DFS2_BUMP_AT],
            raw[document::BOND_ESCROW_BUMP_AT],
        )
    };
    document::document_v8_with_bump(
        program,
        dcm2,
        Some(&descriptor),
        true,
        CL_MALFORMED,
        document_bump,
    )?;
    let (flags, p_count, bond_state, deadline, abandon, open, wins, n, recorded, terms, binding) = {
        let doc = dcm2.try_borrow_data()?;
        (
            u16_at(&doc, 6, CL_MALFORMED)?,
            u32_at(&doc, 72, CL_MALFORMED)?,
            doc[529],
            u64_at(&doc, 144, CL_MALFORMED)?,
            u64_at(&doc, ABANDON_DEADLINE_AT, CL_MALFORMED)?,
            u32_at(&doc, 128, CL_MALFORMED)?,
            u32_at(&doc, 132, CL_MALFORMED)?,
            u32_at(&doc, 84, CL_MALFORMED)?,
            d32(&doc, document::WINNER_AT_V8, CL_MALFORMED)?,
            Terms2::decode_with(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2], hooks)
                .map_err(no)?,
            // The DRB1 v2 block init wrote once. A decode failure here is 794 on a
            // record that init already decoded. No revision-8 document exists on
            // any cluster: revision 8 has not been deployed (stream G is the
            // deploy), so a pre-C5 decision with a wrong count cannot exist.
            // Propagate the decode error for any malformed record that does reach
            // this close path.
            Binding2::decode(&doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8]).map_err(no)?,
        )
    };
    document::positions_with_bump(
        program,
        dpr2,
        &descriptor,
        p_count,
        true,
        CL_MALFORMED,
        position_bump,
    )?;
    expect_derived_with_bump(
        dfs2,
        program,
        &[address::FAMILY_SLOTS_SEED, &descriptor],
        family_bump,
        AccountKind::variable(
            b"DFS2",
            document::DFS2_HEADER,
            document::DFS2_HEADER + 10 * 1024 * 1024,
        ),
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| no(CL_MALFORMED))?;
    // The rent's destination, and the one check that makes the permissionless
    // rows safe: the payer is the recorded payer, never the closer.
    if !payer.is_writable || payer.key.as_ref() != &dcm2.try_borrow_data()?[40..72] {
        return Err(no(super::CL_AUTHORITY));
    }
    // ---------------------------------------------------- the three close rows
    let finalized = flags & FLAG_FINAL != 0;
    let now = now()?;
    let span = binding.output_span(n);
    let (status, cause) = if finalized {
        // Row 1 and row 3 both wait for the dispute window to close and for no
        // challenge to be open.
        if now <= deadline || open != 0 {
            return Err(no(CL_CLOSE));
        }
        if flags & FLAG_REFUTED != 0 {
            (STATUS_REFUTED, CAUSE_CONVICTION)
        } else if span == 0 || span > v.count {
            return Err(no(RESULT_STATE));
        } else if v.attested == span {
            // Row 1: the FINAL condition, evaluated here rather than trusted.
            // `AlreadyFinal` is the skip and takes the same branch as `Final`:
            // the status a closed document carries is SETTLED either way.
            let raw = dcr2.try_borrow_data()?;
            match resolve_check(&binding, n, v.count, v.attested, v.status, &raw)? {
                Verdict::Final | Verdict::AlreadyFinal => (STATUS_SETTLED, CAUSE_NONE),
                Verdict::Violated => {
                    close_conviction(dcm2)?;
                    (STATUS_REFUTED, CAUSE_CONVICTION)
                }
            }
        } else if v.attested < span && now >= abandon {
            // Row 3: finalized, unrefuted, and never fully attested. The later
            // of the two deadlines, which the check above has already applied
            // to the dispute one.
            (STATUS_WITHHELD, CAUSE_WITHHELD)
        } else {
            return Err(no(CL_CLOSE));
        }
    } else {
        // Row 2: unfinalized, and past its own production deadline. The status
        // is left exactly as revision 7 leaves it (PENDING).
        if now < abandon {
            return Err(no(CL_CLOSE));
        }
        (v.status, CAUSE_NONE)
    };
    // The template's counter, at the address derived from DCM2's own PT2S and
    // its digest (793 on a substituted or malformed record) -- **after the row
    // test and before the bond**, because the row is the document's business
    // and the counter is the template's: a close that is not yet due is 599
    // whatever the counter says, and nothing has been written when it is
    // answered. This is the write that makes the template closable at all
    // (tag 186 refuses at `documents != 0`).
    let (pt2s_key, digest) = {
        let doc = dcm2.try_borrow_data()?;
        (d32(&doc, 200, CL_MALFORMED)?, d32(&doc, 232, CL_MALFORMED)?)
    };
    super::config::template_release(
        program,
        use_record,
        &Pubkey::new_from_array(pt2s_key),
        &digest,
    )?;
    // ------------------------------------------------------------- the bond
    let (bond_pot, winner_payout, remainder_payout, disposition, bond_state, bond_cause) =
        dispose_bond(
            program,
            dcm2,
            aux,
            tail,
            burn,
            &terms,
            bond_state,
            recorded,
            cause,
            escrow_bump,
        )?;
    // --------------------------------------------------------- the DCR2 write
    let retention_deadline = now
        .checked_add(terms.result_retention_slots)
        .ok_or(no(CL_OVERFLOW))?;
    {
        let mut raw = dcr2.try_borrow_mut_data()?;
        if status != raw[6] {
            raw[6] = status;
            raw[184..192].copy_from_slice(&now.to_le_bytes());
            raw[192..196].copy_from_slice(
                &(wins + u32::from(status == STATUS_REFUTED && flags & FLAG_REFUTED == 0) as u32)
                    .to_le_bytes(),
            );
        }
        raw[7] = 1;
        raw[WINNER_AT_V6..WINNER_AT_V6 + 32].copy_from_slice(&recorded);
        raw[RETENTION_START_AT_V6..RETENTION_START_AT_V6 + 8].copy_from_slice(&now.to_le_bytes());
        raw[RETENTION_DEADLINE_AT_V6..RETENTION_DEADLINE_AT_V6 + 8]
            .copy_from_slice(&retention_deadline.to_le_bytes());
        raw[BOND_STATE_AT_V6] = bond_state;
        raw[BOND_CAUSE_AT_V6] = bond_cause;
    }
    // ------------------------------------------------------------- the drains
    // Everything left in DCM2 is the rent, the skips and (on a returned bond)
    // the pot itself; it all goes to the recorded payer, unconditionally.
    let drained = drain(dcm2, payer)?
        .checked_add(drain(dpr2, payer)?)
        .ok_or(no(CL_OVERFLOW))?
        .checked_add(drain(dfs2, payer)?)
        .ok_or(no(CL_OVERFLOW))?;
    let refund = drained;
    events::emit_v8(
        events::CLOSE,
        &descriptor,
        Body::new()
            .key(payer.key.as_ref())
            .u64(refund)
            .u64(bond_pot)
            .u64(winner_payout)
            .u64(remainder_payout)
            .u8(status)
            .u8(finalized as u8)
            .u8(disposition)
            .u8(bond_cause)
            .pad(4),
    );
    Ok(())
}

/// The stop-rule conviction's two writes on **DCM2**, at the close (spec §1.3
/// (iv)). The same branch [`conviction`] takes, on the same field, so the
/// close's conviction and `ResolveResultV5`'s are the same act; **the write is
/// unobservable** because the close zeroes DCM2 a few lines later, and §1.3
/// says so rather than pretending otherwise. `conviction_winner` is untouched:
/// a stop-rule conviction names nobody.
fn close_conviction(dcm2: &AccountInfo) -> Result<(), ProgramError> {
    if !dcm2.is_writable {
        return Err(no(CL_MALFORMED));
    }
    let mut doc = dcm2.try_borrow_mut_data()?;
    let wins = u32_at(&doc, 132, CL_MALFORMED)?
        .checked_add(1)
        .ok_or(no(CL_OVERFLOW))?;
    doc[132..136].copy_from_slice(&wins.to_le_bytes());
    let flags = u16_at(&doc, 6, CL_MALFORMED)? | FLAG_REFUTED;
    doc[6..8].copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

/// **§1.4's disposition, as one function** (the STANDARD split and the CUSTOM
/// escrow, plus the two "nothing to move" rows), returning
/// `(bond_pot, winner_payout, remainder_payout, disposition, bond_state,
/// bond_cause)`.
///
/// **The order is the rule: this runs before the drain.** C3's shared payout
/// sends skipped shares to the policy remainder and any residual to the
/// incinerator, leaving no conviction bond for the later rent drain to return
/// to the convicted executor.
///
/// **`aux`/`tail` are the two kind-dependent metas** and the key checks enforce
/// the kind. **STANDARD** uses winner, remainder and incinerator; **CUSTOM**
/// uses the bond escrow, system program and incinerator.
///
/// **The escrow move makes no CPI** (D12). `validate_escrow` enforces the
/// system-owned, zero-data shape and `escrow_pot` moves the full pot with direct
/// lamport writes. A third party cannot allocate or assign this PDA because it
/// cannot sign for the address; those former refusal and repair branches were
/// unreachable and are removed.
fn dispose_bond<'a>(
    program: &Pubkey,
    dcm2: &AccountInfo<'a>,
    aux: &AccountInfo<'a>,
    tail: &AccountInfo<'a>,
    burn: &AccountInfo<'a>,
    terms: &Terms2,
    bond_state: u8,
    recorded: [u8; 32],
    cause: u8,
    escrow_bump: u8,
) -> Result<(u64, u64, u64, u8, u8, u8), ProgramError> {
    let pot = terms.executor_bond_lamports;
    // §1.4: "4 on entry means the settle paid for the escrow; 1 on entry means
    // this close does". Everything else that is not HELD has nothing to move,
    // and §1.5's `bond_state` mirrors whatever DCM2 529 ends up holding.
    let recorded_cause = if bond_state == BOND_ESCROWED {
        CAUSE_CONVICTION
    } else {
        cause
    };
    if bond_state != BOND_HELD {
        return Ok((
            0,
            0,
            0,
            if bond_state == BOND_ESCROWED {
                DISPOSITION_ESCROWED
            } else {
                DISPOSITION_NONE
            },
            bond_state,
            if cause == CAUSE_NONE {
                CAUSE_NONE
            } else {
                recorded_cause
            },
        ));
    }
    if cause == CAUSE_NONE {
        // Rows 1-on-SETTLED and 2: the pot returns to its owner with the drain.
        dcm2.try_borrow_mut_data()?[529] = BOND_RETURNED;
        return Ok((pot, 0, 0, DISPOSITION_RETURNED, BOND_RETURNED, CAUSE_NONE));
    }
    if terms.bond_policy_kind == super::terms::BOND_POLICY_STANDARD {
        // The exact same policy, skip handling and residual burn as tag 131.
        if aux.key.as_ref()
            != if recorded == [0; 32] {
                incinerator::ID.as_ref()
            } else {
                &recorded
            }
            || tail.key.as_ref() != terms.bond_remainder
            || burn.key != &incinerator::ID
            || !burn.is_writable
        {
            return Err(no(super::CL_AUTHORITY));
        }
        require_pot(dcm2, pot)?;
        let (winner_payout, remainder_payout, _) = bond::standard_payout(
            dcm2,
            aux,
            tail,
            burn,
            pot,
            terms.bond_slasher_bps,
            recorded != [0; 32],
        )?;
        dcm2.try_borrow_mut_data()?[529] = BOND_PAID;
        Ok((
            pot,
            winner_payout,
            remainder_payout,
            DISPOSITION_SPLIT,
            BOND_PAID,
            cause,
        ))
    } else {
        // The CUSTOM route: the pot waits. The escrow is a 0-byte account at the
        // document's own PDA, and nothing else is touched.
        let doc_key = d32(&dcm2.try_borrow_data()?, 8, CL_MALFORMED)?;
        let key = Pubkey::create_program_address(
            &[address::BOND_ESCROW_SEED, &doc_key, &[escrow_bump]],
            program,
        )
        .map_err(|_| no(CL_MALFORMED))?;
        // Preserve C4's close-side 582 for a wrong escrow key. Check the
        // account's shape after tail/burn and pot checks to keep their refusal
        // precedence, then write only to the validated empty escrow.
        if aux.key != &key {
            return Err(no(super::CL_AUTHORITY));
        }
        if *tail.key != system_program::id() || burn.key != &incinerator::ID || !burn.is_writable {
            return Err(no(super::CL_AUTHORITY));
        }
        if pot != 0 {
            require_pot(dcm2, pot)?;
        }
        bond::validate_escrow_with_bump(program, aux, &doc_key, escrow_bump)?;
        bond::escrow_pot(dcm2, aux, pot)?;
        dcm2.try_borrow_mut_data()?[529] = BOND_ESCROWED;
        Ok((pot, 0, 0, DISPOSITION_ESCROWED, BOND_ESCROWED, cause))
    }
}

/// The pot is inside DCM2, and DCM2's rent floor is the document's own; a
/// document that cannot pay its own bond out is refused **733**, revision 7's
/// own code for the same fact at the same place (`require_bond_lamports`).
fn require_pot(dcm2: &AccountInfo, pot: u64) -> ProgramResult {
    let floor = Rent::get()?.minimum_balance(dcm2.data_len());
    if dcm2.lamports() < floor.checked_add(pot).ok_or(no(CL_OVERFLOW))? {
        return Err(no(DCR1_PHASE));
    }
    Ok(())
}

// ------------------------------------------- the close's CU bound (rev 8, C4)

/// The per-instruction compute cap this bound is measured against. It is
/// Solana's, not DCG's: an instruction is capped at 1,400,000 CU, and a close
/// that cannot fit inside it can never run — which is the failure a capacity cap
/// at the seal exists to make impossible.
pub const CU_INSTRUCTION_CAP: u64 = 1_400_000;
/// **The stated margin: 5% of the cap, 70,000 CU.** The model below is a *fit*
/// to a measurement, not the measurement, and the fit's own error is larger
/// than zero; a template whose worst-case close lands within 5% of the cap is
/// inside the region where the model is least trustworthy, and the cost of
/// refusing a template is one seal, while the cost of admitting one is a
/// document that can never be closed.
pub const CU_MARGIN: u64 = 70_000;
/// **`CU_close_own`, the close's own quoted cost: 40,000 CU.** This rounds up
/// the 37,756-CU maximum from four local SBF runs over the rung-D template;
/// their measurement and run details are in `dcg-revision-8-2026-09-25.md`
/// §9.12. That image measurement is historical and is not a measurement of the
/// current program image. Its run-to-run spread tracked the PDA bump-search
/// work, which the stored-bump fix removed, rather than machine load. The close
/// also zeroes DPR2 before shrinking it, so the bound includes a linear term
/// for its maximum `48 + 32·K` byte size.
pub const CLOSE_OWN_CU: u64 = 40_000;
/// Linear DPR2 zeroing cost, in milli-CU per byte. Measured-local on the SBF
/// image by comparing an otherwise identical row-2 close with a 112-byte page
/// and a page sized for the capacity boundary; the coefficient rounds the
/// observed slope upward.
pub const DPR2_ZERO_MCU_PER_BYTE: u64 = 5;
/// The resolve check's fixed term, in **milli-CU** so the whole model is integer
/// arithmetic on chain: 5,786,000 milli-CU = 5,786 CU. The local measurements
/// and fit are documented in design §9.12; this is not a current-image CU claim.
pub const RESOLVE_FIXED_MCU: u64 = 5_786_000;
/// ≈15.1 CU per attested-bitmap byte, from the difference of two same-record
/// measurements (§9.12: "the least clean number here", and the reason the
/// margin above is 5% rather than 1%).
pub const RESOLVE_BITMAP_MCU_PER_BYTE: u64 = 15_100;
/// **20.378 CU per 16-byte cell compared**, bit-stable in all eight quotients
/// of §9.12's four-run table.
pub const RESOLVE_CELL_MCU: u64 = 20_378;
/// The cell width at which the stop scan is reachable at all. **`stop_plus_one
/// != 0` implies `output_width == 16`** is a `Binding2::decode` clause (794), so
/// a template whose locator is any other width has no document that can declare
/// a stop value and its worst-case close is the fixed term plus the bitmap
/// alone. That is a soundness property of the bound and not conservatism: the
/// `L`-proportional term is unreachable at width 32, where the account bound
/// would admit `count ≈ 326,000` and a scan would be 6.6M CU.
pub const STOP_RULE_WIDTH: u8 = 16;

/// **The worst-case close, in milli-CU, for a template of `positions` outputs
/// per document at `width`**: the fixed close cost, DPR2 zeroing at its maximum
/// `48 + 32·positions` bytes, and [`resolve_check`] at its maximum, which is
/// `L = count` on a completion that declares a stop value (the cells of
/// `[0, L-1)` compared, and the bitmap of `⌈count/8⌉` bytes). No intermediate
/// overflows: the largest term for any `u32` capacity is below `2^40` milli-CU.
pub fn close_worst_case_mcu(positions: u32, width: u8) -> u64 {
    let count = positions as u64;
    let bitmap = count.div_ceil(8);
    let mut mcu = RESOLVE_FIXED_MCU + RESOLVE_BITMAP_MCU_PER_BYTE * bitmap;
    if width == STOP_RULE_WIDTH && count > 1 {
        mcu += RESOLVE_CELL_MCU * (count - 1);
    }
    mcu += DPR2_ZERO_MCU_PER_BYTE * (48 + 32 * count);
    mcu + CLOSE_OWN_CU * 1_000
}

/// **`TemplateSeal`'s capacity bound** (spec §1.7): a template whose worst-case
/// close does not fit the per-instruction cap is refused **793**, the code the
/// seal already answers a structurally wrong template with. This is the refusal
/// that makes §1.3's "every document is closable" true at any capacity: above it
/// a document could reach finalize and then be unable to close, which would
/// strand its rent *and* its template's `documents` counter forever.
///
/// **The bound is on `position_count`, read out of the PT2S's own clause-12 v4
/// block** — the same number the descriptor commits and the same number
/// `UnifiedInit` refuses a document over — so a template cannot seal a capacity
/// it does not itself carry, and `bytes_v8`'s account bound
/// (`416 + 32·count + ⌈count/8⌉ ≤ 10,485,760`, at most `count ≈ 326,000`) is
/// never the binding constraint here.
pub fn close_capacity_bound(positions: u32, width: u8) -> Result<(), ProgramError> {
    if close_worst_case_mcu(positions, width) > (CU_INSTRUCTION_CAP - CU_MARGIN) * 1_000 {
        return Err(no(super::config::TEMPLATE_SEAL));
    }
    Ok(())
}

#[cfg(feature = "revision-7")]
pub fn close_result<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let [signer, dcr2, executor] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    expect_derived(
        dcr2,
        program,
        &[address::RESULT_SEED, &descriptor],
        AccountKind::variable(b"", TOMBSTONE_BYTES, MAX_ACCOUNT),
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| no(CL_MALFORMED))?;
    if dcr2.data_len() == TOMBSTONE_BYTES && dcr2.try_borrow_data()?[..4] == *b"DCRZ" {
        return Err(no(CL_CLOSE));
    }
    if dcr2.data_len() < HEADER {
        return Err(no(CL_MALFORMED));
    }
    let (record_executor, start, deadline) = {
        let raw = dcr2.try_borrow_data()?;
        if raw[..4] != *b"DCR2"
            || u16_at(&raw, 4, CL_MALFORMED)? != VERSION
            || raw[6] > STATUS_SETTLED
            || raw[7] > 1
            || raw[8..40] != descriptor
            || raw[209..216] != [0; 7]
        {
            return Err(no(CL_MALFORMED));
        }
        // Spec §6.12: the document must be closed first (599).
        if raw[7] != 1 {
            return Err(no(CL_CLOSE));
        }
        let terms =
            Terms::decode(&raw[RESULT_TERMS_AT..RESULT_TERMS_AT + TERMS_BYTES]).map_err(no)?;
        let start = u64_at(&raw, RETENTION_START_AT, CL_MALFORMED)?;
        let deadline = u64_at(&raw, RETENTION_DEADLINE_AT, CL_MALFORMED)?;
        let slots = u64_at(&raw, RETENTION_SLOTS_AT, CL_MALFORMED)?;
        // Unreachable on program-written state; spec §6.12 names 598.
        if start == 0
            || slots != terms.result_retention_slots
            || deadline != start.checked_add(slots).ok_or(no(CL_OVERFLOW))?
        {
            return Err(no(CL_OVERFLOW));
        }
        (d32(&raw, 136, CL_MALFORMED)?, start, deadline)
    };
    if !executor.is_writable || executor.key.as_ref() != record_executor {
        return Err(no(super::CL_AUTHORITY));
    }
    let now = now()?;
    if now < deadline {
        return Err(no(CL_CLOSE));
    }
    let floor = Rent::get()?.minimum_balance(TOMBSTONE_BYTES);
    if dcr2.lamports() < floor {
        return Err(no(CL_MALFORMED));
    }
    let refund = dcr2.lamports() - floor;
    let mut tomb = [0u8; TOMBSTONE_BYTES];
    tomb[..4].copy_from_slice(b"DCRZ");
    tomb[4..6].copy_from_slice(&1u16.to_le_bytes());
    tomb[8..40].copy_from_slice(&descriptor);
    tomb[40..72].copy_from_slice(&record_executor);
    tomb[72..80].copy_from_slice(&start.to_le_bytes());
    tomb[80..88].copy_from_slice(&deadline.to_le_bytes());
    tomb[88..96].copy_from_slice(&now.to_le_bytes());
    dcr2.realloc(TOMBSTONE_BYTES, true)?;
    dcr2.try_borrow_mut_data()?.copy_from_slice(&tomb);
    **executor.try_borrow_mut_lamports()? = executor
        .lamports()
        .checked_add(refund)
        .ok_or(no(CL_OVERFLOW))?;
    **dcr2.try_borrow_mut_lamports()? -= refund;
    events::emit(
        events::CLOSE_RESULT,
        &descriptor,
        Body::new()
            .key(executor.key.as_ref())
            .u64(refund)
            .u64(start)
            .u64(deadline)
            .u64(now)
            .pad(4),
    );
    Ok(())
}

/// Revision-8 tag 185. It reads only DCR2 v6 and emits the matching DCRZ
/// version: the compact v1 tombstone for an ordinary close, or v2 while a
/// CUSTOM bond remains escrowed for tag 187.
#[cfg(feature = "revision-8")]
pub fn close_result<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    close_result_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn close_result_v8_with_hooks<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let [signer, record, executor] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if data.len() != 33 || !signer.is_signer {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    expect_derived(
        record,
        program,
        &[address::RESULT_SEED, &descriptor],
        AccountKind::variable(b"", TOMBSTONE_BYTES, MAX_ACCOUNT),
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| no(CL_MALFORMED))?;
    if record.try_borrow_data()?.starts_with(b"DCRZ") {
        return Err(no(CL_CLOSE));
    }
    let view =
        view_v8_status_with_hooks(program, record, &descriptor, true, STATUS_WITHHELD, hooks)?;
    if !view.closed {
        return Err(no(CL_CLOSE));
    }
    let (record_executor, start, deadline, status, bond_state, cause, winner, terms) = {
        let raw = record.try_borrow_data()?;
        let terms = Terms2::decode_with(
            &raw[RESULT_TERMS_AT_V6..RESULT_TERMS_AT_V6 + TERMS_BYTES_V2],
            hooks,
        )
        .map_err(no)?;
        (
            d32(&raw, 136, CL_MALFORMED)?,
            u64_at(&raw, RETENTION_START_AT_V6, CL_MALFORMED)?,
            u64_at(&raw, RETENTION_DEADLINE_AT_V6, CL_MALFORMED)?,
            raw[6],
            raw[BOND_STATE_AT_V6],
            raw[BOND_CAUSE_AT_V6],
            d32(&raw, WINNER_AT_V6, CL_MALFORMED)?,
            terms,
        )
    };
    if !executor.is_writable || executor.key.as_ref() != record_executor {
        return Err(no(super::CL_AUTHORITY));
    }
    if now()? < deadline {
        return Err(no(CL_CLOSE));
    }
    let escrowed = bond_state == BOND_ESCROWED
        && terms.bond_policy_kind == 2
        && terms.settlement_program != [0; 32];
    if (bond_state == BOND_ESCROWED) != escrowed {
        return Err(no(CL_MALFORMED));
    }
    if escrowed {
        if !matches!(cause, CAUSE_CONVICTION | CAUSE_WITHHELD)
            || (cause == CAUSE_WITHHELD && (status != STATUS_WITHHELD || winner != [0; 32]))
            || (cause == CAUSE_CONVICTION && status != STATUS_REFUTED)
        {
            return Err(no(CL_MALFORMED));
        }
    }
    let tombstone_bytes = if escrowed {
        TOMBSTONE_V2_BYTES
    } else {
        TOMBSTONE_BYTES
    };
    let floor = Rent::get()?.minimum_balance(tombstone_bytes);
    if record.lamports() < floor {
        return Err(no(CL_MALFORMED));
    }
    let refund = record.lamports() - floor;
    let now = now()?;
    let mut tombstone = vec![0u8; tombstone_bytes];
    tombstone[..4].copy_from_slice(b"DCRZ");
    tombstone[4..6].copy_from_slice(&(if escrowed { 2u16 } else { 1u16 }).to_le_bytes());
    if escrowed {
        tombstone[6] = status;
        tombstone[7] = 1;
    }
    tombstone[8..40].copy_from_slice(&descriptor);
    tombstone[40..72].copy_from_slice(&record_executor);
    tombstone[72..80].copy_from_slice(&start.to_le_bytes());
    tombstone[80..88].copy_from_slice(&deadline.to_le_bytes());
    tombstone[88..96].copy_from_slice(&now.to_le_bytes());
    if escrowed {
        tombstone[TOMBSTONE_V2_CAUSE_AT] = cause;
        tombstone[TOMBSTONE_V2_PROGRAM_AT..TOMBSTONE_V2_PROGRAM_AT + 32]
            .copy_from_slice(&terms.settlement_program);
        tombstone[TOMBSTONE_V2_REMAINDER_AT..TOMBSTONE_V2_REMAINDER_AT + 32]
            .copy_from_slice(&terms.bond_remainder);
        tombstone[TOMBSTONE_V2_WINNER_AT..TOMBSTONE_V2_WINNER_AT + 32].copy_from_slice(&winner);
    }
    record.realloc(tombstone_bytes, true)?;
    record.try_borrow_mut_data()?.copy_from_slice(&tombstone);
    **executor.try_borrow_mut_lamports()? = executor
        .lamports()
        .checked_add(refund)
        .ok_or(no(CL_OVERFLOW))?;
    **record.try_borrow_mut_lamports()? -= refund;
    events::emit_v8(
        events::CLOSE_RESULT,
        &descriptor,
        Body::new()
            .key(executor.key.as_ref())
            .u64(refund)
            .u64(start)
            .u64(deadline)
            .u64(now)
            .pad(4),
    );
    Ok(())
}

pub fn close_result_with_hooks<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = hooks;
        close_result(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        close_result_v8_with_hooks(program, accounts, data, hooks)
    }
}
