//! Resumable, challenge-bound response bytes for closure-v2 disputes.
//! The upload transport never awards a ruling; replay authenticates its sealed
//! digest before parsing proofs. Each instruction touches at most one 900-byte
//! chunk or grows the account by at most 10,240 bytes.

use crate::hash;
use core::cell::Ref;
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

pub const TAG_BEGIN: u8 = 115;
pub const TAG_GROW: u8 = 116;
pub const TAG_WRITE: u8 = 117;
pub const TAG_SEAL: u8 = 118;
/// Unordered write for the generic PT1 respond: any in-bounds offset, in any
/// order, until seal. Seal's full-body digest is the only content check, so
/// a hole or overwrite can only make the seal refuse.
pub const TAG_WRITE_AT: u8 = 125;
pub const HEADER: usize = 128;
/// DRU1 offset of the executor-declared total (tag 115; capped at
/// [`MAX_BODY`], immutable afterwards). Revision 6: on a unified record the
/// respond path uses this stored total, not the challenger's stored length.
pub const DECLARED_LEN_AT: usize = 72;
/// 1 MiB: a form-30 response carries its 131 KiB state operand, the
/// descriptor core and the 257 KiB claimed output stream (~570 KB). Seal
/// hashes the body once (~530k CU at the cap); later steps never re-hash.
pub const MAX_BODY: usize = 1_048_576;
const MAX_CHUNK: usize = 900;
const GROW: usize = 10_240;
const BAD: u32 = 730;
const AUTH: u32 = 731;
const STATE: u32 = 733;
const PROOF: u32 = 734;
const DEADLINE: u32 = 736;

fn no(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
fn u32_at(raw: &[u8], at: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        raw.get(at..at + 4)
            .ok_or(no(BAD))?
            .try_into()
            .map_err(|_| no(BAD))?,
    ))
}
fn u64_at(raw: &[u8], at: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        raw.get(at..at + 8)
            .ok_or(no(BAD))?
            .try_into()
            .map_err(|_| no(BAD))?,
    ))
}
/// A DCR1 v5 (unified) record logs a `RESPOND` event for every respond step
/// (spec revision 4 §16.5); older record versions log nothing here.
fn v5_respond(challenge: &Pubkey, raw: &[u8], tag: u8) {
    if raw.len() == 8192 && raw[6..8] == crate::unified::challenge::VERSION.to_le_bytes() {
        crate::unified::challenge::respond_event(challenge, raw, tag, 1, raw[4]);
    }
}
pub fn address(program: &Pubkey, challenge: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-response", challenge.as_ref()], program)
}
fn challenge<'a>(
    program: &Pubkey,
    challenge: &'a AccountInfo,
    executor: &AccountInfo,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    if challenge.owner != program || !executor.is_signer || challenge.is_writable {
        return Err(no(AUTH));
    }
    let raw = challenge.try_borrow_data()?;
    if raw.len() != 8192
        || raw[..4] != *b"DCR1"
        || !matches!(raw[4], 1 | 2)
        || raw[40..72] != executor.key.to_bytes()
        || Clock::get()?.slot > u64_at(&raw, 148)?
    {
        return Err(no(DEADLINE));
    }
    Ok(Ref::map(raw, |data| &data[..]))
}
fn account<'a>(
    program: &Pubkey,
    response: &'a AccountInfo,
    challenge: &AccountInfo,
    executor: &AccountInfo,
    phase: u16,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    if response.owner != program || *response.key != address(program, challenge.key).0 {
        return Err(no(AUTH));
    }
    let raw = response.try_borrow_data()?;
    if raw.len() < HEADER
        || raw[..4] != *b"DRU1"
        || raw[4..6] != 1u16.to_le_bytes()
        || raw[6..8] != phase.to_le_bytes()
        || raw[8..40] != challenge.key.to_bytes()
        || raw[40..72] != executor.key.to_bytes()
        || raw[120..128] != [0; 8]
        || u32_at(&raw, 72)? == 0
        || u32_at(&raw, 72)? as usize > MAX_BODY
        || u32_at(&raw, 76)? > u32_at(&raw, 72)?
        || Clock::get()?.slot > u64_at(&raw, 112)?
    {
        return Err(no(STATE));
    }
    Ok(Ref::map(raw, |data| &data[..]))
}

/// tag 115: total:u32 | SHA-256(body)[32].
/// Accounts: response PDA(w), executor(s,w), DCR1(ro), system.
pub fn begin(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 37
        || accounts.len() != 4
        || *accounts[3].key != system_program::ID
        || !accounts[1].is_writable
        || !accounts[0].is_writable
    {
        return Err(no(BAD));
    }
    let response = &accounts[0];
    let executor = &accounts[1];
    let target = &accounts[2];
    let _challenge = challenge(program, target, executor)?;
    let total = u32_at(data, 1)? as usize;
    if total == 0 || total > MAX_BODY || data[5..37] == [0; 32] {
        return Err(no(BAD));
    }
    let (key, bump) = address(program, target.key);
    if *response.key != key {
        return Err(no(AUTH));
    }
    // Revision 6: a pre-funded response address is topped up, not refused,
    // or any watcher could block the executor's answer with dust.
    if *response.owner != system_program::ID || !response.data_is_empty() {
        return Err(no(BAD));
    }
    let rent = Rent::get()?.minimum_balance(HEADER + total);
    if response.lamports() < rent {
        invoke(
            &system_instruction::transfer(executor.key, response.key, rent - response.lamports()),
            &[executor.clone(), response.clone(), accounts[3].clone()],
        )?;
    }
    let seeds: &[&[u8]] = &[b"dcg-hcl-response", target.key.as_ref(), &[bump]];
    invoke_signed(
        &system_instruction::allocate(response.key, HEADER as u64),
        &[response.clone(), accounts[3].clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(response.key, program),
        &[response.clone(), accounts[3].clone()],
        &[seeds],
    )?;
    let mut raw = response.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DRU1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[6..8].copy_from_slice(&1u16.to_le_bytes());
    raw[8..40].copy_from_slice(target.key.as_ref());
    raw[40..72].copy_from_slice(executor.key.as_ref());
    raw[72..76].copy_from_slice(&(total as u32).to_le_bytes());
    raw[80..112].copy_from_slice(&data[5..37]);
    raw[112..120].copy_from_slice(&_challenge[148..156]);
    v5_respond(target.key, &_challenge, TAG_BEGIN);
    Ok(())
}

/// tag 116: no body. Accounts: response(w), executor(s), DCR1(ro).
pub fn grow(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 3 || !accounts[0].is_writable {
        return Err(no(BAD));
    }
    let _challenge = challenge(program, &accounts[2], &accounts[1])?;
    let raw = account(program, &accounts[0], &accounts[2], &accounts[1], 1)?;
    let target = HEADER + u32_at(&raw, 72)? as usize;
    let old = raw.len();
    if old > target {
        return Err(no(STATE));
    }
    drop(raw);
    if old < target {
        accounts[0].realloc(target.min(old + GROW), true)?;
    }
    v5_respond(accounts[2].key, &_challenge, TAG_GROW);
    Ok(())
}

/// tag 117: offset:u32 | 1..900 bytes. Exact retries are no-ops.
pub fn write(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 6
        || data.len() > 5 + MAX_CHUNK
        || accounts.len() != 3
        || !accounts[0].is_writable
    {
        return Err(no(BAD));
    }
    let _challenge = challenge(program, &accounts[2], &accounts[1])?;
    let raw = account(program, &accounts[0], &accounts[2], &accounts[1], 1)?;
    let offset = u32_at(data, 1)? as usize;
    let cursor = u32_at(&raw, 76)? as usize;
    let end = offset.checked_add(data.len() - 5).ok_or(no(BAD))?;
    if end > u32_at(&raw, 72)? as usize || HEADER + end > raw.len() {
        return Err(no(STATE));
    }
    if offset != cursor {
        return if end <= cursor && raw[HEADER + offset..HEADER + end] == data[5..] {
            Ok(())
        } else {
            Err(no(STATE))
        };
    }
    drop(raw);
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[HEADER + offset..HEADER + end].copy_from_slice(&data[5..]);
    raw[76..80].copy_from_slice(&(end as u32).to_le_bytes());
    v5_respond(accounts[2].key, &_challenge, TAG_WRITE);
    Ok(())
}

/// tag 125: offset:u32 | 1..900 bytes. Order-free before seal; `cursor`
/// records the highest written end so seal still requires full coverage.
pub fn write_at(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 6
        || data.len() > 5 + MAX_CHUNK
        || accounts.len() != 3
        || !accounts[0].is_writable
    {
        return Err(no(BAD));
    }
    let _challenge = challenge(program, &accounts[2], &accounts[1])?;
    let raw = account(program, &accounts[0], &accounts[2], &accounts[1], 1)?;
    let offset = u32_at(data, 1)? as usize;
    let end = offset.checked_add(data.len() - 5).ok_or(no(BAD))?;
    if end > u32_at(&raw, 72)? as usize || HEADER + end > raw.len() {
        return Err(no(STATE));
    }
    let cursor = (u32_at(&raw, 76)? as usize).max(end);
    drop(raw);
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[HEADER + offset..HEADER + end].copy_from_slice(&data[5..]);
    raw[76..80].copy_from_slice(&(cursor as u32).to_le_bytes());
    v5_respond(accounts[2].key, &_challenge, TAG_WRITE_AT);
    Ok(())
}

/// tag 118: exact EOF and digest. Sealing is idempotent.
pub fn seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 3 || !accounts[0].is_writable {
        return Err(no(BAD));
    }
    let _challenge = challenge(program, &accounts[2], &accounts[1])?;
    if accounts[0].try_borrow_data()?.get(6..8) == Some(&2u16.to_le_bytes()[..]) {
        let raw = account(program, &accounts[0], &accounts[2], &accounts[1], 2)?;
        let total = u32_at(&raw, 72)? as usize;
        return if u32_at(&raw, 76)? as usize == total
            && raw.len() == HEADER + total
            && hash::sha256(&[&raw[HEADER..]]) == raw[80..112]
        {
            Ok(())
        } else {
            Err(no(PROOF))
        };
    }
    let raw = account(program, &accounts[0], &accounts[2], &accounts[1], 1)?;
    let total = u32_at(&raw, 72)? as usize;
    if u32_at(&raw, 76)? as usize != total
        || raw.len() != HEADER + total
        || hash::sha256(&[&raw[HEADER..]]) != raw[80..112]
    {
        return Err(no(PROOF));
    }
    drop(raw);
    accounts[0].try_borrow_mut_data()?[6..8].copy_from_slice(&2u16.to_le_bytes());
    v5_respond(accounts[2].key, &_challenge, TAG_SEAL);
    Ok(())
}

pub fn sealed<'a>(
    program: &Pubkey,
    response: &'a AccountInfo,
    challenge: &AccountInfo,
    executor: &[u8; 32],
    total: usize,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    if response.owner != program || *response.key != address(program, challenge.key).0 {
        return Err(no(AUTH));
    }
    let raw = response.try_borrow_data()?;
    if raw.len() < HEADER
        || raw[..4] != *b"DRU1"
        || raw[4..6] != 1u16.to_le_bytes()
        || raw[6..8] != 2u16.to_le_bytes()
        || raw[8..40] != challenge.key.to_bytes()
        || raw[40..72] != *executor
        || raw[120..128] != [0; 8]
        || Clock::get()?.slot > u64_at(&raw, 112)?
    {
        return Err(no(STATE));
    }
    if raw.len() != HEADER + total
        || u32_at(&raw, 72)? as usize != total
        || u32_at(&raw, 76)? as usize != total
        || hash::sha256(&[&raw[HEADER..]]) != raw[80..112]
    {
        return Err(no(PROOF));
    }
    Ok(Ref::map(raw, |data| &data[..]))
}

/// A sealed DRU1 without re-hashing its body. Phase 2 is only reachable
/// through `seal`, which verified the full-body digest, and every mutating
/// transport instruction refuses phase 2, so the bytes are immutable.
pub fn sealed_view<'a>(
    program: &Pubkey,
    response: &'a AccountInfo,
    challenge: &Pubkey,
    executor: &[u8],
    total: usize,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    if response.owner != program || *response.key != address(program, challenge).0 {
        return Err(no(AUTH));
    }
    let raw = response.try_borrow_data()?;
    if raw.len() != HEADER + total
        || raw[..4] != *b"DRU1"
        || raw[4..6] != 1u16.to_le_bytes()
        || raw[6..8] != 2u16.to_le_bytes()
        || raw[8..40] != challenge.to_bytes()
        || raw[40..72] != *executor
        || raw[120..128] != [0; 8]
        || u32_at(&raw, 72)? as usize != total
        || u32_at(&raw, 76)? as usize != total
    {
        return Err(no(STATE));
    }
    Ok(Ref::map(raw, |data| &data[HEADER..]))
}
