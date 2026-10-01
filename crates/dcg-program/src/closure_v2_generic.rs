// SPDX-License-Identifier: GPL-3.0-only

//! Shared DGR1 response-envelope decoding for the revision-8 dispute engine.
//!
//! Application form and model semantics do not live in this module. The
//! dispute handler validates the generic layout, then asks the registered app
//! hooks to check artifact witnesses and replay the selected operation.

use crate::{
    account_provenance::{expect_derived_with_bump, AccountKind, RoleFlags},
    closure_v2_response,
    unified::{address, challenge, document},
};
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult,
    program_error::ProgramError, pubkey::Pubkey, sysvar::Sysvar,
};

const MALFORMED: u32 = 730;
const STATE: u32 = 733;
const PROOF: u32 = 734;
const DEADLINE: u32 = 736;
const ROW_BYTES: usize = 120;
const MAX_READS: usize = 128;
const OUTPUT_AT: usize = 1024;
const OUTPUT_BYTES: usize = 2048;
const RESPONSE_BYTES: usize = 128 + closure_v2_response::MAX_BODY;
pub const TAG_VERIFY_TARGET: u8 = 120;
pub const TAG_VERIFY_READS: u8 = 121;
pub const TAG_WEIGHTS_ANCHOR: u8 = 122;
pub const TAG_WEIGHTS_ROWS: u8 = 123;
pub const TAG_EXECUTE: u8 = 124;
pub const TAG_RESTAGE: u8 = 126;
pub const TAG_VERIFY_ARTIFACTS: u8 = 127;
pub const TAG_VERIFY_OUTPUTS: u8 = 128;
pub const TAG_VERIFY_RANGE_SLOTS: u8 = 129;

fn no(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn u16_at(raw: &[u8], at: usize) -> Result<u16, ProgramError> {
    let end = at.checked_add(2).ok_or(no(MALFORMED))?;
    Ok(u16::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(MALFORMED))?
            .try_into()
            .map_err(|_| no(MALFORMED))?,
    ))
}

fn u32_at(raw: &[u8], at: usize) -> Result<u32, ProgramError> {
    let end = at.checked_add(4).ok_or(no(MALFORMED))?;
    Ok(u32::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(MALFORMED))?
            .try_into()
            .map_err(|_| no(MALFORMED))?,
    ))
}

fn slice(raw: &[u8], at: usize, len: usize) -> Result<&[u8], ProgramError> {
    let end = at.checked_add(len).ok_or(no(MALFORMED))?;
    raw.get(at..end).ok_or(no(MALFORMED))
}

fn u64_at(raw: &[u8], at: usize) -> Result<u64, ProgramError> {
    let end = at.checked_add(8).ok_or(no(MALFORMED))?;
    Ok(u64::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(MALFORMED))?
            .try_into()
            .map_err(|_| no(MALFORMED))?,
    ))
}

/// Validate the revision-8 live DCR1 record and its exact challenge PDA.
/// The fresh revision-8 image requires both the challenge and DRU1 bumps that
/// tag 166 committed at open; caller-controlled descriptors do not trigger a
/// second canonical search here.
fn live(program: &Pubkey, record: &AccountInfo) -> ProgramResult {
    if !record.is_writable {
        return Err(no(MALFORMED));
    }
    let raw = record.try_borrow_data()?;
    if raw.len() != challenge::SIZE
        || raw.get(..4) != Some(&b"DCR1"[..])
        || u16_at(&raw, 6)? != challenge::VERSION
        || raw[4] != challenge::PHASE_RESPOND
        || raw[challenge::PT2P_MODE_AT] != 1
    {
        return Err(no(STATE));
    }
    let deadline = u64_at(&raw, 148)?;
    if Clock::get()?.slot > deadline {
        return Err(no(DEADLINE));
    }
    let descriptor: &[u8; 32] = raw[72..104].try_into().map_err(|_| no(STATE))?;
    let challenger = Pubkey::new_from_array(raw[8..40].try_into().map_err(|_| no(STATE))?);
    let nonce = &raw[140..144];
    let seeds = [
        address::CHALLENGE_SEED,
        &descriptor[..],
        challenger.as_ref(),
        nonce,
    ];
    let kind = AccountKind::exact(b"DCR1", challenge::SIZE).with_version(6, challenge::VERSION);
    let role = RoleFlags {
        writable: true,
        signer: false,
    };
    if raw[challenge::RECORD_BUMP_MARKER_AT] != 1 {
        return Err(no(PROOF));
    }
    expect_derived_with_bump(
        record,
        program,
        &seeds,
        raw[challenge::RECORD_BUMP_AT],
        kind,
        role,
    )
    .map(|_| ())
    .map_err(|_| no(PROOF))
}

fn response<'a>(
    program: &Pubkey,
    account: &'a AccountInfo,
    record: &Pubkey,
    state: &[u8],
) -> Result<core::cell::Ref<'a, [u8]>, ProgramError> {
    expect_derived_with_bump(
        account,
        program,
        &[b"dcg-hcl-response", record.as_ref()],
        state[challenge::RESPONSE_BUMP_AT],
        AccountKind::variable(b"DRU1", 128, RESPONSE_BYTES).with_version(4, 1),
        RoleFlags {
            writable: false,
            signer: false,
        },
    )
    .map_err(|_| no(PROOF))?;
    let total = u32_at(
        &account.try_borrow_data()?,
        closure_v2_response::DECLARED_LEN_AT,
    )? as usize;
    if total > closure_v2_response::MAX_BODY || account.data_len() > RESPONSE_BYTES {
        return Err(no(MALFORMED));
    }
    closure_v2_response::sealed_view(program, account, record, &state[40..72], total)
}

fn document(program: &Pubkey, account: &AccountInfo, state: &[u8]) -> ProgramResult {
    let descriptor: &[u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    document::document_v8_stored(program, account, Some(descriptor), false, PROOF)?;
    let raw = account.try_borrow_data()?;
    if raw[40..72] != state[40..72] {
        return Err(no(PROOF));
    }
    Ok(())
}

/// Close the executor's staged response and clear all generic verification
/// progress so it can retry before the unchanged deadline.
fn restage(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1
        || data[0] != TAG_RESTAGE
        || accounts.len() != 3
        || !accounts[0].is_writable
        || !accounts[1].is_signer
        || !accounts[1].is_writable
        || !accounts[2].is_writable
    {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[2])?;
    let mut state = accounts[2].try_borrow_mut_data()?;
    if &state[40..72] != accounts[1].key.as_ref() {
        return Err(no(STATE));
    }
    let response_seeds = [&b"dcg-hcl-response"[..], accounts[2].key.as_ref()];
    let response_kind = AccountKind::variable(b"DRU1", 128, RESPONSE_BYTES).with_version(4, 1);
    let response_role = RoleFlags {
        writable: true,
        signer: false,
    };
    if state[challenge::RECORD_BUMP_MARKER_AT] != 1 {
        return Err(no(PROOF));
    }
    expect_derived_with_bump(
        &accounts[0],
        program,
        &response_seeds,
        state[challenge::RESPONSE_BUMP_AT],
        response_kind,
        response_role,
    )
    .map_err(|_| no(PROOF))?;
    {
        let raw = accounts[0].try_borrow_data()?;
        if raw.len() < 128
            || u16_at(&raw, 4)? != 1
            || raw[6..8] != 2u16.to_le_bytes()
            || &raw[8..40] != accounts[2].key.as_ref()
        {
            return Err(no(STATE));
        }
    }
    accounts[0].try_borrow_mut_data()?.fill(0);
    let refund = accounts[0].lamports();
    let executor_balance = accounts[1]
        .lamports()
        .checked_add(refund)
        .ok_or(no(STATE))?;
    **accounts[1].try_borrow_mut_lamports()? = executor_balance;
    **accounts[0].try_borrow_mut_lamports()? = 0;
    state[176..OUTPUT_AT + OUTPUT_BYTES].fill(0);
    challenge::respond_event(accounts[2].key, &state, TAG_RESTAGE, 1, state[4]);
    Ok(())
}

/// Verify that the app's claimed output bytes produce every committed write
/// digest before an app replay is allowed to compare its output.
fn verify_outputs(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_VERIFY_OUTPUTS || accounts.len() != 2 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0])?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    if state[176] != 1 || state[404] != 0 || accounts[1].key.as_ref() != &state[184..216] {
        return Err(no(STATE));
    }
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    let (_, _, _, _, _, writes) =
        crate::closure_v2::proof::preimage_fields(body.target, &descriptor)?;
    let target = crate::closure_v2::proof::Coordinate {
        position: u32_at(&state, 156)?,
        segment: u16_at(&state, 160)?,
        entry: u32_at(&state, 136)?,
    };
    if body.outputs.is_empty() {
        return Err(no(MALFORMED));
    }
    let mut at = 0usize;
    for write in writes.chunks_exact(48) {
        let len = usize::try_from(u32_at(write, 4)?).map_err(|_| no(MALFORMED))?;
        let bytes = slice(body.outputs, at, len)?;
        if crate::closure_v2::write_digest(
            &descriptor,
            crate::closure_v2::Coordinate {
                position: target.position,
                segment: target.segment,
                entry: target.entry,
            },
            u16_at(write, 0)?,
            u64_at(write, 8)?,
            bytes,
        )
        .map_err(|_| no(PROOF))?
            != write[16..48]
        {
            return Err(no(PROOF));
        }
        at = at.checked_add(len).ok_or(no(MALFORMED))?;
    }
    if at != body.outputs.len() {
        return Err(no(PROOF));
    }
    drop(raw);
    state[404] = 1;
    challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_OUTPUTS, 1, state[4]);
    Ok(())
}

/// Borrowed view of one DGR1 v1/v2 response envelope.
#[allow(dead_code)]
pub(crate) struct Body<'a> {
    raw: &'a [u8],
    head: usize,
    read_count: usize,
    target: &'a [u8],
    rows: &'a [u8],
    core: &'a [u8],
    weights: &'a [u8],
    outputs: &'a [u8],
}

#[allow(dead_code)]
impl<'a> Body<'a> {
    pub(crate) fn parse(raw: &'a [u8]) -> Result<Self, ProgramError> {
        if raw.len() < 28 || raw.get(..4) != Some(&b"DGR1"[..]) {
            return Err(no(MALFORMED));
        }
        let head = match u16_at(raw, 4)? {
            1 => 28,
            2 => 36,
            _ => return Err(no(MALFORMED)),
        };
        let read_count = u16_at(raw, 6)? as usize;
        if read_count > MAX_READS || raw.len() < head {
            return Err(no(MALFORMED));
        }
        let target_len = usize::try_from(u32_at(raw, 8)?).map_err(|_| no(MALFORMED))?;
        let target_at = head
            .checked_add(4usize.checked_mul(read_count).ok_or(no(MALFORMED))?)
            .ok_or(no(MALFORMED))?;
        let target = slice(raw, target_at, target_len)?;
        let rows_at = target_at.checked_add(target_len).ok_or(no(MALFORMED))?;
        let rows_len = read_count.checked_mul(ROW_BYTES).ok_or(no(MALFORMED))?;
        let rows = slice(raw, rows_at, rows_len)?;
        let optional = |off_at: usize| -> Result<&'a [u8], ProgramError> {
            let len_at = off_at.checked_add(4).ok_or(no(MALFORMED))?;
            let off = usize::try_from(u32_at(raw, off_at)?).map_err(|_| no(MALFORMED))?;
            let len = usize::try_from(u32_at(raw, len_at)?).map_err(|_| no(MALFORMED))?;
            if off == 0 && len == 0 {
                Ok(&raw[..0])
            } else {
                slice(raw, off, len)
            }
        };
        let outputs = if head == 36 { optional(28)? } else { &raw[..0] };
        Ok(Self {
            raw,
            head,
            read_count,
            target,
            rows,
            core: optional(12)?,
            weights: optional(20)?,
            outputs,
        })
    }

    pub(crate) fn row(&self, index: usize) -> Result<&'a [u8], ProgramError> {
        if index >= self.read_count {
            return Err(no(MALFORMED));
        }
        let start = index.checked_mul(ROW_BYTES).ok_or(no(MALFORMED))?;
        slice(self.rows, start, ROW_BYTES)
    }

    /// `(witness, binding_kind, proof)` of read `index`, through EOF.
    pub(crate) fn section(&self, index: usize) -> Result<(&'a [u8], u8, &'a [u8]), ProgramError> {
        if index >= self.read_count {
            return Err(no(MALFORMED));
        }
        let directory_at = self
            .head
            .checked_add(index.checked_mul(4).ok_or(no(MALFORMED))?)
            .ok_or(no(MALFORMED))?;
        let at = usize::try_from(u32_at(self.raw, directory_at)?).map_err(|_| no(MALFORMED))?;
        let len = usize::try_from(u32_at(self.raw, at)?).map_err(|_| no(MALFORMED))?;
        let witness_at = at.checked_add(4).ok_or(no(MALFORMED))?;
        let witness = slice(self.raw, witness_at, len)?;
        let kind_at = witness_at.checked_add(len).ok_or(no(MALFORMED))?;
        let kind = *self.raw.get(kind_at).ok_or(no(MALFORMED))?;
        let proof_at = kind_at.checked_add(1).ok_or(no(MALFORMED))?;
        Ok((
            witness,
            kind,
            self.raw.get(proof_at..).ok_or(no(MALFORMED))?,
        ))
    }

    /// Read section bounded by the next canonical offset (or EOF for the last
    /// section), so a proof cannot absorb later witness-only sections.
    pub(crate) fn section_exact(
        &self,
        index: usize,
    ) -> Result<(&'a [u8], u8, &'a [u8]), ProgramError> {
        if index >= self.read_count {
            return Err(no(MALFORMED));
        }
        let directory_at = self
            .head
            .checked_add(index.checked_mul(4).ok_or(no(MALFORMED))?)
            .ok_or(no(MALFORMED))?;
        let at = usize::try_from(u32_at(self.raw, directory_at)?).map_err(|_| no(MALFORMED))?;
        let end = if index + 1 < self.read_count {
            let next_at = self
                .head
                .checked_add((index + 1).checked_mul(4).ok_or(no(MALFORMED))?)
                .ok_or(no(MALFORMED))?;
            usize::try_from(u32_at(self.raw, next_at)?).map_err(|_| no(MALFORMED))?
        } else {
            self.raw.len()
        };
        let sections_at = self
            .head
            .checked_add(4usize.checked_mul(self.read_count).ok_or(no(MALFORMED))?)
            .and_then(|offset| offset.checked_add(self.target.len()))
            .and_then(|offset| offset.checked_add(self.rows.len()))
            .ok_or(no(MALFORMED))?;
        let prefix_end = at.checked_add(5).ok_or(no(MALFORMED))?;
        if at < sections_at || prefix_end > end || end > self.raw.len() {
            return Err(no(MALFORMED));
        }
        let len = usize::try_from(u32_at(self.raw, at)?).map_err(|_| no(MALFORMED))?;
        let witness_at = at.checked_add(4).ok_or(no(MALFORMED))?;
        let kind_at = witness_at.checked_add(len).ok_or(no(MALFORMED))?;
        let section_end = kind_at.checked_add(1).ok_or(no(MALFORMED))?;
        if section_end > end {
            return Err(no(MALFORMED));
        }
        let witness = slice(self.raw, witness_at, len)?;
        let kind = *self.raw.get(kind_at).ok_or(no(MALFORMED))?;
        Ok((
            witness,
            kind,
            slice(self.raw, section_end, end - section_end)?,
        ))
    }
}

#[allow(dead_code)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

#[allow(dead_code)]
impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], ProgramError> {
        let result = slice(self.data, self.at, len)?;
        self.at = self.at.checked_add(len).ok_or(no(MALFORMED))?;
        Ok(result)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ProgramError> {
        u16_at(self.take(2)?, 0)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ProgramError> {
        u32_at(self.take(4)?, 0)
    }

    /// u16-prefixed producer preimage, then u8-counted leaf path siblings.
    pub(crate) fn producer(&mut self) -> Result<(&'a [u8], &'a [u8]), ProgramError> {
        let preimage_len = self.u16()? as usize;
        let preimage = self.take(preimage_len)?;
        let siblings = self.u8()? as usize;
        let sibling_bytes = siblings.checked_mul(32).ok_or(no(MALFORMED))?;
        Ok((preimage, self.take(sibling_bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_body(version: u16) -> Vec<u8> {
        let mut raw = vec![0u8; if version == 1 { 29 } else { 37 }];
        raw[..4].copy_from_slice(b"DGR1");
        raw[4..6].copy_from_slice(&version.to_le_bytes());
        raw[8..12].copy_from_slice(&1u32.to_le_bytes());
        raw[if version == 1 { 28 } else { 36 }] = 0xAA;
        raw
    }

    #[test]
    fn parses_v1_and_v2_empty_read_envelopes() {
        for version in [1, 2] {
            let raw = empty_body(version);
            let body = Body::parse(&raw).unwrap();
            assert_eq!(body.target, &[0xAA]);
            assert_eq!(body.read_count, 0);
            assert!(body.rows.is_empty());
            assert!(body.core.is_empty());
            assert!(body.weights.is_empty());
            assert!(body.outputs.is_empty());
        }
    }

    #[test]
    fn parses_the_retained_dgr1_dispute_plan() {
        let raw = include_bytes!("../tests/fixtures/closure_v2_generic/entry-119.dgr1");
        let body = Body::parse(raw).unwrap();
        assert_eq!(body.read_count, 27);
        assert_eq!(body.target.len(), 243);
        let descriptor: [u8; 32] = body.target[27..59].try_into().unwrap();
        let (position, segment, entry, _, _, _) =
            crate::closure_v2::proof::preimage_fields(body.target, &descriptor).unwrap();
        assert_eq!((position, segment, entry), (1, 1, 117));
    }

    #[test]
    fn parses_a_bounded_read_section() {
        let head = 28usize;
        let target_at = head + 4;
        let rows_at = target_at + 1;
        let section_at = rows_at + ROW_BYTES;
        let mut raw = vec![0u8; section_at + 6];
        raw[..4].copy_from_slice(b"DGR1");
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
        raw[8..12].copy_from_slice(&1u32.to_le_bytes());
        raw[head..head + 4].copy_from_slice(&(section_at as u32).to_le_bytes());
        raw[target_at] = 0xBB;
        raw[section_at..section_at + 4].copy_from_slice(&1u32.to_le_bytes());
        raw[section_at + 4] = 0xCC;
        raw[section_at + 5] = 1;

        let body = Body::parse(&raw).unwrap();
        assert_eq!(body.row(0).unwrap().len(), ROW_BYTES);
        assert_eq!(body.section(0).unwrap(), (&[0xCC][..], 1, &[][..]));
        assert_eq!(body.section_exact(0).unwrap(), (&[0xCC][..], 1, &[][..]));
        assert!(body.row(1).is_err());
        assert!(body.section(1).is_err());
    }

    #[test]
    fn refuses_unknown_versions_and_truncated_sections() {
        let mut unknown = empty_body(1);
        unknown[4..6].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(Body::parse(&unknown), Err(error) if error == no(MALFORMED)));

        let mut truncated = empty_body(1);
        truncated[4..6].copy_from_slice(&2u16.to_le_bytes());
        truncated.truncate(30);
        assert!(matches!(Body::parse(&truncated), Err(error) if error == no(MALFORMED)));
    }
}
