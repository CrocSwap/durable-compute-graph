//! Temporary testnet bootstrap for the first STORED_PAGES document.
//!
//! The canonical BDG1/PT1 admission adapter is still being built. These
//! instructions create only the DCM2/DPR2/DLP2 storage needed to land the
//! retained host-computed leaves. DCM2 bytes 40..72 hold the bootstrap
//! authority instead of a profile digest. This path is deliberately marked
//! as a stub in the runner's progress record; it is not a validity claim.

use crate::closure_v2::{
    dcm2_header, document_address, page_address, page_bytes, position_page_address, position_root,
    DCM2_HEADER, DCM2_V2_HEADER, DPR2_HEADER,
};
use crate::closure_v2_accounts::{create, doc_authority};
use crate::envelope_seal;
use crate::root_only;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent, system_instruction, system_program,
    sysvar::Sysvar,
};

const FORM: u32 = 580;
const AUTHORITY: u32 = 582;
const COORDINATE: u32 = 581;
const GROW_MAX: usize = 10_240;
fn document_header(version: u16) -> Result<usize, ProgramError> {
    dcm2_header(version).ok_or(refuse(FORM))
}

fn refuse(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
fn u16_at(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        data.get(offset..offset + 2)
            .ok_or(refuse(FORM))?
            .try_into()
            .map_err(|_| refuse(FORM))?,
    ))
}
fn u32_at(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .ok_or(refuse(FORM))?
            .try_into()
            .map_err(|_| refuse(FORM))?,
    ))
}
fn descriptor(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    data.get(1..33)
        .ok_or(refuse(FORM))?
        .try_into()
        .map_err(|_| refuse(FORM))
}
/// tag 107: a one-position, one-segment test document using the same DCM2
/// and DPR2 layouts as the live document. No existing account is resized.
/// Data: descriptor32 | segment:u16 | entries:u32 | segment_table_root32 |
/// dispute_window_slots:u64. Accounts: authority, document, positions, system.
pub fn init_small(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || data.len() != 79 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let segment = u16_at(data, 33)?;
    let entries = u32_at(data, 35)?;
    let window = u64::from_le_bytes(data[71..79].try_into().map_err(|_| refuse(FORM))?);
    if entries < 2 || entries > 64 || window == 0 || data[39..71] == [0; 32] {
        return Err(refuse(COORDINATE));
    }
    let (doc_key, doc_bump) = document_address(program, &digest);
    let (pos_key, pos_bump) = position_page_address(program, &digest);
    if *accounts[1].key != doc_key || *accounts[2].key != pos_key {
        return Err(refuse(FORM));
    }
    create(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[3],
        &[b"dcg-hcl-document", &digest, &[doc_bump]],
        DCM2_HEADER + 6,
        DCM2_HEADER + 6,
    )?;
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[b"dcg-hcl-positions", &digest, &[pos_bump]],
        DPR2_HEADER + 32,
        DPR2_HEADER + 32,
    )?;
    let mut doc = accounts[1].try_borrow_mut_data()?;
    doc[..4].copy_from_slice(b"DCM2");
    doc[4..6].copy_from_slice(&1u16.to_le_bytes());
    doc[6..8].copy_from_slice(&1u16.to_le_bytes());
    doc[8..40].copy_from_slice(&digest);
    doc[40..72].copy_from_slice(accounts[0].key.as_ref());
    doc[72..76].copy_from_slice(&1u32.to_le_bytes());
    doc[76..78].copy_from_slice(&1u16.to_le_bytes());
    doc[80..84].copy_from_slice(&entries.to_le_bytes());
    doc[152..184].copy_from_slice(&data[39..71]);
    doc[184..192].copy_from_slice(&window.to_le_bytes());
    doc[192..194].copy_from_slice(&segment.to_le_bytes());
    doc[194..198].copy_from_slice(&entries.to_le_bytes());
    let mut pos = accounts[2].try_borrow_mut_data()?;
    pos[..4].copy_from_slice(b"DPR2");
    pos[4..6].copy_from_slice(&1u16.to_le_bytes());
    pos[8..40].copy_from_slice(&digest);
    pos[40..44].copy_from_slice(&1u32.to_le_bytes());
    Ok(())
}

/// tag 90: digest32 | position_count:u32 | segment_count:u16 |
/// entries_per_position:u32 | segment_table_root32 | dispute_window:u64 | manifest(6*N).
/// Accounts: payer/authority, document PDA, positions PDA, system.
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || data.len() < 83 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let positions = u32_at(data, 33)?;
    let segments = u16_at(data, 37)?;
    let entries = u32_at(data, 39)?;
    let window = u64::from_le_bytes(data[75..83].try_into().map_err(|_| refuse(FORM))?);
    if positions == 0
        || positions > (1 << 19)
        || segments == 0
        || entries == 0
        || window == 0
        || data.len() != 83 + segments as usize * 6
        || data[43..75] == [0; 32]
    {
        return Err(refuse(COORDINATE));
    }
    let manifest = &data[83..];
    let mut last = None;
    let mut sum = 0u32;
    for row in manifest.chunks_exact(6) {
        let id = u16_at(row, 0)?;
        let count = u32_at(row, 2)?;
        if count == 0 || last.is_some_and(|previous| previous >= id) {
            return Err(refuse(FORM));
        }
        last = Some(id);
        sum = sum.checked_add(count).ok_or(refuse(FORM))?;
    }
    if sum != entries {
        return Err(refuse(FORM));
    }
    let (doc_key, doc_bump) = document_address(program, &digest);
    let (pos_key, pos_bump) = position_page_address(program, &digest);
    if *accounts[1].key != doc_key || *accounts[2].key != pos_key {
        return Err(refuse(FORM));
    }
    let doc_bump_bytes = [doc_bump];
    let pos_bump_bytes = [pos_bump];
    create(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[3],
        &[b"dcg-hcl-document", &digest, &doc_bump_bytes],
        DCM2_HEADER + manifest.len(),
        DCM2_HEADER + manifest.len(),
    )?;
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[b"dcg-hcl-positions", &digest, &pos_bump_bytes],
        DPR2_HEADER + positions as usize * 32,
        DPR2_HEADER + positions as usize * 32,
    )?;
    let mut doc = accounts[1].try_borrow_mut_data()?;
    doc[..4].copy_from_slice(b"DCM2");
    doc[4..6].copy_from_slice(&1u16.to_le_bytes());
    doc[6..8].copy_from_slice(&1u16.to_le_bytes());
    doc[8..40].copy_from_slice(&digest);
    doc[40..72].copy_from_slice(accounts[0].key.as_ref());
    doc[72..76].copy_from_slice(&positions.to_le_bytes());
    doc[76..78].copy_from_slice(&segments.to_le_bytes());
    doc[80..84].copy_from_slice(&entries.to_le_bytes());
    doc[152..184].copy_from_slice(&data[43..75]);
    doc[184..192].copy_from_slice(&window.to_le_bytes());
    doc[DCM2_HEADER..].copy_from_slice(manifest);
    drop(doc);
    let mut pos = accounts[2].try_borrow_mut_data()?;
    pos[..4].copy_from_slice(b"DPR2");
    pos[4..6].copy_from_slice(&1u16.to_le_bytes());
    pos[8..40].copy_from_slice(&digest);
    pos[40..44].copy_from_slice(&positions.to_le_bytes());
    Ok(())
}

/// tag 95: digest32 | positions:u32 | segments:u16 | total_entries:u64 |
/// dispute_window:u64. The manifest is uploaded one position at a time.
pub fn init_v2(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_variable(program, accounts, data, 2)
}

/// tag 109: v2 fields followed by PT1 state key, sealed state SHA-256,
/// model-artifact root, position-table root, and prompt commitment.
/// The fifth account is the sealed PT1 state. All anchors are immutable.
pub fn init_v3(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_variable(program, accounts, data, 3)
}

/// tag 155: v3 fields followed by the expected registry table_root[32].
/// The sixth account is a frozen DRP1 registry of this image's epoch whose
/// stored root equals it (774 otherwise). DCM2 v4 binds the registry, its
/// root, and the DEA1 admission PDA of (registry, PT1S); tag 97 refuses the
/// document until that admission walk has completed.
pub fn init_v4(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 6 || data.len() != 251 {
        return Err(refuse(FORM));
    }
    envelope_seal::frozen_registry(program, &accounts[5], &data[219..251])?;
    init_variable(program, &accounts[..5], &data[..219], 4)?;
    let admission = envelope_seal::admission_address(program, accounts[5].key, accounts[4].key).0;
    let mut doc = accounts[1].try_borrow_mut_data()?;
    // init_variable created the account at min(size, GROW_MAX) >= 456 bytes.
    doc[360..392].copy_from_slice(accounts[5].key.as_ref());
    doc[392..424].copy_from_slice(&data[219..251]);
    doc[424..456].copy_from_slice(admission.as_ref());
    Ok(())
}

fn init_variable(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    version: u16,
) -> ProgramResult {
    let bound = version >= 3;
    if accounts.len() != (if bound { 5 } else { 4 }) || data.len() != (if bound { 219 } else { 59 })
    {
        return Err(refuse(FORM));
    }
    if bound {
        let state = &accounts[4];
        if state.owner != program || state.is_writable || state.key.as_ref() != &data[59..91] {
            return Err(refuse(AUTHORITY));
        }
        let raw = state.try_borrow_data()?;
        if !crate::pt1_onchain::is_sealed_template(&raw)
            || crate::hash::sha256(&[&raw]) != data[91..123]
            || data[123..155] == [0; 32]
            || data[155..187] == [0; 32]
            || data[187..219] == [0; 32]
        {
            return Err(refuse(FORM));
        }
    }
    let digest = descriptor(data)?;
    let positions = u32_at(data, 33)?;
    let segments = u16_at(data, 37)?;
    let total = u64::from_le_bytes(data[39..47].try_into().map_err(|_| refuse(FORM))?);
    let window = u64::from_le_bytes(data[47..55].try_into().map_err(|_| refuse(FORM))?);
    // The storage selector is immutable from document creation. This bootstrap
    // is a testnet adapter; canonical descriptor admission remains separate.
    let mode = data[55];
    // ROOT_ONLY is defined for DCM2 v2 only; its paths refuse v3 documents.
    if mode > 1
        || (bound && mode != 0)
        || data[56..59] != [0; 3]
        || positions == 0
        || segments == 0
        || total == 0
        || window == 0
    {
        return Err(refuse(COORDINATE));
    }
    let stride = 32usize
        .checked_add((segments as usize).checked_mul(6).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))?;
    let header = document_header(version)?;
    let size = header
        .checked_add(
            (positions as usize)
                .checked_mul(stride)
                .ok_or(refuse(FORM))?,
        )
        .ok_or(refuse(FORM))?;
    if size > 10_485_760 {
        return Err(refuse(COORDINATE));
    }
    let (doc_key, doc_bump) = document_address(program, &digest);
    let (pos_key, pos_bump) = position_page_address(program, &digest);
    if *accounts[1].key != doc_key || *accounts[2].key != pos_key {
        return Err(refuse(FORM));
    }
    create(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[3],
        &[b"dcg-hcl-document", &digest, &[doc_bump]],
        size.min(GROW_MAX),
        size,
    )?;
    let position_size = DPR2_HEADER
        .checked_add((positions as usize).checked_mul(32).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))?;
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[b"dcg-hcl-positions", &digest, &[pos_bump]],
        position_size.min(GROW_MAX),
        position_size,
    )?;
    let mut doc = accounts[1].try_borrow_mut_data()?;
    doc[..4].copy_from_slice(b"DCM2");
    doc[4..6].copy_from_slice(&version.to_le_bytes());
    doc[6..8].copy_from_slice(&(if mode == 1 { root_only::MODE_FLAG } else { 0 }).to_le_bytes());
    doc[8..40].copy_from_slice(&digest);
    doc[40..72].copy_from_slice(accounts[0].key.as_ref());
    doc[72..76].copy_from_slice(&positions.to_le_bytes());
    doc[76..78].copy_from_slice(&segments.to_le_bytes());
    doc[184..192].copy_from_slice(&window.to_le_bytes());
    doc[192..200].copy_from_slice(&total.to_le_bytes());
    if bound {
        doc[200..360].copy_from_slice(&data[59..219]);
    }
    drop(doc);
    let mut pos = accounts[2].try_borrow_mut_data()?;
    pos[..4].copy_from_slice(b"DPR2");
    pos[4..6].copy_from_slice(&1u16.to_le_bytes());
    pos[8..40].copy_from_slice(&digest);
    pos[40..44].copy_from_slice(&positions.to_le_bytes());
    Ok(())
}

/// tag 108: digest32. Grow the rent-funded DCM2 and DPR2 accounts in bounded
/// steps before any manifest upload. Accounts: authority, document, positions.
pub fn grow_v2(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 33 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let authority = &accounts[0];
    let document = &accounts[1];
    let positions_account = &accounts[2];
    if !authority.is_signer
        || !document.is_writable
        || !positions_account.is_writable
        || document.owner != program
        || positions_account.owner != program
        || *document.key != document_address(program, &digest).0
        || *positions_account.key != position_page_address(program, &digest).0
    {
        return Err(refuse(AUTHORITY));
    }
    let doc = document.try_borrow_data()?;
    let pos = positions_account.try_borrow_data()?;
    if doc.len() < DCM2_V2_HEADER
        || pos.len() < DPR2_HEADER
        || doc[..4] != *b"DCM2"
        || !matches!(u16_at(&doc, 4)?, 2 | 3 | 4)
        || u16_at(&doc, 6)? & !root_only::MODE_FLAG != 0
        || doc[8..40] != digest
        || doc[40..72] != authority.key.to_bytes()
        || pos[..4] != *b"DPR2"
        || pos[8..40] != digest
    {
        return Err(refuse(FORM));
    }
    let position_count = u32_at(&doc, 72)? as usize;
    let segment_count = u16_at(&doc, 76)? as usize;
    if position_count == 0 || segment_count == 0 || u32_at(&pos, 40)? as usize != position_count {
        return Err(refuse(FORM));
    }
    let stride = 32usize
        .checked_add(segment_count.checked_mul(6).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))?;
    let doc_target = document_header(u16_at(&doc, 4)?)?
        .checked_add(position_count.checked_mul(stride).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))?;
    let pos_target = DPR2_HEADER
        .checked_add(position_count.checked_mul(32).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))?;
    let doc_old = doc.len();
    let pos_old = pos.len();
    if doc_old > doc_target
        || pos_old > pos_target
        || (doc_old == doc_target && pos_old == pos_target)
    {
        return Err(refuse(COORDINATE));
    }
    drop(doc);
    drop(pos);
    if doc_old < doc_target {
        document.realloc(doc_target.min(doc_old + GROW_MAX), true)?;
    }
    if pos_old < pos_target {
        positions_account.realloc(pos_target.min(pos_old + GROW_MAX), true)?;
    }
    Ok(())
}

/// tag 96: digest32 | position:u32 | table_root32 | segment rows[6*N].
pub fn upload_v2(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 2 || data.len() < 71 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let position = u32_at(data, 33)?;
    let authority = &accounts[0];
    let document = &accounts[1];
    if !authority.is_signer
        || !document.is_writable
        || document.owner != program
        || *document.key != document_address(program, &digest).0
    {
        return Err(refuse(AUTHORITY));
    }
    let doc = document.try_borrow_data()?;
    if doc[..4] != *b"DCM2"
        || !matches!(u16_at(&doc, 4)?, 2 | 3 | 4)
        || u16_at(&doc, 6)? & !root_only::MODE_FLAG != 0
        || doc[8..40] != digest
        || doc[40..72] != authority.key.to_bytes()
        || position >= u32_at(&doc, 72)?
        || data[37..69] == [0; 32]
    {
        return Err(refuse(FORM));
    }
    let count = u16_at(&doc, 76)? as usize;
    let stride = 32 + 6 * count;
    let header = document_header(u16_at(&doc, 4)?)?;
    let offset = header + position as usize * stride;
    if data.len() != 69 + 6 * count
        || doc.len() != header + u32_at(&doc, 72)? as usize * stride
        || doc[offset..offset + stride] != vec![0; stride]
    {
        return Err(refuse(FORM));
    }
    let mut last = None;
    for row in data[69..].chunks_exact(6) {
        let id = u16_at(row, 0)?;
        if u32_at(row, 2)? == 0 || last.is_some_and(|previous| previous >= id) {
            return Err(refuse(FORM));
        }
        last = Some(id);
    }
    drop(doc);
    document.try_borrow_mut_data()?[offset..offset + stride].copy_from_slice(&data[37..]);
    Ok(())
}

/// tag 97: digest32. Validate the entire uploaded manifest before arming.
/// A v4 document names its completed DEA1 admission record as a third
/// account; v2 and v3 documents take exactly two.
pub fn seal_v2(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 2 | 3) || data.len() != 33 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let authority = &accounts[0];
    let document = &accounts[1];
    if !authority.is_signer
        || !document.is_writable
        || document.owner != program
        || *document.key != document_address(program, &digest).0
    {
        return Err(refuse(AUTHORITY));
    }
    let doc = document.try_borrow_data()?;
    if doc[..4] != *b"DCM2"
        || !matches!(u16_at(&doc, 4)?, 2 | 3 | 4)
        || u16_at(&doc, 6)? & !root_only::MODE_FLAG != 0
        || doc[8..40] != digest
        || doc[40..72] != authority.key.to_bytes()
    {
        return Err(refuse(FORM));
    }
    let count = u16_at(&doc, 76)? as usize;
    let positions = u32_at(&doc, 72)? as usize;
    let stride = 32 + 6 * count;
    let header = document_header(u16_at(&doc, 4)?)?;
    if count == 0 || positions == 0 || doc.len() != header + positions * stride {
        return Err(refuse(FORM));
    }
    if (u16_at(&doc, 4)? == 4) != (accounts.len() == 3) {
        return Err(refuse(FORM));
    }
    if accounts.len() == 3 {
        let admission = envelope_seal::admission_view(program, &accounts[2])?;
        if accounts[2].key.as_ref() != &doc[424..456]
            || admission.registry[..] != doc[360..392]
            || admission.root[..] != doc[392..424]
            || admission.state[..] != doc[200..232]
            || admission.state_sha256[..] != doc[232..264]
        {
            return Err(refuse(envelope_seal::ADMISSION_STATE));
        }
        if !admission.complete {
            return Err(refuse(envelope_seal::ADMISSION_STATE));
        }
    }
    let mut total = 0u64;
    for block in doc[header..].chunks_exact(stride) {
        if block[..32] == [0; 32] {
            return Err(refuse(FORM));
        }
        let mut last = None;
        for row in block[32..].chunks_exact(6) {
            let id = u16_at(row, 0)?;
            let entries = u32_at(row, 2)?;
            if entries == 0 || last.is_some_and(|previous| previous >= id) {
                return Err(refuse(FORM));
            }
            last = Some(id);
            total = total.checked_add(entries as u64).ok_or(refuse(FORM))?;
        }
    }
    if total != u64::from_le_bytes(doc[192..200].try_into().map_err(|_| refuse(FORM))?) {
        return Err(refuse(FORM));
    }
    drop(doc);
    let mode = u16_at(&document.try_borrow_data()?, 6)? & root_only::MODE_FLAG;
    document.try_borrow_mut_data()?[6..8].copy_from_slice(&(1u16 | mode).to_le_bytes());
    Ok(())
}

/// tag 130: descriptor32 | group:u32 | slot counts for every in-range
/// position of this 64-position group. Testnet bootstrap declarations are
/// not a replacement for PT1-derived family slot counts at canonical seal.
/// Accounts: authority, DCM2, DSR1, DSC1, system. A sealed document
/// (`root_only_sealed`) sends no counts and passes its DFT1 as a sixth
/// account: every position expects the table's slots per position.
pub fn init_root_group(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 5 | 6) || data.len() < 37 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let group = u32_at(data, 33)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    let sealed = crate::root_only_sealed::is_sealed(&accounts[1])?;
    if sealed != (accounts.len() == 6) || (sealed && data.len() != 37) {
        return Err(refuse(FORM));
    }
    let derived = if sealed {
        Some(crate::root_only_sealed::expected_slots(
            program,
            &accounts[5],
            &digest,
        )?)
    } else {
        None
    };
    let doc = accounts[1].try_borrow_data()?;
    if u16_at(&doc, 4)? != if sealed { 3 } else { 2 }
        || u16_at(&doc, 6)? & root_only::MODE_FLAG == 0
    {
        return Err(refuse(FORM));
    }
    let positions = u32_at(&doc, 72)?;
    let first = group.checked_mul(64).ok_or(refuse(COORDINATE))?;
    if first >= positions {
        return Err(refuse(COORDINATE));
    }
    let in_group = (positions - first).min(64) as usize;
    if !sealed && data.len() != 37 + in_group * 4 {
        return Err(refuse(FORM));
    }
    let segments = u16_at(&doc, 76)?;
    let (root_key, root_bump) = root_only::root_page_address(program, &digest, group);
    let (slots_key, slots_bump) = root_only::slot_counter_address(program, &digest, group);
    if *accounts[2].key != root_key || *accounts[3].key != slots_key {
        return Err(refuse(FORM));
    }
    let root_size = root_only::root_page_bytes(segments)?;
    let group_bytes = group.to_le_bytes();
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[4],
        &[b"dcg-hcl-roots", &digest, &group_bytes, &[root_bump]],
        root_size.min(GROW_MAX),
        root_size,
    )?;
    create(
        program,
        &accounts[0],
        &accounts[3],
        &accounts[4],
        &[b"dcg-hcl-slots", &digest, &group_bytes, &[slots_bump]],
        root_only::DSC1_BYTES,
        root_only::DSC1_BYTES,
    )?;
    let mut roots = accounts[2].try_borrow_mut_data()?;
    roots[..4].copy_from_slice(b"DSR1");
    roots[4..6].copy_from_slice(&1u16.to_le_bytes());
    roots[8..40].copy_from_slice(&digest);
    roots[40..44].copy_from_slice(&group_bytes);
    roots[44..46].copy_from_slice(&segments.to_le_bytes());
    let mut slots = accounts[3].try_borrow_mut_data()?;
    slots[..4].copy_from_slice(b"DSC1");
    slots[4..6].copy_from_slice(&1u16.to_le_bytes());
    slots[8..40].copy_from_slice(&digest);
    slots[40..44].copy_from_slice(&group_bytes);
    for i in 0..in_group {
        let count = match derived {
            Some(n) => n,
            None => u32_at(data, 37 + i * 4)?,
        };
        slots[48 + i * 8..52 + i * 8].copy_from_slice(&count.to_le_bytes());
    }
    Ok(())
}

/// tag 110: descriptor32 | group:u32. Grow DSR1 by at most 10,240 bytes.
/// Accounts: authority, DCM2, DSR1.
pub fn grow_root_group(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 37 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let group = u32_at(data, 33)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    let doc = accounts[1].try_borrow_data()?;
    if !matches!(u16_at(&doc, 4)?, 2 | 3) || u16_at(&doc, 6)? & root_only::MODE_FLAG == 0 {
        return Err(refuse(FORM));
    }
    let size = root_only::root_page_bytes(u16_at(&doc, 76)?)?;
    if *accounts[2].key != root_only::root_page_address(program, &digest, group).0
        || accounts[2].owner != program
        || !accounts[2].is_writable
    {
        return Err(refuse(FORM));
    }
    let roots = accounts[2].try_borrow_data()?;
    if roots.len() < 48
        || roots.len() >= size
        || roots[..4] != *b"DSR1"
        || roots[8..40] != digest
        || u32_at(&roots, 40)? != group
        || u16_at(&roots, 44)? != u16_at(&doc, 76)?
    {
        return Err(refuse(FORM));
    }
    let next = size.min(roots.len() + GROW_MAX);
    drop(roots);
    drop(doc);
    accounts[2].realloc(next, true)
}

/// tag 91: digest32 | position:u32 | segment:u16 | consumers:u32.
/// Accounts: payer/authority, document PDA, page PDA, system.
pub fn init_page(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || data.len() != 43 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let position = u32_at(data, 33)?;
    let segment = u16_at(data, 37)?;
    let consumers = u32_at(data, 39)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    let doc = accounts[1].try_borrow_data()?;
    if u16_at(&doc, 6)? & root_only::MODE_FLAG != 0 {
        return Err(refuse(FORM));
    }
    if position >= u32_at(&doc, 72)? {
        return Err(refuse(COORDINATE));
    }
    let version = u16_at(&doc, 4)?;
    let base = if version == 1 {
        DCM2_HEADER
    } else {
        document_header(version)? + position as usize * (32 + u16_at(&doc, 76)? as usize * 6) + 32
    };
    let limit = if version == 1 {
        u32_at(&doc, 80)? as u64
    } else {
        u64::from_le_bytes(doc[192..200].try_into().map_err(|_| refuse(FORM))?)
    };
    if consumers as u64 > limit {
        return Err(refuse(COORDINATE));
    }
    let mut entries = None;
    for row in doc[base..base + u16_at(&doc, 76)? as usize * 6].chunks_exact(6) {
        if u16_at(row, 0)? == segment {
            entries = Some(u32_at(row, 2)?);
            break;
        }
    }
    let entries = entries.ok_or(refuse(COORDINATE))?;
    let (key, bump) = page_address(program, &digest, position, segment);
    if *accounts[2].key != key {
        return Err(refuse(FORM));
    }
    let bump_bytes = [bump];
    let p_bytes = position.to_le_bytes();
    let s_bytes = segment.to_le_bytes();
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[b"dcg-hcl-page", &digest, &p_bytes, &s_bytes, &bump_bytes],
        96,
        page_bytes(entries, consumers)?,
    )?;
    let mut page = accounts[2].try_borrow_mut_data()?;
    page[..4].copy_from_slice(b"DLP2");
    page[4..6].copy_from_slice(&1u16.to_le_bytes());
    page[8..40].copy_from_slice(&digest);
    page[40..44].copy_from_slice(&p_bytes);
    page[44..46].copy_from_slice(&s_bytes);
    page[48..52].copy_from_slice(&entries.to_le_bytes());
    page[56..60].copy_from_slice(&consumers.to_le_bytes());
    Ok(())
}

/// tag 92: digest32 | position:u32 | segment:u16. Accounts: authority, doc, page.
/// Repeated calls grow one page by at most 10,240 bytes until exact size.
pub fn grow_page(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 39 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let position = u32_at(data, 33)?;
    let segment = u16_at(data, 37)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    if u16_at(&accounts[1].try_borrow_data()?, 6)? & root_only::MODE_FLAG != 0 {
        return Err(refuse(FORM));
    }
    if *accounts[2].key != page_address(program, &digest, position, segment).0
        || accounts[2].owner != program
        || !accounts[2].is_writable
    {
        return Err(refuse(FORM));
    }
    let page = accounts[2].try_borrow_data()?;
    if page.len() < 96
        || page[..4] != *b"DLP2"
        || page[8..40] != digest
        || u32_at(&page, 40)? != position
        || u16_at(&page, 44)? != segment
        || u16_at(&page, 6)? != 0
        || u32_at(&page, 52)? != 0
        || page[64..96] != [0; 32]
    {
        return Err(refuse(FORM));
    }
    let target = page_bytes(u32_at(&page, 48)?, u32_at(&page, 56)?)?;
    let old = page.len();
    if old >= target {
        return Err(refuse(COORDINATE));
    }
    drop(page);
    accounts[2].realloc(core::cmp::min(target, old + GROW_MAX), true)
}

const ROOTS_HEADER: usize = 48;
fn roots_bytes(segments: usize) -> Result<usize, ProgramError> {
    ROOTS_HEADER
        .checked_add(segments.checked_mul(32).ok_or(refuse(FORM))?)
        .ok_or(refuse(FORM))
}
fn roots_address(program: &Pubkey, digest: &[u8; 32], position: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dcg-hcl-roots", digest, &position.to_le_bytes()],
        program,
    )
}

/// tag 93: digest32 | position:u32 | segment:u16. Accounts: authority, doc,
/// finalized page, roots PDA (writable), system. The first call creates the
/// roots PDA. Each later call records one immutable segment root.
pub fn collect_root(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 5 || data.len() != 39 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let position = u32_at(data, 33)?;
    let segment = u16_at(data, 37)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    let doc = accounts[1].try_borrow_data()?;
    if position >= u32_at(&doc, 72)?
        || *accounts[2].key != page_address(program, &digest, position, segment).0
        || accounts[2].owner != program
    {
        return Err(refuse(FORM));
    }
    let count = u16_at(&doc, 76)? as usize;
    let version = u16_at(&doc, 4)?;
    let base = if version == 1 {
        DCM2_HEADER
    } else {
        document_header(version)? + position as usize * (32 + count * 6) + 32
    };
    let mut index = None;
    for (i, row) in doc[base..base + count * 6].chunks_exact(6).enumerate() {
        if u16_at(row, 0)? == segment {
            index = Some((i, u32_at(row, 2)?));
            break;
        }
    }
    let (index, expected) = index.ok_or(refuse(COORDINATE))?;
    let page = accounts[2].try_borrow_data()?;
    if page.len() < 96
        || page[..4] != *b"DLP2"
        || page[8..40] != digest
        || u32_at(&page, 40)? != position
        || u16_at(&page, 44)? != segment
        || u16_at(&page, 6)? != 1
        || u32_at(&page, 48)? != expected
        || u32_at(&page, 52)? != expected
        || page[64..96] == [0; 32]
    {
        return Err(refuse(FORM));
    }
    let root: [u8; 32] = page[64..96].try_into().map_err(|_| refuse(FORM))?;
    drop(page);
    let (key, bump) = roots_address(program, &digest, position);
    if *accounts[3].key != key || !accounts[3].is_writable {
        return Err(refuse(FORM));
    }
    if accounts[3].lamports() == 0 {
        let position_bytes = position.to_le_bytes();
        let bump_bytes = [bump];
        create(
            program,
            &accounts[0],
            &accounts[3],
            &accounts[4],
            &[b"dcg-hcl-roots", &digest, &position_bytes, &bump_bytes],
            roots_bytes(count)?,
            roots_bytes(count)?,
        )?;
        let mut roots = accounts[3].try_borrow_mut_data()?;
        roots[..4].copy_from_slice(b"DSR2");
        roots[4..6].copy_from_slice(&1u16.to_le_bytes());
        roots[8..40].copy_from_slice(&digest);
        roots[40..44].copy_from_slice(&position_bytes);
    }
    if accounts[3].owner != program {
        return Err(refuse(FORM));
    }
    let mut roots = accounts[3].try_borrow_mut_data()?;
    let offset = ROOTS_HEADER + index * 32;
    if roots.len() != roots_bytes(count)?
        || roots[..4] != *b"DSR2"
        || roots[8..40] != digest
        || u32_at(&roots, 40)? != position
        || roots[offset..offset + 32] != [0; 32]
    {
        return Err(refuse(FORM));
    }
    let next = u16_at(&roots, 6)?.checked_add(1).ok_or(refuse(FORM))?;
    if next as usize > count {
        return Err(refuse(FORM));
    }
    roots[offset..offset + 32].copy_from_slice(&root);
    roots[6..8].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

/// tag 94: digest32 | position:u32. Accounts: authority, doc(w), DPR2(w),
/// collected roots PDA. All authenticated segment roots are folded.
pub fn finalize_from_roots(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 4 || data.len() != 37 {
        return Err(refuse(FORM));
    }
    let digest = descriptor(data)?;
    let position = u32_at(data, 33)?;
    doc_authority(program, &accounts[1], &accounts[0], &digest)?;
    if !accounts[1].is_writable
        || !accounts[2].is_writable
        || *accounts[2].key != position_page_address(program, &digest).0
        || accounts[2].owner != program
        || *accounts[3].key != roots_address(program, &digest, position).0
        || accounts[3].owner != program
    {
        return Err(refuse(FORM));
    }
    let doc = accounts[1].try_borrow_data()?;
    let pos = accounts[2].try_borrow_data()?;
    let roots = accounts[3].try_borrow_data()?;
    let position_count = u32_at(&doc, 72)?;
    let segment_count = u16_at(&doc, 76)? as usize;
    if position >= position_count
        || position != u32_at(&doc, 84)?
        || u32_at(&pos, 44)? != position
        || pos.len() != DPR2_HEADER + position_count as usize * 32
        || pos[..4] != *b"DPR2"
        || pos[8..40] != digest
        || roots.len() != roots_bytes(segment_count)?
        || roots[..4] != *b"DSR2"
        || roots[8..40] != digest
        || u32_at(&roots, 40)? != position
        || u16_at(&roots, 6)? as usize != segment_count
    {
        return Err(refuse(FORM));
    }
    let slot = DPR2_HEADER + position as usize * 32;
    if pos[slot..slot + 32] != [0; 32] {
        return Err(refuse(FORM));
    }
    let mut values = Vec::with_capacity(segment_count);
    for root in roots[ROOTS_HEADER..].chunks_exact(32) {
        if root == [0; 32] {
            return Err(refuse(FORM));
        }
        values.push(root.try_into().map_err(|_| refuse(FORM))?);
    }
    let segment_table_root: [u8; 32] = if u16_at(&doc, 4)? == 1 {
        doc[152..184].try_into().map_err(|_| refuse(FORM))?
    } else {
        let offset =
            document_header(u16_at(&doc, 4)?)? + position as usize * (32 + segment_count * 6);
        doc[offset..offset + 32]
            .try_into()
            .map_err(|_| refuse(FORM))?
    };
    let position_entries: u64 = if u16_at(&doc, 4)? == 1 {
        u32_at(&doc, 80)? as u64
    } else {
        let offset =
            document_header(u16_at(&doc, 4)?)? + position as usize * (32 + segment_count * 6) + 32;
        let mut sum = 0u64;
        for row in doc[offset..offset + segment_count * 6].chunks_exact(6) {
            sum = sum
                .checked_add(u32_at(row, 2)? as u64)
                .ok_or(refuse(FORM))?;
        }
        sum
    };
    let next_entries = u64::from_le_bytes(doc[88..96].try_into().map_err(|_| refuse(FORM))?)
        .checked_add(position_entries)
        .ok_or(refuse(FORM))?;
    let position_digest = position_root(&digest, position, &segment_table_root, &values)?;
    drop(roots);
    drop(pos);
    drop(doc);
    let mut pos = accounts[2].try_borrow_mut_data()?;
    pos[slot..slot + 32].copy_from_slice(&position_digest);
    pos[44..48].copy_from_slice(&(position + 1).to_le_bytes());
    drop(pos);
    let mut doc = accounts[1].try_borrow_mut_data()?;
    doc[84..88].copy_from_slice(&(position + 1).to_le_bytes());
    doc[88..96].copy_from_slice(&next_entries.to_le_bytes());
    Ok(())
}
