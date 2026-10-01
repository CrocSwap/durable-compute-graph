//! Sealed ROOT_ONLY documents: the descriptor digest, the per-position
//! manifest and the DSC1 family-slot counts come from sealed PT1 bytes and a
//! descriptor-bound family table, not from the executor.
//!
//! * tag 137 `InitSealed` recomputes the DPD1 descriptor (see
//!   `src/basanos/dcg/sealed_descriptor.py`) from the phase-3 PT1 state, its
//!   three byte accounts, the DCM2 v3 anchors, the clause-12 storage mode,
//!   the per-run dispute window and the DFT1 family table, and creates the
//!   DCM2 v3 / DPR2 / DFT1 accounts at that digest's PDAs.
//! * tag 138 `BindManifest` copies the clause-12 segment rows and segment
//!   table root into consecutive position blocks (growing DCM2 in bounded
//!   steps) and arms the document when the last position is bound.
//! * tag 139 `LandFamilySlot` proves a family-slot producer leaf against its
//!   landed segment root, stores it as DPL1 and counts the number of DFT1
//!   slots that name the producer's template entry.
//!
//! DCM2 flag 32 marks a sealed document. The bootstrap v2 manifest tags
//! (96, 97, 108) refuse it (their flag mask admits only ROOT_ONLY), and the
//! bootstrap producer feed (136) refuses it. Refusals reuse 580-599.
use crate::account_provenance::CanonicalBump;
use crate::closure_v2::{
    self as h, document_address, position_page_address, DCM2_V3_HEADER, DPR2_HEADER,
};
use crate::closure_v2_accounts::create;
use crate::{hash, position_template as pt, root_only as r};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

pub const TAG_INIT_SEALED: u8 = 137;
pub const TAG_BIND_MANIFEST: u8 = 138;
pub const TAG_LAND_FAMILY_SLOT: u8 = 139;
pub const SEALED_FLAG: u16 = 32;
pub const DOMAIN: &[u8] = b"basanos/dcg-pt1-sealed-descriptor/1";
pub const DFT1_HEADER: usize = 48;
const GROW_MAX: usize = 10_240;
const CLAUSE5_HEADER: usize = 80;

fn refuse(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
fn u16_at(raw: &[u8], at: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        raw.get(at..at + 2)
            .ok_or(refuse(h::FORM))?
            .try_into()
            .map_err(|_| refuse(h::FORM))?,
    ))
}
fn u32_at(raw: &[u8], at: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        raw.get(at..at + 4)
            .ok_or(refuse(h::FORM))?
            .try_into()
            .map_err(|_| refuse(h::FORM))?,
    ))
}
fn u64_at(raw: &[u8], at: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        raw.get(at..at + 8)
            .ok_or(refuse(h::FORM))?
            .try_into()
            .map_err(|_| refuse(h::FORM))?,
    ))
}

pub fn family_table_address(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-families", descriptor], program)
}

/// One DFT1 row: `(family_ordinal, region_id, slot rows)`; a slot row is
/// `template_entry:u32 | write_row_ordinal:u8`.
pub struct Family<'a> {
    pub ordinal: u16,
    pub region: u16,
    pub slots: &'a [u8],
}

/// Exact-EOF parse of a DFT1 body with ascending family ordinals.
pub fn families(body: &[u8]) -> Result<Vec<Family<'_>>, ProgramError> {
    let (out, at) = families_prefix(body)?;
    if at != body.len() {
        return Err(refuse(h::FORM));
    }
    Ok(out)
}

/// The same parse, returning the families and the number of bytes they
/// occupy, so a caller whose instruction data carries a tail after the body
/// can split the two. Revision 8's UnifiedInit appends the typed-decision
/// option table after the DFS2 body; every other caller wants `families`.
pub fn families_prefix(body: &[u8]) -> Result<(Vec<Family<'_>>, usize), ProgramError> {
    let count = u16_at(body, 0)? as usize;
    let mut at = 2usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let ordinal = u16_at(body, at)?;
        let region = u16_at(body, at + 2)?;
        let n = u16_at(body, at + 4)? as usize;
        let end = at.checked_add(6 + 5 * n).ok_or(refuse(h::OVERFLOW))?;
        if n == 0
            || (i > 0 && ordinal <= out.last().map(|f: &Family| f.ordinal).unwrap_or(0))
            || end > body.len()
        {
            return Err(refuse(h::FORM));
        }
        out.push(Family {
            ordinal,
            region,
            slots: &body[at + 6..end],
        });
        at = end;
    }
    if count == 0 {
        return Err(refuse(h::FORM));
    }
    Ok((out, at))
}

/// Every family slot is produced once per position.
pub fn slots_per_position(body: &[u8]) -> Result<u32, ProgramError> {
    families(body)?.iter().try_fold(0u32, |n, f| {
        n.checked_add((f.slots.len() / 5) as u32)
            .ok_or(refuse(h::OVERFLOW))
    })
}

/// Number of DFT1 slots whose producer is template entry `entry`.
pub fn slots_of_entry(body: &[u8], entry: u32) -> Result<u32, ProgramError> {
    let mut n = 0u32;
    for f in families(body)? {
        for slot in f.slots.chunks_exact(5) {
            if u32_at(slot, 0)? == entry {
                n = n.checked_add(1).ok_or(refuse(h::OVERFLOW))?;
            }
        }
    }
    Ok(n)
}

/// DPD1 descriptor digest; the Python twin is `basanos.dcg.sealed_descriptor`.
#[allow(clippy::too_many_arguments)]
pub fn descriptor_digest(
    mode: u8,
    positions: u32,
    segments: u16,
    total: u64,
    window: u64,
    clause5: &[u8],
    clause12: &[u8],
    payloads: &[u8],
    model: &[u8],
    position_table: &[u8],
    prompt: &[u8],
    family_body: &[u8],
) -> Result<[u8; 32], ProgramError> {
    let header = clause5.get(..CLAUSE5_HEADER).ok_or(refuse(h::FORM))?;
    Ok(hash::sha256(&[
        DOMAIN,
        &[mode],
        &positions.to_le_bytes(),
        &segments.to_le_bytes(),
        &total.to_le_bytes(),
        &window.to_le_bytes(),
        header,
        &hash::sha256(&[clause12]),
        &hash::sha256(&[payloads]),
        model,
        position_table,
        prompt,
        &hash::sha256(&[family_body]),
    ]))
}

fn template<'a>(
    routes: &'a [u8],
    geometry: &'a [u8],
) -> Result<(pt::Template<'a>, pt::Clause12<'a>), ProgramError> {
    let (entries, _) = pt::route_header(routes).map_err(refuse)?;
    let (clause, _) = pt::clause12_layout(geometry).map_err(refuse)?;
    if entries != clause.entries_per_position {
        return Err(refuse(h::FORM));
    }
    Ok((
        pt::Template {
            clause5: routes,
            clause12: geometry,
            position_count: clause.position_count,
            prompt_positions: clause.prompt_positions,
            max_producer_delta: clause.max_producer_delta,
            entries_per_position: entries,
            leaf_storage_mode: clause.leaf_storage_mode,
        },
        clause,
    ))
}

/// The phase-3 PT1 state and its byte accounts; `anchor` is the DCM2 v3
/// header when the state must be the one the document pinned at creation.
fn pt1_accounts(
    program: &Pubkey,
    accounts: &[AccountInfo],
    anchor: Option<&[u8]>,
) -> ProgramResult {
    for a in accounts {
        if a.owner != program || a.is_writable {
            return Err(refuse(h::FORM));
        }
    }
    let state = accounts[0].try_borrow_data()?;
    if !crate::pt1_onchain::is_sealed_template(&state) {
        return Err(refuse(h::FORM));
    }
    for kind in 0..accounts.len() - 1 {
        if accounts[kind + 1].key.as_ref() != &state[37 + 32 * kind..69 + 32 * kind]
            || accounts[kind + 1].data_len() != u32_at(&state, 133 + 4 * kind)? as usize
        {
            return Err(refuse(h::FORM));
        }
    }
    if let Some(doc) = anchor {
        // PT1S is immutable after phase 3, so the pinned key fixes its bytes.
        if accounts[0].key.as_ref() != &doc[200..232] {
            return Err(refuse(h::FORM));
        }
    }
    Ok(())
}

fn sealed_document(
    program: &Pubkey,
    document: &AccountInfo,
    descriptor: &[u8; 32],
) -> ProgramResult {
    if document.owner != program || *document.key != document_address(program, descriptor).0 {
        return Err(refuse(h::FORM));
    }
    let doc = document.try_borrow_data()?;
    if doc.len() < DCM2_V3_HEADER
        || doc[..4] != *b"DCM2"
        || u16_at(&doc, 4)? != 3
        || doc[8..40] != *descriptor
        || u16_at(&doc, 6)? & SEALED_FLAG == 0
        || u16_at(&doc, 6)? & r::MODE_FLAG == 0
    {
        return Err(refuse(h::FORM));
    }
    Ok(())
}

/// DFT1 of a sealed document; returns its body.
fn family_table<'a>(
    program: &Pubkey,
    account: &'a AccountInfo,
    descriptor: &[u8; 32],
) -> Result<core::cell::Ref<'a, [u8]>, ProgramError> {
    if account.owner != program || *account.key != family_table_address(program, descriptor).0 {
        return Err(refuse(h::FORM));
    }
    let raw = account.try_borrow_data()?;
    if raw.len() < DFT1_HEADER
        || raw[..4] != *b"DFT1"
        || u16_at(&raw, 4)? != 1
        || raw[6..8] != [0; 2]
        || raw[8..40] != *descriptor
        || u32_at(&raw, 44)? as usize != raw.len() - DFT1_HEADER
    {
        return Err(refuse(h::FORM));
    }
    Ok(core::cell::Ref::map(raw, |r| &r[DFT1_HEADER..]))
}

/// Refused on a sealed document by instructions whose inputs the sealed
/// path derives on chain (bootstrap producer feed, caller slot counts).
pub fn refuse_sealed(document: &AccountInfo) -> ProgramResult {
    let doc = document.try_borrow_data()?;
    if doc.len() >= 8 && u16_at(&doc, 6)? & SEALED_FLAG != 0 {
        return Err(refuse(h::FORM));
    }
    Ok(())
}
pub fn is_sealed(document: &AccountInfo) -> Result<bool, ProgramError> {
    let doc = document.try_borrow_data()?;
    Ok(doc.len() >= 8 && u16_at(&doc, 6)? & SEALED_FLAG != 0)
}
/// DSC1 expected slots per position of a sealed document (tag 130).
pub fn expected_slots(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
) -> Result<u32, ProgramError> {
    let body = family_table(program, account, descriptor)?;
    slots_per_position(&body)
}

/// tag 137: window:u64 | model_root32 | position_table_root32 |
/// prompt_commitment32 | DFT1 body. Accounts: authority(s,w), DCM2(w),
/// DPR2(w), system, PT1S, clause-5 routes, clause-12 geometry, payload
/// table, DFT1(w). The storage mode is the sealed clause-12 byte and must be
/// ROOT_ONLY in this increment.
pub fn init_sealed(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 9 || data.len() < 1 + 8 + 96 + 2 {
        return Err(refuse(h::FORM));
    }
    pt1_accounts(program, &accounts[4..8], None)?;
    let window = u64_at(data, 1)?;
    let (model, table, prompt) = (&data[9..41], &data[41..73], &data[73..105]);
    let body = &data[105..];
    if window == 0 || [model, table, prompt].iter().any(|a| *a == [0; 32]) {
        return Err(refuse(h::FORM));
    }
    let routes = accounts[5].try_borrow_data()?;
    let geometry = accounts[6].try_borrow_data()?;
    let payloads = accounts[7].try_borrow_data()?;
    let (t, clause) = template(&routes, &geometry)?;
    let mode = clause.leaf_storage_mode;
    if mode != 1 {
        return Err(refuse(h::FORM));
    }
    let positions = clause.position_count;
    let segments = clause.segment_count;
    let total = (t.entries_per_position as u64)
        .checked_mul(positions as u64)
        .ok_or(refuse(h::OVERFLOW))?;
    // Every slot must name a declared write of its producer entry into the
    // family's region, and no (entry, write) pair may be listed twice.
    let fams = families(body)?;
    let mut seen: Vec<(u32, u8)> = Vec::new();
    for f in &fams {
        for slot in f.slots.chunks_exact(5) {
            let (entry, write) = (u32_at(slot, 0)?, slot[4]);
            let e = t.entry(entry).map_err(refuse)?;
            if write as u16 >= e.write_count || seen.contains(&(entry, write)) {
                return Err(refuse(h::SLOT));
            }
            let route = t
                .instantiate_with(clause, entry, 0)
                .map_err(refuse)?
                .route(e.read_count + write as u16)
                .map_err(refuse)?;
            if route.direction != 1 || route.region_id != f.region {
                return Err(refuse(h::SLOT));
            }
            seen.push((entry, write));
        }
    }
    let per_position = slots_per_position(body)?;
    let descriptor = descriptor_digest(
        mode, positions, segments, total, window, &routes, &geometry, &payloads, model, table,
        prompt, body,
    )?;
    let state_hash = hash::sha256(&[&accounts[4].try_borrow_data()?]);
    drop((routes, geometry, payloads));
    let doc_bump = CanonicalBump::find(&[b"dcg-hcl-document", &descriptor], program);
    let pos_bump = CanonicalBump::find(&[b"dcg-hcl-positions", &descriptor], program);
    let fam_bump = CanonicalBump::find(&[b"dcg-hcl-families", &descriptor], program);
    if accounts[1].key != doc_bump.address()
        || accounts[2].key != pos_bump.address()
        || accounts[8].key != fam_bump.address()
    {
        return Err(refuse(h::FORM));
    }
    let stride = 32usize
        .checked_add(
            (segments as usize)
                .checked_mul(6)
                .ok_or(refuse(h::OVERFLOW))?,
        )
        .ok_or(refuse(h::OVERFLOW))?;
    let size = DCM2_V3_HEADER
        .checked_add(
            (positions as usize)
                .checked_mul(stride)
                .ok_or(refuse(h::OVERFLOW))?,
        )
        .ok_or(refuse(h::OVERFLOW))?;
    let position_size = DPR2_HEADER
        .checked_add(
            (positions as usize)
                .checked_mul(32)
                .ok_or(refuse(h::OVERFLOW))?,
        )
        .ok_or(refuse(h::OVERFLOW))?;
    if size > 10_485_760 || position_size > 10_485_760 {
        return Err(refuse(h::COORDINATE));
    }
    create(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[3],
        &[b"dcg-hcl-document", &descriptor],
        doc_bump,
        size.min(GROW_MAX),
        size,
    )?;
    create(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[b"dcg-hcl-positions", &descriptor],
        pos_bump,
        position_size.min(GROW_MAX),
        position_size,
    )?;
    let fam_size = DFT1_HEADER + body.len();
    create(
        program,
        &accounts[0],
        &accounts[8],
        &accounts[3],
        &[b"dcg-hcl-families", &descriptor],
        fam_bump,
        fam_size,
        fam_size,
    )?;
    let mut doc = accounts[1].try_borrow_mut_data()?;
    doc[..4].copy_from_slice(b"DCM2");
    doc[4..6].copy_from_slice(&3u16.to_le_bytes());
    doc[6..8].copy_from_slice(&(SEALED_FLAG | r::MODE_FLAG).to_le_bytes());
    doc[8..40].copy_from_slice(&descriptor);
    doc[40..72].copy_from_slice(accounts[0].key.as_ref());
    doc[72..76].copy_from_slice(&positions.to_le_bytes());
    doc[76..78].copy_from_slice(&segments.to_le_bytes());
    doc[184..192].copy_from_slice(&window.to_le_bytes());
    doc[192..200].copy_from_slice(&total.to_le_bytes());
    doc[200..232].copy_from_slice(accounts[4].key.as_ref());
    doc[232..264].copy_from_slice(&state_hash);
    doc[264..296].copy_from_slice(model);
    doc[296..328].copy_from_slice(table);
    doc[328..360].copy_from_slice(prompt);
    drop(doc);
    let mut pos = accounts[2].try_borrow_mut_data()?;
    pos[..4].copy_from_slice(b"DPR2");
    pos[4..6].copy_from_slice(&1u16.to_le_bytes());
    pos[8..40].copy_from_slice(&descriptor);
    pos[40..44].copy_from_slice(&positions.to_le_bytes());
    drop(pos);
    let mut fam = accounts[8].try_borrow_mut_data()?;
    fam[..4].copy_from_slice(b"DFT1");
    fam[4..6].copy_from_slice(&1u16.to_le_bytes());
    fam[8..40].copy_from_slice(&descriptor);
    fam[40..44].copy_from_slice(&per_position.to_le_bytes());
    fam[44..48].copy_from_slice(&(body.len() as u32).to_le_bytes());
    fam[DFT1_HEADER..].copy_from_slice(body);
    Ok(())
}

/// tag 138: descriptor32 | first:u32 | count:u16. Accounts: authority(s),
/// DCM2(w), PT1S, clause-12 geometry. Grows DCM2 by at most 10,240
/// bytes, then fills position blocks `[first, first + count)` in order from
/// the sealed clause-12 segment table; the last block arms the document.
pub fn bind_manifest(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || data.len() != 39 {
        return Err(refuse(h::FORM));
    }
    let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refuse(h::FORM))?;
    let first = u32_at(data, 33)?;
    let count = u16_at(data, 37)? as u32;
    sealed_document(program, &accounts[1], &descriptor)?;
    let (full, positions, stride) = {
        let doc = accounts[1].try_borrow_data()?;
        if !accounts[0].is_signer
            || !accounts[1].is_writable
            || doc[40..72] != accounts[0].key.to_bytes()
            || u16_at(&doc, 6)? & 1 != 0
        {
            return Err(refuse(h::AUTHORITY));
        }
        pt1_accounts(program, &accounts[2..3], Some(&doc))?;
        let positions = u32_at(&doc, 72)?;
        let stride = 32 + 6 * u16_at(&doc, 76)? as usize;
        (
            DCM2_V3_HEADER + positions as usize * stride,
            positions,
            stride,
        )
    };
    {
        let state = accounts[2].try_borrow_data()?;
        if accounts[3].owner != program
            || accounts[3].key.as_ref() != &state[69..101]
            || accounts[3].data_len() != u32_at(&state, 137)? as usize
        {
            return Err(refuse(h::FORM));
        }
    }
    let len = accounts[1].data_len();
    if len < full {
        accounts[1].realloc(full.min(len + GROW_MAX), true)?;
    }
    let end = first.checked_add(count).ok_or(refuse(h::OVERFLOW))?;
    if count == 0
        || end > positions
        || DCM2_V3_HEADER + end as usize * stride > accounts[1].data_len()
    {
        return Err(refuse(h::COORDINATE));
    }
    let geometry = accounts[3].try_borrow_data()?;
    let (clause, _) = pt::clause12_layout(&geometry).map_err(refuse)?;
    let segments = clause.segment_count as usize;
    let mut block = vec![0u8; stride];
    block[..32].copy_from_slice(&geometry[19..51]);
    for i in 0..segments {
        let row = &geometry[59 + 43 * i..59 + 43 * (i + 1)];
        block[32 + 6 * i..34 + 6 * i].copy_from_slice(&row[0..2]);
        block[34 + 6 * i..38 + 6 * i].copy_from_slice(&row[7..11]);
    }
    drop(geometry);
    let mut doc = accounts[1].try_borrow_mut_data()?;
    if stride != 32 + 6 * segments
        || (first > 0
            && doc[DCM2_V3_HEADER + (first as usize - 1) * stride
                ..DCM2_V3_HEADER + first as usize * stride][..32]
                == [0; 32])
    {
        return Err(refuse(h::FINALIZE_ORDER));
    }
    for p in first..end {
        let at = DCM2_V3_HEADER + p as usize * stride;
        if doc[at..at + 32] != [0; 32] {
            return Err(refuse(h::LEAF_WRITTEN));
        }
        doc[at..at + stride].copy_from_slice(&block);
    }
    if end == positions {
        let flags = u16_at(&doc, 6)? | 1;
        doc[6..8].copy_from_slice(&flags.to_le_bytes());
    }
    Ok(())
}

/// tag 139: descriptor32 | position:u32 | template_entry:u32 | leaf32 |
/// height:u8 | sibling[height][32]. Accounts: authority(s,w), DCM2, DPR2,
/// DSR1, DSC1(w), DPL1(w), system, DFT1, PT1S, routes, geometry.
pub fn land_family_slot<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 11 || data.len() < 78 {
        return Err(refuse(h::FORM));
    }
    let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refuse(h::FORM))?;
    let position = u32_at(data, 33)?;
    let entry = u32_at(data, 37)?;
    let leaf: [u8; 32] = data[41..73].try_into().map_err(|_| refuse(h::FORM))?;
    let height = data[73] as usize;
    if data.len() != 74 + 32 * height {
        return Err(refuse(h::FORM));
    }
    sealed_document(program, &accounts[1], &descriptor)?;
    let slots = slots_of_entry(&family_table(program, &accounts[7], &descriptor)?, entry)?;
    if slots == 0 {
        return Err(refuse(h::SLOT));
    }
    let coordinate = {
        let doc = accounts[1].try_borrow_data()?;
        pt1_accounts(program, &accounts[8..11], Some(&doc))?;
        let (routes, geometry) = (
            accounts[9].try_borrow_data()?,
            accounts[10].try_borrow_data()?,
        );
        let (t, _) = template(&routes, &geometry)?;
        let c = t.coordinate(entry).map_err(refuse)?;
        h::Coordinate {
            position,
            segment: c.segment,
            entry: c.local,
        }
    };
    let path: Vec<[u8; 32]> = data[74..]
        .chunks_exact(32)
        .map(|v| v.try_into().map_err(|_| refuse(h::FORM)))
        .collect::<Result<_, _>>()?;
    r::land_producer_leaf(
        program,
        &accounts[..7],
        &descriptor,
        coordinate,
        &leaf,
        &path,
        slots,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_table_parses_the_first_document_table() {
        // `scripts/dcg_root_only_sealed_execute.py identity` on rev7.
        let body = hex_bytes("100000001a0001000e0a00000001001b000100fd090000000200220001002716000000030023000100161600000004002a000100432200000005002b00010032220000000600320001005f2e0000000700330001004e2e00000008003a0001007a3a00000009003b000100693a0000000a004200010096460000000b004300010085460000000c004a000100af520000000d004b0001009e520000000e0052000100cc5e0000000f0053000100bb5e000000");
        assert_eq!(families(&body).unwrap().len(), 16);
        assert_eq!(slots_per_position(&body).unwrap(), 16);
        assert_eq!(slots_of_entry(&body, 2574).unwrap(), 1);
        assert_eq!(slots_of_entry(&body, 0).unwrap(), 0);
        let mut bad = body.clone();
        bad.push(0);
        assert!(families(&bad).is_err());
        let mut swapped = body.clone();
        swapped[2] = 5; // family 0 renamed 5 precedes family 1
        assert!(families(&swapped).is_err());
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
