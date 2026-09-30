//! SM1 ROOT_ONLY storage and segment-tree proof mechanics.  The DSR1 and
//! DSC1 accounts are provisioned by the sealed PT1 adapter; no instruction
//! here accepts caller-created geometry as an authority.

use crate::closure_v2::{self as h, Node};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

pub const MODE_FLAG: u16 = 16;
pub const TAG_LAND_SEGMENT_ROOT: u8 = 88;
pub const TAG_FINALIZE_POSITION: u8 = 89;
pub const TAG_LAND_PRODUCER_BOOTSTRAP: u8 = 136;
pub const PATH: u32 = 586;
const DSR1_HEADER: usize = 48;
pub const DSC1_BYTES: usize = 48 + 64 * 8;
// Descriptor and coordinate are bound by the PDA, so the stored record needs
// only an 8-byte header and X. This avoids duplicating 42 bytes per producer.
pub const DPL1_BYTES: usize = 40;

/// Seal-time storage selector. The PT1 descriptor adapter supplies the
/// descriptor-bound mode and whether any envelope has lifecycle class 4.
pub fn validate_storage_mode(mode: u8, has_consensus_row: bool) -> Result<bool, ProgramError> {
    match mode {
        0 => Ok(false),
        1 if !has_consensus_row => Ok(true),
        _ => Err(refuse(h::FORM)),
    }
}

pub fn deterministic_consumer_binding(
    descriptor: &[u8; 32],
    family_ordinal: u16,
    first: u32,
    end: u32,
    slot_bindings: &[u8],
) -> Result<[u8; 32], ProgramError> {
    h::input_binding_digest(
        descriptor,
        family_ordinal,
        0,
        &[0; 32],
        first,
        end,
        slot_bindings,
    )
}

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

pub fn root_page_address(program: &Pubkey, descriptor: &[u8; 32], group: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dcg-hcl-roots", descriptor, &group.to_le_bytes()],
        program,
    )
}
pub fn slot_counter_address(program: &Pubkey, descriptor: &[u8; 32], group: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dcg-hcl-slots", descriptor, &group.to_le_bytes()],
        program,
    )
}
pub fn producer_leaf_address(
    program: &Pubkey,
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"dcg-hcl-producer",
            descriptor,
            &coordinate.position.to_le_bytes(),
            &coordinate.segment.to_le_bytes(),
            &coordinate.entry.to_le_bytes(),
        ],
        program,
    )
}
pub fn stored_producer_leaf(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
) -> Result<[u8; 32], ProgramError> {
    if account.owner != program
        || account.data_len() != DPL1_BYTES
        || *account.key != producer_leaf_address(program, descriptor, coordinate).0
    {
        return Err(refuse(h::FORM));
    }
    let data = account.try_borrow_data()?;
    if data.iter().all(|&byte| byte == 0) {
        return Err(refuse(h::COORDINATE));
    }
    if data[..4] != *b"DPL1"
        || u16_at(&data, 4)? != 1
        || data[6..8] != [0; 2]
        || data[8..40] == [0; 32]
    {
        return Err(refuse(h::FORM));
    }
    Ok(data[8..40].try_into().map_err(|_| refuse(h::FORM))?)
}

/// Called by the PT1 producer adapter after it has authenticated every mapped
/// family slot and updated the shared DSH2 shard(s) in the same transaction.
/// It stores the recomputed X and counts the slots, never the producer entry.
pub fn land_producer_leaf_after_feed(
    program: &Pubkey,
    state: &AccountInfo,
    authority: &AccountInfo,
    document: &AccountInfo,
    positions: &AccountInfo,
    destination: &AccountInfo,
    counter: &AccountInfo,
    descriptor: &[u8; 32],
    entry: &h::InstantiatedEntry<'_>,
    slot_count: u32,
) -> ProgramResult {
    let seal = crate::seal::open_state(program, state, descriptor, h::FORM)
        .map_err(|_| refuse(h::FORM))?;
    if !seal.sealed || !authority.is_signer || authority.key.to_bytes() != seal.authority {
        return Err(refuse(h::AUTHORITY));
    }
    let facts = h::authenticate_document(program, document, descriptor, false)?;
    h::authenticate_positions(program, positions, descriptor, facts.position_count, false)?;
    let coordinate = entry.coordinate;
    if coordinate.position >= facts.position_count {
        return Err(refuse(h::COORDINATE));
    }
    let doc = document.try_borrow_data()?;
    root_mode(&doc)?;
    if u16_at(&doc, 6)? & 2 != 0 {
        return Err(refuse(h::ALREADY_FINAL));
    }
    let base = h::manifest_base(&doc, coordinate.position)?;
    let mut declared = None;
    let mut previous = None;
    for i in 0..facts.segment_count as usize {
        let at = base + i * 6;
        let id = u16_at(&doc, at)?;
        let entries = u32_at(&doc, at + 2)?;
        if previous.is_some_and(|old| old >= id) || entries == 0 {
            return Err(refuse(h::FORM));
        }
        previous = Some(id);
        if id == coordinate.segment {
            declared = Some(entries);
        }
    }
    if coordinate.entry >= declared.ok_or(refuse(h::COORDINATE))? {
        return Err(refuse(h::COORDINATE));
    }
    let pos = positions.try_borrow_data()?;
    let root_at = h::DPR2_HEADER + coordinate.position as usize * 32;
    if pos[root_at..root_at + 32] != [0; 32] {
        return Err(refuse(h::ALREADY_FINAL));
    }
    if slot_count == 0 {
        return Err(refuse(h::SLOT));
    }
    if destination.owner != program
        || !destination.is_writable
        || destination.data_len() != DPL1_BYTES
        || *destination.key != producer_leaf_address(program, descriptor, coordinate).0
    {
        return Err(refuse(h::FORM));
    }
    let record = destination.try_borrow_data()?;
    if record.iter().any(|&b| b != 0) {
        return Err(refuse(h::LEAF_WRITTEN));
    }
    let x = h::leaf(descriptor, entry)?;
    if x == [0; 32] {
        return Err(refuse(h::FORM));
    }
    drop(record);
    drop(pos);
    drop(doc);
    increment_slots(
        program,
        counter,
        descriptor,
        coordinate.position,
        slot_count,
    )?;
    let mut record = destination.try_borrow_mut_data()?;
    record[..4].copy_from_slice(b"DPL1");
    record[4..6].copy_from_slice(&1u16.to_le_bytes());
    record[8..40].copy_from_slice(&x);
    Ok(())
}
pub fn root_page_bytes(segment_count: u16) -> Result<usize, ProgramError> {
    if segment_count == 0 {
        return Err(refuse(h::FORM));
    }
    DSR1_HEADER
        .checked_add(segment_count as usize * (8 + 64 * 32))
        .ok_or(refuse(h::OVERFLOW))
}
fn root_page(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    group: u32,
    segment_count: u16,
    write: bool,
) -> ProgramResult {
    if account.owner != program
        || (write && !account.is_writable)
        || *account.key != root_page_address(program, descriptor, group).0
    {
        return Err(refuse(h::FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() != root_page_bytes(segment_count)?
        || data[..4] != *b"DSR1"
        || u16_at(&data, 4)? != 1
        || data[6..8] != [0; 2]
        || data[8..40] != *descriptor
        || u32_at(&data, 40)? != group
        || u16_at(&data, 44)? != segment_count
        || data[46..48] != [0; 2]
    {
        return Err(refuse(h::FORM));
    }
    Ok(())
}
fn slot_counter(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    group: u32,
    write: bool,
) -> ProgramResult {
    if account.owner != program
        || (write && !account.is_writable)
        || *account.key != slot_counter_address(program, descriptor, group).0
    {
        return Err(refuse(h::FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() != DSC1_BYTES
        || data[..4] != *b"DSC1"
        || u16_at(&data, 4)? != 1
        || data[6..8] != [0; 2]
        || data[8..40] != *descriptor
        || u32_at(&data, 40)? != group
        || data[44..48] != [0; 4]
    {
        return Err(refuse(h::FORM));
    }
    Ok(())
}
fn offset(local: usize, ordinal: usize, count: usize) -> (usize, usize, u8) {
    let bit = local * count + ordinal;
    (
        DSR1_HEADER + bit / 8,
        DSR1_HEADER + count * 8 + bit * 32,
        1 << (bit % 8),
    )
}
fn root_mode(document: &[u8]) -> ProgramResult {
    // Version 2: bootstrap documents. Version 3: sealed documents (tag 137).
    if u16_at(document, 6)? & 1 == 0
        || u16_at(document, 6)? & MODE_FLAG == 0
        || !matches!(u16_at(document, 4)?, 2 | 3)
    {
        return Err(refuse(h::FORM));
    }
    Ok(())
}

/// Membership gate for the existing commit challenge-open adapter. It derives
/// the entry count and segment ordinal from DCM2, never from the path packet.
pub fn landed_segment(
    program: &Pubkey,
    document: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
) -> Result<(u32, [u8; 32]), ProgramError> {
    landed_segment_at(program, document, page, descriptor, position, segment, true)
}

/// As `landed_segment`; `require_final` is false only for the pre-finalize
/// producer feed, which proves membership against an already landed root.
fn landed_segment_at(
    program: &Pubkey,
    document: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    require_final: bool,
) -> Result<(u32, [u8; 32]), ProgramError> {
    let facts = h::authenticate_document(program, document, descriptor, false)?;
    if position >= facts.position_count {
        return Err(refuse(h::COORDINATE));
    }
    let doc = document.try_borrow_data()?;
    root_mode(&doc)?;
    if require_final && u16_at(&doc, 6)? & 2 == 0 {
        return Err(refuse(h::NOT_FINAL));
    }
    let base = h::manifest_base(&doc, position)?;
    let mut found = None;
    let mut previous = None;
    for ordinal in 0..facts.segment_count as usize {
        let at = base + ordinal * 6;
        let id = u16_at(&doc, at)?;
        let entries = u32_at(&doc, at + 2)?;
        if previous.is_some_and(|old| old >= id) || entries == 0 {
            return Err(refuse(h::FORM));
        }
        previous = Some(id);
        if id == segment {
            found = Some((ordinal, entries));
        }
    }
    let (ordinal, entries) = found.ok_or(refuse(h::COORDINATE))?;
    if entries == 0 {
        return Err(refuse(h::FORM));
    }
    let group = position / 64;
    root_page(program, page, descriptor, group, facts.segment_count, false)?;
    let page_data = page.try_borrow_data()?;
    let (bitmap, at, bit) = offset(
        (position % 64) as usize,
        ordinal,
        facts.segment_count as usize,
    );
    if page_data[bitmap] & bit == 0 || page_data[at..at + 32] == [0; 32] {
        return Err(refuse(h::FINALIZE_ORDER));
    }
    Ok((
        entries,
        page_data[at..at + 32]
            .try_into()
            .map_err(|_| refuse(h::FORM))?,
    ))
}

pub fn challenge_leaf_path(
    program: &Pubkey,
    document: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
) -> ProgramResult {
    let (entries, root) = landed_segment(
        program,
        document,
        page,
        descriptor,
        coordinate.position,
        coordinate.segment,
    )?;
    verify_leaf_path(
        descriptor,
        coordinate.position,
        coordinate.segment,
        entries,
        coordinate.entry,
        leaf,
        path,
        &root,
    )
}

/// A successful authenticated mismatch is ready for the existing settlement
/// lifecycle to award the challenger. This helper does not move a bond.
pub fn producer_mismatch(
    program: &Pubkey,
    document: &AccountInfo,
    page: &AccountInfo,
    producer: &AccountInfo,
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
) -> Result<bool, ProgramError> {
    challenge_leaf_path(program, document, page, descriptor, coordinate, leaf, path)?;
    Ok(stored_producer_leaf(program, producer, descriptor, coordinate)? != *leaf)
}

pub fn land_segment_root(
    program: &Pubkey,
    state: &AccountInfo,
    authority: &AccountInfo,
    document: &AccountInfo,
    positions: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    root: &[u8; 32],
) -> ProgramResult {
    if state.key == document.key {
        // The draft testnet bootstrap stores its authority in DCM2. A
        // canonical BDS2 document continues through the sealed-state path.
        let doc = document.try_borrow_data()?;
        if !authority.is_signer || doc.get(40..72) != Some(authority.key.as_ref()) {
            return Err(refuse(h::AUTHORITY));
        }
    } else {
        let seal = crate::seal::open_state(program, state, descriptor, h::FORM)
            .map_err(|_| refuse(h::FORM))?;
        if !seal.sealed || !authority.is_signer || authority.key.to_bytes() != seal.authority {
            return Err(refuse(h::AUTHORITY));
        }
    }
    let facts = h::authenticate_document(program, document, descriptor, false)?;
    h::authenticate_positions(program, positions, descriptor, facts.position_count, false)?;
    let doc = document.try_borrow_data()?;
    root_mode(&doc)?;
    if position >= facts.position_count {
        return Err(refuse(h::COORDINATE));
    }
    let pos = positions.try_borrow_data()?;
    let pos_at = h::DPR2_HEADER + position as usize * 32;
    if pos[pos_at..pos_at + 32] != [0; 32] {
        return Err(refuse(h::ALREADY_FINAL));
    }
    drop(pos);
    let base = h::manifest_base(&doc, position)?;
    let mut ordinal = None;
    let mut previous = None;
    for i in 0..facts.segment_count as usize {
        let at = base + i * 6;
        let id = u16_at(&doc, at)?;
        if previous.is_some_and(|p| p >= id) || u32_at(&doc, at + 2)? == 0 {
            return Err(refuse(h::FORM));
        }
        previous = Some(id);
        if id == segment {
            ordinal = Some(i);
        }
    }
    let ordinal = ordinal.ok_or(refuse(h::COORDINATE))?;
    if *root == [0; 32] {
        return Err(refuse(h::LEAF_WRITTEN));
    }
    let group = position / 64;
    root_page(program, page, descriptor, group, facts.segment_count, true)?;
    let local = (position % 64) as usize;
    let (bitmap, digest, mask) = offset(local, ordinal, facts.segment_count as usize);
    let data = page.try_borrow_data()?;
    if data[bitmap] & mask != 0 || data[digest..digest + 32] != [0; 32] {
        return Err(refuse(h::LEAF_WRITTEN));
    }
    if u16_at(&doc, 6)? & 2 != 0 {
        return Err(refuse(h::ALREADY_FINAL));
    }
    drop(data);
    drop(doc);
    let mut data = page.try_borrow_mut_data()?;
    data[bitmap] |= mask;
    data[digest..digest + 32].copy_from_slice(root);
    Ok(())
}

/// A producer landing calls this only after all declared slot records were
/// authenticated and written.  DSC1 counts slots, including multiple slots
/// from one entry; a duplicate producer slot must have failed in its shard.
pub fn increment_slots(
    program: &Pubkey,
    counter: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    count: u32,
) -> ProgramResult {
    slot_counter(program, counter, descriptor, position / 64, true)?;
    let at = 48 + (position % 64) as usize * 8;
    let data = counter.try_borrow_data()?;
    let expected = u32_at(&data, at)?;
    let landed = u32_at(&data, at + 4)?;
    let next = landed.checked_add(count).ok_or(refuse(h::OVERFLOW))?;
    if count == 0 || next > expected {
        return Err(refuse(h::SLOT));
    }
    drop(data);
    counter.try_borrow_mut_data()?[at + 4..at + 8].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

pub fn finalize_position(
    program: &Pubkey,
    document: &AccountInfo,
    positions: &AccountInfo,
    page: &AccountInfo,
    counter: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
) -> ProgramResult {
    let facts = h::authenticate_document(program, document, descriptor, true)?;
    h::authenticate_positions(program, positions, descriptor, facts.position_count, true)?;
    if position >= facts.position_count {
        return Err(refuse(h::COORDINATE));
    }
    let group = position / 64;
    root_page(program, page, descriptor, group, facts.segment_count, false)?;
    slot_counter(program, counter, descriptor, group, false)?;
    let doc = document.try_borrow_data()?;
    root_mode(&doc)?;
    if u16_at(&doc, 6)? & 2 != 0 {
        return Err(refuse(h::ALREADY_FINAL));
    }
    let pos = positions.try_borrow_data()?;
    let root_at = h::DPR2_HEADER + position as usize * 32;
    if pos[root_at..root_at + 32] != [0; 32] {
        return Err(refuse(h::ALREADY_FINAL));
    }
    if u32_at(&pos, 44)? != facts.positions_complete {
        return Err(refuse(h::FORM));
    }
    let slots = counter.try_borrow_data()?;
    let slot_at = 48 + (position % 64) as usize * 8;
    if u32_at(&slots, slot_at)? != u32_at(&slots, slot_at + 4)? {
        return Err(refuse(h::FINALIZE_ORDER));
    }
    let data = page.try_borrow_data()?;
    let local = (position % 64) as usize;
    let mut roots = Vec::with_capacity(facts.segment_count as usize);
    let mut sum = 0u64;
    let mut previous = None;
    let base = h::manifest_base(&doc, position)?;
    for i in 0..facts.segment_count as usize {
        let at = base + i * 6;
        let id = u16_at(&doc, at)?;
        if previous.is_some_and(|p| p >= id) {
            return Err(refuse(h::FORM));
        }
        previous = Some(id);
        let entries = u32_at(&doc, at + 2)?;
        if entries == 0 {
            return Err(refuse(h::FORM));
        }
        sum = sum.checked_add(entries as u64).ok_or(refuse(h::OVERFLOW))?;
        let (bitmap, digest, mask) = offset(local, i, facts.segment_count as usize);
        if data[bitmap] & mask == 0 || data[digest..digest + 32] == [0; 32] {
            return Err(refuse(h::FINALIZE_ORDER));
        }
        roots.push(
            data[digest..digest + 32]
                .try_into()
                .map_err(|_| refuse(h::FORM))?,
        );
    }
    let next_entries = facts
        .entries_complete
        .checked_add(sum)
        .ok_or(refuse(h::OVERFLOW))?;
    if next_entries > facts.expected_entries {
        return Err(refuse(h::FORM));
    }
    let next_positions = facts
        .positions_complete
        .checked_add(1)
        .ok_or(refuse(h::OVERFLOW))?;
    let table_root: [u8; 32] = doc[base - 32..base]
        .try_into()
        .map_err(|_| refuse(h::FORM))?;
    if table_root == [0; 32] {
        return Err(refuse(h::FORM));
    }
    let root = h::position_root(descriptor, position, &table_root, &roots)?;
    drop(data);
    drop(slots);
    drop(pos);
    drop(doc);
    let mut pos = positions.try_borrow_mut_data()?;
    pos[root_at..root_at + 32].copy_from_slice(&root);
    pos[44..48].copy_from_slice(&next_positions.to_le_bytes());
    drop(pos);
    let mut doc = document.try_borrow_mut_data()?;
    doc[84..88].copy_from_slice(&next_positions.to_le_bytes());
    doc[88..96].copy_from_slice(&next_entries.to_le_bytes());
    Ok(())
}

/// tag 136 (testnet bootstrap producer feed): descriptor32 | position:u32 |
/// segment:u16 | local:u32 | leaf32 | height:u8 | sibling[height][32].
/// Accounts: authority(s,w), DCM2, DPR2, DSR1, DSC1(w), DPL1(w), system.
/// Until the PT1 family-slot adapter exists, one proven producer leaf counts
/// as one slot. The leaf is proven against the landed segment root, so the
/// executor adds no trusted bytes; it only makes X readable on chain.
pub fn land_producer_leaf_bootstrap<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 7 || data.len() < 80 {
        return Err(refuse(h::FORM));
    }
    let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refuse(h::FORM))?;
    let coordinate = h::Coordinate {
        position: u32_at(data, 33)?,
        segment: u16_at(data, 37)?,
        entry: u32_at(data, 39)?,
    };
    let leaf: [u8; 32] = data[43..75].try_into().map_err(|_| refuse(h::FORM))?;
    let height = data[75] as usize;
    if data.len() != 76 + height * 32 || leaf == [0; 32] {
        return Err(refuse(h::FORM));
    }
    let path: Vec<[u8; 32]> = data[76..]
        .chunks_exact(32)
        .map(|v| v.try_into().map_err(|_| refuse(h::FORM)))
        .collect::<Result<_, _>>()?;
    // A sealed document counts DFT1 family slots through tag 139 instead.
    crate::root_only_sealed::refuse_sealed(&accounts[1])?;
    land_producer_leaf(program, accounts, &descriptor, coordinate, &leaf, &path, 1)
}

/// Shared producer landing of tags 136 and 139: prove `leaf` against the
/// landed, not-yet-finalized segment root, store it as DPL1 and add `slots`
/// to the position's DSC1 landed count. Accounts: authority(s,w), DCM2,
/// DPR2, DSR1, DSC1(w), DPL1(w), system.
pub fn land_producer_leaf<'a>(
    program: &Pubkey,
    accounts: &[AccountInfo<'a>],
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    slots: u32,
) -> ProgramResult {
    if accounts.len() != 7 || *leaf == [0; 32] {
        return Err(refuse(h::FORM));
    }
    let descriptor = *descriptor;
    let leaf = *leaf;
    crate::closure_v2_accounts::doc_authority(program, &accounts[1], &accounts[0], &descriptor)?;
    let facts = h::authenticate_document(program, &accounts[1], &descriptor, false)?;
    h::authenticate_positions(
        program,
        &accounts[2],
        &descriptor,
        facts.position_count,
        false,
    )?;
    {
        let doc = accounts[1].try_borrow_data()?;
        if u16_at(&doc, 6)? & 2 != 0 {
            return Err(refuse(h::ALREADY_FINAL));
        }
        let pos = accounts[2].try_borrow_data()?;
        let root_at = h::DPR2_HEADER + coordinate.position as usize * 32;
        if pos
            .get(root_at..root_at + 32)
            .ok_or(refuse(h::COORDINATE))?
            != [0; 32]
        {
            return Err(refuse(h::ALREADY_FINAL));
        }
    }
    let (entries, root) = landed_segment_at(
        program,
        &accounts[1],
        &accounts[3],
        &descriptor,
        coordinate.position,
        coordinate.segment,
        false,
    )?;
    verify_leaf_path(
        &descriptor,
        coordinate.position,
        coordinate.segment,
        entries,
        coordinate.entry,
        &leaf,
        path,
        &root,
    )?;
    let (key, bump) = producer_leaf_address(program, &descriptor, coordinate);
    if *accounts[5].key != key {
        return Err(refuse(h::FORM));
    }
    if accounts[5].lamports() != 0 {
        return Err(refuse(h::LEAF_WRITTEN));
    }
    increment_slots(
        program,
        &accounts[4],
        &descriptor,
        coordinate.position,
        slots,
    )?;
    crate::closure_v2_accounts::create(
        program,
        &accounts[0],
        &accounts[5],
        &accounts[6],
        &[
            b"dcg-hcl-producer",
            &descriptor,
            &coordinate.position.to_le_bytes(),
            &coordinate.segment.to_le_bytes(),
            &coordinate.entry.to_le_bytes(),
            &[bump],
        ],
        DPL1_BYTES,
        DPL1_BYTES,
    )?;
    let mut record = accounts[5].try_borrow_mut_data()?;
    record[..4].copy_from_slice(b"DPL1");
    record[4..6].copy_from_slice(&1u16.to_le_bytes());
    record[8..40].copy_from_slice(&leaf);
    Ok(())
}

pub fn path_height(mut entries: u32) -> Result<u8, ProgramError> {
    if entries == 0 {
        return Err(refuse(h::COORDINATE));
    }
    let mut height = 0;
    while entries > 1 {
        entries = entries / 2 + entries % 2;
        height += 1;
    }
    Ok(height)
}

/// Verify a path under the shared DCL2 node and segment-wrapper hashes.
/// The duplicate-last sibling is present in the wire path and equals the
/// current digest; its clipped interval is repeated as well.
pub fn verify_leaf_path(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
    entry: u32,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    landed: &[u8; 32],
) -> ProgramResult {
    if entry >= entries {
        return Err(refuse(h::COORDINATE));
    }
    if path.len() != path_height(entries)? as usize {
        return Err(refuse(PATH));
    }
    let mut node = Node {
        digest: *leaf,
        first: entry,
        end: entry + 1,
    };
    let mut index = entry;
    let mut width = entries;
    let mut width_at_height = 1u32;
    for (level, sibling_digest) in path.iter().enumerate() {
        let sibling_index = index ^ 1;
        let sibling = if sibling_index >= width {
            if *sibling_digest != node.digest {
                return Err(refuse(PATH));
            }
            node
        } else {
            let first = sibling_index
                .checked_mul(width_at_height)
                .ok_or(refuse(h::OVERFLOW))?;
            Node {
                digest: *sibling_digest,
                first,
                end: first.saturating_add(width_at_height).min(entries),
            }
        };
        node = if index & 1 == 0 {
            h::parent(descriptor, 1, position, (level + 1) as u8, node, sibling)
        } else {
            h::parent(descriptor, 1, position, (level + 1) as u8, sibling, node)
        };
        index >>= 1;
        width = (width + 1) / 2;
        if level + 1 < path.len() {
            width_at_height = width_at_height.checked_mul(2).ok_or(refuse(h::OVERFLOW))?;
        }
    }
    let wrapped = h::hash(
        b"segment-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &node.digest,
            &[1],
        ],
    );
    if &wrapped != landed {
        return Err(refuse(PATH));
    }
    Ok(())
}

/// Recompute one k<=4 reveal. `first` is the left boundary of the current
/// height-h node and `end` is its clipped right boundary. Exactly the distinct
/// descendants are supplied; duplicate-last children are derived internally.
pub fn verify_reveal(
    descriptor: &[u8; 32],
    position: u32,
    first: u32,
    end: u32,
    height: u8,
    current: &[u8; 32],
    descendants: &[[u8; 32]],
) -> Result<u8, ProgramError> {
    if first >= end
        || height == 0
        || height > 31
        || first % (1u32 << height) != 0
        || end - first > (1u32 << height)
    {
        return Err(refuse(PATH));
    }
    let k = height.min(4);
    let child_height = height - k;
    let width = 1u32 << child_height;
    let count = ((end - first - 1) / width + 1) as usize;
    if descendants.len() != count || descendants.iter().any(|v| *v == [0; 32]) {
        return Err(refuse(PATH));
    }
    let mut nodes = Vec::with_capacity(count);
    for (i, digest) in descendants.iter().enumerate() {
        let start = first + i as u32 * width;
        nodes.push(Node {
            digest: *digest,
            first: start,
            end: start.saturating_add(width).min(end),
        });
    }
    for h in child_height + 1..=height {
        let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
        for pair in nodes.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(h::parent(descriptor, 1, position, h, left, right));
        }
        nodes = next;
    }
    if nodes.len() != 1
        || nodes[0].digest != *current
        || nodes[0].first != first
        || nodes[0].end != end
    {
        return Err(refuse(PATH));
    }
    Ok(child_height)
}

/// Derive one round's selected-child siblings from the already verified
/// distinct descendants. No sibling is re-posted, including duplicate-last.
pub fn reveal_path_chunk(
    descriptor: &[u8; 32],
    position: u32,
    first: u32,
    end: u32,
    height: u8,
    current: &[u8; 32],
    descendants: &[[u8; 32]],
    choice: usize,
) -> Result<Vec<[u8; 32]>, ProgramError> {
    let child_height = verify_reveal(
        descriptor,
        position,
        first,
        end,
        height,
        current,
        descendants,
    )?;
    if choice >= descendants.len() {
        return Err(refuse(h::COORDINATE));
    }
    let span = 1u32 << child_height;
    let mut nodes = Vec::with_capacity(descendants.len());
    for (i, digest) in descendants.iter().enumerate() {
        let start = first + i as u32 * span;
        nodes.push(Node {
            digest: *digest,
            first: start,
            end: start.saturating_add(span).min(end),
        });
    }
    let mut index = choice;
    let mut siblings = Vec::with_capacity((height - child_height) as usize);
    for level in child_height + 1..=height {
        siblings.push(nodes.get(index ^ 1).unwrap_or(&nodes[index]).digest);
        let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
        for pair in nodes.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(h::parent(descriptor, 1, position, level, left, right));
        }
        nodes = next;
        index >>= 1;
    }
    Ok(siblings)
}

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 33 {
        return Err(refuse(h::FORM));
    }
    let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refuse(h::FORM))?;
    match data[0] {
        TAG_LAND_SEGMENT_ROOT if data.len() == 71 && accounts.len() == 5 => {
            let root: [u8; 32] = data[39..71].try_into().map_err(|_| refuse(h::FORM))?;
            land_segment_root(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3],
                &accounts[4],
                &descriptor,
                u32_at(data, 33)?,
                u16_at(data, 37)?,
                &root,
            )
        }
        TAG_FINALIZE_POSITION if data.len() == 37 && accounts.len() == 4 => finalize_position(
            program,
            &accounts[0],
            &accounts[1],
            &accounts[2],
            &accounts[3],
            &descriptor,
            u32_at(data, 33)?,
        ),
        _ => Err(refuse(h::FORM)),
    }
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use serde_json::Value;

    fn source() -> ([u8; 32], Vec<[u8; 32]>) {
        let g: Value = serde_json::from_str(include_str!(
            "../../../tests/golden/dcg/closure_v2_real_rev7.json"
        ))
        .unwrap();
        let hex = g["descriptor_digest"].as_str().unwrap();
        let descriptor =
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
        let hex = g["positions"]["0"]["leaf_blob_hex"].as_str().unwrap();
        let leaves = hex
            .as_bytes()
            .chunks_exact(64)
            .map(|row| {
                std::array::from_fn(|i| {
                    u8::from_str_radix(std::str::from_utf8(&row[i * 2..i * 2 + 2]).unwrap(), 16)
                        .unwrap()
                })
            })
            .collect();
        (descriptor, leaves)
    }
    fn levels(descriptor: &[u8; 32], leaves: &[[u8; 32]]) -> Vec<Vec<Node>> {
        let mut levels = vec![leaves
            .iter()
            .enumerate()
            .map(|(i, v)| Node {
                digest: *v,
                first: i as u32,
                end: i as u32 + 1,
            })
            .collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let height = levels.len() as u8;
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| {
                    let right = *pair.get(1).unwrap_or(&pair[0]);
                    h::parent(descriptor, 1, 0, height, pair[0], right)
                })
                .collect();
            levels.push(next);
        }
        levels
    }
    #[test]
    fn real_rev7_duplicate_last_leaf_path() {
        let (descriptor, leaves) = source();
        let levels = levels(&descriptor, &leaves);
        let entry = leaves.len() - 1;
        let mut index = entry;
        let mut path = Vec::new();
        for level in &levels[..levels.len() - 1] {
            path.push(level.get(index ^ 1).unwrap_or(&level[index]).digest);
            index >>= 1;
        }
        let root = h::segment_root(&descriptor, 0, 0, &leaves).unwrap();
        verify_leaf_path(
            &descriptor,
            0,
            0,
            leaves.len() as u32,
            entry as u32,
            &leaves[entry],
            &path,
            &root,
        )
        .unwrap();
        assert_eq!(path[0], leaves[entry]); // duplicate-last sibling is carried
        path[0][0] ^= 1;
        assert_eq!(
            verify_leaf_path(
                &descriptor,
                0,
                0,
                leaves.len() as u32,
                entry as u32,
                &leaves[entry],
                &path,
                &root
            ),
            Err(refuse(PATH))
        );
    }
    #[test]
    fn k4_descent_and_duplicate_node_rejection() {
        let (descriptor, seed) = source();
        // Shape control only: the host executor's complete 3,244 real leaves
        // are supplied by a separate capture golden, not by this test.
        let leaves: Vec<_> = (0..3244).map(|i| seed[i % seed.len()]).collect();
        let levels = levels(&descriptor, &leaves);
        let mut height = path_height(leaves.len() as u32).unwrap();
        assert_eq!(height, 12);
        let mut first = 0u32;
        let end = leaves.len() as u32;
        let mut current = levels[height as usize][0].digest;
        let mut rounds = 0;
        while height > 0 {
            let child_height = height.saturating_sub(4);
            let width = 1u32 << child_height;
            let descendants: Vec<_> = levels[child_height as usize]
                .iter()
                .filter(|n| n.first >= first && n.first < end)
                .take(((end - first - 1) / width + 1) as usize)
                .map(|n| n.digest)
                .collect();
            assert_eq!(
                verify_reveal(&descriptor, 0, first, end, height, &current, &descendants),
                Ok(child_height)
            );
            let mut extra = descendants.clone();
            extra.push(*extra.last().unwrap());
            assert_eq!(
                verify_reveal(&descriptor, 0, first, end, height, &current, &extra),
                Err(refuse(PATH))
            );
            let mut wrong = descendants.clone();
            wrong[0][0] ^= 1;
            assert_eq!(
                verify_reveal(&descriptor, 0, first, end, height, &current, &wrong),
                Err(refuse(PATH))
            );
            let selected = descendants.len() - 1;
            first += selected as u32 * width;
            current = descendants[selected];
            height = child_height;
            rounds += 1;
        }
        assert_eq!(rounds, 3);
        assert_eq!(first, 3243);
        assert_eq!(current, leaves[3243]);
    }

    #[test]
    fn real_executor_3244_leaf_descent_golden() {
        let g: Value = serde_json::from_str(include_str!(
            "../../../tests/golden/dcg/root_only_real_rev7.json"
        ))
        .unwrap();
        let decode = |v: &Value| -> [u8; 32] {
            let hex = v.as_str().unwrap();
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        };
        let descriptor = decode(&g["descriptor_digest"]);
        let landed = decode(&g["segment_root"]);
        let leaf = decode(&g["target_leaf"]);
        let path: Vec<_> = g["path"].as_array().unwrap().iter().map(decode).collect();
        assert_eq!(path.len(), 12);
        verify_leaf_path(&descriptor, 0, 33, 3244, 3243, &leaf, &path, &landed).unwrap();
        let mut current = decode(&g["tree_root"]);
        let mut rounds = 0;
        let mut chunks = Vec::new();
        for round in g["rounds"].as_array().unwrap() {
            let children: Vec<_> = round["digests"]
                .as_array()
                .unwrap()
                .iter()
                .map(decode)
                .collect();
            let first = round["first"].as_u64().unwrap() as u32;
            let end = round["end"].as_u64().unwrap() as u32;
            let level = round["height"].as_u64().unwrap() as u8;
            let choice = round["choice"].as_u64().unwrap() as usize;
            let child_height =
                verify_reveal(&descriptor, 0, first, end, level, &current, &children).unwrap();
            assert_eq!(child_height, round["child_height"].as_u64().unwrap() as u8);
            chunks.push(
                reveal_path_chunk(
                    &descriptor,
                    0,
                    first,
                    end,
                    level,
                    &current,
                    &children,
                    choice,
                )
                .unwrap(),
            );
            current = children[choice];
            rounds += 1;
        }
        assert_eq!(rounds, 3);
        assert_eq!(current, leaf);
        let assembled: Vec<_> = chunks.into_iter().rev().flatten().collect();
        assert_eq!(assembled, path);
    }

    #[test]
    fn dsr1_real_roots_match_python_page_digest() {
        let g: Value = serde_json::from_str(include_str!(
            "../../../tests/golden/dcg/root_only_real_rev7.json"
        ))
        .unwrap();
        let decode = |v: &Value| -> [u8; 32] {
            let hex = v.as_str().unwrap();
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        };
        let descriptor = decode(&g["descriptor_digest"]);
        let roots: Vec<_> = g["segment_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        assert_eq!(roots.len(), 34);
        let mut page = vec![0u8; root_page_bytes(34).unwrap()];
        page[..4].copy_from_slice(b"DSR1");
        page[4..6].copy_from_slice(&1u16.to_le_bytes());
        page[8..40].copy_from_slice(&descriptor);
        page[44..46].copy_from_slice(&34u16.to_le_bytes());
        for (ordinal, digest) in roots.iter().enumerate() {
            let (bitmap, at, mask) = offset(0, ordinal, 34);
            page[bitmap] |= mask;
            page[at..at + 32].copy_from_slice(digest);
        }
        assert_eq!(page.len(), g["dsr1_bytes"].as_u64().unwrap() as usize);
        assert_eq!(crate::hash::sha256(&[&page]), decode(&g["dsr1_sha256"]));
    }

    #[test]
    fn storage_selector_rejects_byte_two_and_lc4() {
        assert_eq!(validate_storage_mode(0, true), Ok(false));
        assert_eq!(validate_storage_mode(1, false), Ok(true));
        assert_eq!(validate_storage_mode(1, true), Err(refuse(h::FORM)));
        assert_eq!(validate_storage_mode(2, false), Err(refuse(h::FORM)));
    }

    #[test]
    fn consumer_checkpoint_fields_are_zero() {
        let (descriptor, _) = source();
        let slot = h::slot_binding(
            h::Coordinate {
                position: 0,
                segment: 0,
                entry: 0,
            },
            0,
            &[1; 32],
        );
        let zero = deterministic_consumer_binding(&descriptor, 0, 0, 1, &slot).unwrap();
        assert_eq!(
            zero,
            h::input_binding_digest(&descriptor, 0, 0, &[0; 32], 0, 1, &slot).unwrap()
        );
        assert_ne!(
            zero,
            h::input_binding_digest(&descriptor, 0, 1, &[2; 32], 0, 1, &slot).unwrap()
        );
    }

    #[test]
    fn producer_record_binds_coordinate_in_pda() {
        let (descriptor, _) = source();
        let program = Pubkey::new_from_array([7; 32]);
        let coordinate = h::Coordinate {
            position: 1,
            segment: 3,
            entry: 9,
        };
        let key = producer_leaf_address(&program, &descriptor, coordinate).0;
        let mut lamports = 1;
        let mut data = [0u8; DPL1_BYTES];
        data[..4].copy_from_slice(b"DPL1");
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[8..40].copy_from_slice(&[8; 32]);
        let account = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut data,
            &program,
            false,
            0,
        );
        assert_eq!(
            stored_producer_leaf(&program, &account, &descriptor, coordinate),
            Ok([8; 32])
        );
        let wrong = h::Coordinate {
            entry: 10,
            ..coordinate
        };
        assert_eq!(
            stored_producer_leaf(&program, &account, &descriptor, wrong),
            Err(refuse(h::FORM))
        );
        account.try_borrow_mut_data().unwrap().fill(0);
        assert_eq!(
            stored_producer_leaf(&program, &account, &descriptor, coordinate),
            Err(refuse(h::COORDINATE))
        );
    }
}
