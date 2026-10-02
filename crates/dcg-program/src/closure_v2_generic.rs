// SPDX-License-Identifier: GPL-3.0-only

//! Shared DGR1 response-envelope decoding for the revision-8 dispute engine.
//!
//! Application form and model semantics do not live in this module. The
//! dispute handler validates the generic layout, then asks the registered app
//! hooks to check artifact witnesses and replay the selected operation.

use crate::{
    account_provenance::{expect_derived, expect_derived_with_bump, AccountKind, RoleFlags},
    closure_v2_response, position_template as pt,
    pt2p::{self, Pt2p},
    unified::{address, challenge, document},
};
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult,
    program_error::ProgramError, pubkey::Pubkey, sysvar::Sysvar,
};

const MALFORMED: u32 = 730;
const AUTH: u32 = 731;
const STATE: u32 = 733;
const PROOF: u32 = 734;
const DEADLINE: u32 = 736;
const ROUTE: u32 = 738;
const ROW_BYTES: usize = 120;
const MAX_READS: usize = 128;
const MAX_RANGE_SLOTS: usize = 64;
const OUTPUT_AT: usize = 1024;
const OUTPUT_BYTES: usize = 2048;
const RESPONSE_BYTES: usize = 128 + closure_v2_response::MAX_BODY;
const INPUT: &[u8] = b"basanos/dcg-hclosure-input/2";
const READ_BYTES: &[u8] = b"basanos/dcg-hclosure-read-bytes/2";
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";
const DCM2_OPTION_ROUTE_REFERENCE: &[u8] = b"basanos/dcg-dcm2-option-table-route/1";
const BASE: usize = 27;
const WRITE_ROW: usize = 48;
const MAX_PAYLOAD: usize = 66;
const MAX_OUTPUT: usize = 2_048;
const FORM48_READS: usize = 128;
const PROMPT_AT: usize = 328;
const SYNTHETIC_LEAF_FORM: u16 = 0x0100;
const INCOMPLETE: u32 = 741;
const PT2S_AT: usize = 448;
const PT2S_END: usize = 480;
// `commit_target` retains Basanos's route/geometry addresses at 216..280.
// That range includes DCR1's stable DRU1 bump at byte 219, so preserve the
// authenticated bump before writing it and use this marked copy for later
// dispute steps.
pub(crate) const RESPONSE_BUMP_COPY_MARKER_AT: usize = 480;
pub(crate) const RESPONSE_BUMP_COPY_AT: usize = 481;
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

fn u16_put(raw: &mut [u8], at: usize, value: u16) {
    raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn u32_put(raw: &mut [u8], at: usize, value: u32) {
    raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
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

/// Validate a live DCR1 record and the application form catalog. Fresh v5
/// records use their committed PDA bump; the retained v2/v4 formats predate
/// that field and keep their canonical address check.
fn live(
    program: &Pubkey,
    record: &AccountInfo,
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if !record.is_writable {
        return Err(no(MALFORMED));
    }
    let raw = record.try_borrow_data()?;
    if raw.len() != challenge::SIZE || raw.get(..4) != Some(&b"DCR1"[..]) {
        return Err(no(STATE));
    }
    let version = u16_at(&raw, 6)?;
    if !matches!(version, 2 | 4 | challenge::VERSION)
        || raw[4] != challenge::PHASE_RESPOND
        || (version == challenge::VERSION && raw[challenge::PT2P_MODE_AT] != 1)
    {
        return Err(no(STATE));
    }
    if version != challenge::VERSION && record.owner != program {
        return Err(no(AUTH));
    }
    if !manifest
        .dispute_hooks()
        .supports_form(raw[145], u16_at(&raw, 174)?)
    {
        return Err(no(740));
    }
    let deadline = u64_at(&raw, 148)?;
    if Clock::get()?.slot > deadline {
        return Err(no(DEADLINE));
    }
    if version != challenge::VERSION {
        return Ok(());
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
    let kind = AccountKind::variable(b"DRU1", 128, RESPONSE_BYTES).with_version(4, 1);
    let role = RoleFlags {
        writable: false,
        signer: false,
    };
    let version = u16_at(state, 6)?;
    if version == challenge::VERSION {
        let response_bump = if state[176] == 1 {
            if state[RESPONSE_BUMP_COPY_MARKER_AT] != 1 {
                return Err(no(PROOF));
            }
            state[RESPONSE_BUMP_COPY_AT]
        } else {
            state[challenge::RESPONSE_BUMP_AT]
        };
        expect_derived_with_bump(
            account,
            program,
            &[b"dcg-hcl-response", record.as_ref()],
            response_bump,
            kind,
            role,
        )
        .map_err(|_| no(PROOF))?;
    } else {
        expect_derived(
            account,
            program,
            &[b"dcg-hcl-response", record.as_ref()],
            kind,
            role,
        )
        .map_err(|_| no(PROOF))?;
    }
    let total = if version == challenge::VERSION {
        usize::try_from(u32_at(
            &account.try_borrow_data()?,
            closure_v2_response::DECLARED_LEN_AT,
        )?)
        .map_err(|_| no(MALFORMED))?
    } else {
        usize::try_from(u32_at(state, 140)?).map_err(|_| no(MALFORMED))?
    };
    if total > closure_v2_response::MAX_BODY || account.data_len() > RESPONSE_BYTES {
        return Err(no(MALFORMED));
    }
    closure_v2_response::sealed_view(program, account, record, &state[40..72], total)
}

fn document(program: &Pubkey, account: &AccountInfo, state: &[u8]) -> ProgramResult {
    let descriptor: &[u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    let record_version = u16_at(state, 6)?;
    if record_version == challenge::VERSION {
        let raw = account.try_borrow_data()?;
        if raw.len() < 6 || raw.get(..4) != Some(&b"DCM2"[..]) {
            return Err(no(PROOF));
        }
        match u16_at(&raw, 4)? {
            6 => {
                let kind = AccountKind::exact(b"DCM2", document::DCM2_V6_BYTES).with_version(4, 6);
                expect_derived(
                    account,
                    program,
                    &[address::DOCUMENT_SEED, descriptor],
                    kind,
                    RoleFlags {
                        writable: false,
                        signer: false,
                    },
                )
                .map_err(|_| no(PROOF))?;
                if raw.len() != document::DCM2_V6_BYTES
                    || u16_at(&raw, 6)? & (document::FLAG_ROOT_ONLY | document::FLAG_SEALED)
                        != document::FLAG_ROOT_ONLY | document::FLAG_SEALED
                    || raw[8..40] != descriptor[..]
                {
                    return Err(no(PROOF));
                }
            }
            7 => {
                drop(raw);
                document::document_v8_stored(program, account, Some(descriptor), false, PROOF)?;
            }
            _ => return Err(no(PROOF)),
        }
    } else {
        if account.owner != program {
            return Err(no(AUTH));
        }
        if account.key != &crate::closure_v2::document_address(program, descriptor).0 {
            return Err(no(PROOF));
        }
        let raw = account.try_borrow_data()?;
        let version = u16_at(&raw, 4)?;
        if raw.len() < 360
            || &raw[..4] != b"DCM2"
            || (record_version == 2 && version != 2)
            || (record_version == 4 && !crate::closure_v2::pt1_bound(version))
            || raw[8..40] != descriptor[..]
        {
            return Err(no(PROOF));
        }
    }
    let raw = account.try_borrow_data()?;
    if raw[40..72] != state[40..72] {
        return Err(no(PROOF));
    }
    Ok(())
}

/// One instantiated entry from the sealed PT2P plan, optionally resolved
/// against the immutable DCM2 option table for forms 47 and 48.
enum Target<'a> {
    Pt2p(&'a Pt2p<'a>, pt2p::Entry),
    Resolved {
        form: u16,
        reads: u16,
        writes: u16,
        routes: Vec<pt::InstantiatedRoute>,
    },
}

impl Target<'_> {
    fn route(&self, ordinal: u16) -> Result<pt::InstantiatedRoute, ProgramError> {
        match self {
            Self::Pt2p(x, entry) => x.route(entry, ordinal).map_err(no),
            Self::Resolved { routes, .. } => {
                routes.get(usize::from(ordinal)).copied().ok_or(no(ROUTE))
            }
        }
    }

    fn counts(&self) -> (u16, u16, u16) {
        match self {
            Self::Pt2p(_, e) => (e.kernel_index, e.read_count, e.write_count),
            Self::Resolved {
                form,
                reads,
                writes,
                ..
            } => (*form, *reads, *writes),
        }
    }
}

fn dcm2_option_route_reference(region: u16, length: u32, table_hash: &[u8; 32]) -> [u8; 32] {
    crate::hash::sha256(&[
        DCM2_OPTION_ROUTE_REFERENCE,
        &region.to_le_bytes(),
        &length.to_le_bytes(),
        table_hash,
    ])
}

fn dcm2_option_binding(
    doc: &[u8],
) -> Result<(usize, core::ops::Range<usize>, [u8; 32]), ProgramError> {
    use crate::unified::document as d;
    let count = usize::from(*doc.get(d::BINDING_AT_V8 + 151).ok_or(no(PROOF))?);
    let end = d::OPTION_REGION_AT
        .checked_add(count.checked_mul(4).ok_or(no(PROOF))?)
        .ok_or(no(PROOF))?;
    if doc.len() < d::OPTION_REGION_AT
        || &doc[..4] != b"DCM2"
        || u16_at(doc, 4)? != 7
        || count == 0
        || count > crate::kernels::decision::MAX_OPTIONS_SINGLE
        || doc.len() != end
    {
        return Err(no(PROOF));
    }
    let table_hash: [u8; 32] = doc
        .get(d::BINDING_AT_V8 + 164..d::BINDING_AT_V8 + 196)
        .ok_or(no(PROOF))?
        .try_into()
        .map_err(|_| no(PROOF))?;
    let table = d::OPTION_REGION_AT..end;
    if crate::hash::sha256(&[doc.get(table.clone()).ok_or(no(PROOF))?]) != table_hash {
        return Err(no(PROOF));
    }
    Ok((count, table, table_hash))
}

fn document_selected_gather_target(
    x: &Pt2p<'_>,
    entry: pt2p::Entry,
    doc: &[u8],
    routes: &[u8],
    payload_override: Option<&[u8]>,
) -> Result<Target<'static>, ProgramError> {
    use crate::kernels::decision;
    if entry.kernel_index != decision::GATHER_FORM_ID || entry.write_count != 1 {
        return Err(no(ROUTE));
    }
    let pt2p::Item::Base(old) = entry.item else {
        return Err(no(ROUTE));
    };
    let template = pt::entry_at(routes, old).map_err(no)?;
    let (option_count, table_range, _) = dcm2_option_binding(doc)?;
    let table = doc.get(table_range).ok_or(no(PROOF))?;
    let mut payload = [0u8; 16];
    if let Some(bytes) = payload_override {
        if bytes.len() != payload.len() {
            return Err(no(ROUTE));
        }
        payload.copy_from_slice(bytes);
    } else {
        x.payload(&entry, false, &mut payload).map_err(no)?;
    }
    if u16_at(&payload, 0)? != 1 || u16_at(&payload, 6)? != 0 || payload[8..16] != [0; 8] {
        return Err(no(ROUTE));
    }
    let first = usize::from(u16_at(&payload, 2)?);
    let capacity = usize::from(u16_at(&payload, 4)?);
    if (first, capacity) != (0, 128) || usize::from(template.read_count) != capacity {
        return Err(no(ROUTE));
    }
    let live = option_count.saturating_sub(first).min(capacity);
    let (_, _, pxr) = pt::route_header_v4_shallow(routes).map_err(no)?;
    let pxr = pxr.ok_or(no(ROUTE))?;
    let mut resolved = Vec::with_capacity(live + 1);
    for local in 0..live {
        let global = first + local;
        let token = u32::from_le_bytes(
            table[global * 4..global * 4 + 4]
                .try_into()
                .map_err(|_| no(PROOF))?,
        );
        let (row, _) = pxr.find(token).map_err(no)?;
        let producer_index = x
            .old_to_new(row.producer_entry, entry.position)
            .map_err(no)?
            .ok_or(no(pt::PT2_PRODUCER))?;
        if producer_index >= entry.index
            || row.producer_write_ordinal as u32
                >= x.entry(entry.position, producer_index)
                    .map_err(no)?
                    .write_count as u32
        {
            return Err(no(pt::PT2_PRODUCER));
        }
        let producer = x.entry(entry.position, producer_index).map_err(no)?;
        if row.producer_write_ordinal >= 255 {
            return Err(no(pt::PT2_PRODUCER));
        }
        let write = x
            .route(&producer, producer.read_count + row.producer_write_ordinal)
            .map_err(no)?;
        if write.direction != 1
            || write.region_id != pxr.region_id
            || write.effective_offset != row.region_offset
            || write.byte_length != row.byte_length
            || write.producer_position != entry.position
            || write.producer_entry != producer_index
            || write.producer_write_ordinal != row.producer_write_ordinal as u8
        {
            return Err(no(pt::PT2_PRODUCER));
        }
        let placeholder = x.route(&entry, local as u16).map_err(no)?;
        resolved.push(pt::InstantiatedRoute {
            direction: 0,
            ordinal: local as u16,
            region_id: pxr.region_id,
            effective_offset: write.effective_offset,
            byte_length: write.byte_length,
            read_class: 0,
            binding_kind: 1,
            source_supplied: false,
            initial_content: false,
            producer_position: entry.position,
            producer_entry: producer_index,
            producer_write_ordinal: row.producer_write_ordinal as u8,
            range_first: 0,
            range_end: 0,
            family_ordinal: 0,
            template_offset: placeholder.template_offset,
        });
    }
    let mut output = x.route(&entry, template.read_count).map_err(no)?;
    output.ordinal = 0;
    resolved.push(output);
    Ok(Target::Resolved {
        form: entry.kernel_index,
        reads: live as u16,
        writes: 1,
        routes: resolved,
    })
}

fn document_selected_form47_target(
    x: &Pt2p<'_>,
    entry: pt2p::Entry,
    doc: &[u8],
    routes: &[u8],
) -> Result<Target<'static>, ProgramError> {
    use crate::kernels::decision;
    if entry.kernel_index != decision::FORM_ID || entry.read_count != 2 || entry.write_count != 256
    {
        return Err(no(ROUTE));
    }
    let pt2p::Item::Base(old) = entry.item else {
        return Err(no(ROUTE));
    };
    let template = pt::entry_at(routes, old).map_err(no)?;
    if template.read_count != 2 || template.write_count != 256 {
        return Err(no(ROUTE));
    }
    let (option_count, _, _) = dcm2_option_binding(doc)?;
    let (_, _, pxr) = pt::route_header_v4_shallow(routes).map_err(no)?;
    if pxr.is_none() {
        return Err(no(PROOF));
    }
    let mut resolved = Vec::with_capacity(2 + 256);
    let mut option_seen = false;
    let mut gather_seen = false;
    for ordinal in 0..entry.read_count {
        let mut route = x.route(&entry, ordinal).map_err(no)?;
        if route.region_id == u16::MAX {
            if option_seen
                || route.direction != 0
                || route.read_class != 2
                || route.binding_kind != 0
                || route.source_supplied
                || route.effective_offset != 0
                || route.producer_entry != pt::NO_PRODUCER
            {
                return Err(no(ROUTE));
            }
            route.byte_length = u32::try_from(option_count.checked_mul(4).ok_or(no(PROOF))?)
                .map_err(|_| no(PROOF))?;
            option_seen = true;
        } else {
            if gather_seen
                || route.direction != 0
                || route.read_class != 0
                || route.binding_kind != 1
                || route.source_supplied
                || route.producer_entry == pt::NO_PRODUCER
                || route.byte_length != 128 * 8
            {
                return Err(no(ROUTE));
            }
            gather_seen = true;
        }
        resolved.push(route);
    }
    if !option_seen || !gather_seen {
        return Err(no(ROUTE));
    }
    for ordinal in entry.read_count..entry.read_count + entry.write_count {
        resolved.push(x.route(&entry, ordinal).map_err(no)?);
    }
    Ok(Target::Resolved {
        form: entry.kernel_index,
        reads: entry.read_count,
        writes: entry.write_count,
        routes: resolved,
    })
}

fn document_selected_target(
    x: &Pt2p<'_>,
    entry: pt2p::Entry,
    doc: &[u8],
    routes: &[u8],
    payload_override: Option<&[u8]>,
) -> Result<Target<'static>, ProgramError> {
    let target = match entry.kernel_index {
        crate::kernels::decision::GATHER_FORM_ID => {
            document_selected_gather_target(x, entry, doc, routes, payload_override)?
        }
        crate::kernels::decision::FORM_ID => {
            document_selected_form47_target(x, entry, doc, routes)?
        }
        _ => return Err(no(ROUTE)),
    };
    let (form, _, writes) = target.counts();
    let routes = match target {
        Target::Resolved { routes, .. } => routes,
        _ => return Err(no(ROUTE)),
    };
    let reads = (routes.len() as u16).checked_sub(writes).ok_or(no(ROUTE))?;
    Ok(Target::Resolved {
        form,
        reads,
        writes,
        routes,
    })
}

fn check_target(
    state: &[u8],
    body: &Body<'_>,
    entry: &Target<'_>,
    coordinate: pt::EntryCoordinate,
    prompt: &[u8; 32],
    lut: u16,
    decision_options: Option<(usize, [u8; 32])>,
    artifact_verifier: &dyn crate::app_api::ArtifactWitnessVerifier,
    machine: u8,
) -> ProgramResult {
    let position = u32_at(state, 156)?;
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    let target = body.target;
    let (tp, ts, tl, kernel, reads, writes) =
        crate::closure_v2::proof::preimage_fields(target, &descriptor)?;
    let (form, read_count, write_count) = entry.counts();
    if (form != SYNTHETIC_LEAF_FORM && crate::hash::sha256(&[target]) != state[104..136])
        || tp != position
        || ts != u16_at(state, 160)?
        || tl != u32_at(state, 136)?
        || ts != coordinate.segment
        || tl != coordinate.local
        || u16_at(target, BASE + 42)? != coordinate.operation_ordinal
        || kernel != form
        || form != u16_at(state, 174)?
        || u16_at(target, BASE + 46)? != 2
        || target[BASE + 50] != 0
        || target[BASE + 84..BASE + 116] != [0; 32]
        || reads != read_count
        || usize::from(reads) != body.read_count
        || writes.len() != usize::from(write_count) * WRITE_ROW
    {
        return Err(no(PROOF));
    }
    let read_count_bytes = reads.to_le_bytes();
    let root = crate::hash::sha256(&[
        INPUT,
        &descriptor,
        &target[BASE + 32..BASE + 42],
        &target[BASE + 44..BASE + 46],
        &read_count_bytes,
        body.rows,
    ]);
    if root != target[BASE + 52..BASE + 84] {
        return Err(no(PROOF));
    }
    for i in 0..body.read_count {
        let route = entry.route(i as u16)?;
        let row = body.row(i)?;
        let prompt_ok =
            route.source_supplied && route.binding_kind == 0 && row[56..88] == prompt[..];
        let lut_ok = if !route.source_supplied
            && route.binding_kind == 0
            && route.region_id == lut
            && route.effective_offset == 0
            && route.byte_length == 8_192 * 8
        {
            let content_hash = artifact_verifier
                .supplied_read_hash(machine, form, route.region_id, route.byte_length)
                .map_err(no)?;
            row[56..88] == lut_reference(route.region_id, route.byte_length as u64, &content_hash)
        } else {
            false
        };
        let option_ok = decision_options.is_some_and(|(count, table_hash)| {
            !route.source_supplied
                && route.binding_kind == 0
                && route.read_class == 2
                && route.effective_offset == 0
                && route.byte_length as usize == count * 4
                && row[56..88]
                    == dcm2_option_route_reference(route.region_id, route.byte_length, &table_hash)
        });
        if route.direction != 0
            || u16_at(row, 0)? != route.region_id
            || row[2] != route.read_class
            || row[3] != route.binding_kind
            || row[4..8] != [0; 4]
            || row[20..24] != [0; 4]
            || u64_at(row, 8)? != route.effective_offset
            || u32_at(row, 16)? != route.byte_length
            || (route.binding_kind != 2 && row[88..120] != [0; 32])
            || route.read_class == 1
            || (route.read_class == 2 && !(prompt_ok || lut_ok || option_ok))
        {
            return Err(no(ROUTE));
        }
    }
    let mut output_len = 0usize;
    for j in 0..usize::from(write_count) {
        let route = entry.route(read_count + j as u16)?;
        let write = &writes[j * WRITE_ROW..(j + 1) * WRITE_ROW];
        if route.direction != 1
            || u16_at(write, 0)? != route.region_id
            || write[2..4] != [0; 2]
            || u32_at(write, 4)? != route.byte_length
            || u64_at(write, 8)? != route.effective_offset
        {
            return Err(no(ROUTE));
        }
        output_len = output_len
            .checked_add(route.byte_length as usize)
            .ok_or(no(ROUTE))?;
    }
    if form == 4 && output_len > MAX_OUTPUT {
        return Err(no(ROUTE));
    }
    Ok(())
}

fn lut_reference(region: u16, length: u64, content_hash: &[u8; 32]) -> [u8; 32] {
    crate::hash::sha256(&[
        b"basanos/dcg-pt2p-draft-supplied-lut/1",
        &region.to_le_bytes(),
        &length.to_le_bytes(),
        content_hash,
    ])
}

fn commit_target(
    state: &mut [u8],
    reads: u16,
    writes: u16,
    operation: u16,
    response: &Pubkey,
    routes: &Pubkey,
    geometry: &Pubkey,
    payload: &[u8],
    pt2s: &Pubkey,
) {
    state[176] = 1;
    state[177] = 0;
    u16_put(state, 178, reads);
    u16_put(state, 180, writes);
    u16_put(state, 182, operation);
    state[184..216].copy_from_slice(response.as_ref());
    state[RESPONSE_BUMP_COPY_MARKER_AT] = 1;
    state[RESPONSE_BUMP_COPY_AT] = state[challenge::RESPONSE_BUMP_AT];
    state[216..248].copy_from_slice(routes.as_ref());
    state[248..280].copy_from_slice(geometry.as_ref());
    u16_put(state, 280, payload.len() as u16);
    state[282..282 + MAX_PAYLOAD].fill(0);
    state[282..282 + payload.len()].copy_from_slice(payload);
    state[348..356].fill(0);
    u32_put(state, 392, 0);
    state[396..406].fill(0);
    state[448..480].copy_from_slice(pt2s.as_ref());
}

fn synthetic_leaf(
    position: u32,
    descriptor: &[u8; 32],
    coordinate: pt::EntryCoordinate,
) -> [u8; 32] {
    let position = position.to_le_bytes();
    let segment = coordinate.segment.to_le_bytes();
    let local = coordinate.local.to_le_bytes();
    let operation = coordinate.operation_ordinal.to_le_bytes();
    let form = SYNTHETIC_LEAF_FORM.to_le_bytes();
    let mode = 2u16.to_le_bytes();
    let count = 0u16.to_le_bytes();
    let input = crate::hash::sha256(&[
        INPUT, descriptor, &position, &segment, &local, &form, &count,
    ]);
    let zero = [0u8; 32];
    let mut preimage = Vec::with_capacity(147);
    preimage.extend_from_slice(LEAF_DOMAIN);
    preimage.extend_from_slice(descriptor);
    preimage.extend_from_slice(&position);
    preimage.extend_from_slice(&segment);
    preimage.extend_from_slice(&local);
    preimage.extend_from_slice(&operation);
    preimage.extend_from_slice(&form);
    preimage.extend_from_slice(&mode);
    preimage.extend_from_slice(&count);
    preimage.extend_from_slice(&[0, 0]);
    preimage.extend_from_slice(&input);
    preimage.extend_from_slice(&zero);
    preimage.extend_from_slice(&count);
    preimage.extend_from_slice(&[0, 0]);
    crate::hash::sha256(&[&preimage])
}

fn verify_target_unified(
    program: &Pubkey,
    accounts: &[AccountInfo],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if accounts.len() != 8 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    if state[176] != 0 {
        return Err(no(STATE));
    }
    document(program, &accounts[2], &state)?;
    let doc = accounts[2].try_borrow_data()?;
    if accounts[3].key.as_ref() != &doc[200..232]
        || crate::hash::sha256(&[&accounts[3].try_borrow_data()?]) != doc[232..264]
    {
        return Err(no(PROOF));
    }
    crate::unified::plan::bind_pt2s(
        program,
        &accounts[3],
        &accounts[5],
        &accounts[6],
        Some(&accounts[7]),
    )
    .map_err(|_| no(PROOF))?;
    let index_at = crate::unified::plan::bind_pt1s(program, &accounts[3], &accounts[4])
        .map_err(|_| no(PROOF))?;
    let s = accounts[3].try_borrow_data()?;
    let pts = accounts[4].try_borrow_data()?;
    let routes = accounts[5].try_borrow_data()?;
    let geometry = accounts[6].try_borrow_data()?;
    let payloads = accounts[7].try_borrow_data()?;
    let x = crate::unified::plan::view(&s, &routes, &geometry, &payloads, Some(&pts[index_at..]))
        .map_err(|_| no(PROOF))?;
    let index = u32_at(&state, 170)?;
    let position = u32_at(&state, 156)?;
    let entry = x.entry(position, index).map_err(no)?;
    if entry.kernel_index != u16_at(&state, 174)? {
        return Err(no(PROOF));
    }
    let coordinate = x.coordinate(position, index).map_err(no)?;
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let target = if matches!(
        entry.kernel_index,
        crate::kernels::decision::FORM_ID | crate::kernels::decision::GATHER_FORM_ID
    ) {
        document_selected_target(&x, entry, &doc, &routes, None)?
    } else {
        Target::Pt2p(&x, entry)
    };
    let prompt: [u8; 32] = doc[PROMPT_AT..PROMPT_AT + 32]
        .try_into()
        .map_err(|_| no(PROOF))?;
    let decision_options = if entry.kernel_index == crate::kernels::decision::FORM_ID {
        let (count, _, table_hash) = dcm2_option_binding(&doc)?;
        Some((count, table_hash))
    } else {
        None
    };
    check_target(
        &state,
        &body,
        &target,
        coordinate,
        &prompt,
        x.g.lut_region,
        decision_options,
        manifest.artifact_witness_verifier(),
        state[145],
    )?;
    if entry.kernel_index == SYNTHETIC_LEAF_FORM {
        let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
        if (entry.read_count, entry.write_count) != (0, 0)
            || crate::hash::sha256(&[body.target])
                != synthetic_leaf(position, &descriptor, coordinate)
        {
            return Err(no(PROOF));
        }
    }
    let n = x.payload_len(&entry).map_err(no)?;
    if n > MAX_PAYLOAD {
        return Err(no(PROOF));
    }
    let mut patched = [0u8; MAX_PAYLOAD];
    x.payload(&entry, true, &mut patched[..n]).map_err(no)?;
    let (_, reads, writes) = target.counts();
    drop(raw);
    commit_target(
        &mut state,
        reads,
        writes,
        coordinate.operation_ordinal,
        accounts[1].key,
        accounts[5].key,
        accounts[6].key,
        &patched[..n],
        accounts[3].key,
    );
    challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_TARGET, 1, state[4]);
    Ok(())
}

fn verify_target(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 8 {
        return Err(no(MALFORMED));
    }
    verify_target_unified(program, accounts, manifest)
}

fn read_bits(state: &[u8]) -> Result<u128, ProgramError> {
    Ok(u128::from(u64_at(state, 348)?) | (u128::from(u64_at(state, 396)?) << 64))
}

fn put_read_bits(state: &mut [u8], bits: u128) {
    state[348..356].copy_from_slice(&(bits as u64).to_le_bytes());
    state[396..404].copy_from_slice(&((bits >> 64) as u64).to_le_bytes());
}

fn pinned_tables(
    program: &Pubkey,
    state: &[u8],
    routes: &AccountInfo,
    geometry: &AccountInfo,
) -> ProgramResult {
    if routes.owner != program || geometry.owner != program {
        return Err(no(PROOF));
    }
    if routes.key.as_ref() != &state[216..248] || geometry.key.as_ref() != &state[248..280] {
        return Err(no(PROOF));
    }
    Ok(())
}

fn producer_route(
    x: &Pt2p<'_>,
    consumer_position: u32,
    consumer_entry: u32,
    route: pt::InstantiatedRoute,
    read_row: &[u8],
    input: &[u8],
    producer_preimage: &[u8],
    descriptor: &[u8; 32],
) -> Result<crate::closure_v2::proof::Coordinate, ProgramError> {
    if route.direction != 0
        || route.binding_kind != 1
        || route.read_class != 0
        || route.producer_position > consumer_position
        || (route.producer_position == consumer_position && route.producer_entry >= consumer_entry)
        || read_row.len() != ROW_BYTES
        || read_row[2] != 0
        || read_row[3] != 1
        || read_row[4..8] != [0; 4]
        || read_row[20..24] != [0; 4]
        || read_row[88..120] != [0; 32]
        || u16_at(read_row, 0)? != route.region_id
        || u64_at(read_row, 8)? != route.effective_offset
        || u32_at(read_row, 16)? != route.byte_length
        || input.len() != route.byte_length as usize
    {
        return Err(no(ROUTE));
    }
    let q = route.producer_position;
    let location = x.coordinate(q, route.producer_entry).map_err(no)?;
    let (position, segment, local, kernel, _, writes) =
        crate::closure_v2::proof::preimage_fields(producer_preimage, descriptor)?;
    let producer = x.entry(q, route.producer_entry).map_err(no)?;
    if u16::from(route.producer_write_ordinal) >= producer.write_count
        || writes.len() != usize::from(producer.write_count) * WRITE_ROW
    {
        return Err(no(ROUTE));
    }
    let declared = x
        .route(
            &producer,
            producer.read_count + u16::from(route.producer_write_ordinal),
        )
        .map_err(no)?;
    let write_at = usize::from(route.producer_write_ordinal)
        .checked_mul(WRITE_ROW)
        .ok_or(no(ROUTE))?;
    let write = writes
        .get(write_at..write_at + WRITE_ROW)
        .ok_or(no(ROUTE))?;
    if position != q
        || segment != location.segment
        || local != location.local
        || kernel != producer.kernel_index
        || u16_at(producer_preimage, BASE + 42)? != location.operation_ordinal
        || declared.direction != 1
        || declared.region_id != route.region_id
        || declared.effective_offset != route.effective_offset
        || declared.byte_length != route.byte_length
        || u16_at(write, 0)? != route.region_id
        || write[2..4] != [0; 2]
        || u32_at(write, 4)? != route.byte_length
        || u64_at(write, 8)? != route.effective_offset
    {
        return Err(no(ROUTE));
    }
    let leaf = crate::hash::sha256(&[producer_preimage]);
    let coordinate = crate::closure_v2::proof::Coordinate {
        position,
        segment,
        entry: local,
    };
    let digest = crate::closure_v2::write_digest(
        descriptor,
        crate::closure_v2::Coordinate {
            position,
            segment,
            entry: local,
        },
        route.region_id,
        route.effective_offset,
        input,
    )
    .map_err(|_| no(ROUTE))?;
    if read_row[24..56] != digest || read_row[56..88] != leaf || write[16..48] != digest {
        return Err(no(PROOF));
    }
    Ok(coordinate)
}

fn unified_producer(
    x: &Pt2p<'_>,
    dpr2: &AccountInfo,
    descriptor: &[u8; 32],
    at: crate::closure_v2::proof::Coordinate,
    leaf: &[u8; 32],
    siblings: &[u8],
    c: &mut Cursor<'_>,
) -> ProgramResult {
    use crate::unified::challenge as u;
    let mut ordinal = None;
    for s in 0..usize::from(x.segment_count) {
        let (id, entries) = x.segment_row(at.position, s).map_err(no)?;
        if id == at.segment {
            ordinal = Some((s as u16, entries));
        }
    }
    let (ordinal, entries) = ordinal.ok_or(no(PROOF))?;
    if siblings.len() % 32 != 0 {
        return Err(no(PROOF));
    }
    let path: Vec<[u8; 32]> = siblings
        .chunks_exact(32)
        .map(|v| v.try_into().expect("32-byte chunk"))
        .collect();
    let tree =
        u::dl_fold(descriptor, 1, at.position, entries, at.entry, leaf, &path).ok_or(no(PROOF))?;
    let segment_root = crate::closure_v2::hash(
        b"segment-root/2",
        &[
            descriptor,
            &at.position.to_le_bytes(),
            &at.segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    let rest = c.data.get(c.at..).ok_or(no(PROOF))?;
    let (spp1_ordinal, table, path, used) = u::decode_spp1(rest).map_err(|_| no(PROOF))?;
    c.at += used;
    if spp1_ordinal != ordinal {
        return Err(no(PROOF));
    }
    let derived = x.segment_table_root(at.position).map_err(no)?;
    let proven = u::spp1_position_root(
        descriptor,
        at.position,
        x.segment_count,
        &segment_root,
        ordinal,
        &table,
        &path,
        &derived,
    )
    .map_err(|_| no(PROOF))?;
    let landed = document::landed_root(dpr2, at.position, PROOF)?;
    if proven != Some(landed) {
        return Err(no(PROOF));
    }
    Ok(())
}

fn unified_family<'a>(
    state: &[u8],
    dfs2: &'a [u8],
    ordinal: u16,
) -> Result<(&'a [u8], [u8; 32]), ProgramError> {
    use crate::unified::challenge as u;
    if state[u::FTR_AT] != 1 {
        return Err(no(INCOMPLETE));
    }
    let body = dfs2.get(document::DFS2_HEADER..).ok_or(no(PROOF))?;
    let families = document::parse_family_body(body).map_err(|_| no(PROOF))?;
    let i = families
        .iter()
        .position(|family| family.0 == ordinal)
        .ok_or(no(PROOF))?;
    let root = state
        .get(u::FTR_ROOTS_AT + 32 * i..u::FTR_ROOTS_AT + 32 * (i + 1))
        .ok_or(no(PROOF))?
        .try_into()
        .map_err(|_| no(PROOF))?;
    Ok((families[i].2, root))
}

fn unified_range_leaves(
    x: &Pt2p<'_>,
    state: &[u8],
    dfs2: &AccountInfo,
    descriptor: &[u8; 32],
    route: pt::InstantiatedRoute,
    witness: &[u8],
    positions: core::ops::Range<u32>,
) -> Result<Vec<[u8; 32]>, ProgramError> {
    use crate::unified::rsp1;
    if route.binding_kind != 2
        || positions.start < route.range_first
        || positions.end > route.range_end
    {
        return Err(no(ROUTE));
    }
    let raw = dfs2.try_borrow_data()?;
    let (slots, _) = unified_family(state, &raw, route.family_ordinal)?;
    let kind = rsp1::family_kind(x, route.family_ordinal).map_err(|_| no(PROOF))?;
    let family = crate::closure_v2::family_id(descriptor, route.family_ordinal, kind);
    let span = u64::from(route.range_end - route.range_first);
    if span == 0 || witness.len() as u64 % span != 0 {
        return Err(no(ROUTE));
    }
    let per_position = witness.len() as u64 / span;
    let mut cursor = per_position * u64::from(positions.start - route.range_first);
    let mut leaves = Vec::with_capacity((positions.end - positions.start) as usize);
    for q in positions {
        let before = cursor;
        leaves.push(rsp1::summary_leaf_at(
            x,
            descriptor,
            &family,
            slots,
            q,
            route.region_id,
            route.effective_offset,
            witness,
            &mut cursor,
        )?);
        if cursor - before != per_position {
            return Err(no(ROUTE));
        }
    }
    Ok(leaves)
}

fn unified_range_close(
    x: &Pt2p<'_>,
    state: &[u8],
    dfs2: &AccountInfo,
    descriptor: &[u8; 32],
    route: pt::InstantiatedRoute,
    row: &[u8],
    proof: &[u8],
    leaves: &[[u8; 32]],
) -> ProgramResult {
    use crate::unified::rsp1;
    let raw = dfs2.try_borrow_data()?;
    let (_, root) = unified_family(state, &raw, route.family_ordinal)?;
    let auth_count = *proof.get(12).ok_or(no(PROOF))? as usize;
    let size = rsp1::GROUP_HEADER
        .checked_add(auth_count.checked_mul(32).ok_or(no(PROOF))?)
        .ok_or(no(PROOF))?;
    let group = rsp1::decode_group(proof.get(..size).ok_or(no(PROOF))?).map_err(|_| no(PROOF))?;
    if group.family_ordinal != route.family_ordinal
        || group.first != route.range_first
        || group.end != route.range_end
    {
        return Err(no(PROOF));
    }
    let kind = rsp1::family_kind(x, route.family_ordinal).map_err(|_| no(PROOF))?;
    let family = crate::closure_v2::family_id(descriptor, route.family_ordinal, kind);
    if row[56..88] != family || row[88..120] != [0; 32] {
        return Err(no(PROOF));
    }
    let auth: Vec<[u8; 32]> = group
        .auth
        .chunks_exact(32)
        .map(|v| v.try_into().expect("32-byte chunk"))
        .collect();
    let height = crate::unified::classes::rs1_height(x.position_count);
    let read_digest = rsp1::verify_leaves(
        descriptor,
        &family,
        height,
        x.position_count,
        group.first,
        group.end,
        leaves,
        &auth,
        &root,
    )
    .map_err(|_| no(PROOF))?;
    if read_digest != row[24..56] {
        return Err(no(PROOF));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SparseProofNode {
    index: u32,
    digest: [u8; 32],
}

struct Form48ProofGroup {
    segment_ordinal: u16,
    segment_root: [u8; 32],
}

struct Form48ProofLeaf<'a> {
    coordinate: crate::closure_v2::proof::Coordinate,
    preimage: &'a [u8],
}

fn sparse_node(
    index: u32,
    digest: [u8; 32],
    span: u32,
    leaf_count: u32,
) -> Result<crate::closure_v2::Node, ProgramError> {
    let first = index.checked_mul(span).ok_or(no(PROOF))?;
    let end = first.checked_add(span).ok_or(no(PROOF))?.min(leaf_count);
    Ok(crate::closure_v2::Node { digest, first, end })
}

fn fold_sparse_proof(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    leaf_count: u32,
    mut active: Vec<SparseProofNode>,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    if leaf_count == 0 || active.is_empty() {
        return Err(no(PROOF));
    }
    let mut previous = None;
    for node in &active {
        if node.index >= leaf_count || previous.is_some_and(|index| index >= node.index) {
            return Err(no(PROOF));
        }
        previous = Some(node.index);
    }
    let mut width = leaf_count;
    let mut span = 1u32;
    let mut sibling_at = 0usize;
    let mut level = 0u8;
    while width > 1 {
        level = level.checked_add(1).ok_or(no(PROOF))?;
        let mut next = Vec::with_capacity(active.len());
        let mut i = 0usize;
        while i < active.len() {
            let current = active[i];
            let left_index = current.index & !1;
            let current_node = sparse_node(current.index, current.digest, span, leaf_count)?;
            let (left, right, consumed) = if current.index & 1 == 0 {
                if active
                    .get(i + 1)
                    .is_some_and(|node| node.index == current.index + 1)
                {
                    let other = active[i + 1];
                    (
                        current_node,
                        sparse_node(other.index, other.digest, span, leaf_count)?,
                        2,
                    )
                } else if current.index + 1 >= width {
                    (current_node, current_node, 1)
                } else {
                    let digest = *siblings.get(sibling_at).ok_or(no(PROOF))?;
                    sibling_at += 1;
                    (
                        current_node,
                        sparse_node(current.index + 1, digest, span, leaf_count)?,
                        1,
                    )
                }
            } else {
                let digest = *siblings.get(sibling_at).ok_or(no(PROOF))?;
                sibling_at += 1;
                (
                    sparse_node(left_index, digest, span, leaf_count)?,
                    current_node,
                    1,
                )
            };
            let parent = crate::closure_v2::parent(descriptor, kind, scope, level, left, right);
            next.push(SparseProofNode {
                index: current.index / 2,
                digest: parent.digest,
            });
            i += consumed;
        }
        active = next;
        width = width.div_ceil(2);
        span = span.checked_mul(2).ok_or(no(PROOF))?;
    }
    if active.len() != 1 || active[0].index != 0 || sibling_at != siblings.len() {
        return Err(no(PROOF));
    }
    Ok(active[0].digest)
}

/// Form 48's canonical sparse multiproof authenticates all selected producer
/// leaves once, then binds every read row to one authenticated leaf.
fn verify_form48_batch(
    x: &Pt2p<'_>,
    dpr2: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    consumer_index: u32,
    target: &Target<'_>,
    body: &Body<'_>,
    first: usize,
    count: usize,
    bits: &mut u128,
) -> ProgramResult {
    let (form, read_count, write_count) = target.counts();
    if form != crate::kernels::decision::GATHER_FORM_ID
        || usize::from(read_count) != body.read_count
        || write_count != 1
        || body.read_count == 0
        || body.read_count > FORM48_READS
        || first != 0
        || count != body.read_count
    {
        return Err(no(MALFORMED));
    }
    if !body.core.is_empty() || !body.weights.is_empty() || !body.outputs.is_empty() {
        return Err(no(MALFORMED));
    }
    let (first_witness, first_kind, envelope) = body.section_exact(0)?;
    if first_witness.len() != target.route(0)?.byte_length as usize || first_kind != 1 {
        return Err(no(ROUTE));
    }
    let mut c = Cursor {
        data: envelope,
        at: 0,
    };
    if c.take(4)? != b"F48M" || c.u16()? != 1 || usize::from(c.u16()?) != body.read_count {
        return Err(no(MALFORMED));
    }
    let group_count = usize::from(c.u16()?);
    let unique_count = usize::from(c.u16()?);
    if group_count == 0
        || group_count > FORM48_READS
        || unique_count == 0
        || unique_count > body.read_count
        || group_count > unique_count
    {
        return Err(no(MALFORMED));
    }
    let mut mapping = Vec::with_capacity(body.read_count);
    for _ in 0..body.read_count {
        let unique = usize::from(c.u16()?);
        if unique >= unique_count {
            return Err(no(PROOF));
        }
        mapping.push(unique);
    }
    let mut leaves = Vec::with_capacity(unique_count);
    let mut groups = Vec::with_capacity(group_count);
    let mut previous_ordinal = None;
    for _ in 0..group_count {
        let segment_ordinal = c.u16()?;
        let segment_id = c.u16()?;
        let group_leaves = usize::from(c.u16()?);
        if group_leaves == 0
            || group_leaves > unique_count - leaves.len()
            || previous_ordinal.is_some_and(|prior| prior >= segment_ordinal)
            || u32::from(segment_ordinal) >= u32::from(x.segment_count)
        {
            return Err(no(PROOF));
        }
        let (expected_segment, segment_entries) = x
            .segment_row(position, usize::from(segment_ordinal))
            .map_err(no)?;
        if segment_id != expected_segment {
            return Err(no(PROOF));
        }
        previous_ordinal = Some(segment_ordinal);
        let mut active = Vec::with_capacity(group_leaves);
        let mut previous_entry = None;
        for _ in 0..group_leaves {
            let leaf_position = c.u32()?;
            let leaf_segment = c.u16()?;
            let leaf_entry = c.u32()?;
            let preimage_len = usize::from(c.u16()?);
            let preimage = c.take(preimage_len)?;
            if leaf_position != position
                || leaf_segment != segment_id
                || leaf_entry >= segment_entries
                || previous_entry.is_some_and(|prior| prior >= leaf_entry)
            {
                return Err(no(PROOF));
            }
            let (p, segment, local, _, _, _) =
                crate::closure_v2::proof::preimage_fields(preimage, descriptor)?;
            if (p, segment, local) != (leaf_position, leaf_segment, leaf_entry) {
                return Err(no(PROOF));
            }
            let digest = crate::hash::sha256(&[preimage]);
            active.push(SparseProofNode {
                index: leaf_entry,
                digest,
            });
            leaves.push(Form48ProofLeaf {
                coordinate: crate::closure_v2::proof::Coordinate {
                    position: leaf_position,
                    segment: leaf_segment,
                    entry: leaf_entry,
                },
                preimage,
            });
            previous_entry = Some(leaf_entry);
        }
        let sibling_count = usize::from(c.u16()?);
        let sibling_bytes = sibling_count.checked_mul(32).ok_or(no(PROOF))?;
        if sibling_count > group_leaves.saturating_mul(32)
            || sibling_bytes > c.data.len().saturating_sub(c.at)
        {
            return Err(no(PROOF));
        }
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(c.take(32)?.try_into().map_err(|_| no(PROOF))?);
        }
        let tree_root =
            fold_sparse_proof(descriptor, 1, position, segment_entries, active, &siblings)?;
        let segment_root = crate::closure_v2::hash(
            b"segment-root/2",
            &[
                descriptor,
                &position.to_le_bytes(),
                &segment_id.to_le_bytes(),
                &segment_entries.to_le_bytes(),
                &tree_root,
                &[1],
            ],
        );
        groups.push(Form48ProofGroup {
            segment_ordinal,
            segment_root,
        });
    }
    if leaves.len() != unique_count {
        return Err(no(PROOF));
    }
    let outer_sibling_count = usize::from(c.u16()?);
    let outer_sibling_bytes = outer_sibling_count.checked_mul(32).ok_or(no(PROOF))?;
    if outer_sibling_count > group_count.saturating_mul(32)
        || outer_sibling_bytes > c.data.len().saturating_sub(c.at)
    {
        return Err(no(PROOF));
    }
    let mut outer_siblings = Vec::with_capacity(outer_sibling_count);
    for _ in 0..outer_sibling_count {
        outer_siblings.push(c.take(32)?.try_into().map_err(|_| no(PROOF))?);
    }
    if c.at != c.data.len() {
        return Err(no(MALFORMED));
    }
    let outer = groups
        .iter()
        .map(|group| SparseProofNode {
            index: u32::from(group.segment_ordinal),
            digest: group.segment_root,
        })
        .collect();
    let segment_tree = fold_sparse_proof(
        descriptor,
        2,
        position,
        u32::from(x.segment_count),
        outer,
        &outer_siblings,
    )?;
    let table_root = x.segment_table_root(position).map_err(no)?;
    let position_root = crate::closure_v2::hash(
        b"position-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &x.segment_count.to_le_bytes(),
            &table_root,
            &segment_tree,
            &[1],
        ],
    );
    if document::landed_root(dpr2, position, PROOF)? != position_root {
        return Err(no(PROOF));
    }
    let mut used = vec![false; unique_count];
    for i in 0..body.read_count {
        let route = target.route(i as u16)?;
        let row = body.row(i)?;
        let (witness, kind, proof) = body.section_exact(i)?;
        if kind != route.binding_kind
            || kind != 1
            || witness.len() != route.byte_length as usize
            || (i != 0 && !proof.is_empty())
        {
            return Err(no(ROUTE));
        }
        let unique = mapping[i];
        let leaf = leaves.get(unique).ok_or(no(PROOF))?;
        let coordinate = producer_route(
            x,
            position,
            consumer_index,
            route,
            row,
            witness,
            leaf.preimage,
            descriptor,
        )?;
        if coordinate != leaf.coordinate {
            return Err(no(PROOF));
        }
        used[unique] = true;
        *bits |= 1u128 << i;
    }
    if used.iter().any(|is_used| !is_used) {
        return Err(no(PROOF));
    }
    Ok(())
}

fn verify_reads(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() < 5 || accounts.len() != 8 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    if state[176] != 1 || accounts[1].key.as_ref() != &state[184..216] {
        return Err(no(STATE));
    }
    if state[406..414].iter().any(|byte| *byte != 0) {
        return Err(no(STATE));
    }
    document(program, &accounts[2], &state)?;
    pinned_tables(program, &state, &accounts[4], &accounts[5])?;
    if accounts[6].key.as_ref() != &state[PT2S_AT..PT2S_END] {
        return Err(no(PROOF));
    }
    crate::unified::plan::bind_pt2s(program, &accounts[6], &accounts[4], &accounts[5], None)
        .map_err(|_| no(PROOF))?;
    let doc = accounts[2].try_borrow_data()?;
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    if accounts[7].owner != program || accounts[7].key.as_ref() != &doc[456..488] {
        return Err(no(PROOF));
    }
    document::positions(
        program,
        &accounts[3],
        &descriptor,
        u32_at(&doc, 72)?,
        false,
        PROOF,
    )?;
    let s = accounts[6].try_borrow_data()?;
    let routes = accounts[4].try_borrow_data()?;
    let geometry = accounts[5].try_borrow_data()?;
    let x = crate::unified::plan::view(&s, &routes, &geometry, &[], None).map_err(|_| no(PROOF))?;
    let index = u32_at(&state, 170)?;
    let position = u32_at(&state, 156)?;
    let base_entry = x.entry(position, index).map_err(no)?;
    let entry = if matches!(
        base_entry.kernel_index,
        crate::kernels::decision::FORM_ID | crate::kernels::decision::GATHER_FORM_ID
    ) {
        let payload_len = usize::from(u16_at(&state, 280)?);
        let payload = state.get(282..282 + payload_len).ok_or(no(PROOF))?;
        document_selected_target(&x, base_entry, &doc, &routes, Some(payload))?
    } else {
        Target::Pt2p(&x, base_entry)
    };
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let first = usize::from(u16_at(data, 1)?);
    let count = usize::from(u16_at(data, 3)?);
    let end = first.checked_add(count).ok_or(no(MALFORMED))?;
    if count == 0 || end > body.read_count {
        return Err(no(MALFORMED));
    }
    let mut bits = read_bits(&state)?;
    if base_entry.kernel_index == crate::kernels::decision::GATHER_FORM_ID {
        if first != 0 || count != body.read_count || data.len() != 5 {
            return Err(no(MALFORMED));
        }
        verify_form48_batch(
            &x,
            &accounts[3],
            &descriptor,
            position,
            index,
            &entry,
            &body,
            first,
            count,
            &mut bits,
        )?;
        drop(raw);
        drop(entry);
        drop(s);
        drop(routes);
        drop(geometry);
        put_read_bits(&mut state, bits);
        challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_READS, 1, state[4]);
        return Ok(());
    }
    for i in first..end {
        let route = entry.route(i as u16)?;
        let row = body.row(i)?;
        let (witness, kind, proof) = body.section(i)?;
        if kind != route.binding_kind || witness.len() != route.byte_length as usize {
            return Err(no(ROUTE));
        }
        let mut cursor = Cursor { data: proof, at: 0 };
        match kind {
            1 => {
                let (preimage, siblings) = cursor.producer()?;
                let at = producer_route(
                    &x,
                    position,
                    index,
                    route,
                    row,
                    witness,
                    preimage,
                    &descriptor,
                )?;
                unified_producer(
                    &x,
                    &accounts[3],
                    &descriptor,
                    at,
                    &crate::hash::sha256(&[preimage]),
                    siblings,
                    &mut cursor,
                )?;
            }
            2 => {
                let leaves = unified_range_leaves(
                    &x,
                    &state,
                    &accounts[7],
                    &descriptor,
                    route,
                    witness,
                    route.range_first..route.range_end,
                )?;
                unified_range_close(
                    &x,
                    &state,
                    &accounts[7],
                    &descriptor,
                    route,
                    row,
                    proof,
                    &leaves,
                )?;
            }
            0 if route.read_class == 2
                && u16_at(&state, 174)? == crate::kernels::decision::FORM_ID
                && !route.source_supplied =>
            {
                if route.binding_kind != 0 || route.effective_offset != 0 {
                    return Err(no(ROUTE));
                }
                let (option_count, range, table_hash) = dcm2_option_binding(&doc)?;
                let table = doc.get(range).ok_or(no(PROOF))?;
                if route.byte_length as usize != option_count * 4
                    || witness != table
                    || row[56..88]
                        != dcm2_option_route_reference(
                            route.region_id,
                            route.byte_length,
                            &table_hash,
                        )
                {
                    return Err(no(PROOF));
                }
                let digest = crate::hash::sha256(&[
                    READ_BYTES,
                    &descriptor,
                    &consumer_bytes(position, u16_at(&state, 160)?, u32_at(&state, 136)?),
                    &row[0..2],
                    &row[8..16],
                    &row[16..20],
                    witness,
                ]);
                if digest != row[24..56] {
                    return Err(no(PROOF));
                }
            }
            0 if route.read_class == 2 && !route.source_supplied => {
                let expected = manifest
                    .artifact_witness_verifier()
                    .supplied_read_hash(
                        state[145],
                        u16_at(&state, 174)?,
                        route.region_id,
                        route.byte_length,
                    )
                    .map_err(no)?;
                if crate::hash::sha256(&[witness]) != expected {
                    return Err(no(PROOF));
                }
                let digest = crate::hash::sha256(&[
                    READ_BYTES,
                    &descriptor,
                    &consumer_bytes(position, u16_at(&state, 160)?, u32_at(&state, 136)?),
                    &row[0..2],
                    &row[8..16],
                    &row[16..20],
                    witness,
                ]);
                if digest != row[24..56] {
                    return Err(no(PROOF));
                }
            }
            0 if route.read_class == 2 => {
                let len = cursor.u32()? as usize;
                let content = cursor.take(len)?;
                let at = usize::try_from(route.effective_offset).map_err(|_| no(ROUTE))?;
                if !route.source_supplied
                    || row[2] != 2
                    || slice(content, at, witness.len())? != witness
                {
                    return Err(no(ROUTE));
                }
                let seed = crate::region_commitment::seed_v1(route.region_id, len as u64, 1);
                let fold = crate::region_commitment::fold_account_v1(
                    &seed,
                    0,
                    len as u64,
                    &crate::hash::sha256(&[content]),
                );
                if doc[PROMPT_AT..PROMPT_AT + 32] != fold || row[56..88] != fold {
                    return Err(no(PROOF));
                }
                let digest = crate::hash::sha256(&[
                    READ_BYTES,
                    &descriptor,
                    &consumer_bytes(position, u16_at(&state, 160)?, u32_at(&state, 136)?),
                    &row[0..2],
                    &row[8..16],
                    &row[16..20],
                    witness,
                ]);
                if digest != row[24..56] {
                    return Err(no(PROOF));
                }
            }
            0 => {
                if !route.initial_content
                    || row[2] != 0
                    || row[56..88] != [0; 32]
                    || witness.iter().any(|b| *b != 0)
                {
                    return Err(no(ROUTE));
                }
                let digest = crate::hash::sha256(&[
                    READ_BYTES,
                    &descriptor,
                    &consumer_bytes(position, u16_at(&state, 160)?, u32_at(&state, 136)?),
                    &row[0..2],
                    &row[8..16],
                    &row[16..20],
                    witness,
                ]);
                if digest != row[24..56] {
                    return Err(no(PROOF));
                }
            }
            _ => return Err(no(ROUTE)),
        }
        bits |= 1u128 << i;
    }
    if data.len() != 5 {
        return Err(no(MALFORMED));
    }
    drop(raw);
    drop(entry);
    drop(s);
    drop(routes);
    drop(geometry);
    put_read_bits(&mut state, bits);
    challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_READS, 1, state[4]);
    Ok(())
}

fn consumer_bytes(position: u32, segment: u16, entry: u32) -> [u8; 10] {
    let mut bytes = [0u8; 10];
    bytes[..4].copy_from_slice(&position.to_le_bytes());
    bytes[4..6].copy_from_slice(&segment.to_le_bytes());
    bytes[6..10].copy_from_slice(&entry.to_le_bytes());
    bytes
}

/// Process one tag from the generic revision-8 dispute family.
///
/// DCG owns the shared DCR1/DRU1 transitions. Application form execution and
/// artifact verification are exposed through the manifest hooks, but their
/// tags remain refused until the corresponding part-B engine paths land.
pub fn process_generic_dispute_tag(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    match data.first().copied() {
        Some(TAG_VERIFY_TARGET) => verify_target(program, accounts, data, manifest),
        Some(TAG_VERIFY_READS) => verify_reads(program, accounts, data, manifest),
        Some(TAG_WEIGHTS_ANCHOR) => weights_anchor(program, accounts, data, manifest),
        Some(TAG_WEIGHTS_ROWS) => weights_rows(program, accounts, data, manifest),
        Some(TAG_EXECUTE) => execute(program, accounts, data, manifest),
        Some(TAG_RESTAGE) => restage(program, accounts, data, manifest),
        Some(TAG_VERIFY_ARTIFACTS) => verify_artifacts(program, accounts, data, manifest),
        Some(TAG_VERIFY_OUTPUTS) => verify_outputs(program, accounts, data, manifest),
        Some(TAG_VERIFY_RANGE_SLOTS) => verify_range_slots(program, accounts, data, manifest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Tag 122: delegate descriptor/model-row interpretation to the application,
/// then persist only the generic authenticated row anchor.
fn weights_anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_WEIGHTS_ANCHOR || accounts.len() != 3 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    let form = u16_at(&state, 174)?;
    let operation = u16_at(&state, 182)?;
    if state[176] != 1
        || state[177] != 0
        || accounts[1].key.as_ref() != &state[184..216]
        || !manifest
            .dispute_hooks()
            .requires_weight_rows(form, operation)
    {
        return Err(no(STATE));
    }
    document(program, &accounts[2], &state)?;
    let doc = accounts[2].try_borrow_data()?;
    let model_root: [u8; 32] = doc[264..296].try_into().map_err(|_| no(PROOF))?;
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let anchor = manifest
        .artifact_witness_verifier()
        .verify_descriptor_row_anchor(body.core, &model_root)
        .map_err(no)?;
    drop(raw);
    drop(doc);
    state[356..388].copy_from_slice(&anchor.root);
    u32_put(&mut state, 388, anchor.leaf_count);
    state[177] = 1;
    challenge::respond_event(accounts[0].key, &state, TAG_WEIGHTS_ANCHOR, 1, state[4]);
    Ok(())
}

/// Tag 123: authenticate the selected application rows without decoding a
/// model-specific tensor name or witness format in the DCG engine.
fn weights_rows(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_WEIGHTS_ROWS || accounts.len() != 2 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    let form = u16_at(&state, 174)?;
    let operation = u16_at(&state, 182)?;
    if state[176] != 1
        || state[177] != 1
        || accounts[1].key.as_ref() != &state[184..216]
        || !manifest
            .dispute_hooks()
            .requires_weight_rows(form, operation)
    {
        return Err(no(STATE));
    }
    let payload_len = usize::from(u16_at(&state, 280)?);
    let payload = state.get(282..282 + payload_len).ok_or(no(PROOF))?;
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let mut reads = Vec::with_capacity(body.read_count);
    for i in 0..body.read_count {
        reads.push(body.section(i)?.0);
    }
    let anchor = crate::app_api::ArtifactRowAnchor {
        root: state[356..388].try_into().map_err(|_| no(PROOF))?,
        leaf_count: u32_at(&state, 388)?,
    };
    manifest
        .artifact_witness_verifier()
        .verify_weight_rows_for_entry(
            body.weights,
            anchor,
            state[145],
            form,
            operation,
            payload,
            &reads,
        )
        .map_err(no)?;
    drop(raw);
    state[177] = 2;
    challenge::respond_event(accounts[0].key, &state, TAG_WEIGHTS_ROWS, 1, state[4]);
    Ok(())
}

/// Tag 127: authenticate application-owned artifact bytes and store the
/// generic progress marker consumed by tag 124.
fn verify_artifacts(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_VERIFY_ARTIFACTS || accounts.len() != 3 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    let form = u16_at(&state, 174)?;
    let operation = u16_at(&state, 182)?;
    if state[176] != 1
        || state[177] != 0
        || accounts[1].key.as_ref() != &state[184..216]
        || !manifest
            .dispute_hooks()
            .requires_artifact_block(form, operation)
    {
        return Err(no(STATE));
    }
    document(program, &accounts[2], &state)?;
    let doc = accounts[2].try_borrow_data()?;
    let model_root: [u8; 32] = doc[264..296].try_into().map_err(|_| no(PROOF))?;
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    manifest
        .artifact_witness_verifier()
        .verify_artifact_block(
            form,
            operation,
            u32_at(&state, 156)?,
            body.weights,
            body.core,
            &model_root,
        )
        .map_err(no)?;
    drop(raw);
    drop(doc);
    state[177] = 3;
    challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_ARTIFACTS, 1, state[4]);
    Ok(())
}

/// Tag 124: ask the application to replay the committed form, then compare
/// its output with every DCL2 write commitment and rule the challenge.
fn execute(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() < 1 || data[0] != TAG_EXECUTE || accounts.len() != 6 || !accounts[2].is_writable {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    let form = u16_at(&state, 174)?;
    let operation = u16_at(&state, 182)?;
    let reads_expected = usize::from(u16_at(&state, 178)?);
    let all_reads = if reads_expected == MAX_READS {
        u128::MAX
    } else {
        (1u128 << reads_expected) - 1
    };
    let hooks = manifest.dispute_hooks();
    let needs_weights = hooks.requires_weight_rows(form, operation);
    let needs_artifacts = hooks.requires_artifact_block(form, operation);
    if state[176] != 1
        || accounts[1].key.as_ref() != &state[184..216]
        || read_bits(&state)? != all_reads
        || (needs_weights && state[177] != 2)
        || (needs_artifacts && state[177] != 3)
    {
        return Err(no(INCOMPLETE));
    }
    document(program, &accounts[2], &state)?;
    pinned_tables(program, &state, &accounts[3], &accounts[4])?;
    if accounts[5].key.as_ref() != &state[PT2S_AT..PT2S_END] {
        return Err(no(PROOF));
    }
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    let (_, _, _, _, _, writes) =
        crate::closure_v2::proof::preimage_fields(body.target, &descriptor)?;
    let payload_len = usize::from(u16_at(&state, 280)?);
    let payload = state.get(282..282 + payload_len).ok_or(no(PROOF))?;
    let mut read_operands = Vec::with_capacity(body.read_count);
    for i in 0..body.read_count {
        read_operands.push(body.section(i)?.0);
    }
    // C1: the synthetic tag-88 leaf has no kernel; DCG rules it itself.
    // Tag 120 proved the posted target hashes to the canonical synthetic leaf,
    // so the executor is honest iff that equals the committed leaf.
    if form == SYNTHETIC_LEAF_FORM {
        let honest = crate::hash::sha256(&[body.target]) == state[104..136];
        let doc_revision = u16_at(&accounts[2].try_borrow_data()?, 4)?;
        drop(raw);
        if u16_at(&state, 6)? != challenge::VERSION || doc_revision != 7 {
            return Err(no(PROOF));
        }
        return challenge::rule_v8(
            program,
            accounts[0].key,
            &mut state,
            &accounts[2],
            if honest { 1 } else { 2 },
            crate::unified::events::CAUSE_VERDICT,
            0,
        );
    }
    // M3: only pass weights that tag 123 or 127 verified.
    let verified_weights: &[u8] = if state[177] == 2 || state[177] == 3 { body.weights } else { &[] };
    let artifacts: [&[u8]; 1] = [verified_weights];
    let mut output = vec![0u8; OUTPUT_BYTES];
    let output_len = hooks
        .replay_pt1(
            crate::app_api::ApplicationReplayRequest {
                machine: state[145],
                form,
                operation,
                payload,
                reads: &read_operands,
                artifact_operands: &artifacts,
                instruction_data: data,
                output_range: None,
            },
            &mut output,
        )
        .map_err(no)?;
    if output_len > output.len() {
        return Err(no(ROUTE));
    }
    output.truncate(output_len);
    let target = crate::closure_v2::Coordinate {
        position: u32_at(&state, 156)?,
        segment: u16_at(&state, 160)?,
        entry: u32_at(&state, 136)?,
    };
    let mut offset = 0usize;
    let mut honest = true;
    for write in writes.chunks_exact(WRITE_ROW) {
        let len = usize::try_from(u32_at(write, 4)?).map_err(|_| no(MALFORMED))?;
        let bytes = slice(&output, offset, len).map_err(|_| no(ROUTE))?;
        let digest = crate::closure_v2::write_digest(
            &descriptor,
            target,
            u16_at(write, 0)?,
            u64_at(write, 8)?,
            bytes,
        )
        .map_err(|_| no(PROOF))?;
        honest &= digest == write[16..48];
        offset = offset.checked_add(len).ok_or(no(MALFORMED))?;
    }
    if offset != output.len() {
        return Err(no(ROUTE));
    }
    let doc_revision = u16_at(&accounts[2].try_borrow_data()?, 4)?;
    drop(raw);
    if u16_at(&state, 6)? == challenge::VERSION {
        if doc_revision == 7 {
            challenge::rule_v8(
                program,
                accounts[0].key,
                &mut state,
                &accounts[2],
                if honest { 1 } else { 2 },
                crate::unified::events::CAUSE_VERDICT,
                0,
            )?;
        } else if doc_revision == 6 {
            rule_v6(
                accounts[0].key,
                &mut state,
                &accounts[2],
                if honest { 1 } else { 2 },
            )?;
        } else {
            return Err(no(PROOF));
        }
    } else {
        rule_legacy(&mut state, &accounts[2], honest)?;
    }
    Ok(())
}

fn rule_legacy(state: &mut [u8], document: &AccountInfo, honest: bool) -> ProgramResult {
    if !honest {
        let mut doc = document.try_borrow_mut_data()?;
        let wins = u32_at(&doc, 132)?.checked_add(1).ok_or(no(STATE))?;
        doc[132..136].copy_from_slice(&wins.to_le_bytes());
        let flags = u16_at(&doc, 6)? | 4;
        doc[6..8].copy_from_slice(&flags.to_le_bytes());
    }
    state[4] = 3;
    state[5] = if honest { 1 } else { 2 };
    Ok(())
}

fn rule_v6(
    challenge_key: &Pubkey,
    state: &mut [u8],
    document: &AccountInfo,
    winner: u8,
) -> ProgramResult {
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    let deadline = if winner == 2 {
        let terms = {
            let doc = document.try_borrow_data()?;
            let end = crate::unified::document::TERMS_AT
                .checked_add(crate::unified::terms::TERMS_BYTES)
                .ok_or(no(STATE))?;
            crate::unified::terms::Terms::decode(
                doc.get(crate::unified::document::TERMS_AT..end)
                    .ok_or(no(PROOF))?,
            )
            .map_err(no)?
        };
        let mut doc = document.try_borrow_mut_data()?;
        let wins = u32_at(&doc, 132)?.checked_add(1).ok_or(no(STATE))?;
        doc[132..136].copy_from_slice(&wins.to_le_bytes());
        let flags = u16_at(&doc, 6)? | document::FLAG_REFUTED;
        doc[6..8].copy_from_slice(&flags.to_le_bytes());
        if terms.settlement_program == [0; 32] {
            0
        } else {
            Clock::get()?
                .slot
                .checked_add(terms.custom_settle_window_slots)
                .ok_or(no(598))?
        }
    } else {
        u32_at(&document.try_borrow_data()?, 132)?;
        0
    };
    state[4] = challenge::PHASE_RULED;
    state[5] = winner;
    state[170..178].copy_from_slice(&deadline.to_le_bytes());
    state[178] = crate::unified::events::CAUSE_VERDICT;
    crate::unified::events::emit(
        crate::unified::events::RULING,
        &descriptor,
        crate::unified::events::Body::new()
            .key(challenge_key.as_ref())
            .u8(winner)
            .u8(crate::unified::events::CAUSE_VERDICT)
            .pad(2)
            .u32(0)
            .u32(u32_at(&document.try_borrow_data()?, 132)?)
            .pad(4),
    );
    Ok(())
}

fn verify_range_slots(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 7 || accounts.len() != 8 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
    let mut state = accounts[0].try_borrow_mut_data()?;
    if u16_at(&state, 6)? != challenge::VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    if state[176] != 1 || accounts[1].key.as_ref() != &state[184..216] {
        return Err(no(STATE));
    }
    document(program, &accounts[2], &state)?;
    pinned_tables(program, &state, &accounts[4], &accounts[5])?;
    if accounts[6].key.as_ref() != &state[PT2S_AT..PT2S_END] {
        return Err(no(PROOF));
    }
    crate::unified::plan::bind_pt2s(program, &accounts[6], &accounts[4], &accounts[5], None)
        .map_err(|_| no(PROOF))?;
    let doc = accounts[2].try_borrow_data()?;
    let descriptor: [u8; 32] = state[72..104].try_into().map_err(|_| no(PROOF))?;
    if accounts[7].owner != program || accounts[7].key.as_ref() != &doc[456..488] {
        return Err(no(PROOF));
    }
    document::positions(
        program,
        &accounts[3],
        &descriptor,
        u32_at(&doc, 72)?,
        false,
        PROOF,
    )?;
    let s = accounts[6].try_borrow_data()?;
    let routes = accounts[4].try_borrow_data()?;
    let geometry = accounts[5].try_borrow_data()?;
    let x = crate::unified::plan::view(&s, &routes, &geometry, &[], None).map_err(|_| no(PROOF))?;
    let index = u32_at(&state, 170)?;
    let position = u32_at(&state, 156)?;
    let entry = x.entry(position, index).map_err(no)?;
    let raw = response(program, &accounts[1], accounts[0].key, &state)?;
    let body = Body::parse(&raw)?;
    let read = usize::from(u16_at(data, 1)?);
    let first = usize::from(u16_at(data, 3)?);
    let count = usize::from(u16_at(data, 5)?);
    if read >= body.read_count || count == 0 || read_bits(&state)? >> read & 1 == 1 {
        return Err(no(MALFORMED));
    }
    let route = x.route(&entry, read as u16).map_err(no)?;
    let row = body.row(read)?;
    let (witness, kind, proof) = body.section(read)?;
    if kind != 2 || route.binding_kind != 2 || witness.len() != route.byte_length as usize {
        return Err(no(ROUTE));
    }
    let slots = usize::try_from(route.range_end - route.range_first).map_err(|_| no(ROUTE))?;
    let end = first.checked_add(count).ok_or(no(MALFORMED))?;
    if slots > MAX_RANGE_SLOTS || end > slots {
        return Err(no(MALFORMED));
    }
    let in_flight = usize::from(u16_at(&state, 406)?);
    let next = usize::from(u16_at(&state, 408)?);
    if (first == 0 && in_flight != 0) || (first != 0 && (in_flight != read + 1 || first != next)) {
        return Err(no(MALFORMED));
    }
    let q0 = route
        .range_first
        .checked_add(u32::try_from(first).map_err(|_| no(MALFORMED))?)
        .ok_or(no(MALFORMED))?;
    let q_end = q0
        .checked_add(u32::try_from(count).map_err(|_| no(MALFORMED))?)
        .ok_or(no(MALFORMED))?;
    let leaves = unified_range_leaves(
        &x,
        &state,
        &accounts[7],
        &descriptor,
        route,
        witness,
        q0..q_end,
    )?;
    for (i, leaf) in leaves.iter().enumerate() {
        let at = OUTPUT_AT + 32 * (first + i);
        state[at..at + 32].copy_from_slice(leaf);
    }
    if end == slots {
        let all: Vec<[u8; 32]> = state[OUTPUT_AT..OUTPUT_AT + 32 * slots]
            .chunks_exact(32)
            .map(|v| v.try_into().expect("32-byte slot digest"))
            .collect();
        unified_range_close(
            &x,
            &state,
            &accounts[7],
            &descriptor,
            route,
            row,
            proof,
            &all,
        )?;
        drop(raw);
        drop(x);
        drop(s);
        drop(routes);
        drop(geometry);
        drop(doc);
        let bits = read_bits(&state)? | 1u128 << read;
        put_read_bits(&mut state, bits);
        state[OUTPUT_AT..OUTPUT_AT + 32 * slots].fill(0);
        state[406..414].fill(0);
    } else {
        u16_put(&mut state, 406, (read + 1) as u16);
        u16_put(&mut state, 408, end as u16);
    }
    challenge::respond_event(accounts[0].key, &state, TAG_VERIFY_RANGE_SLOTS, 1, state[4]);
    Ok(())
}

/// Close the executor's staged response and clear all generic verification
/// progress so it can retry before the unchanged deadline.
fn restage(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
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
    live(program, &accounts[2], manifest)?;
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
    // C2: after tag 120 byte 219 holds a routes-key byte; the canonical bump
    // lives in the marked copy. Restage must keep it for re-respond and settle.
    let response_bump = if state[176] == 1 {
        if state[RESPONSE_BUMP_COPY_MARKER_AT] != 1 {
            return Err(no(PROOF));
        }
        state[RESPONSE_BUMP_COPY_AT]
    } else {
        state[challenge::RESPONSE_BUMP_AT]
    };
    expect_derived_with_bump(
        &accounts[0],
        program,
        &response_seeds,
        response_bump,
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
    state[challenge::RESPONSE_BUMP_AT] = response_bump;
    challenge::respond_event(accounts[2].key, &state, TAG_RESTAGE, 1, state[4]);
    Ok(())
}

/// Verify that the app's claimed output bytes produce every committed write
/// digest before an app replay is allowed to compare its output.
fn verify_outputs(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &crate::app_api::ApplicationProgramManifest,
) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_VERIFY_OUTPUTS || accounts.len() != 2 {
        return Err(no(MALFORMED));
    }
    live(program, &accounts[0], manifest)?;
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
        let read_count = usize::from(u16_at(raw, 6)?);
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
        let next_index = index.checked_add(1).ok_or(no(MALFORMED))?;
        let end = if next_index < self.read_count {
            let next_at = self
                .head
                .checked_add(next_index.checked_mul(4).ok_or(no(MALFORMED))?)
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
        let preimage_len = usize::from(self.u16()?);
        let preimage = self.take(preimage_len)?;
        let siblings = usize::from(self.u8()?);
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

        let mut out_of_bounds = raw.clone();
        out_of_bounds[head..head + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Body::parse(&out_of_bounds)
            .unwrap()
            .section_exact(0)
            .is_err());
        let mut overlaps_directory = raw;
        overlaps_directory[head..head + 4].copy_from_slice(&(head as u32).to_le_bytes());
        assert!(Body::parse(&overlaps_directory)
            .unwrap()
            .section_exact(0)
            .is_err());
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
