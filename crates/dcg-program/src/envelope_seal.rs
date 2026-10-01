//! PT1 envelope seal (ESL1): every committed entry is disputable within bounds.
//!
//! A frozen per-form registry (DRP1) records, for each PT1 form of machine
//! `basanos/qwen35-4b-pt1/1`, its respond path, witness kind, the shape the
//! census measured, and the measured CU of the respond's kernel step (tag 124)
//! and of its costliest other step. A template admission record (DEA1) holds
//! one bit per entry of one sealed PT1S template, set only when that entry
//! passes against one frozen registry (entries may be checked in any order);
//! a DCM2 v4 document binds the registry address, its table root, and that
//! admission record, and tag 97 refuses to seal it until every bit is set.
//! Design and every [C] choice: docs/design/dcg-envelope-seal-2026-09-23.md.
//!
//! What the program checks itself: a row's respond path and witness kind
//! equal what this image compiles (`closure_v2_generic`); every entry's form
//! has a row with a respond path; both CU numbers are measured and at most
//! 1,400,000; the entry fits the compiled respond limits (at most 64 reads,
//! no supplied/asserted read, a payload of at most 64 bytes, linear output of
//! at most 2,048 bytes); and its route counts and bytes at the template's last
//! position fit the row's measured shape. What it trusts (TA1): the compiled
//! authority froze only measured CU numbers.

use crate::{
    account_provenance::CanonicalBump, compatibility::profile_v1 as generic, hash,
    position_template as pt,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent, system_instruction, system_program,
    sysvar::Sysvar,
};

pub const TAG_REGISTRY_CREATE: u8 = 150;
pub const TAG_REGISTRY_WRITE: u8 = 151;
pub const TAG_REGISTRY_FREEZE: u8 = 152;
pub const TAG_ADMISSION_BEGIN: u8 = 153;
pub const TAG_ADMISSION_STEP: u8 = 154;

// Refusal sub-band 770-789 (envelope seal).
pub const REGISTRY_ACCOUNT: u32 = 770;
pub const REGISTRY_AUTHORITY: u32 = 771;
pub const REGISTRY_STATE: u32 = 772;
pub const REGISTRY_EPOCH: u32 = 773;
pub const REGISTRY_ROOT: u32 = 774;
pub const ROW_MALFORMED: u32 = 775;
pub const ROW_CAPABILITY: u32 = 776;
pub const FORM_ABSENT: u32 = 777;
pub const WITHDRAW_ONLY: u32 = 778;
pub const OVER_CU: u32 = 779;
pub const SHAPE_BOUND: u32 = 780;
pub const RESPOND_LIMIT: u32 = 781;
pub const ADMISSION_STATE: u32 = 782;
pub const ENVELOPE_CANCEL: u32 = 783;
pub const TEMPLATE_BINDING: u32 = 784;

/// Compiled envelope epoch. Increment it whenever this image changes a
/// respond path, a kernel body, or a check below; old registries then stop
/// admitting and old envelope documents stop opening challenges.
/// 1: r5 respond set (testnet GsqQn2…, image ba52c6db). 2: + DeltaNet forms
/// 16/17/19/22/30, respond reads ≤ 128, payload ≤ 66. 3: + forms 1 (DWW1
/// embed row) and 2 (whole gamma), PROMPT_SWITCH reads admitted (origin
/// proven against the prompt commitment), forms 10/21 chunked, form-2 kernel
/// honours its tile and per-head norms.
pub const EPOCH: u32 = 3;
/// The Fogo transaction meter.
pub const CU_LIMIT: u32 = 1_400_000;
pub const MAX_ROWS: u32 = 64;
pub const MACHINE_NAME: &[u8] = b"basanos/qwen35-4b-pt1/1";
pub const REGISTRY_HEADER: usize = 192;
pub const ROW_BYTES: usize = 64;
/// DEA1 header; a one-bit-per-entry admitted bitmap follows it.
pub const ADMISSION_HEADER: usize = 192;
pub const MAX_STEP: u16 = 256;
pub const REGISTRY_SEED: &[u8] = b"dcg-envelope-registry-pt1";
pub const ADMISSION_SEED: &[u8] = b"dcg-envelope-admission";
pub const ROOT_DOMAIN: &[u8] = b"basanos/dcg-envelope-seal-registry/1";
/// Respond path ids. 0: none (withdraw-only in this image); 1: generic PT1
/// respond, tags 120-124 plus 122/123 (DWW1) or 127 (artifacts).
pub const RESPOND_NONE: u8 = 0;
pub const RESPOND_GENERIC: u8 = 1;
/// Witness kinds: routed operands only, DWW1 weight rows, one position-table
/// row, whole model tensors.
pub const WITNESS_ROUTED: u8 = 0;
pub const WITNESS_DWW1: u8 = 1;
pub const WITNESS_POSITION_ROW: u8 = 2;
pub const WITNESS_TENSORS: u8 = 3;
/// PT1S phase-3 layout (`pt1_onchain`).
const PT1S_INDEX: usize = 5285;

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("DCG_ENVELOPE_AUTHORITY_HEX must be lowercase hex"),
    }
}
const fn hex32(hex: &str) -> [u8; 32] {
    let b = hex.as_bytes();
    assert!(
        b.len() == 64,
        "DCG_ENVELOPE_AUTHORITY_HEX must be 64 hex digits"
    );
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
/// Host builds (native tests) default to the public test authority whose
/// Ed25519 seed is 32 bytes of 0xE5; it is never a deploy authority. An SBF
/// build without `DCG_ENVELOPE_AUTHORITY_HEX` compiles no authority, so no
/// registry can be created and no v4 document can be initialized.
#[cfg(not(target_os = "solana"))]
const DEFAULT_AUTHORITY: Option<[u8; 32]> = Some(hex32(
    "4e6008b01b74e49e38d8b11392bfaccc7b5bff86ca2048cbb0f783633a61e2dd",
));
#[cfg(target_os = "solana")]
const DEFAULT_AUTHORITY: Option<[u8; 32]> = None;
pub const AUTHORITY: Option<[u8; 32]> = match option_env!("DCG_ENVELOPE_AUTHORITY_HEX") {
    Some(hex) => Some(hex32(hex)),
    None => DEFAULT_AUTHORITY,
};

fn no(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
fn u16_at(b: &[u8], at: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(no(ROW_MALFORMED))?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(no(ROW_MALFORMED))?
            .try_into()
            .unwrap(),
    ))
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn registry_address(program: &Pubkey, registry_id: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            REGISTRY_SEED,
            &EPOCH.to_le_bytes(),
            &registry_id.to_le_bytes(),
        ],
        program,
    )
}
pub fn admission_address(program: &Pubkey, registry: &Pubkey, pt1_state: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ADMISSION_SEED, registry.as_ref(), pt1_state.as_ref()],
        program,
    )
}
pub fn admission_bytes(entries: u32) -> usize {
    ADMISSION_HEADER + (entries as usize).div_ceil(8)
}

/// One 64-byte DRP1 row. Offsets: 0 form_id:u16, 2 respond_path:u8,
/// 3 witness_kind:u8, 4 max_reads:u16, 6 max_writes:u16, 8 max_read_bytes:u32,
/// 12 max_write_bytes:u32, 16 max_payload_bytes:u32, 20 execute_cu:u32,
/// 24 respond_cu:u32, 28 measured_position:u32, 32 measured_entry:u32,
/// 36..64 zero. CU 0 means "not measured".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub form_id: u16,
    pub respond_path: u8,
    pub witness_kind: u8,
    pub max_reads: u16,
    pub max_writes: u16,
    pub max_read_bytes: u32,
    pub max_write_bytes: u32,
    pub max_payload_bytes: u32,
    pub execute_cu: u32,
    pub respond_cu: u32,
    pub measured_position: u32,
    pub measured_entry: u32,
}

impl Row {
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != ROW_BYTES || raw[36..64] != [0; 28] {
            return Err(ROW_MALFORMED);
        }
        let h = |at: usize| u16::from_le_bytes([raw[at], raw[at + 1]]);
        let w = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let row = Row {
            form_id: h(0),
            respond_path: raw[2],
            witness_kind: raw[3],
            max_reads: h(4),
            max_writes: h(6),
            max_read_bytes: w(8),
            max_write_bytes: w(12),
            max_payload_bytes: w(16),
            execute_cu: w(20),
            respond_cu: w(24),
            measured_position: w(28),
            measured_entry: w(32),
        };
        if row.form_id == 0
            || row.respond_path > RESPOND_GENERIC
            || row.witness_kind > WITNESS_TENSORS
        {
            return Err(ROW_MALFORMED);
        }
        Ok(row)
    }
    pub fn encode(&self) -> [u8; ROW_BYTES] {
        let mut out = [0u8; ROW_BYTES];
        out[0..2].copy_from_slice(&self.form_id.to_le_bytes());
        out[2] = self.respond_path;
        out[3] = self.witness_kind;
        out[4..6].copy_from_slice(&self.max_reads.to_le_bytes());
        out[6..8].copy_from_slice(&self.max_writes.to_le_bytes());
        for (at, v) in [
            (8, self.max_read_bytes),
            (12, self.max_write_bytes),
            (16, self.max_payload_bytes),
            (20, self.execute_cu),
            (24, self.respond_cu),
            (28, self.measured_position),
            (32, self.measured_entry),
        ] {
            out[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

/// What this image compiles for `form`: (respond path, witness kind).
pub fn compiled_capability(form: u16) -> (u8, u8) {
    let respond = if generic::supported_form(form) {
        RESPOND_GENERIC
    } else {
        RESPOND_NONE
    };
    (respond, generic::witness_kind(form))
}

/// Registry table root over the frozen header identity and every row, in
/// stored (strictly ascending form) order.
pub fn table_root(
    registry_id: u32,
    authority: &[u8; 32],
    census: &[u8; 32],
    rows: &[u8],
) -> [u8; 32] {
    let mut name = [0u8; 64];
    name[..MACHINE_NAME.len()].copy_from_slice(MACHINE_NAME);
    hash::sha256(&[
        ROOT_DOMAIN,
        &EPOCH.to_le_bytes(),
        &registry_id.to_le_bytes(),
        &((rows.len() / ROW_BYTES) as u32).to_le_bytes(),
        authority,
        &name,
        census,
        rows,
    ])
}

/// Binary search a frozen, strictly ascending row table.
pub fn find_row(rows: &[u8], form: u16) -> Result<Option<Row>, u32> {
    let n = rows.len() / ROW_BYTES;
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let at = mid * ROW_BYTES;
        let id = u16::from_le_bytes([rows[at], rows[at + 1]]);
        if id == form {
            return Row::decode(&rows[at..at + ROW_BYTES]).map(Some);
        }
        if id < form {
            lo = mid + 1
        } else {
            hi = mid
        }
    }
    Ok(None)
}

/// The per-entry seal rule, in refusal order: absent 777, withdraw-only 778,
/// unmeasured or over-limit CU 779, compiled respond limits 781, measured
/// shape 780. Shape is evaluated at the template's last position, where
/// T-scaled and range lengths are largest. Asserted (class 1) reads are
/// refused at any position: the generic respond has no origin proof for an
/// assertion. PROMPT_SWITCH supplied reads are admitted: tag 121 proves them
/// against the DCM2 v3 prompt commitment (DRS1 fold).
pub fn check_entry(
    rows: &[u8],
    t: &pt::Template<'_>,
    c: pt::Clause12<'_>,
    payload_index: &[u8],
    index: u32,
) -> Result<Row, u32> {
    let e = t.entry(index)?;
    let row = find_row(rows, e.kernel_index)?.ok_or(FORM_ABSENT)?;
    if row.respond_path != RESPOND_GENERIC {
        return Err(WITHDRAW_ONLY);
    }
    if row.execute_cu == 0
        || row.respond_cu == 0
        || row.execute_cu > CU_LIMIT
        || row.respond_cu > CU_LIMIT
    {
        return Err(OVER_CU);
    }
    let last = t.position_count.checked_sub(1).ok_or(TEMPLATE_BINDING)?;
    let at = 4 * index as usize;
    let start = u32::from_le_bytes(
        payload_index
            .get(at..at + 4)
            .ok_or(TEMPLATE_BINDING)?
            .try_into()
            .unwrap(),
    );
    let end = u32::from_le_bytes(
        payload_index
            .get(at + 4..at + 8)
            .ok_or(TEMPLATE_BINDING)?
            .try_into()
            .unwrap(),
    );
    let payload = end
        .checked_sub(start)
        .and_then(|n| n.checked_sub(6))
        .ok_or(TEMPLATE_BINDING)?;
    let entry = t.instantiate_with(c, index, last)?;
    let (mut read_bytes, mut write_bytes) = (0u64, 0u64);
    let mut asserted_read = false;
    for ordinal in 0..entry.route_count() {
        let r = entry.route(ordinal as u16)?;
        if r.direction == 0 {
            read_bytes += r.byte_length as u64;
            let raw = pt::route_at(t.clause5, e, ordinal as u16)?;
            // A supplied (class 2) read is admissible only through PROMPT_SWITCH.
            asserted_read |= raw.read_class == 1
                || (raw.read_class == 2 && c.prompt_for(index, ordinal as u16)?.is_none());
        } else {
            write_bytes += r.byte_length as u64;
        }
    }
    if e.read_count as usize > generic::RESPOND_MAX_READS
        || asserted_read
        || payload as usize > generic::RESPOND_MAX_PAYLOAD
        || (e.kernel_index == generic::LINEAR_FORM_ID
            && write_bytes > generic::RESPOND_MAX_LINEAR_OUTPUT as u64)
    {
        return Err(RESPOND_LIMIT);
    }
    if e.read_count > row.max_reads
        || e.write_count > row.max_writes
        || read_bytes > row.max_read_bytes as u64
        || write_bytes > row.max_write_bytes as u64
        || payload > row.max_payload_bytes
    {
        return Err(SHAPE_BOUND);
    }
    Ok(row)
}

/// PT1X is the v4 base triple and carries its phase-3 payload index in state.
/// Evaluate the same respond limits at the template's last position through
/// the sealed PT2S view. The entry number is the instantiated PT2P entry
/// number; surviving base entries use their PT1X payload row and generated
/// entries have no independent payload row.
pub fn check_entry_pt1x(
    rows: &[u8],
    x: &crate::pt2p::Pt2p<'_>,
    entry_index: u32,
) -> Result<Row, u32> {
    let last = x.position_count.checked_sub(1).ok_or(TEMPLATE_BINDING)?;
    let e = x.entry(last, entry_index).map_err(|_| TEMPLATE_BINDING)?;
    let row = find_row(rows, e.kernel_index)?.ok_or(FORM_ABSENT)?;
    if row.respond_path != RESPOND_GENERIC {
        return Err(WITHDRAW_ONLY);
    }
    if row.execute_cu == 0
        || row.respond_cu == 0
        || row.execute_cu > CU_LIMIT
        || row.respond_cu > CU_LIMIT
    {
        return Err(OVER_CU);
    }
    let payload = match e.old_index() {
        Some(old) => x.base_payload_len(old).map_err(|_| TEMPLATE_BINDING)?,
        None => 0,
    };
    let (mut read_bytes, mut write_bytes) = (0u64, 0u64);
    let mut supplied_without_prompt = false;
    for ordinal in 0..e.route_count() {
        let r = x.route(&e, ordinal as u16).map_err(|_| TEMPLATE_BINDING)?;
        if r.direction == 0 {
            read_bytes = read_bytes
                .checked_add(r.byte_length as u64)
                .ok_or(TEMPLATE_BINDING)?;
            let (raw, _) = x
                .raw_route(&e, ordinal as u16)
                .map_err(|_| TEMPLATE_BINDING)?;
            let prompt = match e.old_index() {
                Some(old) => {
                    x.c.prompt_for(old, ordinal as u16)
                        .map_err(|_| TEMPLATE_BINDING)?
                }
                None => None,
            };
            supplied_without_prompt |=
                raw.read_class == 1 || (raw.read_class == 2 && prompt.is_none());
        } else {
            write_bytes = write_bytes
                .checked_add(r.byte_length as u64)
                .ok_or(TEMPLATE_BINDING)?;
        }
    }
    if e.read_count as usize > generic::RESPOND_MAX_READS
        || supplied_without_prompt
        || payload > generic::RESPOND_MAX_PAYLOAD
        || (e.kernel_index == generic::LINEAR_FORM_ID
            && write_bytes > generic::RESPOND_MAX_LINEAR_OUTPUT as u64)
    {
        return Err(RESPOND_LIMIT);
    }
    if e.read_count > row.max_reads
        || e.write_count > row.max_writes
        || read_bytes > row.max_read_bytes as u64
        || write_bytes > row.max_write_bytes as u64
        || payload as u64 > row.max_payload_bytes as u64
    {
        return Err(SHAPE_BOUND);
    }
    Ok(row)
}

fn pt1x_view<'a>(
    pt2s: &'a [u8],
    routes: &'a [u8],
    geometry: &'a [u8],
    payloads: &'a [u8],
    state: &'a [u8],
) -> Result<crate::pt2p::Pt2p<'a>, u32> {
    let index = state.get(PT1S_INDEX..).ok_or(TEMPLATE_BINDING)?;
    crate::unified::plan::view(pt2s, routes, geometry, payloads, Some(index))
        .map_err(|_| TEMPLATE_BINDING)
}

fn authority_signer(signer: &AccountInfo) -> ProgramResult {
    let key = AUTHORITY.ok_or(no(REGISTRY_AUTHORITY))?;
    if !signer.is_signer || signer.key.to_bytes() != key {
        return Err(no(REGISTRY_AUTHORITY));
    }
    Ok(())
}

fn create_pda<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: CanonicalBump,
    size: usize,
) -> ProgramResult {
    if account.key != bump.address()
        || !payer.is_signer
        || !payer.is_writable
        || !account.is_writable
        || *system.key != system_program::id()
    {
        return Err(no(REGISTRY_ACCOUNT));
    }
    // Fresh means system-owned, empty, unfunded: an existing record is never
    // recreated or reset.
    if account.lamports() != 0 || !account.data_is_empty() || *account.owner != system_program::id()
    {
        return Err(no(REGISTRY_STATE));
    }
    let lamports = Rent::get()?.minimum_balance(size);
    let bump_seed = [bump.value()];
    let mut signer_seeds = seeds.to_vec();
    signer_seeds.push(&bump_seed);
    invoke_signed(
        &system_instruction::create_account(payer.key, account.key, lamports, size as u64, program),
        &[payer.clone(), account.clone(), system.clone()],
        &[&signer_seeds],
    )
}

/// A frozen-or-not DRP1 at its PDA, under this image's epoch.
pub struct RegistryView {
    pub registry_id: u32,
    pub row_count: u32,
    pub written: u32,
    pub frozen: bool,
    pub root: [u8; 32],
}

pub fn registry_view(
    program: &Pubkey,
    account: &AccountInfo,
) -> Result<RegistryView, ProgramError> {
    if account.owner != program {
        return Err(no(REGISTRY_ACCOUNT));
    }
    let raw = account.try_borrow_data()?;
    if raw.len() < REGISTRY_HEADER || raw[..4] != *b"DRP1" || u16_at(&raw, 4)? != 1 {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if u32_at(&raw, 8)? != EPOCH {
        return Err(no(REGISTRY_EPOCH));
    }
    let registry_id = u32_at(&raw, 12)?;
    let row_count = u32_at(&raw, 16)?;
    if *account.key != registry_address(program, registry_id).0
        || raw.len() != REGISTRY_HEADER + row_count as usize * ROW_BYTES
        || raw[184..192] != [0; 8]
        || u16_at(&raw, 6)? & !1 != 0
    {
        return Err(no(REGISTRY_ACCOUNT));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&raw[152..184]);
    Ok(RegistryView {
        registry_id,
        row_count,
        written: u32_at(&raw, 20)?,
        frozen: u16_at(&raw, 6)? & 1 != 0,
        root,
    })
}

/// A frozen registry whose stored root equals `expected` (tampered-root 774).
pub fn frozen_registry(
    program: &Pubkey,
    account: &AccountInfo,
    expected: &[u8],
) -> Result<RegistryView, ProgramError> {
    let view = registry_view(program, account)?;
    if !view.frozen {
        return Err(no(REGISTRY_STATE));
    }
    if view.root[..] != *expected {
        return Err(no(REGISTRY_ROOT));
    }
    Ok(view)
}

/// tag 150: registry_id:u32 | row_count:u32 | census_digest[32].
/// Accounts: authority(s,w), registry PDA(w), system.
pub fn registry_create(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 41 {
        return Err(no(ROW_MALFORMED));
    }
    authority_signer(&accounts[0])?;
    let registry_id = u32_at(data, 1)?;
    let rows = u32_at(data, 5)?;
    if rows == 0 || rows > MAX_ROWS || data[9..41] == [0; 32] {
        return Err(no(ROW_MALFORMED));
    }
    let epoch_bytes = EPOCH.to_le_bytes();
    let registry_id_bytes = registry_id.to_le_bytes();
    let bump = CanonicalBump::find(&[REGISTRY_SEED, &epoch_bytes, &registry_id_bytes], program);
    if accounts[1].key != bump.address() {
        return Err(no(REGISTRY_ACCOUNT));
    }
    let size = REGISTRY_HEADER + rows as usize * ROW_BYTES;
    create_pda(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[2],
        &[REGISTRY_SEED, &epoch_bytes, &registry_id_bytes],
        bump,
        size,
    )?;
    let mut raw = accounts[1].try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DRP1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut raw, 8, EPOCH);
    put_u32(&mut raw, 12, registry_id);
    put_u32(&mut raw, 16, rows);
    raw[24..56].copy_from_slice(accounts[0].key.as_ref());
    raw[56..56 + MACHINE_NAME.len()].copy_from_slice(MACHINE_NAME);
    raw[120..152].copy_from_slice(&data[9..41]);
    Ok(())
}

/// tag 151: registry_id:u32 | index:u32 | row[64]. Rows append in strictly
/// ascending form order; a row's respond path and witness kind must equal the
/// image's (776). Accounts: authority(s), registry(w).
pub fn registry_write(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 2 || data.len() != 9 + ROW_BYTES || !accounts[1].is_writable {
        return Err(no(ROW_MALFORMED));
    }
    authority_signer(&accounts[0])?;
    let view = registry_view(program, &accounts[1])?;
    let index = u32_at(data, 5)?;
    if view.registry_id != u32_at(data, 1)? {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if view.frozen || index != view.written || index >= view.row_count {
        return Err(no(REGISTRY_STATE));
    }
    let row = Row::decode(&data[9..]).map_err(no)?;
    let mut raw = accounts[1].try_borrow_mut_data()?;
    if index > 0 {
        let at = REGISTRY_HEADER + (index as usize - 1) * ROW_BYTES;
        if u16_at(&raw, at)? >= row.form_id {
            return Err(no(ROW_MALFORMED));
        }
    }
    if compiled_capability(row.form_id) != (row.respond_path, row.witness_kind) {
        return Err(no(ROW_CAPABILITY));
    }
    let at = REGISTRY_HEADER + index as usize * ROW_BYTES;
    raw[at..at + ROW_BYTES].copy_from_slice(&data[9..]);
    put_u32(&mut raw, 20, index + 1);
    Ok(())
}

/// tag 152: registry_id:u32. Recompute the table root on chain and freeze.
/// Accounts: authority(s), registry(w).
pub fn registry_freeze(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 2 || data.len() != 5 || !accounts[1].is_writable {
        return Err(no(ROW_MALFORMED));
    }
    authority_signer(&accounts[0])?;
    let view = registry_view(program, &accounts[1])?;
    if view.registry_id != u32_at(data, 1)? {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if view.frozen || view.written != view.row_count {
        return Err(no(REGISTRY_STATE));
    }
    let mut raw = accounts[1].try_borrow_mut_data()?;
    let authority: [u8; 32] = raw[24..56].try_into().unwrap();
    let census: [u8; 32] = raw[120..152].try_into().unwrap();
    let root = table_root(
        view.registry_id,
        &authority,
        &census,
        &raw[REGISTRY_HEADER..],
    );
    raw[152..184].copy_from_slice(&root);
    raw[6..8].copy_from_slice(&1u16.to_le_bytes());
    Ok(())
}

fn template<'a>(
    routes: &'a [u8],
    geometry: &'a [u8],
    allow_pxr1: bool,
) -> Result<(pt::Template<'a>, pt::Clause12<'a>), ProgramError> {
    let (c, _) = pt::clause12_layout(geometry).map_err(no)?;
    let n = if allow_pxr1 {
        pt::route_header_v4_shallow(routes).map_err(no)?.0
    } else {
        pt::route_header(routes).map_err(no)?.0
    };
    if n != c.entries_per_position || c.position_count == 0 {
        return Err(no(TEMPLATE_BINDING));
    }
    Ok((
        pt::Template {
            clause5: routes,
            clause12: geometry,
            position_count: c.position_count,
            prompt_positions: c.prompt_positions,
            max_producer_delta: c.max_producer_delta,
            entries_per_position: n,
            leaf_storage_mode: c.leaf_storage_mode,
        },
        c,
    ))
}

/// PT1S in phase 3 (or a fully bound PT1X) with its base accounts. The legacy
/// PT1S form keeps its original metas; PT1X appends payloads and sealed PT2S.
fn bound_template(
    program: &Pubkey,
    state: &AccountInfo,
    routes: &AccountInfo,
    geometry: &AccountInfo,
    payloads: Option<&AccountInfo>,
    pt2s: Option<&AccountInfo>,
) -> ProgramResult {
    if state.owner != program || routes.owner != program || geometry.owner != program {
        return Err(no(TEMPLATE_BINDING));
    }
    let s = state.try_borrow_data()?;
    if !crate::pt1_onchain::is_sealed_template(&s)
        || routes.key.as_ref() != &s[37..69]
        || geometry.key.as_ref() != &s[69..101]
        || routes.data_len() != u32_at(&s, 133)? as usize
        || geometry.data_len() != u32_at(&s, 137)? as usize
    {
        return Err(no(TEMPLATE_BINDING));
    }
    if crate::pt1_onchain::is_pt1x(&s) {
        let (Some(payloads), Some(pt2s)) = (payloads, pt2s) else {
            return Err(no(TEMPLATE_BINDING));
        };
        crate::unified::plan::bind_pt2s(program, pt2s, routes, geometry, Some(payloads))
            .map_err(|_| no(TEMPLATE_BINDING))?;
        crate::unified::plan::bind_pt1s(program, pt2s, state).map_err(|_| no(TEMPLATE_BINDING))?;
        let sealed = pt2s.try_borrow_data()?;
        let compiler = crate::pt2p::Program::decode(&sealed[crate::pt2p_onchain::OFF_PWR1..])
            .map_err(|_| no(TEMPLATE_BINDING))?;
        if crate::unified::plan::compiler_version(&compiler) != Some(1) {
            return Err(no(TEMPLATE_BINDING));
        }
    } else if payloads.is_some() || pt2s.is_some() {
        return Err(no(TEMPLATE_BINDING));
    }
    Ok(())
}

/// tag 153: begin the admission of one PT1S template against one frozen
/// registry. DEA1: 0 "DEA1" | 4 version:u16 | 6 flags:u16 (bit 0 complete) |
/// 8 registry[32] | 40 table_root[32] | 72 PT1S[32] | 104 PT1S SHA-256[32] |
/// 136 entries:u32 | 140 admitted:u32 | 144 position_count:u32 | 148 zero[44]
/// | 192 admitted bitmap (bit i = entry i passed). Permissionless. The PT1S
/// account form is payer(s,w), DEA1 PDA(w), registry, PT1S, routes, geometry,
/// system. PT1X appends payloads and the PT2S it is bound to (9 accounts).
pub fn admission_begin(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 7 | 9) || data.len() != 1 {
        return Err(no(ADMISSION_STATE));
    }
    let is_pt1x = {
        let s = accounts[3].try_borrow_data()?;
        crate::pt1_onchain::is_pt1x(&s)
    };
    if is_pt1x != (accounts.len() == 9) {
        return Err(no(TEMPLATE_BINDING));
    }
    let view = registry_view(program, &accounts[2])?;
    if !view.frozen {
        return Err(no(REGISTRY_STATE));
    }
    let (payloads, pt2s) = if is_pt1x {
        (Some(&accounts[7]), Some(&accounts[8]))
    } else {
        (None, None)
    };
    bound_template(
        program,
        &accounts[3],
        &accounts[4],
        &accounts[5],
        payloads,
        pt2s,
    )?;
    let bump = CanonicalBump::find(
        &[
            ADMISSION_SEED,
            accounts[2].key.as_ref(),
            accounts[3].key.as_ref(),
        ],
        program,
    );
    if accounts[1].key != bump.address() {
        return Err(no(ADMISSION_STATE));
    }
    let (entries, positions, digest) = if is_pt1x {
        let routes = accounts[4].try_borrow_data()?;
        let geometry = accounts[5].try_borrow_data()?;
        let payloads = accounts[7].try_borrow_data()?;
        let pt2s = accounts[8].try_borrow_data()?;
        let state = accounts[3].try_borrow_data()?;
        let x = pt1x_view(&pt2s, &routes, &geometry, &payloads, &state).map_err(no)?;
        let last = x
            .position_count
            .checked_sub(1)
            .ok_or(no(TEMPLATE_BINDING))?;
        let entries = x.entry_count(last).map_err(|_| no(TEMPLATE_BINDING))?;
        (entries, x.position_count, hash::sha256(&[&state]))
    } else {
        let routes = accounts[4].try_borrow_data()?;
        let geometry = accounts[5].try_borrow_data()?;
        let state = accounts[3].try_borrow_data()?;
        let (t, _) = template(&routes, &geometry, false)?;
        if state.len() < PT1S_INDEX + 4 * (t.entries_per_position as usize + 1) {
            return Err(no(TEMPLATE_BINDING));
        }
        (
            t.entries_per_position,
            t.position_count,
            hash::sha256(&[&state]),
        )
    };
    create_pda(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[6],
        &[
            ADMISSION_SEED,
            accounts[2].key.as_ref(),
            accounts[3].key.as_ref(),
        ],
        bump,
        admission_bytes(entries),
    )
    .map_err(|e| {
        if e == no(REGISTRY_STATE) {
            no(ADMISSION_STATE)
        } else {
            e
        }
    })?;
    let mut raw = accounts[1].try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DEA1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[8..40].copy_from_slice(accounts[2].key.as_ref());
    raw[40..72].copy_from_slice(&view.root);
    raw[72..104].copy_from_slice(accounts[3].key.as_ref());
    raw[104..136].copy_from_slice(&digest);
    put_u32(&mut raw, 136, entries);
    put_u32(&mut raw, 144, positions);
    Ok(())
}

/// Admission record facts: (registry, root, PT1S key, PT1S SHA-256, complete).
pub struct AdmissionView {
    pub registry: [u8; 32],
    pub root: [u8; 32],
    pub state: [u8; 32],
    pub state_sha256: [u8; 32],
    pub entries: u32,
    pub admitted: u32,
    pub complete: bool,
}

pub fn admission_view(
    program: &Pubkey,
    account: &AccountInfo,
) -> Result<AdmissionView, ProgramError> {
    if account.owner != program {
        return Err(no(ADMISSION_STATE));
    }
    let raw = account.try_borrow_data()?;
    if raw.len() < ADMISSION_HEADER
        || raw[..4] != *b"DEA1"
        || u16_at(&raw, 4)? != 1
        || u16_at(&raw, 6)? & !1 != 0
        || raw[148..192] != [0; 44]
    {
        return Err(no(ADMISSION_STATE));
    }
    let a = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().unwrap() };
    let view = AdmissionView {
        registry: a(8),
        root: a(40),
        state: a(72),
        state_sha256: a(104),
        entries: u32_at(&raw, 136)?,
        admitted: u32_at(&raw, 140)?,
        complete: u16_at(&raw, 6)? & 1 != 0,
    };
    let expected = admission_address(
        program,
        &Pubkey::new_from_array(view.registry),
        &Pubkey::new_from_array(view.state),
    )
    .0;
    if *account.key != expected
        || raw.len() != admission_bytes(view.entries)
        || view.admitted > view.entries
        || view.complete != (view.admitted == view.entries)
    {
        return Err(no(ADMISSION_STATE));
    }
    Ok(view)
}

/// tag 154: first:u32 | count:u16. Check template entries
/// `[first, first + count)` in any order and set their bits; a refusal names
/// the rule and changes nothing. Re-checking an admitted entry is a no-op.
/// Permissionless. Accounts: DEA1(w), registry, PT1S, routes, geometry;
/// PT1X appends payloads and its sealed PT2S (7 accounts).
pub fn admission_step(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 5 | 7) || data.len() != 7 || !accounts[0].is_writable {
        return Err(no(ADMISSION_STATE));
    }
    let first = u32_at(data, 1)?;
    let count = u16_at(data, 5)?;
    if count == 0 || count > MAX_STEP {
        return Err(no(ADMISSION_STATE));
    }
    let view = admission_view(program, &accounts[0])?;
    if view.complete {
        return Err(no(ADMISSION_STATE));
    }
    if accounts[1].key.as_ref() != view.registry {
        return Err(no(REGISTRY_ROOT));
    }
    frozen_registry(program, &accounts[1], &view.root)?;
    if accounts[2].key.as_ref() != view.state {
        return Err(no(TEMPLATE_BINDING));
    }
    let is_pt1x = {
        let s = accounts[2].try_borrow_data()?;
        crate::pt1_onchain::is_pt1x(&s)
    };
    if is_pt1x != (accounts.len() == 7) {
        return Err(no(TEMPLATE_BINDING));
    }
    let (payloads, pt2s) = if is_pt1x {
        (Some(&accounts[5]), Some(&accounts[6]))
    } else {
        (None, None)
    };
    bound_template(
        program,
        &accounts[2],
        &accounts[3],
        &accounts[4],
        payloads,
        pt2s,
    )?;
    let end = first.checked_add(count as u32).ok_or(no(ADMISSION_STATE))?;
    if end > view.entries {
        return Err(no(ADMISSION_STATE));
    }
    let registry = accounts[1].try_borrow_data()?;
    let routes = accounts[3].try_borrow_data()?;
    let geometry = accounts[4].try_borrow_data()?;
    let state = accounts[2].try_borrow_data()?;
    if hash::sha256(&[&state]) != view.state_sha256 {
        return Err(no(TEMPLATE_BINDING));
    }
    let rows = &registry[REGISTRY_HEADER..];
    if is_pt1x {
        let payloads = accounts[5].try_borrow_data()?;
        let pt2s = accounts[6].try_borrow_data()?;
        let x = pt1x_view(&pt2s, &routes, &geometry, &payloads, &state).map_err(no)?;
        let last = x
            .position_count
            .checked_sub(1)
            .ok_or(no(TEMPLATE_BINDING))?;
        if x.entry_count(last).map_err(|_| no(TEMPLATE_BINDING))? != view.entries {
            return Err(no(TEMPLATE_BINDING));
        }
        for i in first..end {
            check_entry_pt1x(rows, &x, i).map_err(no)?;
        }
    } else {
        let (t, c) = template(&routes, &geometry, false)?;
        if t.entries_per_position != view.entries {
            return Err(no(TEMPLATE_BINDING));
        }
        let index = &state[PT1S_INDEX..];
        for i in first..end {
            check_entry(rows, &t, c, index, i).map_err(no)?;
        }
    }
    drop((registry, routes, geometry, state));
    let mut raw = accounts[0].try_borrow_mut_data()?;
    let mut admitted = view.admitted;
    for i in first..end {
        let (byte, bit) = (ADMISSION_HEADER + i as usize / 8, 1u8 << (i % 8));
        if raw[byte] & bit == 0 {
            raw[byte] |= bit;
            admitted += 1;
        }
    }
    put_u32(&mut raw, 140, admitted);
    if admitted == view.entries {
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
    }
    Ok(())
}

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Option<ProgramResult> {
    let tag = data.first().copied()?;
    #[cfg(feature = "revision-8")]
    if matches!(tag, TAG_ADMISSION_BEGIN | TAG_ADMISSION_STEP) {
        // Revision 8 uses tag 159/160 and closes only its DTU1-bound DEA2.
        // Refuse creating a DEA1 whose rent has no revision-8 close route.
        return Some(Err(no(crate::unified::PLAN_BINDING)));
    }
    Some(match tag {
        TAG_REGISTRY_CREATE => registry_create(program, accounts, data),
        TAG_REGISTRY_WRITE => registry_write(program, accounts, data),
        TAG_REGISTRY_FREEZE => registry_freeze(program, accounts, data),
        TAG_ADMISSION_BEGIN => admission_begin(program, accounts, data),
        TAG_ADMISSION_STEP => admission_step(program, accounts, data),
        _ => return None,
    })
}
