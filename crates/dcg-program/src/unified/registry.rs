//! DRP2: the frozen per-form registry of the re-key image, row version 2
//! (spec §4), and the per-instance admission rule `check` (spec §3.2).
//!
//! Header (192 bytes), then `row_count` 64-byte rows strictly ascending by
//! `form_id`:
//! ```text
//!   0 "DRP2" | 4 version:u16 = 2 | 6 flags:u16 (bit 0 frozen) | 8 epoch:u32
//!  12 registry_id:u32 | 16 row_count:u32 (1..=64) | 20 rows_written:u32
//!  24 authority[32] | 56 machine_name[64] | 120 census_digest[32] (nonzero)
//! 152 table_root[32] (zero until frozen) | 184 zero[8]
//! ```
//! Row: bytes 0..36 are a DRP1 row; 36 row_version:u8 = 2 | 37 max_rs1_height:u8
//! | 38 reserved:u16 | 40 max_range_slots:u32 | 44 position_limit:u32 |
//! 48 measured_positions:u32 | 52 reserved[12].

use super::{
    no, u16_at, u32_at, EPOCH, REGISTRY_ACCOUNT, REGISTRY_EPOCH, REGISTRY_ROOT, REGISTRY_STATE,
    ROW_CAPABILITY, ROW_MALFORMED,
};
use crate::account_provenance::{
    allocate_derived_account, expect_derived, AccountKind, CanonicalBump, RoleFlags,
};
use crate::envelope_seal::{self as esl, RESPOND_GENERIC, WITNESS_TENSORS};
use crate::hash;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey, system_program,
};

pub const REGISTRY_VERSION: u16 = 2;
pub const ROW_VERSION: u8 = 2;
pub const HEADER: usize = 192;
pub const ROW_BYTES: usize = 64;
pub const MAX_ROWS: u32 = 64;
pub const ROOT_DOMAIN: &[u8] = b"basanos/dcg-envelope-seal-registry/2";
/// The A16 machine version's name (user decision Q12): the machine a 41-byte
/// tag 156 names, so every revision-6 document and golden is unchanged.
pub const MACHINE_NAME: &[u8] = b"basanos/qwen35-4b-a16/1";
/// V7 (spec revision 6.1, §4.1): the A16 machine with the V7 DeltaNet kernels
/// (`pt1_deltanet_core::MACHINE_NAME_V7`). A 105-byte tag 156 names it.
pub const MACHINE_NAME_V7: &[u8] = b"basanos/qwen35-4b-a16/2";
/// The machine names a DRP2 of this image may carry (spec §4.1, revision 6.1).
pub const ACCEPTED_MACHINES: [&[u8]; 2] = [MACHINE_NAME, MACHINE_NAME_V7];
/// RS1 `MAX_HEIGHT` (rev4 §1).
pub const MAX_RS1_HEIGHT: u8 = 19;
/// The selected profile adapter's position-table limit.
pub const POSITION_ROWS: u64 = 32_768;
/// Revision-8 summary-class admission pseudo-form (no clause-5 kernel has it).
/// Its dispute response is revision-7-only; revision 8 retains this row's
/// (1, 0) capability for family summary-class admission.
pub const FORM_RS1_SUMMARY: u16 = 0xF001;
/// The only admissible PT2P supplied read: the whole exp LUT.
pub const EXP_LUT_BYTES: u64 = 8_192 * 8;

/// Compiled capability of the RS1 summary pseudo-form (spec §8.3.11 item 2):
/// the frozen `(1, 0)` class shape. Do not remove its registry row: document
/// admission uses it even though revision 8 has no revision-7 dispute handler.
pub fn summary_capability() -> (u8, u8) {
    (1, 0)
}

/// What this image compiles for `form` over a PT2P source (spec §4.3).
pub fn capability(form: u16) -> (u8, u8) {
    if form == FORM_RS1_SUMMARY {
        summary_capability()
    } else {
        esl::compiled_capability(form)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowV2 {
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
    pub max_rs1_height: u8,
    pub max_range_slots: u32,
    pub position_limit: u32,
    pub measured_positions: u32,
}

impl RowV2 {
    /// 775 unless the row is canonical (spec §4.2).
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != ROW_BYTES
            || raw[36] != ROW_VERSION
            || raw[38..40] != [0; 2]
            || raw[52..64] != [0; 12]
        {
            return Err(ROW_MALFORMED);
        }
        let h = |at: usize| u16::from_le_bytes([raw[at], raw[at + 1]]);
        let w = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let row = RowV2 {
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
            max_rs1_height: raw[37],
            max_range_slots: w(40),
            position_limit: w(44),
            measured_positions: w(48),
        };
        if row.form_id == 0
            || row.respond_path > RESPOND_GENERIC
            || row.witness_kind > WITNESS_TENSORS
            || row.max_rs1_height > MAX_RS1_HEIGHT
            || row.position_limit == 0
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
            (40, self.max_range_slots),
            (44, self.position_limit),
            (48, self.measured_positions),
        ] {
            out[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        out[36] = ROW_VERSION;
        out[37] = self.max_rs1_height;
        out
    }
}

/// The admission shape of an instance or a class (spec §3.1). Counts are
/// `u64` sums; `position` is `p` for an instance and `p̂` for a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub form: u16,
    pub reads: u64,
    pub writes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub payload: u64,
    pub asserted: bool,
    pub range_slots: u64,
    pub rs1_height: u8,
    pub position: u32,
}

impl Shape {
    /// L1's relation: equal form, flags and height; every count `<=`.
    pub fn dominated_by(&self, rep: &Shape) -> bool {
        self.form == rep.form
            && self.asserted == rep.asserted
            && self.rs1_height == rep.rs1_height
            && self.reads <= rep.reads
            && self.writes <= rep.writes
            && self.read_bytes <= rep.read_bytes
            && self.write_bytes <= rep.write_bytes
            && self.payload <= rep.payload
            && self.range_slots <= rep.range_slots
            && self.position <= rep.position
    }
}

/// `check(row, S)`: the first failing code of spec §3.2, else 0.
pub fn check(row: Option<&RowV2>, shape: &Shape) -> u32 {
    check_with(row, shape, &crate::compatibility::REVISION8_COMPATIBILITY)
}

/// Run the class-admission rules supplied by the linked application.
pub fn check_with(
    row: Option<&RowV2>,
    shape: &Shape,
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> u32 {
    hooks.check_registry_class(row, shape)
}

/// `name` NUL-padded to 64 bytes (`name` is at most 64 bytes).
pub fn machine_field_of(name: &[u8]) -> [u8; 64] {
    let mut field = [0u8; 64];
    field[..name.len()].copy_from_slice(name);
    field
}

/// The default machine's field: `basanos/qwen35-4b-a16/1` NUL-padded.
pub fn machine_field() -> [u8; 64] {
    machine_field_of(MACHINE_NAME)
}

/// A 64-byte machine field is admissible iff it is exactly one accepted
/// name followed only by NUL bytes (spec §4.1, revision 6.1).
pub fn accepted_machine(field: &[u8]) -> bool {
    field.len() == 64
        && ACCEPTED_MACHINES
            .iter()
            .any(|name| field == machine_field_of(name))
}

/// DCR1 v5 byte 145 (spec §7.1, revision 6.1): the replay machine a
/// challenge is bound to at open, read from its document's frozen DRP2.
/// `basanos/qwen35-4b-a16/1` replays the revision-6 kernels (`qwen35-4b-pt1/1`
/// rows), `basanos/qwen35-4b-a16/2` the V7 rows.
pub const MACHINE_SELECTOR_A16: u8 = 1;
pub const MACHINE_SELECTOR_V7: u8 = 2;

/// The selector of an accepted 64-byte machine field; `None` otherwise.
pub fn machine_selector(field: &[u8]) -> Option<u8> {
    if field == machine_field_of(MACHINE_NAME) {
        Some(MACHINE_SELECTOR_A16)
    } else if field == machine_field_of(MACHINE_NAME_V7) {
        Some(MACHINE_SELECTOR_V7)
    } else {
        None
    }
}

/// `SHA256(domain | epoch | registry_id | row_count | authority | machine_name[64] | census | rows)`
/// for the default machine (revision-6 goldens).
pub fn table_root(registry_id: u32, authority: &[u8], census: &[u8], rows: &[u8]) -> [u8; 32] {
    table_root_for(registry_id, authority, &machine_field(), census, rows)
}

/// The table root over an explicit machine field (the stored bytes 56..120).
pub fn table_root_for(
    registry_id: u32,
    authority: &[u8],
    machine: &[u8],
    census: &[u8],
    rows: &[u8],
) -> [u8; 32] {
    hash::sha256(&[
        ROOT_DOMAIN,
        &EPOCH.to_le_bytes(),
        &registry_id.to_le_bytes(),
        &((rows.len() / ROW_BYTES) as u32).to_le_bytes(),
        authority,
        machine,
        census,
        rows,
    ])
}

/// Binary search a frozen, strictly ascending DRP2 row table.
pub fn find_row(rows: &[u8], form: u16) -> Result<Option<RowV2>, u32> {
    let (mut lo, mut hi) = (0usize, rows.len() / ROW_BYTES);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let at = mid * ROW_BYTES;
        let id = u16::from_le_bytes([rows[at], rows[at + 1]]);
        if id == form {
            return RowV2::decode(&rows[at..at + ROW_BYTES]).map(Some);
        }
        if id < form {
            lo = mid + 1
        } else {
            hi = mid
        }
    }
    Ok(None)
}

/// A DRP2 at its PDA under this image's epoch.
pub struct View {
    pub registry_id: u32,
    pub row_count: u32,
    pub written: u32,
    pub frozen: bool,
    pub root: [u8; 32],
}

pub fn view(program: &Pubkey, account: &AccountInfo) -> Result<View, ProgramError> {
    if account.owner != program {
        return Err(no(REGISTRY_ACCOUNT));
    }
    let raw = account.try_borrow_data()?;
    if raw.len() < HEADER
        || raw[..4] != *b"DRP2"
        || u16_at(&raw, 4, REGISTRY_ACCOUNT)? != REGISTRY_VERSION
    {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if u32_at(&raw, 8, REGISTRY_ACCOUNT)? != EPOCH {
        return Err(no(REGISTRY_EPOCH));
    }
    let registry_id = u32_at(&raw, 12, REGISTRY_ACCOUNT)?;
    let row_count = u32_at(&raw, 16, REGISTRY_ACCOUNT)?;
    let epoch = EPOCH.to_le_bytes();
    let id = registry_id.to_le_bytes();
    expect_derived(
        account,
        program,
        &[super::address::REGISTRY_SEED, &epoch, &id],
        AccountKind::variable(b"DRP2", HEADER, HEADER + MAX_ROWS as usize * ROW_BYTES)
            .with_version(4, REGISTRY_VERSION),
        RoleFlags {
            writable: false,
            signer: false,
        },
    )
    .map_err(|_| no(REGISTRY_ACCOUNT))?;
    if raw.len() != HEADER + row_count as usize * ROW_BYTES
        || raw[184..192] != [0; 8]
        || u16_at(&raw, 6, REGISTRY_ACCOUNT)? & !1 != 0
    {
        return Err(no(REGISTRY_ACCOUNT));
    }
    Ok(View {
        registry_id,
        row_count,
        written: u32_at(&raw, 20, REGISTRY_ACCOUNT)?,
        frozen: u16_at(&raw, 6, REGISTRY_ACCOUNT)? & 1 != 0,
        root: raw[152..184].try_into().map_err(|_| no(REGISTRY_ACCOUNT))?,
    })
}

/// A frozen DRP2; with `expected` its stored root must equal it (774).
pub fn frozen(
    program: &Pubkey,
    account: &AccountInfo,
    expected: Option<&[u8]>,
) -> Result<View, ProgramError> {
    let v = view(program, account)?;
    if !v.frozen {
        return Err(no(REGISTRY_STATE));
    }
    if expected.is_some_and(|e| v.root[..] != *e) {
        return Err(no(REGISTRY_ROOT));
    }
    Ok(v)
}

/// Create a program PDA at its address: the account must be system-owned
/// with no data (revision 6: it may already hold lamports, e.g. from a
/// pre-funding transfer, so one transfer cannot brick a constant-seed
/// account; the payer tops it up to rent). `state` is the refusal for an
/// existing (non-system or non-empty) account.
pub(crate) fn create_pda<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: CanonicalBump,
    size: usize,
    rent_size: usize,
    bad: u32,
    state: u32,
) -> ProgramResult {
    if !payer.is_signer
        || !payer.is_writable
        || !account.is_writable
        || *system.key != system_program::id()
    {
        return Err(no(bad));
    }
    if *account.owner != system_program::id() || !account.data_is_empty() {
        return Err(no(state));
    }
    allocate_derived_account(
        program, payer, account, system, seeds, bump, size, rent_size,
    )
    .map_err(|_| no(state))
}

/// tag 156: registry_id:u32 | row_count:u32 | census_digest[32]
/// [| machine_name[64]]. 41 bytes names `MACHINE_NAME` (revision 6); 105
/// bytes names the trailing field, which must be an accepted machine,
/// NUL-padded (revision 6.1; 775 otherwise).
/// Accounts: authority(s,w), DCF1, DRP2 PDA(w), system. The signer is DCF1's
/// `registry_authority` (spec revision 4, §16.1; 771 otherwise).
pub fn create(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || (data.len() != 41 && data.len() != 105) {
        return Err(no(ROW_MALFORMED));
    }
    super::config::registry_authority(program, &accounts[0], &accounts[1])?;
    let registry_id = u32_at(data, 1, ROW_MALFORMED)?;
    let rows = u32_at(data, 5, ROW_MALFORMED)?;
    if rows == 0 || rows > MAX_ROWS || data[9..41] == [0; 32] {
        return Err(no(ROW_MALFORMED));
    }
    let machine = if data.len() == 105 {
        &data[41..105]
    } else {
        &machine_field()[..]
    };
    if !accepted_machine(machine) {
        return Err(no(ROW_MALFORMED));
    }
    let (key, bump) = super::address::registry(program, registry_id);
    if *accounts[2].key != key {
        return Err(no(REGISTRY_ACCOUNT));
    }
    let size = HEADER + rows as usize * ROW_BYTES;
    create_pda(
        program,
        &accounts[0],
        &accounts[2],
        &accounts[3],
        &[
            super::address::REGISTRY_SEED,
            &EPOCH.to_le_bytes(),
            &registry_id.to_le_bytes(),
        ],
        bump,
        size,
        size,
        REGISTRY_ACCOUNT,
        REGISTRY_STATE,
    )?;
    let mut raw = accounts[2].try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DRP2");
    raw[4..6].copy_from_slice(&REGISTRY_VERSION.to_le_bytes());
    raw[8..12].copy_from_slice(&EPOCH.to_le_bytes());
    raw[12..16].copy_from_slice(&registry_id.to_le_bytes());
    raw[16..20].copy_from_slice(&rows.to_le_bytes());
    raw[24..56].copy_from_slice(accounts[0].key.as_ref());
    raw[56..120].copy_from_slice(machine);
    raw[120..152].copy_from_slice(&data[9..41]);
    Ok(())
}

/// tag 157: registry_id:u32 | index:u32 | row[64]. Append-only, strictly
/// ascending `form_id` (775), capability equal to the image's (776).
/// Accounts: authority(s), DCF1, DRP2(w).
pub fn write(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 9 + ROW_BYTES || !accounts[2].is_writable {
        return Err(no(ROW_MALFORMED));
    }
    super::config::registry_authority(program, &accounts[0], &accounts[1])?;
    let v = view(program, &accounts[2])?;
    let index = u32_at(data, 5, ROW_MALFORMED)?;
    if v.registry_id != u32_at(data, 1, ROW_MALFORMED)? {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if v.frozen || index != v.written || index >= v.row_count {
        return Err(no(REGISTRY_STATE));
    }
    let row = RowV2::decode(&data[9..]).map_err(no)?;
    let mut raw = accounts[2].try_borrow_mut_data()?;
    if index > 0 {
        let at = HEADER + (index as usize - 1) * ROW_BYTES;
        if u16_at(&raw, at, ROW_MALFORMED)? >= row.form_id {
            return Err(no(ROW_MALFORMED));
        }
    }
    if capability(row.form_id) != (row.respond_path, row.witness_kind) {
        return Err(no(ROW_CAPABILITY));
    }
    let at = HEADER + index as usize * ROW_BYTES;
    raw[at..at + ROW_BYTES].copy_from_slice(&data[9..]);
    raw[20..24].copy_from_slice(&(index + 1).to_le_bytes());
    Ok(())
}

/// tag 158: registry_id:u32. Recompute the table root on chain and freeze.
/// Accounts: authority(s), DCF1, DRP2(w).
pub fn freeze(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() != 5 || !accounts[2].is_writable {
        return Err(no(ROW_MALFORMED));
    }
    super::config::registry_authority(program, &accounts[0], &accounts[1])?;
    let v = view(program, &accounts[2])?;
    if v.registry_id != u32_at(data, 1, ROW_MALFORMED)? {
        return Err(no(REGISTRY_ACCOUNT));
    }
    if v.frozen || v.written != v.row_count {
        return Err(no(REGISTRY_STATE));
    }
    let mut raw = accounts[2].try_borrow_mut_data()?;
    let root = table_root_for(
        v.registry_id,
        &raw[24..56],
        &raw[56..120],
        &raw[120..152],
        &raw[HEADER..],
    );
    raw[152..184].copy_from_slice(&root);
    raw[6..8].copy_from_slice(&1u16.to_le_bytes());
    Ok(())
}
