//! The incremental seal (lifecycle step 5.2).
//!
//! `docs/spec/dcg-lifecycle-v1.md` §4 is normative: the 1,184-byte `BDS2`
//! state record at `["dcg-state", descriptor_digest]` (§4.1), `SealBegin`
//! (tag 9) / `SealStep` (tag 10) / `SealFinish` (tag 11), the four stages and
//! their cursor rules (§4.2), the per-transaction bound (§4.3), and the
//! mountain-range route root.  The Python mirror is
//! `src/basanos/dcg/seal.py`; both reproduce
//! `tests/golden/dcg/lifecycle/route_root_v1.tsv`.
//!
//! **The mountain range.**  Clause 5's `route_root` is a duplicate-last Merkle
//! root over entry leaves.  The running fold of a prefix of the leaves is a
//! mountain range of at most `ceil(log2(entry_count))` nodes, so `BDS2`
//! persists 32 nodes (one per binary level, occupied exactly when that bit of
//! the leaf count is set) and `SealStep` pushes each entry's leaf onto it.
//! Collapsing the range by lifting a carry through empty levels with
//! `node(carry, carry)` is what makes the incremental root equal the
//! level-by-level one; a 33rd level is `SEAL_STACK_OVERFLOW(338)`.
//!
//! **What the spec leaves unstated, and what this module assumes** (stated
//! here rather than hidden; see the step 5.2 report):
//!
//! * The account lists for tags 9-11.  `SealBegin` takes
//!   `0 DCD1 (RO), 1 BDS2 (W), 2 authority (signer, W), 3 system`;
//!   `SealStep` takes `0 DCD1 (RO), 1..k chunks (RO), k BDS2 (W),
//!   k+1 authority (signer)`; `SealFinish` takes `0 DCD1 (RO), 1 BDS2 (W),
//!   2 authority (signer)`.  This follows §3.5's `Execute` layout.
//! * `SealBegin`'s instruction data is `[9] | descriptor_digest[32] |
//!   image_sha256[32]`: the digest is an instruction field whose claim is
//!   checked against the `DCD1` and `BDS2` addresses, exactly as `Execute`
//!   checks its chunk addresses.  No account can be named without it.
//! * `MAX_SEAL_PAIRS_PER_CALL` is named in §4.2 but never valued in
//!   `constants_v1.tsv`; this module uses 512 and the report records it.
//! * Stage 3's "pair index" is the index over generator pairs; the clause-6
//!   wave/edge rules are the `validate_schedule` call that completes the
//!   stage.
//! * The per-item split of the stage validators.  §4.2 assigns each rule to a
//!   stage; every `SealStep` runs the per-item half of that stage's validator
//!   over exactly the items it declares (`validate_placement_slices`,
//!   `validate_routes_entries`, `validate_schedule_waves`/`_edges`) and the
//!   step where the cursor reaches the stage's end runs the cross-item half
//!   (`validate_placement_global`, `validate_routes_global`,
//!   `validate_schedule_global`).  A rule that compares to the preceding row
//!   reads that row from the committed descriptor, so no running cursor is
//!   carried in `BDS2`.  Stage 3's item stream is the clause-6 schedule rows
//!   (waves then edges), not the generator-pair count.  Per-call ITEM caps
//!   (`MAX_SEAL_*_PER_CALL`) bound the CU as well as `SEAL_STEP_MAX_BYTES`.

use crate::desc_upload::{self, Dcd1, DCD1_BYTES, DCD1_FLAG_FINISHED, DCD1_FLAG_FROZEN};
use crate::descriptor::{DcgError, Descriptor, CLAUSE_SCHEDULE};
use crate::hash::sha256;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Refusal codes 330-338.  Numbers are normative in
/// `tests/golden/dcg/lifecycle/refusals_v1.tsv`; append-only.
pub mod seal_err {
    pub const STATE_EXISTS: u32 = 330;
    pub const STAGE_ORDER: u32 = 331;
    pub const CURSOR: u32 = 332;
    pub const STEP_TOO_LARGE: u32 = 333;
    pub const INCOMPLETE: u32 = 334;
    pub const ALREADY: u32 = 335;
    pub const IMAGE_ZERO: u32 = 336;
    pub const ROUTE_ROOT: u32 = 337;
    pub const STACK_OVERFLOW: u32 = 338;
}

/// The `BDS2` state record (spec §4.1, `constants_v1.tsv`).
pub const BDS2_BYTES: usize = 1184;
pub const BDS2_MAGIC: [u8; 4] = *b"BDS2";
pub const BDS2_VERSION: u16 = 2;
pub const BDS2_FLAG_SEALED: u16 = 1 << 0;
pub const BDS2_FLAG_TERMINAL: u16 = 1 << 1;
pub const BDS2_FLAG_EXPORT_SEALED: u16 = 1 << 2;
pub const BDS2_ROUTE_ROOT_STACK_LEVELS: usize = 32;
/// Bytes of descriptor one `SealStep` may declare (spec §4.3).
pub const SEAL_STEP_MAX_BYTES: u32 = 16_384;
/// See the module doc: named by §4.2, valued here because the spec is silent.
pub const MAX_SEAL_PAIRS_PER_CALL: u32 = 512;

pub const SEED_STATE: &[u8] = b"dcg-state";
pub const TAG_ROUTE_NODE: &[u8] = b"basanos/dcg-route-node/1";

pub const TAG_SEAL_BEGIN: u8 = 9;
pub const TAG_SEAL_STEP: u8 = 10;
pub const TAG_SEAL_FINISH: u8 = 11;

pub const STAGE_HEADER: u8 = 0;
/// R16: stage 0's whole-clause validators, one per sub-step.  Spec §4.2 used
/// to say stage 0 is "one call"; on the SBF image the eight validators
/// together exceed the 1,400,000-CU meter on EVERY fly document — measured at
/// 52,596 B, the smallest fixture — so the stage carries a cursor over its
/// own validators, bounded by "the clauses' own maxima" exactly as §4.2 says.
pub const HEADER_VALIDATOR_COUNT: u32 = 8;
pub const STAGE_PLACEMENT: u8 = 1;
pub const STAGE_ROUTES: u8 = 2;
pub const STAGE_CROSS: u8 = 3;
pub const STAGE_DONE: u8 = 4;

/// `[9] | descriptor_digest[32] | image_sha256[32]`, exact EOF.
pub const BEGIN_INSTRUCTION_BYTES: usize = 1 + 32 + 32;
/// `[10] | stage:u8 | start:u32 | count:u32`, exact EOF.
pub const STEP_INSTRUCTION_BYTES: usize = 1 + 1 + 4 + 4;
/// `[11]`, exact EOF.
pub const FINISH_INSTRUCTION_BYTES: usize = 1;

/// Clause-4 explicit slice row width (`descriptor.py::EXPLICIT_SLICE_ROW_BYTES`).
const EXPLICIT_SLICE_ROW_BYTES: u32 = 48;
/// Clause-5 entry row width (`descriptor.py::ENTRY_ROW_BYTES`).
const ENTRY_ROW_BYTES: u32 = 16;
/// Clause-5 route record width (`descriptor.py::ROUTE_RECORD_BYTES`).
const ROUTE_RECORD_BYTES: u32 = 24;
/// Clause-6 edge row width (`descriptor.py::EDGE_ROW_BYTES`).
const EDGE_ROW_BYTES: u32 = 8;
/// Clause-6 wave row width (`descriptor.py::WAVE_ROW_BYTES`).
const WAVE_ROW_BYTES: u32 = 16;

/// R16: per-call ITEM caps for stages 1-3.  `SEAL_STEP_MAX_BYTES` alone is not
/// enough: a placement slice costs ~4.6K CU and a route entry ~13K CU on the
/// SBF image (both measured on the captured fly), so a step packed to 16,384
/// descriptor bytes exceeds the 1,240,000-CU admission ceiling.  These caps are
/// chosen from those measurements with margin; the byte bound still applies.
/// See the R16 experiment note for the measured per-stage CU.
pub const MAX_SEAL_SLICES_PER_CALL: u32 = 96;
pub const MAX_SEAL_ENTRIES_PER_CALL: u32 = 32;
pub const MAX_SEAL_WAVES_PER_CALL: u32 = 512;
pub const MAX_SEAL_EDGES_PER_CALL: u32 = 512;

fn refusal(error: DcgError) -> ProgramError {
    ProgramError::Custom(error.0)
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------------------------------------------------------------------------
// The mountain range (§4.1/§4.2).
// ---------------------------------------------------------------------------

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[TAG_ROUTE_NODE, left, right])
}

/// Push one entry leaf onto the 32-node mountain range.  Level `level` is
/// empty exactly when its node is 32 zero bytes (the count is the cursor and
/// is not stored in the stack).  A 33rd level is `SEAL_STACK_OVERFLOW(338)`.
///
/// This is the raw form the handler uses on the account's bytes; the
/// `[[u8;32];32]` form below delegates to it, so there is one implementation.
pub fn stack_push_raw(stack: &mut [u8], leaf: [u8; 32]) -> Result<(), DcgError> {
    debug_assert_eq!(stack.len(), BDS2_ROUTE_ROOT_STACK_LEVELS * 32);
    let mut carry = leaf;
    let mut level = 0usize;
    while level < BDS2_ROUTE_ROOT_STACK_LEVELS {
        let off = level * 32;
        if stack[off..off + 32] == [0u8; 32] {
            break;
        }
        let mut left = [0u8; 32];
        left.copy_from_slice(&stack[off..off + 32]);
        carry = node_hash(&left, &carry);
        stack[off..off + 32].copy_from_slice(&[0u8; 32]);
        level += 1;
    }
    if level >= BDS2_ROUTE_ROOT_STACK_LEVELS {
        return Err(DcgError(seal_err::STACK_OVERFLOW));
    }
    stack[level * 32..level * 32 + 32].copy_from_slice(&carry);
    Ok(())
}

/// Collapse the raw mountain range to one root: lift a carry through empty
/// levels with `node(carry, carry)`, then combine with the next peak as
/// `node(peak, carry)`.
pub fn stack_collapse_raw(stack: &[u8]) -> [u8; 32] {
    debug_assert_eq!(stack.len(), BDS2_ROUTE_ROOT_STACK_LEVELS * 32);
    let mut carry: Option<([u8; 32], usize)> = None;
    for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
        let off = level * 32;
        let peak_bytes = &stack[off..off + 32];
        if peak_bytes == [0u8; 32] {
            continue;
        }
        let mut peak = [0u8; 32];
        peak.copy_from_slice(peak_bytes);
        match carry {
            None => carry = Some((peak, level)),
            Some((mut running, mut running_level)) => {
                while running_level < level {
                    running = node_hash(&running, &running);
                    running_level += 1;
                }
                running = node_hash(&peak, &running);
                carry = Some((running, level + 1));
            }
        }
    }
    carry.map(|(node, _)| node).unwrap_or([0u8; 32])
}

/// Array form, used by the tests.  Delegates to [`stack_push_raw`].
pub fn stack_push(
    stack: &mut [[u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS],
    leaf: [u8; 32],
) -> Result<(), DcgError> {
    let mut raw = [0u8; BDS2_ROUTE_ROOT_STACK_LEVELS * 32];
    for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
        raw[level * 32..level * 32 + 32].copy_from_slice(&stack[level]);
    }
    stack_push_raw(&mut raw, leaf)?;
    for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
        stack[level].copy_from_slice(&raw[level * 32..level * 32 + 32]);
    }
    Ok(())
}

/// Array form, used by the tests.  Delegates to [`stack_collapse_raw`].
pub fn stack_collapse(stack: &[[u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS]) -> [u8; 32] {
    let mut raw = [0u8; BDS2_ROUTE_ROOT_STACK_LEVELS * 32];
    for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
        raw[level * 32..level * 32 + 32].copy_from_slice(&stack[level]);
    }
    stack_collapse_raw(&raw)
}

/// The level-by-level duplicate-last root -- the normative definition, used
/// only by tests as the oracle for [`stack_collapse`].
pub fn route_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level[level.len() - 1];
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

/// Number of occupied levels = popcount(leaf count).
fn popcount(value: u32) -> u8 {
    value.count_ones() as u8
}

// ---------------------------------------------------------------------------
// The `BDS2` record.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Bds2 {
    pub flags: u16,
    pub descriptor_digest: [u8; 32],
    pub descriptor_id: [u8; 32],
    pub image_sha256: [u8; 32],
    pub authority: [u8; 32],
    pub seal_stage: u8,
    pub stack_len: u8,
    pub seal_cursor: u32,
    pub seal_bytes: u64,
    pub terminal_entry_committed: u32,
    pub route_root_stack: [[u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS],
}

pub const BDS2_OFF_MAGIC: usize = 0;
pub const BDS2_OFF_VERSION: usize = 4;
pub const BDS2_OFF_FLAGS: usize = 6;
pub const BDS2_OFF_DESCRIPTOR_DIGEST: usize = 8;
pub const BDS2_OFF_DESCRIPTOR_ID: usize = 40;
pub const BDS2_OFF_IMAGE: usize = 72;
pub const BDS2_OFF_AUTHORITY: usize = 104;
pub const BDS2_OFF_STAGE: usize = 136;
pub const BDS2_OFF_STACK_LEN: usize = 137;
pub const BDS2_OFF_RESERVED0: usize = 138;
pub const BDS2_OFF_CURSOR: usize = 140;
pub const BDS2_OFF_BYTES: usize = 144;
pub const BDS2_OFF_TERMINAL: usize = 152;
pub const BDS2_OFF_RESERVED1: usize = 156;
pub const BDS2_OFF_STACK: usize = 160;

impl Bds2 {
    pub fn init(
        descriptor_digest: [u8; 32],
        descriptor_id: [u8; 32],
        image_sha256: [u8; 32],
        authority: [u8; 32],
    ) -> Self {
        Self {
            flags: 0,
            descriptor_digest,
            descriptor_id,
            image_sha256,
            authority,
            seal_stage: STAGE_HEADER,
            stack_len: 0,
            seal_cursor: 0,
            seal_bytes: 0,
            terminal_entry_committed: 0,
            route_root_stack: [[0u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS],
        }
    }

    pub fn is_zero(bytes: &[u8]) -> bool {
        bytes.iter().all(|byte| *byte == 0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DcgError> {
        if bytes.len() != BDS2_BYTES {
            return Err(DcgError(seal_err::STATE_EXISTS));
        }
        if bytes[BDS2_OFF_MAGIC..BDS2_OFF_MAGIC + 4] != BDS2_MAGIC {
            return Err(DcgError(seal_err::STATE_EXISTS));
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != BDS2_VERSION {
            return Err(DcgError(seal_err::STATE_EXISTS));
        }
        if bytes[BDS2_OFF_RESERVED0] != 0
            || bytes[BDS2_OFF_RESERVED0 + 1] != 0
            || bytes[BDS2_OFF_RESERVED1..BDS2_OFF_RESERVED1 + 4] != [0u8; 4]
        {
            return Err(DcgError(crate::descriptor::err::NONZERO_RESERVED));
        }
        let mut record = Self::init([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        record.flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        record
            .descriptor_digest
            .copy_from_slice(&bytes[BDS2_OFF_DESCRIPTOR_DIGEST..BDS2_OFF_DESCRIPTOR_DIGEST + 32]);
        record
            .descriptor_id
            .copy_from_slice(&bytes[BDS2_OFF_DESCRIPTOR_ID..BDS2_OFF_DESCRIPTOR_ID + 32]);
        record
            .image_sha256
            .copy_from_slice(&bytes[BDS2_OFF_IMAGE..BDS2_OFF_IMAGE + 32]);
        record
            .authority
            .copy_from_slice(&bytes[BDS2_OFF_AUTHORITY..BDS2_OFF_AUTHORITY + 32]);
        record.seal_stage = bytes[BDS2_OFF_STAGE];
        record.stack_len = bytes[BDS2_OFF_STACK_LEN];
        record.seal_cursor = u32_at(bytes, BDS2_OFF_CURSOR);
        record.seal_bytes = u64::from_le_bytes(
            bytes[BDS2_OFF_BYTES..BDS2_OFF_BYTES + 8]
                .try_into()
                .unwrap(),
        );
        record.terminal_entry_committed = u32_at(bytes, BDS2_OFF_TERMINAL);
        for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
            let off = BDS2_OFF_STACK + level * 32;
            record.route_root_stack[level].copy_from_slice(&bytes[off..off + 32]);
        }
        Ok(record)
    }

    pub fn encode(&self) -> [u8; BDS2_BYTES] {
        let mut out = [0u8; BDS2_BYTES];
        out[BDS2_OFF_MAGIC..BDS2_OFF_MAGIC + 4].copy_from_slice(&BDS2_MAGIC);
        out[4..6].copy_from_slice(&BDS2_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[BDS2_OFF_DESCRIPTOR_DIGEST..BDS2_OFF_DESCRIPTOR_DIGEST + 32]
            .copy_from_slice(&self.descriptor_digest);
        out[BDS2_OFF_DESCRIPTOR_ID..BDS2_OFF_DESCRIPTOR_ID + 32]
            .copy_from_slice(&self.descriptor_id);
        out[BDS2_OFF_IMAGE..BDS2_OFF_IMAGE + 32].copy_from_slice(&self.image_sha256);
        out[BDS2_OFF_AUTHORITY..BDS2_OFF_AUTHORITY + 32].copy_from_slice(&self.authority);
        out[BDS2_OFF_STAGE] = self.seal_stage;
        out[BDS2_OFF_STACK_LEN] = self.stack_len;
        out[BDS2_OFF_CURSOR..BDS2_OFF_CURSOR + 4].copy_from_slice(&self.seal_cursor.to_le_bytes());
        out[BDS2_OFF_BYTES..BDS2_OFF_BYTES + 8].copy_from_slice(&self.seal_bytes.to_le_bytes());
        out[BDS2_OFF_TERMINAL..BDS2_OFF_TERMINAL + 4]
            .copy_from_slice(&self.terminal_entry_committed.to_le_bytes());
        for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
            let off = BDS2_OFF_STACK + level * 32;
            out[off..off + 32].copy_from_slice(&self.route_root_stack[level]);
        }
        out
    }

    pub fn sealed(&self) -> bool {
        self.flags & BDS2_FLAG_SEALED != 0
    }

    pub fn terminal(&self) -> bool {
        self.flags & BDS2_FLAG_TERMINAL != 0
    }
}

// ---------------------------------------------------------------------------
// Addresses.
// ---------------------------------------------------------------------------

pub fn state_seeds(descriptor_digest: &[u8; 32]) -> ([u8; 9], [u8; 32]) {
    let mut prefix = [0u8; 9];
    prefix.copy_from_slice(SEED_STATE);
    (prefix, *descriptor_digest)
}

pub fn find_state_address(program_id: &Pubkey, descriptor_digest: &[u8; 32]) -> (Pubkey, u8) {
    let (prefix, digest) = state_seeds(descriptor_digest);
    Pubkey::find_program_address(&[&prefix, &digest], program_id)
}

/// The rule-visible `BDS2` fields the lifecycle handlers read (spec §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateFacts {
    pub sealed: bool,
    pub terminal: bool,
    pub authority: [u8; 32],
    pub terminal_entry_committed: u32,
}

/// Read a `BDS2` at its derived address: program-owned, at
/// `["dcg-state", digest]`, exactly 1,184 bytes with the right magic and
/// version.  Every framing failure is `bad_state` (the caller's registry
/// code for "this account is not the state the rule needs"), so no new code
/// is spent here.
pub fn open_state(
    program_id: &Pubkey,
    account: &AccountInfo,
    digest: &[u8; 32],
    bad_state: u32,
) -> Result<StateFacts, ProgramError> {
    if account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let (want, _) = find_state_address(program_id, digest);
    if want != *account.key {
        return Err(refusal(DcgError(bad_state)));
    }
    let data = account.try_borrow_data()?;
    if data.len() != BDS2_BYTES
        || data[BDS2_OFF_MAGIC..BDS2_OFF_MAGIC + 4] != BDS2_MAGIC
        || u16::from_le_bytes([data[4], data[5]]) != BDS2_VERSION
    {
        return Err(refusal(DcgError(bad_state)));
    }
    let flags = u16::from_le_bytes([data[BDS2_OFF_FLAGS], data[BDS2_OFF_FLAGS + 1]]);
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[BDS2_OFF_AUTHORITY..BDS2_OFF_AUTHORITY + 32]);
    let mut terminal_entry = [0u8; 4];
    terminal_entry.copy_from_slice(&data[BDS2_OFF_TERMINAL..BDS2_OFF_TERMINAL + 4]);
    Ok(StateFacts {
        sealed: flags & BDS2_FLAG_SEALED != 0,
        terminal: flags & BDS2_FLAG_TERMINAL != 0,
        authority,
        terminal_entry_committed: u32::from_le_bytes(terminal_entry),
    })
}

// ---------------------------------------------------------------------------
// The stage plan (§4.2/§4.3).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct StagePlan {
    pub entry_count: u32,
    pub slice_count: u32,
    pub wave_count: u32,
    pub edge_count: u32,
    pub generator_count: u32,
    pub total_bytes: u32,
}

impl StagePlan {
    pub fn of(document: &Descriptor) -> Self {
        let schedule = document.clause(CLAUSE_SCHEDULE);
        Self {
            entry_count: document.entry_count() as u32,
            slice_count: document.slice_count() as u32,
            wave_count: if schedule.len() >= 4 {
                u32_at(schedule, 0)
            } else {
                0
            },
            edge_count: if schedule.len() >= 8 {
                u32_at(schedule, 4)
            } else {
                0
            },
            generator_count: document.generator_count() as u32,
            total_bytes: document.total_bytes(),
        }
    }

    pub fn pair_count(&self) -> u32 {
        self.generator_count
            .saturating_mul(self.generator_count.saturating_sub(1))
            / 2
    }

    pub fn stage_end(&self, stage: u8) -> u32 {
        match stage {
            STAGE_HEADER => HEADER_VALIDATOR_COUNT,
            STAGE_PLACEMENT => self.slice_count,
            STAGE_ROUTES => self.entry_count,
            // R16: the stage-3 item stream is the clause-6 schedule rows -- the
            // `wave_count` waves then the `edge_count` edges -- so a step
            // validates schedule rows per item.  It was the generator-pair
            // count, which could not be mapped to a schedule row.
            STAGE_CROSS => self.wave_count.saturating_add(self.edge_count),
            _ => 0,
        }
    }

    /// Descriptor bytes one item of the stage consumes.
    pub fn item_bytes(&self, stage: u8) -> u32 {
        match stage {
            STAGE_HEADER => self.total_bytes,
            STAGE_PLACEMENT => EXPLICIT_SLICE_ROW_BYTES,
            // Conservative: an entry row plus two record widths.
            STAGE_ROUTES => ENTRY_ROW_BYTES + 2 * ROUTE_RECORD_BYTES,
            STAGE_CROSS => EDGE_ROW_BYTES,
            _ => 0,
        }
    }

    /// R16: the descriptor bytes stage-3 item `index` consumes: a wave row
    /// while `index < wave_count`, an edge row after it.
    fn schedule_item_bytes(&self, index: u32) -> u32 {
        if index < self.wave_count {
            WAVE_ROW_BYTES
        } else {
            EDGE_ROW_BYTES
        }
    }
}

/// The exact bytes one stage-2 item consumes for entry `index`, read from the
/// document (an entry row plus its read and write records).
fn entry_item_bytes(document: &Descriptor, index: u32) -> u32 {
    let entry = document.entry(index as usize);
    ENTRY_ROW_BYTES + (entry.read_count as u32 + entry.write_count as u32) * ROUTE_RECORD_BYTES
}

/// The `SealStep` transactions the 16,384-byte bound allows: one per stage
/// chunk, in stage order.  `(stage, start, count)`.
///
/// The route pass packs by the document's ACTUAL per-entry bytes
/// (`entry_item_bytes`), not the conservative `item_bytes` constant: on real
/// documents (the fly's 232-byte entries) the constant over-fills a step and
/// the handler refuses 333 (R17).  The Python mirror is
/// `seal.py::plan_steps`.
pub fn plan_steps(plan: &StagePlan, document: &Descriptor) -> Vec<(u8, u32, u32)> {
    let mut steps = Vec::new();
    for stage in 0..STAGE_DONE {
        let end = plan.stage_end(stage);
        if stage == STAGE_HEADER {
            // R16: one call per validator.
            for index in 0..HEADER_VALIDATOR_COUNT {
                steps.push((stage, index, 1));
            }
            continue;
        }
        if end == 0 {
            // An empty stage is still advanced, by a zero-count step.
            steps.push((stage, 0, 0));
            continue;
        }
        if stage == STAGE_ROUTES {
            let mut start = 0u32;
            while start < end {
                let mut consumed = 0u32;
                let mut count = 0u32;
                while start + count < end {
                    let width = entry_item_bytes(document, start + count);
                    if count > 0
                        && (consumed + width > SEAL_STEP_MAX_BYTES
                            || count >= MAX_SEAL_ENTRIES_PER_CALL)
                    {
                        break;
                    }
                    consumed += width;
                    count += 1;
                }
                steps.push((stage, start, count));
                start += count;
            }
            continue;
        }
        if stage == STAGE_CROSS {
            // R16: wave rows first, then edge rows, each capped so one step
            // stays under the CU ceiling.  A step may span the boundary;
            // `run_stage_items` splits it.
            let mut start = 0u32;
            while start < end {
                let mut consumed = 0u32;
                let mut count = 0u32;
                while start + count < end {
                    let index = start + count;
                    let width = plan.schedule_item_bytes(index);
                    let cap = if index < plan.wave_count {
                        MAX_SEAL_WAVES_PER_CALL
                    } else {
                        MAX_SEAL_EDGES_PER_CALL
                    };
                    if count > 0 && (consumed + width > SEAL_STEP_MAX_BYTES || count >= cap) {
                        break;
                    }
                    consumed += width;
                    count += 1;
                }
                steps.push((stage, start, count));
                start += count;
            }
            continue;
        }
        let item = plan.item_bytes(stage);
        let mut bound = if item == 0 {
            1
        } else {
            (SEAL_STEP_MAX_BYTES / item).max(1)
        };
        if stage == STAGE_PLACEMENT {
            bound = bound.min(MAX_SEAL_SLICES_PER_CALL);
        }
        let mut start = 0u32;
        while start < end {
            let count = bound.min(end - start);
            steps.push((stage, start, count));
            start += count;
        }
    }
    steps
}

/// `SealBegin` + every `SealStep` + `SealFinish`.
pub fn minimal_transactions(plan: &StagePlan, document: &Descriptor) -> usize {
    2 + plan_steps(plan, document).len()
}

// ---------------------------------------------------------------------------
// The three handlers.
// ---------------------------------------------------------------------------

fn check_begin_accounts(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if accounts[0].is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !accounts[1].is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !accounts[2].is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

/// `SealBegin` (tag 9).  Creates the `BDS2` state at its derived address.
pub fn process_begin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    descriptor_digest: [u8; 32],
    image_sha256: [u8; 32],
) -> ProgramResult {
    check_begin_accounts(accounts)?;
    let (index_account, state_account, authority) = (&accounts[0], &accounts[1], &accounts[2]);

    if image_sha256 == [0u8; 32] {
        return Err(refusal(DcgError(seal_err::IMAGE_ZERO)));
    }

    // The digest is a claim about account 0's address, exactly as `Execute`
    // checks its chunks (314 is the chunk code; a wrong DCD1 address is not
    // in the registry, so it is a plain framing refusal here).
    let (want_index, _) = desc_upload::find_desc_index_address(program_id, &descriptor_digest);
    if want_index != *index_account.key {
        return Err(ProgramError::InvalidArgument);
    }
    if index_account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let index_bytes = index_account.try_borrow_data()?;
    if index_bytes.len() != DCD1_BYTES {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let record = Dcd1::decode(&index_bytes).map_err(refusal)?;
    if record.flags & (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
        != (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
    {
        return Err(refusal(DcgError(crate::descriptor::err::DESC_NOT_FINISHED)));
    }

    let (want_state, _) = find_state_address(program_id, &descriptor_digest);
    if want_state != *state_account.key {
        return Err(ProgramError::InvalidArgument);
    }
    if state_account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let mut state_data = state_account.try_borrow_mut_data()?;
    // "zero-length-or-absent" is realized here as a program-owned, zeroed
    // 1,184-byte account, the same idiom `region_seal::process_seal` uses for
    // `DRS1`: the handler performs no CPI, so the account arrives pre-funded
    // (see the module doc).  Anything else is a second begin.
    if state_data.len() != 0 && state_data.len() != BDS2_BYTES {
        return Err(refusal(DcgError(seal_err::STATE_EXISTS)));
    }
    if state_data.len() == BDS2_BYTES && !Bds2::is_zero(&state_data) {
        return Err(refusal(DcgError(seal_err::STATE_EXISTS)));
    }
    if state_data.len() != BDS2_BYTES {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let record = Bds2::init(
        descriptor_digest,
        record.descriptor_id,
        image_sha256,
        authority.key.to_bytes(),
    );
    state_data.copy_from_slice(&record.encode());
    Ok(())
}

/// The state account index for a `SealStep`: `0 DCD1, 1..k chunks, k BDS2,
/// k+1 authority`.
fn step_indices(accounts: &[AccountInfo]) -> Result<(usize, usize), ProgramError> {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    Ok((accounts.len() - 2, accounts.len() - 1))
}

/// `SealStep` (tag 10).  Advances exactly one stage from its cursor.
#[allow(clippy::too_many_arguments)]
pub fn process_step(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    stage: u8,
    start: u32,
    count: u32,
) -> ProgramResult {
    let (state_index, authority_index) = step_indices(accounts)?;
    if accounts[0].is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    let (index_account, state_account, authority) = (
        &accounts[0],
        &accounts[state_index],
        &accounts[authority_index],
    );
    if !state_account.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if state_account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let mut state_data = state_account.try_borrow_mut_data()?;
    // Read the state's scalar fields directly out of the account: a
    // `Bds2` value would put 1,184 bytes of frame on the SBF stack, which is
    // what gate 7 caught (M-5.2: `process_step` at 4,928 bytes).  The route
    // stack is pushed in place through `stack_push_raw`.
    if state_data.len() != BDS2_BYTES
        || state_data[BDS2_OFF_MAGIC..BDS2_OFF_MAGIC + 4] != BDS2_MAGIC
    {
        return Err(refusal(DcgError(seal_err::STATE_EXISTS)));
    }
    let state_stage = state_data[BDS2_OFF_STAGE];
    let state_cursor = u32_at(&state_data, BDS2_OFF_CURSOR);
    let state_bytes = u64::from_le_bytes(
        state_data[BDS2_OFF_BYTES..BDS2_OFF_BYTES + 8]
            .try_into()
            .unwrap(),
    );
    let state_flags = u16::from_le_bytes([state_data[6], state_data[7]]);
    let mut state_digest = [0u8; 32];
    state_digest
        .copy_from_slice(&state_data[BDS2_OFF_DESCRIPTOR_DIGEST..BDS2_OFF_DESCRIPTOR_DIGEST + 32]);

    // Read the `DCD1` index for the digest and the chunk count.
    let index_bytes = index_account.try_borrow_data()?;
    if index_bytes.len() != DCD1_BYTES {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let record = Dcd1::decode(&index_bytes).map_err(refusal)?;
    if record.flags & (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
        != (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
    {
        return Err(refusal(DcgError(crate::descriptor::err::DESC_NOT_FINISHED)));
    }
    // The state names a digest; the passed index must be its DCD1.  The
    // address check is the binding (the digest cannot be recovered from the
    // DCD1 account, so the instruction carries it and this re-derives).
    let (want_index, _) = desc_upload::find_desc_index_address(program_id, &state_digest);
    if want_index != *index_account.key {
        return Err(ProgramError::InvalidArgument);
    }

    // Read the descriptor by ADDRESS from the passed chunks, WITHOUT
    // concatenating it.  This used to build one flat `Vec<u8>` of the whole
    // document per step; on the SBF image that is an allocation of
    // `total_bytes` against a 32 KiB heap, so every document past a few
    // kilobytes died `ProgramFailedToComplete` at the first `SealStep` — the
    // same O(document) residue R2 removed from `open_descriptor`, in the one
    // place that had its own copy of it.
    let chunk_accounts = &accounts[1..state_index];
    if chunk_accounts.len() != record.chunk_count as usize {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut guards = Vec::with_capacity(chunk_accounts.len());
    for (position, chunk) in chunk_accounts.iter().enumerate() {
        if chunk.is_writable {
            return Err(ProgramError::InvalidArgument);
        }
        let (want, _) =
            desc_upload::find_desc_chunk_address(program_id, &state_digest, position as u16);
        if want != *chunk.key {
            return Err(refusal(DcgError(
                crate::descriptor::err::DESC_CHUNK_ADDRESS,
            )));
        }
        let exact = desc_upload::chunk_len(record.total_bytes, position as u16) as usize;
        let data = chunk.try_borrow_data()?;
        if data.len() < exact {
            return Err(refusal(DcgError(
                crate::descriptor::err::DESC_CHUNK_ADDRESS,
            )));
        }
        guards.push(data);
    }
    let slices: Vec<&[u8]> = guards
        .iter()
        .enumerate()
        .map(|(position, guard)| {
            let exact = desc_upload::chunk_len(record.total_bytes, position as u16) as usize;
            &guard[..guard.len().min(exact)]
        })
        .collect();
    let document =
        Descriptor::from_chunks(&slices, record.total_bytes as usize).map_err(refusal)?;
    let plan = StagePlan::of(&document);

    // The cursor rules (331, 332, 333).
    if state_flags & BDS2_FLAG_SEALED != 0 {
        return Err(refusal(DcgError(seal_err::ALREADY)));
    }
    if stage != state_stage {
        return Err(refusal(DcgError(seal_err::STAGE_ORDER)));
    }
    if start != state_cursor {
        return Err(refusal(DcgError(seal_err::CURSOR)));
    }
    let end = plan.stage_end(stage);
    // R16: per-stage ITEM caps.  `SEAL_STEP_MAX_BYTES` bounds the descriptor
    // bytes; these bound the item count, because a placement slice and a route
    // entry cost far more CU than their row width suggests.  A stage-3 step may
    // span the wave/edge boundary: the edge cap then stands.
    let item_cap = match stage {
        STAGE_PLACEMENT => MAX_SEAL_SLICES_PER_CALL,
        STAGE_ROUTES => MAX_SEAL_ENTRIES_PER_CALL,
        STAGE_CROSS => {
            if start >= plan.wave_count || start + count > plan.wave_count {
                MAX_SEAL_EDGES_PER_CALL
            } else {
                MAX_SEAL_WAVES_PER_CALL
            }
        }
        _ => u32::MAX,
    };
    if count > SEAL_STEP_MAX_BYTES {
        return Err(refusal(DcgError(seal_err::STEP_TOO_LARGE)));
    }
    if stage != STAGE_HEADER && count > item_cap {
        return Err(refusal(DcgError(seal_err::STEP_TOO_LARGE)));
    }
    if start.checked_add(count).map_or(true, |next| next > end) {
        return Err(refusal(DcgError(seal_err::CURSOR)));
    }
    let bytes_consumed: u64 = if stage == STAGE_ROUTES {
        (start..start + count)
            .map(|index| entry_item_bytes(&document, index) as u64)
            .sum()
    } else if stage == STAGE_CROSS {
        (start..start + count)
            .map(|index| plan.schedule_item_bytes(index) as u64)
            .sum()
    } else if stage == STAGE_HEADER {
        // The header stage reads the whole container once, whichever sub-step
        // is running; charge it to `seal_bytes` on the first and nothing after.
        if start == 0 {
            plan.item_bytes(stage) as u64
        } else {
            0
        }
    } else {
        count as u64 * plan.item_bytes(stage) as u64
    };
    // Spec §4.2: stage 0's per-call bound is "none — one call", bounded by
    // "the clauses' own maxima", NOT by `SEAL_STEP_MAX_BYTES`; only stages
    // 1-3 carry the byte bound (their per-call bound column names it).
    // `item_bytes(STAGE_HEADER)` is `total_bytes` and exists only to move the
    // `seal_bytes` accumulator, so charging it against the step ceiling made
    // every document larger than 16,384 B unsealable at its FIRST step — the
    // fault the 20-window fixture (373,284 B) fires as 333.
    if stage != STAGE_HEADER && bytes_consumed > SEAL_STEP_MAX_BYTES as u64 {
        return Err(refusal(DcgError(seal_err::STEP_TOO_LARGE)));
    }

    // R16: stage 0 runs its validators PER SUB-STEP, not all at the end.
    if stage == STAGE_HEADER {
        for index in start..start + count {
            run_header_validator(index, &document)?;
        }
    }

    // R16: stages 1-3 validate exactly the items `[start, start+count)` here,
    // against the descriptor bytes the chunks commit (the sealed prefix is the
    // same immutable rows); the cross-item passes run when the stage ends.
    run_stage_items(stage, &document, start, count)?;

    let stack_off = BDS2_OFF_STACK;
    let stack_end = BDS2_OFF_STACK + BDS2_ROUTE_ROOT_STACK_LEVELS * 32;
    if stage == STAGE_ROUTES {
        for index in start..start + count {
            let leaf = document.entry_leaf(index as usize);
            stack_push_raw(&mut state_data[stack_off..stack_end], leaf).map_err(refusal)?;
        }
    }
    let mut next_cursor = start + count;
    let mut next_stage = state_stage;
    let next_bytes = state_bytes.saturating_add(bytes_consumed);
    let mut next_flags = state_flags;
    let stack_len = popcount(next_cursor);

    if next_cursor == end {
        // Stage complete: run the document's own validators.  The route root
        // is compared to clause 5's declared root before any validator runs,
        // so a wrong fold is `SEAL_ROUTE_ROOT(337)` and not a document code.
        if stage == STAGE_ROUTES {
            let folded = stack_collapse_raw(&state_data[stack_off..stack_end]);
            if folded != document.route_root() {
                return Err(refusal(DcgError(seal_err::ROUTE_ROOT)));
            }
        }
        run_stage_validators(stage, &document)?;
        next_stage = stage + 1;
        next_cursor = 0;
        if stage == STAGE_CROSS {
            let schedule = document.clause(CLAUSE_SCHEDULE);
            if schedule.len() >= 20 {
                let terminal = u32_at(schedule, 16);
                state_data[BDS2_OFF_TERMINAL..BDS2_OFF_TERMINAL + 4]
                    .copy_from_slice(&terminal.to_le_bytes());
            }
            next_flags |= BDS2_FLAG_TERMINAL;
        }
    }
    state_data[6..8].copy_from_slice(&next_flags.to_le_bytes());
    state_data[BDS2_OFF_STAGE] = next_stage;
    state_data[BDS2_OFF_STACK_LEN] = stack_len;
    state_data[BDS2_OFF_CURSOR..BDS2_OFF_CURSOR + 4].copy_from_slice(&next_cursor.to_le_bytes());
    state_data[BDS2_OFF_BYTES..BDS2_OFF_BYTES + 8].copy_from_slice(&next_bytes.to_le_bytes());
    Ok(())
}

/// Stage 0's whole-clause validators, one per `index` (R16).  The order is
/// the clause order and is normative: it is the `start` a `SealStep` names.
fn run_header_validator(index: u32, document: &Descriptor) -> Result<(), ProgramError> {
    match index {
        0 => document.validate_kernels().map_err(refusal),
        1 => document.validate_placement_framing().map_err(refusal),
        2 => document.validate_regions().map_err(refusal),
        3 => document.validate_machine().map_err(refusal),
        4 => document.validate_policy().map_err(refusal),
        5 => document.validate_closure().map_err(refusal),
        6 => document.validate_supply().map_err(refusal),
        7 => document.validate_successor().map_err(refusal),
        _ => Ok(()),
    }
}

/// R16: the per-item validators for stages 1-3, run by every `SealStep` over
/// exactly the items it declares.  These are the halves of the whole-clause
/// validators that read only the item's own rows and the already-committed
/// prefix; nothing here is a new rule.
fn run_stage_items(
    stage: u8,
    document: &Descriptor,
    start: u32,
    count: u32,
) -> Result<(), ProgramError> {
    match stage {
        STAGE_PLACEMENT => document
            .validate_placement_slices(start, count)
            .map_err(refusal),
        STAGE_ROUTES => {
            document.validate_routes_framing().map_err(refusal)?;
            document
                .validate_routes_entries(start, count)
                .map_err(refusal)
        }
        STAGE_CROSS => {
            document.validate_schedule_framing().map_err(refusal)?;
            let plan = StagePlan::of(document);
            let waves = plan.wave_count;
            let end = start.saturating_add(count);
            if start < waves {
                let wave_end = end.min(waves);
                document
                    .validate_schedule_waves(start, wave_end - start)
                    .map_err(refusal)?;
            }
            if end > waves {
                let edge_start = start.max(waves) - waves;
                let edge_end = end - waves;
                document
                    .validate_schedule_edges(edge_start, edge_end - edge_start)
                    .map_err(refusal)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Run the cross-item validators §4.2 assigns to `stage` when its cursor
/// reaches the end.  R16: the per-item halves ran in `run_stage_items`.
fn run_stage_validators(stage: u8, document: &Descriptor) -> Result<(), ProgramError> {
    match stage {
        // STAGE_HEADER's validators run per sub-step (R16), not here.
        STAGE_PLACEMENT => {
            document.validate_placement_global().map_err(refusal)?;
        }
        STAGE_ROUTES => {
            // The seal's own mountain-range collapse already compared the fold
            // to the declared root (`SEAL_ROUTE_ROOT(337)`), so the O(entries)
            // re-fold in `check_root` is skipped here.
            document.validate_routes_global(false).map_err(refusal)?;
        }
        STAGE_CROSS => {
            document.validate_schedule_global().map_err(refusal)?;
        }
        _ => {}
    }
    Ok(())
}

/// `SealFinish` (tag 11).
pub fn process_finish(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if accounts[0].is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    let (state_account, authority) = (&accounts[1], &accounts[2]);
    if !state_account.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if state_account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let mut state_data = state_account.try_borrow_mut_data()?;
    let mut state = Bds2::decode(&state_data).map_err(refusal)?;
    if state.sealed() {
        return Err(refusal(DcgError(seal_err::ALREADY)));
    }
    if state.seal_stage != STAGE_DONE || state.seal_cursor != 0 {
        return Err(refusal(DcgError(seal_err::INCOMPLETE)));
    }
    state.flags |= BDS2_FLAG_SEALED;
    state_data.copy_from_slice(&state.encode());
    Ok(())
}

// ---------------------------------------------------------------------------
// Instruction data.
// ---------------------------------------------------------------------------

pub fn decode_begin(data: &[u8]) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    if data.len() != BEGIN_INSTRUCTION_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&data[1..33]);
    let mut image = [0u8; 32];
    image.copy_from_slice(&data[33..65]);
    Ok((digest, image))
}

pub fn decode_step(data: &[u8]) -> Result<(u8, u32, u32), ProgramError> {
    if data.len() != STEP_INSTRUCTION_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    let start = u32_at(data, 2);
    let count = u32_at(data, 6);
    Ok((data[1], start, count))
}

pub fn decode_finish(data: &[u8]) -> Result<(), ProgramError> {
    if data.len() != FINISH_INSTRUCTION_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(index: u8) -> [u8; 32] {
        sha256(&[b"leaf", &[index]])
    }

    #[test]
    fn stack_collapse_equals_level_by_level_for_every_count() {
        for count in 1..=256u32 {
            let leaves: Vec<[u8; 32]> = (0..count).map(|index| leaf(index as u8)).collect();
            let mut stack = [[0u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS];
            for value in &leaves {
                stack_push(&mut stack, *value).unwrap();
            }
            assert_eq!(
                stack_collapse(&stack),
                route_root_from_leaves(&leaves),
                "count {count}"
            );
        }
    }

    #[test]
    fn the_33rd_level_is_a_refusal_not_a_panic() {
        // 32 occupied levels and one more push needs a 33rd.
        let mut stack = [[0u8; 32]; BDS2_ROUTE_ROOT_STACK_LEVELS];
        for level in 0..BDS2_ROUTE_ROOT_STACK_LEVELS {
            stack[level] = leaf(level as u8);
        }
        assert_eq!(
            stack_push(&mut stack, leaf(200)).unwrap_err().0,
            seal_err::STACK_OVERFLOW
        );
        assert_eq!(seal_err::STACK_OVERFLOW, 338);
    }

    #[test]
    fn bds2_round_trips_and_reserved_bytes_are_zero_forever() {
        let record = Bds2::init([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let image = record.encode();
        assert_eq!(image.len(), BDS2_BYTES);
        let decoded = Bds2::decode(&image).unwrap();
        assert_eq!(decoded.encode(), image);
        let mut bad = image;
        bad[BDS2_OFF_RESERVED0] = 1;
        assert_eq!(
            Bds2::decode(&bad).unwrap_err().0,
            crate::descriptor::err::NONZERO_RESERVED
        );
    }

    #[test]
    fn the_registry_codes_are_the_assigned_numbers() {
        assert_eq!(seal_err::STATE_EXISTS, 330);
        assert_eq!(seal_err::STAGE_ORDER, 331);
        assert_eq!(seal_err::CURSOR, 332);
        assert_eq!(seal_err::STEP_TOO_LARGE, 333);
        assert_eq!(seal_err::INCOMPLETE, 334);
        assert_eq!(seal_err::ALREADY, 335);
        assert_eq!(seal_err::IMAGE_ZERO, 336);
        assert_eq!(seal_err::ROUTE_ROOT, 337);
        assert_eq!(seal_err::STACK_OVERFLOW, 338);
        assert_eq!(BDS2_BYTES, 1184);
    }
}
