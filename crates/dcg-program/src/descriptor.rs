//! DCG descriptor v1: parse, validate, digest.  Pure.
//!
//! No I/O, no accounts, no execution, no allocation.  The whole module is a
//! set of zero-copy views over one `&[u8]`, so its stack frames stay small
//! enough for the SBF stack-frame gate (M978) and it can be exercised
//! natively at full speed.
//!
//! The grammar is specified in `docs/spec/dcg-descriptor-v1.md`.  The Python
//! mirror is `src/basanos/dcg/descriptor.py`; the refusal codes below are the
//! same registry as `src/basanos/dcg/errors.py`, and the goldens under
//! `tests/golden/dcg/` are read by both.

use crate::hash::{sha256, Parts};

// ---------------------------------------------------------------------------
// Refusal codes.  Mirror of src/basanos/dcg/errors.py; append-only.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcgError(pub u32);

pub mod err {
    pub const TRUNCATED: u32 = 1;
    pub const BAD_MAGIC: u32 = 2;
    pub const BAD_GRAMMAR_VERSION: u32 = 3;
    pub const NONZERO_RESERVED: u32 = 4;
    pub const BAD_TOTAL_BYTES: u32 = 5;
    pub const BAD_CLAUSE_COUNT: u32 = 6;
    pub const CLAUSE_ORDER: u32 = 7;
    pub const CLAUSE_LAYOUT: u32 = 8;
    pub const BAD_FLAGS: u32 = 9;

    pub const CLAUSE_LENGTH: u32 = 20;
    pub const BAD_COUNT: u32 = 21;

    pub const MACHINE_NAME: u32 = 30;
    pub const MACHINE_PROFILE_FORM: u32 = 31;

    pub const KERNEL_COUNT: u32 = 40;
    pub const KERNEL_ORDER: u32 = 41;
    pub const KERNEL_ROUTE_BOUNDS: u32 = 42;
    pub const KERNEL_CEILING: u32 = 43;
    pub const KERNEL_NO_CONSENSUS_FORM: u32 = 44;
    pub const KERNEL_CONSENSUS_STEPS: u32 = 45;
    pub const KERNEL_MODE_COST_MISSING: u32 = 46;
    pub const KERNEL_MODE_COST_ORDER: u32 = 47;
    pub const KERNEL_MODE_COST_UNDECLARED: u32 = 48;
    pub const KERNEL_CLASS: u32 = 49;

    pub const REGION_ORDER: u32 = 60;
    pub const REGION_LENGTH: u32 = 61;
    pub const REGION_LIFETIME: u32 = 62;
    pub const REGION_ENCODING: u32 = 63;
    pub const REGION_SCALE: u32 = 64;
    pub const REGION_PLACEMENT_REF: u32 = 65;
    pub const REGION_INIT_KIND: u32 = 66;

    pub const PLACEMENT_FORM: u32 = 80;
    pub const PLACEMENT_ORDER: u32 = 81;
    pub const PLACEMENT_REGION: u32 = 82;
    pub const PLACEMENT_PARAMS: u32 = 83;
    pub const PLACEMENT_COVERAGE: u32 = 84;
    pub const PLACEMENT_CELL_COLLISION: u32 = 85;
    pub const PLACEMENT_SLICE_ORDER: u32 = 86;
    pub const PLACEMENT_SLICE_RANGE: u32 = 87;
    pub const PLACEMENT_ACCOUNT_OVERLAP: u32 = 88;
    pub const PLACEMENT_TOO_MANY_CELLS: u32 = 89;
    pub const PLACEMENT_SLICE_UNSORTED: u32 = 90;
    pub const PLACEMENT_ACCOUNT_KIND: u32 = 91;
    pub const PLACEMENT_KIND_LIFETIME: u32 = 92;
    pub const PLACEMENT_KIND_CONFLICT: u32 = 93;
    pub const PLACEMENT_ORDINAL_AMBIGUOUS: u32 = 94;
    pub const PLACEMENT_ACCOUNT_TOO_LARGE: u32 = 95;
    pub const PLACEMENT_ACCOUNT_HOLE: u32 = 96;
    pub const PLACEMENT_WINDOW_REGION: u32 = 97;
    pub const DESC_TAG_RETIRED: u32 = 310;
    // Descriptor identity by address (lifecycle spec §3.4, dispatch 5.1).
    // Registry: tests/golden/dcg/lifecycle/refusals_v1.tsv, append-only.
    pub const DESC_OPEN_EXISTS: u32 = 311;
    pub const DESC_TOTAL_BYTES: u32 = 312;
    pub const DESC_CHUNK_COUNT: u32 = 313;
    pub const DESC_CHUNK_ADDRESS: u32 = 314;
    pub const DESC_CHUNK_SIZE: u32 = 315;
    pub const DESC_ALLOC_AFTER_UPLOAD: u32 = 316;
    pub const DESC_UPLOAD_CURSOR: u32 = 317;
    pub const DESC_UPLOAD_OVERRUN: u32 = 318;
    pub const DESC_UPLOAD_SEALED: u32 = 319;
    pub const DESC_UPLOAD_SPAN: u32 = 320;
    pub const DESC_DIGEST_MISMATCH: u32 = 321;
    pub const DESC_NOT_FINISHED: u32 = 322;
    pub const DESC_NOT_SEALED: u32 = 323;
    pub const DESC_CHUNK_ORDER: u32 = 324;
    pub const DESC_CHUNK_MISSING: u32 = 325;
    pub const DESC_AUTHORITY: u32 = 326;
    // Amendment A1 (lifecycle spec §3.1/§3.4, dispatch 5.1b). Registry:
    // tests/golden/dcg/lifecycle/refusals_v1.tsv, append-only.
    pub const DESC_ALLOC_STEP: u32 = 327;
    pub const DESC_OPEN_GRAMMAR_VERSION: u32 = 328;
    /// `DescriptorAlloc` grew the chunk and it did not reach the asked length.
    pub const DESC_ALLOC_SIZE: u32 = 329;

    pub const ROUTE_ENTRY_ORDER: u32 = 100;
    pub const ROUTE_KERNEL_REF: u32 = 101;
    pub const ROUTE_REGION_REF: u32 = 102;
    pub const ROUTE_OUT_OF_REGION: u32 = 103;
    pub const ROUTE_DIRECTION: u32 = 104;
    pub const ROUTE_ORDER: u32 = 105;
    pub const ROUTE_COUNT_MISMATCH: u32 = 106;
    pub const ROUTE_WRITE_PRODUCER: u32 = 107;
    pub const ROUTE_PRODUCER_UNRESOLVED: u32 = 108;
    pub const ROUTE_WRITE_OVERLAP: u32 = 109;
    pub const ROUTE_ROOT: u32 = 110;
    pub const ROUTE_CLASS: u32 = 111;
    pub const ROUTE_KERNEL_LIFETIME: u32 = 112;
    pub const ROUTE_LENGTH: u32 = 113;
    pub const ROUTE_PLACEMENT_CLASS: u32 = 114;

    pub const SCHEDULE_WAVE_ORDER: u32 = 130;
    pub const SCHEDULE_COVERAGE: u32 = 131;
    pub const SCHEDULE_EDGE: u32 = 132;
    pub const SCHEDULE_TERMINAL: u32 = 133;
    pub const SCHEDULE_OPS: u32 = 134;

    pub const POLICY_REGISTRY_ORDER: u32 = 150;
    pub const POLICY_REGISTRY_NAME: u32 = 151;
    pub const POLICY_NO_CONSENSUS: u32 = 152;
    pub const POLICY_UNKNOWN_MODE: u32 = 153;
    pub const POLICY_UNSUPPORTED_MODE: u32 = 154;
    pub const POLICY_RULE_SELECTOR: u32 = 155;
    pub const POLICY_RULE_ORDER: u32 = 156;
    pub const POLICY_RULE_KEY: u32 = 157;
    pub const POLICY_DEFAULT_MODE: u32 = 158;

    pub const CLOSURE_GEOMETRY: u32 = 170;
    pub const CLOSURE_REQUIRED: u32 = 171;
    pub const CLOSURE_FORBIDDEN: u32 = 172;
    pub const CLOSURE_FAMILY_ORDER: u32 = 173;
    pub const CLOSURE_WINDOW: u32 = 174;

    pub const SUPPLY_ORDER: u32 = 190;
    pub const SUPPLY_REGION: u32 = 191;
    pub const SUPPLY_LENGTH: u32 = 192;
    pub const SUPPLY_SHARED_UNSEALED: u32 = 193;
    pub const SUPPLY_SHARED_OWNER: u32 = 194;
    pub const SUPPLY_SHARING: u32 = 195;
    pub const SUPPLY_DIGEST: u32 = 196;
    pub const SUPPLY_UNSUPPLIED_REGION: u32 = 197;

    pub const PROVISION_ACCOUNT_COUNT: u32 = 270;
    pub const PROVISION_ORDINAL_ORDER: u32 = 271;
    pub const PROVISION_UNKNOWN_ORDINAL: u32 = 272;
    pub const PROVISION_ADDRESS: u32 = 273;
    pub const PROVISION_OWNER: u32 = 274;
    pub const PROVISION_SIZE: u32 = 275;
    pub const PROVISION_WRITABLE: u32 = 276;
    pub const PROVISION_NOT_ZEROED: u32 = 277;
    pub const PROVISION_SHARED_NOT_BOUND: u32 = 278;
    /// B2 (steps 1-3 review): the caller's bump is not the canonical one.
    pub const PROVISION_BUMP_NOT_CANONICAL: u32 = 279;

    // Execution (DCG step 4a).  Append-only, like every block above.
    pub const EXEC_SPAN_REF: u32 = 280;
    pub const EXEC_SPAN_BOUNDS: u32 = 281;
    pub const EXEC_SPAN_UNMAPPED: u32 = 282;
    pub const EXEC_WRITE_TO_READ_SPAN: u32 = 283;
    pub const EXEC_NO_IMPLEMENTATION: u32 = 284;
    pub const EXEC_PARAMS_LENGTH: u32 = 285;
    pub const EXEC_PROFILE_FORM: u32 = 286;
    pub const EXEC_PROFILE_DIGEST: u32 = 287;
    pub const EXEC_KERNEL_GEOMETRY: u32 = 288;
    pub const EXEC_FLY_POSTED_MISMATCH: u32 = 289;
    pub const EXEC_MODE_NOT_CONSENSUS: u32 = 290;
    pub const EXEC_ACCOUNT_COUNT: u32 = 291;
    pub const EXEC_ACCOUNT_ORDER: u32 = 292;
    pub const EXEC_ACCOUNT_MISSING: u32 = 293;
    pub const EXEC_ACCOUNT_WRITABLE: u32 = 294;
    pub const EXEC_ACCOUNT_ALIASED: u32 = 295;
    pub const EXEC_SPAN_COUNT: u32 = 296;
    pub const EXEC_SPAN_CELLS: u32 = 297;
    pub const EXEC_SPAN_UNCOVERED: u32 = 298;
    pub const EXEC_INSTRUCTION_FORM: u32 = 299;
    /// B3.2 (steps 1-3 review): the seal account is not owned by this program.
    pub const EXEC_STATE_OWNER: u32 = 300;

    // PT1 misc kernel refusals (director allocation, 2026-09-23).
    pub const PT1_MISC_GEOMETRY: u32 = 710;
    pub const PT1_MISC_SPAN_SHAPE: u32 = 711;
    pub const PT1_MISC_ARITHMETIC: u32 = 712;
    pub const PT1_MISC_EMBED_TOKEN: u32 = 713;
    pub const PT1_MISC_ARTIFACT_ROOT: u32 = 714;

    pub const SUCCESSOR_ORDER: u32 = 210;
    pub const SUCCESSOR_REGION: u32 = 211;
    pub const SUCCESSOR_SEAL: u32 = 212;
    pub const SUCCESSOR_LENGTH: u32 = 213;

    // Access authentication (step 2).  Appended, never renumbered.
    pub const ACCESS_PAYLOAD_LENGTH: u32 = 230;
    pub const ACCESS_PAYLOAD_MAGIC: u32 = 231;
    pub const ACCESS_UNKNOWN_FORM: u32 = 232;
    pub const ACCESS_FORM_MISMATCH: u32 = 233;
    pub const ACCESS_ENTRY_MISMATCH: u32 = 234;
    pub const ACCESS_ENTRY_REF: u32 = 235;
    pub const ACCESS_OPERAND_BOUND: u32 = 236;
    pub const ACCESS_SPAN_COUNT: u32 = 237;
    pub const ACCESS_SPAN_OVERFLOW: u32 = 238;
    pub const ACCESS_REGION_REF: u32 = 239;
    pub const ACCESS_ELEMENT_ALIGN: u32 = 240;
    pub const ACCESS_SPAN_OUT_OF_REGION: u32 = 241;
    pub const ACCESS_LIFETIME: u32 = 242;
    pub const ACCESS_IMMUTABLE_WRITE: u32 = 243;
    pub const ACCESS_PLACEMENT_CLASS: u32 = 244;
    pub const ACCESS_WRITE_ROUTE_MAX: u32 = 245;
    pub const ACCESS_STATE_MODE: u32 = 246;
    pub const ACCESS_SELECTOR: u32 = 247;
    pub const ACCESS_PROVENANCE_CLASS: u32 = 248;
    pub const ACCESS_UNPRODUCED_READ: u32 = 249;
    pub const ACCESS_SPAN_NOT_ROUTED: u32 = 250;
    pub const ACCESS_READ_CLASS_UNWITNESSABLE: u32 = 251;
    pub const ACCESS_READ_CLASS_REGION: u32 = 252;
    pub const ACCESS_POLICY_AMBIGUOUS: u32 = 253;
    pub const ACCESS_IMAGE_BINDING: u32 = 254;
    pub const ACCESS_ROW_STRIDE: u32 = 255;
    pub const ACCESS_WRITE_OVERLAP: u32 = 256;
}

macro_rules! refuse {
    ($code:expr) => {
        return Err(DcgError($code))
    };
}

macro_rules! require {
    ($cond:expr, $code:expr) => {
        if !$cond {
            return Err(DcgError($code));
        }
    };
}

// ---------------------------------------------------------------------------
// Container constants.  Frozen: docs/spec/dcg-descriptor-v1.md §9.
// ---------------------------------------------------------------------------

pub const MAGIC: [u8; 4] = *b"BDG1";
pub const GRAMMAR_VERSION: u16 = 2;

pub const HEADER_BYTES: usize = 64;
pub const DIRECTORY_ENTRY_BYTES: usize = 12;
pub const CLAUSE_COUNT: usize = 10;
pub const DIRECTORY_BYTES: usize = DIRECTORY_ENTRY_BYTES * CLAUSE_COUNT;
pub const BODY_START: usize = HEADER_BYTES + DIRECTORY_BYTES;

pub const CLAUSE_MACHINE: u16 = 1;
pub const CLAUSE_KERNELS: u16 = 2;
pub const CLAUSE_REGIONS: u16 = 3;
pub const CLAUSE_PLACEMENT: u16 = 4;
pub const CLAUSE_ROUTES: u16 = 5;
pub const CLAUSE_SCHEDULE: u16 = 6;
pub const CLAUSE_VERIFICATION_POLICY: u16 = 7;
pub const CLAUSE_CLOSURE_POLICY: u16 = 8;
pub const CLAUSE_SUPPLY: u16 = 9;
pub const CLAUSE_SUCCESSOR: u16 = 10;

pub const MACHINE_BYTES: usize = 136;
pub const MACHINE_NAME_BYTES: usize = 64;

pub const KERNELS_HEADER_BYTES: usize = 8;
pub const KERNEL_ROW_BYTES: usize = 48;
pub const MODE_COST_ROW_BYTES: usize = 16;
pub const MAX_KERNELS: usize = 64;
pub const MAX_MODE_COST_ROWS: usize = 512;

pub const REGIONS_HEADER_BYTES: usize = 8;
pub const REGION_ROW_BYTES: usize = 64;
pub const MAX_REGIONS: usize = 1024;
pub const MAX_REGION_BYTES: u64 = 1 << 40;

pub const PLACEMENT_HEADER_BYTES: usize = 12;
pub const GENERATOR_ROW_BYTES: usize = 40;
pub const EXPLICIT_SLICE_ROW_BYTES: usize = 48;
pub const MAX_GENERATORS: usize = 1024;
pub const MAX_EXPLICIT_SLICES: usize = 65536;
/// Step 3 replaced the pairwise cell scan.  A `grid` generator's cells are
/// NEVER enumerated any more -- the whole cell set is one arithmetic envelope
/// with an O(1) membership test -- so a dense document's cell count is bounded
/// only by its own coverage identity.  What is still enumerated is the
/// explicit slice table, and this is what bounds it.
pub const MAX_PLACEMENT_CELLS: u64 = MAX_EXPLICIT_SLICES as u64;

/// The cluster's maximum account data length.  Not a document byte: a
/// provisioning fact the grammar refuses early rather than at create time.
/// `chain/testnet_provision_v2.py:77` guards at a decimal 10,000,000 B, and a
/// *measured* 10,001,523 B account exists (`out/runs/si4-4b-shard-preflight-a`),
/// so the guard there is a convention and this is the runtime ceiling.
pub const MAX_ACCOUNT_BYTES: u64 = 10 * 1024 * 1024;

/// When two `grid` generators' ordinal ranges AND account byte spans both
/// overlap, the parser enumerates the smaller grid against the larger one's
/// O(1) membership test -- but only up to this many cells.  Above it the
/// document is refused as ambiguously numbered and must renumber its
/// ordinals, which costs it nothing: an ordinal is a free internal name that
/// `provision::placement_account_address` binds to a pubkey, not an external
/// identity.
pub const MAX_GRID_PAIR_CELLS: u64 = 256;

// -- `account_kind`, the closed set (step 3) -----------------------------
pub const ACCOUNT_KIND_STORAGE: u16 = 0;
pub const ACCOUNT_KIND_ACTIVATION_BANK: u16 = 1;
pub const ACCOUNT_KIND_SUPPLY_WINDOW: u16 = 2;
pub const ACCOUNT_KIND_SHARED_WINDOW: u16 = 3;
pub const ACCOUNT_KIND_SCRATCH: u16 = 4;
pub const ACCOUNT_KIND_OUTPUT_LEAF: u16 = 5;
pub const ACCOUNT_KIND_MAX: u16 = ACCOUNT_KIND_OUTPUT_LEAF;

/// Which region lifetimes may be placed in an account of each class.
pub fn account_kind_admits_lifetime(kind: u16, lifetime: u8) -> bool {
    match kind {
        ACCOUNT_KIND_STORAGE => lifetime == LIFETIME_MUTABLE || lifetime == LIFETIME_COMMITTED,
        ACCOUNT_KIND_ACTIVATION_BANK => lifetime == LIFETIME_MUTABLE,
        ACCOUNT_KIND_SUPPLY_WINDOW => {
            lifetime == LIFETIME_COMMITTED || lifetime == LIFETIME_SUPPLIED
        }
        ACCOUNT_KIND_SHARED_WINDOW => lifetime == LIFETIME_SHARED,
        ACCOUNT_KIND_SCRATCH => lifetime == LIFETIME_SCRATCH,
        ACCOUNT_KIND_OUTPUT_LEAF => lifetime == LIFETIME_OUTPUT,
        _ => false,
    }
}

/// Bytes the class appends beyond the highest placement-cell end.
///
/// Lifecycle step 5.5 (the 5.4 seam): every `supply_window` (2) and
/// `shared_window` (3) account carries the 96-byte `DSW1` tail after its
/// body (lifecycle spec §5.1), so a provisioned window is `body + 96`.
pub fn account_kind_tail_bytes(kind: u16) -> u64 {
    match kind {
        ACCOUNT_KIND_ACTIVATION_BANK => 64,
        ACCOUNT_KIND_SUPPLY_WINDOW | ACCOUNT_KIND_SHARED_WINDOW => 96,
        _ => 0,
    }
}

/// A `shared_window` is provisioned once under its OWNER descriptor and only
/// bound here, so it is never created and never closed by this document.
pub fn account_kind_provisioned_here(kind: u16) -> bool {
    kind != ACCOUNT_KIND_SHARED_WINDOW
}

/// Sealed content (either window class) is written by the supply step, never
/// by a kernel.
pub fn account_kind_admits_write(kind: u16, lifetime: u8) -> bool {
    match kind {
        ACCOUNT_KIND_STORAGE | ACCOUNT_KIND_ACTIVATION_BANK => lifetime == LIFETIME_MUTABLE,
        ACCOUNT_KIND_SCRATCH => lifetime == LIFETIME_SCRATCH,
        ACCOUNT_KIND_OUTPUT_LEAF => lifetime == LIFETIME_OUTPUT,
        _ => false,
    }
}

pub const ROUTES_HEADER_BYTES: usize = 80;
pub const ENTRY_ROW_BYTES: usize = 16;
pub const ROUTE_RECORD_BYTES: usize = 24;
pub const MAX_ENTRIES: usize = u32::MAX as usize;
pub const MAX_ROUTE_RECORDS: usize = 1 << 24;

pub const SCHEDULE_HEADER_BYTES: usize = 32;
pub const WAVE_ROW_BYTES: usize = 16;
pub const EDGE_ROW_BYTES: usize = 8;
pub const MAX_WAVES: usize = 1 << 24;
pub const MAX_EDGES: usize = 1 << 26;

pub const POLICY_HEADER_BYTES: usize = 8;
pub const MODE_REGISTRY_ROW_BYTES: usize = 40;
pub const POLICY_RULE_ROW_BYTES: usize = 16;
pub const MODE_NAME_BYTES: usize = 32;
pub const MAX_MODE_REGISTRANTS: usize = 16;
pub const MAX_POLICY_RULES: usize = 256;

pub const CLOSURE_HEADER_BYTES: usize = 40;
pub const CLOSURE_FAMILY_ROW_BYTES: usize = 24;
pub const MAX_CLOSURE_FAMILIES: usize = 256;

pub const SUPPLY_HEADER_BYTES: usize = 8;
pub const SUPPLY_WINDOW_ROW_BYTES: usize = 88;
pub const MAX_SUPPLY_WINDOWS: usize = 4096;

pub const SUCCESSOR_HEADER_BYTES: usize = 40;
pub const SUCCESSOR_IMPORT_ROW_BYTES: usize = 48;
pub const MAX_SUCCESSOR_IMPORTS: usize = 1024;

pub const LIFETIME_MUTABLE: u8 = 0;
pub const LIFETIME_COMMITTED: u8 = 1;
pub const LIFETIME_SHARED: u8 = 2;
pub const LIFETIME_SCRATCH: u8 = 3;
pub const LIFETIME_OUTPUT: u8 = 4;
pub const LIFETIME_SUPPLIED: u8 = 5;
pub const LIFETIME_MAX: u8 = LIFETIME_SUPPLIED;

pub const ENCODING_Q8_SCALED: u16 = 2;
pub const ENCODING_MAX: u16 = 4;

pub const REGION_FLAG_REDERIVED: u8 = 1 << 0;
pub const REGION_FLAG_ASSERTED: u8 = 1 << 1;

pub const NO_SCALE_REGION: u16 = 0xFFFF;
pub const NO_PRODUCER: u32 = 0xFFFF_FFFF;

pub const INIT_MUST_BE_ZERO: u8 = 0;
pub const INIT_DIGEST_SEALED: u8 = 1;
pub const INIT_UNCONSTRAINED: u8 = 2;
pub const INIT_EXTERNAL_DIGEST: u8 = 3;

pub const PLACEMENT_GRID: u16 = 1;
pub const PLACEMENT_EXPLICIT: u16 = 2;

pub const KERNEL_PLACEMENT_SINGLE_REGION: u8 = 0;
pub const KERNEL_PLACEMENT_MULTI_REGION: u8 = 1;

pub const PROVENANCE_MAX: u8 = 3;

pub const CONSENSUS_FORM_SINGLE_TX: u8 = 0;
pub const CONSENSUS_FORM_MULTI_STEP: u8 = 1;

pub const DIRECTION_READ: u8 = 0;
pub const DIRECTION_WRITE: u8 = 1;

pub const READ_CLASS_WITNESSED: u8 = 0;
pub const READ_CLASS_ASSERTED: u8 = 1;
pub const READ_CLASS_SUPPLIED: u8 = 2;
pub const READ_CLASS_CLOSURE_ROOT: u8 = 3;
pub const READ_CLASS_MAX: u8 = READ_CLASS_CLOSURE_ROOT;

pub const MODE_CONSENSUS: u16 = 1;
pub const MODE_COMMIT: u16 = 2;
pub const MODE_NAME_CONSENSUS: &[u8] = b"consensus";
pub const MODE_NAME_COMMIT: &[u8] = b"commit";

pub const MODE_FLAG_REQUIRES_CLOSURE: u16 = 1 << 0;
pub const MODE_FLAG_IN_TRANSACTION_REPLAY: u16 = 1 << 1;
/// `docs/spec/dcg-write-records-v1.md` §1: the document opts every consensus
/// `Execute` into write-record provenance v1. Admissible only on the
/// `consensus` registrant; every other registrant and every bit above it is
/// still refused, so no pre-`WRP1` document can carry it.
pub const MODE_FLAG_WRITE_RECORDS_V1: u16 = 1 << 2;

pub const SELECTOR_KERNEL_KIND: u8 = 0;
pub const SELECTOR_ENTRY_RANGE: u8 = 1;
pub const SELECTOR_MAX: u8 = SELECTOR_ENTRY_RANGE;

pub const CU_CEILING_MAX: u32 = 1_400_000;

pub const DESC_FRAME_BYTES: usize = 1024;
pub const TAG_HEADER: &[u8] = b"basanos/dcg-header/2";
pub const TAG_CLAUSE_FRAME: &[u8] = b"basanos/dcg-clause-frame/2";
pub const TAG_DESCRIPTOR: &[u8] = b"basanos/dcg-descriptor/2";
pub const TAG_CLAUSE: &[u8] = b"basanos/dcg-clause/2";
pub const TAG_ROUTE_ENTRY: &[u8] = b"basanos/dcg-route-entry/1";
pub const TAG_ROUTE_NODE: &[u8] = b"basanos/dcg-route-node/1";
pub const TAG_SUCCESSOR_SEAL: &[u8] = b"basanos/dcg-successor-seal/1";

const ZERO32: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Little-endian readers.  Every one is bounds-checked by the caller's framing.
// ---------------------------------------------------------------------------

#[inline]
fn u8_at(buf: &[u8], off: usize) -> u8 {
    buf[off]
}

#[inline]
fn u16_at(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn u64_at(buf: &[u8], off: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(out)
}

#[inline]
fn digest_at(buf: &[u8], off: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[off..off + 32]);
    out
}

fn all_zero(buf: &[u8]) -> bool {
    buf.iter().all(|byte| *byte == 0)
}

/// A NUL-padded printable-ASCII name field: non-empty, no interior NUL.
fn name_is_valid(field: &[u8]) -> bool {
    let len = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if len == 0 {
        return false;
    }
    field[..len].iter().all(|byte| (0x21..=0x7E).contains(byte))
        && field[len..].iter().all(|byte| *byte == 0)
}

fn name_len(field: &[u8]) -> usize {
    field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len())
}

pub fn mode_support_bit(mode_id: u16) -> Option<u16> {
    if mode_id == 0 || mode_id as usize > MAX_MODE_REGISTRANTS {
        None
    } else {
        Some(1u16 << (mode_id - 1))
    }
}

// ---------------------------------------------------------------------------
// Row views.  Each is a Copy struct decoded from a fixed-width row.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct KernelRow {
    pub kind: u16,
    pub form_id: u16,
    pub read_route_min: u16,
    pub read_route_max: u16,
    pub write_route_min: u16,
    pub write_route_max: u16,
    pub operand_bound: u32,
    pub cu_ceiling: u32,
    pub heap_ceiling: u32,
    pub placement_class: u8,
    pub state_mode: u8,
    pub provenance_class: u8,
    pub consensus_form: u8,
    pub consensus_steps: u16,
    pub mode_support: u16,
    pub read_lifetime_mask: u8,
    pub write_lifetime_mask: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct RegionRow {
    pub region_id: u16,
    pub encoding: u16,
    pub lifetime: u8,
    pub flags: u8,
    pub scale_region: u16,
    pub byte_length: u64,
    pub element_stride: u32,
    pub placement_ref: u16,
    pub initial_content: [u8; 32],
    pub init_kind: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct GeneratorRow {
    pub generator_id: u16,
    pub form: u16,
    pub region_id: u16,
    pub account_kind: u16,
    // grid
    pub grid_base: u32,
    pub page_count: u32,
    pub shard_count: u32,
    pub page_stride: u32,
    pub shard_stride: u32,
    pub slice_length: u32,
    pub slice_offset: u64,
    // explicit
    pub first_slice: u32,
    pub slice_count: u32,
}

/// One resolved placement cell: which account holds which bytes of a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementCell {
    pub ordinal: u32,
    pub account_offset: u64,
    pub region_offset: u64,
    pub byte_length: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SliceRow {
    pub slice_index: u32,
    pub account_ordinal: u32,
    pub account_offset: u64,
    pub region_offset: u64,
    pub byte_length: u32,
    pub flags: u32,
}

/// One account's placement facts: the body an account of this ordinal must
/// have, its class, and the region that reaches furthest into it.  The same
/// triple [`Descriptor::account_body`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountFacts {
    pub body: u64,
    pub account_kind: u16,
    pub region_id: u16,
}

/// Whether an overflow already poisoned this slot (see `account_facts`).
#[inline]
fn is_poisoned(out: &[Option<AccountFacts>], slot: usize) -> bool {
    matches!(out[slot], Some(known) if known.body == u64::MAX)
}

/// Apply one matching cell to a slot's facts, keeping the highest end and the
/// earliest generator on a tie (the `account_body` rule).
#[inline]
fn consider_facts(
    out: &mut [Option<AccountFacts>],
    slot: usize,
    end: u64,
    account_kind: u16,
    region_id: u16,
) {
    let replace = match out[slot] {
        Some(current) => end > current.body,
        None => true,
    };
    if replace {
        out[slot] = Some(AccountFacts {
            body: end,
            account_kind,
            region_id,
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EntryRow {
    pub entry_index: u32,
    pub kernel_index: u16,
    pub read_count: u16,
    pub write_count: u16,
    pub route_start: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RouteRow {
    pub region_id: u16,
    pub direction: u8,
    pub read_class: u8,
    pub region_offset: u64,
    pub byte_length: u32,
    pub producer_entry: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ModeRegistrantRow {
    pub mode_id: u16,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyRuleRow {
    pub selector: u8,
    pub mode_id: u16,
    pub key_lo: u32,
    pub key_hi: u32,
}

/// One clause-8 closure family row (spec §4's selector names one of these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosureFamilyRow {
    pub family_id: u16,
    pub mode_id: u16,
    pub selector: u8,
    pub key_lo: u32,
    pub key_hi: u32,
}

// ---------------------------------------------------------------------------
// The framed descriptor.
// ---------------------------------------------------------------------------

/// Where a `Descriptor`'s bytes live.
///
/// Step 5.3 (lifecycle spec §3.5) binds the descriptor by ADDRESS and reads it
/// out of the chunk accounts, so `Execute` must be able to serve an indexed
/// read without ever materialising the whole document.  `Flat` is the
/// original contiguous buffer every other instruction still uses; `Chunks` is
/// the ascending chunk accounts, each truncated to its exact arithmetic
/// length.  Both variants are `Copy`, so `Descriptor` stays `Copy`.
#[derive(Clone, Copy)]
pub enum DocBuf<'a> {
    Flat(&'a [u8]),
    Chunks(&'a [&'a [u8]]),
}

impl<'a> DocBuf<'a> {
    /// The `len` bytes at `offset`.  For `Chunks` the caller has already
    /// proved (via `execute::required_chunks`) that the range lies inside one
    /// passed chunk; a range that straddles a chunk boundary is a refusal, not
    /// a slice, and never reaches here.
    pub fn at(self, offset: usize, len: usize) -> &'a [u8] {
        match self {
            DocBuf::Flat(buf) => &buf[offset..offset + len],
            DocBuf::Chunks(chunks) => {
                let size = crate::desc_upload::DESC_CHUNK_BYTES as usize;
                let index = offset / size;
                let start = offset % size;
                &chunks[index][start..start + len]
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct Descriptor<'a> {
    buf: DocBuf<'a>,
    spans: [(u32, u32); CLAUSE_COUNT],
}

impl<'a> Descriptor<'a> {
    /// Check the container framing.  Cheap; clause bodies are not yet read.
    pub fn parse(buf: &'a [u8]) -> Result<Self, DcgError> {
        Self::frame(DocBuf::Flat(buf), buf.len())
    }

    /// The same framing check over chunk accounts, each already truncated to
    /// its exact arithmetic length, with `total` the `DCD1.total_bytes` the
    /// addresses commit.  The header, and every clause it can read, must lie
    /// inside the passed chunks; `execute` proves that first.
    pub fn from_chunks(chunks: &'a [&'a [u8]], total: usize) -> Result<Self, DcgError> {
        Self::frame(DocBuf::Chunks(chunks), total)
    }

    fn frame(buf: DocBuf<'a>, total: usize) -> Result<Self, DcgError> {
        require!(total >= BODY_START, err::TRUNCATED);
        require!(buf.at(0, 4) == &MAGIC[..], err::BAD_MAGIC);
        require!(
            u16_at(buf.at(4, 2), 0) == GRAMMAR_VERSION,
            err::BAD_GRAMMAR_VERSION
        );
        require!(u16_at(buf.at(6, 2), 0) == 0, err::BAD_FLAGS);
        require!(
            u16_at(buf.at(8, 2), 0) as usize == CLAUSE_COUNT,
            err::BAD_CLAUSE_COUNT
        );
        require!(u16_at(buf.at(10, 2), 0) == 0, err::NONZERO_RESERVED);
        require!(
            u32_at(buf.at(12, 4), 0) as usize == total,
            err::BAD_TOTAL_BYTES
        );
        require!(all_zero(buf.at(48, 16)), err::NONZERO_RESERVED);

        let mut spans = [(0u32, 0u32); CLAUSE_COUNT];
        let mut cursor = BODY_START;
        for index in 0..CLAUSE_COUNT {
            let base = HEADER_BYTES + index * DIRECTORY_ENTRY_BYTES;
            require!(
                u16_at(buf.at(base, 2), 0) as usize == index + 1,
                err::CLAUSE_ORDER
            );
            require!(u16_at(buf.at(base + 2, 2), 0) == 0, err::NONZERO_RESERVED);
            let offset = u32_at(buf.at(base + 4, 4), 0) as usize;
            let length = u32_at(buf.at(base + 8, 4), 0) as usize;
            require!(offset == cursor, err::CLAUSE_LAYOUT);
            let end = offset
                .checked_add(length)
                .ok_or(DcgError(err::CLAUSE_LAYOUT))?;
            require!(end <= total, err::CLAUSE_LAYOUT);
            spans[index] = (offset as u32, length as u32);
            cursor = end;
        }
        require!(cursor == total, err::CLAUSE_LAYOUT);
        Ok(Self { buf, spans })
    }

    pub fn bytes(&self) -> &'a [u8] {
        match self.buf {
            DocBuf::Flat(buf) => buf,
            DocBuf::Chunks(_) => &[],
        }
    }

    pub fn grammar_version(&self) -> u16 {
        u16_at(self.buf.at(4, 2), 0)
    }

    pub fn container_flags(&self) -> u16 {
        u16_at(self.buf.at(6, 2), 0)
    }

    pub fn total_bytes(&self) -> u32 {
        u32_at(self.buf.at(12, 4), 0)
    }

    pub fn descriptor_id(&self) -> [u8; 32] {
        digest_at(self.buf.at(16, 32), 0)
    }

    pub fn clause(&self, clause_id: u16) -> &'a [u8] {
        let (offset, length) = self.spans[(clause_id - 1) as usize];
        self.buf.at(offset as usize, length as usize)
    }

    /// The offset of a clause body in the whole document.  R16 tests mutate a
    /// captured document row in place, so they need the clause's offset.
    pub fn clause_offset(&self, clause_id: u16) -> usize {
        self.spans[(clause_id - 1) as usize].0 as usize
    }

    // -- clause 1: machine ------------------------------------------------

    pub fn machine_root(&self) -> [u8; 32] {
        digest_at(self.clause(CLAUSE_MACHINE), 0)
    }

    pub fn machine_profile_digest(&self) -> [u8; 32] {
        digest_at(self.clause(CLAUSE_MACHINE), 32)
    }

    /// `machine.profile_form`: 0 = no profile bytes, 1 = the profile is
    /// carried in the entry's parameter block and its digest is recomputed
    /// from those bytes (brief §6 gate 5).
    pub fn machine_profile_form(&self) -> u16 {
        u16_at(self.clause(CLAUSE_MACHINE), 64 + MACHINE_NAME_BYTES)
    }

    pub fn machine_name(&self) -> &'a [u8] {
        let body = self.clause(CLAUSE_MACHINE);
        let field = &body[64..64 + MACHINE_NAME_BYTES];
        &field[..name_len(field)]
    }

    pub(crate) fn validate_machine(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_MACHINE);
        require!(body.len() == MACHINE_BYTES, err::CLAUSE_LENGTH);
        require!(
            name_is_valid(&body[64..64 + MACHINE_NAME_BYTES]),
            err::MACHINE_NAME
        );
        require!(u16_at(body, 128) <= 1, err::MACHINE_PROFILE_FORM);
        require!(all_zero(&body[130..136]), err::NONZERO_RESERVED);
        Ok(())
    }

    // -- clause 2: kernels ------------------------------------------------

    pub fn kernel_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_KERNELS), 0) as usize
    }

    pub fn mode_cost_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_KERNELS), 2) as usize
    }

    pub fn kernel(&self, index: usize) -> KernelRow {
        let body = self.clause(CLAUSE_KERNELS);
        let off = KERNELS_HEADER_BYTES + index * KERNEL_ROW_BYTES;
        KernelRow {
            kind: u16_at(body, off),
            form_id: u16_at(body, off + 2),
            read_route_min: u16_at(body, off + 4),
            read_route_max: u16_at(body, off + 6),
            write_route_min: u16_at(body, off + 8),
            write_route_max: u16_at(body, off + 10),
            operand_bound: u32_at(body, off + 12),
            cu_ceiling: u32_at(body, off + 16),
            heap_ceiling: u32_at(body, off + 20),
            placement_class: u8_at(body, off + 24),
            state_mode: u8_at(body, off + 25),
            provenance_class: u8_at(body, off + 26),
            consensus_form: u8_at(body, off + 27),
            consensus_steps: u16_at(body, off + 28),
            mode_support: u16_at(body, off + 30),
            read_lifetime_mask: u8_at(body, off + 32),
            write_lifetime_mask: u8_at(body, off + 33),
        }
    }

    /// (kernel_index, mode_id, cu_ceiling, heap_ceiling, dispute_headroom_bp)
    pub fn mode_cost(&self, index: usize) -> (u16, u16, u32, u32, u16) {
        let body = self.clause(CLAUSE_KERNELS);
        let off = KERNELS_HEADER_BYTES
            + self.kernel_count() * KERNEL_ROW_BYTES
            + index * MODE_COST_ROW_BYTES;
        (
            u16_at(body, off),
            u16_at(body, off + 2),
            u32_at(body, off + 4),
            u32_at(body, off + 8),
            u16_at(body, off + 12),
        )
    }

    pub(crate) fn validate_kernels(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_KERNELS);
        require!(body.len() >= KERNELS_HEADER_BYTES, err::CLAUSE_LENGTH);
        let count = u16_at(body, 0) as usize;
        let costs = u16_at(body, 2) as usize;
        require!(all_zero(&body[4..8]), err::NONZERO_RESERVED);
        require!(count >= 1 && count <= MAX_KERNELS, err::KERNEL_COUNT);
        require!(costs <= MAX_MODE_COST_ROWS, err::BAD_COUNT);
        require!(
            body.len()
                == KERNELS_HEADER_BYTES + count * KERNEL_ROW_BYTES + costs * MODE_COST_ROW_BYTES,
            err::CLAUSE_LENGTH
        );

        for index in 0..count {
            let off = KERNELS_HEADER_BYTES + index * KERNEL_ROW_BYTES;
            require!(all_zero(&body[off + 34..off + 48]), err::NONZERO_RESERVED);
            let row = self.kernel(index);
            if index > 0 {
                require!(row.kind > self.kernel(index - 1).kind, err::KERNEL_ORDER);
            }
            require!(
                row.read_route_min <= row.read_route_max,
                err::KERNEL_ROUTE_BOUNDS
            );
            require!(
                row.write_route_min <= row.write_route_max && row.write_route_max > 0,
                err::KERNEL_ROUTE_BOUNDS
            );
            require!(
                row.cu_ceiling > 0 && row.cu_ceiling <= CU_CEILING_MAX,
                err::KERNEL_CEILING
            );
            require!(
                row.placement_class <= KERNEL_PLACEMENT_MULTI_REGION,
                err::KERNEL_CLASS
            );
            require!(row.provenance_class <= PROVENANCE_MAX, err::KERNEL_CLASS);
            require!(
                row.consensus_form <= CONSENSUS_FORM_MULTI_STEP,
                err::KERNEL_CLASS
            );
            // Every kernel has a consensus form (§9 rule 1).
            let consensus =
                mode_support_bit(MODE_CONSENSUS).ok_or(DcgError(err::POLICY_UNKNOWN_MODE))?;
            require!(
                row.mode_support & consensus != 0,
                err::KERNEL_NO_CONSENSUS_FORM
            );
            require!(row.consensus_steps >= 1, err::KERNEL_CONSENSUS_STEPS);
            if row.consensus_form == CONSENSUS_FORM_SINGLE_TX {
                require!(row.consensus_steps == 1, err::KERNEL_CONSENSUS_STEPS);
            } else {
                require!(row.consensus_steps >= 2, err::KERNEL_CONSENSUS_STEPS);
            }
            require!(
                row.read_lifetime_mask >> (LIFETIME_MAX + 1) == 0,
                err::KERNEL_CLASS
            );
            require!(
                row.write_lifetime_mask >> (LIFETIME_MAX + 1) == 0,
                err::KERNEL_CLASS
            );
        }

        // Mode-cost rows: sorted, one per declared (kernel, mode) and no more.
        let mut previous: Option<(u16, u16)> = None;
        for index in 0..costs {
            let off = KERNELS_HEADER_BYTES + count * KERNEL_ROW_BYTES + index * MODE_COST_ROW_BYTES;
            require!(all_zero(&body[off + 14..off + 16]), err::NONZERO_RESERVED);
            let (kernel_index, mode_id, cu, _heap, headroom) = self.mode_cost(index);
            let key = (kernel_index, mode_id);
            if let Some(prior) = previous {
                require!(key > prior, err::KERNEL_MODE_COST_ORDER);
            }
            previous = Some(key);
            require!(
                (kernel_index as usize) < count,
                err::KERNEL_MODE_COST_UNDECLARED
            );
            let bit = mode_support_bit(mode_id).ok_or(DcgError(err::POLICY_UNKNOWN_MODE))?;
            require!(
                self.kernel(kernel_index as usize).mode_support & bit != 0,
                err::KERNEL_MODE_COST_UNDECLARED
            );
            require!(cu > 0 && cu <= CU_CEILING_MAX, err::KERNEL_CEILING);
            require!(headroom <= 10_000, err::KERNEL_CEILING);
        }
        for index in 0..count {
            let support = self.kernel(index).mode_support;
            for mode_id in 1..=MAX_MODE_REGISTRANTS as u16 {
                let bit = 1u16 << (mode_id - 1);
                if support & bit == 0 {
                    continue;
                }
                let mut found = false;
                for cost in 0..costs {
                    let (kernel_index, cost_mode, _, _, _) = self.mode_cost(cost);
                    if kernel_index as usize == index && cost_mode == mode_id {
                        found = true;
                        break;
                    }
                }
                require!(found, err::KERNEL_MODE_COST_MISSING);
            }
        }
        Ok(())
    }

    // -- clause 3: regions ------------------------------------------------

    pub fn region_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_REGIONS), 0) as usize
    }

    pub fn region(&self, index: usize) -> RegionRow {
        let body = self.clause(CLAUSE_REGIONS);
        let off = REGIONS_HEADER_BYTES + index * REGION_ROW_BYTES;
        RegionRow {
            region_id: u16_at(body, off),
            encoding: u16_at(body, off + 2),
            lifetime: u8_at(body, off + 4),
            flags: u8_at(body, off + 5),
            scale_region: u16_at(body, off + 6),
            byte_length: u64_at(body, off + 8),
            element_stride: u32_at(body, off + 16),
            placement_ref: u16_at(body, off + 20),
            initial_content: digest_at(body, off + 24),
            init_kind: u8_at(body, off + 56),
        }
    }

    pub fn region_by_id(&self, region_id: u16) -> Option<RegionRow> {
        // Region ids ascend, so this is a binary search.
        let mut low = 0usize;
        let mut high = self.region_count();
        while low < high {
            let mid = (low + high) / 2;
            let row = self.region(mid);
            if row.region_id == region_id {
                return Some(row);
            } else if row.region_id < region_id {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        None
    }

    pub(crate) fn validate_regions(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_REGIONS);
        require!(body.len() >= REGIONS_HEADER_BYTES, err::CLAUSE_LENGTH);
        let count = u16_at(body, 0) as usize;
        require!(all_zero(&body[2..8]), err::NONZERO_RESERVED);
        require!(count >= 1 && count <= MAX_REGIONS, err::BAD_COUNT);
        require!(
            body.len() == REGIONS_HEADER_BYTES + count * REGION_ROW_BYTES,
            err::CLAUSE_LENGTH
        );
        let generators = self.generator_count();
        for index in 0..count {
            let off = REGIONS_HEADER_BYTES + index * REGION_ROW_BYTES;
            require!(all_zero(&body[off + 22..off + 24]), err::NONZERO_RESERVED);
            require!(all_zero(&body[off + 57..off + 64]), err::NONZERO_RESERVED);
            let row = self.region(index);
            if index > 0 {
                require!(
                    row.region_id > self.region(index - 1).region_id,
                    err::REGION_ORDER
                );
            }
            require!(
                row.byte_length > 0 && row.byte_length <= MAX_REGION_BYTES,
                err::REGION_LENGTH
            );
            require!(row.lifetime <= LIFETIME_MAX, err::REGION_LIFETIME);
            require!(row.encoding <= ENCODING_MAX, err::REGION_ENCODING);
            require!(row.flags >> 2 == 0, err::REGION_ENCODING);
            if row.encoding == ENCODING_Q8_SCALED {
                // The scale region must be declared earlier, so the reference
                // resolves without a second pass.
                require!(row.scale_region != NO_SCALE_REGION, err::REGION_SCALE);
                let mut found = false;
                for prior in 0..index {
                    if self.region(prior).region_id == row.scale_region {
                        found = true;
                        break;
                    }
                }
                require!(found, err::REGION_SCALE);
            } else {
                require!(row.scale_region == NO_SCALE_REGION, err::REGION_SCALE);
            }
            require!(row.element_stride > 0, err::REGION_LENGTH);
            require!(
                row.byte_length % row.element_stride as u64 == 0,
                err::REGION_LENGTH
            );
            require!(row.init_kind <= INIT_EXTERNAL_DIGEST, err::REGION_INIT_KIND);
            let sealed = matches!(row.init_kind, INIT_DIGEST_SEALED | INIT_EXTERNAL_DIGEST);
            require!(
                sealed != (row.initial_content == ZERO32),
                err::REGION_INIT_KIND
            );
            require!(
                (row.placement_ref as usize) < generators,
                err::REGION_PLACEMENT_REF
            );
            require!(
                self.generator(row.placement_ref as usize).region_id == row.region_id,
                err::REGION_PLACEMENT_REF
            );
        }
        Ok(())
    }

    // -- clause 4: placement ----------------------------------------------

    pub fn generator_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_PLACEMENT), 0) as usize
    }

    pub fn slice_count(&self) -> usize {
        u32_at(self.clause(CLAUSE_PLACEMENT), 4) as usize
    }

    pub fn generator(&self, index: usize) -> GeneratorRow {
        let body = self.clause(CLAUSE_PLACEMENT);
        let off = PLACEMENT_HEADER_BYTES + index * GENERATOR_ROW_BYTES;
        let params = off + 8;
        GeneratorRow {
            generator_id: u16_at(body, off),
            form: u16_at(body, off + 2),
            region_id: u16_at(body, off + 4),
            account_kind: u16_at(body, off + 6),
            grid_base: u32_at(body, params),
            page_count: u32_at(body, params + 4),
            shard_count: u32_at(body, params + 8),
            page_stride: u32_at(body, params + 12),
            shard_stride: u32_at(body, params + 16),
            slice_length: u32_at(body, params + 20),
            slice_offset: u64_at(body, params + 24),
            first_slice: u32_at(body, params),
            slice_count: u32_at(body, params + 4),
        }
    }

    pub fn slice(&self, index: usize) -> SliceRow {
        let body = self.clause(CLAUSE_PLACEMENT);
        let off = PLACEMENT_HEADER_BYTES
            + self.generator_count() * GENERATOR_ROW_BYTES
            + index * EXPLICIT_SLICE_ROW_BYTES;
        SliceRow {
            slice_index: u32_at(body, off),
            account_ordinal: u32_at(body, off + 4),
            account_offset: u64_at(body, off + 8),
            region_offset: u64_at(body, off + 16),
            byte_length: u32_at(body, off + 24),
            flags: u32_at(body, off + 28),
        }
    }

    /// Framing only.  Runs before `validate_regions`, which resolves
    /// `placement_ref` into this clause's rows.
    pub(crate) fn validate_placement_framing(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_PLACEMENT);
        require!(body.len() >= PLACEMENT_HEADER_BYTES, err::CLAUSE_LENGTH);
        let count = u16_at(body, 0) as usize;
        require!(all_zero(&body[2..4]), err::NONZERO_RESERVED);
        let slices = u32_at(body, 4) as usize;
        require!(all_zero(&body[8..12]), err::NONZERO_RESERVED);
        require!(count >= 1 && count <= MAX_GENERATORS, err::BAD_COUNT);
        require!(slices <= MAX_EXPLICIT_SLICES, err::BAD_COUNT);
        require!(
            body.len()
                == PLACEMENT_HEADER_BYTES
                    + count * GENERATOR_ROW_BYTES
                    + slices * EXPLICIT_SLICE_ROW_BYTES,
            err::CLAUSE_LENGTH
        );
        let slice_base = PLACEMENT_HEADER_BYTES + count * GENERATOR_ROW_BYTES;
        for index in 0..slices {
            let off = slice_base + index * EXPLICIT_SLICE_ROW_BYTES;
            require!(all_zero(&body[off + 32..off + 48]), err::NONZERO_RESERVED);
        }
        Ok(())
    }

    /// R16: the per-item half of `validate_placement`, over the explicit slice
    /// rows `[start, start+count)`.  Every check that reads only the slice rows
    /// and the generator table lives here, so a `SealStep` can run it per item
    /// and a large placement no longer has to be validated in one instruction.
    ///
    /// The running coverage of clause 4 is checked against the PRECEDING slice
    /// row in the same generator rather than an accumulator carried in `BDS2`:
    /// the descriptor bytes are committed by chunk address and never change
    /// between steps, so the sealed prefix is the same immutable row.  The
    /// cross-generator passes stay in [`validate_placement_global`].
    pub(crate) fn validate_placement_slices(&self, start: u32, count: u32) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_PLACEMENT);
        let generators = self.generator_count();
        let slices = self.slice_count();
        let end = start as usize + count as usize;
        for index in start as usize..end {
            if index >= slices {
                return Err(DcgError(err::PLACEMENT_SLICE_RANGE));
            }
            let off = PLACEMENT_HEADER_BYTES
                + generators * GENERATOR_ROW_BYTES
                + index * EXPLICIT_SLICE_ROW_BYTES;
            require!(all_zero(&body[off + 32..off + 48]), err::NONZERO_RESERVED);
            let slice = self.slice(index);
            require!(
                slice.slice_index as usize == index,
                err::PLACEMENT_SLICE_ORDER
            );
            require!(slice.flags == 0, err::PLACEMENT_PARAMS);
            require!(slice.byte_length > 0, err::PLACEMENT_PARAMS);
            require!(
                slice
                    .account_offset
                    .checked_add(slice.byte_length as u64)
                    .map_or(false, |end| end <= MAX_ACCOUNT_BYTES),
                err::PLACEMENT_ACCOUNT_TOO_LARGE
            );

            // Every explicit slice belongs to exactly one generator.
            let mut owners = 0usize;
            let mut owner = 0usize;
            for generator_index in 0..generators {
                let row = self.generator(generator_index);
                if row.form != PLACEMENT_EXPLICIT {
                    continue;
                }
                let first = row.first_slice as usize;
                if index >= first && index < first + row.slice_count as usize {
                    owners += 1;
                    owner = generator_index;
                }
            }
            require!(owners == 1, err::PLACEMENT_SLICE_RANGE);

            let row = self.generator(owner);
            if index == row.first_slice as usize {
                require!(slice.region_offset == 0, err::PLACEMENT_COVERAGE);
            } else {
                let previous = self.slice(index - 1);
                let ordered = slice.account_ordinal > previous.account_ordinal
                    || (slice.account_ordinal == previous.account_ordinal
                        && slice.account_offset >= previous.account_offset);
                require!(ordered, err::PLACEMENT_SLICE_UNSORTED);
                if slice.account_ordinal == previous.account_ordinal {
                    let previous_end = previous
                        .account_offset
                        .checked_add(previous.byte_length as u64)
                        .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
                    require!(
                        slice.account_offset >= previous_end,
                        err::PLACEMENT_ACCOUNT_OVERLAP
                    );
                }
                let expected = previous
                    .region_offset
                    .checked_add(previous.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_COVERAGE))?;
                require!(slice.region_offset == expected, err::PLACEMENT_COVERAGE);
            }
            require!(
                self.has_predecessor(slice.account_ordinal, slice.account_offset),
                err::PLACEMENT_ACCOUNT_HOLE
            );
        }
        Ok(())
    }

    /// R16: the cross-generator half of `validate_placement`, unchanged in its
    /// rules but no longer re-scanning every slice row: generator semantics,
    /// account kinds, generator-pair disjointness, window coverage.
    pub(crate) fn validate_placement_global(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_PLACEMENT);
        let slices = self.slice_count();
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            require!(row.generator_id as usize == index, err::PLACEMENT_ORDER);
            require!(
                row.form == PLACEMENT_GRID || row.form == PLACEMENT_EXPLICIT,
                err::PLACEMENT_FORM
            );
            let region = self
                .region_by_id(row.region_id)
                .ok_or(DcgError(err::PLACEMENT_REGION))?;
            if row.form == PLACEMENT_GRID {
                require!(
                    row.page_count > 0 && row.shard_count > 0 && row.slice_length > 0,
                    err::PLACEMENT_PARAMS
                );
                let cells = (row.page_count as u64)
                    .checked_mul(row.shard_count as u64)
                    .ok_or(DcgError(err::PLACEMENT_PARAMS))?;
                let covered = cells
                    .checked_mul(row.slice_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_PARAMS))?;
                require!(covered == region.byte_length, err::PLACEMENT_COVERAGE);
                if row.shard_count > 1 {
                    require!(row.shard_stride > 0, err::PLACEMENT_CELL_COLLISION);
                }
                if row.page_count > 1 {
                    require!(row.page_stride > 0, err::PLACEMENT_CELL_COLLISION);
                }
                if row.page_count > 1 && row.shard_count > 1 {
                    let span = (row.shard_count as u64) * (row.shard_stride as u64);
                    require!(
                        row.page_stride as u64 >= span,
                        err::PLACEMENT_CELL_COLLISION
                    );
                }
                let highest = (row.grid_base as u64)
                    + (row.page_count as u64 - 1) * row.page_stride as u64
                    + (row.shard_count as u64 - 1) * row.shard_stride as u64;
                require!(highest <= u32::MAX as u64, err::PLACEMENT_PARAMS);
                require!(
                    (row.slice_offset)
                        .checked_add(row.slice_length as u64)
                        .map_or(false, |end| end <= MAX_ACCOUNT_BYTES),
                    err::PLACEMENT_ACCOUNT_TOO_LARGE
                );
            } else {
                let params_off = PLACEMENT_HEADER_BYTES + index * GENERATOR_ROW_BYTES + 8;
                require!(
                    all_zero(&body[params_off + 8..params_off + 32]),
                    err::NONZERO_RESERVED
                );
                require!(row.slice_count > 0, err::PLACEMENT_PARAMS);
                let end = (row.first_slice as u64) + (row.slice_count as u64);
                require!(end <= slices as u64, err::PLACEMENT_SLICE_RANGE);
                // Coverage of the generator's own tiling: the last slice of its
                // contiguous run ends exactly at the region length.  The rows
                // themselves were checked in `validate_placement_slices`.
                let last = self.slice(row.first_slice as usize + row.slice_count as usize - 1);
                let last_end = last
                    .region_offset
                    .checked_add(last.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_COVERAGE))?;
                require!(last_end == region.byte_length, err::PLACEMENT_COVERAGE);
            }
        }

        self.validate_account_kinds()?;
        self.validate_placement_disjointness()?;
        self.validate_account_coverage()
    }

    /// Every rule, composed so `validate()` and the incremental seal run the
    /// same code: the per-slice half, then the cross-generator half.
    pub(crate) fn validate_placement(&self) -> Result<(), DcgError> {
        self.validate_placement_slices(0, self.slice_count() as u32)?;
        self.validate_placement_global()
    }

    fn generator_contains(&self, row: &GeneratorRow, ordinal: u32) -> bool {
        if row.form == PLACEMENT_GRID {
            return Self::grid_contains(row, ordinal);
        }
        let mut lo = row.first_slice as usize;
        let end = lo + row.slice_count as usize;
        let mut hi = end;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slice(mid).account_ordinal < ordinal {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo < end && self.slice(lo).account_ordinal == ordinal
    }

    fn has_predecessor(&self, ordinal: u32, start: u64) -> bool {
        if start == 0 {
            return true;
        }
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            if row.form == PLACEMENT_GRID {
                if Self::grid_contains(&row, ordinal)
                    && row.slice_offset + row.slice_length as u64 == start
                {
                    return true;
                }
            } else {
                let first = row.first_slice as usize;
                let mut lo = first;
                let mut hi = first + row.slice_count as usize;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    let slice = self.slice(mid);
                    if (slice.account_ordinal, slice.account_offset) < (ordinal, start) {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                if lo > first {
                    let slice = self.slice(lo - 1);
                    if slice.account_ordinal == ordinal
                        && slice.account_offset + slice.byte_length as u64 == start
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn generator_cell_count(row: &GeneratorRow) -> u64 {
        if row.form == PLACEMENT_GRID {
            row.page_count as u64 * row.shard_count as u64
        } else {
            row.slice_count as u64
        }
    }

    fn generator_ordinal(&self, row: &GeneratorRow, cell: u64) -> u32 {
        if row.form == PLACEMENT_GRID {
            Self::grid_cell_ordinal(row, cell)
        } else {
            self.slice(row.first_slice as usize + cell as usize)
                .account_ordinal
        }
    }

    fn validate_account_coverage(&self) -> Result<(), DcgError> {
        for left in 0..self.generator_count() {
            let row = self.generator(left);
            if matches!(
                row.account_kind,
                ACCOUNT_KIND_SUPPLY_WINDOW | ACCOUNT_KIND_SHARED_WINDOW
            ) {
                let (lo, hi) = self.ordinal_extent(&row);
                for right in left + 1..self.generator_count() {
                    let other = self.generator(right);
                    let (other_lo, other_hi) = self.ordinal_extent(&other);
                    if row.region_id == other.region_id || hi < other_lo || other_hi < lo {
                        continue;
                    }
                    let (small, large) =
                        if Self::generator_cell_count(&row) <= Self::generator_cell_count(&other) {
                            (&row, &other)
                        } else {
                            (&other, &row)
                        };
                    for cell in 0..Self::generator_cell_count(small) {
                        require!(
                            !self.generator_contains(large, self.generator_ordinal(small, cell)),
                            err::PLACEMENT_WINDOW_REGION
                        );
                    }
                }
            }
            if row.form == PLACEMENT_GRID {
                if row.slice_offset == 0 {
                    continue;
                }
                let mut same_grid_predecessor = false;
                for index in 0..self.generator_count() {
                    let other = self.generator(index);
                    if other.form == PLACEMENT_GRID
                        && other.grid_base == row.grid_base
                        && other.page_count == row.page_count
                        && other.shard_count == row.shard_count
                        && other.page_stride == row.page_stride
                        && other.shard_stride == row.shard_stride
                        && other.slice_offset + other.slice_length as u64 == row.slice_offset
                    {
                        same_grid_predecessor = true;
                        break;
                    }
                }
                if same_grid_predecessor {
                    continue;
                }
                for cell in 0..Self::generator_cell_count(&row) {
                    require!(
                        self.has_predecessor(Self::grid_cell_ordinal(&row, cell), row.slice_offset),
                        err::PLACEMENT_ACCOUNT_HOLE
                    );
                }
            }
            // R16: an explicit generator's per-slice predecessor holes are
            // checked in `validate_placement_slices`, per item, by the seal.
        }
        Ok(())
    }

    /// Every generator declares a registered `account_kind` admissible for its
    /// region's lifetime (step 3, spec §15).
    fn validate_account_kinds(&self) -> Result<(), DcgError> {
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            require!(
                row.account_kind <= ACCOUNT_KIND_MAX,
                err::PLACEMENT_ACCOUNT_KIND
            );
            let region = self
                .region_by_id(row.region_id)
                .ok_or(DcgError(err::PLACEMENT_REGION))?;
            require!(
                account_kind_admits_lifetime(row.account_kind, region.lifetime),
                err::PLACEMENT_KIND_LIFETIME
            );
        }
        Ok(())
    }

    /// Whether `ordinal` is one of a `grid` generator's account ordinals.
    /// O(1): `validate_placement` has already refused a degenerate or folding
    /// stride, so the decomposition into `(page, shard)` is unique.
    pub(crate) fn grid_contains(row: &GeneratorRow, ordinal: u32) -> bool {
        if ordinal < row.grid_base {
            return false;
        }
        let mut rest = (ordinal - row.grid_base) as u64;
        if row.page_count > 1 {
            let page = rest / row.page_stride as u64;
            if page >= row.page_count as u64 {
                return false;
            }
            rest %= row.page_stride as u64;
        }
        if row.shard_count > 1 {
            if rest % row.shard_stride as u64 != 0 {
                return false;
            }
            if rest / row.shard_stride as u64 >= row.shard_count as u64 {
                return false;
            }
        } else if rest != 0 {
            return false;
        }
        true
    }

    fn grid_cell_ordinal(row: &GeneratorRow, cell: u64) -> u32 {
        let page = cell / row.shard_count as u64;
        let shard = cell % row.shard_count as u64;
        (row.grid_base as u64 + page * row.page_stride as u64 + shard * row.shard_stride as u64)
            as u32
    }

    /// `(ordinal_lo, ordinal_hi)`.  O(1) for a grid; for an explicit
    /// generator the slice rows are sorted by `(ordinal, offset)` by the time
    /// this runs, so it is the first and last row.
    fn ordinal_extent(&self, row: &GeneratorRow) -> (u32, u32) {
        if row.form == PLACEMENT_GRID {
            (
                row.grid_base,
                (row.grid_base as u64
                    + (row.page_count as u64 - 1) * row.page_stride as u64
                    + (row.shard_count as u64 - 1) * row.shard_stride as u64)
                    as u32,
            )
        } else {
            let first = self.slice(row.first_slice as usize);
            let last = self.slice(row.first_slice as usize + row.slice_count as usize - 1);
            (first.account_ordinal, last.account_ordinal)
        }
    }

    /// `(byte_lo, byte_hi)` over the generator's cells.
    ///
    /// B1 (steps 1-3 review): every add here is CHECKED and an overflow is a
    /// refusal, not a wrap.  `validate_placement` bounds both offsets at parse
    /// so this cannot fire on a validated document; it is kept because the
    /// deployed profile disables overflow checks and this function is reached
    /// from `validate` itself, before those bounds have all run.
    fn byte_extent(&self, row: &GeneratorRow) -> Result<(u64, u64), DcgError> {
        if row.form == PLACEMENT_GRID {
            let hi = row
                .slice_offset
                .checked_add(row.slice_length as u64)
                .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
            Ok((row.slice_offset, hi))
        } else {
            let mut lo = u64::MAX;
            let mut hi = 0u64;
            for index in
                row.first_slice as usize..row.first_slice as usize + row.slice_count as usize
            {
                let slice = self.slice(index);
                if slice.account_offset < lo {
                    lo = slice.account_offset;
                }
                let end = slice
                    .account_offset
                    .checked_add(slice.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
                if end > hi {
                    hi = end;
                }
            }
            Ok((lo, hi))
        }
    }

    /// Two regions must never claim the same account bytes, at ANY document
    /// size.  Step 1's pairwise scan over materialized cells is gone; this is
    /// structural, allocation-free, and enumerates no grid cell:
    ///
    /// * within one `grid`, every cell has the SAME account byte span and a
    ///   DISTINCT ordinal (the stride rules `validate_placement` enforces), so
    ///   a grid can never overlap itself at any cell count;
    /// * within one `explicit` generator the slice rows must be sorted by
    ///   `(account_ordinal, account_offset)` and one adjacent-overlap pass
    ///   settles it, O(slices);
    /// * a pair of generators is settled in O(1) by the ordinal-range test
    ///   unless BOTH the ordinals and the byte spans overlap, and only then is
    ///   anything enumerated -- the explicit side exactly, the grid side by
    ///   `grid_contains`.
    ///
    /// The ordering requirement costs a document nothing: an account ordinal
    /// is an internal name that `provision` binds to an address, so any
    /// document can be renumbered into the canonical order unchanged.
    fn validate_placement_disjointness(&self) -> Result<(), DcgError> {
        let count = self.generator_count();

        // An account's body is the highest cell end at its ordinal, so it is
        // the largest `byte_hi` of some generator touching it: bounding every
        // generator's envelope bounds every account, in O(generators).
        let mut enumerated: u64 = 0;
        for index in 0..count {
            let row = self.generator(index);
            let (_lo, hi) = self.byte_extent(&row)?;
            require!(
                hi.checked_add(account_kind_tail_bytes(row.account_kind))
                    .map_or(false, |end| end <= MAX_ACCOUNT_BYTES),
                err::PLACEMENT_ACCOUNT_TOO_LARGE
            );
            if row.form != PLACEMENT_EXPLICIT {
                continue;
            }
            enumerated = enumerated
                .checked_add(row.slice_count as u64)
                .ok_or(DcgError(err::PLACEMENT_TOO_MANY_CELLS))?;
            require!(
                enumerated <= MAX_PLACEMENT_CELLS,
                err::PLACEMENT_TOO_MANY_CELLS
            );
            // R16: the within-generator sortedness/overlap pass over this
            // generator's slice rows is `validate_placement_slices`, run per
            // item by the seal; it is not repeated here.
        }

        for left in 0..count {
            for right in left + 1..count {
                self.validate_generator_pair(left, right)?;
            }
        }
        Ok(())
    }

    pub(crate) fn validate_generator_pair(
        &self,
        left: usize,
        right: usize,
    ) -> Result<(), DcgError> {
        let l = self.generator(left);
        let r = self.generator(right);
        let (l_ord_lo, l_ord_hi) = self.ordinal_extent(&l);
        let (r_ord_lo, r_ord_hi) = self.ordinal_extent(&r);
        if l_ord_hi < r_ord_lo || r_ord_hi < l_ord_lo {
            return Ok(()); // disjoint ordinal ranges: no shared account at all
        }
        // One physical account has ONE class, so two generators whose ordinal
        // ranges interleave must agree about it.
        require!(
            l.account_kind == r.account_kind,
            err::PLACEMENT_KIND_CONFLICT
        );
        let (l_byte_lo, l_byte_hi) = self.byte_extent(&l)?;
        let (r_byte_lo, r_byte_hi) = self.byte_extent(&r)?;
        if l_byte_hi <= r_byte_lo || r_byte_hi <= l_byte_lo {
            return Ok(()); // disjoint account byte spans: sharing is fine
        }

        if l.form == PLACEMENT_GRID && r.form == PLACEMENT_GRID {
            let l_cells = (l.page_count as u64) * (l.shard_count as u64);
            let r_cells = (r.page_count as u64) * (r.shard_count as u64);
            let (small, large, cells) = if l_cells <= r_cells {
                (&l, &r, l_cells)
            } else {
                (&r, &l, r_cells)
            };
            require!(
                cells <= MAX_GRID_PAIR_CELLS,
                err::PLACEMENT_ORDINAL_AMBIGUOUS
            );
            for cell in 0..cells {
                let ordinal = Self::grid_cell_ordinal(small, cell);
                if Self::grid_contains(large, ordinal) {
                    refuse!(err::PLACEMENT_ACCOUNT_OVERLAP);
                }
            }
            return Ok(());
        }

        if l.form == PLACEMENT_GRID || r.form == PLACEMENT_GRID {
            let (grid, table) = if l.form == PLACEMENT_GRID {
                (&l, &r)
            } else {
                (&r, &l)
            };
            let lo = grid.slice_offset;
            let hi = grid
                .slice_offset
                .checked_add(grid.slice_length as u64)
                .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
            for index in
                table.first_slice as usize..table.first_slice as usize + table.slice_count as usize
            {
                let slice = self.slice(index);
                let end = slice
                    .account_offset
                    .checked_add(slice.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
                if slice.account_offset < hi
                    && lo < end
                    && Self::grid_contains(grid, slice.account_ordinal)
                {
                    refuse!(err::PLACEMENT_ACCOUNT_OVERLAP);
                }
            }
            return Ok(());
        }

        // Both explicit, each side already sorted by (ordinal, offset): one
        // merge, O(left + right), two cursors and no allocation.
        let mut i = l.first_slice as usize;
        let mut j = r.first_slice as usize;
        let i_end = i + l.slice_count as usize;
        let j_end = j + r.slice_count as usize;
        while i < i_end && j < j_end {
            let a = self.slice(i);
            let b = self.slice(j);
            if a.account_ordinal < b.account_ordinal {
                i += 1;
            } else if b.account_ordinal < a.account_ordinal {
                j += 1;
            } else {
                let a_end = a
                    .account_offset
                    .checked_add(a.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
                let b_end = b
                    .account_offset
                    .checked_add(b.byte_length as u64)
                    .ok_or(DcgError(err::PLACEMENT_ACCOUNT_TOO_LARGE))?;
                if a.account_offset < b_end && b.account_offset < a_end {
                    refuse!(err::PLACEMENT_ACCOUNT_OVERLAP);
                }
                if a.account_offset < b.account_offset {
                    i += 1;
                } else {
                    j += 1;
                }
            }
        }
        Ok(())
    }

    /// The body an account of this ordinal must have: the highest placement
    /// cell end at that ordinal, or `None` when no cell names it.  Its class
    /// and the region that reaches furthest into it come back with it, so
    /// `provision` can add the class tail and resolve a shared window's owner.
    pub fn account_body(&self, ordinal: u32) -> Option<(u64, u16, u16)> {
        let mut body: Option<(u64, u16, u16)> = None;
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            let end = if row.form == PLACEMENT_GRID {
                if !Self::grid_contains(&row, ordinal) {
                    continue;
                }
                row.slice_offset.checked_add(row.slice_length as u64)?
            } else {
                let mut hit: Option<u64> = None;
                for index in
                    row.first_slice as usize..row.first_slice as usize + row.slice_count as usize
                {
                    let slice = self.slice(index);
                    if slice.account_ordinal == ordinal {
                        let end = slice.account_offset.checked_add(slice.byte_length as u64)?;
                        hit = Some(hit.map_or(end, |current: u64| current.max(end)));
                    }
                }
                match hit {
                    Some(end) => end,
                    None => continue,
                }
            };
            body = Some(match body {
                Some((current, kind, region)) if current >= end => (current, kind, region),
                _ => (end, row.account_kind, row.region_id),
            });
        }
        body
    }

    /// [`account_body`] for every ordinal in `ordinals` (strictly ascending),
    /// resolved in ONE pass over the placement instead of one scan per
    /// ordinal.  DCG step 5.5: `Execute` names up to
    /// `MAX_EXEC_ACCOUNTS` ordinals and resolves each twice (address binding
    /// and shared-window admission), so a single scan is the difference
    /// between fitting and not fitting the 1,240,000-CU tile ceiling.
    ///
    /// The verdict for each ordinal is exactly `account_body`'s: the highest
    /// matching cell end wins, the earliest generator wins a tie, any
    /// non-grid form is treated as explicit, and a cell end that overflows
    /// yields `None` for that ordinal.
    pub fn account_facts(&self, ordinals: &[u32], out: &mut [Option<AccountFacts>]) {
        debug_assert_eq!(ordinals.len(), out.len());
        // A cell end that overflows `checked_add` poisons its ordinal to
        // `None`, exactly as `account_body`'s `?` does.  `u64::MAX` is a
        // sentinel no real account body (an offset plus a u32 length) can
        // take, so it marks "poisoned" without a second array.
        const POISON: AccountFacts = AccountFacts {
            body: u64::MAX,
            account_kind: 0,
            region_id: 0,
        };
        for slot in out.iter_mut() {
            *slot = None;
        }
        let generators = self.generator_count();
        for index in 0..generators {
            let row = self.generator(index);
            if row.form == PLACEMENT_GRID {
                for (slot, ordinal) in ordinals.iter().enumerate() {
                    if is_poisoned(out, slot) || !Self::grid_contains(&row, *ordinal) {
                        continue;
                    }
                    match row.slice_offset.checked_add(row.slice_length as u64) {
                        Some(end) => {
                            consider_facts(out, slot, end, row.account_kind, row.region_id)
                        }
                        None => out[slot] = Some(POISON),
                    }
                }
            } else {
                let first = row.first_slice as usize;
                let count = row.slice_count as usize;
                for slice_index in first..first + count {
                    let slice = self.slice(slice_index);
                    if let Ok(slot) = ordinals.binary_search(&slice.account_ordinal) {
                        if is_poisoned(out, slot) {
                            continue;
                        }
                        match slice.account_offset.checked_add(slice.byte_length as u64) {
                            Some(end) => {
                                consider_facts(out, slot, end, row.account_kind, row.region_id)
                            }
                            None => out[slot] = Some(POISON),
                        }
                    }
                }
            }
        }
        for slot in out.iter_mut() {
            if slot.map_or(false, |known| known.body == u64::MAX) {
                *slot = None;
            }
        }
    }

    /// The `init_kind` every region placed in this account declares, when
    /// they all agree; `None` when the ordinal is unplaced or they disagree.
    pub fn account_init_kind(&self, ordinal: u32) -> Option<u8> {
        let mut out: Option<u8> = None;
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            let touches = if row.form == PLACEMENT_GRID {
                Self::grid_contains(&row, ordinal)
            } else {
                let mut hit = false;
                for index in
                    row.first_slice as usize..row.first_slice as usize + row.slice_count as usize
                {
                    if self.slice(index).account_ordinal == ordinal {
                        hit = true;
                        break;
                    }
                }
                hit
            };
            if !touches {
                continue;
            }
            let region = self.region_by_id(row.region_id)?;
            match out {
                None => out = Some(region.init_kind),
                Some(current) if current == region.init_kind => {}
                Some(_) => return None,
            }
        }
        out
    }

    /// [`account_init_kind`] for every ordinal in `ordinals` (strictly
    /// ascending), resolved in one placement pass. `None` has the same
    /// meaning as the scalar method: the ordinal is unplaced, a placement
    /// names an unknown region, or touching regions disagree about
    /// `init_kind`.
    pub fn account_init_kinds(&self, ordinals: &[u32], out: &mut [Option<u8>]) {
        debug_assert_eq!(ordinals.len(), out.len());
        const POISON: u8 = u8::MAX;
        for slot in out.iter_mut() {
            *slot = None;
        }
        for index in 0..self.generator_count() {
            let row = self.generator(index);
            let init_kind = match self.region_by_id(row.region_id) {
                Some(region) => region.init_kind,
                None => {
                    for (slot, ordinal) in ordinals.iter().enumerate() {
                        let touches = if row.form == PLACEMENT_GRID {
                            Self::grid_contains(&row, *ordinal)
                        } else {
                            (row.first_slice as usize
                                ..row.first_slice as usize + row.slice_count as usize)
                                .any(|slice_index| {
                                    self.slice(slice_index).account_ordinal == *ordinal
                                })
                        };
                        if touches {
                            out[slot] = Some(POISON);
                        }
                    }
                    continue;
                }
            };
            if row.form == PLACEMENT_GRID {
                for (slot, ordinal) in ordinals.iter().enumerate() {
                    if out[slot] == Some(POISON) || !Self::grid_contains(&row, *ordinal) {
                        continue;
                    }
                    match out[slot] {
                        None => out[slot] = Some(init_kind),
                        Some(current) if current == init_kind => {}
                        Some(_) => out[slot] = Some(POISON),
                    }
                }
            } else {
                for slice_index in
                    row.first_slice as usize..row.first_slice as usize + row.slice_count as usize
                {
                    let slice = self.slice(slice_index);
                    if let Ok(slot) = ordinals.binary_search(&slice.account_ordinal) {
                        if out[slot] == Some(POISON) {
                            continue;
                        }
                        match out[slot] {
                            None => out[slot] = Some(init_kind),
                            Some(current) if current == init_kind => {}
                            Some(_) => out[slot] = Some(POISON),
                        }
                    }
                }
            }
        }
        for slot in out.iter_mut() {
            if *slot == Some(POISON) {
                *slot = None;
            }
        }
    }

    /// The half-open placement-cell range a byte range of a region touches.
    /// `None` when the range touches no cell at all.
    fn cell_span(&self, region: &RegionRow, offset: u64, length: u64) -> Option<(u64, u64)> {
        let row = self.generator(region.placement_ref as usize);
        if row.form == PLACEMENT_GRID {
            let cell = row.slice_length as u64;
            Some((offset / cell, (offset + length - 1) / cell))
        } else {
            // An explicit generator's slices cover its region CONTIGUOUSLY and
            // in ascending region order -- `validate_placement` requires
            // `region_offset == covered` of every slice in turn -- so the
            // cells a byte range touches are a contiguous index run and each
            // end is a binary search. The linear scan this replaces was
            // O(slices) per route record, which at 82 slices a region and
            // eight routes an entry is what made an on-chain `validate` of a
            // 166-entry document exhaust a 1,399,850-CU meter (*measured*,
            // DCG step 4a). The answer is identical: same slices, same rule.
            let first = row.first_slice as usize;
            let count = row.slice_count as usize;
            let end = offset.checked_add(length)?;
            let locate = |target: u64| -> Option<usize> {
                let mut lo = 0usize;
                let mut hi = count;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    let slice = self.slice(first + mid);
                    if target < slice.region_offset {
                        hi = mid;
                    } else if target >= slice.region_offset + slice.byte_length as u64 {
                        lo = mid + 1;
                    } else {
                        return Some(first + mid);
                    }
                }
                None
            };
            let low = locate(offset)?;
            // `end` is exclusive, so the last touched byte is `end - 1`; a
            // zero-length range touches no cell and `length == 0` never
            // reaches here (every caller bounds it above zero).
            let high = locate(end.checked_sub(1)?)?;
            Some((low as u64, high as u64))
        }
    }

    // -- clause 5: routes -------------------------------------------------

    pub fn entry_count(&self) -> usize {
        let (offset, _) = self.spans[(CLAUSE_ROUTES - 1) as usize];
        u32_at(self.buf.at(offset as usize, 4), 0) as usize
    }

    pub fn route_record_count(&self) -> usize {
        u32_at(self.clause(CLAUSE_ROUTES), 4) as usize
    }

    pub fn route_root(&self) -> [u8; 32] {
        digest_at(self.clause(CLAUSE_ROUTES), 8)
    }

    /// Clause-6 wave rows.  R16: the stage-3 item stream is the waves then the
    /// edges, so a step can validate schedule rows per item.
    pub fn wave_count(&self) -> usize {
        u32_at(self.clause(CLAUSE_SCHEDULE), 0) as usize
    }

    /// Clause-6 edge rows.
    pub fn edge_count(&self) -> usize {
        u32_at(self.clause(CLAUSE_SCHEDULE), 4) as usize
    }

    pub fn entry(&self, index: usize) -> EntryRow {
        let (offset, _) = self.spans[(CLAUSE_ROUTES - 1) as usize];
        let base = offset as usize + ROUTES_HEADER_BYTES + index * ENTRY_ROW_BYTES;
        let row = self.buf.at(base, ENTRY_ROW_BYTES);
        EntryRow {
            entry_index: u32_at(row, 0),
            kernel_index: u16_at(row, 4),
            read_count: u16_at(row, 6),
            write_count: u16_at(row, 8),
            route_start: u32_at(row, 12),
        }
    }

    fn route_record_bytes(&self, index: usize) -> &'a [u8] {
        let (offset, _) = self.spans[(CLAUSE_ROUTES - 1) as usize];
        let base = offset as usize
            + ROUTES_HEADER_BYTES
            + self.entry_count() * ENTRY_ROW_BYTES
            + index * ROUTE_RECORD_BYTES;
        self.buf.at(base, ROUTE_RECORD_BYTES)
    }

    pub fn route(&self, index: usize) -> RouteRow {
        let row = self.route_record_bytes(index);
        RouteRow {
            region_id: u16_at(row, 0),
            direction: u8_at(row, 2),
            read_class: u8_at(row, 3),
            region_offset: u64_at(row, 4),
            byte_length: u32_at(row, 12),
            producer_entry: u32_at(row, 16),
        }
    }

    pub fn entry_leaf(&self, index: usize) -> [u8; 32] {
        let entry = self.entry(index);
        let total = entry.read_count as usize + entry.write_count as usize;
        // The entry's route records are adjacent fixed-width rows in the
        // clause, so they are ONE slice, not `total` of them: the preimage is
        // unchanged and the part count is a constant.
        let body = self.clause(CLAUSE_ROUTES);
        let first = ROUTES_HEADER_BYTES
            + self.entry_count() * ENTRY_ROW_BYTES
            + entry.route_start as usize * ROUTE_RECORD_BYTES;
        let records = &body[first..first + total * ROUTE_RECORD_BYTES];
        let index_bytes = (index as u32).to_le_bytes();
        let kernel_bytes = entry.kernel_index.to_le_bytes();
        let read_bytes = entry.read_count.to_le_bytes();
        let write_bytes = entry.write_count.to_le_bytes();
        let mut parts = Parts::new();
        parts
            .push(TAG_ROUTE_ENTRY)
            .push(&index_bytes)
            .push(&kernel_bytes)
            .push(&read_bytes)
            .push(&write_bytes)
            .push(records);
        parts.finish()
    }

    /// Duplicate-last Merkle root over entry leaves, folded with a bounded
    /// stack (no allocation).  Equivalent to the level-by-level promotion the
    /// Python mirror computes.
    pub fn computed_route_root(&self) -> [u8; 32] {
        let count = self.entry_count();
        if count == 0 {
            return ZERO32;
        }
        let mut stack = [([0u8; 32], 0u8); 40];
        let mut depth = 0usize;
        for index in 0..count {
            let mut node = self.entry_leaf(index);
            let mut height = 0u8;
            while depth > 0 && stack[depth - 1].1 == height {
                depth -= 1;
                node = node_hash(&stack[depth].0, &node);
                height += 1;
            }
            stack[depth] = (node, height);
            depth += 1;
        }
        while depth > 1 {
            let (top, top_height) = stack[depth - 1];
            let (_, next_height) = stack[depth - 2];
            if top_height == next_height {
                depth -= 2;
                let combined = node_hash(&stack[depth].0, &top);
                stack[depth] = (combined, top_height + 1);
                depth += 1;
            } else {
                // Odd node at this level: duplicate it, exactly as the
                // level-by-level promotion does.
                stack[depth - 1] = (node_hash(&top, &top), top_height + 1);
            }
        }
        stack[0].0
    }

    /// Framing only: the clause-5 header, the row counts, and the entry-leaf
    /// domain.  O(1); run before any per-entry work so the row reads are in
    /// bounds.  R16.
    pub(crate) fn validate_routes_framing(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_ROUTES);
        require!(body.len() >= ROUTES_HEADER_BYTES, err::CLAUSE_LENGTH);
        let entries = u32_at(body, 0) as usize;
        let records = u32_at(body, 4) as usize;
        require!(all_zero(&body[72..80]), err::NONZERO_RESERVED);
        require!(entries >= 1 && entries <= MAX_ENTRIES, err::BAD_COUNT);
        require!(records >= 1 && records <= MAX_ROUTE_RECORDS, err::BAD_COUNT);
        require!(
            body.len()
                == ROUTES_HEADER_BYTES + entries * ENTRY_ROW_BYTES + records * ROUTE_RECORD_BYTES,
            err::CLAUSE_LENGTH
        );
        let domain = sha256(&[TAG_ROUTE_ENTRY]);
        require!(digest_at(body, 40) == domain, err::ROUTE_ROOT);
        Ok(())
    }

    /// R16: the per-item half of `validate_routes`, over entry rows
    /// `[start, start+count)`.  `entry.route_start == running` is checked
    /// against the PRECEDING entry row (the committed prefix is immutable), so
    /// no cross-step cursor has to be carried.  Run
    /// [`validate_routes_framing`](Self::validate_routes_framing) first.
    pub(crate) fn validate_routes_entries(&self, start: u32, count: u32) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_ROUTES);
        let entries_count = self.entry_count();
        let records = self.route_record_count();
        let kernels = self.kernel_count();
        let end = start as usize + count as usize;
        for index in start as usize..end {
            if index >= entries_count {
                return Err(DcgError(err::ROUTE_COUNT_MISMATCH));
            }
            let off = ROUTES_HEADER_BYTES + index * ENTRY_ROW_BYTES;
            require!(all_zero(&body[off + 10..off + 12]), err::NONZERO_RESERVED);
            let entry = self.entry(index);
            require!(entry.entry_index as usize == index, err::ROUTE_ENTRY_ORDER);
            let running = if index == 0 {
                require!(entry.route_start == 0, err::ROUTE_COUNT_MISMATCH);
                0usize
            } else {
                let previous = self.entry(index - 1);
                let expected = previous.route_start as usize
                    + previous.read_count as usize
                    + previous.write_count as usize;
                require!(
                    entry.route_start as usize == expected,
                    err::ROUTE_COUNT_MISMATCH
                );
                expected
            };
            require!(
                (entry.kernel_index as usize) < kernels,
                err::ROUTE_KERNEL_REF
            );
            let kernel = self.kernel(entry.kernel_index as usize);
            require!(
                entry.read_count >= kernel.read_route_min
                    && entry.read_count <= kernel.read_route_max,
                err::ROUTE_COUNT_MISMATCH
            );
            require!(
                entry.write_count >= kernel.write_route_min
                    && entry.write_count <= kernel.write_route_max,
                err::ROUTE_COUNT_MISMATCH
            );
            let total = entry.read_count as usize + entry.write_count as usize;
            require!(running + total <= records, err::ROUTE_COUNT_MISMATCH);

            for position in 0..total {
                let route = self.route(running + position);
                let reserved_off = ROUTES_HEADER_BYTES
                    + entries_count * ENTRY_ROW_BYTES
                    + (running + position) * ROUTE_RECORD_BYTES;
                require!(
                    all_zero(&body[reserved_off + 20..reserved_off + 24]),
                    err::NONZERO_RESERVED
                );
                let is_write = position >= entry.read_count as usize;
                let want = if is_write {
                    DIRECTION_WRITE
                } else {
                    DIRECTION_READ
                };
                require!(route.direction == want, err::ROUTE_DIRECTION);
                require!(route.read_class <= READ_CLASS_MAX, err::ROUTE_CLASS);
                if is_write {
                    require!(route.read_class == READ_CLASS_WITNESSED, err::ROUTE_CLASS);
                }
                let region = self
                    .region_by_id(route.region_id)
                    .ok_or(DcgError(err::ROUTE_REGION_REF))?;
                require!(route.byte_length > 0, err::ROUTE_LENGTH);
                let end = route
                    .region_offset
                    .checked_add(route.byte_length as u64)
                    .ok_or(DcgError(err::ROUTE_OUT_OF_REGION))?;
                require!(end <= region.byte_length, err::ROUTE_OUT_OF_REGION);
                let mask = if is_write {
                    kernel.write_lifetime_mask
                } else {
                    kernel.read_lifetime_mask
                };
                require!(
                    mask & (1u8 << region.lifetime) != 0,
                    err::ROUTE_KERNEL_LIFETIME
                );
                if position != 0 && position != entry.read_count as usize {
                    let prior = self.route(running + position - 1);
                    let ordered = (route.region_id, route.region_offset)
                        > (prior.region_id, prior.region_offset);
                    require!(ordered, err::ROUTE_ORDER);
                }
                if is_write {
                    require!(
                        route.producer_entry as usize == index,
                        err::ROUTE_WRITE_PRODUCER
                    );
                    for other in entry.read_count as usize..position {
                        let prior = self.route(running + other);
                        if prior.region_id != route.region_id {
                            continue;
                        }
                        let prior_end = prior.region_offset + prior.byte_length as u64;
                        if prior.region_offset < end && route.region_offset < prior_end {
                            refuse!(err::ROUTE_WRITE_OVERLAP);
                        }
                    }
                    let span = self
                        .cell_span(&region, route.region_offset, route.byte_length as u64)
                        .ok_or(DcgError(err::ROUTE_PLACEMENT_CLASS))?;
                    if kernel.placement_class == KERNEL_PLACEMENT_SINGLE_REGION {
                        require!(span.0 == span.1, err::ROUTE_PLACEMENT_CLASS);
                    }
                } else if route.read_class == READ_CLASS_SUPPLIED {
                    require!(
                        route.producer_entry == NO_PRODUCER,
                        err::ROUTE_PRODUCER_UNRESOLVED
                    );
                } else if route.read_class == READ_CLASS_CLOSURE_ROOT {
                    // Spec §4 reinterprets `producer_entry` as a closure
                    // selector (`family_id:u16le | window_index:u16le`) for this
                    // class only.  Any 32-bit value is grammatically admissible;
                    // the access layer validates it at seal (428).
                } else if route.producer_entry != NO_PRODUCER {
                    require!(
                        (route.producer_entry as usize) < index,
                        err::ROUTE_PRODUCER_UNRESOLVED
                    );
                }
            }
        }
        Ok(())
    }

    /// R16: the cross-item half of `validate_routes`: the record cursor reaches
    /// exactly `records`, and (when `check_root`) the declared route root is the
    /// document's own fold.  The seal passes `check_root = false` because its
    /// incremental mountain-range compare already fired `SEAL_ROUTE_ROOT(337)`.
    pub(crate) fn validate_routes_global(&self, check_root: bool) -> Result<(), DcgError> {
        let entries = self.entry_count();
        let last = self.entry(entries - 1);
        require!(
            last.route_start as usize + last.read_count as usize + last.write_count as usize
                == self.route_record_count(),
            err::ROUTE_COUNT_MISMATCH
        );
        if check_root {
            require!(
                self.computed_route_root() == self.route_root(),
                err::ROUTE_ROOT
            );
        }
        Ok(())
    }

    pub(crate) fn validate_routes(&self) -> Result<(), DcgError> {
        self.validate_routes_framing()?;
        self.validate_routes_entries(0, self.entry_count() as u32)?;
        self.validate_routes_global(true)
    }

    // -- clause 6: schedule -----------------------------------------------

    /// Framing only: the clause-6 header and row counts, and the entry-count
    /// relations.  O(1); run before the per-wave/per-edge reads.  R16.
    pub(crate) fn validate_schedule_framing(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SCHEDULE);
        require!(body.len() >= SCHEDULE_HEADER_BYTES, err::CLAUSE_LENGTH);
        let waves = u32_at(body, 0) as usize;
        let edges = u32_at(body, 4) as usize;
        let op_count = u64_at(body, 8);
        let terminal = u32_at(body, 16) as usize;
        require!(all_zero(&body[20..32]), err::NONZERO_RESERVED);
        require!(waves >= 1 && waves <= MAX_WAVES, err::BAD_COUNT);
        require!(edges <= MAX_EDGES, err::BAD_COUNT);
        require!(
            body.len() == SCHEDULE_HEADER_BYTES + waves * WAVE_ROW_BYTES + edges * EDGE_ROW_BYTES,
            err::CLAUSE_LENGTH
        );
        let entries = self.entry_count();
        require!(op_count >= entries as u64, err::SCHEDULE_OPS);
        require!(terminal + 1 == entries, err::SCHEDULE_TERMINAL);
        Ok(())
    }

    /// R16: the per-item half of `validate_schedule` over wave rows
    /// `[start, start+count)`.  Contiguity is checked against the PRECEDING
    /// wave row, so no cursor is carried across steps.
    pub(crate) fn validate_schedule_waves(&self, start: u32, count: u32) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SCHEDULE);
        let waves = u32_at(body, 0) as usize;
        let entries = self.entry_count();
        let end = start as usize + count as usize;
        for index in start as usize..end {
            if index >= waves {
                return Err(DcgError(err::SCHEDULE_COVERAGE));
            }
            let off = SCHEDULE_HEADER_BYTES + index * WAVE_ROW_BYTES;
            require!(all_zero(&body[off + 12..off + 16]), err::NONZERO_RESERVED);
            require!(
                u32_at(body, off) as usize == index,
                err::SCHEDULE_WAVE_ORDER
            );
            let wave_start = u32_at(body, off + 4) as usize;
            let wave_count = u32_at(body, off + 8) as usize;
            let expected = if index == 0 {
                0usize
            } else {
                let previous_off = SCHEDULE_HEADER_BYTES + (index - 1) * WAVE_ROW_BYTES;
                u32_at(body, previous_off + 4) as usize + u32_at(body, previous_off + 8) as usize
            };
            require!(
                wave_start == expected && wave_count > 0,
                err::SCHEDULE_COVERAGE
            );
            let cursor = wave_start
                .checked_add(wave_count)
                .ok_or(DcgError(err::SCHEDULE_COVERAGE))?;
            require!(cursor <= entries, err::SCHEDULE_COVERAGE);
        }
        Ok(())
    }

    /// R16: the per-item half of `validate_schedule` over edge rows
    /// `[start, start+count)`.  Ordering is checked against the PRECEDING edge
    /// row, so no key is carried across steps.  Run the wave rows first: the
    /// wave membership test reads them.
    pub(crate) fn validate_schedule_edges(&self, start: u32, count: u32) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SCHEDULE);
        let waves = u32_at(body, 0) as usize;
        let edges = u32_at(body, 4) as usize;
        let entries = self.entry_count();
        let edge_base = SCHEDULE_HEADER_BYTES + waves * WAVE_ROW_BYTES;
        let end = start as usize + count as usize;
        for index in start as usize..end {
            if index >= edges {
                return Err(DcgError(err::SCHEDULE_EDGE));
            }
            let off = edge_base + index * EDGE_ROW_BYTES;
            let source = u32_at(body, off);
            let target = u32_at(body, off + 4);
            require!(
                (source as usize) < entries && (target as usize) < entries,
                err::SCHEDULE_EDGE
            );
            require!(source < target, err::SCHEDULE_EDGE);
            require!(
                self.wave_of(source as usize, waves)? < self.wave_of(target as usize, waves)?,
                err::SCHEDULE_EDGE
            );
            if index > 0 {
                let prior_off = edge_base + (index - 1) * EDGE_ROW_BYTES;
                require!(
                    (source, target) > (u32_at(body, prior_off), u32_at(body, prior_off + 4)),
                    err::SCHEDULE_EDGE
                );
            }
        }
        Ok(())
    }

    /// R16: the cross-item half of `validate_schedule`: the waves cover every
    /// entry.
    pub(crate) fn validate_schedule_global(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SCHEDULE);
        let waves = u32_at(body, 0) as usize;
        let last_off = SCHEDULE_HEADER_BYTES + (waves - 1) * WAVE_ROW_BYTES;
        require!(
            u32_at(body, last_off + 4) as usize + u32_at(body, last_off + 8) as usize
                == self.entry_count(),
            err::SCHEDULE_COVERAGE
        );
        Ok(())
    }

    pub(crate) fn validate_schedule(&self) -> Result<(), DcgError> {
        self.validate_schedule_framing()?;
        let waves = u32_at(self.clause(CLAUSE_SCHEDULE), 0) as u32;
        let edges = u32_at(self.clause(CLAUSE_SCHEDULE), 4) as u32;
        self.validate_schedule_waves(0, waves)?;
        self.validate_schedule_edges(0, edges)?;
        self.validate_schedule_global()
    }

    /// Which wave an entry is in.
    ///
    /// Waves cover the entries contiguously in order (checked just above), so
    /// this is a binary search rather than a scan: it is called twice per
    /// dependency edge, and the fly document has one edge per tile per window.
    fn wave_of(&self, entry: usize, waves: usize) -> Result<usize, DcgError> {
        let body = self.clause(CLAUSE_SCHEDULE);
        let mut lo = 0usize;
        let mut hi = waves;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let off = SCHEDULE_HEADER_BYTES + mid * WAVE_ROW_BYTES;
            let start = u32_at(body, off + 4) as usize;
            let count = u32_at(body, off + 8) as usize;
            if entry < start {
                hi = mid;
            } else if entry >= start + count {
                lo = mid + 1;
            } else {
                return Ok(mid);
            }
        }
        Err(DcgError(err::SCHEDULE_COVERAGE))
    }

    // -- clause 7: verification policy ------------------------------------

    pub fn mode_registrant_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_VERIFICATION_POLICY), 0) as usize
    }

    pub fn policy_rule_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_VERIFICATION_POLICY), 2) as usize
    }

    pub fn default_mode(&self) -> u16 {
        u16_at(self.clause(CLAUSE_VERIFICATION_POLICY), 4)
    }

    pub fn mode_registrant(&self, index: usize) -> ModeRegistrantRow {
        let body = self.clause(CLAUSE_VERIFICATION_POLICY);
        let off = POLICY_HEADER_BYTES + index * MODE_REGISTRY_ROW_BYTES;
        ModeRegistrantRow {
            mode_id: u16_at(body, off),
            flags: u16_at(body, off + 2),
        }
    }

    pub fn mode_name(&self, index: usize) -> &'a [u8] {
        let body = self.clause(CLAUSE_VERIFICATION_POLICY);
        let off = POLICY_HEADER_BYTES + index * MODE_REGISTRY_ROW_BYTES + 4;
        let field = &body[off..off + MODE_NAME_BYTES];
        &field[..name_len(field)]
    }

    pub fn policy_rule(&self, index: usize) -> PolicyRuleRow {
        let body = self.clause(CLAUSE_VERIFICATION_POLICY);
        let off = POLICY_HEADER_BYTES
            + self.mode_registrant_count() * MODE_REGISTRY_ROW_BYTES
            + index * POLICY_RULE_ROW_BYTES;
        PolicyRuleRow {
            selector: u8_at(body, off),
            mode_id: u16_at(body, off + 2),
            key_lo: u32_at(body, off + 4),
            key_hi: u32_at(body, off + 8),
        }
    }

    /// Whether the document opted into write-record provenance v1
    /// (`docs/spec/dcg-write-records-v1.md` §1): the `consensus` registrant
    /// carries `MODE_FLAG_WRITE_RECORDS_V1`.
    pub fn write_records_v1(&self) -> bool {
        match self.registrant_of(MODE_CONSENSUS) {
            Some((_, row)) => row.flags & MODE_FLAG_WRITE_RECORDS_V1 != 0,
            None => false,
        }
    }

    fn registrant_of(&self, mode_id: u16) -> Option<(usize, ModeRegistrantRow)> {
        for index in 0..self.mode_registrant_count() {
            let row = self.mode_registrant(index);
            if row.mode_id == mode_id {
                return Some((index, row));
            }
        }
        None
    }

    pub(crate) fn validate_policy(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_VERIFICATION_POLICY);
        require!(body.len() >= POLICY_HEADER_BYTES, err::CLAUSE_LENGTH);
        let registrants = u16_at(body, 0) as usize;
        let rules = u16_at(body, 2) as usize;
        let default_mode = u16_at(body, 4);
        require!(all_zero(&body[6..8]), err::NONZERO_RESERVED);
        require!(
            registrants >= 1 && registrants <= MAX_MODE_REGISTRANTS,
            err::BAD_COUNT
        );
        require!(rules <= MAX_POLICY_RULES, err::BAD_COUNT);
        require!(
            body.len()
                == POLICY_HEADER_BYTES
                    + registrants * MODE_REGISTRY_ROW_BYTES
                    + rules * POLICY_RULE_ROW_BYTES,
            err::CLAUSE_LENGTH
        );

        for index in 0..registrants {
            let off = POLICY_HEADER_BYTES + index * MODE_REGISTRY_ROW_BYTES;
            require!(all_zero(&body[off + 36..off + 40]), err::NONZERO_RESERVED);
            let row = self.mode_registrant(index);
            if index > 0 {
                require!(
                    row.mode_id > self.mode_registrant(index - 1).mode_id,
                    err::POLICY_REGISTRY_ORDER
                );
            }
            require!(
                mode_support_bit(row.mode_id).is_some(),
                err::POLICY_UNKNOWN_MODE
            );
            require!(
                name_is_valid(&body[off + 4..off + 4 + MODE_NAME_BYTES]),
                err::POLICY_REGISTRY_NAME
            );
            require!(row.flags >> 3 == 0, err::POLICY_REGISTRY_NAME);
            require!(
                row.flags & MODE_FLAG_WRITE_RECORDS_V1 == 0 || row.mode_id == MODE_CONSENSUS,
                err::POLICY_REGISTRY_NAME
            );
        }
        // `consensus` is mandatory and its name is fixed; `commit` keeps its
        // name when present.  Further registrants are open.
        match self.registrant_of(MODE_CONSENSUS) {
            Some((index, _)) => {
                require!(
                    self.mode_name(index) == MODE_NAME_CONSENSUS,
                    err::POLICY_NO_CONSENSUS
                )
            }
            None => refuse!(err::POLICY_NO_CONSENSUS),
        }
        if let Some((index, _)) = self.registrant_of(MODE_COMMIT) {
            require!(
                self.mode_name(index) == MODE_NAME_COMMIT,
                err::POLICY_REGISTRY_NAME
            );
        }
        require!(
            self.registrant_of(default_mode).is_some(),
            err::POLICY_DEFAULT_MODE
        );
        // The default applies where no rule does, so every kernel must support it.
        let default_bit =
            mode_support_bit(default_mode).ok_or(DcgError(err::POLICY_UNKNOWN_MODE))?;
        for index in 0..self.kernel_count() {
            require!(
                self.kernel(index).mode_support & default_bit != 0,
                err::POLICY_UNSUPPORTED_MODE
            );
        }

        let mut previous: Option<(u8, u32, u32)> = None;
        for index in 0..rules {
            let off = POLICY_HEADER_BYTES
                + registrants * MODE_REGISTRY_ROW_BYTES
                + index * POLICY_RULE_ROW_BYTES;
            require!(u8_at(body, off + 1) == 0, err::NONZERO_RESERVED);
            require!(all_zero(&body[off + 12..off + 16]), err::NONZERO_RESERVED);
            let rule = self.policy_rule(index);
            require!(rule.selector <= SELECTOR_MAX, err::POLICY_RULE_SELECTOR);
            require!(
                self.registrant_of(rule.mode_id).is_some(),
                err::POLICY_UNKNOWN_MODE
            );
            require!(rule.key_lo <= rule.key_hi, err::POLICY_RULE_KEY);
            let key = (rule.selector, rule.key_lo, rule.key_hi);
            if let Some(prior) = previous {
                require!(key > prior, err::POLICY_RULE_ORDER);
            }
            previous = Some(key);
            let bit = mode_support_bit(rule.mode_id).ok_or(DcgError(err::POLICY_UNKNOWN_MODE))?;
            if rule.selector == SELECTOR_KERNEL_KIND {
                let mut matched = 0usize;
                for kernel_index in 0..self.kernel_count() {
                    let kernel = self.kernel(kernel_index);
                    if kernel.kind as u32 >= rule.key_lo && kernel.kind as u32 <= rule.key_hi {
                        matched += 1;
                        require!(kernel.mode_support & bit != 0, err::POLICY_UNSUPPORTED_MODE);
                    }
                }
                require!(matched > 0, err::POLICY_RULE_KEY);
            } else {
                require!(
                    (rule.key_hi as usize) < self.entry_count(),
                    err::POLICY_RULE_KEY
                );
                for entry_index in rule.key_lo as usize..=rule.key_hi as usize {
                    let kernel = self.kernel(self.entry(entry_index).kernel_index as usize);
                    require!(kernel.mode_support & bit != 0, err::POLICY_UNSUPPORTED_MODE);
                }
            }
        }
        Ok(())
    }

    /// Does any mode this document actually uses require a closure?
    pub fn uses_closure_mode(&self) -> bool {
        // A merely parsed document's clause bodies are not proven to hold
        // their declared rows; close reads this on the scaffold path, so a
        // short clause 7 returns false rather than indexing out of bounds.
        let body = self.clause(CLAUSE_VERIFICATION_POLICY);
        if body.len() < POLICY_HEADER_BYTES {
            return false;
        }
        let registrants = u16_at(body, 0) as usize;
        let rules = u16_at(body, 2) as usize;
        let table = POLICY_HEADER_BYTES
            + registrants.saturating_mul(MODE_REGISTRY_ROW_BYTES)
            + rules.saturating_mul(POLICY_RULE_ROW_BYTES);
        if body.len() < table {
            return false;
        }
        let used = |mode_id: u16| -> bool {
            match self.registrant_of(mode_id) {
                Some((_, row)) => row.flags & MODE_FLAG_REQUIRES_CLOSURE != 0,
                None => false,
            }
        };
        if used(self.default_mode()) {
            return true;
        }
        for index in 0..self.policy_rule_count() {
            if used(self.policy_rule(index).mode_id) {
                return true;
            }
        }
        false
    }

    /// One placement cell of a region, by the index `cell_span_of` returns.
    ///
    /// For a `grid` generator the index is the cell number; for an `explicit`
    /// one it is the absolute slice index. Both come back as the same tuple,
    /// which is what lets `execute` resolve a span to accounts without knowing
    /// which placement form the region uses.
    pub fn placement_cell(&self, region: &RegionRow, index: u64) -> Option<PlacementCell> {
        let row = self.generator(region.placement_ref as usize);
        if row.form == PLACEMENT_GRID {
            let cells = (row.page_count as u64).checked_mul(row.shard_count as u64)?;
            if index >= cells {
                return None;
            }
            let length = row.slice_length as u64;
            Some(PlacementCell {
                ordinal: Self::grid_cell_ordinal(&row, index),
                account_offset: row.slice_offset,
                region_offset: index.checked_mul(length)?,
                byte_length: length,
            })
        } else {
            let first = row.first_slice as u64;
            if index < first || index >= first + row.slice_count as u64 {
                return None;
            }
            let slice = self.slice(index as usize);
            Some(PlacementCell {
                ordinal: slice.account_ordinal,
                account_offset: slice.account_offset,
                region_offset: slice.region_offset,
                byte_length: slice.byte_length as u64,
            })
        }
    }

    /// The half-open placement-cell range a byte range of a region touches.
    /// Public so `access` can enforce `placement_class` on a write without
    /// duplicating the grid arithmetic or the explicit slice scan.
    pub fn cell_span_of(&self, region: &RegionRow, offset: u64, length: u64) -> Option<(u64, u64)> {
        self.cell_span(region, offset, length)
    }

    // -- clause 8: closure policy -----------------------------------------

    pub fn closure_family_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_CLOSURE_POLICY), 0) as usize
    }

    /// Clause-8 policy values consumed by the additive Tier-C profile-3
    /// adapter.  The bytes remain the existing descriptor grammar: offset 20
    /// is the sealed dispute-window slot count and offset 28 is the explicit
    /// fixture bond amount.
    pub fn closure_dispute_window_slots(&self) -> u64 {
        u64_at(self.clause(CLAUSE_CLOSURE_POLICY), 20)
    }

    pub fn closure_bond_lamports(&self) -> u64 {
        u64_at(self.clause(CLAUSE_CLOSURE_POLICY), 28)
    }

    /// One clause-8 closure family row (spec §4's selector names one of these).
    pub fn closure_family(&self, index: usize) -> ClosureFamilyRow {
        let body = self.clause(CLAUSE_CLOSURE_POLICY);
        let off = CLOSURE_HEADER_BYTES + index * CLOSURE_FAMILY_ROW_BYTES;
        ClosureFamilyRow {
            family_id: u16_at(body, off),
            mode_id: u16_at(body, off + 2),
            selector: u8_at(body, off + 4),
            key_lo: u32_at(body, off + 8),
            key_hi: u32_at(body, off + 12),
        }
    }

    /// Does `family` select `entry_index`?  The family's selector is a
    /// `verification_policy` selector: an entry range or a kernel-kind range.
    /// This reads `kernel.kind` here so the access module's AST guard (which
    /// forbids a policy read of `kind` outside `mode_of_entry`) stays honest.
    pub fn closure_family_selects_entry(
        &self,
        family: ClosureFamilyRow,
        entry_index: usize,
    ) -> bool {
        let kind = self
            .kernel(self.entry(entry_index).kernel_index as usize)
            .kind;
        match family.selector {
            SELECTOR_ENTRY_RANGE => {
                family.key_lo as usize <= entry_index && entry_index <= family.key_hi as usize
            }
            SELECTOR_KERNEL_KIND => family.key_lo <= kind as u32 && (kind as u32) <= family.key_hi,
            _ => false,
        }
    }

    pub(crate) fn validate_closure(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_CLOSURE_POLICY);
        require!(body.len() >= CLOSURE_HEADER_BYTES, err::CLAUSE_LENGTH);
        let families = u16_at(body, 0) as usize;
        require!(u16_at(body, 2) == 0, err::NONZERO_RESERVED);
        let leaf_arity = u32_at(body, 4);
        let node_arity = u32_at(body, 8);
        let window_entries = u32_at(body, 12);
        require!(all_zero(&body[16..20]), err::NONZERO_RESERVED);
        let dispute_window = u64_at(body, 20);
        let bond = u64_at(body, 28);
        require!(all_zero(&body[36..40]), err::NONZERO_RESERVED);
        require!(families <= MAX_CLOSURE_FAMILIES, err::BAD_COUNT);
        require!(
            body.len() == CLOSURE_HEADER_BYTES + families * CLOSURE_FAMILY_ROW_BYTES,
            err::CLAUSE_LENGTH
        );

        if self.uses_closure_mode() {
            require!(families >= 1, err::CLOSURE_REQUIRED);
            require!(
                leaf_arity >= 2 && leaf_arity.is_power_of_two(),
                err::CLOSURE_GEOMETRY
            );
            require!(
                node_arity >= 2 && node_arity.is_power_of_two(),
                err::CLOSURE_GEOMETRY
            );
            require!(window_entries >= 1, err::CLOSURE_GEOMETRY);
            require!(dispute_window > 0, err::CLOSURE_GEOMETRY);
            require!(
                window_entries as usize <= self.entry_count(),
                err::CLOSURE_WINDOW
            );
        } else {
            require!(families == 0, err::CLOSURE_FORBIDDEN);
            require!(
                leaf_arity == 0
                    && node_arity == 0
                    && window_entries == 0
                    && dispute_window == 0
                    && bond == 0,
                err::CLOSURE_FORBIDDEN
            );
        }

        let mut previous: Option<(u8, u32, u32)> = None;
        for index in 0..families {
            let off = CLOSURE_HEADER_BYTES + index * CLOSURE_FAMILY_ROW_BYTES;
            require!(all_zero(&body[off + 5..off + 8]), err::NONZERO_RESERVED);
            require!(all_zero(&body[off + 16..off + 24]), err::NONZERO_RESERVED);
            require!(
                u16_at(body, off) as usize == index,
                err::CLOSURE_FAMILY_ORDER
            );
            let mode_id = u16_at(body, off + 2);
            let selector = u8_at(body, off + 4);
            let key_lo = u32_at(body, off + 8);
            let key_hi = u32_at(body, off + 12);
            match self.registrant_of(mode_id) {
                Some((_, row)) => require!(
                    row.flags & MODE_FLAG_REQUIRES_CLOSURE != 0,
                    err::CLOSURE_REQUIRED
                ),
                None => refuse!(err::CLOSURE_REQUIRED),
            }
            require!(selector <= SELECTOR_MAX, err::CLOSURE_FAMILY_ORDER);
            require!(key_lo <= key_hi, err::CLOSURE_FAMILY_ORDER);
            let key = (selector, key_lo, key_hi);
            if let Some(prior) = previous {
                require!(key > prior, err::CLOSURE_FAMILY_ORDER);
            }
            previous = Some(key);
        }
        Ok(())
    }

    // -- clause 9: supply --------------------------------------------------

    pub fn supply_window_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_SUPPLY), 0) as usize
    }

    pub(crate) fn validate_supply(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SUPPLY);
        require!(body.len() >= SUPPLY_HEADER_BYTES, err::CLAUSE_LENGTH);
        let count = u16_at(body, 0) as usize;
        require!(all_zero(&body[2..8]), err::NONZERO_RESERVED);
        require!(count <= MAX_SUPPLY_WINDOWS, err::BAD_COUNT);
        require!(
            body.len() == SUPPLY_HEADER_BYTES + count * SUPPLY_WINDOW_ROW_BYTES,
            err::CLAUSE_LENGTH
        );
        for index in 0..count {
            let off = SUPPLY_HEADER_BYTES + index * SUPPLY_WINDOW_ROW_BYTES;
            require!(u32_at(body, off) as usize == index, err::SUPPLY_ORDER);
            let region_id = u16_at(body, off + 4);
            let sharing = u8_at(body, off + 6);
            let sealed = u8_at(body, off + 7);
            let byte_length = u64_at(body, off + 8);
            let record = digest_at(body, off + 16);
            let owner = digest_at(body, off + 48);
            require!(all_zero(&body[off + 82..off + 88]), err::NONZERO_RESERVED);
            let region = self
                .region_by_id(region_id)
                .ok_or(DcgError(err::SUPPLY_REGION))?;
            require!(
                region.lifetime == LIFETIME_SHARED || region.lifetime == LIFETIME_SUPPLIED,
                err::SUPPLY_REGION
            );
            require!(byte_length == region.byte_length, err::SUPPLY_LENGTH);
            require!(sharing <= 1 && sealed <= 1, err::SUPPLY_SHARING);
            require!(
                (region.lifetime == LIFETIME_SHARED) == (sharing == 1),
                err::SUPPLY_SHARING
            );
            if sharing == 1 {
                require!(sealed == 1, err::SUPPLY_SHARED_UNSEALED);
                require!(owner != ZERO32, err::SUPPLY_SHARED_OWNER);
            } else {
                require!(owner == ZERO32, err::SUPPLY_SHARED_OWNER);
            }
            require!((sealed == 1) == (record != ZERO32), err::SUPPLY_DIGEST);
            require!(
                sealed == 0 || record == region.initial_content,
                err::SUPPLY_DIGEST
            );
        }
        // Every supplied or shared region has a window.
        for index in 0..self.region_count() {
            let region = self.region(index);
            if region.lifetime != LIFETIME_SHARED && region.lifetime != LIFETIME_SUPPLIED {
                continue;
            }
            let mut found = false;
            for window in 0..count {
                let off = SUPPLY_HEADER_BYTES + window * SUPPLY_WINDOW_ROW_BYTES;
                if u16_at(body, off + 4) == region.region_id {
                    found = true;
                    break;
                }
            }
            require!(found, err::SUPPLY_UNSUPPLIED_REGION);
        }
        Ok(())
    }

    // -- clause 10: successor ----------------------------------------------

    pub fn successor_import_count(&self) -> usize {
        u16_at(self.clause(CLAUSE_SUCCESSOR), 0) as usize
    }

    pub fn successor_seal(&self) -> [u8; 32] {
        digest_at(self.clause(CLAUSE_SUCCESSOR), 8)
    }

    pub(crate) fn validate_successor(&self) -> Result<(), DcgError> {
        let body = self.clause(CLAUSE_SUCCESSOR);
        require!(body.len() >= SUCCESSOR_HEADER_BYTES, err::CLAUSE_LENGTH);
        let count = u16_at(body, 0) as usize;
        require!(u16_at(body, 2) == 0, err::NONZERO_RESERVED);
        require!(all_zero(&body[4..8]), err::NONZERO_RESERVED);
        require!(count <= MAX_SUCCESSOR_IMPORTS, err::BAD_COUNT);
        require!(
            body.len() == SUCCESSOR_HEADER_BYTES + count * SUCCESSOR_IMPORT_ROW_BYTES,
            err::CLAUSE_LENGTH
        );
        let seal = digest_at(body, 8);
        if count == 0 {
            require!(seal == ZERO32, err::SUCCESSOR_SEAL);
            return Ok(());
        }
        // The successor seal's preimage takes three NON-ADJACENT fields out of
        // each 48-byte import row, so it is not a slice concatenation and
        // `hash::Parts` does not fit it.  It stays on the software hasher
        // because it is reached only from `validate`, i.e. only at seal, and
        // only for a document that declares successor imports -- which the
        // fly document does not.  Step 5, which owns successor binding, should
        // either pad the preimage to the row or fold per import.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(TAG_SUCCESSOR_SEAL);
        hasher.update((count as u32).to_le_bytes());
        let mut previous: Option<u16> = None;
        for index in 0..count {
            let off = SUCCESSOR_HEADER_BYTES + index * SUCCESSOR_IMPORT_ROW_BYTES;
            let region_id = u16_at(body, off);
            require!(u16_at(body, off + 2) == 0, err::NONZERO_RESERVED);
            require!(all_zero(&body[off + 4..off + 8]), err::NONZERO_RESERVED);
            let byte_length = u64_at(body, off + 8);
            let digest = digest_at(body, off + 16);
            if let Some(prior) = previous {
                require!(region_id > prior, err::SUCCESSOR_ORDER);
            }
            previous = Some(region_id);
            let region = self
                .region_by_id(region_id)
                .ok_or(DcgError(err::SUCCESSOR_REGION))?;
            // A shared window belongs to its owner, never to a successor.
            require!(region.lifetime != LIFETIME_SHARED, err::SUCCESSOR_REGION);
            require!(byte_length == region.byte_length, err::SUCCESSOR_LENGTH);
            require!(digest != ZERO32, err::SUCCESSOR_SEAL);
            hasher.update(region_id.to_le_bytes());
            hasher.update(byte_length.to_le_bytes());
            hasher.update(digest);
        }
        let expected: [u8; 32] = hasher.finalize().into();
        require!(seal == expected, err::SUCCESSOR_SEAL);
        Ok(())
    }

    // -- whole document ----------------------------------------------------

    /// Every rule, in clause order with the cross-clause references last.
    pub fn validate(&self) -> Result<(), DcgError> {
        self.validate_kernels()?;
        self.validate_placement_framing()?;
        self.validate_regions()?;
        self.validate_placement()?;
        self.validate_machine()?;
        self.validate_routes()?;
        self.validate_schedule()?;
        self.validate_policy()?;
        self.validate_closure()?;
        self.validate_supply()?;
        self.validate_successor()?;
        Ok(())
    }

    pub fn clause_digest(&self, clause_id: u16) -> [u8; 32] {
        clause_digest(clause_id, self.clause(clause_id))
    }

    pub fn header_digest(&self) -> [u8; 32] {
        sha256(&[TAG_HEADER, self.buf.at(0, BODY_START)])
    }

    /// The descriptor digest.  See `docs/spec/dcg-descriptor-v1.md` §8.
    pub fn digest(&self) -> [u8; 32] {
        let version = self.grammar_version().to_le_bytes();
        let flags = self.container_flags().to_le_bytes();
        let id = self.descriptor_id();
        let total = self.total_bytes().to_le_bytes();
        let header = self.header_digest();
        let mut clauses = [[0u8; 32]; CLAUSE_COUNT];
        for clause_id in 1..=CLAUSE_COUNT as u16 {
            clauses[clause_id as usize - 1] = self.clause_digest(clause_id);
        }
        let mut parts = Parts::new();
        parts
            .push(TAG_DESCRIPTOR)
            .push(&version)
            .push(&flags)
            .push(&id)
            .push(&total)
            .push(&header);
        for clause in clauses.iter() {
            parts.push(clause);
        }
        parts.finish()
    }
}

impl core::fmt::Debug for Descriptor<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately terse: a descriptor is up to megabytes of bytes.
        f.debug_struct("Descriptor")
            .field("grammar_version", &self.grammar_version())
            .field("total_bytes", &self.total_bytes())
            .finish()
    }
}

pub fn clause_frame_chain(clause_id: u16, body: &[u8]) -> [u8; 32] {
    let mut running = sha256(&[
        TAG_CLAUSE_FRAME,
        &clause_id.to_le_bytes(),
        &(body.len() as u32).to_le_bytes(),
    ]);
    for (index, frame) in body.chunks(DESC_FRAME_BYTES).enumerate() {
        running = sha256(&[
            TAG_CLAUSE_FRAME,
            &running,
            &(index as u32).to_le_bytes(),
            &(frame.len() as u32).to_le_bytes(),
            frame,
        ]);
    }
    running
}

pub fn clause_digest(clause_id: u16, body: &[u8]) -> [u8; 32] {
    sha256(&[
        TAG_CLAUSE,
        &clause_id.to_le_bytes(),
        &(body.len() as u32).to_le_bytes(),
        &clause_frame_chain(clause_id, body),
    ])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[TAG_ROUTE_NODE, left, right])
}

/// Parse, validate and digest in one call.
pub fn validate_and_digest(buf: &[u8]) -> Result<[u8; 32], DcgError> {
    let doc = Descriptor::parse(buf)?;
    doc.validate()?;
    Ok(doc.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The duplicate-last fold, computed the slow level-by-level way.
    fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return ZERO32;
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

    fn leaf(index: u8) -> [u8; 32] {
        sha256(&[&[index]])
    }

    /// The streaming fold in `computed_route_root`, isolated from a document.
    fn streaming_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return ZERO32;
        }
        let mut stack = [([0u8; 32], 0u8); 40];
        let mut depth = 0usize;
        for value in leaves {
            let mut node = *value;
            let mut height = 0u8;
            while depth > 0 && stack[depth - 1].1 == height {
                depth -= 1;
                node = node_hash(&stack[depth].0, &node);
                height += 1;
            }
            stack[depth] = (node, height);
            depth += 1;
        }
        while depth > 1 {
            let (top, top_height) = stack[depth - 1];
            let (_, next_height) = stack[depth - 2];
            if top_height == next_height {
                depth -= 2;
                let combined = node_hash(&stack[depth].0, &top);
                stack[depth] = (combined, top_height + 1);
                depth += 1;
            } else {
                stack[depth - 1] = (node_hash(&top, &top), top_height + 1);
            }
        }
        stack[0].0
    }

    #[test]
    fn streaming_fold_equals_level_by_level_duplicate_last() {
        for count in 1..=64usize {
            let leaves: Vec<[u8; 32]> = (0..count).map(|index| leaf(index as u8)).collect();
            assert_eq!(
                streaming_root(&leaves),
                reference_root(&leaves),
                "count {count}"
            );
        }
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaves = [leaf(7)];
        assert_eq!(streaming_root(&leaves), leaves[0]);
    }

    #[test]
    fn name_field_rules() {
        let mut field = [0u8; 8];
        field[..3].copy_from_slice(b"abc");
        assert!(name_is_valid(&field));
        // Empty is refused.
        assert!(!name_is_valid(&[0u8; 8]));
        // An interior NUL is refused.
        let mut interior = [0u8; 8];
        interior[0] = b'a';
        interior[2] = b'b';
        assert!(!name_is_valid(&interior));
        // A space is refused (printable NON-SPACE ASCII).
        let mut spaced = [0u8; 8];
        spaced[..3].copy_from_slice(b"a b");
        assert!(!name_is_valid(&spaced));
        // A full field with no NUL at all is allowed.
        assert!(name_is_valid(b"abcdefgh"));
    }

    #[test]
    fn mode_support_bits_are_one_based_and_bounded() {
        assert_eq!(mode_support_bit(1), Some(1));
        assert_eq!(mode_support_bit(2), Some(2));
        assert_eq!(mode_support_bit(16), Some(1 << 15));
        assert_eq!(mode_support_bit(0), None);
        assert_eq!(mode_support_bit(17), None);
    }

    #[test]
    fn a_short_buffer_is_truncated_not_a_panic() {
        for length in 0..BODY_START {
            let buf = vec![0u8; length];
            assert_eq!(
                Descriptor::parse(&buf).unwrap_err(),
                DcgError(err::TRUNCATED),
                "length {length}"
            );
        }
    }

    #[test]
    fn wrong_magic_and_version_are_distinct_refusals() {
        let mut buf = vec![0u8; BODY_START];
        assert_eq!(
            Descriptor::parse(&buf).unwrap_err(),
            DcgError(err::BAD_MAGIC)
        );
        buf[0..4].copy_from_slice(&MAGIC);
        assert_eq!(
            Descriptor::parse(&buf).unwrap_err(),
            DcgError(err::BAD_GRAMMAR_VERSION)
        );
        buf[4..6].copy_from_slice(&GRAMMAR_VERSION.to_le_bytes());
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            Descriptor::parse(&buf).unwrap_err(),
            DcgError(err::BAD_FLAGS)
        );
    }

    #[test]
    fn row_widths_are_the_frozen_ones() {
        // Any change here is a grammar version bump, not a patch.
        assert_eq!(HEADER_BYTES, 64);
        assert_eq!(DIRECTORY_BYTES, 120);
        assert_eq!(BODY_START, 184);
        assert_eq!(MACHINE_BYTES, 136);
        assert_eq!(KERNEL_ROW_BYTES, 48);
        assert_eq!(MODE_COST_ROW_BYTES, 16);
        assert_eq!(REGION_ROW_BYTES, 64);
        assert_eq!(GENERATOR_ROW_BYTES, 40);
        assert_eq!(EXPLICIT_SLICE_ROW_BYTES, 48);
        assert_eq!(ENTRY_ROW_BYTES, 16);
        assert_eq!(ROUTE_RECORD_BYTES, 24);
        assert_eq!(WAVE_ROW_BYTES, 16);
        assert_eq!(EDGE_ROW_BYTES, 8);
        assert_eq!(MODE_REGISTRY_ROW_BYTES, 40);
        assert_eq!(POLICY_RULE_ROW_BYTES, 16);
        assert_eq!(CLOSURE_FAMILY_ROW_BYTES, 24);
        assert_eq!(SUPPLY_WINDOW_ROW_BYTES, 88);
        assert_eq!(SUCCESSOR_IMPORT_ROW_BYTES, 48);
    }

    #[test]
    fn domain_tags_are_disjoint_from_every_bcx2_era_tag() {
        // A clean break means no DCG preimage can collide with an old one.
        for tag in [
            TAG_DESCRIPTOR,
            TAG_CLAUSE,
            TAG_ROUTE_ENTRY,
            TAG_ROUTE_NODE,
            TAG_SUCCESSOR_SEAL,
        ] {
            assert!(
                tag.starts_with(b"basanos/dcg-"),
                "{:?}",
                core::str::from_utf8(tag)
            );
        }
    }
}
