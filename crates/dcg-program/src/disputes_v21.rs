// SPDX-License-Identifier: GPL-3.0-only

//! Optimistic disputes v2.1, program skeleton (design
//! `docs/design/optimistic-descent-v2.1.md` §14 step 2, partial). Tag 227 with
//! a subtype byte. Feature `graph-v21`, testnet only.
//!
//! In this skeleton:
//! - enumerated and repeated blocks (at most `MAX_BLOCKS`), with gates, SMALL
//!   state and chunked inputs: the chunked-kernel slice (design §4.3a).
//!   Producer kinds 1, 2, 4 (resolved), 5, 6 and 7; claims SHAPE, EDGE,
//!   GATE, STATE, STEP and OUT. The template's blocks are checked for
//!   consistency and placement and are part of its id;
//! - the template's `spec_root` is **trusted from the admitter** (no on-chain
//!   derivation yet, design O1); testnet only;
//! - first-divergence descent with structural picks, the leaf reveal, and the
//!   SHAPE / EDGE / STEP / OUT claims with the malformed-data rule;
//! - one dispute record per (run, challenger, nonce); phase deadlines on
//!   every action and timeout;
//! - bonds: executor bond at commit, challenger bond at open; a challenger
//!   ruling refutes the run; the ruled prefix and `best_win` pay the
//!   executor bond to the earliest-opened winner (slasher share) and the
//!   payer (remainder); later disputes on a refuted run are moot (§10.1).
//!
//! - per-party staging buffers (§8.2), created and funded by C, written any
//!   time by their owner; a reveal or claim may read its bytes from them.
//!
//! - a run-level reveal cache: a verified reveal may be recorded, and any
//!   other dispute at the same node is answered from it by anyone (§8.3).
//!
//! Rent reclaim: subs 18 to 20 close disputes (with their staging buffers), shrink settled runs to
//! their receipts (or cancel uncommitted ones) and close reveal caches.
//! Not yet: the leaf cache and the full v2.1 template identity. The bounded
//! load extension uses c=1 and extend_slots=phase_window.

use dcg_disputes as D;
use dcg_disputes::blocks::{self, Block};
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::hash::sha256;

#[path = "disputes_v21_lx.rs"]
pub mod lx;

pub const TAG: u8 = 227;
pub const SUB_CREATE_TEMPLATE: u8 = 1;
pub const SUB_INIT_RUN: u8 = 2;
pub const SUB_COMMIT: u8 = 3;
pub const SUB_OPEN: u8 = 4;
pub const SUB_REVEAL_NODES: u8 = 5;
pub const SUB_PICK: u8 = 6;
pub const SUB_REVEAL_LEAF: u8 = 7;
pub const SUB_CLAIM: u8 = 8;
pub const SUB_TIMEOUT: u8 = 9;
pub const SUB_FINALIZE: u8 = 10;
pub const SUB_ADVANCE: u8 = 11;
pub const SUB_MOOT: u8 = 12;
pub const SUB_PAY_POT: u8 = 13;
pub const SUB_STAGE_CREATE: u8 = 14;
pub const SUB_STAGE_WRITE: u8 = 15;

/// Staging buffer "D21S" (design §8.2): magic(4) role(1) pad(3) dispute(32)
/// len:u32 pad(4) then the staged bytes. PDA ["dcg21stg", dispute, role].
/// Role 1 is E's buffer, role 2 is C's; C funds both at creation. A reveal or
/// claim whose data is the single byte `FROM_STAGING` reads its bytes from
/// the party's buffer instead of the instruction. Skeleton: one CPI
/// creation, so at most `MAX_STAGE` bytes (growth comes later).
pub const ROLE_EXECUTOR: u8 = 1;
pub const ROLE_CHALLENGER: u8 = 2;
pub const STAGE_HEADER: usize = 48;
/// Created by one CPI (10 KiB), then grown by `SUB_STAGE_GROW` in steps of at
/// most 10 KiB up to `MAX_STAGE` (a 64 KiB witness plus its claim framing).
pub const CREATE_STAGE: usize = 10_240 - STAGE_HEADER;
pub const MAX_STAGE: usize = 128 * 1024;
pub const SUB_STAGE_GROW: u8 = 17;
/// Rent reclaim (2026-10-03). Close a ruled dispute and its staging buffers.
pub const SUB_CLOSE_DISPUTE: u8 = 18;
/// Shrink a settled run to its receipt once every dispute is closed (anyone),
/// or cancel an uncommitted run (its payer).
pub const SUB_CLOSE_RUN: u8 = 19;
/// Run receipt "D21P": the run's first 136 bytes (magic, status, template,
/// payer, executor, run id) then its 176-byte root, at the run's own address.
pub const RECEIPT_BYTES: usize = 136 + D::RUN_ROOT_BYTES;
/// Close a reveal cache once its run is settled with no open dispute, or gone.
pub const SUB_CLOSE_CACHE: u8 = 20;
/// Close a template with no live runs; its rent returns to its recorded payer.
pub const SUB_CLOSE_TEMPLATE: u8 = 21;
/// Retire a tracked template so no new runs can be initialized from it.
pub const SUB_RETIRE_TEMPLATE: u8 = 22;
/// Builds the pre-provenance template encoding for backwards-compatibility
/// tests. This subtype is absent from non-test program builds.
#[cfg(feature = "test-legacy-template-create")]
pub const SUB_TEST_CREATE_LEGACY_TEMPLATE: u8 = 250;
pub const FROM_STAGING: u8 = 0xFF;
pub const SUB_CACHE_ANSWER: u8 = 16;

/// Reveal cache entry "D21C" (design §8.3): magic(4) kind(1) depth(1) pad(2)
/// level:u32 pad(4) position:u64 node[32] revealed[32 x 32]. PDA
/// ["dcg21rc", run, kind, level, position]. Written only by a verified
/// reveal, keyed by the node it answers; any dispute at that node can then
/// be answered from it by anyone.
pub const CACHE_BYTES: usize = 56 + 32 * 32;
/// Caches created since rent reclaim also record the executor that paid
/// their rent (32 bytes after the revealed nodes), so a cache can be closed
/// after its run. `cache_answer` accepts both sizes.
pub const CACHE_BYTES_V2: usize = CACHE_BYTES + 32;

pub const RULING_OPEN: u8 = 0;
pub const RULING_EXECUTOR: u8 = 1;
pub const RULING_CHALLENGER: u8 = 2;
pub const RULING_MOOT: u8 = 3;

pub const CLAIM_SHAPE: u8 = 1;
pub const CLAIM_EDGE: u8 = 2;
pub const CLAIM_STEP: u8 = 3;
pub const CLAIM_OUT: u8 = 4;
pub const CLAIM_GATE: u8 = 5;
pub const CLAIM_STATE: u8 = 6;

/// Blocks a template may hold in this skeleton.
pub const MAX_BLOCKS: usize = 8;
/// SMALL state is at most this many bytes (design §4.3).
pub const MAX_SMALL_STATE: usize = 4_096;
static ZEROS: [u8; MAX_SMALL_STATE] = [0; MAX_SMALL_STATE];

pub const KIND_STEP_DESCEND: u8 = 1;
pub const KIND_OUT_DESCEND: u8 = 2;

pub const TEMPLATE_DOMAIN: &[u8] = b"dcg.template.id.v2.1-skeleton\x00";
pub const MIN_WINDOW: u64 = 1;
pub const MAX_WINDOW: u64 = 10_000_000;
pub const MAX_LEAF: usize = 1_100;
/// A depth-5 reveal (1,024 bytes of hashes) does not fit one transaction and
/// reveals are not staged yet, so depth is capped at 4 (review B3).
pub const MAX_REVEAL_DEPTH: u8 = 4;
/// The design's wall-time floor for a phase (§8.3): about 30 s at 40 ms.
pub const MIN_PHASE_WINDOW: u64 = 750;

struct Syscall;
impl D::Sha256 for Syscall {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        sha256(parts)
    }
}
const H: Syscall = Syscall;

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(0x6600 + code)
}

fn u16_at(d: &[u8], at: usize) -> Result<u16, ProgramError> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(err(1))
}
fn u32_at(d: &[u8], at: usize) -> Result<u32, ProgramError> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or(err(1))
}
fn u64_at(d: &[u8], at: usize) -> Result<u64, ProgramError> {
    d.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).ok_or(err(1))
}
fn key32(d: &[u8], at: usize) -> Result<[u8; 32], ProgramError> {
    d.get(at..at + 32).map(|b| b.try_into().unwrap()).ok_or(err(1))
}

/// Create (or adopt a pre-funded, empty, system-owned) PDA.
fn create_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    space: usize,
) -> ProgramResult {
    let (expected, bump) = Pubkey::find_program_address(seeds, program_id);
    if expected != *target.key {
        return Err(err(2));
    }
    if *target.owner != solana_program::system_program::id() || !target.data_is_empty() {
        return Err(err(3));
    }
    let bump_seed = [bump];
    let mut signer: [&[u8]; 6] = [&[]; 6];
    signer[..seeds.len()].copy_from_slice(seeds);
    signer[seeds.len()] = &bump_seed;
    let signer = &signer[..seeds.len() + 1];
    let need = Rent::get()?.minimum_balance(space);
    if target.lamports() == 0 {
        return invoke_signed(
            &system_instruction::create_account(payer.key, target.key, need, space as u64, program_id),
            &[payer.clone(), target.clone(), system.clone()],
            &[signer],
        );
    }
    if target.lamports() < need {
        invoke(
            &system_instruction::transfer(payer.key, target.key, need - target.lamports()),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    invoke_signed(&system_instruction::allocate(target.key, space as u64), &[target.clone(), system.clone()], &[signer])?;
    invoke_signed(&system_instruction::assign(target.key, program_id), &[target.clone(), system.clone()], &[signer])
}

fn derived(program_id: &Pubkey, account: &AccountInfo, seeds: &[&[u8]]) -> ProgramResult {
    if account.owner != program_id || Pubkey::find_program_address(seeds, program_id).0 != *account.key {
        return Err(err(2));
    }
    Ok(())
}

fn now() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

// ---------------------------------------------------------------------------
// Template "D21T": magic(4) depth(1) pad(3) total_steps(8) total_outputs(8)
// challenge_window(8) phase_window(8) executor_bond(8) challenger_bond(8)
// out_spec_base(4) step_spec_base(4) spec_root(32) template_id(32)
// slasher_bps(2) pad(6) plan_id(32); byte 134 is the tracked-template
// retired flag (old templates and newly-created templates start at zero).
// block_count(1) pad(7)
// blocks[104 x MAX_BLOCKS] = 1,008 bytes;
// New PDA ["dcg21tmpl", template_id, payer]; old templates retain their original PDA. The bases are the spec-tree leaf indices of
// OutSpec(0) and StepSpec(0) (2 + in_count, and BlockSpec.first_record).
// Create data without blocks (the step-1 form) means one enumerated block of
// `total_steps` at address 0; with blocks, it is followed by
// block_count:u8 and the BlockSpec records, all part of the template id.

const T_FIXED: usize = 168;
const T_BLOCKS: usize = T_FIXED + 8;
const T_BYTES: usize = T_BLOCKS + Block::BYTES * MAX_BLOCKS;
// New templates append provenance and a live-run count. Existing T_BYTES
// templates remain readable and usable, but cannot be closed because their
// payer and live-run count were never recorded.
const T_TRACKING_BYTES: usize = 40;
const T_BYTES_V2: usize = T_BYTES + T_TRACKING_BYTES;
const T_TRACKING_MAGIC: &[u8; 4] = b"D21O";
const T_TRACKING: usize = T_BYTES;
const T_PAYER: usize = T_TRACKING + 4;
const T_ACTIVE_RUNS: usize = T_PAYER + 32;
const T_RETIRED: usize = 134;

struct Template {
    depth: u32,
    total_steps: u64,
    total_outputs: u64,
    challenge_window: u64,
    phase_window: u64,
    executor_bond: u64,
    challenger_bond: u64,
    out_spec_base: u64,
    step_spec_base: u64,
    spec_root: [u8; 32],
    slasher_bps: u64,
    plan_id: [u8; 32],
    /// On the heap: SBF stack frames are 4 KiB.
    blocks: Vec<Block>,
    /// The step tree's height (§6.2).
    height: u32,
    /// LX1 templates (byte 5 = 1) carry their machine binding.
    lx: Option<lx::LxBinding>,
}

impl Template {
    fn blocks(&self) -> &[Block] {
        &self.blocks
    }
    fn block_of(&self, ordinal: u64) -> Result<(usize, Block), ProgramError> {
        self.blocks().iter().enumerate().find(|(_, b)| b.contains(ordinal)).map(|(i, b)| (i, *b)).ok_or(err(19))
    }
    fn ordinal_at(&self, position: u64) -> Option<u64> {
        self.blocks().iter().find_map(|b| b.ordinal_at(position))
    }
    fn position_of(&self, ordinal: u64) -> Result<u64, ProgramError> {
        Ok(self.block_of(ordinal)?.1.position_of(ordinal))
    }
}

/// Check a template's blocks: each parses, bases and records are contiguous
/// from 0, placement is the derived one (§6.2), they cover `total_steps`.
/// Returns the step tree's height.
fn check_blocks(blocks: &[Block], total_steps: u64) -> Result<u32, ProgramError> {
    let (mut base, mut end) = (0u64, 0u64);
    let mut first_record = blocks.first().ok_or(err(6))?.first_record;
    for b in blocks {
        let h = b.derived_height();
        if b.base != base
            || b.first_record != first_record
            || b.address_height as u32 != h
            || blocks::place_after(end, h) != Some(b.address_base)
        {
            return Err(err(6));
        }
        base = base.checked_add(b.step_count).ok_or(err(6))?;
        first_record = first_record.checked_add(b.record_count).ok_or(err(6))?;
        end = b.address_base.checked_add(1u64 << h).ok_or(err(6))?;
    }
    let height = blocks::height_for(end);
    if base != total_steps || height > 40 {
        return Err(err(6));
    }
    Ok(height)
}

fn template(program_id: &Pubkey, account: &AccountInfo) -> Result<Template, ProgramError> {
    let d = account.try_borrow_data()?;
    if (d.len() != T_BYTES && d.len() != T_BYTES_V2) || &d[0..4] != b"D21T" {
        return Err(err(4));
    }
    if d.len() == T_BYTES_V2
        && (&d[T_TRACKING..T_TRACKING + 4] != T_TRACKING_MAGIC
            || d[T_PAYER..T_PAYER + 32] == [0; 32]
            || d[T_RETIRED] > 1)
    {
        return Err(err(4));
    }
    let old_address = Pubkey::find_program_address(&[b"dcg21tmpl", &d[96..128]], program_id).0;
    let new_address = (d.len() == T_BYTES_V2).then(|| Pubkey::find_program_address(
        &[b"dcg21tmpl", &d[96..128], &d[T_PAYER..T_PAYER + 32]], program_id,
    ).0);
    if account.owner != program_id || (*account.key != old_address && new_address != Some(*account.key)) {
        return Err(err(2));
    }
    let block_count = d[T_FIXED] as usize;
    if !(1..=MAX_BLOCKS).contains(&block_count) {
        return Err(err(4));
    }
    let list = (0..block_count)
        .map(|i| Block::parse(&d[T_BLOCKS + Block::BYTES * i..T_BLOCKS + Block::BYTES * (i + 1)]))
        .collect::<Option<Vec<Block>>>()
        .ok_or(err(4))?;
    let height = check_blocks(&list, u64_at(&d, 8)?)?;
    let lx = match d[lx::T_KIND] {
        0 => None,
        lx::TEMPLATE_KIND_LX => Some(lx::parse_tail(&d[lx::T_LX..lx::T_LX + lx::LX_TAIL_BYTES]).ok_or(err(4))?),
        _ => return Err(err(4)),
    };
    Ok(Template {
        blocks: list,
        height,
        lx,
        depth: d[4] as u32,
        total_steps: u64_at(&d, 8)?,
        total_outputs: u64_at(&d, 16)?,
        challenge_window: u64_at(&d, 24)?,
        phase_window: u64_at(&d, 32)?,
        executor_bond: u64_at(&d, 40)?,
        challenger_bond: u64_at(&d, 48)?,
        out_spec_base: u32_at(&d, 56)? as u64,
        step_spec_base: u32_at(&d, 60)? as u64,
        spec_root: key32(&d, 64)?,
        slasher_bps: u16_at(&d, 128)? as u64,
        plan_id: key32(&d, 136)?,
    })
}

/// Whether a template has the close-tracking extension. Old templates have
/// no reliable payer or live-run count, so they are deliberately uncloseable.
fn tracked_template(account: &AccountInfo) -> Result<Option<u32>, ProgramError> {
    let d = account.try_borrow_data()?;
    if d.len() == T_BYTES {
        return Ok(None);
    }
    if d.len() != T_BYTES_V2
        || &d[T_TRACKING..T_TRACKING + 4] != T_TRACKING_MAGIC
        || d[T_PAYER..T_PAYER + 32] == [0; 32]
    {
        return Err(err(4));
    }
    Ok(Some(u32_at(&d, T_ACTIVE_RUNS)?))
}

fn template_retired(account: &AccountInfo) -> Result<bool, ProgramError> {
    let d = account.try_borrow_data()?;
    if d.len() == T_BYTES {
        return Ok(false);
    }
    if d.len() != T_BYTES_V2
        || &d[T_TRACKING..T_TRACKING + 4] != T_TRACKING_MAGIC
        || d[T_RETIRED] > 1
    {
        return Err(err(4));
    }
    Ok(d[T_RETIRED] == 1)
}

fn change_template_run_count(template: &AccountInfo, delta: i8) -> ProgramResult {
    if !template.is_writable {
        return Err(err(35));
    }
    let mut d = template.try_borrow_mut_data()?;
    if d.len() != T_BYTES_V2 || &d[T_TRACKING..T_TRACKING + 4] != T_TRACKING_MAGIC {
        return Err(err(4));
    }
    let count = u32_at(&d, T_ACTIVE_RUNS)?;
    let next = match delta {
        1 => count.checked_add(1).ok_or(err(8))?,
        -1 => count.checked_sub(1).ok_or(err(37))?,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    d[T_ACTIVE_RUNS..T_ACTIVE_RUNS + 4].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

// Run "D21R": magic(4) status(1) pad(3) template(32) payer(32) executor(32)
// run_id(32) commit_slot(8) deadline(8) open_disputes(4) n_ext(4)
// run_root_bytes(176) then external refs (52 each). PDA ["dcg21run", run_id,
// payer]. Before commit, `deadline` is the commit deadline.
const R_STATUS: usize = 4;
const R_TEMPLATE: usize = 8;
const R_PAYER: usize = 40;
const R_EXECUTOR: usize = 72;
const R_RUN_ID: usize = 104;
const R_COMMIT: usize = 136;
const R_DEADLINE: usize = 144;
const R_OPEN: usize = 152;
const R_NEXT: usize = 156; // external ref count
const R_SEQ: usize = 160; // next dispute sequence
const R_PREFIX: usize = 168; // ruled prefix: smallest sequence not yet ruled
const R_BEST: usize = 176; // lowest-sequence challenger win (u64::MAX: none)
const R_PAID: usize = 184; // pot paid (u8)
const R_CLOSED: usize = 188; // disputes closed (u32); a run closes when this reaches R_SEQ
const R_ROOT: usize = 192;
const R_REFS: usize = R_ROOT + D::RUN_ROOT_BYTES;
// After the external refs: waiting_E:u32. Each dispute stores its own deadline.
const R_LOAD_BYTES: usize = 4;

pub const RUN_OPEN: u8 = 0;
pub const RUN_COMMITTED: u8 = 1;
pub const RUN_FINAL: u8 = 2;
pub const RUN_REFUTED: u8 = 3;

fn run_checked(program_id: &Pubkey, run: &AccountInfo, template: &AccountInfo) -> ProgramResult {
    let d = run.try_borrow_data()?;
    if d.len() < R_REFS || &d[0..4] != b"D21R" || d[R_TEMPLATE..R_TEMPLATE + 32] != template.key.to_bytes() {
        return Err(err(5));
    }
    let refs_end = R_REFS.checked_add((u32_at(&d, R_NEXT)? as usize).checked_mul(52).ok_or(err(8))?).ok_or(err(8))?;
    if d.len() == refs_end {
        // A run created before the 4-byte executor-wait trailer (DCG main
        // before the follow-up B fix) cannot be served by this image. Upgrade
        // in place only after every run is finalized or refuted, paid and
        // closed (design §8.3, re-review M1).
        solana_program::msg!("v2.1 run size {} predates the wait trailer; drain all runs before an in-place upgrade", d.len());
        return Err(err(40));
    }
    if d.len() != refs_end.checked_add(R_LOAD_BYTES).ok_or(err(8))? { return Err(err(8)); }
    derived(program_id, run, &[b"dcg21run", &d[R_RUN_ID..R_RUN_ID + 32], &d[R_PAYER..R_PAYER + 32]])
}

// Dispute "D21D": magic(4) phase(1) kind(1) ruling(1) depth(1) level(4)
// pad(4) position(8) deadline(8) challenger(32) run(32) current(32)
// revealed_count(2) pad(6) revealed[32 x 32] leaf_len(2) leaf_present(1) pad(5) leaf[MAX_LEAF]
const D_PHASE: usize = 4;
const D_KIND: usize = 5;
const D_RULING: usize = 6;
const D_DEPTH: usize = 7;
const D_LEVEL: usize = 8;
const D_POSITION: usize = 16;
const D_DEADLINE: usize = 24;
const D_CHALLENGER: usize = 32;
const D_RUN: usize = 64;
const D_CURRENT: usize = 96;
const D_REVEALED_N: usize = 128;
const D_SEQ: usize = 136;
const D_REVEALED: usize = 144;
const D_LEAF_LEN: usize = D_REVEALED + 32 * 32;
const D_LEAF_PRESENT: usize = D_LEAF_LEN + 2;
const D_LEAF: usize = D_LEAF_LEN + 8;
const D_NONCE: usize = D_LEAF + MAX_LEAF;
const D_BYTES: usize = D_NONCE + 32;

const PH_NODES: u8 = 1; // E reveals
const PH_PICK: u8 = 2; // C picks
const PH_LEAF: u8 = 3; // E reveals the leaf
const PH_CLAIM: u8 = 4; // C claims
const PH_RULED: u8 = 5;

/// Tag 227. STEP claims resolve application kernels from `manifest`, the
/// static manifest of the image that embeds this program.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    match data.get(1).copied().ok_or(ProgramError::InvalidInstructionData)? {
        SUB_CREATE_TEMPLATE => create_template(program_id, accounts, &data[2..]),
        #[cfg(feature = "test-legacy-template-create")]
        SUB_TEST_CREATE_LEGACY_TEMPLATE => create_template_inner(program_id, accounts, &data[2..], false),
        SUB_INIT_RUN => init_run(program_id, accounts, &data[2..]),
        SUB_COMMIT => commit(program_id, accounts, &data[2..], manifest),
        SUB_OPEN => open(program_id, accounts, &data[2..], manifest),
        lx::SUB_LX_MIDPOINTS => lx::midpoints(program_id, accounts, &data[2..]),
        lx::SUB_LX_PICK => lx::pick(program_id, accounts, &data[2..]),
        lx::SUB_LX_OPENING => lx::opening(program_id, accounts, &data[2..], manifest),
        lx::SUB_LX_OUTPUT => lx::output(program_id, accounts, &data[2..], manifest),
        lx::SUB_LX_PRESTAGE => prestage(program_id, accounts, &data[2..]),
        SUB_REVEAL_NODES => reveal_nodes(program_id, accounts, &data[2..]),
        SUB_PICK => pick(program_id, accounts, &data[2..]),
        SUB_REVEAL_LEAF => reveal_leaf(program_id, accounts, &data[2..]),
        SUB_CLAIM => claim(program_id, accounts, &data[2..], manifest),
        SUB_TIMEOUT => timeout(program_id, accounts),
        SUB_FINALIZE => finalize(program_id, accounts),
        SUB_ADVANCE => advance(program_id, accounts),
        SUB_MOOT => moot(program_id, accounts),
        SUB_PAY_POT => pay_pot(program_id, accounts),
        SUB_STAGE_CREATE => stage_create(program_id, accounts, &data[2..]),
        SUB_STAGE_WRITE => stage_write(program_id, accounts, &data[2..]),
        SUB_CACHE_ANSWER => cache_answer(program_id, accounts),
        SUB_STAGE_GROW => stage_grow(program_id, accounts, &data[2..]),
        SUB_CLOSE_DISPUTE if data.len() == 2 => close_dispute(program_id, accounts),
        SUB_CLOSE_RUN if data.len() == 2 => close_run(program_id, accounts),
        SUB_CLOSE_CACHE if data.len() == 2 => close_cache(program_id, accounts),
        SUB_CLOSE_TEMPLATE if data.len() == 2 => close_template(program_id, accounts),
        SUB_RETIRE_TEMPLATE if data.len() == 2 => retire_template(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// 1: [admitter(s,w), template(w), system] depth:u8 total_steps:u64
// total_outputs:u64 challenge_window:u64 phase_window:u64 executor_bond:u64
// challenger_bond:u64 out_spec_base:u32 step_spec_base:u32 spec_root[32]
// slasher_bps:u16 (< 10,000: the remainder deterrent, design §10.3) plan_id[32]
fn create_template(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    create_template_inner(program_id, accounts, data, true)
}

fn create_template_inner(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], track_close: bool) -> ProgramResult {
    let [admitter, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    const FIXED: usize = 1 + 6 * 8 + 8 + 32 + 2 + 32;
    if !admitter.is_signer || data.len() < FIXED {
        return Err(ProgramError::InvalidInstructionData);
    }
    let depth = data[0];
    let (cw, pw) = (u64_at(data, 17)?, u64_at(data, 25)?);
    let total_steps = u64_at(data, 1)?;
    if !(1..=MAX_REVEAL_DEPTH).contains(&depth)
        || !(MIN_WINDOW..=MAX_WINDOW).contains(&cw)
        || !(MIN_PHASE_WINDOW..=MAX_WINDOW).contains(&pw)
        || total_steps == 0
        || total_steps > 1 << 40
        || u16_at(data, 89)? >= 10_000
        // Nonzero bonds (review 10-03, F4): the remainder deterrent (§10.3)
        // and the price of opening a dispute need both.
        || u64_at(data, 33)? == 0
        || u64_at(data, 41)? == 0
    {
        return Err(err(6));
    }
    // LX1 templates (design v2.1-lazy-expansion §8) append a "DLX1" tail
    // instead of blocks: one default block of one step and no descent
    // outputs. The spec-root field holds the machine's `constants_root`
    // (§13; zero for a machine without constants).
    let lx_tail = (data.len() == FIXED + lx::LX_TAIL_BYTES && data[FIXED..].starts_with(lx::LX_TAIL_MAGIC))
        .then(|| &data[FIXED..]);
    if let Some(tail) = lx_tail {
        if lx::parse_tail(tail).is_none() || total_steps != 1 || u64_at(data, 9)? != 0 {
            return Err(err(6));
        }
    }
    // The blocks are optional. An ignored trailing word is not a distinct template.
    let block_data_end = if data.len() == FIXED || lx_tail.is_some() {
        FIXED
    } else {
        let count = data[FIXED] as usize;
        let end = FIXED + 1 + Block::BYTES * count;
        if !(1..=MAX_BLOCKS).contains(&count) || data.len() != end {
            return Err(ProgramError::InvalidInstructionData);
        }
        end
    };
    let blocks: Vec<Block> = if block_data_end > FIXED {
        let count = data[FIXED] as usize;
        (0..count)
            .map(|i| Block::parse(&data[FIXED + 1 + Block::BYTES * i..FIXED + 1 + Block::BYTES * (i + 1)]))
            .collect::<Option<Vec<Block>>>()
            .ok_or(err(6))?
    } else {
        vec![Block::parse(&default_block(total_steps, u32_at(data, 53)? as u64)).ok_or(err(6))?]
    };
    let count = blocks.len();
    check_blocks(&blocks, total_steps)?;
    let template_id = sha256(&[TEMPLATE_DOMAIN, data]);
    let template_bytes = if track_close { T_BYTES_V2 } else { T_BYTES };
    if track_close {
        create_pda(program_id, admitter, tmpl, system, &[b"dcg21tmpl", &template_id, admitter.key.as_ref()], template_bytes)?;
    } else {
        create_pda(program_id, admitter, tmpl, system, &[b"dcg21tmpl", &template_id], template_bytes)?;
    }
    let mut d = tmpl.try_borrow_mut_data()?;
    d[T_FIXED] = count as u8;
    if block_data_end > FIXED {
        d[T_BLOCKS..T_BLOCKS + Block::BYTES * count].copy_from_slice(&data[FIXED + 1..block_data_end]);
    } else {
        d[T_BLOCKS..T_BLOCKS + Block::BYTES].copy_from_slice(&default_block(total_steps, u32_at(data, 53)? as u64));
    }
    d[0..4].copy_from_slice(b"D21T");
    d[4] = depth;
    d[8..64].copy_from_slice(&data[1..57]);
    d[64..96].copy_from_slice(&data[57..89]);
    d[128..130].copy_from_slice(&data[89..91]);
    d[136..168].copy_from_slice(&data[91..123]);
    d[96..128].copy_from_slice(&template_id);
    if let Some(tail) = lx_tail {
        d[lx::T_KIND] = lx::TEMPLATE_KIND_LX;
        d[lx::T_LX..lx::T_LX + lx::LX_TAIL_BYTES].copy_from_slice(tail);
    }
    if track_close {
        d[T_TRACKING..T_TRACKING + 4].copy_from_slice(T_TRACKING_MAGIC);
        d[T_PAYER..T_PAYER + 32].copy_from_slice(admitter.key.as_ref());
        d[T_ACTIVE_RUNS..T_ACTIVE_RUNS + 4].copy_from_slice(&0u32.to_le_bytes());
        d[T_RETIRED] = 0;
    }
    Ok(())
}

/// The step-1 template's single enumerated block.
fn default_block(total_steps: u64, first_record: u64) -> [u8; Block::BYTES] {
    let mut b = [0u8; Block::BYTES];
    b[0..4].copy_from_slice(b"DBK1");
    b[4] = 1;
    b[16..24].copy_from_slice(&total_steps.to_le_bytes());
    b[40..48].copy_from_slice(&first_record.to_le_bytes());
    b[48..56].copy_from_slice(&total_steps.to_le_bytes());
    b[64] = blocks::height_for(total_steps) as u8;
    b
}

// 2: [payer(s,w), run(w), template, system] nonce[32] executor[32] n:u32 refs[52 n]
fn init_run(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, run, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let t = template(program_id, tmpl)?;
    let active_runs = tracked_template(tmpl)?;
    if template_retired(tmpl)? {
        return Err(err(37));
    }
    if active_runs.is_some() && !tmpl.is_writable {
        return Err(err(35));
    }
    let next_active_runs = active_runs.map(|n| n.checked_add(1).ok_or(err(8))).transpose()?;
    let n = u32_at(data, 64)? as usize;
    let refs = data.get(68..68 + n * 52).ok_or(err(1))?;
    if data.len() != 68 + n * 52 {
        return Err(err(1));
    }
    // External refs are sorted by strictly increasing external id (design
    // §12); EDGE kind 2 looks a ref up by id, never by position (review B2).
    for i in 1..n {
        if u32_at(refs, 52 * i)? <= u32_at(refs, 52 * (i - 1))? {
            return Err(err(31));
        }
    }
    if payer.key.as_ref() == &data[32..64] {
        // The payer receives the remainder; an executor paying itself
        // removes the deterrent (design §10.3).
        return Err(err(31));
    }
    let template_id = key32(&tmpl.try_borrow_data()?, 96)?;
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &data[0..32], &(n as u32).to_le_bytes(), refs, &data[32..64]]);
    // The payer is part of the run's address (review 10-03, F5): a cancelled
    // run cannot be re-initialized at the same address by someone else.
    create_pda(program_id, payer, run, system, &[b"dcg21run", &run_id, payer.key.as_ref()], R_REFS + refs.len() + R_LOAD_BYTES)?;
    let mut d = run.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"D21R");
    d[R_TEMPLATE..R_TEMPLATE + 32].copy_from_slice(tmpl.key.as_ref());
    d[R_PAYER..R_PAYER + 32].copy_from_slice(payer.key.as_ref());
    d[R_EXECUTOR..R_EXECUTOR + 32].copy_from_slice(&data[32..64]);
    d[R_RUN_ID..R_RUN_ID + 32].copy_from_slice(&run_id);
    d[R_NEXT..R_NEXT + 4].copy_from_slice(&(n as u32).to_le_bytes());
    d[R_BEST..R_BEST + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    // Until commit, the deadline is the commit deadline: the executor commits
    // within the template's challenge window; after it, the payer may cancel.
    let commit_deadline = now()?.checked_add(t.challenge_window).ok_or(err(8))?;
    d[R_DEADLINE..R_DEADLINE + 8].copy_from_slice(&commit_deadline.to_le_bytes());
    d[R_REFS..R_REFS + refs.len()].copy_from_slice(refs);
    drop(d);
    if let Some(next) = next_active_runs {
        let mut t = tmpl.try_borrow_mut_data()?;
        t[T_ACTIVE_RUNS..T_ACTIVE_RUNS + 4].copy_from_slice(&next.to_le_bytes());
    }
    Ok(())
}

// 3: [executor(s,w), run(w), template, system] run_root_bytes[176]
fn commit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [executor, run, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    {
        let d = run.try_borrow_data()?;
        if !executor.is_signer || d[R_EXECUTOR..R_EXECUTOR + 32] != executor.key.to_bytes() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if d[R_STATUS] != RUN_OPEN || now()? > u64_at(&d, R_DEADLINE)? {
            return Err(err(7));
        }
    }
    let lx_root;
    let root: &[u8; D::RUN_ROOT_BYTES] = if let Some(binding) = &t.lx {
        lx_root = lx::check_commit(&t, binding, manifest, run, tmpl, data)?;
        &lx_root
    } else {
        let root: &[u8; D::RUN_ROOT_BYTES] = data.try_into().map_err(|_| err(1))?;
        let rr = D::RunRoot(root);
        let d = run.try_borrow_data()?;
        if rr.run_id() != &d[R_RUN_ID..R_RUN_ID + 32]
            || rr.plan_id() != t.plan_id
            || rr.spec_root() != t.spec_root
            || rr.total_steps() != t.total_steps
            || rr.total_outputs() != t.total_outputs
        {
            return Err(err(7));
        }
        root
    };
    if t.executor_bond > 0 {
        invoke(&system_instruction::transfer(executor.key, run.key, t.executor_bond), &[executor.clone(), run.clone(), system.clone()])?;
    }
    let slot = now()?;
    let mut d = run.try_borrow_mut_data()?;
    d[R_ROOT..R_REFS].copy_from_slice(root);
    d[R_STATUS] = RUN_COMMITTED;
    d[R_COMMIT..R_COMMIT + 8].copy_from_slice(&slot.to_le_bytes());
    let deadline = slot.checked_add(t.challenge_window).ok_or(err(8))?;
    d[R_DEADLINE..R_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

fn tree_height(n: u64) -> u32 {
    if n <= 1 { 0 } else { 64 - (n - 1).leading_zeros() }
}

// 4: [challenger(s,w), run(w), template, dispute(w), system] nonce[32] kind:u8
fn open(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [challenger, run, tmpl, dispute, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    if let Some(binding) = t.lx {
        return lx::open(program_id, accounts, data, &t, &binding, manifest);
    }
    if !challenger.is_signer || data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[32];
    let (status, deadline, root) = {
        let d = run.try_borrow_data()?;
        (d[R_STATUS], u64_at(&d, R_DEADLINE)?, <[u8; D::RUN_ROOT_BYTES]>::try_from(&d[R_ROOT..R_REFS]).unwrap())
    };
    if status != RUN_COMMITTED || now()? > deadline {
        return Err(err(9));
    }
    let rr = D::RunRoot(&root);
    let (level, current) = match kind {
        KIND_STEP_DESCEND => (t.height, key32(&root, 104)?),
        KIND_OUT_DESCEND => (tree_height(t.total_outputs), key32(&root, 144)?),
        _ => return Err(err(10)),
    };
    let _ = rr;
    let (sequence, deadline) = open_record(program_id, challenger, run, dispute, system, &t, &data[..32], true)?;
    let mut d = dispute.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"D21D");
    d[D_PHASE] = if level == 0 { PH_LEAF } else { PH_NODES };
    d[D_KIND] = kind;
    d[D_DEPTH] = t.depth as u8;
    d[D_LEVEL..D_LEVEL + 4].copy_from_slice(&level.to_le_bytes());
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    d[D_CHALLENGER..D_CHALLENGER + 32].copy_from_slice(challenger.key.as_ref());
    d[D_RUN..D_RUN + 32].copy_from_slice(run.key.as_ref());
    d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&current);
    d[D_SEQ..D_SEQ + 8].copy_from_slice(&sequence.to_le_bytes());
    d[D_NONCE..D_NONCE + 32].copy_from_slice(&data[..32]);
    Ok(())
}

/// Create a dispute record, take the challenger's bond, and take its place in
/// the run's sequence. A dispute that starts by waiting on the executor
/// enters an executor wait, whose deadline is returned (zero otherwise).
fn open_record<'a>(
    program_id: &Pubkey,
    challenger: &AccountInfo<'a>,
    run: &AccountInfo<'a>,
    dispute: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    t: &Template,
    nonce: &[u8],
    waits_on_executor: bool,
) -> Result<(u64, u64), ProgramError> {
    create_pda(program_id, challenger, dispute, system, &[b"dcg21dsp", run.key.as_ref(), challenger.key.as_ref(), nonce], D_BYTES)?;
    if t.challenger_bond > 0 {
        invoke(&system_instruction::transfer(challenger.key, dispute.key, t.challenger_bond), &[challenger.clone(), dispute.clone(), system.clone()])?;
    }
    let (sequence, deadline) = {
        let mut r = run.try_borrow_mut_data()?;
        let open = u32_at(&r, R_OPEN)?.checked_add(1).ok_or(err(8))?;
        r[R_OPEN..R_OPEN + 4].copy_from_slice(&open.to_le_bytes());
        let deadline = if waits_on_executor { begin_executor_wait(&mut r, t)? } else { 0 };
        let seq = u64_at(&r, R_SEQ)?;
        r[R_SEQ..R_SEQ + 8].copy_from_slice(&seq.checked_add(1).ok_or(err(8))?.to_le_bytes());
        (seq, deadline)
    };
    dispute.try_borrow_mut_data()?[D_SEQ..D_SEQ + 8].copy_from_slice(&sequence.to_le_bytes());
    Ok((sequence, deadline))
}

/// The descent instructions act only on descent disputes (kinds 1 and 2).
fn descent_only(dispute: &AccountInfo) -> ProgramResult {
    if dispute.try_borrow_data()?[D_KIND] > KIND_OUT_DESCEND {
        return Err(err(10));
    }
    Ok(())
}

struct Ctx<'a, 'b> {
    t: Template,
    run: &'a AccountInfo<'b>,
    dispute: &'a AccountInfo<'b>,
}

fn dispute_ctx<'a, 'b>(program_id: &Pubkey, run: &'a AccountInfo<'b>, tmpl: &AccountInfo<'b>, dispute: &'a AccountInfo<'b>) -> Result<Ctx<'a, 'b>, ProgramError> {
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    let d = dispute.try_borrow_data()?;
    if d.len() != D_BYTES || &d[0..4] != b"D21D" || d[D_RUN..D_RUN + 32] != run.key.to_bytes() {
        return Err(err(11));
    }
    // A dispute is accepted only at its derived address (review B1): a
    // program-owned account holding D21D bytes is not a dispute.
    derived(program_id, dispute, &[b"dcg21dsp", run.key.as_ref(), &d[D_CHALLENGER..D_CHALLENGER + 32], &d[D_NONCE..D_NONCE + 32]])?;
    drop(d);
    Ok(Ctx { t, run, dispute })
}

fn expect_phase(d: &[u8], phase: u8, _run: &AccountInfo) -> ProgramResult {
    if d[D_PHASE] != phase {
        return Err(err(12));
    }
    if Clock::get()?.slot > u64_at(d, D_DEADLINE)? {
        return Err(err(13));
    }
    Ok(())
}

fn load_offset(r: &[u8]) -> Result<usize, ProgramError> {
    let at = R_REFS.checked_add((u32_at(r, R_NEXT)? as usize).checked_mul(52).ok_or(err(8))?).ok_or(err(8))?;
    if r.len() != at + R_LOAD_BYTES { return Err(err(8)); }
    Ok(at)
}

fn begin_executor_wait(r: &mut [u8], t: &Template) -> Result<u64, ProgramError> {
    let at = load_offset(r)?;
    let waiting = u32_at(r, at)?;
    // c=1, extend_slots=phase_window. Cap this phase's entire window.
    let window = t.phase_window.checked_mul(u64::from(waiting).checked_add(1).ok_or(err(8))?)
        .ok_or(err(8))?.min(MAX_WINDOW);
    let deadline = now()?.checked_add(window).ok_or(err(8))?;
    r[at..at + 4].copy_from_slice(&waiting.checked_add(1).ok_or(err(8))?.to_le_bytes());
    Ok(deadline)
}

fn end_executor_wait(r: &mut [u8]) -> ProgramResult {
    let at = load_offset(r)?;
    let waiting = u32_at(r, at)?.checked_sub(1).ok_or(err(8))?;
    r[at..at + 4].copy_from_slice(&waiting.to_le_bytes());
    Ok(())
}

fn next_phase(d: &mut [u8], phase: u8, window: u64) -> ProgramResult {
    d[D_PHASE] = phase;
    let deadline = Clock::get()?.slot.checked_add(window).ok_or(err(8))?;
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

fn executor_signed(run: &AccountInfo, who: &AccountInfo) -> ProgramResult {
    if !who.is_signer || run.try_borrow_data()?[R_EXECUTOR..R_EXECUTOR + 32] != who.key.to_bytes() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

fn challenger_signed(d: &[u8], who: &AccountInfo) -> ProgramResult {
    if !who.is_signer || d[D_CHALLENGER..D_CHALLENGER + 32] != who.key.to_bytes() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

/// Structural pickability (§7.1): the address map for the step tree, the
/// output count for the out tree.
fn pickable(t: &Template, kind: u8, level: u32, position: u64) -> bool {
    if kind == KIND_STEP_DESCEND {
        blocks::pickable(t.blocks(), level, position)
    } else {
        D::pickable(t.total_outputs, level, position)
    }
}

fn tree_of(kind: u8) -> D::Tree {
    if kind == KIND_STEP_DESCEND { D::Tree::Step } else { D::Tree::Out }
}

// 5: [executor(s), run(w), template, dispute(w)] the pickable hashes, in position order.
fn reveal_nodes(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, dispute, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    descent_only(c.dispute)?;
    executor_signed(c.run, executor)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_NODES, c.run)?;
    let level = u32_at(&d, D_LEVEL)?;
    let position = u64_at(&d, D_POSITION)?;
    let depth = (d[D_DEPTH] as u32).min(level);
    let kind = d[D_KIND];
    let first = position << depth;
    let base = level - depth;
    let mut slots = [None; 1 << D::MAX_DEPTH];
    let mut at = 0;
    for (i, slot) in slots.iter_mut().enumerate().take(1 << depth) {
        if pickable(&c.t, kind, base, first + i as u64) {
            *slot = Some(key32(data, at)?);
            at += 32;
        }
    }
    if at != data.len() {
        return Err(err(14));
    }
    let folded = D::fold_reveal_by(&H, tree_of(kind), |l, p| pickable(&c.t, kind, l, p), level, position, depth, &slots[..1 << depth])
        .ok_or(err(14))?;
    if folded != key32(&d, D_CURRENT)? {
        return Err(err(14));
    }
    let n = slots[..1 << depth].iter().filter(|s| s.is_some()).count();
    for (i, slot) in slots[..1 << depth].iter().enumerate() {
        let h = slot.unwrap_or([0; 32]);
        d[D_REVEALED + 32 * i..D_REVEALED + 32 * (i + 1)].copy_from_slice(&h);
    }
    d[D_REVEALED_N..D_REVEALED_N + 2].copy_from_slice(&(n as u16).to_le_bytes());
    if let [cache, system, ..] = rest {
        // Optional: record this verified answer for every other dispute at
        // the same node. The executor pays its rent.
        let level_b = level.to_le_bytes();
        let pos_b = position.to_le_bytes();
        let seeds: [&[u8]; 5] = [b"dcg21rc", c.run.key.as_ref(), &[kind], &level_b, &pos_b];
        if cache.data_is_empty() {
            create_pda(program_id, executor, cache, system, &seeds, CACHE_BYTES_V2)?;
            let mut k = cache.try_borrow_mut_data()?;
            k[0..4].copy_from_slice(b"D21C");
            k[4] = kind;
            k[5] = depth as u8;
            k[8..12].copy_from_slice(&level_b);
            k[16..24].copy_from_slice(&pos_b);
            k[24..56].copy_from_slice(&d[D_CURRENT..D_CURRENT + 32]);
            k[56..CACHE_BYTES].copy_from_slice(&d[D_REVEALED..D_REVEALED + 32 * 32]);
            k[CACHE_BYTES..CACHE_BYTES_V2].copy_from_slice(executor.key.as_ref());
        }
    }
    end_executor_wait(&mut c.run.try_borrow_mut_data()?)?;
    next_phase(&mut d, PH_PICK, c.t.phase_window)
}

// 16: [anyone, run(w), template, dispute(w), cache] answer AWAIT_NODES from a
// cached, verified reveal of the same node.
fn cache_answer(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, cache, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    descent_only(c.dispute)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_NODES, c.run)?;
    let k = cache.try_borrow_data()?;
    let level = u32_at(&d, D_LEVEL)?;
    let position = u64_at(&d, D_POSITION)?;
    let kind = d[D_KIND];
    if (k.len() != CACHE_BYTES && k.len() != CACHE_BYTES_V2) || &k[0..4] != b"D21C" {
        return Err(err(30));
    }
    derived(program_id, cache, &[b"dcg21rc", c.run.key.as_ref(), &[kind], &level.to_le_bytes(), &position.to_le_bytes()])?;
    // The node hash must match too: the cache answers this node only.
    if k[4] != kind || k[5] != d[D_DEPTH].min(level as u8) || k[24..56] != d[D_CURRENT..D_CURRENT + 32] {
        return Err(err(30));
    }
    let depth = k[5] as u32;
    let first = position << depth;
    let n = (0..1u64 << depth).filter(|i| pickable(&c.t, kind, level - depth, first + i)).count();
    d[D_REVEALED..D_REVEALED + 32 * 32].copy_from_slice(&k[56..CACHE_BYTES]);
    d[D_REVEALED_N..D_REVEALED_N + 2].copy_from_slice(&(n as u16).to_le_bytes());
    end_executor_wait(&mut c.run.try_borrow_mut_data()?)?;
    next_phase(&mut d, PH_PICK, c.t.phase_window)
}

// 6: [challenger(s), run(w), template, dispute(w)] index:u8
fn pick(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    descent_only(c.dispute)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    challenger_signed(&d, challenger)?;
    expect_phase(&d, PH_PICK, c.run)?;
    let index = *data.first().ok_or(err(1))? as u64;
    let level = u32_at(&d, D_LEVEL)?;
    let depth = (d[D_DEPTH] as u32).min(level);
    let position = u64_at(&d, D_POSITION)?;
    if index >= 1 << depth || !pickable(&c.t, d[D_KIND], level - depth, (position << depth) + index) {
        return Err(err(15));
    }
    let chosen = key32(&d, D_REVEALED + 32 * index as usize)?;
    let new_level = level - depth;
    d[D_LEVEL..D_LEVEL + 4].copy_from_slice(&new_level.to_le_bytes());
    d[D_POSITION..D_POSITION + 8].copy_from_slice(&((position << depth) + index).to_le_bytes());
    d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&chosen);
    let deadline = begin_executor_wait(&mut c.run.try_borrow_mut_data()?, &c.t)?;
    d[D_PHASE] = if new_level == 0 { PH_LEAF } else { PH_NODES };
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

// 14: [challenger(s,w), run, template, dispute, buffer(w), system] role:u8 size:u32
fn stage_create(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, buffer, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let role = *data.first().ok_or(err(1))?;
    if c.dispute.try_borrow_data()?[D_PHASE] == PH_RULED { return Err(err(37)); }
    // C funds both buffers; E may create its own if C has not (review).
    let by_challenger = challenger_signed(&c.dispute.try_borrow_data()?, challenger).is_ok();
    if !by_challenger && !(role == ROLE_EXECUTOR && executor_signed(c.run, challenger).is_ok()) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let size = if role == ROLE_EXECUTOR { CREATE_STAGE } else { u32_at(data, 1)? as usize };
    if !(role == ROLE_EXECUTOR || role == ROLE_CHALLENGER) || size == 0 || size > CREATE_STAGE || data.len() != 5 {
        return Err(err(29));
    }
    create_pda(program_id, challenger, buffer, system, &[b"dcg21stg", c.dispute.key.as_ref(), &[role]], STAGE_HEADER + size)?;
    let mut b = buffer.try_borrow_mut_data()?;
    b[0..4].copy_from_slice(b"D21S");
    b[4] = role;
    // Who paid the creation rent, for the close: 0 the challenger, 1 the executor.
    b[5] = u8::from(!by_challenger);
    b[8..40].copy_from_slice(c.dispute.key.as_ref());
    Ok(())
}

// 27: staged dispute open (owner decision 8a). The challenger's staging
// buffer for a dispute it has not opened yet: `dispute` is the address
// ["dcg21dsp", run, challenger, nonce] and must still be unopened (empty).
// - op 0 create `size:u32`, op 1 write `offset:u32 bytes`:
//   [challenger(s,w), run, template, dispute, buffer(w), system] nonce[32] op;
//   the challenger alone, while the run is committed and in its window.
// - op 2 close: [caller(s), run, template, dispute, buffer(w), challenger(w)]
//   nonce[32] op; by the challenger at any time, or by anyone once the run
//   can no longer be disputed (final, refuted, a receipt, or gone). The rent
//   returns to the challenger (review 10-05: a buffer must never strand once
//   its run is closed into a receipt).
// The staged bytes are masked (`LX_PRESTAGE_MASK_DOMAIN`) by a secret that only
// the OPEN carries, so the buffer does not reveal the divergence before the
// open lands (review 10-05: a copycat could otherwise open first and take
// the first-divergence reward). An LX1 OPEN reads its body from this buffer;
// after the open it is the dispute's ordinary challenger buffer (grown by
// sub 17, written by sub 15, closed with the dispute by sub 18). No dispute
// state, bond or deadline changes until OPEN.
fn prestage(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [signer, run, tmpl, dispute, buffer, last, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let nonce = data.get(0..32).ok_or(err(1))?;
    let op = *data.get(32).ok_or(err(1))?;
    // op 2 names the challenger in account 5; ops 0 and 1 are signed by it.
    let challenger = if op == 2 { last } else { signer };
    if Pubkey::find_program_address(&[b"dcg21dsp", run.key.as_ref(), challenger.key.as_ref(), nonce], program_id).0 != *dispute.key {
        return Err(err(2));
    }
    if !dispute.data_is_empty() || dispute.owner == program_id {
        return Err(err(37)); // opened: use the dispute's own staging ops
    }
    if Pubkey::find_program_address(&[b"dcg21stg", dispute.key.as_ref(), &[ROLE_CHALLENGER]], program_id).0 != *buffer.key {
        return Err(err(29));
    }
    if op == 2 {
        if data.len() != 33 || buffer.owner != program_id || staging_role(program_id, dispute, buffer)? != ROLE_CHALLENGER {
            return Err(err(29));
        }
        if signer.key != challenger.key && disputable(program_id, run)? {
            return Err(err(37));
        }
        return close_into(buffer, challenger);
    }
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    if t.lx.is_none() {
        return Err(err(10)); // only an LX1 open reads a staged body
    }
    match op {
        0 => {
            let size = u32_at(data, 33)? as usize;
            if data.len() != 37 || size == 0 || size > CREATE_STAGE {
                return Err(err(29));
            }
            if !disputable(program_id, run)? {
                return Err(err(9)); // staging for a dispute that can no longer open
            }
            create_pda(program_id, challenger, buffer, system_of(last)?, &[b"dcg21stg", dispute.key.as_ref(), &[ROLE_CHALLENGER]], STAGE_HEADER + size)?;
            let mut b = buffer.try_borrow_mut_data()?;
            b[0..4].copy_from_slice(b"D21S");
            b[4] = ROLE_CHALLENGER;
            b[5] = 0; // the challenger paid the creation rent
            b[8..40].copy_from_slice(dispute.key.as_ref());
            Ok(())
        }
        1 => {
            if buffer.owner != program_id || staging_role(program_id, dispute, buffer)? != ROLE_CHALLENGER {
                return Err(err(29));
            }
            let offset = u32_at(data, 33)? as usize;
            let bytes = data.get(37..).ok_or(err(1))?;
            let mut b = buffer.try_borrow_mut_data()?;
            let end = offset.checked_add(bytes.len()).ok_or(err(8))?;
            if STAGE_HEADER + end > b.len() {
                return Err(err(29));
            }
            b[STAGE_HEADER + offset..STAGE_HEADER + end].copy_from_slice(bytes);
            let len = (u32_at(&b, 40)? as usize).max(end);
            b[40..44].copy_from_slice(&(len as u32).to_le_bytes());
            Ok(())
        }
        _ => Err(err(29)),
    }
}

fn system_of<'a, 'b>(account: &'a AccountInfo<'b>) -> Result<&'a AccountInfo<'b>, ProgramError> {
    if *account.key != solana_program::system_program::id() {
        return Err(err(29));
    }
    Ok(account)
}

/// Whether a new dispute could still open on `run`: a live run record,
/// committed, inside its challenge window. A run that is final, refuted, a
/// receipt or gone cannot be disputed again.
fn disputable(program_id: &Pubkey, run: &AccountInfo) -> Result<bool, ProgramError> {
    if run.owner != program_id || run.data_is_empty() {
        return Ok(false);
    }
    let r = run.try_borrow_data()?;
    if r.len() < R_REFS || &r[0..4] != b"D21R" {
        return Ok(false); // a receipt (D21P)
    }
    Ok(r[R_STATUS] == RUN_COMMITTED && now()? <= u64_at(&r, R_DEADLINE)?)
}

// 17: [funder(s,w), run, template, dispute, buffer(w), system] add:u32 (at most
// 10 KiB). Grows a staging buffer; anyone may pay for the growth.
fn stage_grow(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [funder, run, tmpl, dispute, buffer, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let role = staging_role(program_id, c.dispute, buffer)?;
    stage_mutable_for_role(c.dispute, role)?;
    let add = u32_at(data, 0)? as usize;
    let new_len = buffer.data_len().checked_add(add).ok_or(err(8))?;
    if !funder.is_signer || add == 0 || add > 10_240 || new_len > STAGE_HEADER + MAX_STAGE || data.len() != 4 {
        return Err(err(29));
    }
    let need = Rent::get()?.minimum_balance(new_len).saturating_sub(buffer.lamports());
    if need > 0 {
        invoke(&system_instruction::transfer(funder.key, buffer.key, need), &[funder.clone(), buffer.clone(), system.clone()])?;
    }
    buffer.resize(new_len)
}

// 15: [writer(s), run, template, dispute, buffer(w)] offset:u32 bytes. Any
// time, by the buffer's owner (E for role 1, C for role 2).
fn stage_write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [writer, run, tmpl, dispute, buffer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let role = staging_role(program_id, c.dispute, buffer)?;
    stage_mutable_for_role(c.dispute, role)?;
    if role == ROLE_EXECUTOR {
        executor_signed(c.run, writer)?;
    } else {
        challenger_signed(&c.dispute.try_borrow_data()?, writer)?;
    }
    let offset = u32_at(data, 0)? as usize;
    let bytes = &data[4..];
    let mut b = buffer.try_borrow_mut_data()?;
    let end = offset.checked_add(bytes.len()).ok_or(err(8))?;
    if STAGE_HEADER + end > b.len() {
        return Err(err(29));
    }
    b[STAGE_HEADER + offset..STAGE_HEADER + end].copy_from_slice(bytes);
    let len = (u32_at(&b, 40)? as usize).max(end);
    b[40..44].copy_from_slice(&(len as u32).to_le_bytes());
    Ok(())
}

/// Once E reveals a leaf, its list refs are authenticated by that leaf's list
/// digests and the staged reveal bytes become immutable for this dispute.
/// C's buffer remains writable while making its claim.
fn stage_mutable_for_role(dispute: &AccountInfo, role: u8) -> ProgramResult {
    let phase = dispute.try_borrow_data()?[D_PHASE];
    if phase == PH_RULED || (role == ROLE_EXECUTOR && phase >= PH_CLAIM) {
        return Err(err(37));
    }
    Ok(())
}

fn staging_role(program_id: &Pubkey, dispute: &AccountInfo, buffer: &AccountInfo) -> Result<u8, ProgramError> {
    let b = buffer.try_borrow_data()?;
    if b.len() < STAGE_HEADER || &b[0..4] != b"D21S" || b[8..40] != dispute.key.to_bytes() {
        return Err(err(29));
    }
    let role = b[4];
    derived(program_id, buffer, &[b"dcg21stg", dispute.key.as_ref(), &[role]])?;
    Ok(role)
}

const LIST_REVEAL_MAGIC: &[u8; 4] = b"LVR1";

/// Staged list reveal: `LVR1 present:u8 leaf_len:u16 leaf list_count:u8`,
/// then `(input_index:u8 count:u8 refs[55*count])*`. Legacy staged leaf
/// reveals remain `[present:u8 leaf]` and cannot carry list inputs.
fn decode_leaf_reveal(data: &[u8]) -> Result<(u8, &[u8], Vec<(usize, Vec<[u8; D::VALUE_REF_BYTES]>)>, bool), ProgramError> {
    if data.starts_with(LIST_REVEAL_MAGIC) {
        let present = *data.get(4).ok_or(err(1))?;
        let len = u16_at(data, 5)? as usize;
        let leaf_end = 7usize.checked_add(len).ok_or(err(8))?;
        let body = data.get(7..leaf_end).ok_or(err(1))?;
        let n = *data.get(leaf_end).ok_or(err(1))? as usize;
        let mut at = leaf_end + 1;
        let mut lists = Vec::with_capacity(n);
        let mut previous = None;
        for _ in 0..n {
            let input = *data.get(at).ok_or(err(1))? as usize;
            let count = *data.get(at + 1).ok_or(err(1))? as usize;
            at += 2;
            if count == 0 || count > D::MAX_LIST_ELEMENTS || previous.is_some_and(|p| p >= input) {
                return Err(err(16));
            }
            previous = Some(input);
            let bytes = count.checked_mul(D::VALUE_REF_BYTES).ok_or(err(8))?;
            let raw = data.get(at..at + bytes).ok_or(err(1))?;
            let refs = raw.chunks_exact(D::VALUE_REF_BYTES)
                .map(|r| <[u8; D::VALUE_REF_BYTES]>::try_from(r).unwrap()).collect();
            lists.push((input, refs));
            at += bytes;
        }
        if at != data.len() {
            return Err(err(16));
        }
        Ok((present, body, lists, true))
    } else {
        let present = *data.first().ok_or(err(1))?;
        Ok((present, &data[1..], Vec::new(), false))
    }
}

/// Validate list refs against the list-layout inputs in a step leaf. This is
/// called both when E reveals and when C claims, so mutating E's staging
/// buffer after reveal cannot change the authenticated refs.
fn validate_leaf_lists(
    present: u8,
    body: &[u8],
    lists: Vec<(usize, Vec<[u8; D::VALUE_REF_BYTES]>)>,
    framed: bool,
) -> Result<Vec<Vec<[u8; D::VALUE_REF_BYTES]>>, ProgramError> {
    let Some(leaf) = (present == 1).then(|| D::parse_leaf(body)).flatten() else {
        if !lists.is_empty() {
            return Err(err(16));
        }
        return Ok(Vec::new());
    };
    let mut lists = lists.into_iter();
    let mut result = Vec::with_capacity(leaf.input_count());
    let mut total_elements = 0usize;
    for i in 0..leaf.input_count() {
        let r = leaf.input(i);
        let layout = u32::from_le_bytes(r[7..11].try_into().unwrap());
        if layout != D::LAYOUT_LIST {
            result.push(Vec::new());
            continue;
        }
        if !framed {
            return Err(err(16));
        }
        let (index, refs) = lists.next().ok_or(err(16))?;
        if index != i || refs.is_empty() || refs.len() > D::MAX_LIST_ELEMENTS {
            return Err(err(16));
        }
        total_elements = total_elements.checked_add(refs.len()).ok_or(err(8))?;
        if total_elements > D::MAX_LIST_ELEMENTS_PER_STEP {
            return Err(err(16));
        }
        if D::list_digest_elements(&H, &refs).is_none_or(|digest| digest.as_slice() != &r[23..55]) {
            return Err(err(16));
        }
        result.push(refs);
    }
    if lists.next().is_some() {
        return Err(err(16));
    }
    Ok(result)
}

fn staged_leaf_lists(
    program_id: &Pubkey,
    dispute: &AccountInfo,
    buffer: &AccountInfo,
    expected_present: u8,
    expected_leaf: &[u8],
) -> Result<Vec<Vec<[u8; D::VALUE_REF_BYTES]>>, ProgramError> {
    if staging_role(program_id, dispute, buffer)? != ROLE_EXECUTOR {
        return Err(err(29));
    }
    let b = buffer.try_borrow_data()?;
    let len = u32_at(&b, 40)? as usize;
    let end = STAGE_HEADER.checked_add(len).ok_or(err(8))?;
    let raw = b.get(STAGE_HEADER..end).ok_or(err(29))?;
    let (present, body, lists, framed) = decode_leaf_reveal(raw)?;
    if !framed || present != expected_present || body != expected_leaf {
        return Err(err(29));
    }
    validate_leaf_lists(present, body, lists, framed)
}

// 7: [executor(s), run(w), template, dispute(w)] present:u8 preimage
fn reveal_leaf(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, dispute, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    descent_only(c.dispute)?;
    executor_signed(c.run, executor)?;
    let staged;
    let from_staging = data == [FROM_STAGING];
    let data: &[u8] = if from_staging {
        let buffer = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if staging_role(program_id, c.dispute, buffer)? != ROLE_EXECUTOR {
            return Err(err(29));
        }
        staged = buffer.try_borrow_data()?;
        let len = u32_at(&staged, 40)? as usize;
        let end = STAGE_HEADER.checked_add(len).ok_or(err(8))?;
        staged.get(STAGE_HEADER..end).ok_or(err(29))?
    } else {
        data
    };
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_LEAF, c.run)?;
    let (present, body, list_reveals, framed) = decode_leaf_reveal(data)?;
    if present > 1 || (present == 0 && !body.is_empty()) || body.len() > MAX_LEAF {
        return Err(err(16));
    }
    if present == 1 {
        validate_leaf_lists(present, body, list_reveals, framed)?;
    } else if !list_reveals.is_empty() {
        return Err(err(16));
    }
    if !from_staging && present == 1 {
        if let Some(leaf) = D::parse_leaf(body) {
            if (0..leaf.input_count()).any(|i| u32::from_le_bytes(leaf.input(i)[7..11].try_into().unwrap()) == D::LAYOUT_LIST) {
                return Err(err(16));
            }
        }
    }
    let position = u64_at(&d, D_POSITION)?;
    let h = if d[D_KIND] == KIND_STEP_DESCEND {
        D::leaf_hash(&H, (present == 1).then_some(body))
    } else {
        D::out_leaf(&H, position, (present == 1).then_some(body))
    };
    if h != key32(&d, D_CURRENT)? {
        return Err(err(16));
    }
    d[D_LEAF_LEN..D_LEAF_LEN + 2].copy_from_slice(&(body.len() as u16).to_le_bytes());
    d[D_LEAF_PRESENT] = present;
    d[D_LEAF..D_LEAF + body.len()].copy_from_slice(body);
    end_executor_wait(&mut c.run.try_borrow_mut_data()?)?;
    next_phase(&mut d, PH_CLAIM, c.t.phase_window)
}

/// Parse a spec opening `type:u8 len:u16 record path_len:u8 path[32 x]` and
/// check it at `leaf_index` against the template's spec root.
fn spec_record<'a>(t: &Template, data: &'a [u8], at: &mut usize, leaf_index: u64) -> Result<(u8, &'a [u8]), ProgramError> {
    let type_code = *data.get(*at).ok_or(err(1))?;
    let len = u16_at(data, *at + 1)? as usize;
    let record = data.get(*at + 3..*at + 3 + len).ok_or(err(1))?;
    let path = read_path(data, *at + 3 + len)?;
    *at += 3 + len + 1 + 32 * path.1;
    let leaf = D::spec_leaf(&H, type_code, record);
    if D::root_from_path(&H, D::Tree::Spec, &leaf, leaf_index, &path.0[..path.1]) != t.spec_root {
        return Err(err(17));
    }
    Ok((type_code, record))
}

fn read_path(data: &[u8], at: usize) -> Result<(Vec<D::Hash>, usize), ProgramError> {
    let n = *data.get(at).ok_or(err(1))? as usize;
    if n > 48 {
        return Err(err(1));
    }
    let out = (0..n).map(|i| key32(data, at + 1 + 32 * i)).collect::<Result<Vec<_>, _>>()?;
    Ok((out, n))
}

/// A leaf of the committed step tree at an ordinal's address:
/// `present:u8 len:u16 preimage path_len:u8 path`.
fn step_opening<'a>(t: &Template, root: &[u8], data: &'a [u8], at: &mut usize, ordinal: u64) -> Result<Option<&'a [u8]>, ProgramError> {
    let position = t.position_of(ordinal)?;
    let present = *data.get(*at).ok_or(err(1))?;
    let len = u16_at(data, *at + 1)? as usize;
    let pre = data.get(*at + 3..*at + 3 + len).ok_or(err(1))?;
    let path = read_path(data, *at + 3 + len)?;
    *at += 3 + len + 1 + 32 * path.1;
    let leaf = D::leaf_hash(&H, (present == 1).then_some(pre));
    if D::root_from_path(&H, D::Tree::Step, &leaf, position, &path.0[..path.1]).as_slice() != &root[104..136] {
        return Err(err(18));
    }
    Ok((present == 1).then_some(pre))
}

// 8: [challenger(s), run(w), template, dispute(w), executor(w), challenger_account(w)]
// claim:u8 index:u8 spec_opening, then by claim (design §7.3):
//   SHAPE  -
//   EDGE   kind 1: step_opening(producer); kind 2, 7: -; kind 3: const_opening;
//          kind 8: element:u8 list_spec_index:u32 list_spec_opening, then
//                  kind 1: step_opening(producer), kind 3: const_opening;
//          kind 5: [const_opening, from a constant] chunk_opening; kind 6: last_running(t)
//   GATE   step_opening(gate leaf of iteration i-1) gate_value
//   STATE  kind 1 predecessor: step_opening
//   STEP   n:u8; each ordinary input has one (len:u32 bytes), and a list
//          input has one pair per element; then prior state if stateful.
//   OUT    kind 1: step_opening(producer); kind 6: last_running(t)
// step_opening = present:u8 len:u16 preimage path_len:u8 path;
// chunk_opening = len:u16 chunk path_len:u8 path;
// gate_value = len:u8 bytes (len 0 when the gate leaf is empty);
// const_opening = leaf_index:u32 spec_opening (of the constant's ConstSpec);
// last_running(t) = t:u32 step_opening(leaf (B, t, e')) and, unless
// t = K - 1, step_opening(gate leaf (B, t, g)) gate_value.
fn claim(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [challenger, run, tmpl, dispute, executor_acct, _challenger_acct, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    descent_only(c.dispute)?;
    let claim_from_staging = data == [FROM_STAGING];
    let staged;
    let data: &[u8] = if claim_from_staging {
        let buffer = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if staging_role(program_id, c.dispute, buffer)? != ROLE_CHALLENGER {
            return Err(err(29));
        }
        staged = buffer.try_borrow_data()?;
        let len = u32_at(&staged, 40)? as usize;
        staged.get(STAGE_HEADER..STAGE_HEADER.checked_add(len).ok_or(err(8))?).ok_or(err(1))?
    } else {
        data
    };
    let (kind, position, present, leaf_buf) = {
        let d = c.dispute.try_borrow_data()?;
        challenger_signed(&d, challenger)?;
        expect_phase(&d, PH_CLAIM, c.run)?;
        let len = u16_at(&d, D_LEAF_LEN)? as usize;
        let buf = d[D_LEAF..D_LEAF + len].to_vec();
        (d[D_KIND], u64_at(&d, D_POSITION)?, d[D_LEAF_PRESENT] == 1, (buf, len))
    };
    let leaf_bytes = &leaf_buf.0[..];
    let leaf_list_refs = if let Some(leaf) = D::parse_leaf(leaf_bytes) {
        let has_lists = (0..leaf.input_count()).any(|i| {
            u32::from_le_bytes(leaf.input(i)[7..11].try_into().unwrap()) == D::LAYOUT_LIST
        });
        if has_lists {
            let executor_buffer = rest.get(if claim_from_staging { 1 } else { 0 }).ok_or(ProgramError::NotEnoughAccountKeys)?;
            staged_leaf_lists(program_id, c.dispute, executor_buffer, 1, leaf_bytes)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let root: [u8; D::RUN_ROOT_BYTES] = c.run.try_borrow_data()?[R_ROOT..R_REFS].try_into().unwrap();
    let refs_buf = c.run.try_borrow_data()?;
    let refs_end = load_offset(&refs_buf)?;
    let refs = &refs_buf[R_REFS..refs_end];
    let k = Referee { t: &c.t, root: &root, refs, data, list_refs: &leaf_list_refs, manifest };
    let name = *data.first().ok_or(err(1))?;
    let index = *data.get(1).ok_or(err(1))? as usize;
    let mut at = 2;
    let mut neutral = false;
    let winner_is_challenger = if kind == KIND_OUT_DESCEND {
        // OUT(j): the spec's OutSpec(j), then the producer leaf.
        let (_t, record) = spec_record(&c.t, data, &mut at, out_spec_leaf_index(&c.t, position)?)?;
        if record.len() != 56 || &record[0..4] != b"DOU1" {
            return Err(err(17));
        }
        let (pk, p, port, entry, _) = D::producer(&record[32..56]);
        let entry_ok = present && leaf_bytes.len() == 55 && leaf_bytes[..23] == record[8..31];
        if !entry_ok {
            true
        } else {
            match pk {
                1 => match step_opening(&c.t, &root, data, &mut at, p)?.and_then(D::parse_leaf) {
                    None => true,
                    Some(prod) => match prod.output_port(port as u16) {
                        None => true,
                        Some(o) => leaf_bytes[23..55] != o[23..55],
                    },
                },
                6 => match k.last_running_port(&mut at, p, port, entry)? {
                    None => false,
                    Some(o) => leaf_bytes[23..55] != o[23..55],
                },
                _ => return Err(err(19)),
            }
        }
    } else {
        let ordinal = c.t.ordinal_at(position).ok_or(err(19))?;
        let (bi, block) = c.t.block_of(ordinal)?;
        let (it, entry) = block.split(ordinal);
        let (_t, stored) = spec_record(&c.t, data, &mut at, block.first_record + entry)?;
        let mut generated = vec![0u8; stored.len()];
        let record: &[u8] = if block.kind == 1 {
            stored
        } else {
            if !blocks::generate(stored, &block, it, &mut generated) {
                return Err(err(17));
            }
            &generated
        };
        let spec = D::StepSpec(record);
        if !spec.valid() {
            return Err(err(17));
        }
        let gated = block.kind == 2 && it >= 1;
        // Every LOG STATE and STEP claim is neutral (moot) until LOG is judged
        // on chain: the program sees only the spec root, so it cannot refuse a
        // LOG chain that changes scheme or capacity (re-review A1).
        if !present {
            // Empty is a violation unless the step is gated; then GATE decides.
            if !gated {
                true
            } else if name != CLAIM_GATE {
                return Err(err(19));
            } else {
                k.gate_says(&mut at, bi, &block, it, false)?
            }
        } else {
            match D::parse_leaf(leaf_bytes) {
                // Malformed under E's own commitment: C wins.
                None => true,
                Some(leaf) => {
                    if spec.state_scheme() > 1 {
                        // Template creation commits only a spec root. It cannot
                        // inspect the predecessor's scheme or capacity, so a
                        // LOG STATE claim is unsafe to judge in this image.
                        neutral = matches!(name, CLAIM_STEP | CLAIM_STATE);
                    }
                    match name {
                    CLAIM_GATE => gated && k.gate_says(&mut at, bi, &block, it, true)?,
                    CLAIM_SHAPE => D::shape_wrong(&leaf, &spec, D::RunRoot(&root).plan_id(), D::RunRoot(&root).run_id(), ordinal),
                    CLAIM_EDGE => k.edge(&mut at, &leaf, &spec, index)?,
                    // Neutral claims are not evaluated.
                    CLAIM_STATE | CLAIM_STEP if neutral => false,
                    CLAIM_STATE => k.state(&mut at, &leaf, &spec)?,
                    CLAIM_STEP => k.step(&mut at, &leaf, &spec)?,
                    _ => return Err(err(19)),
                    }
                },
            }
        }
    };
    drop(refs_buf);
    rule(&c, executor_acct, challenger, if neutral { Outcome::Neutral } else { winner_is_challenger.into() })
}

/// The claim rules (§7.3) over one claim's data. Each returns whether C
/// wins; a party's own malformed submission is an error (it may retry).
struct Referee<'a> {
    t: &'a Template,
    root: &'a [u8; D::RUN_ROOT_BYTES],
    refs: &'a [u8],
    data: &'a [u8],
    list_refs: &'a [Vec<[u8; D::VALUE_REF_BYTES]>],
    manifest: &'static crate::kernel::ApplicationManifest,
}

impl<'a> Referee<'a> {
    fn external_ref(&self, id: u64) -> Option<&'a [u8]> {
        self.refs.chunks_exact(52).find(|r| u32::from_le_bytes(r[0..4].try_into().unwrap()) as u64 == id)
    }

    /// A constant's `ConstSpec`, opened as `leaf_index:u32 spec_opening`. The
    /// index lies between the BlockSpecs and the OutSpecs (where ConstSpec
    /// and InSpec records sit), the record is a ConstSpec, and its id is the
    /// producer's. Spec leaves are typed, so this pins the constant.
    fn constant(&self, at: &mut usize, id: u64) -> Result<Vec<u8>, ProgramError> {
        let index = u32_at(self.data, *at)? as u64;
        *at += 4;
        if index < 1 + self.t.blocks().len() as u64 || index >= self.t.out_spec_base {
            return Err(err(34));
        }
        let (type_code, record) = spec_record(self.t, self.data, at, index)?;
        if type_code != 3 || record.len() != 104 || &record[..4] != b"DCN1" || u32_at(record, 4)? as u64 != id {
            return Err(err(34));
        }
        Ok(record.to_vec())
    }

    fn opening(&self, at: &mut usize, ordinal: u64) -> Result<Option<&'a [u8]>, ProgramError> {
        step_opening(self.t, self.root, self.data, at, ordinal)
    }

    /// `len:u8 bytes`, checked against the gate port's digest; None when the
    /// port is missing (malformed: the caller decides).
    fn gate_value(&self, at: &mut usize, gate_leaf: &D::Leaf, port: u16) -> Result<Option<i32>, ProgramError> {
        let len = *self.data.get(*at).ok_or(err(1))? as usize;
        let bytes = self.data.get(*at + 1..*at + 1 + len).ok_or(err(1))?;
        *at += 1 + len;
        let Some(r) = gate_leaf.output_port(port) else { return Ok(None) };
        if len != 4 || D::value_digest(&H, bytes) != r[23..55] {
            return Err(err(33));
        }
        Ok(Some(i32::from_le_bytes(bytes.try_into().unwrap())))
    }

    /// GATE (R2-S1): C wins when the leaf's presence disagrees with the gate
    /// of the previous iteration.
    fn gate_says(&self, at: &mut usize, _bi: usize, block: &Block, it: u64, present: bool) -> Result<bool, ProgramError> {
        let g = block.ordinal(it - 1, block.gate_entry as u64);
        let expected = match self.opening(at, g)? {
            None => {
                *at += 1; // an empty gate leaf carries a zero-length value
                false
            }
            Some(raw) => match D::parse_leaf(raw) {
                None => return Ok(true),
                Some(gate_leaf) => match self.gate_value(at, &gate_leaf, block.gate_port)? {
                    None => return Ok(true),
                    Some(v) => v != 0,
                },
            },
        };
        Ok(present != expected)
    }

    /// Kind 6 (§3.4, R3-S1): port `port` of entry `entry` at C's named
    /// iteration t, if t is the last running iteration of block `b` by the
    /// (honest, earlier) leaves; None means E wins.
    fn last_running_port(&self, at: &mut usize, b: u64, port: u32, entry: u32) -> Result<Option<[u8; 55]>, ProgramError> {
        let t = u32_at(self.data, *at)? as u64;
        *at += 4;
        let block = *self.t.blocks().get(b as usize).ok_or(err(19))?;
        if block.kind != 2 || entry >= block.body_len || t >= block.k as u64 {
            return Ok(None);
        }
        let leaf = match self.opening(at, block.ordinal(t, entry as u64))?.and_then(D::parse_leaf) {
            None => return Ok(None),
            Some(l) => l,
        };
        if t != block.k as u64 - 1 {
            let gate_leaf = match self.opening(at, block.ordinal(t, block.gate_entry as u64))?.and_then(D::parse_leaf) {
                None => return Ok(None),
                Some(g) => g,
            };
            if self.gate_value(at, &gate_leaf, block.gate_port)? != Some(0) {
                return Ok(None);
            }
        }
        Ok(leaf.output_port(port as u16).map(|o| o.try_into().unwrap()))
    }

    fn edge(&self, at: &mut usize, leaf: &D::Leaf, spec: &D::StepSpec, index: usize) -> Result<bool, ProgramError> {
        if index >= spec.input_count() || index >= leaf.input_count() {
            return Err(err(19));
        }
        let got = leaf.input(index);
        let header = spec.input_header(index);
        let (pk, a, b, c, d) = spec.input_producer(index);
        if pk == D::PRODUCER_LIST {
            return self.list_edge(at, index, a);
        }
        Ok(match pk {
            // The spec names an input the run never posted: C wins.
            2 => self.external_ref(a).is_none_or(|r| got[7..55] != r[4..52]),
            1 => match self.opening(at, a)?.and_then(D::parse_leaf) {
                None => true,
                Some(prod) => prod.output_port(b as u16).is_none_or(|o| got[7..55] != o[7..55]),
            },
            3 => {
                let record = self.constant(at, a)?;
                got[7..23] != record[8 + 7..8 + 23] || got[23..55] != record[40..72]
            }
            5 => {
                let root: [u8; 32] = if b == 3 {
                    key32(&self.constant(at, a)?, 40)?
                } else {
                    let Some(r) = self.external_ref(a) else { return Ok(true) };
                    r[20..52].try_into().unwrap()
                };
                let len = u16_at(self.data, *at)? as usize;
                let chunk = self.data.get(*at + 2..*at + 2 + len).ok_or(err(1))?;
                let path = read_path(self.data, *at + 2 + len)?;
                *at += 2 + len + 1 + 32 * path.1;
                let leaf_hash = D::chunk_leaf(&H, d as u64, chunk);
                if D::root_from_path(&H, D::Tree::Chunk, &leaf_hash, d as u64, &path.0[..path.1]) != root {
                    return Err(err(32));
                }
                got[23..55] != D::value_digest(&H, chunk) || got[7..23] != header[7..23]
            }
            6 => match self.last_running_port(at, a, b, c)? {
                None => false,
                Some(o) => got[7..55] != o[7..55],
            },
            7 => got[23..55] != D::value_digest(&H, &(a as u32).to_le_bytes()),
            _ => return Err(err(19)),
        })
    }

    /// EDGE(i,j) opens the committed ListSpec and checks one E-revealed ref
    /// against its element header and one ordinary producer opening.
    fn list_edge(&self, at: &mut usize, input: usize, list_id: u64) -> Result<bool, ProgramError> {
        let element = *self.data.get(*at).ok_or(err(1))? as usize;
        *at += 1;
        let index = u32_at(self.data, *at)? as u64;
        *at += 4;
        if list_id > u32::MAX as u64 {
            return Err(err(17));
        }
        let (type_code, record) = spec_record(self.t, self.data, at, index)?;
        let list = D::ListSpec(record);
        if type_code != D::TYPE_LIST || !list.valid() || list.id() as u64 != list_id {
            return Err(err(17));
        }
        if element >= list.count() {
            return Err(err(19));
        }
        let Some(input_refs) = self.list_refs.get(input) else { return Ok(true) };
        if input_refs.len() != list.count() {
            return Ok(true);
        }
        let got = &input_refs[element];
        let header = list.element_header(element);
        if got[..D::PORT_HEADER_BYTES] != *header {
            return Ok(true);
        }
        let (pk, a, b, _c, _d) = list.element_producer(element);
        Ok(match pk {
            1 => match self.opening(at, a)?.and_then(D::parse_leaf) {
                None => true,
                Some(prod) => prod.output_port(b as u16).is_none_or(|o| got[7..55] != o[7..55]),
            },
            2 => self.external_ref(a).is_none_or(|r| got[7..55] != r[4..52]),
            3 => {
                let c = self.constant(at, a)?;
                got[7..23] != c[15..31] || got[23..55] != c[40..72]
            }
            _ => return Err(err(19)),
        })
    }

    fn state(&self, at: &mut usize, leaf: &D::Leaf, spec: &D::StepSpec) -> Result<bool, ProgramError> {
        if spec.state_scheme() == 0 {
            return Ok(false);
        }
        let (pk, a, _, _, _) = spec.state_predecessor();
        Ok(match pk {
            1 => match self.opening(at, a)?.and_then(D::parse_leaf) {
                None => true,
                Some(p) => leaf.prior != p.next,
            },
            2 => self.external_ref(a).is_none_or(|r| *leaf.prior != r[20..52]),
            _ => {
                let size = spec.state_size() as usize;
                let zeros = ZEROS.get(..size).ok_or(err(19))?;
                *leaf.prior != D::value_digest(&H, zeros)
            }
        })
    }

    fn step(&self, at: &mut usize, leaf: &D::Leaf, spec: &D::StepSpec) -> Result<bool, ProgramError> {
        let n = *self.data.get(*at).ok_or(err(1))? as usize;
        *at += 1;
        if n != leaf.input_count() || n != spec.input_count() || n > 8 {
            return Err(err(20));
        }
        let list_capacity: usize = self.list_refs.iter().map(Vec::len).sum();
        let mut ins = Vec::with_capacity(n + list_capacity.min(D::MAX_LIST_ELEMENTS_PER_STEP));
        let mut total_list_elements = 0usize;
        for i in 0..n {
            let (kind, _, _, _, _) = spec.input_producer(i);
            if kind == D::PRODUCER_LIST {
                let refs = self.list_refs.get(i).ok_or(err(20))?;
                if refs.is_empty() || refs.len() > D::MAX_LIST_ELEMENTS {
                    return Err(err(20));
                }
                total_list_elements = total_list_elements.checked_add(refs.len()).ok_or(err(8))?;
                if total_list_elements > D::MAX_LIST_ELEMENTS_PER_STEP {
                    return Err(err(20));
                }
                for r in refs {
                    let len = u32_at(self.data, *at)? as usize;
                    let end = (*at).checked_add(4).and_then(|x| x.checked_add(len)).ok_or(err(8))?;
                    let v = self.data.get(*at + 4..end).ok_or(err(1))?;
                    *at = end;
                    if D::value_digest(&H, v) != r[23..55] {
                        return Err(err(20));
                    }
                    ins.push(v);
                }
            } else {
                let len = u32_at(self.data, *at)? as usize;
                let end = (*at).checked_add(4).and_then(|x| x.checked_add(len)).ok_or(err(8))?;
                let v = self.data.get(*at + 4..end).ok_or(err(1))?;
                *at = end;
                if D::value_digest(&H, v) != leaf.input(i)[23..55] {
                    return Err(err(20));
                }
                ins.push(v);
            }
        }
        let prior = if spec.state_scheme() != 0 {
            let len = u32_at(self.data, *at)? as usize;
            let v = self.data.get(*at + 4..*at + 4 + len).ok_or(err(1))?;
            *at += 4 + len;
            if D::value_digest(&H, v) != *leaf.prior {
                return Err(err(20));
            }
            Some(v)
        } else {
            None
        };
        if D::reductions::lookup(spec.kernel_id()).is_some() {
            // A refused replay cannot carry committed outputs: C wins.
            let Some(r) = D::reductions::replay(spec.kernel_id(), &ins, prior) else { return Ok(true) };
            return Ok(r.output_count != leaf.output_count()
                || (0..r.output_count).any(|i| D::value_digest(&H, r.output(i)) != leaf.output(i)[23..55])
                || r.next().is_some_and(|nx| D::value_digest(&H, nx) != *leaf.next));
        }
        if prior.is_some() {
            return Ok(true); // no stateful kernel by that id
        }
        // An application kernel, resolved by id and versions from the
        // embedding image's manifest: one output, stateless (this slice).
        let id = crate::kernel::KernelId(spec.kernel_id().try_into().unwrap());
        // Only a kernel that advertises the v2.1 STEP mode replays a step
        // (review 10-03, F2): other manifest kernels are unknown here.
        let step_kernel = self
            .manifest
            .resolve(id, spec.semantic_version(), spec.abi_version())
            .filter(|k| k.manifest().modes.contains(&crate::kernel::MODE_STEP_V21));
        if let Some(kernel) = step_kernel {
            let m = kernel.manifest();
            let spans: Vec<crate::kernel::AccountSpan> = ins
                .iter()
                .map(|v| crate::kernel::AccountSpan {
                    key: [0; 32],
                    owner: [0; 32],
                    is_signer: false,
                    is_writable: false,
                    schema: m.input.id,
                    offset: 0,
                    data: v,
                })
                .collect();
            let mut out = vec![0u8; m.output.max_bytes as usize];
            return Ok(match kernel.execute_spans(&spans, &mut out) {
                Err(_) => true,
                Ok(len) => leaf.output_count() != 1 || D::value_digest(&H, &out[..len]) != leaf.output(0)[23..55],
            });
        }
        let mut out = [0u8; 4];
        // An unknown kernel cannot replay any output (as in the Python
        // referee): it rules for C.
        Ok(match kernel_code(spec.kernel_id()).ok_or(0u16).and_then(|code| dcg_kernels::execute(code, &ins, &mut out)) {
            Err(_) => true,
            Ok(_) => leaf.output_count() != 1 || D::value_digest(&H, &out) != leaf.output(0)[23..55],
        })
    }
}

/// The registered kernel whose name equals the spec's 16-byte kernel id
/// without its NUL padding (for example `identity_i32/v1`).
fn kernel_code(id: &[u8]) -> Option<u16> {
    let end = id.iter().position(|b| *b == 0).unwrap_or(id.len());
    if id[end..].iter().any(|b| *b != 0) {
        return None; // an interior NUL is not a kernel name (review 10-03, F9)
    }
    let name = &id[..end];
    (1..=255u16).find(|k| dcg_kernels::info(*k).is_some_and(|i| i.name.as_bytes() == name))
}

fn out_spec_leaf_index(t: &Template, j: u64) -> Result<u64, ProgramError> {
    t.out_spec_base.checked_add(j).ok_or(err(8))
}

/// What a claim or timeout decides. `Neutral` is a moot ruling: the
/// challenger's bond returns and nobody is convicted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Executor,
    Challenger,
    Neutral,
}

impl From<bool> for Outcome {
    fn from(challenger_wins: bool) -> Self {
        if challenger_wins { Outcome::Challenger } else { Outcome::Executor }
    }
}

fn rule(c: &Ctx, executor: &AccountInfo, challenger: &AccountInfo, outcome: impl Into<Outcome>) -> ProgramResult {
    let mut outcome = outcome.into();
    {
        // A dispute opened after the run's lowest challenger win is moot
        // (§10.1), whatever its own claim or timeout would decide: neither
        // party can take the other's bond through it (review 10-03, F1).
        let r = c.run.try_borrow_data()?;
        let d = c.dispute.try_borrow_data()?;
        if r[R_STATUS] == RUN_REFUTED && u64_at(&d, D_SEQ)? > u64_at(&r, R_BEST)? {
            outcome = Outcome::Neutral;
        }
    }
    let challenger_wins = outcome == Outcome::Challenger;
    let (seq, was_waiting) = {
        let mut d = c.dispute.try_borrow_mut_data()?;
        if d[D_RULING] != RULING_OPEN {
            return Err(err(25));
        }
        if challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32] {
            return Err(err(22));
        }
        let was_waiting = matches!(d[D_PHASE], PH_NODES | PH_LEAF);
        d[D_PHASE] = PH_RULED;
        d[D_RULING] = match outcome {
            Outcome::Challenger => RULING_CHALLENGER,
            Outcome::Executor => RULING_EXECUTOR,
            Outcome::Neutral => RULING_MOOT,
        };
        (u64_at(&d, D_SEQ)?, was_waiting)
    };
    {
        let mut r = c.run.try_borrow_mut_data()?;
        if executor.key.to_bytes() != r[R_EXECUTOR..R_EXECUTOR + 32] {
            return Err(err(22));
        }
        if r[R_STATUS] != RUN_COMMITTED && r[R_STATUS] != RUN_REFUTED {
            return Err(err(25));
        }
        if was_waiting { end_executor_wait(&mut r)?; }
        let open = u32_at(&r, R_OPEN)?.checked_sub(1).ok_or(err(8))?;
        r[R_OPEN..R_OPEN + 4].copy_from_slice(&open.to_le_bytes());
        if challenger_wins {
            // Refuted at once for consumers. The executor bond waits for the
            // ruled prefix to pass the lowest winning sequence (§10.1).
            r[R_STATUS] = RUN_REFUTED;
            if seq < u64_at(&r, R_BEST)? {
                r[R_BEST..R_BEST + 8].copy_from_slice(&seq.to_le_bytes());
            }
        }
    }
    // The challenger's bond: back to a winning or neutral challenger, to E otherwise.
    if outcome == Outcome::Executor {
        move_all(c.dispute, executor)
    } else {
        move_all(c.dispute, challenger)
    }
}

fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    **from.try_borrow_mut_lamports()? = from.lamports().checked_sub(amount).ok_or(err(8))?;
    **to.try_borrow_mut_lamports()? = to.lamports().checked_add(amount).ok_or(err(8))?;
    Ok(())
}

/// The dispute's lamports above its rent floor (the challenger bond).
fn move_all(dispute: &AccountInfo, to: &AccountInfo) -> ProgramResult {
    let floor = Rent::get()?.minimum_balance(dispute.data_len());
    let extra = dispute.lamports().saturating_sub(floor);
    if extra > 0 {
        move_lamports(dispute, to, extra)?;
    }
    Ok(())
}

// 9: [anyone, run(w), template, dispute(w), executor(w), challenger(w)] after a phase deadline.
fn timeout(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, executor, challenger, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let phase = {
        let d = c.dispute.try_borrow_data()?;
        if d[D_PHASE] == PH_RULED || Clock::get()?.slot <= u64_at(&d, D_DEADLINE)? {
            return Err(err(23));
        }
        d[D_PHASE]
    };
    // E owes NODES and LEAF; C owes PICK and CLAIM.
    let challenger_wins = matches!(phase, PH_NODES | PH_LEAF);
    rule(&c, executor, challenger, challenger_wins)
}

// 11: [anyone, run(w), template, dispute] the dispute at `ruled_prefix` is ruled or moot.
fn advance(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let (seq, ruling) = {
        let d = c.dispute.try_borrow_data()?;
        (u64_at(&d, D_SEQ)?, d[D_RULING])
    };
    let mut r = c.run.try_borrow_mut_data()?;
    let prefix = u64_at(&r, R_PREFIX)?;
    if seq != prefix || ruling == RULING_OPEN {
        return Err(err(26));
    }
    r[R_PREFIX..R_PREFIX + 8].copy_from_slice(&prefix.checked_add(1).ok_or(err(8))?.to_le_bytes());
    Ok(())
}

// 12: [anyone, run(w), template, dispute(w), challenger(w)] a dispute opened
// after the lowest challenger win on a refuted run is moot; its bond returns.
fn moot(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, challenger, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let was_waiting = {
        let mut d = c.dispute.try_borrow_mut_data()?;
        let r = c.run.try_borrow_data()?;
        if r[R_STATUS] != RUN_REFUTED
            || d[D_RULING] != RULING_OPEN
            || u64_at(&d, D_SEQ)? <= u64_at(&r, R_BEST)?
            || challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32]
        {
            return Err(err(27));
        }
        let was_waiting = matches!(d[D_PHASE], PH_NODES | PH_LEAF);
        d[D_PHASE] = PH_RULED;
        d[D_RULING] = RULING_MOOT;
        was_waiting
    };
    {
        let mut r = c.run.try_borrow_mut_data()?;
        if was_waiting { end_executor_wait(&mut r)?; }
        let open = u32_at(&r, R_OPEN)?.checked_sub(1).ok_or(err(8))?;
        r[R_OPEN..R_OPEN + 4].copy_from_slice(&open.to_le_bytes());
    }
    move_all(c.dispute, challenger)
}

// 13: [anyone, run(w), template, best dispute, challenger(w), payer(w)] once
// the ruled prefix has passed `best_win`: the slasher share of the executor
// bond to that challenger, the remainder to the run's payer.
fn pay_pot(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, challenger, payer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    {
        let d = c.dispute.try_borrow_data()?;
        let mut r = c.run.try_borrow_mut_data()?;
        let best = u64_at(&r, R_BEST)?;
        if r[R_STATUS] != RUN_REFUTED
            || r[R_PAID] != 0
            || u64_at(&r, R_PREFIX)? <= best
            || u64_at(&d, D_SEQ)? != best
            || d[D_RULING] != RULING_CHALLENGER
            || challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32]
            || payer.key.to_bytes() != r[R_PAYER..R_PAYER + 32]
        {
            return Err(err(28));
        }
        r[R_PAID] = 1;
    }
    let bond = c.t.executor_bond;
    let share = bond.checked_mul(c.t.slasher_bps).ok_or(err(8))? / 10_000;
    move_lamports(c.run, challenger, share)?;
    move_lamports(c.run, payer, bond - share)
}

// 10: [anyone, run(w), template, executor(w)] after the challenge deadline with no open dispute.
fn finalize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, executor, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    let mut d = run.try_borrow_mut_data()?;
    if d[R_STATUS] != RUN_COMMITTED || Clock::get()?.slot <= u64_at(&d, R_DEADLINE)? || u32_at(&d, R_OPEN)? != 0 {
        return Err(err(24));
    }
    if executor.key.to_bytes() != d[R_EXECUTOR..R_EXECUTOR + 32] {
        return Err(err(22));
    }
    d[R_STATUS] = RUN_FINAL;
    drop(d);
    if t.executor_bond > 0 {
        move_lamports(run, executor, t.executor_bond)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rent reclaim (tag 227 subs 18-22, 2026-10-03). Each close moves every lamport of a program
// account to the party that paid its rent, empties it and returns it to the
// system program. Bonds have already moved by then (rule, moot, pay_pot,
// finalize); a close never decides who is owed a bond.

/// Drain `account` to `to` and close it.
fn close_into(account: &AccountInfo, to: &AccountInfo) -> ProgramResult {
    if !account.is_writable || !to.is_writable || account.key == to.key {
        return Err(err(35));
    }
    let all = account.lamports();
    move_lamports(account, to, all)?;
    account.resize(0)?;
    account.assign(&solana_program::system_program::id());
    Ok(())
}

/// The run is settled: final, or refuted with the pot paid. No dispute can
/// open on it again, and its bond has moved.
fn settled(r: &[u8]) -> bool {
    r[R_STATUS] == RUN_FINAL || (r[R_STATUS] == RUN_REFUTED && r[R_PAID] != 0)
}

// 18: [anyone, run(w), template, dispute(w), challenger(w), executor(w),
// executor buffer(w), challenger buffer(w)]. A ruled or moot dispute whose
// sequence the ruled prefix has passed (so `advance` no longer needs it), and,
// if it is the run's lowest challenger win, after the pot is paid. Closes both
// staging buffers if they exist (creation rent to the party that created
// them; growth of the executor's buffer to the executor) and the dispute (its
// rent to the challenger).
fn close_dispute(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, tmpl, dispute, challenger, executor, buffer_e, buffer_c, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    {
        let d = c.dispute.try_borrow_data()?;
        let r = c.run.try_borrow_data()?;
        let seq = u64_at(&d, D_SEQ)?;
        if d[D_RULING] == RULING_OPEN
            || seq >= u64_at(&r, R_PREFIX)?
            || (r[R_STATUS] == RUN_REFUTED && seq == u64_at(&r, R_BEST)? && r[R_PAID] == 0)
            || challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32]
            || executor.key.to_bytes() != r[R_EXECUTOR..R_EXECUTOR + 32]
        {
            return Err(err(36));
        }
    }
    for (role, buffer) in [(ROLE_EXECUTOR, buffer_e), (ROLE_CHALLENGER, buffer_c)] {
        // The derived address, whether or not the buffer was ever created.
        if Pubkey::find_program_address(&[b"dcg21stg", c.dispute.key.as_ref(), &[role]], program_id).0 != *buffer.key {
            return Err(err(2));
        }
        if buffer.owner != program_id {
            continue; // never created
        }
        let creator = {
            let b = buffer.try_borrow_data()?;
            if b.len() < STAGE_HEADER || &b[0..4] != b"D21S" || b[4] != role || b[8..40] != c.dispute.key.to_bytes() {
                return Err(err(29));
            }
            b[5]
        };
        // The executor's buffer (role 1) is created at exactly CREATE_STAGE
        // bytes; when the challenger created it, the challenger gets back that
        // creation rent and every lamport above it (growth the executor paid
        // to answer, or anything pre-funded) goes to the executor. Before
        // this, a losing challenger collected the executor's growth rent (R2
        // reviews 10-05, A-H1 / B-M1).
        if role == ROLE_EXECUTOR && creator == 0 {
            let creation = Rent::get()?.minimum_balance(STAGE_HEADER + CREATE_STAGE).min(buffer.lamports());
            if !challenger.is_writable {
                return Err(err(35));
            }
            move_lamports(buffer, challenger, creation)?;
            close_into(buffer, executor)?;
        } else {
            close_into(buffer, if creator == 1 { executor } else { challenger })?;
        }
    }
    {
        let mut r = c.run.try_borrow_mut_data()?;
        let closed = u32_at(&r, R_CLOSED)?.checked_add(1).ok_or(err(8))?;
        r[R_CLOSED..R_CLOSED + 4].copy_from_slice(&closed.to_le_bytes());
    }
    close_into(c.dispute, challenger)
}

// 19: [caller(s), run(w), template(w for tracked templates), payer(w)]. A settled run whose disputes
// are all closed shrinks to its receipt (design §6.4) at the same address, so
// consumers can still read its final status and root at the run's address
// (consumers identify a run by its address: the run id alone is not unique
// across payers); anyone may send it. An uncommitted run is cancelled (closed
// whole) by anyone after the commit deadline. Freed rent always goes to the
// run's payer.
fn close_run(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [caller, run, tmpl, payer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    run_checked(program_id, run, tmpl)?;
    template(program_id, tmpl)?;
    let active_runs = tracked_template(tmpl)?;
    if let Some(count) = active_runs {
        if count == 0 || !tmpl.is_writable {
            return Err(err(37));
        }
    }
    let status = {
        let r = run.try_borrow_data()?;
        if payer.key.to_bytes() != r[R_PAYER..R_PAYER + 32] {
            return Err(err(22));
        }
        if r[R_STATUS] == RUN_OPEN {
            if !caller.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // Anyone can release an expired uncommitted run. Rent is still
            // returned to its payer, so the caller's benefit is only freeing
            // the template's run slot and allowing template close.
            if now()? <= u64_at(&r, R_DEADLINE)? {
                return Err(err(37));
            }
        } else if !settled(&r) || u32_at(&r, R_OPEN)? != 0 || u32_at(&r, R_CLOSED)? as u64 != u64_at(&r, R_SEQ)? {
            return Err(err(37));
        }
        r[R_STATUS]
    };
    if active_runs.is_some() {
        // This instruction is atomic: a later close/refund failure rolls the
        // count change back with the run mutation.
        change_template_run_count(tmpl, -1)?;
    }
    if status == RUN_OPEN {
        return close_into(run, payer);
    }
    {
        let mut r = run.try_borrow_mut_data()?;
        r.copy_within(R_ROOT..R_REFS, 136);
        r[0..4].copy_from_slice(b"D21P");
    }
    run.resize(RECEIPT_BYTES)?;
    let floor = Rent::get()?.minimum_balance(RECEIPT_BYTES);
    let extra = run.lamports().checked_sub(floor).ok_or(err(8))?;
    if !payer.is_writable {
        return Err(err(35));
    }
    move_lamports(run, payer, extra)
}

// 21: [recorded payer(s,w), template(w)]. Closing is payer-authorized to
// avoid griefing a reusable template by an executor, challenger or bystander.
// A zero active-run count means no run or dispute still needs the template.
fn close_template(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [payer, tmpl, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    template(program_id, tmpl)?;
    let Some(active_runs) = tracked_template(tmpl)? else {
        return Err(err(37));
    };
    let recorded_payer = {
        let d = tmpl.try_borrow_data()?;
        Pubkey::new_from_array(d[T_PAYER..T_PAYER + 32].try_into().unwrap())
    };
    if payer.key != &recorded_payer || active_runs != 0 {
        return Err(err(37));
    }
    close_into(tmpl, payer)
}

// 22: [recorded payer(s,w), template(w)]. Stop future runs while existing
// runs settle or expire. A zero-count template may be retired and then closed
// immediately by its payer.
fn retire_template(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [payer, tmpl, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    template(program_id, tmpl)?;
    if tracked_template(tmpl)?.is_none() || !tmpl.is_writable {
        return Err(err(37));
    }
    let mut d = tmpl.try_borrow_mut_data()?;
    if d[T_PAYER..T_PAYER + 32] != payer.key.to_bytes() || d[T_RETIRED] != 0 {
        return Err(err(37));
    }
    d[T_RETIRED] = 1;
    Ok(())
}

// 20: [anyone, run, cache(w), executor(w)]. A reveal cache closes once its
// run is settled with no open dispute (so no dispute can read it again), or
// once the run is closed. Its rent goes to the executor: the one the cache
// records, or, for a cache from before rent reclaim, the live run's executor.
fn close_cache(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, cache, executor, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let recorded = {
        let k = cache.try_borrow_data()?;
        if cache.owner != program_id || (k.len() != CACHE_BYTES && k.len() != CACHE_BYTES_V2) || &k[0..4] != b"D21C" {
            return Err(err(30));
        }
        derived(program_id, cache, &[b"dcg21rc", run.key.as_ref(), &[k[4]], &k[8..12], &k[16..24]])?;
        (k.len() == CACHE_BYTES_V2).then(|| <[u8; 32]>::try_from(&k[CACHE_BYTES..CACHE_BYTES_V2]).unwrap())
    };
    let live = run.owner == program_id && !run.data_is_empty();
    let payee = if live {
        // A live run (settled, no open dispute) or its receipt.
        let r = run.try_borrow_data()?;
        let receipt = r.len() == RECEIPT_BYTES && &r[0..4] == b"D21P";
        if !receipt && (r.len() < R_REFS || &r[0..4] != b"D21R") {
            return Err(err(5));
        }
        derived(program_id, run, &[b"dcg21run", &r[R_RUN_ID..R_RUN_ID + 32], &r[R_PAYER..R_PAYER + 32]])?;
        if !receipt && (!settled(&r) || u32_at(&r, R_OPEN)? != 0) {
            return Err(err(38));
        }
        recorded.unwrap_or_else(|| r[R_EXECUTOR..R_EXECUTOR + 32].try_into().unwrap())
    } else {
        // A cancelled run: only a cache that records its executor can close
        // (an uncommitted run has no disputes, so it has no caches).
        recorded.ok_or(err(38))?
    };
    if executor.key.to_bytes() != payee {
        return Err(err(22));
    }
    close_into(cache, executor)
}
