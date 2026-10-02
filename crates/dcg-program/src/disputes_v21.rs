// SPDX-License-Identifier: GPL-3.0-only

//! Optimistic disputes v2.1, program skeleton (design
//! `docs/design/optimistic-descent-v2.1.md` §14 step 2, partial). Tag 227 with
//! a subtype byte. Feature `graph-v21`, testnet only.
//!
//! In this skeleton:
//! - one enumerated block, stateless, producer kinds 1 and 2;
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
//! Not yet: staging growth past one CPI creation (10 KiB), the reveal cache, the load extension, receipts, closes, and the full v2.1
//! template identity.

use dcg_disputes as D;
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
pub const MAX_STAGE: usize = 10_240 - STAGE_HEADER;
pub const FROM_STAGING: u8 = 0xFF;

pub const RULING_OPEN: u8 = 0;
pub const RULING_EXECUTOR: u8 = 1;
pub const RULING_CHALLENGER: u8 = 2;
pub const RULING_MOOT: u8 = 3;

pub const CLAIM_SHAPE: u8 = 1;
pub const CLAIM_EDGE: u8 = 2;
pub const CLAIM_STEP: u8 = 3;
pub const CLAIM_OUT: u8 = 4;

pub const KIND_STEP_DESCEND: u8 = 1;
pub const KIND_OUT_DESCEND: u8 = 2;

pub const TEMPLATE_DOMAIN: &[u8] = b"dcg.template.id.v2.1-skeleton\x00";
pub const MIN_WINDOW: u64 = 1;
pub const MAX_WINDOW: u64 = 10_000_000;
pub const MAX_LEAF: usize = 1_100;

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
    let mut signer: [&[u8]; 5] = [&[]; 5];
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
// slasher_bps(2) pad(6) = 136 bytes;
// PDA ["dcg21tmpl", template_id]. The bases are the spec-tree leaf indices of
// OutSpec(0) and StepSpec(0) (2 + in_count, and BlockSpec.first_record).

const T_BYTES: usize = 136;

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
}

fn template(program_id: &Pubkey, account: &AccountInfo) -> Result<Template, ProgramError> {
    let d = account.try_borrow_data()?;
    if d.len() != T_BYTES || &d[0..4] != b"D21T" {
        return Err(err(4));
    }
    derived(program_id, account, &[b"dcg21tmpl", &d[96..128]])?;
    Ok(Template {
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
    })
}

// Run "D21R": magic(4) status(1) pad(3) template(32) payer(32) executor(32)
// run_id(32) commit_slot(8) deadline(8) open_disputes(4) n_ext(4)
// run_root_bytes(176) then external refs (52 each).
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
const R_PAID: usize = 184; // pot paid
const R_ROOT: usize = 192;
const R_REFS: usize = R_ROOT + D::RUN_ROOT_BYTES;

pub const RUN_OPEN: u8 = 0;
pub const RUN_COMMITTED: u8 = 1;
pub const RUN_FINAL: u8 = 2;
pub const RUN_REFUTED: u8 = 3;

fn run_checked(program_id: &Pubkey, run: &AccountInfo, template: &AccountInfo) -> ProgramResult {
    let d = run.try_borrow_data()?;
    if d.len() < R_REFS || &d[0..4] != b"D21R" || d[R_TEMPLATE..R_TEMPLATE + 32] != template.key.to_bytes() {
        return Err(err(5));
    }
    derived(program_id, run, &[b"dcg21run", &d[R_RUN_ID..R_RUN_ID + 32]])
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
const D_BYTES: usize = D_LEAF + MAX_LEAF;

const PH_NODES: u8 = 1; // E reveals
const PH_PICK: u8 = 2; // C picks
const PH_LEAF: u8 = 3; // E reveals the leaf
const PH_CLAIM: u8 = 4; // C claims
const PH_RULED: u8 = 5;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match data.get(1).copied().ok_or(ProgramError::InvalidInstructionData)? {
        SUB_CREATE_TEMPLATE => create_template(program_id, accounts, &data[2..]),
        SUB_INIT_RUN => init_run(program_id, accounts, &data[2..]),
        SUB_COMMIT => commit(program_id, accounts, &data[2..]),
        SUB_OPEN => open(program_id, accounts, &data[2..]),
        SUB_REVEAL_NODES => reveal_nodes(program_id, accounts, &data[2..]),
        SUB_PICK => pick(program_id, accounts, &data[2..]),
        SUB_REVEAL_LEAF => reveal_leaf(program_id, accounts, &data[2..]),
        SUB_CLAIM => claim(program_id, accounts, &data[2..]),
        SUB_TIMEOUT => timeout(program_id, accounts),
        SUB_FINALIZE => finalize(program_id, accounts),
        SUB_ADVANCE => advance(program_id, accounts),
        SUB_MOOT => moot(program_id, accounts),
        SUB_PAY_POT => pay_pot(program_id, accounts),
        SUB_STAGE_CREATE => stage_create(program_id, accounts, &data[2..]),
        SUB_STAGE_WRITE => stage_write(program_id, accounts, &data[2..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// 1: [admitter(s,w), template(w), system] depth:u8 total_steps:u64
// total_outputs:u64 challenge_window:u64 phase_window:u64 executor_bond:u64
// challenger_bond:u64 out_spec_base:u32 step_spec_base:u32 spec_root[32]
// slasher_bps:u16 (< 10,000: the remainder deterrent, design §10.3)
fn create_template(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [admitter, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !admitter.is_signer || data.len() != 1 + 6 * 8 + 8 + 32 + 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let depth = data[0];
    let (cw, pw) = (u64_at(data, 17)?, u64_at(data, 25)?);
    let total_steps = u64_at(data, 1)?;
    if !(1..=D::MAX_DEPTH as u8).contains(&depth)
        || !(MIN_WINDOW..=MAX_WINDOW).contains(&cw)
        || !(MIN_WINDOW..=MAX_WINDOW).contains(&pw)
        || total_steps == 0
        || total_steps > 1 << 40
        || u16_at(data, 89)? >= 10_000
    {
        return Err(err(6));
    }
    let template_id = sha256(&[TEMPLATE_DOMAIN, data]);
    create_pda(program_id, admitter, tmpl, system, &[b"dcg21tmpl", &template_id], T_BYTES)?;
    let mut d = tmpl.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"D21T");
    d[4] = depth;
    d[8..64].copy_from_slice(&data[1..57]);
    d[64..96].copy_from_slice(&data[57..89]);
    d[128..130].copy_from_slice(&data[89..91]);
    d[96..128].copy_from_slice(&template_id);
    Ok(())
}

// 2: [payer(s,w), run(w), template, system] nonce[32] executor[32] n:u32 refs[52 n]
fn init_run(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, run, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let t = template(program_id, tmpl)?;
    let _ = t;
    let n = u32_at(data, 64)? as usize;
    let refs = data.get(68..68 + n * 52).ok_or(err(1))?;
    if data.len() != 68 + n * 52 {
        return Err(err(1));
    }
    let template_id = key32(&tmpl.try_borrow_data()?, 96)?;
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &data[0..32], &(n as u32).to_le_bytes(), refs, &data[32..64]]);
    create_pda(program_id, payer, run, system, &[b"dcg21run", &run_id], R_REFS + refs.len())?;
    let mut d = run.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"D21R");
    d[R_TEMPLATE..R_TEMPLATE + 32].copy_from_slice(tmpl.key.as_ref());
    d[R_PAYER..R_PAYER + 32].copy_from_slice(payer.key.as_ref());
    d[R_EXECUTOR..R_EXECUTOR + 32].copy_from_slice(&data[32..64]);
    d[R_RUN_ID..R_RUN_ID + 32].copy_from_slice(&run_id);
    d[R_NEXT..R_NEXT + 4].copy_from_slice(&(n as u32).to_le_bytes());
    d[R_BEST..R_BEST + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    d[R_REFS..].copy_from_slice(refs);
    Ok(())
}

// 3: [executor(s,w), run(w), template, system] run_root_bytes[176]
fn commit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
    let root: &[u8; D::RUN_ROOT_BYTES] = data.try_into().map_err(|_| err(1))?;
    let rr = D::RunRoot(root);
    {
        let d = run.try_borrow_data()?;
        if !executor.is_signer || d[R_EXECUTOR..R_EXECUTOR + 32] != executor.key.to_bytes() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if d[R_STATUS] != RUN_OPEN
            || rr.run_id() != &d[R_RUN_ID..R_RUN_ID + 32]
            || rr.spec_root() != t.spec_root
            || rr.total_steps() != t.total_steps
            || rr.total_outputs() != t.total_outputs
        {
            return Err(err(7));
        }
    }
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
fn open(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !challenger.is_signer || data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let t = template(program_id, tmpl)?;
    run_checked(program_id, run, tmpl)?;
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
        KIND_STEP_DESCEND => (tree_height(t.total_steps), key32(&root, 104)?),
        KIND_OUT_DESCEND => (tree_height(t.total_outputs), key32(&root, 144)?),
        _ => return Err(err(10)),
    };
    let _ = rr;
    create_pda(program_id, challenger, dispute, system, &[b"dcg21dsp", run.key.as_ref(), challenger.key.as_ref(), &data[..32]], D_BYTES)?;
    if t.challenger_bond > 0 {
        invoke(&system_instruction::transfer(challenger.key, dispute.key, t.challenger_bond), &[challenger.clone(), dispute.clone(), system.clone()])?;
    }
    let sequence = {
        let mut r = run.try_borrow_mut_data()?;
        let open = u32_at(&r, R_OPEN)?.checked_add(1).ok_or(err(8))?;
        r[R_OPEN..R_OPEN + 4].copy_from_slice(&open.to_le_bytes());
        let seq = u64_at(&r, R_SEQ)?;
        r[R_SEQ..R_SEQ + 8].copy_from_slice(&seq.checked_add(1).ok_or(err(8))?.to_le_bytes());
        seq
    };
    let mut d = dispute.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"D21D");
    d[D_PHASE] = if level == 0 { PH_LEAF } else { PH_NODES };
    d[D_KIND] = kind;
    d[D_DEPTH] = t.depth as u8;
    d[D_LEVEL..D_LEVEL + 4].copy_from_slice(&level.to_le_bytes());
    let deadline = now()?.checked_add(t.phase_window).ok_or(err(8))?;
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    d[D_CHALLENGER..D_CHALLENGER + 32].copy_from_slice(challenger.key.as_ref());
    d[D_RUN..D_RUN + 32].copy_from_slice(run.key.as_ref());
    d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&current);
    d[D_SEQ..D_SEQ + 8].copy_from_slice(&sequence.to_le_bytes());
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
    if dispute.owner != program_id {
        return Err(err(2));
    }
    drop(d);
    Ok(Ctx { t, run, dispute })
}

fn expect_phase(d: &[u8], phase: u8) -> ProgramResult {
    if d[D_PHASE] != phase {
        return Err(err(12));
    }
    if Clock::get()?.slot > u64_at(d, D_DEADLINE)? {
        return Err(err(13));
    }
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

fn limit(t: &Template, kind: u8) -> u64 {
    if kind == KIND_STEP_DESCEND { t.total_steps } else { t.total_outputs }
}

fn tree_of(kind: u8) -> D::Tree {
    if kind == KIND_STEP_DESCEND { D::Tree::Step } else { D::Tree::Out }
}

// 5: [executor(s), run, template, dispute(w)] the pickable hashes, in position order.
fn reveal_nodes(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    executor_signed(c.run, executor)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_NODES)?;
    let level = u32_at(&d, D_LEVEL)?;
    let position = u64_at(&d, D_POSITION)?;
    let depth = (d[D_DEPTH] as u32).min(level);
    let kind = d[D_KIND];
    let first = position << depth;
    let base = level - depth;
    let mut slots = [None; 1 << D::MAX_DEPTH];
    let mut at = 0;
    for (i, slot) in slots.iter_mut().enumerate().take(1 << depth) {
        if D::pickable(limit(&c.t, kind), base, first + i as u64) {
            *slot = Some(key32(data, at)?);
            at += 32;
        }
    }
    if at != data.len() {
        return Err(err(14));
    }
    let folded = D::fold_reveal(&H, tree_of(kind), limit(&c.t, kind), level, position, depth, &slots[..1 << depth])
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
    next_phase(&mut d, PH_PICK, c.t.phase_window)
}

// 6: [challenger(s), run, template, dispute(w)] index:u8
fn pick(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    challenger_signed(&d, challenger)?;
    expect_phase(&d, PH_PICK)?;
    let index = *data.first().ok_or(err(1))? as u64;
    let level = u32_at(&d, D_LEVEL)?;
    let depth = (d[D_DEPTH] as u32).min(level);
    let position = u64_at(&d, D_POSITION)?;
    if index >= 1 << depth || !D::pickable(limit(&c.t, d[D_KIND]), level - depth, (position << depth) + index) {
        return Err(err(15));
    }
    let chosen = key32(&d, D_REVEALED + 32 * index as usize)?;
    let new_level = level - depth;
    d[D_LEVEL..D_LEVEL + 4].copy_from_slice(&new_level.to_le_bytes());
    d[D_POSITION..D_POSITION + 8].copy_from_slice(&((position << depth) + index).to_le_bytes());
    d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&chosen);
    next_phase(&mut d, if new_level == 0 { PH_LEAF } else { PH_NODES }, c.t.phase_window)
}

// 14: [challenger(s,w), run, template, dispute, buffer(w), system] role:u8 size:u32
fn stage_create(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, buffer, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    {
        let d = c.dispute.try_borrow_data()?;
        challenger_signed(&d, challenger)?;
    }
    let role = *data.first().ok_or(err(1))?;
    let size = u32_at(data, 1)? as usize;
    if !(role == ROLE_EXECUTOR || role == ROLE_CHALLENGER) || size == 0 || size > MAX_STAGE || data.len() != 5 {
        return Err(err(29));
    }
    create_pda(program_id, challenger, buffer, system, &[b"dcg21stg", c.dispute.key.as_ref(), &[role]], STAGE_HEADER + size)?;
    let mut b = buffer.try_borrow_mut_data()?;
    b[0..4].copy_from_slice(b"D21S");
    b[4] = role;
    b[8..40].copy_from_slice(c.dispute.key.as_ref());
    Ok(())
}

// 15: [writer(s), run, template, dispute, buffer(w)] offset:u32 bytes. Any
// time, by the buffer's owner (E for role 1, C for role 2).
fn stage_write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [writer, run, tmpl, dispute, buffer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let role = staging_role(program_id, c.dispute, buffer)?;
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

fn staging_role(program_id: &Pubkey, dispute: &AccountInfo, buffer: &AccountInfo) -> Result<u8, ProgramError> {
    let b = buffer.try_borrow_data()?;
    if b.len() < STAGE_HEADER || &b[0..4] != b"D21S" || b[8..40] != dispute.key.to_bytes() {
        return Err(err(29));
    }
    let role = b[4];
    derived(program_id, buffer, &[b"dcg21stg", dispute.key.as_ref(), &[role]])?;
    Ok(role)
}

// 7: [executor(s), run, template, dispute(w)] present:u8 preimage
fn reveal_leaf(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, dispute, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    executor_signed(c.run, executor)?;
    let staged;
    let data: &[u8] = if data == [FROM_STAGING] {
        let buffer = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if staging_role(program_id, c.dispute, buffer)? != ROLE_EXECUTOR {
            return Err(err(29));
        }
        staged = buffer.try_borrow_data()?;
        let len = u32_at(&staged, 40)? as usize;
        &staged[STAGE_HEADER..STAGE_HEADER + len]
    } else {
        data
    };
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_LEAF)?;
    let present = *data.first().ok_or(err(1))?;
    let body = &data[1..];
    if present > 1 || (present == 0 && !body.is_empty()) || body.len() > MAX_LEAF {
        return Err(err(16));
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

fn read_path(data: &[u8], at: usize) -> Result<([D::Hash; 48], usize), ProgramError> {
    let n = *data.get(at).ok_or(err(1))? as usize;
    if n > 48 {
        return Err(err(1));
    }
    let mut out = [[0u8; 32]; 48];
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = key32(data, at + 1 + 32 * i)?;
    }
    Ok((out, n))
}

/// A leaf of the committed step tree: `present:u8 len:u16 preimage path_len:u8 path`.
fn step_opening<'a>(root: &[u8], data: &'a [u8], at: &mut usize, ordinal: u64) -> Result<Option<&'a [u8]>, ProgramError> {
    let present = *data.get(*at).ok_or(err(1))?;
    let len = u16_at(data, *at + 1)? as usize;
    let pre = data.get(*at + 3..*at + 3 + len).ok_or(err(1))?;
    let path = read_path(data, *at + 3 + len)?;
    *at += 3 + len + 1 + 32 * path.1;
    let leaf = D::leaf_hash(&H, (present == 1).then_some(pre));
    if D::root_from_path(&H, D::Tree::Step, &leaf, ordinal, &path.0[..path.1]).as_slice() != &root[104..136] {
        return Err(err(18));
    }
    Ok((present == 1).then_some(pre))
}

// 8: [challenger(s), run(w), template, dispute(w), executor(w), challenger_account(w)]
// claim:u8 index:u8 spec_opening [producer_opening] [witness: n:u8 (len:u16 bytes)*]
fn claim(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, executor_acct, _challenger_acct, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let staged;
    let data: &[u8] = if data == [FROM_STAGING] {
        let buffer = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if staging_role(program_id, c.dispute, buffer)? != ROLE_CHALLENGER {
            return Err(err(29));
        }
        staged = buffer.try_borrow_data()?;
        let len = u32_at(&staged, 40)? as usize;
        &staged[STAGE_HEADER..STAGE_HEADER + len]
    } else {
        data
    };
    let (kind, position, present, leaf_buf, chal) = {
        let d = c.dispute.try_borrow_data()?;
        challenger_signed(&d, challenger)?;
        expect_phase(&d, PH_CLAIM)?;
        let len = u16_at(&d, D_LEAF_LEN)? as usize;
        let mut buf = [0u8; MAX_LEAF];
        buf[..len].copy_from_slice(&d[D_LEAF..D_LEAF + len]);
        (d[D_KIND], u64_at(&d, D_POSITION)?, d[D_LEAF_PRESENT] == 1, (buf, len), key32(&d, D_CHALLENGER)?)
    };
    let _ = chal;
    let leaf_bytes = &leaf_buf.0[..leaf_buf.1];
    let root: [u8; D::RUN_ROOT_BYTES] = c.run.try_borrow_data()?[R_ROOT..R_REFS].try_into().unwrap();
    let rr = D::RunRoot(&root);
    let name = *data.first().ok_or(err(1))?;
    let index = *data.get(1).ok_or(err(1))? as usize;
    let mut at = 2;
    let winner_is_challenger = if kind == KIND_OUT_DESCEND {
        // OUT(j): the spec's OutSpec(j), then the producer leaf.
        let (_t, record) = spec_record(&c.t, data, &mut at, out_spec_leaf_index(&c.t, position)?)?;
        if record.len() != 56 || &record[0..4] != b"DOU1" {
            return Err(err(17));
        }
        let (pk, p, port, _, _) = D::producer(&record[32..56]);
        let entry_ok = present && leaf_bytes.len() == 55 && leaf_bytes[..23] == record[8..31];
        if !entry_ok {
            true
        } else {
            if pk != 1 {
                return Err(err(19));
            }
            match step_opening(&root, data, &mut at, p)?.and_then(D::parse_leaf) {
                None => true,
                Some(prod) => match prod.output_port(port as u16) {
                    None => true,
                    Some(o) => leaf_bytes[23..55] != o[23..55],
                },
            }
        }
    } else {
        let (_t, record) = spec_record(&c.t, data, &mut at, step_spec_leaf_index(&c.t, position)?)?;
        let spec = D::StepSpec(record);
        if !spec.valid() {
            return Err(err(17));
        }
        let leaf = if present { D::parse_leaf(leaf_bytes) } else { None };
        match leaf {
            // Malformed or empty under E's own commitment: C wins.
            None => true,
            Some(leaf) => match name {
                CLAIM_SHAPE => D::shape_wrong(&leaf, &spec, rr.plan_id(), rr.run_id(), position),
                CLAIM_EDGE => {
                    if index >= spec.input_count() || index >= leaf.input_count() {
                        return Err(err(19));
                    }
                    let got = leaf.input(index);
                    let (pk, a, b, _, _) = spec.input_producer(index);
                    match pk {
                        2 => {
                            let refs = &c.run.try_borrow_data()?[R_REFS..];
                            let r = refs.get(a as usize * 52..a as usize * 52 + 52).ok_or(err(19))?;
                            got[7..55] != r[4..52]
                        }
                        1 => match step_opening(&root, data, &mut at, a)?.and_then(D::parse_leaf) {
                            None => true,
                            Some(prod) => match prod.output_port(b as u16) {
                                None => true,
                                Some(o) => got[7..55] != o[7..55],
                            },
                        },
                        _ => return Err(err(19)),
                    }
                }
                CLAIM_STEP => {
                    let n = *data.get(at).ok_or(err(1))? as usize;
                    at += 1;
                    if n != leaf.input_count() || n > 8 {
                        return Err(err(20));
                    }
                    let mut ins: [&[u8]; 8] = [&[]; 8];
                    for (i, slot) in ins.iter_mut().enumerate().take(n) {
                        let len = u16_at(data, at)? as usize;
                        let v = data.get(at + 2..at + 2 + len).ok_or(err(1))?;
                        at += 2 + len;
                        if D::value_digest(&H, v) != leaf.input(i)[23..55] {
                            return Err(err(20));
                        }
                        *slot = v;
                    }
                    let code = kernel_code(spec.kernel_id()).ok_or(err(21))?;
                    let mut out = [0u8; 4];
                    match dcg_kernels::execute(code, &ins[..n], &mut out) {
                        Err(_) => true,
                        Ok(_) => leaf.output_count() != 1 || D::value_digest(&H, &out) != leaf.output(0)[23..55],
                    }
                }
                _ => return Err(err(19)),
            },
        }
    };
    rule(&c, executor_acct, challenger, winner_is_challenger)
}

/// The registered kernel whose name equals the spec's 16-byte kernel id
/// without its NUL padding (for example `identity_i32/v1`).
fn kernel_code(id: &[u8]) -> Option<u16> {
    let end = id.iter().position(|b| *b == 0).unwrap_or(id.len());
    let name = &id[..end];
    (1..=255u16).find(|k| dcg_kernels::info(*k).is_some_and(|i| i.name.as_bytes() == name))
}

fn step_spec_leaf_index(t: &Template, ordinal: u64) -> Result<u64, ProgramError> {
    t.step_spec_base.checked_add(ordinal).ok_or(err(8))
}

fn out_spec_leaf_index(t: &Template, j: u64) -> Result<u64, ProgramError> {
    t.out_spec_base.checked_add(j).ok_or(err(8))
}

fn rule(c: &Ctx, executor: &AccountInfo, challenger: &AccountInfo, challenger_wins: bool) -> ProgramResult {
    let seq = {
        let mut d = c.dispute.try_borrow_mut_data()?;
        if d[D_RULING] != RULING_OPEN {
            return Err(err(25));
        }
        if challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32] {
            return Err(err(22));
        }
        d[D_PHASE] = PH_RULED;
        d[D_RULING] = if challenger_wins { RULING_CHALLENGER } else { RULING_EXECUTOR };
        u64_at(&d, D_SEQ)?
    };
    {
        let mut r = c.run.try_borrow_mut_data()?;
        if executor.key.to_bytes() != r[R_EXECUTOR..R_EXECUTOR + 32] {
            return Err(err(22));
        }
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
    // The challenger's bond: back to a winning challenger, to E otherwise.
    if challenger_wins {
        move_all(c.dispute, challenger)
    } else {
        move_all(c.dispute, executor)
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
    {
        let mut d = c.dispute.try_borrow_mut_data()?;
        let r = c.run.try_borrow_data()?;
        if r[R_STATUS] != RUN_REFUTED
            || d[D_RULING] != RULING_OPEN
            || u64_at(&d, D_SEQ)? <= u64_at(&r, R_BEST)?
            || challenger.key.to_bytes() != d[D_CHALLENGER..D_CHALLENGER + 32]
        {
            return Err(err(27));
        }
        d[D_PHASE] = PH_RULED;
        d[D_RULING] = RULING_MOOT;
    }
    {
        let mut r = c.run.try_borrow_mut_data()?;
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
