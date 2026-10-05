// SPDX-License-Identifier: GPL-3.0-only

//! LX1 checkpointed state chains on tag 227 (design
//! `docs/design/v2.1-lazy-expansion.md` §8). An LX1 dispute is an ordinary
//! v2.1 dispute: it has a sequence, a bond, the executor-wait accounting, and
//! it ends through the shared `rule`, so moot, the ruled prefix, the pot,
//! finalize and every close are unchanged. Only its descent is new:
//!
//! - `NODES`: the executor owes the midpoint roots of the current interval;
//! - `PICK`: the challenger names a sub-interval;
//! - `LEAF`: the executor owes the opening of the agreed lower state at the
//!   one remaining transition, which the program replays and rules on;
//! - `CLAIM` (kind `KIND_LX_OUTPUT` only): the challenger opens the output
//!   slots against the final root.
//!
//! The application registers its machine as code (`LxFactory`, through the
//! kernel manifest). The run's root commits the checkpoint tree root, the
//! claimed outputs' digest, the machine parameters' digest, the position count
//! and `k`.

use super::*;
use dcg_disputes::lx as X;

pub const SUB_LX_MIDPOINTS: u8 = 23;
pub const SUB_LX_PICK: u8 = 24;
pub const SUB_LX_OPENING: u8 = 25;
pub const SUB_LX_OUTPUT: u8 = 26;
/// Staged dispute open (owner decision 8a, 2026-10-04): before opening a
/// `KIND_LX_STATE` dispute, the challenger creates, writes or closes its own
/// staging buffer for the dispute it is about to open (the dispute address is
/// known from run, challenger and nonce). OPEN then takes the body
/// `FROM_STAGING`. Two checkpoint paths no longer have to fit one packet
/// (~512 checkpoints at most before; 2,561 at K=10,240, k=4).
pub const SUB_LX_PRESTAGE: u8 = 27;
pub const KIND_LX_STATE: u8 = 3;
pub const KIND_LX_OUTPUT: u8 = 4;

/// Largest machine parameter block a run may bind.
pub const LX_PARAMS_MAX: usize = 128;
/// Largest arity: the midpoint roots live in the dispute's 32-root reveal area.
pub const LX_MAX_ARITY: u64 = 16;

// Template tail "DLX1": kernel id(16) semantic(2) abi(2) arity(1) pad(3)
// k_min(4) k_max(4) max_positions(8). It follows the template's single
// default block and is part of the template id.
pub const LX_TAIL_MAGIC: &[u8; 4] = b"DLX1";
pub const LX_TAIL_BYTES: usize = 44;
pub const T_LX: usize = T_BLOCKS + Block::BYTES;
pub const T_KIND: usize = 5;
pub const TEMPLATE_KIND_LX: u8 = 1;

// LX run root (the run's 176-byte root field): run_id(32) checkpoint_root(32)
// outputs_digest(32) params_digest(32) positions(8) k(4) zero(36).
const RR_CHECKPOINTS: usize = 32;
const RR_OUTPUTS: usize = 64;
const RR_PARAMS: usize = 96;
const RR_POSITIONS: usize = 128;
const RR_K: usize = 136;

// LX dispute fields reuse the descent record: lo in D_POSITION, the agreed
// lower root in D_CURRENT, the midpoints in D_REVEALED / D_REVEALED_N.
const D_LX_HI: usize = D_LEAF;
const D_LX_ROOT_HI: usize = D_LEAF + 8;

pub const PARAMS_DOMAIN: &[u8] = b"dcg.lx.params.v1\x00";

/// The mode an LX1 machine kernel advertises; resolution requires it, as STEP
/// replay requires `MODE_STEP_V21` (review F2).
pub const MODE_LX1_V1: crate::kernel::ModeId = crate::kernel::VersionedId { id: 0x4c58_3156, version: 1 };

/// An application's LX1 machine, registered through its kernel manifest.
pub trait LxFactory: Sync {
    /// Bind a run's machine parameters, or `None` if they are malformed.
    fn bind(&self, params: &[u8]) -> Option<Box<dyn LxBound>>;
}

/// A machine bound to one run's parameters.
pub trait LxBound: X::LxMachine {
    /// The root of the admitted initial state (review H1).
    fn initial_root(&self, h: &dyn D::Sha256) -> D::Hash;
    /// The output slots: non-empty and strictly ascending (checked at bind),
    /// so an OUTPUT claim can always be opened and ruled.
    fn output_slots(&self) -> &[u32];
    /// The most read slots, written slots, output bytes and constant reads
    /// of any transition.
    fn max_transition(&self) -> (usize, usize, usize, usize);
}

#[derive(Clone, Copy, Debug)]
pub struct LxBinding {
    pub kernel: [u8; 16],
    pub semantic: u16,
    pub abi: u16,
    pub arity: u64,
    pub k_min: u64,
    pub k_max: u64,
    pub max_positions: u64,
}

pub fn parse_tail(b: &[u8]) -> Option<LxBinding> {
    if b.len() < LX_TAIL_BYTES || &b[0..4] != LX_TAIL_MAGIC || b[25..28] != [0; 3] {
        return None;
    }
    let binding = LxBinding {
        kernel: b[4..20].try_into().ok()?,
        semantic: u16::from_le_bytes(b[20..22].try_into().ok()?),
        abi: u16::from_le_bytes(b[22..24].try_into().ok()?),
        arity: b[24] as u64,
        k_min: u32::from_le_bytes(b[28..32].try_into().ok()?) as u64,
        k_max: u32::from_le_bytes(b[32..36].try_into().ok()?) as u64,
        max_positions: u64::from_le_bytes(b[36..44].try_into().ok()?),
    };
    let ok = (2..=LX_MAX_ARITY).contains(&binding.arity)
        && binding.k_min >= 1
        && binding.k_min <= binding.k_max
        && (1..=1 << 32).contains(&binding.max_positions);
    ok.then_some(binding)
}

fn checkpoint_height(count: u64) -> u32 {
    tree_height(count)
}

struct Bound {
    machine: Box<dyn LxBound>,
    positions: u64,
    k: u64,
}

/// Bind the run's machine: the template's kernel resolves to an LX1 machine,
/// `params` hash to the committed digest, and the committed positions and `k`
/// are within the template's bounds and match the machine.
fn bind(
    lx: &LxBinding,
    manifest: &'static crate::kernel::ApplicationManifest,
    root: &[u8],
    params: &[u8],
) -> Result<Bound, ProgramError> {
    if params.len() > LX_PARAMS_MAX || sha256(&[PARAMS_DOMAIN, params]) != key32(root, RR_PARAMS)? {
        return Err(err(42));
    }
    let factory = manifest
        .resolve(crate::kernel::KernelId(lx.kernel), lx.semantic, lx.abi)
        .filter(|k| k.manifest().modes.contains(&MODE_LX1_V1))
        .and_then(|k| k.lx_machine())
        .ok_or(err(43))?;
    let machine = factory.bind(params).ok_or(err(42))?;
    let positions = u64_at(root, RR_POSITIONS)?;
    let k = u32_at(root, RR_K)? as u64;
    if positions == 0
        || positions > lx.max_positions
        || !(lx.k_min..=lx.k_max).contains(&k)
        || machine.positions() != positions
        || machine.height() > 32
        || machine.output_slots().is_empty()
        || machine.output_slots().windows(2).any(|w| w[0] >= w[1])
        || root[RR_K + 4..D::RUN_ROOT_BYTES] != [0; 36]
    {
        return Err(err(42));
    }
    Ok(Bound { machine, positions, k })
}

fn read_hashes(data: &[u8], at: usize, n: usize) -> Result<Vec<D::Hash>, ProgramError> {
    (0..n).map(|i| key32(data, at + 32 * i)).collect()
}

/// COMMIT for an LX1 template: `run_root[176] r0_path[h*32] params`. Checks
/// the run id, binds the machine, and verifies that checkpoint 0 is the
/// admitted initial state's root (review H1).
pub(crate) fn check_commit(
    t: &Template,
    lx: &LxBinding,
    manifest: &'static crate::kernel::ApplicationManifest,
    run: &AccountInfo,
    tmpl: &AccountInfo,
    data: &[u8],
) -> Result<[u8; D::RUN_ROOT_BYTES], ProgramError> {
    let root: [u8; D::RUN_ROOT_BYTES] = data.get(..D::RUN_ROOT_BYTES).ok_or(err(1))?.try_into().unwrap();
    {
        // The payer admitted the machine parameters at INIT_RUN: an LX1 run's
        // 32-byte input id is their digest, and it is part of the run id. The
        // executor cannot substitute other inputs or another length (review
        // H1 of the LX1 program).
        let r = run.try_borrow_data()?;
        let n = u32_at(&r, R_NEXT)? as usize;
        let refs = r.get(R_REFS..R_REFS + 52 * n).ok_or(err(8))?;
        let template_id = key32(&tmpl.try_borrow_data()?, 96)?;
        let expected = sha256(&[
            b"dcg.run.id.v2.1\x00",
            &template_id,
            &root[RR_PARAMS..RR_PARAMS + 32],
            &(n as u32).to_le_bytes(),
            refs,
            &r[R_EXECUTOR..R_EXECUTOR + 32],
        ]);
        if root[0..32] != r[R_RUN_ID..R_RUN_ID + 32] || expected[..] != r[R_RUN_ID..R_RUN_ID + 32] {
            return Err(err(7));
        }
    }
    let positions = u64_at(&root, RR_POSITIONS)?;
    let k = u32_at(&root, RR_K)? as u64;
    let count = X::checkpoint_count(positions, k).ok_or(err(42))?;
    let h = checkpoint_height(count) as usize;
    let path_end = D::RUN_ROOT_BYTES.checked_add(32 * h).ok_or(err(1))?;
    let path = read_hashes(data, D::RUN_ROOT_BYTES, h)?;
    let params = data.get(path_end..).ok_or(err(1))?;
    let b = bind(lx, manifest, &root, params)?;
    let r0 = b.machine.initial_root(&H);
    if D::root_from_path(&H, D::Tree::LxCheckpoint, &r0, 0, &path) != key32(&root, RR_CHECKPOINTS)? {
        return Err(err(7));
    }
    let _ = t;
    Ok(root)
}

/// OPEN for an LX1 run. `KIND_LX_STATE`: `pair:u32 root_lo root_hi
/// path_lo[h*32] path_hi[h*32] params`, the checkpoint pair the challenger
/// disputes, opened against the committed checkpoint root. The body may
/// instead be the single byte `FROM_STAGING`: it is then read from the
/// challenger's staging buffer (account 5, written by `SUB_LX_PRESTAGE`),
/// checked exactly as an inline body, and the buffer's staged length is reset
/// so later staged claims start clean. `KIND_LX_OUTPUT`: no body; the
/// challenger then owes its output claim.
pub(crate) fn open(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    t: &Template,
    lx: &LxBinding,
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [challenger, run, _tmpl, dispute, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !challenger.is_signer || data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[32];
    let root = run_root_if_open(run)?;
    match kind {
        KIND_LX_STATE => {
            let staged_body;
            let body: &[u8] = if data[33..] == [FROM_STAGING] {
                let buffer = accounts.get(5).ok_or(ProgramError::NotEnoughAccountKeys)?;
                if buffer.owner != program_id || staging_role(program_id, dispute, buffer)? != ROLE_CHALLENGER {
                    return Err(err(29));
                }
                staged_body = {
                    let b = buffer.try_borrow_data()?;
                    let len = u32_at(&b, 40)? as usize;
                    b.get(STAGE_HEADER..STAGE_HEADER.checked_add(len).ok_or(err(8))?).ok_or(err(29))?.to_vec()
                };
                buffer.try_borrow_mut_data()?[40..44].copy_from_slice(&0u32.to_le_bytes());
                &staged_body
            } else {
                &data[33..]
            };
            let pair = u32_at(body, 0)? as u64;
            let positions = u64_at(&root, RR_POSITIONS)?;
            let k = u32_at(&root, RR_K)? as u64;
            let count = X::checkpoint_count(positions, k).ok_or(err(42))?;
            let h = checkpoint_height(count) as usize;
            let (root_lo, root_hi) = (key32(body, 4)?, key32(body, 36)?);
            let path_lo = read_hashes(body, 68, h)?;
            let path_hi = read_hashes(body, 68 + 32 * h, h)?;
            let params = body.get(68 + 64 * h..).ok_or(err(1))?;
            let b = bind(lx, manifest, &root, params)?;
            let committed = key32(&root, RR_CHECKPOINTS)?;
            if pair + 1 >= count
                || D::root_from_path(&H, D::Tree::LxCheckpoint, &root_lo, pair, &path_lo) != committed
                || D::root_from_path(&H, D::Tree::LxCheckpoint, &root_hi, pair + 1, &path_hi) != committed
            {
                return Err(err(44));
            }
            let lo = b.machine.position_start(X::checkpoint_position(b.positions, b.k, pair).ok_or(err(44))?);
            let hi = b.machine.position_start(X::checkpoint_position(b.positions, b.k, pair + 1).ok_or(err(44))?);
            if hi <= lo {
                return Err(err(44)); // review L1: an empty interval cannot be disputed
            }
            let (_, deadline) = open_record(program_id, challenger, run, dispute, system, t, &data[..32], true)?;
            let mut d = dispute.try_borrow_mut_data()?;
            write_header(&mut d, kind, lx.arity, deadline, challenger, run, &data[..32]);
            d[D_PHASE] = if hi - lo == 1 { PH_LEAF } else { PH_NODES };
            d[D_POSITION..D_POSITION + 8].copy_from_slice(&lo.to_le_bytes());
            d[D_LX_HI..D_LX_HI + 8].copy_from_slice(&hi.to_le_bytes());
            d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&root_lo);
            d[D_LX_ROOT_HI..D_LX_ROOT_HI + 32].copy_from_slice(&root_hi);
            Ok(())
        }
        KIND_LX_OUTPUT if data.len() == 33 => {
            let (_, _) = open_record(program_id, challenger, run, dispute, system, t, &data[..32], false)?;
            let deadline = now()?.checked_add(t.phase_window).ok_or(err(8))?;
            let mut d = dispute.try_borrow_mut_data()?;
            write_header(&mut d, kind, lx.arity, deadline, challenger, run, &data[..32]);
            d[D_PHASE] = PH_CLAIM;
            Ok(())
        }
        _ => Err(err(10)),
    }
}

fn run_root_if_open(run: &AccountInfo) -> Result<[u8; D::RUN_ROOT_BYTES], ProgramError> {
    let d = run.try_borrow_data()?;
    if d[R_STATUS] != RUN_COMMITTED || now()? > u64_at(&d, R_DEADLINE)? {
        return Err(err(9));
    }
    Ok(d[R_ROOT..R_REFS].try_into().unwrap())
}

fn write_header(d: &mut [u8], kind: u8, arity: u64, deadline: u64, challenger: &AccountInfo, run: &AccountInfo, nonce: &[u8]) {
    d[0..4].copy_from_slice(b"D21D");
    d[D_KIND] = kind;
    d[D_DEPTH] = arity as u8;
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    d[D_CHALLENGER..D_CHALLENGER + 32].copy_from_slice(challenger.key.as_ref());
    d[D_RUN..D_RUN + 32].copy_from_slice(run.key.as_ref());
    d[D_NONCE..D_NONCE + 32].copy_from_slice(nonce);
    // The sequence was written by `open_record`.
}

fn lx_ctx<'a, 'b>(
    program_id: &Pubkey,
    run: &'a AccountInfo<'b>,
    tmpl: &AccountInfo<'b>,
    dispute: &'a AccountInfo<'b>,
    kind: u8,
) -> Result<(Ctx<'a, 'b>, LxBinding), ProgramError> {
    let c = dispute_ctx(program_id, run, tmpl, dispute)?;
    let lx = c.t.lx.ok_or(err(10))?;
    if c.dispute.try_borrow_data()?[D_KIND] != kind {
        return Err(err(10));
    }
    Ok((c, lx))
}

/// 23: [executor(s), run(w), template, dispute(w)] roots[m*32], the roots at
/// the interval's fixed midpoint coordinates.
pub(crate) fn midpoints(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let (c, lx) = lx_ctx(program_id, run, tmpl, dispute, KIND_LX_STATE)?;
    executor_signed(c.run, executor)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    expect_phase(&d, PH_NODES, c.run)?;
    let (lo, hi) = (u64_at(&d, D_POSITION)?, u64_at(&d, D_LX_HI)?);
    let mut coords = [0u64; 16];
    let m = X::midpoint_coordinates(lo, hi, lx.arity, &mut coords).ok_or(err(45))?;
    if data.len() != 32 * m {
        return Err(err(45));
    }
    d[D_REVEALED..D_REVEALED + 32 * m].copy_from_slice(data);
    d[D_REVEALED_N..D_REVEALED_N + 2].copy_from_slice(&(m as u16).to_le_bytes());
    end_executor_wait(&mut c.run.try_borrow_mut_data()?)?;
    next_phase(&mut d, PH_PICK, c.t.phase_window)
}

/// 24: [challenger(s), run(w), template, dispute(w)] index:u8, the
/// sub-interval whose upper root the challenger disputes.
pub(crate) fn pick(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, tmpl, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let (c, lx) = lx_ctx(program_id, run, tmpl, dispute, KIND_LX_STATE)?;
    let mut d = c.dispute.try_borrow_mut_data()?;
    challenger_signed(&d, challenger)?;
    expect_phase(&d, PH_PICK, c.run)?;
    if data.len() != 1 {
        return Err(err(15));
    }
    let index = data[0] as u64;
    let (lo, hi) = (u64_at(&d, D_POSITION)?, u64_at(&d, D_LX_HI)?);
    let (nlo, nhi) = X::pick_interval(lo, hi, lx.arity, index).ok_or(err(15))?;
    let m = u16_at(&d, D_REVEALED_N)? as u64;
    let root_at = |i: u64, d: &[u8]| -> Result<D::Hash, ProgramError> {
        if i == 0 {
            key32(d, D_CURRENT)
        } else if i <= m {
            key32(d, D_REVEALED + 32 * (i as usize - 1))
        } else {
            key32(d, D_LX_ROOT_HI)
        }
    };
    let (rlo, rhi) = (root_at(index, &d)?, root_at(index + 1, &d)?);
    d[D_POSITION..D_POSITION + 8].copy_from_slice(&nlo.to_le_bytes());
    d[D_LX_HI..D_LX_HI + 8].copy_from_slice(&nhi.to_le_bytes());
    d[D_CURRENT..D_CURRENT + 32].copy_from_slice(&rlo);
    d[D_LX_ROOT_HI..D_LX_ROOT_HI + 32].copy_from_slice(&rhi);
    d[D_REVEALED_N..D_REVEALED_N + 2].copy_from_slice(&0u16.to_le_bytes());
    let deadline = begin_executor_wait(&mut c.run.try_borrow_mut_data()?, &c.t)?;
    d[D_PHASE] = if nhi - nlo == 1 { PH_LEAF } else { PH_NODES };
    d[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

/// A staged opening: `n:u32 (slot:u32 present:u8 [len:u32 bytes])*` then
/// `siblings:u32 hash*`, slots strictly increasing. A replay opening is
/// followed by its constants ([`decode_constants`]).
fn decode_opening<'a>(b: &'a [u8], at: &mut usize) -> Result<(Vec<(u32, Option<&'a [u8]>)>, Vec<D::Hash>), ProgramError> {
    let n = u32_at(b, *at)? as usize;
    *at += 4;
    let mut opened = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let slot = u32_at(b, *at)?;
        let present = *b.get(*at + 4).ok_or(err(46))?;
        *at += 5;
        let value = match present {
            0 => None,
            1 => {
                let len = u32_at(b, *at)? as usize;
                let start = *at + 4;
                let v = b.get(start..start.checked_add(len).ok_or(err(46))?).ok_or(err(46))?;
                *at = start + len;
                Some(v)
            }
            _ => return Err(err(46)),
        };
        opened.push((slot, value));
    }
    let s = u32_at(b, *at)? as usize;
    *at += 4;
    let siblings = read_hashes(b, *at, s)?;
    *at += 32 * s;
    Ok((opened, siblings))
}

/// The constants of a replay opening (design §13): `n:u32` then, per declared
/// read in order, `len:u32 chunk  chunk_path_n:u8 hash*  digest  const_path_n:u8 hash*`.
/// Chunks and paths are borrowed from the staged bytes (review M1). A count
/// above the machine's maximum, or a path above its cap, is refused before
/// anything is read (review L2); a section past the end does not decode (46).
fn decode_constants<'a>(b: &'a [u8], at: &mut usize, max_reads: usize) -> Result<Vec<X::ConstOpening<'a>>, ProgramError> {
    let n = u32_at(b, *at)? as usize;
    *at += 4;
    if n > max_reads {
        return Err(err(50));
    }
    let take = |at: &mut usize, len: usize| -> Result<&'a [u8], ProgramError> {
        let v = b.get(*at..at.checked_add(len).ok_or(err(46))?).ok_or(err(46))?;
        *at += len;
        Ok(v)
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = u32_at(b, *at)? as usize;
        *at += 4;
        let chunk = take(at, len)?;
        let nc = *b.get(*at).ok_or(err(46))? as usize;
        *at += 1;
        if nc > X::MAX_CHUNK_PATH {
            return Err(err(50));
        }
        let chunk_path = take(at, 32 * nc)?;
        let digest: D::Hash = take(at, 32)?.try_into().unwrap();
        let nk = *b.get(*at).ok_or(err(46))? as usize;
        *at += 1;
        if nk > X::MAX_CONST_PATH {
            return Err(err(50));
        }
        let const_path = take(at, 32 * nk)?;
        out.push(X::ConstOpening { chunk, chunk_path, digest, const_path });
    }
    Ok(out)
}

fn refusal(r: X::LxRefusal) -> ProgramError {
    match r {
        X::LxRefusal::Coordinate => err(47),
        X::LxRefusal::Coverage => err(48),
        X::LxRefusal::Proof => err(49),
        X::LxRefusal::Constant => err(50),
    }
}

/// 25: [executor(s), run(w), template, dispute(w), challenger(w), E's staging
/// buffer] params. The executor's opening of the agreed lower state at the
/// one remaining transition, staged in its buffer, is replayed and ruled in
/// this instruction (review M5). The opening is followed by the transition's
/// constant reads, checked against the template's `constants_root` (§13). A
/// malformed opening is refused; the executor may retry until its deadline.
pub(crate) fn opening(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [executor, run, tmpl, dispute, challenger, buffer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let (c, lx) = lx_ctx(program_id, run, tmpl, dispute, KIND_LX_STATE)?;
    executor_signed(c.run, executor)?;
    let (coordinate, root_lo, root_hi) = {
        let d = c.dispute.try_borrow_data()?;
        expect_phase(&d, PH_LEAF, c.run)?;
        (u64_at(&d, D_POSITION)?, key32(&d, D_CURRENT)?, key32(&d, D_LX_ROOT_HI)?)
    };
    if staging_role(program_id, c.dispute, buffer)? != ROLE_EXECUTOR {
        return Err(err(29));
    }
    let root: [u8; D::RUN_ROOT_BYTES] = c.run.try_borrow_data()?[R_ROOT..R_REFS].try_into().unwrap();
    let b = bind(&lx, manifest, &root, data)?;
    let staged = buffer.try_borrow_data()?;
    let mut at = STAGE_HEADER;
    let (opened, siblings) = decode_opening(&staged, &mut at)?;
    let (nr, nw, nout, nc) = b.machine.max_transition();
    let consts = decode_constants(&staged, &mut at, nc)?;
    let (mut reads, mut writes) = (vec![0u32; nr], vec![0u32; nw]);
    let mut nodes = vec![(0u64, [0u8; 32]); opened.len()];
    let mut read_values: Vec<Option<&[u8]>> = vec![None; nr];
    let mut effects = vec![X::Write::Keep; nw];
    let mut out = vec![0u8; nout];
    let mut const_reads = vec![(0u32, 0u64); nc];
    let mut const_values: Vec<&[u8]> = vec![&[]; nc];
    let mut s = X::Scratch {
        reads: &mut reads,
        writes: &mut writes,
        nodes: &mut nodes,
        read_values: &mut read_values,
        write_effects: &mut effects,
        out: &mut out,
        const_reads: &mut const_reads,
        const_values: &mut const_values,
    };
    let ruling = X::replay(&H, &*b.machine, coordinate, &opened, &siblings, &consts, &c.t.spec_root, &root_lo, &root_hi, &mut s)
        .map_err(refusal)?;
    drop(staged);
    rule(&c, executor, challenger, ruling == X::LxRuling::Challenger)
}

/// 26: [challenger(s), run(w), template, dispute(w), executor(w), C's staging
/// buffer] params. The challenger's OUTPUT claim (review H3), staged as the
/// final root and its checkpoint path, then the opening of the output slots
/// against it. The executor committed only a digest of its claimed outputs,
/// so the program hashes the opened (true) values and rules for the
/// challenger exactly when they do not match the committed digest. No
/// preimage of the claim is needed (LX1 program review H2).
pub(crate) fn output(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> ProgramResult {
    let [challenger, run, tmpl, dispute, executor, buffer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let (c, lx) = lx_ctx(program_id, run, tmpl, dispute, KIND_LX_OUTPUT)?;
    {
        let d = c.dispute.try_borrow_data()?;
        challenger_signed(&d, challenger)?;
        expect_phase(&d, PH_CLAIM, c.run)?;
    }
    if staging_role(program_id, c.dispute, buffer)? != ROLE_CHALLENGER {
        return Err(err(29));
    }
    let root: [u8; D::RUN_ROOT_BYTES] = c.run.try_borrow_data()?[R_ROOT..R_REFS].try_into().unwrap();
    let b = bind(&lx, manifest, &root, data)?;
    let slots = b.machine.output_slots();
    let staged = buffer.try_borrow_data()?;
    let mut at = STAGE_HEADER;
    // The final root, opened from the committed checkpoint tree.
    let count = X::checkpoint_count(b.positions, b.k).ok_or(err(42))?;
    let h = checkpoint_height(count) as usize;
    let root_t = key32(&staged, at)?;
    let path = read_hashes(&staged, at + 32, h)?;
    at += 32 + 32 * h;
    if D::root_from_path(&H, D::Tree::LxCheckpoint, &root_t, count - 1, &path) != key32(&root, RR_CHECKPOINTS)? {
        return Err(err(49));
    }
    let (opened, siblings) = decode_opening(&staged, &mut at)?;
    // The opening covers exactly the output slots and verifies against R_T.
    let mut nodes = vec![(0u64, [0u8; 32]); opened.len()];
    let values: Vec<Option<&[u8]>> = opened.iter().map(|(_, v)| *v).collect();
    if X::output_claim(&H, b.machine.height(), slots, &opened, &siblings, &root_t, &values, &mut nodes).map_err(refusal)?
        != X::LxRuling::Executor
    {
        return Err(err(48)); // unreachable: the values compared are the opened ones
    }
    let lie = X::outputs_digest(&H, &values) != key32(&root, RR_OUTPUTS)?;
    drop(staged);
    rule(&c, executor, challenger, lie)
}

/// The Python toy machine (`python/dcg/disputes_v21/lx_toy.py`) as a
/// registered LX1 machine, for tests and the DCG example. Parameters:
/// `positions:u64 window:u64 h0:i64 [weights:u8]`; with `weights = 1` (or 2,
/// the start's first chunk chosen by h, as the Python toy's `by_value`) each
/// start reads two template constant chunks (design §13), as the Python toy's
/// `weights=True`.
#[cfg(feature = "test-kernel")]
pub mod toy {
    use super::*;
    use crate::kernel::{Kernel, KernelError, KernelId, KernelManifest, ModeId, PortLayout, ResourceLimits, VersionedId};

    const MOD: i64 = 1 << 31;

    pub struct Toy {
        p: u64,
        w: u64,
        h0: i64,
        weights: bool,
        /// The start's constant-0 chunk is chosen by h (a data-dependent read).
        by_value: bool,
        outputs: [u32; 1],
    }

    impl Toy {
        fn a(&self) -> u32 {
            1 + self.p as u32
        }
        fn windows(&self, p: u64) -> u64 {
            p.div_ceil(self.w)
        }
        fn floor_sum(&self, m: u64) -> u64 {
            let k = m / self.w;
            self.w * k * k.saturating_sub(1) / 2 + k * (m - k * self.w)
        }
        fn logs(&self, p: u64, w: u64, out: &mut [u32], from: usize) -> usize {
            let (lo, hi) = (w * self.w, p.min((w + 1) * self.w));
            for (n, j) in (lo..hi).enumerate() {
                out[from + n] = 1 + j as u32;
            }
            from + (hi - lo) as usize
        }
    }

    fn dec(v: Option<&[u8]>) -> Option<i64> {
        v.and_then(|b| b.try_into().ok()).map(i64::from_le_bytes)
    }

    impl X::LxMachine for Toy {
        fn positions(&self) -> u64 {
            self.p
        }
        fn height(&self) -> u16 {
            let n = self.a() as u64 + 3;
            (64 - (n - 1).leading_zeros()) as u16
        }
        fn transitions_in(&self, p: u64) -> u64 {
            2 + 2 * self.windows(p)
        }
        fn position_start(&self, p: u64) -> u64 {
            2 * p + 2 * self.floor_sum(p + self.w - 1)
        }
        fn slots(&self, p: u64, i: u64, r: &mut [u32], w: &mut [u32]) -> Option<(usize, usize)> {
            let (h, a) = (0u32, self.a());
            let (m, s) = (a + 1, a + 2);
            let nw = self.windows(p);
            if r.len() < 4 + self.w as usize || w.len() < 5 {
                return None;
            }
            Some(if i == 0 {
                r[0] = h;
                w[0] = a;
                (1, 1)
            } else if i <= nw {
                r[0] = m;
                w[0] = m;
                (self.logs(p, i - 1, r, 1), 1)
            } else if i <= 2 * nw {
                r[0] = m;
                r[1] = s;
                w[0] = s;
                (self.logs(p, i - 1 - nw, r, 2), 1)
            } else if i == 2 * nw + 1 {
                r[..4].copy_from_slice(&[h, a, m, s]);
                w[..5].copy_from_slice(&[h, 1 + p as u32, a, m, s]);
                (4, 5)
            } else {
                return None;
            })
        }
        fn constants(&self, p: u64, i: u64, reads: &[Option<&[u8]>], out: &mut [(u32, u64)]) -> Option<usize> {
            if !self.weights || i != 0 {
                return Some(0);
            }
            let first = if self.by_value { dec(*reads.first()?)?.rem_euclid(4) as u64 } else { p % 4 };
            out.get_mut(..2)?.copy_from_slice(&[(0, first), (2, p % 3)]);
            Some(2)
        }
        fn apply(&self, p: u64, i: u64, r: &[Option<&[u8]>], c: &[&[u8]], out: &mut X::Outputs) -> Result<(), X::KernelFailure> {
            let nw = self.windows(p);
            let f = X::KernelFailure;
            // Exact (i128) arithmetic, as the Python toy's unbounded integers;
            // a value that does not fit i64 fails like Python's struct pack
            // (fuzz seed 901, play 116).
            let wide = |v: Option<&[u8]>| dec(v).map(i128::from);
            let narrow = |v: i128| i64::try_from(v).map_err(|_| f);
            if i == 0 {
                let w = match c {
                    [a, b] => wide(a.get(..8)).ok_or(f)? - wide(b.get(..8)).ok_or(f)?,
                    _ => 0,
                };
                let v = (3 * wide(r[0]).ok_or(f)? + p as i128 + 1 + w).rem_euclid(MOD as i128);
                return out.set(0, &narrow(v)?.to_le_bytes());
            }
            if i <= nw {
                let mut m = dec(r[0]);
                for v in &r[1..] {
                    let v = dec(*v).ok_or(f)?;
                    m = Some(m.map_or(v, |m| m.max(v)));
                }
                return out.set(0, &m.ok_or(f)?.to_le_bytes());
            }
            if i <= 2 * nw {
                let m = wide(r[0]).ok_or(f)?;
                let mut acc = wide(r[1]).unwrap_or(0);
                for v in &r[2..] {
                    acc += m - wide(*v).ok_or(f)?;
                }
                return out.set(0, &narrow(acc)?.to_le_bytes());
            }
            let a = wide(r[1]).ok_or(f)?;
            let (m, s) = (wide(r[2]).unwrap_or(0), wide(r[3]).unwrap_or(0));
            let h = narrow((a + s - m).rem_euclid(MOD as i128))?.to_le_bytes();
            out.set(0, &h)?;
            out.set(1, &h)?;
            out.clear(2)?;
            out.clear(3)?;
            out.clear(4)
        }
    }

    impl LxBound for Toy {
        fn initial_root(&self, h: &dyn D::Sha256) -> D::Hash {
            let height = X::LxMachine::height(self);
            let leaf = X::slot_leaf(h, 0, Some(&self.h0.to_le_bytes()));
            let siblings: Vec<D::Hash> = (0..height).map(|l| D::empty(h, D::Tree::LxState, l)).collect();
            let mut nodes = [(0u64, leaf)];
            X::fold(h, height, &mut nodes, &siblings).expect("one leaf and its empty path")
        }
        fn output_slots(&self) -> &[u32] {
            &self.outputs
        }
        fn max_transition(&self) -> (usize, usize, usize, usize) {
            (4 + self.w as usize, 5, 16, 2)
        }
    }

    pub struct ToyFactory;

    impl LxFactory for ToyFactory {
        fn bind(&self, params: &[u8]) -> Option<Box<dyn LxBound>> {
            let (weights, by_value) = match params.len() {
                24 => (false, false),
                25 if params[24] == 1 => (true, false),
                25 if params[24] == 2 => (true, true),
                _ => return None,
            };
            let p = u64::from_le_bytes(params[0..8].try_into().ok()?);
            let w = u64::from_le_bytes(params[8..16].try_into().ok()?);
            let h0 = i64::from_le_bytes(params[16..24].try_into().ok()?);
            // Small bounds keep the toy's slots and sums in range.
            if !(1..=1 << 16).contains(&p) || !(1..=64).contains(&w) {
                return None;
            }
            Some(Box::new(Toy { p, w, h0, weights, by_value, outputs: [0] }))
        }
    }

    pub static TOY_FACTORY: ToyFactory = ToyFactory;

    /// The toy as a manifest kernel; it is only an LX1 machine.
    pub struct ToyKernel;

    static TOY_MODES: [ModeId; 1] = [MODE_LX1_V1];
    pub static TOY_MANIFEST: KernelManifest = KernelManifest {
        id: KernelId(*b"dcg-lx-toy-v1\0\0\0"),
        semantic_version: 1,
        abi_version: 1,
        input: PortLayout { id: VersionedId { id: 5, version: 1 }, max_bytes: 0, alignment: 1 },
        output: PortLayout { id: VersionedId { id: 6, version: 1 }, max_bytes: 0, alignment: 1 },
        state: None,
        resources: ResourceLimits {
            max_input_bytes: 0,
            max_output_bytes: 0,
            max_state_bytes: 0,
            max_operations: 1,
            max_compute_units: 100_000,
        },
        modes: &TOY_MODES,
    };

    impl Kernel for ToyKernel {
        fn manifest(&self) -> &'static KernelManifest {
            &TOY_MANIFEST
        }
        fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
            Err(KernelError::Refused)
        }
        fn lx_machine(&self) -> Option<&dyn LxFactory> {
            Some(&TOY_FACTORY)
        }
    }

    pub static TOY_KERNEL: ToyKernel = ToyKernel;
}
