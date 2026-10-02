// SPDX-License-Identifier: GPL-3.0-only

//! DCG v2 graph lifecycle (fast path, stages 3 and 5).
//!
//! Immutable content-addressed blobs hold the canonical graph (DCGG), plan
//! (DCPL), and the lowered step table. A template binds their identities to
//! this program image and a kernel manifest root. A run commits external
//! inputs; an executor either executes every step on chain (consensus mode)
//! or posts the full output trace optimistically. In optimistic mode, anyone
//! may challenge one step before the deadline: the program replays that step
//! through the registered `dcg-kernels` callback against the committed trace
//! and rules for the challenger on mismatch. The sampling audit (stage 5)
//! derives step indices from a slot hash newer than the commit and replays
//! only those steps.
//!
//! Fast-path simplifications (not the frozen v2.0 spec): the on-chain program
//! trusts the template admitter's lowered step table instead of decoding
//! DCPL; values are fixed 4-byte cells; the dispute is a direct step replay
//! over the on-chain trace rather than a root -> region -> step descent; no
//! bonds or economics are attached.
//!
//! Tags:
//! 209 close run, 210 blob create, 211 blob write, 212 blob seal,
//! 213 admit template, 214 init run, 215 execute (consensus), 216 commit
//! (optimistic), 217 challenge step, 218 finalize, 219 sampling audit.

use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::{self, Sysvar},
};

use crate::hash::sha256;

pub const GRAPH_DOMAIN: &[u8] = b"dcg.graph.id.v2\x00";
pub const PLAN_DOMAIN: &[u8] = b"dcg.plan.id.v2\x00";
pub const TABLE_DOMAIN: &[u8] = b"dcg.steptable.id.v2\x00";
pub const TEMPLATE_DOMAIN: &[u8] = b"dcg.template.id.v2\x00";
pub const RUN_DOMAIN: &[u8] = b"dcg.run.id.v2\x00";

pub const KIND_GRAPH: u8 = 1;
pub const KIND_PLAN: u8 = 2;
pub const KIND_TABLE: u8 = 3;

pub const MODE_CONSENSUS: u8 = 1;
pub const MODE_OPTIMISTIC: u8 = 2;
pub const MODE_SAMPLING: u8 = 3;

pub const STATUS_OPEN: u8 = 0;
pub const STATUS_COMMITTED: u8 = 1;
pub const STATUS_FINAL: u8 = 2;
pub const STATUS_CHALLENGER_WON: u8 = 3;

const CELL: usize = 4;

// Blob: magic(4) kind(1) sealed(1) pad(2) len(4) id(32) writer(32) bytes.
const BLOB_HEADER: usize = 76;
// Template: magic(4) mode(1) samples(1) pad(2) window(8) template_id(32)
// graph_id(32) plan_id(32) table_id(32) manifest_root(32) image_id(32) table_key(32).
/// Header, seven identities, then the executor bond (u64 lamports).
const TEMPLATE_BYTES: usize = 16 + 32 * 7 + 8;
const TEMPLATE_BOND: usize = 16 + 32 * 7;
// Run: magic(4) status(1) audited(1) n_in(2) n_steps(2) bad_step(2) pad(4)
// commit_slot(8) deadline(8) run_id(32) template(32) payer(32) executor(32)
// then inputs (n_in cells) then trace (n_steps cells).
const RUN_HEADER: usize = 32 + 32 * 4;

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(0x6200 + code)
}

fn u16_at(d: &[u8], at: usize) -> Result<u16, ProgramError> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(err(1))
}
fn u32_at(d: &[u8], at: usize) -> Result<u32, ProgramError> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or(err(1))
}
fn u64_at(d: &[u8], at: usize) -> Result<u64, ProgramError> {
    d.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).ok_or(err(1))
}
fn key32(d: &[u8], at: usize) -> Result<[u8; 32], ProgramError> {
    d.get(at..at + 32).map(|b| b.try_into().unwrap()).ok_or(err(1))
}

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
    if target.lamports() != 0 {
        return Err(err(3));
    }
    let lamports = Rent::get()?.minimum_balance(space);
    let bump_seed = [bump];
    let mut signer: [&[u8]; 4] = [&[]; 4];
    signer[..seeds.len()].copy_from_slice(seeds);
    signer[seeds.len()] = &bump_seed;
    invoke_signed(
        &system_instruction::create_account(payer.key, target.key, lamports, space as u64, program_id),
        &[payer.clone(), target.clone(), system.clone()],
        &[&signer[..seeds.len() + 1]],
    )
}

fn owned(program_id: &Pubkey, account: &AccountInfo) -> ProgramResult {
    if account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    Ok(())
}

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match data[0] {
        208 => raw_write(program_id, accounts, data),
        209 => close_run(program_id, accounts),
        210 => blob_create(program_id, accounts, data),
        211 => blob_write(program_id, accounts, data),
        212 => blob_seal(program_id, accounts),
        213 => admit_template(program_id, accounts, data),
        214 => init_run(program_id, accounts, data),
        215 => execute(program_id, accounts),
        216 => commit(program_id, accounts, data),
        217 => challenge(program_id, accounts, data),
        218 => finalize(program_id, accounts),
        219 => sample_audit(program_id, accounts),
        220 => commit_root(program_id, accounts, data),
        221 => open_dispute(program_id, accounts),
        222 => reveal_region(program_id, accounts, data),
        223 => choose(program_id, accounts, data),
        224 => reveal_leaf(program_id, accounts, data),
        225 => replay_leaf(program_id, accounts, data),
        226 => settle_descent(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// 210: [payer(s,w), blob(w), system] tag kind:u8 len:u32 id[32]
fn blob_create(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, blob, system, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let kind = *data.get(1).ok_or(err(1))?;
    if !(KIND_GRAPH..=KIND_TABLE).contains(&kind) {
        return Err(err(4));
    }
    let len = u32_at(data, 2)? as usize;
    if len == 0 || len > 4 * 1024 * 1024 {
        return Err(err(5));
    }
    let id = key32(data, 6)?;
    create_pda(program_id, payer, blob, system, &[b"dcg2blob", &[kind], &id], BLOB_HEADER + len)?;
    let mut d = blob.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"DCB2");
    d[4] = kind;
    d[8..12].copy_from_slice(&(len as u32).to_le_bytes());
    d[12..44].copy_from_slice(&id);
    d[44..76].copy_from_slice(payer.key.as_ref());
    Ok(())
}

// 211: [writer(s), blob(w)] tag offset:u32 bytes
fn blob_write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [writer, blob, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    owned(program_id, blob)?;
    let mut d = blob.try_borrow_mut_data()?;
    if !writer.is_signer || d[44..76] != writer.key.as_ref()[..] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if &d[0..4] != b"DCB2" || d[5] != 0 {
        return Err(err(6));
    }
    let len = u32_at(&d, 8)? as usize;
    let offset = u32_at(data, 1)? as usize;
    let bytes = &data[5..];
    if offset + bytes.len() > len {
        return Err(err(7));
    }
    d[BLOB_HEADER + offset..BLOB_HEADER + offset + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

// 212: [writer(s), blob(w)]
fn blob_seal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [writer, blob, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    owned(program_id, blob)?;
    let mut d = blob.try_borrow_mut_data()?;
    if !writer.is_signer || d[44..76] != writer.key.as_ref()[..] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if d[5] != 0 {
        return Err(err(6));
    }
    let len = u32_at(&d, 8)? as usize;
    let domain = match d[4] {
        KIND_GRAPH => GRAPH_DOMAIN,
        KIND_PLAN => PLAN_DOMAIN,
        _ => TABLE_DOMAIN,
    };
    let digest = sha256(&[domain, &d[BLOB_HEADER..BLOB_HEADER + len]]);
    if digest[..] != d[12..44] {
        return Err(err(8));
    }
    d[5] = 1;
    Ok(())
}

fn sealed_blob(program_id: &Pubkey, blob: &AccountInfo, kind: u8) -> Result<[u8; 32], ProgramError> {
    owned(program_id, blob)?;
    let d = blob.try_borrow_data()?;
    if &d[0..4] != b"DCB2" || d[4] != kind || d[5] != 1 {
        return Err(err(9));
    }
    key32(&d, 12)
}

/// Parsed step table: n_inputs, n_steps, then per step kernel:u16 n_in:u8 refs:u16*n_in.
struct Table<'a> {
    n_inputs: usize,
    n_steps: usize,
    body: &'a [u8],
}

impl<'a> Table<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        let n_inputs = u16_at(bytes, 0)? as usize;
        let n_steps = u16_at(bytes, 2)? as usize;
        let table = Table { n_inputs, n_steps, body: &bytes[4..] };
        // Validate: refs only point backwards (static DAG, no loops).
        let mut at = 0;
        for step in 0..n_steps {
            let (_, refs, next) = table.step_at(at)?;
            for r in refs.chunks(2) {
                let r = u16::from_le_bytes([r[0], r[1]]) as usize;
                if r >= n_inputs + step {
                    return Err(err(10));
                }
            }
            at = next;
        }
        Ok(table)
    }

    fn step_at(&self, at: usize) -> Result<(u16, &'a [u8], usize), ProgramError> {
        let kernel = u16_at(self.body, at)?;
        let n = *self.body.get(at + 2).ok_or(err(1))? as usize;
        let refs = self.body.get(at + 3..at + 3 + 2 * n).ok_or(err(1))?;
        Ok((kernel, refs, at + 3 + 2 * n))
    }

    fn step(&self, index: usize) -> Result<(u16, &'a [u8]), ProgramError> {
        let mut at = 0;
        for _ in 0..index {
            at = self.step_at(at)?.2;
        }
        let (k, refs, _) = self.step_at(at)?;
        Ok((k, refs))
    }
}

// 213: [admitter(s,w), template(w), graph, plan, table, system]
// tag mode:u8 samples:u8 window_slots:u64 manifest_root[32]
fn admit_template(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [admitter, template, graph, plan, table, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admitter.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mode = data[1];
    if !(MODE_CONSENSUS..=MODE_SAMPLING).contains(&mode) {
        return Err(err(11));
    }
    let samples = data[2];
    let window = u64_at(data, 3)?;
    let manifest_root = key32(data, 11)?;
    let graph_id = sealed_blob(program_id, graph, KIND_GRAPH)?;
    let plan_id = sealed_blob(program_id, plan, KIND_PLAN)?;
    let table_id = sealed_blob(program_id, table, KIND_TABLE)?;
    let verified = verify_canonical_lowering(graph, plan, table, &graph_id, &manifest_root, mode)?;
    {
        let t = table.try_borrow_data()?;
        let len = u32_at(&t, 8)? as usize;
        let parsed = Table::parse(&t[BLOB_HEADER..BLOB_HEADER + len])?;
        let mut at = 0;
        for _ in 0..parsed.n_steps {
            let (kernel, refs, next) = parsed.step_at(at)?;
            let info = dcg_kernels::info(kernel).ok_or(err(12))?;
            if info.inputs as usize * 2 != refs.len() {
                return Err(err(13));
            }
            at = next;
        }
    }
    let image_id = sha256(&[b"dcg.app.image.v2\x00", program_id.as_ref()]);
    // Optional executor bond (lamports) after the manifest root; bound into
    // the template identity when present.
    let bond = data.get(43..51).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
    let bond_bytes = if data.len() >= 51 { &data[43..51] } else { &[][..] };
    let template_id =
        sha256(&[TEMPLATE_DOMAIN, &graph_id, &plan_id, &image_id, &manifest_root, &table_id, &data[1..11], bond_bytes]);
    create_pda(program_id, admitter, template, system, &[b"dcg2tmpl", &template_id], TEMPLATE_BYTES)?;
    let mut d = template.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"DCT2");
    d[4] = mode;
    d[5] = samples;
    d[6] = verified as u8;
    d[8..16].copy_from_slice(&window.to_le_bytes());
    for (i, part) in [template_id, graph_id, plan_id, table_id, manifest_root, image_id, table.key.to_bytes()]
        .iter()
        .enumerate()
    {
        d[16 + 32 * i..48 + 32 * i].copy_from_slice(part);
    }
    d[TEMPLATE_BOND..TEMPLATE_BOND + 8].copy_from_slice(&bond.to_le_bytes());
    Ok(())
}

/// Conformance (v2.0 §2–3): a canonical DCGG/DCPL pair is decoded and
/// validated on chain with the reference's refusal rules, the plan must bind
/// this graph's ID and the declared kernel-manifest root, and its lowering
/// must equal the step table the template executes (the table blob's prefix;
/// the rest is the policy suffix). A wire refusal is `0x6400 + code`.
/// Returns false for the fast-path `DCGGF1` encoding, whose table stays
/// trusted (the template records which, at byte 6).
fn verify_canonical_lowering(
    graph: &AccountInfo,
    plan: &AccountInfo,
    table: &AccountInfo,
    graph_id: &[u8; 32],
    manifest_root: &[u8; 32],
    mode: u8,
) -> Result<bool, ProgramError> {
    let g = graph.try_borrow_data()?;
    let g = &g[BLOB_HEADER..BLOB_HEADER + u32_at(&g, 8)? as usize];
    if !g.starts_with(b"DCGG") {
        return Ok(false);
    }
    let wire = |c: dcg_wire::Code| ProgramError::Custom(0x6400 + c as u32);
    let decoded = dcg_wire::decode_graph(g).map_err(wire)?;
    let p = plan.try_borrow_data()?;
    let p = &p[BLOB_HEADER..BLOB_HEADER + u32_at(&p, 8)? as usize];
    let decoded_plan = dcg_wire::decode_plan(p).map_err(wire)?;
    if decoded_plan.graph_id != graph_id.as_slice() {
        return Err(wire(dcg_wire::Code::LowerGraphId));
    }
    if decoded_plan.kernel_manifest_root != manifest_root.as_slice() {
        return Err(err(29));
    }
    // Every region resolves in the template's mode (sampling is optimistic
    // resolution plus a slot-hash audit).
    let region_mode = if mode == MODE_CONSENSUS { dcg_wire::MODE_CONSENSUS } else { dcg_wire::MODE_OPTIMISTIC };
    if decoded_plan.regions.iter().any(|r| r.mode_id != region_mode)
        || decoded.regions.iter().any(|r| r.mode_id != region_mode)
    {
        return Err(err(31));
    }
    let lowered = dcg_wire::lower(&decoded, &decoded_plan, |id, semantic, abi| {
        dcg_kernels::REGISTRY
            .iter()
            .find(|k| {
                let name = k.name.as_bytes();
                name.len() <= 16
                    && id[..name.len()] == *name
                    && id[name.len()..].iter().all(|b| *b == 0)
                    && k.semantic_version == semantic
                    && k.abi_version == abi
            })
            .map(|k| k.code)
    })
    .map_err(wire)?;
    let t = table.try_borrow_data()?;
    let t = &t[BLOB_HEADER..BLOB_HEADER + u32_at(&t, 8)? as usize];
    if t.len() < lowered.len() || t[..lowered.len()] != lowered[..] {
        return Err(err(30));
    }
    Ok(true)
}

struct TemplateView {
    mode: u8,
    samples: u8,
    window: u64,
    template_id: [u8; 32],
    table_key: [u8; 32],
    bond: u64,
}

fn template_view(program_id: &Pubkey, template: &AccountInfo) -> Result<TemplateView, ProgramError> {
    owned(program_id, template)?;
    let d = template.try_borrow_data()?;
    if &d[0..4] != b"DCT2" {
        return Err(err(14));
    }
    Ok(TemplateView {
        mode: d[4],
        samples: d[5],
        window: u64_at(&d, 8)?,
        template_id: key32(&d, 16)?,
        table_key: key32(&d, 16 + 32 * 6)?,
        // Templates admitted before bonds are 240 bytes and carry none.
        bond: if d.len() >= TEMPLATE_BYTES { u64_at(&d, TEMPLATE_BOND)? } else { 0 },
    })
}

fn table_bytes<'b>(view: &TemplateView, table: &'b AccountInfo) -> Result<core::cell::Ref<'b, &'b mut [u8]>, ProgramError> {
    if table.key.to_bytes() != view.table_key {
        return Err(err(15));
    }
    Ok(table.try_borrow_data()?)
}

// 214: [payer(s,w), run(w), template, table, system] tag nonce[32] inputs
fn init_run(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, run, template, table, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    let (n_in, n_steps) = {
        let t = table_bytes(&view, table)?;
        (u16_at(&t, BLOB_HEADER)? as usize, u16_at(&t, BLOB_HEADER + 2)? as usize)
    };
    let nonce = key32(data, 1)?;
    let inputs = &data[33..];
    if inputs.len() != n_in * CELL {
        return Err(err(16));
    }
    let run_id = sha256(&[RUN_DOMAIN, &view.template_id, &nonce, inputs]);
    create_pda(program_id, payer, run, system, &[b"dcg2run", &run_id], RUN_HEADER + (n_in + n_steps) * CELL)?;
    let mut d = run.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"DCR2");
    d[6..8].copy_from_slice(&(n_in as u16).to_le_bytes());
    d[8..10].copy_from_slice(&(n_steps as u16).to_le_bytes());
    d[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    d[32..64].copy_from_slice(&run_id);
    d[64..96].copy_from_slice(template.key.as_ref());
    d[96..128].copy_from_slice(payer.key.as_ref());
    d[RUN_HEADER..RUN_HEADER + inputs.len()].copy_from_slice(inputs);
    Ok(())
}

fn run_checked(program_id: &Pubkey, run: &AccountInfo, template: &AccountInfo) -> ProgramResult {
    owned(program_id, run)?;
    let d = run.try_borrow_data()?;
    if &d[0..4] != b"DCR2" || d[64..96] != template.key.as_ref()[..] {
        return Err(err(17));
    }
    Ok(())
}

/// Evaluate one step against the run's cells (inputs then trace).
fn eval_step(table: &Table, cells: &[u8], index: usize) -> Result<Result<[u8; CELL], u16>, ProgramError> {
    let (kernel, refs) = table.step(index)?;
    let mut ins: [&[u8]; 8] = [&[]; 8];
    let n = refs.len() / 2;
    if n > ins.len() {
        return Err(err(13));
    }
    for (i, r) in refs.chunks(2).enumerate() {
        let r = u16::from_le_bytes([r[0], r[1]]) as usize;
        ins[i] = &cells[r * CELL..(r + 1) * CELL];
    }
    let mut out = [0u8; CELL];
    Ok(dcg_kernels::execute(kernel, &ins[..n], &mut out).map(|_| out))
}

// 215: [caller(s), run(w), template, table] consensus mode: execute every step on chain.
fn execute(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [caller, run, template, table, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    if view.mode != MODE_CONSENSUS {
        return Err(err(18));
    }
    let t = table_bytes(&view, table)?;
    let len = u32_at(&t, 8)? as usize;
    let parsed = Table::parse(&t[BLOB_HEADER..BLOB_HEADER + len])?;
    let mut d = run.try_borrow_mut_data()?;
    if d[4] != STATUS_OPEN {
        return Err(err(19));
    }
    for step in 0..parsed.n_steps {
        let out = eval_step(&parsed, &d[RUN_HEADER..], step)?.map_err(|code| err(0x100 + code as u32))?;
        let at = RUN_HEADER + (parsed.n_inputs + step) * CELL;
        d[at..at + CELL].copy_from_slice(&out);
    }
    d[4] = STATUS_FINAL;
    d[16..24].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
    d[128..160].copy_from_slice(caller.key.as_ref());
    Ok(())
}

// 216: [executor(s,w), run(w), template, system] tag trace(n_steps cells) optimistic commit.
// The executor posts the template's bond into the run account.
fn commit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, template, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !executor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    if view.mode == MODE_CONSENSUS {
        return Err(err(18));
    }
    let mut d = run.try_borrow_mut_data()?;
    if d[4] != STATUS_OPEN {
        return Err(err(19));
    }
    let n_in = u16_at(&d, 6)? as usize;
    let n_steps = u16_at(&d, 8)? as usize;
    let trace = &data[1..];
    if trace.len() != n_steps * CELL {
        return Err(err(16));
    }
    let at = RUN_HEADER + n_in * CELL;
    d[at..at + trace.len()].copy_from_slice(trace);
    let slot = Clock::get()?.slot;
    d[4] = STATUS_COMMITTED;
    if view.bond > 0 {
        let system = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        drop(d);
        invoke(&system_instruction::transfer(executor.key, run.key, view.bond), &[executor.clone(), run.clone(), system.clone()])?;
        d = run.try_borrow_mut_data()?;
    }
    d[16..24].copy_from_slice(&slot.to_le_bytes());
    d[24..32].copy_from_slice(&(slot + view.window).to_le_bytes());
    d[128..160].copy_from_slice(executor.key.as_ref());
    Ok(())
}

/// The run's bond: its lamports above the rent-exempt minimum for its size.
fn take_bond(run: &AccountInfo, to: &AccountInfo) -> ProgramResult {
    let floor = Rent::get()?.minimum_balance(run.data_len());
    let bond = run.lamports().saturating_sub(floor);
    if bond > 0 {
        if !to.is_writable {
            return Err(err(27));
        }
        **run.try_borrow_mut_lamports()? -= bond;
        **to.try_borrow_mut_lamports()? += bond;
    }
    Ok(())
}

/// Replay `step`; returns true when the committed cell is wrong.
fn step_is_wrong(parsed: &Table, d: &[u8], step: usize) -> Result<bool, ProgramError> {
    let at = RUN_HEADER + (parsed.n_inputs + step) * CELL;
    Ok(match eval_step(parsed, &d[RUN_HEADER..], step)? {
        Ok(out) => d[at..at + CELL] != out,
        // A refused step can never carry a valid committed output.
        Err(_) => true,
    })
}

// 217: [challenger(s), run(w), template, table] tag step:u16
fn challenge(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, template, table, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !challenger.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    let step = u16_at(data, 1)? as usize;
    let t = table_bytes(&view, table)?;
    let len = u32_at(&t, 8)? as usize;
    let parsed = Table::parse(&t[BLOB_HEADER..BLOB_HEADER + len])?;
    let mut d = run.try_borrow_mut_data()?;
    // A root-committed run is disputed only by descent (221..226).
    if d[4] != STATUS_COMMITTED || d[RUN_ROOT_MODE] == 1 {
        return Err(err(19));
    }
    if Clock::get()?.slot > u64_at(&d, 24)? {
        return Err(err(20));
    }
    if step >= parsed.n_steps {
        return Err(err(21));
    }
    if !step_is_wrong(&parsed, &d, step)? {
        // Matching opening: the challenge is refused, the commitment stands.
        return Err(err(22));
    }
    d[4] = STATUS_CHALLENGER_WON;
    d[10..12].copy_from_slice(&(step as u16).to_le_bytes());
    drop(d);
    // The executor's bond goes to the challenger who proved the step wrong.
    take_bond(run, challenger)
}

// 218: [caller, run(w), template, executor(w)?] after the deadline with no
// winning challenge; the bond, if any, returns to the committing executor.
fn finalize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, template, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    let mut d = run.try_borrow_mut_data()?;
    if d[4] != STATUS_COMMITTED || d[RUN_ROOT_MODE] == 1 {
        return Err(err(19));
    }
    if Clock::get()?.slot <= u64_at(&d, 24)? {
        return Err(err(23));
    }
    if view.mode == MODE_SAMPLING && d[5] == 0 {
        return Err(err(24));
    }
    d[4] = STATUS_FINAL;
    let executor_key = key32(&d, 128)?;
    drop(d);
    if view.bond > 0 {
        let executor = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if executor.key.to_bytes() != executor_key {
            return Err(err(28));
        }
        take_bond(run, executor)?;
    }
    Ok(())
}

// 219: [caller, run(w), template, table, slot_hashes] sampling audit.
fn sample_audit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [caller, run, template, table, slot_hashes, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if *slot_hashes.key != sysvar::slot_hashes::id() {
        return Err(err(25));
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    if view.mode != MODE_SAMPLING {
        return Err(err(18));
    }
    let t = table_bytes(&view, table)?;
    let len = u32_at(&t, 8)? as usize;
    let parsed = Table::parse(&t[BLOB_HEADER..BLOB_HEADER + len])?;
    let mut d = run.try_borrow_mut_data()?;
    if d[4] != STATUS_COMMITTED || d[5] != 0 {
        return Err(err(19));
    }
    let commit_slot = u64_at(&d, 16)?;
    // SlotHashes: u64 count, then (slot u64, hash [32]) newest first.
    let sh = slot_hashes.try_borrow_data()?;
    let newest_slot = u64_at(&sh, 8)?;
    if newest_slot <= commit_slot {
        // Randomness must come from a slot after the commitment.
        return Err(err(26));
    }
    let seed = sha256(&[&sh[16..48], &d[32..64]]);
    for i in 0..view.samples.max(1) as usize {
        let draw = sha256(&[&seed, &(i as u32).to_le_bytes()]);
        let step = (u32::from_le_bytes([draw[0], draw[1], draw[2], draw[3]]) as usize) % parsed.n_steps.max(1);
        if step_is_wrong(&parsed, &d, step)? {
            d[4] = STATUS_CHALLENGER_WON;
            d[10..12].copy_from_slice(&(step as u16).to_le_bytes());
            d[5] = 1;
            drop(d);
            // An audit that catches a wrong step pays the bond to the auditor.
            return take_bond(run, caller);
        }
    }
    d[5] = 1;
    Ok(())
}

// 209: [payer(s,w), run(w), template] close a terminal run, rent to its payer.
fn close_run(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [payer, run, template, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    run_checked(program_id, run, template)?;
    {
        let d = run.try_borrow_data()?;
        if d[4] != STATUS_FINAL && d[4] != STATUS_CHALLENGER_WON {
            return Err(err(19));
        }
        if !payer.is_signer || d[96..128] != payer.key.as_ref()[..] {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    let lamports = run.lamports();
    **run.try_borrow_mut_lamports()? = 0;
    **payer.try_borrow_mut_lamports()? += lamports;
    run.try_borrow_mut_data()?.fill(0);
    Ok(())
}

// 208: [account(s,w)] tag offset:u32 bytes. Raw bytes into a keypair account
// this program owns (e.g. a large immutable resource source). The account
// must sign, so a program-derived account can never be targeted.
fn raw_write(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [account, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    owned(program_id, account)?;
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let offset = u32_at(data, 1)? as usize;
    let bytes = &data[5..];
    let mut d = account.try_borrow_mut_data()?;
    let end = offset.checked_add(bytes.len()).ok_or(err(7))?;
    if end > d.len() {
        return Err(err(7));
    }
    d[offset..end].copy_from_slice(bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// Root-committed optimistic runs and the root → region → step descent
// (v2.0 §5 commitments; fast path, see docs/hello-graph.md).
//
// The executor commits only the root region digest (RegionRootV1, §5). A
// challenger opens a dispute; the executor reveals the target region's
// RegionRootV1; the challenger descends into a child region or picks a leaf of
// the region's step tree; the executor reveals that leaf with its Merkle path;
// then anyone replays the leaf. Each input is authenticated against its
// source: an external input against the run's own cell, a producer in the
// same region by its leaf and path under the same step-tree root, a producer
// in a child region by that child's revealed RegionRootV1 outputs. A silent
// party loses at its deadline.
//
// A value digest is SHA256("dcg.value.v2\0" || value bytes) (graph-plan-v2
// §5, value digest; owner decision 2026-10-02).

pub const VALUE_DOMAIN: &[u8] = b"dcg.value.v2\x00";
pub const LEAF_DOMAIN: &[u8] = b"dcg.region.leaf.v2\x00";
pub const NODE_DOMAIN: &[u8] = b"dcg.region.node.v2\x00";
pub const ROOT_DOMAIN: &[u8] = b"dcg.region.root.v2\x00";

// Dispute record "DCD2", PDA ["dcg2disp", run].
const D_PHASE: usize = 4;
const D_WINNER: usize = 5;
const D_CHILDREN: usize = 6; // u16
const D_DEADLINE: usize = 8;
const D_ROOT: usize = 16;
const D_TARGET: usize = 48;
const D_REGION: usize = 80;
const D_LEAF_INDEX: usize = 84;
const D_CHALLENGER: usize = 88;
const D_STEP_ROOT: usize = 120;
const D_LEAF: usize = 152;
const D_CHILD_TABLE: usize = 192; // 8 × (region u32, root[32])
const D_MAX_CHILDREN: usize = 8;
/// The step-tree root of the region the descent came from (zero at the root).
const D_PARENT_STEP_ROOT: usize = D_CHILD_TABLE + D_MAX_CHILDREN * 36;
const DISPUTE_BYTES: usize = D_PARENT_STEP_ROOT + 32;

const PHASE_IDLE: u8 = 1;
const PHASE_AWAIT_REGION: u8 = 2;
const PHASE_AWAIT_CHOICE: u8 = 3;
const PHASE_AWAIT_LEAF: u8 = 4;
const PHASE_AWAIT_REPLAY: u8 = 5;
const PHASE_RULED: u8 = 6;

const RUN_ROOT_MODE: usize = 12; // run byte: 1 = root-committed
const VALUE_REF: usize = 55;
const CHILD_REF: usize = 54;

fn value_digest(bytes: &[u8]) -> [u8; 32] {
    sha256(&[VALUE_DOMAIN, bytes])
}

fn dispute_checked<'a>(program_id: &Pubkey, run: &AccountInfo, dispute: &'a AccountInfo) -> ProgramResult {
    owned(program_id, dispute)?;
    let (expected, _) = Pubkey::find_program_address(&[b"dcg2disp", run.key.as_ref()], program_id);
    if expected != *dispute.key || &dispute.try_borrow_data()?[0..4] != b"DCD2" {
        return Err(err(40));
    }
    Ok(())
}

fn root_mode_run(run: &AccountInfo) -> Result<bool, ProgramError> {
    Ok(run.try_borrow_data()?[RUN_ROOT_MODE] == 1)
}

fn now() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

/// A RegionRootV1 view (§5): the parts the descent uses.
struct RegionView<'a> {
    plan_id: &'a [u8],
    run_id: &'a [u8],
    region_id: u32,
    step_root: &'a [u8],
    children: Vec<(u32, [u8; 32])>,
    outputs: &'a [u8],
    output_count: usize,
}

fn parse_region(b: &[u8]) -> Result<RegionView<'_>, ProgramError> {
    let bad = || err(41);
    let mut at = 64;
    let region_id = u32_at(b, at)?;
    at += 4 + 4 + 2 + 4 + 2 + 4 + 2;
    let n_in = u16_at(b, at)? as usize;
    at += 2 + n_in * VALUE_REF;
    let step_root = b.get(at..at + 32).ok_or(bad())?;
    at += 32;
    let n_child = u16_at(b, at)? as usize;
    at += 2;
    let mut children = Vec::new();
    for i in 0..n_child {
        let c = b.get(at + i * CHILD_REF..at + (i + 1) * CHILD_REF).ok_or(bad())?;
        children.push((u32::from_le_bytes(c[0..4].try_into().unwrap()), c[22..54].try_into().unwrap()));
    }
    at += n_child * CHILD_REF;
    let n_out = u16_at(b, at)? as usize;
    at += 2;
    let outputs = b.get(at..at + n_out * VALUE_REF).ok_or(bad())?;
    at += n_out * VALUE_REF;
    if b.len() != at + 32 {
        return Err(bad());
    }
    Ok(RegionView { plan_id: &b[0..32], run_id: &b[32..64], region_id, step_root, children, outputs, output_count: n_out })
}

/// The digest of the value ref `(node, direction, port)` in a ref list, if present.
fn ref_digest(refs: &[u8], count: usize, node: u32, direction: u8, port: u16) -> Option<[u8; 32]> {
    (0..count).find_map(|i| {
        let r = &refs[i * VALUE_REF..(i + 1) * VALUE_REF];
        (u32::from_le_bytes(r[0..4].try_into().unwrap()) == node
            && r[4] == direction
            && u16::from_le_bytes([r[5], r[6]]) == port)
            .then(|| r[23..55].try_into().unwrap())
    })
}

/// Fold a leaf up its Merkle path (§5: level-tagged nodes, odd layers duplicate).
fn merkle_fold(leaf: [u8; 32], mut index: u32, path: &[u8]) -> Result<[u8; 32], ProgramError> {
    if path.len() % 32 != 0 {
        return Err(err(42));
    }
    let mut node = leaf;
    for (level, sibling) in path.chunks(32).enumerate() {
        let level = (level as u16).to_le_bytes();
        node = if index & 1 == 0 {
            sha256(&[NODE_DOMAIN, &level, &node, sibling])
        } else {
            sha256(&[NODE_DOMAIN, &level, sibling, &node])
        };
        index >>= 1;
    }
    Ok(node)
}

struct Cursor<'a> {
    d: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let s = self.d.get(self.at..self.at + n).ok_or(err(43))?;
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProgramError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn blob16(&mut self) -> Result<&'a [u8], ProgramError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Rule the dispute for the challenger: the run is refuted and the executor's
/// bond goes to the challenger.
fn rule_challenger(run: &AccountInfo, dispute: &AccountInfo, challenger: &AccountInfo, step: u16) -> ProgramResult {
    {
        let mut dd = dispute.try_borrow_mut_data()?;
        if dd[D_CHALLENGER..D_CHALLENGER + 32] != challenger.key.as_ref()[..] {
            return Err(err(44));
        }
        dd[D_PHASE] = PHASE_RULED;
        dd[D_WINNER] = 2;
    }
    {
        let mut d = run.try_borrow_mut_data()?;
        d[4] = STATUS_CHALLENGER_WON;
        d[10..12].copy_from_slice(&step.to_le_bytes());
    }
    // The challenger takes the executor's bond and gets its own back.
    take_bond(run, challenger)?;
    take_bond(dispute, challenger)
}

/// The executor answered every question: the dispute closes and the
/// commitment stands (another challenger may open while the window lasts).
/// The losing challenger's bond goes to the executor it held up.
fn rule_executor(run: &AccountInfo, dispute: &AccountInfo, executor: Option<&AccountInfo>) -> ProgramResult {
    {
        let mut dd = dispute.try_borrow_mut_data()?;
        dd[D_PHASE] = PHASE_IDLE;
        dd[D_WINNER] = 1;
        dd[D_CHALLENGER..D_CHALLENGER + 32].fill(0);
    }
    let floor = Rent::get()?.minimum_balance(dispute.data_len());
    if dispute.lamports() > floor {
        let executor = executor.ok_or(ProgramError::NotEnoughAccountKeys)?;
        if executor.key.as_ref() != &run.try_borrow_data()?[128..160] {
            return Err(err(28));
        }
        take_bond(dispute, executor)?;
    }
    Ok(())
}

// 220: [executor(s,w), run(w), template, dispute(w), system] tag root[32] trace_copy
fn commit_root(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, template, dispute, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !executor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    if view.mode != MODE_OPTIMISTIC {
        return Err(err(18));
    }
    let root = key32(data, 1)?;
    {
        let mut d = run.try_borrow_mut_data()?;
        if d[4] != STATUS_OPEN {
            return Err(err(19));
        }
        let n_in = u16_at(&d, 6)? as usize;
        let n_steps = u16_at(&d, 8)? as usize;
        // A convenience copy of the trace for readers; only the root is
        // authoritative and only it is ever checked.
        let copy = &data[33..];
        if copy.len() != n_steps * CELL {
            return Err(err(16));
        }
        let at = RUN_HEADER + n_in * CELL;
        d[at..at + copy.len()].copy_from_slice(copy);
        let slot = now()?;
        d[4] = STATUS_COMMITTED;
        d[RUN_ROOT_MODE] = 1;
        d[16..24].copy_from_slice(&slot.to_le_bytes());
        d[24..32].copy_from_slice(&(slot + view.window).to_le_bytes());
        d[128..160].copy_from_slice(executor.key.as_ref());
    }
    create_pda(program_id, executor, dispute, system, &[b"dcg2disp", run.key.as_ref()], DISPUTE_BYTES)?;
    {
        let mut dd = dispute.try_borrow_mut_data()?;
        dd[0..4].copy_from_slice(b"DCD2");
        dd[D_PHASE] = PHASE_IDLE;
        dd[D_ROOT..D_ROOT + 32].copy_from_slice(&root);
    }
    if view.bond > 0 {
        invoke(&system_instruction::transfer(executor.key, run.key, view.bond), &[executor.clone(), run.clone(), system.clone()])?;
    }
    Ok(())
}

// 221: [challenger(s,w), run, template, dispute(w), system] open a dispute on
// the root; the challenger posts the template's bond into the dispute record.
fn open_dispute(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [challenger, run, template, dispute, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !challenger.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    let d = run.try_borrow_data()?;
    if d[4] != STATUS_COMMITTED || d[RUN_ROOT_MODE] != 1 {
        return Err(err(19));
    }
    if now()? > u64_at(&d, 24)? {
        return Err(err(20));
    }
    let mut dd = dispute.try_borrow_mut_data()?;
    if dd[D_PHASE] != PHASE_IDLE {
        return Err(err(45));
    }
    let root = key32(&dd, D_ROOT)?;
    dd[D_PHASE] = PHASE_AWAIT_REGION;
    dd[D_WINNER] = 0;
    dd[D_TARGET..D_TARGET + 32].copy_from_slice(&root);
    dd[D_REGION..D_REGION + 4].copy_from_slice(&0u32.to_le_bytes());
    dd[D_CHALLENGER..D_CHALLENGER + 32].copy_from_slice(challenger.key.as_ref());
    dd[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&(now()? + view.window).to_le_bytes());
    drop(dd);
    drop(d);
    if view.bond > 0 {
        let system = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        invoke(&system_instruction::transfer(challenger.key, dispute.key, view.bond),
               &[challenger.clone(), dispute.clone(), system.clone()])?;
    }
    Ok(())
}

// 222: [executor(s), run, template, dispute(w)] tag RegionRootV1 bytes
fn reveal_region(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, template, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    let d = run.try_borrow_data()?;
    if !executor.is_signer || d[128..160] != executor.key.as_ref()[..] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let bytes = &data[1..];
    let mut dd = dispute.try_borrow_mut_data()?;
    if dd[D_PHASE] != PHASE_AWAIT_REGION {
        return Err(err(45));
    }
    if sha256(&[ROOT_DOMAIN, bytes]) != key32(&dd, D_TARGET)? {
        return Err(err(46));
    }
    let r = parse_region(bytes)?;
    let plan_id = key32(&template.try_borrow_data()?, 16 + 32 * 2)?;
    if r.plan_id != plan_id || r.run_id != &d[32..64] || r.region_id != u32_at(&dd, D_REGION)? {
        return Err(err(47));
    }
    if r.children.len() > D_MAX_CHILDREN {
        return Err(err(48));
    }
    dd[D_STEP_ROOT..D_STEP_ROOT + 32].copy_from_slice(r.step_root);
    dd[D_CHILDREN..D_CHILDREN + 2].copy_from_slice(&(r.children.len() as u16).to_le_bytes());
    for (i, (id, root)) in r.children.iter().enumerate() {
        let at = D_CHILD_TABLE + i * 36;
        dd[at..at + 4].copy_from_slice(&id.to_le_bytes());
        dd[at + 4..at + 36].copy_from_slice(root);
    }
    dd[D_PHASE] = PHASE_AWAIT_CHOICE;
    dd[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&(now()? + view.window).to_le_bytes());
    Ok(())
}

// 223: [challenger(s), run, template, dispute(w)] tag kind:u8 (0 child, 1 leaf) value:u32
fn choose(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, template, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    let mut dd = dispute.try_borrow_mut_data()?;
    if !challenger.is_signer || dd[D_CHALLENGER..D_CHALLENGER + 32] != challenger.key.as_ref()[..] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if dd[D_PHASE] != PHASE_AWAIT_CHOICE {
        return Err(err(45));
    }
    let kind = *data.get(1).ok_or(err(43))?;
    let value = u32_at(data, 2)?;
    if kind == 0 {
        let n = u16_at(&dd, D_CHILDREN)? as usize;
        let child = (0..n).find(|i| u32_at(&dd, D_CHILD_TABLE + i * 36).ok() == Some(value)).ok_or(err(49))?;
        let root = key32(&dd, D_CHILD_TABLE + child * 36 + 4)?;
        let parent_step_root = key32(&dd, D_STEP_ROOT)?;
        dd[D_PARENT_STEP_ROOT..D_PARENT_STEP_ROOT + 32].copy_from_slice(&parent_step_root);
        dd[D_TARGET..D_TARGET + 32].copy_from_slice(&root);
        dd[D_REGION..D_REGION + 4].copy_from_slice(&value.to_le_bytes());
        dd[D_PHASE] = PHASE_AWAIT_REGION;
    } else if kind == 1 {
        dd[D_LEAF_INDEX..D_LEAF_INDEX + 4].copy_from_slice(&value.to_le_bytes());
        dd[D_PHASE] = PHASE_AWAIT_LEAF;
    } else {
        return Err(err(43));
    }
    dd[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&(now()? + view.window).to_le_bytes());
    Ok(())
}

// 224: [executor(s), run, template, dispute(w)] tag leaf:blob16 path:blob16
fn reveal_leaf(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [executor, run, template, dispute, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    let view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    let d = run.try_borrow_data()?;
    if !executor.is_signer || d[128..160] != executor.key.as_ref()[..] {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut c = Cursor { d: &data[1..], at: 0 };
    let leaf = c.blob16()?;
    let path = c.blob16()?;
    let mut dd = dispute.try_borrow_mut_data()?;
    if dd[D_PHASE] != PHASE_AWAIT_LEAF {
        return Err(err(45));
    }
    let digest = sha256(&[LEAF_DOMAIN, leaf]);
    if merkle_fold(digest, u32_at(&dd, D_LEAF_INDEX)?, path)? != key32(&dd, D_STEP_ROOT)? {
        return Err(err(46));
    }
    dd[D_LEAF..D_LEAF + 32].copy_from_slice(&digest);
    dd[D_PHASE] = PHASE_AWAIT_REPLAY;
    dd[D_DEADLINE..D_DEADLINE + 8].copy_from_slice(&(now()? + view.window).to_le_bytes());
    Ok(())
}

// 225: [challenger(s,w), run(w), template, dispute(w), graph, plan, executor(w)]
// tag leaf:blob16 then per input: value:blob16 auth:u8 [1: leaf:blob16 index:u32 path:blob16 | 2: region:blob16]
fn replay_leaf(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [challenger, run, template, dispute, graph, plan, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let _view = template_view(program_id, template)?;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    {
        let dd = dispute.try_borrow_data()?;
        if dd[D_PHASE] != PHASE_AWAIT_REPLAY {
            return Err(err(45));
        }
        if !challenger.is_signer || dd[D_CHALLENGER..D_CHALLENGER + 32] != challenger.key.as_ref()[..] {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    let (graph_id, plan_id) = {
        let t = template.try_borrow_data()?;
        (key32(&t, 16 + 32)?, key32(&t, 16 + 64)?)
    };
    if sealed_blob(program_id, graph, KIND_GRAPH)? != graph_id || sealed_blob(program_id, plan, KIND_PLAN)? != plan_id {
        return Err(err(50));
    }
    let gb = graph.try_borrow_data()?;
    let gb = &gb[BLOB_HEADER..BLOB_HEADER + u32_at(&gb, 8)? as usize];
    let pb = plan.try_borrow_data()?;
    let pb = &pb[BLOB_HEADER..BLOB_HEADER + u32_at(&pb, 8)? as usize];
    let wire = |c: dcg_wire::Code| ProgramError::Custom(0x6400 + c as u32);
    let g = dcg_wire::decode_graph(gb).map_err(wire)?;
    let p = dcg_wire::decode_plan(pb).map_err(wire)?;

    let mut c = Cursor { d: &data[1..], at: 0 };
    let leaf = c.blob16()?;
    let (step_root, leaf_digest, children, parent_step_root) = {
        let dd = dispute.try_borrow_data()?;
        let n = u16_at(&dd, D_CHILDREN)? as usize;
        let ch: Vec<[u8; 32]> = (0..n).map(|i| key32(&dd, D_CHILD_TABLE + i * 36 + 4)).collect::<Result<_, _>>()?;
        (key32(&dd, D_STEP_ROOT)?, key32(&dd, D_LEAF)?, ch, key32(&dd, D_PARENT_STEP_ROOT).ok())
    };
    if sha256(&[LEAF_DOMAIN, leaf]) != leaf_digest {
        return Err(err(46));
    }
    // Leaf: plan_id run_id region coordinate(region segment ordinal node kernel_step) inputs outputs states.
    let run_id = key32(&run.try_borrow_data()?, 32)?;
    let mut l = Cursor { d: leaf, at: 0 };
    if l.take(32)? != plan_id || l.take(32)? != run_id {
        return Err(err(47));
    }
    let _region = l.u32()?;
    let (coord_region, segment) = (l.u32()?, l.u32()?);
    let ordinal = u64::from_le_bytes(l.take(8)?.try_into().unwrap());
    let (node_id, kernel_step) = (l.u32()?, l.u32()?);
    let n_in = l.u16()? as usize;
    let inputs = l.take(n_in * VALUE_REF)?;
    let n_out = l.u16()? as usize;
    let outputs = l.take(n_out * VALUE_REF)?;
    let step = p.steps.get(ordinal as usize).ok_or(err(51))?;
    if (step.region_id, step.segment_id, step.node_id, step.kernel_step) != (coord_region, segment, node_id, kernel_step)
        || step.inputs.len() != n_in
        || step.outputs.len() != 1
        || n_out != 1
    {
        return Err(err(51));
    }
    let mut values: Vec<&[u8]> = Vec::new();
    for (i, port_ref) in step.inputs.iter().enumerate() {
        let r = &inputs[i * VALUE_REF..(i + 1) * VALUE_REF];
        if u32::from_le_bytes(r[0..4].try_into().unwrap()) != port_ref.node_id || r[4] != 0
            || u16::from_le_bytes([r[5], r[6]]) != port_ref.port_id
        {
            return Err(err(51));
        }
        let claimed: [u8; 32] = r[23..55].try_into().unwrap();
        let value = c.blob16()?;
        if value_digest(value) != claimed {
            // The caller must supply the bytes the leaf names.
            return Err(err(52));
        }
        let auth = c.u8()?;
        let external = g.inputs.iter().position(|e| (e.node_id, e.port_id) == (port_ref.node_id, port_ref.port_id));
        let consistent = match (auth, external) {
            (0, Some(index)) => {
                let d = run.try_borrow_data()?;
                d.get(RUN_HEADER + index * CELL..RUN_HEADER + (index + 1) * CELL) == Some(value)
            }
            (1 | 3, None) => {
                // 1: the producer is a step of this region; 3: of the parent
                // region the descent came from.
                let producer = c.blob16()?;
                let index = c.u32()?;
                let path = c.blob16()?;
                let root = if auth == 1 { Some(step_root) } else { parent_step_root.filter(|r| *r != [0; 32]) };
                if Some(merkle_fold(sha256(&[LEAF_DOMAIN, producer]), index, path)?) != root {
                    return Err(err(53));
                }
                let edge = g.edges.iter().find(|e| (e.destination_node, e.destination_port) == (port_ref.node_id, port_ref.port_id)).ok_or(err(53))?;
                producer_output(producer, edge.source_node, edge.source_port)? == claimed
            }
            (2, None) => {
                let region = c.blob16()?;
                if !children.contains(&sha256(&[ROOT_DOMAIN, region])) {
                    return Err(err(53));
                }
                let edge = g.edges.iter().find(|e| (e.destination_node, e.destination_port) == (port_ref.node_id, port_ref.port_id)).ok_or(err(53))?;
                let rv = parse_region(region)?;
                ref_digest(rv.outputs, rv.output_count, edge.source_node, 1, edge.source_port) == Some(claimed)
            }
            _ => return Err(err(53)),
        };
        if !consistent {
            // The leaf's input disagrees with its authenticated source.
            drop(g);
            return rule_challenger(run, dispute, challenger, ordinal as u16);
        }
        values.push(value);
    }
    let node = g.nodes.iter().find(|n| n.node_id == node_id).ok_or(err(51))?;
    let code = dcg_kernels::REGISTRY
        .iter()
        .find(|k| {
            let name = k.name.as_bytes();
            node.kernel_id[..name.len()] == *name && node.kernel_id[name.len()..].iter().all(|b| *b == 0)
        })
        .map(|k| k.code)
        .ok_or(err(12))?;
    let mut out = [0u8; CELL];
    let claimed_out: [u8; 32] = outputs[23..55].try_into().unwrap();
    let wrong = match dcg_kernels::execute(code, &values, &mut out) {
        Ok(n) => value_digest(&out[..n]) != claimed_out,
        Err(_) => true,
    };
    drop(g);
    if wrong {
        rule_challenger(run, dispute, challenger, ordinal as u16)
    } else {
        rule_executor(run, dispute, rest.first())
    }
}

fn producer_output(leaf: &[u8], node: u32, port: u16) -> Result<[u8; 32], ProgramError> {
    let mut l = Cursor { d: leaf, at: 64 + 4 + 4 + 4 + 8 + 4 + 4 };
    let n_in = l.u16()? as usize;
    l.take(n_in * VALUE_REF)?;
    let n_out = l.u16()? as usize;
    let outs = l.take(n_out * VALUE_REF)?;
    ref_digest(outs, n_out, node, 1, port).ok_or(err(53))
}

// 226: [caller(s), run(w), template, dispute(w), executor(w), challenger(w)]
// Deadlines: a silent executor loses, a silent challenger loses, and an idle
// run past its window finalizes (bond back to the executor).
fn settle_descent(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [_caller, run, template, dispute, executor, challenger, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let view = template_view(program_id, template)?;
    let _ = view;
    run_checked(program_id, run, template)?;
    dispute_checked(program_id, run, dispute)?;
    let slot = now()?;
    let (phase, deadline, run_deadline, status, exec_key) = {
        let dd = dispute.try_borrow_data()?;
        let d = run.try_borrow_data()?;
        (dd[D_PHASE], u64_at(&dd, D_DEADLINE)?, u64_at(&d, 24)?, d[4], key32(&d, 128)?)
    };
    if status != STATUS_COMMITTED {
        return Err(err(19));
    }
    match phase {
        PHASE_AWAIT_REGION | PHASE_AWAIT_LEAF if slot > deadline => rule_challenger(run, dispute, challenger, u16::MAX),
        PHASE_AWAIT_CHOICE | PHASE_AWAIT_REPLAY if slot > deadline => rule_executor(run, dispute, Some(executor)),
        PHASE_IDLE if slot > run_deadline => {
            if executor.key.to_bytes() != exec_key {
                return Err(err(28));
            }
            run.try_borrow_mut_data()?[4] = STATUS_FINAL;
            take_bond(run, executor)
        }
        _ => Err(err(23)),
    }
}

#[cfg(test)]
mod value_digest_tests {
    /// graph-plan-v2 §5 vector, shared with python/tests/test_descent_vectors.py.
    #[test]
    fn value_digest_matches_the_spec_vector() {
        let d = super::value_digest(&42i32.to_le_bytes());
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "1747c7d807a1bde7bbdbf92a721cfbe688e61715ce4391980fe7ee09e2ff95e1");
    }
}
