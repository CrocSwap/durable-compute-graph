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
    let verified = verify_canonical_lowering(graph, plan, table, &graph_id, &manifest_root)?;
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
    if d[4] != STATUS_COMMITTED {
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
    if d[4] != STATUS_COMMITTED {
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
