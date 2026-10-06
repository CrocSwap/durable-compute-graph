//! Run-level fuzzer for v2.1 disputes (tag 227): alpha plan R1, exit criterion 2.
//!
//! Each sequence is one template on the Hello Graph goldens, with:
//! - a random challenge window, phase window, bonds and slasher share;
//! - one committed run whose truth is honest, or any mix of a wrong step
//!   output, an empty leaf and a wrong posted output;
//! - sometimes a second run that is never committed (cancelled at the end);
//! - an executor that is diligent or lazy;
//! - one to seven disputes from honest challengers (protected: they always
//!   move on time), griefers (any move, any time, or none; sometimes
//!   reopening at a closed dispute's address) and executor puppets.
//!
//! The parties' moves interleave at random with:
//! - clock warps, and probes at a deadline's exact slot and the slot after;
//! - permissionless settlement calls, the template's retirement, and a run
//!   on a retired template;
//! - staging (create, grow by either party or the payer, write), and cache
//!   answers;
//! - perturbed instructions that must be refused: a wrong signer, an
//!   out-of-turn move, a corrupted reveal, a wrong recipient on a call that
//!   would otherwise be accepted, a foreign staging write, or a forged
//!   dispute record.
//!
//! Checked after every transaction:
//! - **a shadow ledger:** every tracked account's balance equals the model's
//!   prediction for the instruction (rent for creations, bonds at open and
//!   commit, bond moves at each ruling, moot, pot and finalize, and each
//!   close's refunds to the recorded payers); fees come from the untracked
//!   test payer;
//! - **a precondition model** for every settlement call (timeout, moot,
//!   advance, pay_pot, finalize, the closes, retire): accepted exactly when
//!   the program's rules say it may be;
//! - the run status moves only COMMITTED -> FINAL | REFUTED; the open and
//!   executor-wait counters match the live disputes; the sequence and closed
//!   counters match the accepted opens and closes; a ruling never changes;
//!   `best` is the lowest sequence ruled for the challenger;
//! - **ruling oracles:** a claim whose verdict the committed data fixes
//!   (SHAPE, OUT, and STEP at the second step) is ruled as predicted; an
//!   honest commitment answered diligently is never ruled for the
//!   challenger; an honest challenger is never ruled against.
//!
//! At the end every account closes, the run's receipt holds exactly its rent
//! floor, the template closes, honest parties net non-negative, a lie that
//! an honest challenger disputed ends REFUTED, and an honest run answered
//! diligently ends FINAL.
//!
//! Sequence `i` of seed `s` depends only on `(s, i)`:
//!
//!   cargo test -p dcg-program --features graph-v21 --test disputes_v21_run_fuzz
//!   V21_FUZZ_SEED=7 V21_FUZZ_COUNT=500 cargo test ... -- --ignored run_fuzz_campaign
//!   V21_FUZZ_SEED=7 V21_FUZZ_ONLY=123 ...      # one sequence, with its trace
//!
//! `V21_SBF=1`, with `BPF_OUT_DIR` naming a graph-v21 image, runs the SBF
//! program instead of the native one.
//!
//! Not reached (Hello Graph is two steps and one output): a descent deeper
//! than one level, more than one reveal cache, list inputs, LX1 templates
//! and staged opens. Those are covered by the oracle and LX fuzz suites.
#![cfg(feature = "graph-v21")]

use dcg_disputes as D;
use dcg_program::disputes_v21 as V;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{clock::Clock, rent::Rent, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::collections::BTreeMap;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD6; 32]);
const SYSTEM: Pubkey = system_program::ID;
const OUT_BASE: u32 = 4; // header, block, 2 InSpecs
const STEP_BASE: u32 = 7; // + 1 OutSpec, 2 RegionSpecs
const FUND: u64 = 10_000_000_000;
const A: u8 = 0xA1; // admitter and run payer
const E: u8 = 0xE1; // executor
const B: u8 = 0xB1; // bystander
/// remainder_to on a version-1 run (mainnet hardening H4): a convicted
/// executor's bond remainder goes here instead of to the payer A.
const R: u8 = 0xD1;
const CHALLENGERS: [u8; 5] = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
const ACTORS: [u8; 9] = [A, E, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, B, R];
/// Funds forged accounts, so the bank's capitalization stays exact. Outside
/// the ledger.
const FORGER: u8 = 0xF1;
/// Protected moves are made at least this many slots before their deadline.
const MARGIN: u64 = 50;

// Account offsets (crates/dcg-program/src/disputes_v21.rs).
const R_STATUS: usize = 4;
const R_DEADLINE: usize = 144;
const R_OPEN: usize = 152;
const R_SEQ: usize = 160;
const R_PREFIX: usize = 168;
const R_BEST: usize = 176;
const R_PAID: usize = 184;
const R_CLOSED: usize = 188;
const D_PHASE: usize = 4;
const D_RULING: usize = 6;
const D_POSITION: usize = 16;
const D_DEADLINE: usize = 24;
const D_SEQ: usize = 136;
const D_BYTES: usize = 136 + 8 + 32 * 32 + 8 + V::MAX_LEAF + 32;
const PH_NODES: u8 = 1;
const PH_PICK: u8 = 2;
const PH_LEAF: u8 = 3;
const PH_CLAIM: u8 = 4;
const PH_RULED: u8 = 5;
const STAGE_OTHER_GROWTH: usize = 44;

// ---------------------------------------------------------------------------
// Goldens and commitments (as in disputes_v21_skeleton.rs).

struct Soft;
impl D::Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        sha256(parts)
    }
}

fn kp(b: u8) -> Keypair {
    Keypair::new_from_array([b; 32])
}

fn pk(b: u8) -> Pubkey {
    kp(b).pubkey()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Golden {
    records: Vec<(u8, Vec<u8>)>,
    spec_root: [u8; 32],
    plan_id: Vec<u8>,
    leaves: Vec<Vec<u8>>,
    out_entries: Vec<Vec<u8>>,
    refs: Vec<Vec<u8>>,
}

fn golden() -> Golden {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let h = &v["hello"];
    let strs = |k: &str| -> Vec<Vec<u8>> { h[k].as_array().unwrap().iter().map(|x| hex(x.as_str().unwrap())).collect() };
    Golden {
        records: h["spec_records"].as_array().unwrap().iter().map(|r| (r[0].as_u64().unwrap() as u8, hex(r[1].as_str().unwrap()))).collect(),
        spec_root: hex(h["spec_root"].as_str().unwrap()).try_into().unwrap(),
        plan_id: hex(h["plan_id"].as_str().unwrap()),
        leaves: strs("leaves"),
        out_entries: strs("out_entries"),
        refs: (0..2).map(|e| hex(h["external_refs"][e.to_string()].as_str().unwrap())).collect(),
    }
}

fn levels(tree: D::Tree, leaves: &[D::Hash]) -> Vec<Vec<D::Hash>> {
    let n = leaves.len().max(1);
    let height = usize::BITS - (n - 1).leading_zeros();
    let mut row = leaves.to_vec();
    row.resize(1 << height, D::empty(&Soft, tree, 0));
    let mut out = vec![row.clone()];
    for l in 0..height {
        row = row.chunks(2).map(|p| D::node(&Soft, tree, l as u16, &p[0], &p[1])).collect();
        out.push(row.clone());
    }
    out
}

fn path(levels: &[Vec<D::Hash>], mut position: usize) -> Vec<D::Hash> {
    let mut out = vec![];
    for row in &levels[..levels.len() - 1] {
        out.push(row[position ^ 1]);
        position >>= 1;
    }
    out
}

fn enc_path(p: &[D::Hash]) -> Vec<u8> {
    let mut v = vec![p.len() as u8];
    for h in p {
        v.extend_from_slice(h);
    }
    v
}

struct Commit {
    leaves: Vec<Option<Vec<u8>>>,
    outs: Vec<Vec<u8>>,
    step: Vec<Vec<D::Hash>>,
    root_bytes: [u8; 176],
}

fn commitment(g: &Golden, run_id: &[u8], leaves: Vec<Option<Vec<u8>>>, outs: Vec<Vec<u8>>) -> Commit {
    let hashes: Vec<D::Hash> = leaves.iter().map(|l| D::leaf_hash(&Soft, l.as_deref())).collect();
    let step = levels(D::Tree::Step, &hashes);
    let out_hashes: Vec<D::Hash> = outs.iter().enumerate().map(|(j, e)| D::out_leaf(&Soft, j as u64, Some(e))).collect();
    let out = levels(D::Tree::Out, &out_hashes);
    let mut root = Vec::new();
    root.extend_from_slice(&g.plan_id);
    root.extend_from_slice(run_id);
    root.extend_from_slice(&g.spec_root);
    root.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    root.extend_from_slice(step.last().unwrap()[0].as_slice());
    root.extend_from_slice(&(outs.len() as u64).to_le_bytes());
    root.extend_from_slice(out.last().unwrap()[0].as_slice());
    Commit { leaves, outs, step, root_bytes: root.try_into().unwrap() }
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}

fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Generator.

struct Rng(u64);

impl Rng {
    fn new(seed: u64, index: u64) -> Self {
        let mut r = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5851_F42D_4C95_7F2D);
        r.next();
        r
    }

    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    fn pct(&mut self, p: u64) -> bool {
        self.below(100) < p
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Lie {
    Step,  // leaf 1 commits a wrong output: STEP convicts at position 1
    Empty, // leaf 0 is absent: SHAPE convicts at position 0
    Out,   // the posted output is wrong: OUT convicts
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Plan {
    Honest(Lie), // the right line against one lie; always on time
    Grief,       // any line, any time, or none
    Puppet(Lie), // the executor challenging its own lie; not protected
}

impl Plan {
    fn protected(self) -> bool {
        matches!(self, Plan::Honest(_))
    }
}

fn kind_for(lie: Lie) -> u8 {
    if lie == Lie::Out { V::KIND_OUT_DESCEND } else { V::KIND_STEP_DESCEND }
}

struct Dsp {
    key: Pubkey,
    who: u8,
    nonce: u8,
    kind: u8,
    plan: Plan,
    opened: bool,
    gave_up: bool,
    seq: u64,
    phase: u8,
    ruling: u8,
    deadline: u64,
    position: u64,
    closed: bool,
    skip: BTreeMap<u8, bool>,
}

impl Dsp {
    fn live(&self) -> bool {
        self.opened && !self.closed
    }

    fn unruled(&self) -> bool {
        self.live() && self.ruling == V::RULING_OPEN
    }

    fn pending(&self) -> bool {
        !self.opened && !self.closed && !self.gave_up
    }

    /// The party that owes the next move, by phase.
    fn owner(&self) -> u8 {
        if matches!(self.phase, PH_NODES | PH_LEAF) { E } else { self.who }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Perm {
    Timeout,
    Moot,
    Advance,
    PayPot,
    CloseDispute,
    Finalize,
    CloseCache,
    CloseRun,
    CloseRun2,
    CloseTemplate,
    Retire,
}

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    Any,
    Accepted,
    Refused,
}

/// What an instruction does to lamports, for the shadow ledger.
#[derive(Clone, Copy, Debug)]
enum Op {
    None,
    CreateTemplate,
    InitRun(Pubkey),
    Commit,
    Open(usize),
    Nodes { cache: bool },
    StageCreate { k: usize, role: u8, creator: u8 },
    StageGrow { k: usize, role: u8, funder: u8 },
    Rule(usize),
    Moot(usize),
    PayPot(usize),
    Finalize,
    CloseDispute(usize),
    CloseRun(Pubkey),
    CloseCache,
    CloseTemplate,
}

/// Pre-state an op's ledger rule needs.
#[derive(Default)]
struct Pre {
    lamports: BTreeMap<Pubkey, u64>,
    buffers: Vec<(u8, u8, u64, u64)>, // (role, creator byte, other_paid, lamports)
    run_open: bool,
}

struct World {
    ctx: ProgramTestContext,
    rng: Rng,
    rent: Rent,
    case: String,
    label: String,
    trace: Vec<String>,
    g: Golden,
    spec_levels: Vec<Vec<D::Hash>>,
    c: Commit,
    lies: Vec<Lie>,
    e_diligent: bool,
    executor_bond: u64,
    challenger_bond: u64,
    slasher_bps: u64,
    /// Who receives a convicted executor's remainder: A (version 0) or R (version 1).
    remainder: u8,
    template: Pubkey,
    template_id: [u8; 32],
    run: Pubkey,
    run2: Option<Pubkey>,
    cache: Pubkey,
    ds: Vec<Dsp>,
    opened: u64,
    closed: u32,
    status: u8,
    best: u64,
    paid: bool,
    run_closed: bool,
    run2_closed: bool,
    retired: bool,
    template_closed: bool,
    ledger: Vec<Pubkey>,
    init: BTreeMap<u8, u64>,
    txs: u64,
    accepted: u64,
    refused_perturbations: u64,
    rulings_by_proof: u64,
    oracle_checked: u64,
    boundary_probes: u64,
    coverage: BTreeMap<String, u64>,
    /// A fault the checks must catch (planted-fault tests only).
    plant: Option<&'static str>,
}

fn buffer(d: Pubkey, role: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg21stg", d.as_ref(), &[role]], &PROGRAM).0
}

fn dispute_key(run: Pubkey, who: u8, nonce: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg21dsp", run.as_ref(), pk(who).as_ref(), &[nonce; 32]], &PROGRAM).0
}

fn run_key(template_id: &[u8; 32], nonce: u8, refs: &[u8]) -> Pubkey {
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", template_id, &[nonce; 32], &2u32.to_le_bytes(), refs, pk(E).as_ref()]);
    Pubkey::find_program_address(&[b"dcg21run", &run_id, pk(A).as_ref()], &PROGRAM).0
}

impl World {
    async fn new(seed: u64, index: u64) -> Self {
        let mut rng = Rng::new(seed, index);
        let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
        let mut test = ProgramTest::default();
        test.prefer_bpf(sbf);
        if sbf {
            test.add_program("dcg_program", PROGRAM, None);
        } else {
            test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
        }
        for b in ACTORS.into_iter().chain([FORGER]) {
            test.add_account(pk(b), Account { lamports: FUND, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
        }
        let mut ctx = test.start_with_context().await;
        let rent = ctx.banks_client.get_rent().await.unwrap();
        let g = golden();
        let spec_leaves: Vec<D::Hash> = g.records.iter().map(|(t, r)| D::spec_leaf(&Soft, *t, r)).collect();
        let spec_levels = levels(D::Tree::Spec, &spec_leaves);

        // Template parameters.
        let challenge_window = rng.range(750, 2_500);
        let phase_window = rng.range(750, 1_200);
        let executor_bond = rng.pick(&[1_000_000u64, 2_000_000, 3_500_000]);
        let challenger_bond = rng.pick(&[500_000u64, 1_000_000, 1_700_000]);
        let slasher_bps = rng.pick(&[1u64, 2_500, 5_000, 7_777, 9_999]); // admission: 1..=9,999
        let mut data = vec![4u8];
        for x in [2u64, 1, challenge_window, phase_window, executor_bond, challenger_bond] {
            data.extend_from_slice(&x.to_le_bytes());
        }
        data.extend_from_slice(&OUT_BASE.to_le_bytes());
        data.extend_from_slice(&STEP_BASE.to_le_bytes());
        data.extend_from_slice(&g.spec_root);
        data.extend_from_slice(&(slasher_bps as u16).to_le_bytes());
        data.extend_from_slice(&g.plan_id);
        let template_id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
        let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, pk(A).as_ref()], &PROGRAM).0;
        let mut refs = Vec::new();
        for r in &g.refs {
            refs.extend_from_slice(r);
        }
        let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &[0u8; 32], &2u32.to_le_bytes(), &refs, pk(E).as_ref()]);
        let run = run_key(&template_id, 0, &refs);
        let run2 = rng.pct(30).then(|| run_key(&template_id, 1, &refs));
        let cache = Pubkey::find_program_address(&[b"dcg21rc", run.as_ref(), &[V::KIND_STEP_DESCEND], &1u32.to_le_bytes(), &0u64.to_le_bytes()], &PROGRAM).0;

        // The committed truth.
        let mut lies = vec![];
        if rng.pct(70) {
            for lie in [Lie::Step, Lie::Empty, Lie::Out] {
                if rng.pct(45) {
                    lies.push(lie);
                }
            }
            if lies.is_empty() {
                lies.push(rng.pick(&[Lie::Step, Lie::Empty, Lie::Out]));
            }
        }
        let mut leaves: Vec<Option<Vec<u8>>> = g.leaves.iter().map(|l| {
            let mut l = l.clone();
            l[32..64].copy_from_slice(&run_id);
            Some(l)
        }).collect();
        let mut outs = g.out_entries.clone();
        if lies.contains(&Lie::Step) {
            let l = leaves[1].as_mut().unwrap();
            let n = l.len();
            l[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
        }
        if lies.contains(&Lie::Empty) {
            leaves[0] = None;
        }
        if lies.contains(&Lie::Out) {
            outs[0][23..55].copy_from_slice(&D::value_digest(&Soft, &7i32.to_le_bytes()));
        }
        let c = commitment(&g, &run_id, leaves, outs);
        let e_diligent = rng.pct(if lies.is_empty() { 75 } else { 55 });
        let remainder = if rng.pct(50) { R } else { A };

        // The disputes that will be opened.
        let mut plans = vec![];
        if !lies.is_empty() {
            let honest = if rng.pct(80) { rng.range(1, 2) } else { 0 };
            for _ in 0..honest {
                plans.push(Plan::Honest(rng.pick(&lies)));
            }
            if rng.pct(20) {
                plans.push(Plan::Puppet(rng.pick(&lies)));
            }
        }
        for _ in 0..rng.range(if plans.is_empty() { 1 } else { 0 }, 4) {
            plans.push(Plan::Grief);
        }
        // Each challenger account is honest or a griefer, never both, so its
        // net can be judged; honest plans take the first accounts.
        let mut ds = vec![];
        let mut next_honest = 0usize;
        for (n, plan) in plans.iter().enumerate() {
            let who = match plan {
                Plan::Puppet(_) => E,
                Plan::Honest(_) => {
                    let w = CHALLENGERS[next_honest];
                    next_honest += 1;
                    w
                }
                Plan::Grief => {
                    let free = &CHALLENGERS[next_honest..];
                    free[rng.below(free.len() as u64) as usize]
                }
            };
            let kind = match plan {
                Plan::Honest(l) | Plan::Puppet(l) => kind_for(*l),
                Plan::Grief => rng.pick(&[V::KIND_STEP_DESCEND, V::KIND_STEP_DESCEND, V::KIND_STEP_DESCEND, V::KIND_OUT_DESCEND, V::KIND_OUT_DESCEND, 9]),
            };
            let nonce = n as u8 + 1;
            let key = dispute_key(run, who, nonce);
            ds.push(Dsp { key, who, nonce, kind, plan: *plan, opened: false, gave_up: false, seq: 0, phase: 0, ruling: 0, deadline: 0, position: 0, closed: false, skip: BTreeMap::new() });
        }

        let mut ledger: Vec<Pubkey> = ACTORS.iter().map(|b| pk(*b)).collect();
        ledger.extend([template, run, cache]);
        ledger.extend(run2);
        for d in &ds {
            ledger.extend([d.key, buffer(d.key, V::ROLE_EXECUTOR), buffer(d.key, V::ROLE_CHALLENGER)]);
        }
        ledger.sort();
        ledger.dedup();
        let label = format!("run v{} lies {lies:?} executor {} windows {challenge_window}/{phase_window} bonds {executor_bond}/{challenger_bond} slasher {slasher_bps} second run {} plans {:?}",
            u8::from(remainder == R), if e_diligent { "diligent" } else { "lazy" }, run2.is_some(), ds.iter().map(|d| (d.plan, format!("{:x}", d.who), d.kind)).collect::<Vec<_>>());
        let _ = &mut ctx;
        let mut w = World {
            ctx, rng, rent, case: format!("seed {seed} sequence {index}"), label, trace: vec![], g, spec_levels, c, lies, e_diligent,
            executor_bond, challenger_bond, slasher_bps, remainder, template, template_id, run, run2, cache, ds, opened: 0, closed: 0,
            status: V::RUN_OPEN, best: u64::MAX, paid: false, run_closed: false, run2_closed: false, retired: false,
            template_closed: false, ledger, init: BTreeMap::new(), txs: 0, accepted: 0, refused_perturbations: 0,
            rulings_by_proof: 0, oracle_checked: 0, boundary_probes: 0, coverage: BTreeMap::new(), plant: None,
        };
        for b in ACTORS {
            let bal = w.balance(pk(b)).await;
            w.init.insert(b, bal);
        }

        // Template, runs and commit.
        let create = ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(pk(A), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        w.send("create_template", create, A, Expect::Accepted, Op::CreateTemplate).await;
        for (nonce, key) in [(0u8, Some(run)), (1, run2)] {
            let Some(key) = key else { continue };
            let i = w.init_ix(nonce, key);
            w.send(&format!("init_run {nonce}"), i, A, Expect::Accepted, Op::InitRun(key)).await;
        }
        let root = w.c.root_bytes;
        let i = ix(V::SUB_COMMIT, &root, vec![AccountMeta::new(pk(E), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        w.send("commit", i, E, Expect::Accepted, Op::Commit).await;
        w
    }

    fn init_ix(&self, nonce: u8, key: Pubkey) -> Instruction {
        let mut init = vec![nonce; 32];
        init.extend_from_slice(pk(E).as_ref());
        init.extend_from_slice(&2u32.to_le_bytes());
        for r in &self.g.refs {
            init.extend_from_slice(r);
        }
        let sub = if self.remainder == R {
            init.extend_from_slice(pk(R).as_ref());
            V::SUB_INIT_RUN_V1
        } else {
            V::SUB_INIT_RUN
        };
        ix(sub, &init, vec![AccountMeta::new(pk(A), true), AccountMeta::new(key, false), AccountMeta::new(self.template, false), AccountMeta::new_readonly(SYSTEM, false)])
    }

    fn fail(&self, what: &str) -> ! {
        let tail = self.trace.len().saturating_sub(60);
        panic!("{}: {what}\n  sequence: {}\n  trace (last {}):\n    {}", self.case, self.label, self.trace.len() - tail, self.trace[tail..].join("\n    "));
    }

    async fn balance(&mut self, k: Pubkey) -> u64 {
        self.ctx.banks_client.get_balance(k).await.unwrap()
    }

    async fn balances(&mut self) -> BTreeMap<Pubkey, u64> {
        let mut m = BTreeMap::new();
        for k in self.ledger.clone() {
            let b = self.balance(k).await;
            m.insert(k, b);
        }
        m
    }

    async fn now(&mut self) -> u64 {
        self.ctx.banks_client.get_sysvar::<Clock>().await.unwrap().slot
    }

    async fn account(&mut self, k: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(k).await.unwrap().filter(|a| a.lamports > 0 || !a.data.is_empty())
    }

    async fn run_data(&mut self) -> Option<Vec<u8>> {
        self.account(self.run).await.map(|a| a.data).filter(|d| d.len() != V::RECEIPT_BYTES)
    }

    // --- sending, and the shadow ledger ---------------------------------------------

    /// Send one instruction signed by `signer` (the test payer pays fees), then
    /// check the ledger and every invariant.
    async fn send(&mut self, name: &str, i: Instruction, signer: u8, expect: Expect, op: Op) -> bool {
        let ok = self.send_raw(name, i, signer, expect, op).await;
        self.check().await;
        ok
    }

    async fn pre(&mut self, op: Op) -> Pre {
        let mut p = Pre { lamports: self.balances().await, ..Pre::default() };
        if let Op::CloseDispute(k) = op {
            let d = self.ds[k].key;
            for role in [V::ROLE_EXECUTOR, V::ROLE_CHALLENGER] {
                if let Some(b) = self.account(buffer(d, role)).await {
                    if b.data.len() >= 48 {
                        p.buffers.push((role, b.data[5], u32_at(&b.data, STAGE_OTHER_GROWTH) as u64, b.lamports));
                    }
                }
            }
        }
        if let Op::CloseRun(r) = op {
            p.run_open = self.account(r).await.is_some_and(|a| a.data.len() != V::RECEIPT_BYTES && a.data[R_STATUS] == V::RUN_OPEN);
        }
        p
    }

    /// The balance changes `op` must cause, given the pre-state.
    async fn deltas(&mut self, op: Op, pre: &Pre) -> BTreeMap<Pubkey, i128> {
        let mut m: BTreeMap<Pubkey, i128> = BTreeMap::new();
        let mut mv = |from: Pubkey, to: Pubkey, amount: u64| {
            *m.entry(from).or_default() -= amount as i128;
            *m.entry(to).or_default() += amount as i128;
        };
        let rent_of = |w: &World, len: usize| w.rent.minimum_balance(len);
        let lam = |k: &Pubkey| *pre.lamports.get(k).unwrap_or(&0);
        match op {
            Op::None => {}
            Op::CreateTemplate => {
                let len = self.account(self.template).await.unwrap().data.len();
                mv(pk(A), self.template, rent_of(self, len));
            }
            Op::InitRun(r) => {
                let len = self.account(r).await.unwrap().data.len();
                mv(pk(A), r, rent_of(self, len));
            }
            Op::Commit => mv(pk(E), self.run, self.executor_bond),
            Op::Open(k) => {
                let (who, key) = (self.ds[k].who, self.ds[k].key);
                let len = self.account(key).await.unwrap().data.len();
                if len != D_BYTES {
                    self.fail(&format!("dispute size {len}, expected {D_BYTES}"));
                }
                mv(pk(who), key, rent_of(self, len) + self.challenger_bond);
            }
            Op::Nodes { cache } => {
                if cache {
                    let len = self.account(self.cache).await.unwrap().data.len();
                    mv(pk(E), self.cache, rent_of(self, len));
                }
            }
            Op::StageCreate { k, role, creator } => {
                let b = buffer(self.ds[k].key, role);
                let len = self.account(b).await.unwrap().data.len();
                mv(pk(creator), b, rent_of(self, len));
            }
            Op::StageGrow { k, role, funder } => {
                let b = buffer(self.ds[k].key, role);
                let len = self.account(b).await.unwrap().data.len();
                mv(pk(funder), b, rent_of(self, len).saturating_sub(lam(&b)));
            }
            Op::Rule(k) | Op::Moot(k) => {
                let (key, who) = (self.ds[k].key, self.ds[k].who);
                let ruling = self.account(key).await.map(|a| a.data[D_RULING]).unwrap_or(0);
                let extra = lam(&key) - rent_of(self, D_BYTES);
                if ruling == V::RULING_EXECUTOR {
                    mv(key, pk(E), extra);
                } else if ruling != V::RULING_OPEN {
                    mv(key, pk(who), extra);
                }
            }
            Op::PayPot(k) => {
                let share = self.executor_bond * self.slasher_bps / 10_000;
                mv(self.run, pk(self.ds[k].who), share);
                mv(self.run, pk(self.remainder), self.executor_bond - share);
            }
            Op::Finalize => mv(self.run, pk(E), self.executor_bond),
            Op::CloseDispute(k) => {
                let (key, who) = (self.ds[k].key, self.ds[k].who);
                for &(role, creator, other_paid, lamports) in &pre.buffers {
                    let b = buffer(key, role);
                    let (to_creator, to_other) = if creator == 1 { (pk(E), pk(who)) } else { (pk(who), pk(E)) };
                    let other = other_paid.min(lamports);
                    mv(b, to_other, other);
                    mv(b, to_creator, lamports - other);
                }
                mv(key, pk(who), lam(&key));
            }
            Op::CloseRun(r) => {
                let keep = if pre.run_open { 0 } else { rent_of(self, V::RECEIPT_BYTES) };
                mv(r, pk(A), lam(&r) - keep);
            }
            Op::CloseCache => mv(self.cache, pk(E), lam(&self.cache)),
            Op::CloseTemplate => mv(self.template, pk(A), lam(&self.template)),
        }
        m
    }

    async fn send_raw(&mut self, name: &str, i: Instruction, signer: u8, expect: Expect, op: Op) -> bool {
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let pre = self.pre(op).await;
        let n = NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let blockhash = self.ctx.banks_client.get_latest_blockhash().await.unwrap();
        let price = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_price(n);
        let s = kp(signer);
        let all = vec![&self.ctx.payer, &s];
        let tx = Transaction::new(&all, solana_message::Message::new(&[i, price], Some(&self.ctx.payer.pubkey())), blockhash);
        let result = self.ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| format!("{e:?}")).and_then(|m| m.result.map_err(|e| format!("{e:?}")));
        self.txs += 1;
        let ok = result.is_ok();
        let slot = self.now().await;
        self.trace.push(format!("@{slot} {name} by {signer:x}: {}", match &result { Ok(()) => "ok".into(), Err(e) => e.clone() }));
        if ok {
            self.accepted += 1;
            let key = name.split(" d").next().unwrap_or(name).to_string();
            *self.coverage.entry(key).or_default() += 1;
        }
        match expect {
            Expect::Accepted if !ok => self.fail(&format!("{name} must be accepted")),
            Expect::Refused if ok => self.fail(&format!("{name} must be refused")),
            Expect::Refused => self.refused_perturbations += 1,
            _ => {}
        }
        if ok && self.plant == Some("transfer") && self.status == V::RUN_COMMITTED {
            self.apply_plant(true).await; // as if this instruction had moved it
        }
        // The shadow ledger: exactly the op's moves, or none on refusal.
        let want = if ok { self.deltas(op, &pre).await } else { BTreeMap::new() };
        let post = self.balances().await;
        for (k, after) in &post {
            let expected = pre.lamports[k] as i128 + want.get(k).copied().unwrap_or(0);
            if *after as i128 != expected {
                self.fail(&format!("ledger: after {name} ({op:?}), {k} holds {after}, the model says {expected}"));
            }
        }
        ok
    }

    /// Every invariant other than the ledger, against the accounts.
    async fn check(&mut self) {
        if self.balance(pk(B)).await != self.init[&B] {
            self.fail("the bystander's balance changed");
        }
        let Some(run) = self.account(self.run).await else {
            if self.status != V::RUN_OPEN {
                self.fail("the run account vanished");
            }
            return;
        };
        let status = run.data[R_STATUS];
        let allowed = match self.status {
            V::RUN_OPEN => [V::RUN_OPEN, V::RUN_COMMITTED].contains(&status),
            V::RUN_COMMITTED => [V::RUN_COMMITTED, V::RUN_FINAL, V::RUN_REFUTED].contains(&status),
            s => status == s,
        };
        if !allowed {
            self.fail(&format!("run status {} -> {status}", self.status));
        }
        self.status = status;
        if run.data.len() == V::RECEIPT_BYTES {
            if !self.run_closed {
                self.fail("the run shrank to its receipt without an accepted close");
            }
            if run.lamports != self.rent.minimum_balance(V::RECEIPT_BYTES) {
                self.fail("the receipt holds more than its rent floor");
            }
            return;
        }
        if self.run_closed {
            self.fail("an accepted close_run left the full run");
        }
        let r = run.data;
        let mut unruled = 0u32;
        let mut waiting = 0u32;
        let mut best = u64::MAX;
        for k in 0..self.ds.len() {
            let (key, live, opened, closed, who, nonce, seq, old_ruling, old_phase) = {
                let d = &self.ds[k];
                (d.key, d.live(), d.opened, d.closed, d.who, d.nonce, d.seq, d.ruling, d.phase)
            };
            let acct = self.account(key).await;
            if !live {
                // A reopened dispute shares its address with the closed one.
                let reused = self.ds.iter().any(|o| o.key == key && o.live());
                if acct.is_some() && !reused && !opened {
                    self.fail(&format!("dispute {who:x}/{nonce} exists without an accepted open"));
                }
                if acct.is_some() && !reused && closed {
                    self.fail(&format!("dispute {who:x}/{nonce} survived its close"));
                }
                continue;
            }
            let Some(a) = acct else {
                self.fail(&format!("live dispute {who:x}/{nonce} vanished"));
            };
            let (phase, ruling) = (a.data[D_PHASE], a.data[D_RULING]);
            if u64_at(&a.data, D_SEQ) != seq {
                self.fail(&format!("dispute {who:x}/{nonce} sequence {} != {seq}", u64_at(&a.data, D_SEQ)));
            }
            if old_ruling != V::RULING_OPEN && ruling != old_ruling {
                self.fail(&format!("dispute seq {seq} ruling changed: {old_ruling} -> {ruling}"));
            }
            if (ruling != V::RULING_OPEN) != (phase == PH_RULED) {
                self.fail(&format!("dispute seq {seq} phase {phase} with ruling {ruling}"));
            }
            if old_ruling == V::RULING_OPEN && old_phase == PH_CLAIM && matches!(ruling, V::RULING_CHALLENGER | V::RULING_EXECUTOR) {
                self.rulings_by_proof += 1;
            }
            let d = &mut self.ds[k];
            d.phase = phase;
            d.ruling = ruling;
            d.deadline = u64_at(&a.data, D_DEADLINE);
            d.position = u64_at(&a.data, D_POSITION);
            if ruling == V::RULING_OPEN {
                unruled += 1;
                if matches!(phase, PH_NODES | PH_LEAF) {
                    waiting += 1;
                }
            }
        }
        for d in &self.ds {
            if d.opened && d.ruling == V::RULING_CHALLENGER {
                best = best.min(d.seq);
            }
            if d.plan.protected() && d.opened && d.ruling == V::RULING_EXECUTOR {
                self.fail(&format!("honest challenger {:x} ruled against (seq {})", d.who, d.seq));
            }
            if self.lies.is_empty() && self.e_diligent && d.opened && d.ruling == V::RULING_CHALLENGER {
                self.fail(&format!("an honest, diligent executor ruled against (seq {})", d.seq));
            }
        }
        let wait = u32_at(&r, r.len() - 4 - if r[5] == 1 { 32 } else { 0 }); // waiting_E precedes a v1 run's remainder_to
        let checks = [
            ("open count", u32_at(&r, R_OPEN) as u64, unruled as u64),
            ("executor-wait count", wait as u64, waiting as u64),
            ("sequence counter", u64_at(&r, R_SEQ), self.opened),
            ("closed counter", u32_at(&r, R_CLOSED) as u64, self.closed as u64),
            ("best win", u64_at(&r, R_BEST), best),
        ];
        for (name, got, want) in checks {
            if got != want {
                self.fail(&format!("{name}: run has {got}, accounts imply {want}"));
            }
        }
        if (best != u64::MAX) != (status == V::RUN_REFUTED) {
            self.fail("refuted iff some dispute was ruled for the challenger");
        }
        let paid = r[R_PAID] != 0;
        if paid != self.paid {
            self.fail("pot-paid flag differs from accepted pay_pot");
        }
        if paid && (status != V::RUN_REFUTED || u64_at(&r, R_PREFIX) <= best) {
            self.fail("pot paid before the ruled prefix passed the best win");
        }
        if u64_at(&r, R_PREFIX) > self.opened {
            self.fail("ruled prefix past the sequence counter");
        }
        self.best = best;
        self.apply_plant(false).await;
    }

    /// Planted-fault tests: corrupt the state once, the way a program bug
    /// would, and let the next check catch it.
    async fn apply_plant(&mut self, in_tx: bool) {
        let Some(plant) = self.plant else { return };
        if in_tx != (plant == "transfer") {
            return;
        }
        let mut run = self.ctx.banks_client.get_account(self.run).await.unwrap().unwrap();
        match plant {
            // One lamport from the run to the executor: conserved overall, so
            // only the per-account ledger can see it.
            "transfer" if self.status == V::RUN_COMMITTED => {
                let mut e = self.ctx.banks_client.get_account(pk(E)).await.unwrap().unwrap();
                run.lamports -= 1;
                e.lamports += 1;
                self.ctx.set_account(&pk(E), &e.into());
                self.ctx.set_account(&self.run, &run.into());
            }
            "wait" if self.status == V::RUN_COMMITTED => {
                let n = run.data.len();
                run.data[n - 4] = run.data[n - 4].wrapping_add(1);
                self.ctx.set_account(&self.run, &run.into());
            }
            "ruling" => {
                let Some(k) = (0..self.ds.len()).find(|&k| self.ds[k].live() && matches!(self.ds[k].ruling, V::RULING_CHALLENGER | V::RULING_EXECUTOR)) else { return };
                let mut d = self.ctx.banks_client.get_account(self.ds[k].key).await.unwrap().unwrap();
                d.data[D_RULING] = 3 - d.data[D_RULING];
                self.ctx.set_account(&self.ds[k].key, &d.into());
            }
            _ => return,
        }
        self.trace.push(format!("planted fault: {plant}"));
        self.plant = None;
    }

    // --- instruction builders ----------------------------------------------

    fn party(&self, who: u8, d: Pubkey) -> Vec<AccountMeta> {
        vec![AccountMeta::new_readonly(pk(who), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false)]
    }

    fn spec_opening(&self, leaf: usize) -> Vec<u8> {
        let (t, r) = &self.g.records[leaf];
        let mut v = vec![*t];
        v.extend_from_slice(&(r.len() as u16).to_le_bytes());
        v.extend_from_slice(r);
        v.extend(enc_path(&path(&self.spec_levels, leaf)));
        v
    }

    fn step_opening(&self, ordinal: usize) -> Vec<u8> {
        let l = self.c.leaves[ordinal].clone();
        let mut v = vec![l.is_some() as u8];
        let body = l.unwrap_or_default();
        v.extend_from_slice(&(body.len() as u16).to_le_bytes());
        v.extend_from_slice(&body);
        v.extend(enc_path(&path(&self.c.step, ordinal)));
        v
    }

    fn nodes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.c.step[0][0]);
        v.extend_from_slice(&self.c.step[0][1]);
        v
    }

    fn leaf_bytes(&self, d: &Dsp) -> Vec<u8> {
        if d.kind == V::KIND_OUT_DESCEND {
            let mut v = vec![1u8];
            v.extend_from_slice(&self.c.outs[0]);
            return v;
        }
        let l = &self.c.leaves[d.position as usize % 2];
        let mut v = vec![l.is_some() as u8];
        if let Some(l) = l {
            v.extend_from_slice(l);
        }
        v
    }

    /// A claim for dispute `k` by its plan, and the ruling the committed data
    /// fixes for it, where the oracle knows it.
    fn claim_body(&mut self, k: usize) -> (Vec<u8>, Option<u8>) {
        let (plan, kind, pos) = (self.ds[k].plan, self.ds[k].kind, self.ds[k].position as usize % 2);
        let lie = |l: Lie| self.lies.contains(&l);
        let (step_lie, empty_lie, out_lie) = (lie(Lie::Step), lie(Lie::Empty), lie(Lie::Out));
        let verdict = |c: bool| Some(if c { V::RULING_CHALLENGER } else { V::RULING_EXECUTOR });
        let step = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_STEP, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            b.push(1);
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(&42i32.to_le_bytes());
            // STEP at the second step replays identity(42): wrong iff its output is.
            (b, if pos == 1 && !empty_lie { verdict(step_lie) } else { None })
        };
        let shape = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_SHAPE, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            // SHAPE convicts an absent leaf and loses against a well-formed one.
            (b, verdict(w.c.leaves[pos].is_none()))
        };
        let edge = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_EDGE, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            b.extend(w.step_opening(1 - pos));
            (b, None)
        };
        let out = |w: &Self| {
            let mut b = vec![V::CLAIM_OUT, 0];
            b.extend(w.spec_opening(OUT_BASE as usize));
            b.extend(w.step_opening(1));
            // OUT compares the posted output with the second step's output.
            (b, verdict(out_lie || step_lie))
        };
        match plan {
            Plan::Honest(l) | Plan::Puppet(l) => match l {
                Lie::Step => step(self, 1),
                Lie::Empty => shape(self, 0),
                Lie::Out => out(self),
            },
            Plan::Grief => {
                if kind == V::KIND_OUT_DESCEND {
                    match self.rng.below(3) {
                        0 => step(self, pos),
                        _ => out(self),
                    }
                } else {
                    match self.rng.below(5) {
                        0 => step(self, pos),
                        1 => shape(self, pos),
                        2 => edge(self, pos),
                        3 => out(self),
                        _ => (vec![self.rng.pick(&[V::CLAIM_GATE, V::CLAIM_STATE, 0, 77]), 0], None),
                    }
                }
            }
        }
    }

    fn claim_accounts(&self, signer: u8, k: usize) -> Vec<AccountMeta> {
        let d = &self.ds[k];
        vec![AccountMeta::new_readonly(pk(signer), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d.key, false), AccountMeta::new(pk(E), false), AccountMeta::new(pk(d.who), false)]
    }

    fn perm_ix(&self, p: Perm, k: usize, caller: u8, challenger: u8, payer: u8, executor: u8) -> Instruction {
        let d = self.ds[k].key;
        let caller_meta = AccountMeta::new_readonly(pk(caller), true);
        let run = AccountMeta::new(self.run, false);
        let tmpl = AccountMeta::new_readonly(self.template, false);
        match p {
            Perm::Timeout => ix(V::SUB_TIMEOUT, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(executor), false), AccountMeta::new(pk(challenger), false)]),
            Perm::Moot => ix(V::SUB_MOOT, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(challenger), false)]),
            Perm::Advance => ix(V::SUB_ADVANCE, &[], vec![caller_meta, run, tmpl, AccountMeta::new_readonly(d, false)]),
            Perm::PayPot => ix(V::SUB_PAY_POT, &[], vec![caller_meta, run, tmpl, AccountMeta::new_readonly(d, false), AccountMeta::new(pk(challenger), false), AccountMeta::new(pk(payer), false)]),
            Perm::CloseDispute => ix(V::SUB_CLOSE_DISPUTE, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(challenger), false), AccountMeta::new(pk(executor), false), AccountMeta::new(buffer(d, V::ROLE_EXECUTOR), false), AccountMeta::new(buffer(d, V::ROLE_CHALLENGER), false)]),
            Perm::Finalize => ix(V::SUB_FINALIZE, &[], vec![caller_meta, run, tmpl, AccountMeta::new(pk(executor), false)]),
            Perm::CloseCache => ix(V::SUB_CLOSE_CACHE, &[], vec![caller_meta, AccountMeta::new_readonly(self.run, false), AccountMeta::new(self.cache, false), AccountMeta::new(pk(executor), false)]),
            Perm::CloseRun => ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(pk(caller), true), run, AccountMeta::new(self.template, false), AccountMeta::new(pk(payer), false)]),
            Perm::CloseRun2 => ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(pk(caller), true), AccountMeta::new(self.run2.unwrap_or(self.run), false), AccountMeta::new(self.template, false), AccountMeta::new(pk(payer), false)]),
            Perm::CloseTemplate => ix(V::SUB_CLOSE_TEMPLATE, &[], vec![AccountMeta::new(pk(caller), true), AccountMeta::new(self.template, false)]),
            Perm::Retire => ix(V::SUB_RETIRE_TEMPLATE, &[], vec![AccountMeta::new(pk(caller), true), AccountMeta::new(self.template, false)]),
        }
    }

    fn perm_op(&self, p: Perm, k: usize) -> Op {
        match p {
            Perm::Timeout => Op::Rule(k),
            Perm::Moot => Op::Moot(k),
            Perm::PayPot => Op::PayPot(k),
            Perm::CloseDispute => Op::CloseDispute(k),
            Perm::Finalize => Op::Finalize,
            Perm::CloseCache => Op::CloseCache,
            Perm::CloseRun => Op::CloseRun(self.run),
            Perm::CloseRun2 => Op::CloseRun(self.run2.unwrap_or(self.run)),
            Perm::CloseTemplate => Op::CloseTemplate,
            Perm::Advance | Perm::Retire => Op::None,
        }
    }

    /// The precondition model: whether the program must accept `p` on
    /// dispute `k` from `caller`, with the right recipients.
    async fn perm_allowed(&mut self, p: Perm, k: usize, caller: u8) -> bool {
        let now = self.now().await;
        let template_live = !self.template_closed;
        if matches!(p, Perm::CloseTemplate | Perm::Retire) {
            return caller == A && template_live && match p {
                Perm::Retire => !self.retired,
                _ => self.run_closed && (self.run2.is_none() || self.run2_closed),
            };
        }
        if p == Perm::CloseRun2 {
            let Some(r2) = self.run2 else { return false };
            if self.run2_closed || !template_live {
                return false;
            }
            let d = self.account(r2).await.unwrap().data;
            return now > u64_at(&d, R_DEADLINE);
        }
        if p == Perm::CloseCache {
            if self.account(self.cache).await.is_none() {
                return false;
            }
            if self.run_closed {
                return true;
            }
            let r = self.run_data().await.unwrap();
            let settled = r[R_STATUS] == V::RUN_FINAL || (r[R_STATUS] == V::RUN_REFUTED && r[R_PAID] != 0);
            return settled && u32_at(&r, R_OPEN) == 0;
        }
        let Some(r) = self.run_data().await else { return false };
        if !template_live {
            return false;
        }
        let (status, prefix, best, paid) = (r[R_STATUS], u64_at(&r, R_PREFIX), u64_at(&r, R_BEST), r[R_PAID] != 0);
        let settled = status == V::RUN_FINAL || (status == V::RUN_REFUTED && paid);
        match p {
            Perm::Finalize => status == V::RUN_COMMITTED && now > u64_at(&r, R_DEADLINE) && u32_at(&r, R_OPEN) == 0,
            Perm::CloseRun => settled && u32_at(&r, R_OPEN) == 0 && u32_at(&r, R_CLOSED) as u64 == u64_at(&r, R_SEQ),
            _ => {
                let d = &self.ds[k];
                if !d.live() {
                    return false;
                }
                let ruled = d.ruling != V::RULING_OPEN;
                match p {
                    Perm::Timeout => !ruled && now > d.deadline && matches!(status, V::RUN_COMMITTED | V::RUN_REFUTED),
                    Perm::Moot => !ruled && status == V::RUN_REFUTED && d.seq > best,
                    Perm::Advance => ruled && d.seq == prefix,
                    Perm::PayPot => status == V::RUN_REFUTED && !paid && prefix > best && d.seq == best && d.ruling == V::RULING_CHALLENGER,
                    Perm::CloseDispute => ruled && d.seq < prefix && !(status == V::RUN_REFUTED && d.seq == best && !paid),
                    _ => unreachable!(),
                }
            }
        }
    }

    /// A settlement call with the right recipients: accepted exactly when the
    /// precondition model allows it (or as `force` says).
    async fn perm(&mut self, p: Perm, k: usize, caller: u8, force: Option<Expect>) -> bool {
        let allowed = self.perm_allowed(p, k, caller).await;
        if force == Some(Expect::Accepted) && !allowed {
            self.fail(&format!("settlement step {p:?} is required but the precondition model refuses it"));
        }
        let expect = force.unwrap_or(if allowed { Expect::Accepted } else { Expect::Refused });
        let who = self.ds[k].who;
        let i = self.perm_ix(p, k, caller, who, if p == Perm::PayPot { self.remainder } else { A }, E);
        let op = self.perm_op(p, k);
        // The timeout's verdict: moot after the lowest challenger win, else the
        // party that owed the move loses.
        let timeout_ruling = if self.status == V::RUN_REFUTED && self.ds[k].seq > self.best {
            V::RULING_MOOT
        } else if matches!(self.ds[k].phase, PH_NODES | PH_LEAF) {
            V::RULING_CHALLENGER
        } else {
            V::RULING_EXECUTOR
        };
        let ok = self.send_raw(&format!("{p:?} d{}", self.ds[k].nonce), i, caller, expect, op).await;
        if ok {
            self.note_perm(p, k).await;
        } else if expect == Expect::Refused {
            self.refused_perturbations -= 1; // a modelled refusal, not a perturbation
        }
        self.check().await;
        if ok && matches!(p, Perm::Timeout | Perm::Moot) {
            let want = if p == Perm::Moot { V::RULING_MOOT } else { timeout_ruling };
            if self.ds[k].ruling != want {
                self.fail(&format!("{p:?} on dispute seq {} ruled {}, the model says {want}", self.ds[k].seq, self.ds[k].ruling));
            }
            self.oracle_checked += 1;
        }
        ok
    }

    async fn note_perm(&mut self, p: Perm, k: usize) {
        match p {
            Perm::CloseDispute => {
                self.ds[k].closed = true;
                self.closed += 1;
                // A griefer sometimes reopens at the same address.
                let d = &self.ds[k];
                if d.plan == Plan::Grief && self.rng.pct(40) {
                    let (key, who, nonce, kind) = (d.key, d.who, d.nonce, d.kind);
                    self.ds.push(Dsp { key, who, nonce, kind, plan: Plan::Grief, opened: false, gave_up: false, seq: 0, phase: 0, ruling: 0, deadline: 0, position: 0, closed: false, skip: BTreeMap::new() });
                }
            }
            Perm::PayPot => self.paid = true,
            Perm::CloseRun => self.run_closed = true,
            Perm::CloseRun2 => self.run2_closed = true,
            Perm::CloseTemplate => self.template_closed = true,
            Perm::Retire => self.retired = true,
            _ => {}
        }
    }

    // --- actions -------------------------------------------------------------

    async fn open(&mut self, k: usize, expect_override: Option<Expect>) {
        let (who, nonce, kind, protected) = (self.ds[k].who, self.ds[k].nonce, self.ds[k].kind, self.ds[k].plan.protected());
        let key = self.ds[k].key;
        let mut data = vec![nonce; 32];
        data.push(kind);
        let i = ix(V::SUB_OPEN, &data, vec![AccountMeta::new(pk(who), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(key, false), AccountMeta::new_readonly(SYSTEM, false)]);
        let can = match self.run_data().await {
            Some(run) => run[R_STATUS] == V::RUN_COMMITTED && self.now().await <= u64_at(&run, R_DEADLINE) && kind != 9 && !self.template_closed,
            None => false,
        };
        // The record is counted before the check runs; undone on refusal.
        self.ds[k].opened = true;
        self.ds[k].seq = self.opened;
        self.opened += 1;
        let expect = expect_override.unwrap_or(if can { Expect::Accepted } else { Expect::Refused });
        let name = format!("open d{nonce} kind {kind} by {:?}", self.ds[k].plan);
        let ok = self.send_raw(&name, i, who, Expect::Any, Op::Open(k)).await;
        if !ok {
            self.ds[k].opened = false;
            self.opened -= 1;
        }
        self.check().await;
        if ok != can {
            self.fail(&format!("an open {} the challenge window was {}", if can { "inside" } else { "outside" }, if ok { "accepted" } else { "refused" }));
        }
        if expect == Expect::Accepted && !ok {
            self.fail("an open that must be accepted was refused");
        }
        let _ = protected;
    }

    /// Whether the owing party will skip the move owed at this phase
    /// (decided once).
    fn skips(&mut self, k: usize) -> bool {
        let phase = self.ds[k].phase;
        if let Some(s) = self.ds[k].skip.get(&phase) {
            return *s;
        }
        let s = !self.protected_move(k) && self.rng.pct(40);
        self.ds[k].skip.insert(phase, s);
        s
    }

    fn protected_move(&self, k: usize) -> bool {
        let d = &self.ds[k];
        if matches!(d.phase, PH_NODES | PH_LEAF) { self.e_diligent } else { d.plan.protected() }
    }

    /// The owed move of dispute `k`, maybe through a staging buffer or the
    /// reveal cache. `expect` overrides the default (protected: accepted).
    async fn moves(&mut self, k: usize, probe: Option<Expect>) {
        let protected = self.protected_move(k);
        let expect = probe.unwrap_or(if protected { Expect::Accepted } else { Expect::Any });
        let d = self.ds[k].key;
        let who = self.ds[k].who;
        let nonce = self.ds[k].nonce;
        match self.ds[k].phase {
            PH_NODES => {
                let cache_exists = self.account(self.cache).await.is_some();
                if probe.is_none() && cache_exists && (self.rng.pct(50) || self.ds[k].skip.get(&PH_NODES) == Some(&true)) {
                    // Anyone may answer from the cache; the challenger usually does.
                    let caller = if self.rng.pct(80) { who } else { B };
                    let i = ix(V::SUB_CACHE_ANSWER, &[], vec![AccountMeta::new_readonly(pk(caller), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(self.cache, false)]);
                    let now = self.now().await;
                    let e = if now <= self.ds[k].deadline { Expect::Accepted } else { Expect::Refused };
                    self.send(&format!("cache_answer d{nonce}"), i, caller, e, Op::None).await;
                    return;
                }
                if probe.is_none() && self.skips(k) {
                    return;
                }
                let nodes = self.nodes();
                let mut accounts = self.party(E, d);
                let make_cache = !cache_exists && self.rng.pct(50);
                if make_cache {
                    accounts[0] = AccountMeta::new(pk(E), true);
                    accounts.push(AccountMeta::new(self.cache, false));
                    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
                }
                self.send(&format!("reveal_nodes d{nonce}"), ix(V::SUB_REVEAL_NODES, &nodes, accounts), E, expect, Op::Nodes { cache: make_cache }).await;
            }
            PH_PICK => {
                if probe.is_none() && self.skips(k) {
                    return;
                }
                let index = match self.ds[k].plan {
                    Plan::Honest(Lie::Empty) | Plan::Puppet(Lie::Empty) => 0u8,
                    Plan::Honest(_) | Plan::Puppet(_) => 1,
                    Plan::Grief if probe.is_some() => self.rng.pick(&[0u8, 1]),
                    Plan::Grief => self.rng.pick(&[0u8, 1, 1, 2]),
                };
                let i = ix(V::SUB_PICK, &[index], self.party(who, d));
                self.send(&format!("pick {index} d{nonce}"), i, who, expect, Op::None).await;
            }
            PH_LEAF => {
                if probe.is_none() && self.skips(k) {
                    return;
                }
                let leaf = self.leaf_bytes(&self.ds[k]);
                if probe.is_none() && self.rng.pct(20) && self.account(buffer(d, V::ROLE_EXECUTOR)).await.is_none() {
                    // The executor creates its own buffer, or the challenger did.
                    let creator = if protected || self.rng.pct(60) { E } else { who };
                    if self.stage(k, V::ROLE_EXECUTOR, creator, &leaf, expect).await {
                        let mut accounts = self.party(E, d);
                        accounts.push(AccountMeta::new_readonly(buffer(d, V::ROLE_EXECUTOR), false));
                        self.send(&format!("reveal_leaf staged d{nonce}"), ix(V::SUB_REVEAL_LEAF, &[V::FROM_STAGING], accounts), E, expect, Op::None).await;
                    }
                    return;
                }
                self.send(&format!("reveal_leaf d{nonce}"), ix(V::SUB_REVEAL_LEAF, &leaf, self.party(E, d)), E, expect, Op::None).await;
            }
            PH_CLAIM => {
                if probe.is_none() && self.skips(k) {
                    return;
                }
                let (body, oracle) = self.claim_body(k);
                // A dispute opened after the lowest challenger win is ruled moot,
                // whatever its claim (review 10-03, F1).
                let oracle = if self.status == V::RUN_REFUTED && self.ds[k].seq > self.best { Some(V::RULING_MOOT) } else { oracle };
                if probe.is_none() && self.rng.pct(20) && body.len() > 2 && self.account(buffer(d, V::ROLE_CHALLENGER)).await.is_none() {
                    if self.stage(k, V::ROLE_CHALLENGER, who, &body, expect).await {
                        let mut accounts = self.claim_accounts(who, k);
                        accounts.push(AccountMeta::new_readonly(buffer(d, V::ROLE_CHALLENGER), false));
                        let ok = self.send(&format!("claim staged d{nonce}"), ix(V::SUB_CLAIM, &[V::FROM_STAGING], accounts), who, expect, Op::Rule(k)).await;
                        self.judge(k, ok, oracle);
                    }
                    return;
                }
                let accounts = self.claim_accounts(who, k);
                let ok = self.send(&format!("claim {} d{nonce}", body[0]), ix(V::SUB_CLAIM, &body, accounts), who, expect, Op::Rule(k)).await;
                self.judge(k, ok, oracle);
            }
            _ => {}
        }
    }

    /// An accepted claim with a known verdict must be ruled that way.
    fn judge(&mut self, k: usize, ok: bool, oracle: Option<u8>) {
        if let (true, Some(want)) = (ok, oracle) {
            self.oracle_checked += 1;
            if self.ds[k].ruling != want {
                self.fail(&format!("claim on dispute seq {} ruled {}, the oracle says {want}", self.ds[k].seq, self.ds[k].ruling));
            }
        }
    }

    /// Create a staging buffer for `role` (rent from `creator`), sometimes grow
    /// it, and write `bytes` in random chunks by the role's party.
    async fn stage(&mut self, k: usize, role: u8, creator: u8, bytes: &[u8], expect: Expect) -> bool {
        let d = self.ds[k].key;
        let nonce = self.ds[k].nonce;
        let who = self.ds[k].who;
        let buf = buffer(d, role);
        // A challenger buffer starts small sometimes, so it must grow.
        let small = role == V::ROLE_CHALLENGER && self.rng.pct(40);
        let size = if small { (bytes.len() as u32 / 2).max(1) } else { bytes.len() as u32 + self.rng.range(0, 600) as u32 };
        let mut data = vec![role];
        data.extend_from_slice(&size.to_le_bytes());
        let i = ix(V::SUB_STAGE_CREATE, &data, vec![AccountMeta::new(pk(creator), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false), AccountMeta::new_readonly(SYSTEM, false)]);
        // Only the challenger, or the executor for its own buffer, may create.
        let may = creator == who || (role == V::ROLE_EXECUTOR && creator == E);
        let e = if may && expect == Expect::Accepted { Expect::Accepted } else if !may { Expect::Refused } else { Expect::Any };
        if !self.send(&format!("stage_create role {role} d{nonce}"), i, creator, e, Op::StageCreate { k, role, creator }).await {
            return false;
        }
        if small || self.rng.pct(15) {
            // Growth paid by either party, or by the payer as a gift to the creator.
            let funder = self.rng.pick(&[E, who, A]);
            let add = (bytes.len() as u32).max(64);
            let i = ix(V::SUB_STAGE_GROW, &add.to_le_bytes(), vec![AccountMeta::new(pk(funder), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false), AccountMeta::new_readonly(SYSTEM, false)]);
            let e = if expect == Expect::Accepted { Expect::Accepted } else { Expect::Any };
            if !self.send(&format!("stage_grow role {role} d{nonce}"), i, funder, e, Op::StageGrow { k, role, funder }).await {
                return false;
            }
        }
        let writer = if role == V::ROLE_EXECUTOR { E } else { who };
        let chunk = self.rng.range(64, 500) as usize;
        for (n, part) in bytes.chunks(chunk).enumerate() {
            let mut w = ((n * chunk) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(part);
            let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(pk(writer), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false)]);
            if !self.send(&format!("stage_write role {role} d{nonce}"), i, writer, expect, Op::None).await {
                return false;
            }
        }
        true
    }

    /// The latest slot a warp may reach: no protected party's move or open
    /// may expire.
    async fn warp_limit(&mut self) -> u64 {
        let mut limit = u64::MAX;
        for k in 0..self.ds.len() {
            if self.ds[k].unruled() && self.protected_move(k) {
                limit = limit.min(self.ds[k].deadline.saturating_sub(MARGIN));
            }
        }
        if self.ds.iter().any(|d| d.pending() && d.plan.protected()) && self.status == V::RUN_COMMITTED {
            if let Some(run) = self.run_data().await {
                limit = limit.min(u64_at(&run, R_DEADLINE).saturating_sub(MARGIN));
            }
        }
        limit
    }

    async fn warp_to(&mut self, target: u64) -> bool {
        let now = self.now().await;
        if target <= now {
            return target == now;
        }
        self.ctx.warp_to_slot(target).unwrap();
        self.trace.push(format!("warp {now} -> {target}"));
        self.check().await;
        true
    }

    async fn warp(&mut self) {
        let now = self.now().await;
        let run_deadline = self.run_data().await.map(|d| u64_at(&d, R_DEADLINE)).unwrap_or(now);
        let deadlines: Vec<u64> = self.ds.iter().filter(|d| d.unruled()).map(|d| d.deadline).collect();
        let target = match self.rng.below(4) {
            0 | 1 => now + self.rng.range(1, 250),
            2 if !deadlines.is_empty() => self.rng.pick(&deadlines) + self.rng.range(0, 3),
            _ => run_deadline + self.rng.range(0, 3),
        };
        let target = target.min(self.warp_limit().await);
        if target > now + 1 {
            self.warp_to(target).await;
        }
    }

    /// Probe a deadline at its exact slot or the slot after: at the deadline
    /// the owed move (or an open) is accepted and a timeout refused; one slot
    /// later the move is refused and the timeout accepted.
    async fn boundary(&mut self) {
        let limit = self.warp_limit().await;
        let now = self.now().await;
        // A dispute whose owed move is well formed whatever the plan.
        let candidates: Vec<usize> = (0..self.ds.len()).filter(|&k| {
            let d = &self.ds[k];
            d.unruled() && d.deadline > now && d.deadline < limit
                && (matches!(d.phase, PH_NODES | PH_LEAF | PH_PICK) || (d.phase == PH_CLAIM && d.plan != Plan::Grief))
        }).collect();
        let run_deadline = self.run_data().await.filter(|r| r[R_STATUS] == V::RUN_COMMITTED).map(|r| u64_at(&r, R_DEADLINE));
        let opens: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].pending() && !self.ds[k].plan.protected() && self.ds[k].kind != 9).collect();
        if self.rng.pct(30) && !opens.is_empty() && run_deadline.is_some_and(|d| d > now && d < limit) {
            let k = self.rng.pick(&opens);
            let at = run_deadline.unwrap() + self.rng.below(2);
            self.warp_to(at).await;
            self.boundary_probes += 1;
            self.trace.push(format!("probe: open at window end + {}", at - run_deadline.unwrap()));
            self.open(k, None).await;
            return;
        }
        if candidates.is_empty() {
            return;
        }
        let k = self.rng.pick(&candidates);
        let deadline = self.ds[k].deadline;
        let after = self.rng.pct(50);
        if !self.warp_to(deadline + after as u64).await {
            return;
        }
        self.boundary_probes += 1;
        self.trace.push(format!("probe: dispute d{} at deadline + {}", self.ds[k].nonce, after as u8));
        self.perm(Perm::Timeout, k, B, None).await; // modelled: refused at, accepted after
        if !after {
            self.moves(k, Some(Expect::Accepted)).await;
        }
    }

    /// A random settlement call, modelled exactly, mostly from the bystander.
    async fn random_perm(&mut self) {
        let p = self.rng.pick(&[Perm::Timeout, Perm::Timeout, Perm::Moot, Perm::Advance, Perm::Advance, Perm::PayPot, Perm::CloseDispute, Perm::CloseDispute, Perm::Finalize, Perm::CloseCache, Perm::CloseRun, Perm::CloseRun2, Perm::CloseTemplate, Perm::Retire]);
        let k = self.rng.below(self.ds.len() as u64) as usize;
        if p == Perm::CloseRun2 && self.run2.is_none() {
            return;
        }
        let caller = if matches!(p, Perm::CloseTemplate | Perm::Retire) { if self.rng.pct(60) { A } else { B } } else if self.rng.pct(80) { B } else { self.rng.pick(&ACTORS) };
        self.perm(p, k, caller, None).await;
        if p == Perm::Retire && self.retired && self.rng.pct(50) {
            // No run may start on a retired template.
            let i = self.init_ix(9, run_key(&self.template_id, 9, &self.g.refs.concat()));
            self.send("init_run on a retired template", i, A, Expect::Refused, Op::None).await;
        }
    }

    /// An instruction that must be refused.
    async fn perturb(&mut self) {
        let live: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].unruled()).collect();
        let others = |x: u8| -> Vec<u8> { ACTORS.iter().copied().filter(|a| *a != x).collect() };
        match self.rng.below(6) {
            // A move signed by someone other than the party that owes it.
            0 if !live.is_empty() => {
                let k = self.rng.pick(&live);
                let d = self.ds[k].key;
                let owner = self.ds[k].owner();
                let signer = self.rng.pick(&others(owner));
                let i = match self.ds[k].phase {
                    PH_NODES => ix(V::SUB_REVEAL_NODES, &self.nodes(), self.party(signer, d)),
                    PH_LEAF => ix(V::SUB_REVEAL_LEAF, &self.leaf_bytes(&self.ds[k]), self.party(signer, d)),
                    PH_PICK => ix(V::SUB_PICK, &[1], self.party(signer, d)),
                    _ => {
                        let (body, _) = self.claim_body(k);
                        ix(V::SUB_CLAIM, &body, self.claim_accounts(signer, k))
                    }
                };
                self.send("perturb: wrong signer", i, signer, Expect::Refused, Op::None).await;
            }
            // The party that does not owe the move tries one.
            1 if !live.is_empty() => {
                let k = self.rng.pick(&live);
                let d = self.ds[k].key;
                let who = self.ds[k].who;
                let (i, s) = if matches!(self.ds[k].phase, PH_NODES | PH_LEAF) {
                    (ix(V::SUB_PICK, &[self.rng.pick(&[0u8, 1])], self.party(who, d)), who)
                } else {
                    let i = if self.rng.pct(50) { ix(V::SUB_REVEAL_NODES, &self.nodes(), self.party(E, d)) } else { ix(V::SUB_REVEAL_LEAF, &self.leaf_bytes(&self.ds[k]), self.party(E, d)) };
                    (i, E)
                };
                if who != E {
                    self.send("perturb: out of turn", i, s, Expect::Refused, Op::None).await;
                }
            }
            // A corrupted executor reveal.
            2 if !live.is_empty() => {
                let k = self.rng.pick(&live);
                let d = self.ds[k].key;
                let mut data = match self.ds[k].phase {
                    PH_NODES => self.nodes(),
                    PH_LEAF => self.leaf_bytes(&self.ds[k]),
                    _ => return,
                };
                let sub = if self.ds[k].phase == PH_NODES { V::SUB_REVEAL_NODES } else { V::SUB_REVEAL_LEAF };
                match self.rng.below(3) {
                    0 if data.len() > 1 => {
                        let at = self.rng.range(1, data.len() as u64 - 1) as usize;
                        data[at] ^= 1 << self.rng.below(8);
                    }
                    1 if data.len() > 1 => data.truncate(self.rng.range(0, data.len() as u64 - 1) as usize),
                    _ => data.push(self.rng.below(256) as u8),
                }
                self.send("perturb: corrupted reveal", ix(sub, &data, self.party(E, d)), E, Expect::Refused, Op::None).await;
            }
            // A settlement call the model would accept, naming a wrong recipient.
            3 => {
                let k = self.rng.below(self.ds.len() as u64) as usize;
                let p = self.rng.pick(&[Perm::Timeout, Perm::Moot, Perm::PayPot, Perm::CloseDispute, Perm::Finalize, Perm::CloseRun, Perm::CloseCache]);
                if !self.perm_allowed(p, k, B).await {
                    return;
                }
                let who = self.ds[k].who;
                let wrong_c = self.rng.pick(&others(who));
                let wrong_e = self.rng.pick(&others(E));
                let wrong_a = self.rng.pick(&others(A));
                let wrong_r = self.rng.pick(&others(self.remainder));
                let (challenger, payer, executor) = match p {
                    Perm::Moot => (wrong_c, A, E),
                    Perm::Timeout | Perm::CloseDispute => if self.rng.pct(50) { (wrong_c, A, E) } else { (who, A, wrong_e) },
                    Perm::PayPot => if self.rng.pct(50) { (wrong_c, self.remainder, E) } else { (who, wrong_r, E) },
                    Perm::CloseRun => (who, wrong_a, E),
                    _ => (who, A, wrong_e),
                };
                // Under a puppet the executor is the challenger: skip the aliased case.
                if (challenger == E && who != E && matches!(p, Perm::Timeout | Perm::CloseDispute)) || (executor == who) {
                    return;
                }
                let i = self.perm_ix(p, k, B, challenger, payer, executor);
                self.send(&format!("perturb: {p:?} wrong recipient"), i, B, Expect::Refused, Op::None).await;
            }
            // A write to an existing buffer by the party that does not own it.
            4 => {
                let k = self.rng.below(self.ds.len() as u64) as usize;
                let role = self.rng.pick(&[V::ROLE_EXECUTOR, V::ROLE_CHALLENGER]);
                let d = self.ds[k].key;
                let buf = buffer(d, role);
                if self.account(buf).await.is_none() {
                    return;
                }
                let owner = if role == V::ROLE_EXECUTOR { E } else { self.ds[k].who };
                let writer = self.rng.pick(&others(owner));
                let mut w = 0u32.to_le_bytes().to_vec();
                w.push(0xAB);
                let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(pk(writer), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false)]);
                self.send("perturb: foreign staging write", i, writer, Expect::Refused, Op::None).await;
            }
            // A copy of a live dispute at an address the program did not derive.
            5 if !live.is_empty() => {
                let k = self.rng.pick(&live);
                let copy = self.account(self.ds[k].key).await.unwrap();
                let fake = Pubkey::new_unique();
                let mut forger = self.ctx.banks_client.get_account(pk(FORGER)).await.unwrap().unwrap();
                forger.lamports -= copy.lamports;
                self.ctx.set_account(&pk(FORGER), &forger.into());
                self.ctx.set_account(&fake, &copy.into());
                let who = self.ds[k].who;
                let i = match self.rng.below(3) {
                    0 => ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(pk(B), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(fake, false), AccountMeta::new(pk(E), false), AccountMeta::new(pk(who), false)]),
                    1 => ix(V::SUB_ADVANCE, &[], vec![AccountMeta::new_readonly(pk(B), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(fake, false)]),
                    _ => ix(V::SUB_MOOT, &[], vec![AccountMeta::new_readonly(pk(B), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(fake, false), AccountMeta::new(pk(who), false)]),
                };
                self.send("perturb: forged dispute", i, B, Expect::Refused, Op::None).await;
            }
            _ => {}
        }
    }

    // --- the sequence ----------------------------------------------------------

    async fn play(&mut self) {
        let budget = self.rng.range(20, 160);
        for _ in 0..budget {
            if self.template_closed {
                break;
            }
            let now = self.now().await;
            let run_open = self.status == V::RUN_COMMITTED && !self.run_closed;
            let run_deadline = if run_open { self.run_data().await.map(|d| u64_at(&d, R_DEADLINE)).unwrap_or(0) } else { 0 };
            let pending: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].pending()).collect();
            let movable: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].unruled() && now <= self.ds[k].deadline).collect();
            if movable.is_empty() && (pending.is_empty() || !run_open || now > run_deadline) && self.rng.pct(70) {
                break;
            }
            // Protected parties at their margin move first.
            let urgent: Vec<usize> = movable.iter().copied().filter(|&k| self.protected_move(k) && self.ds[k].deadline <= now + MARGIN + 5).collect();
            if let Some(&k) = urgent.first() {
                self.moves(k, None).await;
                continue;
            }
            match self.rng.below(22) {
                0..=7 if !movable.is_empty() => {
                    let k = self.rng.pick(&movable);
                    self.moves(k, None).await;
                }
                8..=11 if !pending.is_empty() => {
                    let k = self.rng.pick(&pending);
                    self.open(k, None).await;
                    if !self.ds[k].opened && !self.ds[k].plan.protected() && self.rng.pct(50) {
                        self.ds[k].gave_up = true;
                    }
                }
                12..=13 => self.warp().await,
                14 => self.boundary().await,
                15..=17 => self.random_perm().await,
                _ => self.perturb().await,
            }
        }
        // Protected parties still owed an open or a move get them now.
        for k in 0..self.ds.len() {
            if self.ds[k].pending() && self.ds[k].plan.protected() {
                self.open(k, None).await;
            }
        }
        loop {
            let now = self.now().await;
            let Some(k) = (0..self.ds.len()).find(|&k| self.ds[k].unruled() && self.protected_move(k) && now <= self.ds[k].deadline) else { break };
            let before = (self.ds[k].phase, self.ds[k].ruling);
            self.moves(k, None).await;
            if (self.ds[k].phase, self.ds[k].ruling) == before {
                self.fail("a protected move made no progress");
            }
        }
        self.settle().await;
    }

    /// Past every deadline, settle and close everything; each step must be
    /// accepted (unless an earlier random call already did it).
    async fn settle(&mut self) {
        let mut horizon = self.now().await;
        if let Some(r) = self.run_data().await {
            horizon = horizon.max(u64_at(&r, R_DEADLINE));
        }
        if let (Some(r2), false) = (self.run2, self.run2_closed) {
            horizon = horizon.max(u64_at(&self.account(r2).await.unwrap().data, R_DEADLINE));
        }
        for d in &self.ds {
            if d.unruled() {
                horizon = horizon.max(d.deadline);
            }
        }
        self.warp_to(horizon + 2).await;
        for k in 0..self.ds.len() {
            if !self.ds[k].unruled() {
                continue;
            }
            let p = if self.status == V::RUN_REFUTED && self.ds[k].seq > self.best && self.rng.pct(50) { Perm::Moot } else { Perm::Timeout };
            self.perm(p, k, B, Some(Expect::Accepted)).await;
        }
        let mut order: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].live()).collect();
        order.sort_by_key(|&k| self.ds[k].seq);
        for &k in &order {
            if let Some(r) = self.run_data().await {
                if self.ds[k].seq >= u64_at(&r, R_PREFIX) {
                    self.perm(Perm::Advance, k, B, Some(Expect::Accepted)).await;
                }
            }
        }
        if let Some(r) = self.run_data().await {
            if u64_at(&r, R_PREFIX) != self.opened {
                self.fail("the ruled prefix did not reach the sequence counter");
            }
        }
        if self.status == V::RUN_REFUTED && !self.paid {
            let Some(k) = (0..self.ds.len()).find(|&k| self.ds[k].live() && self.ds[k].seq == self.best) else {
                self.fail("the best win is not live before the pot is paid");
            };
            self.perm(Perm::PayPot, k, B, Some(Expect::Accepted)).await;
        }
        for &k in &order {
            if self.ds[k].live() {
                self.perm(Perm::CloseDispute, k, B, Some(Expect::Accepted)).await;
            }
        }
        if self.status == V::RUN_COMMITTED {
            self.perm(Perm::Finalize, 0, B, Some(Expect::Accepted)).await;
        }
        if self.account(self.cache).await.is_some() {
            self.perm(Perm::CloseCache, 0, B, Some(Expect::Accepted)).await;
        }
        if !self.run_closed {
            self.perm(Perm::CloseRun, 0, B, Some(Expect::Accepted)).await;
        }
        if self.run2.is_some() && !self.run2_closed {
            self.perm(Perm::CloseRun2, 0, B, Some(Expect::Accepted)).await;
        }
        if !self.template_closed {
            self.perm(Perm::CloseTemplate, 0, A, Some(Expect::Accepted)).await;
        }
        self.final_checks().await;
    }

    async fn final_checks(&mut self) {
        for k in self.ledger.clone() {
            if k == self.run || ACTORS.iter().any(|a| pk(*a) == k) {
                continue;
            }
            if self.account(k).await.is_some() {
                self.fail(&format!("{k} still holds lamports or data after settlement"));
            }
        }
        if self.account(self.run).await.unwrap().data.len() != V::RECEIPT_BYTES {
            self.fail("the run did not shrink to its receipt");
        }
        let refuted = self.status == V::RUN_REFUTED;
        let honest_opened = self.ds.iter().any(|d| d.plan.protected() && d.opened);
        if !self.lies.is_empty() && honest_opened && !refuted {
            self.fail("an honest challenger disputed a lie, but the run was not refuted");
        }
        if self.lies.is_empty() && self.e_diligent {
            if self.status != V::RUN_FINAL {
                self.fail("an honest, diligent run did not finalize");
            }
            if self.balance(pk(E)).await < self.init[&E] {
                self.fail("an honest, diligent executor netted negative");
            }
        }
        for who in CHALLENGERS {
            let mine: Vec<&Dsp> = self.ds.iter().filter(|d| d.who == who && d.opened).collect();
            if !mine.is_empty() && mine.iter().all(|d| d.plan.protected()) && self.balance(pk(who)).await < self.init[&who] {
                self.fail(&format!("honest challenger {who:x} netted negative"));
            }
        }
    }
}

#[derive(Default)]
struct Totals {
    sequences: u64,
    txs: u64,
    accepted: u64,
    refused_perturbations: u64,
    rulings_by_proof: u64,
    oracle_checked: u64,
    boundary_probes: u64,
    refuted: u64,
    final_: u64,
    disputes: u64,
    coverage: BTreeMap<String, u64>,
}

async fn run_planted(seed: u64, index: u64, totals: &mut Totals, plant: Option<&'static str>) {
    let mut w = World::new(seed, index).await;
    w.plant = plant;
    w.play().await;
    for (k, v) in &w.coverage {
        *totals.coverage.entry(k.clone()).or_default() += v;
    }
    totals.sequences += 1;
    totals.txs += w.txs;
    totals.accepted += w.accepted;
    totals.refused_perturbations += w.refused_perturbations;
    totals.rulings_by_proof += w.rulings_by_proof;
    totals.oracle_checked += w.oracle_checked;
    totals.boundary_probes += w.boundary_probes;
    totals.disputes += w.opened;
    match w.status {
        V::RUN_REFUTED => totals.refuted += 1,
        V::RUN_FINAL => totals.final_ += 1,
        _ => {}
    }
    if std::env::var_os("V21_FUZZ_ONLY").is_some() {
        eprintln!("{}\n  {}", w.label, w.trace.join("\n  "));
    }
}

fn report(seed: u64, t: &Totals, secs: f64) {
    eprintln!("v21 run fuzz seed {seed}: {} sequences, {} disputes, {} transactions ({} accepted, {} perturbations refused), {} rulings by proof ({} against the oracle), {} boundary probes, {} refuted, {} final, {secs:.1} s",
        t.sequences, t.disputes, t.txs, t.accepted, t.refused_perturbations, t.rulings_by_proof, t.oracle_checked, t.boundary_probes, t.refuted, t.final_);
    eprintln!("  accepted by kind: {}", t.coverage.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_fuzz_smoke() {
    let start = std::time::Instant::now();
    let mut t = Totals::default();
    for i in 0..24 {
        run_planted(1, i, &mut t, None).await;
    }
    report(1, &t, start.elapsed().as_secs_f64());
    // The smoke run must reach the paths it exists to exercise.
    for (what, n) in [("rulings by proof", t.rulings_by_proof), ("oracle checks", t.oracle_checked), ("boundary probes", t.boundary_probes),
                      ("refuted runs", t.refuted), ("final runs", t.final_)] {
        assert!(n > 0, "smoke coverage: no {what}");
    }
    for kind in ["Timeout", "Moot", "PayPot", "Finalize", "CloseDispute", "cache_answer", "stage_grow role 2", "reveal_leaf staged"] {
        assert!(t.coverage.get(kind).copied().unwrap_or(0) > 0, "smoke coverage: no accepted {kind}");
    }
}

/// The campaign: `V21_FUZZ_SEED`, `V21_FUZZ_COUNT` (default 200) and
/// `V21_FUZZ_START`, or `V21_FUZZ_ONLY` for one sequence with its trace.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "fuzz campaign; set V21_FUZZ_SEED"]
async fn run_fuzz_campaign() {
    let seed: u64 = std::env::var("V21_FUZZ_SEED").expect("V21_FUZZ_SEED").parse().unwrap();
    let start = std::time::Instant::now();
    let mut t = Totals::default();
    if let Ok(only) = std::env::var("V21_FUZZ_ONLY") {
        run_planted(seed, only.parse().unwrap(), &mut t, None).await;
    } else {
        let first: u64 = std::env::var("V21_FUZZ_START").map(|s| s.parse().unwrap()).unwrap_or(0);
        let count: u64 = std::env::var("V21_FUZZ_COUNT").map(|s| s.parse().unwrap()).unwrap_or(200);
        for i in first..first + count {
            run_planted(seed, i, &mut t, None).await;
        }
    }
    report(seed, &t, start.elapsed().as_secs_f64());
}

/// The checks catch a fault planted the way a program bug would leave it.
async fn planted(plant: &'static str) {
    let mut t = Totals::default();
    for i in 0..40 {
        run_planted(3, i, &mut t, Some(plant)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "ledger: after")]
async fn run_fuzz_catches_a_planted_transfer_between_parties() {
    planted("transfer").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "executor-wait count: run has")]
async fn run_fuzz_catches_a_planted_wait_counter_drift() {
    planted("wait").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "ruling changed:")]
async fn run_fuzz_catches_a_planted_ruling_flip() {
    planted("ruling").await;
}
