//! Run-level fuzzer for v2.1 disputes (tag 227): alpha plan R1, exit criterion 2.
//!
//! Each sequence is one template and one run on the Hello Graph goldens:
//! - the template has a random challenge window, phase window, bonds and
//!   slasher share;
//! - the committed truth is honest, or any mix of a wrong step output, an
//!   empty leaf and a wrong posted output;
//! - the executor is diligent or lazy;
//! - one to six disputes are opened by honest challengers (protected: they
//!   always move on time), griefers (any move, any time, or none) and
//!   executor puppets.
//!
//! The parties' moves interleave at random with:
//! - clock warps;
//! - permissionless settlement calls (timeout, moot, advance, pay_pot, the
//!   closes) from a bystander;
//! - staged openings and claims, and cache answers;
//! - perturbed instructions that must be refused: a wrong signer, an
//!   out-of-turn move, a corrupted reveal, a wrong recipient, a foreign
//!   staging write, or a forged dispute record.
//!
//! Invariants, checked after every transaction:
//! - lamports are conserved over every account the run can touch (fees come
//!   from the untracked test payer);
//! - the run status moves only COMMITTED -> FINAL | REFUTED;
//! - the run's open count is the number of live unruled disputes, and its
//!   executor-wait count is the number of those waiting on the executor
//!   (NODES or LEAF);
//! - the sequence and closed counters match the accepted opens and closes;
//!   a ruling never changes; `best` is the lowest sequence ruled for the
//!   challenger; the pot is paid only on a refuted run whose ruled prefix
//!   has passed `best`;
//! - an honest commitment answered diligently is never ruled for the
//!   challenger, and an honest challenger is never ruled against;
//! - the bystander's balance never changes.
//!
//! At the end the run is settled and everything is closed:
//! - every dispute, buffer and cache closes, the run shrinks to its receipt,
//!   and the template closes;
//! - the payer nets exactly its pot share less the receipt rent;
//! - honest parties never net negative;
//! - a lie that an honest challenger disputed ends REFUTED, and an honest
//!   run answered diligently ends FINAL.
//!
//! Sequence `i` of seed `s` depends only on `(s, i)`:
//!
//!   cargo test -p dcg-program --features graph-v21 --test disputes_v21_run_fuzz
//!   V21_FUZZ_SEED=7 V21_FUZZ_COUNT=500 cargo test ... -- --ignored run_fuzz_campaign
//!   V21_FUZZ_SEED=7 V21_FUZZ_ONLY=123 ...      # one sequence, with its trace
//!
//! `V21_SBF=1`, with `BPF_OUT_DIR` naming a graph-v21 image, runs the SBF
//! program instead of the native one.
#![cfg(feature = "graph-v21")]

use dcg_disputes as D;
use dcg_program::disputes_v21 as V;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{clock::Clock, system_program};
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
const CHALLENGERS: [u8; 5] = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
const ACTORS: [u8; 8] = [A, E, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, B];
/// Funds forged accounts, so the bank's capitalization stays exact. Outside
/// the ledger.
const FORGER: u8 = 0xF1;
/// Protected moves are made at least this many slots before their deadline,
/// so slots the bank advances on its own cannot expire them.
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
const PH_NODES: u8 = 1;
const PH_PICK: u8 = 2;
const PH_LEAF: u8 = 3;
const PH_CLAIM: u8 = 4;
const PH_RULED: u8 = 5;

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

    /// The party that owes the next move, by phase.
    fn owner(&self) -> u8 {
        if matches!(self.phase, PH_NODES | PH_LEAF) { E } else { self.who }
    }
}

#[derive(Clone, Copy, Debug)]
enum Perm {
    Timeout,
    Moot,
    Advance,
    PayPot,
    CloseDispute,
    Finalize,
    CloseCache,
    CloseRun,
    CloseTemplate,
}

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    Any,
    Accepted,
    Refused,
}

struct World {
    ctx: ProgramTestContext,
    rng: Rng,
    case: String,
    label: String,
    trace: Vec<String>,
    g: Golden,
    spec_levels: Vec<Vec<D::Hash>>,
    c: Commit,
    lies: Vec<Lie>,
    e_diligent: bool,
    executor_bond: u64,
    slasher_bps: u64,
    template: Pubkey,
    run: Pubkey,
    cache: Pubkey,
    ds: Vec<Dsp>,
    opened: u64,
    closed: u32,
    status: u8,
    best: u64,
    paid: bool,
    run_closed: bool,
    template_closed: bool,
    ledger: Vec<Pubkey>,
    ledger0: u128,
    init: BTreeMap<u8, u64>,
    receipt_rent: u64,
    txs: u64,
    accepted: u64,
    refused_perturbations: u64,
    rulings_by_proof: u64,
    coverage: BTreeMap<String, u64>,
    /// A fault the checks must catch (planted-fault tests only).
    plant: Option<&'static str>,
}

fn buffer(d: Pubkey, role: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg21stg", d.as_ref(), &[role]], &PROGRAM).0
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
        let ctx = test.start_with_context().await;
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
        let run = Pubkey::find_program_address(&[b"dcg21run", &run_id, pk(A).as_ref()], &PROGRAM).0;
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
            let key = Pubkey::find_program_address(&[b"dcg21dsp", run.as_ref(), pk(who).as_ref(), &[nonce; 32]], &PROGRAM).0;
            ds.push(Dsp { key, who, nonce, kind, plan: *plan, opened: false, seq: 0, phase: 0, ruling: 0, deadline: 0, position: 0, closed: false, skip: BTreeMap::new() });
        }

        let mut ledger: Vec<Pubkey> = ACTORS.iter().map(|b| pk(*b)).collect();
        ledger.extend([template, run, cache]);
        for d in &ds {
            ledger.extend([d.key, buffer(d.key, V::ROLE_EXECUTOR), buffer(d.key, V::ROLE_CHALLENGER)]);
        }
        let label = format!("lies {lies:?} executor {} windows {challenge_window}/{phase_window} bonds {executor_bond}/{challenger_bond} slasher {slasher_bps} plans {:?}",
            if e_diligent { "diligent" } else { "lazy" }, ds.iter().map(|d| (d.plan, format!("{:x}", d.who), d.kind)).collect::<Vec<_>>());
        let mut w = World {
            ctx, rng, case: format!("seed {seed} sequence {index}"), label, trace: vec![], g, spec_levels, c, lies, e_diligent, executor_bond, slasher_bps,
            template, run, cache, ds, opened: 0, closed: 0, status: V::RUN_OPEN, best: u64::MAX, paid: false,
            run_closed: false, template_closed: false, ledger, ledger0: 0, init: BTreeMap::new(), receipt_rent: 0,
            txs: 0, accepted: 0, refused_perturbations: 0, rulings_by_proof: 0, coverage: BTreeMap::new(), plant: None,
        };
        w.ledger0 = w.ledger_total().await;
        for b in ACTORS {
            let bal = w.balance(pk(b)).await;
            w.init.insert(b, bal);
        }

        // Template, run and commit.
        let create = ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(pk(A), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        w.send("create_template", create, A, Expect::Accepted).await;
        let mut init = vec![0u8; 32];
        init.extend_from_slice(pk(E).as_ref());
        init.extend_from_slice(&2u32.to_le_bytes());
        for r in &w.g.refs {
            init.extend_from_slice(r);
        }
        let i = ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(pk(A), true), AccountMeta::new(run, false), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        w.send("init_run", i, A, Expect::Accepted).await;
        let root = w.c.root_bytes;
        let i = ix(V::SUB_COMMIT, &root, vec![AccountMeta::new(pk(E), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        w.send("commit", i, E, Expect::Accepted).await;
        w
    }

    fn fail(&self, what: &str) -> ! {
        let tail = self.trace.len().saturating_sub(60);
        panic!("{}: {what}\n  sequence: {}\n  trace (last {}):\n    {}", self.label_head(), self.label, self.trace.len() - tail, self.trace[tail..].join("\n    "));
    }

    fn label_head(&self) -> String {
        self.case.clone()
    }

    async fn balance(&mut self, k: Pubkey) -> u64 {
        self.ctx.banks_client.get_balance(k).await.unwrap()
    }

    async fn ledger_total(&mut self) -> u128 {
        let mut t = 0u128;
        for k in self.ledger.clone() {
            t += self.balance(k).await as u128;
        }
        t
    }

    async fn now(&mut self) -> u64 {
        self.ctx.banks_client.get_sysvar::<Clock>().await.unwrap().slot
    }

    async fn account(&mut self, k: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(k).await.unwrap().filter(|a| a.lamports > 0 || !a.data.is_empty())
    }

    /// Send one instruction signed by `signer` (the test payer pays fees), then
    /// check every invariant.
    async fn send(&mut self, name: &str, i: Instruction, signer: u8, expect: Expect) -> bool {
        let ok = self.send_raw(name, i, signer, expect).await;
        self.check().await;
        ok
    }

    /// Send without the check, for callers that record the effect first.
    async fn send_raw(&mut self, name: &str, i: Instruction, signer: u8, expect: Expect) -> bool {
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
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
        ok
    }

    /// Every invariant, against the accounts.
    async fn check(&mut self) {
        if self.ledger_total().await != self.ledger0 {
            self.fail("lamports not conserved");
        }
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
                if acct.is_some() && !opened {
                    self.fail(&format!("dispute {who:x}/{nonce} exists without an accepted open"));
                }
                if acct.is_some() && closed {
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
                self.fail(&format!("dispute seq {seq} ruling {old_ruling} -> {ruling}"));
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
            if d.plan.protected() && d.ruling == V::RULING_EXECUTOR {
                self.fail(&format!("honest challenger {:x} ruled against (seq {})", d.who, d.seq));
            }
            if self.lies.is_empty() && self.e_diligent && d.ruling == V::RULING_CHALLENGER {
                self.fail(&format!("an honest, diligent executor ruled against (seq {})", d.seq));
            }
        }
        let wait = u32_at(&r, r.len() - 4);
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
        self.apply_plant().await;
    }

    /// Planted-fault tests: corrupt the state once, the way a program bug
    /// would, and let the next check catch it.
    async fn apply_plant(&mut self) {
        let Some(plant) = self.plant else { return };
        let mut run = self.ctx.banks_client.get_account(self.run).await.unwrap().unwrap();
        match plant {
            "lamports" if self.status == V::RUN_COMMITTED => {
                let mut forger = self.ctx.banks_client.get_account(pk(FORGER)).await.unwrap().unwrap();
                run.lamports -= 1;
                forger.lamports += 1;
                self.ctx.set_account(&pk(FORGER), &forger.into());
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

    fn claim_body(&mut self, k: usize) -> Vec<u8> {
        let (plan, kind, pos) = (self.ds[k].plan, self.ds[k].kind, self.ds[k].position as usize % 2);
        let step = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_STEP, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            b.push(1);
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(&42i32.to_le_bytes());
            b
        };
        let shape = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_SHAPE, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            b
        };
        let edge = |w: &Self, pos: usize| {
            let mut b = vec![V::CLAIM_EDGE, 0];
            b.extend(w.spec_opening(STEP_BASE as usize + pos));
            b.extend(w.step_opening(1 - pos));
            b
        };
        let out = |w: &Self| {
            let mut b = vec![V::CLAIM_OUT, 0];
            b.extend(w.spec_opening(OUT_BASE as usize));
            b.extend(w.step_opening(1));
            b
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
                        _ => vec![self.rng.pick(&[V::CLAIM_GATE, V::CLAIM_STATE, 0, 77]), 0],
                    }
                }
            }
        }
    }

    fn claim_accounts(&self, signer: u8, k: usize) -> Vec<AccountMeta> {
        let d = &self.ds[k];
        vec![AccountMeta::new_readonly(pk(signer), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d.key, false), AccountMeta::new(pk(E), false), AccountMeta::new(pk(d.who), false)]
    }

    fn perm_ix(&self, p: Perm, k: usize, caller: u8, challenger: u8, payer: u8, executor: u8) -> (Instruction, u8) {
        let d = self.ds[k].key;
        let caller_meta = AccountMeta::new_readonly(pk(caller), true);
        let run = AccountMeta::new(self.run, false);
        let tmpl = AccountMeta::new_readonly(self.template, false);
        let i = match p {
            Perm::Timeout => ix(V::SUB_TIMEOUT, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(executor), false), AccountMeta::new(pk(challenger), false)]),
            Perm::Moot => ix(V::SUB_MOOT, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(challenger), false)]),
            Perm::Advance => ix(V::SUB_ADVANCE, &[], vec![caller_meta, run, tmpl, AccountMeta::new_readonly(d, false)]),
            Perm::PayPot => ix(V::SUB_PAY_POT, &[], vec![caller_meta, run, tmpl, AccountMeta::new_readonly(d, false), AccountMeta::new(pk(challenger), false), AccountMeta::new(pk(payer), false)]),
            Perm::CloseDispute => ix(V::SUB_CLOSE_DISPUTE, &[], vec![caller_meta, run, tmpl, AccountMeta::new(d, false), AccountMeta::new(pk(challenger), false), AccountMeta::new(pk(executor), false), AccountMeta::new(buffer(d, V::ROLE_EXECUTOR), false), AccountMeta::new(buffer(d, V::ROLE_CHALLENGER), false)]),
            Perm::Finalize => ix(V::SUB_FINALIZE, &[], vec![caller_meta, run, tmpl, AccountMeta::new(pk(executor), false)]),
            Perm::CloseCache => ix(V::SUB_CLOSE_CACHE, &[], vec![caller_meta, AccountMeta::new_readonly(self.run, false), AccountMeta::new(self.cache, false), AccountMeta::new(pk(executor), false)]),
            Perm::CloseRun => ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(pk(caller), true), run, AccountMeta::new(self.template, false), AccountMeta::new(pk(payer), false)]),
            Perm::CloseTemplate => ix(V::SUB_CLOSE_TEMPLATE, &[], vec![AccountMeta::new(pk(caller), true), AccountMeta::new(self.template, false)]),
        };
        (i, caller)
    }

    /// Record the effects of an accepted permissionless call.
    async fn perm(&mut self, p: Perm, k: usize, caller: u8, expect: Expect) -> bool {
        let who = self.ds[k].who;
        let (i, s) = self.perm_ix(p, k, caller, who, A, E);
        let ok = self.send_raw(&format!("{p:?} d{}", self.ds[k].nonce), i, s, expect).await;
        if ok {
            self.note_perm(p, k).await;
        }
        self.check().await;
        ok
    }

    async fn note_perm(&mut self, p: Perm, k: usize) {
        match p {
            Perm::CloseDispute => {
                self.ds[k].closed = true;
                self.closed += 1;
            }
            Perm::PayPot => self.paid = true,
            Perm::CloseRun => {
                let receipt = self.balance(self.run).await;
                self.receipt_rent = receipt;
                self.run_closed = true;
            }
            Perm::CloseTemplate => self.template_closed = true,
            _ => {}
        }
    }

    // --- actions -------------------------------------------------------------

    async fn open(&mut self, k: usize) {
        let (who, nonce, kind, protected) = (self.ds[k].who, self.ds[k].nonce, self.ds[k].kind, self.ds[k].plan.protected());
        let key = self.ds[k].key;
        let mut data = vec![nonce; 32];
        data.push(kind);
        let i = ix(V::SUB_OPEN, &data, vec![AccountMeta::new(pk(who), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(key, false), AccountMeta::new_readonly(SYSTEM, false)]);
        let run = self.account(self.run).await.unwrap().data;
        let can = run[R_STATUS] == V::RUN_COMMITTED && self.now().await <= u64_at(&run, R_DEADLINE);
        // An open goes through the check only after its record exists, so mark
        // it first and undo on refusal.
        self.ds[k].opened = true;
        self.ds[k].seq = self.opened;
        self.opened += 1;
        let expect = if protected && can && kind != 9 { Expect::Accepted } else { Expect::Any };
        let name = format!("open d{nonce} kind {kind} by {:?}", self.ds[k].plan);
        let ok = self.send_raw(&name, i, who, Expect::Any).await;
        if !ok {
            self.ds[k].opened = false;
            self.opened -= 1;
            if expect == Expect::Accepted {
                self.fail("an honest open in the window must be accepted");
            }
        }
        self.check().await;
        if ok && !can {
            self.fail("an open outside the challenge window or after a refutation was accepted");
        }
    }

    /// Whether `party` will skip the move owed at this phase (decided once).
    fn skips(&mut self, k: usize) -> bool {
        let phase = self.ds[k].phase;
        if let Some(s) = self.ds[k].skip.get(&phase) {
            return *s;
        }
        let owner = self.ds[k].owner();
        let protected = if owner == E && self.ds[k].phase != PH_PICK && self.ds[k].phase != PH_CLAIM { self.e_diligent } else { self.ds[k].plan.protected() };
        let s = !protected && self.rng.pct(40);
        self.ds[k].skip.insert(phase, s);
        s
    }

    fn protected_move(&self, k: usize) -> bool {
        let d = &self.ds[k];
        if matches!(d.phase, PH_NODES | PH_LEAF) { self.e_diligent } else { d.plan.protected() }
    }

    /// The owed move of dispute `k`, maybe through a staging buffer or the
    /// reveal cache.
    async fn moves(&mut self, k: usize) {
        let protected = self.protected_move(k);
        let expect = if protected { Expect::Accepted } else { Expect::Any };
        let d = self.ds[k].key;
        let who = self.ds[k].who;
        match self.ds[k].phase {
            PH_NODES => {
                let cache_exists = self.account(self.cache).await.is_some();
                if cache_exists && (self.rng.pct(50) || self.ds[k].skip.get(&PH_NODES) == Some(&true)) {
                    // Anyone may answer from the cache; the challenger usually does.
                    let caller = if self.rng.pct(80) { who } else { B };
                    let i = ix(V::SUB_CACHE_ANSWER, &[], vec![AccountMeta::new_readonly(pk(caller), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(self.cache, false)]);
                    let now = self.now().await;
                    let e = if now + 10 <= self.ds[k].deadline { Expect::Accepted } else { Expect::Any };
                    self.send(&format!("cache_answer d{}", self.ds[k].nonce), i, caller, e).await;
                    return;
                }
                if self.skips(k) {
                    return;
                }
                let nodes = self.nodes();
                let mut accounts = self.party(E, d);
                if !cache_exists && self.rng.pct(50) {
                    accounts[0] = AccountMeta::new(pk(E), true);
                    accounts.push(AccountMeta::new(self.cache, false));
                    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
                }
                self.send(&format!("reveal_nodes d{}", self.ds[k].nonce), ix(V::SUB_REVEAL_NODES, &nodes, accounts), E, expect).await;
            }
            PH_PICK => {
                if self.skips(k) {
                    return;
                }
                let index = match self.ds[k].plan {
                    Plan::Honest(Lie::Empty) | Plan::Puppet(Lie::Empty) => 0u8,
                    Plan::Honest(_) | Plan::Puppet(_) => 1,
                    Plan::Grief => self.rng.pick(&[0u8, 1, 1, 2]),
                };
                let i = ix(V::SUB_PICK, &[index], self.party(who, d));
                self.send(&format!("pick {index} d{}", self.ds[k].nonce), i, who, expect).await;
            }
            PH_LEAF => {
                if self.skips(k) {
                    return;
                }
                let leaf = self.leaf_bytes(&self.ds[k]);
                if self.rng.pct(20) && self.account(buffer(d, V::ROLE_EXECUTOR)).await.is_none() {
                    let creator = if protected || self.rng.pct(50) { E } else { who };
                    if self.stage(k, V::ROLE_EXECUTOR, creator, &leaf, expect).await {
                        let mut accounts = self.party(E, d);
                        accounts.push(AccountMeta::new_readonly(buffer(d, V::ROLE_EXECUTOR), false));
                        self.send(&format!("reveal_leaf staged d{}", self.ds[k].nonce), ix(V::SUB_REVEAL_LEAF, &[V::FROM_STAGING], accounts), E, expect).await;
                    }
                    return;
                }
                self.send(&format!("reveal_leaf d{}", self.ds[k].nonce), ix(V::SUB_REVEAL_LEAF, &leaf, self.party(E, d)), E, expect).await;
            }
            PH_CLAIM => {
                if self.skips(k) {
                    return;
                }
                let body = self.claim_body(k);
                if self.rng.pct(20) && body.len() > 2 && self.account(buffer(d, V::ROLE_CHALLENGER)).await.is_none() {
                    let creator = if protected || self.rng.pct(70) { who } else { E };
                    if self.stage(k, V::ROLE_CHALLENGER, creator, &body, expect).await {
                        let mut accounts = self.claim_accounts(who, k);
                        accounts.push(AccountMeta::new_readonly(buffer(d, V::ROLE_CHALLENGER), false));
                        self.send(&format!("claim staged d{}", self.ds[k].nonce), ix(V::SUB_CLAIM, &[V::FROM_STAGING], accounts), who, expect).await;
                    }
                    return;
                }
                let accounts = self.claim_accounts(who, k);
                self.send(&format!("claim {} d{}", body[0], self.ds[k].nonce), ix(V::SUB_CLAIM, &body, accounts), who, expect).await;
            }
            _ => {}
        }
    }

    /// Create a staging buffer for `role` (rent from `creator`) and write
    /// `bytes` in random chunks by the role's party.
    async fn stage(&mut self, k: usize, role: u8, creator: u8, bytes: &[u8], expect: Expect) -> bool {
        let d = self.ds[k].key;
        let buf = buffer(d, role);
        let size = bytes.len() as u32 + self.rng.range(0, 600) as u32;
        let mut data = vec![role];
        data.extend_from_slice(&size.to_le_bytes());
        let i = ix(V::SUB_STAGE_CREATE, &data, vec![AccountMeta::new(pk(creator), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false), AccountMeta::new_readonly(SYSTEM, false)]);
        if !self.send(&format!("stage_create role {role} d{}", self.ds[k].nonce), i, creator, expect).await {
            return false;
        }
        let writer = if role == V::ROLE_EXECUTOR { E } else { self.ds[k].who };
        let chunk = self.rng.range(64, 500) as usize;
        for (n, part) in bytes.chunks(chunk).enumerate() {
            let mut w = ((n * chunk) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(part);
            let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(pk(writer), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false)]);
            if !self.send(&format!("stage_write role {role} d{}", self.ds[k].nonce), i, writer, expect).await {
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
        if self.ds.iter().any(|d| !d.opened && d.plan.protected()) && self.status == V::RUN_COMMITTED {
            let run = self.account(self.run).await.unwrap().data;
            limit = limit.min(u64_at(&run, R_DEADLINE).saturating_sub(MARGIN));
        }
        limit
    }

    async fn warp(&mut self) {
        let now = self.now().await;
        let run_deadline = match self.account(self.run).await {
            Some(a) if a.data.len() != V::RECEIPT_BYTES => u64_at(&a.data, R_DEADLINE),
            _ => now,
        };
        let deadlines: Vec<u64> = self.ds.iter().filter(|d| d.unruled()).map(|d| d.deadline).collect();
        let target = match self.rng.below(4) {
            0 | 1 => now + self.rng.range(1, 250),
            2 if !deadlines.is_empty() => self.rng.pick(&deadlines) + self.rng.range(0, 3),
            _ => run_deadline + self.rng.range(0, 3),
        };
        let target = target.min(self.warp_limit().await);
        if target > now + 1 {
            self.ctx.warp_to_slot(target).unwrap();
            self.trace.push(format!("warp {now} -> {target}"));
            self.check().await;
        }
    }

    /// A random permissionless call, mostly from the bystander.
    async fn random_perm(&mut self) {
        let p = self.rng.pick(&[Perm::Timeout, Perm::Timeout, Perm::Moot, Perm::Advance, Perm::Advance, Perm::PayPot, Perm::CloseDispute, Perm::CloseDispute, Perm::Finalize, Perm::CloseCache, Perm::CloseRun, Perm::CloseTemplate]);
        let k = self.rng.below(self.ds.len() as u64) as usize;
        let caller = if matches!(p, Perm::CloseTemplate) { if self.rng.pct(50) { A } else { B } } else if self.rng.pct(80) { B } else { self.rng.pick(&ACTORS) };
        // A close from the payer or the bystander before the run settles must
        // be refused; the checks catch any premature effect.
        self.perm(p, k, caller, Expect::Any).await;
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
                        let body = self.claim_body(k);
                        ix(V::SUB_CLAIM, &body, self.claim_accounts(signer, k))
                    }
                };
                self.send("perturb: wrong signer", i, signer, Expect::Refused).await;
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
                    self.send("perturb: out of turn", i, s, Expect::Refused).await;
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
                self.send("perturb: corrupted reveal", ix(sub, &data, self.party(E, d)), E, Expect::Refused).await;
            }
            // A settlement call naming the wrong recipient.
            3 => {
                let k = self.rng.below(self.ds.len() as u64) as usize;
                let who = self.ds[k].who;
                let p = self.rng.pick(&[Perm::Timeout, Perm::Moot, Perm::PayPot, Perm::CloseDispute, Perm::Finalize, Perm::CloseRun, Perm::CloseCache]);
                let wrong_c = self.rng.pick(&others(who));
                let (challenger, payer, executor) = match p {
                    // Moot names no executor: only its challenger can be wrong.
                    Perm::Moot => (wrong_c, A, E),
                    Perm::Timeout | Perm::CloseDispute if self.rng.pct(50) => (wrong_c, A, E),
                    Perm::PayPot if self.rng.pct(50) => (wrong_c, A, E),
                    Perm::PayPot | Perm::CloseRun => (who, self.rng.pick(&others(A)), E),
                    _ => (who, A, self.rng.pick(&others(E))),
                };
                let (i, s) = self.perm_ix(p, k, B, challenger, payer, executor);
                self.send(&format!("perturb: {p:?} wrong recipient"), i, s, Expect::Refused).await;
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
                if writer == E && owner == E {
                    return;
                }
                let mut w = 0u32.to_le_bytes().to_vec();
                w.push(0xAB);
                let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(pk(writer), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false)]);
                self.send("perturb: foreign staging write", i, writer, Expect::Refused).await;
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
                self.send("perturb: forged dispute", i, B, Expect::Refused).await;
            }
            _ => {}
        }
    }

    // --- the sequence ----------------------------------------------------------

    async fn play(&mut self) {
        let budget = self.rng.range(20, 160);
        for _ in 0..budget {
            let now = self.now().await;
            let run_open = self.status == V::RUN_COMMITTED && !self.run_closed;
            let run_deadline = if run_open { u64_at(&self.account(self.run).await.unwrap().data, R_DEADLINE) } else { 0 };
            let pending: Vec<usize> = (0..self.ds.len()).filter(|&k| !self.ds[k].opened && !self.ds[k].closed).collect();
            let movable: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].unruled() && now <= self.ds[k].deadline).collect();
            if movable.is_empty() && (pending.is_empty() || !run_open || now > run_deadline) && self.rng.pct(70) {
                break;
            }
            // Protected parties at their margin move first.
            let urgent: Vec<usize> = movable.iter().copied().filter(|&k| self.protected_move(k) && self.ds[k].deadline <= now + MARGIN + 5).collect();
            if let Some(&k) = urgent.first() {
                self.moves(k).await;
                continue;
            }
            match self.rng.below(20) {
                0..=7 if !movable.is_empty() => {
                    let k = self.rng.pick(&movable);
                    self.moves(k).await;
                }
                8..=11 if !pending.is_empty() => {
                    let k = self.rng.pick(&pending);
                    self.open(k).await;
                    if !self.ds[k].opened && !self.ds[k].plan.protected() && self.rng.pct(50) {
                        self.ds[k].closed = true; // gave up; never opens
                    }
                }
                12..=14 => self.warp().await,
                15..=16 => self.random_perm().await,
                _ => self.perturb().await,
            }
        }
        // Protected parties still owed an open or a move get them now.
        for k in 0..self.ds.len() {
            if !self.ds[k].opened && !self.ds[k].closed && self.ds[k].plan.protected() {
                self.open(k).await;
            }
        }
        loop {
            let now = self.now().await;
            let Some(k) = (0..self.ds.len()).find(|&k| self.ds[k].unruled() && self.protected_move(k) && now <= self.ds[k].deadline) else { break };
            let before = (self.ds[k].phase, self.ds[k].ruling);
            self.moves(k).await;
            if (self.ds[k].phase, self.ds[k].ruling) == before {
                self.fail("a protected move made no progress");
            }
        }
        self.settle().await;
    }

    /// Past every deadline, settle and close everything; each step must be
    /// accepted.
    async fn settle(&mut self) {
        if self.run_closed {
            self.fail("the run closed before settlement");
        }
        let mut horizon = self.now().await;
        if let Some(a) = self.account(self.run).await {
            horizon = horizon.max(u64_at(&a.data, R_DEADLINE));
        }
        for d in &self.ds {
            if d.unruled() {
                horizon = horizon.max(d.deadline);
            }
        }
        let now = self.now().await;
        if horizon + 2 > now {
            self.ctx.warp_to_slot(horizon + 2).unwrap();
            self.trace.push(format!("settle: warp to {}", horizon + 2));
        }
        for k in 0..self.ds.len() {
            if !self.ds[k].unruled() {
                continue;
            }
            let p = if self.status == V::RUN_REFUTED && self.ds[k].seq > self.best && self.rng.pct(50) { Perm::Moot } else { Perm::Timeout };
            self.perm(p, k, B, Expect::Accepted).await;
        }
        let mut order: Vec<usize> = (0..self.ds.len()).filter(|&k| self.ds[k].live()).collect();
        order.sort_by_key(|&k| self.ds[k].seq);
        for &k in &order {
            let prefix = u64_at(&self.account(self.run).await.unwrap().data, R_PREFIX);
            if self.ds[k].seq >= prefix {
                self.perm(Perm::Advance, k, B, Expect::Accepted).await;
            }
        }
        if u64_at(&self.account(self.run).await.unwrap().data, R_PREFIX) != self.opened {
            self.fail("the ruled prefix did not reach the sequence counter");
        }
        if self.status == V::RUN_REFUTED && !self.paid {
            let Some(k) = (0..self.ds.len()).find(|&k| self.ds[k].live() && self.ds[k].seq == self.best) else {
                self.fail("the best win is not live before the pot is paid");
            };
            self.perm(Perm::PayPot, k, B, Expect::Accepted).await;
        }
        for &k in &order {
            if self.ds[k].live() {
                self.perm(Perm::CloseDispute, k, B, Expect::Accepted).await;
            }
        }
        if self.status == V::RUN_COMMITTED {
            self.perm(Perm::Finalize, 0, B, Expect::Accepted).await;
        }
        if self.account(self.cache).await.is_some() {
            self.perm(Perm::CloseCache, 0, B, Expect::Accepted).await;
        }
        self.perm(Perm::CloseRun, 0, B, Expect::Accepted).await;
        if !self.template_closed {
            self.perm(Perm::CloseTemplate, 0, A, Expect::Accepted).await;
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
        let share = self.executor_bond * self.slasher_bps / 10_000;
        let payer_share = if refuted { self.executor_bond - share } else { 0 };
        let a = self.balance(pk(A)).await;
        if a != self.init[&A] + payer_share - self.receipt_rent {
            self.fail(&format!("payer nets {} (want pot share {payer_share} less receipt {})", a as i128 - self.init[&A] as i128, self.receipt_rent));
        }
        let honest_opened = self.ds.iter().any(|d| d.plan.protected() && d.opened);
        if !self.lies.is_empty() && honest_opened && !refuted {
            self.fail("an honest challenger disputed a lie, but the run was not refuted");
        }
        if self.lies.is_empty() && self.e_diligent {
            if self.status != V::RUN_FINAL {
                self.fail("an honest, diligent run did not finalize");
            }
            let e = self.balance(pk(E)).await;
            if e < self.init[&E] {
                self.fail("an honest, diligent executor netted negative");
            }
        }
        for who in CHALLENGERS {
            let mine: Vec<&Dsp> = self.ds.iter().filter(|d| d.who == who).collect();
            if !mine.is_empty() && mine.iter().all(|d| d.plan.protected()) {
                let bal = self.balance(pk(who)).await;
                if bal < self.init[&who] {
                    self.fail(&format!("honest challenger {who:x} netted negative"));
                }
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
    refuted: u64,
    final_: u64,
    disputes: u64,
    coverage: BTreeMap<String, u64>,
}

async fn run_one(seed: u64, index: u64, totals: &mut Totals) {
    run_planted(seed, index, totals, None).await;
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
    eprintln!("v21 run fuzz seed {seed}: {} sequences, {} disputes, {} transactions ({} accepted, {} perturbations refused), {} rulings by proof, {} refuted, {} final, {secs:.1} s",
        t.sequences, t.disputes, t.txs, t.accepted, t.refused_perturbations, t.rulings_by_proof, t.refuted, t.final_);
    eprintln!("  accepted by kind: {}", t.coverage.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_fuzz_smoke() {
    let start = std::time::Instant::now();
    let mut t = Totals::default();
    for i in 0..12 {
        run_one(1, i, &mut t).await;
    }
    report(1, &t, start.elapsed().as_secs_f64());
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
        run_one(seed, only.parse().unwrap(), &mut t).await;
    } else {
        let first: u64 = std::env::var("V21_FUZZ_START").map(|s| s.parse().unwrap()).unwrap_or(0);
        let count: u64 = std::env::var("V21_FUZZ_COUNT").map(|s| s.parse().unwrap()).unwrap_or(200);
        for i in first..first + count {
            run_one(seed, i, &mut t).await;
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
#[should_panic(expected = "lamports not conserved")]
async fn run_fuzz_catches_a_planted_lamport_leak() {
    planted("lamports").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "executor-wait count")]
async fn run_fuzz_catches_a_planted_wait_counter_drift() {
    planted("wait").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "ruling")]
async fn run_fuzz_catches_a_planted_ruling_flip() {
    planted("ruling").await;
}
