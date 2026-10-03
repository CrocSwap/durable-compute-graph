//! Optimistic disputes v2.1 program skeleton (tag 227), native ProgramTest on
//! the Hello Graph goldens: honest finalize, and lies refuted by STEP, SHAPE
//! (malformed rule), OUT and timeout; an EDGE against an honest leaf loses.
#![cfg(feature = "graph-v21")]

use dcg_disputes as D;
use dcg_program::disputes_v21 as V;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::system_program;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD6; 32]);
const SYSTEM: Pubkey = system_program::ID;
const EXECUTOR_BOND: u64 = 2_000_000;
const CHALLENGER_BOND: u64 = 1_000_000;
const SLASHER_BPS: u16 = 5_000;
const OUT_BASE: u32 = 4; // header, block, 2 InSpecs
const STEP_BASE: u32 = 7; // + 1 OutSpec, 2 RegionSpecs

struct Soft;
impl D::Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        sha256(parts)
    }
}

fn kp(b: u8) -> Keypair {
    Keypair::new_from_array([b; 32])
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

/// A full tree as levels (for paths), capacity 2^ceil(log2 max(n,1)).
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

struct Chain {
    ctx: ProgramTestContext,
    template: Pubkey,
    run: Pubkey,
    run_id: [u8; 32],
    g: Golden,
    spec_levels: Vec<Vec<D::Hash>>,
    legacy_template: bool,
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

impl Chain {
    async fn new(challenge_window: u64) -> Self {
        Self::new_template_mode(challenge_window, false).await
    }

    #[cfg(feature = "test-legacy-template-create")]
    async fn new_legacy_template(challenge_window: u64) -> Self {
        Self::new_template_mode(challenge_window, true).await
    }

    async fn new_template_mode(challenge_window: u64, legacy_template: bool) -> Self {
        // V21_SBF=1 (with BPF_OUT_DIR naming a graph-v21 image) runs the SBF
        // program; otherwise native.
        let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
        let mut test = ProgramTest::default();
        test.prefer_bpf(sbf);
        if sbf {
            test.add_program("dcg_program", PROGRAM, None);
        } else {
            test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
        }
        for b in [0xA1u8, 0xE1, 0xC1, 0xB1] {
            test.add_account(kp(b).pubkey(), Account { lamports: 10_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
        }
        let mut ctx = test.start_with_context().await;
        let g = golden();
        let spec_leaves: Vec<D::Hash> = g.records.iter().map(|(t, r)| D::spec_leaf(&Soft, *t, r)).collect();
        let spec_levels = levels(D::Tree::Spec, &spec_leaves);
        assert_eq!(spec_levels.last().unwrap()[0], g.spec_root);
        // Template.
        let mut data = vec![4u8];
        for x in [2u64, 1, challenge_window, 750, EXECUTOR_BOND, CHALLENGER_BOND] {
            data.extend_from_slice(&x.to_le_bytes());
        }
        data.extend_from_slice(&OUT_BASE.to_le_bytes());
        data.extend_from_slice(&STEP_BASE.to_le_bytes());
        data.extend_from_slice(&g.spec_root);
        data.extend_from_slice(&SLASHER_BPS.to_le_bytes());
        data.extend_from_slice(&g.plan_id);
        let template_id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
        let template = if legacy_template {
            Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0
        } else {
            Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, kp(0xA1).pubkey().as_ref()], &PROGRAM).0
        };
        let admitter = kp(0xA1);
        #[cfg(feature = "test-legacy-template-create")]
        let create_sub = if legacy_template { V::SUB_TEST_CREATE_LEGACY_TEMPLATE } else { V::SUB_CREATE_TEMPLATE };
        #[cfg(not(feature = "test-legacy-template-create"))]
        let create_sub = V::SUB_CREATE_TEMPLATE;
        #[cfg(not(feature = "test-legacy-template-create"))]
        assert!(!legacy_template, "legacy fixture mode requires test-legacy-template-create");
        send(&mut ctx, ix(create_sub, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
        // Run.
        let executor = kp(0xE1).pubkey();
        let mut init = vec![0u8; 32];
        init.extend_from_slice(executor.as_ref());
        init.extend_from_slice(&2u32.to_le_bytes());
        for r in &g.refs {
            init.extend_from_slice(r);
        }
        let mut refs = Vec::new();
        for r in &g.refs {
            refs.extend_from_slice(r);
        }
        let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &[0u8; 32], &2u32.to_le_bytes(), &refs, executor.as_ref()]);
        let run = Pubkey::find_program_address(&[b"dcg21run", &run_id, admitter.pubkey().as_ref()], &PROGRAM).0;
        if !legacy_template {
            let readonly = ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
            assert!(send(&mut ctx, readonly, &[&admitter]).await.is_err(), "new templates must be writable while incrementing their run count");
        }
        let template_meta = if legacy_template { AccountMeta::new_readonly(template, false) } else { AccountMeta::new(template, false) };
        send(&mut ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), template_meta, AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
        Chain { ctx, template, run, run_id, g, spec_levels, legacy_template }
    }

    fn honest(&self) -> Commit {
        let leaves = self.g.leaves.iter().map(|l| {
            let mut l = l.clone();
            l[32..64].copy_from_slice(&self.run_id);
            Some(l)
        }).collect();
        commitment(&self.g, &self.run_id, leaves, self.g.out_entries.clone())
    }

    async fn commit(&mut self, c: &Commit) {
        let e = kp(0xE1);
        send(&mut self.ctx, ix(V::SUB_COMMIT, &c.root_bytes, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&e]).await.unwrap();
    }

    fn dispute(&self, nonce: u8) -> Pubkey {
        Pubkey::find_program_address(&[b"dcg21dsp", self.run.as_ref(), kp(0xC1).pubkey().as_ref(), &[nonce; 32]], &PROGRAM).0
    }

    async fn open(&mut self, nonce: u8, kind: u8) -> Pubkey {
        let c = kp(0xC1);
        let d = self.dispute(nonce);
        let mut data = vec![nonce; 32];
        data.push(kind);
        send(&mut self.ctx, ix(V::SUB_OPEN, &data, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c]).await.unwrap();
        d
    }

    fn party(&self, who: u8, d: Pubkey) -> Vec<AccountMeta> {
        vec![AccountMeta::new_readonly(kp(who).pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false)]
    }

    async fn step(&mut self, d: Pubkey, c: &Commit, leaf_index: usize) {
        // Height 1: reveal both children, pick, reveal the leaf.
        let e = kp(0xE1);
        let mut nodes = Vec::new();
        nodes.extend_from_slice(&c.step[0][0]);
        nodes.extend_from_slice(&c.step[0][1]);
        let i = ix(V::SUB_REVEAL_NODES, &nodes, self.party(0xE1, d));
        send(&mut self.ctx, i, &[&e]).await.unwrap();
        let i = ix(V::SUB_PICK, &[leaf_index as u8], self.party(0xC1, d));
        send(&mut self.ctx, i, &[&kp(0xC1)]).await.unwrap();
        let mut leaf = vec![c.leaves[leaf_index].is_some() as u8];
        if let Some(l) = &c.leaves[leaf_index] {
            leaf.extend_from_slice(l);
        }
        let i = ix(V::SUB_REVEAL_LEAF, &leaf, self.party(0xE1, d));
        send(&mut self.ctx, i, &[&e]).await.unwrap();
    }

    fn spec_opening(&self, leaf: usize) -> Vec<u8> {
        let (t, r) = &self.g.records[leaf];
        let mut v = vec![*t];
        v.extend_from_slice(&(r.len() as u16).to_le_bytes());
        v.extend_from_slice(r);
        v.extend(enc_path(&path(&self.spec_levels, leaf)));
        v
    }

    fn step_opening(&self, c: &Commit, ordinal: usize) -> Vec<u8> {
        let l = c.leaves[ordinal].clone();
        let mut v = vec![l.is_some() as u8];
        let body = l.unwrap_or_default();
        v.extend_from_slice(&(body.len() as u16).to_le_bytes());
        v.extend_from_slice(&body);
        v.extend(enc_path(&path(&c.step, ordinal)));
        v
    }

    async fn claim(&mut self, d: Pubkey, body: Vec<u8>) -> Result<(), TransactionError> {
        let c = kp(0xC1);
        let accounts = vec![AccountMeta::new_readonly(c.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(c.pubkey(), false)];
        send(&mut self.ctx, ix(V::SUB_CLAIM, &body, accounts), &[&c]).await
    }

    async fn run_status(&mut self) -> u8 {
        self.ctx.banks_client.get_account(self.run).await.unwrap().unwrap().data[4]
    }

    async fn ruling(&mut self, d: Pubkey) -> u8 {
        self.ctx.banks_client.get_account(d).await.unwrap().unwrap().data[6]
    }
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), TransactionError> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| e.unwrap())?.result
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_run_finalizes_and_returns_the_bond() {
    let mut ch = Chain::new(10).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let before = ch.ctx.banks_client.get_balance(kp(0xE1).pubkey()).await.unwrap();
    ch.ctx.warp_to_slot(40).unwrap();
    let caller = kp(0xA1);
    send(&mut ch.ctx, ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(kp(0xE1).pubkey(), false)]), &[&caller]).await.unwrap();
    assert_eq!(ch.run_status().await, V::RUN_FINAL);
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xE1).pubkey()).await.unwrap(), before + EXECUTOR_BOND);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_output_is_refuted_by_step() {
    let mut ch = Chain::new(1_000).await;
    let mut c = ch.honest();
    // Leaf 1 (identity of 42) claims output 43.
    let mut l = c.leaves[1].clone().unwrap();
    let n = l.len();
    let wrong = D::value_digest(&Soft, &43i32.to_le_bytes());
    l[n - 64 - 32..n - 64].copy_from_slice(&wrong);
    c = commitment(&ch.g, &ch.run_id, vec![c.leaves[0].clone(), Some(l)], c.outs.clone());
    ch.commit(&c).await;
    let d = ch.open(1, V::KIND_STEP_DESCEND).await;
    ch.step(d, &c, 1).await;
    let mut body = vec![V::CLAIM_STEP, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
    body.push(1);
    body.extend_from_slice(&4u32.to_le_bytes());
    body.extend_from_slice(&42i32.to_le_bytes());
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, 2, "challenger");
    assert_eq!(ch.run_status().await, V::RUN_REFUTED);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_leaf_rules_for_the_challenger() {
    let mut ch = Chain::new(1_000).await;
    let h = ch.honest();
    let c = commitment(&ch.g, &ch.run_id, vec![None, h.leaves[1].clone()], h.outs.clone());
    ch.commit(&c).await;
    let d = ch.open(2, V::KIND_STEP_DESCEND).await;
    ch.step(d, &c, 0).await;
    let mut body = vec![V::CLAIM_SHAPE, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize));
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_posted_output_is_refuted_by_out() {
    let mut ch = Chain::new(1_000).await;
    let h = ch.honest();
    let mut outs = h.outs.clone();
    outs[0][23..55].copy_from_slice(&D::value_digest(&Soft, &7i32.to_le_bytes()));
    let c = commitment(&ch.g, &ch.run_id, h.leaves.clone(), outs);
    ch.commit(&c).await;
    let d = ch.open(3, V::KIND_OUT_DESCEND).await;
    let mut entry = vec![1u8];
    entry.extend_from_slice(&c.outs[0]);
    let i = ix(V::SUB_REVEAL_LEAF, &entry, ch.party(0xE1, d));
    send(&mut ch.ctx, i, &[&kp(0xE1)]).await.unwrap();
    let mut body = vec![V::CLAIM_OUT, 0];
    body.extend(ch.spec_opening(OUT_BASE as usize));
    body.extend(ch.step_opening(&c, 1));
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_against_an_honest_leaf_rules_for_the_executor() {
    let mut ch = Chain::new(1_000).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let d = ch.open(4, V::KIND_STEP_DESCEND).await;
    ch.step(d, &c, 1).await;
    let mut body = vec![V::CLAIM_EDGE, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
    body.extend(ch.step_opening(&c, 0));
    let before = ch.ctx.banks_client.get_balance(kp(0xE1).pubkey()).await.unwrap();
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, 1, "executor");
    assert_eq!(ch.run_status().await, V::RUN_COMMITTED);
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xE1).pubkey()).await.unwrap(), before + CHALLENGER_BOND);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_executor_loses_at_its_deadline() {
    let mut ch = Chain::new(1_000).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let d = ch.open(5, V::KIND_STEP_DESCEND).await;
    let caller = kp(0xA1);
    let accounts = vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)];
    assert!(send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], accounts.clone()), &[&caller]).await.is_err(), "not before the deadline");
    ch.ctx.warp_to_slot(2_000).unwrap();
    send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], accounts), &[&caller]).await.unwrap();
    assert_eq!(ch.ruling(d).await, 2);
    assert_eq!(ch.run_status().await, V::RUN_REFUTED);
}

impl Chain {
    async fn win_by_step(&mut self, d: Pubkey, c: &Commit) {
        self.step(d, c, 1).await;
        let mut body = vec![V::CLAIM_STEP, 0];
        body.extend(self.spec_opening(STEP_BASE as usize + 1));
        body.push(1);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&42i32.to_le_bytes());
        self.claim(d, body).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn earliest_opened_winner_takes_the_pot_and_later_disputes_are_moot() {
    let mut ch = Chain::new(1_000).await;
    let h = ch.honest();
    let mut l = h.leaves[1].clone().unwrap();
    let n = l.len();
    l[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
    let c = commitment(&ch.g, &ch.run_id, vec![h.leaves[0].clone(), Some(l)], h.outs.clone());
    // Conservation: every lamport moved below stays among these accounts
    // (fees come from the test payer, which is not tracked).
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), ch.run, ch.dispute(10), ch.dispute(11), ch.dispute(12)];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    ch.commit(&c).await;
    let d0 = ch.open(10, V::KIND_STEP_DESCEND).await; // sequence 0 (the honest challenger)
    let d1 = ch.open(11, V::KIND_STEP_DESCEND).await; // sequence 1 (a faster puppet)
    let d2 = ch.open(12, V::KIND_STEP_DESCEND).await; // sequence 2
    let mut d2_nodes = Vec::new();
    d2_nodes.extend_from_slice(&c.step[0][0]);
    d2_nodes.extend_from_slice(&c.step[0][1]);
    let d2_reveal = ix(V::SUB_REVEAL_NODES, &d2_nodes, ch.party(0xE1, d2));
    send(&mut ch.ctx, d2_reveal, &[&kp(0xE1)]).await.unwrap();
    matrix_pick(&mut ch, d2).await; // leave the later puppet waiting in LEAF
    ch.win_by_step(d1, &c).await;
    assert_eq!(ch.run_status().await, V::RUN_REFUTED);
    // No new opens on a refuted run.
    let c1 = kp(0xC1);
    let mut data = vec![13u8; 32];
    data.push(V::KIND_STEP_DESCEND);
    let late = ch.dispute(13);
    let i = ix(V::SUB_OPEN, &data, vec![AccountMeta::new(c1.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(late, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, i, &[&c1]).await.is_err());
    // Sequence 2 is after the best win: moot, bond refunded.
    let caller = kp(0xA1);
    let moot = |d: Pubkey, run: Pubkey, template: Pubkey| ix(V::SUB_MOOT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xC1).pubkey(), false)]);
    send(&mut ch.ctx, moot(d2, ch.run, ch.template), &[&caller]).await.unwrap();
    assert_eq!(ch.ruling(d2).await, V::RULING_MOOT);
    // Sequence 0 is earlier than the best win: not moot; it plays on and wins.
    assert!(send(&mut ch.ctx, moot(d0, ch.run, ch.template), &[&caller]).await.is_err());
    ch.win_by_step(d0, &c).await;
    // The pot waits for the ruled prefix to pass sequence 0.
    let payer = kp(0xA1).pubkey();
    let pot = |d: Pubkey, run: Pubkey, template: Pubkey| ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(payer, false)]);
    assert!(send(&mut ch.ctx, pot(d0, ch.run, ch.template), &[&caller]).await.is_err(), "prefix has not passed best_win");
    let adv = ix(V::SUB_ADVANCE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d0, false)]);
    send(&mut ch.ctx, adv, &[&caller]).await.unwrap();
    assert!(send(&mut ch.ctx, pot(d1, ch.run, ch.template), &[&caller]).await.is_err(), "the puppet is not best_win");
    let challenger_before = ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap();
    send(&mut ch.ctx, pot(d0, ch.run, ch.template), &[&caller]).await.unwrap();
    let share = EXECUTOR_BOND * SLASHER_BPS as u64 / 10_000;
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap(), challenger_before + share);
    assert!(send(&mut ch.ctx, pot(d0, ch.run, ch.template), &[&caller]).await.is_err(), "paid once");
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "lamports are conserved");
    // The run keeps exactly its rent floor; the disputes keep theirs.
    let run_acct = ch.ctx.banks_client.get_account(ch.run).await.unwrap().unwrap();
    let rent = ch.ctx.banks_client.get_rent().await.unwrap();
    assert_eq!(run_acct.lamports, rent.minimum_balance(run_acct.data.len()));
    for d in [d0, d1, d2] {
        let a = ch.ctx.banks_client.get_account(d).await.unwrap().unwrap();
        assert_eq!(a.lamports, rent.minimum_balance(a.data.len()));
    }
}

impl Chain {
    fn buffer(&self, d: Pubkey, role: u8) -> Pubkey {
        Pubkey::find_program_address(&[b"dcg21stg", d.as_ref(), &[role]], &PROGRAM).0
    }

    async fn stage(&mut self, d: Pubkey, role: u8, size: u32, bytes: &[u8], chunk: usize) {
        let c = kp(0xC1);
        let buf = self.buffer(d, role);
        let mut data = vec![role];
        data.extend_from_slice(&size.to_le_bytes());
        let i = ix(V::SUB_STAGE_CREATE, &data, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false), AccountMeta::new_readonly(SYSTEM, false)]);
        send(&mut self.ctx, i, &[&c]).await.unwrap();
        let writer = if role == V::ROLE_EXECUTOR { kp(0xE1) } else { kp(0xC1) };
        for (k, part) in bytes.chunks(chunk).enumerate() {
            let mut w = ((k * chunk) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(part);
            let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(writer.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buf, false)]);
            send(&mut self.ctx, i, &[&writer]).await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn openings_and_witnesses_can_come_from_staging_buffers() {
    let mut ch = Chain::new(1_000).await;
    let h = ch.honest();
    let mut l = h.leaves[1].clone().unwrap();
    let n = l.len();
    l[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
    let c = commitment(&ch.g, &ch.run_id, vec![h.leaves[0].clone(), Some(l.clone())], h.outs.clone());
    ch.commit(&c).await;
    let d = ch.open(20, V::KIND_STEP_DESCEND).await;
    // Descend to leaf 1.
    let e = kp(0xE1);
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    let i = ix(V::SUB_REVEAL_NODES, &nodes, ch.party(0xE1, d));
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    let i = ix(V::SUB_PICK, &[1], ch.party(0xC1, d));
    send(&mut ch.ctx, i, &[&kp(0xC1)]).await.unwrap();
    // E stages its leaf (in 100-byte writes) and reveals from staging.
    let mut leaf = vec![1u8];
    leaf.extend_from_slice(&l);
    ch.stage(d, V::ROLE_EXECUTOR, 2_000, &leaf, 100).await;
    let mut accounts = ch.party(0xE1, d);
    accounts.push(AccountMeta::new_readonly(ch.buffer(d, V::ROLE_EXECUTOR), false));
    let i = ix(V::SUB_REVEAL_LEAF, &[V::FROM_STAGING], accounts);
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    // C stages its STEP claim and submits from staging.
    let mut body = vec![V::CLAIM_STEP, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
    body.push(1);
    body.extend_from_slice(&4u32.to_le_bytes());
    body.extend_from_slice(&42i32.to_le_bytes());
    ch.stage(d, V::ROLE_CHALLENGER, 4_000, &body, 300).await;
    let cl = kp(0xC1);
    let base = vec![AccountMeta::new_readonly(cl.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(cl.pubkey(), false)];
    // E's buffer is not C's: refused.
    let mut wrong = base.clone();
    wrong.push(AccountMeta::new_readonly(ch.buffer(d, V::ROLE_EXECUTOR), false));
    let i = ix(V::SUB_CLAIM, &[V::FROM_STAGING], wrong);
    assert!(send(&mut ch.ctx, i, &[&cl]).await.is_err());
    // C cannot write E's buffer.
    let mut w = 0u32.to_le_bytes().to_vec();
    w.push(9);
    let i = ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(cl.pubkey(), true), AccountMeta::new_readonly(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(ch.buffer(d, V::ROLE_EXECUTOR), false)]);
    assert!(send(&mut ch.ctx, i, &[&cl]).await.is_err());
    let mut right = base;
    right.push(AccountMeta::new_readonly(ch.buffer(d, V::ROLE_CHALLENGER), false));
    let i = ix(V::SUB_CLAIM, &[V::FROM_STAGING], right);
    send(&mut ch.ctx, i, &[&cl]).await.unwrap();
    assert_eq!(ch.ruling(d).await, V::RULING_CHALLENGER);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cached_reveal_answers_a_second_dispute_without_the_executor() {
    let mut ch = Chain::new(1_000).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let a = ch.open(30, V::KIND_STEP_DESCEND).await;
    let b = ch.open(31, V::KIND_STEP_DESCEND).await;
    let e = kp(0xE1);
    let cache = Pubkey::find_program_address(&[b"dcg21rc", ch.run.as_ref(), &[V::KIND_STEP_DESCEND], &1u32.to_le_bytes(), &0u64.to_le_bytes()], &PROGRAM).0;
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    // The executor's signer pays the cache rent, so it is writable here.
    let mut accounts = vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(a, false)];
    accounts.push(AccountMeta::new(cache, false));
    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
    let i = ix(V::SUB_REVEAL_NODES, &nodes, accounts);
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    assert_eq!(matrix_wait(&mut ch).await.0, 1);
    // Dispute B is answered from the cache by its own challenger.
    let cl = kp(0xC1);
    let answer = |d: Pubkey, run: Pubkey, template: Pubkey, k: Pubkey| ix(V::SUB_CACHE_ANSWER, &[], vec![AccountMeta::new_readonly(cl.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(k, false)]);
    send(&mut ch.ctx, answer(b, ch.run, ch.template, cache), &[&cl]).await.unwrap();
    assert_eq!(matrix_wait(&mut ch).await.0, 0, "CACHE_ANSWER ends B's executor wait");
    assert_eq!(ch.ctx.banks_client.get_account(b).await.unwrap().unwrap().data[4], 2, "B awaits a pick");
    // A forged cache (any program-owned account with the bytes) is refused.
    let mut forged = ch.ctx.banks_client.get_account(cache).await.unwrap().unwrap();
    forged.data[24] ^= 1;
    let fake = Pubkey::new_unique();
    ch.ctx.set_account(&fake, &forged.into());
    let d3 = ch.open(32, V::KIND_STEP_DESCEND).await;
    assert!(send(&mut ch.ctx, answer(d3, ch.run, ch.template, fake), &[&cl]).await.is_err());
    // A then B play on: picking the honest leaf and losing EDGE, as usual.
    let i = ix(V::SUB_PICK, &[1], ch.party(0xC1, b));
    send(&mut ch.ctx, i, &[&cl]).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_dispute_record_is_refused() {
    // Review B1: a program-owned account holding a copy of a real dispute
    // (same run, challenger, phase) is not a dispute.
    let mut ch = Chain::new(1_000).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let real = ch.open(40, V::KIND_STEP_DESCEND).await;
    let copy = ch.ctx.banks_client.get_account(real).await.unwrap().unwrap();
    ch.ctx.warp_to_slot(2_000).unwrap();
    let fake = Pubkey::new_unique();
    ch.ctx.set_account(&fake, &copy.into());
    let caller = kp(0xA1);
    let accounts = |d: Pubkey, run: Pubkey, template: Pubkey| vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)];
    assert!(send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], accounts(fake, ch.run, ch.template)), &[&caller]).await.is_err());
    assert_eq!(ch.run_status().await, V::RUN_COMMITTED, "the forged timeout changed nothing");
    // The real dispute still times out normally.
    send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], accounts(real, ch.run, ch.template)), &[&caller]).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_refuses_bad_templates_and_runs() {
    let mut ch = Chain::new(1_000).await;
    let admitter = kp(0xA1);
    // Depth 5 (review B3), a phase window under the 750-slot floor, and a
    // zero executor or challenger bond (review 10-03, F4).
    for (depth, phase, eb, cb) in [(5u8, 750u64, EXECUTOR_BOND, CHALLENGER_BOND), (4, 749, EXECUTOR_BOND, CHALLENGER_BOND), (4, 750, 0, CHALLENGER_BOND), (4, 750, EXECUTOR_BOND, 0)] {
        let mut data = vec![depth];
        for x in [2u64, 1, 1_000, phase, eb, cb] {
            data.extend_from_slice(&x.to_le_bytes());
        }
        data.extend_from_slice(&OUT_BASE.to_le_bytes());
        data.extend_from_slice(&STEP_BASE.to_le_bytes());
        data.extend_from_slice(&ch.g.spec_root);
        data.extend_from_slice(&SLASHER_BPS.to_le_bytes());
        data.extend_from_slice(&ch.g.plan_id);
        let id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
        let t = Pubkey::find_program_address(&[b"dcg21tmpl", &id, admitter.pubkey().as_ref()], &PROGRAM).0;
        let i = ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(t, false), AccountMeta::new_readonly(SYSTEM, false)]);
        assert!(send(&mut ch.ctx, i, &[&admitter]).await.is_err(), "depth {depth} phase {phase} bonds {eb} {cb}");
    }
    // An ignored trailer used to alias one semantic template under 2^32 IDs.
    let mut data = template_body(&ch.g, 1_000);
    data.extend_from_slice(&[0, 0, 0, 0]);
    let id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
    let t = Pubkey::find_program_address(&[b"dcg21tmpl", &id, admitter.pubkey().as_ref()], &PROGRAM).0;
    let i = ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(t, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, i, &[&admitter]).await.is_err());
    // Unsorted external refs (review B2), and a payer naming itself executor.
    let init = |executor: &Pubkey, refs: &[&Vec<u8>]| {
        let mut d = vec![9u8; 32];
        d.extend_from_slice(executor.as_ref());
        d.extend_from_slice(&(refs.len() as u32).to_le_bytes());
        for r in refs {
            d.extend_from_slice(r);
        }
        d
    };
    let unsorted = init(&kp(0xE1).pubkey(), &[&ch.g.refs[1], &ch.g.refs[0]]);
    let selfpaid = init(&admitter.pubkey(), &[&ch.g.refs[0], &ch.g.refs[1]]);
    for data in [unsorted, selfpaid] {
        let run = Pubkey::new_unique();
        let i = ix(V::SUB_INIT_RUN, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
        assert!(send(&mut ch.ctx, i, &[&admitter]).await.is_err());
    }
    // A commit under another plan id is refused.
    let mut c = ch.honest();
    c.root_bytes[0] ^= 1;
    let e = kp(0xE1);
    let i = ix(V::SUB_COMMIT, &c.root_bytes, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, i, &[&e]).await.is_err());
}

async fn total_lamports(ctx: &mut ProgramTestContext, keys: &[Pubkey]) -> u128 {
    let mut t = 0u128;
    for k in keys {
        t += ctx.banks_client.get_balance(*k).await.unwrap() as u128;
    }
    t
}

// L6: the same real-instruction state builder is used in native and SBF
// ProgramTest (V21_SBF=1).  "truth" describes the committed computation;
// the party that misses a move is culpable even when its preceding data was
// correct.  The four timeout rows cover every owed phase.
#[derive(Clone, Copy, Debug)]
enum Ending { Proof, NodesTimeout, PickTimeout, LeafTimeout, ClaimTimeout, Moot }

async fn matrix_balance(ch: &mut Chain, key: Pubkey) -> u64 {
    ch.ctx.banks_client.get_balance(key).await.unwrap()
}

async fn matrix_timeout(ch: &mut Chain, d: Pubkey) {
    let caller = kp(0xA1);
    let i = ix(V::SUB_TIMEOUT, &[], vec![
        AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false),
        AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false),
        AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false),
    ]);
    assert!(send(&mut ch.ctx, i.clone(), &[&caller]).await.is_err(), "early timeout");
    ch.ctx.warp_to_slot(5_000).unwrap();
    send(&mut ch.ctx, i, &[&caller]).await.unwrap();
}

async fn matrix_nodes(ch: &mut Chain, d: Pubkey, c: &Commit) {
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    let mut accounts = ch.party(0xE1, d);
    accounts[0] = AccountMeta::new(kp(0xE1).pubkey(), true); // pays cache rent
    let cache = matrix_cache(ch);
    accounts.push(AccountMeta::new(cache, false));
    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
    send(&mut ch.ctx, ix(V::SUB_REVEAL_NODES, &nodes, accounts.clone()), &[&kp(0xE1)]).await.unwrap();
    let before = matrix_wait(ch).await;
    assert!(send(&mut ch.ctx, ix(V::SUB_REVEAL_NODES, &nodes, accounts), &[&kp(0xE1)]).await.is_err(),
        "executor cannot answer again while the challenger owes PICK");
    assert_eq!(matrix_wait(ch).await, before, "executor cannot bank an extension on the challenger's turn");
}

fn matrix_cache(ch: &Chain) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg21rc", ch.run.as_ref(), &[V::KIND_STEP_DESCEND], &1u32.to_le_bytes(), &0u64.to_le_bytes()], &PROGRAM).0
}

async fn matrix_pick(ch: &mut Chain, d: Pubkey) {
    let accounts = ch.party(0xC1, d);
    send(&mut ch.ctx, ix(V::SUB_PICK, &[1], accounts), &[&kp(0xC1)]).await.unwrap();
}

async fn matrix_leaf(ch: &mut Chain, d: Pubkey, c: &Commit) {
    let mut leaf = vec![1];
    leaf.extend_from_slice(c.leaves[1].as_ref().unwrap());
    let accounts = ch.party(0xE1, d);
    send(&mut ch.ctx, ix(V::SUB_REVEAL_LEAF, &leaf, accounts), &[&kp(0xE1)]).await.unwrap();
}

async fn matrix_wait(ch: &mut Chain) -> (u32, u64) {
    let run = ch.ctx.banks_client.get_account(ch.run).await.unwrap().unwrap();
    let tail = &run.data[run.data.len() - 4..];
    (u32::from_le_bytes(tail.try_into().unwrap()), 0)
}

#[tokio::test(flavor = "multi_thread")]
async fn l6_endings_matrix_native_and_sbf() {
    let rows = [Ending::Proof, Ending::NodesTimeout, Ending::PickTimeout,
        Ending::LeafTimeout, Ending::ClaimTimeout, Ending::Moot];
    for executor_truthful in [true, false] {
        for ending in rows {
            // A moot dispute requires an earlier challenger proof win.  A
            // truthful E cannot supply that state while still answering all
            // owed moves, so this logical cell has no honest role order.
            if executor_truthful && matches!(ending, Ending::Moot) { continue; }
            let cell = format!("{ending:?}/executor_truthful={executor_truthful}");
            let mut ch = Chain::new(30).await;
            let h = ch.honest();
            let c = if executor_truthful { h } else {
                let mut leaf = h.leaves[1].clone().unwrap();
                let n = leaf.len();
                leaf[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
                commitment(&ch.g, &ch.run_id, vec![h.leaves[0].clone(), Some(leaf)], h.outs)
            };
            let d = ch.dispute(201);
            let d_moot = ch.dispute(202);
            let cache = matrix_cache(&ch);
            let keys = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(),
                ch.run, ch.template, d, d_moot, cache];
            let before = total_lamports(&mut ch.ctx, &keys).await;
            let payer_before = matrix_balance(&mut ch, kp(0xA1).pubkey()).await;
            let (run_key, template_key) = (ch.run, ch.template);
            let run_rent = matrix_balance(&mut ch, run_key).await;
            let template_rent = matrix_balance(&mut ch, template_key).await;
            let e_before = matrix_balance(&mut ch, kp(0xE1).pubkey()).await;
            let c_before = matrix_balance(&mut ch, kp(0xC1).pubkey()).await;
            ch.commit(&c).await;
            assert_eq!(ch.open(201, V::KIND_STEP_DESCEND).await, d);
            if matches!(ending, Ending::Moot) { ch.open(202, V::KIND_STEP_DESCEND).await; }
            if !matches!(ending, Ending::NodesTimeout) { matrix_nodes(&mut ch, d, &c).await; }
            if !matches!(ending, Ending::NodesTimeout | Ending::PickTimeout) { matrix_pick(&mut ch, d).await; }
            if !matches!(ending, Ending::NodesTimeout | Ending::PickTimeout | Ending::LeafTimeout) {
                matrix_leaf(&mut ch, d, &c).await;
            }
            let winner = match ending {
                Ending::NodesTimeout | Ending::LeafTimeout => { matrix_timeout(&mut ch, d).await; V::RULING_CHALLENGER }
                Ending::PickTimeout | Ending::ClaimTimeout => { matrix_timeout(&mut ch, d).await; V::RULING_EXECUTOR }
                Ending::Proof | Ending::Moot => {
                    let mut body = vec![if executor_truthful { V::CLAIM_EDGE } else { V::CLAIM_STEP }, 0];
                    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
                    if executor_truthful { body.extend(ch.step_opening(&c, 0)); }
                    else {
                        body.push(1);
                        body.extend_from_slice(&4u32.to_le_bytes());
                        body.extend_from_slice(&42i32.to_le_bytes());
                    }
                    ch.claim(d, body).await.unwrap();
                    if executor_truthful { V::RULING_EXECUTOR } else { V::RULING_CHALLENGER }
                }
            };
            assert_eq!(ch.ruling(d).await, winner, "{cell}: ruling");
            // A terminal dispute never accepts another claim, timeout, reveal,
            // pick, or open.  Advance and settlement are its permitted closes.
            assert!(matrix_timeout_after_ruling(&mut ch, d).await.is_err(), "{cell}: second timeout");
            let accounts = ch.party(0xC1, d);
            assert!(send(&mut ch.ctx, ix(V::SUB_PICK, &[1], accounts), &[&kp(0xC1)]).await.is_err(), "{cell}: pick after ruling");
            if matches!(ending, Ending::Moot) {
                // A later dispute is moot only when this first claim refutes E.
                if winner == V::RULING_CHALLENGER {
                    let before_wait = matrix_wait(&mut ch).await;
                    let caller = kp(0xA1);
                    send(&mut ch.ctx, ix(V::SUB_MOOT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d_moot, false), AccountMeta::new(kp(0xC1).pubkey(), false)]), &[&caller]).await.unwrap();
                    assert_eq!(ch.ruling(d_moot).await, V::RULING_MOOT, "{cell}");
                    assert_eq!(matrix_wait(&mut ch).await.1, before_wait.1, "{cell}: challenger wait banked E time");
                }
            }
            ch.advance(d).await.unwrap();
            if matches!(ending, Ending::Moot) { ch.advance(d_moot).await.unwrap(); }
            let caller = kp(0xA1);
            if ch.run_status().await == V::RUN_REFUTED {
                let best = if winner == V::RULING_CHALLENGER { d } else { d_moot };
                let pay = ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(best, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
                send(&mut ch.ctx, pay.clone(), &[&caller]).await.unwrap();
                assert!(send(&mut ch.ctx, pay, &[&caller]).await.is_err(), "{cell}: second pot");
            }
            ch.close_dispute(d).await.unwrap();
            assert!(ch.close_dispute(d).await.is_err(), "{cell}: second dispute close");
            if matches!(ending, Ending::Moot) { ch.close_dispute(d_moot).await.unwrap(); }
            if ch.run_status().await == V::RUN_COMMITTED {
                ch.ctx.warp_to_slot(10_000).unwrap();
                let fin = ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(kp(0xE1).pubkey(), false)]);
                send(&mut ch.ctx, fin.clone(), &[&caller]).await.unwrap();
                assert!(send(&mut ch.ctx, fin, &[&caller]).await.is_err(), "{cell}: second executor bond");
            }
            if !matches!(ending, Ending::NodesTimeout) {
                let cache_rent = matrix_balance(&mut ch, cache).await;
                let e_pre_close = matrix_balance(&mut ch, kp(0xE1).pubkey()).await;
                assert!(ch.close_cache(cache, kp(0xC1).pubkey()).await.is_err(), "{cell}: cache rent to nonpayer");
                // The cache was created by E's NODES reveal and records E.
                // It cannot exist in the NODES-timeout row.
                ch.close_cache(cache, kp(0xE1).pubkey()).await.unwrap();
                assert_eq!(matrix_balance(&mut ch, kp(0xE1).pubkey()).await, e_pre_close + cache_rent, "{cell}: cache rent refund");
                assert!(ch.close_cache(cache, kp(0xE1).pubkey()).await.is_err(), "{cell}: second cache close");
            }
            ch.close_run(0xB1).await.unwrap();
            assert!(ch.close_run(0xB1).await.is_err(), "{cell}: second run close");
            ch.close_template().await.unwrap();
            assert!(ch.close_template().await.is_err(), "{cell}: second template close");
            assert_eq!(total_lamports(&mut ch.ctx, &keys).await, before, "{cell}: lamports");
            let receipt_rent = matrix_balance(&mut ch, run_key).await;
            let payer_share = if ch.run_status().await == V::RUN_REFUTED {
                EXECUTOR_BOND - EXECUTOR_BOND * SLASHER_BPS as u64 / 10_000
            } else { 0 };
            assert_eq!(matrix_balance(&mut ch, kp(0xA1).pubkey()).await,
                payer_before + run_rent + template_rent - receipt_rent + payer_share,
                "{cell}: recorded payer's rent and pot remainder");
            // Only a party that performed its owed moves is labelled honest
            // in a timeout cell.  C's bond is held until close, so compare
            // after every rent refund has landed.
            if !executor_truthful && !matches!(ending, Ending::PickTimeout | Ending::ClaimTimeout) {
                assert!(matrix_balance(&mut ch, kp(0xC1).pubkey()).await >= c_before, "{cell}: honest C net negative");
            }
            if executor_truthful && !matches!(ending, Ending::NodesTimeout | Ending::LeafTimeout) {
                assert!(matrix_balance(&mut ch, kp(0xE1).pubkey()).await >= e_before, "{cell}: honest E net negative");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn l6_finding_staging_after_proof_ruling() {
    let mut ch = Chain::new(30).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let d = ch.open(221, V::KIND_STEP_DESCEND).await;
    ch.step(d, &c, 1).await;
    let mut body = vec![V::CLAIM_EDGE, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
    body.extend(ch.step_opening(&c, 0));
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, V::RULING_EXECUTOR);
    let challenger = kp(0xC1);
    let mut data = vec![V::ROLE_CHALLENGER];
    data.extend_from_slice(&1u32.to_le_bytes());
    let buffer = ch.buffer(d, V::ROLE_CHALLENGER);
    let create = ix(V::SUB_STAGE_CREATE, &data, vec![
        AccountMeta::new(challenger.pubkey(), true), AccountMeta::new_readonly(ch.run, false),
        AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d, false),
        AccountMeta::new(buffer, false), AccountMeta::new_readonly(SYSTEM, false),
    ]);
    let create_result = send(&mut ch.ctx, create, &[&challenger]).await;
    let write = ix(V::SUB_STAGE_WRITE, &[0, 0, 0, 0, 0xAA], vec![
        AccountMeta::new_readonly(challenger.pubkey(), true), AccountMeta::new_readonly(ch.run, false),
        AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d, false),
        AccountMeta::new(buffer, false),
    ]);
    let write_result = send(&mut ch.ctx, write, &[&challenger]).await;
    let grow = ix(V::SUB_STAGE_GROW, &1u32.to_le_bytes(), vec![
        AccountMeta::new(challenger.pubkey(), true), AccountMeta::new_readonly(ch.run, false),
        AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d, false),
        AccountMeta::new(buffer, false), AccountMeta::new_readonly(SYSTEM, false),
    ]);
    let grow_result = send(&mut ch.ctx, grow, &[&challenger]).await;
    assert!(create_result.is_err() && write_result.is_err() && grow_result.is_err(),
        "post-proof staging succeeded: create={create_result:?}, write={write_result:?}, grow={grow_result:?}");
}

async fn matrix_timeout_after_ruling(ch: &mut Chain, d: Pubkey) -> Result<(), TransactionError> {
    let caller = kp(0xB1);
    send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)]), &[&caller]).await
}

fn template_body(g: &Golden, challenge_window: u64) -> Vec<u8> {
    let mut data = vec![4u8];
    for x in [2u64, 1, challenge_window, 750, EXECUTOR_BOND, CHALLENGER_BOND] {
        data.extend_from_slice(&x.to_le_bytes());
    }
    data.extend_from_slice(&OUT_BASE.to_le_bytes());
    data.extend_from_slice(&STEP_BASE.to_le_bytes());
    data.extend_from_slice(&g.spec_root);
    data.extend_from_slice(&SLASHER_BPS.to_le_bytes());
    data.extend_from_slice(&g.plan_id);
    data
}

// --- rent reclaim and template retirement (subs 18 to 22) ------------------------------

impl Chain {
    fn close_dispute_ix(&self, d: Pubkey, buffer_e: Pubkey, buffer_c: Pubkey) -> Instruction {
        ix(V::SUB_CLOSE_DISPUTE, &[], vec![AccountMeta::new_readonly(kp(0xA1).pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(buffer_e, false), AccountMeta::new(buffer_c, false)])
    }

    async fn close_dispute(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let i = self.close_dispute_ix(d, self.buffer(d, V::ROLE_EXECUTOR), self.buffer(d, V::ROLE_CHALLENGER));
        send(&mut self.ctx, i, &[&kp(0xA1)]).await
    }

    /// Sub 19 sent by `signer`, naming `payer` as the run's payer.
    async fn close_run_by(&mut self, signer: u8, payer: u8) -> Result<(), TransactionError> {
        let s = kp(signer);
        let template_meta = if self.legacy_template { AccountMeta::new_readonly(self.template, false) } else { AccountMeta::new(self.template, false) };
        let i = ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(s.pubkey(), true), AccountMeta::new(self.run, false), template_meta, AccountMeta::new(kp(payer).pubkey(), false)]);
        send(&mut self.ctx, i, &[&s]).await
    }

    async fn close_run(&mut self, signer: u8) -> Result<(), TransactionError> {
        self.close_run_by(signer, 0xA1).await
    }

    async fn close_template_by(&mut self, signer: u8) -> Result<(), TransactionError> {
        let s = kp(signer);
        let i = ix(V::SUB_CLOSE_TEMPLATE, &[], vec![AccountMeta::new(s.pubkey(), true), AccountMeta::new(self.template, false)]);
        send(&mut self.ctx, i, &[&s]).await
    }

    async fn close_template(&mut self) -> Result<(), TransactionError> {
        self.close_template_by(0xA1).await
    }

    async fn retire_template_by(&mut self, signer: u8) -> Result<(), TransactionError> {
        let s = kp(signer);
        let i = ix(V::SUB_RETIRE_TEMPLATE, &[], vec![AccountMeta::new(s.pubkey(), true), AccountMeta::new(self.template, false)]);
        send(&mut self.ctx, i, &[&s]).await
    }

    /// The receipt left at the run's address: magic, status, root.
    async fn receipt(&mut self) -> (Vec<u8>, u8, Vec<u8>) {
        let a = self.ctx.banks_client.get_account(self.run).await.unwrap().unwrap();
        assert_eq!(a.data.len(), V::RECEIPT_BYTES);
        (a.data[0..4].to_vec(), a.data[4], a.data[136..].to_vec())
    }

    async fn close_cache(&mut self, cache: Pubkey, executor: Pubkey) -> Result<(), TransactionError> {
        let caller = kp(0xA1);
        let i = ix(V::SUB_CLOSE_CACHE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new(cache, false), AccountMeta::new(executor, false)]);
        send(&mut self.ctx, i, &[&caller]).await
    }

    async fn advance(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let caller = kp(0xA1);
        let i = ix(V::SUB_ADVANCE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false)]);
        send(&mut self.ctx, i, &[&caller]).await
    }

    async fn gone(&mut self, k: Pubkey) -> bool {
        self.ctx.banks_client.get_account(k).await.unwrap().is_none()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_honest_run_closes_every_account_and_returns_all_rent() {
    let mut ch = Chain::new(30).await;
    let c = ch.honest();
    let d = ch.dispute(50);
    let cache = Pubkey::find_program_address(&[b"dcg21rc", ch.run.as_ref(), &[V::KIND_STEP_DESCEND], &1u32.to_le_bytes(), &0u64.to_le_bytes()], &PROGRAM).0;
    let (buf_e, buf_c) = (ch.buffer(d, V::ROLE_EXECUTOR), ch.buffer(d, V::ROLE_CHALLENGER));
    // Fees come from the test payer, so these balances must sum exactly.
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), kp(0xB1).pubkey(), ch.run, ch.template, d, cache, buf_e, buf_c];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    let template_before = ch.ctx.banks_client.get_balance(ch.template).await.unwrap();
    let payer_before = ch.ctx.banks_client.get_balance(kp(0xA1).pubkey()).await.unwrap();
    let run_rent = ch.ctx.banks_client.get_balance(ch.run).await.unwrap(); // paid by A1 at init
    assert!(ch.close_template().await.is_err(), "an initialized run needs its template");
    ch.commit(&c).await;
    ch.open(50, V::KIND_STEP_DESCEND).await;
    // E reveals the root's children and records them in a reveal cache.
    let e = kp(0xE1);
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    let i = ix(V::SUB_REVEAL_NODES, &nodes, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false), AccountMeta::new(cache, false), AccountMeta::new_readonly(SYSTEM, false)]);
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    assert_eq!(ch.ctx.banks_client.get_account(cache).await.unwrap().unwrap().data.len(), V::CACHE_BYTES_V2);
    let i = ix(V::SUB_PICK, &[1], ch.party(0xC1, d));
    send(&mut ch.ctx, i, &[&kp(0xC1)]).await.unwrap();
    // E's leaf from a staging buffer that C created; C's buffer is never created.
    let mut leaf = vec![1u8];
    leaf.extend_from_slice(c.leaves[1].as_ref().unwrap());
    ch.stage(d, V::ROLE_EXECUTOR, 2_000, &leaf, 300).await;
    let mut accounts = ch.party(0xE1, d);
    accounts.push(AccountMeta::new_readonly(buf_e, false));
    send(&mut ch.ctx, ix(V::SUB_REVEAL_LEAF, &[V::FROM_STAGING], accounts), &[&e]).await.unwrap();
    // Nothing closes while the dispute is open.
    assert!(ch.close_dispute(d).await.is_err(), "open dispute");
    let mut body = vec![V::CLAIM_EDGE, 0];
    body.extend(ch.spec_opening(STEP_BASE as usize + 1));
    body.extend(ch.step_opening(&c, 0));
    ch.claim(d, body).await.unwrap();
    assert_eq!(ch.ruling(d).await, V::RULING_EXECUTOR);
    assert!(ch.close_dispute(d).await.is_err(), "the ruled prefix has not passed it");
    ch.advance(d).await.unwrap();
    // The buffers must be the dispute's own derived addresses.
    let i = ch.close_dispute_ix(d, buf_c, buf_e);
    assert!(send(&mut ch.ctx, i, &[&kp(0xA1)]).await.is_err(), "buffers swapped");
    assert!(ch.close_cache(cache, e.pubkey()).await.is_err(), "the run is not settled");
    assert!(ch.close_run(0xA1).await.is_err(), "the run is not settled");
    let c_before = ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap();
    let rent_d = ch.ctx.banks_client.get_balance(d).await.unwrap();
    let rent_b = ch.ctx.banks_client.get_balance(buf_e).await.unwrap();
    ch.close_dispute(d).await.unwrap();
    assert!(ch.gone(d).await && ch.gone(buf_e).await && ch.gone(buf_c).await);
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap(), c_before + rent_d + rent_b, "C created the buffer");
    assert!(ch.close_dispute(d).await.is_err(), "closed once");
    assert!(ch.close_run(0xC1).await.is_err(), "every dispute is closed, but the run is not final yet");
    // Finalize, then the payer (only) closes the run.
    ch.ctx.warp_to_slot(100).unwrap();
    let caller = kp(0xA1);
    send(&mut ch.ctx, ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(e.pubkey(), false)]), &[&caller]).await.unwrap();
    assert!(ch.close_template().await.is_err(), "a finalized run still needs its template until it becomes a receipt");
    assert!(ch.close_cache(cache, kp(0xC1).pubkey()).await.is_err(), "rent goes to the recorded executor only");
    assert!(ch.close_run_by(0xC1, 0xC1).await.is_err(), "the freed rent goes to the run's payer only");
    let receipt_rent = ch.ctx.banks_client.get_rent().await.unwrap().minimum_balance(V::RECEIPT_BYTES);
    ch.close_run(0xC1).await.unwrap(); // anyone may shrink a settled run
    let (magic, status, root) = ch.receipt().await;
    assert_eq!((magic.as_slice(), status, root.as_slice()), (&b"D21P"[..], V::RUN_FINAL, &c.root_bytes[..]));
    assert_eq!(ch.ctx.banks_client.get_balance(ch.run).await.unwrap(), receipt_rent);
    assert!(ch.close_run(0xC1).await.is_err(), "a receipt is not a run");
    // The run id stays single-use: the same run cannot be initialized again.
    let mut init = vec![0u8; 32];
    init.extend_from_slice(e.pubkey().as_ref());
    init.extend_from_slice(&2u32.to_le_bytes());
    for r in &ch.g.refs {
        init.extend_from_slice(r);
    }
    let i = ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, i, &[&caller]).await.is_err(), "run id reused");
    assert!(ch.close_template_by(0xE1).await.is_err(), "the executor did not pay for the template");
    assert!(ch.close_template_by(0xC1).await.is_err(), "the challenger did not pay for the template");
    assert!(ch.close_template_by(0xB1).await.is_err(), "a bystander cannot close it");
    ch.close_template().await.unwrap();
    assert!(ch.gone(ch.template).await);
    // The cache records its executor, so it still closes after the run.
    let e_before = ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap();
    let rent_k = ch.ctx.banks_client.get_balance(cache).await.unwrap();
    ch.close_cache(cache, e.pubkey()).await.unwrap();
    assert!(ch.gone(cache).await);
    assert_eq!(ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap(), e_before + rent_k);
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "lamports are conserved");
    // The payer receives both the run's excess and the template's rent.
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xA1).pubkey()).await.unwrap(), payer_before + run_rent - receipt_rent + template_before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refuted_run_closes_after_the_pot_and_buffers_refund_their_creator() {
    let mut ch = Chain::new(1_000).await;
    let h = ch.honest();
    let mut l = h.leaves[1].clone().unwrap();
    let n = l.len();
    l[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
    let c = commitment(&ch.g, &ch.run_id, vec![h.leaves[0].clone(), Some(l)], h.outs.clone());
    let (d0, d1) = (ch.dispute(60), ch.dispute(61));
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), ch.run, ch.template, d0, d1, ch.buffer(d1, V::ROLE_EXECUTOR)];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    ch.commit(&c).await;
    ch.open(60, V::KIND_STEP_DESCEND).await; // sequence 0
    ch.open(61, V::KIND_STEP_DESCEND).await; // sequence 1
    // On d1, E creates its own staging buffer (it pays that rent).
    let e = kp(0xE1);
    let buf = ch.buffer(d1, V::ROLE_EXECUTOR);
    let mut data = vec![V::ROLE_EXECUTOR];
    data.extend_from_slice(&0u32.to_le_bytes());
    let i = ix(V::SUB_STAGE_CREATE, &data, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new_readonly(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d1, false), AccountMeta::new(buf, false), AccountMeta::new_readonly(SYSTEM, false)]);
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    ch.win_by_step(d1, &c).await;
    ch.win_by_step(d0, &c).await; // the lowest sequence wins the pot
    ch.advance(d0).await.unwrap();
    assert!(ch.close_dispute(d0).await.is_err(), "the best win waits for the pot");
    assert!(ch.close_dispute(d1).await.is_err(), "the ruled prefix has not passed d1");
    ch.advance(d1).await.unwrap();
    let e_before = ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap();
    let rent_b = ch.ctx.banks_client.get_balance(buf).await.unwrap();
    ch.close_dispute(d1).await.unwrap();
    assert_eq!(ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap(), e_before + rent_b, "E created that buffer");
    assert!(ch.close_run(0xA1).await.is_err(), "the pot is unpaid and d0 is open");
    let caller = kp(0xA1);
    let i = ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d0, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
    send(&mut ch.ctx, i, &[&caller]).await.unwrap();
    assert!(ch.close_run(0xA1).await.is_err(), "d0 is not closed");
    ch.close_dispute(d0).await.unwrap();
    assert!(ch.close_template().await.is_err(), "a refuted run still needs the template until it becomes a receipt");
    ch.close_run(0xE1).await.unwrap();
    assert_eq!(ch.receipt().await.1, V::RUN_REFUTED, "the receipt keeps the refutation");
    ch.close_template().await.unwrap();
    assert!(ch.gone(ch.template).await);
    for k in [d0, d1, buf] {
        assert!(ch.gone(k).await);
    }
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "lamports are conserved");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uncommitted_run_cancels_for_its_payer_after_the_commit_deadline() {
    // The commit deadline is the init slot plus the challenge window (30).
    let mut ch = Chain::new(30).await;
    let other = kp(0xC1);
    let theirs = Pubkey::find_program_address(&[b"dcg21run", &ch.run_id, other.pubkey().as_ref()], &PROGRAM).0;
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), other.pubkey(), ch.template, ch.run, theirs];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    assert!(ch.close_template().await.is_err(), "a live uncommitted run needs its template");
    assert!(ch.close_run(0xA1).await.is_err(), "not before the commit deadline");
    ch.ctx.warp_to_slot(100).unwrap();
    // A late commit is refused (review 10-03, F5).
    let c = ch.honest();
    let e = kp(0xE1);
    let commit = |run: Pubkey, template: Pubkey| ix(V::SUB_COMMIT, &c.root_bytes, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, commit(ch.run, ch.template), &[&e]).await.is_err(), "past the commit deadline");
    let payer = kp(0xA1).pubkey();
    let payer_before_cancel = ch.ctx.banks_client.get_balance(payer).await.unwrap();
    let run_rent = ch.ctx.banks_client.get_balance(ch.run).await.unwrap();
    ch.close_run(0xE1).await.unwrap(); // any signer may cancel after the deadline
    assert_eq!(
        ch.ctx.banks_client.get_balance(payer).await.unwrap(),
        payer_before_cancel + run_rent,
        "expired-run rent goes to its recorded payer"
    );
    assert!(ch.gone(ch.run).await, "a cancelled run leaves no receipt");
    // Someone else re-initializing the same run id gets a different address:
    // the payer is part of it, so the executor's commit cannot be redirected.
    let mut init = vec![0u8; 32];
    init.extend_from_slice(e.pubkey().as_ref());
    init.extend_from_slice(&2u32.to_le_bytes());
    for r in &ch.g.refs {
        init.extend_from_slice(r);
    }
    assert_ne!(theirs, ch.run);
    let i = ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(other.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
    assert!(send(&mut ch.ctx, i, &[&other]).await.is_err(), "the payer's address is not theirs");
    let i = ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(other.pubkey(), true), AccountMeta::new(theirs, false), AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
    send(&mut ch.ctx, i, &[&other]).await.unwrap();
    assert!(send(&mut ch.ctx, commit(ch.run, ch.template), &[&e]).await.is_err(), "the cancelled address is gone");
    assert!(ch.close_template().await.is_err(), "the other live run still needs the template");
    ch.ctx.warp_to_slot(200).unwrap();
    let close_theirs = ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(other.pubkey(), true), AccountMeta::new(theirs, false), AccountMeta::new(ch.template, false), AccountMeta::new(other.pubkey(), false)]);
    send(&mut ch.ctx, close_theirs, &[&other]).await.unwrap();
    ch.close_template().await.unwrap();
    assert!(ch.gone(ch.template).await);
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "cancellation and template close conserve lamports");
}

#[cfg(feature = "test-legacy-template-create")]
#[tokio::test(flavor = "multi_thread")]
async fn an_existing_template_keeps_its_read_only_account_lists_and_cannot_be_closed() {
    let mut ch = Chain::new_legacy_template(30).await;
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), ch.template, ch.run];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    assert!(ch.close_template().await.is_err(), "legacy templates have no recorded payer or active-run count");
    let committed = ch.honest();
    ch.commit(&committed).await; // commit still reads the old template as readonly
    ch.ctx.warp_to_slot(100).unwrap();
    let caller = kp(0xC1);
    let finalize = ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(kp(0xE1).pubkey(), false)]);
    send(&mut ch.ctx, finalize, &[&caller]).await.unwrap();
    ch.close_run(0xC1).await.unwrap(); // legacy CLOSE_RUN keeps a readonly template
    assert_eq!(ch.receipt().await.1, V::RUN_FINAL);
    assert!(ch.close_template().await.is_err(), "legacy templates remain usable but not closeable");
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "legacy run closure conserves lamports");
}

#[tokio::test(flavor = "multi_thread")]
async fn both_timeout_winners_can_close_their_run_and_template() {
    // C misses PICK, so E wins the dispute and the run can finalize.
    let mut executor_win = Chain::new(30).await;
    let committed = executor_win.honest();
    let d = executor_win.dispute(90);
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), executor_win.run, executor_win.template, d];
    let before = total_lamports(&mut executor_win.ctx, &tracked).await;
    executor_win.commit(&committed).await;
    executor_win.open(90, V::KIND_STEP_DESCEND).await;
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&committed.step[0][0]);
    nodes.extend_from_slice(&committed.step[0][1]);
    let e = kp(0xE1);
    let reveal_accounts = executor_win.party(0xE1, d);
    send(&mut executor_win.ctx, ix(V::SUB_REVEAL_NODES, &nodes, reveal_accounts), &[&e]).await.unwrap();
    executor_win.ctx.warp_to_slot(5_000).unwrap();
    let caller = kp(0xA1);
    let timeout = ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(executor_win.run, false), AccountMeta::new_readonly(executor_win.template, false), AccountMeta::new(d, false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)]);
    send(&mut executor_win.ctx, timeout, &[&caller]).await.unwrap();
    assert_eq!(executor_win.ruling(d).await, V::RULING_EXECUTOR);
    executor_win.advance(d).await.unwrap();
    let close_d = executor_win.close_dispute_ix(d, executor_win.buffer(d, V::ROLE_EXECUTOR), executor_win.buffer(d, V::ROLE_CHALLENGER));
    send(&mut executor_win.ctx, close_d, &[&caller]).await.unwrap();
    let finalize = ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(executor_win.run, false), AccountMeta::new_readonly(executor_win.template, false), AccountMeta::new(e.pubkey(), false)]);
    send(&mut executor_win.ctx, finalize, &[&caller]).await.unwrap();
    executor_win.close_run(0xC1).await.unwrap();
    executor_win.close_template().await.unwrap();
    assert_eq!(total_lamports(&mut executor_win.ctx, &tracked).await, before, "executor timeout win conserves lamports");

    // E misses NODES, so C wins; after the ruled prefix passes, the pot and
    // the refuted receipt can close, followed by the now-unused template.
    let mut challenger_win = Chain::new(30).await;
    let committed = challenger_win.honest();
    let d = challenger_win.dispute(91);
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), challenger_win.run, challenger_win.template, d];
    let before = total_lamports(&mut challenger_win.ctx, &tracked).await;
    challenger_win.commit(&committed).await;
    challenger_win.open(91, V::KIND_STEP_DESCEND).await;
    challenger_win.ctx.warp_to_slot(5_000).unwrap();
    let c = kp(0xC1);
    let timeout = ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(challenger_win.run, false), AccountMeta::new_readonly(challenger_win.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(c.pubkey(), false)]);
    send(&mut challenger_win.ctx, timeout, &[&caller]).await.unwrap();
    assert_eq!(challenger_win.ruling(d).await, V::RULING_CHALLENGER);
    challenger_win.advance(d).await.unwrap();
    let pay = ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(challenger_win.run, false), AccountMeta::new_readonly(challenger_win.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(c.pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
    send(&mut challenger_win.ctx, pay, &[&caller]).await.unwrap();
    challenger_win.close_dispute(d).await.unwrap();
    assert!(challenger_win.close_template().await.is_err(), "the refuted run still needs the template until receipt conversion");
    challenger_win.close_run(0xE1).await.unwrap();
    assert_eq!(challenger_win.receipt().await.1, V::RUN_REFUTED);
    challenger_win.close_template().await.unwrap();
    assert_eq!(total_lamports(&mut challenger_win.ctx, &tracked).await, before, "challenger timeout win conserves lamports");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_timeout_after_the_best_win_is_moot_and_keeps_the_challengers_bond() {
    let mut ch = Chain::new(1_000).await;
    let d0 = ch.dispute(70);
    let d1 = ch.dispute(71);
    let tracked = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), ch.run, ch.template, d0, d1];
    let before = total_lamports(&mut ch.ctx, &tracked).await;
    let h = ch.honest();
    let mut l = h.leaves[1].clone().unwrap();
    let n = l.len();
    l[n - 96..n - 64].copy_from_slice(&D::value_digest(&Soft, &43i32.to_le_bytes()));
    let c = commitment(&ch.g, &ch.run_id, vec![h.leaves[0].clone(), Some(l)], h.outs.clone());
    assert!(ch.close_template().await.is_err(), "a committed run needs its template");
    ch.commit(&c).await;
    assert_eq!(ch.open(70, V::KIND_STEP_DESCEND).await, d0); // sequence 0
    assert_eq!(ch.open(71, V::KIND_STEP_DESCEND).await, d1); // sequence 1
    // E answers d1's first reveal, so d1 waits on its challenger's pick.
    let e = kp(0xE1);
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    let i = ix(V::SUB_REVEAL_NODES, &nodes, ch.party(0xE1, d1));
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    ch.win_by_step(d0, &c).await;
    assert_eq!(ch.run_status().await, V::RUN_REFUTED);
    // d1's challenger stops playing (d1 is after the best win). Its timeout
    // would rule for E, but the dispute is moot instead (review 10-03, F1).
    ch.ctx.warp_to_slot(5_000).unwrap();
    let (e_before, c_before) = (ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap(), ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap());
    let caller = kp(0xA1);
    let accounts = vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d1, false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)];
    send(&mut ch.ctx, ix(V::SUB_TIMEOUT, &[], accounts), &[&caller]).await.unwrap();
    assert_eq!(ch.ruling(d1).await, V::RULING_MOOT);
    assert_eq!(ch.ctx.banks_client.get_balance(e.pubkey()).await.unwrap(), e_before, "E gains nothing");
    assert_eq!(ch.ctx.banks_client.get_balance(kp(0xC1).pubkey()).await.unwrap(), c_before + CHALLENGER_BOND, "C's bond returns");
    ch.advance(d0).await.unwrap();
    ch.advance(d1).await.unwrap();
    ch.close_dispute(d1).await.unwrap(); // the moot dispute does not wait for the pot
    assert!(ch.close_template().await.is_err(), "ruled disputes do not release the template before run closure");
    let pay = ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(d0, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
    send(&mut ch.ctx, pay, &[&caller]).await.unwrap();
    ch.close_dispute(d0).await.unwrap();
    ch.close_run(0xC1).await.unwrap();
    ch.close_template().await.unwrap();
    assert_eq!(ch.receipt().await.1, V::RUN_REFUTED);
    assert!(ch.gone(ch.template).await);
    assert_eq!(total_lamports(&mut ch.ctx, &tracked).await, before, "timeout, moot, pot, and closes conserve lamports");
}

#[tokio::test(flavor = "multi_thread")]
async fn executor_wait_extension_is_additive_and_challenger_puppets_do_not_bank_it() {
    let mut ch = Chain::new(1_000).await;
    let c = ch.honest();
    ch.commit(&c).await;
    let deadline = |a: &solana_account::Account| u64::from_le_bytes(a.data[24..32].try_into().unwrap());
    let slot = ch.ctx.banks_client.get_root_slot().await.unwrap();
    let d0 = ch.open(80, V::KIND_STEP_DESCEND).await;
    let first = deadline(&ch.ctx.banks_client.get_account(d0).await.unwrap().unwrap());
    // E answers d0, placing its puppet on the challenger side.
    let e = kp(0xE1);
    let mut nodes = Vec::new();
    nodes.extend_from_slice(&c.step[0][0]);
    nodes.extend_from_slice(&c.step[0][1]);
    let i = ix(V::SUB_REVEAL_NODES, &nodes, ch.party(0xE1, d0));
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    let pick = deadline(&ch.ctx.banks_client.get_account(d0).await.unwrap().unwrap());
    let d1 = ch.open(81, V::KIND_STEP_DESCEND).await;
    let second = deadline(&ch.ctx.banks_client.get_account(d1).await.unwrap().unwrap());
    let d2 = ch.open(82, V::KIND_STEP_DESCEND).await;
    let third = deadline(&ch.ctx.banks_client.get_account(d2).await.unwrap().unwrap());
    // Each E wait gets its own fixed, capped deadline; d0's C deadline is unchanged.
    assert!(first <= slot + 750 + 5, "{first} vs {slot}");
    assert!(second <= slot + 750 + 10 && third <= slot + 1_500 + 15, "{second} {third} vs {slot}");
    assert!(pick <= slot + 750 + 10, "{pick} vs {slot}");
    let run = ch.ctx.banks_client.get_account(ch.run).await.unwrap().unwrap();
    let tail = &run.data[run.data.len() - 4..];
    assert_eq!(u32::from_le_bytes(tail.try_into().unwrap()), 2);
    ch.ctx.warp_to_slot(slot + 1_200).unwrap();
    let caller = kp(0xA1);
    let (run_key, template_key) = (ch.run, ch.template);
    let timeout = |d| ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run_key, false), AccountMeta::new_readonly(template_key, false), AccountMeta::new(d, false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)]);
    send(&mut ch.ctx, timeout(d0), &[&caller]).await.unwrap();
    assert_eq!(ch.ruling(d0).await, V::RULING_EXECUTOR);
    send(&mut ch.ctx, timeout(d1), &[&caller]).await.unwrap();
    assert_eq!(ch.ruling(d1).await, V::RULING_CHALLENGER);
    assert!(send(&mut ch.ctx, timeout(d2), &[&caller]).await.is_err(), "d2's fixed second-window deadline protects it");
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_executor_phase_cannot_be_revived_by_later_open() {
    for executor_first in [true, false] {
        let mut ch = Chain::new(5_000).await;
        let c = ch.honest();
        ch.commit(&c).await;
        let start = ch.ctx.banks_client.get_root_slot().await.unwrap();
        let expired = ch.open(90, V::KIND_STEP_DESCEND).await;
        ch.ctx.warp_to_slot(start + 800).unwrap();
        if executor_first {
            let puppet = ch.open(91, V::KIND_STEP_DESCEND).await;
            matrix_nodes(&mut ch, puppet, &c).await;
            matrix_pick(&mut ch, puppet).await; // later PICK also cannot revive expired
        } else {
            ch.open(91, V::KIND_STEP_DESCEND).await; // later OPEN cannot revive expired
        }
        let caller = kp(0xA1);
        let timeout = ix(V::SUB_TIMEOUT, &[], vec![
            AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false),
            AccountMeta::new_readonly(ch.template, false), AccountMeta::new(expired, false),
            AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false),
        ]);
        send(&mut ch.ctx, timeout, &[&caller]).await.unwrap();
        assert_eq!(ch.ruling(expired).await, V::RULING_CHALLENGER);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ended_puppets_do_not_extend_a_fresh_dispute() {
    for executor_first in [true, false] {
        let mut ch = Chain::new(5_000).await;
        let c = ch.honest();
        ch.commit(&c).await;
        let a = ch.open(92, V::KIND_STEP_DESCEND).await;
        let b = ch.open(93, V::KIND_STEP_DESCEND).await;
        for d in if executor_first { [a, b] } else { [b, a] } {
            matrix_nodes(&mut ch, d, &c).await;
        }
        assert_eq!(matrix_wait(&mut ch).await.0, 0);
        let fresh = ch.open(94, V::KIND_STEP_DESCEND).await;
        let opened = ch.ctx.banks_client.get_root_slot().await.unwrap();
        let account = ch.ctx.banks_client.get_account(fresh).await.unwrap().unwrap();
        let deadline = u64::from_le_bytes(account.data[24..32].try_into().unwrap());
        assert!(deadline <= opened + 750, "fresh dispute inherited banked time");
        ch.ctx.warp_to_slot(opened + 751).unwrap();
        let caller = kp(0xA1);
        let timeout = ix(V::SUB_TIMEOUT, &[], vec![
            AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(ch.run, false),
            AccountMeta::new_readonly(ch.template, false), AccountMeta::new(fresh, false),
            AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false),
        ]);
        send(&mut ch.ctx, timeout, &[&caller]).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn retiring_a_template_blocks_new_runs_and_anyone_can_cancel_an_expired_run() {
    let mut ch = Chain::new(30).await;
    let bystander = kp(0xB1);
    let executor = kp(0xE1);
    let mut init = vec![7u8; 32];
    init.extend_from_slice(executor.pubkey().as_ref());
    init.extend_from_slice(&(ch.g.refs.len() as u32).to_le_bytes());
    let mut refs = Vec::new();
    for r in &ch.g.refs {
        init.extend_from_slice(r);
        refs.extend_from_slice(r);
    }
    let template_id = ch.ctx.banks_client.get_account(ch.template).await.unwrap().unwrap().data[96..128].to_vec();
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &[7u8; 32],
                          &(ch.g.refs.len() as u32).to_le_bytes(), &refs, executor.pubkey().as_ref()]);
    let bystander_run = Pubkey::find_program_address(
        &[b"dcg21run", &run_id, bystander.pubkey().as_ref()], &PROGRAM).0;
    let bystander_before = ch.ctx.banks_client.get_balance(bystander.pubkey()).await.unwrap();
    send(&mut ch.ctx, ix(V::SUB_INIT_RUN, &init, vec![
        AccountMeta::new(bystander.pubkey(), true), AccountMeta::new(bystander_run, false),
        AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&bystander]).await.unwrap();
    assert!(ch.retire_template_by(0xB1).await.is_err(), "only the recorded template payer may retire it");
    ch.retire_template_by(0xA1).await.unwrap();
    assert!(ch.retire_template_by(0xA1).await.is_err(), "retirement is one-way");

    let next_payer = kp(0xC1);
    let next_nonce = [8u8; 32];
    let next_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &next_nonce,
                           &(ch.g.refs.len() as u32).to_le_bytes(), &refs, executor.pubkey().as_ref()]);
    let next_run = Pubkey::find_program_address(
        &[b"dcg21run", &next_id, next_payer.pubkey().as_ref()], &PROGRAM).0;
    let mut next_init = next_nonce.to_vec();
    next_init.extend_from_slice(executor.pubkey().as_ref());
    next_init.extend_from_slice(&(ch.g.refs.len() as u32).to_le_bytes());
    for r in &ch.g.refs { next_init.extend_from_slice(r); }
    assert!(send(&mut ch.ctx, ix(V::SUB_INIT_RUN, &next_init, vec![
        AccountMeta::new(next_payer.pubkey(), true), AccountMeta::new(next_run, false),
        AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&next_payer]).await.is_err(), "a retired template refuses new runs");

    let close_bystander = |caller: &Keypair| ix(V::SUB_CLOSE_RUN, &[], vec![
        AccountMeta::new(caller.pubkey(), true), AccountMeta::new(bystander_run, false),
        AccountMeta::new(ch.template, false), AccountMeta::new(bystander.pubkey(), false),
    ]);
    let caller = kp(0xC1);
    assert!(send(&mut ch.ctx, close_bystander(&caller), &[&caller]).await.is_err(),
            "no one may cancel before the deadline");
    ch.ctx.warp_to_slot(10_000).unwrap();
    // A caller that did not fund the run cancels it. The run's rent still
    // returns to its recorded payer; the caller only unblocks template close.
    send(&mut ch.ctx, close_bystander(&caller), &[&caller]).await.unwrap();
    assert_eq!(ch.ctx.banks_client.get_balance(bystander.pubkey()).await.unwrap(), bystander_before,
               "the run payer receives its rent");
    assert!(ch.close_run_by(0xC1, 0xA1).await.is_ok(), "any signer may cancel the expired original run");
    let template_data = ch.ctx.banks_client.get_account(ch.template).await.unwrap().unwrap().data;
    assert_eq!(u32::from_le_bytes(template_data[template_data.len()-4..].try_into().unwrap()), 0);
    ch.close_template().await.unwrap();
    assert!(ch.gone(ch.template).await, "a retired template closes at active_runs == 0");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefunded_template_is_adopted_and_its_lamports_go_to_the_recorded_payer() {
    let mut ch = Chain::new(30).await;
    ch.ctx.warp_to_slot(10_000).unwrap();
    ch.close_run(0xA1).await.unwrap();
    ch.close_template().await.unwrap();

    let prefunder = kp(0xB1);
    let gift = 20_000_000u64;
    let before_prefunder = ch.ctx.banks_client.get_balance(prefunder.pubkey()).await.unwrap();
    let before_admitter = ch.ctx.banks_client.get_balance(kp(0xA1).pubkey()).await.unwrap();
    let transfer = solana_program::system_instruction::transfer(&prefunder.pubkey(), &ch.template, gift);
    send(&mut ch.ctx, transfer, &[&prefunder]).await.unwrap();
    let data = template_body(&ch.g, 30);
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
    assert_eq!(Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, kp(0xA1).pubkey().as_ref()], &PROGRAM).0, ch.template);
    let admitter = kp(0xA1);
    send(&mut ch.ctx, ix(V::SUB_CREATE_TEMPLATE, &data, vec![
        AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(ch.template, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&admitter]).await.unwrap();
    ch.close_template().await.unwrap();
    assert_eq!(ch.ctx.banks_client.get_balance(admitter.pubkey()).await.unwrap(), before_admitter + gift,
               "pre-funded lamports are a gift to the recorded payer at close");
    assert_eq!(ch.ctx.banks_client.get_balance(prefunder.pubkey()).await.unwrap(), before_prefunder - gift);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_front_runner_cannot_squat_on_another_payers_template() {
    let mut ch = Chain::new(30).await;
    ch.ctx.warp_to_slot(10_000).unwrap();
    ch.close_run(0xA1).await.unwrap();
    ch.close_template().await.unwrap();
    let data = template_body(&ch.g, 30);
    let front_runner = kp(0xB1);
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
    let squat = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, front_runner.pubkey().as_ref()], &PROGRAM).0;
    assert_ne!(squat, ch.template);
    send(&mut ch.ctx, ix(V::SUB_CREATE_TEMPLATE, &data, vec![
        AccountMeta::new(front_runner.pubkey(), true), AccountMeta::new(squat, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&front_runner]).await.unwrap();
    send(&mut ch.ctx, ix(V::SUB_RETIRE_TEMPLATE, &[], vec![
        AccountMeta::new(front_runner.pubkey(), true), AccountMeta::new(squat, false),
    ]), &[&front_runner]).await.unwrap();
    assert!(ch.gone(ch.template).await);
    let admitter = kp(0xA1);
    send(&mut ch.ctx, ix(V::SUB_CREATE_TEMPLATE, &data, vec![
        AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(ch.template, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&admitter]).await.unwrap();
    assert!(ch.ctx.banks_client.get_account(ch.template).await.unwrap().is_some());
    assert!(ch.ctx.banks_client.get_account(squat).await.unwrap().is_some());
    let nonce = [9u8; 32];
    let executor = kp(0xE1).pubkey();
    let mut refs = ch.g.refs[0].clone();
    refs.extend_from_slice(&ch.g.refs[1]);
    let mut init = nonce.to_vec();
    init.extend_from_slice(executor.as_ref());
    init.extend_from_slice(&2u32.to_le_bytes());
    init.extend_from_slice(&refs);
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &nonce, &2u32.to_le_bytes(), &refs, executor.as_ref()]);
    let honest_run = Pubkey::find_program_address(&[b"dcg21run", &run_id, admitter.pubkey().as_ref()], &PROGRAM).0;
    send(&mut ch.ctx, ix(V::SUB_INIT_RUN, &init, vec![
        AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(honest_run, false),
        AccountMeta::new(ch.template, false), AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&admitter]).await.unwrap();
    assert!(ch.ctx.banks_client.get_account(honest_run).await.unwrap().is_some());
    assert!(ch.close_template_by(0xB1).await.is_err());
    assert!(ch.close_template().await.is_err(), "an active honest run prevents close");
    assert!(ch.ctx.banks_client.get_account(squat).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_tracked_template_at_the_old_address_remains_readable() {
    let mut ch = Chain::new(30).await;
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &template_body(&ch.g, 30)]);
    let old = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0;
    assert_ne!(old, ch.template);
    let account = ch.ctx.banks_client.get_account(ch.template).await.unwrap().unwrap();
    ch.ctx.set_account(&old, &account.into());
    let admitter = kp(0xA1);
    let executor = kp(0xE1).pubkey();
    let nonce = [7u8; 32];
    let mut refs = ch.g.refs[0].clone();
    refs.extend_from_slice(&ch.g.refs[1]);
    let mut init = nonce.to_vec();
    init.extend_from_slice(executor.as_ref());
    init.extend_from_slice(&2u32.to_le_bytes());
    init.extend_from_slice(&refs);
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &nonce, &2u32.to_le_bytes(), &refs, executor.as_ref()]);
    let run = Pubkey::find_program_address(&[b"dcg21run", &run_id, admitter.pubkey().as_ref()], &PROGRAM).0;
    send(&mut ch.ctx, ix(V::SUB_INIT_RUN, &init, vec![
        AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false),
        AccountMeta::new(old, false), AccountMeta::new_readonly(SYSTEM, false),
    ]), &[&admitter]).await.unwrap();
    assert!(ch.ctx.banks_client.get_account(run).await.unwrap().is_some());
}

#[cfg(all(feature = "test-kernel", not(feature = "test-legacy-template-create")))]
#[tokio::test(flavor = "multi_thread")]
async fn the_shared_test_kernel_image_does_not_dispatch_legacy_create_subtype_250() {
    let mut ch = Chain::new(30).await;
    ch.ctx.warp_to_slot(10_000).unwrap();
    ch.close_run(0xA1).await.unwrap();
    ch.close_template().await.unwrap();
    assert!(ch.gone(ch.template).await);

    let attacker = kp(0xB1);
    let data = template_body(&ch.g, 30);
    let i = ix(250, &data, vec![
        AccountMeta::new(attacker.pubkey(), true), AccountMeta::new(ch.template, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    assert!(send(&mut ch.ctx, i, &[&attacker]).await.is_err());
    assert!(ch.gone(ch.template).await, "the shared image cannot recreate it through subtype 250");
}
