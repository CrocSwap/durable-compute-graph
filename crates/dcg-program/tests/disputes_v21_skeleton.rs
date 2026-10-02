//! Optimistic disputes v2.1 program skeleton (tag 227), native ProgramTest on
//! the Hello Graph goldens: honest finalize, and lies refuted by STEP, SHAPE
//! (malformed rule), OUT and timeout; an EDGE against an honest leaf loses.
#![cfg(feature = "graph-v21")]

use dcg_disputes::{self as D, Sha256 as _};
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
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

impl Chain {
    async fn new(challenge_window: u64) -> Self {
        let mut test = ProgramTest::default();
        test.prefer_bpf(false);
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
        for b in [0xA1u8, 0xE1, 0xC1] {
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
        let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0;
        let admitter = kp(0xA1);
        send(&mut ctx, ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
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
        let run = Pubkey::find_program_address(&[b"dcg21run", &run_id], &PROGRAM).0;
        send(&mut ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
        Chain { ctx, template, run, run_id, g, spec_levels }
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
        vec![AccountMeta::new_readonly(kp(who).pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false)]
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
    let mut accounts = vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new_readonly(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(a, false)];
    accounts.push(AccountMeta::new(cache, false));
    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
    let i = ix(V::SUB_REVEAL_NODES, &nodes, accounts);
    send(&mut ch.ctx, i, &[&e]).await.unwrap();
    // Dispute B is answered from the cache by its own challenger.
    let cl = kp(0xC1);
    let answer = |d: Pubkey, run: Pubkey, template: Pubkey, k: Pubkey| ix(V::SUB_CACHE_ANSWER, &[], vec![AccountMeta::new_readonly(cl.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(k, false)]);
    send(&mut ch.ctx, answer(b, ch.run, ch.template, cache), &[&cl]).await.unwrap();
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
    // Depth 5 (review B3) and a phase window under the 750-slot floor.
    for (depth, phase) in [(5u8, 750u64), (4, 749)] {
        let mut data = vec![depth];
        for x in [2u64, 1, 1_000, phase, EXECUTOR_BOND, CHALLENGER_BOND] {
            data.extend_from_slice(&x.to_le_bytes());
        }
        data.extend_from_slice(&OUT_BASE.to_le_bytes());
        data.extend_from_slice(&STEP_BASE.to_le_bytes());
        data.extend_from_slice(&ch.g.spec_root);
        data.extend_from_slice(&SLASHER_BPS.to_le_bytes());
        data.extend_from_slice(&ch.g.plan_id);
        let id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
        let t = Pubkey::find_program_address(&[b"dcg21tmpl", &id], &PROGRAM).0;
        let i = ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(t, false), AccountMeta::new_readonly(SYSTEM, false)]);
        assert!(send(&mut ch.ctx, i, &[&admitter]).await.is_err(), "depth {depth} phase {phase}");
    }
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
        let i = ix(V::SUB_INIT_RUN, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new_readonly(SYSTEM, false)]);
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
