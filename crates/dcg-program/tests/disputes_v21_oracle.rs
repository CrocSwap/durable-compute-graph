//! The disputes v2.1 program agrees with the Python oracle: every scenario in
//! tests/golden/dcg/disputes_v21/scenarios.json (from
//! scripts/disputes_v21_scenarios.py) is replayed on the program with the
//! Python honest challenger's moves, and must reach the same ruling.
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

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD5; 32]);
const SYSTEM: Pubkey = system_program::ID;

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

fn path(levels: &[Vec<D::Hash>], mut position: usize) -> Vec<u8> {
    let mut v = vec![(levels.len() - 1) as u8];
    for row in &levels[..levels.len() - 1] {
        v.extend_from_slice(&row[position ^ 1]);
        position >>= 1;
    }
    v
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), TransactionError> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let mut ixs = vec![solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
    ixs.push(i);
    let tx = Transaction::new(&all, solana_message::Message::new(&ixs, Some(&ctx.payer.pubkey())), blockhash);
    ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| e.unwrap())?.result
}

async fn replay(s: &serde_json::Value) -> u8 {
    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    for b in [0xA1u8, 0xE1, 0xC1] {
        test.add_account(kp(b).pubkey(), Account { lamports: 10_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
    }
    let mut ctx = test.start_with_context().await;
    let (admitter, e, c) = (kp(0xA1), kp(0xE1), kp(0xC1));
    let tdata = hex(s["template_data"].as_str().unwrap());
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &tdata]);
    let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0;
    send(&mut ctx, ix(V::SUB_CREATE_TEMPLATE, &tdata, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();

    let refs: Vec<Vec<u8>> = s["refs"].as_array().unwrap().iter().map(|r| hex(r.as_str().unwrap())).collect();
    let mut init = vec![0u8; 32];
    init.extend_from_slice(e.pubkey().as_ref());
    init.extend_from_slice(&(refs.len() as u32).to_le_bytes());
    for r in &refs {
        init.extend_from_slice(r);
    }
    let mut flat = Vec::new();
    for r in &refs {
        flat.extend_from_slice(r);
    }
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &[0u8; 32], &(refs.len() as u32).to_le_bytes(), &flat, e.pubkey().as_ref()]);
    let run = Pubkey::find_program_address(&[b"dcg21run", &run_id], &PROGRAM).0;
    send(&mut ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();

    // E's commitment.
    let leaves: Vec<Option<Vec<u8>>> = s["leaves"].as_array().unwrap().iter().map(|x| x.as_str().map(hex)).collect();
    let outs: Vec<Option<Vec<u8>>> = s["out_entries"].as_array().unwrap().iter().map(|x| x.as_str().map(hex)).collect();
    let step = levels(D::Tree::Step, &leaves.iter().map(|l| D::leaf_hash(&Soft, l.as_deref())).collect::<Vec<_>>());
    let out = levels(D::Tree::Out, &outs.iter().enumerate().map(|(j, o)| D::out_leaf(&Soft, j as u64, o.as_deref())).collect::<Vec<_>>());
    let records: Vec<(u8, Vec<u8>)> = s["spec_records"].as_array().unwrap().iter().map(|r| (r[0].as_u64().unwrap() as u8, hex(r[1].as_str().unwrap()))).collect();
    let spec = levels(D::Tree::Spec, &records.iter().map(|(t, r)| D::spec_leaf(&Soft, *t, r)).collect::<Vec<_>>());
    let mut root = vec![7u8; 32];
    root.extend_from_slice(&run_id);
    root.extend_from_slice(&spec.last().unwrap()[0]);
    root.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    root.extend_from_slice(&step.last().unwrap()[0]);
    root.extend_from_slice(&(outs.len() as u64).to_le_bytes());
    root.extend_from_slice(&out.last().unwrap()[0]);
    send(&mut ctx, ix(V::SUB_COMMIT, &root, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&e]).await.unwrap();

    // Open, descend with the oracle's picks, reveal, claim.
    let step_kind = s["kind"].as_str().unwrap() == "STEP_DESCEND";
    let kind = if step_kind { V::KIND_STEP_DESCEND } else { V::KIND_OUT_DESCEND };
    let dispute = Pubkey::find_program_address(&[b"dcg21dsp", run.as_ref(), c.pubkey().as_ref(), &[1u8; 32]], &PROGRAM).0;
    let mut open = vec![1u8; 32];
    open.push(kind);
    send(&mut ctx, ix(V::SUB_OPEN, &open, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c]).await.unwrap();
    let party = |who: &Keypair| vec![AccountMeta::new_readonly(who.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false)];
    let tree = if step_kind { &step } else { &out };
    let limit = if step_kind { leaves.len() } else { outs.len() };
    let depth = s["depth"].as_u64().unwrap() as usize;
    let (mut level, mut position) = (tree.len() - 1, 0usize);
    for pick in s["picks"].as_array().unwrap() {
        let d = depth.min(level);
        let base = level - d;
        let mut hashes = Vec::new();
        for i in 0..1usize << d {
            let p = (position << d) + i;
            if (p << base) < limit {
                hashes.extend_from_slice(&tree[base][p]);
            }
        }
        send(&mut ctx, ix(V::SUB_REVEAL_NODES, &hashes, party(&e)), &[&e]).await.expect("E's reveal folds");
        let index = pick.as_u64().unwrap() as usize;
        send(&mut ctx, ix(V::SUB_PICK, &[index as u8], party(&c)), &[&c]).await.expect("C's pick");
        level = base;
        position = (position << d) + index;
    }
    assert_eq!(level, 0, "descent reaches the leaf level");
    assert_eq!(position as u64, s["position"].as_u64().unwrap());
    let revealed = if step_kind { &leaves[position] } else { &outs[position] };
    let mut leaf = vec![revealed.is_some() as u8];
    leaf.extend_from_slice(revealed.as_deref().unwrap_or(&[]));
    send(&mut ctx, ix(V::SUB_REVEAL_LEAF, &leaf, party(&e)), &[&e]).await.expect("E's leaf");

    let claim = match s["claim"].as_str().unwrap() {
        "SHAPE" => V::CLAIM_SHAPE,
        "EDGE" => V::CLAIM_EDGE,
        "STEP" => V::CLAIM_STEP,
        _ => V::CLAIM_OUT,
    };
    let mut body = vec![claim, s["index"].as_u64().unwrap() as u8];
    let spec_leaf = if step_kind { s["step_base"].as_u64().unwrap() as usize + position } else { s["out_base"].as_u64().unwrap() as usize + position };
    let (t, r) = &records[spec_leaf];
    body.push(*t);
    body.extend_from_slice(&(r.len() as u16).to_le_bytes());
    body.extend_from_slice(r);
    body.extend(path(&spec, spec_leaf));
    if let Some(p) = s["producer"].as_u64() {
        let p = p as usize;
        let l = &leaves[p];
        body.push(l.is_some() as u8);
        let b = l.clone().unwrap_or_default();
        body.extend_from_slice(&(b.len() as u16).to_le_bytes());
        body.extend_from_slice(&b);
        body.extend(path(&step, p));
    }
    if claim == V::CLAIM_STEP {
        let w = s["witness"].as_array().unwrap();
        body.push(w.len() as u8);
        for v in w {
            let v = hex(v.as_str().unwrap());
            body.extend_from_slice(&(v.len() as u16).to_le_bytes());
            body.extend_from_slice(&v);
        }
    }
    let accounts = vec![AccountMeta::new_readonly(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(c.pubkey(), false)];
    send(&mut ctx, ix(V::SUB_CLAIM, &body, accounts), &[&c]).await.expect("the claim is accepted");
    ctx.banks_client.get_account(dispute).await.unwrap().unwrap().data[6]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_program_rules_as_the_python_oracle_on_every_scenario() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/scenarios.json");
    let scenarios: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(scenarios.len() >= 80);
    let mut disagreements = vec![];
    for s in &scenarios {
        let want = if s["ruling"].as_str().unwrap() == "C" { V::RULING_CHALLENGER } else { V::RULING_EXECUTOR };
        let got = replay(s).await;
        if got != want {
            disagreements.push(format!("{}: program {got}, oracle {want}", s["name"].as_str().unwrap()));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}
