//! Chunked kernels on the disputes v2.1 program agree with the Python
//! oracle: every scenario in tests/golden/dcg/disputes_v21/chunked_scenarios.json
//! (from scripts/disputes_v21_chunked_scenarios.py) is sent as recorded, the
//! instruction bodies being Python's encoding, and must reach the same
//! ruling. Claims and leaves too large for one transaction go through the
//! dispute's staging buffers. All scenarios share one test context; each has
//! its own run nonce.
#![cfg(feature = "graph-v21")]

use dcg_program::disputes_v21 as V;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_hash::Hash;
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
/// Bodies above this go through staging (a transaction is 1,232 bytes).
const DIRECT_LIMIT: usize = 700;

fn kp(b: u8) -> Keypair {
    Keypair::new_from_array([b; 32])
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

struct Sender {
    blockhash: Hash,
    uses: u32,
    /// A per-transaction compute-unit price keeps repeated bodies distinct.
    serial: u64,
}

impl Sender {
    async fn send(&mut self, ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), TransactionError> {
        if self.uses >= 150 {
            self.blockhash = ctx.get_new_latest_blockhash().await.unwrap();
            self.uses = 0;
        }
        self.uses += 1;
        self.serial += 1;
        let mut all = vec![&ctx.payer];
        all.extend_from_slice(signers);
        let ixs = vec![
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_price(self.serial),
            i,
        ];
        let tx = Transaction::new(&all, solana_message::Message::new(&ixs, Some(&ctx.payer.pubkey())), self.blockhash);
        ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| e.unwrap())?.result
    }
}

async fn replay(ctx: &mut ProgramTestContext, tx: &mut Sender, s: &serde_json::Value) -> u8 {
    let (admitter, e, c) = (kp(0xA1), kp(0xE1), kp(0xC1));
    let name = s["name"].as_str().unwrap();
    let tdata = hex(s["template_data"].as_str().unwrap());
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &tdata]);
    let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0;
    if ctx.banks_client.get_account(template).await.unwrap().is_none() {
        tx.send(ctx, ix(V::SUB_CREATE_TEMPLATE, &tdata, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter])
            .await
            .unwrap_or_else(|err| panic!("{name}: template: {err:?}"));
    }
    let nonce = hex(s["nonce"].as_str().unwrap());
    let refs: Vec<Vec<u8>> = s["refs"].as_array().unwrap().iter().map(|r| hex(r.as_str().unwrap())).collect();
    let mut init = nonce.clone();
    init.extend_from_slice(e.pubkey().as_ref());
    init.extend_from_slice(&(refs.len() as u32).to_le_bytes());
    let flat: Vec<u8> = refs.concat();
    init.extend_from_slice(&flat);
    let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &nonce, &(refs.len() as u32).to_le_bytes(), &flat, e.pubkey().as_ref()]);
    let run = Pubkey::find_program_address(&[b"dcg21run", &run_id, admitter.pubkey().as_ref()], &PROGRAM).0;
    tx.send(ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter])
        .await
        .unwrap_or_else(|err| panic!("{name}: init: {err:?}"));
    let root = hex(s["root_bytes"].as_str().unwrap());
    assert_eq!(&root[32..64], &run_id, "{name}: the oracle's run id");
    tx.send(ctx, ix(V::SUB_COMMIT, &root, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&e])
        .await
        .unwrap_or_else(|err| panic!("{name}: commit: {err:?}"));

    let kind = if s["kind"].as_str().unwrap() == "STEP_DESCEND" { V::KIND_STEP_DESCEND } else { V::KIND_OUT_DESCEND };
    let dispute = Pubkey::find_program_address(&[b"dcg21dsp", run.as_ref(), c.pubkey().as_ref(), &[1u8; 32]], &PROGRAM).0;
    let mut open = vec![1u8; 32];
    open.push(kind);
    tx.send(ctx, ix(V::SUB_OPEN, &open, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c])
        .await
        .unwrap_or_else(|err| panic!("{name}: open: {err:?}"));
    let party = |who: &Keypair| vec![AccountMeta::new_readonly(who.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false)];
    for (r, round) in s["rounds"].as_array().unwrap().iter().enumerate() {
        tx.send(ctx, ix(V::SUB_REVEAL_NODES, &hex(round["reveal"].as_str().unwrap()), party(&e)), &[&e])
            .await
            .unwrap_or_else(|err| panic!("{name}: reveal {r}: {err:?}"));
        tx.send(ctx, ix(V::SUB_PICK, &[round["pick"].as_u64().unwrap() as u8], party(&c)), &[&c])
            .await
            .unwrap_or_else(|err| panic!("{name}: pick {r}: {err:?}"));
    }
    let buffer = |role: u8| Pubkey::find_program_address(&[b"dcg21stg", dispute.as_ref(), &[role]], &PROGRAM).0;
    // Stage `body` in role's buffer (C creates and funds both).
    let leaf = hex(s["leaf"].as_str().unwrap());
    let claim = hex(s["claim"].as_str().unwrap());
    let mut stage = |role: u8, body: Vec<u8>| (role, body);
    let staged = [stage(V::ROLE_EXECUTOR, leaf.clone()), stage(V::ROLE_CHALLENGER, claim.clone())];
    for (role, body) in &staged {
        if body.len() <= DIRECT_LIMIT {
            continue;
        }
        // Created at most CREATE_STAGE (the role-1 buffer always is), then
        // grown in 10 KiB steps.
        let created = if *role == V::ROLE_EXECUTOR { V::CREATE_STAGE } else { body.len().min(V::CREATE_STAGE) };
        let mut data = vec![*role];
        data.extend_from_slice(&(created as u32).to_le_bytes());
        tx.send(ctx, ix(V::SUB_STAGE_CREATE, &data, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(dispute, false), AccountMeta::new(buffer(*role), false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c])
            .await
            .unwrap_or_else(|err| panic!("{name}: stage create: {err:?}"));
        let mut size = created;
        while size < body.len() {
            let add = (body.len() - size).min(10_240);
            tx.send(ctx, ix(V::SUB_STAGE_GROW, &(add as u32).to_le_bytes(), vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(dispute, false), AccountMeta::new(buffer(*role), false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c])
                .await
                .unwrap_or_else(|err| panic!("{name}: stage grow: {err:?}"));
            size += add;
        }
        let writer = if *role == V::ROLE_EXECUTOR { &e } else { &c };
        // 600-byte pieces fit a live 1,232-byte transaction (as the client).
        for (i, piece) in body.chunks(600).enumerate() {
            let mut w = ((i * 600) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(piece);
            tx.send(ctx, ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(writer.pubkey(), true), AccountMeta::new_readonly(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(dispute, false), AccountMeta::new(buffer(*role), false)]), &[writer])
                .await
                .unwrap_or_else(|err| panic!("{name}: stage write: {err:?}"));
        }
    }
    let (leaf_data, mut leaf_accounts) = if leaf.len() > DIRECT_LIMIT { (vec![V::FROM_STAGING], party(&e)) } else { (leaf, party(&e)) };
    if leaf_data == [V::FROM_STAGING] {
        leaf_accounts.push(AccountMeta::new_readonly(buffer(V::ROLE_EXECUTOR), false));
    }
    tx.send(ctx, ix(V::SUB_REVEAL_LEAF, &leaf_data, leaf_accounts), &[&e])
        .await
        .unwrap_or_else(|err| panic!("{name}: leaf: {err:?}"));
    let mut accounts = vec![AccountMeta::new_readonly(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(c.pubkey(), false)];
    let claim_data = if claim.len() > DIRECT_LIMIT {
        accounts.push(AccountMeta::new_readonly(buffer(V::ROLE_CHALLENGER), false));
        vec![V::FROM_STAGING]
    } else {
        claim
    };
    let sent = tx.send(ctx, ix(V::SUB_CLAIM, &claim_data, accounts), &[&c]).await;
    if s["ruling"].as_str() == Some("refused") {
        // A forged opening must be refused and leave the dispute open.
        assert!(sent.is_err(), "{name}: a forged claim was accepted");
        return ctx.banks_client.get_account(dispute).await.unwrap().unwrap().data[6];
    }
    sent.unwrap_or_else(|err| panic!("{name}: the claim is refused: {err:?}"));
    ctx.banks_client.get_account(dispute).await.unwrap().unwrap().data[6]
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_kernels_rule_as_the_python_oracle() {
    // CHUNKED_SCENARIOS names another recorded set (for example Basanos
    // captures); by default, the checked-in goldens.
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/chunked_scenarios.json");
    let path = std::env::var("CHUNKED_SCENARIOS").unwrap_or_else(|_| golden.to_string());
    let scenarios: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(path != golden || scenarios.len() >= 400);
    // V21_SBF=1 (with BPF_OUT_DIR naming a graph-v21 image) runs the SBF
    // program, which also checks stack frames and compute; otherwise native.
    let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    for b in [0xA1u8, 0xE1, 0xC1] {
        test.add_account(kp(b).pubkey(), Account { lamports: 1_000_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
    }
    let mut ctx = test.start_with_context().await;
    let mut tx = Sender { blockhash: ctx.last_blockhash, uses: 0, serial: 0 };
    let limit = std::env::var("CHUNKED_ORACLE_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let mut disagreements = vec![];
    for s in scenarios.iter().take(limit) {
        let want = match s["ruling"].as_str().unwrap() {
            "C" => V::RULING_CHALLENGER,
            "E" => V::RULING_EXECUTOR,
            "moot" => V::RULING_MOOT,
            _ => V::RULING_OPEN,
        };
        let got = replay(&mut ctx, &mut tx, s).await;
        if got != want {
            disagreements.push(format!("{} ({}): program {got}, oracle {want}", s["name"].as_str().unwrap(), s["claim_name"].as_str().unwrap()));
        }
    }
    assert!(disagreements.is_empty(), "{} of {}: {disagreements:#?}", disagreements.len(), scenarios.len().min(limit));
}
