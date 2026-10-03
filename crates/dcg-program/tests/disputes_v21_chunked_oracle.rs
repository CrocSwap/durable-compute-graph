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
use std::path::PathBuf;

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

async fn replay(ctx: &mut ProgramTestContext, tx: &mut Sender, s: &serde_json::Value, settle: bool) -> u8 {
    let (admitter, e, c) = (kp(0xA1), kp(0xE1), kp(0xC1));
    let name = s["name"].as_str().unwrap();
    let tdata = hex(s["template_data"].as_str().unwrap());
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &tdata]);
    let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, admitter.pubkey().as_ref()], &PROGRAM).0;
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
    tx.send(ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter])
        .await
        .unwrap_or_else(|err| panic!("{name}: init: {err:?}"));
    let root = hex(s["root_bytes"].as_str().unwrap());
    assert_eq!(&root[32..64], &run_id, "{name}: the oracle's run id");
    tx.send(ctx, ix(V::SUB_COMMIT, &root, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&e])
        .await
        .unwrap_or_else(|err| panic!("{name}: commit: {err:?}"));

    let kind = if s["kind"].as_str().unwrap() == "STEP_DESCEND" { V::KIND_STEP_DESCEND } else { V::KIND_OUT_DESCEND };
    let dispute = Pubkey::find_program_address(&[b"dcg21dsp", run.as_ref(), c.pubkey().as_ref(), &[1u8; 32]], &PROGRAM).0;
    let buffer = |role: u8| Pubkey::find_program_address(&[b"dcg21stg", dispute.as_ref(), &[role]], &PROGRAM).0;
    let tracked = [admitter.pubkey(), e.pubkey(), c.pubkey(), run, template, dispute,
        buffer(V::ROLE_EXECUTOR), buffer(V::ROLE_CHALLENGER)];
    let before = if settle { total_lamports(ctx, &tracked).await } else { 0 };
    let e_before = if settle { ctx.banks_client.get_balance(e.pubkey()).await.unwrap() } else { 0 };
    let c_before = if settle { ctx.banks_client.get_balance(c.pubkey()).await.unwrap() } else { 0 };
    let mut open = vec![1u8; 32];
    open.push(kind);
    tx.send(ctx, ix(V::SUB_OPEN, &open, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c])
        .await
        .unwrap_or_else(|err| panic!("{name}: open: {err:?}"));
    let party = |who: &Keypair| vec![AccountMeta::new_readonly(who.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false)];
    for (r, round) in s["rounds"].as_array().unwrap().iter().enumerate() {
        let reveal = ix(V::SUB_REVEAL_NODES, &hex(round["reveal"].as_str().unwrap()), party(&e));
        tx.send(ctx, reveal.clone(), &[&e])
            .await
            .unwrap_or_else(|err| panic!("{name}: reveal {r}: {err:?}"));
        if settle {
            let raw = ctx.banks_client.get_account(run).await.unwrap().unwrap().data;
            let extension = &raw[raw.len() - 4..];
            let before = extension.to_vec();
            assert!(tx.send(ctx, reveal, &[&e]).await.is_err(), "{name}: E banked time while C owed PICK");
            let raw = ctx.banks_client.get_account(run).await.unwrap().unwrap().data;
            assert_eq!(&raw[raw.len() - 4..], before, "{name}: E wait count changed on C's turn");
        }
        tx.send(ctx, ix(V::SUB_PICK, &[round["pick"].as_u64().unwrap() as u8], party(&c)), &[&c])
            .await
            .unwrap_or_else(|err| panic!("{name}: pick {r}: {err:?}"));
    }
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
    if settle {
        let mut third_party = accounts.clone();
        third_party[0] = AccountMeta::new_readonly(admitter.pubkey(), true);
        assert!(tx.send(ctx, ix(V::SUB_CLAIM, &claim_data, third_party), &[&admitter]).await.is_err(),
            "{name}: third party called permissioned ruling");
    }
    let sent = tx.send(ctx, ix(V::SUB_CLAIM, &claim_data, accounts), &[&c]).await;
    if s["ruling"].as_str() == Some("refused") {
        // A forged opening must be refused and leave the dispute open.
        assert!(sent.is_err(), "{name}: a forged claim was accepted");
        return ctx.banks_client.get_account(dispute).await.unwrap().unwrap().data[6];
    }
    sent.unwrap_or_else(|err| panic!("{name}: the claim is refused: {err:?}"));
    let ruling = ctx.banks_client.get_account(dispute).await.unwrap().unwrap().data[6];
    if settle {
        let caller = &admitter;
        let party = |sub, d: Vec<u8>| ix(sub, &d, vec![AccountMeta::new_readonly(c.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false)]);
        assert!(tx.send(ctx, party(V::SUB_PICK, vec![0]), &[&c]).await.is_err(), "{name}: move after ruling");
        let advance = ix(V::SUB_ADVANCE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(dispute, false)]);
        tx.send(ctx, advance, &[caller]).await.unwrap();
        if ruling == V::RULING_CHALLENGER {
            let pot = ix(V::SUB_PAY_POT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new_readonly(dispute, false), AccountMeta::new(c.pubkey(), false), AccountMeta::new(admitter.pubkey(), false)]);
            tx.send(ctx, pot.clone(), &[caller]).await.unwrap();
            assert!(tx.send(ctx, pot, &[caller]).await.is_err(), "{name}: bond paid twice");
        }
        let close_dispute = ix(V::SUB_CLOSE_DISPUTE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(dispute, false), AccountMeta::new(c.pubkey(), false), AccountMeta::new(e.pubkey(), false), AccountMeta::new(buffer(V::ROLE_EXECUTOR), false), AccountMeta::new(buffer(V::ROLE_CHALLENGER), false)]);
        let dispute_rent = ctx.banks_client.get_balance(dispute).await.unwrap();
        let buffer_rent = ctx.banks_client.get_balance(buffer(V::ROLE_EXECUTOR)).await.unwrap()
            + ctx.banks_client.get_balance(buffer(V::ROLE_CHALLENGER)).await.unwrap();
        let c_pre_close = ctx.banks_client.get_balance(c.pubkey()).await.unwrap();
        tx.send(ctx, close_dispute.clone(), &[caller]).await.unwrap();
        assert_eq!(ctx.banks_client.get_balance(c.pubkey()).await.unwrap(), c_pre_close + dispute_rent + buffer_rent, "{name}: challenger rent refund");
        assert!(tx.send(ctx, close_dispute, &[caller]).await.is_err(), "{name}: second dispute close");
        if ruling != V::RULING_CHALLENGER {
            ctx.warp_to_slot(5_000).unwrap();
            tx.blockhash = ctx.get_new_latest_blockhash().await.unwrap();
            tx.uses = 0;
            let finalize = ix(V::SUB_FINALIZE, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new_readonly(template, false), AccountMeta::new(e.pubkey(), false)]);
            tx.send(ctx, finalize.clone(), &[caller]).await.unwrap();
            assert!(tx.send(ctx, finalize, &[caller]).await.is_err(), "{name}: executor bond paid twice");
        }
        let close_run = ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(caller.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new(template, false), AccountMeta::new(admitter.pubkey(), false)]);
        tx.send(ctx, close_run.clone(), &[caller]).await.unwrap();
        assert!(tx.send(ctx, close_run, &[caller]).await.is_err(), "{name}: second run close");
        let close_template = ix(V::SUB_CLOSE_TEMPLATE, &[], vec![AccountMeta::new(caller.pubkey(), true), AccountMeta::new(template, false)]);
        tx.send(ctx, close_template.clone(), &[caller]).await.unwrap();
        assert!(tx.send(ctx, close_template, &[caller]).await.is_err(), "{name}: second template close");
        assert_eq!(total_lamports(ctx, &tracked).await, before, "{name}: lamports conserved");
        if name.contains("honest") {
            assert!(ctx.banks_client.get_balance(e.pubkey()).await.unwrap() >= e_before, "{name}: honest executor net negative");
        } else {
            assert!(ctx.banks_client.get_balance(c.pubkey()).await.unwrap() >= c_before, "{name}: honest challenger net negative");
        }
    }
    ruling
}

async fn total_lamports(ctx: &mut ProgramTestContext, keys: &[Pubkey]) -> u128 {
    let mut total = 0;
    for key in keys { total += ctx.banks_client.get_balance(*key).await.unwrap() as u128; }
    total
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_kernels_rule_as_the_python_oracle() {
    // CHUNKED_SCENARIOS names another recorded set (for example Basanos
    // captures); by default, the checked-in goldens.
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/chunked_scenarios.json");
    let path = std::env::var_os("CHUNKED_SCENARIOS").map_or_else(
        || PathBuf::from(golden),
        |raw| {
            let path = PathBuf::from(raw);
            if path.is_absolute() || path.exists() {
                path
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)
            }
        },
    );
    let scenarios: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(path != PathBuf::from(golden) || scenarios.len() >= 400);
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
        let got = replay(&mut ctx, &mut tx, s, false).await;
        if got != want {
            disagreements.push(format!("{} ({}): program {got}, oracle {want}", s["name"].as_str().unwrap(), s["claim_name"].as_str().unwrap()));
        }
    }
    assert!(disagreements.is_empty(), "{} of {}: {disagreements:#?}", disagreements.len(), scenarios.len().min(limit));
}

#[tokio::test(flavor = "multi_thread")]
async fn l6_log_endings_use_real_claims_and_close() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/log_neutral_scenarios.json");
    let scenarios: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(scenarios.iter().any(|s| s["name"] == "log-k2-false-prior-STATE"));
    for s in &scenarios {
        let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
        let mut test = ProgramTest::default();
        test.prefer_bpf(sbf);
        if sbf { test.add_program("dcg_program", PROGRAM, None); }
        else { test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction)); }
        for b in [0xA1u8, 0xE1, 0xC1] {
            test.add_account(kp(b).pubkey(), Account { lamports: 1_000_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
        }
        let mut ctx = test.start_with_context().await;
        let mut tx = Sender { blockhash: ctx.last_blockhash, uses: 0, serial: 0 };
        let want = match s["ruling"].as_str().unwrap() {
            "C" => V::RULING_CHALLENGER, "E" => V::RULING_EXECUTOR,
            "moot" => V::RULING_MOOT, other => panic!("unexpected LOG ruling {other}"),
        };
        assert_eq!(replay(&mut ctx, &mut tx, s, true).await, want, "{}", s["name"]);
    }
}
