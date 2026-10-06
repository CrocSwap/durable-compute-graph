//! Regression: PT1X upload can carry forged DCR1 bytes, but tag 124 must reject the record in live.
#![cfg(feature = "revision-8")]
extern crate dcg_program as dcg_program;
use dcg_program::pt2p_onchain as PT2;
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::{rent::Rent, system_instruction, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD2; 32]);
const UPLOAD_CHUNK: usize = 900;
const DCR1_SIZE: usize = 8192;
const TAG_EXECUTE: u8 = 124;

fn ix(data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: PROGRAM, accounts, data }
}
fn w(key: Pubkey) -> AccountMeta { AccountMeta::new(key, false) }
fn r(key: Pubkey) -> AccountMeta { AccountMeta::new_readonly(key, false) }
fn ws(key: Pubkey) -> AccountMeta { AccountMeta::new(key, true) }
fn rs(key: Pubkey) -> AccountMeta { AccountMeta::new_readonly(key, true) }
fn funded(lamports: u64) -> Account {
    Account { lamports, data: vec![], owner: system_program::ID, executable: false, rent_epoch: 0 }
}

async fn send(ctx: &mut ProgramTestContext, nonce: &mut u64, instructions: &[Instruction],
              extra: &[&Keypair]) -> Result<(), TransactionError> {
    *nonce += 1;
    loop {
        let mut signers = vec![&ctx.payer];
        signers.extend_from_slice(extra);
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ComputeBudgetInstruction::set_compute_unit_price(*nonce)];
        all.extend_from_slice(instructions);
        let tx = Transaction::new(&signers, Message::new(&all, Some(&ctx.payer.pubkey())), ctx.last_blockhash);
        let result = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
        if matches!(result.result, Err(TransactionError::BlockhashNotFound)) {
            ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
            continue;
        }
        return result.result;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_records_are_refused_at_live() {
    for version in [2u16, 4, 5] {
        forge_and_execute(version).await;
    }
}

async fn forge_and_execute(version: u16) {
    let author = Keypair::new();
    let state = Keypair::new();
    // kind 0 is the 8,192-byte DCR1 carrier; kinds 1/2 are filler (must be nonzero, distinct).
    let byte_accounts = [Keypair::new(), Keypair::new(), Keypair::new()];
    let state_len = dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4;
    let lens = [DCR1_SIZE, 16usize, 16usize];

    let mut test = ProgramTest::new("dcg_program", PROGRAM,
        processor!(dcg_program::process_instruction));
    test.set_compute_max_units(1_400_000);
    test.add_account(author.pubkey(), funded(1_000_000_000_000));
    let mut ctx = test.start_with_context().await;
    let mut nonce = 0u64;

    // Step 1: attacker creates a program-owned (via create_account owner=PROGRAM),
    // zeroed, signer PT1X state account and three system-owned signer byte accounts.
    let mut create = vec![system_instruction::create_account(&author.pubkey(), &state.pubkey(),
        Rent::default().minimum_balance(state_len), state_len as u64, &PROGRAM)];
    for (i, key) in byte_accounts.iter().enumerate() {
        create.push(system_instruction::create_account(&author.pubkey(), &key.pubkey(),
            Rent::default().minimum_balance(lens[i]), lens[i] as u64, &system_program::ID));
    }
    send(&mut ctx, &mut nonce, &create,
        &[&author, &state, &byte_accounts[0], &byte_accounts[1], &byte_accounts[2]]).await.unwrap();

    // Step 2: tag 140 (init_pt1x) assigns the three byte accounts to the program.
    send(&mut ctx, &mut nonce, &[ix(vec![PT2::TAG_BASE_INIT], vec![
        ws(state.pubkey()), ws(byte_accounts[0].pubkey()), ws(byte_accounts[1].pubkey()),
        ws(byte_accounts[2].pubkey()), rs(author.pubkey()), r(system_program::ID),
    ])], &[&state, &byte_accounts[0], &byte_accounts[1], &byte_accounts[2], &author]).await.unwrap();

    // Build a fully attacker-chosen 8,192-byte DCR1 v2 (legacy) record.
    let mut forged = vec![0u8; DCR1_SIZE];
    forged[..4].copy_from_slice(b"DCR1");
    forged[4] = 1;                                   // PHASE_RESPOND
    forged[6..8].copy_from_slice(&version.to_le_bytes());
    forged[144] = 1;                                 // PT2P mode for v5
    forged[145] = 0;                                 // machine
    forged[174..176].copy_from_slice(&4u16.to_le_bytes()); // supported form 4
    forged[148..156].copy_from_slice(&u64::MAX.to_le_bytes()); // deadline far future
    forged[176] = 1;                                 // "target posted" marker
    // descriptor / seal bytes arbitrary (attacker-chosen)
    for (i, b) in forged[72..104].iter_mut().enumerate() { *b = (i as u8).wrapping_add(1); }
    if version == 5 {
        forged[8..40].copy_from_slice(author.pubkey().as_ref());
        let (_, bump) = Pubkey::find_program_address(&[
            b"dcg-unified-challenge", &forged[72..104], author.pubkey().as_ref(), &[0; 4],
        ], &PROGRAM);
        forged[146] = bump;
        forged[147] = 1; // Valid bump metadata, but the keypair is still not the PDA.
    }

    // Step 3: tag 141 (upload) copies the chosen bytes into the program-owned,
    // NON-PDA keypair account, in 900-byte chunks, no PDA check on the target.
    let mut offset = 0usize;
    while offset < DCR1_SIZE {
        let end = (offset + UPLOAD_CHUNK).min(DCR1_SIZE);
        let mut data = vec![PT2::TAG_BASE_UPLOAD, 0u8];
        data.extend_from_slice(&(offset as u32).to_le_bytes());
        data.extend_from_slice(&forged[offset..end]);
        send(&mut ctx, &mut nonce, &[ix(data, vec![
            w(state.pubkey()), w(byte_accounts[0].pubkey()), rs(author.pubkey()),
        ])], &[&author]).await.unwrap();
        offset = end;
    }

    // Verify the forge: program-owned keypair account holding exactly the chosen DCR1 bytes.
    let forged_acct = ctx.banks_client.get_account(byte_accounts[0].pubkey()).await.unwrap().unwrap();
    assert_eq!(forged_acct.owner, PROGRAM, "byte account is now program-owned");
    assert_eq!(forged_acct.data.len(), DCR1_SIZE);
    assert_eq!(&forged_acct.data[..4], b"DCR1");
    assert_eq!(&forged_acct.data[..], &forged[..], "attacker chose every byte");
    eprintln!("FORGE-OK owner={} len={} magic={:?} version={}",
        forged_acct.owner, forged_acct.data.len(), &forged_acct.data[..4],
        u16::from_le_bytes([forged_acct.data[6], forged_acct.data[7]]));

    // Now attempt the end-to-end attack: tag 124 (execute) with the forged challenge.
    // No real legacy DCM2 v3/v4 document exists (and cannot be created on this image),
    // so document()/the PDA check must stop it: no ruling, challenge phase stays 1.
    let resp = Keypair::new();
    let document = Keypair::new();
    let routes = Keypair::new();
    let geom = Keypair::new();
    let pt2s = Keypair::new();
    for k in [&resp, &document, &routes, &geom, &pt2s] {
        ctx.banks_client.get_account(k.pubkey()).await.ok();
    }
    let exec = send(&mut ctx, &mut nonce, &[ix(vec![TAG_EXECUTE], vec![
        w(byte_accounts[0].pubkey()), r(resp.pubkey()), w(document.pubkey()),
        r(routes.pubkey()), r(geom.pubkey()), r(pt2s.pubkey()),
    ])], &[]).await;
    eprintln!("EXECUTE-RESULT {exec:?}");
    let expected = if version == 5 { 734 } else { 742 };
    assert!(format!("{exec:?}").contains(&format!("Custom({expected})")),
        "v{version} must fail in live with {expected}, got {exec:?}");

    // The forged challenge was NOT ruled (phase still 1, winner byte still 0).
    let after = ctx.banks_client.get_account(byte_accounts[0].pubkey()).await.unwrap().unwrap();
    assert_eq!(after.data[4], 1, "challenge phase unchanged (not ruled to 3)");
    assert_eq!(after.data[5], 0, "no winner recorded");
}
