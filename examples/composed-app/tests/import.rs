//! The composed app on real v2.1 run bytes: the Hello Graph run's live record,
//! receipt and template, captured from DCG's own flow test
//! (`tests/golden/dcg/result/run.json`), under their host program. A FINAL
//! run's output imports into the consensus session and the kernel sums it;
//! a raw write, a wrong value, a wrong path, an unfinished or refuted run and
//! an untrusted template are refused.

use dcg_composed_app as app;
use dcg_program::result::ResultError;
use dcg_program::stateful::{self as sw, v3};
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, rent::Rent, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const APP: Pubkey = Pubkey::new_from_array([0xC0; 32]);
const SYSTEM: Pubkey = system_program::ID;

fn unhex(s: &serde_json::Value) -> Vec<u8> {
    let s = s.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn key(s: &serde_json::Value) -> Pubkey {
    Pubkey::new_from_array(unhex(s).try_into().unwrap())
}
fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &APP).0
}
fn w(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, false)
}
fn r(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, false)
}
fn signer(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, true)
}
fn ix(tag: u8, payload: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(&payload);
    Instruction { program_id: APP, accounts, data }
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), u32> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    match ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap().result {
        Ok(()) => Ok(()),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Err(code),
        Err(_) => Err(u32::MAX),
    }
}

struct Fixture {
    f: serde_json::Value,
    run: Pubkey,
    template: Pubkey,
}

impl Fixture {
    fn load() -> Self {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/result/run.json");
        let f: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(key(&f["host"]), app::RUN_HOST);
        let (run, template) = (key(&f["run"]), key(&f["template"]));
        Fixture { f, run, template }
    }
    fn set(&self, ctx: &mut ProgramTestContext, k: Pubkey, data: Vec<u8>) {
        let account = solana_account::Account { lamports: Rent::default().minimum_balance(data.len()), data, owner: app::RUN_HOST, executable: false, rent_epoch: 0 };
        ctx.set_account(&k, &account.into());
    }
    fn import_ix(&self, auth: Pubkey, s: Pubkey, sequence: u32, value: &[u8], path: Option<Vec<[u8; 32]>>) -> Instruction {
        let mut p = sequence.to_le_bytes().to_vec();
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend(unhex(&self.f["output0"]));
        p.extend_from_slice(value);
        let path = path.unwrap_or_else(|| self.f["output0_path"].as_array().unwrap().iter().map(|h| unhex(h).try_into().unwrap()).collect());
        for h in path {
            p.extend_from_slice(&h);
        }
        ix(app::TAG_IMPORT, p, vec![signer(auth), w(s), w(pda(&[b"dcg-input-v3", s.as_ref()])), r(self.run), r(self.template)])
    }
}

/// An open, initialized session of the import-sum kernel (two 8-byte spans).
async fn session(ctx: &mut ProgramTestContext, auth: &Keypair) -> Pubkey {
    let m = &app::MANIFEST;
    let payer = ctx.payer.pubkey();
    let id = 1u64;
    let s = pda(&[b"dcg-session-v3", auth.pubkey().as_ref(), &id.to_le_bytes()]);
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&[0, app::VALUE_BYTES as u8]);
    p.extend_from_slice(&16u32.to_le_bytes());
    p.push(8);
    p.extend_from_slice(&m.id.0);
    p.extend_from_slice(&m.semantic_version.to_le_bytes());
    p.extend_from_slice(&m.abi_version.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    p.extend_from_slice(&[0x33; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&[0; 32]);
    p.push(0);
    send(ctx, ix(sw::TAG_OPEN_SESSION, p, vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]), &[auth]).await.unwrap();
    let stream = pda(&[b"dcg-input-v3", s.as_ref()]);
    send(ctx, ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0],
                 vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()), w(stream), r(SYSTEM)]), &[auth]).await.unwrap();
    let (st0, st1) = (pda(&[b"dcg-state-v3", s.as_ref(), &[0]]), pda(&[b"dcg-state-v3", s.as_ref(), &[1]]));
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&8u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    send(ctx, ix(sw::TAG_CREATE_STATE, p, vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()), w(st0), w(st1), r(SYSTEM)]), &[auth]).await.unwrap();
    send(ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
                 vec![signer(auth.pubkey()), w(s), w(st0), w(st1)]), &[auth]).await.unwrap();
    s
}

async fn advance(ctx: &mut ProgramTestContext, auth: &Keypair, s: Pubkey, cursor: u32, steps: u8) -> Result<(), u32> {
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&cursor.to_le_bytes());
    p.push(steps);
    let stream = pda(&[b"dcg-input-v3", s.as_ref()]);
    let (st0, st1) = (pda(&[b"dcg-state-v3", s.as_ref(), &[0]]), pda(&[b"dcg-state-v3", s.as_ref(), &[1]]));
    send(ctx, ix(sw::TAG_ADVANCE, p, vec![signer(auth.pubkey()), w(s), w(stream), w(st0), w(st1)]), &[auth]).await
}

async fn sum(ctx: &mut ProgramTestContext, s: Pubkey) -> (u64, i64) {
    let mut state = Vec::new();
    for i in 0..2u8 {
        let a = ctx.banks_client.get_account(pda(&[b"dcg-state-v3", s.as_ref(), &[i]])).await.unwrap().unwrap();
        state.extend_from_slice(&a.data[v3::CHILD_HEADER_BYTES..]);
    }
    (u64::from_le_bytes(state[..8].try_into().unwrap()), i64::from_le_bytes(state[8..].try_into().unwrap()))
}

fn err(e: ResultError) -> u32 {
    app::IMPORT_ERROR_BASE + e as u32
}

#[tokio::test]
async fn a_final_runs_output_is_the_sessions_input() {
    // Natively by default; with `V3_SBF=1` and `SBF_OUT_DIR`, the app's SBF image.
    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    if std::env::var("V3_SBF").is_ok_and(|v| v == "1") {
        let dir = std::env::var("SBF_OUT_DIR").expect("SBF_OUT_DIR");
        let elf = std::fs::read(std::path::Path::new(&dir).join("dcg_composed_app.so")).expect("dcg_composed_app.so");
        let lamports = Rent::default().minimum_balance(elf.len());
        test.add_account(APP, solana_account::Account { lamports, data: elf, owner: solana_program::bpf_loader::id(), executable: true, rent_epoch: 0 });
    } else {
        test.add_program("dcg_composed_app", APP, processor!(app::process_instruction));
    }
    let mut ctx = test.start_with_context().await;
    let fx = Fixture::load();
    let auth = solana_keypair::keypair_from_seed(&[81; 32]).unwrap();
    fx.set(&mut ctx, fx.template, unhex(&fx.f["template_data"]));
    fx.set(&mut ctx, fx.run, unhex(&fx.f["live"]));
    let s = session(&mut ctx, &auth).await;
    let forty_two = 42i32.to_le_bytes();

    // No raw write: inputs enter only by import.
    let mut raw = vec![v3::WIRE_VERSION];
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&[4, 1, 0, 0, 0]);
    assert_eq!(send(&mut ctx, ix(sw::TAG_WRITE_INPUT, raw, vec![signer(auth.pubkey()), w(s), w(pda(&[b"dcg-input-v3", s.as_ref()]))]), &[&auth]).await, Err(u32::MAX));
    // Not the output's bytes; another path.
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 0, &43i32.to_le_bytes(), None), &[&auth]).await, Err(app::IMPORT_ERROR_BASE + 100));
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 0, &forty_two, Some(vec![[0; 32]])), &[&auth]).await, Err(err(ResultError::Opening)));

    // The FINAL run's output 42 imports, live and then as the receipt.
    send(&mut ctx, fx.import_ix(auth.pubkey(), s, 0, &forty_two, None), &[&auth]).await.unwrap();
    fx.set(&mut ctx, fx.run, unhex(&fx.f["receipt"]));
    send(&mut ctx, fx.import_ix(auth.pubkey(), s, 1, &forty_two, None), &[&auth]).await.unwrap();
    advance(&mut ctx, &auth, s, 0, 2).await.unwrap();
    assert_eq!(sum(&mut ctx, s).await, (2, 84), "the consensus state sums the optimistic outputs");

    // A committed (unfinished) or refuted run is not a result.
    let mut committed = unhex(&fx.f["live"]);
    committed[4] = 1;
    fx.set(&mut ctx, fx.run, committed);
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 2, &forty_two, None), &[&auth]).await, Err(err(ResultError::NotFinal)));
    let mut refuted = unhex(&fx.f["receipt"]);
    refuted[4] = 3;
    fx.set(&mut ctx, fx.run, refuted);
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 2, &forty_two, None), &[&auth]).await, Err(err(ResultError::NotFinal)));
    // Another template's run (its id is not the trusted one).
    fx.set(&mut ctx, fx.run, unhex(&fx.f["live"]));
    let mut other = unhex(&fx.f["template_data"]);
    other[96] ^= 1;
    fx.set(&mut ctx, fx.template, other);
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 2, &forty_two, None), &[&auth]).await, Err(err(ResultError::Computation)));
    // A run under another owner.
    let mut foreign = solana_account::Account { lamports: 1_000_000_000, data: unhex(&fx.f["live"]), owner: APP, executable: false, rent_epoch: 0 };
    foreign.data[4] = 2;
    ctx.set_account(&fx.run, &foreign.into());
    fx.set(&mut ctx, fx.template, unhex(&fx.f["template_data"]));
    assert_eq!(send(&mut ctx, fx.import_ix(auth.pubkey(), s, 2, &forty_two, None), &[&auth]).await, Err(err(ResultError::Owner)));
    assert_eq!(sum(&mut ctx, s).await, (2, 84), "nothing else entered");
}
