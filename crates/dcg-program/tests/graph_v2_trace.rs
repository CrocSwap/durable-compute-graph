//! Native ProgramTest for the trace-committed v2 graph lifecycle (tags
//! 209-218), including the 2026-10-02 review's fixes: records are accepted
//! only at their derived address (B1), a pre-funded address can still be
//! created (S1), the challenge window is bounded (S3), and a run no executor
//! committed can be closed by its payer (S5). Mechanics only: the kernels are
//! `add_i32` and `identity_i32`.
#![cfg(feature = "graph-v2")]

use dcg_program::graph_v2::{
    GRAPH_DOMAIN, MAX_WINDOW_SLOTS, PLAN_DOMAIN, RUN_DOMAIN, TABLE_DOMAIN, TEMPLATE_DOMAIN,
};
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{instruction::InstructionError, rent::Rent, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

#[path = "fixtures/graph_v2_hello.rs"]
mod hello;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD7; 32]);
const SYSTEM: Pubkey = system_program::ID;
const BOND: u64 = 1_000_000;
const WINDOW: u64 = 20;
const MODE_CONSENSUS: u8 = 1;
const MODE_OPTIMISTIC: u8 = 2;
const MODE_SAMPLING: u8 = 3;

fn kp(byte: u8) -> Keypair {
    Keypair::new_from_array([byte; 32])
}

fn custom(code: u32) -> TransactionError {
    TransactionError::InstructionError(0, InstructionError::Custom(0x6200 + code))
}

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM).0
}

fn funded(lamports: u64) -> Account {
    Account { lamports, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 }
}

struct Chain {
    ctx: ProgramTestContext,
}

impl Chain {
    async fn start(extra: Vec<(Pubkey, Account)>) -> Self {
        let mut test = ProgramTest::default();
        test.prefer_bpf(false);
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
        for who in [0xE1u8, 0xC1, 0xA1] {
            test.add_account(kp(who).pubkey(), funded(10_000_000_000));
        }
        for (key, account) in extra {
            test.add_account(key, account);
        }
        Chain { ctx: test.start_with_context().await }
    }

    async fn send(&mut self, data: Vec<u8>, accounts: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<(), TransactionError> {
        let blockhash = self.ctx.get_new_latest_blockhash().await.unwrap();
        let mut all = vec![&self.ctx.payer];
        all.extend_from_slice(signers);
        let ix = Instruction { program_id: PROGRAM, accounts, data };
        let tx = Transaction::new(&all, solana_message::Message::new(&[ix], Some(&self.ctx.payer.pubkey())), blockhash);
        self.ctx
            .banks_client
            .process_transaction_with_metadata(tx)
            .await
            .map_err(|error| error.unwrap())?
            .result
    }

    async fn account(&mut self, key: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(key).await.unwrap()
    }

    async fn lamports(&mut self, key: Pubkey) -> u64 {
        self.account(key).await.map(|a| a.lamports).unwrap_or(0)
    }

    async fn slot(&mut self) -> u64 {
        self.ctx.banks_client.get_root_slot().await.unwrap()
    }

    async fn warp_past(&mut self, slot: u64) {
        self.ctx.warp_to_slot(slot + 2).unwrap();
    }

    async fn upload(&mut self, kind: u8, body: &[u8], domain: &[u8]) -> Pubkey {
        let writer = kp(0xA1);
        let id = sha256(&[domain, body]);
        let blob = pda(&[b"dcg2blob", &[kind], &id]);
        if self.account(blob).await.is_some() {
            return blob;
        }
        let mut create = vec![210, kind];
        create.extend_from_slice(&(body.len() as u32).to_le_bytes());
        create.extend_from_slice(&id);
        self.send(create, vec![AccountMeta::new(writer.pubkey(), true), AccountMeta::new(blob, false),
                               AccountMeta::new_readonly(SYSTEM, false)], &[&writer]).await.unwrap();
        for (i, chunk) in body.chunks(900).enumerate() {
            let mut write = vec![211];
            write.extend_from_slice(&((i * 900) as u32).to_le_bytes());
            write.extend_from_slice(chunk);
            self.send(write, vec![AccountMeta::new_readonly(writer.pubkey(), true), AccountMeta::new(blob, false)],
                      &[&writer]).await.unwrap();
        }
        self.send(vec![212], vec![AccountMeta::new_readonly(writer.pubkey(), true), AccountMeta::new(blob, false)],
                  &[&writer]).await.unwrap();
        blob
    }
}

struct Admitted {
    template: Pubkey,
    template_id: [u8; 32],
    table: Pubkey,
}

fn policy(mode: u8, window: u64) -> Vec<u8> {
    let mut p = b"POL".to_vec();
    p.extend_from_slice(&[mode, 0]);
    p.extend_from_slice(&window.to_le_bytes());
    p
}

fn admit_data(mode: u8, window: u64, manifest: &[u8]) -> Vec<u8> {
    let mut data = vec![213, mode, 0];
    data.extend_from_slice(&window.to_le_bytes());
    data.extend_from_slice(manifest);
    data.extend_from_slice(&BOND.to_le_bytes());
    data
}

async fn admit(chain: &mut Chain, mode: u8, window: u64) -> Result<Admitted, TransactionError> {
    let (graph, plan, manifest) = if mode == MODE_CONSENSUS {
        (hello::GRAPH_CONSENSUS, hello::PLAN_CONSENSUS, hello::MANIFEST_CONSENSUS)
    } else {
        (hello::GRAPH_OPTIMISTIC, hello::PLAN_OPTIMISTIC, hello::MANIFEST_OPTIMISTIC)
    };
    let table_body = [hello::STEP_TABLE, &policy(mode, window)].concat();
    let graph_blob = chain.upload(1, graph, GRAPH_DOMAIN).await;
    let plan_blob = chain.upload(2, plan, PLAN_DOMAIN).await;
    let table = chain.upload(3, &table_body, TABLE_DOMAIN).await;
    let image_id = sha256(&[b"dcg.app.image.v2\x00", PROGRAM.as_ref()]);
    let data = admit_data(mode, window, manifest);
    let template_id = sha256(&[TEMPLATE_DOMAIN, &sha256(&[GRAPH_DOMAIN, graph]), &sha256(&[PLAN_DOMAIN, plan]),
                               &image_id, manifest, &sha256(&[TABLE_DOMAIN, &table_body]), &data[1..11],
                               &BOND.to_le_bytes()]);
    let template = pda(&[b"dcg2tmpl", &template_id]);
    let admitter = kp(0xA1);
    chain.send(data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false),
                          AccountMeta::new_readonly(graph_blob, false), AccountMeta::new_readonly(plan_blob, false),
                          AccountMeta::new_readonly(table, false), AccountMeta::new_readonly(SYSTEM, false)],
               &[&admitter]).await?;
    Ok(Admitted { template, template_id, table })
}

fn cells(values: &[i32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn run_address(admitted: &Admitted, nonce: [u8; 32], inputs: &[i32]) -> Pubkey {
    let run_id = sha256(&[RUN_DOMAIN, &admitted.template_id, &nonce, &cells(inputs)]);
    pda(&[b"dcg2run", &run_id])
}

async fn init_run(chain: &mut Chain, admitted: &Admitted, nonce: u8) -> Result<Pubkey, TransactionError> {
    let payer = kp(0xA1);
    let mut data = vec![214];
    data.extend_from_slice(&[nonce; 32]);
    data.extend_from_slice(&cells(&[20, 22]));
    let run = run_address(admitted, [nonce; 32], &[20, 22]);
    chain.send(data, vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(run, false),
                          AccountMeta::new_readonly(admitted.template, false),
                          AccountMeta::new_readonly(admitted.table, false), AccountMeta::new_readonly(SYSTEM, false)],
               &[&payer]).await?;
    Ok(run)
}

async fn commit(chain: &mut Chain, admitted: &Admitted, run: Pubkey, trace: &[i32]) -> Result<(), TransactionError> {
    let executor = kp(0xE1);
    let mut data = vec![216];
    data.extend_from_slice(&cells(trace));
    chain.send(data, vec![AccountMeta::new(executor.pubkey(), true), AccountMeta::new(run, false),
                          AccountMeta::new_readonly(admitted.template, false), AccountMeta::new_readonly(SYSTEM, false)],
               &[&executor]).await
}

async fn challenge(chain: &mut Chain, admitted: &Admitted, run: Pubkey, step: u16) -> Result<(), TransactionError> {
    let challenger = kp(0xC1);
    let mut data = vec![217];
    data.extend_from_slice(&step.to_le_bytes());
    chain.send(data, vec![AccountMeta::new(challenger.pubkey(), true), AccountMeta::new(run, false),
                          AccountMeta::new_readonly(admitted.template, false),
                          AccountMeta::new_readonly(admitted.table, false)], &[&challenger]).await
}

async fn finalize(chain: &mut Chain, admitted: &Admitted, run: Pubkey) -> Result<(), TransactionError> {
    let caller = kp(0xA1);
    chain.send(vec![218], vec![AccountMeta::new(caller.pubkey(), true), AccountMeta::new(run, false),
                               AccountMeta::new_readonly(admitted.template, false),
                               AccountMeta::new(kp(0xE1).pubkey(), false)], &[&caller]).await
}

async fn close(chain: &mut Chain, admitted: &Admitted, run: Pubkey, who: &Keypair) -> Result<(), TransactionError> {
    chain.send(vec![209], vec![AccountMeta::new(who.pubkey(), true), AccountMeta::new(run, false),
                               AccountMeta::new_readonly(admitted.template, false)], &[who]).await
}

async fn status(chain: &mut Chain, run: Pubkey) -> u8 {
    chain.account(run).await.expect("run exists").data[4]
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_commit_survives_a_challenge_then_finalizes_and_closes() {
    let mut chain = Chain::start(vec![]).await;
    let t = admit(&mut chain, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    let run = init_run(&mut chain, &t, 1).await.unwrap();
    let executor_before = chain.lamports(kp(0xE1).pubkey()).await;
    commit(&mut chain, &t, run, &[42, 42]).await.unwrap();
    assert_eq!(challenge(&mut chain, &t, run, 0).await, Err(custom(22)));
    assert_eq!(finalize(&mut chain, &t, run).await, Err(custom(23)), "not before the deadline");
    let deadline = u64::from_le_bytes(chain.account(run).await.unwrap().data[24..32].try_into().unwrap());
    chain.warp_past(deadline).await;
    assert_eq!(challenge(&mut chain, &t, run, 0).await, Err(custom(20)), "no challenge after the deadline");
    finalize(&mut chain, &t, run).await.unwrap();
    assert_eq!(status(&mut chain, run).await, 2);
    // The bond went out at commit and came back at finalize; only fees differ.
    let executor_after = chain.lamports(kp(0xE1).pubkey()).await;
    assert!(executor_before - executor_after < 50_000, "bond refunded");
    assert_eq!(close(&mut chain, &t, run, &kp(0xC1)).await,
               Err(TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)));
    close(&mut chain, &t, run, &kp(0xA1)).await.unwrap();
    assert!(chain.account(run).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_step_pays_the_bond_to_the_challenger() {
    let mut chain = Chain::start(vec![]).await;
    let t = admit(&mut chain, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    let run = init_run(&mut chain, &t, 2).await.unwrap();
    commit(&mut chain, &t, run, &[43, 43]).await.unwrap();
    assert_eq!(challenge(&mut chain, &t, run, 1).await, Err(custom(22)), "step 1 is consistent with step 0");
    let before = chain.lamports(kp(0xC1).pubkey()).await;
    challenge(&mut chain, &t, run, 0).await.unwrap();
    assert_eq!(status(&mut chain, run).await, 3);
    assert!(chain.lamports(kp(0xC1).pubkey()).await >= before + BOND - 10_000);
    let run_account = chain.account(run).await.unwrap();
    assert_eq!(run_account.lamports, Rent::default().minimum_balance(run_account.data.len()));
}

#[tokio::test(flavor = "multi_thread")]
async fn consensus_executes_every_step_on_chain() {
    let mut chain = Chain::start(vec![]).await;
    let t = admit(&mut chain, MODE_CONSENSUS, WINDOW).await.unwrap();
    let run = init_run(&mut chain, &t, 3).await.unwrap();
    let caller = kp(0xA1);
    chain.send(vec![215], vec![AccountMeta::new(caller.pubkey(), true), AccountMeta::new(run, false),
                               AccountMeta::new_readonly(t.template, false),
                               AccountMeta::new_readonly(t.table, false)], &[&caller]).await.unwrap();
    let d = chain.account(run).await.unwrap().data;
    assert_eq!(d[4], 2);
    assert_eq!(&d[160 + 8..160 + 16], &cells(&[42, 42])[..]);
}

#[tokio::test(flavor = "multi_thread")]
async fn records_are_accepted_only_at_their_derived_address() {
    // B1: a program-owned keypair account holding a copy of a real run (same
    // magic, same template field) is not a run.
    let forged = Pubkey::new_from_array([0xF0; 32]);
    let mut chain = Chain::start(vec![]).await;
    let t = admit(&mut chain, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    let run = init_run(&mut chain, &t, 4).await.unwrap();
    let mut copy = chain.account(run).await.unwrap();
    copy.lamports += BOND;
    let mut chain2 = Chain::start(vec![(forged, copy)]).await;
    let t2 = admit(&mut chain2, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    assert_eq!(t2.template, t.template, "same template in both banks");
    assert_eq!(commit(&mut chain2, &t2, forged, &[43, 43]).await, Err(custom(2)));
    assert_eq!(challenge(&mut chain2, &t2, forged, 0).await, Err(custom(2)));

    // A forged template: the real template's bytes at another address.
    let template_copy = chain.account(t.template).await.unwrap();
    let fake_template = Pubkey::new_from_array([0xF1; 32]);
    let mut chain3 = Chain::start(vec![(fake_template, template_copy)]).await;
    let mut t3 = admit(&mut chain3, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    t3.template = fake_template;
    assert_eq!(init_run(&mut chain3, &t3, 5).await, Err(custom(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_blob_is_refused_at_admission() {
    // A sealed-looking graph blob at a keypair address claiming the real id.
    let mut chain = Chain::start(vec![]).await;
    let real = chain.upload(1, hello::GRAPH_OPTIMISTIC, GRAPH_DOMAIN).await;
    let copy = chain.account(real).await.unwrap();
    let fake = Pubkey::new_from_array([0xF2; 32]);
    let mut chain = Chain::start(vec![(fake, copy)]).await;
    let plan = chain.upload(2, hello::PLAN_OPTIMISTIC, PLAN_DOMAIN).await;
    let table_body = [hello::STEP_TABLE, &policy(MODE_OPTIMISTIC, WINDOW)].concat();
    let table = chain.upload(3, &table_body, TABLE_DOMAIN).await;
    let admitter = kp(0xA1);
    let template = Pubkey::new_unique();
    let result = chain.send(admit_data(MODE_OPTIMISTIC, WINDOW, hello::MANIFEST_OPTIMISTIC),
                            vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false),
                                 AccountMeta::new_readonly(fake, false), AccountMeta::new_readonly(plan, false),
                                 AccountMeta::new_readonly(table, false), AccountMeta::new_readonly(SYSTEM, false)],
                            &[&admitter]).await;
    assert_eq!(result, Err(custom(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefunded_run_address_can_still_be_created() {
    // S1: one lamport sent to the predictable run address must not block it.
    let mut probe = Chain::start(vec![]).await;
    let t = admit(&mut probe, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    let run = run_address(&t, [6; 32], &[20, 22]);
    let mut chain = Chain::start(vec![(run, funded(1))]).await;
    let t = admit(&mut chain, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    assert_eq!(init_run(&mut chain, &t, 6).await, Ok(run));
    let account = chain.account(run).await.unwrap();
    assert_eq!(account.owner, PROGRAM);
    assert_eq!(account.lamports, Rent::default().minimum_balance(account.data.len()));
    assert_eq!(init_run(&mut chain, &t, 6).await, Err(custom(3)), "an initialized run is never recreated");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_challenge_window_is_bounded() {
    // S3: zero and oversize windows are refused at admission.
    let mut chain = Chain::start(vec![]).await;
    assert!(matches!(admit(&mut chain, MODE_OPTIMISTIC, 0).await, Err(e) if e == custom(32)));
    assert!(matches!(admit(&mut chain, MODE_OPTIMISTIC, MAX_WINDOW_SLOTS + 1).await, Err(e) if e == custom(32)));
    assert!(admit(&mut chain, MODE_OPTIMISTIC, MAX_WINDOW_SLOTS).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_payer_can_close_a_run_nobody_committed() {
    // S5: an open run holds no bond; its payer recovers the rent.
    let mut chain = Chain::start(vec![]).await;
    let t = admit(&mut chain, MODE_OPTIMISTIC, WINDOW).await.unwrap();
    let run = init_run(&mut chain, &t, 7).await.unwrap();
    assert_eq!(close(&mut chain, &t, run, &kp(0xE1)).await,
               Err(TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)));
    close(&mut chain, &t, run, &kp(0xA1)).await.unwrap();
    assert!(chain.account(run).await.is_none());
    // A committed run cannot be closed early: it holds the executor's bond.
    let run = init_run(&mut chain, &t, 8).await.unwrap();
    commit(&mut chain, &t, run, &[42, 42]).await.unwrap();
    assert_eq!(close(&mut chain, &t, run, &kp(0xA1)).await, Err(custom(19)));
}

#[cfg(not(feature = "graph-v2-experimental"))]
#[tokio::test(flavor = "multi_thread")]
async fn experimental_tags_and_sampling_are_absent_from_this_image() {
    let mut chain = Chain::start(vec![]).await;
    assert!(matches!(admit(&mut chain, MODE_SAMPLING, WINDOW).await, Err(e) if e == custom(11)));
    let caller = kp(0xA1);
    for tag in [219u8, 220, 221, 225, 226] {
        let result = chain.send(vec![tag], vec![AccountMeta::new(caller.pubkey(), true)], &[&caller]).await;
        assert_eq!(result, Err(TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)),
                   "tag {tag}");
    }
}

#[cfg(not(feature = "graph-v2-raw-write"))]
#[tokio::test(flavor = "multi_thread")]
async fn raw_write_is_absent_from_this_image() {
    let owned = Keypair::new_from_array([0xB7; 32]);
    let mut chain = Chain::start(vec![(owned.pubkey(), Account { lamports: 1_000_000, data: vec![0; 8], owner: PROGRAM,
                                                                executable: false, rent_epoch: 0 })]).await;
    let mut data = vec![208];
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(b"forged");
    let result = chain.send(data, vec![AccountMeta::new(owned.pubkey(), true)], &[&owned]).await;
    assert_eq!(result, Err(TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)));
    let _ = chain.slot().await;
}
