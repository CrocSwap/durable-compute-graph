#![cfg(all(feature = "revision-8", feature = "sbf-real-lifecycle-test"))]

//! SBF checks for the generic revision-8 dispute dispatcher.
//!
//! Run against the linked image with `BPF_OUT_DIR` and `SBF_OUT_DIR` set. The
//! first cases pin the malformed-account refusal boundary without invoking a
//! host processor.

use solana_account::{Account, AccountSharedData};
use solana_instruction::error::InstructionError;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD2; 32]);
const SYSTEM: Pubkey = system_program::ID;

fn instruction(tag: u8) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: Vec::<AccountMeta>::new(),
        data: vec![tag],
    }
}

async fn start() -> ProgramTestContext {
    let out = std::env::var("SBF_OUT_DIR").expect("set SBF_OUT_DIR to the SBF build output");
    assert!(std::path::Path::new(&out).join("dcg_program.so").is_file());
    let payer = solana_keypair::keypair_from_seed(&[0xD2; 32]).unwrap();
    let mut test = ProgramTest::new("dcg_program", PROGRAM, None);
    test.prefer_bpf(true);
    test.add_genesis_account(
        payer.pubkey(),
        Account {
            lamports: 100_000_000_000,
            data: vec![],
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        },
    );
    let mut context = test.start_with_context().await;
    context.payer = payer;
    context
}

async fn malformed_refusal(context: &mut ProgramTestContext, tag: u8) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let transaction = Transaction::new_signed_with_payer(
        &[instruction(tag)],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        blockhash,
    );
    let result = context
        .banks_client
        .process_transaction_with_metadata(transaction)
        .await
        .unwrap();
    let units = result
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.compute_units_consumed);
    assert_eq!(
        result.result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(730)
        )),
        "tag {tag} malformed account list"
    );
    eprintln!("DCG_GENERIC_SBF_CU|{tag}|malformed|{units}");
    units
}

#[tokio::test]
async fn generic_dispute_tags_refuse_malformed_sbf_inputs() {
    let mut context = start().await;
    for tag in [120, 121, 122, 123, 124, 126, 127, 128, 129] {
        assert!(malformed_refusal(&mut context, tag).await > 0);
    }
}

#[tokio::test]
async fn new_generic_tags_refuse_unsupported_forms_with_740_on_sbf() {
    let mut context = start().await;
    let executor = context.payer.pubkey();
    for (tag, account_count) in [(122, 3usize), (123, 2), (124, 6), (127, 3), (129, 8)] {
        let (challenge, response) =
            challenge_fixture(&mut context, 0x12F0_0000 + u32::from(tag), executor, true);
        let mut record = context
            .banks_client
            .get_account(challenge)
            .await
            .unwrap()
            .unwrap();
        record.data[174..176].copy_from_slice(&999u16.to_le_bytes());
        context.set_account(&challenge, &AccountSharedData::from(record));
        let mut accounts = vec![AccountMeta::new(challenge, false)];
        for index in 1..account_count {
            let key = if index == 1 {
                response
            } else {
                Pubkey::new_unique()
            };
            accounts.push(if tag == 124 && index == 2 {
                AccountMeta::new(key, false)
            } else if index == 0 {
                AccountMeta::new(key, false)
            } else {
                AccountMeta::new_readonly(key, false)
            });
        }
        let mut ix = instruction_with_accounts(tag, accounts);
        if tag == 129 {
            ix.data = vec![129, 0, 0, 0, 0, 1, 0];
        }
        let (result, units) = send(&mut context, ix).await;
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::Custom(740)
            )),
            "tag {tag} unsupported form"
        );
        assert!(units > 0);
        eprintln!("DCG_GENERIC_SBF_CU|{tag}|unsupported-form-740|{units}");
    }
}

#[tokio::test]
async fn output_verifier_rejects_retained_v1_fixture_with_descriptor_mismatch() {
    let mut context = start().await;
    let executor = context.payer.pubkey();
    let (challenge, response) = challenge_fixture(&mut context, 0x1280_0001, executor, true);
    let fixture = include_bytes!("../tests/fixtures/closure_v2_generic/entry-119.dgr1");
    set_owned(
        &mut context,
        response,
        response_fixture(challenge, executor, fixture),
    );
    let ix = instruction_with_accounts(
        128,
        vec![
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(response, false),
        ],
    );
    let (result, units) = send(&mut context, ix).await;
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(734)
        )),
        "the retained DGR1 v1 fixture is bound to its original descriptor"
    );
    assert!(units > 0);
    eprintln!("DCG_GENERIC_SBF_CU|128|retained-v1-fixture-descriptor-mismatch|{units}");
}

const DCR1_BYTES: usize = 8_192;
const DESCRIPTOR: [u8; 32] = [0x63; 32];
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";

fn set_owned(context: &mut ProgramTestContext, key: Pubkey, data: Vec<u8>) {
    context.set_account(
        &key,
        &AccountSharedData::from(Account {
            lamports: 10_000_000,
            data,
            owner: PROGRAM,
            executable: false,
            rent_epoch: 0,
        }),
    );
}

fn challenge_fixture(
    context: &mut ProgramTestContext,
    nonce: u32,
    executor: Pubkey,
    staged_response: bool,
) -> (Pubkey, Pubkey) {
    challenge_fixture_for_roles(
        context,
        nonce,
        context.payer.pubkey(),
        executor,
        staged_response,
    )
}

fn challenge_fixture_for_roles(
    context: &mut ProgramTestContext,
    nonce: u32,
    challenger: Pubkey,
    executor: Pubkey,
    staged_response: bool,
) -> (Pubkey, Pubkey) {
    let (challenge, challenge_bump) =
        dcg_program::unified::address::challenge(&PROGRAM, &DESCRIPTOR, &challenger, nonce);
    let (response, response_bump) = dcg_program::closure_v2_response::address(&PROGRAM, &challenge);
    let mut state = vec![0u8; DCR1_BYTES];
    state[..4].copy_from_slice(b"DCR1");
    state[4] = dcg_program::unified::challenge::PHASE_RESPOND;
    state[6..8].copy_from_slice(&dcg_program::unified::challenge::VERSION.to_le_bytes());
    state[8..40].copy_from_slice(challenger.as_ref());
    state[40..72].copy_from_slice(executor.as_ref());
    state[72..104].copy_from_slice(&DESCRIPTOR);
    state[140..144].copy_from_slice(&nonce.to_le_bytes());
    state[144] = 1;
    state[174..176].copy_from_slice(&22u16.to_le_bytes());
    state[146] = challenge_bump.value();
    state[147] = 1;
    state[148..156].copy_from_slice(&u64::MAX.to_le_bytes());
    state[dcg_program::unified::challenge::RESPONSE_BUMP_STAGED_AT] = response_bump.value();
    state[dcg_program::unified::challenge::RESPONSE_BUMP_AT] = response_bump.value();
    if staged_response {
        state[176] = 1;
        state[480] = 1;
        state[481] = response_bump.value();
        state[184..216].copy_from_slice(response.as_ref());
    }
    set_owned(context, challenge, state);
    (challenge, response)
}

fn replay_body(committed_output: &[u8], read: &[u8]) -> Vec<u8> {
    let position = 0u32;
    let segment = 0u16;
    let entry = 1u32;
    let operation = 1u16;
    let region = 9u16;
    let offset = 128u64;
    let write_digest = dcg_program::closure_v2::write_digest(
        &DESCRIPTOR,
        dcg_program::closure_v2::Coordinate {
            position,
            segment,
            entry,
        },
        region,
        offset,
        committed_output,
    )
    .unwrap();
    let base = LEAF_DOMAIN.len();
    let mut target = vec![0u8; base + 120 + 48];
    target[..base].copy_from_slice(LEAF_DOMAIN);
    target[base..base + 32].copy_from_slice(&DESCRIPTOR);
    target[base + 32..base + 36].copy_from_slice(&position.to_le_bytes());
    target[base + 36..base + 38].copy_from_slice(&segment.to_le_bytes());
    target[base + 38..base + 42].copy_from_slice(&entry.to_le_bytes());
    target[base + 42..base + 44].copy_from_slice(&operation.to_le_bytes());
    target[base + 44..base + 46].copy_from_slice(&22u16.to_le_bytes());
    target[base + 48..base + 50].copy_from_slice(&1u16.to_le_bytes());
    target[base + 116..base + 118].copy_from_slice(&1u16.to_le_bytes());
    let write = base + 120;
    target[write..write + 2].copy_from_slice(&region.to_le_bytes());
    target[write + 4..write + 8].copy_from_slice(&(committed_output.len() as u32).to_le_bytes());
    target[write + 8..write + 16].copy_from_slice(&offset.to_le_bytes());
    target[write + 16..write + 48].copy_from_slice(&write_digest);

    let head = 36usize;
    let target_at = head + 4;
    let rows_at = target_at + target.len();
    let section_at = rows_at + 120;
    let section_len = 4 + read.len() + 1;
    let core = b"DCGTEST-DESCRIPTOR/1";
    let core_at = section_at + section_len;
    let weights = b"DCGTEST-ROWS/1";
    let weights_at = core_at + core.len();
    let mut body = vec![0u8; weights_at + weights.len()];
    body[..4].copy_from_slice(b"DGR1");
    body[4..6].copy_from_slice(&2u16.to_le_bytes());
    body[6..8].copy_from_slice(&1u16.to_le_bytes());
    body[8..12].copy_from_slice(&(target.len() as u32).to_le_bytes());
    body[36..40].copy_from_slice(&(section_at as u32).to_le_bytes());
    body[40..target_at + target.len()].copy_from_slice(&target);
    body[section_at..section_at + 4].copy_from_slice(&(read.len() as u32).to_le_bytes());
    body[section_at + 4..section_at + 4 + read.len()].copy_from_slice(read);
    body[section_at + 4 + read.len()] = 1;
    body[12..16].copy_from_slice(&(core_at as u32).to_le_bytes());
    body[16..20].copy_from_slice(&(core.len() as u32).to_le_bytes());
    body[20..24].copy_from_slice(&(weights_at as u32).to_le_bytes());
    body[24..28].copy_from_slice(&(weights.len() as u32).to_le_bytes());
    body[core_at..core_at + core.len()].copy_from_slice(core);
    body[weights_at..].copy_from_slice(weights);
    body
}

async fn run_generic_replay(
    context: &mut ProgramTestContext,
    nonce: u32,
    cheat: bool,
    swapped: bool,
) {
    let payer = context.payer.pubkey();
    let other_role = Pubkey::new_unique();
    let (challenger, executor) = if swapped {
        (other_role, payer)
    } else {
        (payer, other_role)
    };
    let (challenge, response) =
        challenge_fixture_for_roles(context, nonce, challenger, executor, true);
    let (document, _) = dcg_program::unified::address::document(&PROGRAM, &DESCRIPTOR);
    let mut doc = vec![0u8; dcg_program::unified::document::DCM2_V6_BYTES];
    doc[..4].copy_from_slice(b"DCM2");
    doc[4..6].copy_from_slice(&6u16.to_le_bytes());
    doc[6..8].copy_from_slice(
        &(dcg_program::unified::document::FLAG_ROOT_ONLY
            | dcg_program::unified::document::FLAG_SEALED)
            .to_le_bytes(),
    );
    doc[8..40].copy_from_slice(&DESCRIPTOR);
    doc[40..72].copy_from_slice(executor.as_ref());
    doc[264..296].fill(0x44);
    let terms = dcg_program::unified::terms::Terms {
        challenge_window_slots: 10,
        response_window_slots: 10,
        challenger_bond_lamports: 0,
        executor_bond_lamports: 0,
        executor_reward_bps: 0,
        settlement_program: [0; 32],
        custom_settle_window_slots: 0,
        result_retention_slots: 1,
    }
    .encode();
    let terms_at = dcg_program::unified::document::TERMS_AT;
    doc[terms_at..terms_at + terms.len()].copy_from_slice(&terms);
    set_owned(context, document, doc);

    let routes = Pubkey::new_unique();
    let geometry = Pubkey::new_unique();
    let pt2s = Pubkey::new_unique();
    set_owned(context, routes, vec![0; 8]);
    set_owned(context, geometry, vec![0; 8]);
    set_owned(context, pt2s, vec![0; 8]);

    let correct: [u8; 8] = 5u64.to_le_bytes();
    let committed = if cheat { 6u64.to_le_bytes() } else { correct };
    let body = replay_body(&committed, &[2, 3]);
    set_owned(
        context,
        response,
        response_fixture(challenge, executor, &body),
    );
    let mut record = context
        .banks_client
        .get_account(challenge)
        .await
        .unwrap()
        .unwrap();
    record.data[136..140].copy_from_slice(&1u32.to_le_bytes());
    record.data[145] = 0;
    record.data[174..176].copy_from_slice(&22u16.to_le_bytes());
    record.data[178..180].copy_from_slice(&1u16.to_le_bytes());
    record.data[182..184].copy_from_slice(&1u16.to_le_bytes());
    record.data[216..248].copy_from_slice(routes.as_ref());
    record.data[248..280].copy_from_slice(geometry.as_ref());
    record.data[448..480].copy_from_slice(pt2s.as_ref());
    context.set_account(&challenge, &AccountSharedData::from(record));

    let anchor = instruction_with_accounts(
        122,
        vec![
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(response, false),
            AccountMeta::new_readonly(document, false),
        ],
    );
    let (result, units) = send(context, anchor).await;
    assert_eq!(
        result,
        Ok(()),
        "tag 122 verifies the test descriptor row anchor"
    );
    eprintln!("DCG_GENERIC_SBF_CU|122|weights-anchor|{units}");

    let rows = instruction_with_accounts(
        123,
        vec![
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(response, false),
        ],
    );
    let (result, units) = send(context, rows).await;
    assert_eq!(result, Ok(()), "tag 123 verifies test weight rows");
    eprintln!("DCG_GENERIC_SBF_CU|123|weights-rows|{units}");

    let mut record = context
        .banks_client
        .get_account(challenge)
        .await
        .unwrap()
        .unwrap();
    record.data[348] = 1; // tag 121's authenticated single read
    context.set_account(&challenge, &AccountSharedData::from(record));
    let execute = instruction_with_accounts(
        124,
        vec![
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(response, false),
            AccountMeta::new(document, false),
            AccountMeta::new_readonly(routes, false),
            AccountMeta::new_readonly(geometry, false),
            AccountMeta::new_readonly(pt2s, false),
        ],
    );
    let (result, units) = send(context, execute).await;
    assert_eq!(
        result,
        Ok(()),
        "tag 124 replays and rules the staged response"
    );
    let ruled = context
        .banks_client
        .get_account(challenge)
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(ruled[4], dcg_program::unified::challenge::PHASE_RULED);
    assert_eq!(ruled[5], if cheat { 2 } else { 1 });
    let ruled_doc = context
        .banks_client
        .get_account(document)
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(
        u16::from_le_bytes(ruled_doc[6..8].try_into().unwrap())
            & dcg_program::unified::document::FLAG_REFUTED,
        if cheat {
            dcg_program::unified::document::FLAG_REFUTED
        } else {
            0
        }
    );
    eprintln!(
        "DCG_GENERIC_SBF_CU|124|{}|{units}",
        if cheat { "cheat-convicted" } else { "honest" }
    );
}

#[tokio::test]
async fn test_application_dispute_hooks_replay_and_convict_on_sbf() {
    for (cheat, swapped, nonce) in [
        (false, false, 0x1240_0001),
        (false, true, 0x1240_0002),
        (true, false, 0x1240_0003),
    ] {
        let mut context = start().await;
        run_generic_replay(&mut context, nonce, cheat, swapped).await;
    }
}

#[tokio::test]
async fn legacy_dcr2_dcr4_and_unified_dcm6_are_accepted_on_sbf() {
    let mut context = start().await;
    let executor = Pubkey::new_unique();
    for (record_version, document_version, document_len) in [(2u16, 2u16, 360usize), (4, 4, 456)] {
        let nonce = 0x1220_0000 + u32::from(record_version);
        let (challenge, response) = challenge_fixture(&mut context, nonce, executor, true);
        let body = replay_body(&5u64.to_le_bytes(), &[2, 3]);
        set_owned(
            &mut context,
            response,
            response_fixture(challenge, executor, &body),
        );
        let mut record = context
            .banks_client
            .get_account(challenge)
            .await
            .unwrap()
            .unwrap();
        record.data[6..8].copy_from_slice(&record_version.to_le_bytes());
        record.data[140..144].copy_from_slice(&(body.len() as u32).to_le_bytes());
        record.data[174..176].copy_from_slice(&22u16.to_le_bytes());
        context.set_account(&challenge, &AccountSharedData::from(record));

        let (document, _) = dcg_program::closure_v2::document_address(&PROGRAM, &DESCRIPTOR);
        let mut doc = vec![0u8; document_len];
        doc[..4].copy_from_slice(b"DCM2");
        doc[4..6].copy_from_slice(&document_version.to_le_bytes());
        doc[8..40].copy_from_slice(&DESCRIPTOR);
        doc[40..72].copy_from_slice(executor.as_ref());
        doc[264..296].fill(0x44);
        set_owned(&mut context, document, doc);

        let ix = instruction_with_accounts(
            122,
            vec![
                AccountMeta::new(challenge, false),
                AccountMeta::new_readonly(response, false),
                AccountMeta::new_readonly(document, false),
            ],
        );
        let (result, units) = send(&mut context, ix).await;
        assert_eq!(
            result,
            Ok(()),
            "DCR1 v{record_version} / DCM2 v{document_version}"
        );
        assert!(units > 0);
        eprintln!(
            "DCG_GENERIC_SBF_CU|122|dcr{record_version}-dcm{document_version}-accepted|{units}"
        );
    }
}

fn response_fixture(challenge: Pubkey, executor: Pubkey, body: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 128];
    data[..4].copy_from_slice(b"DRU1");
    data[4..6].copy_from_slice(&1u16.to_le_bytes());
    data[6..8].copy_from_slice(&2u16.to_le_bytes());
    data[8..40].copy_from_slice(challenge.as_ref());
    data[40..72].copy_from_slice(executor.as_ref());
    data[72..76].copy_from_slice(&(body.len() as u32).to_le_bytes());
    data[76..80].copy_from_slice(&(body.len() as u32).to_le_bytes());
    data[80..112].copy_from_slice(&dcg_program::hash::sha256(&[body]));
    data[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
    data.extend_from_slice(body);
    data
}

fn valid_output_body(
    position: u32,
    segment: u16,
    entry: u32,
    committed_output: &[u8],
    claimed_output: &[u8],
) -> Vec<u8> {
    let region = 9u16;
    let offset = 128u64;
    let write_digest = dcg_program::closure_v2::write_digest(
        &DESCRIPTOR,
        dcg_program::closure_v2::Coordinate {
            position,
            segment,
            entry,
        },
        region,
        offset,
        committed_output,
    )
    .unwrap();
    let mut target = vec![0u8; LEAF_DOMAIN.len() + 120 + 48];
    target[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    let base = LEAF_DOMAIN.len();
    target[base..base + 32].copy_from_slice(&DESCRIPTOR);
    target[base + 32..base + 36].copy_from_slice(&position.to_le_bytes());
    target[base + 36..base + 38].copy_from_slice(&segment.to_le_bytes());
    target[base + 38..base + 42].copy_from_slice(&entry.to_le_bytes());
    target[base + 42..base + 44].copy_from_slice(&3u16.to_le_bytes());
    target[base + 44..base + 46].copy_from_slice(&1u16.to_le_bytes());
    target[base + 46..base + 48].copy_from_slice(&2u16.to_le_bytes());
    target[base + 116..base + 118].copy_from_slice(&1u16.to_le_bytes());
    let write = base + 120;
    target[write..write + 2].copy_from_slice(&region.to_le_bytes());
    target[write + 4..write + 8].copy_from_slice(&(committed_output.len() as u32).to_le_bytes());
    target[write + 8..write + 16].copy_from_slice(&offset.to_le_bytes());
    target[write + 16..write + 48].copy_from_slice(&write_digest);

    let header = 36usize;
    let output_at = header + target.len();
    let mut body = vec![0u8; output_at + claimed_output.len()];
    body[..4].copy_from_slice(b"DGR1");
    body[4..6].copy_from_slice(&2u16.to_le_bytes());
    body[8..12].copy_from_slice(&(target.len() as u32).to_le_bytes());
    body[28..32].copy_from_slice(&(output_at as u32).to_le_bytes());
    body[32..36].copy_from_slice(&(claimed_output.len() as u32).to_le_bytes());
    body[header..output_at].copy_from_slice(&target);
    body[output_at..].copy_from_slice(claimed_output);
    body
}

async fn send(
    context: &mut ProgramTestContext,
    ix: Instruction,
) -> (Result<(), TransactionError>, u64) {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let transaction = Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        blockhash,
    );
    let result = context
        .banks_client
        .process_transaction_with_metadata(transaction)
        .await
        .unwrap();
    let units = result
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.compute_units_consumed);
    (result.result, units)
}

fn instruction_with_accounts(tag: u8, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: vec![tag],
    }
}

#[tokio::test]
async fn restage_accepts_executor_and_refuses_executor_substitution_on_sbf() {
    let mut context = start().await;
    let executor = context.payer.pubkey();
    let nonce = 0x1260_0001;
    let (challenge, response) = challenge_fixture(&mut context, nonce, executor, true);
    set_owned(
        &mut context,
        response,
        response_fixture(challenge, executor, &[]),
    );
    let ix = instruction_with_accounts(
        126,
        vec![
            AccountMeta::new(response, false),
            AccountMeta::new(executor, true),
            AccountMeta::new(challenge, false),
        ],
    );
    let (result, units) = send(&mut context, ix).await;
    assert_eq!(result, Ok(()));
    assert!(units > 0);
    eprintln!("DCG_GENERIC_SBF_CU|126|honest|{units}");

    let mut context = start().await;
    let forged_executor = Pubkey::new_unique();
    let nonce = 0x1260_0002;
    let (challenge, response) = challenge_fixture(&mut context, nonce, forged_executor, true);
    set_owned(
        &mut context,
        response,
        response_fixture(challenge, forged_executor, &[]),
    );
    let ix = instruction_with_accounts(
        126,
        vec![
            AccountMeta::new(response, false),
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new(challenge, false),
        ],
    );
    let (result, units) = send(&mut context, ix).await;
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(733)
        ))
    );
    eprintln!("DCG_GENERIC_SBF_CU|126|executor-substitution|{units}");
}

#[tokio::test]
async fn verify_outputs_accepts_claim_and_rejects_mismatch_and_fixture_envelope_on_sbf() {
    let output = [0x21, 0x43, 0x65];
    let mut cases = vec![
        (0x1280_0001, output.to_vec(), output.to_vec(), None),
        (0x1280_0002, output.to_vec(), vec![0xFF, 0x43, 0x65], None),
    ];
    cases.push((
        0x1280_0003,
        Vec::new(),
        Vec::new(),
        Some(include_bytes!("fixtures/closure_v2_generic/entry-119.dgr1").as_slice()),
    ));
    for (nonce, committed, claimed, retained_fixture) in cases {
        let mut context = start().await;
        let executor = context.payer.pubkey();
        let (challenge, response) = challenge_fixture(&mut context, nonce, executor, true);
        let position = 2u32;
        let segment = 1u16;
        let entry = 7u32;
        let mut state = vec![0u8; DCR1_BYTES];
        state[..4].copy_from_slice(b"DCR1");
        state[4] = dcg_program::unified::challenge::PHASE_RESPOND;
        state[6..8].copy_from_slice(&dcg_program::unified::challenge::VERSION.to_le_bytes());
        state[8..40].copy_from_slice(executor.as_ref());
        state[40..72].copy_from_slice(executor.as_ref());
        state[72..104].copy_from_slice(&DESCRIPTOR);
        state[140..144].copy_from_slice(&nonce.to_le_bytes());
        state[144] = 1;
        state[146] =
            dcg_program::unified::address::challenge(&PROGRAM, &DESCRIPTOR, &executor, nonce)
                .1
                .value();
        state[147] = 1;
        state[148..156].copy_from_slice(&u64::MAX.to_le_bytes());
        let response_bump = dcg_program::closure_v2_response::address(&PROGRAM, &challenge)
            .1
            .value();
        state[dcg_program::unified::challenge::RESPONSE_BUMP_STAGED_AT] = response_bump;
        state[dcg_program::unified::challenge::RESPONSE_BUMP_AT] = response_bump;
        state[136..140].copy_from_slice(&entry.to_le_bytes());
        state[156..160].copy_from_slice(&position.to_le_bytes());
        state[160..162].copy_from_slice(&segment.to_le_bytes());
        state[170..174].copy_from_slice(&entry.to_le_bytes());
        state[174..176].copy_from_slice(&22u16.to_le_bytes());
        state[176] = 1;
        state[480] = 1;
        state[481] = response_bump;
        state[184..216].copy_from_slice(response.as_ref());
        set_owned(&mut context, challenge, state);
        let body = retained_fixture.map_or_else(
            || valid_output_body(position, segment, entry, &committed, &claimed),
            |fixture| fixture.to_vec(),
        );
        set_owned(
            &mut context,
            response,
            response_fixture(challenge, executor, &body),
        );
        let (result, units) = send(
            &mut context,
            instruction_with_accounts(
                128,
                vec![
                    AccountMeta::new(challenge, false),
                    AccountMeta::new_readonly(response, false),
                ],
            ),
        )
        .await;
        let name = if nonce == 0x1280_0001 {
            "honest"
        } else if nonce == 0x1280_0002 {
            "write-mismatch"
        } else {
            "retained-fixture"
        };
        if nonce == 0x1280_0001 {
            assert_eq!(result, Ok(()));
        } else {
            let expected = 734;
            assert_eq!(
                result,
                Err(TransactionError::InstructionError(
                    0,
                    InstructionError::Custom(expected)
                ))
            );
        }
        eprintln!("DCG_GENERIC_SBF_CU|128|{name}|{units}");
    }
}
