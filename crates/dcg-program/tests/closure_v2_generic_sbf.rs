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
    let target = malformed_refusal(&mut context, 120).await;
    let reads = malformed_refusal(&mut context, 121).await;
    let restage = malformed_refusal(&mut context, 126).await;
    let outputs = malformed_refusal(&mut context, 128).await;
    assert!(target > 0);
    assert!(reads > 0);
    assert!(restage > 0);
    assert!(outputs > 0);
}

#[tokio::test]
async fn generic_part_b_tags_remain_refused_on_sbf() {
    let mut context = start().await;
    for tag in [122, 123, 124, 127, 129] {
        let (result, units) = send(&mut context, instruction(tag)).await;
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::InvalidInstructionData
            )),
            "tag {tag} remains reserved until its generic engine path lands"
        );
        assert!(units > 0);
        eprintln!("DCG_GENERIC_SBF_CU|{tag}|part-b-refused|{units}");
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
    let challenger = context.payer.pubkey();
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
    state[146] = challenge_bump.value();
    state[147] = 1;
    state[148..156].copy_from_slice(&u64::MAX.to_le_bytes());
    state[dcg_program::unified::challenge::RESPONSE_BUMP_STAGED_AT] = response_bump.value();
    state[dcg_program::unified::challenge::RESPONSE_BUMP_AT] = response_bump.value();
    if staged_response {
        state[176] = 1;
        state[184..216].copy_from_slice(response.as_ref());
    }
    set_owned(context, challenge, state);
    (challenge, response)
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
        state[dcg_program::unified::challenge::RESPONSE_BUMP_STAGED_AT] =
            dcg_program::closure_v2_response::address(&PROGRAM, &challenge)
                .1
                .value();
        state[dcg_program::unified::challenge::RESPONSE_BUMP_AT] =
            dcg_program::closure_v2_response::address(&PROGRAM, &challenge)
                .1
                .value();
        state[136..140].copy_from_slice(&entry.to_le_bytes());
        state[156..160].copy_from_slice(&position.to_le_bytes());
        state[160..162].copy_from_slice(&segment.to_le_bytes());
        state[170..174].copy_from_slice(&entry.to_le_bytes());
        state[174..176].copy_from_slice(&1u16.to_le_bytes());
        state[176] = 1;
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
