//! Runs the ByteSum application lifecycle in the compiled SBF image.
//!
//! This is intentionally separate from native `cargo test`: the test requires
//! `SBF_OUT_DIR/dcg_program.so`, and every measured transaction has one SBF
//! application instruction so its consumed compute units are directly
//! attributable.
#![cfg(feature = "sbf-lifecycle-test")]

use dcg_program::{kernel::test_kernel, test_lifecycle as demo};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD8; 32]);
const STAKE: u64 = demo::TEST_STAKE_LAMPORTS;
const SYSTEM: Pubkey = system_program::ID;

fn fixed_keypair(seed: u8) -> solana_keypair::Keypair {
    solana_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn template_pda(authority: &Pubkey, case_id: u8) -> Pubkey {
    Pubkey::find_program_address(
        &[b"dcg-test-template", authority.as_ref(), &[case_id]],
        &PROGRAM,
    )
    .0
}

fn document_pda(template: &Pubkey, case_id: u8) -> Pubkey {
    Pubkey::find_program_address(
        &[b"dcg-test-document", template.as_ref(), &[case_id]],
        &PROGRAM,
    )
    .0
}

fn bond_pda(document: &Pubkey, case_id: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-test-bond", document.as_ref(), &[case_id]], &PROGRAM).0
}

fn ix(_tag: u8, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn template_ix(case_id: u8, template: Pubkey, payer: Pubkey) -> Instruction {
    let mut data = vec![demo::TAG_REGISTER_TEMPLATE, case_id];
    data.extend_from_slice(b"dcg-test-sum-v1\0");
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&test_kernel::MODE_OPTIMISTIC_V1.id.to_le_bytes());
    data.extend_from_slice(&test_kernel::MODE_OPTIMISTIC_V1.version.to_le_bytes());
    ix(
        demo::TAG_REGISTER_TEMPLATE,
        data,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(template, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn entries(case_id: u8, wrong_step: Option<usize>) -> (Vec<u8>, [[u8; 32]; 4], [[u8; 32]; 4]) {
    let inputs: [&[u8]; 4] = [&[1, 2, 3], &[7], &[10, 11], &[4, 5, 6]];
    let mut encoded = Vec::with_capacity(4 * 17);
    let mut actual_leaves = [[0u8; 32]; 4];
    let mut claimed_leaves = [[0u8; 32]; 4];
    for (index, input) in inputs.iter().enumerate() {
        let sum = input.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let actual = sum.to_le_bytes();
        let mut claimed = actual;
        if wrong_step == Some(index) {
            claimed = (sum + 1).to_le_bytes();
        }
        encoded.push(input.len() as u8);
        encoded.extend_from_slice(input);
        encoded.resize(encoded.len() + 8 - input.len(), 0);
        encoded.extend_from_slice(&claimed);
        actual_leaves[index] = demo::leaf_for_test(case_id, index, input, &actual);
        claimed_leaves[index] = demo::leaf_for_test(case_id, index, input, &claimed);
    }
    (encoded, actual_leaves, claimed_leaves)
}

fn init_document_ix(
    case_id: u8,
    template: Pubkey,
    document: Pubkey,
    bond: Pubkey,
    executor: Pubkey,
    entry_bytes: &[u8],
) -> Instruction {
    assert_eq!(entry_bytes.len(), 4 * 17);
    let mut data = vec![demo::TAG_INIT_DOCUMENT, case_id];
    data.extend_from_slice(&STAKE.to_le_bytes());
    data.extend_from_slice(entry_bytes);
    ix(
        demo::TAG_INIT_DOCUMENT,
        data,
        vec![
            AccountMeta::new(executor, true),
            AccountMeta::new_readonly(template, false),
            AccountMeta::new(document, false),
            AccountMeta::new(bond, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn executor_doc_ix(
    tag: u8,
    case_id: u8,
    payer: Pubkey,
    template: Pubkey,
    document: Pubkey,
) -> Instruction {
    ix(
        tag,
        vec![tag, case_id],
        vec![
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new_readonly(template, false),
            AccountMeta::new(document, false),
        ],
    )
}

async fn send(
    context: &mut ProgramTestContext,
    instruction: Instruction,
    extra_signers: &[&solana_keypair::Keypair],
    label: &str,
    should_succeed: bool,
) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&context.payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new(
        &signers,
        solana_message::Message::new(&[instruction], Some(&context.payer.pubkey())),
        blockhash,
    );
    let result = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    let cu = result
        .metadata
        .as_ref()
        .map(|metadata| metadata.compute_units_consumed)
        .unwrap_or(0);
    println!("SBF_CU|{label}|{cu}");
    assert_eq!(
        result.result.is_ok(),
        should_succeed,
        "{label}: {:?}",
        result.result
    );
    cu
}

async fn balance(context: &mut ProgramTestContext, key: Pubkey) -> u64 {
    context.banks_client.get_balance(key).await.unwrap()
}

async fn account(context: &mut ProgramTestContext, key: Pubkey) -> Account {
    context
        .banks_client
        .get_account(key)
        .await
        .unwrap()
        .unwrap_or_default()
}

async fn prepare(
    context: &mut ProgramTestContext,
    case_id: u8,
    wrong_step: Option<usize>,
) -> (Pubkey, Pubkey, Pubkey, [[u8; 32]; 4], [[u8; 32]; 4]) {
    let payer = context.payer.pubkey();
    let template = template_pda(&payer, case_id);
    let document = document_pda(&template, case_id);
    let bond = bond_pda(&document, case_id);
    let (entry_bytes, actual_leaves, claim_leaves) = entries(case_id, wrong_step);
    send(
        context,
        template_ix(case_id, template, payer),
        &[],
        &format!("case{case_id}.register"),
        true,
    )
    .await;
    send(
        context,
        ix(
            demo::TAG_ADMIT,
            vec![demo::TAG_ADMIT, case_id],
            vec![
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new(template, false),
            ],
        ),
        &[],
        &format!("case{case_id}.admit"),
        true,
    )
    .await;
    send(
        context,
        init_document_ix(case_id, template, document, bond, payer, &entry_bytes),
        &[],
        &format!("case{case_id}.init_document"),
        true,
    )
    .await;
    send(
        context,
        executor_doc_ix(demo::TAG_LAND_ROOTS, case_id, payer, template, document),
        &[],
        &format!("case{case_id}.land_roots"),
        true,
    )
    .await;
    send(
        context,
        executor_doc_ix(demo::TAG_FINALIZE, case_id, payer, template, document),
        &[],
        &format!("case{case_id}.finalize"),
        true,
    )
    .await;
    (template, document, bond, actual_leaves, claim_leaves)
}

#[tokio::test]
async fn bytesum_sbf_honest_and_cheat_optimistic_lifecycles() {
    let out_dir =
        std::env::var("SBF_OUT_DIR").expect("set SBF_OUT_DIR to the SBF build output directory");
    assert!(std::path::Path::new(&out_dir)
        .join("dcg_program.so")
        .is_file());
    let payer = fixed_keypair(11);
    let mut program_test = ProgramTest::new("dcg_program", PROGRAM, None);
    program_test.prefer_bpf(true);
    program_test.add_genesis_account(
        payer.pubkey(),
        Account {
            lamports: 100_000_000_000,
            data: vec![],
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        },
    );
    let mut context = program_test.start_with_context().await;
    context.payer = payer;
    let payer = context.payer.pubkey();

    // One short malformed wire input for every lifecycle/dispute stage.
    for tag in demo::TAG_REGISTER_TEMPLATE..=demo::TAG_CLOSE {
        send(
            &mut context,
            ix(tag, vec![tag], vec![]),
            &[],
            &format!("malformed.tag{tag}"),
            false,
        )
        .await;
    }

    // Honest lifecycle: registry/template, admission, init, root landing,
    // finalize, model resolution and rent close.
    let (template, document, bond, _actual, _claim) = prepare(&mut context, 1, None).await;
    let resolve = executor_doc_ix(demo::TAG_RESOLVE, 1, payer, template, document);
    send(&mut context, resolve, &[], "honest.resolve", true).await;
    let refund = fixed_keypair(12);
    let before_refund = balance(&mut context, refund.pubkey()).await;
    let refundable = account(&mut context, template).await.lamports
        + account(&mut context, document).await.lamports
        + account(&mut context, bond).await.lamports;
    send(
        &mut context,
        ix(
            demo::TAG_CLOSE,
            vec![demo::TAG_CLOSE, 1],
            vec![
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new(refund.pubkey(), false),
                AccountMeta::new(template, false),
                AccountMeta::new(document, false),
                AccountMeta::new(bond, false),
            ],
        ),
        &[],
        "honest.close",
        true,
    )
    .await;
    assert_eq!(
        balance(&mut context, refund.pubkey()).await - before_refund,
        refundable
    );
    assert_eq!(account(&mut context, document).await.lamports, 0);

    // Cheat lifecycle: the executor commits one wrong output. The challenger
    // supplies the honest root, proves two authenticated bisection rounds, and
    // ByteSum::OptimisticReplay re-executes the disputed entry in the SBF image.
    let (template, document, bond, actual_leaves, claim_leaves) =
        prepare(&mut context, 2, Some(2)).await;
    let actual_root = demo::root_for_test(&actual_leaves, 2);
    let claim_root = demo::root_for_test(&claim_leaves, 2);
    assert_ne!(actual_root, claim_root);
    let challenger = fixed_keypair(13);
    let challenge_balance_before = balance(&mut context, challenger.pubkey()).await;
    let mut challenge_data = vec![demo::TAG_CHALLENGE, 2];
    challenge_data.extend_from_slice(&actual_root);
    send(
        &mut context,
        ix(
            demo::TAG_CHALLENGE,
            challenge_data,
            vec![
                AccountMeta::new(challenger.pubkey(), true),
                AccountMeta::new_readonly(template, false),
                AccountMeta::new(document, false),
            ],
        ),
        &[&challenger],
        "cheat.challenge",
        true,
    )
    .await;
    for (round, (level, start)) in [(2, 0), (1, 2)].into_iter().enumerate() {
        let (claim_left, claim_right) = demo::children_for_test(2, level, start, &claim_leaves);
        let (actual_left, actual_right) = demo::children_for_test(2, level, start, &actual_leaves);
        let mut data = vec![demo::TAG_BISECT, 2];
        data.extend_from_slice(&claim_left);
        data.extend_from_slice(&claim_right);
        data.extend_from_slice(&actual_left);
        data.extend_from_slice(&actual_right);
        send(
            &mut context,
            ix(
                demo::TAG_BISECT,
                data,
                vec![
                    AccountMeta::new_readonly(challenger.pubkey(), true),
                    AccountMeta::new(document, false),
                ],
            ),
            &[&challenger],
            &format!("cheat.bisect{round}"),
            true,
        )
        .await;
    }
    let leaf_state = account(&mut context, document).await.data;
    assert_eq!(leaf_state[232], 2);
    assert_eq!(leaf_state[233], 0);
    assert_ne!(&leaf_state[168..200], &leaf_state[200..232]);
    send(
        &mut context,
        ix(
            demo::TAG_REPLAY,
            vec![demo::TAG_REPLAY, 2],
            vec![
                AccountMeta::new_readonly(challenger.pubkey(), true),
                AccountMeta::new_readonly(template, false),
                AccountMeta::new(document, false),
            ],
        ),
        &[&challenger],
        "cheat.replay",
        true,
    )
    .await;
    let ruling = account(&mut context, document).await.data;
    assert_eq!(ruling[234], 1, "the executor should lose the challenge");
    send(
        &mut context,
        ix(
            demo::TAG_SETTLE,
            vec![demo::TAG_SETTLE, 2],
            vec![
                AccountMeta::new(payer, false),
                AccountMeta::new(challenger.pubkey(), false),
                AccountMeta::new(document, false),
                AccountMeta::new(bond, false),
            ],
        ),
        &[],
        "cheat.settle",
        true,
    )
    .await;
    assert_eq!(
        balance(&mut context, challenger.pubkey()).await - challenge_balance_before,
        STAKE,
        "the challenger receives the executor's test bond"
    );
    let refund = fixed_keypair(14);
    let before_refund = balance(&mut context, refund.pubkey()).await;
    let refundable = account(&mut context, template).await.lamports
        + account(&mut context, document).await.lamports
        + account(&mut context, bond).await.lamports;
    send(
        &mut context,
        ix(
            demo::TAG_CLOSE,
            vec![demo::TAG_CLOSE, 2],
            vec![
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new(refund.pubkey(), false),
                AccountMeta::new(template, false),
                AccountMeta::new(document, false),
                AccountMeta::new(bond, false),
            ],
        ),
        &[],
        "cheat.close",
        true,
    )
    .await;
    assert_eq!(
        balance(&mut context, refund.pubkey()).await - before_refund,
        refundable
    );
    assert_eq!(account(&mut context, document).await.lamports, 0);
}
