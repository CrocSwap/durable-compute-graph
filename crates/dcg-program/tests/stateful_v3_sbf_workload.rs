#![cfg(feature = "sbf-real-lifecycle-test")]

//! Stateful v3 proof on the feature-built SBF image. The first scenario uses a
//! 10 MB headerless primary state account and the fixed-address test engine.

use dcg_program::{
    hash::sha256, kernel::Kernel, stateful as sw, stateful::v3, stateful_test as app,
};
use solana_account::{Account, AccountSharedData};
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const RESOURCE: Pubkey = Pubkey::new_from_array(app::V3_RESOURCE_KEY);
const SYSTEM: Pubkey = system_program::ID;
const RESOURCE_LEN: usize = 4_096;
const STREAM_CAPACITY: u32 = 8;
const COMMANDS: [u8; 4] = [1, 2, 0xEE, 3];

fn keypair(seed: u8) -> Keypair {
    solana_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn session_pda(authority: &Pubkey, id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"dcg-session-v3", authority.as_ref(), &id.to_le_bytes()],
        &PROGRAM,
    )
    .0
}

fn stream_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-input-v3", session.as_ref()], &PROGRAM).0
}

fn state_pda(session: &Pubkey, index: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-state-v3", session.as_ref(), &[index]], &PROGRAM).0
}

fn view_pda(session: &Pubkey, role: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-view-v3", session.as_ref(), &[role]], &PROGRAM).0
}

fn instruction(tag: u8, payload: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(&payload);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn open_primary(payer: Pubkey, authority: Pubkey, id: u64, commitment: [u8; 32]) -> Instruction {
    let manifest = app::V3_FIXED_ENGINE.manifest();
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&id.to_le_bytes());
    payload.push(0); // indexed input policy
    payload.push(1); // one byte per command
    payload.extend_from_slice(&STREAM_CAPACITY.to_le_bytes());
    payload.push(8); // maximum steps per advance
    payload.extend_from_slice(&manifest.id.0);
    payload.extend_from_slice(&manifest.semantic_version.to_le_bytes());
    payload.extend_from_slice(&manifest.abi_version.to_le_bytes());
    payload.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    payload.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    payload.extend_from_slice(&[0xA5; 32]);
    payload.extend_from_slice(Pubkey::default().as_ref());
    payload.extend_from_slice(RESOURCE.as_ref());
    payload.extend_from_slice(&app::V3_RESOURCE_SCHEMA.id.to_le_bytes());
    payload.extend_from_slice(&app::V3_RESOURCE_SCHEMA.version.to_le_bytes());
    payload.extend_from_slice(&commitment);
    payload.push(1); // primary headerless state account
    instruction(
        sw::TAG_OPEN_SESSION,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session_pda(&authority, id), false),
            AccountMeta::new_readonly(RESOURCE, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_stream(payer: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STREAM,
        vec![v3::WIRE_VERSION, 0],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_primary_state(payer: Pubkey, session: Pubkey, resource: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 1];
    payload.extend_from_slice(&app::V3_FIXED_STATE_LEN.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource, false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn grow_state(payer: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STATE,
        vec![v3::WIRE_VERSION, v3::STATE_OP_GROW, 0],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(session, false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn begin_initialization(authority: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::STATE_OP_BEGIN_INITIALIZE];
    payload.extend_from_slice(&app::V3_FIXED_STATE_LEN.to_le_bytes());
    payload.extend_from_slice(&app::V3_INIT_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
        ],
    )
}

fn run_initialization(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::STATE_OP_RUN_INITIALIZE];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.extend_from_slice(&app::V3_INIT_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(RESOURCE, false),
        ],
    )
}

fn write_input(authority: Pubkey, session: Pubkey, sequence: u32, command: u8) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.push(1);
    payload.push(command);
    instruction(
        sw::TAG_WRITE_INPUT,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
        ],
    )
}

fn advance(authority: Pubkey, session: Pubkey, cursor: u32, steps: u8) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.push(steps);
    instruction(
        sw::TAG_ADVANCE,
        payload,
        vec![
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
        ],
    )
}

fn advance_with_substitute(
    substitute: Pubkey,
    authority: Pubkey,
    session: Pubkey,
    cursor: u32,
    steps: u8,
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.push(steps);
    instruction(
        sw::TAG_ADVANCE,
        payload,
        vec![
            AccountMeta::new(substitute, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
        ],
    )
}

fn anchor_primary(session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    instruction(
        sw::TAG_ANCHOR,
        payload,
        vec![
            AccountMeta::new_readonly(state_pda(&session, 0), false),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(stream_pda(&session), false),
        ],
    )
}

fn create_view(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 0];
    payload.extend_from_slice(&app::V3_VIEW_ABI);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&32u32.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(view_pda(&session, 0), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_workspace(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::WORKSPACE_ROLE];
    payload.extend_from_slice(&app::V3_VIEW_WORKSPACE_BYTES.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(view_pda(&session, v3::WORKSPACE_ROLE), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_staging_scratch(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::SCRATCH_ROLE];
    payload.extend_from_slice(&[0; 32]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&32u32.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(view_pda(&session, v3::SCRATCH_ROLE), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn publication_accounts(
    authority: Pubkey,
    session: Pubkey,
    outputs_writable: bool,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(state_pda(&session, 0), false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(session, false),
        AccountMeta::new_readonly(RESOURCE, false),
        if outputs_writable {
            AccountMeta::new(view_pda(&session, 0), false)
        } else {
            AccountMeta::new_readonly(view_pda(&session, 0), false)
        },
        AccountMeta::new(view_pda(&session, v3::WORKSPACE_ROLE), false),
        AccountMeta::new(view_pda(&session, v3::SCRATCH_ROLE), false),
    ]
}

fn begin_view(authority: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 0];
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&500_000u32.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication_accounts(authority, session, false),
    )
}

fn run_view(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 1];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.extend_from_slice(&500_000u32.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication_accounts(authority, session, false),
    )
}

fn commit_view(authority: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 2];
    payload.extend_from_slice(&0u32.to_le_bytes()); // state cursor
    payload.extend_from_slice(&32u32.to_le_bytes()); // staged cursor
    payload.extend_from_slice(&500_000u32.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication_accounts(authority, session, true),
    )
}

async fn send(
    context: &mut ProgramTestContext,
    ix: Instruction,
    signers: &[&Keypair],
    label: &str,
    expected: Result<(), u32>,
    emit: bool,
) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut all_signers = vec![&context.payer];
    all_signers.extend_from_slice(signers);
    let tx = Transaction::new(
        &all_signers,
        solana_message::Message::new(&[ix], Some(&context.payer.pubkey())),
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
        .map(|meta| meta.compute_units_consumed)
        .unwrap_or(0);
    let logs = result
        .metadata
        .as_ref()
        .map(|meta| meta.log_messages.join("\n"))
        .unwrap_or_default();
    match (expected, result.result) {
        (Ok(()), Ok(())) => {}
        (Err(want), Err(TransactionError::InstructionError(_, InstructionError::Custom(got))))
            if want == got => {}
        (want, got) => panic!("{label}: expected {want:?}, got {got:?}\n{logs}"),
    }
    if emit {
        eprintln!("stateful-v3 CU instruction={label} transaction={cu}");
    }
    cu
}

async fn send_many(
    context: &mut ProgramTestContext,
    instructions: Vec<Instruction>,
    signer: Option<&Keypair>,
    label: &str,
) -> Vec<u64> {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&context.payer];
    if let Some(signer) = signer {
        signers.push(signer);
    }
    let tx = Transaction::new(
        &signers,
        solana_message::Message::new(&instructions, Some(&context.payer.pubkey())),
        blockhash,
    );
    let result = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    assert_eq!(result.result, Ok(()), "{label}");
    let logs = result.metadata.as_ref().map(|meta| &meta.log_messages);
    let prefix = format!("Program {PROGRAM} consumed ");
    let values: Vec<u64> = logs
        .into_iter()
        .flatten()
        .filter(|line| line.starts_with(&prefix))
        .filter_map(|line| line.split_whitespace().nth(3)?.parse().ok())
        .collect();
    assert_eq!(values.len(), instructions.len(), "{label} CU log");
    eprintln!(
        "stateful-v3 CU batch={label} instruction_count={} each={values:?}",
        values.len()
    );
    values
}

async fn expect_compute_budget_exceeded(
    context: &mut ProgramTestContext,
    ix: Instruction,
    label: &str,
) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let tx = Transaction::new(
        &[&context.payer],
        solana_message::Message::new(&[ix], Some(&context.payer.pubkey())),
        blockhash,
    );
    let result = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    assert_eq!(
        result.result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::ComputationalBudgetExceeded
        )),
        "{label}"
    );
    let cu = result
        .metadata
        .as_ref()
        .map(|meta| meta.compute_units_consumed)
        .unwrap_or(0);
    eprintln!("stateful-v3 CU instruction={label} outcome=budget-exceeded transaction={cu}");
    cu
}

async fn account(context: &mut ProgramTestContext, key: Pubkey) -> Account {
    context
        .banks_client
        .get_account(key)
        .await
        .unwrap()
        .unwrap()
}

async fn start_sbf() -> (ProgramTestContext, Vec<u8>) {
    let out_dir = std::env::var("SBF_OUT_DIR")
        .or_else(|_| std::env::var("BPF_OUT_DIR"))
        .expect("set SBF_OUT_DIR to the sbf-real-lifecycle-test build output");
    let elf = std::fs::read(std::path::Path::new(&out_dir).join("dcg_program.so"))
        .expect("dcg_program.so in SBF_OUT_DIR");
    let mut test = ProgramTest::default();
    test.prefer_bpf(true);
    test.add_program("dcg_program", PROGRAM, None);
    test.add_genesis_account(
        RESOURCE,
        Account {
            lamports: 1_000_000,
            data: vec![0x5A; RESOURCE_LEN],
            owner: PROGRAM,
            executable: false,
            rent_epoch: 0,
        },
    );
    (test.start_with_context().await, elf)
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_primary_prefix_halt_resource_views_and_phased_init() {
    let (mut context, elf) = start_sbf().await;
    eprintln!(
        "stateful-v3 SBF image bytes={} sha256={:02x?}",
        elf.len(),
        sha256(&[&elf])
    );
    let payer = context.payer.pubkey();
    let authority = keypair(63);
    let id = 3;
    let session = session_pda(&authority.pubkey(), id);
    let stream = stream_pda(&session);
    let state = state_pda(&session, 0);
    let view = view_pda(&session, 0);
    let workspace = view_pda(&session, v3::WORKSPACE_ROLE);
    let resource = vec![0x5A; RESOURCE_LEN];
    let commitment = sha256(&[&resource]);

    send(
        &mut context,
        open_primary(payer, authority.pubkey(), id, commitment),
        &[&authority],
        "OPEN_SESSION-v3-primary-headerless",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3",
        Ok(()),
        true,
    )
    .await;
    send_many(
        &mut context,
        COMMANDS
            .iter()
            .enumerate()
            .map(|(sequence, command)| {
                write_input(authority.pubkey(), session, sequence as u32, *command)
            })
            .collect(),
        Some(&authority),
        "WRITE_INPUT-v3-four-slots",
    )
    .await;
    send(
        &mut context,
        create_primary_state(payer, session, RESOURCE),
        &[],
        "CREATE_STATE-v3-headerless-10mb",
        Ok(()),
        true,
    )
    .await;
    let growth_rounds =
        (app::V3_FIXED_STATE_LEN - v3::CHILD_GROW_BYTES).div_ceil(v3::CHILD_GROW_BYTES);
    let mut growth_cus = Vec::with_capacity(growth_rounds as usize);
    for batch_start in (0..growth_rounds).step_by(8) {
        let batch_end = (batch_start + 8).min(growth_rounds);
        let instructions = (batch_start..batch_end)
            .map(|_| grow_state(payer, session))
            .collect();
        growth_cus.extend(
            send_many(
                &mut context,
                instructions,
                None,
                &format!("GROW_STATE-v3-{batch_start}..{batch_end}"),
            )
            .await,
        );
    }
    let min_growth = *growth_cus.iter().min().unwrap();
    let max_growth = *growth_cus.iter().max().unwrap();
    eprintln!(
        "stateful-v3 CU GROW_STATE count={} min={min_growth} max={max_growth}",
        growth_cus.len()
    );
    assert_eq!(
        account(&mut context, state).await.data.len(),
        app::V3_FIXED_STATE_LEN as usize
    );
    assert_eq!(&account(&mut context, state).await.data[..16], &[0; 16]);

    send(
        &mut context,
        begin_initialization(authority.pubkey(), session),
        &[&authority],
        "BEGIN_INITIALIZATION-v3",
        Ok(()),
        true,
    )
    .await;
    let session_before_bad_schema = account(&mut context, session).await;
    let mut wrong_schema_session = session_before_bad_schema.clone();
    wrong_schema_session.data[1183..1187].copy_from_slice(&0xBAD0u32.to_le_bytes());
    context.set_account(&session, &AccountSharedData::from(wrong_schema_session));
    let state_before_bad_schema = account(&mut context, state).await.data;
    let mutated_session_bytes = account(&mut context, session).await.data;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-wrong-session-schema",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data,
        state_before_bad_schema
    );
    assert_eq!(
        account(&mut context, session).await.data,
        mutated_session_bytes
    );
    context.set_account(
        &session,
        &AccountSharedData::from(session_before_bad_schema),
    );

    let first_phase_cu = send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-phase-0",
        Ok(()),
        true,
    )
    .await;
    assert!(first_phase_cu < app::V3_INIT_COMPUTE_UNITS as u64);
    let state_after_first_init = account(&mut context, state).await.data;
    let session_after_first_init = account(&mut context, session).await.data;
    send(
        &mut context,
        advance(authority.pubkey(), session, 0, 4),
        &[&authority],
        "ADVANCE-v3-before-initialization-complete",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data,
        state_after_first_init
    );
    assert_eq!(
        account(&mut context, session).await.data,
        session_after_first_init
    );
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-stale-phase",
        Err(v3::REFUSAL_PHASE_CURSOR),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data,
        state_after_first_init
    );
    assert_eq!(
        account(&mut context, session).await.data,
        session_after_first_init
    );

    let mut init_cus = vec![first_phase_cu];
    let mut cursor = app::V3_INIT_PHASE_BYTES;
    while cursor < app::V3_FIXED_STATE_LEN {
        init_cus.push(
            send(
                &mut context,
                run_initialization(authority.pubkey(), session, cursor),
                &[&authority],
                &format!("RUN_INITIALIZATION-v3-phase-{cursor}"),
                Ok(()),
                false,
            )
            .await,
        );
        cursor += (app::V3_FIXED_STATE_LEN - cursor).min(app::V3_INIT_PHASE_BYTES);
    }
    eprintln!(
        "stateful-v3 CU RUN_INITIALIZATION phase_count={} min={} max={} all={init_cus:?}",
        init_cus.len(),
        init_cus.iter().min().unwrap(),
        init_cus.iter().max().unwrap()
    );
    let initialized = account(&mut context, state).await.data;
    assert_eq!(initialized.len(), app::V3_FIXED_STATE_LEN as usize);
    assert_eq!(&initialized[..RESOURCE_LEN], &resource);
    assert_eq!(&initialized[RESOURCE_LEN..RESOURCE_LEN + 32], &[0; 32]);

    send(
        &mut context,
        create_view(payer, session),
        &[],
        "CREATE_VIEW-v3-resource-output",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_workspace(payer, session),
        &[],
        "CREATE_VIEW-v3-render-workspace",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_staging_scratch(payer, session),
        &[],
        "CREATE_VIEW-v3-publication-staging",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        begin_view(authority.pubkey(), session),
        &[&authority],
        "BEGIN_PHASE-v3-render",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        run_view(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_PHASE-v3-resource-and-workspace",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(account(&mut context, view).await.data[128..], [0; 32]);
    assert_eq!(account(&mut context, workspace).await.data[128], 1);
    assert_eq!(
        &account(&mut context, workspace).await.data[129..133],
        &0u32.to_le_bytes()
    );
    send(
        &mut context,
        commit_view(authority.pubkey(), session),
        &[&authority],
        "COMMIT_PHASE-v3-view",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, view).await.data[128..],
        resource[..32]
    );

    let before_substitution_state = account(&mut context, state).await.data;
    let before_substitution_session = account(&mut context, session).await.data;
    send(
        &mut context,
        advance_with_substitute(RESOURCE, authority.pubkey(), session, 0, 4),
        &[&authority],
        "ADVANCE-v3-primary-account-substitution",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data,
        before_substitution_state
    );
    assert_eq!(
        account(&mut context, session).await.data,
        before_substitution_session
    );

    send(
        &mut context,
        advance(authority.pubkey(), session, 1, 4),
        &[&authority],
        "ADVANCE-v3-stale-cursor-atomic-refusal",
        Err(v3::REFUSAL_CURSOR),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data,
        before_substitution_state
    );
    assert_eq!(
        account(&mut context, session).await.data,
        before_substitution_session
    );

    let cu = send(
        &mut context,
        advance(authority.pubkey(), session, 0, 4),
        &[&authority],
        "ADVANCE-v3-commit-prefix-2-of-4-halt",
        Ok(()),
        true,
    )
    .await;
    assert!(cu < 1_400_000);
    let halted_session = account(&mut context, session).await.data;
    let halted_state = account(&mut context, state).await.data;
    let halted_stream = account(&mut context, stream).await.data;
    assert_eq!(halted_session[6], 2);
    assert_eq!(
        u32::from_le_bytes(halted_session[112..116].try_into().unwrap()),
        2
    );
    assert_eq!(
        u32::from_le_bytes(halted_session[1254..1258].try_into().unwrap()),
        app::V3_HALT_REASON
    );
    assert_eq!(
        u32::from_le_bytes(halted_session[1258..1262].try_into().unwrap()),
        2
    );
    assert_eq!(
        u64::from_le_bytes(
            halted_state[app::V3_FIXED_STATE_LEN as usize - 8..]
                .try_into()
                .unwrap()
        ),
        3
    );
    assert_eq!(
        u32::from_le_bytes(halted_stream[76..80].try_into().unwrap()),
        2
    );
    assert_eq!(
        u32::from_le_bytes(halted_stream[80..84].try_into().unwrap()),
        4
    );
    let anchor_cu = expect_compute_budget_exceeded(
        &mut context,
        anchor_primary(session, 2),
        "ANCHOR-v3-primary-headerless-state",
    )
    .await;
    assert_eq!(anchor_cu, 200_000);
    let anchored = account(&mut context, session).await.data;
    assert_eq!(
        u32::from_le_bytes(anchored[188..192].try_into().unwrap()),
        0
    );
    assert_eq!(&anchored[192..224], &[0; 32]);
}

fn open_default(payer: Pubkey, authority: Pubkey, id: u64) -> Instruction {
    let manifest = app::COUNTER.manifest();
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&id.to_le_bytes());
    payload.extend_from_slice(&[0, 1]);
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.push(2);
    payload.extend_from_slice(&manifest.id.0);
    payload.extend_from_slice(&manifest.semantic_version.to_le_bytes());
    payload.extend_from_slice(&manifest.abi_version.to_le_bytes());
    payload.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    payload.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    payload.extend_from_slice(&[0x33; 32]);
    payload.extend_from_slice(Pubkey::default().as_ref());
    payload.extend_from_slice(Pubkey::default().as_ref());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&[0; 32]);
    payload.push(0); // keep the existing headered state layout by default
    instruction(
        sw::TAG_OPEN_SESSION,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session_pda(&authority, id), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_default_layout_remains_headered() {
    let (mut context, _) = start_sbf().await;
    let payer = context.payer.pubkey();
    let authority = keypair(64);
    let id = 4;
    let session = session_pda(&authority.pubkey(), id);
    let stream = stream_pda(&session);
    let states = [state_pda(&session, 0), state_pda(&session, 1)];

    send(
        &mut context,
        open_default(payer, authority.pubkey(), id),
        &[&authority],
        "OPEN_SESSION-v3-default-layout",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-default",
        Ok(()),
        true,
    )
    .await;
    let mut create_payload = vec![v3::WIRE_VERSION, 2];
    create_payload.extend_from_slice(&8u32.to_le_bytes());
    create_payload.extend_from_slice(&8u32.to_le_bytes());
    send(
        &mut context,
        instruction(
            sw::TAG_CREATE_STATE,
            create_payload,
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(session, false),
                AccountMeta::new(states[0], false),
                AccountMeta::new(states[1], false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        ),
        &[],
        "CREATE_STATE-v3-default-headered",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(&account(&mut context, states[0]).await.data[..4], b"DSE3");
    for index in 0..2 {
        send(
            &mut context,
            write_input(authority.pubkey(), session, index, 1),
            &[&authority],
            &format!("WRITE_INPUT-v3-default-{index}"),
            Ok(()),
            true,
        )
        .await;
    }
    send(
        &mut context,
        instruction(
            sw::TAG_CREATE_STATE,
            vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
            vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(session, false),
                AccountMeta::new(states[0], false),
                AccountMeta::new(states[1], false),
            ],
        ),
        &[&authority],
        "INITIALIZE_STATE-v3-default",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        instruction(
            sw::TAG_ADVANCE,
            [vec![v3::WIRE_VERSION], 0u32.to_le_bytes().to_vec(), vec![2]].concat(),
            vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(session, false),
                AccountMeta::new(stream, false),
                AccountMeta::new(states[0], false),
                AccountMeta::new(states[1], false),
            ],
        ),
        &[&authority],
        "ADVANCE-v3-default-headered",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, states[0]).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        2
    );
}
