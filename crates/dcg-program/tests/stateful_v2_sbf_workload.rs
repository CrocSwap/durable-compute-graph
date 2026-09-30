#![cfg(feature = "sbf-real-lifecycle-test")]

//! Scaled stateful v2 ProgramTest. Every call below is submitted to the actual
//! feature-built SBF image; host helpers only construct transactions/readback.

use dcg_program::{
    hash::sha256, kernel::Kernel, stateful as sw, stateful::v2, stateful_test as app,
};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::collections::BTreeMap;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const RESOURCE: Pubkey = Pubkey::new_from_array(app::WORKLOAD_RESOURCE_KEY);
const WRONG_RESOURCE: Pubkey = Pubkey::new_from_array([0xC2; 32]);
const SYSTEM: Pubkey = system_program::ID;
const STEPS: u32 = 1_001;

fn keypair(seed: u8) -> Keypair {
    solana_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn session_pda(authority: &Pubkey, id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"dcg-session-v2", authority.as_ref(), &id.to_le_bytes()],
        &PROGRAM,
    )
    .0
}

fn stream_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-input-v2", session.as_ref()], &PROGRAM).0
}

fn state_pda(session: &Pubkey, index: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-state-v2", session.as_ref(), &[index]], &PROGRAM).0
}

fn view_pda(session: &Pubkey, role: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-view-v2", session.as_ref(), &[role]], &PROGRAM).0
}

fn scratch_pda(session: &Pubkey) -> Pubkey {
    view_pda(session, v2::SCRATCH_ROLE)
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

fn open_session(payer: Pubkey, authority: Pubkey, id: u64) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION];
    payload.extend_from_slice(&id.to_le_bytes());
    payload.push(0); // indexed input policy
    payload.push(1); // one byte per command
    payload.extend_from_slice(&64u32.to_le_bytes()); // first stream window
    payload.push(8); // max steps per transition instruction
    payload.extend_from_slice(&app::SCALED_WORKLOAD.manifest().id.0);
    payload.extend_from_slice(
        &app::SCALED_WORKLOAD
            .manifest()
            .semantic_version
            .to_le_bytes(),
    );
    payload.extend_from_slice(&app::SCALED_WORKLOAD.manifest().abi_version.to_le_bytes());
    payload.extend_from_slice(&v2::MODE_CONSENSUS_V2.id.to_le_bytes());
    payload.extend_from_slice(&v2::MODE_CONSENSUS_V2.version.to_le_bytes());
    payload.extend_from_slice(&[0xA5; 32]); // session input commitment, unchanged by growth
    payload.extend_from_slice(Pubkey::default().as_ref()); // indexed policy fixes writer=authority
    payload.extend_from_slice(RESOURCE.as_ref());
    payload.extend_from_slice(&app::WORKLOAD_RESOURCE_SCHEMA.id.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_RESOURCE_SCHEMA.version.to_le_bytes());
    payload.extend_from_slice(&sha256(&[app::WORKLOAD_RESOURCE_BYTES]));
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
        vec![v2::WIRE_VERSION, 0],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn grow_stream(payer: Pubkey, session: Pubkey, capacity: u32) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 1];
    payload.extend_from_slice(&capacity.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STREAM,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_state(payer: Pubkey, session: Pubkey, resource: Pubkey) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 2];
    payload.extend_from_slice(&16u32.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_VIEW_BYTES.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource, false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new(state_pda(&session, 1), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn grow_state(payer: Pubkey, session: Pubkey, index: u8) -> Instruction {
    instruction(
        sw::TAG_CREATE_STATE,
        vec![v2::WIRE_VERSION, v2::STATE_OP_GROW, index],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(session, false),
            AccountMeta::new(state_pda(&session, index), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn initialize_state(authority: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STATE,
        vec![v2::WIRE_VERSION, v2::STATE_OP_INITIALIZE],
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(RESOURCE, false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new(state_pda(&session, 1), false),
        ],
    )
}

fn grow_view(payer: Pubkey, session: Pubkey, role: u8) -> Instruction {
    instruction(
        sw::TAG_CREATE_VIEW,
        vec![v2::WIRE_VERSION, v2::VIEW_OP_GROW, role],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(session, false),
            AccountMeta::new(view_pda(&session, role), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn growth_rounds(len: u32) -> u32 {
    len.saturating_sub(v2::CHILD_GROW_BYTES)
        .div_ceil(v2::CHILD_GROW_BYTES)
}

fn create_view(
    payer: Pubkey,
    session: Pubkey,
    role: u8,
    abi: [u8; 32],
    offset: u32,
    len: u32,
) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, role];
    payload.extend_from_slice(&abi);
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&len.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(view_pda(&session, role), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_scratch(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, v2::SCRATCH_ROLE];
    payload.extend_from_slice(&[0; 32]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_VIEW_BYTES.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(scratch_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn write_input(authority: Pubkey, session: Pubkey, sequence: u32, command: u8) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION];
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
    let mut payload = vec![v2::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.push(steps);
    instruction(
        sw::TAG_ADVANCE,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new(state_pda(&session, 1), false),
        ],
    )
}

fn publication(authority: Pubkey, session: Pubkey, outputs_writable: bool) -> Vec<AccountMeta> {
    let mut accounts = vec![
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(session, false),
        AccountMeta::new_readonly(state_pda(&session, 0), false),
        AccountMeta::new_readonly(state_pda(&session, 1), false),
    ];
    for role in 0..=8 {
        accounts.push(if outputs_writable {
            AccountMeta::new(view_pda(&session, role), false)
        } else {
            AccountMeta::new_readonly(view_pda(&session, role), false)
        });
    }
    accounts.push(AccountMeta::new(scratch_pda(&session), false));
    accounts
}

fn begin_phase(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 0];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_PHASE_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication(authority, session, false),
    )
}

fn run_phase(authority: Pubkey, session: Pubkey, phase_cursor: u32) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 1];
    payload.extend_from_slice(&phase_cursor.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_PHASE_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication(authority, session, false),
    )
}

fn commit_phase(
    authority: Pubkey,
    session: Pubkey,
    state_cursor: u32,
    phase_cursor: u32,
) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 2];
    payload.extend_from_slice(&state_cursor.to_le_bytes());
    payload.extend_from_slice(&phase_cursor.to_le_bytes());
    payload.extend_from_slice(&app::WORKLOAD_PHASE_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        publication(authority, session, true),
    )
}

fn abort_phase(authority: Pubkey, session: Pubkey, phase_state_cursor: u32) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION, 3];
    payload.extend_from_slice(&phase_state_cursor.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
        ],
    )
}

fn close_child(session: Pubkey, child: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    instruction(
        sw::TAG_CLOSE_ACCOUNT,
        vec![v2::WIRE_VERSION, kind],
        vec![
            AccountMeta::new(session, false),
            AccountMeta::new(child, false),
            AccountMeta::new(refund, false),
        ],
    )
}

fn halt(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v2::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    instruction(
        sw::TAG_HALT_SESSION,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
        ],
    )
}

fn close_session(session: Pubkey, refund: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CLOSE_ACCOUNT,
        vec![v2::WIRE_VERSION, v2::KIND_SESSION],
        vec![
            AccountMeta::new(session, false),
            AccountMeta::new(refund, false),
        ],
    )
}

async fn send(
    context: &mut ProgramTestContext,
    ix: Instruction,
    extra_signers: &[&Keypair],
    label: &str,
    expected: Result<(), u32>,
) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&context.payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new(
        &signers,
        solana_message::Message::new(&[ix.clone()], Some(&context.payer.pubkey())),
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
    match (expected, result.result) {
        (Ok(()), Ok(())) => {}
        (Err(want), Err(TransactionError::InstructionError(_, InstructionError::Custom(got))))
            if want == got => {}
        (want, got) => panic!("{label}: expected {want:?}, got {got:?}"),
    }
    eprintln!(
        "stateful-v2 CU label={label} tag={} outcome={expected:?} transaction_cu={cu}",
        ix.data[0]
    );
    cu
}

async fn send_many(
    context: &mut ProgramTestContext,
    instructions: Vec<Instruction>,
    extra_signers: &[&Keypair],
    label: &str,
) -> u64 {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&context.payer];
    signers.extend_from_slice(extra_signers);
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
    let total = result
        .metadata
        .as_ref()
        .map(|meta| meta.compute_units_consumed)
        .unwrap_or(0);
    let logs = result.metadata.as_ref().map(|meta| &meta.log_messages);
    let program_prefix = format!("Program {PROGRAM} consumed ");
    let consumed: Vec<u64> = logs
        .into_iter()
        .flatten()
        .filter(|line| line.starts_with(&program_prefix))
        .filter_map(|line| line.split_whitespace().nth(3)?.parse().ok())
        .collect();
    let mut by_tag: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
    for (index, ix) in instructions.iter().enumerate() {
        if let Some(cu) = consumed.get(index) {
            by_tag.entry(ix.data[0]).or_default().push(*cu);
        }
    }
    for (tag, mut values) in by_tag {
        values.sort_unstable();
        let median = values[values.len() / 2];
        eprintln!(
            "stateful-v2 CU batch={label} tag={tag} count={} min={} median={} max={}",
            values.len(),
            values[0],
            median,
            values[values.len() - 1]
        );
    }
    eprintln!(
        "stateful-v2 CU batch={label} transaction_cu={total} instruction_count={}",
        instructions.len()
    );
    total
}

async fn account(context: &mut ProgramTestContext, key: Pubkey) -> Account {
    context
        .banks_client
        .get_account(key)
        .await
        .unwrap()
        .unwrap()
}

async fn start_sbf() -> ProgramTestContext {
    let out_dir = std::env::var("SBF_OUT_DIR")
        .or_else(|_| std::env::var("BPF_OUT_DIR"))
        .expect("set SBF_OUT_DIR to the sbf-real-lifecycle-test build output");
    let elf = std::fs::read(std::path::Path::new(&out_dir).join("dcg_program.so"))
        .expect("dcg_program.so in SBF_OUT_DIR");
    let mut test = ProgramTest::default();
    test.prefer_bpf(true);
    test.add_program("dcg_program", PROGRAM, None);
    for (key, bytes) in [
        (RESOURCE, app::WORKLOAD_RESOURCE_BYTES),
        (WRONG_RESOURCE, app::WORKLOAD_RESOURCE_BYTES),
    ] {
        test.add_genesis_account(
            key,
            Account {
                lamports: 1_000_000,
                data: bytes.to_vec(),
                owner: PROGRAM,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    let context = test.start_with_context().await;
    eprintln!(
        "stateful-v2 SBF image bytes={} program={PROGRAM}",
        elf.len()
    );
    context
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v2_windows_resources_phased_views_and_lifecycle() {
    let mut context = start_sbf().await;
    let payer = context.payer.pubkey();
    let authority = keypair(31);
    let stranger = keypair(32);
    let session = session_pda(&authority.pubkey(), 10);
    let stream = stream_pda(&session);
    let states = [state_pda(&session, 0), state_pda(&session, 1)];
    let scratch = scratch_pda(&session);
    let output_keys: Vec<Pubkey> = (0..=8).map(|role| view_pda(&session, role)).collect();

    send(
        &mut context,
        open_session(payer, authority.pubkey(), 10),
        &[&authority],
        "v2-open-session",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "v2-create-stream-window-64",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        close_child(session, stream, authority.pubkey(), v2::KIND_STREAM),
        &[],
        "v2-close-live-control",
        Err(v2::REFUSAL_LIVE),
    )
    .await;

    let before_bad_resource = account(&mut context, session).await.data;
    send(
        &mut context,
        create_state(payer, session, WRONG_RESOURCE),
        &[],
        "v2-wrong-resource-control",
        Err(v2::REFUSAL_RESOURCE),
    )
    .await;
    assert_eq!(
        account(&mut context, session).await.data,
        before_bad_resource
    );
    assert!(context
        .banks_client
        .get_account(states[0])
        .await
        .unwrap()
        .is_none());
    assert!(context
        .banks_client
        .get_account(states[1])
        .await
        .unwrap()
        .is_none());

    send(
        &mut context,
        create_state(payer, session, RESOURCE),
        &[],
        "v2-create-authenticated-large-state",
        Ok(()),
    )
    .await;
    let state_growth_rounds = growth_rounds(app::WORKLOAD_VIEW_BYTES);
    for round in 0..state_growth_rounds {
        send_many(
            &mut context,
            vec![grow_state(payer, session, 1)],
            &[],
            &format!("v2-grow-state-{round}"),
        )
        .await;
    }
    send(
        &mut context,
        initialize_state(authority.pubkey(), session),
        &[&authority],
        "v2-authenticate-and-initialize-state",
        Ok(()),
    )
    .await;
    let initial_state = account(&mut context, states[1]).await;
    assert_eq!(
        &initial_state.data[128..128 + app::WORKLOAD_RESOURCE_BYTES.len()],
        app::WORKLOAD_RESOURCE_BYTES
    );
    for role in 0..=8 {
        let (abi, offset, len) = if role == 0 {
            (app::WORKLOAD_SNAPSHOT_ABI, 16, app::WORKLOAD_SNAPSHOT_BYTES)
        } else {
            let strip = role as u32 - 1;
            (
                app::WORKLOAD_STRIP_ABIS[strip as usize],
                16 + app::WORKLOAD_SNAPSHOT_BYTES + strip * app::WORKLOAD_STRIP_BYTES,
                app::WORKLOAD_STRIP_BYTES,
            )
        };
        send(
            &mut context,
            create_view(payer, session, role, abi, offset, len),
            &[],
            "v2-create-view",
            Ok(()),
        )
        .await;
    }
    send(
        &mut context,
        create_scratch(payer, session),
        &[],
        "v2-create-phase-scratch",
        Ok(()),
    )
    .await;
    let view_growth_rounds =
        growth_rounds(app::WORKLOAD_SNAPSHOT_BYTES).max(growth_rounds(app::WORKLOAD_VIEW_BYTES));
    for round in 0..view_growth_rounds {
        let mut instructions = Vec::new();
        if round < growth_rounds(app::WORKLOAD_SNAPSHOT_BYTES) {
            instructions.push(grow_view(payer, session, 0));
        }
        if round < growth_rounds(app::WORKLOAD_VIEW_BYTES) {
            instructions.push(grow_view(payer, session, v2::SCRATCH_ROLE));
        }
        send_many(
            &mut context,
            instructions,
            &[],
            &format!("v2-grow-view-round-{round}"),
        )
        .await;
    }

    // The first 64-command window deliberately omits sequence 7. ADVANCE must
    // refuse the gap atomically; filling it then permits the same session to
    // continue, and a second write to that absolute slot is refused.
    let first_window: Vec<Instruction> = (0..64)
        .filter(|sequence| *sequence != 7)
        .map(|sequence| write_input(authority.pubkey(), session, sequence, 1))
        .collect();
    for (batch, instructions) in first_window.chunks(32).enumerate() {
        send_many(
            &mut context,
            instructions.to_vec(),
            &[&authority],
            &format!("v2-window-0-deposit-{batch}"),
        )
        .await;
    }
    let session_before_gap = account(&mut context, session).await.data;
    let stream_before_gap = account(&mut context, stream).await.data;
    let state_before_gap = account(&mut context, states[0]).await.data;
    send(
        &mut context,
        advance(authority.pubkey(), session, 0, 8),
        &[&authority],
        "v2-input-gap-control",
        Err(v2::REFUSAL_INPUT_GAP),
    )
    .await;
    assert_eq!(
        account(&mut context, session).await.data,
        session_before_gap
    );
    assert_eq!(account(&mut context, stream).await.data, stream_before_gap);
    assert_eq!(
        account(&mut context, states[0]).await.data,
        state_before_gap
    );
    send(
        &mut context,
        write_input(authority.pubkey(), session, 7, 1),
        &[&authority],
        "v2-fill-input-gap",
        Ok(()),
    )
    .await;
    let stream_before_double = account(&mut context, stream).await.data;
    send(
        &mut context,
        write_input(authority.pubkey(), session, 7, 2),
        &[&authority],
        "v2-double-input-control",
        Err(v2::REFUSAL_DUPLICATE_SLOT),
    )
    .await;
    assert_eq!(
        account(&mut context, stream).await.data,
        stream_before_double
    );

    let mut first_advances = Vec::new();
    for step in 0..8 {
        first_advances.push(advance(authority.pubkey(), session, step * 8, 8));
    }
    send_many(
        &mut context,
        first_advances,
        &[&authority],
        "v2-advance-first-window",
    )
    .await;
    assert_eq!(
        account(&mut context, session).await.data[112..116],
        64u32.to_le_bytes()
    );

    send(
        &mut context,
        grow_stream(payer, session, 576),
        &[],
        "v2-grow-stream-64-to-576",
        Ok(()),
    )
    .await;
    assert_eq!(
        account(&mut context, stream).await.data.len(),
        128 + 576 * 16
    );
    assert_eq!(
        &account(&mut context, stream).await.data[40..72],
        &[0xA5; 32]
    );

    async fn process_window(
        context: &mut ProgramTestContext,
        authority: &Keypair,
        session: Pubkey,
        first: u32,
        count: u32,
    ) {
        let writes: Vec<Instruction> = (first..first + count)
            .map(|sequence| write_input(authority.pubkey(), session, sequence, 1))
            .collect();
        for (batch, instructions) in writes.chunks(32).enumerate() {
            send_many(
                context,
                instructions.to_vec(),
                &[authority],
                &format!("v2-deposit-{first}-{}-{batch}", first + count),
            )
            .await;
        }
        let mut advances = Vec::new();
        let mut cursor = first;
        let end = first + count;
        while cursor < end {
            let steps = (end - cursor).min(8) as u8;
            advances.push(advance(authority.pubkey(), session, cursor, steps));
            cursor += steps as u32;
        }
        send_many(
            context,
            advances,
            &[authority],
            &format!("v2-advance-{first}-{}", first + count),
        )
        .await;
    }

    let mut cursor = 64u32;
    while cursor < 576 {
        process_window(&mut context, &authority, session, cursor, 64).await;
        cursor += 64;
    }
    assert_eq!(
        account(&mut context, session).await.data[112..116],
        576u32.to_le_bytes()
    );
    send(
        &mut context,
        grow_stream(payer, session, 1_024),
        &[],
        "v2-grow-stream-576-to-1024",
        Ok(()),
    )
    .await;
    assert_eq!(
        account(&mut context, stream).await.data.len(),
        128 + 1_024 * 16
    );
    assert_eq!(
        &account(&mut context, stream).await.data[40..72],
        &[0xA5; 32]
    );

    cursor = 576;
    while cursor < 960 {
        process_window(&mut context, &authority, session, cursor, 64).await;
        cursor += 64;
    }
    process_window(&mut context, &authority, session, 960, 41).await;
    assert_eq!(
        account(&mut context, session).await.data[112..116],
        STEPS.to_le_bytes()
    );
    assert_eq!(
        account(&mut context, states[0]).await.data[128..136],
        (STEPS as u64).to_le_bytes()
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, states[0]).await.data[136..144]
                .try_into()
                .unwrap()
        ),
        (STEPS as u64 * (STEPS as u64 + 1)) / 2,
    );

    let mut untouched_outputs = Vec::with_capacity(output_keys.len());
    for key in &output_keys {
        untouched_outputs.push(account(&mut context, *key).await.data);
    }
    send(
        &mut context,
        begin_phase(authority.pubkey(), session, STEPS),
        &[&authority],
        "v2-begin-view-phase",
        Ok(()),
    )
    .await;
    let scratch_before_stale = account(&mut context, scratch).await.data;
    let phase_before_stale = account(&mut context, session).await.data;
    send(
        &mut context,
        run_phase(authority.pubkey(), session, 123),
        &[&authority],
        "v2-stale-phase-cursor-control",
        Err(v2::REFUSAL_PHASE_CURSOR),
    )
    .await;
    assert_eq!(
        account(&mut context, scratch).await.data,
        scratch_before_stale
    );
    assert_eq!(
        account(&mut context, session).await.data,
        phase_before_stale
    );
    send(
        &mut context,
        run_phase(authority.pubkey(), session, 0),
        &[&authority],
        "v2-render-first-phase",
        Ok(()),
    )
    .await;
    let scratch_after_first_phase = account(&mut context, scratch).await.data;

    // An otherwise valid state transition changes the state version while the
    // publication is suspended. The next phase refuses before modifying its
    // scratch, and the partially staged view is explicitly aborted.
    send(
        &mut context,
        write_input(authority.pubkey(), session, STEPS, 1),
        &[&authority],
        "v2-deposit-after-window",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        advance(authority.pubkey(), session, STEPS, 1),
        &[&authority],
        "v2-state-change-mid-phase",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        run_phase(authority.pubkey(), session, app::WORKLOAD_PHASE_BYTES),
        &[&authority],
        "v2-state-version-changed-control",
        Err(v2::REFUSAL_PHASE_STATE_CHANGED),
    )
    .await;
    assert_eq!(
        account(&mut context, scratch).await.data,
        scratch_after_first_phase
    );
    for (key, before) in output_keys.iter().zip(untouched_outputs.iter()) {
        assert_eq!(account(&mut context, *key).await.data, *before);
    }
    send(
        &mut context,
        abort_phase(authority.pubkey(), session, STEPS),
        &[&authority],
        "v2-abort-stale-publication",
        Ok(()),
    )
    .await;

    let committed_cursor = STEPS + 1;
    send(
        &mut context,
        begin_phase(authority.pubkey(), session, committed_cursor),
        &[&authority],
        "v2-rebegin-view-phase",
        Ok(()),
    )
    .await;
    let total = app::WORKLOAD_VIEW_BYTES;
    let phase_bytes = app::WORKLOAD_PHASE_BYTES;
    let mut phase_cursor = 0u32;
    while phase_cursor < total {
        send(
            &mut context,
            run_phase(authority.pubkey(), session, phase_cursor),
            &[&authority],
            "v2-run-view-phase",
            Ok(()),
        )
        .await;
        phase_cursor += (total - phase_cursor).min(phase_bytes);
    }
    for (key, before) in output_keys.iter().zip(untouched_outputs.iter()) {
        assert_eq!(account(&mut context, *key).await.data, *before);
    }
    send(
        &mut context,
        commit_phase(authority.pubkey(), session, committed_cursor, total),
        &[&authority],
        "v2-atomic-view-commit",
        Ok(()),
    )
    .await;

    let large_state = account(&mut context, states[1]).await.data;
    let snapshot = account(&mut context, output_keys[0]).await.data;
    assert_eq!(
        snapshot[128..],
        large_state[128..128 + app::WORKLOAD_SNAPSHOT_BYTES as usize]
    );
    assert_eq!(
        &snapshot[128..128 + app::WORKLOAD_RESOURCE_BYTES.len()],
        app::WORKLOAD_RESOURCE_BYTES
    );
    assert_eq!(
        u32::from_le_bytes(snapshot[112..116].try_into().unwrap()),
        committed_cursor
    );
    for strip in 0..8usize {
        let output = account(&mut context, output_keys[strip + 1]).await.data;
        let source_start = 128
            + app::WORKLOAD_SNAPSHOT_BYTES as usize
            + strip * app::WORKLOAD_STRIP_BYTES as usize;
        assert_eq!(
            output[128..],
            large_state[source_start..source_start + app::WORKLOAD_STRIP_BYTES as usize]
        );
        assert_eq!(
            u32::from_le_bytes(output[112..116].try_into().unwrap()),
            committed_cursor
        );
    }

    send(
        &mut context,
        halt(authority.pubkey(), session, committed_cursor),
        &[&authority],
        "v2-halt",
        Ok(()),
    )
    .await;
    let mut children = vec![
        (stream, v2::KIND_STREAM),
        (states[0], v2::KIND_STATE),
        (states[1], v2::KIND_STATE),
    ];
    children.extend(output_keys.iter().copied().map(|key| (key, v2::KIND_VIEW)));
    children.push((scratch, v2::KIND_SCRATCH));
    for (child, kind) in children {
        send(
            &mut context,
            close_child(session, child, authority.pubkey(), kind),
            &[],
            "v2-close-halted-child",
            Ok(()),
        )
        .await;
    }
    send(
        &mut context,
        close_session(session, authority.pubkey()),
        &[],
        "v2-close-halted-session",
        Ok(()),
    )
    .await;
    assert!(context
        .banks_client
        .get_account(session)
        .await
        .unwrap()
        .is_none());
    assert!(context
        .banks_client
        .get_account(stream)
        .await
        .unwrap()
        .is_none());
    assert!(context
        .banks_client
        .get_account(output_keys[0])
        .await
        .unwrap()
        .is_none());
    let _ = stranger;
}
