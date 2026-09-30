#![cfg(feature = "sbf-real-lifecycle-test")]

//! Executes the versioned stateful workload instructions from the actual SBF
//! image. The counter app uses no state or input hashing until TAG_ANCHOR.

use dcg_program::{kernel::Kernel, stateful as sw, stateful_test as app};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{bpf_loader_upgradeable, pubkey::Pubkey, system_program};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const SYSTEM: Pubkey = system_program::ID;

fn keypair(seed: u8) -> Keypair {
    solana_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn session_pda(authority: &Pubkey, id: u64) -> Pubkey {
    let id = id.to_le_bytes();
    Pubkey::find_program_address(&[b"dcg-session-v1", authority.as_ref(), &id], &PROGRAM).0
}

fn stream_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-input-v1", session.as_ref()], &PROGRAM).0
}

fn state_pda(session: &Pubkey, index: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-state-v1", session.as_ref(), &[index]], &PROGRAM).0
}

fn view_pda(session: &Pubkey, role: u8) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-view-v1", session.as_ref(), &[role]], &PROGRAM).0
}

fn instruction(tag: u8, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&data);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: bytes,
    }
}

fn open_instruction(
    payer: Pubkey,
    authority: Pubkey,
    id: u64,
    policy: u8,
    width: u8,
    capacity: u16,
    max_steps: u8,
    writer: Pubkey,
) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION];
    data.extend_from_slice(&id.to_le_bytes());
    data.push(policy);
    data.push(width);
    data.extend_from_slice(&capacity.to_le_bytes());
    data.push(max_steps);
    data.extend_from_slice(&app::COUNTER.manifest().id.0);
    data.extend_from_slice(&app::COUNTER.manifest().semantic_version.to_le_bytes());
    data.extend_from_slice(&app::COUNTER.manifest().abi_version.to_le_bytes());
    data.extend_from_slice(&sw::MODE_CONSENSUS_V1.id.to_le_bytes());
    data.extend_from_slice(&sw::MODE_CONSENSUS_V1.version.to_le_bytes());
    data.extend_from_slice(&[0xA5; 32]);
    data.extend_from_slice(writer.as_ref());
    instruction(
        sw::TAG_OPEN_SESSION,
        data,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session_pda(&authority, id), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_stream(payer: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STREAM,
        vec![sw::WIRE_VERSION],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_state(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION, 2];
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(&8u32.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        data,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new(state_pda(&session, 1), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_view(payer: Pubkey, session: Pubkey, role: u8) -> Instruction {
    let (abi, offset, len) = match role {
        sw::KIND_VIEW_COUNTER => (app::VALUE_VIEW_ABI, 0u32, 8u32),
        sw::KIND_VIEW_TOTAL => (app::TOTAL_VIEW_ABI, 8u32, 8u32),
        sw::KIND_SCRATCH => ([0; 32], 0, 32),
        _ => panic!("unknown view role"),
    };
    let mut data = vec![sw::WIRE_VERSION, role];
    data.extend_from_slice(&abi);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(&len.to_le_bytes());
    instruction(
        sw::TAG_CREATE_VIEW,
        data,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(view_pda(&session, role), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn write_input(writer: Pubkey, session: Pubkey, sequence: u32, command: u8) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION];
    data.extend_from_slice(&sequence.to_le_bytes());
    data.push(1);
    data.push(command);
    instruction(
        sw::TAG_WRITE_INPUT,
        data,
        vec![
            AccountMeta::new_readonly(writer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(stream_pda(&session), false),
        ],
    )
}

fn advance(
    session: Pubkey,
    authority: Pubkey,
    expected: u32,
    steps: u8,
    state_keys: &[Pubkey],
) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION];
    data.extend_from_slice(&expected.to_le_bytes());
    data.push(steps);
    let mut accounts = vec![
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(session, false),
        AccountMeta::new(stream_pda(&session), false),
    ];
    accounts.extend(
        state_keys
            .iter()
            .copied()
            .map(|key| AccountMeta::new(key, false)),
    );
    instruction(sw::TAG_ADVANCE, data, accounts)
}

fn publish_views(session: Pubkey, expected: u32) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION];
    data.extend_from_slice(&expected.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        data,
        vec![
            AccountMeta::new_readonly(session, false),
            AccountMeta::new_readonly(state_pda(&session, 0), false),
            AccountMeta::new_readonly(state_pda(&session, 1), false),
            AccountMeta::new(view_pda(&session, sw::KIND_VIEW_COUNTER), false),
            AccountMeta::new(view_pda(&session, sw::KIND_VIEW_TOTAL), false),
            AccountMeta::new(view_pda(&session, sw::KIND_SCRATCH), false),
        ],
    )
}

fn halt(session: Pubkey, authority: Pubkey, expected: u32) -> Instruction {
    let mut data = vec![sw::WIRE_VERSION];
    data.extend_from_slice(&expected.to_le_bytes());
    instruction(
        sw::TAG_HALT_SESSION,
        data,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
        ],
    )
}

fn close_child(session: Pubkey, child: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    instruction(
        sw::TAG_CLOSE_ACCOUNT,
        vec![sw::WIRE_VERSION, kind],
        vec![
            AccountMeta::new(session, false),
            AccountMeta::new(child, false),
            AccountMeta::new(refund, false),
        ],
    )
}

fn close_session(session: Pubkey, refund: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CLOSE_ACCOUNT,
        vec![sw::WIRE_VERSION, sw::KIND_SESSION],
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
        .map(|metadata| metadata.compute_units_consumed)
        .unwrap_or(0);
    match (expected, result.result) {
        (Ok(()), Ok(())) => {}
        (Err(want), Err(TransactionError::InstructionError(_, InstructionError::Custom(got))))
            if want == got => {}
        (want, got) => panic!("{label}: expected {want:?}, got {got:?}"),
    }
    eprintln!(
        "stateful CU instruction={} tag={} outcome={:?} cu={}",
        label, ix.data[0], expected, cu
    );
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

async fn close_all(
    context: &mut ProgramTestContext,
    session: Pubkey,
    refund: Pubkey,
    children: &[(Pubkey, u8)],
) -> u64 {
    let mut expected_refund = 0u64;
    for (key, kind) in children {
        expected_refund += account(context, *key).await.lamports;
        send(
            context,
            close_child(session, *key, refund, *kind),
            &[],
            "close-child",
            Ok(()),
        )
        .await;
    }
    expected_refund += account(context, session).await.lamports;
    send(
        context,
        close_session(session, refund),
        &[],
        "close-session",
        Ok(()),
    )
    .await;
    expected_refund
}

async fn start_sbf() -> ProgramTestContext {
    let out_dir = std::env::var("SBF_OUT_DIR")
        .or_else(|_| std::env::var("BPF_OUT_DIR"))
        .expect("set SBF_OUT_DIR to the sbf-real-lifecycle-test build output");
    let elf = std::fs::read(std::path::Path::new(&out_dir).join("dcg_program.so"))
        .expect("dcg_program.so in SBF_OUT_DIR");
    let data_address = bpf_loader_upgradeable::get_program_data_address(&PROGRAM);
    let mut program_state = 2u32.to_le_bytes().to_vec();
    program_state.extend_from_slice(data_address.as_ref());
    let mut program_data = 3u32.to_le_bytes().to_vec();
    program_data.extend_from_slice(&0u64.to_le_bytes());
    program_data.push(1);
    let authority = keypair(240);
    program_data.extend_from_slice(authority.pubkey().as_ref());
    program_data.extend_from_slice(&elf);
    let mut test = ProgramTest::default();
    test.prefer_bpf(true);
    test.add_genesis_account(
        PROGRAM,
        Account {
            lamports: 1_000_000_000,
            data: program_state,
            owner: bpf_loader_upgradeable::id(),
            executable: true,
            rent_epoch: 0,
        },
    );
    test.add_genesis_account(
        data_address,
        Account {
            lamports: 1_000_000_000_000,
            data: program_data,
            owner: bpf_loader_upgradeable::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    let context = test.start_with_context().await;
    eprintln!("stateful SBF image bytes={} program={}", elf.len(), PROGRAM);
    context
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_consensus_stream_views_close_and_refusal_atomicity() {
    let mut context = start_sbf().await;
    let payer = context.payer.pubkey();
    let authority = keypair(17);
    let stranger = keypair(19);
    let wrong_refund = keypair(20);
    let session = session_pda(&authority.pubkey(), 1);
    let stream = stream_pda(&session);
    let state0 = state_pda(&session, 0);
    let state1 = state_pda(&session, 1);
    let view1 = view_pda(&session, sw::KIND_VIEW_COUNTER);
    let view2 = view_pda(&session, sw::KIND_VIEW_TOTAL);
    let scratch = view_pda(&session, sw::KIND_SCRATCH);

    // An over-declared operation count is refused before a session account is created.
    let invalid = session_pda(&authority.pubkey(), 99);
    send(
        &mut context,
        open_instruction(
            payer,
            authority.pubkey(),
            99,
            sw::POLICY_INDEXED,
            1,
            8,
            sw::MAX_STEPS_PER_ADVANCE + 1,
            Pubkey::default(),
        ),
        &[&authority],
        "resource-limit-refusal",
        Err(sw::REFUSAL_RESOURCE),
    )
    .await;
    assert!(context
        .banks_client
        .get_account(invalid)
        .await
        .unwrap()
        .is_none());

    send(
        &mut context,
        open_instruction(
            payer,
            authority.pubkey(),
            1,
            sw::POLICY_INDEXED,
            1,
            8,
            4,
            Pubkey::default(),
        ),
        &[&authority],
        "open-indexed",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "create-stream",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        create_state(payer, session),
        &[],
        "create-split-state",
        Ok(()),
    )
    .await;
    for role in [sw::KIND_VIEW_COUNTER, sw::KIND_VIEW_TOTAL, sw::KIND_SCRATCH] {
        send(
            &mut context,
            create_view(payer, session, role),
            &[],
            "declare-view-or-scratch",
            Ok(()),
        )
        .await;
    }

    // Indexed input allows a bounded gap and later filling it; advancing still
    // requires a consecutive run beginning at the committed cursor.
    for (sequence, command) in [(2, 3), (0, 1), (1, 2)] {
        send(
            &mut context,
            write_input(authority.pubkey(), session, sequence, command),
            &[&authority],
            "indexed-write",
            Ok(()),
        )
        .await;
    }
    let stream_before_duplicate = account(&mut context, stream).await.data;
    send(
        &mut context,
        write_input(authority.pubkey(), session, 2, 4),
        &[&authority],
        "double-write-control",
        Err(sw::REFUSAL_DUPLICATE_SLOT),
    )
    .await;
    assert_eq!(
        account(&mut context, stream).await.data,
        stream_before_duplicate
    );

    let state_before_stale = account(&mut context, state0).await.data;
    send(
        &mut context,
        advance(session, authority.pubkey(), 1, 1, &[state0, state1]),
        &[&authority],
        "stale-cursor-control",
        Err(sw::REFUSAL_CURSOR),
    )
    .await;
    assert_eq!(account(&mut context, state0).await.data, state_before_stale);

    send(
        &mut context,
        advance(session, stranger.pubkey(), 0, 1, &[state0, state1]),
        &[&stranger],
        "wrong-advance-authority-control",
        Err(sw::REFUSAL_AUTHORITY),
    )
    .await;
    assert_eq!(account(&mut context, state0).await.data, state_before_stale);

    send(
        &mut context,
        advance(session, authority.pubkey(), 0, 1, &[state0, state0]),
        &[&authority],
        "aliased-state-control",
        Err(sw::REFUSAL_ALIAS),
    )
    .await;
    assert_eq!(account(&mut context, state0).await.data, state_before_stale);

    // Refuse closing any child while its session is live; the transaction
    // leaves both the child and session bytes unchanged.
    let live_session_before = account(&mut context, session).await.data;
    let live_stream_before = account(&mut context, stream).await;
    send(
        &mut context,
        close_child(session, stream, authority.pubkey(), sw::KIND_STREAM),
        &[],
        "close-while-live-control",
        Err(sw::REFUSAL_LIVE),
    )
    .await;
    assert_eq!(
        account(&mut context, session).await.data,
        live_session_before
    );
    let live_stream_after = account(&mut context, stream).await;
    assert_eq!(live_stream_after.data, live_stream_before.data);
    assert_eq!(live_stream_after.lamports, live_stream_before.lamports);

    send(
        &mut context,
        advance(session, authority.pubkey(), 0, 3, &[state0, state1]),
        &[&authority],
        "advance-three-indexed-inputs",
        Ok(()),
    )
    .await;
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, state0).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        6
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, state1).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        10
    );

    for expected_cursor in [2u32] {
        let output_before = account(&mut context, view1).await.data;
        send(
            &mut context,
            publish_views(session, expected_cursor),
            &[],
            "wrong-view-state-version-control",
            Err(sw::REFUSAL_CURSOR),
        )
        .await;
        assert_eq!(account(&mut context, view1).await.data, output_before);
    }
    send(
        &mut context,
        publish_views(session, 3),
        &[],
        "publish-two-views-from-one-cursor",
        Ok(()),
    )
    .await;
    let counter_view = account(&mut context, view1).await.data;
    let total_view = account(&mut context, view2).await.data;
    assert_eq!(
        u64::from_le_bytes(counter_view[128..136].try_into().unwrap()),
        6
    );
    assert_eq!(
        u64::from_le_bytes(total_view[128..136].try_into().unwrap()),
        10
    );
    assert_eq!(
        u32::from_le_bytes(counter_view[112..116].try_into().unwrap()),
        3
    );
    assert_eq!(
        u32::from_le_bytes(total_view[112..116].try_into().unwrap()),
        3
    );

    // Consensus transitions above did not hash. This explicit request computes
    // the input and state anchors once at cursor 3.
    send(
        &mut context,
        instruction(
            sw::TAG_ANCHOR,
            [sw::WIRE_VERSION, 3, 0, 0, 0].to_vec(),
            vec![
                AccountMeta::new(session, false),
                AccountMeta::new_readonly(stream, false),
                AccountMeta::new_readonly(state0, false),
                AccountMeta::new_readonly(state1, false),
            ],
        ),
        &[],
        "explicit-anchor",
        Ok(()),
    )
    .await;
    let session_after_anchor = account(&mut context, session).await.data;
    assert_ne!(&session_after_anchor[156..188], &[0; 32]);
    assert_ne!(&session_after_anchor[192..224], &[0; 32]);

    send(
        &mut context,
        halt(session, authority.pubkey(), 3),
        &[&authority],
        "halt-session",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        close_child(session, stream, wrong_refund.pubkey(), sw::KIND_STREAM),
        &[],
        "wrong-refund-authority-control",
        Err(sw::REFUSAL_REFUND),
    )
    .await;
    let indexed_children = [
        (stream, sw::KIND_STREAM),
        (state0, sw::KIND_STATE),
        (state1, sw::KIND_STATE),
        (view1, sw::KIND_VIEW_COUNTER),
        (view2, sw::KIND_VIEW_TOTAL),
        (scratch, sw::KIND_SCRATCH),
    ];
    let refund_before = context
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap();
    let indexed_refund =
        close_all(&mut context, session, authority.pubkey(), &indexed_children).await;
    let refund_after = context
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap();
    assert_eq!(refund_after - refund_before, indexed_refund);
    assert_eq!(
        context.banks_client.get_account(session).await.unwrap(),
        None
    );
    assert_eq!(
        context.banks_client.get_account(stream).await.unwrap(),
        None
    );

    // The same input layer in append mode assigns only the next sequence and
    // permits only its declared writer.
    let append_authority = keypair(21);
    let append_writer = keypair(22);
    let append_session = session_pda(&append_authority.pubkey(), 2);
    let append_stream = stream_pda(&append_session);
    let append_state0 = state_pda(&append_session, 0);
    let append_state1 = state_pda(&append_session, 1);
    send(
        &mut context,
        open_instruction(
            payer,
            append_authority.pubkey(),
            2,
            sw::POLICY_APPEND,
            1,
            8,
            4,
            append_writer.pubkey(),
        ),
        &[&append_authority],
        "open-append",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        create_stream(payer, append_session),
        &[],
        "create-append-stream",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        create_state(payer, append_session),
        &[],
        "create-append-state",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        write_input(append_writer.pubkey(), append_session, 0, 2),
        &[&append_writer],
        "append-write-0",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        write_input(append_writer.pubkey(), append_session, 2, 3),
        &[&append_writer],
        "append-gap-control",
        Err(sw::REFUSAL_CURSOR),
    )
    .await;
    send(
        &mut context,
        write_input(stranger.pubkey(), append_session, 1, 3),
        &[&stranger],
        "append-wrong-writer-control",
        Err(sw::REFUSAL_AUTHORITY),
    )
    .await;
    send(
        &mut context,
        write_input(append_writer.pubkey(), append_session, 1, 3),
        &[&append_writer],
        "append-write-1",
        Ok(()),
    )
    .await;
    send(
        &mut context,
        advance(
            append_session,
            append_authority.pubkey(),
            0,
            2,
            &[append_state0, append_state1],
        ),
        &[&append_authority],
        "advance-append-inputs",
        Ok(()),
    )
    .await;
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, append_state0).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        5
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, append_state1).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        7
    );
    send(
        &mut context,
        halt(append_session, append_authority.pubkey(), 2),
        &[&append_authority],
        "halt-append-session",
        Ok(()),
    )
    .await;
    let append_children = [
        (append_stream, sw::KIND_STREAM),
        (append_state0, sw::KIND_STATE),
        (append_state1, sw::KIND_STATE),
    ];
    let append_refund = close_all(
        &mut context,
        append_session,
        append_authority.pubkey(),
        &append_children,
    )
    .await;
    assert!(append_refund > 0);
}
