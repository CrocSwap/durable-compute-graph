#![cfg(feature = "sbf-real-lifecycle-test")]

//! Stateful v3 proof on the feature-built SBF image. The first scenario uses a
//! 10 MB headerless primary state account and the fixed-address test engine.

use dcg_program::{
    hash::sha256,
    kernel::{Kernel, MAX_DECLARED_KERNEL_COMPUTE_UNITS},
    stateful as sw,
    stateful::v3,
    stateful_test as app,
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
const DOOM_WAD_BYTES: usize = 4_400_000;
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

fn resource_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-resource-v3", session.as_ref()], &PROGRAM).0
}

fn anchor_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-anchor-v3", session.as_ref()], &PROGRAM).0
}

fn resource_leaf(index: u32, len: u32, bytes: &[u8]) -> [u8; 32] {
    sha256(&[
        b"dcg/resource-chunk/1",
        &index.to_le_bytes(),
        &len.to_le_bytes(),
        bytes,
    ])
}

fn resource_levels(resource: &[u8]) -> Vec<Vec<[u8; 32]>> {
    let chunks: Vec<[u8; 32]> = resource
        .chunks(v3::RESOURCE_CHUNK_BYTES as usize)
        .enumerate()
        .map(|(index, chunk)| resource_leaf(index as u32, resource.len() as u32, chunk))
        .collect();
    let mut levels = vec![chunks];
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let next = current
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                sha256(&[b"dcg/resource-node/1", &pair[0], right])
            })
            .collect();
        levels.push(next);
    }
    levels
}

fn resource_root(resource: &[u8]) -> [u8; 32] {
    resource_levels(resource).last().unwrap()[0]
}

fn resource_proof(resource: &[u8], index: u32) -> Vec<[u8; 32]> {
    let levels = resource_levels(resource);
    let mut proof = Vec::new();
    let mut at = index as usize;
    for level in &levels[..levels.len() - 1] {
        let sibling = at ^ 1;
        if sibling < level.len() {
            proof.push(level[sibling]);
        }
        at >>= 1;
    }
    proof
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
            AccountMeta::new(resource_pda(&session_pda(&authority, id)), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn upload_resource_chunk(
    authority: Pubkey,
    session: Pubkey,
    source: Pubkey,
    index: u32,
    proof: &[[u8; 32]],
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&index.to_le_bytes());
    payload.push(proof.len() as u8);
    for sibling in proof {
        payload.extend_from_slice(sibling);
    }
    instruction(
        v3::RESOURCE_CHUNK_TAG,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(resource_pda(&session), false),
            AccountMeta::new_readonly(source, false),
        ],
    )
}

fn grow_resource_copy(
    payer: Pubkey,
    authority: Pubkey,
    session: Pubkey,
    allocated: u32,
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::RESOURCE_GROW_OP];
    payload.extend_from_slice(&allocated.to_le_bytes());
    instruction(
        v3::RESOURCE_CHUNK_TAG,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(resource_pda(&session), false),
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

fn create_primary_state(payer: Pubkey, session: Pubkey) -> Instruction {
    create_primary_state_len(payer, session, app::V3_FIXED_STATE_LEN)
}

fn create_primary_state_len(payer: Pubkey, session: Pubkey, len: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 1];
    payload.extend_from_slice(&len.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource_pda(&session), false),
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
    begin_initialization_len(authority, session, app::V3_FIXED_STATE_LEN)
}

fn initialize_primary_one_call(authority: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STATE,
        vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
        vec![
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource_pda(&session), false),
        ],
    )
}

fn begin_initialization_len(authority: Pubkey, session: Pubkey, len: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::STATE_OP_BEGIN_INITIALIZE];
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&app::V3_INIT_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource_pda(&session), false),
        ],
    )
}

fn one_shot_anchor(
    authority: Pubkey,
    session: Pubkey,
    primary_layout: bool,
    authority_signer: bool,
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&0u32.to_le_bytes());
    let accounts = if primary_layout {
        vec![
            AccountMeta::new_readonly(state_pda(&session, 0), false),
            AccountMeta::new_readonly(authority, authority_signer),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(stream_pda(&session), false),
        ]
    } else {
        vec![
            AccountMeta::new_readonly(authority, authority_signer),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(stream_pda(&session), false),
            AccountMeta::new_readonly(state_pda(&session, 0), false),
        ]
    };
    instruction(sw::TAG_ANCHOR, payload, accounts)
}

fn run_initialization(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    run_initialization_with_state(authority, session, state_pda(&session, 0), cursor)
}

fn run_initialization_with_state(
    authority: Pubkey,
    session: Pubkey,
    primary: Pubkey,
    cursor: u32,
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::STATE_OP_RUN_INITIALIZE];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.extend_from_slice(&app::V3_INIT_COMPUTE_UNITS.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(primary, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(resource_pda(&session), false),
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

fn advance_with_spans(
    authority: Pubkey,
    session: Pubkey,
    cursor: u32,
    steps: u8,
    spans: &[Pubkey],
) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.push(steps);
    let mut accounts = vec![
        AccountMeta::new(spans[0], false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(session, false),
        AccountMeta::new(stream_pda(&session), false),
    ];
    accounts.extend(spans[1..].iter().map(|key| AccountMeta::new(*key, false)));
    instruction(sw::TAG_ADVANCE, payload, accounts)
}

fn begin_anchor(payer: Pubkey, authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::ANCHOR_OP_BEGIN];
    payload.extend_from_slice(&cursor.to_le_bytes());
    instruction(
        sw::TAG_ANCHOR,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(stream_pda(&session), false),
            AccountMeta::new(anchor_pda(&session), false),
            AccountMeta::new_readonly(state_pda(&session, 0), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn anchor_chunk(authority: Pubkey, session: Pubkey, cursor: u32, offset: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::ANCHOR_OP_CHUNK];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.extend_from_slice(&offset.to_le_bytes());
    instruction(
        sw::TAG_ANCHOR,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(stream_pda(&session), false),
            AccountMeta::new(anchor_pda(&session), false),
            AccountMeta::new_readonly(state_pda(&session, 0), false),
        ],
    )
}

fn finish_anchor(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, v3::ANCHOR_OP_FINISH];
    payload.extend_from_slice(&cursor.to_le_bytes());
    instruction(
        sw::TAG_ANCHOR,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(anchor_pda(&session), false),
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

fn halt_session(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
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
        vec![v3::WIRE_VERSION, v3::KIND_SESSION],
        vec![
            AccountMeta::new(session, false),
            AccountMeta::new(refund, false),
        ],
    )
}

fn close_child(session: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    instruction(
        sw::TAG_CLOSE_ACCOUNT,
        vec![v3::WIRE_VERSION, kind],
        vec![
            AccountMeta::new(session, false),
            AccountMeta::new(target, false),
            AccountMeta::new(refund, false),
        ],
    )
}

fn abort_view(authority: Pubkey, session: Pubkey, cursor: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 3];
    payload.extend_from_slice(&cursor.to_le_bytes());
    instruction(
        sw::TAG_PUBLISH_VIEWS,
        payload,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
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
        AccountMeta::new_readonly(resource_pda(&session), false),
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
    begin_view_with_accounts(authority, publication_accounts(authority, session, false))
}

fn begin_view_with_accounts(authority: Pubkey, accounts: Vec<AccountMeta>) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 0];
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&500_000u32.to_le_bytes());
    instruction(sw::TAG_PUBLISH_VIEWS, payload, accounts)
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

async fn account(context: &mut ProgramTestContext, key: Pubkey) -> Account {
    context
        .banks_client
        .get_account(key)
        .await
        .unwrap()
        .unwrap()
}

async fn start_sbf() -> (ProgramTestContext, Vec<u8>) {
    start_sbf_with_resource(vec![0x5A; RESOURCE_LEN]).await
}

async fn start_sbf_with_resource(resource: Vec<u8>) -> (ProgramTestContext, Vec<u8>) {
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
            data: resource,
            owner: PROGRAM,
            executable: false,
            rent_epoch: 0,
        },
    );
    (test.start_with_context().await, elf)
}

async fn open_fixed_small(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    id: u64,
    resource: &[u8],
) -> (Pubkey, Pubkey, Pubkey) {
    let payer = context.payer.pubkey();
    let session = session_pda(&authority.pubkey(), id);
    let stream = stream_pda(&session);
    let state = state_pda(&session, 0);
    send(
        context,
        open_primary(payer, authority.pubkey(), id, resource_root(resource)),
        &[authority],
        "OPEN_SESSION-v3-small-fixture",
        Ok(()),
        false,
    )
    .await;
    send(
        context,
        upload_resource_chunk(
            authority.pubkey(),
            session,
            RESOURCE,
            0,
            &resource_proof(resource, 0),
        ),
        &[authority],
        "RESOURCE_CHUNK-v3-small-fixture",
        Ok(()),
        false,
    )
    .await;
    send(
        context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-small",
        Ok(()),
        false,
    )
    .await;
    send(
        context,
        create_primary_state_len(payer, session, 1_280),
        &[],
        "CREATE_STATE-v3-small",
        Ok(()),
        false,
    )
    .await;
    send(
        context,
        begin_initialization_len(authority.pubkey(), session, 1_280),
        &[authority],
        "BEGIN_INITIALIZATION-v3-small",
        Ok(()),
        false,
    )
    .await;
    send(
        context,
        run_initialization(authority.pubkey(), session, 0),
        &[authority],
        "RUN_INITIALIZATION-v3-small",
        Ok(()),
        false,
    )
    .await;
    (session, stream, state)
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
    let commitment = resource_root(&resource);

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
        upload_resource_chunk(
            authority.pubkey(),
            session,
            RESOURCE,
            0,
            &resource_proof(&resource, 0),
        ),
        &[&authority],
        "RESOURCE_CHUNK-v3-small-copy",
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
        create_primary_state(payer, session),
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
    let session_after_begin = account(&mut context, session).await;
    send(
        &mut context,
        begin_initialization(authority.pubkey(), session),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-duplicate-refused",
        Err(v3::REFUSAL_INITIALIZATION),
        true,
    )
    .await;
    send(
        &mut context,
        grow_state(payer, session),
        &[],
        "GROW_STATE-v3-during-initialization-refused",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await, session_after_begin);
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
    assert!((app::V3_INIT_COMPUTE_UNITS as u64) < MAX_DECLARED_KERNEL_COMPUTE_UNITS);
    assert!(first_phase_cu < app::V3_INIT_COMPUTE_UNITS as u64);
    let state_after_first_init = account(&mut context, state).await.data;
    let session_after_first_init = account(&mut context, session).await.data;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 2 * app::V3_INIT_PHASE_BYTES),
        &[&authority],
        "RUN_INITIALIZATION-v3-future-phase-cursor",
        Err(v3::REFUSAL_PHASE_CURSOR),
        true,
    )
    .await;
    send(
        &mut context,
        advance(authority.pubkey(), session, 0, 4),
        &[&authority],
        "ADVANCE-v3-before-initialization-complete",
        Err(v3::REFUSAL_LIVE),
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
        begin_initialization(authority.pubkey(), session),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-after-completion-refused",
        Err(v3::REFUSAL_INITIALIZATION),
        true,
    )
    .await;
    send(
        &mut context,
        initialize_primary_one_call(authority.pubkey(), session),
        &[&authority],
        "INITIALIZE_STATE-v3-after-phased-init-refused",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;

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
    send(
        &mut context,
        begin_view(authority.pubkey(), session),
        &[&authority],
        "BEGIN_PHASE-v3-render-clears-workspace",
        Ok(()),
        true,
    )
    .await;
    assert!(account(&mut context, workspace).await.data[128..]
        .iter()
        .all(|byte| *byte == 0));
    send(
        &mut context,
        abort_view(authority.pubkey(), session, 0),
        &[&authority],
        "ABORT_PHASE-v3-render-workspace-reset",
        Ok(()),
        true,
    )
    .await;

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

    let anchor_begin_cu = send(
        &mut context,
        begin_anchor(payer, authority.pubkey(), session, 0),
        &[&authority],
        "ANCHOR-v3-begin-10mb",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        advance(authority.pubkey(), session, 0, 4),
        &[&authority],
        "ADVANCE-v3-refused-during-anchor",
        Err(v3::REFUSAL_LIVE),
        true,
    )
    .await;
    let mut anchor_cus = Vec::new();
    let mut anchor_offset = 0u32;
    while anchor_offset < app::V3_FIXED_STATE_LEN {
        anchor_cus.push(
            send(
                &mut context,
                anchor_chunk(authority.pubkey(), session, 0, anchor_offset),
                &[&authority],
                "ANCHOR-v3-chunk-10mb",
                Ok(()),
                false,
            )
            .await,
        );
        anchor_offset += (app::V3_FIXED_STATE_LEN - anchor_offset).min(v3::ANCHOR_CHUNK_BYTES);
    }
    let anchor_finish_cu = send(
        &mut context,
        finish_anchor(authority.pubkey(), session, 0),
        &[&authority],
        "ANCHOR-v3-finish-10mb",
        Ok(()),
        true,
    )
    .await;
    let anchor_total_cu: u64 = anchor_cus.iter().sum::<u64>() + anchor_begin_cu + anchor_finish_cu;
    eprintln!(
        "stateful-v3 CU ANCHOR-v3 total_bytes={} chunk_count={} chunk_min={} chunk_max={} chunk_total={} lifecycle_total={} each={anchor_cus:?}",
        app::V3_FIXED_STATE_LEN,
        anchor_cus.len(),
        anchor_cus.iter().min().unwrap(),
        anchor_cus.iter().max().unwrap(),
        anchor_cus.iter().sum::<u64>(),
        anchor_total_cu,
    );
    assert!(anchor_cus.iter().all(|cu| *cu < 200_000));
    assert_ne!(anchor_total_cu, 0);

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
    let anchored = account(&mut context, session).await.data;
    assert_eq!(
        u32::from_le_bytes(anchored[188..192].try_into().unwrap()),
        0
    );
    assert_ne!(&anchored[192..224], &[0; 32]);
    let anchor = anchor_pda(&session);
    send(
        &mut context,
        close_child(session, anchor, authority.pubkey(), v3::KIND_ANCHOR),
        &[],
        "CLOSE_ACCOUNT-v3-finished-anchor",
        Ok(()),
        true,
    )
    .await;
    assert!(context
        .banks_client
        .get_account(anchor)
        .await
        .unwrap()
        .is_none());
}

fn open_default(payer: Pubkey, authority: Pubkey, id: u64) -> Instruction {
    let manifest = app::V3_COUNTER.manifest();
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

fn open_counter_primary(payer: Pubkey, authority: Pubkey, id: u64) -> Instruction {
    let mut ix = open_default(payer, authority, id);
    *ix.data.last_mut().unwrap() = 1;
    ix
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_primary_and_headered_spans_advance_twice() {
    let (mut context, _) = start_sbf().await;
    let payer = context.payer.pubkey();
    let authority = keypair(65);
    let id = 5;
    let session = session_pda(&authority.pubkey(), id);
    let states = [state_pda(&session, 0), state_pda(&session, 1)];

    send(
        &mut context,
        open_counter_primary(payer, authority.pubkey(), id),
        &[&authority],
        "OPEN_SESSION-v3-counter-primary",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-counter-primary",
        Ok(()),
        true,
    )
    .await;
    let mut create = vec![v3::WIRE_VERSION, 2];
    create.extend_from_slice(&8u32.to_le_bytes());
    create.extend_from_slice(&8u32.to_le_bytes());
    send(
        &mut context,
        instruction(
            sw::TAG_CREATE_STATE,
            create,
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(session, false),
                AccountMeta::new(states[0], false),
                AccountMeta::new(states[1], false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        ),
        &[],
        "CREATE_STATE-v3-primary-plus-span",
        Ok(()),
        true,
    )
    .await;
    for sequence in 0..2 {
        send(
            &mut context,
            write_input(authority.pubkey(), session, sequence, sequence as u8 + 1),
            &[&authority],
            &format!("WRITE_INPUT-v3-counter-{sequence}"),
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
                AccountMeta::new(states[1], false),
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(session, false),
                AccountMeta::new(states[0], false),
            ],
        ),
        &[&authority],
        "INITIALIZE_STATE-v3-wrong-primary-account-order-refused",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;
    send(
        &mut context,
        instruction(
            sw::TAG_CREATE_STATE,
            vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
            vec![
                AccountMeta::new(states[0], false),
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(session, false),
                AccountMeta::new(states[1], false),
            ],
        ),
        &[&authority],
        "INITIALIZE_STATE-v3-primary-plus-span",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        advance_with_spans(authority.pubkey(), session, 0, 1, &states),
        &[&authority],
        "ADVANCE-v3-primary-plus-span-cursor-0",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        advance_with_spans(authority.pubkey(), session, 1, 1, &states),
        &[&authority],
        "ADVANCE-v3-primary-plus-span-cursor-1",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, states[0]).await.data[..8]
                .try_into()
                .unwrap()
        ),
        3
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, states[1]).await.data[128..136]
                .try_into()
                .unwrap()
        ),
        4
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_closes_two_spans_in_order_and_recovers_all_rent() {
    let (mut context, _) = start_sbf().await;
    let payer = context.payer.pubkey();

    for (id, primary_layout) in [(15, true), (16, false)] {
        let authority = keypair(id as u8);
        let session = session_pda(&authority.pubkey(), id);
        let stream = stream_pda(&session);
        let states = [state_pda(&session, 0), state_pda(&session, 1)];
        let open = if primary_layout {
            open_counter_primary(payer, authority.pubkey(), id)
        } else {
            open_default(payer, authority.pubkey(), id)
        };
        send(
            &mut context,
            open,
            &[&authority],
            &format!("OPEN_SESSION-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;
        send(
            &mut context,
            create_stream(payer, session),
            &[],
            &format!("CREATE_STREAM-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;

        let mut create_state_data = vec![v3::WIRE_VERSION, 2];
        create_state_data.extend_from_slice(&8u32.to_le_bytes());
        create_state_data.extend_from_slice(&8u32.to_le_bytes());
        send(
            &mut context,
            instruction(
                sw::TAG_CREATE_STATE,
                create_state_data,
                vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(session, false),
                    AccountMeta::new(states[0], false),
                    AccountMeta::new(states[1], false),
                    AccountMeta::new_readonly(SYSTEM, false),
                ],
            ),
            &[],
            &format!("CREATE_STATE-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;
        let accounts = [session, stream, states[0], states[1]];
        let mut rent_before_close = 0u64;
        for key in accounts {
            rent_before_close += account(&mut context, key).await.lamports;
        }
        let authority_balance_before = context
            .banks_client
            .get_balance(authority.pubkey())
            .await
            .unwrap_or(0);

        send(
            &mut context,
            halt_session(authority.pubkey(), session, 0),
            &[&authority],
            &format!("HALT_SESSION-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;
        for index in (0..states.len()).rev() {
            send(
                &mut context,
                close_child(session, states[index], authority.pubkey(), v3::KIND_STATE),
                &[],
                &format!("CLOSE_STATE-v3-span-{index}-session-{id}"),
                Ok(()),
                false,
            )
            .await;
        }
        send(
            &mut context,
            close_child(session, stream, authority.pubkey(), v3::KIND_STREAM),
            &[],
            &format!("CLOSE_STREAM-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;
        send(
            &mut context,
            close_session(session, authority.pubkey()),
            &[],
            &format!("CLOSE_SESSION-v3-close-two-spans-{id}"),
            Ok(()),
            false,
        )
        .await;

        let authority_balance_after = context
            .banks_client
            .get_balance(authority.pubkey())
            .await
            .unwrap_or(0);
        assert_eq!(
            authority_balance_after - authority_balance_before,
            rent_before_close,
            "all session, stream, and state rent is refunded for layout {primary_layout}"
        );
        for key in accounts {
            assert!(context
                .banks_client
                .get_account(key)
                .await
                .unwrap()
                .is_none());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_halt_before_at_snapshot_cap_with_eight_step_advance() {
    const SNAPSHOT_CAP_BYTES: u32 = 8 * 1024;
    let resource = vec![0x5A; RESOURCE_LEN];
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let payer = context.payer.pubkey();
    let authority = keypair(77);
    let id = 17;
    let session = session_pda(&authority.pubkey(), id);
    let state = state_pda(&session, 0);

    send(
        &mut context,
        open_primary(payer, authority.pubkey(), id, resource_root(&resource)),
        &[&authority],
        "OPEN_SESSION-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        upload_resource_chunk(
            authority.pubkey(),
            session,
            RESOURCE,
            0,
            &resource_proof(&resource, 0),
        ),
        &[&authority],
        "RESOURCE_CHUNK-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        create_primary_state_len(payer, session, SNAPSHOT_CAP_BYTES),
        &[],
        "CREATE_STATE-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        begin_initialization_len(authority.pubkey(), session, SNAPSHOT_CAP_BYTES),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-halt-before-snapshot-cap",
        Ok(()),
        false,
    )
    .await;
    assert_eq!(
        account(&mut context, state).await.data.len(),
        SNAPSHOT_CAP_BYTES as usize
    );

    for sequence in 0..8 {
        let command = if sequence == 7 { 0xEE } else { 1 };
        send(
            &mut context,
            write_input(authority.pubkey(), session, sequence, command),
            &[&authority],
            &format!("WRITE_INPUT-v3-halt-before-cap-{sequence}"),
            Ok(()),
            false,
        )
        .await;
    }
    send(
        &mut context,
        advance(authority.pubkey(), session, 0, 8),
        &[&authority],
        "ADVANCE-v3-halt-before-cap-eight-steps",
        Ok(()),
        true,
    )
    .await;
    let session_after = account(&mut context, session).await.data;
    assert_eq!(session_after[6], 2);
    assert_eq!(
        u32::from_le_bytes(session_after[112..116].try_into().unwrap()),
        7
    );
    assert_eq!(
        u32::from_le_bytes(session_after[1254..1258].try_into().unwrap()),
        app::V3_HALT_REASON
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, state).await.data[SNAPSHOT_CAP_BYTES as usize - 8..]
                .try_into()
                .unwrap()
        ),
        7
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_begin_initialization_requires_sealed_resource() {
    let resource = vec![0x5A; RESOURCE_LEN];
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let payer = context.payer.pubkey();
    let authority = keypair(78);
    let id = 18;
    let session = session_pda(&authority.pubkey(), id);

    send(
        &mut context,
        open_primary(payer, authority.pubkey(), id, resource_root(&resource)),
        &[&authority],
        "OPEN_SESSION-v3-unsealed-init",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-unsealed-init",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        create_primary_state_len(payer, session, 1_280),
        &[],
        "CREATE_STATE-v3-unsealed-init",
        Ok(()),
        false,
    )
    .await;
    let session_before = account(&mut context, session).await;
    send(
        &mut context,
        begin_initialization_len(authority.pubkey(), session, 1_280),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-unsealed-resource-refused",
        Err(v3::REFUSAL_RESOURCE),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await, session_before);

    send(
        &mut context,
        upload_resource_chunk(
            authority.pubkey(),
            session,
            RESOURCE,
            0,
            &resource_proof(&resource, 0),
        ),
        &[&authority],
        "RESOURCE_CHUNK-v3-seal-before-init",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        begin_initialization_len(authority.pubkey(), session, 1_280),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-sealed-resource",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-sealed-resource",
        Ok(()),
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_one_shot_anchor_requires_authority_and_active_session() {
    let resource = vec![0x5A; RESOURCE_LEN];
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let authority = keypair(79);
    let (session, _, _) = open_fixed_small(&mut context, &authority, 19, &resource).await;

    let session_before_unsigned_anchor = account(&mut context, session).await;
    send(
        &mut context,
        one_shot_anchor(authority.pubkey(), session, true, false),
        &[],
        "ANCHOR-v3-one-shot-nonsigner-refused",
        Err(v3::REFUSAL_AUTHORITY),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, session).await,
        session_before_unsigned_anchor
    );

    send(
        &mut context,
        one_shot_anchor(authority.pubkey(), session, true, true),
        &[&authority],
        "ANCHOR-v3-one-shot-valid-authority",
        Ok(()),
        true,
    )
    .await;
    let session_after_anchor = account(&mut context, session).await;
    assert_ne!(&session_after_anchor.data[192..224], &[0; 32]);
    let state = account(&mut context, state_pda(&session, 0)).await;
    let schema_id = app::V3_STATE_SCHEMA.id.to_le_bytes();
    let schema_version = app::V3_STATE_SCHEMA.version.to_le_bytes();
    let cursor = 0u32.to_le_bytes();
    let mut expected_anchor = dcg_program::hash::Parts::new();
    expected_anchor
        .push(b"dcg/state-anchor-one-shot/3")
        .push(&session_after_anchor.data[86..102])
        .push(&schema_id)
        .push(&schema_version)
        .push(&cursor)
        .push(&session_after_anchor.data[156..188])
        .push(&state.data);
    assert_eq!(
        &session_after_anchor.data[192..224],
        &expected_anchor.finish()
    );

    let wrong_authority = keypair(80);
    send(
        &mut context,
        one_shot_anchor(wrong_authority.pubkey(), session, true, true),
        &[&wrong_authority],
        "ANCHOR-v3-one-shot-wrong-authority-refused",
        Err(v3::REFUSAL_AUTHORITY),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await, session_after_anchor);

    send(
        &mut context,
        halt_session(authority.pubkey(), session, 0),
        &[&authority],
        "HALT_SESSION-v3-one-shot-anchor",
        Ok(()),
        false,
    )
    .await;
    let halted_session = account(&mut context, session).await;
    send(
        &mut context,
        one_shot_anchor(authority.pubkey(), session, true, true),
        &[&authority],
        "ANCHOR-v3-one-shot-halted-refused",
        Err(v3::REFUSAL_LIVE),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await, halted_session);
}

fn forged_session_resource(authority: Pubkey, id: u64) -> Vec<u8> {
    let (_, bump) = Pubkey::find_program_address(
        &[b"dcg-session-v3", authority.as_ref(), &id.to_le_bytes()],
        &PROGRAM,
    );
    let manifest = app::V3_FIXED_ENGINE.manifest();
    let mut raw = vec![0u8; 1_280];
    raw[..4].copy_from_slice(b"DSS3");
    raw[4..6].copy_from_slice(&3u16.to_le_bytes());
    raw[6] = 2; // halted: an unchecked CLOSE_ACCOUNT would accept this shape
    raw[7] = 0; // indexed policy
    raw[8] = 1;
    raw[9] = 8;
    raw[10..14].copy_from_slice(&8u32.to_le_bytes());
    raw[14..22].copy_from_slice(&id.to_le_bytes());
    raw[22..54].copy_from_slice(authority.as_ref());
    raw[54..86].copy_from_slice(authority.as_ref());
    raw[86..102].copy_from_slice(&manifest.id.0);
    raw[102..104].copy_from_slice(&manifest.semantic_version.to_le_bytes());
    raw[104..106].copy_from_slice(&manifest.abi_version.to_le_bytes());
    raw[106..110].copy_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    raw[110..112].copy_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    raw[124..156].fill(0xA5);
    raw[156..188].fill(0xA5);
    raw[1183..1187].copy_from_slice(&app::V3_STATE_SCHEMA.id.to_le_bytes());
    raw[1187..1189].copy_from_slice(&app::V3_STATE_SCHEMA.version.to_le_bytes());
    raw[1189] = 1;
    raw[1262] = bump;
    raw
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_forged_session_and_other_primary_are_refused() {
    let authority = keypair(66);
    let id = 6;
    let resource = forged_session_resource(authority.pubkey(), id);
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let (session, _, forged_primary) =
        open_fixed_small(&mut context, &authority, id, &resource).await;
    let victim_authority = keypair(67);
    let (victim_session, _, victim_primary) =
        open_fixed_small(&mut context, &victim_authority, id + 1, &resource).await;
    assert_ne!(session, victim_session);

    let payer = context.payer.pubkey();
    for child_session in [session, victim_session] {
        for (ix, label) in [
            (
                create_view(payer, child_session),
                "CREATE_VIEW-v3-provenance",
            ),
            (
                create_workspace(payer, child_session),
                "CREATE_WORKSPACE-v3-provenance",
            ),
            (
                create_staging_scratch(payer, child_session),
                "CREATE_SCRATCH-v3-provenance",
            ),
        ] {
            send(&mut context, ix, &[], label, Ok(()), false).await;
        }
    }
    let mut foreign_workspace = publication_accounts(authority.pubkey(), session, false);
    foreign_workspace[5] = AccountMeta::new(view_pda(&victim_session, v3::WORKSPACE_ROLE), false);
    let mut foreign_scratch = publication_accounts(authority.pubkey(), session, false);
    foreign_scratch[6] = AccountMeta::new(view_pda(&victim_session, v3::SCRATCH_ROLE), false);
    send(
        &mut context,
        begin_view_with_accounts(authority.pubkey(), foreign_workspace),
        &[&authority],
        "BEGIN_PHASE-v3-other-session-workspace-refused",
        Err(v3::REFUSAL_VIEW),
        true,
    )
    .await;
    send(
        &mut context,
        begin_view_with_accounts(authority.pubkey(), foreign_scratch),
        &[&authority],
        "BEGIN_PHASE-v3-other-session-scratch-refused",
        Err(v3::REFUSAL_VIEW),
        true,
    )
    .await;

    let before_forged = account(&mut context, forged_primary).await;
    let refund_before = context
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap_or(0);
    send(
        &mut context,
        close_session(forged_primary, authority.pubkey()),
        &[],
        "CLOSE_ACCOUNT-v3-forged-session-primary",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;
    assert_eq!(account(&mut context, forged_primary).await, before_forged);
    assert_eq!(
        context
            .banks_client
            .get_balance(authority.pubkey())
            .await
            .unwrap_or(0),
        refund_before
    );

    let mut active_forgery = before_forged.clone();
    active_forgery.data[6] = 1;
    active_forgery.data[116..120].copy_from_slice(&0u32.to_le_bytes());
    active_forgery.data[120..122].copy_from_slice(&1u16.to_le_bytes());
    active_forgery.data[122] = 1;
    active_forgery.data[260..292].copy_from_slice(stream_pda(&forged_primary).as_ref());
    active_forgery.data[292..324].copy_from_slice(state_pda(&forged_primary, 0).as_ref());
    active_forgery.data[224..228].copy_from_slice(&1_280u32.to_le_bytes());
    active_forgery.data[1182] = 0;
    active_forgery.data[1164] = 2;
    active_forgery.data[1170..1174].copy_from_slice(&0u32.to_le_bytes());
    active_forgery.data[1174..1178].copy_from_slice(&1_280u32.to_le_bytes());
    active_forgery.data[1178..1182].copy_from_slice(&app::V3_INIT_COMPUTE_UNITS.to_le_bytes());
    active_forgery.data[1222..1226].copy_from_slice(&1_280u32.to_le_bytes());
    active_forgery.data[1263..1267].copy_from_slice(&0u32.to_le_bytes());
    context.set_account(&forged_primary, &AccountSharedData::from(active_forgery));
    send(
        &mut context,
        advance_with_substitute(victim_primary, authority.pubkey(), forged_primary, 0, 1),
        &[&authority],
        "ADVANCE-v3-through-forged-session-image",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;
    send(
        &mut context,
        run_initialization_with_state(authority.pubkey(), forged_primary, victim_primary, 0),
        &[&authority],
        "RUN_INITIALIZE-v3-through-forged-session-image",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;

    send(
        &mut context,
        write_input(authority.pubkey(), session, 0, 1),
        &[&authority],
        "WRITE_INPUT-v3-for-primary-substitution",
        Ok(()),
        false,
    )
    .await;
    let victim_before = account(&mut context, victim_primary).await;
    let state_before = account(&mut context, forged_primary).await;
    let session_before = account(&mut context, session).await;
    send(
        &mut context,
        advance_with_substitute(victim_primary, authority.pubkey(), session, 0, 1),
        &[&authority],
        "ADVANCE-v3-other-session-primary-at-index-0",
        Err(v3::REFUSAL_STATE),
        true,
    )
    .await;
    assert_eq!(account(&mut context, victim_primary).await, victim_before);
    assert_eq!(account(&mut context, forged_primary).await, state_before);
    assert_eq!(account(&mut context, session).await, session_before);
    send(
        &mut context,
        halt_session(authority.pubkey(), session, 0),
        &[&authority],
        "HALT_SESSION-v3-before-close-substitution",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        halt_session(victim_authority.pubkey(), victim_session, 0),
        &[&victim_authority],
        "HALT_SESSION-v3-before-cross-primary-close",
        Ok(()),
        false,
    )
    .await;
    let mut halted_forgery = account(&mut context, forged_primary).await;
    halted_forgery.data[6] = 2;
    halted_forgery.data[1164] = 0;
    halted_forgery.data[1166..1182].fill(0);
    halted_forgery.data[1254..1262].fill(0);
    context.set_account(&forged_primary, &AccountSharedData::from(halted_forgery));
    send(
        &mut context,
        close_child(session, victim_primary, authority.pubkey(), v3::KIND_STATE),
        &[],
        "CLOSE_ACCOUNT-v3-other-session-primary",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;
    send(
        &mut context,
        close_child(
            victim_session,
            forged_primary,
            victim_authority.pubkey(),
            v3::KIND_STATE,
        ),
        &[],
        "CLOSE_ACCOUNT-v3-primary-through-other-session",
        Err(v3::REFUSAL_SESSION),
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_failed_initialization_can_halt_and_recover_rent() {
    let resource = vec![0xEE; RESOURCE_LEN];
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let payer = context.payer.pubkey();
    let authority = keypair(68);
    let session = session_pda(&authority.pubkey(), 8);
    let state = state_pda(&session, 0);
    let stream = stream_pda(&session);
    let resource_copy = resource_pda(&session);
    send(
        &mut context,
        open_primary(payer, authority.pubkey(), 8, resource_root(&resource)),
        &[&authority],
        "OPEN_SESSION-v3-permanent-init-failure",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        upload_resource_chunk(
            authority.pubkey(),
            session,
            RESOURCE,
            0,
            &resource_proof(&resource, 0),
        ),
        &[&authority],
        "RESOURCE_CHUNK-v3-permanent-init-failure",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-failure",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        create_primary_state_len(payer, session, 1_280),
        &[],
        "CREATE_STATE-v3-failure",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        begin_initialization_len(authority.pubkey(), session, 1_280),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-permanent-failure",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-permanent-failure",
        Err(v3::REFUSAL_KERNEL),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await.data[1164], 2);
    let refund_before = context
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap_or(0);
    send(
        &mut context,
        halt_session(authority.pubkey(), session, 0),
        &[&authority],
        "HALT_SESSION-v3-aborts-failed-initialization",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await.data[1164], 0);
    for (target, kind, label) in [
        (state, v3::KIND_STATE, "CLOSE_ACCOUNT-v3-failed-state"),
        (stream, v3::KIND_STREAM, "CLOSE_ACCOUNT-v3-failed-stream"),
        (
            resource_copy,
            v3::KIND_RESOURCE,
            "CLOSE_ACCOUNT-v3-failed-resource",
        ),
    ] {
        send(
            &mut context,
            close_child(session, target, authority.pubkey(), kind),
            &[],
            label,
            Ok(()),
            true,
        )
        .await;
    }
    send(
        &mut context,
        close_session(session, authority.pubkey()),
        &[],
        "CLOSE_ACCOUNT-v3-failed-session",
        Ok(()),
        true,
    )
    .await;
    let refund_after = context
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap_or(0);
    assert!(refund_after > refund_before);
    assert!(context
        .banks_client
        .get_account(session)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_halt_with_view_phase_open_still_allows_closing_children() {
    let (mut context, _) = start_sbf().await;
    let authority = keypair(69);
    let (session, stream, state) =
        open_fixed_small(&mut context, &authority, 9, &vec![0x5A; RESOURCE_LEN]).await;
    let payer = context.payer.pubkey();
    let output = view_pda(&session, 0);
    let workspace = view_pda(&session, v3::WORKSPACE_ROLE);
    let scratch = view_pda(&session, v3::SCRATCH_ROLE);
    let resource_copy = resource_pda(&session);
    for (ix, label) in [
        (
            create_view(payer, session),
            "CREATE_VIEW-v3-halt-open-phase",
        ),
        (
            create_workspace(payer, session),
            "CREATE_WORKSPACE-v3-halt-open-phase",
        ),
        (
            create_staging_scratch(payer, session),
            "CREATE_SCRATCH-v3-halt-open-phase",
        ),
    ] {
        send(&mut context, ix, &[], label, Ok(()), true).await;
    }
    send(
        &mut context,
        begin_view(authority.pubkey(), session),
        &[&authority],
        "BEGIN_PHASE-v3-halt-open-view",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        halt_session(authority.pubkey(), session, 0),
        &[&authority],
        "HALT_SESSION-v3-open-view-phase",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(account(&mut context, session).await.data[1164], 0);
    for (target, kind, label) in [
        (state, v3::KIND_STATE, "CLOSE_ACCOUNT-v3-halted-view-state"),
        (
            stream,
            v3::KIND_STREAM,
            "CLOSE_ACCOUNT-v3-halted-view-stream",
        ),
        (output, 3, "CLOSE_ACCOUNT-v3-halted-view-output"),
        (
            workspace,
            v3::KIND_WORKSPACE,
            "CLOSE_ACCOUNT-v3-halted-view-workspace",
        ),
        (scratch, 4, "CLOSE_ACCOUNT-v3-halted-view-scratch"),
        (
            resource_copy,
            v3::KIND_RESOURCE,
            "CLOSE_ACCOUNT-v3-halted-view-resource",
        ),
    ] {
        send(
            &mut context,
            close_child(session, target, authority.pubkey(), kind),
            &[],
            label,
            Ok(()),
            false,
        )
        .await;
    }
    send(
        &mut context,
        close_session(session, authority.pubkey()),
        &[],
        "CLOSE_ACCOUNT-v3-halted-view-session",
        Ok(()),
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_halt_outcomes_are_atomic_and_close_input_after_halt() {
    let (mut context, _) = start_sbf().await;
    let resource = vec![0x5A; RESOURCE_LEN];

    let mutation_authority = keypair(70);
    let (mutation_session, mutation_stream, mutation_state) =
        open_fixed_small(&mut context, &mutation_authority, 10, &resource).await;
    send(
        &mut context,
        write_input(mutation_authority.pubkey(), mutation_session, 0, 0xED),
        &[&mutation_authority],
        "WRITE_INPUT-v3-halt-before-mutation",
        Ok(()),
        false,
    )
    .await;
    let mutation_state_before = account(&mut context, mutation_state).await;
    let mutation_session_before = account(&mut context, mutation_session).await;
    let mutation_stream_before = account(&mut context, mutation_stream).await;
    send(
        &mut context,
        advance(mutation_authority.pubkey(), mutation_session, 0, 1),
        &[&mutation_authority],
        "ADVANCE-v3-halt-before-mutation-refused",
        Err(v3::REFUSAL_KERNEL),
        true,
    )
    .await;
    assert_eq!(
        account(&mut context, mutation_state).await,
        mutation_state_before
    );
    assert_eq!(
        account(&mut context, mutation_session).await,
        mutation_session_before
    );
    assert_eq!(
        account(&mut context, mutation_stream).await,
        mutation_stream_before
    );

    let after_authority = keypair(71);
    let (after_session, _, after_state) =
        open_fixed_small(&mut context, &after_authority, 11, &resource).await;
    send(
        &mut context,
        write_input(after_authority.pubkey(), after_session, 0, 0xEF),
        &[&after_authority],
        "WRITE_INPUT-v3-halt-after",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        advance(after_authority.pubkey(), after_session, 0, 1),
        &[&after_authority],
        "ADVANCE-v3-halt-after-commits-trigger",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(account(&mut context, after_session).await.data[6], 2);
    assert_eq!(
        u32::from_le_bytes(
            account(&mut context, after_session).await.data[112..116]
                .try_into()
                .unwrap()
        ),
        1
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, after_state).await.data[1272..1280]
                .try_into()
                .unwrap()
        ),
        u64::from_le_bytes([0x5A; 8]) + 0xEF
    );
    send(
        &mut context,
        write_input(after_authority.pubkey(), after_session, 1, 1),
        &[&after_authority],
        "WRITE_INPUT-v3-after-halt-refused",
        Err(v3::REFUSAL_AUTHORITY),
        true,
    )
    .await;
    send(
        &mut context,
        advance(after_authority.pubkey(), after_session, 1, 1),
        &[&after_authority],
        "ADVANCE-v3-after-halt-refused",
        Err(v3::REFUSAL_AUTHORITY),
        true,
    )
    .await;

    let first_authority = keypair(72);
    let (first_session, _, _) =
        open_fixed_small(&mut context, &first_authority, 12, &resource).await;
    send(
        &mut context,
        write_input(first_authority.pubkey(), first_session, 0, 0xEE),
        &[&first_authority],
        "WRITE_INPUT-v3-halt-at-first-step",
        Ok(()),
        false,
    )
    .await;
    send(
        &mut context,
        advance(first_authority.pubkey(), first_session, 0, 1),
        &[&first_authority],
        "ADVANCE-v3-halt-at-first-step",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(
        u32::from_le_bytes(
            account(&mut context, first_session).await.data[112..116]
                .try_into()
                .unwrap()
        ),
        0
    );

    let last_authority = keypair(73);
    let (last_session, _, last_state) =
        open_fixed_small(&mut context, &last_authority, 13, &resource).await;
    for (sequence, command) in [1, 0xEE].into_iter().enumerate() {
        send(
            &mut context,
            write_input(
                last_authority.pubkey(),
                last_session,
                sequence as u32,
                command,
            ),
            &[&last_authority],
            &format!("WRITE_INPUT-v3-halt-last-step-{sequence}"),
            Ok(()),
            false,
        )
        .await;
    }
    send(
        &mut context,
        advance(last_authority.pubkey(), last_session, 0, 2),
        &[&last_authority],
        "ADVANCE-v3-halt-at-last-step",
        Ok(()),
        true,
    )
    .await;
    assert_eq!(
        u32::from_le_bytes(
            account(&mut context, last_session).await.data[112..116]
                .try_into()
                .unwrap()
        ),
        1
    );
    assert_eq!(
        u64::from_le_bytes(
            account(&mut context, last_state).await.data[1272..1280]
                .try_into()
                .unwrap()
        ),
        u64::from_le_bytes([0x5A; 8]) + 1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateful_v3_sealed_resource_accepts_4_4mb_chunks_once() {
    let resource: Vec<u8> = (0..DOOM_WAD_BYTES)
        .map(|index| ((index.wrapping_mul(31) + 7) & 0xFF) as u8)
        .collect();
    let original_root = resource_root(&resource);
    let (mut context, _) = start_sbf_with_resource(resource.clone()).await;
    let payer = context.payer.pubkey();
    let authority = keypair(74);
    let id = 14;
    let session = session_pda(&authority.pubkey(), id);
    let resource_copy = resource_pda(&session);
    let state = state_pda(&session, 0);
    send(
        &mut context,
        open_primary(payer, authority.pubkey(), id, original_root),
        &[&authority],
        "OPEN_SESSION-v3-4_4mb-resource",
        Ok(()),
        true,
    )
    .await;

    let initial_allocated = (account(&mut context, resource_copy).await.data.len() - 128) as u32;
    let grow_count = (resource.len() as u32 - initial_allocated).div_ceil(v3::CHILD_GROW_BYTES);
    let mut grow_cus = Vec::new();
    for batch_start in (0..grow_count).step_by(4) {
        let batch_end = (batch_start + 4).min(grow_count);
        let instructions = (batch_start..batch_end)
            .map(|round| {
                let allocated = (initial_allocated + (round + 1) * v3::CHILD_GROW_BYTES)
                    .min(resource.len() as u32);
                grow_resource_copy(payer, authority.pubkey(), session, allocated)
            })
            .collect();
        grow_cus.extend(
            send_many(
                &mut context,
                instructions,
                Some(&authority),
                &format!("RESOURCE_GROW-v3-4_4mb-{batch_start}..{batch_end}"),
            )
            .await,
        );
    }
    assert_eq!(grow_cus.len(), grow_count as usize);
    assert!(grow_cus.iter().all(|cu| *cu < 200_000));
    eprintln!(
        "stateful-v3 CU RESOURCE_GROW total_bytes={} calls={} min={} max={} total={}",
        resource.len(),
        grow_cus.len(),
        grow_cus.iter().min().unwrap(),
        grow_cus.iter().max().unwrap(),
        grow_cus.iter().sum::<u64>()
    );

    let mut chunk_cus = Vec::new();
    let chunk_count = resource.len().div_ceil(v3::RESOURCE_CHUNK_BYTES as usize);
    for batch_start in (0..chunk_count).step_by(4) {
        let batch_end = (batch_start + 4).min(chunk_count);
        let instructions = (batch_start..batch_end)
            .map(|index| {
                upload_resource_chunk(
                    authority.pubkey(),
                    session,
                    RESOURCE,
                    index as u32,
                    &resource_proof(&resource, index as u32),
                )
            })
            .collect();
        chunk_cus.extend(
            send_many(
                &mut context,
                instructions,
                Some(&authority),
                &format!("RESOURCE_CHUNK-v3-4_4mb-{batch_start}..{batch_end}"),
            )
            .await,
        );
    }
    assert_eq!(chunk_cus.len(), chunk_count);
    assert!(chunk_cus.iter().all(|cu| *cu < 200_000));
    let uploaded: u64 = chunk_cus.iter().sum();
    eprintln!(
        "stateful-v3 CU RESOURCE_CHUNK total_bytes={} chunk_count={} chunk_min={} chunk_max={} upload_total={} each={chunk_cus:?}",
        resource.len(),
        chunk_cus.len(),
        chunk_cus.iter().min().unwrap(),
        chunk_cus.iter().max().unwrap(),
        uploaded,
    );
    let sealed = account(&mut context, resource_copy).await.data;
    assert_eq!(&sealed[128..], resource.as_slice());

    let mut changed_source = account(&mut context, RESOURCE).await;
    changed_source.data.fill(0xA7);
    context.set_account(&RESOURCE, &AccountSharedData::from(changed_source));
    send(
        &mut context,
        create_stream(payer, session),
        &[],
        "CREATE_STREAM-v3-4_4mb-resource",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        create_primary_state_len(payer, session, 1_280),
        &[],
        "CREATE_STATE-v3-4_4mb-resource",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        begin_initialization_len(authority.pubkey(), session, 1_280),
        &[&authority],
        "BEGIN_INITIALIZATION-v3-4_4mb-resource",
        Ok(()),
        true,
    )
    .await;
    send(
        &mut context,
        run_initialization(authority.pubkey(), session, 0),
        &[&authority],
        "RUN_INITIALIZATION-v3-4_4mb-resource",
        Ok(()),
        true,
    )
    .await;
    let initialized = account(&mut context, state).await.data;
    assert_eq!(&initialized[..228], &resource[..228]);
    assert_eq!(&initialized[260..], &resource[260..1_280]);
    let sealed_after = account(&mut context, resource_copy).await.data;
    assert_eq!(&sealed_after[128..], resource.as_slice());
}
