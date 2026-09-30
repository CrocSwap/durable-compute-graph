// SPDX-License-Identifier: GPL-3.0-only

use dcg_program::{kernel::Kernel, stateful, stateful_test};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::{keypair_from_seed, Keypair};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest};
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]);

fn pda(seed: &[u8], parts: &[&[u8]]) -> Pubkey {
    let mut all = Vec::with_capacity(parts.len() + 1);
    all.push(seed);
    all.extend_from_slice(parts);
    Pubkey::find_program_address(&all, &PROGRAM_ID).0
}

fn session_address(authority: &Pubkey, id: u64) -> Pubkey {
    let id = id.to_le_bytes();
    pda(b"dcg-session-v1", &[authority.as_ref(), &id])
}

fn child_address(seed: &[u8], session: &Pubkey, index: Option<u8>) -> Pubkey {
    match index {
        Some(index) => pda(seed, &[session.as_ref(), &[index]]),
        None => pda(seed, &[session.as_ref()]),
    }
}

fn ix(tag: u8, body: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend(body);
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

fn open_session(payer: Pubkey, authority: Pubkey, session_id: u64) -> Instruction {
    let kernel = stateful_test::COUNTER.manifest();
    let mut body = vec![stateful::WIRE_VERSION];
    body.extend_from_slice(&session_id.to_le_bytes());
    body.extend_from_slice(&[
        stateful::POLICY_APPEND,
        1, // one-byte input
    ]);
    body.extend_from_slice(&8u16.to_le_bytes()); // input slots
    body.push(1); // one step per advance
    body.extend_from_slice(&kernel.id.0);
    body.extend_from_slice(&kernel.semantic_version.to_le_bytes());
    body.extend_from_slice(&kernel.abi_version.to_le_bytes());
    body.extend_from_slice(&stateful::MODE_CONSENSUS_V1.id.to_le_bytes());
    body.extend_from_slice(&stateful::MODE_CONSENSUS_V1.version.to_le_bytes());
    body.extend_from_slice(&[0xA5; 32]); // app-defined stream identity
    body.extend_from_slice(authority.as_ref()); // this app uses authority as writer
    ix(
        stateful::TAG_OPEN_SESSION,
        body,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session_address(&authority, session_id), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

fn create_stream(payer: Pubkey, session: Pubkey) -> Instruction {
    ix(
        stateful::TAG_CREATE_STREAM,
        vec![stateful::WIRE_VERSION],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(child_address(b"dcg-input-v1", &session, None), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

fn create_state(payer: Pubkey, session: Pubkey) -> Instruction {
    let mut body = vec![stateful::WIRE_VERSION, 2]; // two 8-byte state spans
    body.extend_from_slice(&8u32.to_le_bytes());
    body.extend_from_slice(&8u32.to_le_bytes());
    ix(
        stateful::TAG_CREATE_STATE,
        body,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new(child_address(b"dcg-state-v1", &session, Some(0)), false),
            AccountMeta::new(child_address(b"dcg-state-v1", &session, Some(1)), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

fn write_one(authority: Pubkey, session: Pubkey, delta: u8) -> Instruction {
    let mut body = vec![stateful::WIRE_VERSION];
    body.extend_from_slice(&0u32.to_le_bytes()); // first input slot
    body.push(1); // input width
    body.push(delta);
    ix(
        stateful::TAG_WRITE_INPUT,
        body,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(child_address(b"dcg-input-v1", &session, None), false),
        ],
    )
}

fn advance(authority: Pubkey, session: Pubkey) -> Instruction {
    let mut body = vec![stateful::WIRE_VERSION];
    body.extend_from_slice(&0u32.to_le_bytes()); // expected input cursor
    body.push(1); // one transition
    ix(
        stateful::TAG_ADVANCE,
        body,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(session, false),
            AccountMeta::new(child_address(b"dcg-input-v1", &session, None), false),
            AccountMeta::new(child_address(b"dcg-state-v1", &session, Some(0)), false),
            AccountMeta::new(child_address(b"dcg-state-v1", &session, Some(1)), false),
        ],
    )
}

async fn submit(
    context: &mut solana_program_test::ProgramTestContext,
    instruction: Instruction,
    authority: &Keypair,
    label: &str,
) {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let authority_is_signer = instruction
        .accounts
        .iter()
        .any(|meta| meta.pubkey == authority.pubkey() && meta.is_signer);
    let mut signers = vec![&context.payer];
    if authority_is_signer {
        signers.push(authority);
    }
    let transaction = Transaction::new(
        &signers,
        solana_program::message::Message::new(&[instruction], Some(&context.payer.pubkey())),
        blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap_or_else(|error| panic!("DCG {label} instruction failed: {error:?}"));
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let delta: u8 = args
        .next()
        .expect("usage: dcg-hello-world <increment-0-to-255>")
        .parse()
        .expect("increment must be an integer from 0 to 255");
    assert!(args.next().is_none(), "provide exactly one increment");

    let authority = keypair_from_seed(&[17; 32]).expect("fixed demo keypair");
    let authority_pubkey = authority.pubkey();
    let session_id = 1;
    let session = session_address(&authority_pubkey, session_id);
    let state0 = child_address(b"dcg-state-v1", &session, Some(0));
    let state1 = child_address(b"dcg-state-v1", &session, Some(1));

    let mut test = ProgramTest::new(
        "dcg_program",
        PROGRAM_ID,
        processor!(dcg_program::process_instruction),
    );
    test.prefer_bpf(false);
    solana_logger::setup_with("error");
    test.set_compute_max_units(1_400_000);
    test.add_account(
        authority_pubkey,
        Account {
            lamports: 10_000_000_000,
            data: Vec::new(),
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let mut context = test.start_with_context().await;
    let payer = context.payer.pubkey();

    submit(
        &mut context,
        open_session(payer, authority_pubkey, session_id),
        &authority,
        "open session",
    )
    .await;
    submit(
        &mut context,
        create_stream(payer, session),
        &authority,
        "create input stream",
    )
    .await;
    submit(
        &mut context,
        create_state(payer, session),
        &authority,
        "create state",
    )
    .await;
    submit(
        &mut context,
        write_one(authority_pubkey, session, delta),
        &authority,
        "write input",
    )
    .await;
    submit(
        &mut context,
        advance(authority_pubkey, session),
        &authority,
        "advance counter",
    )
    .await;

    let value_account = context
        .banks_client
        .get_account(state0)
        .await
        .unwrap()
        .unwrap();
    let total_account = context
        .banks_client
        .get_account(state1)
        .await
        .unwrap()
        .unwrap();
    let value = u64::from_le_bytes(value_account.data[128..136].try_into().unwrap());
    let total = u64::from_le_bytes(total_account.data[128..136].try_into().unwrap());
    assert_eq!(value, delta as u64);
    assert_eq!(total, delta as u64);
    println!("input={delta} value={value} total={total}");
}
