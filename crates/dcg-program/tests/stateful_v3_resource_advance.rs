#![cfg(feature = "sbf-real-lifecycle-test")]

//! Stateful v3: the sealed resource during ADVANCE (DCG v0.3.0 item 1,
//! `KernelCapabilities::READS_RESOURCE`). The resource-reading fixed engine
//! adds the input and the resource byte at `value % len` on every step.
//! Native ProgramTest by default, or the feature-built SBF image with
//! `V3_SBF=1` and `BPF_OUT_DIR`/`SBF_OUT_DIR`.

use dcg_program::{hash::sha256, kernel::Kernel, stateful as sw, stateful::v3, stateful_test as app};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const RESOURCE: Pubkey = Pubkey::new_from_array(app::V3_RESOURCE_KEY);
const SYSTEM: Pubkey = system_program::ID;
const RESOURCE_LEN: usize = 4_096;
const STREAM_CAPACITY: u32 = 8;
const PRIMARY_LEN: u32 = 1_280;

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

fn resource_pda(session: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dcg-resource-v3", session.as_ref()], &PROGRAM).0
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

fn create_stream(payer: Pubkey, authority: Pubkey, session: Pubkey) -> Instruction {
    instruction(
        sw::TAG_CREATE_STREAM,
        vec![v3::WIRE_VERSION, 0],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(stream_pda(&session), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn create_primary_state_len(payer: Pubkey, authority: Pubkey, session: Pubkey, len: u32) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION, 1];
    payload.extend_from_slice(&len.to_le_bytes());
    instruction(
        sw::TAG_CREATE_STATE,
        payload,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(resource_pda(&session), false),
            AccountMeta::new(state_pda(&session, 0), false),
            AccountMeta::new_readonly(SYSTEM, false),
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

fn open_primary(payer: Pubkey, authority: Pubkey, id: u64, commitment: [u8; 32]) -> Instruction {
    let manifest = app::V3_RESOURCE_ENGINE.manifest();
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
    payload.extend_from_slice(&[0, v3::FEATURE_READS_RESOURCE]); // no lanes; the recorded capability
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

fn resource_bytes() -> Vec<u8> {
    (0..RESOURCE_LEN).map(|i| ((i * 7 + 3) % 251) as u8).collect()
}

fn advance_accounts(authority: Pubkey, session: Pubkey, cursor: u32, steps: u8, resource: Option<AccountMeta>) -> Instruction {
    let mut payload = vec![v3::WIRE_VERSION];
    payload.extend_from_slice(&cursor.to_le_bytes());
    payload.push(steps);
    let mut accounts = vec![
        AccountMeta::new(state_pda(&session, 0), false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(session, false),
        AccountMeta::new(stream_pda(&session), false),
    ];
    accounts.extend(resource);
    instruction(sw::TAG_ADVANCE, payload, accounts)
}

async fn start() -> ProgramTestContext {
    let sbf = std::env::var("V3_SBF").is_ok_and(|v| v == "1");
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    test.add_genesis_account(
        RESOURCE,
        Account { lamports: 1_000_000, data: resource_bytes(), owner: PROGRAM, executable: false, rent_epoch: 0 },
    );
    test.start_with_context().await
}

async fn try_send(context: &mut ProgramTestContext, ix: Instruction, signers: &[&Keypair]) -> Result<u64, String> {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&context.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[ix], Some(&context.payer.pubkey())), blockhash);
    let r = context.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    let cu = r.metadata.as_ref().map(|m| m.compute_units_consumed).unwrap_or(0);
    r.result.map(|_| cu).map_err(|e| format!("{e:?}"))
}

async fn ok(context: &mut ProgramTestContext, ix: Instruction, signers: &[&Keypair], label: &str) -> u64 {
    try_send(context, ix, signers).await.unwrap_or_else(|e| panic!("{label}: {e}"))
}

async fn counter(context: &mut ProgramTestContext, session: &Pubkey) -> u64 {
    let raw = context.banks_client.get_account(state_pda(session, 0)).await.unwrap().unwrap().data;
    let at = PRIMARY_LEN as usize - 8;
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

/// Open, seal the resource, create the stream and the 1,280-byte headerless
/// primary, and initialize it from the resource.
async fn open_reading_session(context: &mut ProgramTestContext, authority: &Keypair, id: u64) -> Pubkey {
    let payer = context.payer.pubkey();
    let session = session_pda(&authority.pubkey(), id);
    let resource = resource_bytes();
    ok(context, open_primary(payer, authority.pubkey(), id, resource_root(&resource)), &[authority], "open").await;
    ok(context, upload_resource_chunk(authority.pubkey(), session, RESOURCE, 0, &resource_proof(&resource, 0)), &[authority], "chunk").await;
    ok(context, create_stream(payer, authority.pubkey(), session), &[authority], "stream").await;
    ok(context, create_primary_state_len(payer, authority.pubkey(), session, PRIMARY_LEN), &[authority], "state").await;
    ok(context, begin_initialization_len(authority.pubkey(), session, PRIMARY_LEN), &[authority], "begin-init").await;
    ok(context, run_initialization(authority.pubkey(), session, 0), &[authority], "run-init").await;
    session
}

fn model(mut value: u64, inputs: &[u8]) -> u64 {
    let resource = resource_bytes();
    for input in inputs {
        value += *input as u64 + resource[(value % resource.len() as u64) as usize] as u64;
    }
    value
}

#[tokio::test(flavor = "multi_thread")]
async fn advance_passes_the_sealed_resource_to_a_declaring_kernel() {
    assert!(app::V3_RESOURCE_ENGINE.manifest().capabilities.reads_resource());
    let mut context = start().await;
    let authority = keypair(41);
    let session = open_reading_session(&mut context, &authority, 1).await;
    let inputs = [1u8, 2, 3, 250, 7];
    for (seq, input) in inputs.iter().enumerate() {
        ok(&mut context, write_input(authority.pubkey(), session, seq as u32, *input), &[&authority], "write").await;
    }
    let start_value = counter(&mut context, &session).await;
    let copy = AccountMeta::new_readonly(resource_pda(&session), false);
    let cu = ok(&mut context, advance_accounts(authority.pubkey(), session, 0, 3, Some(copy.clone())), &[&authority], "advance-3").await;
    assert_eq!(counter(&mut context, &session).await, model(start_value, &inputs[..3]));
    ok(&mut context, advance_accounts(authority.pubkey(), session, 3, 2, Some(copy)), &[&authority], "advance-2").await;
    assert_eq!(counter(&mut context, &session).await, model(start_value, &inputs));
    eprintln!("stateful-v3 resource ADVANCE 3 steps: {cu} CU");
}

#[tokio::test(flavor = "multi_thread")]
async fn advance_refuses_a_missing_wrong_or_writable_resource() {
    let mut context = start().await;
    let authority = keypair(42);
    let session = open_reading_session(&mut context, &authority, 1).await;
    let other = open_reading_session(&mut context, &authority, 2).await;
    ok(&mut context, write_input(authority.pubkey(), session, 0, 5), &[&authority], "write").await;
    let before = counter(&mut context, &session).await;
    let cases: Vec<(&str, Option<AccountMeta>)> = vec![
        ("missing (the pre-0.3 account list)", None),
        ("another session's sealed copy", Some(AccountMeta::new_readonly(resource_pda(&other), false))),
        ("the unsealed source account", Some(AccountMeta::new_readonly(RESOURCE, false))),
        ("the right copy, writable (refused by the program)", Some(AccountMeta::new(resource_pda(&session), false))),
        ("a state account in the resource slot", Some(AccountMeta::new_readonly(state_pda(&other, 0), false))),
    ];
    for (label, resource) in cases {
        let program_refusal = label.contains("writable") || label.contains("another session") || label.contains("source") || label.contains("state account");
        let got = try_send(&mut context, advance_accounts(authority.pubkey(), session, 0, 1, resource), &[&authority]).await;
        assert!(got.is_err(), "{label}: ADVANCE was accepted");
        if program_refusal {
            let want = format!("Custom({})", v3::REFUSAL_RESOURCE);
            assert!(got.as_ref().unwrap_err().contains(&want), "{label}: {got:?}, want {want}");
        }
        assert_eq!(counter(&mut context, &session).await, before, "{label}: state changed");
    }
    // The honest list still advances afterwards.
    ok(&mut context, advance_accounts(authority.pubkey(), session, 0, 1, Some(AccountMeta::new_readonly(resource_pda(&session), false))), &[&authority], "honest").await;
    assert_eq!(counter(&mut context, &session).await, model(before, &[5]));
}

#[tokio::test(flavor = "multi_thread")]
async fn open_refuses_a_resource_reading_kernel_without_a_resource() {
    let mut context = start().await;
    let authority = keypair(43);
    let payer = context.payer.pubkey();
    let mut open = open_primary(payer, authority.pubkey(), 1, [0; 32]);
    // No resource: zero key, schema and commitment, and the short account list.
    open.data[107..177].fill(0);
    open.accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(authority.pubkey(), true),
        AccountMeta::new(session_pda(&authority.pubkey(), 1), false),
        AccountMeta::new_readonly(SYSTEM, false),
    ];
    let got = try_send(&mut context, open.clone(), &[&authority]).await;
    assert!(got.is_err(), "a READS_RESOURCE session opened without a resource");
    // Control: the same resource-free open, without the feature, succeeds for
    // the plain fixed engine.
    open.data[17..33].copy_from_slice(&app::V3_FIXED_ENGINE.manifest().id.0);
    open.data.truncate(178);
    ok(&mut context, open, &[&authority], "control open").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_recorded_feature_must_equal_the_kernels_declaration() {
    let mut context = start().await;
    let authority = keypair(44);
    let payer = context.payer.pubkey();
    let resource = resource_bytes();
    // The resource engine without the feature byte.
    let want = format!("Custom({})", v3::REFUSAL_RESOURCE);
    let mut open = open_primary(payer, authority.pubkey(), 1, resource_root(&resource));
    open.data.truncate(178);
    let got = try_send(&mut context, open, &[&authority]).await;
    assert!(got.as_ref().is_err_and(|e| e.contains(&want)), "READS_RESOURCE kernel without the feature: {got:?}");
    // The plain fixed engine with the feature.
    let mut open = open_primary(payer, authority.pubkey(), 2, resource_root(&resource));
    open.data[17..33].copy_from_slice(&app::V3_FIXED_ENGINE.manifest().id.0);
    open.accounts[2] = AccountMeta::new(session_pda(&authority.pubkey(), 2), false);
    open.accounts[4] = AccountMeta::new(resource_pda(&session_pda(&authority.pubkey(), 2)), false);
    let got = try_send(&mut context, open, &[&authority]).await;
    assert!(got.as_ref().is_err_and(|e| e.contains(&want)), "the feature without the capability: {got:?}");
}

/// The ADVANCE half of review M3: a live session whose recorded feature no
/// longer matches the kernel's declaration (as after an upgrade without a
/// version bump; here the record is edited directly) refuses with
/// REFUSAL_SESSION. And review L3: a sealed copy that is not fully allocated
/// refuses with REFUSAL_RESOURCE.
#[tokio::test(flavor = "multi_thread")]
async fn advance_refuses_a_changed_feature_or_a_partly_allocated_copy() {
    let mut context = start().await;
    let authority = keypair(46);
    let session = open_reading_session(&mut context, &authority, 1).await;
    ok(&mut context, write_input(authority.pubkey(), session, 0, 5), &[&authority], "write").await;
    let honest = || advance_accounts(authority.pubkey(), session, 0, 1, Some(AccountMeta::new_readonly(resource_pda(&session), false)));
    // The feature byte cleared.
    let original = context.banks_client.get_account(session).await.unwrap().unwrap();
    let mut edited = original.clone();
    edited.data[1273] &= !v3::FEATURE_READS_RESOURCE;
    context.set_account(&session, &edited.into());
    let got = try_send(&mut context, honest(), &[&authority]).await;
    assert!(got.as_ref().is_err_and(|e| e.contains(&format!("Custom({})", v3::REFUSAL_SESSION))), "{got:?}");
    context.set_account(&session, &original.into());
    // The copy shortened by 8 bytes with `allocated` to match: still every
    // chunk received, but not the whole resource.
    let copy = context.banks_client.get_account(resource_pda(&session)).await.unwrap().unwrap();
    let mut short = copy.clone();
    let allocated = u32::from_le_bytes(short.data[112..116].try_into().unwrap());
    short.data[112..116].copy_from_slice(&(allocated - 8).to_le_bytes());
    short.data.truncate(short.data.len() - 8);
    context.set_account(&resource_pda(&session), &short.into());
    let got = try_send(&mut context, honest(), &[&authority]).await;
    assert!(got.as_ref().is_err_and(|e| e.contains(&format!("Custom({})", v3::REFUSAL_RESOURCE))), "{got:?}");
    context.set_account(&resource_pda(&session), &copy.into());
    ok(&mut context, honest(), &[&authority], "restored").await;
}

/// The headered layout: `[authority, session, stream, resource, spans...]`
/// with the resource counter (two 8-byte headered spans).
#[tokio::test(flavor = "multi_thread")]
async fn a_headered_session_reads_the_resource() {
    let mut context = start().await;
    let authority = keypair(45);
    let payer = context.payer.pubkey();
    let session = session_pda(&authority.pubkey(), 7);
    let resource = resource_bytes();
    let mut open = open_primary(payer, authority.pubkey(), 7, resource_root(&resource));
    let m = app::V3_RESOURCE_COUNTER.manifest();
    open.data[17..33].copy_from_slice(&m.id.0);
    open.data[177] = 0; // headered state
    ok(&mut context, open, &[&authority], "open").await;
    ok(&mut context, upload_resource_chunk(authority.pubkey(), session, RESOURCE, 0, &resource_proof(&resource, 0)), &[&authority], "chunk").await;
    ok(&mut context, create_stream(payer, authority.pubkey(), session), &[&authority], "stream").await;
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&8u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    ok(&mut context, instruction(sw::TAG_CREATE_STATE, p, vec![
        AccountMeta::new(payer, true), AccountMeta::new(session, false), AccountMeta::new_readonly(authority.pubkey(), true),
        AccountMeta::new_readonly(resource_pda(&session), false),
        AccountMeta::new(state_pda(&session, 0), false), AccountMeta::new(state_pda(&session, 1), false),
        AccountMeta::new_readonly(SYSTEM, false)]), &[&authority], "state").await;
    ok(&mut context, instruction(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE], vec![
        AccountMeta::new_readonly(authority.pubkey(), true), AccountMeta::new(session, false),
        AccountMeta::new_readonly(resource_pda(&session), false),
        AccountMeta::new(state_pda(&session, 0), false), AccountMeta::new(state_pda(&session, 1), false)]), &[&authority], "init").await;
    for (seq, cmd) in [3u8, 9, 1].iter().enumerate() {
        ok(&mut context, write_input(authority.pubkey(), session, seq as u32, *cmd), &[&authority], "write").await;
    }
    let mut d = vec![v3::WIRE_VERSION];
    d.extend_from_slice(&0u32.to_le_bytes());
    d.push(3);
    let accounts = vec![
        AccountMeta::new_readonly(authority.pubkey(), true), AccountMeta::new(session, false),
        AccountMeta::new(stream_pda(&session), false), AccountMeta::new_readonly(resource_pda(&session), false),
        AccountMeta::new(state_pda(&session, 0), false), AccountMeta::new(state_pda(&session, 1), false)];
    ok(&mut context, instruction(sw::TAG_ADVANCE, d, accounts), &[&authority], "advance").await;
    let (mut value, mut total) = (0u64, 0u64);
    for cmd in [3u8, 9, 1] {
        value += cmd as u64 + resource[(value % resource.len() as u64) as usize] as u64;
        total += value;
    }
    let v = context.banks_client.get_account(state_pda(&session, 0)).await.unwrap().unwrap().data;
    let t = context.banks_client.get_account(state_pda(&session, 1)).await.unwrap().unwrap().data;
    assert_eq!(u64::from_le_bytes(v[128..136].try_into().unwrap()), value);
    assert_eq!(u64::from_le_bytes(t[128..136].try_into().unwrap()), total);
}
