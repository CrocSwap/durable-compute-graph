#![cfg(feature = "sbf-real-lifecycle-test")]

//! The session verdict reader (`stateful::v3::read_verdict`, v0.3.0) and an
//! example registry program that copies a finished session's verdict into its
//! own account, without a CPI into DCG, so the session can then close.
//! Native ProgramTest (two programs: DCG's test image and the registry).

use dcg_program::{
    hash::sha256,
    kernel::{Kernel, KernelId},
    stateful as sw,
    stateful::v3,
    stateful_test as app,
};
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed, program_error::ProgramError,
    pubkey::Pubkey, rent::Rent, system_instruction, system_program, sysvar::Sysvar,
};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xDA; 32]);
const REGISTRY: Pubkey = Pubkey::new_from_array([0xBB; 32]);
const SYSTEM: Pubkey = system_program::ID;
const STREAM_ROOT: [u8; 32] = [0x33; 32];
const TICKS: u8 = v3::FEATURE_RING_STREAM | v3::FEATURE_TICKS | v3::FEATURE_REJECTABLE;

// --- the example registry ---------------------------------------------------------------------

/// Record layout: session(32) authority(32) kernel(16) halt reason(4)
/// halt cursor(4) input root(32) resource commitment(32).
const RECORD_BYTES: usize = 152;

/// RECORD: data = kernel id(16) semver(2) abi(2) required reason(4);
/// accounts [payer(s,w), session(r), record(w), system]. Reads the verdict
/// with `read_verdict` against DCG's host program and the required kernel and
/// reason, then writes the record at `["verdict", session]`.
fn registry(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, session, record, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 24 || !payer.is_signer || *system.key != system_program::ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kernel = KernelId(data[..16].try_into().unwrap());
    let sv = u16::from_le_bytes(data[16..18].try_into().unwrap());
    let av = u16::from_le_bytes(data[18..20].try_into().unwrap());
    let reason = u32::from_le_bytes(data[20..24].try_into().unwrap());
    let verdict = v3::read_verdict(&PROGRAM, session).map_err(|e| ProgramError::Custom(100 + e as u32))?;
    verdict
        .require(&v3::VerdictRequirements { kernel: Some((kernel, sv, av)), halt_reason: Some(reason), ..Default::default() })
        .map_err(|e| ProgramError::Custom(100 + e as u32))?;
    let (address, bump) = Pubkey::find_program_address(&[b"verdict", session.key.as_ref()], program);
    if record.key != &address {
        return Err(ProgramError::InvalidSeeds);
    }
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            record.key,
            Rent::get()?.minimum_balance(RECORD_BYTES),
            RECORD_BYTES as u64,
            program,
        ),
        &[payer.clone(), record.clone(), system.clone()],
        &[&[b"verdict", session.key.as_ref(), &[bump]]],
    )?;
    let mut out = record.try_borrow_mut_data()?;
    out[..32].copy_from_slice(verdict.session.as_ref());
    out[32..64].copy_from_slice(verdict.authority.as_ref());
    out[64..80].copy_from_slice(&verdict.kernel.0);
    out[80..84].copy_from_slice(&verdict.halt_reason.to_le_bytes());
    out[84..88].copy_from_slice(&verdict.halt_cursor.to_le_bytes());
    out[88..120].copy_from_slice(&verdict.input_root);
    out[120..152].copy_from_slice(&verdict.resource_commitment);
    Ok(())
}

// --- helpers ----------------------------------------------------------------------------------

fn keypair(seed: u8) -> Keypair {
    solana_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}
fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM).0
}
fn session_pda(authority: &Pubkey, id: u64) -> Pubkey {
    pda(&[b"dcg-session-v3", authority.as_ref(), &id.to_le_bytes()])
}
fn stream_pda(s: &Pubkey) -> Pubkey {
    pda(&[b"dcg-input-v3", s.as_ref()])
}
fn state_pda(s: &Pubkey, i: u8) -> Pubkey {
    pda(&[b"dcg-state-v3", s.as_ref(), &[i]])
}
fn record_pda(s: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"verdict", s.as_ref()], &REGISTRY).0
}
fn ix(tag: u8, payload: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(&payload);
    Instruction { program_id: PROGRAM, accounts, data }
}
fn w(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, false)
}
fn r(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, false)
}
fn signer(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, true)
}

async fn start() -> ProgramTestContext {
    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    test.add_program("verdict_registry", REGISTRY, processor!(registry));
    test.start_with_context().await
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), u32> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    match ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap().result {
        Ok(()) => Ok(()),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Err(code),
        Err(_) => Err(u32::MAX),
    }
}

/// An indexed ring session of the tick-and-reject counter, opened and
/// initialized (two 8-byte spans).
async fn session(ctx: &mut ProgramTestContext, auth: &Keypair, id: u64) -> Pubkey {
    let m = app::V3_TICK_REJECT.manifest();
    let payer = ctx.payer.pubkey();
    let s = session_pda(&auth.pubkey(), id);
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&[0, 1]);
    p.extend_from_slice(&v3::MIN_RING_CAPACITY.to_le_bytes());
    p.push(8);
    p.extend_from_slice(&m.id.0);
    p.extend_from_slice(&m.semantic_version.to_le_bytes());
    p.extend_from_slice(&m.abi_version.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    p.extend_from_slice(&STREAM_ROOT);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&[0; 32]);
    p.push(0);
    p.extend_from_slice(&[0, TICKS]);
    send(ctx, ix(sw::TAG_OPEN_SESSION, p, vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]), &[auth])
        .await
        .unwrap();
    send(ctx, ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0],
                 vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()), w(stream_pda(&s)), r(SYSTEM)]), &[auth])
        .await
        .unwrap();
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&8u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    send(ctx, ix(sw::TAG_CREATE_STATE, p, vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()),
                                                w(state_pda(&s, 0)), w(state_pda(&s, 1)), r(SYSTEM)]), &[auth])
        .await
        .unwrap();
    send(ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
                 vec![signer(auth.pubkey()), w(s), w(state_pda(&s, 0)), w(state_pda(&s, 1))]), &[auth])
        .await
        .unwrap();
    s
}

async fn tick(ctx: &mut ProgramTestContext, auth: &Keypair, s: Pubkey, cursor: u32, steps: u8) -> Result<(), u32> {
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&cursor.to_le_bytes());
    p.extend_from_slice(&[steps, v3::ADVANCE_TICK]);
    send(ctx, ix(sw::TAG_ADVANCE, p, vec![signer(auth.pubkey()), w(s), w(stream_pda(&s)), w(state_pda(&s, 0)), w(state_pda(&s, 1))]), &[auth]).await
}

async fn read(ctx: &mut ProgramTestContext, s: Pubkey) -> Result<v3::SessionVerdict, v3::VerdictError> {
    let account = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    v3::read_verdict_bytes(&PROGRAM, &s, &account.owner, &account.data)
}

fn record_ix(payer: Pubkey, s: Pubkey, reason: u32) -> Instruction {
    let m = app::V3_TICK_REJECT.manifest();
    let mut data = m.id.0.to_vec();
    data.extend_from_slice(&m.semantic_version.to_le_bytes());
    data.extend_from_slice(&m.abi_version.to_le_bytes());
    data.extend_from_slice(&reason.to_le_bytes());
    Instruction {
        program_id: REGISTRY,
        accounts: vec![AccountMeta::new(payer, true), r(s), w(record_pda(&s)), r(SYSTEM)],
        data,
    }
}

fn close(s: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(target), w(refund)])
}

/// A close the authority signs (with `pipelines-v1`, the only way to close a
/// kernel-halted session's state before it is sealed).
fn close_signed(s: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(target), AccountMeta::new(refund, true)])
}

// --- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_kernel_halt_is_a_verdict_a_registry_copies_before_the_session_closes() {
    let mut ctx = start().await;
    let auth = keypair(61);
    let s = session(&mut ctx, &auth, 1).await;
    tick(&mut ctx, &auth, s, 0, 4).await.unwrap();
    assert_eq!(read(&mut ctx, s).await, Err(v3::VerdictError::NotHalted));
    // The tick-and-reject counter halts after when the value reaches 10.
    tick(&mut ctx, &auth, s, 4, 8).await.unwrap();
    tick(&mut ctx, &auth, s, 12, 1).await.unwrap_err();
    let verdict = read(&mut ctx, s).await.unwrap();
    assert_eq!((verdict.halt_reason, verdict.halt_cursor), (app::V3_REJECT_HALT_REASON, 10));
    assert_eq!(verdict.kernel, app::V3_TICK_REJECT.manifest().id);
    assert_eq!(verdict.authority, auth.pubkey());
    let mut root = STREAM_ROOT;
    for seq in 0..10u32 {
        root = sha256(&[v3::INPUT_CHAIN_V3, &root, &seq.to_le_bytes(), &[0], &[]]);
    }
    assert_eq!(verdict.input_root, root, "the verdict binds the input chain");
    // What a consumer requires.
    let m = app::V3_TICK_REJECT.manifest();
    let want = v3::VerdictRequirements { kernel: Some((m.id, m.semantic_version, m.abi_version)), halt_reason: Some(app::V3_REJECT_HALT_REASON), ..Default::default() };
    assert_eq!(verdict.require(&want), Ok(()));
    let other = app::V3_COUNTER.manifest();
    assert_eq!(verdict.require(&v3::VerdictRequirements { kernel: Some((other.id, 1, 1)), ..Default::default() }), Err(v3::VerdictError::Kernel));
    assert_eq!(verdict.require(&v3::VerdictRequirements { halt_reason: Some(1), ..Default::default() }), Err(v3::VerdictError::Reason));
    assert_eq!(verdict.require(&v3::VerdictRequirements { resource_commitment: Some([1; 32]), ..Default::default() }), Err(v3::VerdictError::Resource));

    // The registry refuses a wrong required reason, then records the verdict.
    let payer = ctx.payer.pubkey();
    assert_eq!(send(&mut ctx, record_ix(payer, s, 1), &[]).await, Err(100 + v3::VerdictError::Reason as u32));
    send(&mut ctx, record_ix(payer, s, app::V3_REJECT_HALT_REASON), &[]).await.unwrap();
    // The session closes; the record stays. With `pipelines-v1` the unsealed
    // final state closes only with the authority's signature; once trimmed,
    // the rest closes as before.
    if cfg!(feature = "pipelines-v1") {
        assert_eq!(send(&mut ctx, close(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[]).await, Err(v3::REFUSAL_AUTHORITY));
    }
    send(&mut ctx, close_signed(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[&auth]).await.unwrap();
    for (key, kind) in [(state_pda(&s, 0), v3::KIND_STATE), (stream_pda(&s), v3::KIND_STREAM)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[])
        .await
        .unwrap();
    assert!(ctx.banks_client.get_account(s).await.unwrap().is_none(), "session closed");
    let record = ctx.banks_client.get_account(record_pda(&s)).await.unwrap().unwrap();
    assert_eq!(record.owner, REGISTRY);
    assert_eq!(&record.data[..32], s.as_ref());
    assert_eq!(u32::from_le_bytes(record.data[80..84].try_into().unwrap()), app::V3_REJECT_HALT_REASON);
    assert_eq!(record.data[88..120], root);
}

#[tokio::test]
async fn an_authority_halt_a_foreign_owner_a_moved_record_or_bad_bytes_are_not_verdicts() {
    let mut ctx = start().await;
    let auth = keypair(62);
    let s = session(&mut ctx, &auth, 1).await;
    tick(&mut ctx, &auth, s, 0, 3).await.unwrap();
    // The authority halts it: reason 0, no kernel verdict.
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&3u32.to_le_bytes());
    send(&mut ctx, ix(sw::TAG_HALT_SESSION, p, vec![signer(auth.pubkey()), w(s)]), &[&auth]).await.unwrap();
    assert_eq!(read(&mut ctx, s).await, Err(v3::VerdictError::NoKernelVerdict));
    let payer = ctx.payer.pubkey();
    assert_eq!(send(&mut ctx, record_ix(payer, s, 0), &[]).await, Err(100 + v3::VerdictError::NoKernelVerdict as u32));

    // A halted session's bytes under another owner, at another address, or cut short.
    let other = keypair(63);
    let s2 = session(&mut ctx, &other, 1).await;
    tick(&mut ctx, &other, s2, 0, 8).await.unwrap();
    tick(&mut ctx, &other, s2, 8, 8).await.unwrap();
    let account = ctx.banks_client.get_account(s2).await.unwrap().unwrap();
    assert!(v3::read_verdict_bytes(&PROGRAM, &s2, &account.owner, &account.data).is_ok());
    assert_eq!(v3::read_verdict_bytes(&REGISTRY, &s2, &account.owner, &account.data), Err(v3::VerdictError::Owner));
    assert_eq!(v3::read_verdict_bytes(&PROGRAM, &s, &account.owner, &account.data), Err(v3::VerdictError::Address));
    assert_eq!(v3::read_verdict_bytes(&PROGRAM, &s2, &account.owner, &account.data[..100]), Err(v3::VerdictError::Layout));
    let mut flipped = account.data.clone();
    flipped[0] ^= 1;
    assert_eq!(v3::read_verdict_bytes(&PROGRAM, &s2, &account.owner, &flipped), Err(v3::VerdictError::Layout));
}
