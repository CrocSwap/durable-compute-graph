#![cfg(feature = "sbf-real-lifecycle-test")]

//! Mode results v1 for consensus sessions (design
//! `docs/design/mode-results-v1.md` §3.2): sealing a session its kernel
//! halted, reading its `ResultRef` (`stateful::v3::read_session_result`),
//! opening the final state against the seal, and an example consumer program
//! that does both on chain, without a CPI into DCG, and keeps the result.
//! Native ProgramTest by default; with `V3_SBF=1` and `SBF_OUT_DIR`/
//! `BPF_OUT_DIR`, DCG runs from its feature-built SBF image (the consumer
//! stays native).

use dcg_program::{
    kernel::Kernel,
    result::{self as res, ResultError, ResultRef, ResultRequirements},
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
const CONSUMER: Pubkey = Pubkey::new_from_array([0xCC; 32]);
const SYSTEM: Pubkey = system_program::ID;
const STREAM_ROOT: [u8; 32] = [0x33; 32];
const TICKS: u8 = v3::FEATURE_RING_STREAM | v3::FEATURE_TICKS | v3::FEATURE_REJECTABLE;

// --- the example consumer ---------------------------------------------------------------------

/// KEEP: data = required halt reason(4); accounts [payer(s,w), session(r),
/// record(w), system, state accounts(r)...]. Reads the session's result,
/// requires the tick-and-reject kernel and the reason, opens the final state
/// from the state accounts against the seal, then keeps the 256-byte
/// `ResultRef` at `["result", session]`.
fn consumer(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, session, record, system, states @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 4 || !payer.is_signer || *system.key != system_program::ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    let reason = u32::from_le_bytes(data.try_into().unwrap());
    let fail = |e: ResultError| ProgramError::Custom(100 + e as u32);
    let result = v3::read_session_result(&PROGRAM, session).map_err(fail)?;
    let m = app::V3_TICK_REJECT.manifest();
    result
        .require(&ResultRequirements {
            mode: Some(res::MODE_CONSENSUS),
            kernel: Some((m.id, m.semantic_version, m.abi_version)),
            halt_reason: Some(reason),
            ..Default::default()
        })
        .map_err(fail)?;
    let guards = states.iter().map(|a| a.try_borrow_data()).collect::<Result<Vec<_>, _>>()?;
    let spans: Vec<&[u8]> = guards
        .iter()
        .map(|g| g.get(v3::CHILD_HEADER_BYTES..).ok_or(ProgramError::InvalidAccountData))
        .collect::<Result<_, _>>()?;
    result.open_state_spans(&spans).map_err(fail)?;
    let (address, bump) = Pubkey::find_program_address(&[b"result", session.key.as_ref()], program);
    if record.key != &address {
        return Err(ProgramError::InvalidSeeds);
    }
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            record.key,
            Rent::get()?.minimum_balance(res::RESULT_BYTES),
            res::RESULT_BYTES as u64,
            program,
        ),
        &[payer.clone(), record.clone(), system.clone()],
        &[&[b"result", session.key.as_ref(), &[bump]]],
    )?;
    record.try_borrow_mut_data()?.copy_from_slice(&result.encode());
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
fn anchor_pda(s: &Pubkey) -> Pubkey {
    pda(&[b"dcg-anchor-v3", s.as_ref()])
}
fn record_pda(s: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"result", s.as_ref()], &CONSUMER).0
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
    let sbf = std::env::var("V3_SBF").is_ok_and(|v| v == "1");
    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    if sbf {
        // DCG from its feature-built image; the consumer has no image and
        // stays native.
        let dir = std::env::var("SBF_OUT_DIR").or_else(|_| std::env::var("BPF_OUT_DIR")).expect("SBF_OUT_DIR");
        let elf = std::fs::read(std::path::Path::new(&dir).join("dcg_program.so")).expect("dcg_program.so");
        test.add_account(
            PROGRAM,
            solana_account::Account {
                lamports: Rent::default().minimum_balance(elf.len()),
                data: elf,
                owner: solana_program::bpf_loader::id(),
                executable: true,
                rent_epoch: 0,
            },
        );
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    test.add_program("result_consumer", CONSUMER, processor!(consumer));
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

/// An indexed ring session of the tick-and-reject counter (two 8-byte state
/// spans), opened and initialized. Its kernel halts when the count reaches 10.
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

/// A session its kernel halted at cursor 10.
async fn halted(ctx: &mut ProgramTestContext, auth: &Keypair, id: u64) -> Pubkey {
    let s = session(ctx, auth, id).await;
    tick(ctx, auth, s, 0, 8).await.unwrap();
    tick(ctx, auth, s, 8, 8).await.unwrap();
    let account = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    let verdict = v3::read_verdict_bytes(&PROGRAM, &s, &account.owner, &account.data).unwrap();
    assert_eq!((verdict.halt_reason, verdict.halt_cursor), (app::V3_REJECT_HALT_REASON, 10));
    s
}

fn anchor_op(op: u8, cursor: u32) -> Vec<u8> {
    let mut p = vec![v3::WIRE_VERSION, op];
    p.extend_from_slice(&cursor.to_le_bytes());
    p
}
fn begin(payer: Pubkey, auth: Pubkey, s: Pubkey, op: u8, cursor: u32) -> Instruction {
    ix(sw::TAG_ANCHOR, anchor_op(op, cursor), vec![
        AccountMeta::new(payer, true), signer(auth), w(s), r(stream_pda(&s)), w(anchor_pda(&s)),
        r(state_pda(&s, 0)), r(state_pda(&s, 1)), r(SYSTEM),
    ])
}
fn chunk(auth: Pubkey, s: Pubkey, cursor: u32, offset: u32) -> Instruction {
    let mut p = anchor_op(v3::ANCHOR_OP_CHUNK, cursor);
    p.extend_from_slice(&offset.to_le_bytes());
    ix(sw::TAG_ANCHOR, p, vec![signer(auth), w(s), r(stream_pda(&s)), w(anchor_pda(&s)), r(state_pda(&s, 0)), r(state_pda(&s, 1))])
}
fn finish(auth: Pubkey, s: Pubkey, cursor: u32) -> Instruction {
    ix(sw::TAG_ANCHOR, anchor_op(v3::ANCHOR_OP_FINISH, cursor), vec![signer(auth), w(s), w(anchor_pda(&s))])
}
fn abort(auth: Pubkey, s: Pubkey, cursor: u32) -> Instruction {
    ix(sw::TAG_ANCHOR, anchor_op(v3::ANCHOR_OP_ABORT, cursor), vec![signer(auth), w(s), w(anchor_pda(&s))])
}

async fn seal(ctx: &mut ProgramTestContext, auth: &Keypair, s: Pubkey, cursor: u32) -> Result<(), u32> {
    let payer = ctx.payer.pubkey();
    send(ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, cursor), &[auth]).await?;
    send(ctx, chunk(auth.pubkey(), s, cursor, 0), &[auth]).await?;
    send(ctx, finish(auth.pubkey(), s, cursor), &[auth]).await
}

async fn read(ctx: &mut ProgramTestContext, s: Pubkey) -> Result<ResultRef, ResultError> {
    let account = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    v3::read_session_result_bytes(&PROGRAM, &s, &account.owner, &account.data)
}

async fn state_bytes(ctx: &mut ProgramTestContext, s: Pubkey) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..2 {
        let a = ctx.banks_client.get_account(state_pda(&s, i)).await.unwrap().unwrap();
        out.extend_from_slice(&a.data[v3::CHILD_HEADER_BYTES..]);
    }
    out
}

fn keep(payer: Pubkey, s: Pubkey, reason: u32) -> Instruction {
    Instruction {
        program_id: CONSUMER,
        accounts: vec![AccountMeta::new(payer, true), r(s), w(record_pda(&s)), r(SYSTEM), r(state_pda(&s, 0)), r(state_pda(&s, 1))],
        data: reason.to_le_bytes().to_vec(),
    }
}

fn close(s: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(target), w(refund)])
}


/// Real account bytes for the Python reader's cross-check
/// (`python/tests/test_result.py`): written with `DCG_WRITE_GOLDENS=1`,
/// otherwise compared, so a change in either reader or the program shows.
fn result_fixture(name: &str, value: serde_json::Value) {
    let path = format!("{}/../../tests/golden/dcg/result/{name}.json", env!("CARGO_MANIFEST_DIR"));
    if std::env::var("DCG_WRITE_GOLDENS").is_ok_and(|v| v == "1") {
        std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap() + "\n").unwrap();
    } else {
        let kept: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(kept, value, "{name}.json: regenerate with DCG_WRITE_GOLDENS=1 if the change is intended");
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_sealed_session_is_a_result_a_consumer_opens_and_keeps_after_the_session_closes() {
    let mut ctx = start().await;
    let auth = keypair(71);
    let s = halted(&mut ctx, &auth, 1).await;
    assert_eq!(read(&mut ctx, s).await, Err(ResultError::NotSealed));
    seal(&mut ctx, &auth, s, 10).await.unwrap();

    let result = read(&mut ctx, s).await.unwrap();
    let account = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    let verdict = v3::read_verdict_bytes(&PROGRAM, &s, &account.owner, &account.data).unwrap();
    assert_eq!((result.mode(), result.scheme, result.count), (res::MODE_CONSENSUS, res::SCHEME_STATE_SEAL_V1, 16));
    assert_eq!((result.host, result.source, result.root), (PROGRAM, s, verdict.state_anchor));
    let res::Body::Consensus(body) = result.body else { panic!("consensus body") };
    assert_eq!((body.kernel_id, body.halt_reason, body.halt_cursor), (verdict.kernel, verdict.halt_reason, 10));
    assert_eq!((body.input_root, body.stream_root), (verdict.input_root, STREAM_ROOT));
    assert_eq!(result.basis(), res::Basis::ChainExecution { host: PROGRAM });
    assert_eq!(ResultRef::decode(&result.encode()), Ok(result));

    // The final state opens against the seal; a changed byte does not.
    let state = state_bytes(&mut ctx, s).await;
    result_fixture("session", serde_json::json!({
        "host": hex_of(PROGRAM.as_ref()), "key": hex_of(s.as_ref()), "owner": hex_of(account.owner.as_ref()),
        "record": hex_of(&account.data), "state": hex_of(&state), "result": hex_of(&result.encode()),
    }));
    assert_eq!(result.open_state(&state), Ok(()));
    assert_eq!(res::seal_digest(&body, &state), result.root);
    let mut forged = state.clone();
    forged[3] ^= 1;
    assert_eq!(result.open_state(&forged), Err(ResultError::Opening));

    // Sealed once only, and a halted session takes no anchor.
    let payer = ctx.payer.pubkey();
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&auth]).await, Err(v3::REFUSAL_CURSOR));
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_BEGIN, 10), &[&auth]).await, Err(v3::REFUSAL_CURSOR));

    // The consumer refuses a wrong reason, then opens the state on chain and
    // keeps the result.
    assert_eq!(send(&mut ctx, keep(payer, s, 1), &[]).await, Err(100 + ResultError::Reason as u32));
    send(&mut ctx, keep(payer, s, app::V3_REJECT_HALT_REASON), &[]).await.unwrap();
    let record = ctx.banks_client.get_account(record_pda(&s)).await.unwrap().unwrap();
    assert_eq!(record.owner, CONSUMER);
    assert_eq!(record.data, result.encode().to_vec());

    // The whole session closes (anchor account included); the kept result
    // still opens against the state a client recorded.
    for (key, kind) in [(anchor_pda(&s), v3::KIND_ANCHOR), (state_pda(&s, 1), v3::KIND_STATE), (state_pda(&s, 0), v3::KIND_STATE), (stream_pda(&s), v3::KIND_STREAM)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[])
        .await
        .unwrap();
    assert!(ctx.banks_client.get_account(s).await.unwrap().is_none(), "session closed");
    let kept = ResultRef::decode(&ctx.banks_client.get_account(record_pda(&s)).await.unwrap().unwrap().data).unwrap();
    assert_eq!(kept.open_state(&state), Ok(()));
}

#[tokio::test]
async fn seals_need_a_kernel_halt_the_authority_and_the_halt_cursor() {
    let mut ctx = start().await;
    let auth = keypair(72);
    let payer = ctx.payer.pubkey();

    // A live session takes no seal.
    let live = session(&mut ctx, &auth, 1).await;
    tick(&mut ctx, &auth, live, 0, 3).await.unwrap();
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), live, v3::ANCHOR_OP_SEAL, 3), &[&auth]).await, Err(v3::REFUSAL_CURSOR));
    // An authority halt is not a verdict, so it takes no seal.
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&3u32.to_le_bytes());
    send(&mut ctx, ix(sw::TAG_HALT_SESSION, p, vec![signer(auth.pubkey()), w(live)]), &[&auth]).await.unwrap();
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), live, v3::ANCHOR_OP_SEAL, 3), &[&auth]).await, Err(v3::REFUSAL_CURSOR));
    assert_eq!(read(&mut ctx, live).await, Err(ResultError::NoKernelVerdict));

    let s = halted(&mut ctx, &auth, 2).await;
    // Not at the halt cursor; not the authority.
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 9), &[&auth]).await, Err(v3::REFUSAL_CURSOR));
    let other = keypair(73);
    assert_eq!(send(&mut ctx, begin(payer, other.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&other]).await, Err(v3::REFUSAL_AUTHORITY));
    // Begun: no finish before the chunks, no chunk at another offset; abort,
    // then seal again.
    send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&auth]).await.unwrap();
    assert_eq!(send(&mut ctx, finish(auth.pubkey(), s, 10), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR));
    assert_eq!(send(&mut ctx, chunk(auth.pubkey(), s, 10, 8), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR));
    assert_eq!(read(&mut ctx, s).await, Err(ResultError::NotSealed));
    send(&mut ctx, abort(auth.pubkey(), s, 10), &[&auth]).await.unwrap();
    seal(&mut ctx, &auth, s, 10).await.unwrap();
    let result = read(&mut ctx, s).await.unwrap();
    assert_eq!(result.open_state(&state_bytes(&mut ctx, s).await), Ok(()));
    // A requirement for an optimistic result fails on it.
    assert_eq!(result.require(&ResultRequirements { template_id: Some([0; 32]), ..Default::default() }), Err(ResultError::Mode));

    // Record bytes claiming a seal the program did not write are refused.
    let unsealed = halted(&mut ctx, &auth, 3).await;
    let account = ctx.banks_client.get_account(unsealed).await.unwrap().unwrap();
    let mut claimed = account.data.clone();
    claimed[1278] = 1;
    assert_eq!(v3::read_session_result_bytes(&PROGRAM, &unsealed, &account.owner, &claimed), Err(ResultError::Layout));
    let sealed = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    assert_eq!(v3::read_session_result_bytes(&CONSUMER, &s, &sealed.owner, &sealed.data), Err(ResultError::Owner));
    assert_eq!(v3::read_session_result_bytes(&PROGRAM, &unsealed, &sealed.owner, &sealed.data), Err(ResultError::Address));
}

/// Review 10-14 findings 1-4: the seal covers the whole final state or
/// nothing. No child closes during a seal (an abort always ends it); a state
/// span or the resource copy closed after the halt marks the session trimmed,
/// which takes no seal and reads as no result.
#[tokio::test]
async fn a_seal_covers_the_whole_final_state_or_nothing() {
    let mut ctx = start().await;
    let auth = keypair(74);
    let payer = ctx.payer.pubkey();

    // F1: a span closed after the halt, then a seal of what is left: refused.
    let s = halted(&mut ctx, &auth, 1).await;
    send(&mut ctx, close(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[]).await.unwrap();
    assert_eq!(send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&auth]).await, Err(v3::REFUSAL_STATE));
    // The rest still closes, and the session with it.
    for (key, kind) in [(state_pda(&s, 0), v3::KIND_STATE), (stream_pda(&s), v3::KIND_STREAM)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[]).await.unwrap();

    // F2, F3: during a seal nothing closes, the anchor and the spans included;
    // an abort ends it and the closes then go through.
    let s = halted(&mut ctx, &auth, 2).await;
    send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&auth]).await.unwrap();
    send(&mut ctx, chunk(auth.pubkey(), s, 10, 0), &[&auth]).await.unwrap();
    for (key, kind) in [(anchor_pda(&s), v3::KIND_ANCHOR), (state_pda(&s, 1), v3::KIND_STATE), (stream_pda(&s), v3::KIND_STREAM)] {
        assert_eq!(send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await, Err(v3::REFUSAL_LIVE), "kind {kind} mid-seal");
    }
    send(&mut ctx, abort(auth.pubkey(), s, 10), &[&auth]).await.unwrap();
    for (key, kind) in [(anchor_pda(&s), v3::KIND_ANCHOR), (state_pda(&s, 1), v3::KIND_STATE), (state_pda(&s, 0), v3::KIND_STATE), (stream_pda(&s), v3::KIND_STREAM)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[]).await.unwrap();
    assert!(ctx.banks_client.get_account(s).await.unwrap().is_none(), "every ending reclaims the session");

    // F4: a sealed result reads until its state is cleaned up. Closing the
    // anchor or the stream leaves it; closing a state span ends it.
    let s = halted(&mut ctx, &auth, 3).await;
    seal(&mut ctx, &auth, s, 10).await.unwrap();
    let sealed = read(&mut ctx, s).await.unwrap();
    for (key, kind) in [(anchor_pda(&s), v3::KIND_ANCHOR), (stream_pda(&s), v3::KIND_STREAM)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
        assert_eq!(read(&mut ctx, s).await, Ok(sealed), "after closing kind {kind}");
    }
    send(&mut ctx, close(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[]).await.unwrap();
    assert_eq!(read(&mut ctx, s).await, Err(ResultError::Trimmed));
    let payer = ctx.payer.pubkey();
    assert_eq!(send(&mut ctx, keep(payer, s, app::V3_REJECT_HALT_REASON), &[]).await, Err(100 + ResultError::Trimmed as u32));
}

/// An open, initialized session of the big-seal kernel (two 40,000-byte
/// spans, grown 8 KiB at a time), with `commands` written and advanced, the
/// last one halting it.
async fn big_halted(ctx: &mut ProgramTestContext, auth: &Keypair, id: u64, commands: &[u8]) -> Pubkey {
    let m = app::V3_BIG_SEAL.manifest();
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
    p.push(0); // headered state, no lanes, no features: the 178-byte form
    send(ctx, ix(sw::TAG_OPEN_SESSION, p, vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]), &[auth]).await.unwrap();
    send(ctx, ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0],
                 vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()), w(stream_pda(&s)), r(SYSTEM)]), &[auth]).await.unwrap();
    let n = app::V3_BIG_SEAL_SPAN_BYTES;
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&n.to_le_bytes());
    p.extend_from_slice(&n.to_le_bytes());
    send(ctx, ix(sw::TAG_CREATE_STATE, p, vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()),
                                                w(state_pda(&s, 0)), w(state_pda(&s, 1)), r(SYSTEM)]), &[auth]).await.unwrap();
    for i in 0..2u8 {
        for _ in 0..8 {
            let len = ctx.banks_client.get_account(state_pda(&s, i)).await.unwrap().unwrap().data.len();
            if len == v3::CHILD_HEADER_BYTES + n as usize {
                break;
            }
            send(ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_GROW, i],
                         vec![AccountMeta::new(payer, true), r(s), w(state_pda(&s, i)), r(SYSTEM)]), &[]).await.unwrap();
        }
    }
    send(ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
                 vec![signer(auth.pubkey()), w(s), w(state_pda(&s, 0)), w(state_pda(&s, 1))]), &[auth]).await.unwrap();
    for (seq, cmd) in commands.iter().enumerate() {
        let mut p = vec![v3::WIRE_VERSION];
        p.extend_from_slice(&(seq as u32).to_le_bytes());
        p.extend_from_slice(&[1, *cmd]);
        send(ctx, ix(sw::TAG_WRITE_INPUT, p, vec![signer(auth.pubkey()), w(s), w(stream_pda(&s))]), &[auth]).await.unwrap();
    }
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&0u32.to_le_bytes());
    p.push(commands.len() as u8);
    send(ctx, ix(sw::TAG_ADVANCE, p, vec![signer(auth.pubkey()), w(s), w(stream_pda(&s)), w(state_pda(&s, 0)), w(state_pda(&s, 1))]), &[auth]).await.unwrap();
    s
}

/// Review 10-14 gap: a seal over more than 64 KiB through the program's chunk
/// handler, its first chunk crossing the span boundary and its last chunk
/// short, opened against the state bytes and the host model's state.
#[tokio::test]
async fn a_large_state_seals_in_chunks_that_cross_spans() {
    let mut ctx = start().await;
    let auth = keypair(75);
    let commands = [7u8, 9, app::V3_BIG_SEAL_HALT_COMMAND];
    let s = big_halted(&mut ctx, &auth, 1, &commands).await;
    let account = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    let verdict = v3::read_verdict_bytes(&PROGRAM, &s, &account.owner, &account.data).unwrap();
    assert_eq!((verdict.halt_reason, verdict.halt_cursor), (app::V3_BIG_SEAL_HALT_REASON, 3));

    let payer = ctx.payer.pubkey();
    send(&mut ctx, begin(payer, auth.pubkey(), s, v3::ANCHOR_OP_SEAL, 3), &[&auth]).await.unwrap();
    assert_eq!(send(&mut ctx, finish(auth.pubkey(), s, 3), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR), "two chunks to go");
    send(&mut ctx, chunk(auth.pubkey(), s, 3, 0), &[&auth]).await.unwrap();
    assert_eq!(send(&mut ctx, finish(auth.pubkey(), s, 3), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR), "one chunk to go");
    assert_eq!(send(&mut ctx, chunk(auth.pubkey(), s, 3, 0), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR), "a chunk twice");
    send(&mut ctx, chunk(auth.pubkey(), s, 3, res::SEAL_CHUNK_BYTES as u32), &[&auth]).await.unwrap();
    send(&mut ctx, finish(auth.pubkey(), s, 3), &[&auth]).await.unwrap();

    let result = read(&mut ctx, s).await.unwrap();
    assert_eq!(result.count, 80_000);
    // The host model of the kernel's final state.
    let n = app::V3_BIG_SEAL_SPAN_BYTES as usize;
    let mut want = vec![0u8; 2 * n];
    for (step, cmd) in commands.iter().enumerate() {
        want[8 + (step * 7_919) % (2 * n - 8)] = *cmd;
    }
    want[..8].copy_from_slice(&(commands.len() as u64).to_le_bytes());
    let state = state_bytes(&mut ctx, s).await;
    assert_eq!(state, want, "the kernel's final state");
    assert_eq!(result.open_state(&state), Ok(()));
    let (a, b) = state.split_at(n);
    assert_eq!(result.open_state_spans(&[a, b]), Ok(()));
    let mut forged = state.clone();
    forged[79_999] ^= 1;
    assert_eq!(result.open_state(&forged), Err(ResultError::Opening), "a change in the short last chunk");
    forged[79_999] ^= 1;
    forged[n] ^= 1;
    assert_eq!(result.open_state(&forged), Err(ResultError::Opening), "a change just past the span boundary");
}
