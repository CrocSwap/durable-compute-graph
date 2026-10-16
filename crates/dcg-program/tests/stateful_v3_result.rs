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

/// A close the authority signs: with `pipelines-v1`, the only way to close a
/// kernel-halted session's state before it is sealed.
fn close_signed(s: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(target), AccountMeta::new(refund, true)])
}

const OPEN_SEAL: bool = cfg!(feature = "pipelines-v1");


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
    if !OPEN_SEAL {
        assert_eq!(send(&mut ctx, begin(payer, other.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&other]).await, Err(v3::REFUSAL_AUTHORITY));
    }
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
    send(&mut ctx, close_signed(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[&auth]).await.unwrap();
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
        send(&mut ctx, close_signed(s, key, auth.pubkey(), kind), &[&auth]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[]).await.unwrap();
    assert!(ctx.banks_client.get_account(s).await.unwrap().is_none(), "every ending reclaims the session");

    // Re-review 10-15: a stream closed after the halt does not block a seal
    // (the seal never reads it).
    let s = halted(&mut ctx, &auth, 4).await;
    send(&mut ctx, close(s, stream_pda(&s), auth.pubkey(), v3::KIND_STREAM), &[]).await.unwrap();
    seal(&mut ctx, &auth, s, 10).await.unwrap();
    let after_stream = read(&mut ctx, s).await.unwrap();
    assert_eq!(after_stream.open_state(&state_bytes(&mut ctx, s).await), Ok(()));

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

/// Compute units of one transaction holding `i` (with the metadata's count).
async fn send_cu(ctx: &mut ProgramTestContext, i: Instruction) -> Result<u64, u32> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let tx = Transaction::new(&[&ctx.payer], solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    let out = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    match out.result {
        Ok(()) => Ok(out.metadata.map_or(0, |m| m.compute_units_consumed)),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Err(code),
        Err(_) => Err(u32::MAX),
    }
}

fn probe(op: u8, host: &Pubkey, rest: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![app::RESULT_PROBE_TAG, op];
    data.extend_from_slice(host.as_ref());
    data.extend_from_slice(rest);
    Instruction { program_id: PROGRAM, accounts, data }
}

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/../../tests/golden/dcg/result/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(s: &serde_json::Value) -> Vec<u8> {
    let s = s.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Mode results v1: the compute of the readers and openings on chain, through
/// the test image's probe (tag 251). Meaningful with `V3_SBF=1`; natively it
/// checks the probe accepts real results and refuses a forged state.
#[tokio::test]
async fn the_readers_and_openings_cost_on_chain() {
    let mut ctx = start().await;
    let auth = keypair(76);
    let mut line = Vec::new();
    let base = send_cu(&mut ctx, probe(0, &PROGRAM, &[], vec![])).await.unwrap();
    line.push(format!("baseline {base}"));

    // Sessions: the 16-byte tick-and-reject state and the 80,000-byte state.
    let small = halted(&mut ctx, &auth, 1).await;
    seal(&mut ctx, &auth, small, 10).await.unwrap();
    let big = big_halted(&mut ctx, &auth, 2, &[7, 9, app::V3_BIG_SEAL_HALT_COMMAND]).await;
    let payer = ctx.payer.pubkey();
    send(&mut ctx, begin(payer, auth.pubkey(), big, v3::ANCHOR_OP_SEAL, 3), &[&auth]).await.unwrap();
    for offset in [0, res::SEAL_CHUNK_BYTES as u32] {
        send(&mut ctx, chunk(auth.pubkey(), big, 3, offset), &[&auth]).await.unwrap();
    }
    send(&mut ctx, finish(auth.pubkey(), big, 3), &[&auth]).await.unwrap();
    for (name, s) in [("16 B", small), ("80,000 B", big)] {
        let states = vec![r(s), r(state_pda(&s, 0)), r(state_pda(&s, 1))];
        let read = send_cu(&mut ctx, probe(1, &PROGRAM, &[], vec![r(s)])).await.unwrap();
        let open = send_cu(&mut ctx, probe(2, &PROGRAM, &[], states)).await.unwrap();
        line.push(format!("session {name}: read {} open_state {}", read - base, open - read));
    }
    // A forged state refuses (the probe opens what the accounts hold).
    let mut forged = ctx.banks_client.get_account(state_pda(&big, 1)).await.unwrap().unwrap();
    forged.data[v3::CHILD_HEADER_BYTES] ^= 1;
    ctx.set_account(&state_pda(&big, 1), &forged.into());
    assert_eq!(send_cu(&mut ctx, probe(2, &PROGRAM, &[], vec![r(big), r(state_pda(&big, 0)), r(state_pda(&big, 1))])).await,
               Err(100 + ResultError::Opening as u32));

    // Runs: the real generic and LX1 accounts from the fixtures, under their host.
    for name in ["run", "lx_run"] {
        let f = fixture(name);
        let host = Pubkey::new_from_array(unhex(&f["host"]).try_into().unwrap());
        let run = Pubkey::new_from_array(unhex(&f["run"]).try_into().unwrap());
        let template = Pubkey::new_from_array(unhex(&f["template"]).try_into().unwrap());
        let account = |data: Vec<u8>| solana_account::Account { lamports: Rent::default().minimum_balance(data.len()), data, owner: host, executable: false, rent_epoch: 0 };
        ctx.set_account(&template, &account(unhex(&f["template_data"])).into());
        for form in ["live", "receipt"] {
            ctx.set_account(&run, &account(unhex(&f[form])).into());
            let read = send_cu(&mut ctx, probe(3, &host, &[], vec![r(run), r(template)])).await.unwrap();
            let mut text = format!("{name} {form}: read {}", read - base);
            if name == "run" {
                let mut rest = 0u64.to_le_bytes().to_vec();
                rest.extend(unhex(&f["output0"]));
                let path = f["output0_path"].as_array().unwrap();
                for p in path {
                    rest.extend(unhex(p));
                }
                let open = send_cu(&mut ctx, probe(4, &host, &rest, vec![r(run), r(template)])).await.unwrap();
                text += &format!(" open_output (path {}) {}", path.len(), open - read);
            }
            line.push(text);
        }
    }
    println!("result compute (sbf {}): {}", std::env::var("V3_SBF").unwrap_or_default(), line.join("; "));
}

/// Pipelines slice 1 B (design §3.4 B): anyone may begin, continue and finish
/// a seal, and the result equals the authority's own; only the authority
/// aborts; a sealed session takes no second seal. Until the seal, a
/// kernel-halted session's state closes only with the authority's signature,
/// so no one can trim it first and deny its result; the authority escapes a
/// stranger's seal with an abort and a close in one transaction.
#[cfg(feature = "pipelines-v1")]
#[tokio::test]
async fn anyone_may_seal_and_only_the_authority_trims_before_a_seal() {
    let mut ctx = start().await;
    let auth = keypair(75);
    let (alice, bob) = (keypair(76), keypair(77));
    let payer = ctx.payer.pubkey();

    // The authority's own seal, for comparison.
    let mine = halted(&mut ctx, &auth, 1).await;
    seal(&mut ctx, &auth, mine, 10).await.unwrap();
    let mine = read(&mut ctx, mine).await.unwrap();

    // Alice begins (paying), Bob chunks and finishes; Alice cannot abort.
    let s = halted(&mut ctx, &auth, 2).await;
    send(&mut ctx, begin(payer, alice.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&alice]).await.unwrap();
    assert_eq!(send(&mut ctx, abort(alice.pubkey(), s, 10), &[&alice]).await, Err(v3::REFUSAL_AUTHORITY));
    send(&mut ctx, chunk(bob.pubkey(), s, 10, 0), &[&bob]).await.unwrap();
    send(&mut ctx, finish(bob.pubkey(), s, 10), &[&bob]).await.unwrap();
    let theirs = read(&mut ctx, s).await.unwrap();
    assert_eq!((theirs.root, theirs.count), (mine.root, mine.count), "the same state seals the same, whoever sends it");
    assert_eq!(theirs.open_state(&state_bytes(&mut ctx, s).await), Ok(()));
    assert_eq!(send(&mut ctx, begin(payer, alice.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&alice]).await, Err(v3::REFUSAL_CURSOR), "sealed once");
    // Sealed: anyone may close, and the result reads until a span closes.
    send(&mut ctx, close(s, anchor_pda(&s), auth.pubkey(), v3::KIND_ANCHOR), &[]).await.unwrap();
    send(&mut ctx, close(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[]).await.unwrap();
    assert_eq!(read(&mut ctx, s).await, Err(ResultError::Trimmed));

    // Before a seal, a stranger cannot trim; the anchor and stream still close.
    let s = halted(&mut ctx, &auth, 3).await;
    assert_eq!(send(&mut ctx, close(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[]).await, Err(v3::REFUSAL_AUTHORITY));
    send(&mut ctx, close(s, stream_pda(&s), auth.pubkey(), v3::KIND_STREAM), &[]).await.unwrap();
    // A stranger's seal blocks closes; the authority aborts and closes in one
    // transaction, so no one can re-begin in between.
    send(&mut ctx, begin(payer, alice.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&alice]).await.unwrap();
    assert_eq!(send(&mut ctx, close_signed(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE), &[&auth]).await, Err(v3::REFUSAL_LIVE));
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let both = [abort(auth.pubkey(), s, 10), close_signed(s, state_pda(&s, 1), auth.pubkey(), v3::KIND_STATE)];
    let tx = Transaction::new(&[&ctx.payer, &auth], solana_message::Message::new(&both, Some(&ctx.payer.pubkey())), blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();
    assert_eq!(ctx.banks_client.get_account(s).await.unwrap().unwrap().data[1278], 2, "trimmed, not sealed");
    assert_eq!(read(&mut ctx, s).await, Err(ResultError::NotSealed));
    assert_eq!(send(&mut ctx, begin(payer, alice.pubkey(), s, v3::ANCHOR_OP_SEAL, 10), &[&alice]).await, Err(v3::REFUSAL_STATE), "trimmed: no seal");
    // Trimmed: the rest closes without a signature, the session with it.
    for (key, kind) in [(anchor_pda(&s), v3::KIND_ANCHOR), (state_pda(&s, 0), v3::KIND_STATE)] {
        send(&mut ctx, close(s, key, auth.pubkey(), kind), &[]).await.unwrap();
    }
    send(&mut ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(auth.pubkey())]), &[]).await.unwrap();
    assert!(ctx.banks_client.get_account(s).await.unwrap().is_none());

    // An authority halt has no result to protect: anyone closes, as before.
    let live = session(&mut ctx, &auth, 4).await;
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&0u32.to_le_bytes());
    send(&mut ctx, ix(sw::TAG_HALT_SESSION, p, vec![signer(auth.pubkey()), w(live)]), &[&auth]).await.unwrap();
    send(&mut ctx, close(live, state_pda(&live, 1), auth.pubkey(), v3::KIND_STATE), &[]).await.unwrap();
    // An anchor on a live session still needs the authority.
    let active = session(&mut ctx, &auth, 5).await;
    tick(&mut ctx, &auth, active, 0, 3).await.unwrap();
    assert_eq!(send(&mut ctx, begin(payer, alice.pubkey(), active, v3::ANCHOR_OP_BEGIN, 3), &[&alice]).await, Err(v3::REFUSAL_AUTHORITY));
}

// --- tree seals (pipelines slice 1 C) -----------------------------------------------------------

#[cfg(feature = "pipelines-v1")]
fn begin_tree(payer: Pubkey, auth: Pubkey, s: Pubkey, cursor: u32, log2: u8) -> Instruction {
    let mut i = begin(payer, auth, s, v3::ANCHOR_OP_TREE_SEAL, cursor);
    i.data.push(log2);
    i
}

/// One transaction with a 1.4M compute limit (a tree seal's chunk hashes up
/// to 1,024 leaves); returns the compute used.
#[cfg(feature = "pipelines-v1")]
async fn send_big(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<u64, u32> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let ixs = [solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), i];
    let tx = Transaction::new(&all, solana_message::Message::new(&ixs, Some(&ctx.payer.pubkey())), blockhash);
    let out = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    match out.result {
        Ok(()) => Ok(out.metadata.map_or(0, |m| m.compute_units_consumed)),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Err(code),
        Err(_) => Err(u32::MAX),
    }
}

/// The sibling path of chunk `index` in the chunk tree over `state`.
#[cfg(feature = "pipelines-v1")]
fn chunk_path(state: &[u8], log2: u8, index: usize) -> Vec<[u8; 32]> {
    use dcg_program::hash::sha256;
    let size = 1usize << log2;
    let n = state.len().div_ceil(size).max(1);
    let leaf = |i: usize| sha256(&[b"dcg.chunk.leaf.v2.1\0", &(i as u64).to_le_bytes(), &state[i * size..((i + 1) * size).min(state.len())]]);
    let mut level: Vec<[u8; 32]> = (0..n).map(leaf).collect();
    let height = res::tree_height(n as u64);
    let mut empty = sha256(&[b"dcg.chunk.empty.v2.1\0"]);
    let mut path = Vec::new();
    let mut at = index;
    for l in 0..height {
        if level.len() % 2 == 1 {
            level.push(empty);
        }
        path.push(level[at ^ 1]);
        level = level.chunks(2).map(|p| sha256(&[b"dcg.chunk.node.v2.1\0", &(l as u16).to_le_bytes(), &p[0], &p[1]])).collect();
        empty = sha256(&[b"dcg.chunk.node.v2.1\0", &(l as u16).to_le_bytes(), &empty, &empty]);
        at >>= 1;
    }
    path
}

/// Pipelines slice 1 C (design §3.4 C): a tree seal through the program is the
/// v2.1 chunked-value digest of the final state, for one chunk and for 80,000
/// bytes in two transactions at the smallest and largest chunk sizes; a chunk
/// opens with its path, also one that crosses the span boundary; the record
/// marks it (byte 1278 bit 2, byte 1279); an aborted tree seal leaves the
/// anchor account usable for a linear seal.
#[cfg(feature = "pipelines-v1")]
#[tokio::test]
async fn a_tree_seal_is_the_chunked_value_digest_and_opens_by_chunk() {
    let mut ctx = start().await;
    let auth = keypair(78);
    let payer = ctx.payer.pubkey();

    // A 16-byte state: one 64-byte chunk.
    let s = halted(&mut ctx, &auth, 1).await;
    for bad in [5u8, 17] {
        assert_eq!(send(&mut ctx, begin_tree(payer, auth.pubkey(), s, 10, bad), &[&auth]).await, Err(u32::MAX), "log2 {bad}");
    }
    send(&mut ctx, begin_tree(payer, auth.pubkey(), s, 10, 6), &[&auth]).await.unwrap();
    assert_eq!(ctx.banks_client.get_account(anchor_pda(&s)).await.unwrap().unwrap().data.len(), 704);
    send(&mut ctx, chunk(auth.pubkey(), s, 10, 0), &[&auth]).await.unwrap();
    send(&mut ctx, finish(auth.pubkey(), s, 10), &[&auth]).await.unwrap();
    let record = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    assert_eq!((record.data[1278], record.data[1279]), (1 | 4, 6));
    let state = state_bytes(&mut ctx, s).await;
    let result = read(&mut ctx, s).await.unwrap();
    let res::Body::Consensus(c) = result.body else { panic!("consensus") };
    assert_eq!((result.scheme, c.chunk_log2, result.count), (res::SCHEME_STATE_TREE_V1, 6, 16));
    assert_eq!(result.root, res::tree_seal_spans(&[&state], 6));
    assert_eq!(result.open_state(&state), Ok(()));
    assert_eq!(result.open_state_chunk(0, &state, &[]), Ok(()));
    assert_eq!(ResultRef::decode(&result.encode()), Ok(result));
    // Record bytes claiming a tree seal the program did not write.
    for (flags, log2) in [(1u8 | 4, 0u8), (1 | 4, 5), (4, 6), (1, 6)] {
        let mut bad = record.data.clone();
        bad[1278] = flags;
        bad[1279] = log2;
        assert_eq!(v3::read_session_result_bytes(&PROGRAM, &s, &record.owner, &bad).err(), Some(ResultError::Layout), "flags {flags} log2 {log2}");
    }
    result_fixture("tree_session", serde_json::json!({
        "host": hex_of(PROGRAM.as_ref()), "key": hex_of(s.as_ref()), "owner": hex_of(record.owner.as_ref()),
        "record": hex_of(&record.data), "state": hex_of(&state), "result": hex_of(&result.encode()),
    }));

    // 80,000 bytes in two transactions, chunks of 64 bytes and of 64 KiB.
    let commands = [7u8, 9, app::V3_BIG_SEAL_HALT_COMMAND];
    let n = app::V3_BIG_SEAL_SPAN_BYTES as usize;
    for (id, log2) in [(2u64, 6u8), (3, 16)] {
        let s = big_halted(&mut ctx, &auth, id, &commands).await;
        send(&mut ctx, begin_tree(payer, auth.pubkey(), s, 3, log2), &[&auth]).await.unwrap();
        let cu0 = send_big(&mut ctx, chunk(auth.pubkey(), s, 3, 0), &[&auth]).await.unwrap();
        assert_eq!(send(&mut ctx, finish(auth.pubkey(), s, 3), &[&auth]).await, Err(v3::REFUSAL_PHASE_CURSOR), "one chunk to go");
        let cu1 = send_big(&mut ctx, chunk(auth.pubkey(), s, 3, res::SEAL_CHUNK_BYTES as u32), &[&auth]).await.unwrap();
        let cu2 = send_big(&mut ctx, finish(auth.pubkey(), s, 3), &[&auth]).await.unwrap();
        println!("tree seal log2 {log2}: chunk {cu0} CU, last chunk {cu1} CU, finish {cu2} CU");
        let state = state_bytes(&mut ctx, s).await;
        let result = read(&mut ctx, s).await.unwrap();
        assert_eq!((result.scheme, result.count), (res::SCHEME_STATE_TREE_V1, 80_000));
        assert_eq!(result.root, res::tree_seal_spans(&[&state], log2), "log2 {log2}");
        let (a, b) = state.split_at(n);
        assert_eq!(result.open_state_spans(&[a, b]), Ok(()));
        let size = 1usize << log2;
        for index in [0usize, n / size, (state.len() - 1) / size] {
            let chunk = &state[index * size..((index + 1) * size).min(state.len())];
            assert_eq!(result.open_state_chunk(index as u64, chunk, &chunk_path(&state, log2, index)), Ok(()), "log2 {log2} chunk {index}");
        }
        let mut forged = state.clone();
        forged[n] ^= 1;
        assert_eq!(result.open_state(&forged), Err(ResultError::Opening));
    }

    // An aborted tree seal; then a linear seal on the grown anchor account.
    let s = halted(&mut ctx, &auth, 4).await;
    send(&mut ctx, begin_tree(payer, auth.pubkey(), s, 10, 7), &[&auth]).await.unwrap();
    send(&mut ctx, chunk(auth.pubkey(), s, 10, 0), &[&auth]).await.unwrap();
    send(&mut ctx, abort(auth.pubkey(), s, 10), &[&auth]).await.unwrap();
    seal(&mut ctx, &auth, s, 10).await.unwrap();
    let record = ctx.banks_client.get_account(s).await.unwrap().unwrap();
    assert_eq!((record.data[1278], record.data[1279]), (1, 0));
    let linear = read(&mut ctx, s).await.unwrap();
    assert_eq!(linear.scheme, res::SCHEME_STATE_SEAL_V1);
    assert_eq!(linear.open_state(&state_bytes(&mut ctx, s).await), Ok(()));
    let anchor = ctx.banks_client.get_account(anchor_pda(&s)).await.unwrap().unwrap();
    assert!(anchor.data.len() == 704 && anchor.data[116..].iter().all(|b| *b == 0), "the frontier is cleared");
    // A stranger's tree seal (anyone may seal) equals the authority's.
    let stranger = keypair(79);
    let t = halted(&mut ctx, &auth, 5).await;
    send(&mut ctx, begin_tree(payer, stranger.pubkey(), t, 10, 6), &[&stranger]).await.unwrap();
    send(&mut ctx, chunk(stranger.pubkey(), t, 10, 0), &[&stranger]).await.unwrap();
    send(&mut ctx, finish(stranger.pubkey(), t, 10), &[&stranger]).await.unwrap();
    assert_eq!(read(&mut ctx, t).await.unwrap().root, res::tree_seal_spans(&[&state_bytes(&mut ctx, t).await], 6));
}
