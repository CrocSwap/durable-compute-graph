#![cfg(feature = "sbf-real-lifecycle-test")]

//! Declared input rejection and ring-buffer streams (design
//! `docs/design/session-reject-and-ring-v1.md`), native ProgramTest by
//! default, or the feature-built SBF image with `V3_SBF=1` and
//! `BPF_OUT_DIR`/`SBF_OUT_DIR`.

use dcg_program::{hash::sha256, kernel::Kernel, stateful as sw, stateful::v3, stateful_test as app};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xDA; 32]);
const SYSTEM: Pubkey = system_program::ID;
const OTHER: u32 = u32::MAX;
const STREAM_ROOT: [u8; 32] = [0x33; 32];

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
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
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
        Err(_) => Err(OTHER),
    }
}

async fn data(ctx: &mut ProgramTestContext, key: Pubkey) -> Vec<u8> {
    ctx.banks_client.get_account(key).await.unwrap().map(|a: Account| a.data).unwrap()
}

fn u32_at(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().unwrap())
}

/// Open payload for `kernel` (headered state, indexed policy, width 1);
/// `features` None is the 178-byte form, Some(f) the 180-byte form.
fn open_payload(kernel: &dyn Kernel, id: u64, capacity: u32, features: Option<u8>) -> Vec<u8> {
    open_payload_lanes(kernel, id, capacity, features, 0)
}

fn open_payload_lanes(kernel: &dyn Kernel, id: u64, capacity: u32, features: Option<u8>, lanes: u8) -> Vec<u8> {
    let m = kernel.manifest();
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&[0, 1]);
    p.extend_from_slice(&capacity.to_le_bytes());
    p.push(8); // max steps
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
    if let Some(f) = features {
        p.extend_from_slice(&[lanes, f]);
    }
    p
}

struct Session {
    auth: Keypair,
    key: Pubkey,
}

/// Open, create the stream and two state spans, initialize.
async fn session(ctx: &mut ProgramTestContext, kernel: &dyn Kernel, capacity: u32, features: Option<u8>)
    -> Result<Session, u32> {
    session_lanes(ctx, kernel, capacity, features, 0).await
}

async fn session_lanes(ctx: &mut ProgramTestContext, kernel: &dyn Kernel, capacity: u32, features: Option<u8>, lanes: u8)
    -> Result<Session, u32> {
    let auth = keypair(7);
    let payer = ctx.payer.pubkey();
    let s = session_pda(&auth.pubkey(), 1);
    send(ctx, ix(sw::TAG_OPEN_SESSION, open_payload_lanes(kernel, 1, capacity, features, lanes),
                 vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]), &[&auth]).await?;
    send(ctx, ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0],
                 vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()), w(stream_pda(&s)), r(SYSTEM)]), &[&auth])
        .await.unwrap();
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&8u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    send(ctx, ix(sw::TAG_CREATE_STATE, p, vec![AccountMeta::new(payer, true), w(s), signer(auth.pubkey()),
                                                w(state_pda(&s, 0)), w(state_pda(&s, 1)), r(SYSTEM)]), &[&auth])
        .await.unwrap();
    send(ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE],
                 vec![signer(auth.pubkey()), w(s), w(state_pda(&s, 0)), w(state_pda(&s, 1))]), &[&auth])
        .await.unwrap();
    Ok(Session { auth, key: s })
}

async fn write(ctx: &mut ProgramTestContext, s: &Session, seq: u32, cmd: u8) -> Result<(), u32> {
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&seq.to_le_bytes());
    p.extend_from_slice(&[1, cmd]);
    send(ctx, ix(sw::TAG_WRITE_INPUT, p, vec![signer(s.auth.pubkey()), w(s.key), w(stream_pda(&s.key))]), &[&s.auth]).await
}

async fn advance(ctx: &mut ProgramTestContext, s: &Session, cursor: u32, steps: u8) -> Result<(), u32> {
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&cursor.to_le_bytes());
    p.push(steps);
    send(ctx, ix(sw::TAG_ADVANCE, p, vec![signer(s.auth.pubkey()), w(s.key), w(stream_pda(&s.key)),
                                          w(state_pda(&s.key, 0)), w(state_pda(&s.key, 1))]), &[&s.auth]).await
}

async fn value(ctx: &mut ProgramTestContext, s: &Session) -> u64 {
    let raw = data(ctx, state_pda(&s.key, 0)).await;
    u64::from_le_bytes(raw[128..136].try_into().unwrap())
}

/// The host chain: `/2` for ordinary sessions, `/3` (with dispositions) for
/// rejectable ones.
fn chain(rejectable: bool, commands: &[(u32, u8, Option<u32>)]) -> [u8; 32] {
    let mut root = STREAM_ROOT;
    for &(seq, cmd, rejected) in commands {
        root = if !rejectable {
            sha256(&[b"dcg/input-chain/2", &root, &seq.to_le_bytes(), &[cmd]])
        } else if let Some(code) = rejected {
            sha256(&[v3::INPUT_CHAIN_V3, &root, &seq.to_le_bytes(), &[1], &code.to_le_bytes(), &[cmd]])
        } else {
            sha256(&[v3::INPUT_CHAIN_V3, &root, &seq.to_le_bytes(), &[0], &[cmd]])
        };
    }
    root
}

const SESSION_CURSOR: usize = 112;
const SESSION_INPUT_ROOT: usize = 156;
const SESSION_FEATURES: usize = 1273;
const SESSION_REJECTED: usize = 1274;

#[tokio::test]
async fn the_rejectable_flag_must_equal_the_kernels_capability() {
    let mut ctx = start().await;
    // A declaring kernel cannot open without the flag, a plain one cannot open with it.
    assert_eq!(session(&mut ctx, &app::V3_REJECT_COUNTER, 16, None).await.err(), Some(v3::REFUSAL_RESOURCE));
    assert_eq!(session(&mut ctx, &app::V3_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.err(),
               Some(v3::REFUSAL_RESOURCE));
    // The 180-byte form needs a nonzero, known features byte.
    assert_eq!(session(&mut ctx, &app::V3_COUNTER, 16, Some(0)).await.err(), Some(OTHER));
    assert_eq!(session(&mut ctx, &app::V3_COUNTER, 16, Some(4)).await.err(), Some(OTHER));
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    assert_eq!(data(&mut ctx, s.key).await[SESSION_FEATURES], v3::FEATURE_REJECTABLE, "visible in the session record");
}

#[tokio::test]
async fn a_rejected_input_is_consumed_without_changing_state() {
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    let cmds = [3u8, app::V3_REJECT_COMMAND, 5, app::V3_REJECT_COMMAND, 1];
    for (i, c) in cmds.iter().enumerate() {
        write(&mut ctx, &s, i as u32, *c).await.unwrap();
    }
    advance(&mut ctx, &s, 0, 5).await.unwrap();
    assert_eq!(value(&mut ctx, &s).await, 9, "only 3 + 5 + 1 applied");
    let raw = data(&mut ctx, s.key).await;
    assert_eq!(u32_at(&raw, SESSION_CURSOR), 5, "rejected inputs consumed");
    assert_eq!(u32_at(&raw, SESSION_REJECTED), 2);
    let stream = data(&mut ctx, stream_pda(&s.key)).await;
    assert_eq!((u32_at(&stream, 120), u32_at(&stream, 124)), (3, app::V3_REJECT_CODE), "last rejection");
    let code = Some(app::V3_REJECT_CODE);
    let want = chain(true, &[(0, 3, None), (1, 0xEE, code), (2, 5, None), (3, 0xEE, code), (4, 1, None)]);
    assert_eq!(raw[SESSION_INPUT_ROOT..SESSION_INPUT_ROOT + 32], want, "chain /3 records each disposition");
    // A session whose next input is rejectable keeps going (no wedge).
    write(&mut ctx, &s, 5, app::V3_REJECT_COMMAND).await.unwrap();
    write(&mut ctx, &s, 6, 2).await.unwrap();
    advance(&mut ctx, &s, 5, 2).await.unwrap();
    assert_eq!(value(&mut ctx, &s).await, 11);
}

#[tokio::test]
async fn a_dirty_or_codeless_rejection_is_refused_and_rolls_back() {
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    write(&mut ctx, &s, 0, 4).await.unwrap();
    write(&mut ctx, &s, 1, app::V3_REJECT_DIRTY_COMMAND).await.unwrap();
    let before = (data(&mut ctx, s.key).await, data(&mut ctx, state_pda(&s.key, 0)).await);
    assert_eq!(advance(&mut ctx, &s, 0, 2).await, Err(v3::REFUSAL_KERNEL), "state changed before Reject");
    assert_eq!((data(&mut ctx, s.key).await, data(&mut ctx, state_pda(&s.key, 0)).await), before);
    let s2_ctx = &mut start().await;
    let s2 = session(s2_ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    write(s2_ctx, &s2, 0, app::V3_REJECT_ZERO_COMMAND).await.unwrap();
    assert_eq!(advance(s2_ctx, &s2, 0, 1).await, Err(v3::REFUSAL_KERNEL), "code 0");
}

#[tokio::test]
async fn an_undeclared_rejection_is_refused() {
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_UNDECLARED_REJECT, 16, None).await.unwrap();
    write(&mut ctx, &s, 0, app::V3_REJECT_COMMAND).await.unwrap();
    assert_eq!(advance(&mut ctx, &s, 0, 1).await, Err(v3::REFUSAL_KERNEL));
    assert_eq!(u32_at(&data(&mut ctx, s.key).await, SESSION_CURSOR), 0);
}

#[tokio::test]
async fn an_ordinary_session_keeps_the_v2_chain() {
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_COUNTER, 16, None).await.unwrap();
    for (i, c) in [2u8, 3, 4].iter().enumerate() {
        write(&mut ctx, &s, i as u32, *c).await.unwrap();
    }
    advance(&mut ctx, &s, 0, 3).await.unwrap();
    let raw = data(&mut ctx, s.key).await;
    assert_eq!(raw[SESSION_INPUT_ROOT..SESSION_INPUT_ROOT + 32], chain(false, &[(0, 2, None), (1, 3, None), (2, 4, None)]));
    assert_eq!((raw[SESSION_FEATURES], u32_at(&raw, SESSION_REJECTED)), (0, 0));
}

#[tokio::test]
async fn a_ring_stream_runs_several_laps_at_fixed_size() {
    let mut ctx = start().await;
    assert_eq!(session(&mut ctx, &app::V3_COUNTER, v3::MIN_RING_CAPACITY - 1, Some(v3::FEATURE_RING_STREAM)).await.err(),
               Some(v3::REFUSAL_RESOURCE), "a ring below two windows");
    let cap = v3::MIN_RING_CAPACITY;
    let s = session(&mut ctx, &app::V3_COUNTER, cap, Some(v3::FEATURE_RING_STREAM)).await.unwrap();
    let stream_len = data(&mut ctx, stream_pda(&s.key)).await.len();
    let total = 3 * cap + 17;
    let (mut written, mut cursor, mut sum) = (0u32, 0u32, 0u64);
    while cursor < total {
        while written < total && written < cursor + v3::MAX_STREAM_WINDOW {
            write(&mut ctx, &s, written, (written % 5) as u8 + 1).await.unwrap();
            sum += (written % 5) as u64 + 1;
            written += 1;
        }
        // Once per lap: a duplicate of a live input, and one past the window, refuse.
        if cursor % cap < 8 {
            assert_eq!(write(&mut ctx, &s, cursor, 1).await, Err(v3::REFUSAL_DUPLICATE_SLOT));
            assert_eq!(write(&mut ctx, &s, cursor + v3::MAX_STREAM_WINDOW, 1).await, Err(v3::REFUSAL_BACKPRESSURE));
        }
        let steps = (written - cursor).min(8) as u8;
        advance(&mut ctx, &s, cursor, steps).await.unwrap();
        cursor += steps as u32;
    }
    assert_eq!(value(&mut ctx, &s).await, sum);
    assert_eq!(data(&mut ctx, stream_pda(&s.key)).await.len(), stream_len, "no growth");
    let mut grow = vec![v3::WIRE_VERSION, 1];
    grow.extend_from_slice(&(cap + 512).to_le_bytes());
    let payer = ctx.payer.pubkey();
    assert_eq!(send(&mut ctx, ix(sw::TAG_CREATE_STREAM, grow, vec![AccountMeta::new(payer, true), w(s.key),
                                                               w(stream_pda(&s.key)), r(SYSTEM)]), &[]).await,
               Err(v3::REFUSAL_RESOURCE), "a ring never grows");
}

#[tokio::test]
async fn a_rejectable_ring_session_combines_both() {
    let mut ctx = start().await;
    let f = v3::FEATURE_RING_STREAM | v3::FEATURE_REJECTABLE;
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, v3::MIN_RING_CAPACITY, Some(f)).await.unwrap();
    let total = v3::MIN_RING_CAPACITY + 40;
    let (mut cursor, mut sum, mut rejected) = (0u32, 0u64, 0u32);
    while cursor < total {
        let n = (total - cursor).min(8);
        for seq in cursor..cursor + n {
            let cmd = if seq % 7 == 3 { app::V3_REJECT_COMMAND } else { 1 };
            if cmd == 1 { sum += 1 } else { rejected += 1 }
            write(&mut ctx, &s, seq, cmd).await.unwrap();
        }
        advance(&mut ctx, &s, cursor, n as u8).await.unwrap();
        cursor += n;
    }
    assert_eq!(value(&mut ctx, &s).await, sum);
    assert_eq!(u32_at(&data(&mut ctx, s.key).await, SESSION_REJECTED), rejected);
}

const SESSION_STATUS: usize = 6;
const SESSION_HALT_REASON: usize = 1254;

/// Review M2: a rejection mixed with HaltBefore and HaltAfter in one ADVANCE
/// commits a consistent prefix, chain, count and last-rejection record.
#[tokio::test]
async fn rejection_mixes_with_halts_in_one_advance() {
    let code = Some(app::V3_REJECT_CODE);
    // [2, reject, halt-before]: two consumed, the halt-before input stays.
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    for (i, c) in [2u8, app::V3_REJECT_COMMAND, app::V3_REJECT_HALT_BEFORE_COMMAND].iter().enumerate() {
        write(&mut ctx, &s, i as u32, *c).await.unwrap();
    }
    advance(&mut ctx, &s, 0, 3).await.unwrap();
    let raw = data(&mut ctx, s.key).await;
    assert_eq!((u32_at(&raw, SESSION_CURSOR), raw[SESSION_STATUS], u32_at(&raw, SESSION_HALT_REASON)), (2, 2, app::V3_REJECT_HALT_REASON));
    assert_eq!(u32_at(&raw, SESSION_REJECTED), 1);
    assert_eq!(raw[SESSION_INPUT_ROOT..SESSION_INPUT_ROOT + 32], chain(true, &[(0, 2, None), (1, 0xEE, code)]));
    assert_eq!(value(&mut ctx, &s).await, 2);
    // [reject, halt-after]: both consumed; halt-after applies +1.
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_REJECT_COUNTER, 16, Some(v3::FEATURE_REJECTABLE)).await.unwrap();
    for (i, c) in [app::V3_REJECT_COMMAND, app::V3_REJECT_HALT_AFTER_COMMAND, 9].iter().enumerate() {
        write(&mut ctx, &s, i as u32, *c).await.unwrap();
    }
    advance(&mut ctx, &s, 0, 3).await.unwrap();
    let raw = data(&mut ctx, s.key).await;
    assert_eq!((u32_at(&raw, SESSION_CURSOR), raw[SESSION_STATUS]), (2, 2));
    assert_eq!(u32_at(&raw, SESSION_REJECTED), 1);
    assert_eq!(raw[SESSION_INPUT_ROOT..SESSION_INPUT_ROOT + 32], chain(true, &[(0, 0xEE, code), (1, 0xEA, None)]));
    let stream = data(&mut ctx, stream_pda(&s.key)).await;
    assert_eq!((u32_at(&stream, 120), u32_at(&stream, 124)), (0, app::V3_REJECT_CODE), "a rejection at sequence 0");
    assert_eq!(value(&mut ctx, &s).await, 1);
}

/// Review M2: after a lap, a gap in an indexed ring is not served from the
/// previous lap's slot.
#[tokio::test]
async fn a_ring_gap_after_a_lap_refuses_rather_than_reading_the_old_lap() {
    let mut ctx = start().await;
    let cap = v3::MIN_RING_CAPACITY;
    let s = session(&mut ctx, &app::V3_COUNTER, cap, Some(v3::FEATURE_RING_STREAM)).await.unwrap();
    let mut cursor = 0;
    while cursor < cap {
        for seq in cursor..cursor + 8 {
            write(&mut ctx, &s, seq, 1).await.unwrap();
        }
        advance(&mut ctx, &s, cursor, 8).await.unwrap();
        cursor += 8;
    }
    // Skip sequence `cap` (its slot still holds sequence 0); write `cap + 1`.
    write(&mut ctx, &s, cap + 1, 1).await.unwrap();
    assert_eq!(advance(&mut ctx, &s, cap, 1).await, Err(v3::REFUSAL_INPUT_GAP));
    write(&mut ctx, &s, cap, 2).await.unwrap();
    advance(&mut ctx, &s, cap, 2).await.unwrap();
    assert_eq!(value(&mut ctx, &s).await, cap as u64 + 3);
}

/// Review M2: a ring refuses writes at the sequence ceiling. The session and
/// stream counters are moved near the top directly (no 4-billion-input run).
#[tokio::test]
async fn a_ring_refuses_writes_at_the_sequence_ceiling() {
    let mut ctx = start().await;
    let s = session(&mut ctx, &app::V3_COUNTER, v3::MIN_RING_CAPACITY, Some(v3::FEATURE_RING_STREAM)).await.unwrap();
    let c = v3::RING_SEQUENCE_CEILING - 2;
    // Session cursor/frontier/last start, stream cursor/frontier, and each
    // state span's before/after cursors.
    let targets = [
        (s.key, vec![SESSION_CURSOR, 116, 1263]),
        (stream_pda(&s.key), vec![76, 80]),
        (state_pda(&s.key, 0), vec![88, 92]),
        (state_pda(&s.key, 1), vec![88, 92]),
    ];
    for (key, offsets) in targets {
        let mut account = ctx.banks_client.get_account(key).await.unwrap().unwrap();
        for at in offsets {
            account.data[at..at + 4].copy_from_slice(&c.to_le_bytes());
        }
        ctx.set_account(&key, &account.into());
    }
    write(&mut ctx, &s, c, 1).await.unwrap();
    write(&mut ctx, &s, c + 1, 1).await.unwrap();
    assert_eq!(write(&mut ctx, &s, c + 2, 1).await, Err(v3::REFUSAL_BACKPRESSURE), "the ceiling");
    advance(&mut ctx, &s, c, 2).await.unwrap();
    assert_eq!(u32_at(&data(&mut ctx, s.key).await, SESSION_CURSOR), v3::RING_SEQUENCE_CEILING);
    assert_eq!(write(&mut ctx, &s, v3::RING_SEQUENCE_CEILING, 1).await, Err(v3::REFUSAL_BACKPRESSURE), "no write past the ceiling");
}

/// Review M1: a rejectable session with render lanes (the Doom shape) opens
/// and rejects inputs.
#[tokio::test]
async fn a_rejectable_session_with_lanes_rejects() {
    let mut ctx = start().await;
    let f = v3::FEATURE_REJECTABLE | v3::FEATURE_RING_STREAM;
    let s = session_lanes(&mut ctx, &app::V3_REJECT_COUNTER, v3::MIN_RING_CAPACITY, Some(f), 2).await.unwrap();
    assert_eq!(data(&mut ctx, s.key).await[1267], 2, "two lanes");
    for (i, c) in [5u8, app::V3_REJECT_COMMAND, 6].iter().enumerate() {
        write(&mut ctx, &s, i as u32, *c).await.unwrap();
    }
    advance(&mut ctx, &s, 0, 3).await.unwrap();
    assert_eq!(value(&mut ctx, &s).await, 11);
    assert_eq!(u32_at(&data(&mut ctx, s.key).await, SESSION_REJECTED), 1);
}
