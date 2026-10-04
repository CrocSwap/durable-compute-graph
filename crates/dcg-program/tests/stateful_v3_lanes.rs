#![cfg(feature = "sbf-real-lifecycle-test")]

//! Stateful v3 render lanes (design `docs/design/stateful-session-lanes-v1.md`
//! §10) on the lane counter test kernel, native ProgramTest (or the SBF image
//! with `V3_LANES_SBF=1` and `BPF_OUT_DIR`). A capture copies the state at
//! cursor `c` into a lane; the lane renders and commits while the session
//! advances and another lane captures; views publish newest-first only.

use dcg_program::{kernel::Kernel, stateful as sw, stateful::v3, stateful::v3::lanes as ln, stateful_test as app};
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
const VALUE: u8 = sw::KIND_VIEW_COUNTER;
const TOTAL: u8 = sw::KIND_VIEW_TOTAL;
const DECLARED: u32 = 100_000;

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
fn view_pda(s: &Pubkey, role: u8) -> Pubkey {
    pda(&[b"dcg-view-v3", s.as_ref(), &[role]])
}
fn lane_pda(s: &Pubkey, k: u8) -> Pubkey {
    pda(&[ln::LANE_SEED, s.as_ref(), &[k]])
}
fn lane_ws(s: &Pubkey, k: u8) -> Pubkey {
    view_pda(s, ln::WORKSPACE_ROLE_BASE + k)
}
fn lane_scratch(s: &Pubkey, k: u8) -> Pubkey {
    view_pda(s, ln::SCRATCH_ROLE_BASE + k)
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

fn op(op: u8, k: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![v3::WIRE_VERSION, op, k];
    p.extend_from_slice(rest);
    p
}

struct Lanes {
    ctx: ProgramTestContext,
    auth: Keypair,
    session: Pubkey,
    states: [Pubkey; 2],
    cursor: u32,
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), u32> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    match ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap().result {
        Ok(()) => Ok(()),
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Err(code),
        Err(_) => Err(u32::MAX), // a non-custom refusal (malformed data, missing accounts)
    }
}

fn open_payload(id: u64, kernel: &dyn Kernel, lanes: Option<u8>) -> Vec<u8> {
    let m = kernel.manifest();
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&[0, 1]); // indexed, width 1
    p.extend_from_slice(&16u32.to_le_bytes()); // capacity
    p.push(2); // max steps
    p.extend_from_slice(&m.id.0);
    p.extend_from_slice(&m.semantic_version.to_le_bytes());
    p.extend_from_slice(&m.abi_version.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    p.extend_from_slice(&[0x33; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&[0; 32]);
    p.push(0); // headered state
    p.extend(lanes);
    p
}

async fn start() -> ProgramTestContext {
    let sbf = std::env::var("V3_LANES_SBF").is_ok_and(|v| v == "1");
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    test.start_with_context().await
}

impl Lanes {
    /// A lane-counter session with `lanes` lanes, both views, every lane
    /// created, and inputs 1, 2, 3, ... written ahead.
    async fn new(lanes: u8) -> Self {
        let mut ctx = start().await;
        let auth = keypair(7);
        let payer = ctx.payer.pubkey();
        let session = session_pda(&auth.pubkey(), 1);
        let states = [state_pda(&session, 0), state_pda(&session, 1)];
        let open = ix(sw::TAG_OPEN_SESSION, open_payload(1, &app::V3_LANE_COUNTER, Some(lanes)), vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(session), r(SYSTEM)]);
        send(&mut ctx, open, &[&auth]).await.unwrap();
        send(&mut ctx, ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0], vec![AccountMeta::new(payer, true), w(session), w(stream_pda(&session)), r(SYSTEM)]), &[]).await.unwrap();
        let mut cs = vec![v3::WIRE_VERSION, 2];
        cs.extend_from_slice(&8u32.to_le_bytes());
        cs.extend_from_slice(&8u32.to_le_bytes());
        send(&mut ctx, ix(sw::TAG_CREATE_STATE, cs, vec![AccountMeta::new(payer, true), w(session), w(states[0]), w(states[1]), r(SYSTEM)]), &[]).await.unwrap();
        send(&mut ctx, ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE], vec![signer(auth.pubkey()), w(session), w(states[0]), w(states[1])]), &[&auth]).await.unwrap();
        for (role, abi, offset) in [(VALUE, app::VALUE_VIEW_ABI, 0u32), (TOTAL, app::TOTAL_VIEW_ABI, 8)] {
            let mut p = vec![v3::WIRE_VERSION, role];
            p.extend_from_slice(&abi);
            p.extend_from_slice(&offset.to_le_bytes());
            p.extend_from_slice(&8u32.to_le_bytes());
            send(&mut ctx, ix(sw::TAG_CREATE_VIEW, p, vec![AccountMeta::new(payer, true), w(session), w(view_pda(&session, role)), r(SYSTEM)]), &[]).await.unwrap();
        }
        let mut me = Lanes { ctx, auth, session, states, cursor: 0 };
        for k in 0..lanes {
            me.create_lane(k).await.unwrap();
        }
        for seq in 0..12u32 {
            let mut p = vec![v3::WIRE_VERSION];
            p.extend_from_slice(&seq.to_le_bytes());
            p.extend_from_slice(&[1, seq as u8 + 1]);
            send(&mut me.ctx, ix(sw::TAG_WRITE_INPUT, p, vec![signer(me.auth.pubkey()), w(session), w(stream_pda(&session))]), &[&me.auth]).await.unwrap();
        }
        me
    }

    async fn create_lane(&mut self, k: u8) -> Result<(), u32> {
        let mut rest = app::V3_LANE_WORKSPACE_BYTES.to_le_bytes().to_vec();
        rest.extend_from_slice(&16u32.to_le_bytes());
        let p = op(ln::OP_CREATE, k, &rest);
        let s = self.session;
        let i = ix(sw::TAG_PUBLISH_VIEWS, p, vec![AccountMeta::new(self.ctx.payer.pubkey(), true), signer(self.auth.pubkey()), w(s), w(lane_pda(&s, k)), w(lane_ws(&s, k)), w(lane_scratch(&s, k)), r(SYSTEM)]);
        send(&mut self.ctx, i, &[&self.auth]).await
    }

    async fn advance(&mut self) -> Result<(), u32> {
        let mut p = vec![v3::WIRE_VERSION];
        p.extend_from_slice(&self.cursor.to_le_bytes());
        p.push(1);
        let s = self.session;
        let i = ix(sw::TAG_ADVANCE, p, vec![signer(self.auth.pubkey()), w(s), w(stream_pda(&s)), w(self.states[0]), w(self.states[1])]);
        let out = send(&mut self.ctx, i, &[&self.auth]).await;
        if out.is_ok() {
            self.cursor += 1;
        }
        out
    }

    fn views(&self) -> Vec<AccountMeta> {
        vec![r(view_pda(&self.session, VALUE)), r(view_pda(&self.session, TOTAL))]
    }

    async fn begin(&mut self, k: u8, c: u32) -> Result<(), u32> {
        let mut rest = c.to_le_bytes().to_vec();
        rest.extend_from_slice(&DECLARED.to_le_bytes());
        let mut a = vec![signer(self.auth.pubkey()), w(self.session), w(lane_pda(&self.session, k))];
        a.extend(self.views());
        let i = ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_CAPTURE_BEGIN, k, &rest), a);
        send(&mut self.ctx, i, &[&self.auth]).await
    }

    async fn capture(&mut self, k: u8, c: u32, at: u32, phases: Option<u8>) -> Result<(), u32> {
        let mut rest = c.to_le_bytes().to_vec();
        rest.extend_from_slice(&at.to_le_bytes());
        rest.extend_from_slice(&DECLARED.to_le_bytes());
        rest.extend(phases);
        let s = self.session;
        let a = vec![signer(self.auth.pubkey()), r(s), r(self.states[0]), r(self.states[1]), w(lane_pda(&s, k)), w(lane_ws(&s, k))];
        send(&mut self.ctx, ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_CAPTURE_RUN, k, &rest), a), &[&self.auth]).await
    }

    async fn end(&mut self, k: u8, c: u32) -> Result<(), u32> {
        let a = vec![signer(self.auth.pubkey()), w(self.session), w(lane_pda(&self.session, k))];
        send(&mut self.ctx, ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_CAPTURE_END, k, &c.to_le_bytes()), a), &[&self.auth]).await
    }

    /// Render: the lane workspace first, then authority, lane, scratch. No
    /// session or state account is passed.
    async fn render(&mut self, k: u8, c: u32, at: u32, phases: Option<u8>) -> Result<(), u32> {
        let mut rest = c.to_le_bytes().to_vec();
        rest.extend_from_slice(&at.to_le_bytes());
        rest.extend_from_slice(&DECLARED.to_le_bytes());
        rest.extend(phases);
        let s = self.session;
        let a = vec![w(lane_ws(&s, k)), signer(self.auth.pubkey()), w(lane_pda(&s, k)), w(lane_scratch(&s, k))];
        send(&mut self.ctx, ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_RUN, k, &rest), a), &[&self.auth]).await
    }

    async fn commit(&mut self, k: u8, c: u32) -> Result<(), u32> {
        let s = self.session;
        let a = vec![signer(self.auth.pubkey()), r(s), w(lane_pda(&s, k)), r(lane_scratch(&s, k)), w(view_pda(&s, VALUE)), w(view_pda(&s, TOTAL))];
        send(&mut self.ctx, ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_COMMIT, k, &c.to_le_bytes()), a), &[&self.auth]).await
    }

    async fn abort(&mut self, k: u8, c: u32) -> Result<(), u32> {
        let a = vec![signer(self.auth.pubkey()), w(self.session), w(lane_pda(&self.session, k))];
        send(&mut self.ctx, ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_ABORT, k, &c.to_le_bytes()), a), &[&self.auth]).await
    }

    /// Capture `c` on lane `k` completely (two 8-byte calls).
    async fn capture_all(&mut self, k: u8, c: u32) {
        self.begin(k, c).await.unwrap();
        self.capture(k, c, 0, None).await.unwrap();
        self.capture(k, c, 8, None).await.unwrap();
        self.end(k, c).await.unwrap();
    }

    /// Render all 16 view bytes (6-byte phases) and commit.
    async fn publish(&mut self, k: u8, c: u32) -> Result<(), u32> {
        self.render(k, c, 0, Some(3)).await?;
        self.commit(k, c).await
    }

    async fn data(&mut self, key: Pubkey) -> Vec<u8> {
        self.ctx.banks_client.get_account(key).await.unwrap().map(|a: Account| a.data).unwrap_or_default()
    }

    /// The (value, total) state after the current cursor, from the state spans.
    async fn state(&mut self) -> [u8; 16] {
        let (a, b) = (self.data(self.states[0]).await, self.data(self.states[1]).await);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&a[128..136]);
        out[8..].copy_from_slice(&b[128..136]);
        out
    }

    /// The published views: (value bytes, total bytes, stamps).
    async fn published(&mut self) -> ([u8; 16], [u32; 2]) {
        let (v, t) = (self.data(view_pda(&self.session, VALUE)).await, self.data(view_pda(&self.session, TOTAL)).await);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&v[128..136]);
        out[8..].copy_from_slice(&t[128..136]);
        let stamp = |d: &[u8]| u32::from_le_bytes(d[112..116].try_into().unwrap());
        (out, [stamp(&v), stamp(&t)])
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lane_publishes_the_captured_state_while_the_session_advances_and_another_lane_captures() {
    let mut l = Lanes::new(2).await;
    l.advance().await.unwrap();
    let at1 = l.state().await;
    // Lane 0 captures cursor 1; the state cannot advance while it captures.
    l.begin(0, 1).await.unwrap();
    l.capture(0, 1, 0, None).await.unwrap();
    assert_eq!(l.advance().await, Err(v3::REFUSAL_CAPTURE_OPEN));
    l.capture(0, 1, 8, None).await.unwrap();
    assert_eq!(l.capture(0, 1, 16, None).await, Err(v3::REFUSAL_LANE_CURSOR), "capture is complete");
    l.end(0, 1).await.unwrap();
    // The session advances; lane 1 captures cursor 2 while lane 0 renders cursor 1.
    l.advance().await.unwrap();
    let at2 = l.state().await;
    assert_ne!(at1, at2);
    l.begin(1, 2).await.unwrap();
    l.render(0, 1, 0, None).await.unwrap(); // 6 bytes
    l.capture(1, 2, 0, Some(2)).await.unwrap();
    l.render(0, 1, 6, Some(2)).await.unwrap(); // the remaining 10 bytes
    l.end(1, 2).await.unwrap();
    l.advance().await.unwrap();
    l.commit(0, 1).await.unwrap();
    assert_eq!(l.published().await, (at1, [1, 1]), "views show cursor 1 though the state is at 3");
    l.publish(1, 2).await.unwrap();
    assert_eq!(l.published().await, (at2, [2, 2]));
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_is_newest_only_and_cursors_never_repeat() {
    let mut l = Lanes::new(2).await;
    l.advance().await.unwrap();
    l.capture_all(0, 1).await;
    // No lane captures the same cursor twice, or an older one.
    assert_eq!(l.begin(1, 1).await, Err(v3::REFUSAL_LANE_CURSOR));
    assert_eq!(l.begin(1, 0).await, Err(v3::REFUSAL_LANE_CURSOR));
    l.advance().await.unwrap();
    assert_eq!(l.begin(1, 1).await, Err(v3::REFUSAL_LANE_CURSOR), "not the current cursor");
    l.capture_all(1, 2).await;
    // Lane 1 (cursor 2) publishes first; lane 0's older cursor 1 is stale.
    l.publish(1, 2).await.unwrap();
    l.render(0, 1, 0, Some(3)).await.unwrap();
    assert_eq!(l.commit(0, 1).await, Err(v3::REFUSAL_STALE_PUBLICATION));
    assert_eq!(l.published().await.1, [2, 2]);
    // The stale lane aborts and is reusable.
    l.abort(0, 1).await.unwrap();
    l.advance().await.unwrap();
    l.capture_all(0, 3).await;
    l.publish(0, 3).await.unwrap();
    assert_eq!(l.published().await.1, [3, 3]);
}

#[tokio::test(flavor = "multi_thread")]
async fn lane_steps_refuse_wrong_lanes_phases_cursors_and_accounts() {
    let mut l = Lanes::new(2).await;
    l.advance().await.unwrap();
    // Undeclared lane, rendering before a capture, a second begin.
    assert_eq!(l.create_lane(2).await, Err(v3::REFUSAL_LANE));
    assert_eq!(l.render(0, 1, 0, None).await, Err(v3::REFUSAL_LANE));
    l.begin(0, 1).await.unwrap();
    assert_eq!(l.begin(0, 1).await, Err(v3::REFUSAL_LANE));
    assert_eq!(l.render(0, 1, 0, None).await, Err(v3::REFUSAL_LANE), "not before the capture ends");
    assert_eq!(l.end(0, 1).await, Err(v3::REFUSAL_LANE_CURSOR), "capture incomplete");
    assert_eq!(l.capture(0, 1, 8, None).await, Err(v3::REFUSAL_LANE_CURSOR), "out of order");
    assert_eq!(l.capture(0, 2, 0, None).await, Err(v3::REFUSAL_LANE), "wrong cursor");
    l.capture(0, 1, 0, Some(2)).await.unwrap();
    l.end(0, 1).await.unwrap();
    assert_eq!(l.render(0, 1, 6, None).await, Err(v3::REFUSAL_LANE_CURSOR), "out of order");
    assert_eq!(l.commit(0, 1).await, Err(v3::REFUSAL_LANE_CURSOR), "not fully rendered");
    // Another lane's workspace or scratch is refused.
    let s = l.session;
    let mut rest = 1u32.to_le_bytes().to_vec();
    rest.extend_from_slice(&0u32.to_le_bytes());
    rest.extend_from_slice(&DECLARED.to_le_bytes());
    for (ws, sc) in [(lane_ws(&s, 1), lane_scratch(&s, 0)), (lane_ws(&s, 0), lane_scratch(&s, 1))] {
        let a = vec![w(ws), signer(l.auth.pubkey()), w(lane_pda(&s, 0)), w(sc)];
        let i = ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_RUN, 0, &rest), a);
        assert_eq!(send(&mut l.ctx, i, &[&l.auth]).await, Err(v3::REFUSAL_LANE));
    }
    // A signer other than the session authority cannot render.
    let other = keypair(9);
    let a = vec![w(lane_ws(&s, 0)), signer(other.pubkey()), w(lane_pda(&s, 0)), w(lane_scratch(&s, 0))];
    let i = ix(sw::TAG_PUBLISH_VIEWS, op(ln::OP_RUN, 0, &rest), a);
    assert_eq!(send(&mut l.ctx, i, &[&other]).await, Err(v3::REFUSAL_AUTHORITY));
    // A lane session refuses the single-workspace publication path.
    let mut p = vec![v3::WIRE_VERSION, 0];
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(&DECLARED.to_le_bytes());
    let i = ix(sw::TAG_PUBLISH_VIEWS, p, vec![signer(l.auth.pubkey()), w(s), r(l.states[0])]);
    assert_eq!(send(&mut l.ctx, i, &[&l.auth]).await, Err(v3::REFUSAL_LANE));
    l.publish(0, 1).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_without_lanes_are_unchanged_and_kernels_without_lanes_refuse_them() {
    let mut ctx = start().await;
    let auth = keypair(8);
    let payer = ctx.payer.pubkey();
    // The plain v3 counter has no lane hooks.
    let s = session_pda(&auth.pubkey(), 2);
    let open = ix(sw::TAG_OPEN_SESSION, open_payload(2, &app::V3_COUNTER, Some(1)), vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]);
    assert_eq!(send(&mut ctx, open, &[&auth]).await, Err(v3::REFUSAL_LANE));
    let open = ix(sw::TAG_OPEN_SESSION, open_payload(2, &app::V3_LANE_COUNTER, Some(5)), vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]);
    assert!(send(&mut ctx, open, &[&auth]).await.is_err(), "more than MAX_LANES");
    // Without the trailing byte the session has no lanes, and its tail bytes stay zero.
    let open = ix(sw::TAG_OPEN_SESSION, open_payload(2, &app::V3_LANE_COUNTER, None), vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(SYSTEM)]);
    send(&mut ctx, open, &[&auth]).await.unwrap();
    let raw = ctx.banks_client.get_account(s).await.unwrap().unwrap().data;
    assert!(raw[1267..].iter().all(|b| *b == 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn halt_clears_captures_and_every_lane_account_closes_with_its_rent() {
    let mut l = Lanes::new(2).await;
    l.advance().await.unwrap();
    l.capture_all(1, 1).await;
    l.begin(0, 1).await.err(); // cursor 1 already captured
    l.advance().await.unwrap();
    l.begin(0, 2).await.unwrap(); // capturing at halt
    let s = l.session;
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&l.cursor.to_le_bytes());
    send(&mut l.ctx, ix(sw::TAG_HALT_SESSION, p, vec![signer(l.auth.pubkey()), w(s)]), &[&l.auth]).await.unwrap();
    let raw = l.data(s).await;
    assert_eq!(raw[1268], 0, "capture mask cleared");
    // Lane steps stop; children close; the session closes last.
    assert!(l.capture(0, 2, 0, None).await.is_err());
    let refund = l.auth.pubkey();
    let mut children = vec![];
    for k in 0..2 {
        children.extend([(lane_pda(&s, k), ln::KIND_LANE), (lane_ws(&s, k), ln::KIND_LANE_WORKSPACE), (lane_scratch(&s, k), ln::KIND_LANE_SCRATCH)]);
    }
    children.extend([(view_pda(&s, VALUE), v3::KIND_VIEW), (view_pda(&s, TOTAL), v3::KIND_VIEW), (stream_pda(&s), v3::KIND_STREAM), (l.states[1], v3::KIND_STATE), (l.states[0], v3::KIND_STATE)]);
    let before = l.ctx.banks_client.get_balance(refund).await.unwrap();
    let mut rent = 0;
    for (key, kind) in children {
        rent += l.ctx.banks_client.get_balance(key).await.unwrap();
        let i = ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(key), w(refund)]);
        send(&mut l.ctx, i, &[]).await.unwrap_or_else(|e| panic!("close {kind}: {e}"));
    }
    rent += l.ctx.banks_client.get_balance(s).await.unwrap();
    send(&mut l.ctx, ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(refund)]), &[]).await.unwrap();
    assert_eq!(l.ctx.banks_client.get_balance(refund).await.unwrap(), before + rent, "every lamport returns to the authority");
}
