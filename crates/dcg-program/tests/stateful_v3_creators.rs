#![cfg(feature = "sbf-real-lifecycle-test")]

//! Sessions v3 review fixes H1-H3 (`docs/experiments/sessions-v3-review-2026-10-05.md`),
//! native ProgramTest by default, or the feature-built SBF image with
//! `V3_SBF=1` (or `V3_LANES_SBF=1`) and `BPF_OUT_DIR`/`SBF_OUT_DIR`.
//!
//! H1: every child creator (stream, state, view, workspace, scratch) takes the
//! session authority as account 2 and requires its signature; the authority
//! may be the payer. H2: a session or child address pre-funded by a plain
//! lamport transfer is still created. H3: a halted session closes a headerless
//! primary that stopped part-way through its growth, then the session itself.

use dcg_program::{hash::sha256, kernel::Kernel, stateful as sw, stateful::v3, stateful_test as app};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_instruction, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xDA; 32]);
const SYSTEM: Pubkey = system_program::ID;
const RESOURCE: Pubkey = Pubkey::new_from_array(app::V3_RESOURCE_KEY);
const VALUE: u8 = sw::KIND_VIEW_COUNTER;
/// A non-custom failure (missing accounts, malformed data).
const OTHER: u32 = u32::MAX;

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
fn resource_pda(s: &Pubkey) -> Pubkey {
    pda(&[b"dcg-resource-v3", s.as_ref()])
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

async fn start(resource: Option<Vec<u8>>) -> ProgramTestContext {
    let sbf = ["V3_SBF", "V3_LANES_SBF"]
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|v| v == "1"));
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    if let Some(data) = resource {
        test.add_genesis_account(
            RESOURCE,
            Account { lamports: 1_000_000, data, owner: PROGRAM, executable: false, rent_epoch: 0 },
        );
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

async fn balance(ctx: &mut ProgramTestContext, key: Pubkey) -> u64 {
    ctx.banks_client.get_balance(key).await.unwrap()
}

async fn data(ctx: &mut ProgramTestContext, key: Pubkey) -> Option<Vec<u8>> {
    ctx.banks_client.get_account(key).await.unwrap().map(|a: Account| a.data)
}

/// Lane-counter open payload (headered state, no lanes).
fn open_payload(id: u64) -> Vec<u8> {
    let m = app::V3_LANE_COUNTER.manifest();
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
    p
}

fn open(payer: Pubkey, auth: Pubkey, id: u64) -> Instruction {
    let s = session_pda(&auth, id);
    ix(sw::TAG_OPEN_SESSION, open_payload(id), vec![AccountMeta::new(payer, true), signer(auth), w(s), r(SYSTEM)])
}

/// Account 2 of every creator: the claimed authority and whether it signs.
#[derive(Clone, Copy)]
struct Slot(Pubkey, bool);

impl Slot {
    fn meta(self) -> AccountMeta {
        AccountMeta::new_readonly(self.0, self.1)
    }
}

fn create_stream(payer: Pubkey, s: Pubkey, a: Slot) -> Instruction {
    ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0], vec![AccountMeta::new(payer, true), w(s), a.meta(), w(stream_pda(&s)), r(SYSTEM)])
}

fn create_state(payer: Pubkey, s: Pubkey, a: Slot) -> Instruction {
    let mut p = vec![v3::WIRE_VERSION, 2];
    p.extend_from_slice(&8u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    ix(sw::TAG_CREATE_STATE, p, vec![AccountMeta::new(payer, true), w(s), a.meta(), w(state_pda(&s, 0)), w(state_pda(&s, 1)), r(SYSTEM)])
}

fn initialize(auth: Pubkey, s: Pubkey) -> Instruction {
    ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_INITIALIZE], vec![signer(auth), w(s), w(state_pda(&s, 0)), w(state_pda(&s, 1))])
}

fn create_view(payer: Pubkey, s: Pubkey, a: Slot) -> Instruction {
    let mut p = vec![v3::WIRE_VERSION, VALUE];
    p.extend_from_slice(&app::VALUE_VIEW_ABI);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&8u32.to_le_bytes());
    ix(sw::TAG_CREATE_VIEW, p, vec![AccountMeta::new(payer, true), w(s), a.meta(), w(view_pda(&s, VALUE)), r(SYSTEM)])
}

fn create_workspace(payer: Pubkey, s: Pubkey, a: Slot) -> Instruction {
    let mut p = vec![v3::WIRE_VERSION, v3::WORKSPACE_ROLE];
    p.extend_from_slice(&app::V3_LANE_WORKSPACE_BYTES.to_le_bytes());
    ix(sw::TAG_CREATE_VIEW, p, vec![AccountMeta::new(payer, true), w(s), a.meta(), w(view_pda(&s, v3::WORKSPACE_ROLE)), r(SYSTEM)])
}

fn create_scratch(payer: Pubkey, s: Pubkey, a: Slot) -> Instruction {
    let mut p = vec![v3::WIRE_VERSION, v3::SCRATCH_ROLE];
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&16u32.to_le_bytes());
    ix(sw::TAG_CREATE_VIEW, p, vec![AccountMeta::new(payer, true), w(s), a.meta(), w(view_pda(&s, v3::SCRATCH_ROLE)), r(SYSTEM)])
}

fn halt(auth: Pubkey, s: Pubkey, cursor: u32) -> Instruction {
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&cursor.to_le_bytes());
    ix(sw::TAG_HALT_SESSION, p, vec![signer(auth), w(s)])
}

fn close_child(s: Pubkey, target: Pubkey, refund: Pubkey, kind: u8) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, kind], vec![w(s), w(target), w(refund)])
}

fn close_session(s: Pubkey, refund: Pubkey) -> Instruction {
    ix(sw::TAG_CLOSE_ACCOUNT, vec![v3::WIRE_VERSION, v3::KIND_SESSION], vec![w(s), w(refund)])
}

type Builder = fn(Pubkey, Pubkey, Slot) -> Instruction;

/// The five creators in the order a session needs them (state initialization
/// runs between state and the view).
const CREATORS: [(&str, Builder); 5] = [
    ("stream", create_stream),
    ("state", create_state),
    ("view", create_view),
    ("workspace", create_workspace),
    ("scratch", create_scratch),
];

/// Every child of a session built by `CREATORS`, in a valid close order.
fn children(s: &Pubkey) -> [(Pubkey, u8); 6] {
    [
        (view_pda(s, v3::SCRATCH_ROLE), v3::KIND_SCRATCH),
        (view_pda(s, v3::WORKSPACE_ROLE), v3::KIND_WORKSPACE),
        (view_pda(s, VALUE), v3::KIND_VIEW),
        (stream_pda(s), v3::KIND_STREAM),
        (state_pda(s, 1), v3::KIND_STATE),
        (state_pda(s, 0), v3::KIND_STATE),
    ]
}

/// H1: a bystander cannot create any child; only the authority's signature at
/// account 2 does. Refused creations leave the session and target untouched.
#[tokio::test(flavor = "multi_thread")]
async fn h1_creators_require_the_session_authority() {
    let mut ctx = start(None).await;
    let auth = keypair(31);
    let bystander = keypair(32);
    let payer = ctx.payer.pubkey();
    let s = session_pda(&auth.pubkey(), 1);
    send(&mut ctx, open(payer, auth.pubkey(), 1), &[&auth]).await.unwrap();

    let old_layout = ix(sw::TAG_CREATE_STREAM, vec![v3::WIRE_VERSION, 0], vec![AccountMeta::new(payer, true), w(s), w(stream_pda(&s)), r(SYSTEM)]);
    assert_eq!(send(&mut ctx, old_layout, &[]).await, Err(OTHER), "the pre-H1 account list no longer parses");

    for (index, (name, build)) in CREATORS.into_iter().enumerate() {
        let session_before = data(&mut ctx, s).await;
        // A separate bystander signing account 2.
        let i = build(payer, s, Slot(bystander.pubkey(), true));
        assert_eq!(send(&mut ctx, i, &[&bystander]).await, Err(v3::REFUSAL_AUTHORITY), "{name}: bystander signer");
        // The fee payer alone, named as the authority.
        let i = build(payer, s, Slot(payer, true));
        assert_eq!(send(&mut ctx, i, &[]).await, Err(v3::REFUSAL_AUTHORITY), "{name}: payer as authority");
        // The real authority's key without its signature.
        let i = build(payer, s, Slot(auth.pubkey(), false));
        assert_eq!(send(&mut ctx, i, &[]).await, Err(v3::REFUSAL_AUTHORITY), "{name}: unsigned authority");
        assert_eq!(data(&mut ctx, s).await, session_before, "{name}: refusals leave the session unchanged");
        let target = build(payer, s, Slot(auth.pubkey(), true)).accounts[3].pubkey;
        assert_eq!(data(&mut ctx, target).await, None, "{name}: refusals create nothing");
        // The authority's create succeeds.
        let i = build(payer, s, Slot(auth.pubkey(), true));
        send(&mut ctx, i, &[&auth]).await.unwrap_or_else(|e| panic!("{name}: authority create refused {e}"));
        assert!(data(&mut ctx, target).await.is_some(), "{name}: created");
        if index == 1 {
            send(&mut ctx, initialize(auth.pubkey(), s), &[&auth]).await.unwrap();
        }
    }
    // Grows stay open (review: "grows may stay open"); a second create refuses.
    let again = create_view(payer, s, Slot(auth.pubkey(), true));
    assert_eq!(send(&mut ctx, again, &[&auth]).await, Err(v3::REFUSAL_VIEW));
}

/// H1: the authority may also be the creation payer; account 2 then repeats
/// account 0. (Open itself refuses payer == authority with 2323, so the
/// session is opened with a separate payer and the authority pays its children.)
#[tokio::test(flavor = "multi_thread")]
async fn h1_authority_as_payer_creates_every_child() {
    let mut ctx = start(None).await;
    let fee_payer = ctx.payer.pubkey();
    let auth = keypair(36);
    send(&mut ctx, system_instruction::transfer(&fee_payer, &auth.pubkey(), 1_000_000_000), &[]).await.unwrap();
    let s = session_pda(&auth.pubkey(), 7);
    assert_eq!(send(&mut ctx, open(auth.pubkey(), auth.pubkey(), 7), &[&auth]).await, Err(v3::REFUSAL_ALIAS));
    send(&mut ctx, open(fee_payer, auth.pubkey(), 7), &[&auth]).await.unwrap();
    let a = auth.pubkey();
    for (index, (name, build)) in CREATORS.into_iter().enumerate() {
        send(&mut ctx, build(a, s, Slot(a, true)), &[&auth]).await.unwrap_or_else(|e| panic!("{name}: {e}"));
        if index == 1 {
            send(&mut ctx, initialize(a, s), &[&auth]).await.unwrap();
        }
    }
    for (key, _) in children(&s) {
        assert!(data(&mut ctx, key).await.is_some());
    }
}

/// H2: a plain lamport transfer to the session address or any child address
/// does not block it; creation tops up to rent and keeps the excess, and every
/// lamport (the pre-funding included) returns to the authority at close.
#[tokio::test(flavor = "multi_thread")]
async fn h2_prefunded_session_and_child_addresses_are_still_created() {
    let mut ctx = start(None).await;
    let auth = keypair(33);
    let payer = ctx.payer.pubkey();
    let s = session_pda(&auth.pubkey(), 2);
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let small = rent.minimum_balance(0);
    // The session and stream get less than their rent, a state span more.
    let large = rent.minimum_balance(4_096) + 12_345;
    let funded = [(s, small), (stream_pda(&s), small), (state_pda(&s, 1), large), (view_pda(&s, VALUE), small), (view_pda(&s, v3::WORKSPACE_ROLE), small), (view_pda(&s, v3::SCRATCH_ROLE), small)];
    for (key, lamports) in funded {
        send(&mut ctx, system_instruction::transfer(&payer, &key, lamports), &[]).await.unwrap();
        assert_eq!(balance(&mut ctx, key).await, lamports);
    }

    send(&mut ctx, open(payer, auth.pubkey(), 2), &[&auth]).await.expect("open on a pre-funded session address");
    for (index, (name, build)) in CREATORS.into_iter().enumerate() {
        send(&mut ctx, build(payer, s, Slot(auth.pubkey(), true)), &[&auth]).await.unwrap_or_else(|e| panic!("{name} on a pre-funded address: {e}"));
        if index == 1 {
            send(&mut ctx, initialize(auth.pubkey(), s), &[&auth]).await.unwrap();
        }
    }
    let mut held = 0;
    for key in [s].into_iter().chain(children(&s).map(|(k, _)| k)) {
        let account = ctx.banks_client.get_account(key).await.unwrap().unwrap();
        assert_eq!(account.owner, PROGRAM);
        assert!(account.lamports >= rent.minimum_balance(account.data.len()), "rent-exempt");
        held += account.lamports;
    }
    assert_eq!(balance(&mut ctx, state_pda(&s, 1)).await, large, "excess pre-funding is kept, not refunded early");

    send(&mut ctx, halt(auth.pubkey(), s, 0), &[&auth]).await.unwrap();
    let before = balance(&mut ctx, auth.pubkey()).await;
    for (key, kind) in children(&s) {
        send(&mut ctx, close_child(s, key, auth.pubkey(), kind), &[]).await.unwrap_or_else(|e| panic!("close {kind}: {e}"));
    }
    send(&mut ctx, close_session(s, auth.pubkey()), &[]).await.unwrap();
    assert_eq!(balance(&mut ctx, auth.pubkey()).await, before + held, "every lamport returns to the authority");
}

/// H3: a headerless primary halted part-way through its growth closes (any
/// length from 1 byte to the declared one), and the session then closes with
/// all rent back to the authority.
#[tokio::test(flavor = "multi_thread")]
async fn h3_partly_grown_primary_closes_after_halt() {
    const DECLARED: u32 = 20_000;
    let resource = vec![0x5Au8; 1000];
    let mut ctx = start(Some(resource.clone())).await;
    let auth = keypair(34);
    let payer = ctx.payer.pubkey();
    let id = 3u64;
    let s = session_pda(&auth.pubkey(), id);
    let leaf = sha256(&[b"dcg/resource-chunk/1", &0u32.to_le_bytes(), &(resource.len() as u32).to_le_bytes(), &resource]);
    let m = app::V3_FIXED_ENGINE.manifest();
    let mut p = vec![v3::WIRE_VERSION];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&[0, 1]);
    p.extend_from_slice(&64u32.to_le_bytes());
    p.push(8);
    p.extend_from_slice(&m.id.0);
    p.extend_from_slice(&m.semantic_version.to_le_bytes());
    p.extend_from_slice(&m.abi_version.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
    p.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
    p.extend_from_slice(&[0xA5; 32]);
    p.extend_from_slice(&[0; 32]);
    p.extend_from_slice(RESOURCE.as_ref());
    p.extend_from_slice(&app::V3_RESOURCE_SCHEMA.id.to_le_bytes());
    p.extend_from_slice(&app::V3_RESOURCE_SCHEMA.version.to_le_bytes());
    p.extend_from_slice(&leaf);
    p.push(1); // headerless primary
    let slot = Slot(auth.pubkey(), true);
    send(&mut ctx, ix(sw::TAG_OPEN_SESSION, p, vec![AccountMeta::new(payer, true), signer(auth.pubkey()), w(s), r(RESOURCE), w(resource_pda(&s)), r(SYSTEM)]), &[&auth]).await.unwrap();
    send(&mut ctx, create_stream(payer, s, slot), &[&auth]).await.unwrap();
    let mut cs = vec![v3::WIRE_VERSION, 1];
    cs.extend_from_slice(&DECLARED.to_le_bytes());
    let primary = state_pda(&s, 0);
    let create_primary = ix(sw::TAG_CREATE_STATE, cs, vec![AccountMeta::new(payer, true), w(s), slot.meta(), r(resource_pda(&s)), w(primary), r(SYSTEM)]);
    // The primary also needs the authority (H1).
    let mut unsigned = create_primary.clone();
    unsigned.accounts[2].is_signer = false;
    assert_eq!(send(&mut ctx, unsigned, &[]).await, Err(v3::REFUSAL_AUTHORITY));
    send(&mut ctx, create_primary, &[&auth]).await.unwrap();
    let grow = ix(sw::TAG_CREATE_STATE, vec![v3::WIRE_VERSION, v3::STATE_OP_GROW, 0], vec![AccountMeta::new(payer, true), r(s), w(primary), r(SYSTEM)]);
    send(&mut ctx, grow.clone(), &[]).await.unwrap();
    let partial = data(&mut ctx, primary).await.unwrap().len();
    assert!(partial > 0 && partial < DECLARED as usize, "halted part-way: {partial} of {DECLARED}");

    // An active session still refuses to close it.
    assert_eq!(send(&mut ctx, close_child(s, primary, auth.pubkey(), v3::KIND_STATE), &[]).await, Err(v3::REFUSAL_LIVE));
    send(&mut ctx, halt(auth.pubkey(), s, 0), &[&auth]).await.unwrap();
    assert!(send(&mut ctx, grow, &[]).await.is_err(), "growth needs an active session");

    let mut held = 0;
    for key in [s, resource_pda(&s), stream_pda(&s), primary] {
        held += balance(&mut ctx, key).await;
    }
    let before = balance(&mut ctx, auth.pubkey()).await;
    // Wrong refund is still refused for the partial primary.
    assert!(send(&mut ctx, close_child(s, primary, keypair(35).pubkey(), v3::KIND_STATE), &[]).await.is_err());
    for (key, kind) in [(resource_pda(&s), v3::KIND_RESOURCE), (stream_pda(&s), v3::KIND_STREAM), (primary, v3::KIND_STATE)] {
        send(&mut ctx, close_child(s, key, auth.pubkey(), kind), &[]).await.unwrap_or_else(|e| panic!("close {kind}: {e}"));
    }
    send(&mut ctx, close_session(s, auth.pubkey()), &[]).await.unwrap();
    assert_eq!(balance(&mut ctx, auth.pubkey()).await, before + held, "nothing stranded");
    for key in [s, resource_pda(&s), stream_pda(&s), primary] {
        assert_eq!(balance(&mut ctx, key).await, 0);
    }
}

fn anchor_pda(s: &Pubkey) -> Pubkey {
    pda(&[b"dcg-anchor-v3", s.as_ref()])
}

/// H2 (re-review 10-05): a pre-funded anchor address still takes a
/// multi-chunk anchor. Before the fix `begin_anchor` treated any address with
/// lamports as an existing anchor and refused it (2324) for good.
#[tokio::test(flavor = "multi_thread")]
async fn h2_prefunded_anchor_address_still_anchors() {
    let mut ctx = start(None).await;
    let auth = keypair(37);
    let payer = ctx.payer.pubkey();
    let s = session_pda(&auth.pubkey(), 3);
    send(&mut ctx, open(payer, auth.pubkey(), 3), &[&auth]).await.unwrap();
    send(&mut ctx, create_stream(payer, s, Slot(auth.pubkey(), true)), &[&auth]).await.unwrap();
    send(&mut ctx, create_state(payer, s, Slot(auth.pubkey(), true)), &[&auth]).await.unwrap();
    send(&mut ctx, initialize(auth.pubkey(), s), &[&auth]).await.unwrap();
    let anchor = anchor_pda(&s);
    let small = ctx.banks_client.get_rent().await.unwrap().minimum_balance(0);
    send(&mut ctx, system_instruction::transfer(&payer, &anchor, small), &[]).await.unwrap();
    let mut payload = vec![v3::WIRE_VERSION, v3::ANCHOR_OP_BEGIN];
    payload.extend_from_slice(&0u32.to_le_bytes());
    let begin = ix(
        sw::TAG_ANCHOR,
        payload,
        vec![
            AccountMeta::new(payer, true),
            signer(auth.pubkey()),
            w(s),
            r(stream_pda(&s)),
            w(anchor),
            r(state_pda(&s, 0)),
            r(state_pda(&s, 1)),
            r(SYSTEM),
        ],
    );
    send(&mut ctx, begin, &[&auth]).await.expect("anchor begins on a pre-funded address");
    let account = ctx.banks_client.get_account(anchor).await.unwrap().unwrap();
    assert_eq!(account.owner, PROGRAM, "the anchor was created");
}
