#![cfg(feature = "sbf-real-lifecycle-test")]

//! Run-level fuzzer for stateful sessions v3 and render lanes (alpha R2; spec:
//! "Fuzzer scope" in `docs/experiments/sessions-v3-review-2026-10-05.md`;
//! results in `docs/experiments/sessions-v3-fuzz-2026-10-05.md`).
//!
//! Each sequence opens one session on its own ProgramTest bank and plays a
//! seeded, state-dependent sequence of transactions from five actors (the
//! fee payer, the session authority, an APPEND-policy writer, a bystander and
//! a lamport pre-funder): open, every child create and grow, resource grow and
//! upload, inputs, single and batched advances, phased initialization, view
//! publication, lanes (create, grow, capture begin/run/end, render, commit,
//! abort), one-shot and chunked anchors, halts in every phase, closes in any
//! order, pre-funding transfers, resends of earlier transactions, reordered
//! pairs, multi-instruction bundles and (SBF only) compute-limit failures.
//!
//! A host reference model predicts whether every transaction is accepted and
//! what it changes; after every transaction the runner compares the program's
//! accounts with the model and checks the review's invariants. At the end of
//! each sequence a liveness oracle (accepting kernel: the authority can still
//! advance and, with lanes, publish) and a closability oracle (halt and close
//! everything; every lamport returns to the authority) run.
//!
//! Two kernels from the `test-kernel` feature are used: the lane counter
//! (headered two-span state, lanes 0-4; an accepting kernel with width 1, a
//! refusing one with width 2) and the workspace-first fixed-address engine
//! (headerless 1,280- or 8,192-byte primary, sealed resource, phased
//! initialization, halt-before 0xEE, halt-after 0xEF, an injected refusal
//! 0xED, an initialization refusal when the resource starts with 0xEE, and a
//! render that refuses any phase past the first 16 bytes). Its render needs
//! the SBF fixed input address, so view commits run only on SBF.
//!
//! Run (native):
//! `V3_FUZZ_SEED=1 V3_FUZZ_COUNT=200 cargo test -p dcg-program --features sbf-real-lifecycle-test --test stateful_v3_fuzz -- --ignored fuzz_campaign --nocapture`
//! `V3_FUZZ_ONLY=<i>` replays one sequence verbosely; `V3_FUZZ_SBF=1` with
//! `BPF_OUT_DIR`/`SBF_OUT_DIR` runs the feature-built SBF image.

use std::collections::BTreeMap;

use dcg_program::{hash::sha256, kernel::Kernel, stateful as sw, stateful::v3, stateful::v3::lanes as ln, stateful_test as app};
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::{pubkey::Pubkey, system_instruction, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

/// The fixed engine checks that the resource copy's owner is `[0xD9; 32]`.
const PROGRAM: Pubkey = Pubkey::new_from_array([0xD9; 32]);
const SYSTEM: Pubkey = system_program::ID;
const RESOURCE_SRC: Pubkey = Pubkey::new_from_array(app::V3_RESOURCE_KEY);
const VALUE: u8 = sw::KIND_VIEW_COUNTER;
const TOTAL: u8 = sw::KIND_VIEW_TOTAL;
const WS_VIEW: u8 = 0;
const LANE_PHASE_CU: u32 = 100_000;
const WS_PHASE_CU: u32 = 500_000;
const LANE_INIT_CU: u32 = 80_000;
const NO_STAMP: u32 = u32::MAX;
const PH_NONE: u8 = 0;
const PH_VIEW: u8 = 1;
const PH_INIT: u8 = 2;
const PH_ANCHOR: u8 = 3;
const L_IDLE: u8 = 0;
const L_CAP: u8 = 1;
const L_REN: u8 = 2;
const HALT_BEFORE: u32 = app::V3_HALT_REASON;
const HALT_AFTER: u32 = app::V3_HALT_AFTER_REASON;

// ---------------------------------------------------------------- rng ----

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64, index: u64) -> Self {
        let mut r = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03);
        r.next();
        r
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    /// Inclusive range.
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.below((hi - lo) as u64 + 1) as u32
    }
    fn pct(&mut self, p: u64) -> bool {
        self.below(100) < p
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }
}

// ------------------------------------------------------------- actors ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Actor {
    Payer,
    Authority,
    Writer,
    Bystander,
    Prefunder,
}
const ACTORS: [Actor; 5] = [Actor::Payer, Actor::Authority, Actor::Writer, Actor::Bystander, Actor::Prefunder];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Child {
    Stream,
    State(u8),
    View(u8),
    Workspace,
    Scratch,
    Resource,
    Anchor,
    Lane(u8),
    LaneWs(u8),
    LaneScratch(u8),
}

impl Child {
    fn kind(self) -> u8 {
        match self {
            Child::Stream => v3::KIND_STREAM,
            Child::State(_) => v3::KIND_STATE,
            Child::View(_) => v3::KIND_VIEW,
            Child::Workspace => v3::KIND_WORKSPACE,
            Child::Scratch => v3::KIND_SCRATCH,
            Child::Resource => v3::KIND_RESOURCE,
            Child::Anchor => v3::KIND_ANCHOR,
            Child::Lane(_) => ln::KIND_LANE,
            Child::LaneWs(_) => ln::KIND_LANE_WORKSPACE,
            Child::LaneScratch(_) => ln::KIND_LANE_SCRATCH,
        }
    }
}

// ------------------------------------------------------------- params ----

#[derive(Clone, Debug)]
struct Params {
    /// Workspace-first fixed-address engine (else the lane counter).
    ws: bool,
    lanes: u8,
    append: bool,
    width: u8,
    capacity: u32,
    max_steps: u8,
    root: [u8; 32],
    id: u64,
    resource: Vec<u8>,
    state_len: u32,
    view_len: u32,
}

impl Params {
    fn gen(rng: &mut Rng) -> Self {
        let ws = rng.pct(40);
        let lanes = if ws { 0 } else if rng.pct(25) { 0 } else { rng.range(1, 4) as u8 };
        let mut root = rng.bytes32();
        root[0] |= 1;
        let resource = if ws {
            let len = rng.pick(&[32usize, 64, 700, 1_000, 4_096, 9_000, 17_000]);
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            bytes[0] = if rng.pct(8) { 0xEE } else { 0x11 }; // 0xEE: initialization refuses
            bytes
        } else {
            Vec::new()
        };
        Params {
            ws,
            lanes,
            append: rng.pct(40),
            width: if !ws && rng.pct(8) { 2 } else { 1 },
            capacity: if rng.pct(10) { rng.range(65, 80) } else { rng.range(2, 10) },
            max_steps: rng.range(1, 8) as u8,
            root,
            id: rng.below(1 << 20),
            resource,
            state_len: match rng.below(100) {
                0..=74 => 1_280,
                75..=89 => 8_192,
                _ => 20_000,
            },
            view_len: if rng.pct(80) { 16 } else { 32 },
        }
    }
    fn state_bytes(&self) -> u32 {
        if self.ws { self.state_len } else { 16 }
    }
    fn span_count(&self) -> u8 {
        if self.ws { 1 } else { 2 }
    }
    fn kernel_id(&self) -> [u8; 16] {
        if self.ws { app::V3_WORKSPACE_ENGINE.manifest().id.0 } else { app::V3_LANE_COUNTER.manifest().id.0 }
    }
    fn schema(&self) -> (u32, u16) {
        let s = if self.ws { app::V3_STATE_SCHEMA } else { app::COUNTER_SCHEMA };
        (s.id, s.version)
    }
    fn phase_cu(&self) -> u32 {
        if self.ws { WS_PHASE_CU } else { LANE_PHASE_CU }
    }
    fn init_cu(&self) -> u32 {
        if self.ws { app::V3_INIT_COMPUTE_UNITS } else { LANE_INIT_CU }
    }
    fn view_roles(&self) -> Vec<u8> {
        if self.ws { vec![WS_VIEW] } else { vec![VALUE, TOTAL] }
    }
    /// (abi, source offset, len) for a role.
    fn view_def(&self, role: u8) -> ([u8; 32], u32, u32) {
        match (self.ws, role) {
            (true, _) => (app::V3_VIEW_ABI, 0, self.view_len),
            (false, VALUE) => (app::VALUE_VIEW_ABI, 0, 8),
            (false, _) => (app::TOTAL_VIEW_ABI, 8, 8),
        }
    }
    fn commitment(&self) -> [u8; 32] {
        leaf(0, self.resource.len() as u32, &self.resource)
    }
}

fn leaf(index: u32, len: u32, bytes: &[u8]) -> [u8; 32] {
    sha256(&[b"dcg/resource-chunk/1", &index.to_le_bytes(), &len.to_le_bytes(), bytes])
}

// ----------------------------------------------------------------- ops ----

#[derive(Clone, Debug)]
enum Op {
    Open { payer: Actor, auth: Actor, lanes: Option<u8> },
    CreateStream { payer: Actor, auth: Actor, signed: bool },
    GrowStream { payer: Actor, cap: u32 },
    CreateState { payer: Actor, auth: Actor, signed: bool },
    GrowState { payer: Actor, index: u8 },
    InitOneCall { auth: Actor },
    BeginInit { auth: Actor, len: u32 },
    RunInit { auth: Actor, at: u32 },
    ResourceGrow { payer: Actor, auth: Actor, next: u32 },
    ResourceChunk { auth: Actor, bad: bool },
    CreateView { payer: Actor, auth: Actor, signed: bool, role: u8, bad_abi: bool },
    CreateWorkspace { payer: Actor, auth: Actor, len: u32 },
    CreateScratch { payer: Actor, auth: Actor, len: u32 },
    GrowView { payer: Actor, role: u8 },
    Write { actor: Actor, seq: u32, bytes: Vec<u8> },
    Advance { actor: Actor, cursor: u32, steps: u8 },
    Begin { actor: Actor, cursor: u32 },
    Run { actor: Actor, at: u32, phases: Option<u8> },
    Commit { actor: Actor, cursor: u32, staged: u32 },
    Abort { actor: Actor, cursor: u32 },
    LaneCreate { payer: Actor, auth: Actor, k: u8, ws_len: u32, sc_len: u32 },
    LaneGrow { payer: Actor, k: u8, scratch: bool },
    CapBegin { actor: Actor, k: u8, c: u32 },
    CapRun { actor: Actor, k: u8, c: u32, at: u32, phases: Option<u8> },
    CapEnd { actor: Actor, k: u8, c: u32 },
    Render { actor: Actor, k: u8, c: u32, at: u32, phases: Option<u8> },
    LaneCommit { actor: Actor, k: u8, c: u32 },
    LaneAbort { actor: Actor, k: u8, c: u32 },
    Halt { actor: Actor, cursor: u32 },
    AnchorOne { actor: Actor, cursor: u32 },
    AnchorBegin { payer: Actor, auth: Actor, cursor: u32 },
    AnchorChunk { auth: Actor, cursor: u32, offset: u32 },
    AnchorFinish { auth: Actor, cursor: u32 },
    AnchorAbort { auth: Actor, cursor: u32 },
    Close { child: Child, kind: u8, refund: Actor },
    CloseSession { refund: Actor },
    Prefund { target: Pubkey, lamports: u64 },
}

impl Op {
    fn name(&self) -> &'static str {
        match self {
            Op::Open { .. } => "open",
            Op::CreateStream { .. } => "create_stream",
            Op::GrowStream { .. } => "grow_stream",
            Op::CreateState { .. } => "create_state",
            Op::GrowState { .. } => "grow_state",
            Op::InitOneCall { .. } => "init_one_call",
            Op::BeginInit { .. } => "begin_init",
            Op::RunInit { .. } => "run_init",
            Op::ResourceGrow { .. } => "resource_grow",
            Op::ResourceChunk { .. } => "resource_chunk",
            Op::CreateView { .. } => "create_view",
            Op::CreateWorkspace { .. } => "create_workspace",
            Op::CreateScratch { .. } => "create_scratch",
            Op::GrowView { .. } => "grow_view",
            Op::Write { .. } => "write_input",
            Op::Advance { .. } => "advance",
            Op::Begin { .. } => "begin_phase",
            Op::Run { .. } => "run_phase",
            Op::Commit { .. } => "commit_phase",
            Op::Abort { .. } => "abort_phase",
            Op::LaneCreate { .. } => "lane_create",
            Op::LaneGrow { .. } => "lane_grow",
            Op::CapBegin { .. } => "capture_begin",
            Op::CapRun { .. } => "capture_run",
            Op::CapEnd { .. } => "capture_end",
            Op::Render { .. } => "lane_render",
            Op::LaneCommit { .. } => "lane_commit",
            Op::LaneAbort { .. } => "lane_abort",
            Op::Halt { .. } => "halt",
            Op::AnchorOne { .. } => "anchor_one_shot",
            Op::AnchorBegin { .. } => "anchor_begin",
            Op::AnchorChunk { .. } => "anchor_chunk",
            Op::AnchorFinish { .. } => "anchor_finish",
            Op::AnchorAbort { .. } => "anchor_abort",
            Op::Close { .. } => "close_child",
            Op::CloseSession { .. } => "close_session",
            Op::Prefund { .. } => "prefund",
        }
    }
}

// --------------------------------------------------------------- model ----

#[derive(Clone, Debug, Default)]
struct LaneM {
    status: u8,
    captured: u32,
    cap_at: u32,
    ren_at: u32,
    ren_total: u32,
    /// (role, source offset, len) of the views at capture begin.
    views: Vec<(u8, u32, u32)>,
    ws_len: u32,
    sc_len: u32,
}

#[derive(Clone, Debug)]
struct ViewM {
    offset: u32,
    len: u32,
    stamp: u32,
    content: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AnchorM {
    open: bool,
    cursor: u32,
    total: u32,
    progress: u32,
    input_root: [u8; 32],
    acc: [u8; 32],
}

/// The host reference model of one session.
#[derive(Clone, Debug, Default)]
struct M {
    open: bool,
    active: bool,
    halt_reason: u32,
    halt_cursor: u32,
    lanes: u8,
    stream: bool,
    capacity: u32,
    cursor: u32,
    frontier: u32,
    slots: Vec<Option<Vec<u8>>>,
    states: u8,
    /// Allocated bytes of the headerless primary (fixed engine).
    state_alloc: u32,
    initialized: bool,
    last_start: u32,
    views: BTreeMap<u8, ViewM>,
    workspace: Option<u32>,
    scratch: Option<u32>,
    resource: bool,
    res_alloc: u32,
    res_received: bool,
    anchor: Option<AnchorM>,
    anchor_cursor: u32,
    state_anchor: [u8; 32],
    phase: u8,
    ph_state: u32,
    ph_at: u32,
    ph_total: u32,
    lane: [Option<LaneM>; 4],
    lane_ws: [bool; 4],
    lane_sc: [bool; 4],
    last_captured: u32,
    mask: u8,
    /// Newest stamp ever published (for monotonicity).
    newest_stamp: Option<u32>,
}

impl M {
    fn children(&self) -> Vec<Child> {
        let mut out = Vec::new();
        if self.stream {
            out.push(Child::Stream);
        }
        for i in 0..self.states {
            out.push(Child::State(i));
        }
        for role in self.views.keys() {
            out.push(Child::View(*role));
        }
        if self.workspace.is_some() {
            out.push(Child::Workspace);
        }
        if self.scratch.is_some() {
            out.push(Child::Scratch);
        }
        if self.resource {
            out.push(Child::Resource);
        }
        if self.anchor.is_some() {
            out.push(Child::Anchor);
        }
        for k in 0..4u8 {
            if self.lane[k as usize].is_some() {
                out.push(Child::Lane(k));
            }
            if self.lane_ws[k as usize] {
                out.push(Child::LaneWs(k));
            }
            if self.lane_sc[k as usize] {
                out.push(Child::LaneScratch(k));
            }
        }
        out
    }
    fn has(&self, child: Child) -> bool {
        self.children().contains(&child)
    }
    fn view_total(&self) -> u32 {
        self.views.values().map(|v| v.len).sum()
    }
    fn clear_phase(&mut self) {
        self.phase = PH_NONE;
        self.ph_state = 0;
        self.ph_at = 0;
        self.ph_total = 0;
    }
}

// ----------------------------------------------------------- snapshots ----

type Snap = Vec<Option<Account>>;

#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    Custom(u32),
    /// Another instruction error (budget exhaustion, malformed data, keys).
    Other(String),
    /// Not executed (no fee charged), e.g. an identical resend.
    NotRun(String),
}

#[derive(Default, Debug, Clone)]
struct Stats {
    sequences: u64,
    txs: u64,
    accepted: u64,
    refused: u64,
    not_run: u64,
    cu_failures: u64,
    resends: u64,
    reorders: u64,
    bundles: u64,
    checks: u64,
    ops: BTreeMap<&'static str, (u64, u64)>,
    halts: BTreeMap<String, u64>,
    liveness_runs: u64,
    liveness_publish: u64,
    liveness_skipped: BTreeMap<&'static str, u64>,
    closability_runs: u64,
    reopened: u64,
    ws_sequences: u64,
    lane_sequences: u64,
    max_cursor: u32,
    commits: u64,
    lane_commits: u64,
    anchors_finished: u64,
    one_shot_anchors: u64,
    prefunds: u64,
}

impl Stats {
    fn merge(&mut self, o: &Stats) {
        self.sequences += o.sequences;
        self.txs += o.txs;
        self.accepted += o.accepted;
        self.refused += o.refused;
        self.not_run += o.not_run;
        self.cu_failures += o.cu_failures;
        self.resends += o.resends;
        self.reorders += o.reorders;
        self.bundles += o.bundles;
        self.checks += o.checks;
        for (k, v) in &o.ops {
            let e = self.ops.entry(k).or_default();
            e.0 += v.0;
            e.1 += v.1;
        }
        for (k, v) in &o.halts {
            *self.halts.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.liveness_skipped {
            *self.liveness_skipped.entry(k).or_default() += v;
        }
        self.liveness_runs += o.liveness_runs;
        self.liveness_publish += o.liveness_publish;
        self.closability_runs += o.closability_runs;
        self.reopened += o.reopened;
        self.ws_sequences += o.ws_sequences;
        self.lane_sequences += o.lane_sequences;
        self.max_cursor = self.max_cursor.max(o.max_cursor);
        self.commits += o.commits;
        self.lane_commits += o.lane_commits;
        self.anchors_finished += o.anchors_finished;
        self.one_shot_anchors += o.one_shot_anchors;
        self.prefunds += o.prefunds;
    }
}

// ---------------------------------------------------------------- keys ----

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM).0
}

struct Keys {
    actors: [Keypair; 4], // authority, writer, bystander, prefunder
    session: Pubkey,
    stream: Pubkey,
    states: [Pubkey; 2],
    views: BTreeMap<u8, Pubkey>,
    resource: Pubkey,
    anchor: Pubkey,
    lanes: [Pubkey; 4],
    lane_ws: [Pubkey; 4],
    lane_sc: [Pubkey; 4],
}

impl Keys {
    fn new(rng: &mut Rng, id: u64) -> Self {
        let actors = [0, 1, 2, 3].map(|_| solana_keypair::keypair_from_seed(&rng.bytes32()).unwrap());
        let session = pda(&[b"dcg-session-v3", actors[0].pubkey().as_ref(), &id.to_le_bytes()]);
        let view = |role: u8| pda(&[b"dcg-view-v3", session.as_ref(), &[role]]);
        let mut views = BTreeMap::new();
        for role in [WS_VIEW, VALUE, TOTAL, v3::WORKSPACE_ROLE, v3::SCRATCH_ROLE] {
            views.insert(role, view(role));
        }
        Keys {
            stream: pda(&[b"dcg-input-v3", session.as_ref()]),
            states: [0u8, 1].map(|i| pda(&[b"dcg-state-v3", session.as_ref(), &[i]])),
            resource: pda(&[b"dcg-resource-v3", session.as_ref()]),
            anchor: pda(&[b"dcg-anchor-v3", session.as_ref()]),
            lanes: [0u8, 1, 2, 3].map(|k| pda(&[ln::LANE_SEED, session.as_ref(), &[k]])),
            lane_ws: [0u8, 1, 2, 3].map(|k| view(ln::WORKSPACE_ROLE_BASE + k)),
            lane_sc: [0u8, 1, 2, 3].map(|k| view(ln::SCRATCH_ROLE_BASE + k)),
            views,
            actors,
            session,
        }
    }
    fn view(&self, role: u8) -> Pubkey {
        self.views[&role]
    }
    fn child(&self, c: Child) -> Pubkey {
        match c {
            Child::Stream => self.stream,
            Child::State(i) => self.states[i as usize],
            Child::View(r) => self.view(r),
            Child::Workspace => self.view(v3::WORKSPACE_ROLE),
            Child::Scratch => self.view(v3::SCRATCH_ROLE),
            Child::Resource => self.resource,
            Child::Anchor => self.anchor,
            Child::Lane(k) => self.lanes[k as usize],
            Child::LaneWs(k) => self.lane_ws[k as usize],
            Child::LaneScratch(k) => self.lane_sc[k as usize],
        }
    }
    /// Every session-derived address, with its child identity (None: session).
    fn derived(&self) -> Vec<(Option<Child>, Pubkey)> {
        let mut out = vec![(None, self.session), (Some(Child::Stream), self.stream)];
        for i in 0..2 {
            out.push((Some(Child::State(i)), self.states[i as usize]));
        }
        for role in [WS_VIEW, VALUE, TOTAL] {
            out.push((Some(Child::View(role)), self.view(role)));
        }
        out.push((Some(Child::Workspace), self.view(v3::WORKSPACE_ROLE)));
        out.push((Some(Child::Scratch), self.view(v3::SCRATCH_ROLE)));
        out.push((Some(Child::Resource), self.resource));
        out.push((Some(Child::Anchor), self.anchor));
        for k in 0..4u8 {
            out.push((Some(Child::Lane(k)), self.lanes[k as usize]));
            out.push((Some(Child::LaneWs(k)), self.lane_ws[k as usize]));
            out.push((Some(Child::LaneScratch(k)), self.lane_sc[k as usize]));
        }
        out
    }
}

fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn u16_at(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(d[at..at + 2].try_into().unwrap())
}
fn w(k: Pubkey) -> AccountMeta {
    AccountMeta::new(k, false)
}
fn r(k: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(k, false)
}
fn ix(tag: u8, payload: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(&payload);
    Instruction { program_id: PROGRAM, accounts, data }
}

// ---------------------------------------------------------------- fuzz ----

struct Config {
    sbf: bool,
    verbose: bool,
    /// Planted model error (self-test): 1, the host input chain uses a wrong
    /// domain; 2, the model forbids the authority's halt; 3, the host
    /// counter adds one extra per input.
    plant: u8,
}

struct Fuzz {
    ctx: ProgramTestContext,
    p: Params,
    k: Keys,
    m: M,
    rng: Rng,
    cfg: Config,
    stats: Stats,
    nonce: u32,
    history: Vec<Vec<Op>>,
    tag: String,
    log: Vec<String>,
    keys_tracked: Vec<Pubkey>,
    rent0: u64,
    /// Whether this sequence tends to halt near its end (else it usually
    /// ends active, for the liveness oracle).
    halt_late: bool,
    last_logs: String,
    /// Set while predicting a transaction that marks the resource copy writable.
    res_writable: bool,
}

macro_rules! fail {
    ($f:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        panic!("{}: {}\n--- last logs ---\n{}\n--- last steps ---\n{}", $f.tag, msg, $f.last_logs, $f.log.iter().rev().take(25).rev().cloned().collect::<Vec<_>>().join("\n"));
    }};
}

impl Fuzz {
    fn actor_key(&self, a: Actor) -> Pubkey {
        match a {
            Actor::Payer => self.ctx.payer.pubkey(),
            Actor::Authority => self.k.actors[0].pubkey(),
            Actor::Writer => self.k.actors[1].pubkey(),
            Actor::Bystander => self.k.actors[2].pubkey(),
            Actor::Prefunder => self.k.actors[3].pubkey(),
        }
    }
    fn writer(&self) -> Actor {
        if self.p.append { Actor::Writer } else { Actor::Authority }
    }
    fn auth(&self) -> Pubkey {
        self.k.actors[0].pubkey()
    }

    // --------------------------------------------------------- build ----

    fn signer(&self, a: Actor) -> AccountMeta {
        AccountMeta::new_readonly(self.actor_key(a), true)
    }
    fn payer_meta(&self, a: Actor) -> AccountMeta {
        AccountMeta::new(self.actor_key(a), true)
    }
    /// Creator account 2: the claimed authority, signing or not.
    fn slot(&self, a: Actor, signed: bool) -> AccountMeta {
        AccountMeta::new_readonly(self.actor_key(a), signed)
    }
    fn state_metas(&self, writable: bool) -> Vec<AccountMeta> {
        (0..self.p.span_count() as usize).map(|i| if writable { w(self.k.states[i]) } else { r(self.k.states[i]) }).collect()
    }
    fn view_metas(&self, roles: &[u8], writable: bool) -> Vec<AccountMeta> {
        roles.iter().map(|role| if writable { w(self.k.view(*role)) } else { r(self.k.view(*role)) }).collect()
    }
    fn model_roles(&self) -> Vec<u8> {
        self.m.views.keys().copied().collect()
    }
    /// The v3 publication prefix: [state0?, authority, session, resource?, other states].
    fn prefix(&self, actor: Actor, session_writable: bool, states_writable: bool) -> Vec<AccountMeta> {
        let s = if session_writable { w(self.k.session) } else { r(self.k.session) };
        if self.p.ws {
            let st = if states_writable { w(self.k.states[0]) } else { r(self.k.states[0]) };
            vec![st, self.signer(actor), s, r(self.k.resource)]
        } else {
            let mut a = vec![self.signer(actor), s];
            a.extend(self.state_metas(states_writable));
            a
        }
    }

    fn open_payload(&self, lanes: Option<u8>) -> Vec<u8> {
        let p = &self.p;
        let mut d = vec![v3::WIRE_VERSION];
        d.extend_from_slice(&p.id.to_le_bytes());
        d.extend_from_slice(&[u8::from(p.append), p.width]);
        d.extend_from_slice(&p.capacity.to_le_bytes());
        d.push(p.max_steps);
        let manifest = if p.ws { app::V3_WORKSPACE_ENGINE.manifest() } else { app::V3_LANE_COUNTER.manifest() };
        d.extend_from_slice(&manifest.id.0);
        d.extend_from_slice(&manifest.semantic_version.to_le_bytes());
        d.extend_from_slice(&manifest.abi_version.to_le_bytes());
        d.extend_from_slice(&v3::MODE_CONSENSUS_V3.id.to_le_bytes());
        d.extend_from_slice(&v3::MODE_CONSENSUS_V3.version.to_le_bytes());
        d.extend_from_slice(&p.root);
        if p.append {
            d.extend_from_slice(self.actor_key(Actor::Writer).as_ref());
        } else {
            d.extend_from_slice(&[0; 32]);
        }
        if p.ws {
            d.extend_from_slice(RESOURCE_SRC.as_ref());
            d.extend_from_slice(&app::V3_RESOURCE_SCHEMA.id.to_le_bytes());
            d.extend_from_slice(&app::V3_RESOURCE_SCHEMA.version.to_le_bytes());
            d.extend_from_slice(&p.commitment());
            d.push(1);
        } else {
            d.extend_from_slice(&[0; 32]);
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&0u16.to_le_bytes());
            d.extend_from_slice(&[0; 32]);
            d.push(0);
        }
        d.extend(lanes);
        d
    }

    fn build(&self, op: &Op) -> Vec<Instruction> {
        let ver = v3::WIRE_VERSION;
        let k = &self.k;
        let s = k.session;
        let one = |i: Instruction| vec![i];
        match op.clone() {
            Op::Open { payer, auth, lanes } => {
                let mut a = vec![self.payer_meta(payer), self.signer(auth), w(s)];
                if self.p.ws {
                    a.extend([r(RESOURCE_SRC), w(k.resource)]);
                }
                a.push(r(SYSTEM));
                one(ix(sw::TAG_OPEN_SESSION, self.open_payload(lanes), a))
            }
            Op::CreateStream { payer, auth, signed } => {
                one(ix(sw::TAG_CREATE_STREAM, vec![ver, 0], vec![self.payer_meta(payer), w(s), self.slot(auth, signed), w(k.stream), r(SYSTEM)]))
            }
            Op::GrowStream { payer, cap } => {
                let mut d = vec![ver, 1];
                d.extend_from_slice(&cap.to_le_bytes());
                one(ix(sw::TAG_CREATE_STREAM, d, vec![self.payer_meta(payer), w(s), w(k.stream), r(SYSTEM)]))
            }
            Op::CreateState { payer, auth, signed } => {
                let mut d = vec![ver, self.p.span_count()];
                let mut a = vec![self.payer_meta(payer), w(s), self.slot(auth, signed)];
                if self.p.ws {
                    d.extend_from_slice(&self.p.state_len.to_le_bytes());
                    a.push(r(k.resource));
                } else {
                    d.extend_from_slice(&8u32.to_le_bytes());
                    d.extend_from_slice(&8u32.to_le_bytes());
                }
                a.extend(self.state_metas(true));
                a.push(r(SYSTEM));
                one(ix(sw::TAG_CREATE_STATE, d, a))
            }
            Op::GrowState { payer, index } => {
                one(ix(sw::TAG_CREATE_STATE, vec![ver, v3::STATE_OP_GROW, index], vec![self.payer_meta(payer), r(s), w(k.states[index as usize % 2]), r(SYSTEM)]))
            }
            Op::InitOneCall { auth } => {
                let a = if self.p.ws {
                    vec![w(k.states[0]), self.signer(auth), w(s), r(k.resource)]
                } else {
                    let mut a = vec![self.signer(auth), w(s)];
                    a.extend(self.state_metas(true));
                    a
                };
                one(ix(sw::TAG_CREATE_STATE, vec![ver, v3::STATE_OP_INITIALIZE], a))
            }
            Op::BeginInit { auth, len } => {
                let mut d = vec![ver, v3::STATE_OP_BEGIN_INITIALIZE];
                d.extend_from_slice(&len.to_le_bytes());
                d.extend_from_slice(&self.p.init_cu().to_le_bytes());
                let mut a = vec![self.signer(auth), w(s)];
                if self.p.ws {
                    a.push(r(k.resource));
                }
                one(ix(sw::TAG_CREATE_STATE, d, a))
            }
            Op::RunInit { auth, at } => {
                let mut d = vec![ver, v3::STATE_OP_RUN_INITIALIZE];
                d.extend_from_slice(&at.to_le_bytes());
                d.extend_from_slice(&self.p.init_cu().to_le_bytes());
                let a = if self.p.ws {
                    vec![w(k.states[0]), self.signer(auth), w(s), r(k.resource)]
                } else {
                    let mut a = vec![self.signer(auth), w(s)];
                    a.extend(self.state_metas(true));
                    a
                };
                one(ix(sw::TAG_CREATE_STATE, d, a))
            }
            Op::ResourceGrow { payer, auth, next } => {
                let mut d = vec![ver, v3::RESOURCE_GROW_OP];
                d.extend_from_slice(&next.to_le_bytes());
                one(ix(v3::RESOURCE_CHUNK_TAG, d, vec![self.payer_meta(payer), self.signer(auth), w(s), w(k.resource), r(SYSTEM)]))
            }
            Op::ResourceChunk { auth, bad } => {
                let mut d = vec![ver];
                d.extend_from_slice(&0u32.to_le_bytes());
                if bad {
                    d.push(1);
                    d.extend_from_slice(&[0x77; 32]);
                } else {
                    d.push(0);
                }
                one(ix(v3::RESOURCE_CHUNK_TAG, d, vec![self.signer(auth), w(s), w(k.resource), r(RESOURCE_SRC)]))
            }
            Op::CreateView { payer, auth, signed, role, bad_abi } => {
                let (mut abi, offset, len) = self.p.view_def(role);
                if bad_abi {
                    abi[0] ^= 0xFF;
                }
                let mut d = vec![ver, role];
                d.extend_from_slice(&abi);
                d.extend_from_slice(&offset.to_le_bytes());
                d.extend_from_slice(&len.to_le_bytes());
                one(ix(sw::TAG_CREATE_VIEW, d, vec![self.payer_meta(payer), w(s), self.slot(auth, signed), w(k.view(role)), r(SYSTEM)]))
            }
            Op::CreateWorkspace { payer, auth, len } => {
                let mut d = vec![ver, v3::WORKSPACE_ROLE];
                d.extend_from_slice(&len.to_le_bytes());
                one(ix(sw::TAG_CREATE_VIEW, d, vec![self.payer_meta(payer), w(s), self.signer(auth), w(k.view(v3::WORKSPACE_ROLE)), r(SYSTEM)]))
            }
            Op::CreateScratch { payer, auth, len } => {
                let mut d = vec![ver, v3::SCRATCH_ROLE];
                d.extend_from_slice(&[0; 32]);
                d.extend_from_slice(&0u32.to_le_bytes());
                d.extend_from_slice(&len.to_le_bytes());
                one(ix(sw::TAG_CREATE_VIEW, d, vec![self.payer_meta(payer), w(s), self.signer(auth), w(k.view(v3::SCRATCH_ROLE)), r(SYSTEM)]))
            }
            Op::GrowView { payer, role } => {
                one(ix(sw::TAG_CREATE_VIEW, vec![ver, v3::VIEW_OP_GROW, role], vec![self.payer_meta(payer), r(s), w(k.view(role)), r(SYSTEM)]))
            }
            Op::Write { actor, seq, bytes } => {
                let mut d = vec![ver];
                d.extend_from_slice(&seq.to_le_bytes());
                d.push(bytes.len() as u8);
                d.extend_from_slice(&bytes);
                one(ix(sw::TAG_WRITE_INPUT, d, vec![self.signer(actor), w(s), w(k.stream)]))
            }
            Op::Advance { actor, cursor, steps } => {
                let mut d = vec![ver];
                d.extend_from_slice(&cursor.to_le_bytes());
                d.push(steps);
                let a = if self.p.ws {
                    vec![w(k.states[0]), self.signer(actor), w(s), w(k.stream)]
                } else {
                    let mut a = vec![self.signer(actor), w(s), w(k.stream)];
                    a.extend(self.state_metas(true));
                    a
                };
                one(ix(sw::TAG_ADVANCE, d, a))
            }
            Op::Begin { actor, cursor } => {
                let mut d = vec![ver, 0];
                d.extend_from_slice(&cursor.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                let mut a = self.prefix(actor, true, false);
                a.extend(self.view_metas(&self.model_roles(), false));
                a.extend([w(k.view(v3::WORKSPACE_ROLE)), w(k.view(v3::SCRATCH_ROLE))]);
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::Run { actor, at, phases } => {
                let mut d = vec![ver, 1];
                d.extend_from_slice(&at.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                d.extend(phases);
                let a = if self.p.ws {
                    // Workspace-first order: [workspace, authority, session, resource, state0, views, scratch].
                    let mut a = vec![w(k.view(v3::WORKSPACE_ROLE)), self.signer(actor), w(s), r(k.resource), w(k.states[0])];
                    a.extend(self.view_metas(&self.model_roles(), false));
                    a.push(w(k.view(v3::SCRATCH_ROLE)));
                    a
                } else {
                    let mut a = self.prefix(actor, true, false);
                    a.extend(self.view_metas(&self.model_roles(), false));
                    a.extend([w(k.view(v3::WORKSPACE_ROLE)), w(k.view(v3::SCRATCH_ROLE))]);
                    a
                };
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::Commit { actor, cursor, staged } => {
                let mut d = vec![ver, 2];
                d.extend_from_slice(&cursor.to_le_bytes());
                d.extend_from_slice(&staged.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                let mut a = self.prefix(actor, true, false);
                a.extend(self.view_metas(&self.model_roles(), true));
                a.extend([r(k.view(v3::WORKSPACE_ROLE)), r(k.view(v3::SCRATCH_ROLE))]);
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::Abort { actor, cursor } => {
                let mut d = vec![ver, 3];
                d.extend_from_slice(&cursor.to_le_bytes());
                one(ix(sw::TAG_PUBLISH_VIEWS, d, vec![self.signer(actor), w(s)]))
            }
            Op::LaneCreate { payer, auth, k: lane, ws_len, sc_len } => {
                let mut d = vec![ver, ln::OP_CREATE, lane];
                d.extend_from_slice(&ws_len.to_le_bytes());
                d.extend_from_slice(&sc_len.to_le_bytes());
                let i = (lane % 4) as usize;
                one(ix(sw::TAG_PUBLISH_VIEWS, d, vec![self.payer_meta(payer), self.signer(auth), w(s), w(k.lanes[i]), w(k.lane_ws[i]), w(k.lane_sc[i]), r(SYSTEM)]))
            }
            Op::LaneGrow { payer, k: lane, scratch } => {
                let i = (lane % 4) as usize;
                let target = if scratch { k.lane_sc[i] } else { k.lane_ws[i] };
                one(ix(sw::TAG_PUBLISH_VIEWS, vec![ver, ln::OP_GROW, lane], vec![self.payer_meta(payer), r(s), r(k.lanes[i]), w(target), r(SYSTEM)]))
            }
            Op::CapBegin { actor, k: lane, c } => {
                let mut d = vec![ver, ln::OP_CAPTURE_BEGIN, lane];
                d.extend_from_slice(&c.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                let mut a = vec![self.signer(actor), w(s), w(k.lanes[(lane % 4) as usize])];
                a.extend(self.view_metas(&self.model_roles(), false));
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::CapRun { actor, k: lane, c, at, phases } => {
                let mut d = vec![ver, ln::OP_CAPTURE_RUN, lane];
                d.extend_from_slice(&c.to_le_bytes());
                d.extend_from_slice(&at.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                d.extend(phases);
                let i = (lane % 4) as usize;
                let mut a = self.prefix(actor, false, false);
                a.extend([w(k.lanes[i]), w(k.lane_ws[i])]);
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::CapEnd { actor, k: lane, c } => {
                let mut d = vec![ver, ln::OP_CAPTURE_END, lane];
                d.extend_from_slice(&c.to_le_bytes());
                one(ix(sw::TAG_PUBLISH_VIEWS, d, vec![self.signer(actor), w(s), w(k.lanes[(lane % 4) as usize])]))
            }
            Op::Render { actor, k: lane, c, at, phases } => {
                let mut d = vec![ver, ln::OP_RUN, lane];
                d.extend_from_slice(&c.to_le_bytes());
                d.extend_from_slice(&at.to_le_bytes());
                d.extend_from_slice(&self.p.phase_cu().to_le_bytes());
                d.extend(phases);
                let i = (lane % 4) as usize;
                one(ix(sw::TAG_PUBLISH_VIEWS, d, vec![w(k.lane_ws[i]), self.signer(actor), w(k.lanes[i]), w(k.lane_sc[i])]))
            }
            Op::LaneCommit { actor, k: lane, c } => {
                let mut d = vec![ver, ln::OP_COMMIT, lane];
                d.extend_from_slice(&c.to_le_bytes());
                let i = (lane % 4) as usize;
                let roles: Vec<u8> = match &self.m.lane[i] {
                    Some(l) if !l.views.is_empty() => l.views.iter().map(|v| v.0).collect(),
                    _ => self.model_roles(),
                };
                let mut a = vec![self.signer(actor), r(s), w(k.lanes[i]), r(k.lane_sc[i])];
                a.extend(self.view_metas(&roles, true));
                one(ix(sw::TAG_PUBLISH_VIEWS, d, a))
            }
            Op::LaneAbort { actor, k: lane, c } => {
                let mut d = vec![ver, ln::OP_ABORT, lane];
                d.extend_from_slice(&c.to_le_bytes());
                one(ix(sw::TAG_PUBLISH_VIEWS, d, vec![self.signer(actor), w(s), w(k.lanes[(lane % 4) as usize])]))
            }
            Op::Halt { actor, cursor } => {
                let mut d = vec![ver];
                d.extend_from_slice(&cursor.to_le_bytes());
                one(ix(sw::TAG_HALT_SESSION, d, vec![self.signer(actor), w(s)]))
            }
            Op::AnchorOne { actor, cursor } => {
                let mut d = vec![ver];
                d.extend_from_slice(&cursor.to_le_bytes());
                let a = if self.p.ws {
                    vec![r(k.states[0]), self.signer(actor), w(s), r(k.stream)]
                } else {
                    let mut a = vec![self.signer(actor), w(s), r(k.stream)];
                    a.extend(self.state_metas(false));
                    a
                };
                one(ix(sw::TAG_ANCHOR, d, a))
            }
            Op::AnchorBegin { payer, auth, cursor } => {
                let mut d = vec![ver, v3::ANCHOR_OP_BEGIN];
                d.extend_from_slice(&cursor.to_le_bytes());
                let mut a = vec![self.payer_meta(payer), self.signer(auth), w(s), r(k.stream), w(k.anchor)];
                a.extend(self.state_metas(false));
                a.push(r(SYSTEM));
                one(ix(sw::TAG_ANCHOR, d, a))
            }
            Op::AnchorChunk { auth, cursor, offset } => {
                let mut d = vec![ver, v3::ANCHOR_OP_CHUNK];
                d.extend_from_slice(&cursor.to_le_bytes());
                d.extend_from_slice(&offset.to_le_bytes());
                let mut a = vec![self.signer(auth), w(s), r(k.stream), w(k.anchor)];
                a.extend(self.state_metas(false));
                one(ix(sw::TAG_ANCHOR, d, a))
            }
            Op::AnchorFinish { auth, cursor } | Op::AnchorAbort { auth, cursor } => {
                let code = if matches!(op, Op::AnchorFinish { .. }) { v3::ANCHOR_OP_FINISH } else { v3::ANCHOR_OP_ABORT };
                let mut d = vec![ver, code];
                d.extend_from_slice(&cursor.to_le_bytes());
                one(ix(sw::TAG_ANCHOR, d, vec![self.signer(auth), w(s), w(k.anchor)]))
            }
            Op::Close { child, kind, refund } => {
                one(ix(sw::TAG_CLOSE_ACCOUNT, vec![ver, kind], vec![w(s), w(k.child(child)), w(self.actor_key(refund))]))
            }
            Op::CloseSession { refund } => one(ix(sw::TAG_CLOSE_ACCOUNT, vec![ver, v3::KIND_SESSION], vec![w(s), w(self.actor_key(refund))])),
            Op::Prefund { target, lamports } => one(system_instruction::transfer(&self.actor_key(Actor::Prefunder), &target, lamports)),
        }
    }

    // ---------------------------------------------------- host replay ----

    /// The consumed inputs (slots below the cursor).
    fn consumed<'a>(&self, m: &'a M) -> Vec<&'a [u8]> {
        (0..m.cursor as usize).map(|i| m.slots[i].as_deref().expect("consumed slot")).collect()
    }

    fn input_root(&self, m: &M) -> [u8; 32] {
        let domain: &[u8] = if self.cfg.plant == 1 { b"dcg/input-chain/X" } else { b"dcg/input-chain/2" };
        let mut root = self.p.root;
        for (seq, cmd) in self.consumed(m).iter().enumerate() {
            root = sha256(&[domain, &root, &(seq as u32).to_le_bytes(), cmd]);
        }
        root
    }

    /// The logical state bytes after `cursor` inputs (lane counter: value,
    /// total; fixed engine: the resource-initialized primary plus the sum of
    /// consumed inputs in its last eight bytes).
    fn state_at(&self, m: &M, cursor: u32) -> Vec<u8> {
        if !m.initialized {
            return vec![0; self.p.state_bytes() as usize];
        }
        if self.p.ws {
            let len = self.p.state_len as usize;
            let mut st = vec![0u8; len];
            let n = len.min(self.p.resource.len());
            st[..n].copy_from_slice(&self.p.resource[..n]);
            let mut v = u64::from_le_bytes(st[len - 8..].try_into().unwrap());
            for i in 0..cursor as usize {
                v = v.wrapping_add(m.slots[i].as_ref().unwrap()[0] as u64);
            }
            st[len - 8..].copy_from_slice(&v.to_le_bytes());
            st
        } else {
            let (mut value, mut total) = (0u64, 0u64);
            for i in 0..cursor as usize {
                value += m.slots[i].as_ref().unwrap()[0] as u64 + u64::from(self.cfg.plant == 3);
                total += value;
            }
            let mut st = value.to_le_bytes().to_vec();
            st.extend_from_slice(&total.to_le_bytes());
            st
        }
    }

    /// Kernel outcome of advancing `steps` from the model cursor:
    /// Some((new cursor, halt reason)) or None if the kernel refuses.
    fn kernel_advance(&self, m: &M, steps: u8) -> Option<(u32, Option<u32>)> {
        let mut c = m.cursor;
        for seq in m.cursor..m.cursor + steps as u32 {
            let cmd = m.slots[seq as usize].as_ref()?;
            if !self.p.ws {
                if cmd.len() != 1 {
                    return None;
                }
                c += 1;
                continue;
            }
            match cmd[0] {
                0xEE => return Some((c, Some(HALT_BEFORE))),
                0xED => return None,
                0xEF => return Some((c + 1, Some(HALT_AFTER))),
                _ => c += 1,
            }
        }
        Some((c, None))
    }

    fn schema_parts(&self) -> ([u8; 4], [u8; 2]) {
        let (id, version) = self.p.schema();
        (id.to_le_bytes(), version.to_le_bytes())
    }

    // ------------------------------------------------------ predict ----

    fn valid(&self, m: &M, op: &Op) -> bool {
        use Actor::Authority as A;
        let p = &self.p;
        let live = m.open && m.active;
        match op {
            Op::Open { payer, auth, lanes } => {
                let lanes_ok = match lanes {
                    None => true,
                    Some(n) => !p.ws && (1..=4).contains(n),
                };
                !m.open && *auth == A && *payer != A && lanes_ok
            }
            Op::CreateStream { auth, signed, .. } => live && *auth == A && *signed && !m.stream,
            Op::GrowStream { cap, .. } => {
                live && m.stream && m.cursor == m.capacity && *cap > m.capacity && *cap - m.capacity <= v3::MAX_STREAM_GROWTH_SLOTS
            }
            Op::CreateState { auth, signed, .. } => live && *auth == A && *signed && m.states == 0,
            // Only the fixed engine's 20,000-byte primary is created short.
            Op::GrowState { index, .. } => p.ws && live && !m.initialized && m.phase == PH_NONE && *index == 0 && m.states > 0 && m.state_alloc < p.state_len,
            Op::InitOneCall { auth } => !p.ws && live && *auth == A && !m.initialized && m.phase == PH_NONE && m.states == 2,
            Op::BeginInit { auth, len } => {
                live && *auth == A && !m.initialized && m.states > 0 && m.phase == PH_NONE && *len == p.state_bytes() && (!p.ws || m.res_received)
            }
            Op::RunInit { auth, at } => {
                p.ws && live && *auth == A && !m.initialized && m.phase == PH_INIT && m.ph_state == m.cursor && *at == m.ph_at && p.resource[0] != 0xEE && p.state_len <= 8_192 && !self.res_writable
            }
            Op::ResourceGrow { payer, auth, next } => {
                let len = p.resource.len() as u32;
                p.ws && live && m.phase == PH_NONE && !m.initialized && *auth == A && *payer != A && m.resource && *next == (m.res_alloc + v3::CHILD_GROW_BYTES).min(len) && *next > m.res_alloc
            }
            Op::ResourceChunk { auth, bad } => {
                p.ws && live && m.phase == PH_NONE && !m.initialized && *auth == A && m.resource && !m.res_received && m.res_alloc >= p.resource.len() as u32 && !bad
            }
            Op::CreateView { auth, signed, role, bad_abi, .. } => {
                live && *auth == A && *signed && m.initialized && m.states > 0 && m.stream && !m.views.contains_key(role) && !bad_abi && p.view_roles().contains(role)
            }
            Op::CreateWorkspace { auth, len, .. } => live && *auth == A && m.initialized && m.workspace.is_none() && (1..=64).contains(len),
            Op::CreateScratch { auth, len, .. } => live && *auth == A && m.initialized && m.states > 0 && !m.views.is_empty() && m.scratch.is_none() && *len > 0,
            Op::GrowView { .. } => false,
            Op::Write { actor, seq, bytes } => {
                if !(live && *actor == self.writer() && m.stream && bytes.len() == p.width as usize) {
                    return false;
                }
                let seq = *seq;
                if seq < m.cursor || seq >= m.capacity || seq - m.cursor >= v3::MAX_STREAM_WINDOW {
                    return false;
                }
                let next = if p.append {
                    if seq != m.frontier {
                        return false;
                    }
                    seq + 1
                } else {
                    m.frontier.max(seq + 1)
                };
                next - m.cursor <= v3::MAX_STREAM_WINDOW && m.slots[seq as usize].is_none()
            }
            Op::Advance { actor, cursor, steps } => {
                let end = m.cursor + *steps as u32;
                live && *actor == A
                    && m.phase == PH_NONE
                    && m.mask == 0
                    && *cursor == m.cursor
                    && *steps >= 1
                    && *steps <= p.max_steps
                    && m.stream
                    && m.states > 0
                    && end <= m.capacity
                    && end <= m.frontier
                    && m.initialized
                    && (m.cursor..end).all(|i| m.slots[i as usize].is_some())
                    && self.kernel_advance(m, *steps).is_some()
            }
            Op::Begin { actor, cursor } => {
                live && *actor == A
                    && m.phase == PH_NONE
                    && m.lanes == 0
                    && *cursor == m.cursor
                    && !m.views.is_empty()
                    && m.workspace.is_some_and(|len| len >= 64)
                    && m.scratch.is_some_and(|len| len >= m.view_total())
                    && m.states > 0
                    && m.initialized
                    && m.views.values().all(|v| v.stamp == NO_STAMP || v.stamp <= m.cursor)
            }
            Op::Run { actor, at, phases } => {
                if !(live && *actor == A && m.phase == PH_VIEW && m.cursor == m.ph_state && *at == m.ph_at && m.ph_at < m.ph_total) {
                    return false;
                }
                // The lane counter cannot render a non-lane view (its workspace
                // is non-empty). The fixed engine renders only the first 16
                // bytes at the SBF fixed input address and refuses later phases.
                let runs = (phases.unwrap_or(1) as u32).min((m.ph_total - m.ph_at).div_ceil(16));
                p.ws && self.cfg.sbf && p.state_len == 1_280 && *at == 0 && runs == 1 && !self.res_writable
            }
            Op::Commit { actor, cursor, staged } => {
                live && *actor == A && m.phase == PH_VIEW && m.cursor == m.ph_state && *cursor == m.ph_state && *staged == m.ph_at && m.ph_at == m.ph_total
            }
            Op::Abort { actor, cursor } => live && *actor == A && m.phase == PH_VIEW && *cursor == m.ph_state,
            Op::LaneCreate { payer, auth, k, ws_len, sc_len } => {
                *k < 4 && *payer != A && *auth == A && live && *k < m.lanes && m.initialized && (16..=64).contains(ws_len) && *sc_len > 0 && m.lane[*k as usize].is_none() && !m.lane_ws[*k as usize] && !m.lane_sc[*k as usize]
            }
            Op::LaneGrow { .. } => false,
            Op::CapBegin { actor, k, c } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && m.open && *k < m.lanes && m.active && m.phase == PH_NONE && m.initialized && l.status == L_IDLE && m.cursor == *c && *c + 1 > m.last_captured && !m.views.is_empty()
            }
            Op::CapRun { actor, k, c, at, .. } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && m.open && *k < m.lanes && m.active && l.status == L_CAP && l.captured == *c && m.cursor == *c && m.mask & (1 << k) != 0 && *at == l.cap_at && l.cap_at < 16 && m.lane_ws[*k as usize] && l.ws_len >= 16
            }
            Op::CapEnd { actor, k, c } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && m.open && *k < m.lanes && l.status == L_CAP && m.active && l.captured == *c && l.cap_at == 16 && m.mask & (1 << k) != 0
            }
            Op::Render { actor, k, c, at, .. } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && l.status == L_REN && l.captured == *c && *at == l.ren_at && l.ren_at < l.ren_total && m.lane_ws[*k as usize] && m.lane_sc[*k as usize] && l.sc_len >= l.ren_total
            }
            Op::LaneCommit { actor, k, c } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && m.open && *k < m.lanes && l.status == L_REN && m.active && l.captured == *c && l.ren_at == l.ren_total && m.lane_sc[*k as usize]
                    && m.views.len() == l.views.len()
                    && l.views.iter().all(|(role, offset, len)| m.views.get(role).is_some_and(|v| v.offset == *offset && v.len == *len && (v.stamp == NO_STAMP || v.stamp < *c)))
            }
            Op::LaneAbort { actor, k, c } => {
                let Some(l) = (*k < 4).then(|| m.lane[*k as usize].as_ref()).flatten() else { return false };
                *actor == A && m.open && *k < m.lanes && l.status != L_IDLE && l.captured == *c
            }
            Op::Halt { actor, cursor } => live && *actor == A && *cursor == m.cursor && self.cfg.plant != 2,
            Op::AnchorOne { actor, cursor } => {
                live && *actor == A && m.phase == PH_NONE && m.initialized && *cursor == m.cursor && m.anchor_cursor <= *cursor && p.state_bytes() <= v3::ANCHOR_CHUNK_BYTES && m.stream && m.states > 0
            }
            Op::AnchorBegin { payer, auth, cursor } => {
                live && *payer != A && *auth == A && m.phase == PH_NONE && m.initialized && *cursor == m.cursor && m.anchor_cursor <= *cursor && m.stream && m.states > 0 && m.anchor.as_ref().is_none_or(|a| !a.open)
            }
            Op::AnchorChunk { auth, cursor, offset } => {
                let Some(a) = &m.anchor else { return false };
                live && *auth == A && m.phase == PH_ANCHOR && *cursor == m.ph_state && m.cursor == *cursor && *offset == m.ph_at && a.open && a.progress == *offset && a.progress < a.total && m.stream
            }
            Op::AnchorFinish { auth, cursor } => {
                let Some(a) = &m.anchor else { return false };
                live && *auth == A && m.phase == PH_ANCHOR && m.cursor == *cursor && m.ph_state == *cursor && m.ph_at == m.ph_total && a.open && a.progress == a.total
            }
            Op::AnchorAbort { auth, cursor } => {
                let Some(a) = &m.anchor else { return false };
                live && *auth == A && m.phase == PH_ANCHOR && *cursor == m.ph_state && a.open && a.progress == m.ph_at
            }
            Op::Close { child, kind, refund } => {
                // Finding F1 (observed, 10-05): `close_account` checks the kind
                // byte against the target's byte 6, which for the anchor is its
                // open flag and for the headerless primary is application state;
                // `close_child` then closes either by address. A wrong kind equal
                // to that byte (and not 0, the session path) is accepted.
                let byte6 = match child {
                    Child::Anchor => m.anchor.as_ref().map_or(0, |a| u8::from(a.open)),
                    Child::State(0) if p.ws => {
                        if m.initialized { self.state_at(m, m.cursor)[6] } else { 0 }
                    }
                    _ => child.kind(),
                };
                let kind_ok = *kind == child.kind() || (*kind != v3::KIND_SESSION && *kind == byte6);
                m.open && !m.active && *refund == A && m.has(*child) && kind_ok && match child {
                    Child::State(i) => *i + 1 == m.states,
                    _ => true,
                }
            }
            Op::CloseSession { refund } => m.open && !m.active && *refund == A && m.children().is_empty() && m.phase == PH_NONE,
            Op::Prefund { .. } => true,
        }
    }

    // -------------------------------------------------------- apply ----

    fn apply(&self, m: &mut M, op: &Op) {
        let p = &self.p;
        match op {
            Op::Open { lanes, .. } => {
                *m = M {
                    open: true,
                    active: true,
                    lanes: lanes.unwrap_or(0),
                    capacity: p.capacity,
                    resource: p.ws,
                    res_alloc: if p.ws { (p.resource.len() as u32).min(v3::CHILD_GROW_BYTES) } else { 0 },
                    ..M::default()
                };
            }
            Op::CreateStream { .. } => {
                m.stream = true;
                m.slots = vec![None; m.capacity as usize];
            }
            Op::GrowStream { cap, .. } => {
                m.capacity = *cap;
                m.slots.resize(*cap as usize, None);
            }
            Op::CreateState { .. } => {
                m.states = p.span_count();
                m.state_alloc = p.state_bytes().min(v3::CHILD_GROW_BYTES);
                m.initialized = false;
            }
            Op::GrowState { .. } => m.state_alloc = (m.state_alloc + v3::CHILD_GROW_BYTES).min(p.state_len),
            Op::InitOneCall { .. } => m.initialized = true,
            Op::BeginInit { .. } => {
                m.phase = PH_INIT;
                m.ph_state = m.cursor;
                m.ph_at = 0;
                m.ph_total = p.state_bytes();
            }
            Op::RunInit { .. } => {
                m.ph_at = (m.ph_at + 65_536).min(m.ph_total);
                if m.ph_at == m.ph_total {
                    m.initialized = true;
                    m.clear_phase();
                }
            }
            Op::ResourceGrow { next, .. } => m.res_alloc = *next,
            Op::ResourceChunk { .. } => m.res_received = true,
            Op::CreateView { role, .. } => {
                let (_, offset, len) = p.view_def(*role);
                m.views.insert(*role, ViewM { offset, len, stamp: NO_STAMP, content: vec![0; len as usize] });
            }
            Op::CreateWorkspace { len, .. } => m.workspace = Some(*len),
            Op::CreateScratch { len, .. } => m.scratch = Some(*len),
            Op::Write { seq, bytes, .. } => {
                m.slots[*seq as usize] = Some(bytes.clone());
                m.frontier = if p.append { seq + 1 } else { m.frontier.max(seq + 1) };
            }
            Op::Advance { steps, .. } => {
                let (cursor, halt) = self.kernel_advance(m, *steps).unwrap();
                m.last_start = m.cursor;
                m.cursor = cursor;
                if let Some(reason) = halt {
                    m.active = false;
                    m.halt_reason = reason;
                    m.halt_cursor = cursor;
                }
            }
            Op::Begin { cursor, .. } => {
                m.phase = PH_VIEW;
                m.ph_state = *cursor;
                m.ph_at = 0;
                m.ph_total = m.view_total();
            }
            Op::Run { phases, .. } => {
                m.ph_at = (m.ph_at + 16 * phases.unwrap_or(1) as u32).min(m.ph_total);
            }
            Op::Commit { .. } => {
                let stamp = m.ph_state;
                for v in m.views.values_mut() {
                    v.content = p.resource[..v.len as usize].to_vec();
                    v.stamp = stamp;
                }
                m.newest_stamp = Some(stamp);
                m.clear_phase();
            }
            Op::Abort { .. } => m.clear_phase(),
            Op::LaneCreate { k, ws_len, sc_len, .. } => {
                let k = *k as usize;
                m.lane[k] = Some(LaneM { ws_len: *ws_len, sc_len: *sc_len, ..LaneM::default() });
                m.lane_ws[k] = true;
                m.lane_sc[k] = true;
            }
            Op::CapBegin { k, c, .. } => {
                m.mask |= 1 << k;
                m.last_captured = c + 1;
                let views: Vec<(u8, u32, u32)> = m.views.iter().map(|(role, v)| (*role, v.offset, v.len)).collect();
                let total = views.iter().map(|v| v.2).sum();
                let l = m.lane[*k as usize].as_mut().unwrap();
                l.status = L_CAP;
                l.captured = *c;
                l.cap_at = 0;
                l.ren_at = 0;
                l.ren_total = total;
                l.views = views;
            }
            Op::CapRun { k, at, phases, .. } => {
                let l = m.lane[*k as usize].as_mut().unwrap();
                l.cap_at = (at + 8 * phases.unwrap_or(1) as u32).min(16);
            }
            Op::CapEnd { k, .. } => {
                m.mask &= !(1 << k);
                m.lane[*k as usize].as_mut().unwrap().status = L_REN;
            }
            Op::Render { k, at, phases, .. } => {
                let l = m.lane[*k as usize].as_mut().unwrap();
                l.ren_at = (at + 6 * phases.unwrap_or(1) as u32).min(l.ren_total);
            }
            Op::LaneCommit { k, c, .. } => {
                let state = self.state_at(m, *c);
                let l = m.lane[*k as usize].take().unwrap();
                for (role, offset, len) in &l.views {
                    let v = m.views.get_mut(role).unwrap();
                    v.content = state[*offset as usize..(*offset + *len) as usize].to_vec();
                    v.stamp = *c;
                }
                m.newest_stamp = Some(*c);
                m.lane[*k as usize] = Some(LaneM { ws_len: l.ws_len, sc_len: l.sc_len, ..LaneM::default() });
            }
            Op::LaneAbort { k, .. } => {
                m.mask &= !(1 << k);
                let l = m.lane[*k as usize].take().unwrap();
                m.lane[*k as usize] = Some(LaneM { ws_len: l.ws_len, sc_len: l.sc_len, ..LaneM::default() });
            }
            Op::Halt { cursor, .. } => {
                m.active = false;
                m.halt_reason = 0;
                m.halt_cursor = *cursor;
                m.mask = 0;
                m.clear_phase();
            }
            Op::AnchorOne { cursor, .. } => {
                let (sid, sver) = self.schema_parts();
                let state = self.state_at(m, m.cursor);
                m.state_anchor = sha256(&[b"dcg/state-anchor-one-shot/3", &p.kernel_id(), &sid, &sver, &cursor.to_le_bytes(), &self.input_root(m), &state]);
                m.anchor_cursor = *cursor;
            }
            Op::AnchorBegin { cursor, .. } => {
                let (sid, sver) = self.schema_parts();
                let input_root = self.input_root(m);
                let total = p.state_bytes();
                let acc = sha256(&[b"dcg/state-anchor-init/3", &m.state_anchor, &input_root, &p.kernel_id(), &sid, &sver, &cursor.to_le_bytes(), &total.to_le_bytes()]);
                m.anchor = Some(AnchorM { open: true, cursor: *cursor, total, progress: 0, input_root, acc });
                m.phase = PH_ANCHOR;
                m.ph_state = *cursor;
                m.ph_at = 0;
                m.ph_total = total;
            }
            Op::AnchorChunk { offset, .. } => {
                let state = self.state_at(m, m.cursor);
                let a = m.anchor.as_mut().unwrap();
                let end = (a.total - offset).min(v3::ANCHOR_CHUNK_BYTES) + offset;
                a.acc = sha256(&[b"dcg/state-anchor-chunk/3", &a.acc, &offset.to_le_bytes(), &state[*offset as usize..end as usize]]);
                a.progress = end;
                m.ph_at = end;
            }
            Op::AnchorFinish { cursor, .. } => {
                let (sid, sver) = self.schema_parts();
                let a = m.anchor.as_mut().unwrap();
                m.state_anchor = sha256(&[b"dcg/state-anchor-chunked/3", &a.acc, &a.input_root, &p.kernel_id(), &sid, &sver, &cursor.to_le_bytes(), &a.total.to_le_bytes()]);
                a.open = false;
                m.anchor_cursor = *cursor;
                m.clear_phase();
            }
            Op::AnchorAbort { .. } => {
                m.anchor.as_mut().unwrap().open = false;
                m.clear_phase();
            }
            Op::Close { child, .. } => match child {
                Child::Stream => m.stream = false,
                Child::State(_) => m.states -= 1,
                Child::View(role) => {
                    m.views.remove(role);
                }
                Child::Workspace => m.workspace = None,
                Child::Scratch => m.scratch = None,
                Child::Resource => m.resource = false,
                Child::Anchor => m.anchor = None,
                Child::Lane(k) => m.lane[*k as usize] = None,
                Child::LaneWs(k) => m.lane_ws[*k as usize] = false,
                Child::LaneScratch(k) => m.lane_sc[*k as usize] = false,
            },
            Op::CloseSession { .. } => *m = M::default(),
            Op::GrowView { .. } | Op::LaneGrow { .. } | Op::Prefund { .. } => {}
        }
    }

    // ------------------------------------------------------- execute ----

    async fn snapshot(&mut self) -> Snap {
        let mut out = Vec::with_capacity(self.keys_tracked.len());
        for key in self.keys_tracked.clone() {
            out.push(self.ctx.banks_client.get_account(key).await.unwrap());
        }
        out
    }

    async fn send(&mut self, ixs: Vec<Instruction>, cu: Option<u32>) -> (Outcome, u64) {
        self.nonce += 1;
        // A per-transaction compute limit keeps resends distinct (no new
        // blockhash wait); a low one injects a budget failure.
        let limit = cu.unwrap_or(1_400_000 - self.nonce % 100_000);
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(limit)];
        all.extend(ixs);
        let payer = self.ctx.payer.pubkey();
        let blockhash = self.ctx.banks_client.get_latest_blockhash().await.unwrap();
        let message = solana_message::Message::new_with_blockhash(&all, Some(&payer), &blockhash);
        let mut signers: Vec<&Keypair> = vec![&self.ctx.payer];
        for (i, key) in message.account_keys.iter().enumerate() {
            if message.is_signer(i) && *key != payer {
                let kp = self.k.actors.iter().find(|a| a.pubkey() == *key).expect("signer is an actor");
                if !signers.iter().any(|s| s.pubkey() == *key) {
                    signers.push(kp);
                }
            }
        }
        let fee = self.ctx.banks_client.get_fee_for_message(message.clone()).await.unwrap().expect("fee");
        let tx = Transaction::new(&signers, message, blockhash);
        let res = self.ctx.banks_client.process_transaction_with_metadata(tx).await;
        self.last_logs = res.as_ref().ok().and_then(|m| m.metadata.as_ref()).map(|m| m.log_messages.join("\n")).unwrap_or_default();
        let outcome = match res {
            Ok(meta) => match meta.result {
                Ok(()) => Outcome::Ok,
                Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => Outcome::Custom(code),
                Err(TransactionError::InstructionError(_, e)) => Outcome::Other(format!("{e:?}")),
                Err(e) => Outcome::NotRun(format!("{e:?}")),
            },
            Err(e) => Outcome::NotRun(format!("{e:?}")),
        };
        (outcome, fee)
    }

    /// Run one transaction of `ops`, predict and check it. `must`: a
    /// refusal is an oracle failure.
    async fn step(&mut self, ops: Vec<Op>, cu: Option<u32>, label: &str, must: bool) -> bool {
        // Each instruction's account list (views, lanes) follows the state its
        // predecessors in the same transaction leave.
        let saved = self.m.clone();
        let mut ixs: Vec<Instruction> = Vec::new();
        for op in &ops {
            ixs.extend(self.build(op));
            if self.valid(&self.m, op) {
                let mut next = self.m.clone();
                self.apply(&mut next, op);
                self.m = next;
            }
        }
        self.m = saved;
        // A signature is per transaction: an account meta marked unsigned is
        // still a signer if its key signs anywhere in the message.
        let mut signing: Vec<Pubkey> = ixs.iter().flat_map(|i| i.accounts.iter().filter(|a| a.is_signer).map(|a| a.pubkey)).collect();
        signing.push(self.ctx.payer.pubkey());
        // Writability is per transaction too: the fixed engine refuses a
        // resource copy that any instruction in the message marks writable.
        self.res_writable = ixs.iter().any(|i| i.accounts.iter().any(|a| a.pubkey == self.k.resource && a.is_writable));
        let mut sim = self.m.clone();
        let mut predicted = true;
        for op in &ops {
            let op = self.effective(op, &signing);
            if !self.valid(&sim, &op) {
                predicted = false;
                break;
            }
            self.apply(&mut sim, &op);
        }
        self.res_writable = false;
        let before = self.snapshot().await;
        let (outcome, fee) = self.send(ixs, cu).await;
        let after = self.snapshot().await;
        self.stats.txs += 1;
        self.stats.checks += 1;
        let names: Vec<&str> = ops.iter().map(Op::name).collect();
        let line = format!("[{label}] {:?} => {:?} (predicted {})", ops, outcome, if predicted { "ok" } else { "refuse" });
        if self.cfg.verbose {
            eprintln!("{} {}", self.tag, line);
        }
        self.log.push(line);
        let accepted = outcome == Outcome::Ok;
        for (i, name) in names.iter().enumerate() {
            let e = self.stats.ops.entry(name).or_default();
            let _ = i;
            if accepted {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        }
        // Lamports: the tracked set loses exactly the fee (or nothing if the
        // transaction did not run).
        let total = |s: &Snap| -> u128 { s.iter().flatten().map(|a| a.lamports as u128).sum() };
        let charged = if matches!(outcome, Outcome::NotRun(_)) { 0 } else { fee as u128 };
        if total(&before) != total(&after) + charged {
            fail!(self, "lamport conservation: before {} after {} fee {}", total(&before), total(&after), charged);
        }
        match &outcome {
            Outcome::Ok => {
                self.stats.accepted += 1;
                if !predicted {
                    fail!(self, "unexpected acceptance of {:?}", names);
                }
                self.m = sim;
            }
            _ => {
                if matches!(outcome, Outcome::NotRun(_)) {
                    self.stats.not_run += 1;
                } else {
                    self.stats.refused += 1;
                }
                // Every refused transaction leaves every account byte-identical
                // (the fee payer loses only the fee).
                for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
                    let key = self.keys_tracked[i];
                    if key == self.ctx.payer.pubkey() {
                        let (b, a) = (b.as_ref().unwrap(), a.as_ref().unwrap());
                        if b.data != a.data || b.lamports != a.lamports + charged as u64 {
                            fail!(self, "refused transaction changed the fee payer beyond the fee");
                        }
                    } else if b != a {
                        fail!(self, "refused transaction ({outcome:?}) changed account {key}");
                    }
                }
                let budget = cu.is_some()
                    && matches!(&outcome, Outcome::Other(e) if e.contains("ComputationalBudgetExceeded") || (e.contains("ProgramFailedToComplete") && self.last_logs.contains("exceeded CUs meter")));
                if budget {
                    self.stats.cu_failures += 1;
                }
                if predicted && !budget {
                    fail!(self, "unexpected refusal {outcome:?} of {:?}", names);
                }
                if must {
                    fail!(self, "oracle step refused: {outcome:?}");
                }
            }
        }
        self.check(&after);
        accepted
    }

    fn effective(&self, op: &Op, signing: &[Pubkey]) -> Op {
        let signs = |a: &Actor| signing.contains(&self.actor_key(*a));
        match op.clone() {
            Op::CreateStream { payer, auth, signed } => Op::CreateStream { payer, auth, signed: signed || signs(&auth) },
            Op::CreateState { payer, auth, signed } => Op::CreateState { payer, auth, signed: signed || signs(&auth) },
            Op::CreateView { payer, auth, signed, role, bad_abi } => Op::CreateView { payer, auth, signed: signed || signs(&auth), role, bad_abi },
            other => other,
        }
    }

    fn halt_stat(&mut self, what: String) {
        *self.stats.halts.entry(what).or_default() += 1;
    }

    // --------------------------------------------------------- check ----

    fn check(&mut self, snap: &Snap) {
        let get = |key: Pubkey| -> Option<&Account> {
            let i = self.keys_tracked.iter().position(|k| *k == key).unwrap();
            snap[i].as_ref().filter(|a| a.owner == PROGRAM)
        };
        let m = self.m.clone();
        // Child count equals live children; children exist only as modelled.
        let mut live = 0u16;
        for (child, key) in self.k.derived() {
            let Some(child) = child else { continue };
            let exists = get(key).is_some();
            if exists != m.has(child) {
                fail!(self, "child {child:?} exists={exists}, model {}", m.has(child));
            }
            live += u16::from(exists);
        }
        let Some(sess) = get(self.k.session) else {
            if m.open {
                fail!(self, "session missing");
            }
            return;
        };
        if !m.open {
            fail!(self, "session exists but the model has it closed");
        }
        let d = &sess.data;
        let cursor = u32_at(d, 112);
        let frontier = u32_at(d, 116);
        let capacity = u32_at(d, 10);
        // Counters and window.
        if !(cursor <= frontier && frontier <= capacity && frontier - cursor <= v3::MAX_STREAM_WINDOW) {
            fail!(self, "counters: cursor {cursor} frontier {frontier} capacity {capacity}");
        }
        if u16_at(d, 120) != live {
            fail!(self, "child count {} != live children {live}", u16_at(d, 120));
        }
        let want_status = if m.active { 1 } else { 2 };
        let checks: [(&str, u64, u64); 16] = [
            ("status", d[6] as u64, want_status),
            ("cursor", cursor as u64, m.cursor as u64),
            ("frontier", frontier as u64, m.frontier as u64),
            ("capacity", capacity as u64, m.capacity as u64),
            ("span count", d[122] as u64, m.states as u64),
            ("view count", d[123] as u64, m.views.len() as u64),
            ("initialized", d[1182] as u64, m.initialized as u64),
            ("phase", d[1164] as u64, m.phase as u64),
            ("phase state cursor", u32_at(d, 1166) as u64, m.ph_state as u64),
            ("phase cursor", u32_at(d, 1170) as u64, m.ph_at as u64),
            ("phase total", u32_at(d, 1174) as u64, m.ph_total as u64),
            ("halt reason", u32_at(d, 1254) as u64, m.halt_reason as u64),
            ("halt cursor", u32_at(d, 1258) as u64, if m.active { 0 } else { m.halt_cursor as u64 }),
            ("lanes", d[1267] as u64, m.lanes as u64),
            ("capture mask", d[1268] as u64, m.mask as u64),
            ("last captured", u32_at(d, 1269) as u64, m.last_captured as u64),
        ];
        for (name, got, want) in checks {
            if got != want {
                fail!(self, "session {name}: program {got}, model {want}");
            }
        }
        if u32_at(d, 188) != m.anchor_cursor || d[192..224] != m.state_anchor {
            fail!(self, "state anchor or anchor cursor differs from the host hash");
        }
        if u32_at(d, 1263) != m.last_start {
            fail!(self, "last advance start");
        }
        // The input root is the host hash chain of the consumed inputs.
        if d[156..188] != self.input_root(&m) {
            fail!(self, "input root differs from the host chain over {} consumed inputs", m.cursor);
        }
        // Capture bits match the capturing lanes (cleared by halt).
        let mut capturing = 0u8;
        let mut captured_cursors = Vec::new();
        for k in 0..4usize {
            let Some(lane) = get(self.k.lanes[k]) else { continue };
            let l = &lane.data;
            let ml = m.lane[k].as_ref().unwrap();
            let fields = [(l[72] as u32, ml.status as u32), (u32_at(l, 76), ml.captured), (u32_at(l, 80), ml.cap_at), (u32_at(l, 88), ml.ren_at), (u32_at(l, 92), ml.ren_total)];
            if fields.iter().any(|(a, b)| a != b) {
                fail!(self, "lane {k} record {fields:?} (program, model)");
            }
            if l[72] == L_CAP {
                capturing |= 1 << k;
            }
            if l[72] != L_IDLE {
                captured_cursors.push(u32_at(l, 76));
            }
        }
        let mask = d[1268];
        if (m.active && mask != capturing) || (!m.active && mask != 0) {
            fail!(self, "capture mask {mask:#b} vs capturing lanes {capturing:#b} (active {})", m.active);
        }
        // Captured cursors are distinct and below the newest capture.
        let mut sorted = captured_cursors.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != captured_cursors.len() || captured_cursors.iter().any(|c| c + 1 > u32_at(d, 1269)) {
            fail!(self, "captured cursors {captured_cursors:?} last {}", u32_at(d, 1269));
        }
        // The stream header mirrors the session; written slots never change.
        if let Some(stream) = get(self.k.stream) {
            let s = &stream.data;
            let writer = self.actor_key(self.writer());
            if s.len() != 128 + 16 * capacity as usize
                || s[6] != v3::KIND_STREAM
                || s[40..72] != self.p.root
                || u32_at(s, 72) != capacity
                || u32_at(s, 76) != cursor
                || u32_at(s, 80) != frontier
                || s[88..120] != writer.to_bytes()
            {
                fail!(self, "stream header does not mirror the session");
            }
            for (seq, slot) in m.slots.iter().enumerate() {
                let raw = &s[128 + 16 * seq..128 + 16 * seq + 16];
                let mut want = [0u8; 16];
                if let Some(bytes) = slot {
                    want[..4].copy_from_slice(&(seq as u32).to_le_bytes());
                    want[4] = 1;
                    want[8..8 + bytes.len()].copy_from_slice(bytes);
                }
                if raw != want {
                    fail!(self, "stream slot {seq} {raw:?} != host {want:?}");
                }
            }
        }
        // State equals the host replay of the test kernel.
        if m.states == self.p.span_count() {
            let want = self.state_at(&m, m.cursor);
            let want = if self.p.ws { want[..m.state_alloc as usize].to_vec() } else { want };
            let got: Vec<u8> = if self.p.ws {
                get(self.k.states[0]).unwrap().data.clone()
            } else {
                let mut g = Vec::new();
                for i in 0..2 {
                    let a = &get(self.k.states[i]).unwrap().data;
                    if u32_at(a, 88) != m.last_start || u32_at(a, 92) != m.cursor {
                        fail!(self, "state span {i} before/after cursors");
                    }
                    g.extend_from_slice(&a[128..136]);
                }
                g
            };
            if got != want {
                fail!(self, "state digest {} != host {}", hex(&sha256(&[&got])), hex(&sha256(&[&want])));
            }
        }
        // Views: stamps equal across published views, monotone, and the
        // content equals the host render at the stamp.
        let mut stamps = Vec::new();
        for (role, vm) in &m.views {
            let v = &get(self.k.view(*role)).unwrap().data;
            let stamp = u32_at(v, 112);
            if stamp != vm.stamp || v[128..128 + vm.len as usize] != vm.content[..] {
                fail!(self, "view {role} stamp {stamp} (model {}) or content differs", vm.stamp);
            }
            if stamp != NO_STAMP {
                stamps.push(stamp);
                if stamp > cursor {
                    fail!(self, "view stamp {stamp} ahead of cursor {cursor}");
                }
            }
        }
        if stamps.windows(2).any(|p| p[0] != p[1]) {
            fail!(self, "published view stamps differ: {stamps:?}");
        }
        if let Some(anchor) = (&m.anchor).as_ref() {
            let a = &get(self.k.anchor).unwrap().data;
            if (a[6] == 1) != anchor.open || u32_at(a, 40) != anchor.cursor || u32_at(a, 48) != anchor.progress || a[84..116] != anchor.acc {
                fail!(self, "anchor account differs from the host accumulator");
            }
        }
        self.stats.max_cursor = self.stats.max_cursor.max(cursor);
    }

    // ----------------------------------------------------- generator ----

    fn rand_actor(&mut self) -> Actor {
        self.rng.pick(&ACTORS)
    }
    fn fund_actor(&mut self) -> Actor {
        // Any funded payer; the authority some of the time.
        self.rng.pick(&[Actor::Payer, Actor::Payer, Actor::Authority, Actor::Bystander, Actor::Prefunder])
    }

    /// The canonical (most likely valid) op of kind `kind`.
    fn canonical(&mut self, kind: u32) -> Option<Op> {
        use Actor::Authority as A;
        let m = self.m.clone();
        let p = self.p.clone();
        let lane_k = |rng: &mut Rng, pred: &dyn Fn(&LaneM) -> bool| -> Option<u8> {
            let ks: Vec<u8> = (0..4u8).filter(|k| m.lane[*k as usize].as_ref().is_some_and(pred)).collect();
            (!ks.is_empty()).then(|| rng.pick(&ks))
        };
        let payer = self.fund_actor();
        let nonauth_payer = self.rng.pick(&[Actor::Payer, Actor::Bystander, Actor::Prefunder]);
        Some(match kind {
            0 => Op::Open { payer: nonauth_payer, auth: A, lanes: (p.lanes > 0).then_some(p.lanes) },
            1 => Op::CreateStream { payer, auth: A, signed: true },
            2 => Op::GrowStream { payer, cap: m.capacity + self.rng.range(1, 6) },
            3 => Op::CreateState { payer, auth: A, signed: true },
            4 => {
                if p.ws {
                    if m.phase == PH_INIT {
                        Op::RunInit { auth: A, at: m.ph_at }
                    } else {
                        Op::BeginInit { auth: A, len: p.state_bytes() }
                    }
                } else if self.rng.pct(3) {
                    Op::BeginInit { auth: A, len: p.state_bytes() } // wedges the one-call kernel until halt
                } else {
                    Op::InitOneCall { auth: A }
                }
            }
            5 => {
                if !p.ws {
                    return None;
                }
                if m.res_alloc < p.resource.len() as u32 {
                    Op::ResourceGrow { payer: nonauth_payer, auth: A, next: (m.res_alloc + v3::CHILD_GROW_BYTES).min(p.resource.len() as u32) }
                } else {
                    Op::ResourceChunk { auth: A, bad: self.rng.pct(10) }
                }
            }
            6 => {
                let roles: Vec<u8> = p.view_roles().into_iter().filter(|r| !m.views.contains_key(r)).collect();
                let role = if roles.is_empty() { self.rng.pick(&p.view_roles()) } else { self.rng.pick(&roles) };
                Op::CreateView { payer, auth: A, signed: true, role, bad_abi: false }
            }
            7 => Op::CreateWorkspace { payer, auth: A, len: 64 },
            8 => Op::CreateScratch { payer, auth: A, len: if p.ws { 32 } else { 16 } },
            9 => {
                let seq = if p.append || self.rng.pct(50) {
                    m.frontier
                } else {
                    let hi = m.capacity.min(m.cursor + v3::MAX_STREAM_WINDOW);
                    if hi <= m.cursor { m.cursor } else { self.rng.range(m.cursor, hi - 1) }
                };
                let bytes = if p.ws {
                    vec![match self.rng.below(100) {
                        0..=3 => 0xEE,
                        4..=7 => 0xEF,
                        8..=11 => 0xED,
                        _ => self.rng.range(0, 0x40) as u8,
                    }]
                } else {
                    (0..p.width).map(|_| self.rng.next() as u8).collect()
                };
                Op::Write { actor: self.writer(), seq, bytes }
            }
            10 => {
                let mut ready = 0u32;
                while m.cursor + ready < m.frontier && m.slots.get((m.cursor + ready) as usize).is_some_and(|s| s.is_some()) {
                    ready += 1;
                }
                let steps = self.rng.range(1, ready.clamp(1, p.max_steps as u32)) as u8;
                Op::Advance { actor: A, cursor: m.cursor, steps }
            }
            11 => match m.phase {
                PH_VIEW if m.ph_at < m.ph_total && self.rng.pct(60) => Op::Run { actor: A, at: m.ph_at, phases: if self.rng.pct(50) { None } else { Some(self.rng.range(1, 3) as u8) } },
                PH_VIEW if m.ph_at == m.ph_total && self.rng.pct(70) => Op::Commit { actor: A, cursor: m.ph_state, staged: m.ph_at },
                PH_VIEW => Op::Abort { actor: A, cursor: m.ph_state },
                _ => Op::Begin { actor: A, cursor: m.cursor },
            },
            12 => {
                let free: Vec<u8> = (0..m.lanes).filter(|k| m.lane[*k as usize].is_none()).collect();
                let k = if free.is_empty() { self.rng.below(4) as u8 } else { self.rng.pick(&free) };
                Op::LaneCreate { payer: nonauth_payer, auth: A, k, ws_len: 64, sc_len: if self.rng.pct(10) { 8 } else { 16 } }
            }
            13 => {
                if let Some(k) = lane_k(&mut self.rng, &|l: &LaneM| l.status == L_CAP) {
                    let l = m.lane[k as usize].clone().unwrap();
                    if l.cap_at < 16 {
                        Op::CapRun { actor: A, k, c: l.captured, at: l.cap_at, phases: if self.rng.pct(50) { None } else { Some(self.rng.range(1, 2) as u8) } }
                    } else {
                        Op::CapEnd { actor: A, k, c: l.captured }
                    }
                } else {
                    let k = lane_k(&mut self.rng, &|l: &LaneM| l.status == L_IDLE)?;
                    Op::CapBegin { actor: A, k, c: m.cursor }
                }
            }
            14 => {
                let k = lane_k(&mut self.rng, &|l: &LaneM| l.status == L_REN)?;
                let l = m.lane[k as usize].clone().unwrap();
                if l.ren_at < l.ren_total {
                    Op::Render { actor: A, k, c: l.captured, at: l.ren_at, phases: if self.rng.pct(40) { None } else { Some(self.rng.range(1, 3) as u8) } }
                } else {
                    Op::LaneCommit { actor: A, k, c: l.captured }
                }
            }
            15 => {
                let k = lane_k(&mut self.rng, &|l: &LaneM| l.status != L_IDLE)?;
                Op::LaneAbort { actor: A, k, c: m.lane[k as usize].as_ref().unwrap().captured }
            }
            16 => Op::Halt { actor: A, cursor: m.cursor },
            17 => match (m.phase, m.anchor.as_ref()) {
                (PH_ANCHOR, Some(a)) if a.progress < a.total => Op::AnchorChunk { auth: A, cursor: m.ph_state, offset: m.ph_at },
                (PH_ANCHOR, _) if self.rng.pct(80) => Op::AnchorFinish { auth: A, cursor: m.ph_state },
                (PH_ANCHOR, _) => Op::AnchorAbort { auth: A, cursor: m.ph_state },
                _ if self.rng.pct(40) => Op::AnchorOne { actor: A, cursor: m.cursor },
                _ => Op::AnchorBegin { payer: nonauth_payer, auth: A, cursor: m.cursor },
            },
            18 => {
                let kids = m.children();
                if kids.is_empty() {
                    Op::CloseSession { refund: A }
                } else {
                    // Highest state first is required; other children in any order.
                    let child = self.rng.pick(&kids);
                    Op::Close { child, kind: child.kind(), refund: A }
                }
            }
            19 => {
                let derived = self.k.derived();
                let target = derived[self.rng.below(derived.len() as u64) as usize].1;
                let lamports = self.rent0 + self.rng.below(50_000);
                Op::Prefund { target, lamports }
            }
            20 => Op::GrowState { payer, index: if self.rng.pct(80) { 0 } else { 1 } },
            21 => {
                let role = self.rng.pick(&[WS_VIEW, VALUE, TOTAL, v3::WORKSPACE_ROLE, v3::SCRATCH_ROLE]);
                Op::GrowView { payer, role }
            }
            22 => Op::LaneGrow { payer, k: self.rng.below(4) as u8, scratch: self.rng.pct(50) },
            _ => return None,
        })
    }

    const KINDS: u32 = 23;

    /// Perturb one field of an op (wrong actor, off-by-one cursor or offset,
    /// another lane, a malformed variant).
    fn perturb(&mut self, op: Op) -> Op {
        let a = self.rand_actor();
        let d = |rng: &mut Rng, x: u32| -> u32 { if rng.pct(50) { x.wrapping_add(1) } else { x.wrapping_sub(1) } };
        let flip = self.rng.pct(50);
        match op {
            Op::Open { payer, auth, lanes } => match self.rng.below(3) {
                0 => Op::Open { payer: a, auth, lanes },
                1 => Op::Open { payer, auth: a, lanes },
                _ => Op::Open { payer, auth, lanes: Some(self.rng.pick(&[0u8, 1, 4, 5])) },
            },
            Op::CreateStream { payer, auth, signed } => if flip { Op::CreateStream { payer, auth: a, signed } } else { Op::CreateStream { payer, auth, signed: !signed } },
            Op::GrowStream { payer, cap } => Op::GrowStream { payer, cap: if flip { cap + v3::MAX_STREAM_GROWTH_SLOTS } else { cap.saturating_sub(self.rng.range(1, 3)) } },
            Op::CreateState { payer, auth, signed } => if flip { Op::CreateState { payer, auth: a, signed } } else { Op::CreateState { payer, auth, signed: !signed } },
            Op::InitOneCall { .. } => Op::InitOneCall { auth: a },
            Op::BeginInit { auth, len } => if flip { Op::BeginInit { auth: a, len } } else { Op::BeginInit { auth, len: len + 1 } },
            Op::RunInit { auth, at } => if flip { Op::RunInit { auth: a, at } } else { Op::RunInit { auth, at: d(&mut self.rng, at) } },
            Op::ResourceGrow { payer, auth, next } => match self.rng.below(3) {
                0 => Op::ResourceGrow { payer: a, auth, next },
                1 => Op::ResourceGrow { payer, auth: a, next },
                _ => Op::ResourceGrow { payer, auth, next: d(&mut self.rng, next) },
            },
            Op::ResourceChunk { auth, bad } => if flip { Op::ResourceChunk { auth: a, bad } } else { Op::ResourceChunk { auth, bad: !bad } },
            Op::CreateView { payer, auth, signed, role, bad_abi } => match self.rng.below(3) {
                0 => Op::CreateView { payer, auth: a, signed, role, bad_abi },
                1 => Op::CreateView { payer, auth, signed: !signed, role, bad_abi },
                _ => Op::CreateView { payer, auth, signed, role, bad_abi: !bad_abi },
            },
            Op::CreateWorkspace { payer, auth, len } => if flip { Op::CreateWorkspace { payer, auth: a, len } } else { Op::CreateWorkspace { payer, auth, len: len + 1 } },
            Op::CreateScratch { payer, auth, len } => if flip { Op::CreateScratch { payer, auth: a, len } } else { Op::CreateScratch { payer, auth, len: 0 } },
            Op::Write { actor, seq, bytes } => match self.rng.below(3) {
                0 => Op::Write { actor: a, seq, bytes },
                1 => Op::Write { actor, seq: if self.rng.pct(50) { d(&mut self.rng, seq) } else { seq + v3::MAX_STREAM_WINDOW }, bytes },
                _ => {
                    let mut b = bytes;
                    if b.len() > 1 || self.rng.pct(50) { b.pop(); } else { b.push(1); }
                    Op::Write { actor, seq, bytes: b }
                }
            },
            Op::Advance { actor, cursor, steps } => match self.rng.below(3) {
                0 => Op::Advance { actor: a, cursor, steps },
                1 => Op::Advance { actor, cursor: d(&mut self.rng, cursor), steps },
                _ => Op::Advance { actor, cursor, steps: if self.rng.pct(50) { steps.saturating_add(1) } else { self.rng.pick(&[0u8, 9]) } },
            },
            Op::Begin { actor, cursor } => if flip { Op::Begin { actor: a, cursor } } else { Op::Begin { actor, cursor: d(&mut self.rng, cursor) } },
            Op::Run { actor, at, phases } => if flip { Op::Run { actor: a, at, phases } } else { Op::Run { actor, at: d(&mut self.rng, at), phases } },
            Op::Commit { actor, cursor, staged } => match self.rng.below(3) {
                0 => Op::Commit { actor: a, cursor, staged },
                1 => Op::Commit { actor, cursor: d(&mut self.rng, cursor), staged },
                _ => Op::Commit { actor, cursor, staged: d(&mut self.rng, staged) },
            },
            Op::Abort { actor, cursor } => if flip { Op::Abort { actor: a, cursor } } else { Op::Abort { actor, cursor: d(&mut self.rng, cursor) } },
            Op::LaneCreate { payer, auth, k, ws_len, sc_len } => match self.rng.below(4) {
                0 => Op::LaneCreate { payer: a, auth, k, ws_len, sc_len },
                1 => Op::LaneCreate { payer, auth: a, k, ws_len, sc_len },
                2 => Op::LaneCreate { payer, auth, k: self.rng.below(5) as u8, ws_len, sc_len },
                _ => Op::LaneCreate { payer, auth, k, ws_len: self.rng.pick(&[8u32, 65]), sc_len },
            },
            Op::CapBegin { actor, k, c } => match self.rng.below(3) {
                0 => Op::CapBegin { actor: a, k, c },
                1 => Op::CapBegin { actor, k: self.rng.below(5) as u8, c },
                _ => Op::CapBegin { actor, k, c: d(&mut self.rng, c) },
            },
            Op::CapRun { actor, k, c, at, phases } => match self.rng.below(4) {
                0 => Op::CapRun { actor: a, k, c, at, phases },
                1 => Op::CapRun { actor, k: self.rng.below(4) as u8, c, at, phases },
                2 => Op::CapRun { actor, k, c: d(&mut self.rng, c), at, phases },
                _ => Op::CapRun { actor, k, c, at: d(&mut self.rng, at), phases },
            },
            Op::CapEnd { actor, k, c } => match self.rng.below(3) {
                0 => Op::CapEnd { actor: a, k, c },
                1 => Op::CapEnd { actor, k: self.rng.below(4) as u8, c },
                _ => Op::CapEnd { actor, k, c: d(&mut self.rng, c) },
            },
            Op::Render { actor, k, c, at, phases } => match self.rng.below(4) {
                0 => Op::Render { actor: a, k, c, at, phases },
                1 => Op::Render { actor, k: self.rng.below(4) as u8, c, at, phases },
                2 => Op::Render { actor, k, c: d(&mut self.rng, c), at, phases },
                _ => Op::Render { actor, k, c, at: d(&mut self.rng, at), phases },
            },
            Op::LaneCommit { actor, k, c } => match self.rng.below(3) {
                0 => Op::LaneCommit { actor: a, k, c },
                1 => Op::LaneCommit { actor, k: self.rng.below(4) as u8, c },
                _ => Op::LaneCommit { actor, k, c: d(&mut self.rng, c) },
            },
            Op::LaneAbort { actor, k, c } => match self.rng.below(3) {
                0 => Op::LaneAbort { actor: a, k, c },
                1 => Op::LaneAbort { actor, k: self.rng.below(4) as u8, c },
                _ => Op::LaneAbort { actor, k, c: d(&mut self.rng, c) },
            },
            Op::Halt { actor, cursor } => if flip { Op::Halt { actor: a, cursor } } else { Op::Halt { actor, cursor: d(&mut self.rng, cursor) } },
            Op::AnchorOne { actor, cursor } => if flip { Op::AnchorOne { actor: a, cursor } } else { Op::AnchorOne { actor, cursor: d(&mut self.rng, cursor) } },
            Op::AnchorBegin { payer, auth, cursor } => match self.rng.below(3) {
                0 => Op::AnchorBegin { payer: a, auth, cursor },
                1 => Op::AnchorBegin { payer, auth: a, cursor },
                _ => Op::AnchorBegin { payer, auth, cursor: d(&mut self.rng, cursor) },
            },
            Op::AnchorChunk { auth, cursor, offset } => match self.rng.below(3) {
                0 => Op::AnchorChunk { auth: a, cursor, offset },
                1 => Op::AnchorChunk { auth, cursor: d(&mut self.rng, cursor), offset },
                _ => Op::AnchorChunk { auth, cursor, offset: d(&mut self.rng, offset) },
            },
            Op::AnchorFinish { auth, cursor } => if flip { Op::AnchorFinish { auth: a, cursor } } else { Op::AnchorFinish { auth, cursor: d(&mut self.rng, cursor) } },
            Op::AnchorAbort { auth, cursor } => if flip { Op::AnchorAbort { auth: a, cursor } } else { Op::AnchorAbort { auth, cursor: d(&mut self.rng, cursor) } },
            Op::Close { child, kind, refund } => match self.rng.below(3) {
                0 => Op::Close { child, kind, refund: a },
                1 => Op::Close { child, kind: self.rng.range(1, 10) as u8, refund },
                _ => {
                    let derived = self.k.derived();
                    let other = derived[1 + self.rng.below(derived.len() as u64 - 1) as usize].0.unwrap();
                    Op::Close { child: other, kind: other.kind(), refund }
                }
            },
            Op::CloseSession { .. } => Op::CloseSession { refund: a },
            other => other,
        }
    }

    /// One op: mostly a valid next step, sometimes a perturbed or adversarial one.
    fn gen_op(&mut self, step: usize, len: usize) -> Op {
        let roll = self.rng.below(100);
        if roll < 72 {
            // Valid candidates, weighted toward progress; halts grow likelier late.
            let mut cands: Vec<(Op, u64)> = Vec::new();
            for kind in 0..Self::KINDS {
                let Some(op) = self.canonical(kind) else { continue };
                if !self.valid(&self.m, &op) {
                    continue;
                }
                let late = step * 10 >= len * 8;
                let weight = match kind {
                    0 => 2, // reopen after a full close
                    9 | 10 => 40,
                    11 | 13 | 14 => 30,
                    16 if late && self.halt_late => 12,
                    16 if self.halt_late && self.rng.pct(25) => 1,
                    16 => continue,
                    18 => 25,
                    19 => 2,
                    15 => 4,
                    17 => 8,
                    _ => 15,
                };
                cands.push((op, weight));
            }
            if !cands.is_empty() {
                let total: u64 = cands.iter().map(|c| c.1).sum();
                let mut x = self.rng.below(total);
                for (op, weight) in cands {
                    if x < weight {
                        return op;
                    }
                    x -= weight;
                }
            }
        }
        // A random kind, often perturbed; bystander and pre-funder actions included.
        loop {
            let kind = self.rng.below(Self::KINDS as u64) as u32;
            if let Some(op) = self.canonical(kind) {
                // Valid halts come from the weighted path only.
                let force = matches!(op, Op::Halt { .. } | Op::CloseSession { .. } | Op::Open { .. });
                return if force || self.rng.pct(65) { self.perturb(op) } else { op };
            }
        }
    }

    // ------------------------------------------------------ sequence ----

    async fn run(&mut self) {
        let len = self.rng.range(25, 140) as usize;
        let mut step = 0usize;
        while step < len {
            let roll = self.rng.below(100);
            if roll < 6 && !self.history.is_empty() {
                // Resend an earlier transaction (stale duplicate or replay).
                let i = self.rng.below(self.history.len() as u64) as usize;
                let ops = self.history[i].clone();
                self.stats.resends += 1;
                self.step(ops, None, "resend", false).await;
            } else if roll < 11 {
                // A reordered pair: generated in order, sent swapped.
                let a = self.gen_op(step, len);
                let b = self.gen_op(step, len);
                self.stats.reorders += 1;
                self.history.push(vec![b.clone()]);
                self.step(vec![b], None, "reorder-b", false).await;
                self.history.push(vec![a.clone()]);
                self.step(vec![a], None, "reorder-a", false).await;
            } else if roll < 17 {
                // A multi-instruction transaction; atomic as a whole.
                let n = self.rng.range(2, 3);
                let mut ops = Vec::new();
                let saved = self.m.clone();
                for _ in 0..n {
                    // Each op is generated against the state its predecessors leave.
                    let op = self.gen_op(step, len);
                    if self.valid(&self.m, &op) {
                        let mut next = self.m.clone();
                        self.apply(&mut next, &op);
                        self.m = next;
                    }
                    ops.push(op);
                }
                self.m = saved;
                self.stats.bundles += 1;
                self.history.push(ops.clone());
                self.step(ops, None, "bundle", false).await;
            } else {
                let op = self.gen_op(step, len);
                let cu = (self.cfg.sbf && self.rng.pct(4)).then(|| self.rng.range(1_000, 25_000));
                let was_active = self.m.open && self.m.active;
                let phase = self.m.phase;
                let lanes_busy = self.m.lane.iter().flatten().filter(|l| l.status != L_IDLE).count();
                let is_prefund = matches!(op, Op::Prefund { .. });
                let is_open = matches!(op, Op::Open { .. });
                let reopened = is_open && self.history.iter().flatten().any(|o| matches!(o, Op::CloseSession { .. }));
                self.history.push(vec![op.clone()]);
                let ok = self.step(vec![op], cu, "op", false).await;
                if ok && is_prefund {
                    self.stats.prefunds += 1;
                }
                if ok && reopened {
                    self.stats.reopened += 1;
                }
                if ok && was_active && !self.m.active {
                    let what = format!("phase {phase} lanes-busy {lanes_busy} reason {:#x}", self.m.halt_reason);
                    self.halt_stat(what);
                }
            }
            step += 1;
            // A fully closed session usually ends the sequence (reopening is
            // still exercised).
            if !self.m.open && self.history.iter().flatten().any(|o| matches!(o, Op::CloseSession { .. })) && self.rng.pct(60) {
                break;
            }
        }
        self.liveness().await;
        self.closability().await;
    }

    /// With an accepting kernel and an active session, the authority (and
    /// writer) can still advance one input and, with lanes, publish it,
    /// whatever the bystander and pre-funder did.
    async fn liveness(&mut self) {
        use Actor::Authority as A;
        let m = self.m.clone();
        let skip = if !m.open || !m.active {
            Some("halted or closed")
        } else if self.p.ws {
            Some("fixed engine (not an accepting kernel)")
        } else if self.p.width != 1 {
            Some("refusing kernel (width 2)")
        } else if m.phase == PH_INIT {
            Some("authority began phased init on a one-call kernel")
        } else {
            None
        };
        if let Some(why) = skip {
            *self.stats.liveness_skipped.entry(why).or_default() += 1;
            return;
        }
        self.stats.liveness_runs += 1;
        let payer = Actor::Payer;
        if m.phase == PH_VIEW {
            self.step(vec![Op::Abort { actor: A, cursor: m.ph_state }], None, "live", true).await;
        }
        if m.phase == PH_ANCHOR {
            self.step(vec![Op::AnchorAbort { auth: A, cursor: m.ph_state }], None, "live", true).await;
        }
        for k in 0..4u8 {
            if let Some(l) = self.m.lane[k as usize].clone() {
                if l.status != L_IDLE {
                    self.step(vec![Op::LaneAbort { actor: A, k, c: l.captured }], None, "live", true).await;
                }
            }
        }
        if !self.m.stream {
            self.step(vec![Op::CreateStream { payer, auth: A, signed: true }], None, "live", true).await;
        }
        if self.m.states == 0 {
            self.step(vec![Op::CreateState { payer, auth: A, signed: true }], None, "live", true).await;
        }
        if !self.m.initialized {
            self.step(vec![Op::InitOneCall { auth: A }], None, "live", true).await;
        }
        if self.m.cursor == self.m.capacity {
            let cap = self.m.capacity + 1;
            self.step(vec![Op::GrowStream { payer, cap }], None, "live", true).await;
        }
        let cursor = self.m.cursor;
        if self.m.slots[cursor as usize].is_none() {
            self.step(vec![Op::Write { actor: self.writer(), seq: cursor, bytes: vec![1] }], None, "live", true).await;
        }
        self.step(vec![Op::Advance { actor: A, cursor, steps: 1 }], None, "live", true).await;
        if self.m.lanes == 0 {
            return;
        }
        if self.m.views.is_empty() {
            self.step(vec![Op::CreateView { payer, auth: A, signed: true, role: VALUE, bad_abi: false }], None, "live", true).await;
        }
        // A lane that exists with a scratch large enough, or a free one.
        let total = self.m.view_total();
        let k = (0..self.m.lanes).find(|k| self.m.lane[*k as usize].as_ref().is_some_and(|l| l.sc_len >= total)).or_else(|| (0..self.m.lanes).find(|k| self.m.lane[*k as usize].is_none()));
        let Some(k) = k else {
            *self.stats.liveness_skipped.entry("publish: authority's lanes all have short scratch").or_default() += 1;
            return;
        };
        if self.m.lane[k as usize].is_none() {
            self.step(vec![Op::LaneCreate { payer, auth: A, k, ws_len: 64, sc_len: 16 }], None, "live", true).await;
        }
        let c = self.m.cursor;
        self.step(vec![Op::CapBegin { actor: A, k, c }], None, "live", true).await;
        self.step(vec![Op::CapRun { actor: A, k, c, at: 0, phases: Some(2) }], None, "live", true).await;
        self.step(vec![Op::CapEnd { actor: A, k, c }], None, "live", true).await;
        self.step(vec![Op::Render { actor: A, k, c, at: 0, phases: Some(3) }], None, "live", true).await;
        self.step(vec![Op::LaneCommit { actor: A, k, c }], None, "live", true).await;
        self.stats.liveness_publish += 1;
    }

    /// From the reached state, halt and close every child and the session;
    /// every session address ends empty and the authority receives every
    /// lamport they held.
    async fn closability(&mut self) {
        use Actor::Authority as A;
        if !self.m.open {
            return;
        }
        self.stats.closability_runs += 1;
        let before = self.snapshot().await;
        let held: u64 = self
            .k
            .derived()
            .iter()
            .map(|(_, key)| {
                let i = self.keys_tracked.iter().position(|k| k == key).unwrap();
                before[i].as_ref().filter(|a| a.owner == PROGRAM).map_or(0, |a| a.lamports)
            })
            .sum();
        let auth_before = self.ctx.banks_client.get_balance(self.auth()).await.unwrap();
        if self.m.active {
            let cursor = self.m.cursor;
            self.step(vec![Op::Halt { actor: A, cursor }], None, "close", true).await;
        }
        // Closes need no signer; the order: everything but states, then states
        // from the highest index down.
        let mut kids: Vec<Child> = self.m.children().into_iter().filter(|c| !matches!(c, Child::State(_))).collect();
        let mut states: Vec<Child> = self.m.children().into_iter().filter(|c| matches!(c, Child::State(_))).collect();
        states.sort();
        states.reverse();
        kids.extend(states);
        for child in kids {
            self.step(vec![Op::Close { child, kind: child.kind(), refund: A }], None, "close", true).await;
        }
        self.step(vec![Op::CloseSession { refund: A }], None, "close", true).await;
        let after = self.snapshot().await;
        for (_, key) in self.k.derived() {
            let i = self.keys_tracked.iter().position(|k| *k == key).unwrap();
            if after[i].as_ref().is_some_and(|a| a.owner == PROGRAM || (!a.data.is_empty())) {
                fail!(self, "address {key} not emptied by the closes");
            }
        }
        let auth_after = self.ctx.banks_client.get_balance(self.auth()).await.unwrap();
        if auth_after != auth_before + held {
            fail!(self, "authority received {} of {held} lamports", auth_after as i128 - auth_before as i128);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().take(6).map(|x| format!("{x:02x}")).collect()
}

async fn start(sbf: bool, resource: &[u8]) -> ProgramTestContext {
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
    }
    let data = if resource.is_empty() { vec![0x5A; 64] } else { resource.to_vec() };
    test.add_genesis_account(RESOURCE_SRC, Account { lamports: 1_000_000_000, data, owner: PROGRAM, executable: false, rent_epoch: 0 });
    test.start_with_context().await
}

async fn run_sequence(seed: u64, index: u64, sbf: bool, verbose: bool, plant: u8) -> Stats {
    let mut rng = Rng::new(seed, index);
    let p = Params::gen(&mut rng);
    let k = Keys::new(&mut rng, p.id);
    let ctx = start(sbf, &p.resource).await;
    let rent0 = ctx.banks_client.get_rent().await.unwrap().minimum_balance(0);
    // Fund the actors (outside the per-step accounting).
    for (i, kp) in k.actors.iter().enumerate() {
        let lamports = if i == 1 { 1_000_000_000 } else { 100_000_000_000 };
        let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
        let tx = Transaction::new_signed_with_payer(&[system_instruction::transfer(&ctx.payer.pubkey(), &kp.pubkey(), lamports)], Some(&ctx.payer.pubkey()), &[&ctx.payer], blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    let mut keys_tracked = vec![ctx.payer.pubkey(), RESOURCE_SRC];
    keys_tracked.extend(k.actors.iter().map(|a| a.pubkey()));
    keys_tracked.extend(k.derived().into_iter().map(|(_, key)| key));
    let tag = format!("seed {seed} index {index} ({} lanes {} append {} width {} cap {} steps {} sbf {sbf})", if p.ws { "fixed-engine" } else { "lane-counter" }, p.lanes, p.append, p.width, p.capacity, p.max_steps);
    let mut f = Fuzz { ctx, p, k, m: M::default(), rng, cfg: Config { sbf, verbose, plant }, stats: Stats::default(), nonce: 0, history: Vec::new(), tag, log: Vec::new(), keys_tracked, rent0, halt_late: false, last_logs: String::new(), res_writable: false };
    f.halt_late = f.rng.pct(50);
    f.stats.sequences = 1;
    if f.p.ws {
        f.stats.ws_sequences = 1;
    } else {
        f.stats.lane_sequences = 1;
    }
    f.run().await;
    f.stats.commits = f.stats.ops.get("commit_phase").map_or(0, |e| e.0);
    f.stats.lane_commits = f.stats.ops.get("lane_commit").map_or(0, |e| e.0);
    f.stats.anchors_finished = f.stats.ops.get("anchor_finish").map_or(0, |e| e.0);
    f.stats.one_shot_anchors = f.stats.ops.get("anchor_one_shot").map_or(0, |e| e.0);
    f.stats
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().map_or(default, |v| v.parse().unwrap())
}

async fn campaign(seed: u64, from: u64, count: u64, jobs: usize, sbf: bool, only: Option<u64>) -> Stats {
    let started = std::time::Instant::now();
    let mut total = Stats::default();
    if let Some(i) = only {
        total.merge(&run_sequence(seed, i, sbf, true, 0).await);
        return total;
    }
    let mut set = tokio::task::JoinSet::new();
    let mut next = from;
    loop {
        while set.len() < jobs && next < from + count {
            set.spawn(run_sequence(seed, next, sbf, false, 0));
            next += 1;
        }
        match set.join_next().await {
            Some(Ok(s)) => total.merge(&s),
            Some(Err(e)) => std::panic::resume_unwind(e.into_panic()),
            None => break,
        }
    }
    eprintln!("v3 fuzz: seed {seed} sequences {from}..{} sbf {sbf} in {:.1} s", from + count, started.elapsed().as_secs_f64());
    total
}

fn report(s: &Stats) {
    eprintln!(
        "v3 fuzz stats: sequences {} (lane-counter {}, fixed-engine {}), txs {} (accepted {}, refused {}, not run {}), compute failures {}, resends {}, reordered pairs {}, bundles {}, invariant checks {}, max cursor {}, non-lane commits {}, lane commits {}, chunked anchors {}, one-shot anchors {}, prefunds {}, reopened {}, liveness {} (publish {}), closability {}",
        s.sequences, s.lane_sequences, s.ws_sequences, s.txs, s.accepted, s.refused, s.not_run, s.cu_failures, s.resends, s.reorders, s.bundles, s.checks, s.max_cursor, s.commits, s.lane_commits, s.anchors_finished, s.one_shot_anchors, s.prefunds, s.reopened, s.liveness_runs, s.liveness_publish, s.closability_runs
    );
    eprintln!("v3 fuzz liveness skipped: {:?}", s.liveness_skipped);
    eprintln!("v3 fuzz halts: {:?}", s.halts);
    let ops: Vec<String> = s.ops.iter().map(|(k, (a, r))| format!("{k} {a}/{r}")).collect();
    eprintln!("v3 fuzz ops (accepted/refused): {}", ops.join(", "));
}

/// The campaign (ignored; see the module docs for the environment).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "fuzz campaign; V3_FUZZ_SEED, V3_FUZZ_COUNT, V3_FUZZ_JOBS, V3_FUZZ_ONLY, V3_FUZZ_SBF"]
async fn fuzz_campaign() {
    let sbf = std::env::var("V3_FUZZ_SBF").is_ok_and(|v| v == "1");
    let seed = env_u64("V3_FUZZ_SEED", 1);
    let only = std::env::var("V3_FUZZ_ONLY").ok().map(|v| v.parse().unwrap());
    let stats = campaign(seed, env_u64("V3_FUZZ_FROM", 0), env_u64("V3_FUZZ_COUNT", 50), env_u64("V3_FUZZ_JOBS", 8) as usize, sbf, only).await;
    report(&stats);
}

/// A small native campaign in the default suite.
#[tokio::test(flavor = "multi_thread")]
async fn fuzz_smoke() {
    let stats = campaign(7, 0, 6, 6, false, None).await;
    assert_eq!(stats.sequences, 6);
    assert!(stats.accepted > 0 && stats.refused > 0);
}

/// Planted checks: a wrong host input chain, a wrong acceptance prediction
/// and a wrong host kernel are each caught.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "input root differs")]
async fn fuzz_catches_a_planted_input_chain_error() {
    for index in 0..20 {
        run_sequence(11, index, false, false, 1).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "unexpected acceptance")]
async fn fuzz_catches_a_planted_acceptance_error() {
    for index in 0..20 {
        run_sequence(11, index, false, false, 2).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "state digest")]
async fn fuzz_catches_a_planted_kernel_error() {
    for index in 0..20 {
        run_sequence(11, index, false, false, 3).await;
    }
}

// ------------------------------------------------------------ findings ----

/// Finding F1 reproducer (fuzz seed 1001 index 316, native): a close of an
/// open anchor (session halted mid-anchor) with kind byte 1 (`KIND_STREAM`)
/// is accepted, because `close_account` compares the kind byte with the
/// target's byte 6 (the anchor's open flag) and `close_child` then recognizes
/// the anchor by its address. The effect equals a correct close (rent to the
/// authority, child count decremented); the kind byte is just not enforced.
/// The same holds for a headerless primary whose application byte 6 equals the
/// kind. Ignored: it asserts the strict behavior the program does not have.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "finding F1: close kind byte not enforced for the anchor and the headerless primary"]
async fn finding_f1_open_anchor_closes_under_a_wrong_kind() {
    let ctx = start(false, &[]).await;
    let mut rng = Rng::new(0xF1, 0);
    let p = Params { ws: false, lanes: 0, append: false, width: 1, capacity: 4, max_steps: 1, root: [7; 32], id: 1, resource: Vec::new(), state_len: 1_280, view_len: 16 };
    let k = Keys::new(&mut rng, p.id);
    let mut f = Fuzz { ctx, p, k, m: M::default(), rng, cfg: Config { sbf: false, verbose: true, plant: 0 }, stats: Stats::default(), nonce: 0, history: Vec::new(), tag: "F1".into(), log: Vec::new(), keys_tracked: Vec::new(), rent0: 0, halt_late: false, last_logs: String::new(), res_writable: false };
    let auth = f.auth();
    let payer = f.ctx.payer.pubkey();
    let fund = system_instruction::transfer(&payer, &auth, 10_000_000_000);
    let blockhash = f.ctx.banks_client.get_latest_blockhash().await.unwrap();
    f.ctx.banks_client.process_transaction(Transaction::new_signed_with_payer(&[fund], Some(&payer), &[&f.ctx.payer], blockhash)).await.unwrap();
    use Actor::{Authority as A, Payer as P};
    for op in [
        Op::Open { payer: P, auth: A, lanes: None },
        Op::CreateStream { payer: P, auth: A, signed: true },
        Op::CreateState { payer: P, auth: A, signed: true },
        Op::InitOneCall { auth: A },
        Op::AnchorBegin { payer: P, auth: A, cursor: 0 },
        Op::Halt { actor: A, cursor: 0 },
    ] {
        let (outcome, _) = f.send(f.build(&op), None).await;
        assert_eq!(outcome, Outcome::Ok, "{op:?}");
    }
    // The anchor is still open (byte 6 == 1); close it as a stream.
    let wrong = Op::Close { child: Child::Anchor, kind: v3::KIND_STREAM, refund: A };
    let (outcome, _) = f.send(f.build(&wrong), None).await;
    assert_ne!(outcome, Outcome::Ok, "an anchor closed under kind {} (stream)", v3::KIND_STREAM);
}
