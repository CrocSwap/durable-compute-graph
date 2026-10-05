//! LX1 checkpointed state chains on tag 227 (design
//! `docs/design/v2.1-lazy-expansion.md` §8), native ProgramTest (or SBF with
//! `V21_SBF=1`). The registered toy machine replays played Python disputes
//! (`scripts/disputes_v21_lx_program_scenarios.py`) through the program in
//! both role orders: every round's midpoints and picks, the terminal opening
//! from the executor's staging buffer, and the shared ruling; the OUTPUT
//! claim; refusals; timeouts; and the guards between LX1 and descent disputes.
#![cfg(all(feature = "graph-v21", feature = "test-kernel"))]

use dcg_disputes as D;
use dcg_program::disputes_v21 as V;
use dcg_program::disputes_v21::lx as LX;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program::system_program;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD7; 32]);
const SYSTEM: Pubkey = system_program::ID;
const EXECUTOR_BOND: u64 = 2_000_000;
const CHALLENGER_BOND: u64 = 1_000_000;
const PHASE_WINDOW: u64 = 750;
const LX_MAX_CHUNK_PATH: usize = dcg_disputes::lx::MAX_CHUNK_PATH;

struct Soft;
impl D::Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        sha256(parts)
    }
}

fn kp(b: u8) -> Keypair {
    Keypair::new_from_array([b; 32])
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(v: &serde_json::Value) -> D::Hash {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

fn golden() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/lx_program.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn custom(code: u32) -> TransactionError {
    TransactionError::InstructionError(0, InstructionError::Custom(0x6600 + code))
}

/// A full checkpoint tree as levels, padded with the empty leaf.
fn checkpoint_levels(roots: &[D::Hash]) -> Vec<Vec<D::Hash>> {
    let h = if roots.len() <= 1 { 0 } else { 64 - (roots.len() as u64 - 1).leading_zeros() };
    let mut level: Vec<D::Hash> = roots.to_vec();
    level.resize(1 << h, D::empty(&Soft, D::Tree::LxCheckpoint, 0));
    let mut levels = vec![level.clone()];
    for l in 0..h {
        level = level.chunks(2).map(|p| D::node(&Soft, D::Tree::LxCheckpoint, l as u16, &p[0], &p[1])).collect();
        levels.push(level.clone());
    }
    levels
}

fn path(levels: &[Vec<D::Hash>], mut i: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for level in &levels[..levels.len() - 1] {
        out.extend_from_slice(&level[i ^ 1]);
        i >>= 1;
    }
    out
}

/// The staged opening encoding: `n (slot present [len bytes])* s hash*`.
fn encode_opening(o: &serde_json::Value) -> Vec<u8> {
    let opened = o["opened"].as_array().unwrap();
    let mut v = (opened.len() as u32).to_le_bytes().to_vec();
    for e in opened {
        v.extend_from_slice(&(e[0].as_u64().unwrap() as u32).to_le_bytes());
        match e[1].as_str() {
            None => v.push(0),
            Some(x) => {
                let b = hex(x);
                v.push(1);
                v.extend_from_slice(&(b.len() as u32).to_le_bytes());
                v.extend_from_slice(&b);
            }
        }
    }
    let s = o["siblings"].as_array().unwrap();
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    for x in s {
        v.extend_from_slice(&h32(x));
    }
    v
}

/// A replay opening: the state opening, then its constant reads (design §13):
/// `n (len chunk cn chunk_path dig kn const_path)*`.
fn encode_replay(o: &serde_json::Value) -> Vec<u8> {
    let mut v = encode_opening(o);
    let cs = o["constants"].as_array().unwrap();
    v.extend_from_slice(&(cs.len() as u32).to_le_bytes());
    for e in cs {
        let chunk = hex(e["chunk"].as_str().unwrap());
        v.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        v.extend_from_slice(&chunk);
        for (key, with_digest) in [("chunk_path", true), ("const_path", false)] {
            let path = e[key].as_array().unwrap();
            v.push(path.len() as u8);
            for x in path {
                v.extend_from_slice(&h32(x));
            }
            if with_digest {
                v.extend_from_slice(&h32(&e["digest"]));
            }
        }
    }
    v
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut d = vec![V::TAG, sub];
    d.extend_from_slice(data);
    Instruction { program_id: PROGRAM, accounts, data: d }
}

async fn send(ctx: &mut ProgramTestContext, i: Instruction, signers: &[&Keypair]) -> Result<(), TransactionError> {
    if std::env::var_os("LX_FUZZ_PLAYS").is_some() {
        // Fuzz campaign: no wait for a new blockhash per transaction; a
        // per-transaction compute-unit price (paid by the payer only) keeps
        // repeated identical instructions distinct.
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
        let price = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_price(n);
        let mut all = vec![&ctx.payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new(&all, solana_message::Message::new(&[i, price], Some(&ctx.payer.pubkey())), blockhash);
        return ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| e.unwrap())?.result;
    }
    // Many banks at once can starve the slot clock; a blockhash wait that
    // times out is retried, not a test failure.
    let mut tries = 0;
    let blockhash = loop {
        match ctx.get_new_latest_blockhash().await {
            Ok(b) => break b,
            Err(e) if tries < 10 && e.to_string().contains("Unable to get new blockhash") => tries += 1,
            Err(e) => panic!("{e:?}"),
        }
    };
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, solana_message::Message::new(&[i], Some(&ctx.payer.pubkey())), blockhash);
    ctx.banks_client.process_transaction_with_metadata(tx).await.map_err(|e| e.unwrap())?.result
}

struct Chain {
    ctx: ProgramTestContext,
    template: Pubkey,
    run: Pubkey,
    run_id: [u8; 32],
    params: Vec<u8>,
    /// The position count the run root commits (the golden toy's 9 by default).
    positions: u64,
    levels: Vec<Vec<D::Hash>>,
    count: usize,
}

/// The template's LX1 tail bounds: k_min, k_max, max_positions.
#[derive(Clone, Copy)]
struct Bounds(u32, u32, u64);
const GOLDEN_BOUNDS: Bounds = Bounds(1, 16, 1 << 16);

impl Chain {
    /// An LX1 template for the toy machine at `arity`, and a run.
    async fn new(arity: u8, challenge_window: u64) -> Self {
        Self::new_with_input(arity, challenge_window, None).await
    }

    /// `input`: the run's input id; by default the digest of the golden params.
    async fn new_with_input(arity: u8, challenge_window: u64, input: Option<[u8; 32]>) -> Self {
        let g = golden();
        Self::new_full(arity, challenge_window, input, hex(g["params"].as_str().unwrap()), [0; 32], GOLDEN_BOUNDS, 9).await
    }

    /// The toy with weights (design §13): the weighted params, and a template
    /// committing `constants_root`.
    async fn new_weighted(arity: u8, constants_root: [u8; 32]) -> Self {
        let g = golden();
        Self::new_full(arity, 100_000, None, hex(g["weighted"]["params"].as_str().unwrap()), constants_root, GOLDEN_BOUNDS, 9).await
    }

    async fn new_full(arity: u8, challenge_window: u64, input: Option<[u8; 32]>, params: Vec<u8>, constants_root: [u8; 32], bounds: Bounds, positions: u64) -> Self {
        let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
        let mut test = ProgramTest::default();
        test.prefer_bpf(sbf);
        if sbf {
            test.add_program("dcg_program", PROGRAM, None);
        } else {
            test.add_program("dcg_program", PROGRAM, processor!(dcg_program::process_instruction));
        }
        for b in [0xA1u8, 0xE1, 0xC1, 0xB1] {
            test.add_account(kp(b).pubkey(), Account { lamports: 10_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 });
        }
        let mut ctx = test.start_with_context().await;
        let admitter = kp(0xA1);
        let mut data = vec![1u8];
        for x in [1u64, 0, challenge_window, PHASE_WINDOW, EXECUTOR_BOND, CHALLENGER_BOND] {
            data.extend_from_slice(&x.to_le_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&constants_root);
        data.extend_from_slice(&5_000u16.to_le_bytes());
        data.extend_from_slice(&[0; 32]);
        data.extend_from_slice(LX::LX_TAIL_MAGIC);
        data.extend_from_slice(b"dcg-lx-toy-v1\0\0\0");
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&[arity, 0, 0, 0]);
        data.extend_from_slice(&bounds.0.to_le_bytes());
        data.extend_from_slice(&bounds.1.to_le_bytes());
        data.extend_from_slice(&bounds.2.to_le_bytes());
        let template_id = sha256(&[V::TEMPLATE_DOMAIN, &data]);
        let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id, admitter.pubkey().as_ref()], &PROGRAM).0;
        send(&mut ctx, ix(V::SUB_CREATE_TEMPLATE, &data, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
        let executor = kp(0xE1).pubkey();
        // The payer admits the machine parameters: an LX1 run's input id is
        // their digest (LX1 program review H1).
        let input = input.unwrap_or_else(|| sha256(&[LX::PARAMS_DOMAIN, &params]));
        let mut init = input.to_vec();
        init.extend_from_slice(executor.as_ref());
        init.extend_from_slice(&0u32.to_le_bytes());
        let run_id = sha256(&[b"dcg.run.id.v2.1\x00", &template_id, &input, &0u32.to_le_bytes(), &[], executor.as_ref()]);
        let run = Pubkey::find_program_address(&[b"dcg21run", &run_id, admitter.pubkey().as_ref()], &PROGRAM).0;
        send(&mut ctx, ix(V::SUB_INIT_RUN, &init, vec![AccountMeta::new(admitter.pubkey(), true), AccountMeta::new(run, false), AccountMeta::new(template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&admitter]).await.unwrap();
        Chain { ctx, template, run, run_id, params, positions, levels: vec![], count: 0 }
    }

    fn commit_data(&mut self, c: &serde_json::Value) -> Vec<u8> {
        let roots: Vec<D::Hash> = c["roots"].as_array().unwrap().iter().map(h32).collect();
        self.levels = checkpoint_levels(&roots);
        self.count = roots.len();
        assert_eq!(self.levels.last().unwrap()[0], h32(&c["checkpoint_root"]), "checkpoint tree matches Python");
        let mut root = [0u8; D::RUN_ROOT_BYTES];
        root[0..32].copy_from_slice(&self.run_id);
        root[32..64].copy_from_slice(&h32(&c["checkpoint_root"]));
        root[64..96].copy_from_slice(&h32(&c["outputs_digest"]));
        root[96..128].copy_from_slice(&sha256(&[LX::PARAMS_DOMAIN, &self.params]));
        root[128..136].copy_from_slice(&self.positions.to_le_bytes());
        root[136..140].copy_from_slice(&(c["k"].as_u64().unwrap() as u32).to_le_bytes());
        let mut data = root.to_vec();
        data.extend(path(&self.levels, 0));
        data.extend_from_slice(&self.params);
        data
    }

    async fn commit(&mut self, c: &serde_json::Value) -> Result<(), TransactionError> {
        let data = self.commit_data(c);
        let e = kp(0xE1);
        send(&mut self.ctx, ix(V::SUB_COMMIT, &data, vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&e]).await
    }

    fn dispute(&self, nonce: u8) -> Pubkey {
        Pubkey::find_program_address(&[b"dcg21dsp", self.run.as_ref(), kp(0xC1).pubkey().as_ref(), &[nonce; 32]], &PROGRAM).0
    }

    async fn open_raw(&mut self, nonce: u8, body: &[u8]) -> Result<Pubkey, TransactionError> {
        let c = kp(0xC1);
        let d = self.dispute(nonce);
        let mut data = vec![nonce; 32];
        data.extend_from_slice(body);
        send(&mut self.ctx, ix(V::SUB_OPEN, &data, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c]).await?;
        Ok(d)
    }

    /// Sub 27 (staged open): `op` 0 create, 1 write (signed by `who` as the
    /// challenger), 2 close (signed by `who`, naming the challenger 0xC1),
    /// for the dispute `d` the challenger would open with `nonce`.
    async fn prestage(&mut self, who: u8, nonce: u8, d: Pubkey, op: u8, rest: &[u8]) -> Result<(), TransactionError> {
        let signer = kp(who);
        let mut data = vec![nonce; 32];
        data.push(op);
        data.extend_from_slice(rest);
        let last = if op == 2 { AccountMeta::new(kp(0xC1).pubkey(), false) } else { AccountMeta::new_readonly(SYSTEM, false) };
        let accounts = vec![AccountMeta::new(signer.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(self.buffer(d, V::ROLE_CHALLENGER), false), last];
        send(&mut self.ctx, ix(LX::SUB_LX_PRESTAGE, &data, accounts), &[&signer]).await
    }

    /// Stage `body` (a state body without its kind byte), masked with the
    /// secret `[nonce ^ 0x5A; 32]`, before the open, in 800-byte writes.
    async fn prestage_body(&mut self, nonce: u8, body: &[u8]) -> Result<(), TransactionError> {
        let d = self.dispute(nonce);
        let mut masked = body.to_vec();
        LX::prestage_mask(&[nonce ^ 0x5A; 32], &d, &mut masked);
        self.prestage(0xC1, nonce, d, 0, &(V::CREATE_STAGE as u32).to_le_bytes()).await?;
        for (n, chunk) in masked.chunks(800).enumerate() {
            let mut w = ((800 * n) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(chunk);
            self.prestage(0xC1, nonce, d, 1, &w).await?;
        }
        Ok(())
    }

    /// OPEN a state dispute whose body is read from the staged buffer and
    /// unmasked with `secret` (the staging secret by default).
    async fn open_staged_with(&mut self, nonce: u8, secret: [u8; 32]) -> Result<Pubkey, TransactionError> {
        let c = kp(0xC1);
        let d = self.dispute(nonce);
        let mut data = vec![nonce; 32];
        data.extend_from_slice(&[LX::KIND_LX_STATE, V::FROM_STAGING]);
        data.extend_from_slice(&secret);
        let accounts = vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new_readonly(SYSTEM, false), AccountMeta::new(self.buffer(d, V::ROLE_CHALLENGER), false)];
        send(&mut self.ctx, ix(V::SUB_OPEN, &data, accounts), &[&c]).await?;
        Ok(d)
    }

    async fn open_staged(&mut self, nonce: u8) -> Result<Pubkey, TransactionError> {
        self.open_staged_with(nonce, [nonce ^ 0x5A; 32]).await
    }

    fn state_body(&self, c: &serde_json::Value, pair: usize) -> Vec<u8> {
        let roots = c["roots"].as_array().unwrap();
        let mut body = vec![LX::KIND_LX_STATE];
        body.extend_from_slice(&(pair as u32).to_le_bytes());
        body.extend_from_slice(&h32(&roots[pair]));
        body.extend_from_slice(&h32(&roots[pair + 1]));
        body.extend(path(&self.levels, pair));
        body.extend(path(&self.levels, pair + 1));
        body.extend_from_slice(&self.params);
        body
    }

    fn party(&self, who: u8, d: Pubkey) -> Vec<AccountMeta> {
        vec![AccountMeta::new_readonly(kp(who).pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false)]
    }

    async fn midpoints(&mut self, d: Pubkey, roots: &[u8]) -> Result<(), TransactionError> {
        let i = ix(LX::SUB_LX_MIDPOINTS, roots, self.party(0xE1, d));
        send(&mut self.ctx, i, &[&kp(0xE1)]).await
    }

    async fn pick(&mut self, d: Pubkey, index: u8) -> Result<(), TransactionError> {
        let i = ix(LX::SUB_LX_PICK, &[index], self.party(0xC1, d));
        send(&mut self.ctx, i, &[&kp(0xC1)]).await
    }

    fn buffer(&self, d: Pubkey, role: u8) -> Pubkey {
        Pubkey::find_program_address(&[b"dcg21stg", d.as_ref(), &[role]], &PROGRAM).0
    }

    /// Create and fill a party's staging buffer (the challenger creates both).
    async fn stage(&mut self, d: Pubkey, role: u8, bytes: &[u8]) {
        let c = kp(0xC1);
        let buffer = self.buffer(d, role);
        let mut create = vec![role];
        create.extend_from_slice(&(V::CREATE_STAGE as u32).to_le_bytes());
        send(&mut self.ctx, ix(V::SUB_STAGE_CREATE, &create, vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buffer, false), AccountMeta::new_readonly(SYSTEM, false)]), &[&c]).await.unwrap();
        self.write(d, role, 0, bytes).await.unwrap();
    }

    async fn write(&mut self, d: Pubkey, role: u8, from: usize, bytes: &[u8]) -> Result<(), TransactionError> {
        let writer = if role == V::ROLE_EXECUTOR { kp(0xE1) } else { kp(0xC1) };
        let buffer = self.buffer(d, role);
        for (n, chunk) in bytes.chunks(800).enumerate() {
            let mut w = ((from + 800 * n) as u32).to_le_bytes().to_vec();
            w.extend_from_slice(chunk);
            send(&mut self.ctx, ix(V::SUB_STAGE_WRITE, &w, vec![AccountMeta::new_readonly(writer.pubkey(), true), AccountMeta::new_readonly(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new_readonly(d, false), AccountMeta::new(buffer, false)]), &[&writer]).await?;
        }
        Ok(())
    }

    async fn opening(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let e = kp(0xE1);
        let accounts = vec![AccountMeta::new(e.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new_readonly(self.buffer(d, V::ROLE_EXECUTOR), false)];
        let params = self.params.clone();
        send(&mut self.ctx, ix(LX::SUB_LX_OPENING, &params, accounts), &[&e]).await
    }

    async fn output(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let c = kp(0xC1);
        let accounts = vec![AccountMeta::new(c.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new_readonly(self.buffer(d, V::ROLE_CHALLENGER), false)];
        let params = self.params.clone();
        send(&mut self.ctx, ix(LX::SUB_LX_OUTPUT, &params, accounts), &[&c]).await
    }

    async fn timeout(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let caller = kp(0xB1);
        let i = ix(V::SUB_TIMEOUT, &[], vec![AccountMeta::new_readonly(caller.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(kp(0xC1).pubkey(), false)]);
        send(&mut self.ctx, i, &[&caller]).await
    }

    async fn account(&mut self, k: Pubkey) -> Account {
        self.ctx.banks_client.get_account(k).await.unwrap().unwrap()
    }

    async fn lamports(&mut self, k: Pubkey) -> u64 {
        self.ctx.banks_client.get_account(k).await.unwrap().map_or(0, |a| a.lamports)
    }

    async fn warp(&mut self, slots: u64) {
        let now = self.ctx.banks_client.get_root_slot().await.unwrap();
        self.ctx.warp_to_slot(now + slots).unwrap();
    }
}

fn ruling_of(r: &str) -> u8 {
    if r == "E" { V::RULING_EXECUTOR } else { V::RULING_CHALLENGER }
}

#[tokio::test(flavor = "multi_thread")]
async fn played_disputes_rule_like_python_in_both_role_orders() {
    let g = golden();
    let plays = g["plays"].as_array().unwrap();
    assert!(plays.len() >= 16);
    for p in plays {
        let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
        check_play(&mut ch, p).await;
    }
}

/// Play one golden dispute through the program and check the ruling and the
/// bond movement.
async fn check_play(ch: &mut Chain, p: &serde_json::Value) {
    let name = p["name"].as_str().unwrap();
    let d = to_leaf(ch, p, name).await;
    ch.stage(d, V::ROLE_EXECUTOR, &encode_replay(&p["opening"])).await;
    rule_and_check(ch, d, p, name, false).await;
}

/// Commit, open the play's pair and play its rounds; the dispute then owes
/// the terminal opening.
async fn to_leaf(ch: &mut Chain, p: &serde_json::Value, name: &str) -> Pubkey {
    ch.commit(&p["commitment"]).await.unwrap_or_else(|e| panic!("{name}: commit {e:?}"));
    let pair = p["pair"].as_u64().unwrap() as usize;
    let body = ch.state_body(&p["commitment"], pair);
    let d = ch.open_raw(1, &body).await.unwrap_or_else(|e| panic!("{name}: open {e:?}"));
    for r in p["rounds"].as_array().unwrap() {
        let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
        ch.midpoints(d, &mids).await.unwrap_or_else(|e| panic!("{name}: midpoints {e:?}"));
        ch.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap_or_else(|e| panic!("{name}: pick {e:?}"));
    }
    let dd = ch.account(d).await.data;
    assert_eq!(u64::from_le_bytes(dd[16..24].try_into().unwrap()), p["terminal"].as_u64().unwrap(), "{name}: terminal coordinate");
    d
}

/// Submit the staged opening (the executor's replay opening, or with `output`
/// the challenger's OUTPUT claim) and check the ruling and the bond movement.
async fn rule_and_check(ch: &mut Chain, d: Pubkey, p: &serde_json::Value, name: &str, output: bool) {
    let (e0, c0) = (ch.lamports(kp(0xE1).pubkey()).await, ch.lamports(kp(0xC1).pubkey()).await);
    let r = if output { ch.output(d).await } else { ch.opening(d).await };
    r.unwrap_or_else(|e| panic!("{name}: opening {e:?}"));
    let want = ruling_of(p["ruling"].as_str().unwrap());
    assert_eq!(ch.account(d).await.data[6], want, "{name}: ruling");
    let (e1, c1) = (ch.lamports(kp(0xE1).pubkey()).await, ch.lamports(kp(0xC1).pubkey()).await);
    // The challenger's bond goes to the winner (fees are paid by the payer).
    if want == V::RULING_EXECUTOR {
        assert_eq!((e1 - e0, c1), (CHALLENGER_BOND, c0), "{name}: bond to the executor");
        assert_eq!(ch.account(ch.run).await.data[4], V::RUN_COMMITTED, "{name}: still committed");
    } else {
        assert_eq!((e1, c1 - c0), (e0, CHALLENGER_BOND), "{name}: bond back to the challenger");
        assert_eq!(ch.account(ch.run).await.data[4], V::RUN_REFUTED, "{name}: refuted");
    }
    // Only closes may act after the ruling.
    let again = if output { ch.output(d).await } else { ch.opening(d).await };
    assert!(again.is_err(), "{name}: a second opening");
    assert!(ch.timeout(d).await.is_err(), "{name}: a timeout after the ruling");
}

// --- constants in openings (design §13) -------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn weighted_disputes_rule_like_python_in_both_role_orders() {
    let g = golden();
    let w = &g["weighted"];
    let root = h32(&w["constants_root"]);
    let plays = w["plays"].as_array().unwrap();
    assert!(plays.len() >= 8);
    for p in plays {
        let mut ch = Chain::new_weighted(p["arity"].as_u64().unwrap() as u8, root).await;
        check_play(&mut ch, p).await;
    }
}

/// Drive a weighted play to its terminal opening phase.
async fn weighted_at_opening(p: &serde_json::Value, root: D::Hash) -> (Chain, Pubkey) {
    let mut ch = Chain::new_weighted(p["arity"].as_u64().unwrap() as u8, root).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d = ch.open_raw(1, &body).await.unwrap();
    for r in p["rounds"].as_array().unwrap() {
        let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
        ch.midpoints(d, &mids).await.unwrap();
        ch.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap();
    }
    (ch, d)
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_missing_or_reordered_constants_are_refused_and_the_executor_may_retry() {
    let g = golden();
    let w = &g["weighted"];
    let root = h32(&w["constants_root"]);
    let p = w["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E").unwrap();
    let (mut ch, d) = weighted_at_opening(p, root).await;
    let o = &p["opening"];
    let good = encode_replay(o);
    ch.stage(d, V::ROLE_EXECUTOR, &good).await;
    let variant = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut o = o.clone();
        f(&mut o);
        encode_replay(&o)
    };
    let flip = |v: &mut serde_json::Value| {
        let mut b = hex(v.as_str().unwrap());
        b[0] ^= 1;
        *v = serde_json::Value::String(hex_of(&b));
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("wrong chunk", variant(&|o| flip(&mut o["constants"][0]["chunk"]))),
        ("wrong chunk path", variant(&|o| flip(&mut o["constants"][0]["chunk_path"][0]))),
        ("wrong digest", variant(&|o| flip(&mut o["constants"][1]["digest"]))),
        ("wrong constant path", variant(&|o| flip(&mut o["constants"][1]["const_path"][0]))),
        ("missing read", variant(&|o| {
            o["constants"].as_array_mut().unwrap().pop();
        })),
        ("extra read", variant(&|o| {
            let first = o["constants"][0].clone();
            o["constants"].as_array_mut().unwrap().push(first);
        })),
        ("swapped reads", variant(&|o| o["constants"].as_array_mut().unwrap().swap(0, 1))),
        ("no reads", variant(&|o| o["constants"] = serde_json::json!([]))),
    ];
    for (name, bytes) in &cases {
        // Each variant is staged over the whole buffer prefix; trailing bytes
        // of a longer earlier staging are ignored after the decoded end.
        ch.write(d, V::ROLE_EXECUTOR, 0, bytes).await.unwrap();
        assert_eq!(ch.opening(d).await, Err(custom(50)), "{name}");
        assert_eq!(ch.account(d).await.data[6], V::RULING_OPEN, "{name}: nothing ruled");
    }
    // A count above the machine's maximum is refused before decoding (50).
    let mut many = encode_opening(o);
    many.extend_from_slice(&3u32.to_le_bytes());
    ch.write(d, V::ROLE_EXECUTOR, 0, &many).await.unwrap();
    assert_eq!(ch.opening(d).await, Err(custom(50)), "too many reads");
    // A section that runs past the buffer does not decode (46): a chunk
    // length larger than the whole buffer.
    let mut past = encode_opening(o);
    past.extend_from_slice(&1u32.to_le_bytes());
    past.extend_from_slice(&(V::CREATE_STAGE as u32).to_le_bytes());
    ch.write(d, V::ROLE_EXECUTOR, 0, &past).await.unwrap();
    assert_eq!(ch.opening(d).await, Err(custom(46)), "truncated");
    // A path length above its cap is refused before its hashes are read (50).
    let mut capped = encode_opening(o);
    capped.extend_from_slice(&1u32.to_le_bytes());
    capped.extend_from_slice(&0u32.to_le_bytes());
    capped.push(LX_MAX_CHUNK_PATH as u8 + 1);
    ch.write(d, V::ROLE_EXECUTOR, 0, &capped).await.unwrap();
    assert_eq!(ch.opening(d).await, Err(custom(50)), "overlong path");
    // The honest opening still wins before the deadline.
    ch.write(d, V::ROLE_EXECUTOR, 0, &good).await.unwrap();
    ch.opening(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
}

#[tokio::test(flavor = "multi_thread")]
async fn data_dependent_constant_reads_rule_like_python_in_both_role_orders() {
    let g = golden();
    let b = &g["by_value"];
    let root = h32(&b["constants_root"]);
    let params = hex(b["params"].as_str().unwrap());
    for p in b["plays"].as_array().unwrap() {
        let mut ch = Chain::new_full(p["arity"].as_u64().unwrap() as u8, 100_000, None, params.clone(), root, GOLDEN_BOUNDS, 9).await;
        check_play(&mut ch, p).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_data_dependent_read_of_the_wrong_chunk_is_refused() {
    // Review M2: the chunk the position would select, with a valid path, is
    // not the one the verified h selects.
    let g = golden();
    let b = &g["by_value"];
    let root = h32(&b["constants_root"]);
    let params = hex(b["params"].as_str().unwrap());
    let p = b["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E" && p.get("by_position").is_some()).unwrap();
    let mut ch = Chain::new_full(p["arity"].as_u64().unwrap() as u8, 100_000, None, params, root, GOLDEN_BOUNDS, 9).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d = ch.open_raw(1, &body).await.unwrap();
    for r in p["rounds"].as_array().unwrap() {
        let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
        ch.midpoints(d, &mids).await.unwrap();
        ch.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap();
    }
    let mut wrong = p["opening"].clone();
    wrong["constants"][0]["chunk"] = p["by_position"]["chunk"].clone();
    wrong["constants"][0]["chunk_path"] = p["by_position"]["chunk_path"].clone();
    ch.stage(d, V::ROLE_EXECUTOR, &encode_replay(&wrong)).await;
    assert_eq!(ch.opening(d).await, Err(custom(50)));
    ch.write(d, V::ROLE_EXECUTOR, 0, &encode_replay(&p["opening"])).await.unwrap();
    ch.opening(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
}

#[tokio::test(flavor = "multi_thread")]
async fn constants_must_be_under_the_template_constants_root() {
    // The same weighted run on a template that commits other constants (here
    // none): no opening can verify, so the executor cannot answer and loses
    // at its deadline.
    let g = golden();
    let w = &g["weighted"];
    let p = w["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E").unwrap();
    let (mut ch, d) = weighted_at_opening(p, [0; 32]).await;
    ch.stage(d, V::ROLE_EXECUTOR, &encode_replay(&p["opening"])).await;
    assert_eq!(ch.opening(d).await, Err(custom(50)));
    ch.warp(PHASE_WINDOW + 5).await;
    ch.timeout(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_CHALLENGER);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_openings_are_refused_and_the_executor_may_retry() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E").unwrap();
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d = ch.open_raw(1, &body).await.unwrap();
    for r in p["rounds"].as_array().unwrap() {
        let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
        ch.midpoints(d, &mids).await.unwrap();
        ch.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap();
    }
    let good = encode_replay(&p["opening"]);
    // A changed opened value does not rebuild the agreed lower root (49).
    let mut bad = good.clone();
    let first_value = 4 + 4 + 1 + 4; // n, slot, present, len
    bad[first_value] ^= 1;
    ch.stage(d, V::ROLE_EXECUTOR, &bad).await;
    assert_eq!(ch.opening(d).await, Err(custom(49)));
    // A missing slot does not cover the transition (48).
    let mut short = (p["opening"]["opened"].as_array().unwrap().len() as u32 - 1).to_le_bytes().to_vec();
    short.extend_from_slice(&good[4..]);
    ch.write(d, V::ROLE_EXECUTOR, 0, &short).await.unwrap();
    assert!(ch.opening(d).await.is_err());
    // Wrong machine parameters are refused (42).
    let accounts = vec![AccountMeta::new(kp(0xE1).pubkey(), true), AccountMeta::new(ch.run, false), AccountMeta::new_readonly(ch.template, false), AccountMeta::new(d, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new_readonly(ch.buffer(d, V::ROLE_EXECUTOR), false)];
    let mut params = ch.params.clone();
    params[16] ^= 1;
    assert_eq!(send(&mut ch.ctx, ix(LX::SUB_LX_OPENING, &params, accounts), &[&kp(0xE1)]).await, Err(custom(42)));
    // Nothing was ruled; the honest opening still wins before the deadline.
    assert_eq!(ch.account(d).await.data[6], V::RULING_OPEN);
    ch.write(d, V::ROLE_EXECUTOR, 0, &good).await.unwrap();
    ch.opening(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_requires_the_admitted_initial_state_and_open_the_committed_pair() {
    let g = golden();
    let p = &g["plays"][0];
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    // A commitment whose checkpoint 0 is not the initial state's root (H1).
    let mut wrong = p["commitment"].clone();
    let mut roots = wrong["roots"].as_array().unwrap().clone();
    roots[0] = serde_json::Value::String(hex_of(&[9u8; 32]));
    let levels = checkpoint_levels(&roots.iter().map(h32).collect::<Vec<_>>());
    wrong["roots"] = serde_json::Value::Array(roots);
    wrong["checkpoint_root"] = serde_json::Value::String(hex_of(&levels.last().unwrap()[0]));
    assert_eq!(ch.commit(&wrong).await, Err(custom(7)));
    ch.commit(&p["commitment"]).await.unwrap();
    // A pair opened with a root that is not committed is refused (44).
    let mut body = ch.state_body(&p["commitment"], 0);
    body[5] ^= 1;
    assert_eq!(ch.open_raw(1, &body).await.err(), Some(custom(44)));
    // The last checkpoint has no successor.
    let last = ch.count - 1;
    let mut body = ch.state_body(&p["commitment"], last - 1);
    body[1..5].copy_from_slice(&(last as u32).to_le_bytes());
    assert!(ch.open_raw(2, &body).await.is_err());
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_executor_loses_and_a_silent_challenger_loses() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| !p["rounds"].as_array().unwrap().is_empty()).unwrap();
    // The executor owes midpoints and stays silent.
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d = ch.open_raw(1, &body).await.unwrap();
    assert_eq!(ch.timeout(d).await, Err(custom(23)), "not before the deadline");
    ch.warp(PHASE_WINDOW + 5).await;
    ch.timeout(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_CHALLENGER);
    // The challenger owes a pick and stays silent.
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let d = ch.open_raw(1, &body).await.unwrap();
    let r = &p["rounds"][0];
    let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
    ch.midpoints(d, &mids).await.unwrap();
    ch.warp(PHASE_WINDOW + 5).await;
    assert!(ch.pick(d, 0).await.is_err(), "a late pick is refused");
    ch.timeout(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_parties_wrong_phases_and_wrong_midpoint_lists_are_refused() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| !p["rounds"].as_array().unwrap().is_empty()).unwrap();
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d = ch.open_raw(1, &body).await.unwrap();
    let r = &p["rounds"][0];
    let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
    // The challenger cannot post midpoints; the executor cannot pick.
    let i = ix(LX::SUB_LX_MIDPOINTS, &mids, ch.party(0xC1, d));
    assert!(send(&mut ch.ctx, i, &[&kp(0xC1)]).await.is_err());
    assert!(ch.pick(d, 0).await.is_err(), "no pick before midpoints");
    assert_eq!(ch.midpoints(d, &mids[..mids.len() - 32]).await, Err(custom(45)), "one root short");
    // Descent instructions do not act on an LX1 dispute.
    let i = ix(V::SUB_REVEAL_NODES, &mids, ch.party(0xE1, d));
    assert_eq!(send(&mut ch.ctx, i, &[&kp(0xE1)]).await, Err(custom(10)));
    ch.midpoints(d, &mids).await.unwrap();
    let i = ix(LX::SUB_LX_PICK, &[0], ch.party(0xE1, d));
    assert!(send(&mut ch.ctx, i, &[&kp(0xE1)]).await.is_err(), "the executor cannot pick");
    assert_eq!(ch.pick(d, 200).await, Err(custom(15)), "no such sub-interval");
    let i = ix(V::SUB_PICK, &[0], ch.party(0xC1, d));
    assert_eq!(send(&mut ch.ctx, i, &[&kp(0xC1)]).await, Err(custom(10)), "descent pick refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn output_claims_rule_like_python() {
    let g = golden();
    for o in g["outputs"].as_array().unwrap() {
        let mut ch = Chain::new(16, 100_000).await;
        ch.commit(&o["commitment"]).await.unwrap();
        let d = ch.open_raw(3, &[LX::KIND_LX_OUTPUT]).await.unwrap();
        // The final root with its path, then the opening of the output slots.
        // The executor's claimed values are never needed: only their digest.
        let roots = o["commitment"]["roots"].as_array().unwrap();
        let mut staged = h32(roots.last().unwrap()).to_vec();
        staged.extend(path(&ch.levels, ch.count - 1));
        staged.extend(encode_opening(&o["opening"]));
        ch.stage(d, V::ROLE_CHALLENGER, &staged).await;
        ch.output(d).await.unwrap();
        assert_eq!(ch.account(d).await.data[6], ruling_of(o["ruling"].as_str().unwrap()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_output_claimant_loses_its_bond() {
    let g = golden();
    let o = &g["outputs"][0];
    let mut ch = Chain::new(16, 100_000).await;
    ch.commit(&o["commitment"]).await.unwrap();
    let d = ch.open_raw(3, &[LX::KIND_LX_OUTPUT]).await.unwrap();
    ch.warp(PHASE_WINDOW + 5).await;
    let e0 = ch.lamports(kp(0xE1).pubkey()).await;
    ch.timeout(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
    assert_eq!(ch.lamports(kp(0xE1).pubkey()).await - e0, CHALLENGER_BOND);
}

// --- every ending: settlement and closes through the shared v2.1 paths -------------------

impl Chain {
    fn caller_ix(&self, sub: u8, extra: Vec<AccountMeta>) -> Instruction {
        let mut a = vec![AccountMeta::new_readonly(kp(0xB1).pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new_readonly(self.template, false)];
        a.extend(extra);
        ix(sub, &[], a)
    }

    async fn by_bystander(&mut self, i: Instruction) -> Result<(), TransactionError> {
        send(&mut self.ctx, i, &[&kp(0xB1)]).await
    }

    async fn play(&mut self, nonce: u8, p: &serde_json::Value) -> Pubkey {
        let body = self.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
        let d = self.open_raw(nonce, &body).await.unwrap();
        self.drive(d, p).await;
        d
    }

    async fn drive(&mut self, d: Pubkey, p: &serde_json::Value) {
        for r in p["rounds"].as_array().unwrap() {
            let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
            self.midpoints(d, &mids).await.unwrap();
            self.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap();
        }
        self.stage(d, V::ROLE_EXECUTOR, &encode_replay(&p["opening"])).await;
        self.opening(d).await.unwrap();
    }

    async fn close_dispute(&mut self, d: Pubkey) -> Result<(), TransactionError> {
        let (be, bc) = (self.buffer(d, V::ROLE_EXECUTOR), self.buffer(d, V::ROLE_CHALLENGER));
        let i = self.caller_ix(V::SUB_CLOSE_DISPUTE, vec![AccountMeta::new(d, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xE1).pubkey(), false), AccountMeta::new(be, false), AccountMeta::new(bc, false)]);
        self.by_bystander(i).await
    }

    async fn close_run(&mut self) -> Result<(), TransactionError> {
        let s = kp(0xB1);
        let i = ix(V::SUB_CLOSE_RUN, &[], vec![AccountMeta::new(s.pubkey(), true), AccountMeta::new(self.run, false), AccountMeta::new(self.template, false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
        send(&mut self.ctx, i, &[&s]).await
    }

    async fn close_template(&mut self) -> Result<(), TransactionError> {
        let a = kp(0xA1);
        let i = ix(V::SUB_CLOSE_TEMPLATE, &[], vec![AccountMeta::new(a.pubkey(), true), AccountMeta::new(self.template, false)]);
        send(&mut self.ctx, i, &[&a]).await
    }

    async fn balances(&mut self, keys: &[Pubkey]) -> Vec<u64> {
        let mut v = Vec::new();
        for k in keys {
            v.push(self.lamports(*k).await);
        }
        v
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lying_executor_is_convicted_later_disputes_are_moot_and_every_account_closes() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "C").unwrap();
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let parties = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), kp(0xB1).pubkey()];
    let mut tracked: Vec<Pubkey> = parties.to_vec();
    tracked.extend([ch.run, ch.template]);
    let before = ch.balances(&parties).await;
    let total_before: u64 = ch.balances(&tracked).await.iter().sum();
    // Two disputes on the same lie: sequence 0 wins; sequence 1 is then moot.
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    let d_first = ch.open_raw(1, &body).await.unwrap();
    let d_late = ch.open_raw(2, &body).await.unwrap();
    ch.drive(d_first, p).await;
    assert_eq!(ch.account(d_first).await.data[6], V::RULING_CHALLENGER);
    assert!(ch.open_raw(3, &body).await.is_err(), "no new opens on a refuted run");
    // The later dispute is moot: anyone may rule it, the challenger's bond returns.
    let i = ch.caller_ix(V::SUB_MOOT, vec![AccountMeta::new(d_late, false), AccountMeta::new(kp(0xC1).pubkey(), false)]);
    ch.by_bystander(i).await.unwrap();
    assert_eq!(ch.account(d_late).await.data[6], V::RULING_MOOT);
    for d in [d_first, d_late] {
        let i = ch.caller_ix(V::SUB_ADVANCE, vec![AccountMeta::new_readonly(d, false)]);
        ch.by_bystander(i).await.unwrap();
    }
    assert!(ch.close_dispute(d_first).await.is_err(), "the best win closes only after the pot");
    let i = ch.caller_ix(V::SUB_PAY_POT, vec![AccountMeta::new_readonly(d_first, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
    ch.by_bystander(i).await.unwrap();
    let i = ch.caller_ix(V::SUB_PAY_POT, vec![AccountMeta::new_readonly(d_first, false), AccountMeta::new(kp(0xC1).pubkey(), false), AccountMeta::new(kp(0xA1).pubkey(), false)]);
    assert!(ch.by_bystander(i).await.is_err(), "the pot pays once");
    for d in [d_first, d_late] {
        ch.close_dispute(d).await.unwrap();
        assert!(ch.close_dispute(d).await.is_err(), "a second close");
    }
    ch.close_run().await.unwrap();
    ch.close_template().await.unwrap();
    let after = ch.balances(&parties).await;
    let total_after: u64 = ch.balances(&tracked).await.iter().sum::<u64>() - ch.lamports(ch.run).await;
    let receipt = ch.lamports(ch.run).await;
    // Conservation: everything that left the tracked accounts is the receipt's rent.
    assert_eq!(total_before, total_after + receipt, "lamports conserved");
    let share = EXECUTOR_BOND / 2; // slasher_bps 5,000
    assert_eq!(after[2], before[2] + share, "the honest challenger gains the slasher share, all rent back");
    assert_eq!(after[1], before[1], "the lying executor's bond was already in the run");
    assert_eq!(after[3], before[3], "the bystander gains nothing");
    // The payer started the window owning the run and template balances (their
    // rent plus the executor's bond); it ends with them, less the receipt's rent
    // and the challenger's slasher share.
    let held = total_before - before.iter().sum::<u64>();
    assert_eq!(after[0] + receipt + share, before[0] + held, "the payer gets the remainder and all rent but the receipt's");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_honest_executor_beats_a_false_challenge_finalizes_and_closes() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E").unwrap();
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 3_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    let parties = [kp(0xA1).pubkey(), kp(0xE1).pubkey(), kp(0xC1).pubkey(), kp(0xB1).pubkey()];
    let before = ch.balances(&parties).await;
    let d = ch.play(1, p).await;
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
    let fin = |ch: &Chain| ch.caller_ix(V::SUB_FINALIZE, vec![AccountMeta::new(kp(0xE1).pubkey(), false)]);
    let i = fin(&ch);
    assert!(ch.by_bystander(i).await.is_err(), "not before the challenge window ends");
    ch.warp(3_100).await;
    let i = fin(&ch);
    ch.by_bystander(i).await.unwrap();
    assert_eq!(ch.account(ch.run).await.data[4], V::RUN_FINAL);
    let i = ch.caller_ix(V::SUB_ADVANCE, vec![AccountMeta::new_readonly(d, false)]);
    ch.by_bystander(i).await.unwrap();
    ch.close_dispute(d).await.unwrap();
    ch.close_run().await.unwrap();
    let after = ch.balances(&parties).await;
    assert_eq!(after[1], before[1] + EXECUTOR_BOND + CHALLENGER_BOND, "the honest executor gets its bond back and the challenger's");
    assert_eq!(before[2] - after[2], CHALLENGER_BOND, "the false challenger loses exactly its bond; all rent back");
    assert_eq!(after[3], before[3], "the bystander gains nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_executor_cannot_commit_inputs_the_payer_did_not_admit() {
    // Review H1 (probe RV-P1 reversed): the payer initialized the run with a
    // different input id, so a commit binding these parameters is refused.
    let g = golden();
    let p = &g["plays"][0];
    let mut ch = Chain::new_with_input(p["arity"].as_u64().unwrap() as u8, 100_000, Some([7u8; 32])).await;
    assert_eq!(ch.commit(&p["commitment"]).await, Err(custom(7)));
}

#[tokio::test(flavor = "multi_thread")]
async fn withheld_false_outputs_are_convicted_from_the_opening_alone() {
    // Review H2 (probe RV-P2 reversed): the executor commits the digest of
    // false outputs and never publishes them; the challenger opens the true
    // output slots against R_T and wins.
    let g = golden();
    let lie = g["outputs"].as_array().unwrap().iter().find(|o| o["ruling"] == "C").unwrap();
    let mut ch = Chain::new(16, 100_000).await;
    ch.commit(&lie["commitment"]).await.unwrap();
    let d = ch.open_raw(3, &[LX::KIND_LX_OUTPUT]).await.unwrap();
    let roots = lie["commitment"]["roots"].as_array().unwrap();
    let mut staged = h32(roots.last().unwrap()).to_vec();
    staged.extend(path(&ch.levels, ch.count - 1));
    staged.extend(encode_opening(&lie["opening"]));
    ch.stage(d, V::ROLE_CHALLENGER, &staged).await;
    let c0 = ch.lamports(kp(0xC1).pubkey()).await;
    ch.output(d).await.unwrap();
    assert_eq!(ch.account(d).await.data[6], V::RULING_CHALLENGER);
    assert_eq!(ch.lamports(kp(0xC1).pubkey()).await - c0, CHALLENGER_BOND);
}

// --- generated-scenario fuzz campaign (scripts/disputes_v21_lx_fuzz.py) ----------------------

impl Chain {
    /// A template and run for one generated play: its machine parameters,
    /// constants root, arity and LX1 bounds all come from the play.
    async fn for_play(p: &serde_json::Value) -> Self {
        let m = &p["machine"];
        let t = &p["template"];
        let bounds = Bounds(t["k_min"].as_u64().unwrap() as u32, t["k_max"].as_u64().unwrap() as u32, t["max_positions"].as_u64().unwrap());
        let params = hex(m["params"].as_str().unwrap());
        Self::new_full(t["arity"].as_u64().unwrap() as u8, 100_000, None, params, h32(&m["constants_root"]), bounds, m["positions"].as_u64().unwrap()).await
    }

    /// Everything a refused submission must leave unchanged.
    async fn snapshot(&mut self, d: Pubkey) -> (Vec<u8>, Vec<u8>, u64, u64, u64) {
        let (dd, rr) = (self.account(d).await, self.account(self.run).await);
        (dd.data, rr.data, dd.lamports + rr.lamports, self.lamports(kp(0xE1).pubkey()).await, self.lamports(kp(0xC1).pubkey()).await)
    }
}

/// splitmix64, for the byte-level mutations (no dependency).
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Malformed variants of a staged submission: the play's structured
/// mutations (each refused by the Python reference), then two single-byte
/// flips and one truncation of the good bytes. A flip changes a hashed value,
/// a length or a count, and a truncation drops a nonzero byte, so none of
/// them can decode to an opening that verifies.
fn malformed(p: &serde_json::Value, good: &[u8], encode: &dyn Fn(&serde_json::Value) -> Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = p["mutations"].as_array().unwrap().iter().map(|m| (m["kind"].as_str().unwrap().to_string(), encode(&m["opening"]))).collect();
    let mut rng = Mix(p["raw_seed"].as_u64().unwrap_or(p["index"].as_u64().unwrap()));
    for _ in 0..2 {
        let mut b = good.to_vec();
        let i = rng.below(b.len());
        b[i] ^= 1 + rng.below(255) as u8;
        out.push((format!("flip byte {i}"), b));
    }
    if let Some(last) = good.iter().rposition(|&x| x != 0) {
        let cut = rng.below(last + 1);
        out.push((format!("truncate at {cut}"), good[..cut].to_vec()));
    }
    out
}

/// Stage each malformed variant over the whole used prefix (zero padded, so
/// no earlier bytes survive) and check it is refused with nothing changed;
/// then restage the good bytes.
async fn refuse_all(ch: &mut Chain, d: Pubkey, role: u8, good: &[u8], bad: &[(String, Vec<u8>)], name: &str, output: bool) -> usize {
    let mut used = good.len();
    let before = ch.snapshot(d).await;
    for (kind, bytes) in bad {
        assert!(bytes.len() <= V::CREATE_STAGE, "{name}: {kind} fits the buffer");
        let mut padded = bytes.clone();
        padded.resize(used.max(bytes.len()), 0);
        used = padded.len();
        ch.write(d, role, 0, &padded).await.unwrap();
        let r = if output { ch.output(d).await } else { ch.opening(d).await };
        assert!(r.is_err(), "{name}: malformed opening ({kind}) was accepted");
        assert!(ch.snapshot(d).await == before, "{name}: malformed opening ({kind}) changed state");
    }
    let mut padded = good.to_vec();
    padded.resize(used, 0);
    ch.write(d, role, 0, &padded).await.unwrap();
    bad.len()
}

async fn fuzz_state(ch: &mut Chain, p: &serde_json::Value, name: &str) -> usize {
    let d = to_leaf(ch, p, name).await;
    let good = encode_replay(&p["opening"]);
    ch.stage(d, V::ROLE_EXECUTOR, &good).await;
    let bad = malformed(p, &good, &encode_replay);
    let n = refuse_all(ch, d, V::ROLE_EXECUTOR, &good, &bad, name, false).await;
    rule_and_check(ch, d, p, name, false).await;
    n
}

async fn fuzz_output(ch: &mut Chain, p: &serde_json::Value, name: &str) -> usize {
    ch.commit(&p["commitment"]).await.unwrap_or_else(|e| panic!("{name}: commit {e:?}"));
    let d = ch.open_raw(3, &[LX::KIND_LX_OUTPUT]).await.unwrap_or_else(|e| panic!("{name}: open {e:?}"));
    let roots = p["commitment"]["roots"].as_array().unwrap();
    let mut head = h32(roots.last().unwrap()).to_vec();
    head.extend(path(&ch.levels, ch.count - 1));
    let encode = |o: &serde_json::Value| {
        let mut v = head.clone();
        v.extend(encode_opening(o));
        v
    };
    let good = encode(&p["opening"]);
    ch.stage(d, V::ROLE_CHALLENGER, &good).await;
    let bad = malformed(p, &good, &encode);
    let n = refuse_all(ch, d, V::ROLE_CHALLENGER, &good, &bad, name, true).await;
    rule_and_check(ch, d, p, name, true).await;
    n
}

/// One generated play through the program; returns the malformed openings refused.
async fn fuzz_play(p: serde_json::Value) -> usize {
    let name = format!("seed {} index {}: {}", p["seed"], p["index"], p["name"].as_str().unwrap());
    let mut ch = Chain::for_play(&p).await;
    match p["kind"].as_str().unwrap() {
        "state" => fuzz_state(&mut ch, &p, &name).await,
        "output" => fuzz_output(&mut ch, &p, &name).await,
        k => panic!("{name}: unknown kind {k}"),
    }
}

/// The fuzz campaign: every generated play through the program, its ruling
/// and bond movement as the Python reference rules, and its malformed
/// openings refused without changing state. Plays come from
/// `PYTHONPATH=python python3 scripts/disputes_v21_lx_fuzz.py --seed S --count N`;
/// run with `LX_FUZZ_PLAYS=<file>[,<file>...] cargo test ... -- --ignored lx_fuzz`.
/// Each play has its own ProgramTest bank; `LX_FUZZ_JOBS` (default 12) of
/// them run at once, since each mostly waits for new blockhashes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "fuzz campaign; needs LX_FUZZ_PLAYS"]
async fn lx_fuzz_plays_rule_like_python() {
    let files = std::env::var("LX_FUZZ_PLAYS").expect("LX_FUZZ_PLAYS=<plays.json>[,...]");
    let jobs: usize = std::env::var("LX_FUZZ_JOBS").ok().map_or(12, |j| j.parse().unwrap());
    let mut all = Vec::new();
    for file in files.split(',') {
        let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        all.extend(data["plays"].as_array().unwrap().iter().cloned());
    }
    let rulings_c = all.iter().filter(|p| p["ruling"] == "C").count();
    let (plays, mut refused) = (all.len(), 0usize);
    let mut set = tokio::task::JoinSet::new();
    let mut queue = all.into_iter();
    loop {
        while set.len() < jobs {
            match queue.next() {
                Some(p) => {
                    set.spawn(fuzz_play(p));
                }
                None => break,
            }
        }
        match set.join_next().await {
            Some(Ok(n)) => refused += n,
            Some(Err(e)) => std::panic::resume_unwind(e.into_panic()),
            None => break,
        }
    }
    eprintln!("lx fuzz: {plays} plays ({} E, {rulings_c} C), {refused} malformed openings refused", plays - rulings_c);
}

// --- staged open (owner decision 8a, 2026-10-04) -----------------------------------------------

/// Every golden play, opened from a staged body instead of an inline one,
/// reaches the same terminal coordinate and the same ruling and bond movement.
#[tokio::test(flavor = "multi_thread")]
async fn staged_opens_rule_like_inline_opens_in_both_role_orders() {
    let g = golden();
    for p in g["plays"].as_array().unwrap() {
        let name = p["name"].as_str().unwrap();
        let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
        ch.commit(&p["commitment"]).await.unwrap_or_else(|e| panic!("{name}: commit {e:?}"));
        let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
        ch.prestage_body(1, &body[1..]).await.unwrap_or_else(|e| panic!("{name}: prestage {e:?}"));
        let d = ch.open_staged(1).await.unwrap_or_else(|e| panic!("{name}: staged open {e:?}"));
        let buffer = ch.account(ch.buffer(d, V::ROLE_CHALLENGER)).await;
        assert_eq!(&buffer.data[40..44], &[0; 4], "{name}: staged length reset at open");
        for r in p["rounds"].as_array().unwrap() {
            let mids: Vec<u8> = r["midpoints"].as_array().unwrap().iter().flat_map(h32).collect();
            ch.midpoints(d, &mids).await.unwrap_or_else(|e| panic!("{name}: midpoints {e:?}"));
            ch.pick(d, r["pick"].as_u64().unwrap() as u8).await.unwrap_or_else(|e| panic!("{name}: pick {e:?}"));
        }
        let dd = ch.account(d).await.data;
        assert_eq!(u64::from_le_bytes(dd[16..24].try_into().unwrap()), p["terminal"].as_u64().unwrap(), "{name}: terminal coordinate");
        ch.stage(d, V::ROLE_EXECUTOR, &encode_replay(&p["opening"])).await;
        rule_and_check(&mut ch, d, p, name, false).await;
    }
}

/// Staging before the open is the challenger's alone, only for an unopened
/// dispute of a committed run in its window; a staged body is checked exactly
/// like an inline one and only with the open's secret; an unused buffer closes
/// with its rent to the challenger, by the challenger at any time or by anyone
/// once the run cannot be disputed, so it never strands (review 10-05).
#[tokio::test(flavor = "multi_thread")]
async fn staged_open_refusals_and_close() {
    let g = golden();
    let p = &g["plays"][0];
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 100_000).await;
    let size = (V::CREATE_STAGE as u32).to_le_bytes();
    // Before commit: no dispute can open, so no staging (9).
    let d1 = ch.dispute(1);
    assert_eq!(ch.prestage(0xC1, 1, d1, 0, &size).await, Err(custom(9)));
    ch.commit(&p["commitment"]).await.unwrap();
    // A dispute address that is not the signer's (the executor signing for
    // the challenger's dispute) is refused (2), for create and write.
    assert_eq!(ch.prestage(0xE1, 1, d1, 0, &size).await, Err(custom(2)));
    assert_eq!(ch.prestage(0xE1, 1, d1, 1, &[0, 0, 0, 0, 1]).await, Err(custom(2)));
    // Oversized and malformed creates (29); an unknown op (29).
    assert_eq!(ch.prestage(0xC1, 1, d1, 0, &((V::CREATE_STAGE + 1) as u32).to_le_bytes()).await, Err(custom(29)));
    assert_eq!(ch.prestage(0xC1, 1, d1, 3, &[]).await, Err(custom(29)));
    // Writing, closing or opening from a buffer that does not exist is refused.
    assert!(ch.prestage(0xC1, 1, d1, 1, &[0, 0, 0, 0, 1]).await.is_err());
    assert!(ch.prestage(0xC1, 1, d1, 2, &[]).await.is_err());
    assert!(ch.open_staged(1).await.is_err());
    // A staged body with a root that is not committed is refused (44), as inline.
    let mut body = ch.state_body(&p["commitment"], 0);
    body[5] ^= 1;
    ch.prestage_body(1, &body[1..]).await.unwrap();
    assert_eq!(ch.open_staged(1).await.err(), Some(custom(44)));
    // A bystander cannot close a buffer whose run is still disputable (37).
    assert_eq!(ch.prestage(0xB1, 1, d1, 2, &[]).await, Err(custom(37)));
    // The challenger closes it at any time; its rent returns to the challenger.
    let buffer = ch.buffer(d1, V::ROLE_CHALLENGER);
    let (c0, b0) = (ch.lamports(kp(0xC1).pubkey()).await, ch.lamports(buffer).await);
    assert!(b0 > 0);
    ch.prestage(0xC1, 1, d1, 2, &[]).await.unwrap();
    assert_eq!((ch.lamports(buffer).await, ch.lamports(kp(0xC1).pubkey()).await - c0), (0, b0));
    // The right body with the wrong secret does not open.
    let good = ch.state_body(&p["commitment"], 0);
    ch.prestage_body(2, &good[1..]).await.unwrap();
    assert!(ch.open_staged_with(2, [7; 32]).await.is_err(), "wrong secret");
    // The staged bytes are not the body (masked).
    let staged = ch.account(ch.buffer(ch.dispute(2), V::ROLE_CHALLENGER)).await.data;
    assert_ne!(&staged[48..48 + good.len() - 1], &good[1..], "staged bytes are masked");
    // After an open, pre-open staging is refused (37): the dispute's own
    // staging ops apply.
    let d2 = ch.open_staged(2).await.unwrap();
    assert_eq!(ch.prestage(0xC1, 2, d2, 2, &[]).await, Err(custom(37)));
    assert_eq!(ch.prestage(0xC1, 2, d2, 1, &[0, 0, 0, 0, 1]).await, Err(custom(37)));
    // After the challenge window, no new staging (9).
    ch.warp(100_001).await;
    assert_eq!(ch.prestage(0xC1, 3, ch.dispute(3), 0, &size).await, Err(custom(9)));
}

/// A buffer staged for a dispute that never opens does not strand when the
/// run settles and closes into a receipt: anyone closes it then, rent to the
/// challenger; and a dispute opened from staging closes with its buffer's
/// rent to the challenger (review 10-05).
#[tokio::test(flavor = "multi_thread")]
async fn staged_buffers_never_strand() {
    let g = golden();
    let p = g["plays"].as_array().unwrap().iter().find(|p| p["ruling"] == "E").unwrap();
    let mut ch = Chain::new(p["arity"].as_u64().unwrap() as u8, 3_000).await;
    ch.commit(&p["commitment"]).await.unwrap();
    // Dispute 1 opens from staging and plays to the executor's win.
    let body = ch.state_body(&p["commitment"], p["pair"].as_u64().unwrap() as usize);
    ch.prestage_body(1, &body[1..]).await.unwrap();
    let d = ch.open_staged(1).await.unwrap();
    ch.drive(d, p).await;
    assert_eq!(ch.account(d).await.data[6], V::RULING_EXECUTOR);
    // Dispute 2 is staged and never opened.
    ch.prestage_body(2, &body[1..]).await.unwrap();
    let stranded = ch.buffer(ch.dispute(2), V::ROLE_CHALLENGER);
    let rent = ch.lamports(stranded).await;
    ch.warp(3_100).await;
    let i = ch.caller_ix(V::SUB_FINALIZE, vec![AccountMeta::new(kp(0xE1).pubkey(), false)]);
    ch.by_bystander(i).await.unwrap();
    let i = ch.caller_ix(V::SUB_ADVANCE, vec![AccountMeta::new_readonly(d, false)]);
    ch.by_bystander(i).await.unwrap();
    // The opened dispute's buffer closes with the dispute, rent to the challenger.
    let opened = ch.buffer(d, V::ROLE_CHALLENGER);
    let (c0, b0) = (ch.lamports(kp(0xC1).pubkey()).await, ch.lamports(opened).await);
    assert!(b0 > 0);
    ch.close_dispute(d).await.unwrap();
    assert_eq!(ch.lamports(opened).await, 0);
    assert!(ch.lamports(kp(0xC1).pubkey()).await - c0 >= b0, "the staged buffer's rent returns with the dispute");
    // The run closes into a receipt with the unopened buffer still there.
    ch.close_run().await.unwrap();
    assert_eq!(&ch.account(ch.run).await.data[0..4], b"D21P");
    let c1 = ch.lamports(kp(0xC1).pubkey()).await;
    ch.prestage(0xB1, 2, ch.dispute(2), 2, &[]).await.unwrap();
    assert_eq!((ch.lamports(stranded).await, ch.lamports(kp(0xC1).pubkey()).await - c1), (0, rent));
}

/// The staged-open mask agrees with the Python client's (`lx_client.prestage_mask`,
/// secret 0x11 x 32, dispute 0x22 x 32, bytes 0..70).
#[test]
fn prestage_mask_matches_python() {
    let mut b: Vec<u8> = (0u8..70).collect();
    LX::prestage_mask(&[0x11; 32], &Pubkey::new_from_array([0x22; 32]), &mut b);
    assert_eq!(hex_of(&b), "c8573628a73cb18e957c7bce105933e989a47f152d9e5094e3a4ac80a7670e77c8a2597389c8acfda18f1bd640ea9dc94c312e06be4b97c26c6116983ea5a970e292cda41b03");
}
