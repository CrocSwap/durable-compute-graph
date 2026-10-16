// SPDX-License-Identifier: GPL-3.0-only

//! Mode results v1 (design `docs/design/mode-results-v1.md`): one result
//! reference for every resolution mode.
//!
//! A finished computation, in whatever mode, is read into the same 256-byte
//! [`ResultRef`]: its mode, the program and account it was read from, a
//! commitment to its values and how that commitment opens, and a body that
//! says what was computed and what the result's security rests on. A
//! consumer reads results one way ([`ResultRef::require`], the openings)
//! whichever mode produced them, and a later mode (sampling, Freivalds, ZK)
//! adds a producer, not a new reader for each pair of modes.
//!
//! Producers in v1:
//! - optimistic: a v2.1 run that is `FINAL`, live or as its receipt, read with
//!   its template ([`read_run_result`]);
//! - consensus: a session its kernel halted, with its final state sealed
//!   (`stateful::v3::read_session_result`).
//!
//! Every reader is CPI-free and works on chain and on a client. A result is
//! only as trustworthy as the host program's image and upgrade authority
//! (`dcg verify`); [`ResultRef::basis`] reports that with the mode's own
//! assumptions. A consumer that needs a result after its source accounts close
//! copies the 256 bytes into its own account when it first reads them.

extern crate alloc;

use crate::kernel::{KernelId, VersionedId};
use dcg_disputes as D;
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

pub const RESULT_BYTES: usize = 256;
pub const RESULT_MAGIC: &[u8; 4] = b"DRR1";
pub const RESULT_VERSION: u16 = 1;
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"dcg.result.v1\0";

pub const MODE_CONSENSUS: u8 = 1;
pub const MODE_OPTIMISTIC: u8 = 2;

/// One output opens against the v2.1 out tree (`root` = `out_tree_root`).
pub const SCHEME_OUT_TREE_V21: u8 = 1;
/// Every output slot rehashes to an LX1 `outputs_digest`.
pub const SCHEME_LX_OUTPUTS_V1: u8 = 2;
/// The whole final state rehashes to a session seal.
pub const SCHEME_STATE_SEAL_V1: u8 = 3;

pub const SEAL_INIT_DOMAIN: &[u8] = b"dcg/state-seal-init/1";
pub const SEAL_CHUNK_DOMAIN: &[u8] = b"dcg/state-seal-chunk/1";
pub const SEAL_DOMAIN: &[u8] = b"dcg/state-seal/1";
/// The seal hashes the state in chunks of this size (the anchor chunk).
pub const SEAL_CHUNK_BYTES: usize = 65_536;

const BODY: usize = 112;

// The v2.1 run read layout (`docs/spec/run-read-layout-v21.md`).
const RUN_STATUS: usize = 4;
const RUN_VERSION: usize = 5;
const RUN_TEMPLATE: usize = 8;
const RUN_PAYER: usize = 40;
const RUN_ID: usize = 104;
const RUN_N_EXT: usize = 156;
const RUN_LIVE_ROOT: usize = 192;
const RUN_RECEIPT_ROOT: usize = 136;
const RUN_ROOT_BYTES: usize = D::RUN_ROOT_BYTES;
const RECEIPT_BYTES: usize = 136 + RUN_ROOT_BYTES;
/// `D21Q`: a `D21P` plus template_id, kind, 3 zero bytes and the template's
/// windows and bonds (pipelines design §3.4 A).
const RECEIPT_V2_BYTES: usize = RECEIPT_BYTES + 68;
const RUN_FINAL: u8 = 2;
const RUN_SEED: &[u8] = b"dcg21run";
// The template (`D21T`) fields a result reads.
const TEMPLATE_KIND: usize = 5;
const TEMPLATE_KIND_LX: u8 = 1;
const TEMPLATE_CHALLENGE_WINDOW: usize = 24;
const TEMPLATE_PHASE_WINDOW: usize = 32;
const TEMPLATE_EXECUTOR_BOND: usize = 40;
const TEMPLATE_CHALLENGER_BOND: usize = 48;
const TEMPLATE_ID: usize = 96;
const TEMPLATE_MIN_BYTES: usize = 168;

/// Why bytes are not a result, or a result is not the one required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultError {
    /// An account is not owned by the named host program.
    Owner,
    /// Not the expected account form, or a malformed `ResultRef`.
    Layout,
    /// The account is not at the address its record derives.
    Address,
    /// The template account is not the run's template.
    Template,
    /// The run is not `FINAL` (open, committed or refuted).
    NotFinal,
    /// The session has not halted.
    NotHalted,
    /// The session was halted by its authority, not its kernel.
    NoKernelVerdict,
    /// The session's final state is not sealed.
    NotSealed,
    /// A requirement does not hold: the mode.
    Mode,
    /// A requirement does not hold: what was computed (template, kernel, schema).
    Computation,
    /// A requirement does not hold: which instance (source, run id).
    Instance,
    /// A requirement does not hold: the halt reason.
    Reason,
    /// A requirement does not hold: the resource commitment.
    Resource,
    /// A requirement does not hold: the challenge window or bond.
    Security,
    /// An opening does not match the result's root.
    Opening,
    /// A state span or the resource copy of the sealed session has closed:
    /// read a session's result before its state is cleaned up.
    Trimmed,
}

/// What an optimistic (v2.1) result's body records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptimisticBody {
    pub template_id: [u8; 32],
    pub run_id: [u8; 32],
    /// Generic root: `spec_root`. LX1: `params_digest`.
    pub root_aux: [u8; 32],
    pub challenge_window: u64,
    pub phase_window: u64,
    pub executor_bond: u64,
    pub challenger_bond: u64,
    /// Generic root: `total_steps`. LX1: `positions`.
    pub steps: u64,
}

/// What a consensus (session) result's body records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusBody {
    pub kernel_id: KernelId,
    pub semantic_version: u16,
    pub abi_version: u16,
    pub state_schema: VersionedId,
    pub resource_schema: VersionedId,
    pub features: u8,
    pub halt_reason: u32,
    pub halt_cursor: u32,
    pub input_root: [u8; 32],
    pub stream_root: [u8; 32],
    pub resource_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    Optimistic(OptimisticBody),
    Consensus(ConsensusBody),
}

/// A finished computation's result, in any mode (design §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultRef {
    pub scheme: u8,
    /// The program that holds the source account.
    pub host: Pubkey,
    /// The account the result was read from.
    pub source: Pubkey,
    /// The commitment to the result's values, opened per `scheme`.
    pub root: [u8; 32],
    /// Values under `root`: outputs (out tree), or state bytes (seal).
    pub count: u64,
    pub body: Body,
}

/// What a consumer requires of a result; `None` leaves a field unchecked.
/// An optimistic-only requirement on a consensus result (or the reverse)
/// fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResultRequirements {
    pub mode: Option<u8>,
    pub source: Option<Pubkey>,
    /// Optimistic: the template id; the run id (which binds the executor,
    /// nonce and external inputs); `root_aux` (an LX1 run's parameters
    /// digest, which the template does not fix); and the least windows and
    /// bonds the consumer accepts.
    pub template_id: Option<[u8; 32]>,
    pub run_id: Option<[u8; 32]>,
    pub root_aux: Option<[u8; 32]>,
    pub min_challenge_window: Option<u64>,
    pub min_phase_window: Option<u64>,
    pub min_executor_bond: Option<u64>,
    pub min_challenger_bond: Option<u64>,
    /// Consensus: the kernel and its versions, the state schema, the halt
    /// reason, the resource schema and commitment, and the input chain and
    /// stream roots (which tell two sessions at one reused address apart).
    pub kernel: Option<(KernelId, u16, u16)>,
    pub state_schema: Option<VersionedId>,
    pub halt_reason: Option<u32>,
    pub resource_schema: Option<VersionedId>,
    pub resource_commitment: Option<[u8; 32]>,
    pub input_root: Option<[u8; 32]>,
    pub stream_root: Option<[u8; 32]>,
}

/// What a result's security rests on (design §5): always the host program,
/// then the mode's own assumptions. Not a single scalar: a composed output's
/// basis is the union over its ancestry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// Every step ran on chain in `host`.
    ChainExecution { host: Pubkey },
    /// The challenge window passed with no successful challenge: an honest,
    /// live challenger, the windows and the bonds.
    Optimistic {
        host: Pubkey,
        challenge_window: u64,
        phase_window: u64,
        executor_bond: u64,
        challenger_bond: u64,
    },
}

struct Hasher;
impl D::Sha256 for Hasher {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        crate::hash::sha256(parts)
    }
}

fn u16_at(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(d[at..at + 2].try_into().expect("fixed width"))
}
fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().expect("fixed width"))
}
fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().expect("fixed width"))
}
fn key_at(d: &[u8], at: usize) -> [u8; 32] {
    d[at..at + 32].try_into().expect("fixed width")
}

impl ResultRef {
    pub fn mode(&self) -> u8 {
        match self.body {
            Body::Consensus(_) => MODE_CONSENSUS,
            Body::Optimistic(_) => MODE_OPTIMISTIC,
        }
    }

    /// The canonical 256 bytes (design §2).
    pub fn encode(&self) -> [u8; RESULT_BYTES] {
        let mut out = [0u8; RESULT_BYTES];
        out[0..4].copy_from_slice(RESULT_MAGIC);
        out[4..6].copy_from_slice(&RESULT_VERSION.to_le_bytes());
        out[6] = self.mode();
        out[7] = self.scheme;
        out[8..40].copy_from_slice(self.host.as_ref());
        out[40..72].copy_from_slice(self.source.as_ref());
        out[72..104].copy_from_slice(&self.root);
        out[104..112].copy_from_slice(&self.count.to_le_bytes());
        let b = &mut out[BODY..];
        match &self.body {
            Body::Optimistic(o) => {
                b[0..32].copy_from_slice(&o.template_id);
                b[32..64].copy_from_slice(&o.run_id);
                b[64..96].copy_from_slice(&o.root_aux);
                b[96..104].copy_from_slice(&o.challenge_window.to_le_bytes());
                b[104..112].copy_from_slice(&o.phase_window.to_le_bytes());
                b[112..120].copy_from_slice(&o.executor_bond.to_le_bytes());
                b[120..128].copy_from_slice(&o.challenger_bond.to_le_bytes());
                b[128..136].copy_from_slice(&o.steps.to_le_bytes());
            }
            Body::Consensus(c) => {
                b[0..16].copy_from_slice(&c.kernel_id.0);
                b[16..18].copy_from_slice(&c.semantic_version.to_le_bytes());
                b[18..20].copy_from_slice(&c.abi_version.to_le_bytes());
                b[20..24].copy_from_slice(&c.state_schema.id.to_le_bytes());
                b[24..26].copy_from_slice(&c.state_schema.version.to_le_bytes());
                b[26..30].copy_from_slice(&c.resource_schema.id.to_le_bytes());
                b[30..32].copy_from_slice(&c.resource_schema.version.to_le_bytes());
                b[32] = c.features;
                b[36..40].copy_from_slice(&c.halt_reason.to_le_bytes());
                b[40..44].copy_from_slice(&c.halt_cursor.to_le_bytes());
                b[48..80].copy_from_slice(&c.input_root);
                b[80..112].copy_from_slice(&c.stream_root);
                b[112..144].copy_from_slice(&c.resource_commitment);
            }
        }
        out
    }

    /// Parse canonical bytes, refusing anything [`encode`](Self::encode)
    /// would not produce (an unknown mode or scheme, a scheme the mode does
    /// not use, nonzero padding).
    pub fn decode(raw: &[u8]) -> Result<Self, ResultError> {
        if raw.len() != RESULT_BYTES || &raw[0..4] != RESULT_MAGIC || u16_at(raw, 4) != RESULT_VERSION {
            return Err(ResultError::Layout);
        }
        let (mode, scheme) = (raw[6], raw[7]);
        let b = &raw[BODY..];
        let body = match (mode, scheme) {
            (MODE_OPTIMISTIC, SCHEME_OUT_TREE_V21 | SCHEME_LX_OUTPUTS_V1) => {
                if b[136..144].iter().any(|x| *x != 0) || (scheme == SCHEME_LX_OUTPUTS_V1 && u64_at(raw, 104) != 0) {
                    return Err(ResultError::Layout);
                }
                Body::Optimistic(OptimisticBody {
                    template_id: key_at(b, 0),
                    run_id: key_at(b, 32),
                    root_aux: key_at(b, 64),
                    challenge_window: u64_at(b, 96),
                    phase_window: u64_at(b, 104),
                    executor_bond: u64_at(b, 112),
                    challenger_bond: u64_at(b, 120),
                    steps: u64_at(b, 128),
                })
            }
            (MODE_CONSENSUS, SCHEME_STATE_SEAL_V1) => {
                if b[33..36].iter().any(|x| *x != 0) || b[44..48].iter().any(|x| *x != 0) {
                    return Err(ResultError::Layout);
                }
                Body::Consensus(ConsensusBody {
                    kernel_id: KernelId(b[0..16].try_into().expect("fixed width")),
                    semantic_version: u16_at(b, 16),
                    abi_version: u16_at(b, 18),
                    state_schema: VersionedId { id: u32_at(b, 20), version: u16_at(b, 24) },
                    resource_schema: VersionedId { id: u32_at(b, 26), version: u16_at(b, 30) },
                    features: b[32],
                    halt_reason: u32_at(b, 36),
                    halt_cursor: u32_at(b, 40),
                    input_root: key_at(b, 48),
                    stream_root: key_at(b, 80),
                    resource_commitment: key_at(b, 112),
                })
            }
            _ => return Err(ResultError::Layout),
        };
        Ok(ResultRef {
            scheme,
            host: Pubkey::new_from_array(key_at(raw, 8)),
            source: Pubkey::new_from_array(key_at(raw, 40)),
            root: key_at(raw, 72),
            count: u64_at(raw, 104),
            body,
        })
    }

    /// `SHA256("dcg.result.v1\0" || encode())`: what another mode commits to
    /// when it takes this result as an input.
    pub fn digest(&self) -> [u8; 32] {
        crate::hash::sha256(&[RESULT_DIGEST_DOMAIN, &self.encode()])
    }

    pub fn basis(&self) -> Basis {
        match self.body {
            Body::Consensus(_) => Basis::ChainExecution { host: self.host },
            Body::Optimistic(o) => Basis::Optimistic {
                host: self.host,
                challenge_window: o.challenge_window,
                phase_window: o.phase_window,
                executor_bond: o.executor_bond,
                challenger_bond: o.challenger_bond,
            },
        }
    }

    /// Check the result against what the consumer requires.
    pub fn require(&self, r: &ResultRequirements) -> Result<(), ResultError> {
        if r.mode.is_some_and(|m| m != self.mode()) {
            return Err(ResultError::Mode);
        }
        if r.source.is_some_and(|s| s != self.source) {
            return Err(ResultError::Instance);
        }
        let optimistic = r.template_id.is_some()
            || r.run_id.is_some()
            || r.root_aux.is_some()
            || r.min_challenge_window.is_some()
            || r.min_phase_window.is_some()
            || r.min_executor_bond.is_some()
            || r.min_challenger_bond.is_some();
        let consensus = r.kernel.is_some()
            || r.state_schema.is_some()
            || r.halt_reason.is_some()
            || r.resource_schema.is_some()
            || r.resource_commitment.is_some()
            || r.input_root.is_some()
            || r.stream_root.is_some();
        match &self.body {
            Body::Optimistic(o) => {
                if consensus {
                    return Err(ResultError::Mode);
                }
                if r.template_id.is_some_and(|t| t != o.template_id) || r.root_aux.is_some_and(|a| a != o.root_aux) {
                    return Err(ResultError::Computation);
                }
                if r.run_id.is_some_and(|id| id != o.run_id) {
                    return Err(ResultError::Instance);
                }
                if r.min_challenge_window.is_some_and(|w| o.challenge_window < w)
                    || r.min_phase_window.is_some_and(|w| o.phase_window < w)
                    || r.min_executor_bond.is_some_and(|b| o.executor_bond < b)
                    || r.min_challenger_bond.is_some_and(|b| o.challenger_bond < b)
                {
                    return Err(ResultError::Security);
                }
            }
            Body::Consensus(c) => {
                if optimistic {
                    return Err(ResultError::Mode);
                }
                if r.kernel.is_some_and(|k| k != (c.kernel_id, c.semantic_version, c.abi_version))
                    || r.state_schema.is_some_and(|s| s != c.state_schema)
                {
                    return Err(ResultError::Computation);
                }
                if r.input_root.is_some_and(|x| x != c.input_root) || r.stream_root.is_some_and(|x| x != c.stream_root) {
                    return Err(ResultError::Instance);
                }
                if r.halt_reason.is_some_and(|h| h != c.halt_reason) {
                    return Err(ResultError::Reason);
                }
                if r.resource_commitment.is_some_and(|x| x != c.resource_commitment)
                    || r.resource_schema.is_some_and(|x| x != c.resource_schema)
                {
                    return Err(ResultError::Resource);
                }
            }
        }
        Ok(())
    }

    /// `OUT_TREE_V21`: output `index`'s 55-byte value reference is in the
    /// result's out tree. `path` is the sibling path from the leaf up, of
    /// height `ceil(log2 max(count, 1))`. What the reference's digest commits
    /// depends on its layout; for a plain value, check the bytes with
    /// [`plain_value_matches`].
    pub fn open_output(&self, index: u64, value_ref: &[u8; D::VALUE_REF_BYTES], path: &[[u8; 32]]) -> Result<(), ResultError> {
        if self.scheme != SCHEME_OUT_TREE_V21 || index >= self.count || path.len() != tree_height(self.count) {
            return Err(ResultError::Opening);
        }
        let leaf = D::out_leaf(&Hasher, index, Some(value_ref));
        if D::root_from_path(&Hasher, D::Tree::Out, &leaf, index, path) != self.root {
            return Err(ResultError::Opening);
        }
        Ok(())
    }

    /// `LX_OUTPUTS_V1`: every output slot, in slot order, rehashes to the root.
    pub fn open_lx_outputs(&self, outputs: &[Option<&[u8]>]) -> Result<(), ResultError> {
        if self.scheme != SCHEME_LX_OUTPUTS_V1 || D::lx::outputs_digest(&Hasher, outputs) != self.root {
            return Err(ResultError::Opening);
        }
        Ok(())
    }

    /// `STATE_SEAL_V1`: the whole final state rehashes to the seal.
    pub fn open_state(&self, state: &[u8]) -> Result<(), ResultError> {
        self.open_state_spans(&[state])
    }

    /// [`open_state`](Self::open_state) over the state's spans in order (for
    /// a program reading them from the session's state accounts, past each
    /// account's `CHILD_HEADER_BYTES`), without copying them together. Any
    /// bytes that rehash to the seal are the sealed state, so the accounts
    /// need no other check.
    pub fn open_state_spans(&self, spans: &[&[u8]]) -> Result<(), ResultError> {
        let Body::Consensus(c) = &self.body else {
            return Err(ResultError::Opening);
        };
        let total: u64 = spans.iter().map(|s| s.len() as u64).sum();
        if self.scheme != SCHEME_STATE_SEAL_V1 || total != self.count || total > u64::from(u32::MAX) {
            return Err(ResultError::Opening);
        }
        if seal_digest_spans(c, spans) != self.root {
            return Err(ResultError::Opening);
        }
        Ok(())
    }
}

/// The v2.1 tree height over `count` leaves: `ceil(log2 max(count, 1))`.
pub fn tree_height(count: u64) -> usize {
    let n = count.max(1);
    (u64::BITS - (n - 1).leading_zeros()) as usize
}

/// Whether `value` is the plain value a reference names: its byte length
/// (reference bytes 19..23) and `SHA256("dcg.value.v2\0" || value)`.
pub fn plain_value_matches(value_ref: &[u8; D::VALUE_REF_BYTES], value: &[u8]) -> bool {
    u32_at(value_ref, 19) as usize == value.len() && D::value_digest(&Hasher, value)[..] == value_ref[23..55]
}

/// The seal over a final state (design §3.2), from the result's body.
pub fn seal_digest(c: &ConsensusBody, state: &[u8]) -> [u8; 32] {
    seal_digest_spans(c, &[state])
}

/// [`seal_digest`] over the state's spans in order. Chunks are 64 KiB of the
/// concatenated state, so a chunk may cross spans.
///
/// Panics if the spans total more than `u32::MAX` bytes (no session state
/// can: the cap is 10,000,000).
pub fn seal_digest_spans(c: &ConsensusBody, spans: &[&[u8]]) -> [u8; 32] {
    let total_len: usize = spans.iter().map(|s| s.len()).sum();
    assert!(total_len <= u32::MAX as usize, "state longer than u32::MAX bytes");
    let total = (total_len as u32).to_le_bytes();
    let cursor = c.halt_cursor.to_le_bytes();
    let schema_id = c.state_schema.id.to_le_bytes();
    let schema_version = c.state_schema.version.to_le_bytes();
    let tail: [&[u8]; 6] = [&c.input_root, &c.kernel_id.0, &schema_id, &schema_version, &cursor, &total];
    let mut acc = crate::hash::sha256(&[SEAL_INIT_DOMAIN, tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]]);
    let (mut span, mut within) = (0usize, 0usize);
    let mut offset = 0usize;
    while offset < total_len {
        let end = (offset + SEAL_CHUNK_BYTES).min(total_len);
        let offset_bytes = (offset as u32).to_le_bytes();
        let mut parts: alloc::vec::Vec<&[u8]> = alloc::vec![SEAL_CHUNK_DOMAIN, &acc, &offset_bytes];
        let mut need = end - offset;
        while need > 0 {
            let s = spans[span];
            let take = (s.len() - within).min(need);
            if take > 0 {
                parts.push(&s[within..within + take]);
            }
            within += take;
            need -= take;
            if within == s.len() {
                span += 1;
                within = 0;
            }
        }
        acc = crate::hash::sha256(&parts);
        offset = end;
    }
    crate::hash::sha256(&[SEAL_DOMAIN, &acc, tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]])
}

/// Read a finished v2.1 run's result (design §3.1) from the run account (live
/// `D21R`, or receipt `D21P` or `D21Q`) and its template account, both owned
/// by `host`. Only a `FINAL` run is a result. A `D21Q` receipt carries what the
/// result needs from the template, so `template` may be `None` for it (the
/// template may have closed); every other form needs the template.
pub fn read_run_result(host: &Pubkey, run: &AccountInfo, template: Option<&AccountInfo>) -> Result<ResultRef, ResultError> {
    let r = run.try_borrow_data().map_err(|_| ResultError::Layout)?;
    match template {
        Some(template) => {
            let t = template.try_borrow_data().map_err(|_| ResultError::Layout)?;
            read_run_result_bytes(host, (run.key, run.owner, &r), Some((template.key, template.owner, &t)))
        }
        None => read_run_result_bytes(host, (run.key, run.owner, &r), None),
    }
}

/// [`read_run_result`] over each account's key, owner and data (for clients).
pub fn read_run_result_bytes(
    host: &Pubkey,
    run: (&Pubkey, &Pubkey, &[u8]),
    template: Option<(&Pubkey, &Pubkey, &[u8])>,
) -> Result<ResultRef, ResultError> {
    let (run_key, run_owner, r) = run;
    if run_owner != host || template.is_some_and(|(_, owner, _)| owner != host) {
        return Err(ResultError::Owner);
    }
    let root_at = match r.get(0..4) {
        Some(b"D21R") => {
            if r.len() < RUN_LIVE_ROOT + RUN_ROOT_BYTES {
                return Err(ResultError::Layout);
            }
            let trailer = match r[RUN_VERSION] {
                0 => 4,
                1 => 4 + 32,
                _ => return Err(ResultError::Layout),
            };
            let n_ext = u32_at(r, RUN_N_EXT) as usize;
            let len = n_ext
                .checked_mul(52)
                .and_then(|refs| (RUN_LIVE_ROOT + RUN_ROOT_BYTES + trailer).checked_add(refs));
            if len != Some(r.len()) {
                return Err(ResultError::Layout);
            }
            RUN_LIVE_ROOT
        }
        Some(b"D21P") if r.len() == RECEIPT_BYTES => RUN_RECEIPT_ROOT,
        Some(b"D21Q") if r.len() == RECEIPT_V2_BYTES => {
            if r[RECEIPT_BYTES + 33..RECEIPT_BYTES + 36].iter().any(|b| *b != 0) {
                return Err(ResultError::Layout);
            }
            RUN_RECEIPT_ROOT
        }
        _ => return Err(ResultError::Layout),
    };
    let run_id = key_at(r, RUN_ID);
    let (derived, _) = Pubkey::try_find_program_address(&[RUN_SEED, &run_id, &r[RUN_PAYER..RUN_PAYER + 32]], host)
        .ok_or(ResultError::Address)?;
    if &derived != run_key {
        return Err(ResultError::Address);
    }
    if let Some((template_key, _, t)) = template {
        if r[RUN_TEMPLATE..RUN_TEMPLATE + 32] != template_key.to_bytes() {
            return Err(ResultError::Template);
        }
        if t.len() < TEMPLATE_MIN_BYTES || &t[0..4] != b"D21T" {
            return Err(ResultError::Template);
        }
    }
    // What the result takes from the template: from the receipt when it
    // carries it (D21Q), else from the template account.
    let (template_id, kind, windows) = if &r[0..4] == b"D21Q" {
        let tail = &r[RECEIPT_BYTES..];
        // A template passed with a D21Q must be the one it recorded.
        if let Some((_, _, t)) = template {
            if t[TEMPLATE_ID..TEMPLATE_ID + 32] != tail[0..32] || t[TEMPLATE_KIND] != tail[32] {
                return Err(ResultError::Template);
            }
        }
        (key_at(tail, 0), tail[32], [u64_at(tail, 36), u64_at(tail, 44), u64_at(tail, 52), u64_at(tail, 60)])
    } else {
        let Some((_, _, t)) = template else { return Err(ResultError::Template) };
        (
            key_at(t, TEMPLATE_ID),
            t[TEMPLATE_KIND],
            [
                u64_at(t, TEMPLATE_CHALLENGE_WINDOW),
                u64_at(t, TEMPLATE_PHASE_WINDOW),
                u64_at(t, TEMPLATE_EXECUTOR_BOND),
                u64_at(t, TEMPLATE_CHALLENGER_BOND),
            ],
        )
    };
    if r[RUN_STATUS] != RUN_FINAL {
        return Err(ResultError::NotFinal);
    }
    let root = &r[root_at..root_at + RUN_ROOT_BYTES];
    let lx = kind == TEMPLATE_KIND_LX;
    // The committed root names the run (COMMIT checks it); refuse a record
    // that says otherwise rather than mix two runs.
    let root_run_id = if lx { key_at(root, 0) } else { key_at(root, 32) };
    if root_run_id != run_id {
        return Err(ResultError::Layout);
    }
    let (scheme, value_root, count, root_aux, steps) = if lx {
        (SCHEME_LX_OUTPUTS_V1, key_at(root, 64), 0, key_at(root, 96), u64_at(root, 128))
    } else {
        (SCHEME_OUT_TREE_V21, key_at(root, 144), u64_at(root, 136), key_at(root, 64), u64_at(root, 96))
    };
    Ok(ResultRef {
        scheme,
        host: *host,
        source: *run_key,
        root: value_root,
        count,
        body: Body::Optimistic(OptimisticBody {
            template_id,
            run_id,
            root_aux,
            challenge_window: windows[0],
            phase_window: windows[1],
            executor_bond: windows[2],
            challenger_bond: windows[3],
            steps,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consensus() -> ResultRef {
        ResultRef {
            scheme: SCHEME_STATE_SEAL_V1,
            host: Pubkey::new_from_array([1; 32]),
            source: Pubkey::new_from_array([2; 32]),
            root: [3; 32],
            count: 70_000,
            body: Body::Consensus(ConsensusBody {
                kernel_id: KernelId(*b"dcg-test-v1\0\0\0\0\0"),
                semantic_version: 1,
                abi_version: 3,
                state_schema: VersionedId { id: 7, version: 1 },
                resource_schema: VersionedId { id: 0, version: 0 },
                features: 2,
                halt_reason: 9,
                halt_cursor: 12,
                input_root: [4; 32],
                stream_root: [5; 32],
                resource_commitment: [0; 32],
            }),
        }
    }

    fn optimistic() -> ResultRef {
        ResultRef {
            scheme: SCHEME_OUT_TREE_V21,
            host: Pubkey::new_from_array([1; 32]),
            source: Pubkey::new_from_array([6; 32]),
            root: [7; 32],
            count: 5,
            body: Body::Optimistic(OptimisticBody {
                template_id: [8; 32],
                run_id: [9; 32],
                root_aux: [10; 32],
                challenge_window: 1_500,
                phase_window: 750,
                executor_bond: 2_000_000,
                challenger_bond: 1_000_000,
                steps: 40,
            }),
        }
    }

    #[test]
    fn encoding_round_trips_and_refuses_what_encode_would_not_write() {
        for r in [consensus(), optimistic()] {
            let raw = r.encode();
            assert_eq!(ResultRef::decode(&raw), Ok(r));
            for at in [0, 4, 6, 7] {
                let mut bad = raw;
                bad[at] ^= 0x40;
                assert_eq!(ResultRef::decode(&bad), Err(ResultError::Layout), "byte {at}");
            }
            assert_eq!(ResultRef::decode(&raw[..255]), Err(ResultError::Layout));
        }
        let mut pad = consensus().encode();
        pad[BODY + 34] = 1;
        assert_eq!(ResultRef::decode(&pad), Err(ResultError::Layout));
        let mut pad = optimistic().encode();
        pad[BODY + 140] = 1;
        assert_eq!(ResultRef::decode(&pad), Err(ResultError::Layout));
        // A consensus scheme under the optimistic mode.
        let mut cross = optimistic().encode();
        cross[7] = SCHEME_STATE_SEAL_V1;
        assert_eq!(ResultRef::decode(&cross), Err(ResultError::Layout));
    }

    #[test]
    fn requirements_are_typed_by_mode() {
        let (c, o) = (consensus(), optimistic());
        assert_eq!(c.require(&ResultRequirements::default()), Ok(()));
        let want = ResultRequirements { mode: Some(MODE_OPTIMISTIC), ..Default::default() };
        assert_eq!(c.require(&want), Err(ResultError::Mode));
        assert_eq!(o.require(&want), Ok(()));
        let template = ResultRequirements { template_id: Some([8; 32]), ..Default::default() };
        assert_eq!(o.require(&template), Ok(()));
        assert_eq!(c.require(&template), Err(ResultError::Mode));
        let other = ResultRequirements { template_id: Some([0; 32]), ..Default::default() };
        assert_eq!(o.require(&other), Err(ResultError::Computation));
        let window = ResultRequirements { min_challenge_window: Some(1_501), ..Default::default() };
        assert_eq!(o.require(&window), Err(ResultError::Security));
        let bond = ResultRequirements { min_executor_bond: Some(2_000_000), ..Default::default() };
        assert_eq!(o.require(&bond), Ok(()));
        let reason = ResultRequirements { halt_reason: Some(8), ..Default::default() };
        assert_eq!(c.require(&reason), Err(ResultError::Reason));
        assert_eq!(o.require(&reason), Err(ResultError::Mode));
        // Review 10-14 F5: the parameters digest, the other windows and bonds,
        // the input and stream roots and the resource schema.
        let aux = ResultRequirements { root_aux: Some([0; 32]), ..Default::default() };
        assert_eq!(o.require(&aux), Err(ResultError::Computation));
        assert_eq!(o.require(&ResultRequirements { root_aux: Some([10; 32]), ..Default::default() }), Ok(()));
        assert_eq!(c.require(&aux), Err(ResultError::Mode));
        assert_eq!(o.require(&ResultRequirements { min_challenger_bond: Some(1_000_001), ..Default::default() }), Err(ResultError::Security));
        assert_eq!(o.require(&ResultRequirements { min_phase_window: Some(751), ..Default::default() }), Err(ResultError::Security));
        assert_eq!(c.require(&ResultRequirements { stream_root: Some([0; 32]), ..Default::default() }), Err(ResultError::Instance));
        assert_eq!(c.require(&ResultRequirements { input_root: Some([4; 32]), stream_root: Some([5; 32]), ..Default::default() }), Ok(()));
        assert_eq!(c.require(&ResultRequirements { resource_schema: Some(VersionedId { id: 1, version: 1 }), ..Default::default() }), Err(ResultError::Resource));
        assert_eq!(o.require(&ResultRequirements { input_root: Some([4; 32]), ..Default::default() }), Err(ResultError::Mode));
        let source = ResultRequirements { source: Some(Pubkey::new_from_array([2; 32])), ..Default::default() };
        assert_eq!(c.require(&source), Ok(()));
        assert_eq!(o.require(&source), Err(ResultError::Instance));
    }

    #[test]
    fn a_state_seal_opens_only_with_the_exact_state() {
        let mut r = consensus();
        let state: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let Body::Consensus(c) = r.body else { unreachable!() };
        r.root = seal_digest(&c, &state);
        assert_eq!(r.open_state(&state), Ok(()));
        let mut changed = state.clone();
        changed[69_999] ^= 1;
        assert_eq!(r.open_state(&changed), Err(ResultError::Opening));
        assert_eq!(r.open_state(&state[..69_999]), Err(ResultError::Opening));
        // The same seal over spans, chunks crossing span boundaries.
        let (a, rest) = state.split_at(10);
        let (b, c2) = rest.split_at(65_530);
        assert_eq!(r.open_state_spans(&[a, b, c2]), Ok(()));
        assert_eq!(r.open_state_spans(&[a, &[], b, c2]), Ok(()));
        assert_eq!(r.open_state_spans(&[b, a, c2]), Err(ResultError::Opening));
    }

    #[test]
    fn an_output_opens_against_the_out_tree() {
        let refs: Vec<[u8; 55]> = (0..5u8)
            .map(|i| {
                let value = [i; 4];
                let mut r = [0u8; 55];
                r[19..23].copy_from_slice(&4u32.to_le_bytes());
                r[23..55].copy_from_slice(&D::value_digest(&Hasher, &value));
                r
            })
            .collect();
        let leaves: Vec<D::Hash> = (0..8u64)
            .map(|j| D::out_leaf(&Hasher, j, refs.get(j as usize).map(|r| &r[..])))
            .collect();
        let node = |l: u16, a: &D::Hash, b: &D::Hash| D::node(&Hasher, D::Tree::Out, l, a, b);
        let l1: Vec<D::Hash> = (0..4).map(|i| node(0, &leaves[2 * i], &leaves[2 * i + 1])).collect();
        let l2: Vec<D::Hash> = (0..2).map(|i| node(1, &l1[2 * i], &l1[2 * i + 1])).collect();
        let root = node(2, &l2[0], &l2[1]);
        let mut r = optimistic();
        r.root = root;
        let path3 = [leaves[2], l1[0], l2[1]];
        assert_eq!(r.open_output(3, &refs[3], &path3), Ok(()));
        assert!(plain_value_matches(&refs[3], &[3; 4]));
        assert!(!plain_value_matches(&refs[3], &[4; 4]));
        assert_eq!(r.open_output(3, &refs[2], &path3), Err(ResultError::Opening));
        assert_eq!(r.open_output(2, &refs[3], &path3), Err(ResultError::Opening));
        assert_eq!(r.open_output(5, &refs[3], &path3), Err(ResultError::Opening));
        assert_eq!(r.open_output(3, &refs[3], &path3[..2]), Err(ResultError::Opening));
        assert_eq!(tree_height(1), 0);
        assert_eq!(tree_height(5), 3);
        assert_eq!(tree_height(8), 3);
        assert_eq!(tree_height(9), 4);
    }
}
