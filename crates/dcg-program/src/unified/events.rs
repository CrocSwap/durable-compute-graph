//! DLE1 log events (spec revision 4, §16.5): one fixed-layout event per
//! state change, logged last with a single `sol_log_data` call.
//!
//! ```text
//!  0 "DLE1" | 4 version:u16 | 6 kind:u8 | 7 zero:u8 | 8 descriptor[32]
//! 40 slot:u64 | 48 body (fixed length per kind; 32-byte fields are keys or
//!    digests, an output value is zero-padded; integers LE; pads zero)
//! ```
//! State is authoritative; events are an index. Every field here is also in
//! account state or derivable from it.
//!
//! **The version is per record, not per program.** Revision 7
//! (`docs/spec/dcg-unified-v1.md` §16.5) emits `version = 2` with revision 7's
//! body lengths; revision 8 (`docs/spec/dcg-unified-v8.md` §1.8) emits
//! `version = 3`, whose `init` and `finalize` bodies carry the prompt length,
//! the stop value, the option count and the policy kind, whose `close` body
//! gains the two bond bytes, and which adds kind 12 `bond_retry`. A revision-7
//! event is emitted byte for byte as before.

use solana_program::{clock::Clock, sysvar::Sysvar};

pub const MAGIC: &[u8; 4] = b"DLE1";
pub const VERSION: u16 = 2;
/// Revision 8's header version (spec §1.8); the header is otherwise unchanged.
pub const VERSION_V3: u16 = 3;
pub const HEADER: usize = 48;

pub const INIT: u8 = 1;
pub const LAND: u8 = 2;
pub const FINALIZE: u8 = 3;
pub const CHALLENGE_OPEN: u8 = 4;
pub const RESPOND: u8 = 5;
pub const RULING: u8 = 6;
pub const SETTLE: u8 = 7;
pub const CLOSE: u8 = 8;
pub const OUTPUT: u8 = 9;
pub const RESOLVE: u8 = 10;
pub const CLOSE_RESULT: u8 = 11;

/// Body length of each kind (index = kind), revision 7 (`DLE1` v2).
pub const BODY: [usize; 12] = [0, 80, 48, 72, 88, 48, 48, 112, 56, 48, 16, 68];
/// Body length of each kind, revision 8 (`DLE1` v3, spec §1.8): `init` 92,
/// `land` 48, `finalize` 80, the four dispute kinds unchanged, `close` 72,
/// `output` 48, `resolve` 16, `close_result` 68, and the new kind 12
/// `bond_retry` 96.
pub const BODY_V3: [usize; 13] = [0, 92, 48, 80, 88, 48, 48, 112, 72, 48, 16, 68, 96];
/// `bond_retry`, emitted by tag 187. Kind number and body length are frozen
/// here (spec §1.8); the instruction that emits it is
/// [`crate::unified::bond::retry`].
pub const BOND_RETRY: u8 = 12;
/// The only value `bond_retry`'s `outcome` byte can carry: the "nothing to do"
/// case is refused **599** before any event is logged, so there is no state in
/// which a retry succeeds and does nothing, and `0` is unassigned (spec §1.8).
pub const OUTCOME_SETTLED: u8 = 1;

/// Ruling causes (spec §7.9).
pub const CAUSE_VERDICT: u8 = 1;
pub const CAUSE_CONVICT: u8 = 2;
pub const CAUSE_TIMEOUT: u8 = 3;
/// The revision-8 DCR1 v6 app-kernel replay result selected the winner.
pub const CAUSE_APP_REPLAY: u8 = 4;
/// The admitted app identity changed before replay could safely decide a
/// winner; settlement refunds the challenge bond neutrally.
pub const CAUSE_APP_IDENTITY_CHANGED: u8 = 5;

/// A fixed-length body under construction.
pub struct Body {
    buf: [u8; 112],
    len: usize,
}

impl Body {
    pub fn new() -> Self {
        Body {
            buf: [0; 112],
            len: 0,
        }
    }
    pub fn key(mut self, v: &[u8]) -> Self {
        let n = v.len().min(32);
        self.buf[self.len..self.len + n].copy_from_slice(&v[..n]);
        self.len += 32;
        self
    }
    pub fn u8(mut self, v: u8) -> Self {
        self.buf[self.len] = v;
        self.len += 1;
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.buf[self.len..self.len + 4].copy_from_slice(&v.to_le_bytes());
        self.len += 4;
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.buf[self.len..self.len + 8].copy_from_slice(&v.to_le_bytes());
        self.len += 8;
        self
    }
    pub fn pad(mut self, n: usize) -> Self {
        self.len += n;
        self
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode one event (the single `sol_log_data` argument), revision 7.
pub fn encode(kind: u8, descriptor: &[u8; 32], slot: u64, body: &Body) -> Vec<u8> {
    debug_assert_eq!(
        body.len, BODY[kind as usize],
        "event kind {kind} body length"
    );
    let mut out = Vec::with_capacity(HEADER + body.len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(body.bytes());
    out
}

/// Encode one revision-8 event: the same header with `version = 3` and the
/// v3 body length of its kind.
pub fn encode_v3(kind: u8, descriptor: &[u8; 32], slot: u64, body: &Body) -> Vec<u8> {
    debug_assert_eq!(
        body.len, BODY_V3[kind as usize],
        "event kind {kind} body length"
    );
    let mut out = Vec::with_capacity(HEADER + body.len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION_V3.to_le_bytes());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(body.bytes());
    out
}

/// Log one event as the last action of a successful instruction.
pub fn emit(kind: u8, descriptor: &[u8; 32], body: Body) {
    emit_versioned(VERSION, kind, descriptor, body, &BODY);
}

/// Log one revision-8 event as the last action of a successful instruction.
pub fn emit_v8(kind: u8, descriptor: &[u8; 32], body: Body) {
    emit_versioned(VERSION_V3, kind, descriptor, body, &BODY_V3);
}

fn emit_versioned(version: u16, kind: u8, descriptor: &[u8; 32], body: Body, lengths: &[usize]) {
    debug_assert_eq!(
        body.len, lengths[kind as usize],
        "event kind {kind} body length"
    );
    let slot = Clock::get().map(|c| c.slot).unwrap_or(0);
    let mut out = Vec::with_capacity(HEADER + body.len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&version.to_le_bytes());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(body.bytes());
    solana_program::log::sol_log_data(&[&out]);
}
