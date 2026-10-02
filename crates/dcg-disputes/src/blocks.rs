// SPDX-License-Identifier: GPL-3.0-only
//! Multi-block step trees (design §3, §5.2, §6.2): `BlockSpec` records, the
//! address map, structural pickability and generated `StepSpec`s for
//! repeated blocks. Mirrors `python/dcg/disputes_v21/spec.py`.

use crate::{u32_at, u64_at};

/// `ceil(log2(max(n, 1)))`.
pub fn height_for(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

/// One `BlockSpec` (104 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub kind: u8,
    pub base: u64,
    pub step_count: u64,
    pub k: u32,
    pub body_len: u32,
    pub gate_entry: u32,
    pub gate_port: u16,
    pub first_record: u64,
    pub record_count: u64,
    pub address_base: u64,
    pub address_height: u8,
}

impl Block {
    pub const BYTES: usize = 104;

    /// Parse and check internal consistency: the kind, the step count of a
    /// repeated block, the gate entry within the body, a non-empty block.
    pub fn parse(raw: &[u8]) -> Option<Block> {
        if raw.len() != Self::BYTES || &raw[..4] != b"DBK1" || raw[5..8] != [0; 3] {
            return None;
        }
        let b = Block {
            kind: raw[4],
            base: u64_at(raw, 8)?,
            step_count: u64_at(raw, 16)?,
            k: u32_at(raw, 24)?,
            body_len: u32_at(raw, 28)?,
            gate_entry: u32_at(raw, 32)?,
            gate_port: u16::from_le_bytes([raw[36], raw[37]]),
            first_record: u64_at(raw, 40)?,
            record_count: u64_at(raw, 48)?,
            address_base: u64_at(raw, 56)?,
            address_height: raw[64],
        };
        let ok = match b.kind {
            1 => b.step_count >= 1 && b.record_count == b.step_count && b.k == 0 && b.body_len == 0,
            2 => {
                b.k >= 1
                    && b.body_len >= 1
                    && b.gate_entry < b.body_len
                    && b.record_count == b.body_len as u64
                    && b.step_count == b.k as u64 * b.body_len as u64
            }
            _ => false,
        };
        (ok && b.address_height <= 40).then_some(b)
    }

    pub fn hb(&self) -> u32 {
        if self.kind == 2 {
            height_for(self.body_len as u64)
        } else {
            0
        }
    }

    /// The address height this block must have (§6.2).
    pub fn derived_height(&self) -> u32 {
        match self.kind {
            1 => height_for(self.step_count),
            _ => height_for(self.k as u64) + height_for(self.body_len as u64),
        }
    }

    pub fn contains(&self, ordinal: u64) -> bool {
        ordinal >= self.base && ordinal - self.base < self.step_count
    }

    /// (iteration, entry) of an ordinal in this block.
    pub fn split(&self, ordinal: u64) -> (u64, u64) {
        let r = ordinal - self.base;
        if self.kind == 1 {
            (0, r)
        } else {
            (r / self.body_len as u64, r % self.body_len as u64)
        }
    }

    pub fn ordinal(&self, iteration: u64, entry: u64) -> u64 {
        if self.kind == 1 {
            self.base + entry
        } else {
            self.base + iteration * self.body_len as u64 + entry
        }
    }

    pub fn position_of(&self, ordinal: u64) -> u64 {
        let (i, e) = self.split(ordinal);
        self.address_base + if self.kind == 1 { e } else { (i << self.hb()) + e }
    }

    /// The ordinal at an address inside this block's range, if a step position.
    pub fn ordinal_at(&self, position: u64) -> Option<u64> {
        let r = position.checked_sub(self.address_base)?;
        if r >> self.address_height != 0 {
            return None;
        }
        if self.kind == 1 {
            return (r < self.step_count).then_some(self.base + r);
        }
        let (i, e) = (r >> self.hb(), r & ((1u64 << self.hb()) - 1));
        (i < self.k as u64 && e < self.body_len as u64).then(|| self.base + i * self.body_len as u64 + e)
    }

    /// Whether [lo, hi) holds a step position of this block.
    pub fn holds_step(&self, lo: u64, hi: u64) -> bool {
        let start = self.address_base;
        let end = start + (1u64 << self.address_height);
        let (blo, bhi) = (lo.max(start) - start, hi.min(end).saturating_sub(start));
        if lo >= end || hi <= start || blo >= bhi {
            return false;
        }
        if self.kind == 1 {
            return blo < self.step_count;
        }
        let i = blo >> self.hb();
        (i < self.k as u64 && (i << self.hb()) + self.body_len as u64 > blo)
            || (i + 1 < self.k as u64 && ((i + 1) << self.hb()) < bhi)
    }
}

/// Where a block of the given shape goes after `end` (§6.2): its
/// (address_base, address_height).
pub fn place_after(end: u64, height: u32) -> Option<u64> {
    let size = 1u64.checked_shl(height)?;
    end.checked_add(size - 1).map(|v| v / size * size)
}

/// Structural pickability over a list of blocks (§7.1).
pub fn pickable(blocks: &[Block], level: u32, position: u64) -> bool {
    let Some(lo) = position.checked_shl(level) else { return false };
    let Some(hi) = (position + 1).checked_shl(level) else { return false };
    blocks.iter().any(|b| b.holds_step(lo, hi))
}

/// Resolve one producer of a body entry for iteration `i` (§5.2).
fn resolve(prod: &[u8], initial: &[u8], b: &Block, i: u64, out: &mut [u8]) {
    let (kind, a, pb, c, d) = crate::producer(prod);
    out.copy_from_slice(prod);
    match kind {
        4 => {
            let lag = c as u64;
            if i >= lag {
                let target = b.base + (i - lag) * b.body_len as u64 + a;
                out.copy_from_slice(&crate::encode_producer(1, target, pb, 0, 0));
            } else {
                out.copy_from_slice(initial);
            }
        }
        5 => {
            let index = i * c as u64 + d as u64;
            out.copy_from_slice(&crate::encode_producer(5, a, pb, 0, index as u32));
        }
        7 => out.copy_from_slice(&crate::encode_producer(7, i, 0, 0, 0)),
        _ => {}
    }
}

/// StepSpec(k) for iteration `i` of repeated block `b`, from its body entry,
/// written into `out` (same length). False if `body` is not a body entry.
pub fn generate(body: &[u8], b: &Block, i: u64, out: &mut [u8]) -> bool {
    if body.len() < 192 || &body[..4] != b"DSB1" || out.len() != body.len() {
        return false;
    }
    out.copy_from_slice(body);
    out[..4].copy_from_slice(b"DSS1");
    let initial_state: [u8; 24] = body[160..184].try_into().unwrap();
    resolve(&body[136..160], &initial_state, b, i, &mut out[136..160]);
    let n_in = body[184] as usize;
    for x in 0..n_in {
        let at = 192 + 72 * x;
        if at + 72 > body.len() {
            return false;
        }
        let initial: [u8; 24] = body[at + 47..at + 71].try_into().unwrap();
        resolve(&body[at + 23..at + 47], &initial, b, i, &mut out[at + 23..at + 47]);
        out[at + 47..at + 71].fill(0);
    }
    true
}
