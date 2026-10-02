// SPDX-License-Identifier: GPL-3.0-only
//! Generic chunked reduction kernels (design §4.3a): integer-exact, fixed
//! widths, an overflow is a refusal. Mirrors
//! `python/dcg/disputes_v21/reductions.py`. No allocation.

/// Outputs (by port order) and next state of one replayed step.
#[derive(Debug, PartialEq, Eq)]
pub struct Replay {
    pub outputs: [[u8; MAX_STATE]; 2],
    pub output_len: [usize; 2],
    pub output_count: usize,
    pub next: [u8; MAX_STATE],
    pub next_len: usize,
}

/// The largest reduction state (`rowdot_i32c`: 64 rows of i64).
pub const MAX_STATE: usize = 8 * ROWDOT_ROWS;
pub const ROWDOT_ROWS: usize = 64;

impl Default for Replay {
    fn default() -> Self {
        Replay { outputs: [[0; MAX_STATE]; 2], output_len: [0; 2], output_count: 0, next: [0; MAX_STATE], next_len: 0 }
    }
}

impl Replay {
    pub fn output(&self, i: usize) -> &[u8] {
        &self.outputs[i][..self.output_len[i]]
    }
    pub fn next(&self) -> Option<&[u8]> {
        (self.next_len > 0).then(|| &self.next[..self.next_len])
    }
    fn push(&mut self, v: &[u8]) {
        let i = self.output_count;
        self.outputs[i][..v.len()].copy_from_slice(v);
        self.output_len[i] = v.len();
        self.output_count += 1;
    }
    fn set_next(&mut self, v: &[u8]) {
        self.next[..v.len()].copy_from_slice(v);
        self.next_len = v.len();
    }
}

/// (name, state bytes, arity)
pub fn lookup(kernel_id: &[u8]) -> Option<(&'static str, usize, usize)> {
    let end = kernel_id.iter().position(|&b| b == b'/' || b == 0).unwrap_or(kernel_id.len());
    match &kernel_id[..end] {
        b"sumchunk_i32" => Some(("sumchunk_i32", 8, 1)),
        b"argmax_i32c" => Some(("argmax_i32c", 12, 2)),
        b"scan_i32c" => Some(("scan_i32c", 8, 3)),
        b"head_i32" => Some(("head_i32", 0, 1)),
        b"rowdot_i32c" => Some(("rowdot_i32c", MAX_STATE, 3)),
        _ => None,
    }
}

fn words(chunk: &[u8]) -> Option<impl Iterator<Item = i32> + '_> {
    (chunk.len() % 4 == 0).then(|| chunk.chunks_exact(4).map(|w| i32::from_le_bytes(w.try_into().unwrap())))
}

fn u32_of(v: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(v.try_into().ok()?))
}

fn gate(on: bool) -> [u8; 4] {
    (on as i32).to_le_bytes()
}

/// Replay a reduction kernel; None on refusal or an unknown kernel.
pub fn replay(kernel_id: &[u8], inputs: &[&[u8]], prior: Option<&[u8]>) -> Option<Replay> {
    let (name, state_bytes, arity) = lookup(kernel_id)?;
    if inputs.len() != arity || prior.map_or(0, |p| p.len()) != state_bytes || prior.is_some() != (state_bytes > 0) {
        return None;
    }
    let mut r = Replay::default();
    match name {
        "sumchunk_i32" => {
            let mut acc = i64::from_le_bytes(prior?.try_into().ok()?);
            for v in words(inputs[0])? {
                acc = acc.checked_add(v as i64)?;
            }
            let nxt = acc.to_le_bytes();
            r.push(&nxt);
            r.push(&gate(true));
            r.set_next(&nxt);
        }
        "argmax_i32c" => {
            let p = prior?;
            let (mut seen, mut best, mut index) =
                (u32_of(&p[0..4])?, i32::from_le_bytes(p[4..8].try_into().ok()?), u32_of(&p[8..12])?);
            let n = (inputs[0].len() / 4) as u64;
            let it = u32_of(inputs[1])? as u64;
            for (j, v) in words(inputs[0])?.enumerate() {
                if seen == 0 || v > best {
                    seen = 1;
                    best = v;
                    index = u32::try_from(it * n + j as u64).ok()?;
                }
            }
            let mut nxt = [0u8; 12];
            nxt[0..4].copy_from_slice(&seen.to_le_bytes());
            nxt[4..8].copy_from_slice(&best.to_le_bytes());
            nxt[8..12].copy_from_slice(&index.to_le_bytes());
            r.push(&nxt);
            r.push(&gate(true));
            r.set_next(&nxt);
        }
        "scan_i32c" => {
            let p = prior?;
            let (mut found, mut index) = (u32_of(&p[0..4])?, u32_of(&p[4..8])?);
            let n = (inputs[0].len() / 4) as u64;
            let it = u32_of(inputs[1])? as u64;
            let needle = i32::from_le_bytes(inputs[2].try_into().ok()?);
            let ws = words(inputs[0])?;
            if found == 0 {
                for (j, v) in ws.enumerate() {
                    if v == needle {
                        found = 1;
                        index = u32::try_from(it * n + j as u64).ok()?;
                        break;
                    }
                }
            }
            let mut nxt = [0u8; 8];
            nxt[0..4].copy_from_slice(&found.to_le_bytes());
            nxt[4..8].copy_from_slice(&index.to_le_bytes());
            r.push(&nxt);
            r.push(&gate(found == 0));
            r.set_next(&nxt);
        }
        "rowdot_i32c" => {
            // y[i] = sum_j w[j] * x[j] in i64; y is 64 i64 entries of state.
            let (w, x) = (inputs[0], inputs[1]);
            let i = u32_of(inputs[2])? as usize;
            if w.len() % 4 != 0 || w.len() != x.len() || i >= ROWDOT_ROWS {
                return None;
            }
            let mut acc: i64 = 0;
            for (a, b) in words(w)?.zip(words(x)?) {
                acc = acc.checked_add((a as i64).checked_mul(b as i64)?)?;
            }
            let mut nxt = [0u8; MAX_STATE];
            nxt.copy_from_slice(prior?);
            nxt[8 * i..8 * i + 8].copy_from_slice(&acc.to_le_bytes());
            r.push(&nxt);
            r.push(&gate(true));
            r.set_next(&nxt);
        }
        "head_i32" => {
            r.push(inputs[0].get(..4)?);
        }
        _ => return None,
    }
    Some(r)
}
