// SPDX-License-Identifier: GPL-3.0-only
//! LX1 state commitments (design `docs/design/v2.1-lazy-expansion.md`):
//! slot leaves and the canonical multi-proof fold used by the terminal replay
//! and the OUTPUT claim. Mirrors `python/dcg/disputes_v21/lx.py`;
//! `tests/lx_goldens.rs` pins it to `tests/golden/dcg/disputes_v21/lx.json`.

use crate::{empty, node, Hash, Sha256, Tree};

pub const SLOT_LEAF_DOMAIN: &[u8] = b"dcg.lx.slot.leaf.v1\x00";

/// The leaf of one slot: its index and value, or the empty-slot leaf.
pub fn slot_leaf<H: Sha256>(h: &H, slot: u32, value: Option<&[u8]>) -> Hash {
    match value {
        None => empty(h, Tree::LxState, 0),
        Some(v) => h.hash(&[SLOT_LEAF_DOMAIN, &slot.to_le_bytes(), &(v.len() as u32).to_le_bytes(), v]),
    }
}

/// Fold opened leaves into the state root.
///
/// `nodes` holds `(slot, leaf)` pairs sorted by strictly increasing slot; it
/// is used as scratch and overwritten. `siblings` are the hashes of exactly
/// the nodes not derivable from the opened leaves, in canonical order: level
/// ascending, then position ascending. Returns `None` for unsorted or
/// out-of-range slots, a missing or extra sibling, or an empty opening.
pub fn fold<H: Sha256>(h: &H, height: u16, nodes: &mut [(u64, Hash)], siblings: &[Hash]) -> Option<Hash> {
    let mut n = nodes.len();
    if n == 0 {
        return None;
    }
    for i in 0..n {
        if (height < 64 && nodes[i].0 >> height != 0) || (i > 0 && nodes[i].0 <= nodes[i - 1].0) {
            return None;
        }
    }
    let mut next = 0usize;
    for level in 0..height {
        let (mut i, mut out) = (0usize, 0usize);
        while i < n {
            let (pos, hash) = nodes[i];
            let parent = if pos & 1 == 0 && i + 1 < n && nodes[i + 1].0 == pos + 1 {
                let right = nodes[i + 1].1;
                i += 2;
                node(h, Tree::LxState, level, &hash, &right)
            } else {
                let sibling = siblings.get(next)?;
                next += 1;
                i += 1;
                if pos & 1 == 0 {
                    node(h, Tree::LxState, level, &hash, sibling)
                } else {
                    node(h, Tree::LxState, level, sibling, &hash)
                }
            };
            nodes[out] = (pos >> 1, parent);
            out += 1;
        }
        n = out;
    }
    (next == siblings.len() && n == 1).then_some(nodes[0].1)
}

/// Checkpoint positions for `positions` positions every `k`: 0, k, 2k, ... and
/// `positions`, without duplicates. Their coordinates are the schedule's
/// position starts (design H2: derived, never executor-chosen).
pub fn checkpoint_count(positions: u64, k: u64) -> Option<u64> {
    (k >= 1).then(|| positions.div_ceil(k) + 1)
}

/// The `index`th checkpoint position, or `None` past the last.
pub fn checkpoint_position(positions: u64, k: u64, index: u64) -> Option<u64> {
    let count = checkpoint_count(positions, k)?;
    (index < count).then(|| if index + 1 == count { positions } else { index * k })
}

/// The interior coordinates bisection asks the executor for over `[lo, hi)`:
/// `min(arity, hi - lo) - 1` evenly spaced points, `lo + span * i / parts`.
/// Writes them to `out` and returns how many; `None` if `hi <= lo`, `arity < 2`
/// or `out` is too short.
pub fn midpoint_coordinates(lo: u64, hi: u64, arity: u64, out: &mut [u64]) -> Option<usize> {
    if hi <= lo || arity < 2 {
        return None;
    }
    let span = hi - lo;
    let parts = arity.min(span);
    let n = (parts - 1) as usize;
    if out.len() < n {
        return None;
    }
    for i in 1..parts {
        out[(i - 1) as usize] = lo + ((span as u128 * i as u128) / parts as u128) as u64;
    }
    Some(n)
}

/// The sub-interval a challenger names by `index` after the executor's
/// midpoints over `[lo, hi)`: bounds are `lo`, the midpoints, then `hi`, and
/// `index` selects `[bound[index], bound[index + 1]]`. `None` if the interval
/// is empty, `arity < 2`, or `index` names no sub-interval.
pub fn pick_interval(lo: u64, hi: u64, arity: u64, index: u64) -> Option<(u64, u64)> {
    let mut mids = [0u64; 255];
    let cap = (arity.min(256) as usize).saturating_sub(1);
    let n = midpoint_coordinates(lo, hi, arity, &mut mids[..cap])?;
    let bound = |i: usize| if i == 0 { lo } else if i <= n { mids[i - 1] } else { hi };
    let i = index as usize;
    (index <= n as u64).then(|| (bound(i), bound(i + 1)))
}
