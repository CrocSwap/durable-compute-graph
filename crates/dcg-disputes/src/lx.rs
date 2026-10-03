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
