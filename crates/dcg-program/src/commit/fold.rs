//! The closure fold (DCG commit mode v1, step 6.2).
//!
//! `docs/spec/dcg-commit-v1.md` §3.2–§3.4 is normative; the Python mirror is
//! `src/basanos/dcg/commit/fold.py`, and both reproduce
//! `tests/golden/dcg/commit/fold_vectors_v1.tsv` byte for byte.
//!
//! One construction, and it is the Merkle tree (q3, spec §3.1):
//!
//! ```text
//! leaf(e)         = closure_leaf(e)                    (step 6.1, leaf.rs)
//! node(l, r)      = sha256("basanos/dcg-closure-node/1" | l[32] | r[32])
//! closure_root(w) = sha256("basanos/dcg-closure-root/1"
//!                          | descriptor_digest[32] | family_id:u16le
//!                          | window_index:u32le | leaf_count:u32le
//!                          | tree_root[32])
//! ```
//!
//! `tree_root` is the **duplicate-last promotion** of the window's leaves in
//! ascending `entry_index` (spec §3.2): at every level, an odd final node is
//! duplicated and paired with itself; a single leaf is its own root.
//! [`tree_root_reference`] is that definition, level by level.
//!
//! `DCC1` stores no leaf table, only a 32-level binary-carry frontier
//! (spec §3.3).  Posting a leaf pushes it at level 0 and carries upward while
//! the level is occupied; **level `i` is occupied exactly when bit `i` of
//! `leaf_cursor` is set**.  A stored frontier whose occupancy disagrees with
//! the cursor is [`err::CLOSURE_FRONTIER`] (459), not an ambiguity.
//!
//! Collapsing the frontier at finalize is **lift by duplication** (spec §3.3):
//! walking levels upward, the running carry is lifted one level at a time by
//! `node(carry, carry)` until it reaches the level of the next occupied peak,
//! and only then combined as `node(peak, carry)`.  This is not the obvious
//! rule: combining peaks across levels without lifting -- the naive "bag the
//! peaks" -- disagrees with the level-by-level reference at three leaves, and
//! the tests pin both the equality and the disagreement.
//!
//! Membership is the sibling path from the leaf upward, each step tagged
//! `left` or `right` (spec §3.4), verified by re-applying [`node`] in the
//! tagged order.  Depth is `ceil(log2(leaf_count))`, at most
//! [`MAX_RECORD_PROOF_DEPTH`] (32): the legacy `MAX_RECORD_PROOF_DEPTH = 24`
//! would make a window of more than 16,777,216 leaves unprovable, and
//! `entry_count` is now bounded at `2^32-1`.
//!
//! Everything here is pure: no account, no I/O, no clock.  [`Frontier`],
//! [`membership_verify`] and [`node`] allocate nothing, so the on-chain path
//! (`ClosurePost`/`ClosureFinalize`, dispatch 6.4) can carry them.
//! [`tree_root_reference`] and [`membership_proof`] are the reference
//! generators and do allocate; they are the normative definition and the
//! test/offline path, never the on-chain one.

use crate::commit::{err, COMMIT_FRONTIER_LEVELS, TAG_CLOSURE_NODE, TAG_CLOSURE_ROOT};
use crate::descriptor::DcgError;
use crate::hash::sha256;

/// The membership proof depth DCG accepts: the frontier bound, not the legacy
/// 24 (spec §3.4).
pub const MAX_RECORD_PROOF_DEPTH: usize = COMMIT_FRONTIER_LEVELS;

/// A 32-byte digest.  All of the fold is over these.
pub type Digest = [u8; 32];

/// Which side a sibling sits on when re-applying [`node`] upward.
///
/// [`Side::Left`] means the sibling is the LEFT input (`node(sibling, acc)`);
/// [`Side::Right`] means it is the right input (`node(acc, sibling)`).  This
/// matches the `left`/`right` tags `fold_vectors_v1.tsv` stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// `node(l, r)`: the one node construction, under its own domain tag so a
/// route root can never be presented as a closure node or the reverse.
pub fn node(left: &Digest, right: &Digest) -> Digest {
    sha256(&[TAG_CLOSURE_NODE, left, right])
}

/// The level-by-level duplicate-last promotion -- the NORMATIVE `tree_root`
/// (spec §3.2).
///
/// Returns `None` for zero leaves: the spec defines no root over an empty
/// window, and this function does not invent one.
pub fn tree_root_reference(leaves: &[Digest]) -> Option<Digest> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<Digest> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level[level.len() - 1]);
        }
        level = level.chunks(2).map(|pair| node(&pair[0], &pair[1])).collect();
    }
    Some(level[0])
}

/// The 32-level binary-carry frontier `DCC1` stores, with the leaf cursor
/// whose bits are its occupancy mask (spec §3.3).
///
/// An unoccupied level is `None` here; `DCC1`'s zero-filled `u8[32][32]`
/// encoding is the record layer's concern (dispatch 6.4), not the fold's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontier {
    levels: [Option<Digest>; COMMIT_FRONTIER_LEVELS],
    leaf_cursor: u32,
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    pub const fn new() -> Self {
        Self { levels: [None; COMMIT_FRONTIER_LEVELS], leaf_cursor: 0 }
    }

    /// Load a stored frontier: the 32 levels plus the cursor whose bits must
    /// be its occupancy.
    ///
    /// This is how the record layer (dispatch 6.4) hands the fold what it
    /// decoded out of `DCC1`, and how a test builds a deliberate
    /// disagreement; [`Frontier::check`] is the 459 gate over it.
    pub const fn from_levels(
        levels: [Option<Digest>; COMMIT_FRONTIER_LEVELS],
        leaf_cursor: u32,
    ) -> Self {
        Self { levels, leaf_cursor }
    }

    /// Leaves posted so far; its bits are the occupancy mask.
    pub const fn leaf_cursor(&self) -> u32 {
        self.leaf_cursor
    }

    /// The node stored at `level`, if the level is occupied.
    pub fn level(&self, level: usize) -> Option<&Digest> {
        self.levels.get(level).and_then(|node| node.as_ref())
    }

    /// The occupancy mask the stored nodes imply: bit `i` set iff level `i`
    /// holds a node.
    pub fn occupancy(&self) -> u32 {
        let mut mask = 0u32;
        for (level, node) in self.levels.iter().enumerate() {
            if node.is_some() {
                mask |= 1u32 << level;
            }
        }
        mask
    }

    /// 459: the stored occupancy must equal the bits of `leaf_cursor`.
    ///
    /// `DCC1` stores no occupancy mask precisely because the cursor is one;
    /// a frontier and a cursor that disagree are refused rather than guessed
    /// at (spec §3.3).
    pub fn check(&self) -> Result<(), DcgError> {
        if self.occupancy() == self.leaf_cursor {
            Ok(())
        } else {
            Err(DcgError(err::CLOSURE_FRONTIER))
        }
    }

    /// Push one leaf at level 0, carrying upward while the level is occupied
    /// (spec §3.3).  The level written is the number of trailing set bits of
    /// the cursor before the increment, so the new occupancy is exactly the
    /// bits of the new cursor.
    ///
    /// Returns 459 if the frontier and the cursor already disagree, if a level
    /// that must be occupied is empty, or if the cursor would overflow.
    pub fn push(&mut self, leaf: &Digest) -> Result<(), DcgError> {
        let level = self.leaf_cursor.trailing_ones() as usize;
        if level >= COMMIT_FRONTIER_LEVELS {
            return Err(DcgError(err::CLOSURE_FRONTIER));
        }
        self.check()?;
        let mut carry = *leaf;
        for i in 0..level {
            let peak = self.levels[i].take().ok_or(DcgError(err::CLOSURE_FRONTIER))?;
            carry = node(&peak, &carry);
        }
        if self.levels[level].is_some() {
            return Err(DcgError(err::CLOSURE_FRONTIER));
        }
        self.levels[level] = Some(carry);
        self.leaf_cursor =
            self.leaf_cursor.checked_add(1).ok_or(DcgError(err::CLOSURE_FRONTIER))?;
        Ok(())
    }

    /// Collapse the mountain range to one root by **lift by duplication**
    /// (spec §3.3).
    ///
    /// The running carry is lifted by `node(carry, carry)` until it reaches
    /// the next occupied peak's level, then combined as `node(peak, carry)`.
    /// Returns `None` only for an empty frontier (`leaf_cursor == 0`); an
    /// occupancy that disagrees with the cursor is [`Frontier::check`]'s 459.
    pub fn collapse(&self) -> Option<Digest> {
        let mut carry: Option<Digest> = None;
        let mut carry_level = 0usize;
        for level in 0..COMMIT_FRONTIER_LEVELS {
            if self.leaf_cursor & (1u32 << level) == 0 {
                continue;
            }
            let peak = match self.levels[level] {
                Some(peak) => peak,
                None => return None,
            };
            match carry {
                None => {
                    carry = Some(peak);
                    carry_level = level;
                }
                Some(current) => {
                    let mut lifted = current;
                    while carry_level < level {
                        lifted = node(&lifted, &lifted);
                        carry_level += 1;
                    }
                    carry = Some(node(&peak, &lifted));
                    carry_level = level + 1;
                }
            }
        }
        carry
    }
}

/// Build a fresh frontier over `leaves` and collapse it.
///
/// Returns `None` for zero leaves, exactly as [`tree_root_reference`] does.
/// This is the incremental half of gate 3's equality: it must equal
/// [`tree_root_reference`] for every leaf count.
pub fn tree_root_frontier(leaves: &[Digest]) -> Option<Digest> {
    if leaves.is_empty() {
        return None;
    }
    let mut frontier = Frontier::new();
    for leaf in leaves {
        if frontier.push(leaf).is_err() {
            return None;
        }
    }
    frontier.collapse()
}

/// `closure_root(w)`: the window root that binds the document, family, window
/// and length (spec §3.2), so a closure is not transferable between them.
pub fn closure_root(
    descriptor_digest: &Digest,
    family_id: u16,
    window_index: u32,
    leaf_count: u32,
    tree_root: &Digest,
) -> Digest {
    let family = family_id.to_le_bytes();
    let window = window_index.to_le_bytes();
    let count = leaf_count.to_le_bytes();
    sha256(&[TAG_CLOSURE_ROOT, descriptor_digest, &family, &window, &count, tree_root])
}

/// The sibling path for `leaves[index]`, from the leaf upward, as
/// `(side, sibling)` (spec §3.4).
///
/// Returns `None` if `index` is out of range or `leaves` is empty.  This is
/// the reference generator (it allocates); [`membership_verify`] is the
/// allocation-free check.
pub fn membership_proof(leaves: &[Digest], index: usize) -> Option<Vec<(Side, Digest)>> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Digest> = leaves.to_vec();
    let mut pos = index;
    let mut proof: Vec<(Side, Digest)> = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level[level.len() - 1]);
        }
        let sibling = level[pos ^ 1];
        proof.push((if pos % 2 == 1 { Side::Left } else { Side::Right }, sibling));
        level = level.chunks(2).map(|pair| node(&pair[0], &pair[1])).collect();
        pos /= 2;
    }
    Some(proof)
}

/// Re-apply [`node`] in the tagged order to rebuild the root from a leaf.
/// Allocation-free.
pub fn membership_verify(leaf: &Digest, proof: &[(Side, Digest)]) -> Digest {
    let mut acc = *leaf;
    for (side, sibling) in proof {
        acc = match side {
            Side::Left => node(sibling, &acc),
            Side::Right => node(&acc, sibling),
        };
    }
    acc
}

/// 457: a membership proof must rebuild `expected_root`, and its depth must be
/// at most [`MAX_RECORD_PROOF_DEPTH`] (spec §3.4).
pub fn check_membership(
    leaf: &Digest,
    proof: &[(Side, Digest)],
    expected_root: &Digest,
) -> Result<(), DcgError> {
    if proof.len() > MAX_RECORD_PROOF_DEPTH {
        return Err(DcgError(err::CLOSURE_MEMBERSHIP));
    }
    if &membership_verify(leaf, proof) == expected_root {
        Ok(())
    } else {
        Err(DcgError(err::CLOSURE_MEMBERSHIP))
    }
}

/// 452: a declared `tree_root` must be the collapse of the frontier (spec
/// §5.3 rule 4).
pub fn check_tree_root(declared: &Digest, computed: &Digest) -> Result<(), DcgError> {
    if declared == computed {
        Ok(())
    } else {
        Err(DcgError(err::CLOSURE_ROOT_MISMATCH))
    }
}

/// 452: a declared `closure_root` must be §3.2's value (spec §5.3 rule 4).
pub fn check_closure_root(declared: &Digest, computed: &Digest) -> Result<(), DcgError> {
    if declared == computed {
        Ok(())
    } else {
        Err(DcgError(err::CLOSURE_ROOT_MISMATCH))
    }
}

/// `ceil(log2(leaf_count))`, the depth of a membership proof: at most
/// [`MAX_RECORD_PROOF_DEPTH`] (spec §3.4).  Zero for zero or one leaf.
pub fn max_proof_depth(leaf_count: u32) -> u32 {
    match leaf_count.saturating_sub(1).checked_ilog2() {
        Some(bits) => bits + 1,
        None => 0,
    }
}
