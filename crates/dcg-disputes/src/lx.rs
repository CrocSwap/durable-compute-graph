// SPDX-License-Identifier: GPL-3.0-only
//! LX1 state commitments (design `docs/design/v2.1-lazy-expansion.md`):
//! slot leaves and the canonical multi-proof fold used by the terminal replay
//! and the OUTPUT claim. Mirrors `python/dcg/disputes_v21/lx.py`;
//! `tests/lx_goldens.rs` pins it to `tests/golden/dcg/disputes_v21/lx.json`.

use crate::{empty, node, Hash, Sha256, Tree, CHUNK_LEAF_DOMAIN};

pub const SLOT_LEAF_DOMAIN: &[u8] = b"dcg.lx.slot.leaf.v1\x00";
pub const CONST_LEAF_DOMAIN: &[u8] = b"dcg.lx.const.leaf.v1\x00";
/// Longest chunk path (chunk tree height) and constant path (constants tree
/// height) an opening may carry.
pub const MAX_CHUNK_PATH: usize = 48;
pub const MAX_CONST_PATH: usize = 32;

/// The leaf of one slot: its index and value, or the empty-slot leaf.
pub fn slot_leaf<H: Sha256 + ?Sized>(h: &H, slot: u32, value: Option<&[u8]>) -> Hash {
    match value {
        None => empty(h, Tree::LxState, 0),
        Some(v) => h.hash(&[SLOT_LEAF_DOMAIN, &slot.to_le_bytes(), &(v.len() as u32).to_le_bytes(), v]),
    }
}

/// The constants tree's leaf at position `constant_id` (design §13): the id
/// and the constant's chunk-tree root.
pub fn const_leaf<H: Sha256 + ?Sized>(h: &H, constant_id: u32, digest: &Hash) -> Hash {
    h.hash(&[CONST_LEAF_DOMAIN, &constant_id.to_le_bytes(), digest])
}

/// One declared constant read in an opening (design §13): the chunk, its path
/// to the constant's chunk root (`digest`), and `digest`'s path to the
/// template's `constants_root`. Paths are concatenated 32-byte sibling hashes,
/// leaf level first, borrowed from the staged bytes (no copies: review M1).
/// The constant id and chunk index are not carried: they come from the
/// machine.
#[derive(Clone, Copy, Debug)]
pub struct ConstOpening<'a> {
    pub chunk: &'a [u8],
    pub chunk_path: &'a [u8],
    pub digest: Hash,
    pub const_path: &'a [u8],
}

/// `root_from_path` over a path given as concatenated 32-byte hashes.
fn root_from_path_bytes<H: Sha256 + ?Sized>(h: &H, tree: Tree, leaf: &Hash, mut position: u64, path: &[u8]) -> Hash {
    let mut acc = *leaf;
    for (level, sibling) in path.chunks_exact(32).enumerate() {
        let sibling: &Hash = sibling.try_into().expect("32-byte chunk");
        acc = if position & 1 == 1 { node(h, tree, level as u16, sibling, &acc) } else { node(h, tree, level as u16, &acc, sibling) };
        position >>= 1;
    }
    acc
}

/// Check one opened constant read `(constant_id, index)` against
/// `constants_root`: the chunk's leaf rebuilds `digest` and the constant's
/// leaf rebuilds the root. Paths longer than the caps, or too short to hold
/// the id or index, are refused.
pub fn check_constant<H: Sha256 + ?Sized>(h: &H, constant_id: u32, index: u64, e: &ConstOpening, constants_root: &Hash) -> bool {
    if e.chunk_path.len() % 32 != 0 || e.const_path.len() % 32 != 0 {
        return false;
    }
    let (nc, nk) = (e.chunk_path.len() / 32, e.const_path.len() / 32);
    if nc > MAX_CHUNK_PATH || nk > MAX_CONST_PATH || index >> nc != 0 || (constant_id as u64) >> nk != 0 {
        return false;
    }
    let leaf = h.hash(&[CHUNK_LEAF_DOMAIN, &index.to_le_bytes(), e.chunk]);
    root_from_path_bytes(h, Tree::Chunk, &leaf, index, e.chunk_path) == e.digest
        && root_from_path_bytes(h, Tree::LxConst, &const_leaf(h, constant_id, &e.digest), constant_id as u64, e.const_path)
            == *constants_root
}

/// Fold opened leaves into the state root.
///
/// `nodes` holds `(slot, leaf)` pairs sorted by strictly increasing slot; it
/// is used as scratch and overwritten. `siblings` are the hashes of exactly
/// the nodes not derivable from the opened leaves, in canonical order: level
/// ascending, then position ascending. Returns `None` for unsorted or
/// out-of-range slots, a missing or extra sibling, or an empty opening.
pub fn fold<H: Sha256 + ?Sized>(h: &H, height: u16, nodes: &mut [(u64, Hash)], siblings: &[Hash]) -> Option<Hash> {
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

// --- the machine and the terminal replay ---------------------------------------------------

/// A slot's new value after a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    /// Not written: the slot keeps its opened value.
    Keep,
    /// Cleared to the empty slot.
    Clear,
    /// Set to `out[start..start + len]` of the caller's output buffer.
    Set { start: usize, len: usize },
}

/// Where a kernel puts its outputs: one [`Write`] per declared write slot, in
/// the machine's write order, with bytes in a caller-provided buffer.
pub struct Outputs<'a> {
    pub buf: &'a mut [u8],
    pub used: usize,
    pub writes: &'a mut [Write],
}

/// The kernel could not produce an output; on a verified opening this rules
/// for the challenger (design review L2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelFailure;

impl Outputs<'_> {
    /// Set the `index`th declared write slot to `value`.
    pub fn set(&mut self, index: usize, value: &[u8]) -> Result<(), KernelFailure> {
        let end = self.used.checked_add(value.len()).ok_or(KernelFailure)?;
        let dst = self.buf.get_mut(self.used..end).ok_or(KernelFailure)?;
        dst.copy_from_slice(value);
        *self.writes.get_mut(index).ok_or(KernelFailure)? = Write::Set { start: self.used, len: value.len() };
        self.used = end;
        Ok(())
    }

    /// Clear the `index`th declared write slot.
    pub fn clear(&mut self, index: usize) -> Result<(), KernelFailure> {
        *self.writes.get_mut(index).ok_or(KernelFailure)? = Write::Clear;
        Ok(())
    }
}

/// An application's LX1 machine, registered through its manifest. It is
/// consensus code: the template commits to its id and version. Mirrors the
/// Python `Machine` protocol.
///
/// Constants (design §13): `constants` names the template constant chunks a
/// transition reads, as `(constant_id, chunk_index)` in order; `apply`
/// receives those chunks in that order. The set is fixed by the machine, so an
/// executor cannot choose which constants a replay sees.
///
/// Contract (LX1 program review M1): every position has at least one
/// transition (`transitions_in(p) >= 1`), so no checkpoint interval is empty
/// and every checkpoint pair can be disputed; `slots` returns distinct slots;
/// `apply` writes only declared slots. A machine that breaks the first rule
/// lets a lie at an empty interval go undisputed, so admitters must check it.
pub trait LxMachine {
    /// Positions in the run.
    fn positions(&self) -> u64;
    /// The state tree's height.
    fn height(&self) -> u16;
    /// Finest transitions in position `p` (a closed-form rule).
    fn transitions_in(&self, p: u64) -> u64;
    /// The global coordinate of position `p`'s first transition, for
    /// `p <= positions()` (a closed-form prefix sum of `transitions_in`).
    fn position_start(&self, p: u64) -> u64;
    /// Fill `reads` and `writes` with the slots of transition `(p, i)` and
    /// return their counts, or `None` if they do not fit.
    fn slots(&self, p: u64, i: u64, reads: &mut [u32], writes: &mut [u32]) -> Option<(usize, usize)>;
    /// Fill `out` with the `(constant_id, chunk_index)` reads of transition
    /// `(p, i)` and return their count, or `None` if they do not fit. A
    /// machine without constants reads none. `reads` holds the read slots'
    /// values (as for `apply`), already verified against the agreed root, so
    /// a read chosen by data (an embedding row by token) is still fixed by
    /// the committed state, not by the executor.
    fn constants(&self, p: u64, i: u64, reads: &[Option<&[u8]>], out: &mut [(u32, u64)]) -> Option<usize> {
        let _ = (p, i, reads, out);
        Some(0)
    }
    /// Apply transition `(p, i)`: `reads` holds the read slots' values in the
    /// order `slots` gave and `consts` the constant chunks in the order
    /// `constants` gave; record outputs through `out` by write index.
    fn apply(&self, p: u64, i: u64, reads: &[Option<&[u8]>], consts: &[&[u8]], out: &mut Outputs) -> Result<(), KernelFailure>;
}

/// Map a global coordinate to `(position, index)`. `None` outside the
/// schedule, or if the machine's prefix sums are inconsistent there.
pub fn locate<M: LxMachine + ?Sized>(m: &M, coordinate: u64) -> Option<(u64, u64)> {
    let n = m.positions();
    if coordinate >= m.position_start(n) {
        return None;
    }
    let (mut lo, mut hi) = (0u64, n);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if m.position_start(mid) <= coordinate {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let start = m.position_start(lo);
    let count = m.transitions_in(lo);
    if start.checked_add(count)? != m.position_start(lo + 1) || coordinate < start || coordinate - start >= count {
        return None;
    }
    Some((lo, coordinate - start))
}

/// The result of a replay or claim that reached a ruling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LxRuling {
    Executor,
    Challenger,
}

/// A refusal: no state changes, and the sender may retry before its deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LxRefusal {
    /// The coordinate is outside the schedule.
    Coordinate,
    /// The opening does not cover exactly the transition's slots (or the
    /// output slots), or a caller buffer is too small.
    Coverage,
    /// The opening does not rebuild the agreed root.
    Proof,
    /// The opened constants are not exactly the transition's declared reads,
    /// in order, each verifying against the template's `constants_root`.
    Constant,
}

/// Caller-provided working memory for [`replay`]; each slice must be at least
/// as long as the largest transition needs.
pub struct Scratch<'a> {
    pub reads: &'a mut [u32],
    pub writes: &'a mut [u32],
    pub nodes: &'a mut [(u64, Hash)],
    pub read_values: &'a mut [Option<&'a [u8]>],
    pub write_effects: &'a mut [Write],
    pub out: &'a mut [u8],
    pub const_reads: &'a mut [(u32, u64)],
    pub const_values: &'a mut [&'a [u8]],
}

/// The terminal replay (design §4.3). `opened` is the executor's opening of the
/// agreed lower state at transition `coordinate`: `(slot, value)` sorted by
/// strictly increasing slot, covering exactly the transition's reads and
/// writes, with `siblings` in canonical order, and `consts` holds one entry per
/// declared constant read, in order (design §13). Refuses an opening that does
/// not cover the slots or rebuild `root_lo`, or whose constants do not verify
/// against `constants_root`. Otherwise rules: the executor wins if the
/// replayed state rebuilds `root_hi`; the challenger wins on a mismatch or a
/// kernel failure.
#[allow(clippy::too_many_arguments)]
pub fn replay<'v, H: Sha256 + ?Sized, M: LxMachine + ?Sized>(
    h: &H,
    m: &M,
    coordinate: u64,
    opened: &[(u32, Option<&'v [u8]>)],
    siblings: &[Hash],
    consts: &[ConstOpening<'v>],
    constants_root: &Hash,
    root_lo: &Hash,
    root_hi: &Hash,
    s: &mut Scratch<'v>,
) -> Result<LxRuling, LxRefusal> {
    let (p, i) = locate(m, coordinate).ok_or(LxRefusal::Coordinate)?;
    let (nr, nw) = m.slots(p, i, s.reads, s.writes).ok_or(LxRefusal::Coverage)?;
    let (reads, writes) = (&s.reads[..nr], &s.writes[..nw]);
    // The opening covers exactly reads ∪ writes.
    let mut covered = 0usize;
    for (k, (slot, _)) in opened.iter().enumerate() {
        if k > 0 && *slot <= opened[k - 1].0 {
            return Err(LxRefusal::Coverage);
        }
        if !reads.contains(slot) && !writes.contains(slot) {
            return Err(LxRefusal::Coverage);
        }
        covered += 1;
    }
    let distinct = |xs: &[u32], i: usize| !xs[..i].contains(&xs[i]);
    let union = (0..nr).filter(|&k| distinct(reads, k)).count()
        + (0..nw).filter(|&k| distinct(writes, k) && !reads.contains(&writes[k])).count();
    if covered != union || s.nodes.len() < covered {
        return Err(LxRefusal::Coverage);
    }
    if union == 0 {
        // A transition that touches no slot is the identity (LX1 program
        // review M1): nothing can be opened, so the roots must already agree.
        if !siblings.is_empty() {
            return Err(LxRefusal::Proof);
        }
        if check_constants(h, m, p, i, &[], consts, constants_root, s.const_reads, s.const_values)?.is_none() {
            return Ok(LxRuling::Challenger); // the machine cannot name its reads (review M3)
        }
        return Ok(if root_lo == root_hi { LxRuling::Executor } else { LxRuling::Challenger });
    }
    let value = |slot: u32| opened.binary_search_by_key(&slot, |e| e.0).ok().map(|k| opened[k].1);
    // The opening rebuilds the agreed lower root.
    for (k, (slot, v)) in opened.iter().enumerate() {
        s.nodes[k] = (*slot as u64, slot_leaf(h, *slot, *v));
    }
    if fold(h, m.height(), &mut s.nodes[..covered], siblings) != Some(*root_lo) {
        return Err(LxRefusal::Proof);
    }
    // Replay.
    if s.read_values.len() < nr || s.write_effects.len() < nw {
        return Err(LxRefusal::Coverage);
    }
    for k in 0..nr {
        s.read_values[k] = value(reads[k]).ok_or(LxRefusal::Coverage)?;
    }
    // The constants are exactly the declared reads (a function of the
    // verified read values), in order, each verified.
    // A machine that cannot name its reads for this verified state rules for
    // the challenger, as a kernel failure does (review M3).
    let Some(nc) = check_constants(h, m, p, i, &s.read_values[..nr], consts, constants_root, s.const_reads, s.const_values)?
    else {
        return Ok(LxRuling::Challenger);
    };
    for e in s.write_effects[..nw].iter_mut() {
        *e = Write::Keep;
    }
    let mut out = Outputs { buf: &mut *s.out, used: 0, writes: &mut s.write_effects[..nw] };
    if m.apply(p, i, &s.read_values[..nr], &s.const_values[..nc], &mut out).is_err() {
        return Ok(LxRuling::Challenger);
    }
    // Rebuild over the same slots with the written values.
    for (k, (slot, v)) in opened.iter().enumerate() {
        let mut new: Option<&[u8]> = *v;
        for (w, ws) in writes.iter().enumerate() {
            if ws == slot {
                match s.write_effects[w] {
                    Write::Keep => {}
                    Write::Clear => new = None,
                    Write::Set { start, len } => new = Some(&s.out[start..start + len]),
                }
            }
        }
        s.nodes[k] = (*slot as u64, slot_leaf(h, *slot, new));
    }
    let rebuilt = fold(h, m.height(), &mut s.nodes[..covered], siblings).ok_or(LxRefusal::Proof)?;
    Ok(if rebuilt == *root_hi { LxRuling::Executor } else { LxRuling::Challenger })
}

/// Check the opened constants against the machine's declared reads for
/// transition `(p, i)` given its verified read values; returns their count
/// with `const_values` filled, or `None` if the machine cannot name its reads
/// for these values (which rules for the challenger).
#[allow(clippy::too_many_arguments)]
fn check_constants<'v, H: Sha256 + ?Sized, M: LxMachine + ?Sized>(
    h: &H,
    m: &M,
    p: u64,
    i: u64,
    read_values: &[Option<&[u8]>],
    consts: &[ConstOpening<'v>],
    constants_root: &Hash,
    const_reads: &mut [(u32, u64)],
    const_values: &mut [&'v [u8]],
) -> Result<Option<usize>, LxRefusal> {
    let Some(nc) = m.constants(p, i, read_values, const_reads) else {
        return Ok(None);
    };
    if nc > const_reads.len() || const_values.len() < nc {
        return Err(LxRefusal::Coverage); // a machine past its declared maximum (review L3)
    }
    if consts.len() != nc {
        return Err(LxRefusal::Constant);
    }
    for (k, e) in consts.iter().enumerate() {
        let (cid, index) = const_reads[k];
        if !check_constant(h, cid, index, e, constants_root) {
            return Err(LxRefusal::Constant);
        }
        const_values[k] = e.chunk;
    }
    Ok(Some(nc))
}

/// The OUTPUT claim (design review H3): `opened` covers exactly `output_slots`
/// (sorted, distinct) against the final root `root_t`; the challenger wins if
/// any opened value differs from the claimed output at the same index.
pub fn output_claim<H: Sha256 + ?Sized>(
    h: &H,
    height: u16,
    output_slots: &[u32],
    opened: &[(u32, Option<&[u8]>)],
    siblings: &[Hash],
    root_t: &Hash,
    claimed: &[Option<&[u8]>],
    nodes: &mut [(u64, Hash)],
) -> Result<LxRuling, LxRefusal> {
    if opened.len() != output_slots.len() || claimed.len() != output_slots.len() || nodes.len() < opened.len() {
        return Err(LxRefusal::Coverage);
    }
    for (k, ((slot, v), want)) in opened.iter().zip(output_slots).enumerate() {
        if slot != want {
            return Err(LxRefusal::Coverage);
        }
        nodes[k] = (*slot as u64, slot_leaf(h, *slot, *v));
    }
    if fold(h, height, &mut nodes[..opened.len()], siblings) != Some(*root_t) {
        return Err(LxRefusal::Proof);
    }
    let lie = opened.iter().zip(claimed).any(|((_, v), c)| v != c);
    Ok(if lie { LxRuling::Challenger } else { LxRuling::Executor })
}

pub const OUTPUTS_DOMAIN: &[u8] = b"dcg.lx.outputs.v1\x00";

/// The digest a run commits for its claimed outputs, in output-slot order:
/// each value is `present:u8` then, if present, `len:u32le` and its bytes.
pub fn outputs_digest<H: Sha256 + ?Sized>(h: &H, outputs: &[Option<&[u8]>]) -> Hash {
    // One hash call per value keeps this allocation-free; the chaining is
    // `acc = H(domain, acc, present, len, bytes)` from a zero start.
    let mut acc = [0u8; 32];
    for v in outputs {
        acc = match v {
            None => h.hash(&[OUTPUTS_DOMAIN, &acc, &[0]]),
            Some(b) => h.hash(&[OUTPUTS_DOMAIN, &acc, &[1], &(b.len() as u32).to_le_bytes(), b]),
        };
    }
    acc
}
