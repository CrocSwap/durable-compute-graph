// SPDX-License-Identifier: GPL-3.0-only
//! Optimistic disputes v2.1 consensus bytes (design
//! `docs/design/optimistic-descent-v2.1.md`): v2.1 trees with
//! empty constants (§6.1), structural reveal folding (§7.1), the frozen step
//! leaf, out leaves, `RunRootV21` (§6.3), spec leaves and `StepSpec` fields
//! (§5.1); multi-block address maps and generated specs (`blocks`), and the
//! generic chunked reductions (`reductions`). Mirrors
//! `python/dcg/disputes_v21`; `tests/goldens.rs` pins it to
//! `tests/golden/dcg/disputes_v21/vectors.json` and `chunked.json`.
//!
//! Hashing is supplied by the caller (`Sha256`), so the program can use the
//! SBF syscall and the host a software SHA-256.
#![no_std]

pub mod blocks;
pub mod reductions;

pub type Hash = [u8; 32];

/// SHA-256 over the concatenation of `parts`.
pub trait Sha256 {
    fn hash(&self, parts: &[&[u8]]) -> Hash;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tree {
    Step,
    Out,
    Chunk,
    Log,
    Spec,
    List,
}

impl Tree {
    pub fn node_domain(self) -> &'static [u8] {
        match self {
            Tree::Step => b"dcg.trace.node.v2.1\x00",
            Tree::Out => b"dcg.out.node.v2.1\x00",
            Tree::Chunk => b"dcg.chunk.node.v2.1\x00",
            Tree::Log => b"dcg.log.node.v2.1\x00",
            Tree::Spec => b"dcg.spec.node.v2.1\x00",
            Tree::List => b"dcg.list.node.v2.1\x00",
        }
    }
    pub fn empty_label(self) -> &'static [u8] {
        match self {
            Tree::Step => b"dcg.leaf.empty.v2.1\x00",
            Tree::Out => b"dcg.out.empty.v2.1\x00",
            Tree::Chunk => b"dcg.chunk.empty.v2.1\x00",
            Tree::Log => b"dcg.log.empty.v2.1\x00",
            Tree::Spec => b"dcg.spec.empty.v2.1\x00",
            Tree::List => b"dcg.list.empty.v2.1\x00",
        }
    }
}

pub const LEAF_DOMAIN: &[u8] = b"dcg.region.leaf.v2\x00"; // frozen v2.0 step leaf
pub const VALUE_DOMAIN: &[u8] = b"dcg.value.v2\x00";
pub const OUT_LEAF_DOMAIN: &[u8] = b"dcg.out.leaf.v2.1\x00";
pub const RUN_ROOT_DOMAIN: &[u8] = b"dcg.run.root.v2.1\x00";
pub const SPEC_LEAF_DOMAIN: &[u8] = b"dcg.spec.leaf.v2.1\x00";
pub const LIST_LEAF_DOMAIN: &[u8] = b"dcg.list.leaf.v2.1\x00";
pub const LIST_DIGEST_DOMAIN: &[u8] = b"dcg.list.v2.1\x00";
pub const RUN_ROOT_BYTES: usize = 176;
pub const VALUE_REF_BYTES: usize = 55;
pub const PORT_HEADER_BYTES: usize = 23;
pub const MAX_LIST_ELEMENTS: usize = 128;
pub const PRODUCER_LIST: u8 = 8;
pub const LAYOUT_LIST: u32 = 6;
pub const TYPE_LIST: u8 = 10;
pub const MAX_DEPTH: u32 = 5;

pub fn node<H: Sha256>(h: &H, tree: Tree, level: u16, left: &Hash, right: &Hash) -> Hash {
    h.hash(&[tree.node_domain(), &level.to_le_bytes(), left, right])
}

/// EMPTY_t[level], computed by folding (no table: level is at most ~40).
pub fn empty<H: Sha256>(h: &H, tree: Tree, level: u16) -> Hash {
    let mut acc = h.hash(&[tree.empty_label()]);
    for l in 0..level {
        acc = node(h, tree, l, &acc, &acc);
    }
    acc
}

/// Fold a leaf (or node at `level0`) with its sibling path up to the root.
pub fn root_from_path<H: Sha256>(h: &H, tree: Tree, leaf: &Hash, mut position: u64, path: &[Hash]) -> Hash {
    let mut acc = *leaf;
    for (level, sibling) in path.iter().enumerate() {
        acc = if position & 1 == 1 {
            node(h, tree, level as u16, sibling, &acc)
        } else {
            node(h, tree, level as u16, &acc, sibling)
        };
        position >>= 1;
    }
    acc
}

/// Structural pickability for one enumerated block of `steps` steps (§7.1):
/// the subtree at (level, position) holds at least one step position.
pub fn pickable(steps: u64, level: u32, position: u64) -> bool {
    position.checked_shl(level).is_some_and(|first| first < steps)
}

/// Fold a reveal of the `2^depth` descendants of (level, position).
/// `revealed[i]` is `Some` exactly for the pickable descendants; the rest are
/// filled with EMPTY[level - depth]. Returns None when the set is wrong.
pub fn fold_reveal<H: Sha256>(
    h: &H,
    tree: Tree,
    steps: u64,
    level: u32,
    position: u64,
    depth: u32,
    revealed: &[Option<Hash>],
) -> Option<Hash> {
    fold_reveal_by(h, tree, |l, p| pickable(steps, l, p), level, position, depth, revealed)
}

/// `fold_reveal` with a caller's structural pickability (multi-block step
/// trees use `blocks::pickable`).
pub fn fold_reveal_by<H: Sha256>(
    h: &H,
    tree: Tree,
    pick: impl Fn(u32, u64) -> bool,
    level: u32,
    position: u64,
    depth: u32,
    revealed: &[Option<Hash>],
) -> Option<Hash> {
    if depth == 0 || depth > MAX_DEPTH || depth > level || revealed.len() != 1usize << depth {
        return None;
    }
    let base = level - depth;
    let first = position << depth;
    let fill = empty(h, tree, base as u16);
    let mut row = [[0u8; 32]; 1 << MAX_DEPTH];
    for (i, slot) in revealed.iter().enumerate() {
        let want = pick(base, first + i as u64);
        match (want, slot) {
            (true, Some(v)) => row[i] = *v,
            (false, None) => row[i] = fill,
            _ => return None,
        }
    }
    let mut width = revealed.len();
    let mut l = base;
    while width > 1 {
        for i in 0..width / 2 {
            row[i] = node(h, tree, l as u16, &row[2 * i], &row[2 * i + 1]);
        }
        width /= 2;
        l += 1;
    }
    Some(row[0])
}

pub fn value_digest<H: Sha256>(h: &H, value: &[u8]) -> Hash {
    h.hash(&[VALUE_DOMAIN, value])
}

/// A step leaf's hash; `None` is the empty leaf.
pub fn leaf_hash<H: Sha256>(h: &H, preimage: Option<&[u8]>) -> Hash {
    match preimage {
        Some(p) => h.hash(&[LEAF_DOMAIN, p]),
        None => h.hash(&[Tree::Step.empty_label()]),
    }
}

pub fn out_leaf<H: Sha256>(h: &H, index: u64, entry: Option<&[u8]>) -> Hash {
    match entry {
        Some(e) => h.hash(&[OUT_LEAF_DOMAIN, &index.to_le_bytes(), e]),
        None => h.hash(&[Tree::Out.empty_label()]),
    }
}

pub fn spec_leaf<H: Sha256>(h: &H, type_code: u8, record: &[u8]) -> Hash {
    h.hash(&[SPEC_LEAF_DOMAIN, &[type_code], record])
}

/// One DLS1 list element: `H("dcg.list.leaf.v2.1\\0" || index:u32 || ref55)`.
pub fn list_leaf<H: Sha256>(h: &H, index: u32, element_ref: &[u8]) -> Option<Hash> {
    (element_ref.len() == VALUE_REF_BYTES)
        .then(|| h.hash(&[LIST_LEAF_DOMAIN, &index.to_le_bytes(), element_ref]))
}

/// Digest of a packed sequence of 55-byte refs. The list tree uses its own
/// empty leaf and ordinary v2.1 odd-tree padding; count is committed outside
/// the root, exactly as in the Python reference.
pub fn list_digest<H: Sha256>(h: &H, refs: &[u8]) -> Option<Hash> {
    if refs.is_empty() || refs.len() % VALUE_REF_BYTES != 0 {
        return None;
    }
    let count = refs.len() / VALUE_REF_BYTES;
    list_digest_iter(h, count, refs.chunks_exact(VALUE_REF_BYTES))
}

/// Digest an already parsed list of fixed-width refs without packing them into
/// a second buffer. This keeps wide STEP claims inside the SVM heap limit.
pub fn list_digest_elements<H: Sha256>(h: &H, refs: &[[u8; VALUE_REF_BYTES]]) -> Option<Hash> {
    list_digest_iter(h, refs.len(), refs.iter().map(|r| r.as_slice()))
}

fn list_digest_iter<'a, H: Sha256>(
    h: &H,
    count: usize,
    mut refs: impl Iterator<Item = &'a [u8]>,
) -> Option<Hash> {
    if count == 0 {
        return None;
    }
    if count > MAX_LIST_ELEMENTS {
        return None;
    }
    let height = usize::BITS - (count - 1).leading_zeros();
    let capacity = 1usize << height;
    // Fold as a binary carry so SBF uses 256 bytes of stack instead of a
    // 128-hash (4 KiB) row.
    let mut stack = [[0u8; 32]; 8];
    let empty_leaf = empty(h, Tree::List, 0);
    for position in 0..capacity {
        let mut current = if position < count {
            list_leaf(h, position as u32, refs.next()?)?
        } else {
            empty_leaf
        };
        let mut p = position;
        let mut level = 0usize;
        while p & 1 == 1 {
            current = node(h, Tree::List, level as u16, &stack[level], &current);
            p >>= 1;
            level += 1;
        }
        stack[level] = current;
    }
    Some(h.hash(&[LIST_DIGEST_DOMAIN, &(count as u32).to_le_bytes(), &stack[height as usize]]))
}

pub fn run_root<H: Sha256>(h: &H, root_bytes: &[u8; RUN_ROOT_BYTES]) -> Hash {
    h.hash(&[RUN_ROOT_DOMAIN, root_bytes])
}

/// `RunRootV21` field views.
pub struct RunRoot<'a>(pub &'a [u8; RUN_ROOT_BYTES]);

impl RunRoot<'_> {
    pub fn plan_id(&self) -> &[u8] {
        &self.0[0..32]
    }
    pub fn run_id(&self) -> &[u8] {
        &self.0[32..64]
    }
    pub fn spec_root(&self) -> &[u8] {
        &self.0[64..96]
    }
    pub fn total_steps(&self) -> u64 {
        u64::from_le_bytes(self.0[96..104].try_into().unwrap())
    }
    pub fn step_root(&self) -> &[u8] {
        &self.0[104..136]
    }
    pub fn total_outputs(&self) -> u64 {
        u64::from_le_bytes(self.0[136..144].try_into().unwrap())
    }
    pub fn out_root(&self) -> &[u8] {
        &self.0[144..176]
    }
}

/// A parsed step leaf (frozen v2.0 preimage). Refs are 55-byte slices.
#[derive(Debug)]
pub struct Leaf<'a> {
    pub plan_id: &'a [u8],
    pub run_id: &'a [u8],
    pub region: u32,
    pub coord_region: u32,
    pub segment: u32,
    pub ordinal: u64,
    pub node: u32,
    pub kernel_step: u32,
    pub inputs: &'a [u8],
    pub outputs: &'a [u8],
    pub prior: &'a [u8],
    pub next: &'a [u8],
}

impl<'a> Leaf<'a> {
    pub fn input_count(&self) -> usize {
        self.inputs.len() / VALUE_REF_BYTES
    }
    pub fn output_count(&self) -> usize {
        self.outputs.len() / VALUE_REF_BYTES
    }
    pub fn input(&self, i: usize) -> &'a [u8] {
        &self.inputs[i * VALUE_REF_BYTES..(i + 1) * VALUE_REF_BYTES]
    }
    pub fn output(&self, i: usize) -> &'a [u8] {
        &self.outputs[i * VALUE_REF_BYTES..(i + 1) * VALUE_REF_BYTES]
    }
    /// The output ref whose port id is `port`.
    pub fn output_port(&self, port: u16) -> Option<&'a [u8]> {
        (0..self.output_count()).map(|i| self.output(i)).find(|r| u16::from_le_bytes([r[5], r[6]]) == port)
    }
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

pub const CHUNK_LEAF_DOMAIN: &[u8] = b"dcg.chunk.leaf.v2.1\x00";

/// A chunk-tree leaf (§4.2).
pub fn chunk_leaf<H: Sha256>(h: &H, index: u64, chunk: &[u8]) -> Hash {
    h.hash(&[CHUNK_LEAF_DOMAIN, &index.to_le_bytes(), chunk])
}

/// The 24-byte producer record.
pub fn encode_producer(kind: u8, a: u64, b: u32, c: u32, d: u32) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0] = kind;
    out[4..12].copy_from_slice(&a.to_le_bytes());
    out[12..16].copy_from_slice(&b.to_le_bytes());
    out[16..20].copy_from_slice(&c.to_le_bytes());
    out[20..24].copy_from_slice(&d.to_le_bytes());
    out
}

/// Strict parse; None for anything malformed (the malformed-data rule).
pub fn parse_leaf(raw: &[u8]) -> Option<Leaf<'_>> {
    if raw.len() < 64 + 28 + 2 {
        return None;
    }
    let ordinal = u64::from_le_bytes(raw.get(76..84)?.try_into().ok()?);
    let n_in = u16::from_le_bytes(raw.get(92..94)?.try_into().ok()?) as usize;
    let ins_end = 94usize.checked_add(n_in.checked_mul(VALUE_REF_BYTES)?)?;
    let n_out = u16::from_le_bytes(raw.get(ins_end..ins_end + 2)?.try_into().ok()?) as usize;
    let outs_start = ins_end + 2;
    let outs_end = outs_start.checked_add(n_out.checked_mul(VALUE_REF_BYTES)?)?;
    if raw.len() != outs_end.checked_add(64)? {
        return None;
    }
    Some(Leaf {
        plan_id: &raw[0..32],
        run_id: &raw[32..64],
        region: u32_at(raw, 64)?,
        coord_region: u32_at(raw, 68)?,
        segment: u32_at(raw, 72)?,
        ordinal,
        node: u32_at(raw, 84)?,
        kernel_step: u32_at(raw, 88)?,
        inputs: &raw[94..ins_end],
        outputs: &raw[outs_start..outs_end],
        prior: &raw[outs_end..outs_end + 32],
        next: &raw[outs_end + 32..outs_end + 64],
    })
}

/// `StepSpec` fields the referee compares (§5.1).
pub struct StepSpec<'a>(pub &'a [u8]);

impl<'a> StepSpec<'a> {
    pub const HEAD: usize = 192;
    pub const INPUT: usize = 72;
    pub const OUTPUT: usize = 24;
    pub fn valid(&self) -> bool {
        let r = self.0;
        r.len() >= Self::HEAD
            && &r[..4] == b"DSS1"
            && r[184] <= 8
            && r[185] <= 8
            && r.len() == Self::HEAD + r[184] as usize * Self::INPUT + r[185] as usize * Self::OUTPUT
    }
    pub fn region(&self) -> u32 {
        u32_at(self.0, 4).unwrap()
    }
    pub fn segment(&self) -> u32 {
        u32_at(self.0, 8).unwrap()
    }
    pub fn node(&self) -> u32 {
        u32_at(self.0, 12).unwrap()
    }
    pub fn kernel_step(&self) -> u32 {
        u32_at(self.0, 16).unwrap()
    }
    pub fn kernel_id(&self) -> &'a [u8] {
        &self.0[20..36]
    }
    pub fn semantic_version(&self) -> u16 {
        u16::from_le_bytes([self.0[36], self.0[37]])
    }
    pub fn abi_version(&self) -> u16 {
        u16::from_le_bytes([self.0[38], self.0[39]])
    }
    pub fn state_scheme(&self) -> u8 {
        self.0[120]
    }
    /// The state export port, or `0xFF` for none.
    pub fn state_export(&self) -> u8 {
        self.0[121]
    }
    pub fn state_size(&self) -> u64 {
        u64_at(self.0, 128).unwrap()
    }
    pub fn state_predecessor(&self) -> (u8, u64, u32, u32, u32) {
        producer(&self.0[136..160])
    }
    pub fn input_count(&self) -> usize {
        self.0[184] as usize
    }
    pub fn output_count(&self) -> usize {
        self.0[185] as usize
    }
    pub fn input_header(&self, i: usize) -> &'a [u8] {
        let at = Self::HEAD + i * Self::INPUT;
        &self.0[at..at + PORT_HEADER_BYTES]
    }
    /// (kind, a, b, c, d)
    pub fn input_producer(&self, i: usize) -> (u8, u64, u32, u32, u32) {
        producer(&self.0[Self::HEAD + i * Self::INPUT + 23..Self::HEAD + i * Self::INPUT + 47])
    }
    pub fn output_header(&self, i: usize) -> &'a [u8] {
        let at = Self::HEAD + self.input_count() * Self::INPUT + i * Self::OUTPUT;
        &self.0[at..at + PORT_HEADER_BYTES]
    }
}

/// Strict view of a DLS1 record. Elements are `header(23), producer(24), pad(1)`.
pub struct ListSpec<'a>(pub &'a [u8]);

impl<'a> ListSpec<'a> {
    pub fn valid(&self) -> bool {
        let r = self.0;
        if r.len() < 12 || &r[..4] != b"DLS1" {
            return false;
        }
        let count = u32_at(r, 8).unwrap_or(0) as usize;
        (1..=MAX_LIST_ELEMENTS).contains(&count) && r.len() == 12 + 48 * count
    }
    pub fn id(&self) -> u32 {
        u32_at(self.0, 4).unwrap()
    }
    pub fn count(&self) -> usize {
        u32_at(self.0, 8).unwrap() as usize
    }
    pub fn element_header(&self, index: usize) -> &'a [u8] {
        let at = 12 + 48 * index;
        &self.0[at..at + PORT_HEADER_BYTES]
    }
    /// (kind, a, b, c, d)
    pub fn element_producer(&self, index: usize) -> (u8, u64, u32, u32, u32) {
        let at = 12 + 48 * index + PORT_HEADER_BYTES;
        producer(&self.0[at..at + 24])
    }
}

pub fn producer(raw: &[u8]) -> (u8, u64, u32, u32, u32) {
    (
        raw[0],
        u64::from_le_bytes(raw[4..12].try_into().unwrap()),
        u32_at(raw, 12).unwrap(),
        u32_at(raw, 16).unwrap(),
        u32_at(raw, 20).unwrap(),
    )
}

/// SHAPE (§7.3): true when the leaf differs from the spec in anything but
/// digests, when its state digests are present or absent against the
/// scheme, or when a state export's digest is not the next state's.
pub fn shape_wrong(leaf: &Leaf<'_>, spec: &StepSpec<'_>, plan_id: &[u8], run_id: &[u8], ordinal: u64) -> bool {
    let stateful = spec.state_scheme() != 0;
    let zero = [0u8; 32];
    let wrong = leaf.plan_id != plan_id
        || leaf.run_id != run_id
        || leaf.region != spec.region()
        || leaf.coord_region != spec.region()
        || leaf.segment != spec.segment()
        || leaf.ordinal != ordinal
        || leaf.node != spec.node()
        || leaf.kernel_step != spec.kernel_step()
        || leaf.input_count() != spec.input_count()
        || leaf.output_count() != spec.output_count()
        || (0..spec.input_count()).any(|i| leaf.input(i)[..PORT_HEADER_BYTES] != *spec.input_header(i))
        || (0..spec.output_count()).any(|i| leaf.output(i)[..PORT_HEADER_BYTES] != *spec.output_header(i))
        || (leaf.prior == zero) == stateful
        || (leaf.next == zero) == stateful;
    if wrong || !stateful || spec.state_export() == 0xFF {
        return wrong;
    }
    match leaf.output_port(spec.state_export() as u16) {
        Some(export) => export[23..55] != *leaf.next,
        None => true,
    }
}
