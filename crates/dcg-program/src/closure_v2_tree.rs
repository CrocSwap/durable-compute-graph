// SPDX-License-Identifier: GPL-3.0-only

//! Pure HClosure commitment, Merkle-tree, summary, and certificate helpers.
//! This module defines no account mutation path or instruction dispatcher.

use crate::hash::sha256;
use solana_program::{entrypoint::ProgramResult, program_error::ProgramError};

const PREFIX: &[u8] = b"basanos/dcg-hclosure-";
pub const FORM: u32 = 580;
pub const COORDINATE: u32 = 581;
pub const AUTHORITY: u32 = 582;
pub const LEAF_WRITTEN: u32 = 583;
pub const PRODUCER_PREIMAGE: u32 = 584;
pub const SLOT: u32 = 585;
pub const CHECKPOINT: u32 = 586;
pub const CERTIFICATE: u32 = 587;
pub const INCOMPLETE_COVER: u32 = 588;
pub const BINDING: u32 = 589;
pub const CONTENT: u32 = 590;
pub const FINALIZE_ORDER: u32 = 591;
pub const ALREADY_FINAL: u32 = 592;
pub const NOT_FINAL: u32 = 593;
pub const DEADLINE: u32 = 594;
pub const CHALLENGE: u32 = 595;
pub const STAGE: u32 = 596;
pub const WITNESS_STATE: u32 = 597;
pub const OVERFLOW: u32 = 598;
pub const CLOSE: u32 = 599;

pub(crate) fn refusal(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
/// `sha256(PREFIX | domain | parts...)`, the one domain-separated hash every
/// closure-v2 commitment uses. `pub` because an out-of-crate proof **fixture**
/// has to name a domain (`segment-root/2`) it cannot otherwise reach: the
/// integration tests build a segment root from a fold the program itself
/// computed, and a test that re-spelled the domain layout would be testing its
/// own arithmetic instead of the program's.
pub fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    assert!(parts.len() + 2 <= 16, "closure hash parts overflow");
    let mut all: [&[u8]; 16] = [&[]; 16];
    all[0] = PREFIX;
    all[1] = domain;
    all[2..parts.len() + 2].copy_from_slice(parts);
    sha256(&all[..parts.len() + 2])
}
pub(crate) fn u16_at(b: &[u8], i: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or(refusal(FORM))?
            .try_into()
            .map_err(|_| refusal(FORM))?,
    ))
}
pub(crate) fn u32_at(b: &[u8], i: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or(refusal(FORM))?
            .try_into()
            .map_err(|_| refusal(FORM))?,
    ))
}
pub(crate) fn u64_at(b: &[u8], i: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8)
            .ok_or(refusal(FORM))?
            .try_into()
            .map_err(|_| refusal(FORM))?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub position: u32,
    pub segment: u16,
    pub entry: u32,
}
impl Coordinate {
    pub fn bytes(self) -> [u8; 10] {
        let mut b = [0; 10];
        b[..4].copy_from_slice(&self.position.to_le_bytes());
        b[4..6].copy_from_slice(&self.segment.to_le_bytes());
        b[6..].copy_from_slice(&self.entry.to_le_bytes());
        b
    }
}

/// Narrow PT1 seam.  The adapter must validate the sealed template, operation
/// locator, mode, read/write routes and sampled bytes before constructing it.
pub struct InstantiatedEntry<'a> {
    pub coordinate: Coordinate,
    pub operation_ordinal: u16,
    pub kernel_index: u16,
    pub mode_id: u16,
    pub witness_state: u8,
    pub midstate_digest: [u8; 32],
    pub read_rows: &'a [u8],  // exactly read_count * 120 canonical bytes
    pub write_rows: &'a [u8], // exactly write_count * 48 canonical bytes
}

pub fn write_digest(
    descriptor: &[u8; 32],
    coordinate: Coordinate,
    region: u16,
    offset: u64,
    bytes: &[u8],
) -> Result<[u8; 32], ProgramError> {
    let len = u32::try_from(bytes.len()).map_err(|_| refusal(OVERFLOW))?;
    Ok(hash(
        b"write/2",
        &[
            descriptor,
            &coordinate.bytes(),
            &region.to_le_bytes(),
            &offset.to_le_bytes(),
            &len.to_le_bytes(),
            bytes,
        ],
    ))
}

pub fn input_root(
    descriptor: &[u8; 32],
    entry: &InstantiatedEntry<'_>,
) -> Result<[u8; 32], ProgramError> {
    if entry.read_rows.len() % 120 != 0 {
        return Err(refusal(FORM));
    }
    let count = u16::try_from(entry.read_rows.len() / 120).map_err(|_| refusal(OVERFLOW))?;
    let mut previous = None;
    for row in entry.read_rows.chunks_exact(120) {
        let pair = (row[2], row[3]);
        if row[4..8] != [0; 4]
            || row[20..24] != [0; 4]
            || !matches!(pair, (0, 0 | 1) | (1 | 2, 0) | (3, 2))
            || u32_at(row, 16)? == 0
        {
            return Err(refusal(FORM));
        }
        let key = (u16_at(row, 0)?, u64_at(row, 8)?);
        if previous.is_some_and(|p| p >= key) {
            return Err(refusal(FORM));
        }
        previous = Some(key);
    }
    Ok(hash(
        b"input/2",
        &[
            descriptor,
            &entry.coordinate.bytes(),
            &entry.kernel_index.to_le_bytes(),
            &count.to_le_bytes(),
            entry.read_rows,
        ],
    ))
}

pub fn leaf(
    descriptor: &[u8; 32],
    entry: &InstantiatedEntry<'_>,
) -> Result<[u8; 32], ProgramError> {
    if entry.write_rows.len() % 48 != 0 {
        return Err(refusal(FORM));
    }
    if entry.mode_id != 1 && entry.mode_id != 2 {
        return Err(refusal(FORM));
    }
    if entry.witness_state > 1
        || (entry.witness_state == 0 && entry.midstate_digest != [0; 32])
        || (entry.witness_state == 1 && entry.midstate_digest == [0; 32])
    {
        return Err(refusal(WITNESS_STATE));
    }
    let read_count = u16::try_from(entry.read_rows.len() / 120).map_err(|_| refusal(OVERFLOW))?;
    let write_count = u16::try_from(entry.write_rows.len() / 48).map_err(|_| refusal(OVERFLOW))?;
    let mut previous = None;
    for row in entry.write_rows.chunks_exact(48) {
        if row[2..4] != [0; 2] || u32_at(row, 4)? == 0 {
            return Err(refusal(FORM));
        }
        let key = (u16_at(row, 0)?, u64_at(row, 8)?);
        if previous.is_some_and(|p| p >= key) {
            return Err(refusal(FORM));
        }
        previous = Some(key);
    }
    let input = input_root(descriptor, entry)?;
    Ok(hash(
        b"leaf/2",
        &[
            descriptor,
            &entry.coordinate.bytes(),
            &entry.operation_ordinal.to_le_bytes(),
            &entry.kernel_index.to_le_bytes(),
            &entry.mode_id.to_le_bytes(),
            &read_count.to_le_bytes(),
            &[entry.witness_state, 0],
            &input,
            &entry.midstate_digest,
            &write_count.to_le_bytes(),
            &[0, 0],
            entry.write_rows,
        ],
    ))
}

#[derive(Clone, Copy)]
pub(crate) struct Node {
    pub digest: [u8; 32],
    pub first: u32,
    pub end: u32,
}

pub(crate) fn parent(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    height: u8,
    left: Node,
    right: Node,
) -> Node {
    Node {
        digest: hash(
            b"node/2",
            &[
                descriptor,
                &[kind],
                &scope.to_le_bytes(),
                &left.first.to_le_bytes(),
                &right.end.to_le_bytes(),
                &[height, 1],
                &left.digest,
                &right.digest,
            ],
        ),
        first: left.first,
        end: right.end,
    }
}

/// Constant-memory tree fold over a flat digest array.  A segment of 3,244
/// leaves and a 2,000-position document use the same 20-node frontier.
pub fn tree_flat(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    flat: &[u8],
) -> Result<[u8; 32], ProgramError> {
    if flat.is_empty() || flat.len() % 32 != 0 || !(1..=3).contains(&kind) {
        return Err(refusal(FORM));
    }
    let count = u32::try_from(flat.len() / 32).map_err(|_| refusal(OVERFLOW))?;
    let mut stack: [Option<Node>; 20] = [None; 20];
    for (i, raw) in flat.chunks_exact(32).enumerate() {
        let mut node = Node {
            digest: raw.try_into().map_err(|_| refusal(FORM))?,
            first: i as u32,
            end: i as u32 + 1,
        };
        let mut h = 0usize;
        loop {
            let slot = stack.get_mut(h).ok_or(refusal(OVERFLOW))?;
            if let Some(left) = slot.take() {
                node = parent(descriptor, kind, scope, (h + 1) as u8, left, node);
                h += 1;
            } else {
                *slot = Some(node);
                break;
            }
        }
    }
    let mut carry: Option<(Node, usize)> = None;
    for h in 0..20 {
        let Some(left) = stack[h] else { continue };
        carry = Some(if let Some((mut right, mut right_h)) = carry {
            while right_h < h {
                right = parent(descriptor, kind, scope, (right_h + 1) as u8, right, right);
                right_h += 1;
            }
            (
                parent(descriptor, kind, scope, (h + 1) as u8, left, right),
                h + 1,
            )
        } else {
            (left, h)
        });
    }
    let (root, _) = carry.ok_or(refusal(FORM))?;
    debug_assert_eq!(root.first, 0);
    debug_assert_eq!(root.end, count);
    Ok(root.digest)
}

/// Complete duplicate-last tree.  The odd right child repeats the last digest
/// and clipped interval; height is the parent's height, beginning at one.
pub fn tree(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    values: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    if values.is_empty() || !(1..=3).contains(&kind) {
        return Err(refusal(FORM));
    }
    let mut level: Vec<Node> = values
        .iter()
        .enumerate()
        .map(|(i, digest)| Node {
            digest: *digest,
            first: i as u32,
            end: i as u32 + 1,
        })
        .collect();
    let mut height = 0u8;
    while level.len() > 1 {
        height = height.checked_add(1).ok_or(refusal(OVERFLOW))?;
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(Node {
                digest: hash(
                    b"node/2",
                    &[
                        descriptor,
                        &[kind],
                        &scope.to_le_bytes(),
                        &left.first.to_le_bytes(),
                        &right.end.to_le_bytes(),
                        &[height, 1],
                        &left.digest,
                        &right.digest,
                    ],
                ),
                first: left.first,
                end: right.end,
            });
        }
        level = next;
    }
    Ok(level[0].digest)
}

pub fn segment_root(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    let n = u32::try_from(leaves.len()).map_err(|_| refusal(OVERFLOW))?;
    let root = tree(descriptor, 1, position, leaves)?;
    Ok(hash(
        b"segment-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &segment.to_le_bytes(),
            &n.to_le_bytes(),
            &root,
            &[1],
        ],
    ))
}

pub fn position_root(
    descriptor: &[u8; 32],
    position: u32,
    segment_table_root: &[u8; 32],
    segments: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    let n = u16::try_from(segments.len()).map_err(|_| refusal(OVERFLOW))?;
    let root = tree(descriptor, 2, position, segments)?;
    Ok(hash(
        b"position-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &n.to_le_bytes(),
            segment_table_root,
            &root,
            &[1],
        ],
    ))
}

pub fn document_root(
    descriptor: &[u8; 32],
    positions: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    let n = u32::try_from(positions.len()).map_err(|_| refusal(OVERFLOW))?;
    let root = tree(descriptor, 3, u32::MAX, positions)?;
    Ok(hash(
        b"document-root/2",
        &[descriptor, &n.to_le_bytes(), &root, &[1]],
    ))
}

pub fn family_id(descriptor: &[u8; 32], ordinal: u16, kind: u8) -> [u8; 32] {
    hash(
        b"family/2",
        &[descriptor, &ordinal.to_le_bytes(), &[kind, 0]],
    )
}
pub fn producer_ref(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    coordinate: Coordinate,
    row: u8,
    data_digest: &[u8; 32],
) -> [u8; 32] {
    hash(
        b"producer-seal/2",
        &[descriptor, family, &coordinate.bytes(), &[row], data_digest],
    )
}
pub fn slot_binding(coordinate: Coordinate, write_ordinal: u8, data_digest: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..10].copy_from_slice(&coordinate.bytes());
    out[10] = write_ordinal;
    out[16..48].copy_from_slice(data_digest);
    out
}
pub fn range_bytes_digest(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    data_digests: &[u8],
) -> Result<[u8; 32], ProgramError> {
    if data_digests.is_empty() || data_digests.len() % 32 != 0 {
        return Err(refusal(FORM));
    }
    let count = u32::try_from(data_digests.len() / 32).map_err(|_| refusal(OVERFLOW))?;
    Ok(hash(
        b"range-bytes/2",
        &[descriptor, family, &count.to_le_bytes(), data_digests],
    ))
}
pub fn input_binding_digest(
    descriptor: &[u8; 32],
    family_ordinal: u16,
    sequence: u64,
    checkpoint: &[u8; 32],
    first: u32,
    end: u32,
    slot_bindings: &[u8],
) -> Result<[u8; 32], ProgramError> {
    if first >= end || slot_bindings.is_empty() || slot_bindings.len() % 48 != 0 {
        return Err(refusal(BINDING));
    }
    let count = u32::try_from(slot_bindings.len() / 48).map_err(|_| refusal(OVERFLOW))?;
    let mut previous = None;
    for row in slot_bindings.chunks_exact(48) {
        let pos = u32_at(row, 0)?;
        if !(first..end).contains(&pos) || row[11..16] != [0; 5] {
            return Err(refusal(BINDING));
        }
        let key = (pos, u16_at(row, 4)?, u32_at(row, 6)?, row[10]);
        if previous.is_some_and(|old| old >= key) {
            return Err(refusal(BINDING));
        }
        previous = Some(key);
    }
    Ok(hash(
        b"input-binding/2",
        &[
            descriptor,
            &family_ordinal.to_le_bytes(),
            &[0, 0],
            &sequence.to_le_bytes(),
            checkpoint,
            &first.to_le_bytes(),
            &end.to_le_bytes(),
            &count.to_le_bytes(),
            slot_bindings,
        ],
    ))
}
pub fn summary_leaf(
    family: &[u8; 32],
    position: u32,
    slot_rows: &[u8],
) -> Result<([u8; 32], bool), ProgramError> {
    if slot_rows.len() % 40 != 0 {
        return Err(refusal(FORM));
    }
    let count = u8::try_from(slot_rows.len() / 40).map_err(|_| refusal(OVERFLOW))?;
    let mut previous = None;
    for row in slot_rows.chunks_exact(40) {
        if row[7] != 0 {
            return Err(refusal(FORM));
        }
        let key = (u16_at(row, 0)?, u32_at(row, 2)?, row[6]);
        if previous.is_some_and(|old| old >= key) {
            return Err(refusal(SLOT));
        }
        previous = Some(key);
    }
    let complete = slot_rows.chunks_exact(40).all(|row| row[8..40] != [0; 32]);
    Ok((
        hash(
            b"summary-leaf/2",
            &[
                family,
                &position.to_le_bytes(),
                &[count, complete as u8, 0, 0],
                slot_rows,
            ],
        ),
        complete,
    ))
}
pub fn summary_node(
    family: &[u8; 32],
    first: u32,
    end: u32,
    height: u8,
    left: &([u8; 32], bool),
    right: &([u8; 32], bool),
) -> ([u8; 32], bool) {
    let complete = left.1 && right.1;
    (
        hash(
            b"summary-node/2",
            &[
                family,
                &first.to_le_bytes(),
                &end.to_le_bytes(),
                &[height, complete as u8],
                &left.0,
                &right.0,
            ],
        ),
        complete,
    )
}
pub fn padding(descriptor: &[u8; 32], family: &[u8; 32], position: u32) -> [u8; 32] {
    hash(b"padding/2", &[descriptor, family, &position.to_le_bytes()])
}
pub fn checkpoint_digest(
    sequence: u64,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    family_root: &[u8; 32],
    complete: bool,
) -> [u8; 32] {
    hash(
        b"certificate/2",
        &[
            &sequence.to_le_bytes(),
            descriptor,
            family,
            family_root,
            &[complete as u8],
        ],
    )
}
pub const CHECKPOINT_BYTES: usize = 338;

/// Exact rev-3 §5.4 checkpoint bytes.  The three cross-shard nodes must be
/// derived from the four authenticated shard roots by the caller.
pub fn checkpoint_record(
    sequence: u64,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    capacity: u32,
    positions: u32,
    shards: &[[u8; 32]; 4],
    cross: &[[u8; 32]; 3],
    complete: bool,
) -> Result<([u8; CHECKPOINT_BYTES], [u8; 32]), ProgramError> {
    let root = family_root(
        descriptor, family, capacity, positions, shards, cross, complete,
    )?;
    let mut out = [0u8; CHECKPOINT_BYTES];
    out[..8].copy_from_slice(&sequence.to_le_bytes());
    out[8..40].copy_from_slice(descriptor);
    out[40..72].copy_from_slice(family);
    out[72..76].copy_from_slice(&capacity.to_le_bytes());
    out[76..80].copy_from_slice(&positions.to_le_bytes());
    out[80] = 4;
    for (i, shard) in shards.iter().enumerate() {
        out[81 + i * 32..113 + i * 32].copy_from_slice(shard);
    }
    for (i, node) in cross.iter().enumerate() {
        out[209 + i * 32..241 + i * 32].copy_from_slice(node);
    }
    out[305..337].copy_from_slice(&root);
    out[337] = complete as u8;
    Ok((
        out,
        checkpoint_digest(sequence, descriptor, family, &root, complete),
    ))
}

pub fn family_root(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    capacity: u32,
    positions: u32,
    shards: &[[u8; 32]; 4],
    cross: &[[u8; 32]; 3],
    complete: bool,
) -> Result<[u8; 32], ProgramError> {
    if capacity < 4 || !capacity.is_power_of_two() || positions > capacity {
        return Err(refusal(FORM));
    }
    let cap = capacity.to_le_bytes();
    let count = positions.to_le_bytes();
    Ok(hash(
        b"summary-root/2",
        &[
            descriptor,
            family,
            &cap,
            &count,
            &shards[0],
            &shards[1],
            &shards[2],
            &shards[3],
            &cross[0],
            &cross[1],
            &cross[2],
            &[complete as u8],
        ],
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateNode {
    pub first: u32,
    pub height: u8,
    pub complete: bool,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateGroup {
    pub family_ordinal: u16,
    pub first: u32,
    pub end: u32,
    pub sequence: u64,
    pub cover: Vec<CertificateNode>,
    pub auth: Vec<CertificateNode>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub coordinate: Coordinate,
    pub groups: Vec<CertificateGroup>,
}

pub fn greedy_cover(mut first: u32, end: u32) -> Result<Vec<(u32, u8)>, ProgramError> {
    if first >= end || end > (1 << 19) {
        return Err(refusal(CERTIFICATE));
    }
    let mut out = Vec::new();
    while first < end {
        let remaining = end - first;
        let mut height = (31 - remaining.leading_zeros()) as u8;
        if first != 0 {
            height = height.min(first.trailing_zeros() as u8);
        }
        out.push((first, height));
        first = first.checked_add(1 << height).ok_or(refusal(OVERFLOW))?;
    }
    Ok(out)
}

/// DHR2 exact-EOF framing and canonical-cover checks.  The caller checks the
/// parsed groups against the sealed range declarations and checkpoint roots.
pub fn parse_certificate(raw: &[u8]) -> Result<Certificate, ProgramError> {
    if raw.len() < 28
        || raw.len() > 3164
        || raw[..4] != *b"DHR2"
        || u16_at(raw, 4)? != 1
        || u16_at(raw, 6)? != 0
        || u16_at(raw, 14)? != 0
        || raw[21] != 0
        || u16_at(raw, 26)? != 0
    {
        return Err(refusal(CERTIFICATE));
    }
    let groups = raw[20] as usize;
    if !(1..=4).contains(&groups) || u16_at(raw, 22)? > 38 || u16_at(raw, 24)? > 38 {
        return Err(refusal(CERTIFICATE));
    }
    let coordinate = Coordinate {
        position: u32_at(raw, 8)?,
        segment: u16_at(raw, 12)?,
        entry: u32_at(raw, 16)?,
    };
    let mut offset = 28usize;
    let mut parsed = Vec::with_capacity(groups);
    let mut total_cover = 0usize;
    let mut total_auth = 0usize;
    for _ in 0..groups {
        let head = raw.get(offset..offset + 24).ok_or(refusal(CERTIFICATE))?;
        if u16_at(head, 2)? != 0 || u16_at(head, 14)? != 0 {
            return Err(refusal(CERTIFICATE));
        }
        let family_ordinal = u16_at(head, 0)?;
        if parsed
            .last()
            .is_some_and(|g: &CertificateGroup| g.family_ordinal >= family_ordinal)
        {
            return Err(refusal(CERTIFICATE));
        }
        let first = u32_at(head, 4)?;
        let end = u32_at(head, 8)?;
        let cover_count = head[12] as usize;
        let auth_count = head[13] as usize;
        total_cover = total_cover
            .checked_add(cover_count)
            .ok_or(refusal(OVERFLOW))?;
        total_auth = total_auth
            .checked_add(auth_count)
            .ok_or(refusal(OVERFLOW))?;
        if total_cover > 38 || total_auth > 38 {
            return Err(refusal(CERTIFICATE));
        }
        let sequence = u64_at(head, 16)?;
        offset += 24;
        let mut nodes = Vec::with_capacity(cover_count + auth_count);
        for _ in 0..cover_count + auth_count {
            let b = raw.get(offset..offset + 40).ok_or(refusal(CERTIFICATE))?;
            if u16_at(b, 6)? != 0 || b[5] > 1 || b[4] > 19 {
                return Err(refusal(CERTIFICATE));
            }
            nodes.push(CertificateNode {
                first: u32_at(b, 0)?,
                height: b[4],
                complete: b[5] == 1,
                digest: b[8..40].try_into().map_err(|_| refusal(CERTIFICATE))?,
            });
            offset += 40;
        }
        let expected = greedy_cover(first, end)?;
        if expected.len() != cover_count
            || nodes[..cover_count]
                .iter()
                .zip(&expected)
                .any(|(node, &(f, h))| node.first != f || node.height != h)
        {
            return Err(refusal(CERTIFICATE));
        }
        if nodes[..cover_count].iter().any(|node| !node.complete) {
            return Err(refusal(INCOMPLETE_COVER));
        }
        parsed.push(CertificateGroup {
            family_ordinal,
            first,
            end,
            sequence,
            cover: nodes[..cover_count].to_vec(),
            auth: nodes[cover_count..].to_vec(),
        });
    }
    if offset != raw.len()
        || total_cover != u16_at(raw, 22)? as usize
        || total_auth != u16_at(raw, 24)? as usize
    {
        return Err(refusal(CERTIFICATE));
    }
    Ok(Certificate {
        coordinate,
        groups: parsed,
    })
}

/// Rebuild a canonical DHR2 group against an immutable checkpoint.  The
/// minimum authentication multiproof is the left-first DFS of subtrees fully
/// outside the requested range.  The parser already checked the greedy cover.
pub fn verify_certificate_group(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    group: &CertificateGroup,
    checkpoint: &[u8],
) -> ProgramResult {
    if checkpoint.len() != CHECKPOINT_BYTES
        || checkpoint[8..40] != *descriptor
        || checkpoint[40..72] != *family
        || u64_at(checkpoint, 0)? != group.sequence
        || checkpoint[80] != 4
        || checkpoint[337] > 1
    {
        return Err(refusal(CHECKPOINT));
    }
    let capacity = u32_at(checkpoint, 72)?;
    let positions = u32_at(checkpoint, 76)?;
    if capacity < 4
        || capacity > (1 << 19)
        || !capacity.is_power_of_two()
        || positions == 0
        || positions > capacity
        || group.first >= group.end
        || group.end > positions
    {
        return Err(refusal(CERTIFICATE));
    }
    let shards: [[u8; 32]; 4] =
        std::array::from_fn(|i| checkpoint[81 + i * 32..113 + i * 32].try_into().unwrap());
    let cross: [[u8; 32]; 3] =
        std::array::from_fn(|i| checkpoint[209 + i * 32..241 + i * 32].try_into().unwrap());
    let root = family_root(
        descriptor,
        family,
        capacity,
        positions,
        &shards,
        &cross,
        checkpoint[337] == 1,
    )?;
    if checkpoint[305..337] != root {
        return Err(refusal(CHECKPOINT));
    }

    fn fold(
        family: &[u8; 32],
        first: u32,
        height: u8,
        range: (u32, u32),
        cover: &mut std::slice::Iter<'_, CertificateNode>,
        auth: &mut std::slice::Iter<'_, CertificateNode>,
    ) -> Result<([u8; 32], bool), ProgramError> {
        let end = first.checked_add(1u32 << height).ok_or(refusal(OVERFLOW))?;
        if range.0 <= first && end <= range.1 {
            let n = cover.next().ok_or(refusal(CERTIFICATE))?;
            if n.first != first || n.height != height || !n.complete {
                return Err(refusal(CERTIFICATE));
            }
            return Ok((n.digest, true));
        }
        if end <= range.0 || first >= range.1 {
            let n = auth.next().ok_or(refusal(CERTIFICATE))?;
            if n.first != first || n.height != height {
                return Err(refusal(CERTIFICATE));
            }
            return Ok((n.digest, n.complete));
        }
        if height == 0 {
            return Err(refusal(CERTIFICATE));
        }
        let mid = first + (1u32 << (height - 1));
        let left = fold(family, first, height - 1, range, cover, auth)?;
        let right = fold(family, mid, height - 1, range, cover, auth)?;
        Ok(summary_node(family, first, end, height, &left, &right))
    }
    let mut cover = group.cover.iter();
    let mut auth = group.auth.iter();
    let height = capacity.trailing_zeros() as u8;
    let computed = fold(
        family,
        0,
        height,
        (group.first, group.end),
        &mut cover,
        &mut auth,
    )?;
    if cover.next().is_some() || auth.next().is_some() || computed.0 != cross[2] {
        return Err(refusal(CERTIFICATE));
    }
    Ok(())
}
