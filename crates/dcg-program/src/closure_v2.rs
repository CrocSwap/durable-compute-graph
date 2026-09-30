//! Closure-v2 STORED_PAGES primitives.  The PT1 adapter supplies an
//! `InstantiatedEntry`; this module never decodes a template or guesses a
//! template-entry-to-segment locator.  Account handlers below authenticate
//! their already-provisioned program-owned pages before mutation.

use crate::hash::sha256;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

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

fn refusal(code: u32) -> ProgramError {
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
fn u16_at(b: &[u8], i: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or(refusal(FORM))?
            .try_into()
            .map_err(|_| refusal(FORM))?,
    ))
}
fn u32_at(b: &[u8], i: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or(refusal(FORM))?
            .try_into()
            .map_err(|_| refusal(FORM))?,
    ))
}
fn u64_at(b: &[u8], i: usize) -> Result<u64, ProgramError> {
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

pub fn shard_address(
    program: &Pubkey,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    shard: u8,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-shard", descriptor, family, &[shard]], program)
}
pub fn checkpoint_address(program: &Pubkey, family: &[u8; 32], sequence: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"dcg-hcl-checkpoint", family, &sequence.to_le_bytes()],
        program,
    )
}

/// PROPOSED DSH2 shard layout: 96-byte header followed by heap-order
/// `(digest[32], complete:u8)` nodes, root first. The sealed PT1 adapter
/// provisions this account from the static family slot table.
pub const DSH2_HEADER: usize = 96;
pub fn shard_bytes(capacity: u32) -> Result<usize, ProgramError> {
    if capacity < 4 || capacity > (1 << 19) || !capacity.is_power_of_two() {
        return Err(refusal(FORM));
    }
    let per_shard = capacity / 4;
    let nodes = per_shard
        .checked_mul(2)
        .and_then(|n| n.checked_sub(1))
        .ok_or(refusal(OVERFLOW))?;
    DSH2_HEADER
        .checked_add((nodes as usize).checked_mul(33).ok_or(refusal(OVERFLOW))?)
        .ok_or(refusal(OVERFLOW))
}
fn shard_root(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    capacity: u32,
    positions: u32,
    shard: u8,
) -> Result<([u8; 32], bool), ProgramError> {
    if account.owner != program
        || *account.key != shard_address(program, descriptor, family, shard).0
    {
        return Err(refusal(FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() != shard_bytes(capacity)?
        || data[..4] != *b"DSH2"
        || u16_at(&data, 4)? != 1
        || u16_at(&data, 6)? != 0
        || data[8..40] != *descriptor
        || data[40..72] != *family
        || u32_at(&data, 72)? != capacity
        || u32_at(&data, 76)? != positions
        || data[80] != shard
        || data[81..96] != [0; 15]
        || data[128] > 1
    {
        return Err(refusal(FORM));
    }
    let root: [u8; 32] = data[96..128].try_into().map_err(|_| refusal(FORM))?;
    if root == [0; 32] {
        return Err(refusal(FORM));
    }
    Ok((root, data[128] == 1))
}

/// CheckpointPublish writes only after every account, sequence and root has
/// been checked. Destination is an already-provisioned, zeroed 338-byte PDA.
pub fn publish_checkpoint(
    program: &Pubkey,
    state: &AccountInfo,
    authority: &AccountInfo,
    destination: &AccountInfo,
    shards: &[AccountInfo],
    previous: Option<&AccountInfo>,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    sequence: u64,
) -> ProgramResult {
    let facts =
        crate::seal::open_state(program, state, descriptor, FORM).map_err(|_| refusal(FORM))?;
    if !facts.sealed || !authority.is_signer || authority.key.to_bytes() != facts.authority {
        return Err(refusal(AUTHORITY));
    }
    if shards.len() != 4
        || destination.owner != program
        || !destination.is_writable
        || *destination.key != checkpoint_address(program, family, sequence).0
        || destination.data_len() != CHECKPOINT_BYTES
    {
        return Err(refusal(FORM));
    }
    let dest = destination.try_borrow_data()?;
    if dest.iter().any(|&b| b != 0) {
        return Err(refusal(CHECKPOINT));
    }
    drop(dest);
    let first = shards[0].try_borrow_data()?;
    if first.len() < DSH2_HEADER {
        return Err(refusal(FORM));
    }
    let capacity = u32_at(&first, 72)?;
    let positions = u32_at(&first, 76)?;
    drop(first);
    if positions == 0 || positions > capacity {
        return Err(refusal(FORM));
    }
    let mut roots = [[0u8; 32]; 4];
    let mut complete = [false; 4];
    for i in 0..4 {
        (roots[i], complete[i]) = shard_root(
            program, &shards[i], descriptor, family, capacity, positions, i as u8,
        )?;
    }
    let h = (capacity / 4).trailing_zeros() as u8 + 1;
    let left = summary_node(
        family,
        0,
        capacity / 2,
        h,
        &(roots[0], complete[0]),
        &(roots[1], complete[1]),
    );
    let right = summary_node(
        family,
        capacity / 2,
        capacity,
        h,
        &(roots[2], complete[2]),
        &(roots[3], complete[3]),
    );
    let top = summary_node(family, 0, capacity, h + 1, &left, &right);
    let cross = [left.0, right.0, top.0];
    let (record, _) = checkpoint_record(
        sequence, descriptor, family, capacity, positions, &roots, &cross, top.1,
    )?;
    if sequence == 0 {
        if previous.is_some() {
            return Err(refusal(FORM));
        }
    } else {
        let prior = previous.ok_or(refusal(CHECKPOINT))?;
        if prior.owner != program
            || *prior.key != checkpoint_address(program, family, sequence - 1).0
        {
            return Err(refusal(FORM));
        }
        let raw = prior.try_borrow_data()?;
        if raw.len() != CHECKPOINT_BYTES
            || u64_at(&raw, 0)? != sequence - 1
            || raw[8..40] != *descriptor
            || raw[40..72] != *family
            || u32_at(&raw, 72)? != capacity
            || u32_at(&raw, 76)? != positions
            || raw[80] != 4
            || raw[305..337] == record[305..337]
        {
            return Err(refusal(CHECKPOINT));
        }
    }
    destination.try_borrow_mut_data()?.copy_from_slice(&record);
    Ok(())
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

// Open-seed proposal: all seeds below are <= 32 bytes and bind to a descriptor.
pub fn page_address(
    program: &Pubkey,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"dcg-hcl-page",
            descriptor,
            &position.to_le_bytes(),
            &segment.to_le_bytes(),
        ],
        program,
    )
}
pub fn position_page_address(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-positions", descriptor], program)
}
pub fn document_address(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-document", descriptor], program)
}
pub fn result_address(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dcg-hcl-result", descriptor], program)
}

/// DLP2 exact size, checked before any account slice is read or written.
pub fn page_bytes(entries: u32, consumers: u32) -> Result<usize, ProgramError> {
    let leaves = entries.checked_mul(32).ok_or(refusal(OVERFLOW))?;
    let records = consumers.checked_mul(44).ok_or(refusal(OVERFLOW))?;
    let n = 96u32
        .checked_add(leaves)
        .and_then(|x| x.checked_add(records))
        .ok_or(refusal(OVERFLOW))?;
    usize::try_from(n).map_err(|_| refusal(OVERFLOW))
}

fn authenticate_page(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    require_write: bool,
) -> Result<(u32, u32), ProgramError> {
    if account.owner != program
        || (require_write && !account.is_writable)
        || *account.key != page_address(program, descriptor, position, segment).0
    {
        return Err(refusal(FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() < 96
        || data[..4] != *b"DLP2"
        || u16_at(&data, 4)? != 1
        || data[8..40] != *descriptor
        || u32_at(&data, 40)? != position
        || u16_at(&data, 44)? != segment
        || data[46..48] != [0; 2]
        || data[60..64] != [0; 4]
    {
        return Err(refusal(FORM));
    }
    let entries = u32_at(&data, 48)?;
    let consumers = u32_at(&data, 56)?;
    let flags = u16_at(&data, 6)?;
    if entries == 0
        || data.len() != page_bytes(entries, consumers)?
        || u32_at(&data, 52)? > entries
        || (flags & !1) != 0
        || (flags & 1 == 0 && data[64..96] != [0; 32])
        || (flags & 1 != 0 && (data[64..96] == [0; 32] || u32_at(&data, 52)? != entries))
    {
        return Err(refusal(FORM));
    }
    Ok((entries, consumers))
}

/// Bind a page operation to the sealed document's fixed segment geometry.
/// The DCM2 initializer is the PT1 adapter's responsibility; a page header
/// supplied by an arbitrary account is never itself a segment declaration.
fn declared_segment(
    program: &Pubkey,
    document: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
) -> Result<u32, ProgramError> {
    let facts = authenticate_document(program, document, descriptor, false)?;
    if position >= facts.position_count {
        return Err(refusal(COORDINATE));
    }
    let data = document.try_borrow_data()?;
    if u16_at(&data, 6)? & 1 == 0 {
        return Err(refusal(FORM));
    }
    if u16_at(&data, 6)? & crate::root_only::MODE_FLAG != 0 {
        return Err(refusal(FORM));
    }
    if u16_at(&data, 6)? & 2 != 0 {
        return Err(refusal(ALREADY_FINAL));
    }
    let base = manifest_base(&data, position)?;
    let end = base + u16_at(&data, 76)? as usize * 6;
    if u16_at(&data, 4)? >= 2 && data[base - 32..base] == [0; 32] {
        return Err(refusal(FORM));
    }
    let mut previous = None;
    let mut declared = None;
    for row in data[base..end].chunks_exact(6) {
        let id = u16_at(row, 0)?;
        if previous.is_some_and(|old| old >= id) || u32_at(row, 2)? == 0 {
            return Err(refusal(FORM));
        }
        previous = Some(id);
        if u16_at(row, 0)? == segment {
            declared = Some(u32_at(row, 2)?);
        }
    }
    declared.ok_or(refusal(COORDINATE))
}

/// A page is provisioned by the adapter from its sealed segment descriptor.
/// This landing mutates only after the BDS2 signer, PDA, page shape, position,
/// zero slots, and count have all been checked.
pub fn land_leaves(
    program: &Pubkey,
    state: &AccountInfo,
    authority: &AccountInfo,
    document: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    first: u32,
    leaves: &[[u8; 32]],
) -> ProgramResult {
    let bootstrap = {
        let raw = state.try_borrow_data()?;
        raw.get(..4) == Some(b"DCM2".as_slice())
    };
    if bootstrap {
        crate::closure_v2_bootstrap::doc_authority(program, state, authority, descriptor)?;
    } else {
        let facts =
            crate::seal::open_state(program, state, descriptor, FORM).map_err(|_| refusal(FORM))?;
        if !facts.sealed || !authority.is_signer || authority.key.to_bytes() != facts.authority {
            return Err(refusal(AUTHORITY));
        }
    }
    if bootstrap && state.key != document.key {
        return Err(refusal(FORM));
    }
    let (entries, _) = authenticate_page(program, page, descriptor, position, segment, true)?;
    let declared = declared_segment(program, document, descriptor, position, segment)?;
    if entries != declared {
        return Err(refusal(FORM));
    }
    if leaves.is_empty()
        || first
            .checked_add(leaves.len() as u32)
            .ok_or(refusal(OVERFLOW))?
            > entries
    {
        return Err(refusal(COORDINATE));
    }
    let data = page.try_borrow_data()?;
    if u16_at(&data, 6)? & 1 != 0 {
        return Err(refusal(ALREADY_FINAL));
    }
    let landed = u32_at(&data, 52)?;
    for (i, digest) in leaves.iter().enumerate() {
        let off = 96 + (first as usize + i) * 32;
        if *digest == [0; 32] || data[off..off + 32] != [0; 32] {
            return Err(refusal(LEAF_WRITTEN));
        }
    }
    let next = landed
        .checked_add(leaves.len() as u32)
        .ok_or(refusal(OVERFLOW))?;
    if next > entries {
        return Err(refusal(OVERFLOW));
    }
    drop(data);
    let mut data = page.try_borrow_mut_data()?;
    for (i, digest) in leaves.iter().enumerate() {
        let off = 96 + (first as usize + i) * 32;
        data[off..off + 32].copy_from_slice(digest);
    }
    data[52..56].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

pub fn finalize_segment(
    program: &Pubkey,
    document: &AccountInfo,
    page: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
) -> ProgramResult {
    let (entries, consumers) =
        authenticate_page(program, page, descriptor, position, segment, true)?;
    let declared = declared_segment(program, document, descriptor, position, segment)?;
    if entries != declared {
        return Err(refusal(FORM));
    }
    let data = page.try_borrow_data()?;
    if u16_at(&data, 6)? & 1 != 0 {
        return Err(refusal(ALREADY_FINAL));
    }
    if u32_at(&data, 52)? != entries {
        return Err(refusal(FINALIZE_ORDER));
    }
    let flat = &data[96..96 + entries as usize * 32];
    for row in flat.chunks_exact(32) {
        if row == [0; 32] {
            return Err(refusal(FINALIZE_ORDER));
        }
    }
    let record_start = 96 + entries as usize * 32;
    for record in data[record_start..].chunks_exact(44) {
        if record[2..4] != [0; 2] {
            return Err(refusal(FORM));
        }
        if record[12..44] == [0; 32] {
            return Err(refusal(FINALIZE_ORDER));
        }
    }
    debug_assert_eq!(data[record_start..].len(), consumers as usize * 44);
    let tree_root = tree_flat(descriptor, 1, position, flat)?;
    drop(data);
    let root = hash(
        b"segment-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree_root,
            &[1],
        ],
    );
    let mut data = page.try_borrow_mut_data()?;
    data[6..8].copy_from_slice(&1u16.to_le_bytes());
    data[64..96].copy_from_slice(&root);
    Ok(())
}

/// Rev-3 §8.  The caller authenticates descriptor/profile identity against
/// DCD1/BDS2 before supplying `identities_match`.
pub fn close_allowed(
    armed: bool,
    identities_match: bool,
    finalized: bool,
    positions_complete: u32,
    position_count: u32,
    entries_complete: u64,
    expected_entries: u64,
    open_challenges: u32,
    now: u64,
    deadline: u64,
) -> Result<(), ProgramError> {
    if armed
        && identities_match
        && finalized
        && positions_complete == position_count
        && entries_complete == expected_entries
        && open_challenges == 0
        && now > deadline
    {
        Ok(())
    } else {
        Err(refusal(CLOSE))
    }
}

/// PROPOSED DCM2 account layout (rev-3 §8 offsets are open).  Header 192 B:
/// 0 magic, 4 version:u16=1, 6 flags:u16 (armed=1, finalized=2),
/// 8 descriptor[32], 40 profile[32], 72 position_count:u32,
/// 76 segment_count:u16, 78 reserved[2], 80 version-1 entries_per_position
/// or version-2 reserved zero; version 2 appends total_entries:u64 at 192,
/// 84 positions_complete:u32, 88 entries_complete:u64, 96 document_root[32],
/// 128 open_challenges:u32, 132 refuted_positions:u32, 136 finalize_slot:u64,
/// 144 dispute_deadline:u64, 152 segment_table_root[32],
/// 184 dispute_window_slots:u64; then (segment_id:u16, entry_count:u32)*N
/// for version 1, or after the 200-byte header, position-major
/// `(segment_table_root[32], N rows)` for
/// version 2. The PT1 adapter binds each root to its position class.
/// The PT1 adapter must create this account from the sealed descriptor.
pub const DCM2_HEADER: usize = 192;
pub const DCM2_V2_HEADER: usize = 200;
/// Version 3 appends immutable PT1 and proof anchors before the manifest.
pub const DCM2_V3_HEADER: usize = 360;
/// Version 4 (envelope seal ESL1) is version 3 plus 360 registry[32] |
/// 392 registry table_root[32] | 424 admission DEA1[32]; tag 97 seals it only
/// once that admission walk completed (`envelope_seal`).
pub const DCM2_V4_HEADER: usize = 456;
/// Header bytes of a DCM2 version; versions 3 and 4 carry the PT1 anchors.
pub fn dcm2_header(version: u16) -> Option<usize> {
    match version {
        1 => Some(DCM2_HEADER),
        2 => Some(DCM2_V2_HEADER),
        3 => Some(DCM2_V3_HEADER),
        4 => Some(DCM2_V4_HEADER),
        _ => None,
    }
}
pub fn pt1_bound(version: u16) -> bool {
    matches!(version, 3 | 4)
}
pub const DPR2_HEADER: usize = 48;
/// PROPOSED DCR2 durable result: 136-byte header, `token_count` LE u32
/// tokens, and a ceil(token_count/8)-byte write-once presence bitmap.
/// output tokens. Status 0=pending, 1=undisputed, 2=settled, 3=refuted.
/// The PT1 adapter provisions the token bytes from its authenticated output
/// route; this runtime never interprets the sampler as necessarily argmax.
/// Version 2 stores the per-run dispute window as LE u64 at bytes 128..136.
pub const DCR2_HEADER: usize = 136;
fn result_bytes(count: u32) -> Result<usize, ProgramError> {
    let tokens = (count as usize).checked_mul(4).ok_or(refusal(OVERFLOW))?;
    let bitmap = (count as usize).checked_add(7).ok_or(refusal(OVERFLOW))? / 8;
    let size = DCR2_HEADER
        .checked_add(tokens)
        .and_then(|n| n.checked_add(bitmap))
        .ok_or(refusal(OVERFLOW))?;
    if size > 10_485_760 {
        return Err(refusal(OVERFLOW));
    }
    Ok(size)
}
fn authenticate_result(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    write: bool,
) -> Result<u32, ProgramError> {
    if account.owner != program
        || (write && !account.is_writable)
        || *account.key != result_address(program, descriptor).0
    {
        return Err(refusal(FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() < DCR2_HEADER
        || data[..4] != *b"DCR2"
        || u16_at(&data, 4)? != 2
        || data[6] > 3
        || data[7] != 0
        || data[8..40] != *descriptor
        || data[124..128] != [0; 4]
        || u64_at(&data, 128)? == 0
    {
        return Err(refusal(FORM));
    }
    let count = u32_at(&data, 72)?;
    if data.len() != result_bytes(count)? {
        return Err(refusal(FORM));
    }
    Ok(count)
}

/// Program-create a stable result PDA before any output token lands. The
/// sealed adapter must authenticate token_count against the output schedule.
pub fn init_result<'a>(
    program: &Pubkey,
    state: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    document: &AccountInfo<'a>,
    result: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    descriptor: &[u8; 32],
    count: u32,
) -> ProgramResult {
    use solana_program::{
        program::invoke_signed, rent::Rent, system_instruction, system_program, sysvar::Sysvar,
    };
    let bootstrap = state.key == document.key;
    if bootstrap {
        crate::closure_v2_bootstrap::doc_authority(program, state, payer, descriptor)?;
    } else {
        let authority =
            crate::seal::open_state(program, state, descriptor, FORM).map_err(|_| refusal(FORM))?;
        if !authority.sealed || payer.key.to_bytes() != authority.authority {
            return Err(refusal(AUTHORITY));
        }
    }
    let facts = authenticate_document(program, document, descriptor, false)?;
    if !payer.is_signer || !payer.is_writable {
        return Err(refusal(AUTHORITY));
    }
    if count > facts.position_count
        || !result.is_writable
        || *result.key != result_address(program, descriptor).0
        || result.lamports() != 0
        || !result.data_is_empty()
        || *result.owner != system_program::id()
        || *system.key != system_program::id()
    {
        return Err(refusal(FORM));
    }
    let doc = document.try_borrow_data()?;
    if u16_at(&doc, 6)? & 1 == 0 || u16_at(&doc, 6)? & 2 != 0 || doc[40..72] == [0; 32] {
        return Err(refusal(FORM));
    }
    let profile: [u8; 32] = doc[40..72].try_into().map_err(|_| refusal(FORM))?;
    drop(doc);
    let size = result_bytes(count)?;
    let rent = Rent::get()?.minimum_balance(size);
    let (_, bump) = result_address(program, descriptor);
    let bump_bytes = [bump];
    let ix = system_instruction::create_account(payer.key, result.key, rent, size as u64, program);
    invoke_signed(
        &ix,
        &[payer.clone(), result.clone(), system.clone()],
        &[&[b"dcg-hcl-result", descriptor, &bump_bytes]],
    )?;
    let mut raw = result.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DCR2");
    raw[4..6].copy_from_slice(&2u16.to_le_bytes());
    raw[8..40].copy_from_slice(descriptor);
    raw[72..76].copy_from_slice(&count.to_le_bytes());
    raw[92..124].copy_from_slice(&profile);
    raw[128..136].copy_from_slice(&facts.dispute_window.to_le_bytes());
    Ok(())
}

/// Claim one output token. The PT1 adapter must bind the index and token to
/// the terminal TOKEN write; this tag alone is persistence mechanics.
pub fn write_result_token(
    program: &Pubkey,
    state: &AccountInfo,
    authority: &AccountInfo,
    document: &AccountInfo,
    result: &AccountInfo,
    descriptor: &[u8; 32],
    index: u32,
    token: u32,
) -> ProgramResult {
    if state.key == document.key {
        crate::closure_v2_bootstrap::doc_authority(program, state, authority, descriptor)?;
    } else {
        let signer =
            crate::seal::open_state(program, state, descriptor, FORM).map_err(|_| refusal(FORM))?;
        if !signer.sealed || !authority.is_signer || authority.key.to_bytes() != signer.authority {
            return Err(refusal(AUTHORITY));
        }
    }
    let _facts = authenticate_document(program, document, descriptor, false)?;
    let count = authenticate_result(program, result, descriptor, true)?;
    if index >= count {
        return Err(refusal(COORDINATE));
    }
    let doc = document.try_borrow_data()?;
    let raw = result.try_borrow_data()?;
    if u16_at(&doc, 6)? & 2 != 0
        || raw[6] != 0
        || raw[40..72] != [0; 32]
        || raw[92..124] != doc[40..72]
    {
        return Err(refusal(ALREADY_FINAL));
    }
    let bitmap = DCR2_HEADER + count as usize * 4;
    let byte = bitmap + index as usize / 8;
    let mask = 1u8 << (index % 8);
    if raw[byte] & mask != 0 {
        return Err(refusal(LEAF_WRITTEN));
    }
    drop(raw);
    drop(doc);
    let mut raw = result.try_borrow_mut_data()?;
    let offset = DCR2_HEADER + index as usize * 4;
    raw[offset..offset + 4].copy_from_slice(&token.to_le_bytes());
    raw[byte] |= mask;
    Ok(())
}

pub(crate) struct DocumentFacts {
    pub position_count: u32,
    pub segment_count: u16,
    pub expected_entries: u64,
    pub positions_complete: u32,
    pub entries_complete: u64,
    pub segment_table_root: [u8; 32],
    pub dispute_window: u64,
}
pub(crate) fn manifest_base(data: &[u8], position: u32) -> Result<usize, ProgramError> {
    let version = u16_at(data, 4)?;
    let count = u16_at(data, 76)? as usize;
    let variable = matches!(version, 2 | 3 | 4);
    let index = if version == 1 {
        0
    } else if variable {
        position as usize
    } else {
        return Err(refusal(FORM));
    };
    let stride = count
        .checked_mul(6)
        .and_then(|v| v.checked_add(if variable { 32 } else { 0 }))
        .ok_or(refusal(OVERFLOW))?;
    let header = dcm2_header(version).ok_or(refusal(FORM))?;
    header
        .checked_add(index.checked_mul(stride).ok_or(refusal(OVERFLOW))?)
        .and_then(|v| v.checked_add(if variable { 32 } else { 0 }))
        .ok_or(refusal(OVERFLOW))
}
pub(crate) fn authenticate_document(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    write: bool,
) -> Result<DocumentFacts, ProgramError> {
    if account.owner != program
        || (write && !account.is_writable)
        || *account.key != document_address(program, descriptor).0
    {
        return Err(refusal(FORM));
    }
    let data = account.try_borrow_data()?;
    if data.len() < DCM2_HEADER || data[..4] != *b"DCM2" || !matches!(u16_at(&data, 4)?, 1 | 2 | 3 | 4) ||
       data[8..40] != *descriptor || data[78..80] != [0; 2] ||
       // 32 = sealed ROOT_ONLY document (`root_only_sealed`).
       (u16_at(&data, 6)? & !63) != 0
    {
        return Err(refusal(FORM));
    }
    let positions = u32_at(&data, 72)?;
    if positions == 0 || positions > (1 << 19) || u32_at(&data, 84)? > positions {
        return Err(refusal(FORM));
    }
    let count = u16_at(&data, 76)?;
    let v2 = u16_at(&data, 4)? >= 2;
    let copies = if v2 { positions as usize } else { 1usize };
    let stride = (count as usize)
        .checked_mul(6)
        .and_then(|v| v.checked_add(if v2 { 32 } else { 0 }))
        .ok_or(refusal(OVERFLOW))?;
    let header = dcm2_header(u16_at(&data, 4)?).ok_or(refusal(FORM))?;
    if count == 0
        || data.len()
            != header
                .checked_add(stride.checked_mul(copies).ok_or(refusal(OVERFLOW))?)
                .ok_or(refusal(OVERFLOW))?
    {
        return Err(refusal(FORM));
    }
    if pt1_bound(u16_at(&data, 4)?)
        && data[200..header]
            .chunks_exact(32)
            .any(|root| root == [0; 32])
    {
        return Err(refusal(FORM));
    }
    let finalized = u16_at(&data, 6)? & 2 != 0;
    if (!finalized
        && (data[96..128] != [0; 32] || u64_at(&data, 136)? != 0 || u64_at(&data, 144)? != 0))
        || (finalized && (data[96..128] == [0; 32] || u64_at(&data, 144)? < u64_at(&data, 136)?))
    {
        return Err(refusal(FORM));
    }
    // The sealed initializer validates the complete v2 manifest once.  A
    // landing cannot rescan 10,000 positions; it checks its own rows below.
    let declared_total = if v2 {
        if data[80..84] != [0; 4] {
            return Err(refusal(FORM));
        }
        u64_at(&data, 192)?
    } else {
        u32_at(&data, 80)? as u64
    };
    if declared_total == 0 {
        return Err(refusal(FORM));
    }
    let expected_entries = if v2 {
        declared_total
    } else {
        let mut total = 0u64;
        let mut prev = None;
        for row in data[DCM2_HEADER..].chunks_exact(6) {
            let segment = u16_at(row, 0)?;
            let entries = u32_at(row, 2)?;
            if prev.is_some_and(|old| old >= segment) || entries == 0 {
                return Err(refusal(FORM));
            }
            prev = Some(segment);
            total = total.checked_add(entries as u64).ok_or(refusal(OVERFLOW))?;
        }
        if total != declared_total {
            return Err(refusal(FORM));
        }
        total
            .checked_mul(positions as u64)
            .ok_or(refusal(OVERFLOW))?
    };
    if u64_at(&data, 88)? > expected_entries {
        return Err(refusal(FORM));
    }
    let mut segment_table_root = [0; 32];
    segment_table_root.copy_from_slice(&data[152..184]);
    Ok(DocumentFacts {
        position_count: positions,
        segment_count: count,
        expected_entries,
        positions_complete: u32_at(&data, 84)?,
        entries_complete: u64_at(&data, 88)?,
        segment_table_root,
        dispute_window: u64_at(&data, 184)?,
    })
}
pub(crate) fn authenticate_positions(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    positions: u32,
    write: bool,
) -> ProgramResult {
    if account.owner != program
        || (write && !account.is_writable)
        || *account.key != position_page_address(program, descriptor).0
    {
        return Err(refusal(FORM));
    }
    let data = account.try_borrow_data()?;
    let want = DPR2_HEADER
        .checked_add(
            (positions as usize)
                .checked_mul(32)
                .ok_or(refusal(OVERFLOW))?,
        )
        .ok_or(refusal(OVERFLOW))?;
    if data.len() != want
        || data[..4] != *b"DPR2"
        || u16_at(&data, 4)? != 1
        || u16_at(&data, 6)? != 0
        || data[8..40] != *descriptor
        || u32_at(&data, 40)? != positions
        || u32_at(&data, 44)? > positions
    {
        return Err(refusal(FORM));
    }
    Ok(())
}

/// Permissionless, write-once position transition; every supplied page is
/// checked against the DCM2 segment ID/count manifest before either account
/// is mutated.  Segment IDs need not be contiguous.
pub fn finalize_position(
    program: &Pubkey,
    document: &AccountInfo,
    positions: &AccountInfo,
    pages: &[AccountInfo],
    descriptor: &[u8; 32],
    position: u32,
) -> ProgramResult {
    let facts = authenticate_document(program, document, descriptor, true)?;
    authenticate_positions(program, positions, descriptor, facts.position_count, true)?;
    if position >= facts.position_count || pages.len() != facts.segment_count as usize {
        return Err(refusal(COORDINATE));
    }
    let doc = document.try_borrow_data()?;
    if u16_at(&doc, 6)? & 1 == 0 {
        return Err(refusal(FORM));
    }
    if u16_at(&doc, 6)? & crate::root_only::MODE_FLAG != 0 {
        return Err(refusal(FORM));
    }
    if u16_at(&doc, 6)? & 2 != 0 {
        return Err(refusal(ALREADY_FINAL));
    }
    let pos = positions.try_borrow_data()?;
    let root_at = DPR2_HEADER + position as usize * 32;
    if pos[root_at..root_at + 32] != [0; 32] {
        return Err(refusal(ALREADY_FINAL));
    }
    if u32_at(&pos, 44)? != facts.positions_complete {
        return Err(refusal(FORM));
    }
    let next_positions = facts
        .positions_complete
        .checked_add(1)
        .ok_or(refusal(OVERFLOW))?;
    let mut roots = Vec::with_capacity(pages.len());
    let mut prev_id = None;
    let mut sum = 0u32;
    for (i, page) in pages.iter().enumerate() {
        let manifest = manifest_base(&doc, position)? + i * 6;
        let id = u16_at(&doc, manifest)?;
        let expected_entries = u32_at(&doc, manifest + 2)?;
        if prev_id.is_some_and(|p| p >= id) || expected_entries == 0 {
            return Err(refusal(FORM));
        }
        prev_id = Some(id);
        sum = sum.checked_add(expected_entries).ok_or(refusal(OVERFLOW))?;
        let (entries, _) = authenticate_page(program, page, descriptor, position, id, false)?;
        let data = page.try_borrow_data()?;
        if entries != expected_entries
            || u16_at(&data, 6)? & 1 == 0
            || u32_at(&data, 52)? != entries
            || data[64..96] == [0; 32]
        {
            return Err(refusal(FINALIZE_ORDER));
        }
        roots.push(data[64..96].try_into().map_err(|_| refusal(FORM))?);
    }
    let next_entries = facts
        .entries_complete
        .checked_add(sum as u64)
        .ok_or(refusal(OVERFLOW))?;
    if next_entries > facts.expected_entries {
        return Err(refusal(FORM));
    }
    let table_root = if u16_at(&doc, 4)? == 1 {
        facts.segment_table_root
    } else {
        let base = manifest_base(&doc, position)?;
        doc[base - 32..base].try_into().map_err(|_| refusal(FORM))?
    };
    let root = position_root(descriptor, position, &table_root, &roots)?;
    drop(pos);
    drop(doc);
    let mut pos = positions.try_borrow_mut_data()?;
    pos[root_at..root_at + 32].copy_from_slice(&root);
    pos[44..48].copy_from_slice(&next_positions.to_le_bytes());
    drop(pos);
    let mut doc = document.try_borrow_mut_data()?;
    doc[84..88].copy_from_slice(&next_positions.to_le_bytes());
    doc[88..96].copy_from_slice(&next_entries.to_le_bytes());
    Ok(())
}

pub fn finalize_document(
    program: &Pubkey,
    document: &AccountInfo,
    positions: &AccountInfo,
    result: &AccountInfo,
    descriptor: &[u8; 32],
    now: u64,
) -> ProgramResult {
    let facts = authenticate_document(program, document, descriptor, true)?;
    authenticate_positions(program, positions, descriptor, facts.position_count, false)?;
    let token_count = authenticate_result(program, result, descriptor, true)?;
    let doc = document.try_borrow_data()?;
    let result_data = result.try_borrow_data()?;
    if result_data[6] != 0
        || result_data[40..72] != [0; 32]
        || result_data[76..92] != [0; 16]
        || result_data[92..124] != doc[40..72]
        || u64_at(&result_data, 128)? != facts.dispute_window
    {
        return Err(refusal(FORM));
    }
    let bitmap_at = DCR2_HEADER + token_count as usize * 4;
    for (i, &byte) in result_data[bitmap_at..].iter().enumerate() {
        let remaining = token_count as usize - i * 8;
        let expected = if remaining >= 8 {
            0xff
        } else {
            (1u16 << remaining) as u8 - 1
        };
        if byte != expected {
            return Err(refusal(FINALIZE_ORDER));
        }
    }
    if u16_at(&doc, 6)? & 2 != 0 {
        return Err(refusal(ALREADY_FINAL));
    }
    if u16_at(&doc, 6)? & 1 == 0 {
        return Err(refusal(FORM));
    }
    if facts.positions_complete != facts.position_count
        || facts.entries_complete != facts.expected_entries
    {
        return Err(refusal(FINALIZE_ORDER));
    }
    let deadline = now
        .checked_add(facts.dispute_window)
        .ok_or(refusal(OVERFLOW))?;
    let pos = positions.try_borrow_data()?;
    if u32_at(&pos, 44)? != facts.position_count {
        return Err(refusal(FINALIZE_ORDER));
    }
    let flat = &pos[DPR2_HEADER..];
    for bytes in flat.chunks_exact(32) {
        if bytes == [0; 32] {
            return Err(refusal(FINALIZE_ORDER));
        }
    }
    let tree_root = tree_flat(descriptor, 3, u32::MAX, flat)?;
    let root = hash(
        b"document-root/2",
        &[
            descriptor,
            &facts.position_count.to_le_bytes(),
            &tree_root,
            &[1],
        ],
    );
    drop(pos);
    drop(doc);
    drop(result_data);
    let mut doc = document.try_borrow_mut_data()?;
    let flags = u16_at(&doc, 6)? | 2;
    doc[6..8].copy_from_slice(&flags.to_le_bytes());
    doc[96..128].copy_from_slice(&root);
    doc[136..144].copy_from_slice(&now.to_le_bytes());
    doc[144..152].copy_from_slice(&deadline.to_le_bytes());
    drop(doc);
    let mut result_data = result.try_borrow_mut_data()?;
    result_data[40..72].copy_from_slice(&root);
    result_data[76..84].copy_from_slice(&now.to_le_bytes());
    result_data[84..92].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

/// Account-authenticated §8 close. The DCR2 result is immutable except for
/// the transition from pending to undisputed and is never reclaimed here.
/// The refund destination must be the BDS2 authority. Anyone may submit it.
pub fn close_document(
    program: &Pubkey,
    state: &AccountInfo,
    document: &AccountInfo,
    result: &AccountInfo,
    recipient: &AccountInfo,
    descriptor: &[u8; 32],
    now: u64,
) -> ProgramResult {
    let state_facts =
        crate::seal::open_state(program, state, descriptor, FORM).map_err(|_| refusal(FORM))?;
    let facts = authenticate_document(program, document, descriptor, true)?;
    authenticate_result(program, result, descriptor, true)?;
    if !recipient.is_writable
        || recipient.key.to_bytes() != state_facts.authority
        || recipient.key == document.key
        || recipient.key == result.key
    {
        return Err(refusal(AUTHORITY));
    }
    let doc = document.try_borrow_data()?;
    let output = result.try_borrow_data()?;
    if doc[40..72] == [0; 32] || output[92..124] != doc[40..72] {
        return Err(refusal(FORM));
    }
    let flags = u16_at(&doc, 6)?;
    let root = &doc[96..128];
    let deadline = u64_at(&doc, 144)?;
    close_allowed(
        flags & 1 != 0 && state_facts.sealed,
        true,
        flags & 2 != 0,
        facts.positions_complete,
        facts.position_count,
        facts.entries_complete,
        facts.expected_entries,
        u32_at(&doc, 128)?,
        now,
        deadline,
    )?;
    if flags & 8 != 0
        || u32_at(&doc, 132)? != 0
        || output[6] != 0
        || output[40..72] != *root
        || u64_at(&output, 76)? != u64_at(&doc, 136)?
        || u64_at(&output, 84)? != deadline
    {
        return Err(refusal(CLOSE));
    }
    drop(doc);
    drop(output);
    let refund = document.lamports();
    let balance = recipient
        .lamports()
        .checked_add(refund)
        .ok_or(refusal(OVERFLOW))?;
    result.try_borrow_mut_data()?[6] = if flags & 4 != 0 { 2 } else { 1 };
    document.try_borrow_mut_data()?.fill(0);
    **document.try_borrow_mut_lamports()? = 0;
    **recipient.try_borrow_mut_lamports()? = balance;
    Ok(())
}

/// PROPOSED tags, pending the closure-v2 allocation gate. Exact-EOF wires:
/// 80 | descriptor[32] | position:u32 | segment:u16 | first:u32 |
/// count:u8 | leaf[32]*count;
/// 81 | descriptor[32] | position:u32 | segment:u16.
pub const TAG_LAND_LEAVES: u8 = 80;
pub const TAG_FINALIZE_SEGMENT: u8 = 81;
pub const TAG_FINALIZE_POSITION: u8 = 82;
pub const TAG_FINALIZE_DOCUMENT: u8 = 83;
pub const TAG_CHECKPOINT_PUBLISH: u8 = 84;
pub const TAG_BOOTSTRAP_DOCUMENT: u8 = 90;
pub const TAG_BOOTSTRAP_PAGE: u8 = 91;
pub const TAG_GROW_PAGE: u8 = 92;
pub const TAG_COLLECT_ROOT: u8 = 93;
pub const TAG_FINALIZE_FROM_ROOTS: u8 = 94;
pub const TAG_BOOTSTRAP_SMALL: u8 = 107;
pub const TAG_BOOTSTRAP_V2_INIT: u8 = 95;
pub const TAG_BOOTSTRAP_V2_UPLOAD: u8 = 96;
pub const TAG_BOOTSTRAP_V2_SEAL: u8 = 97;
pub const TAG_BOOTSTRAP_V2_GROW: u8 = 108;
pub const TAG_BOOTSTRAP_V3_INIT: u8 = 109;
/// DCM2 v4 (envelope seal): v3 fields plus the frozen registry root.
pub const TAG_BOOTSTRAP_V4_INIT: u8 = 155;
pub const TAG_BOOTSTRAP_ROOT_GROUP: u8 = 130;
pub const TAG_GROW_ROOT_GROUP: u8 = 110;
pub const TAG_CLOSE_DOCUMENT: u8 = 85;
pub const TAG_INIT_RESULT: u8 = 86;
pub const TAG_WRITE_RESULT_TOKEN: u8 = 87;

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match data.first().copied() {
        Some(TAG_LAND_LEAVES) => {
            if data.len() < 44 || accounts.len() != 4 {
                return Err(refusal(FORM));
            }
            let count = data[43] as usize;
            let bytes = count
                .checked_mul(32)
                .and_then(|v| v.checked_add(44))
                .ok_or(refusal(OVERFLOW))?;
            if count == 0 || data.len() != bytes {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            let position = u32_at(data, 33)?;
            let segment = u16_at(data, 37)?;
            let first = u32_at(data, 39)?;
            let leaves: Vec<[u8; 32]> = data[44..]
                .chunks_exact(32)
                .map(|v| v.try_into().map_err(|_| refusal(FORM)))
                .collect::<Result<_, _>>()?;
            land_leaves(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3],
                &descriptor,
                position,
                segment,
                first,
                &leaves,
            )
        }
        Some(TAG_FINALIZE_SEGMENT) => {
            if data.len() != 39 || accounts.len() != 2 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            finalize_segment(
                program,
                &accounts[0],
                &accounts[1],
                &descriptor,
                u32_at(data, 33)?,
                u16_at(data, 37)?,
            )
        }
        Some(TAG_FINALIZE_POSITION) => {
            if data.len() != 37 || accounts.len() < 3 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            finalize_position(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2..],
                &descriptor,
                u32_at(data, 33)?,
            )
        }
        Some(TAG_FINALIZE_DOCUMENT) => {
            if data.len() != 33 || accounts.len() != 3 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            use solana_program::sysvar::Sysvar;
            let now = solana_program::clock::Clock::get()?.slot;
            finalize_document(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &descriptor,
                now,
            )
        }
        Some(TAG_CLOSE_DOCUMENT) => {
            if data.len() != 33 || accounts.len() != 4 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            use solana_program::sysvar::Sysvar;
            let now = solana_program::clock::Clock::get()?.slot;
            close_document(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3],
                &descriptor,
                now,
            )
        }
        Some(TAG_INIT_RESULT) => {
            if data.len() != 37 || accounts.len() != 5 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            init_result(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3],
                &accounts[4],
                &descriptor,
                u32_at(data, 33)?,
            )
        }
        Some(TAG_WRITE_RESULT_TOKEN) => {
            if data.len() != 41 || accounts.len() != 4 {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            write_result_token(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3],
                &descriptor,
                u32_at(data, 33)?,
                u32_at(data, 37)?,
            )
        }
        Some(TAG_BOOTSTRAP_DOCUMENT) => crate::closure_v2_bootstrap::init(program, accounts, data),
        Some(TAG_BOOTSTRAP_SMALL) => {
            crate::closure_v2_bootstrap::init_small(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V2_INIT) => {
            crate::closure_v2_bootstrap::init_v2(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V3_INIT) => {
            crate::closure_v2_bootstrap::init_v3(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V4_INIT) => {
            crate::closure_v2_bootstrap::init_v4(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V2_UPLOAD) => {
            crate::closure_v2_bootstrap::upload_v2(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V2_SEAL) => {
            crate::closure_v2_bootstrap::seal_v2(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_V2_GROW) => {
            crate::closure_v2_bootstrap::grow_v2(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_ROOT_GROUP) => {
            crate::closure_v2_bootstrap::init_root_group(program, accounts, data)
        }
        Some(TAG_GROW_ROOT_GROUP) => {
            crate::closure_v2_bootstrap::grow_root_group(program, accounts, data)
        }
        Some(TAG_BOOTSTRAP_PAGE) => crate::closure_v2_bootstrap::init_page(program, accounts, data),
        Some(TAG_GROW_PAGE) => crate::closure_v2_bootstrap::grow_page(program, accounts, data),
        Some(TAG_COLLECT_ROOT) => {
            crate::closure_v2_bootstrap::collect_root(program, accounts, data)
        }
        Some(TAG_FINALIZE_FROM_ROOTS) => {
            crate::closure_v2_bootstrap::finalize_from_roots(program, accounts, data)
        }
        Some(TAG_CHECKPOINT_PUBLISH) => {
            if data.len() != 73 || !(accounts.len() == 7 || accounts.len() == 8) {
                return Err(refusal(FORM));
            }
            let descriptor: [u8; 32] = data[1..33].try_into().map_err(|_| refusal(FORM))?;
            let family: [u8; 32] = data[33..65].try_into().map_err(|_| refusal(FORM))?;
            let sequence = u64_at(data, 65)?;
            if (sequence == 0) != (accounts.len() == 7) {
                return Err(refusal(FORM));
            }
            publish_checkpoint(
                program,
                &accounts[0],
                &accounts[1],
                &accounts[2],
                &accounts[3..7],
                accounts.get(7),
                &descriptor,
                &family,
                sequence,
            )
        }
        _ => Err(refusal(FORM)),
    }
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use serde_json::Value;

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    fn digest(hex: &str) -> [u8; 32] {
        bytes(hex).try_into().unwrap()
    }
    fn golden() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/golden/dcg/closure_v2_real_rev7.json"
        ))
        .unwrap()
    }

    #[test]
    fn rev7_tag88_leaves_and_tree_sizes_match_python() {
        let g = golden();
        let descriptor = digest(g["descriptor_digest"].as_str().unwrap());
        let mut source = Vec::new();
        for p in [0u32, 34] {
            let section = &g["positions"][p.to_string()];
            let blob = bytes(section["leaf_blob_hex"].as_str().unwrap());
            assert_eq!(blob.len(), 805 * 32);
            source.extend(
                blob.chunks_exact(32)
                    .map(|v| <[u8; 32]>::try_from(v).unwrap()),
            );
            let selected = &section["selected"][0];
            let entry = InstantiatedEntry {
                coordinate: Coordinate {
                    position: p,
                    segment: selected["segment"].as_u64().unwrap() as u16,
                    entry: selected["local_entry"].as_u64().unwrap() as u32,
                },
                operation_ordinal: selected["operation"].as_u64().unwrap() as u16,
                kernel_index: 256,
                mode_id: 2,
                witness_state: 0,
                midstate_digest: [0; 32],
                read_rows: &[],
                write_rows: &[],
            };
            assert_eq!(
                leaf(&descriptor, &entry).unwrap(),
                digest(selected["leaf"].as_str().unwrap())
            );
        }
        for size in [1usize, 2, 3, 5, 33, 804, 1024, 4096] {
            let leaves: Vec<_> = (0..size).map(|i| source[i % source.len()]).collect();
            let expected = digest(g["tree_roots"][size.to_string()].as_str().unwrap());
            assert_eq!(
                tree(&descriptor, 1, 0, &leaves).unwrap(),
                expected,
                "size {size}"
            );
            let flat: Vec<_> = leaves.iter().flat_map(|d| d.iter().copied()).collect();
            assert_eq!(
                tree_flat(&descriptor, 1, 0, &flat).unwrap(),
                expected,
                "flat size {size}"
            );
        }
    }

    #[test]
    fn malformed_certificate_refuses_before_write() {
        let mut raw = [0u8; 28];
        raw[..4].copy_from_slice(b"DHR2");
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[20] = 1;
        assert_eq!(parse_certificate(&raw), Err(refusal(CERTIFICATE)));
        assert_eq!(greedy_cover(3, 9).unwrap(), vec![(3, 0), (4, 2), (8, 0)]);
    }

    #[test]
    fn input_binding_rejects_reordered_slot_bindings() {
        let descriptor = [1; 32];
        let a = slot_binding(
            Coordinate {
                position: 0,
                segment: 1,
                entry: 1,
            },
            0,
            &[2; 32],
        );
        let b = slot_binding(
            Coordinate {
                position: 0,
                segment: 1,
                entry: 2,
            },
            0,
            &[3; 32],
        );
        let mut ordered = Vec::new();
        ordered.extend_from_slice(&a);
        ordered.extend_from_slice(&b);
        assert!(input_binding_digest(&descriptor, 0, 0, &[4; 32], 0, 1, &ordered).is_ok());
        ordered[..48].copy_from_slice(&b);
        ordered[48..].copy_from_slice(&a);
        assert_eq!(
            input_binding_digest(&descriptor, 0, 0, &[4; 32], 0, 1, &ordered),
            Err(refusal(BINDING))
        );
    }

    #[test]
    fn invalid_read_class_binding_pair_is_refused() {
        let mut row = [0u8; 120];
        row[2] = 3;
        row[3] = 0;
        row[16..20].copy_from_slice(&1u32.to_le_bytes());
        let entry = InstantiatedEntry {
            coordinate: Coordinate {
                position: 0,
                segment: 0,
                entry: 0,
            },
            operation_ordinal: 0,
            kernel_index: 1,
            mode_id: 2,
            witness_state: 0,
            midstate_digest: [0; 32],
            read_rows: &row,
            write_rows: &[],
        };
        assert_eq!(input_root(&[1; 32], &entry), Err(refusal(FORM)));
    }

    #[test]
    fn version_two_counts_each_position_and_keeps_distinct_table_roots() {
        let program = Pubkey::new_from_array([9; 32]);
        let descriptor = [7; 32];
        let key = document_address(&program, &descriptor).0;
        let mut lamports = 1;
        let mut raw = vec![0u8; DCM2_V2_HEADER + 2 * (32 + 6)];
        raw[..4].copy_from_slice(b"DCM2");
        raw[4..6].copy_from_slice(&2u16.to_le_bytes());
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
        raw[8..40].copy_from_slice(&descriptor);
        raw[40..72].copy_from_slice(&[3; 32]);
        raw[72..76].copy_from_slice(&2u32.to_le_bytes());
        raw[76..78].copy_from_slice(&1u16.to_le_bytes());
        raw[184..192].copy_from_slice(&1000u64.to_le_bytes());
        raw[192..200].copy_from_slice(&3u64.to_le_bytes());
        raw[200..232].copy_from_slice(&[4; 32]);
        raw[234..238].copy_from_slice(&1u32.to_le_bytes());
        raw[238..270].copy_from_slice(&[5; 32]);
        raw[272..276].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            crate::hash::sha256(&[&raw]),
            digest("86bc03167706e402adcbd9b2c47854b5e18e6a21cab8e927117c7e330848c060")
        );
        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut raw,
            &program,
            false,
            0,
        );
        let facts = authenticate_document(&program, &account, &descriptor, true).unwrap();
        assert_eq!(facts.expected_entries, 3);
        assert_eq!(
            manifest_base(&account.try_borrow_data().unwrap(), 0).unwrap(),
            232
        );
        assert_eq!(
            manifest_base(&account.try_borrow_data().unwrap(), 1).unwrap(),
            270
        );
        assert!(close_allowed(true, true, true, 2, 2, 3, 3, 0, 4, 3).is_ok());
        assert_eq!(
            close_allowed(true, true, true, 2, 2, 3, 3, 0, 3, 3),
            Err(refusal(CLOSE))
        );
        assert_eq!(
            close_allowed(true, true, true, 2, 2, 2, 3, 0, 4, 3),
            Err(refusal(CLOSE))
        );
    }

    #[test]
    fn duplicate_family_slot_is_refused() {
        let rows = [0u8; 80];
        assert_eq!(summary_leaf(&[1; 32], 0, &rows), Err(refusal(SLOT)));
    }

    #[test]
    fn certificate_group_rebuilds_checkpoint_root() {
        let descriptor = [7; 32];
        let family = family_id(&descriptor, 0, 0);
        let first = summary_leaf(&family, 0, &[]).unwrap();
        let padding = [1u32, 2, 3].map(|p| (padding(&descriptor, &family, p), false));
        let left = summary_node(&family, 0, 2, 1, &first, &padding[0]);
        let right = summary_node(&family, 2, 4, 1, &padding[1], &padding[2]);
        let top = summary_node(&family, 0, 4, 2, &left, &right);
        let shards = [first.0, padding[0].0, padding[1].0, padding[2].0];
        let cross = [left.0, right.0, top.0];
        let (checkpoint, _) =
            checkpoint_record(0, &descriptor, &family, 4, 1, &shards, &cross, top.1).unwrap();
        let mut group = CertificateGroup {
            family_ordinal: 0,
            first: 0,
            end: 1,
            sequence: 0,
            cover: vec![CertificateNode {
                first: 0,
                height: 0,
                complete: true,
                digest: first.0,
            }],
            auth: vec![
                CertificateNode {
                    first: 1,
                    height: 0,
                    complete: false,
                    digest: padding[0].0,
                },
                CertificateNode {
                    first: 2,
                    height: 1,
                    complete: false,
                    digest: right.0,
                },
            ],
        };
        assert_eq!(
            verify_certificate_group(&descriptor, &family, &group, &checkpoint),
            Ok(())
        );
        group.auth[1].digest[0] ^= 1;
        assert_eq!(
            verify_certificate_group(&descriptor, &family, &group, &checkpoint),
            Err(refusal(CERTIFICATE))
        );
    }

    #[test]
    fn rev7_initial_family_checkpoint_matches_python() {
        let g = golden();
        let descriptor = digest(g["descriptor_digest"].as_str().unwrap());
        let family = digest(g["initial_family"]["family_id"].as_str().unwrap());
        assert_eq!(family_id(&descriptor, 0, 0), family);
        let raw = bytes(g["initial_family"]["checkpoint_0_record"].as_str().unwrap());
        assert_eq!(raw.len(), CHECKPOINT_BYTES);
        let shard = bytes(g["initial_family"]["shard_0_hex"].as_str().unwrap());
        assert_eq!(shard.len(), shard_bytes(64).unwrap());
        assert_eq!(&shard[..4], b"DSH2");
        assert_eq!(&shard[8..40], &descriptor);
        assert_eq!(&shard[40..72], &family);
        assert_eq!(&shard[96..128], &raw[81..113]);
        let shards = std::array::from_fn(|i| raw[81 + i * 32..113 + i * 32].try_into().unwrap());
        let cross = std::array::from_fn(|i| raw[209 + i * 32..241 + i * 32].try_into().unwrap());
        let (record, cert) =
            checkpoint_record(0, &descriptor, &family, 64, 35, &shards, &cross, false).unwrap();
        assert_eq!(record.as_slice(), raw);
        assert_eq!(
            cert,
            digest(g["initial_family"]["checkpoint_0_digest"].as_str().unwrap())
        );
        assert_eq!(
            padding(&descriptor, &family, 35),
            digest(g["initial_family"]["padding_leaf_35"].as_str().unwrap())
        );
    }
}
