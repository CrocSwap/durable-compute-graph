//! RS1 range reads in the generic respond of a DCR1 v5 record (spec §7.4,
//! `dcg-closure-v2-rs1-rev4.md` §2-§3).
//!
//! A v5 range read row has `binding_kind = 2`, `bytes_digest` = the RS1 read
//! digest, `producer_ref` = the family id and a zero input binding. Its
//! proof section is one RSP1 group:
//! ```text
//! family_ordinal:u16 | 0:u16 | first:u32 | end:u32 | auth_count:u8 | 0[3] | auth[auth_count][32]
//! ```
//! The verifier derives every slot's producer coordinate from the sealed plan
//! and the DFS2 slot table, hashes the witnessed bytes under it, forms
//! producer references and summary leaves, and folds the canonical cover and
//! the authentication nodes to the family root revealed in the record's FTR
//! region (itself checked against DCM2 488). No producer leaf path is needed:
//! the family root commits the summary leaves (summary disputes, tags
//! 170/171, are how a false family root is contested).

use super::{no, DCR1_PROOF};
use crate::closure_v2::{self as h, Coordinate};
use crate::hash;
use crate::pt2p::Pt2p;
use solana_program::program_error::ProgramError;

pub const MAX_HEIGHT: u8 = 19;
pub const GROUP_HEADER: usize = 16;
pub const MAX_AUTH: usize = 38;
const EMPTY_DOMAIN: &[u8] = b"basanos/dcg-rs1-empty/1";
const NODE_DOMAIN: &[u8] = b"basanos/dcg-rs1-node/1";
const ROOT_DOMAIN: &[u8] = b"basanos/dcg-rs1-root/1";
const READ_DOMAIN: &[u8] = b"basanos/dcg-rs1-read/1";

pub fn node(family: &[u8; 32], level: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash::sha256(&[NODE_DOMAIN, family, &[level], left, right])
}

fn empty_roots(family: &[u8; 32], height: u8) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(height as usize + 1);
    out.push(hash::sha256(&[EMPTY_DOMAIN, family]));
    for level in 1..=height {
        let prior = out[level as usize - 1];
        out.push(node(family, level, &prior, &prior));
    }
    out
}

pub fn family_root(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    height: u8,
    leaf_count: u32,
    tree: &[u8; 32],
) -> Result<[u8; 32], u32> {
    geometry(height, leaf_count)?;
    Ok(hash::sha256(&[
        ROOT_DOMAIN,
        descriptor,
        family,
        &[height],
        &leaf_count.to_le_bytes(),
        tree,
    ]))
}

fn geometry(height: u8, count: u32) -> Result<(), u32> {
    if height > MAX_HEIGHT || count == 0 || count as u64 > 1u64 << height {
        return Err(DCR1_PROOF);
    }
    Ok(())
}

/// The largest-aligned left-to-right cover of `[first, end)`.
pub fn greedy_cover(first: u32, end: u32) -> Result<Vec<(u32, u8)>, u32> {
    if first >= end || end > 1 << MAX_HEIGHT {
        return Err(DCR1_PROOF);
    }
    let mut out = Vec::new();
    let mut at = first;
    while at < end {
        let remaining = (31 - (end - at).leading_zeros()) as u8;
        let align = if at == 0 {
            MAX_HEIGHT
        } else {
            at.trailing_zeros() as u8
        };
        let level = remaining.min(align);
        out.push((at, level));
        at += 1 << level;
    }
    Ok(out)
}

/// `SHA256(rs1-read | descriptor | family | first | end | cover_count | cover)`.
pub fn read_digest(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    first: u32,
    end: u32,
    cover: &[[u8; 32]],
) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(6 + cover.len());
    let (f, e, n) = (first.to_le_bytes(), end.to_le_bytes(), [cover.len() as u8]);
    parts.extend_from_slice(&[READ_DOMAIN, descriptor, family, &f, &e, &n]);
    for c in cover {
        parts.push(c);
    }
    hash::sha256(&parts)
}

#[allow(clippy::too_many_arguments)]
fn visit(
    family: &[u8; 32],
    zero: &[[u8; 32]],
    count: u32,
    first: u32,
    end: u32,
    start: u32,
    level: u8,
    cover: &[(u32, u8, [u8; 32])],
    auth: &[[u8; 32]],
    used: &mut usize,
) -> Result<[u8; 32], u32> {
    let stop = start as u64 + (1u64 << level);
    if first <= start && stop <= end as u64 {
        return cover
            .iter()
            .find(|c| c.0 == start && c.1 == level)
            .map(|c| c.2)
            .ok_or(DCR1_PROOF);
    }
    if stop <= first as u64 || start >= end {
        if start >= count {
            return Ok(zero[level as usize]);
        }
        let d = *auth.get(*used).ok_or(DCR1_PROOF)?;
        *used += 1;
        return Ok(d);
    }
    if level == 0 {
        return Err(DCR1_PROOF);
    }
    let half = 1u32 << (level - 1);
    let left = visit(
        family,
        zero,
        count,
        first,
        end,
        start,
        level - 1,
        cover,
        auth,
        used,
    )?;
    let right = visit(
        family,
        zero,
        count,
        first,
        end,
        start + half,
        level - 1,
        cover,
        auth,
        used,
    )?;
    Ok(node(family, level, &left, &right))
}

/// Fold `leaves` (positions `first..end`) and `auth` to the RS1 tree root,
/// check the wrapped family root, and return the range read digest.
#[allow(clippy::too_many_arguments)]
pub fn verify_leaves(
    descriptor: &[u8; 32],
    family: &[u8; 32],
    height: u8,
    leaf_count: u32,
    first: u32,
    end: u32,
    leaves: &[[u8; 32]],
    auth: &[[u8; 32]],
    committed_root: &[u8; 32],
) -> Result<[u8; 32], u32> {
    geometry(height, leaf_count)?;
    if first >= end
        || end > leaf_count
        || leaves.len() != (end - first) as usize
        || auth.len() > MAX_AUTH
    {
        return Err(DCR1_PROOF);
    }
    let coords = greedy_cover(first, end)?;
    let mut cover = Vec::with_capacity(coords.len());
    for (start, level) in coords {
        let at = (start - first) as usize;
        let mut layer: Vec<[u8; 32]> = leaves[at..at + (1usize << level)].to_vec();
        for lv in 1..=level {
            layer = layer
                .chunks_exact(2)
                .map(|p| node(family, lv, &p[0], &p[1]))
                .collect();
        }
        cover.push((start, level, layer[0]));
    }
    let zero = empty_roots(family, height);
    let mut used = 0usize;
    let root = visit(
        family, &zero, leaf_count, first, end, 0, height, &cover, auth, &mut used,
    )?;
    if used != auth.len()
        || family_root(descriptor, family, height, leaf_count, &root)? != *committed_root
    {
        return Err(DCR1_PROOF);
    }
    let digests: Vec<[u8; 32]> = cover.iter().map(|c| c.2).collect();
    Ok(read_digest(descriptor, family, first, end, &digests))
}

/// One decoded RSP1 group.
pub struct Group<'a> {
    pub family_ordinal: u16,
    pub first: u32,
    pub end: u32,
    pub auth: &'a [u8],
}

pub fn decode_group(raw: &[u8]) -> Result<Group<'_>, u32> {
    if raw.len() < GROUP_HEADER || raw[2..4] != [0; 2] || raw[13..16] != [0; 3] {
        return Err(DCR1_PROOF);
    }
    let count = raw[12] as usize;
    if count > MAX_AUTH || raw.len() != GROUP_HEADER + 32 * count {
        return Err(DCR1_PROOF);
    }
    let first = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let end = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    if first >= end {
        return Err(DCR1_PROOF);
    }
    Ok(Group {
        family_ordinal: u16::from_le_bytes([raw[0], raw[1]]),
        first,
        end,
        auth: &raw[GROUP_HEADER..],
    })
}

/// The family's kind from `PWR1` (1 = a layer's K family, 2 = V).
pub fn family_kind(x: &Pt2p<'_>, ordinal: u16) -> Result<u8, u32> {
    for li in 0..x.layer_count() {
        let rule = x.g.layer(li)?;
        if rule.k_family == ordinal {
            return Ok(1);
        }
        if rule.v_family == ordinal {
            return Ok(2);
        }
    }
    Err(DCR1_PROOF)
}

/// The rev-3 summary leaf of family `family` at position `q`: one slot record
/// per DFS2 slot, ordered by `(segment, local, write_row_ordinal)`, each
/// `segment:u16 | local:u32 | wro:u8 | 0:u8 | producer_ref[32]`, its data
/// digest the write digest of the witnessed bytes at the producer's declared
/// write. `slots` is the family's DFS2 slot list (base entry, write ordinal);
/// the witness covers the read route `[route_offset, route_offset + len)` of
/// the region. The slot writes must tile their share of the witness.
#[allow(clippy::too_many_arguments)]
pub fn summary_leaf_at(
    x: &Pt2p<'_>,
    descriptor: &[u8; 32],
    family: &[u8; 32],
    slots: &[u8],
    q: u32,
    region: u16,
    route_offset: u64,
    witness: &[u8],
    cursor: &mut u64,
) -> Result<[u8; 32], ProgramError> {
    let bad = || no(DCR1_PROOF);
    let mut records: Vec<(u16, u32, u8, [u8; 32])> = Vec::with_capacity(slots.len() / 5);
    for slot in slots.chunks_exact(5) {
        let o = u32::from_le_bytes(slot[..4].try_into().unwrap());
        let t = x.old_to_new(o, q).map_err(|_| bad())?.ok_or(bad())?;
        let e = x.entry(q, t).map_err(|_| bad())?;
        if slot[4] as u16 >= e.write_count {
            return Err(bad());
        }
        let w = x
            .route(&e, e.read_count + slot[4] as u16)
            .map_err(|_| bad())?;
        let c = x.coordinate(q, t).map_err(|_| bad())?;
        if w.direction != 1 || w.region_id != region || w.effective_offset != route_offset + *cursor
        {
            return Err(bad());
        }
        let at = usize::try_from(*cursor).map_err(|_| bad())?;
        let bytes = witness.get(at..at + w.byte_length as usize).ok_or(bad())?;
        let coordinate = Coordinate {
            position: q,
            segment: c.segment,
            entry: c.local,
        };
        let data = h::write_digest(descriptor, coordinate, region, w.effective_offset, bytes)?;
        let reference = h::hash(
            b"producer-seal/2",
            &[
                descriptor,
                family,
                &q.to_le_bytes(),
                &c.segment.to_le_bytes(),
                &c.local.to_le_bytes(),
                &[slot[4]],
                &data,
            ],
        );
        records.push((c.segment, c.local, slot[4], reference));
        *cursor += w.byte_length as u64;
    }
    records.sort_by_key(|r| (r.0, r.1, r.2));
    if records.is_empty()
        || records.len() > u8::MAX as usize
        || records
            .windows(2)
            .any(|w| (w[0].0, w[0].1, w[0].2) == (w[1].0, w[1].1, w[1].2))
    {
        return Err(bad());
    }
    let mut body = Vec::with_capacity(4 + 40 * records.len());
    body.extend_from_slice(&[records.len() as u8, 1, 0, 0]);
    for (segment, local, wro, reference) in &records {
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(&local.to_le_bytes());
        body.extend_from_slice(&[*wro, 0]);
        body.extend_from_slice(reference);
    }
    Ok(h::hash(
        b"summary-leaf/2",
        &[family, &q.to_le_bytes(), &body],
    ))
}
