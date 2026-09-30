//! PT1 revision-8 position-template codec. All table views borrow their input.
//! The closure runtime supplies clause-3 regions, clause-8 families and clause-6
//! waves when sealing; no account or instruction handler lives here.

/// PT1 refusal codes shared with the Python codec.
pub const MALFORMED: u32 = 580;
pub const SLOT: u32 = 585;
pub const OVERFLOW: u32 = 598;
pub const POSITION_ORDER: u32 = 600;
pub const KERNEL_OPERAND: u32 = 601;
pub const PT2_MANIFEST: u32 = 602;
pub const PT2_ROUTE_SET: u32 = 603;
pub const PT2_PRODUCER: u32 = 604;
pub const NO_PRODUCER: u32 = u32::MAX;
pub const PXR1_HEADER_BYTES: usize = 32;
pub const PXR1_ROW_BYTES: usize = 32;

/// PT1 Execute order. The lifecycle owns and advances `executed_position`;
/// this check is called before executing a consensus-mode entry.
pub fn check_position_order(
    position: u32,
    position_count: u32,
    executed_position: u32,
) -> Result<(), u32> {
    if position >= position_count {
        Err(MALFORMED)
    } else if position > executed_position {
        Err(POSITION_ORDER)
    } else {
        Ok(())
    }
}

/// A form has exactly one routed operand per template read ordinal. The
/// runtime passes actual span lengths in that same order.
pub fn check_operand_lengths(declared: &[u32], actual: &[usize]) -> Result<(), u32> {
    if declared.len() != actual.len() || declared.iter().zip(actual).any(|(a, b)| *a as usize != *b)
    {
        Err(KERNEL_OPERAND)
    } else {
        Ok(())
    }
}

/// PT1 embed token is the signed i64 in bytes 8..16 of its routed operand.
pub fn check_embed_token(operand: &[u8], logit_rows: u32) -> Result<u32, u32> {
    if operand.len() != 16 {
        return Err(KERNEL_OPERAND);
    }
    let token = i64::from_le_bytes(operand[8..16].try_into().unwrap());
    if token < 0 || token as u64 >= logit_rows as u64 {
        Err(KERNEL_OPERAND)
    } else {
        Ok(token as u32)
    }
}

/// One 24-byte clause-5 route record, in template order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub region_id: u16,
    pub direction: u8,
    pub read_class: u8,
    pub region_offset: u64,
    pub byte_length: u32,
    pub producer_entry: u32,
    pub producer_delta: u16,
    pub flags: u16,
}

/// A borrowed entry index into the clause-5 route body. `route_start` is a
/// record index; reads precede writes. No routes are copied into the SBF frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateEntry {
    pub index: u32,
    pub kernel_index: u16,
    pub read_count: u16,
    pub write_count: u16,
    pub route_start: u32,
}

/// The canonical closure-v2 coordinate for one PT1 template entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryCoordinate {
    pub segment: u16,
    pub local: u32,
    pub operation_ordinal: u16,
}

/// One effective PT1 route. `binding_kind` is 0 none, 1 producer write row,
/// or 2 range family. `source_supplied` and `initial_content` are independent.
/// Producer fields are `NO_PRODUCER`/`u8::MAX` when no producer is bound.
/// The range is the half-open slot interval `[range_first, range_end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstantiatedRoute {
    pub direction: u8,
    pub ordinal: u16,
    pub region_id: u16,
    pub effective_offset: u64,
    pub byte_length: u32,
    pub read_class: u8,
    pub binding_kind: u8,
    pub source_supplied: bool,
    pub initial_content: bool,
    pub producer_position: u32,
    pub producer_entry: u32,
    pub producer_write_ordinal: u8,
    pub range_first: u32,
    pub range_end: u32,
    pub family_ordinal: u16,
    pub template_offset: u64,
}

/// An entry at position `p`; `routes` yields one `InstantiatedRoute` at a time
/// and `patch_payload` writes into a caller-owned buffer. `attention_t` is
/// `None` if the entry has neither a range nor a T-scaled route.
#[derive(Clone, Copy, Debug)]
pub struct InstantiatedEntry<'a> {
    pub template: &'a Template<'a>,
    pub clause12: Clause12<'a>,
    pub entry: TemplateEntry,
    pub position: u32,
    pub attention_t: Option<u32>,
}

/// Borrowed, validated PT1 tables. Clause-3 region geometry and clause-8
/// family slots are supplied separately at seal; clause-12 has no such fields.
#[derive(Clone, Copy, Debug)]
pub struct Template<'a> {
    pub clause5: &'a [u8],
    pub clause12: &'a [u8],
    pub position_count: u32,
    pub prompt_positions: u32,
    pub max_producer_delta: u16,
    pub entries_per_position: u32,
    pub leaf_storage_mode: u8,
}

const ROUTE_DOMAIN: &[u8] = b"basanos/dcg-route-entry/1";
const NODE_DOMAIN: &[u8] = b"basanos/dcg-route-node/1";
const SEGMENT_DOMAIN: &[u8] = b"basanos/dcg-hclosure-segment-table/2";
const OPERATION_DOMAIN: &[u8] = b"basanos/dcg-hclosure-operation-table/2";

fn u16_at(b: &[u8], i: usize) -> Result<u16, u32> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2).ok_or(MALFORMED)?.try_into().unwrap(),
    ))
}
fn u32_at(b: &[u8], i: usize) -> Result<u32, u32> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4).ok_or(MALFORMED)?.try_into().unwrap(),
    ))
}
fn u64_at(b: &[u8], i: usize) -> Result<u64, u32> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8).ok_or(MALFORMED)?.try_into().unwrap(),
    ))
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        solana_program::hash::hashv(parts).to_bytes()
    }
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }
}

const POSITION_MANIFEST_DOMAIN: &[u8] = b"basanos/dcg-pt1-position-manifest/1";

/// Geometry-v4 keeps a complete v2 geometry byte string and adds exact
/// position-window bindings and an optional ESG4 execution-span table.
#[derive(Clone, Copy, Debug)]
pub struct GeometryV4<'a> {
    pub base_v2: &'a [u8],
    windows: &'a [u8],
    pub window_count: u32,
    pub span_groups: Option<SpanGroupTableV4<'a>>,
}

#[derive(Clone, Copy, Debug)]
pub struct SpanGroupTableV4<'a> {
    raw: &'a [u8],
    pub entry_count: u32,
    pub group_count: u32,
    pub route_count: u32,
}

impl<'a> SpanGroupTableV4<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, u32> {
        if raw.len() < 24
            || raw.get(..4) != Some(b"ESG4".as_slice())
            || u16_at(raw, 4).map_err(|_| PT2_ROUTE_SET)? != 1
            || u16_at(raw, 6).map_err(|_| PT2_ROUTE_SET)? != 0
            || u32_at(raw, 20).map_err(|_| PT2_ROUTE_SET)? != 0
        {
            return Err(PT2_ROUTE_SET);
        }
        let entries = u32_at(raw, 8).map_err(|_| PT2_ROUTE_SET)?;
        let groups = u32_at(raw, 12).map_err(|_| PT2_ROUTE_SET)?;
        let routes = u32_at(raw, 16).map_err(|_| PT2_ROUTE_SET)?;
        let rows_end = 24usize
            .checked_add((entries as usize).checked_mul(16).ok_or(PT2_ROUTE_SET)?)
            .ok_or(PT2_ROUTE_SET)?;
        if rows_end
            .checked_add((groups as usize).checked_mul(4).ok_or(PT2_ROUTE_SET)?)
            .ok_or(PT2_ROUTE_SET)?
            != raw.len()
        {
            return Err(PT2_ROUTE_SET);
        }
        let mut next_group = 0u32;
        let mut next_route = 0u32;
        for i in 0..entries {
            let at = 24 + i as usize * 16;
            let row = raw.get(at..at + 16).ok_or(PT2_ROUTE_SET)?;
            let reads = u16_at(row, 4).map_err(|_| PT2_ROUTE_SET)? as u32;
            let writes = u16_at(row, 6).map_err(|_| PT2_ROUTE_SET)? as u32;
            let group_count = u16_at(row, 12).map_err(|_| PT2_ROUTE_SET)? as u32;
            let route_count = reads.checked_add(writes).ok_or(PT2_ROUTE_SET)?;
            if u32_at(row, 0).map_err(|_| PT2_ROUTE_SET)? != i
                || u32_at(row, 8).map_err(|_| PT2_ROUTE_SET)? != next_group
                || u16_at(row, 14).map_err(|_| PT2_ROUTE_SET)? != 0
                || route_count > u16::MAX as u32
                || (route_count == 0) != (group_count == 0)
            {
                return Err(PT2_ROUTE_SET);
            }
            let mut cursor = 0u32;
            for j in next_group..next_group.checked_add(group_count).ok_or(PT2_ROUTE_SET)? {
                if j >= groups {
                    return Err(PT2_ROUTE_SET);
                }
                let at = rows_end + j as usize * 4;
                let first = u16_at(raw, at).map_err(|_| PT2_ROUTE_SET)? as u32;
                let count = u16_at(raw, at + 2).map_err(|_| PT2_ROUTE_SET)? as u32;
                let end = cursor.checked_add(count).ok_or(PT2_ROUTE_SET)?;
                if first != cursor
                    || count == 0
                    || count > 8
                    || end > route_count
                    || (cursor < reads && reads < end)
                {
                    return Err(PT2_ROUTE_SET);
                }
                cursor = end;
            }
            if cursor != route_count {
                return Err(PT2_ROUTE_SET);
            }
            next_group = next_group.checked_add(group_count).ok_or(PT2_ROUTE_SET)?;
            next_route = next_route.checked_add(route_count).ok_or(PT2_ROUTE_SET)?;
        }
        if next_group != groups || next_route != routes {
            return Err(PT2_ROUTE_SET);
        }
        Ok(Self {
            raw,
            entry_count: entries,
            group_count: groups,
            route_count: routes,
        })
    }

    pub fn row_counts(&self, entry: u32) -> Result<(u16, u16), u32> {
        if entry >= self.entry_count {
            return Err(PT2_ROUTE_SET);
        }
        let at = 24 + entry as usize * 16;
        Ok((
            u16_at(self.raw, at + 4).map_err(|_| PT2_ROUTE_SET)?,
            u16_at(self.raw, at + 6).map_err(|_| PT2_ROUTE_SET)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSubrangeV4 {
    pub entry: u32,
    pub read_ordinal: u16,
    pub family_ordinal: u16,
    pub first_position: u32,
    pub end_position: u32,
}

impl<'a> GeometryV4<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, u32> {
        if raw.get(..5) != Some(b"\x04PTG4".as_slice()) || raw.len() < 17 {
            return Err(PT2_ROUTE_SET);
        }
        let base_len = u32_at(raw, 5).map_err(|_| PT2_ROUTE_SET)? as usize;
        let count = u32_at(raw, 9).map_err(|_| PT2_ROUTE_SET)?;
        let group_len = u32_at(raw, 13).map_err(|_| PT2_ROUTE_SET)? as usize;
        let end_base = 17usize.checked_add(base_len).ok_or(PT2_ROUTE_SET)?;
        let end_rows = end_base
            .checked_add((count as usize).checked_mul(16).ok_or(PT2_ROUTE_SET)?)
            .ok_or(PT2_ROUTE_SET)?;
        if end_rows.checked_add(group_len).ok_or(PT2_ROUTE_SET)? != raw.len() {
            return Err(PT2_ROUTE_SET);
        }
        let base_v2 = raw.get(17..end_base).ok_or(PT2_ROUTE_SET)?;
        decode_clause12_v2(base_v2).map_err(|_| PT2_ROUTE_SET)?;
        let windows = raw.get(end_base..end_rows).ok_or(PT2_ROUTE_SET)?;
        let span_groups = if group_len == 0 {
            None
        } else {
            Some(SpanGroupTableV4::decode(
                raw.get(end_rows..).ok_or(PT2_ROUTE_SET)?,
            )?)
        };
        let result = Self {
            base_v2,
            windows,
            window_count: count,
            span_groups,
        };
        let mut previous = None;
        for i in 0..count {
            let row = result.row(i)?;
            let key = (row.entry, row.read_ordinal);
            if previous.is_some_and(|old| old >= key) || row.first_position >= row.end_position {
                return Err(PT2_ROUTE_SET);
            }
            previous = Some(key);
        }
        Ok(result)
    }

    pub fn row(&self, index: u32) -> Result<WindowSubrangeV4, u32> {
        if index >= self.window_count {
            return Err(PT2_ROUTE_SET);
        }
        let at = index as usize * 16;
        let raw = self.windows.get(at..at + 16).ok_or(PT2_ROUTE_SET)?;
        Ok(WindowSubrangeV4 {
            entry: u32_at(raw, 0).map_err(|_| PT2_ROUTE_SET)?,
            read_ordinal: u16_at(raw, 4).map_err(|_| PT2_ROUTE_SET)?,
            family_ordinal: u16_at(raw, 6).map_err(|_| PT2_ROUTE_SET)?,
            first_position: u32_at(raw, 8).map_err(|_| PT2_ROUTE_SET)?,
            end_position: u32_at(raw, 12).map_err(|_| PT2_ROUTE_SET)?,
        })
    }

    pub fn find(&self, entry: u32, read_ordinal: u16) -> Result<Option<WindowSubrangeV4>, u32> {
        let mut lo = 0u32;
        let mut hi = self.window_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self.row(mid)?;
            if (row.entry, row.read_ordinal) < (entry, read_ordinal) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo < self.window_count {
            let row = self.row(lo)?;
            if (row.entry, row.read_ordinal) == (entry, read_ordinal) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    pub fn instantiate_window(
        &self,
        routes: &[u8],
        c: Clause12<'_>,
        position: u32,
        entry: u32,
        read_ordinal: u16,
    ) -> Result<InstantiatedRoute, u32> {
        if position >= c.position_count {
            return Err(PT2_ROUTE_SET);
        }
        let e = entry_at(routes, entry).map_err(|_| PT2_ROUTE_SET)?;
        if read_ordinal >= e.read_count {
            return Err(PT2_ROUTE_SET);
        }
        let raw = route_at(routes, e, read_ordinal).map_err(|_| PT2_ROUTE_SET)?;
        let row = self.find(entry, read_ordinal)?.ok_or(PT2_ROUTE_SET)?;
        let stride = c
            .region_position(raw.region_id)
            .map_err(|_| PT2_ROUTE_SET)?
            .ok_or(PT2_ROUTE_SET)?
            .stride;
        if raw.direction != 0
            || raw.read_class != 3
            || raw.producer_entry != NO_PRODUCER
            || raw.producer_delta != 0
            || raw.flags != 0
            || stride == 0
            || row.first_position >= row.end_position
            || row.end_position > position.checked_add(1).ok_or(PT2_ROUTE_SET)?
            || raw.region_offset
                != (row.first_position as u64)
                    .checked_mul(stride)
                    .ok_or(PT2_ROUTE_SET)?
            || raw.byte_length as u64
                != ((row.end_position - row.first_position) as u64)
                    .checked_mul(stride)
                    .ok_or(PT2_ROUTE_SET)?
        {
            return Err(PT2_PRODUCER);
        }
        Ok(InstantiatedRoute {
            direction: 0,
            ordinal: read_ordinal,
            region_id: raw.region_id,
            effective_offset: raw.region_offset,
            byte_length: raw.byte_length,
            read_class: 3,
            binding_kind: 2,
            source_supplied: false,
            initial_content: false,
            producer_position: NO_PRODUCER,
            producer_entry: NO_PRODUCER,
            producer_write_ordinal: u8::MAX,
            range_first: row.first_position,
            range_end: row.end_position,
            family_ordinal: row.family_ordinal,
            template_offset: raw.region_offset,
        })
    }
}

/// PT2 position-manifest view. The manifest binds exact per-position route and
/// payload bytes; a count table alone cannot authorize a route set.
#[derive(Clone, Copy, Debug)]
pub struct PositionManifestV3<'a> {
    raw: &'a [u8],
    pub position_count: u32,
    pub segment_count: u16,
    row_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct PositionManifestRowV3<'a> {
    pub position: u32,
    pub entry_count: u32,
    pub segment_counts: &'a [u8],
    pub clause5_sha256: &'a [u8],
    pub geometry_sha256: &'a [u8],
    pub payload_sha256: &'a [u8],
}

impl<'a> PositionManifestV3<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, u32> {
        if raw.get(..5) != Some(b"PTV3\x01".as_slice()) {
            return Err(PT2_MANIFEST);
        }
        let position_count = u32_at(raw, 5).map_err(|_| PT2_MANIFEST)?;
        let segment_count = u16_at(raw, 9).map_err(|_| PT2_MANIFEST)?;
        if position_count == 0 || segment_count == 0 {
            return Err(PT2_MANIFEST);
        }
        let row_bytes = 104usize
            .checked_add(
                4usize
                    .checked_mul(segment_count as usize)
                    .ok_or(PT2_MANIFEST)?,
            )
            .ok_or(PT2_MANIFEST)?;
        let size = 11usize
            .checked_add(
                row_bytes
                    .checked_mul(position_count as usize)
                    .ok_or(PT2_MANIFEST)?,
            )
            .ok_or(PT2_MANIFEST)?;
        if raw.len() != size {
            return Err(PT2_MANIFEST);
        }
        Ok(Self {
            raw,
            position_count,
            segment_count,
            row_bytes,
        })
    }

    pub fn row(&self, position: u32) -> Result<PositionManifestRowV3<'a>, u32> {
        if position >= self.position_count {
            return Err(PT2_MANIFEST);
        }
        let at = 11 + position as usize * self.row_bytes;
        let raw = self.raw.get(at..at + self.row_bytes).ok_or(PT2_MANIFEST)?;
        let n = u32_at(raw, 4).map_err(|_| PT2_MANIFEST)?;
        let counts = &raw[8..8 + self.segment_count as usize * 4];
        let total = counts
            .chunks_exact(4)
            .try_fold(0u64, |sum, b| {
                sum.checked_add(u32::from_le_bytes(b.try_into().unwrap()) as u64)
            })
            .ok_or(PT2_MANIFEST)?;
        let roots = 8 + counts.len();
        let clause5 = &raw[roots..roots + 32];
        let geometry = &raw[roots + 32..roots + 64];
        let payload = &raw[roots + 64..roots + 96];
        if u32_at(raw, 0).map_err(|_| PT2_MANIFEST)? != position
            || n == 0
            || total != n as u64
            || clause5 == [0; 32]
            || geometry == [0; 32]
            || payload == [0; 32]
        {
            return Err(PT2_MANIFEST);
        }
        Ok(PositionManifestRowV3 {
            position,
            entry_count: n,
            segment_counts: counts,
            clause5_sha256: clause5,
            geometry_sha256: geometry,
            payload_sha256: payload,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        hash(&[POSITION_MANIFEST_DOMAIN, self.raw])
    }

    /// Native golden/preflight helper. SBF must fold account bytes in bounded
    /// instructions before admitting a row; hashing megabytes in one call is
    /// above the transaction compute ceiling.
    #[cfg(not(target_os = "solana"))]
    pub fn bind_route_set(
        &self,
        position: u32,
        routes: &[u8],
        geom: &[u8],
        payloads: &[u8],
    ) -> Result<(), u32> {
        let row = self.row(position)?;
        if hash(&[routes]) != row.clause5_sha256
            || hash(&[geom]) != row.geometry_sha256
            || hash(&[payloads]) != row.payload_sha256
        {
            return Err(PT2_ROUTE_SET);
        }
        let n = decode_clause5(routes).map_err(|_| PT2_ROUTE_SET)?;
        let v4 = if geom.first() == Some(&4) {
            Some(GeometryV4::decode(geom)?)
        } else {
            None
        };
        let c = decode_clause12_v2(v4.map_or(geom, |g| g.base_v2)).map_err(|_| PT2_ROUTE_SET)?;
        if n != row.entry_count
            || c.entries_per_position != n
            || c.position_count != self.position_count
            || c.segment_count != self.segment_count
        {
            return Err(PT2_ROUTE_SET);
        }
        for j in 0..self.segment_count as usize {
            let s = c
                .raw
                .get(59 + j * 43..59 + (j + 1) * 43)
                .ok_or(PT2_ROUTE_SET)?;
            let expected = u32_at(row.segment_counts, j * 4).map_err(|_| PT2_ROUTE_SET)?;
            if u32_at(s, 7).map_err(|_| PT2_ROUTE_SET)? != expected {
                return Err(PT2_ROUTE_SET);
            }
        }
        let mut at = 0usize;
        for i in 0..n {
            let header = payloads
                .get(at..at.checked_add(6).ok_or(PT2_ROUTE_SET)?)
                .ok_or(PT2_ROUTE_SET)?;
            if u32_at(header, 0).map_err(|_| PT2_ROUTE_SET)? != i {
                return Err(PT2_ROUTE_SET);
            }
            at = at
                .checked_add(6 + u16_at(header, 4).map_err(|_| PT2_ROUTE_SET)? as usize)
                .ok_or(PT2_ROUTE_SET)?;
        }
        if at != payloads.len() {
            return Err(PT2_ROUTE_SET);
        }
        if let Some(g) = v4 {
            if let Some(groups) = g.span_groups {
                let (_, route_count) = route_header(routes).map_err(|_| PT2_ROUTE_SET)?;
                if groups.entry_count != n || groups.route_count != route_count {
                    return Err(PT2_ROUTE_SET);
                }
                for i in 0..n {
                    let entry = entry_at(routes, i).map_err(|_| PT2_ROUTE_SET)?;
                    if groups.row_counts(i)? != (entry.read_count, entry.write_count) {
                        return Err(PT2_ROUTE_SET);
                    }
                }
            }
            validate_window_subranges_v4(position, routes, payloads, c, g)?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
fn validate_window_subranges_v4(
    position: u32,
    routes: &[u8],
    payloads: &[u8],
    c: Clause12<'_>,
    g: GeometryV4<'_>,
) -> Result<(), u32> {
    let mut payload_at = 0usize;
    let mut found = 0u32;
    for i in 0..c.entries_per_position {
        let e = entry_at(routes, i).map_err(|_| PT2_ROUTE_SET)?;
        let length = u16_at(payloads, payload_at + 4).map_err(|_| PT2_ROUTE_SET)? as usize;
        let body = payloads
            .get(payload_at + 6..payload_at + 6 + length)
            .ok_or(PT2_ROUTE_SET)?;
        payload_at += 6 + length;
        if e.kernel_index != 40 && e.kernel_index != 43 {
            continue;
        }
        if body.len() != 44 || u16_at(body, 2).map_err(|_| PT2_ROUTE_SET)? != e.kernel_index {
            return Err(PT2_ROUTE_SET);
        }
        let w = u16_at(body, 8).map_err(|_| PT2_ROUTE_SET)? as u32;
        let window = u32_at(body, 12).map_err(|_| PT2_ROUTE_SET)?;
        if w != 64 || window >= position / w + 1 {
            // ceil((position + 1) / w) == position / w + 1.
            return Err(PT2_ROUTE_SET);
        }
        let first = window.checked_mul(w).ok_or(PT2_ROUTE_SET)?;
        let end = first
            .checked_add(w)
            .ok_or(PT2_ROUTE_SET)?
            .min(position.checked_add(1).ok_or(PT2_ROUTE_SET)?);
        for k in 0..e.read_count {
            let r = route_at(routes, e, k).map_err(|_| PT2_ROUTE_SET)?;
            if r.read_class != 3 {
                continue;
            }
            let binding = g.find(i, k)?.ok_or(PT2_PRODUCER)?;
            let stride = c
                .region_position(r.region_id)
                .map_err(|_| PT2_ROUTE_SET)?
                .ok_or(PT2_PRODUCER)?
                .stride;
            let offset = (first as u64).checked_mul(stride).ok_or(PT2_ROUTE_SET)?;
            let byte_length = ((end - first) as u64)
                .checked_mul(stride)
                .ok_or(PT2_ROUTE_SET)?;
            if binding.first_position != first
                || binding.end_position != end
                || stride == 0
                || r.producer_entry != NO_PRODUCER
                || r.producer_delta != 0
                || r.flags != 0
                || r.region_offset != offset
                || byte_length != r.byte_length as u64
            {
                return Err(PT2_PRODUCER);
            }
            found += 1;
        }
    }
    if found != g.window_count {
        return Err(PT2_ROUTE_SET);
    }
    Ok(())
}

pub fn decode_clause12_v3(
    raw: &[u8],
    manifest: Option<&PositionManifestV3<'_>>,
) -> Result<(u32, u16, [u8; 32]), u32> {
    if raw.len() != 43 || raw.get(..5) != Some(b"\x03PT2C".as_slice()) {
        return Err(PT2_MANIFEST);
    }
    let positions = u32_at(raw, 5).map_err(|_| PT2_MANIFEST)?;
    let segments = u16_at(raw, 9).map_err(|_| PT2_MANIFEST)?;
    let digest: [u8; 32] = raw[11..43].try_into().unwrap();
    if positions == 0 || segments == 0 || digest == [0; 32] {
        return Err(PT2_MANIFEST);
    }
    if let Some(m) = manifest {
        if positions != m.position_count || segments != m.segment_count || digest != m.digest() {
            return Err(PT2_MANIFEST);
        }
    }
    Ok((positions, segments, digest))
}
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(&[NODE_DOMAIN, left, right])
}

/// Hash a canonical route entry. Incremental on-chain seal uses the same
/// leaf as the all-at-once host decoder.
pub fn route_entry_hash(raw: &[u8], index: u32) -> Result<[u8; 32], u32> {
    let row = entry_at(raw, index)?;
    let n = u32_at(raw, 0)? as usize;
    let body_at = 80usize
        .checked_add(n.checked_mul(16).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    let first = body_at
        .checked_add(
            (row.route_start as usize)
                .checked_mul(24)
                .ok_or(MALFORMED)?,
        )
        .ok_or(MALFORMED)?;
    let last = first
        .checked_add(
            ((row.read_count as usize) + (row.write_count as usize))
                .checked_mul(24)
                .ok_or(MALFORMED)?,
        )
        .ok_or(MALFORMED)?;
    Ok(hash(&[
        ROUTE_DOMAIN,
        &index.to_le_bytes(),
        &row.kernel_index.to_le_bytes(),
        &row.read_count.to_le_bytes(),
        &row.write_count.to_le_bytes(),
        raw.get(first..last).ok_or(MALFORMED)?,
    ]))
}

/// Add a route leaf to a persistent 32-level Merkle frontier.
pub fn route_frontier_push(
    frontier: &mut [[u8; 32]; 32],
    index: u32,
    leaf: [u8; 32],
) -> Result<(), u32> {
    let mut carry = leaf;
    let mut level = 0;
    while index & (1 << level) != 0 {
        carry = node(&frontier[level], &carry);
        level += 1;
        if level == 32 {
            return Err(MALFORMED);
        }
    }
    frontier[level] = carry;
    Ok(())
}

/// Finish a duplicate-last route tree from its persistent frontier.
pub fn route_frontier_root(frontier: &[[u8; 32]; 32], n: u32) -> Result<[u8; 32], u32> {
    if n == 0 {
        return Ok([0; 32]);
    }
    let mut acc: Option<([u8; 32], usize)> = None;
    for level in 0..32 {
        if n & (1 << level) != 0 {
            let left = frontier[level];
            acc = Some(match acc {
                None => (left, level),
                Some((mut right, mut height)) => {
                    while height < level {
                        right = node(&right, &right);
                        height += 1;
                    }
                    (node(&left, &right), level + 1)
                }
            });
        }
    }
    acc.map(|x| x.0).ok_or(MALFORMED)
}

/// Validates the full clause-5 header, record count, canonical row sequence,
/// and duplicate-last Merkle root. This view owns no route memory.
fn route_header_impl(
    raw: &[u8],
    allow_pxr1: bool,
    validate_pxr_rows: bool,
) -> Result<(u32, u32, usize), u32> {
    if raw.len() < 80 || raw.get(40..72) != Some(hash(&[ROUTE_DOMAIN]).as_slice()) {
        return Err(MALFORMED);
    }
    let n = u32_at(raw, 0)?;
    let records = u32_at(raw, 4)?;
    let body_at = 80usize
        .checked_add((n as usize).checked_mul(16).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    let end = body_at
        .checked_add((records as usize).checked_mul(24).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    if raw.len() < end {
        return Err(MALFORMED);
    }
    let extension_offset = u32_at(raw, 72)? as usize;
    let extension_kind = u16_at(raw, 76)?;
    let extension_version = u16_at(raw, 78)?;
    if extension_offset == 0 && extension_kind == 0 && extension_version == 0 {
        if raw.len() != end {
            return Err(MALFORMED);
        }
        return Ok((n, records, end));
    }
    if !allow_pxr1 || extension_offset != end || extension_kind != 1 || extension_version != 1 {
        return Err(MALFORMED);
    }
    if validate_pxr_rows {
        decode_pxr1(&raw[end..])?;
    } else {
        decode_pxr1_header(&raw[end..])?;
    }
    Ok((n, records, end))
}

/// Legacy clause-5 header: PT1S v3/tag 106 refuses every extension.
pub fn route_header(raw: &[u8]) -> Result<(u32, u32), u32> {
    let (n, records, _) = route_header_impl(raw, false, false)?;
    Ok((n, records))
}

/// PT1S-v4-only clause-5 header parser, including the optional PXR1 trailer.
pub fn route_header_v4(raw: &[u8]) -> Result<(u32, u32, Option<Pxr1<'_>>), u32> {
    let (n, records, end) = route_header_impl(raw, true, true)?;
    let pxr = if u32_at(raw, 72)? == 0 {
        None
    } else {
        Some(decode_pxr1(&raw[end..])?)
    };
    Ok((n, records, pxr))
}

/// PT1X seal and already-sealed v4 consumers need the canonical PXR1 header
/// and exact trailer extent without rescanning every directory row on each
/// chunk or instantiation. Row validation is performed by the PT1X cursor and
/// once more by PT2S tag 145 before the plan becomes sealed.
pub fn route_header_v4_shallow(raw: &[u8]) -> Result<(u32, u32, Option<Pxr1<'_>>), u32> {
    let (n, records, end) = route_header_impl(raw, true, false)?;
    let pxr = if u32_at(raw, 72)? == 0 {
        None
    } else {
        Some(decode_pxr1_header(&raw[end..])?)
    };
    Ok((n, records, pxr))
}

fn decode_clause5_impl(raw: &[u8], allow_pxr1: bool) -> Result<u32, u32> {
    let (n, records, _) = route_header_impl(raw, allow_pxr1, allow_pxr1)?;
    let body_at = 80 + n as usize * 16;
    let mut running = 0u32;
    // A Merkle frontier is 32 hashes (1 KiB); no per-entry heap allocation.
    let mut frontier: [Option<[u8; 32]>; 32] = [None; 32];
    for i in 0..n {
        let at = 80 + i as usize * 16;
        let row = entry_at(raw, i)?;
        if row.index != i || row.route_start != running || u16_at(raw, at + 10)? != 0 {
            return Err(MALFORMED);
        }
        running = running
            .checked_add(row.read_count as u32 + row.write_count as u32)
            .ok_or(MALFORMED)?;
        if running > records {
            return Err(MALFORMED);
        }
        let first = body_at + row.route_start as usize * 24;
        let last = body_at + running as usize * 24;
        let leaf = hash(&[
            ROUTE_DOMAIN,
            &i.to_le_bytes(),
            &row.kernel_index.to_le_bytes(),
            &row.read_count.to_le_bytes(),
            &row.write_count.to_le_bytes(),
            &raw[first..last],
        ]);
        let mut carry = leaf;
        let mut level = 0;
        while i & (1 << level) != 0 {
            carry = node(&frontier[level].take().ok_or(MALFORMED)?, &carry);
            level += 1;
        }
        frontier[level] = Some(carry);
    }
    if running != records {
        return Err(MALFORMED);
    }
    let root = if n == 0 {
        [0; 32]
    } else {
        let mut acc: Option<([u8; 32], usize)> = None;
        for level in 0..32 {
            if let Some(left) = frontier[level] {
                acc = Some(match acc {
                    None => (left, level),
                    Some((mut right, mut height)) => {
                        while height < level {
                            right = node(&right, &right);
                            height += 1;
                        }
                        (node(&left, &right), level + 1)
                    }
                });
            }
        }
        acc.ok_or(MALFORMED)?.0
    };
    if raw[8..40] != root {
        return Err(MALFORMED);
    }
    Ok(n)
}

/// PT1S v3 / tag 106 decoder. The header's extension bytes must be zero.
pub fn decode_clause5(raw: &[u8]) -> Result<u32, u32> {
    decode_clause5_impl(raw, false)
}

/// PT1S-v4-only decoder. PXR1 is structurally validated before the route root.
pub fn decode_clause5_v4(raw: &[u8]) -> Result<u32, u32> {
    decode_clause5_impl(raw, true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pxr1Row {
    pub first_token: u32,
    pub token_count: u32,
    pub producer_entry: u32,
    pub producer_write_ordinal: u16,
    pub region_offset: u64,
    pub byte_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pxr1<'a> {
    raw: &'a [u8],
    pub region_id: u16,
    pub token_count: u32,
    pub row_count: u32,
}

impl Pxr1<'_> {
    pub fn row(&self, i: u32) -> Result<Pxr1Row, u32> {
        if i >= self.row_count {
            return Err(MALFORMED);
        }
        let at = PXR1_HEADER_BYTES + i as usize * PXR1_ROW_BYTES;
        let row = Pxr1Row {
            first_token: u32_at(self.raw, at)?,
            token_count: u32_at(self.raw, at + 4)?,
            producer_entry: u32_at(self.raw, at + 8)?,
            producer_write_ordinal: u16_at(self.raw, at + 12)?,
            region_offset: u64_at(self.raw, at + 16)?,
            byte_length: u32_at(self.raw, at + 24)?,
        };
        if row.token_count == 0
            || row.producer_write_ordinal > 254
            || row.byte_length != row.token_count.checked_mul(8).ok_or(MALFORMED)?
            || u16_at(self.raw, at + 14)? != 0
            || u32_at(self.raw, at + 28)? != 0
        {
            return Err(MALFORMED);
        }
        Ok(row)
    }

    /// Resolve a token in the ordered directory. The second value is the
    /// eight-byte cell offset within the full producer write.
    pub fn find(&self, token: u32) -> Result<(Pxr1Row, u32), u32> {
        if token >= self.token_count {
            return Err(PT2_PRODUCER);
        }
        let (mut lo, mut hi) = (0u32, self.row_count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self.row(mid)?;
            if token < row.first_token {
                hi = mid;
            } else if token
                >= row
                    .first_token
                    .checked_add(row.token_count)
                    .ok_or(OVERFLOW)?
            {
                lo = mid + 1;
            } else {
                return Ok((row, (token - row.first_token) * 8));
            }
        }
        Err(PT2_PRODUCER)
    }
}

fn decode_pxr1_header(raw: &[u8]) -> Result<Pxr1<'_>, u32> {
    if raw.len() < PXR1_HEADER_BYTES
        || &raw[..4] != b"PXR1"
        || u16_at(raw, 4)? != 1
        || u16_at(raw, 6)? as usize != PXR1_HEADER_BYTES
        || u16_at(raw, 10)? != 8
        || u32_at(raw, 16)? != 0
        || u16_at(raw, 24)? as usize != PXR1_ROW_BYTES
        || u16_at(raw, 26)? != 0
    {
        return Err(MALFORMED);
    }
    let token_count = u32_at(raw, 12)?;
    let row_count = u32_at(raw, 20)?;
    let directory_bytes = u32_at(raw, 28)? as usize;
    if token_count == 0
        || row_count == 0
        || directory_bytes
            != (row_count as usize)
                .checked_mul(PXR1_ROW_BYTES)
                .ok_or(MALFORMED)?
        || raw.len()
            != PXR1_HEADER_BYTES
                .checked_add(directory_bytes)
                .ok_or(MALFORMED)?
    {
        return Err(MALFORMED);
    }
    let view = Pxr1 {
        raw,
        region_id: u16_at(raw, 8)?,
        token_count,
        row_count,
    };
    Ok(view)
}

pub fn decode_pxr1(raw: &[u8]) -> Result<Pxr1<'_>, u32> {
    let view = decode_pxr1_header(raw)?;
    let mut cursor = 0u32;
    for i in 0..view.row_count {
        let row = view.row(i)?;
        if row.first_token != cursor {
            return Err(MALFORMED);
        }
        cursor = cursor.checked_add(row.token_count).ok_or(MALFORMED)?;
    }
    if cursor != view.token_count {
        return Err(MALFORMED);
    }
    Ok(view)
}

/// Validate PXR1 rows against the immutable clause-5 writes and v4 region
/// geometry. The clause-12 position table omits default invariant regions, so
/// their extent is committed by the exact producer writes named by each row.
pub fn validate_pxr1<'a>(
    routes: &'a [u8],
    c: Clause12<'_>,
    expected_token_count: u32,
) -> Result<Pxr1<'a>, u32> {
    let (_, _, pxr) = route_header_v4_shallow(routes)?;
    let pxr = pxr.ok_or(PT2_ROUTE_SET)?;
    if pxr.token_count != expected_token_count {
        return Err(PT2_ROUTE_SET);
    }
    // Clause-12 records only non-default position geometry. A missing row is
    // the canonical invariant layout used by PT1's constant regions.
    if c.region_position(pxr.region_id)?
        .is_some_and(|r| r.ring != 0 || r.stride != 0)
    {
        return Err(PT2_ROUTE_SET);
    }
    let mut token_cursor = 0u32;
    let mut byte_cursor = None;
    let mut previous_pair = None;
    for i in 0..pxr.row_count {
        let row = pxr.row(i)?;
        if row.first_token != token_cursor {
            return Err(MALFORMED);
        }
        token_cursor = token_cursor.checked_add(row.token_count).ok_or(OVERFLOW)?;
        let end = row
            .region_offset
            .checked_add(row.byte_length as u64)
            .ok_or(OVERFLOW)?;
        if byte_cursor.is_some_and(|cursor| cursor != row.region_offset) {
            return Err(PT2_ROUTE_SET);
        }
        byte_cursor = Some(end);
        let pair = (row.producer_entry, row.producer_write_ordinal);
        if previous_pair.is_some_and(|previous| previous >= pair) {
            return Err(PT2_PRODUCER);
        }
        previous_pair = Some(pair);
        let producer = entry_at(routes, row.producer_entry).map_err(|_| PT2_PRODUCER)?;
        if row.producer_write_ordinal as u32 >= producer.write_count as u32 {
            return Err(PT2_PRODUCER);
        }
        let ordinal = producer
            .read_count
            .checked_add(row.producer_write_ordinal)
            .ok_or(OVERFLOW)?;
        let write = route_at(routes, producer, ordinal)?;
        if write.direction != 1
            || write.region_id != pxr.region_id
            || write.region_offset != row.region_offset
            || write.byte_length != row.byte_length
            || write.producer_entry != row.producer_entry
            || write.producer_delta != 0
            || write.flags != 0
        {
            return Err(PT2_PRODUCER);
        }
    }
    if token_cursor != expected_token_count {
        return Err(MALFORMED);
    }
    Ok(pxr)
}

/// Read one canonical clause-5 entry row after `decode_clause5`.
pub fn entry_at(raw: &[u8], index: u32) -> Result<TemplateEntry, u32> {
    let at = 80usize
        .checked_add((index as usize).checked_mul(16).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    if at + 16 > raw.len() {
        return Err(MALFORMED);
    }
    Ok(TemplateEntry {
        index: u32_at(raw, at)?,
        kernel_index: u16_at(raw, at + 4)?,
        read_count: u16_at(raw, at + 6)?,
        write_count: u16_at(raw, at + 8)?,
        route_start: u32_at(raw, at + 12)?,
    })
}

/// Read one route of an entry; `ordinal` is within reads followed by writes.
pub fn route_at(raw: &[u8], e: TemplateEntry, ordinal: u16) -> Result<Route, u32> {
    if ordinal as u32 >= e.read_count as u32 + e.write_count as u32 {
        return Err(MALFORMED);
    }
    let n = u32_at(raw, 0)? as usize;
    let at = 80usize
        .checked_add(n.checked_mul(16).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?
        .checked_add(
            (e.route_start as usize + ordinal as usize)
                .checked_mul(24)
                .ok_or(MALFORMED)?,
        )
        .ok_or(MALFORMED)?;
    let b = raw.get(at..at + 24).ok_or(MALFORMED)?;
    Ok(Route {
        region_id: u16_at(b, 0)?,
        direction: b[2],
        read_class: b[3],
        region_offset: u64_at(b, 4)?,
        byte_length: u32_at(b, 12)?,
        producer_entry: u32_at(b, 16)?,
        producer_delta: u16_at(b, 20)?,
        flags: u16_at(b, 22)?,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct Clause12<'a> {
    pub raw: &'a [u8],
    pub position_count: u32,
    pub segment_count: u16,
    pub operation_count: u32,
    pub entries_per_position: u32,
    pub producer_slots_per_position: u8,
    pub range_tree_height: u8,
    pub max_cover_refs: u8,
    pub max_auth_refs: u8,
    pub prompt_positions: u32,
    pub max_producer_delta: u16,
    pub leaf_storage_mode: u8,
    tables: [Table; 5],
}

#[derive(Clone, Copy, Debug, Default)]
struct Table {
    at: usize,
    count: u32,
    width: usize,
}
impl Table {
    fn row<'a>(&self, raw: &'a [u8], i: u32) -> Result<&'a [u8], u32> {
        if i >= self.count {
            return Err(MALFORMED);
        }
        let at = self.at + i as usize * self.width;
        raw.get(at..at + self.width).ok_or(MALFORMED)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionPosition {
    pub region_id: u16,
    pub ring: u32,
    pub stride: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromptSwitch {
    pub entry: u32,
    pub ordinal: u16,
    pub region_id: u16,
    pub offset: u64,
    pub stride: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeDeclaration {
    pub entry: u32,
    pub family: u16,
    pub first_rule: u8,
    pub window: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TScaled {
    pub entry: u32,
    pub direction: u8,
    pub ordinal: u16,
    pub offset_per_t: u64,
    pub length_per_t: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadPatch {
    pub entry: u32,
    pub offset: u16,
    pub width: u8,
    pub rule: u8,
    pub base: u64,
    pub stride: u64,
}

impl<'a> Clause12<'a> {
    pub fn region_count(&self) -> u32 {
        self.tables[0].count
    }
    pub fn prompt_switch_count(&self) -> u32 {
        self.tables[1].count
    }
    pub fn range_count(&self) -> u32 {
        self.tables[2].count
    }
    pub fn t_scaled_count(&self) -> u32 {
        self.tables[3].count
    }
    pub fn patch_count(&self) -> u32 {
        self.tables[4].count
    }
    pub fn region(&self, i: u32) -> Result<RegionPosition, u32> {
        let b = self.tables[0].row(self.raw, i)?;
        Ok(RegionPosition {
            region_id: u16_at(b, 0)?,
            ring: u32_at(b, 4)?,
            stride: u64_at(b, 8)?,
        })
    }
    pub fn prompt_switch(&self, i: u32) -> Result<PromptSwitch, u32> {
        let b = self.tables[1].row(self.raw, i)?;
        Ok(PromptSwitch {
            entry: u32_at(b, 0)?,
            ordinal: u16_at(b, 4)?,
            region_id: u16_at(b, 6)?,
            offset: u64_at(b, 8)?,
            stride: u32_at(b, 16)?,
        })
    }
    pub fn range(&self, i: u32) -> Result<RangeDeclaration, u32> {
        let b = self.tables[2].row(self.raw, i)?;
        Ok(RangeDeclaration {
            entry: u32_at(b, 0)?,
            family: u16_at(b, 4)?,
            first_rule: b[6],
            window: u32_at(b, 8)?,
        })
    }
    pub fn t_scaled(&self, i: u32) -> Result<TScaled, u32> {
        let b = self.tables[3].row(self.raw, i)?;
        Ok(TScaled {
            entry: u32_at(b, 0)?,
            direction: b[4],
            ordinal: u16_at(b, 5)?,
            offset_per_t: u64_at(b, 8)?,
            length_per_t: u32_at(b, 16)?,
        })
    }
    pub fn patch(&self, i: u32) -> Result<PayloadPatch, u32> {
        let b = self.tables[4].row(self.raw, i)?;
        Ok(PayloadPatch {
            entry: u32_at(b, 0)?,
            offset: u16_at(b, 4)?,
            width: b[6],
            rule: b[7],
            base: u64_at(b, 8)?,
            stride: u64_at(b, 16)?,
        })
    }
    pub fn region_position(&self, region_id: u16) -> Result<Option<RegionPosition>, u32> {
        let mut lo = 0;
        let mut hi = self.region_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if self.region(m)?.region_id < region_id {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        if lo < self.region_count() && self.region(lo)?.region_id == region_id {
            return self.region(lo).map(Some);
        }
        Ok(None)
    }
    pub fn prompt_for(&self, entry: u32, ordinal: u16) -> Result<Option<PromptSwitch>, u32> {
        let mut lo = 0;
        let mut hi = self.prompt_switch_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            let r = self.prompt_switch(m)?;
            if (r.entry, r.ordinal) < (entry, ordinal) {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        if lo < self.prompt_switch_count()
            && (
                self.prompt_switch(lo)?.entry,
                self.prompt_switch(lo)?.ordinal,
            ) == (entry, ordinal)
        {
            return self.prompt_switch(lo).map(Some);
        }
        Ok(None)
    }
    pub fn t_scaled_for(
        &self,
        entry: u32,
        direction: u8,
        ordinal: u16,
    ) -> Result<Option<TScaled>, u32> {
        let mut lo = 0;
        let mut hi = self.t_scaled_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            let r = self.t_scaled(m)?;
            if (r.entry, r.direction, r.ordinal) < (entry, direction, ordinal) {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        if lo < self.t_scaled_count()
            && (
                self.t_scaled(lo)?.entry,
                self.t_scaled(lo)?.direction,
                self.t_scaled(lo)?.ordinal,
            ) == (entry, direction, ordinal)
        {
            return self.t_scaled(lo).map(Some);
        }
        Ok(None)
    }
    pub fn has_scaled_entry(&self, entry: u32) -> Result<bool, u32> {
        let mut lo = 0;
        let mut hi = self.t_scaled_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if self.t_scaled(m)?.entry < entry {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        Ok(lo < self.t_scaled_count() && self.t_scaled(lo)?.entry == entry)
    }
    pub fn range_for(&self, entry: u32, ordinal: u32) -> Result<Option<RangeDeclaration>, u32> {
        let mut lo = 0;
        let mut hi = self.range_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if self.range(m)?.entry < entry {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        let i = lo.checked_add(ordinal).ok_or(OVERFLOW)?;
        if i < self.range_count() && self.range(i)?.entry == entry {
            return self.range(i).map(Some);
        }
        Ok(None)
    }
}

/// Canonical clause-12 v2 decoder. All layout, derived-count, ordinal,
/// reserved-byte, root, ordering, and rule-3 CLAMP checks match Python's
/// `decode_clause12_v2`; seal conditions use `seal` below.
pub fn decode_clause12_v2(raw: &[u8]) -> Result<Clause12<'_>, u32> {
    if raw.first() != Some(&2) || raw.len() < 59 || raw[55] != 4 || raw[56..59] != [0; 3] {
        return Err(MALFORMED);
    }
    let positions = u32_at(raw, 1)?;
    let nseg = u16_at(raw, 5)?;
    let operations = u32_at(raw, 7)?;
    let entries = u32_at(raw, 11)?;
    let max_segment = u32_at(raw, 15)?;
    let height = raw[52];
    let expected_height = if positions <= 1 {
        0
    } else {
        32 - (positions - 1).leading_zeros()
    };
    if height as u32 != expected_height || height > 19 {
        return Err(MALFORMED);
    }
    let mut at = 59usize;
    let seg_bytes = (nseg as usize).checked_mul(43).ok_or(MALFORMED)?;
    let seg_end = at.checked_add(seg_bytes).ok_or(MALFORMED)?;
    if seg_end > raw.len() {
        return Err(MALFORMED);
    }
    if hash(&[SEGMENT_DOMAIN, &nseg.to_le_bytes(), &raw[at..seg_end]]) != raw[19..51] {
        return Err(MALFORMED);
    }
    let mut prev_sid = None;
    let mut max_seen = 0;
    let mut entries_seen = 0u32;
    let mut ops_seen = 0u32;
    let mut prev_ordinal = None;
    let segment_at = at;
    at = seg_end;
    for i in 0..nseg as usize {
        let s = &raw[segment_at + 43 * i..segment_at + 43 * (i + 1)];
        let sid = u16_at(s, 0)?;
        if prev_sid.is_some_and(|v| sid <= v) {
            return Err(MALFORMED);
        }
        prev_sid = Some(sid);
        let nops = u16_at(s, 5)?;
        let count = u32_at(s, 7)?;
        let op_end = at.checked_add(nops as usize * 12).ok_or(MALFORMED)?;
        if op_end > raw.len() {
            return Err(MALFORMED);
        }
        let mut cursor = 0u32;
        for j in 0..nops as usize {
            let op = &raw[at + 12 * j..at + 12 * (j + 1)];
            let ordinal = u16_at(op, 0)?;
            if prev_ordinal.is_some_and(|v| ordinal as u32 != v + 1)
                || u16_at(op, 2)? != j as u16
                || u32_at(op, 4)? != cursor
            {
                return Err(MALFORMED);
            }
            prev_ordinal = Some(ordinal as u32);
            cursor = cursor.checked_add(u32_at(op, 8)?).ok_or(MALFORMED)?;
        }
        if cursor != count
            || hash(&[
                OPERATION_DOMAIN,
                &sid.to_le_bytes(),
                &nops.to_le_bytes(),
                &raw[at..op_end],
            ]) != s[11..43]
        {
            return Err(MALFORMED);
        }
        at = op_end;
        entries_seen = entries_seen.checked_add(count).ok_or(MALFORMED)?;
        ops_seen += nops as u32;
        max_seen = max_seen.max(count);
    }
    if entries_seen != entries || ops_seen != operations || max_seen != max_segment {
        return Err(MALFORMED);
    }
    let v2 = raw.get(at..at + 24).ok_or(MALFORMED)?;
    let prompt_positions = u32_at(v2, 0)?;
    let mode = v2[6];
    if v2[7] != 0 || mode > 1 || prompt_positions == 0 || prompt_positions > positions {
        return Err(MALFORMED);
    }
    let counts = [
        u16_at(v2, 8)? as u32,
        u16_at(v2, 10)? as u32,
        u32_at(v2, 12)?,
        u32_at(v2, 16)?,
        u32_at(v2, 20)?,
    ];
    at += 24;
    let mut tables = [Table::default(); 5];
    for (i, width) in [16usize, 24, 16, 24, 24].iter().enumerate() {
        let end = at
            .checked_add((counts[i] as usize).checked_mul(*width).ok_or(MALFORMED)?)
            .ok_or(MALFORMED)?;
        if end > raw.len() {
            return Err(MALFORMED);
        }
        tables[i] = Table {
            at,
            count: counts[i],
            width: *width,
        };
        at = end;
    }
    if at != raw.len() {
        return Err(MALFORMED);
    }
    let c = Clause12 {
        raw,
        position_count: positions,
        segment_count: nseg,
        operation_count: operations,
        entries_per_position: entries,
        producer_slots_per_position: raw[51],
        range_tree_height: height,
        max_cover_refs: raw[53],
        max_auth_refs: raw[54],
        prompt_positions,
        max_producer_delta: u16_at(v2, 4)?,
        leaf_storage_mode: mode,
        tables,
    };
    let mut prev = None;
    for i in 0..c.region_count() {
        let b = c.tables[0].row(raw, i)?;
        let r = c.region(i)?;
        if u16_at(b, 2)? != 0 || prev.is_some_and(|v| r.region_id <= v) {
            return Err(MALFORMED);
        }
        prev = Some(r.region_id);
    }
    let mut prev = None;
    for i in 0..c.prompt_switch_count() {
        let b = c.tables[1].row(raw, i)?;
        let r = c.prompt_switch(i)?;
        if u32_at(b, 20)? != 0 || prev.is_some_and(|v| (r.entry, r.ordinal) <= v) {
            return Err(MALFORMED);
        }
        prev = Some((r.entry, r.ordinal));
    }
    let mut prev = None;
    for i in 0..c.range_count() {
        let b = c.tables[2].row(raw, i)?;
        let r = c.range(i)?;
        if b[7] != 0
            || u32_at(b, 12)? != 0
            || r.first_rule > 1
            || (r.first_rule == 1 && r.window == 0)
            || prev.is_some_and(|v| r.entry < v)
        {
            return Err(MALFORMED);
        }
        prev = Some(r.entry);
    }
    let mut prev = None;
    for i in 0..c.t_scaled_count() {
        let b = c.tables[3].row(raw, i)?;
        let r = c.t_scaled(i)?;
        if b[7] != 0
            || u32_at(b, 20)? != 0
            || r.direction > 1
            || r.length_per_t == 0
            || prev.is_some_and(|v| (r.entry, r.direction, r.ordinal) <= v)
        {
            return Err(MALFORMED);
        }
        prev = Some((r.entry, r.direction, r.ordinal));
    }
    let mut prev: Option<(u32, u16, u8)> = None;
    for i in 0..c.patch_count() {
        let r = c.patch(i)?;
        if ![2, 4, 8].contains(&r.width)
            || r.rule > 2
            || prev.is_some_and(|v| {
                (r.entry, r.offset) <= (v.0, v.1)
                    || (r.entry == v.0 && (v.1 as u32 + v.2 as u32) > r.offset as u32)
            })
        {
            return Err(MALFORMED);
        }
        prev = Some((r.entry, r.offset, r.width));
    }
    Ok(c)
}

/// Bounded layout view for SBF. Call `validate_clause12_item` for every item
/// before trusting this view; the complete decoder above remains normative.
pub fn clause12_layout(raw: &[u8]) -> Result<(Clause12<'_>, u32), u32> {
    if raw.first() != Some(&2) || raw.len() < 59 || raw[55] != 4 || raw[56..59] != [0; 3] {
        return Err(MALFORMED);
    }
    let positions = u32_at(raw, 1)?;
    let nseg = u16_at(raw, 5)?;
    let operations = u32_at(raw, 7)?;
    let entries = u32_at(raw, 11)?;
    let max_segment = u32_at(raw, 15)?;
    let height = raw[52];
    let expected_height = if positions <= 1 {
        0
    } else {
        32 - (positions - 1).leading_zeros()
    };
    if height as u32 != expected_height || height > 19 {
        return Err(MALFORMED);
    }
    let seg_end = 59usize.checked_add(nseg as usize * 43).ok_or(MALFORMED)?;
    let segment_rows = raw.get(59..seg_end).ok_or(MALFORMED)?;
    if hash(&[SEGMENT_DOMAIN, &nseg.to_le_bytes(), segment_rows]) != raw[19..51] {
        return Err(MALFORMED);
    }
    let mut at = seg_end;
    let mut total_entries = 0u32;
    let mut total_ops = 0u32;
    let mut max_seen = 0u32;
    for i in 0..nseg as usize {
        let s = &segment_rows[43 * i..43 * (i + 1)];
        let count = u32_at(s, 7)?;
        total_entries = total_entries.checked_add(count).ok_or(MALFORMED)?;
        total_ops = total_ops
            .checked_add(u16_at(s, 5)? as u32)
            .ok_or(MALFORMED)?;
        max_seen = max_seen.max(count);
        at = at
            .checked_add(u16_at(s, 5)? as usize * 12)
            .ok_or(MALFORMED)?;
    }
    if total_entries != entries || total_ops != operations || max_seen != max_segment {
        return Err(MALFORMED);
    }
    let v2 = raw.get(at..at + 24).ok_or(MALFORMED)?;
    let prompt_positions = u32_at(v2, 0)?;
    let mode = v2[6];
    if v2[7] != 0 || mode > 1 || prompt_positions == 0 || prompt_positions > positions {
        return Err(MALFORMED);
    }
    let counts = [
        u16_at(v2, 8)? as u32,
        u16_at(v2, 10)? as u32,
        u32_at(v2, 12)?,
        u32_at(v2, 16)?,
        u32_at(v2, 20)?,
    ];
    at += 24;
    let mut tables = [Table::default(); 5];
    for (i, width) in [16usize, 24, 16, 24, 24].iter().enumerate() {
        let end = at
            .checked_add((counts[i] as usize).checked_mul(*width).ok_or(MALFORMED)?)
            .ok_or(MALFORMED)?;
        if end > raw.len() {
            return Err(MALFORMED);
        }
        tables[i] = Table {
            at,
            count: counts[i],
            width: *width,
        };
        at = end;
    }
    if at != raw.len() {
        return Err(MALFORMED);
    }
    let c = Clause12 {
        raw,
        position_count: positions,
        segment_count: nseg,
        operation_count: operations,
        entries_per_position: entries,
        producer_slots_per_position: raw[51],
        range_tree_height: height,
        max_cover_refs: raw[53],
        max_auth_refs: raw[54],
        prompt_positions,
        max_producer_delta: u16_at(v2, 4)?,
        leaf_storage_mode: mode,
        tables,
    };
    let total = nseg as u32 + counts.iter().sum::<u32>();
    Ok((c, total))
}

/// Validate one canonical clause-12 segment or table row. A persistent cursor
/// in the PT1 seal ensures every item is visited before the route seal begins.
pub fn validate_clause12_item(c: &Clause12<'_>, mut item: u32) -> Result<(), u32> {
    if item < c.segment_count as u32 {
        let i = item as usize;
        let s = c.raw.get(59 + i * 43..59 + (i + 1) * 43).ok_or(MALFORMED)?;
        if i > 0 && u16_at(s, 0)? <= u16_at(c.raw, 59 + (i - 1) * 43)? {
            return Err(MALFORMED);
        }
        let nops = u16_at(s, 5)?;
        let mut at = 59 + c.segment_count as usize * 43;
        let first_op = 59 + c.segment_count as usize * 43;
        let mut ordinal = u16_at(c.raw, first_op)? as u32;
        for k in 0..i {
            let prior = u16_at(c.raw, 59 + k * 43 + 5)? as u32;
            at += prior as usize * 12;
            ordinal += prior;
        }
        let end = at.checked_add(nops as usize * 12).ok_or(MALFORMED)?;
        let ops = c.raw.get(at..end).ok_or(MALFORMED)?;
        let mut cursor = 0u32;
        for j in 0..nops as usize {
            let op = &ops[j * 12..(j + 1) * 12];
            if u16_at(op, 0)? as u32 != ordinal + j as u32
                || u16_at(op, 2)? != j as u16
                || u32_at(op, 4)? != cursor
            {
                return Err(MALFORMED);
            }
            cursor = cursor.checked_add(u32_at(op, 8)?).ok_or(MALFORMED)?;
        }
        if cursor != u32_at(s, 7)?
            || hash(&[
                OPERATION_DOMAIN,
                &u16_at(s, 0)?.to_le_bytes(),
                &nops.to_le_bytes(),
                ops,
            ]) != s[11..43]
        {
            return Err(MALFORMED);
        }
        return Ok(());
    }
    item -= c.segment_count as u32;
    for table in 0..5 {
        if item >= c.tables[table].count {
            item -= c.tables[table].count;
            continue;
        }
        let b = c.tables[table].row(c.raw, item)?;
        match table {
            0 => {
                let r = c.region(item)?;
                if u16_at(b, 2)? != 0 || (item > 0 && r.region_id <= c.region(item - 1)?.region_id)
                {
                    return Err(MALFORMED);
                }
            }
            1 => {
                let r = c.prompt_switch(item)?;
                if u32_at(b, 20)? != 0
                    || (item > 0
                        && (r.entry, r.ordinal) <= {
                            let p = c.prompt_switch(item - 1)?;
                            (p.entry, p.ordinal)
                        })
                {
                    return Err(MALFORMED);
                }
            }
            2 => {
                let r = c.range(item)?;
                if b[7] != 0
                    || u32_at(b, 12)? != 0
                    || r.first_rule > 1
                    || (r.first_rule == 1 && r.window == 0)
                    || (item > 0 && r.entry < c.range(item - 1)?.entry)
                {
                    return Err(MALFORMED);
                }
            }
            3 => {
                let r = c.t_scaled(item)?;
                if b[7] != 0
                    || u32_at(b, 20)? != 0
                    || r.direction > 1
                    || r.length_per_t == 0
                    || (item > 0
                        && (r.entry, r.direction, r.ordinal) <= {
                            let p = c.t_scaled(item - 1)?;
                            (p.entry, p.direction, p.ordinal)
                        })
                {
                    return Err(MALFORMED);
                }
            }
            4 => {
                let r = c.patch(item)?;
                if ![2, 4, 8].contains(&r.width) || r.rule > 2 {
                    return Err(MALFORMED);
                }
                if item > 0 {
                    let p = c.patch(item - 1)?;
                    if (r.entry, r.offset) <= (p.entry, p.offset)
                        || (r.entry == p.entry
                            && (p.offset as u32 + p.width as u32) > r.offset as u32)
                    {
                        return Err(MALFORMED);
                    }
                }
            }
            _ => unreachable!(),
        }
        return Ok(());
    }
    Err(MALFORMED)
}

/// Decode both normative clauses without copying either body.
pub fn decode<'a>(clause5: &'a [u8], clause12: &'a [u8]) -> Result<Template<'a>, u32> {
    let n = decode_clause5(clause5)?;
    let c = decode_clause12_v2(clause12)?;
    if n != c.entries_per_position {
        return Err(SLOT);
    }
    Ok(Template {
        clause5,
        clause12,
        position_count: c.position_count,
        prompt_positions: c.prompt_positions,
        max_producer_delta: c.max_producer_delta,
        entries_per_position: n,
        leaf_storage_mode: c.leaf_storage_mode,
    })
}

impl<'a> Template<'a> {
    /// Locate an entry using the sealed clause-12 segment and operation tables.
    /// This is intentionally computed from the table, never from a caller's
    /// claimed segment/local coordinate in a dispute response.
    pub fn coordinate(&self, index: u32) -> Result<EntryCoordinate, u32> {
        if index >= self.entries_per_position {
            return Err(MALFORMED);
        }
        let raw = self.clause12;
        let nseg = u16_at(raw, 5)? as usize;
        let mut first_entry = 0u32;
        let mut operation_at = 59usize
            .checked_add(nseg.checked_mul(43).ok_or(MALFORMED)?)
            .ok_or(MALFORMED)?;
        for i in 0..nseg {
            let segment = raw.get(59 + i * 43..59 + (i + 1) * 43).ok_or(MALFORMED)?;
            let count = u32_at(segment, 7)?;
            let nops = u16_at(segment, 5)? as usize;
            let operation_end = operation_at
                .checked_add(nops.checked_mul(12).ok_or(MALFORMED)?)
                .ok_or(MALFORMED)?;
            let operations = raw.get(operation_at..operation_end).ok_or(MALFORMED)?;
            let segment_end = first_entry.checked_add(count).ok_or(OVERFLOW)?;
            if index < segment_end {
                let local = index - first_entry;
                for op in operations.chunks_exact(12) {
                    let start = u32_at(op, 4)?;
                    let end = start.checked_add(u32_at(op, 8)?).ok_or(OVERFLOW)?;
                    if local >= start && local < end {
                        return Ok(EntryCoordinate {
                            segment: u16_at(segment, 0)?,
                            local,
                            operation_ordinal: u16_at(op, 0)?,
                        });
                    }
                }
                return Err(SLOT);
            }
            first_entry = segment_end;
            operation_at = operation_end;
        }
        Err(SLOT)
    }

    pub fn clause12(&self) -> Result<Clause12<'a>, u32> {
        decode_clause12_v2(self.clause12)
    }
    pub fn entry(&self, index: u32) -> Result<TemplateEntry, u32> {
        if index >= self.entries_per_position {
            return Err(MALFORMED);
        }
        entry_at(self.clause5, index)
    }
    /// Bind one template entry to a document position. Routes are requested
    /// individually through `InstantiatedEntry::route` to avoid a route array.
    pub fn instantiate(&'a self, index: u32, position: u32) -> Result<InstantiatedEntry<'a>, u32> {
        let c = self.clause12()?;
        self.instantiate_with(c, index, position)
    }
    pub fn instantiate_with(
        &'a self,
        c: Clause12<'a>,
        index: u32,
        position: u32,
    ) -> Result<InstantiatedEntry<'a>, u32> {
        if position >= self.position_count {
            return Err(MALFORMED);
        }
        let entry = self.entry(index)?;
        let first_range = c.range_for(index, 0)?;
        let scaled = first_range.is_none() && c.has_scaled_entry(index)?;
        let attention_t = match first_range {
            Some(r) => Some(
                position + 1
                    - if r.first_rule == 0 {
                        0
                    } else {
                        position.saturating_sub(r.window)
                    },
            ),
            None if scaled => Some(position + 1),
            None => None,
        };
        Ok(InstantiatedEntry {
            template: self,
            clause12: c,
            entry,
            position,
            attention_t,
        })
    }
}

impl InstantiatedEntry<'_> {
    pub fn route_count(&self) -> u32 {
        self.entry.read_count as u32 + self.entry.write_count as u32
    }

    /// Instantiate one route in template ordinal order (reads then writes).
    /// The caller must have run `seal` before trusting producer bindings.
    pub fn route(&self, ordinal: u16) -> Result<InstantiatedRoute, u32> {
        self.route_pt2(ordinal, None, None)
    }

    /// PT2 route instantiation. `source` is the committed template at p-d for
    /// a named producer; `windows` is the current position's v4 geometry.
    /// Passing None for either keeps the PT1 rev7 behavior.
    pub fn route_pt2(
        &self,
        ordinal: u16,
        source: Option<(&Template<'_>, Clause12<'_>)>,
        windows: Option<&GeometryV4<'_>>,
    ) -> Result<InstantiatedRoute, u32> {
        let t = self.template;
        let c = self.clause12;
        let e = self.entry;
        let p = self.position;
        let raw = route_at(t.clause5, e, ordinal)?;
        let direction = if ordinal < e.read_count { 0 } else { 1 };
        let k = if direction == 0 {
            ordinal
        } else {
            ordinal - e.read_count
        };
        let pos = c.region_position(raw.region_id)?;
        let stride = pos.map_or(0, |r| r.stride);
        let ring = pos.map_or(0, |r| r.ring);
        let slot = |q: u32| -> u64 {
            if stride == 0 {
                0
            } else if ring == 0 {
                q as u64
            } else {
                (q % ring) as u64
            }
        };
        let x = c.t_scaled_for(e.index, direction, k)?;
        if x.is_some() != (raw.flags & 2 != 0) {
            return Err(if windows.is_some() || source.is_some() {
                PT2_ROUTE_SET
            } else {
                MALFORMED
            });
        }
        let (off, length) = match x {
            Some(row) => (
                raw.region_offset
                    .checked_add(
                        (p as u64 + 1)
                            .checked_mul(row.offset_per_t)
                            .ok_or(OVERFLOW)?,
                    )
                    .ok_or(OVERFLOW)?,
                (p + 1).checked_mul(row.length_per_t).ok_or(OVERFLOW)?,
            ),
            None => (raw.region_offset, raw.byte_length),
        };
        let mut out = InstantiatedRoute {
            direction,
            ordinal: k,
            region_id: raw.region_id,
            effective_offset: 0,
            byte_length: length,
            read_class: if direction == 0 { raw.read_class } else { 0 },
            binding_kind: 0,
            source_supplied: false,
            initial_content: false,
            producer_position: NO_PRODUCER,
            producer_entry: NO_PRODUCER,
            producer_write_ordinal: u8::MAX,
            range_first: 0,
            range_end: 0,
            family_ordinal: 0,
            template_offset: raw.region_offset,
        };
        if direction == 1 {
            out.effective_offset = off
                .checked_add(slot(p).checked_mul(stride).ok_or(OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.producer_position = p;
            out.producer_entry = e.index;
            out.producer_write_ordinal = k as u8;
            return Ok(out);
        }
        if raw.read_class == 3 {
            if let Some(g) = windows {
                if g.find(e.index, k)?.is_some() {
                    return g.instantiate_window(t.clause5, c, p, e.index, k);
                }
            }
            let mut c3 = 0;
            for j in 0..k {
                if route_at(t.clause5, e, j)?.read_class == 3 {
                    c3 += 1;
                }
            }
            let decl = c.range_for(e.index, c3)?.ok_or(SLOT)?;
            let first = if decl.first_rule == 0 {
                0
            } else {
                p.saturating_sub(decl.window)
            };
            let end = p.checked_add(1).ok_or(OVERFLOW)?;
            out.effective_offset = raw
                .region_offset
                .checked_add((first as u64).checked_mul(stride).ok_or(OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.byte_length = (end - first)
                .checked_mul(u32::try_from(stride).map_err(|_| OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.binding_kind = 2;
            out.range_first = first;
            out.range_end = end;
            out.family_ordinal = decl.family;
            return Ok(out);
        }
        if let Some(ps) = c.prompt_for(e.index, k)? {
            if p < c.prompt_positions {
                out.region_id = ps.region_id;
                out.effective_offset = ps
                    .offset
                    .checked_add((p as u64).checked_mul(ps.stride as u64).ok_or(OVERFLOW)?)
                    .ok_or(OVERFLOW)?;
                out.byte_length = raw.byte_length;
                out.read_class = 2;
                out.source_supplied = true;
                return Ok(out);
            }
        }
        let named = raw.producer_entry != NO_PRODUCER;
        if named && p >= raw.producer_delta as u32 {
            let q = p - raw.producer_delta as u32;
            out.effective_offset = off
                .checked_add(slot(q).checked_mul(stride).ok_or(OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.binding_kind = 1;
            out.producer_position = q;
            out.producer_entry = raw.producer_entry;
            out.producer_write_ordinal = if let Some((producer_t, producer_c)) = source {
                matching_write_cross(producer_t, producer_c, c, e.index, k, raw)?
            } else {
                matching_write(t, &c, e.index, k, raw)?
            };
        } else if named {
            let initial_slot = if stride == 0 {
                0
            } else if ring >= 2 {
                // Python computes (p + ring - d) % ring with unbounded ints.
                // Do the same modular arithmetic without an intermediate u32
                // overflow near the maximum legal document position.
                ((p as u64 + ring as u64 - (raw.producer_delta as u64 % ring as u64)) % ring as u64)
                    as u32
            } else {
                return Err(SLOT);
            };
            out.effective_offset = off
                .checked_add((initial_slot as u64).checked_mul(stride).ok_or(OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.initial_content = true;
        } else {
            out.effective_offset = off
                .checked_add(slot(p).checked_mul(stride).ok_or(OVERFLOW)?)
                .ok_or(OVERFLOW)?;
            out.initial_content = raw.read_class == 0;
        }
        Ok(out)
    }

    /// Copy the normalized payload into `out`, then apply PT1 patch rows.
    /// `out` must be exactly as long as `payload`; no allocation is performed.
    pub fn patch_payload(&self, payload: &[u8], out: &mut [u8]) -> Result<(), u32> {
        if out.len() != payload.len() {
            return Err(MALFORMED);
        }
        out.copy_from_slice(payload);
        let c = self.clause12;
        let mut lo = 0;
        let mut hi = c.patch_count();
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if c.patch(m)?.entry < self.entry.index {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        for i in lo..c.patch_count() {
            let r = c.patch(i)?;
            if r.entry > self.entry.index {
                break;
            }
            let value = match r.rule {
                0 => self.position as u64 + 1,
                1 => self.position as u64,
                2 => r
                    .base
                    .checked_add(
                        (self.position as u64)
                            .checked_mul(r.stride)
                            .ok_or(OVERFLOW)?,
                    )
                    .ok_or(OVERFLOW)?,
                _ => return Err(MALFORMED),
            };
            if r.width < 8 && value >= (1u64 << (8 * r.width)) {
                return Err(OVERFLOW);
            }
            let at = r.offset as usize;
            out.get_mut(at..at + r.width as usize)
                .ok_or(MALFORMED)?
                .copy_from_slice(&value.to_le_bytes()[..r.width as usize]);
        }
        Ok(())
    }
}

fn matching_write(
    t: &Template<'_>,
    c: &Clause12<'_>,
    reader: u32,
    k: u16,
    r: Route,
) -> Result<u8, u32> {
    matching_write_cross(t, *c, *c, reader, k, r).map_err(|code| {
        if code == PT2_PRODUCER {
            SLOT
        } else {
            code
        }
    })
}

fn matching_write_cross(
    producer_template: &Template<'_>,
    producer_geometry: Clause12<'_>,
    reader_geometry: Clause12<'_>,
    reader: u32,
    k: u16,
    r: Route,
) -> Result<u8, u32> {
    let producer = producer_template
        .entry(r.producer_entry)
        .map_err(|_| PT2_PRODUCER)?;
    let read_x = if r.flags & 2 != 0 {
        reader_geometry.t_scaled_for(reader, 0, k)?
    } else {
        None
    };
    let mut found = None;
    for j in 0..producer.write_count {
        let w = route_at(producer_template.clause5, producer, producer.read_count + j)?;
        if w.region_id != r.region_id
            || w.region_offset != r.region_offset
            || (w.flags & 2) != (r.flags & 2)
        {
            continue;
        }
        let equal = if let Some(rx) = read_x {
            let wx = producer_geometry
                .t_scaled_for(producer.index, 1, j)?
                .ok_or(PT2_PRODUCER)?;
            (rx.offset_per_t, rx.length_per_t) == (wx.offset_per_t, wx.length_per_t)
        } else {
            w.byte_length == r.byte_length
        };
        if equal {
            if found.is_some() || j > u8::MAX as u16 {
                return Err(PT2_PRODUCER);
            }
            found = Some(j as u8);
        }
    }
    found.ok_or(PT2_PRODUCER)
}

/// Clause-3 region data needed by PT1 seal. Sorted, unique region IDs.
#[derive(Clone, Copy, Debug)]
pub struct SealRegion {
    pub region_id: u16,
    pub byte_length: u64,
    pub lifetime: u8,
    pub init_kind: u8,
}

/// Clause-8 family/slot binding needed by a class-3 PT1 read. Multiple slots
/// of one family are represented by consecutive rows with equal family ID.
#[derive(Clone, Copy, Debug)]
pub struct SealFamilySlot {
    pub family: u16,
    pub region_id: u16,
    pub template_entry: u32,
    pub write_ordinal: u16,
}

/// Optional seal facts supplied by closure runtime. `waves` is clause-6 wave
/// number by template entry; `None` means serial `wave(t)=t`. `attention_forms`
/// names forms subject to the PT1 full-attention T cap. The three optional
/// envelope arrays are indexed by template entry and checked when supplied.
pub struct SealContext<'a> {
    pub regions: &'a [SealRegion],
    pub family_slots: &'a [SealFamilySlot],
    pub waves: Option<&'a [u32]>,
    pub attention_forms: &'a [u16],
    pub envelope_max_t: Option<&'a [u32]>,
    pub envelope_closure_cost: Option<&'a [u32]>,
    pub kernel_read_lifetime_masks: Option<&'a [(u16, u64)]>,
    /// Form schema entries `(kernel_index, payload_offset, width, rule)`.
    pub patch_schema: &'a [(u16, u16, u8, u8)],
    /// Normalized payload lengths by template entry, when available.
    pub payload_lengths: Option<&'a [u16]>,
    /// Maximum patched values `(entry, offset, max)` from the envelope census.
    pub patch_census_bounds: Option<&'a [(u32, u16, u64)]>,
}

impl SealContext<'_> {
    fn region(&self, id: u16) -> Result<SealRegion, u32> {
        self.regions
            .iter()
            .find(|r| r.region_id == id)
            .copied()
            .ok_or(MALFORMED)
    }
    fn wave(&self, t: u32) -> Result<u32, u32> {
        self.waves
            .map_or(Ok(t), |w| w.get(t as usize).copied().ok_or(SLOT))
    }
    fn family(&self, id: u16) -> Option<SealFamilySlot> {
        self.family_slots.iter().find(|s| s.family == id).copied()
    }
}

/// Cross-table layout checks that require both decoded clauses and clause-8
/// family IDs. They are 580 checks and precede all 585 seal rules.
pub fn seal_layout(t: &Template<'_>, c: &Clause12<'_>, ctx: &SealContext<'_>) -> Result<(), u32> {
    for i in 0..c.t_scaled_count() {
        let x = c.t_scaled(i)?;
        let e = t.entry(x.entry).map_err(|_| MALFORMED)?;
        let ordinal = if x.direction == 0 {
            if x.ordinal >= e.read_count {
                return Err(MALFORMED);
            }
            x.ordinal
        } else {
            if x.ordinal >= e.write_count {
                return Err(MALFORMED);
            }
            e.read_count + x.ordinal
        };
        if route_at(t.clause5, e, ordinal)?.flags & 2 == 0 {
            return Err(MALFORMED);
        }
    }
    for i in 0..c.prompt_switch_count() {
        let ps = c.prompt_switch(i)?;
        if ps.ordinal >= t.entry(ps.entry).map_err(|_| MALFORMED)?.read_count {
            return Err(MALFORMED);
        }
        ctx.region(ps.region_id)?;
    }
    for i in 0..c.range_count() {
        let d = c.range(i)?;
        if d.entry >= t.entries_per_position || ctx.family(d.family).is_none() {
            return Err(MALFORMED);
        }
    }
    for i in 0..c.patch_count() {
        let p = c.patch(i)?;
        if p.entry >= t.entries_per_position {
            return Err(MALFORMED);
        }
        if let Some(lengths) = ctx.payload_lengths {
            if p.offset as usize + p.width as usize
                > *lengths.get(p.entry as usize).ok_or(MALFORMED)? as usize
            {
                return Err(MALFORMED);
            }
        }
    }
    for i in 0..t.entries_per_position {
        let e = t.entry(i)?;
        for j in 0..e.read_count as u32 + e.write_count as u32 {
            let r = route_at(t.clause5, e, j as u16)?;
            ctx.region(r.region_id)?;
            if r.direction > 1
                || r.read_class > 3
                || r.flags & !3 != 0
                || (r.byte_length == 0 && r.flags & 2 == 0)
                || (r.direction == 1 && r.read_class != 0)
            {
                return Err(MALFORMED);
            }
            let direction = if j < e.read_count as u32 { 0 } else { 1 };
            let k = if direction == 0 {
                j as u16
            } else {
                (j - e.read_count as u32) as u16
            };
            if r.flags & 2 != 0 && c.t_scaled_for(i, direction, k)?.is_none() {
                return Err(MALFORMED);
            }
        }
    }
    Ok(())
}

/// PT1 §3 rules 1–9, isolated so a host seal can complete this precedence
/// band over the whole template before any later geometry refusal.
pub fn seal_route_rules(t: &Template<'_>, c: &Clause12<'_>, e: TemplateEntry) -> Result<(), u32> {
    for k in 0..e.write_count {
        let w = route_at(t.clause5, e, e.read_count + k)?;
        if w.producer_entry != e.index || w.producer_delta != 0 || w.flags & 1 != 0 {
            return Err(SLOT);
        }
    }
    let mut class3 = 0u32;
    let mut prev_read = None;
    let mut prev_write = None;
    for k in 0..e.read_count {
        let r = route_at(t.clause5, e, k)?;
        let named = r.producer_entry != NO_PRODUCER;
        if (!named && r.producer_delta != 0)
            || (named && r.producer_delta == 0 && r.producer_entry >= e.index)
            || r.producer_delta > t.max_producer_delta
        {
            return Err(SLOT);
        }
        if named && r.read_class == 0 {
            matching_write(t, c, e.index, k, r)?;
        }
        if r.read_class == 3 {
            class3 += 1;
            if named || r.producer_delta != 0 || r.flags != 0 {
                return Err(SLOT);
            }
        }
        if (r.read_class == 1 || r.read_class == 2) && named {
            return Err(SLOT);
        }
        if r.flags & 1 != 0
            && (r.read_class != 0
                || !named
                || r.producer_delta == 0
                || c.prompt_for(e.index, k)?.is_none())
        {
            return Err(SLOT);
        }
        let tail = c.t_scaled_for(e.index, 0, k)?.map_or(0, |x| x.offset_per_t);
        let key = (r.region_id, r.region_offset, tail, r.producer_delta);
        if prev_read.is_some_and(|v| key <= v) {
            return Err(SLOT);
        }
        prev_read = Some(key);
    }
    if c.range_for(e.index, class3)?.is_some()
        || (class3 > 0 && c.range_for(e.index, class3 - 1)?.is_none())
    {
        return Err(SLOT);
    }
    for k in 0..e.write_count {
        let w = route_at(t.clause5, e, e.read_count + k)?;
        let tail = c.t_scaled_for(e.index, 1, k)?.map_or(0, |x| x.offset_per_t);
        let key = (w.region_id, w.region_offset, tail);
        if prev_write.is_some_and(|v| key <= v) {
            return Err(SLOT);
        }
        prev_write = Some(key);
    }
    for i in 0..c.prompt_switch_count() {
        let ps = c.prompt_switch(i)?;
        if ps.entry == e.index
            && (ps.ordinal >= e.read_count || route_at(t.clause5, e, ps.ordinal)?.flags & 1 == 0)
        {
            return Err(SLOT);
        }
    }
    Ok(())
}

fn position_geometry(c: &Clause12<'_>, id: u16) -> Result<(u64, u32), u32> {
    Ok(c.region_position(id)?
        .map_or((0, 0), |r| (r.stride, r.ring)))
}
fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Checks layout-dependent PT1 seal rules for a single entry. The runtime can
/// call this incrementally at seal: work and stack are bounded by that entry's
/// read/write count. Global last-writer and overlap checks are in
/// `seal_global_host`, because the current account format has no persistent
/// writer index or position-class checkpoint for incremental on-chain sealing.
pub fn seal_entry(
    t: &Template<'_>,
    c: &Clause12<'_>,
    ctx: &SealContext<'_>,
    e: TemplateEntry,
) -> Result<(), u32> {
    let mut class3 = 0u32;
    let mut prev_read: Option<(u16, u64, u64, u16)> = None;
    let mut prev_write: Option<(u16, u64, u64)> = None;
    for ordinal in 0..e.read_count as u32 + e.write_count as u32 {
        let direction = if ordinal < e.read_count as u32 { 0 } else { 1 };
        let k = if direction == 0 {
            ordinal as u16
        } else {
            (ordinal - e.read_count as u32) as u16
        };
        let r = route_at(t.clause5, e, ordinal as u16)?;
        let reg = ctx.region(r.region_id)?;
        if r.direction != direction
            || r.read_class > 3
            || r.flags & !3 != 0
            || (r.byte_length == 0 && r.flags & 2 == 0)
            || (direction == 1 && r.read_class != 0)
        {
            return Err(MALFORMED);
        }
        let scaled = c.t_scaled_for(e.index, direction, k)?;
        if (r.flags & 2 != 0) != scaled.is_some() {
            return Err(MALFORMED);
        }
        let tail = scaled.map_or(0, |x| x.offset_per_t);
        if direction == 0 {
            let key = (r.region_id, r.region_offset, tail, r.producer_delta);
            if prev_read.is_some_and(|v| key <= v) {
                return Err(SLOT);
            }
            prev_read = Some(key);
            let named = r.producer_entry != NO_PRODUCER;
            if (!named && r.producer_delta != 0)
                || (named && r.producer_delta == 0 && r.producer_entry >= e.index)
                || r.producer_delta > t.max_producer_delta
            {
                return Err(SLOT);
            }
            if named && r.read_class == 0 {
                matching_write(t, c, e.index, k, r)?;
            }
            if r.read_class == 3 {
                if named || r.producer_delta != 0 || r.flags != 0 {
                    return Err(SLOT);
                }
                let d = c.range_for(e.index, class3)?.ok_or(SLOT)?;
                class3 += 1;
                let slot = ctx.family(d.family).ok_or(MALFORMED)?;
                if slot.region_id != r.region_id {
                    return Err(SLOT);
                }
                let (stride, ring) = position_geometry(c, r.region_id)?;
                if stride == 0 || ring != 0 || r.byte_length as u64 != stride {
                    return Err(SLOT);
                }
                let producer = t.entry(slot.template_entry).map_err(|_| SLOT)?;
                let w = route_at(
                    t.clause5,
                    producer,
                    producer.read_count + slot.write_ordinal,
                )?;
                if r.region_offset != w.region_offset
                    || slot.template_entry >= e.index
                    || w.region_id != r.region_id
                    || w.region_offset != 0
                    || w.byte_length as u64 != stride
                {
                    return Err(SLOT);
                }
                if ctx.wave(slot.template_entry)? >= ctx.wave(e.index)? {
                    return Err(SLOT);
                }
                let tmax = if d.first_rule == 0 {
                    t.position_count
                } else {
                    t.position_count.min(d.window.saturating_add(1))
                };
                if (tmax as u64).checked_mul(stride).ok_or(OVERFLOW)? > u32::MAX as u64 {
                    return Err(OVERFLOW);
                }
                if ctx.attention_forms.contains(&e.kernel_index) && tmax > 35 {
                    return Err(587);
                }
                let cover = if d.first_rule == 0 {
                    2 * c.range_tree_height as u32
                } else {
                    2 * (32 - d.window.leading_zeros()) + 2 * c.range_tree_height as u32
                };
                if cover > c.max_cover_refs as u32 + c.max_auth_refs as u32 {
                    return Err(587);
                }
                if let Some(cost) = ctx.envelope_closure_cost {
                    if cover > *cost.get(e.index as usize).ok_or(587u32)? {
                        return Err(587);
                    }
                }
            } else if (r.read_class == 1 || r.read_class == 2) && named {
                return Err(SLOT);
            }
            if r.flags & 1 != 0 {
                if r.read_class != 0
                    || !named
                    || r.producer_delta == 0
                    || c.prompt_for(e.index, k)?.is_none()
                {
                    return Err(SLOT);
                }
            }
            if r.producer_delta > 0 {
                let (stride, ring) = position_geometry(c, r.region_id)?;
                if stride > 0 && ring == 0 || (r.flags & 1 == 0 && reg.init_kind != 0) {
                    return Err(SLOT);
                }
            }
            if let Some(mask_rows) = ctx.kernel_read_lifetime_masks {
                let mask = mask_rows
                    .iter()
                    .find(|(form, _)| *form == e.kernel_index)
                    .map_or(0, |(_, m)| *m);
                if reg.lifetime >= 64 || (mask >> reg.lifetime) & 1 == 0 {
                    return Err(SLOT);
                }
            }
        } else {
            let key = (r.region_id, r.region_offset, tail);
            if prev_write.is_some_and(|v| key <= v) {
                return Err(SLOT);
            }
            prev_write = Some(key);
            if r.producer_entry != e.index || r.producer_delta != 0 || r.flags & 1 != 0 {
                return Err(SLOT);
            }
        }
        let (stride, ring) = position_geometry(c, r.region_id)?;
        if ring == 1 || (ring > 0 && stride == 0) {
            return Err(SLOT);
        }
        let slots = if stride == 0 {
            1
        } else if ring == 0 {
            t.position_count as u64
        } else {
            ring as u64
        };
        if slots.checked_mul(stride).ok_or(OVERFLOW)? > reg.byte_length && stride != 0 {
            return Err(SLOT);
        }
        if let Some(x) = scaled {
            if stride != 0
                || r.byte_length != 0
                || (direction == 0 && (r.producer_delta != 0 || r.read_class != 0))
            {
                return Err(SLOT);
            }
            if r.region_offset
                .checked_add(
                    (t.position_count as u64)
                        .checked_mul(
                            x.offset_per_t
                                .checked_add(x.length_per_t as u64)
                                .ok_or(OVERFLOW)?,
                        )
                        .ok_or(OVERFLOW)?,
                )
                .ok_or(OVERFLOW)?
                > reg.byte_length
            {
                return Err(SLOT);
            }
            if t.position_count.checked_mul(x.length_per_t).is_none() {
                return Err(OVERFLOW);
            }
        } else if r.read_class != 3 {
            let end = r
                .region_offset
                .checked_add(r.byte_length as u64)
                .ok_or(OVERFLOW)?;
            if end > if stride == 0 { reg.byte_length } else { stride } {
                return Err(SLOT);
            }
        }
    }
    if c.range_for(e.index, class3)?.is_some() {
        return Err(SLOT);
    }
    for i in 0..c.prompt_switch_count() {
        let ps = c.prompt_switch(i)?;
        if ps.entry != e.index {
            continue;
        }
        if ps.ordinal >= e.read_count || route_at(t.clause5, e, ps.ordinal)?.flags & 1 == 0 {
            return Err(SLOT);
        }
        let rec = route_at(t.clause5, e, ps.ordinal)?;
        let reg = ctx.region(ps.region_id)?;
        if reg.lifetime != 5 || rec.producer_delta as u32 > t.prompt_positions {
            return Err(SLOT);
        }
        let end = ps
            .offset
            .checked_add(
                (t.prompt_positions as u64 - 1)
                    .checked_mul(ps.stride as u64)
                    .ok_or(OVERFLOW)?,
            )
            .and_then(|v| v.checked_add(rec.byte_length as u64))
            .ok_or(OVERFLOW)?;
        if end > reg.byte_length {
            return Err(SLOT);
        }
    }
    for i in 0..c.patch_count() {
        let patch = c.patch(i)?;
        if patch.entry != e.index {
            continue;
        }
        if !ctx
            .patch_schema
            .contains(&(e.kernel_index, patch.offset, patch.width, patch.rule))
        {
            return Err(SLOT);
        }
        if let Some(lengths) = ctx.payload_lengths {
            if patch.offset as usize + patch.width as usize
                > *lengths.get(e.index as usize).ok_or(MALFORMED)? as usize
            {
                return Err(MALFORMED);
            }
        }
        let value = match patch.rule {
            0 => t.position_count as u64,
            1 => t.position_count as u64 - 1,
            2 => patch
                .base
                .checked_add(
                    (t.position_count as u64 - 1)
                        .checked_mul(patch.stride)
                        .ok_or(OVERFLOW)?,
                )
                .ok_or(OVERFLOW)?,
            _ => return Err(MALFORMED),
        };
        if patch.width < 8 && value >= (1u64 << (8 * patch.width)) {
            return Err(OVERFLOW);
        }
        if let Some(bounds) = ctx.patch_census_bounds {
            let max = bounds
                .iter()
                .find(|(te, off, _)| *te == e.index && *off == patch.offset)
                .ok_or(587u32)?
                .2;
            if value > max {
                return Err(587);
            }
        }
    }
    let mut required_max_t = 0u32;
    for j in 0..class3 {
        let d = c.range_for(e.index, j)?.ok_or(SLOT)?;
        required_max_t = required_max_t.max(if d.first_rule == 0 {
            t.position_count
        } else {
            t.position_count.min(d.window.saturating_add(1))
        });
    }
    if (0..e.read_count as u32 + e.write_count as u32)
        .any(|i| route_at(t.clause5, e, i as u16).is_ok_and(|r| r.flags & 2 != 0))
    {
        required_max_t = t.position_count;
    }
    for i in 0..c.patch_count() {
        let p = c.patch(i)?;
        if p.entry == e.index && p.rule == 0 {
            required_max_t = t.position_count;
        }
    }
    if required_max_t > 0 {
        if let Some(maxima) = ctx.envelope_max_t {
            if *maxima.get(e.index as usize).ok_or(587u32)? < required_max_t {
                return Err(587);
            }
        }
    }
    Ok(())
}

/// Host preflight of cross-entry PT1 rules. It uses heap-backed writer spans
/// and position-class vectors, so it is not called by the SBF seal handler.
/// A chain seal must enforce the same result through an incremental writer
/// index/checkpoint before accepting a PT1 descriptor.
#[derive(Clone, Copy)]
struct Writer {
    region: u16,
    lo: u64,
    hi: u64,
    entry: u32,
}

fn writer_hits(
    writers: &[Writer],
    prefix_max: &[u64],
    region: u16,
    lo: u64,
    hi: u64,
) -> alloc::vec::Vec<u32> {
    use alloc::vec::Vec;
    let mut left = 0;
    let mut right = writers.len();
    while left < right {
        let mid = left + (right - left) / 2;
        if (writers[mid].region, writers[mid].lo) < (region, hi) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    let mut out = Vec::new();
    while left > 0 {
        left -= 1;
        let w = writers[left];
        if w.region != region || prefix_max[left] <= lo {
            break;
        }
        if w.lo < hi && lo < w.hi {
            out.push(w.entry);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn seal_global_host(
    t: &Template<'_>,
    c: Clause12<'_>,
    ctx: &SealContext<'_>,
) -> Result<(), u32> {
    use alloc::vec::Vec;
    seal_layout(t, &c, ctx)?;
    for i in 0..t.entries_per_position {
        seal_route_rules(t, &c, t.entry(i)?)?;
    }
    let mut writers = Vec::<Writer>::new();
    let mut band_regions = Vec::<(u16, u64)>::new();
    let mut plain_regions = Vec::<u16>::new();
    for i in 0..t.entries_per_position {
        let e = t.entry(i)?;
        seal_entry(t, &c, ctx, e)?;
        for j in 0..e.read_count as u32 + e.write_count as u32 {
            let direction = if j < e.read_count as u32 { 0 } else { 1 };
            let ordinal = if direction == 0 {
                j as u16
            } else {
                (j - e.read_count as u32) as u16
            };
            let r = route_at(t.clause5, e, j as u16)?;
            let span = if let Some(x) = c.t_scaled_for(i, direction, ordinal)? {
                if band_regions
                    .iter()
                    .any(|(id, origin)| *id == r.region_id && *origin != r.region_offset)
                {
                    return Err(SLOT);
                }
                band_regions.push((r.region_id, r.region_offset));
                (
                    x.offset_per_t,
                    x.offset_per_t
                        .checked_add(x.length_per_t as u64)
                        .ok_or(OVERFLOW)?,
                )
            } else {
                if r.read_class != 3 {
                    plain_regions.push(r.region_id);
                }
                (
                    r.region_offset,
                    r.region_offset
                        .checked_add(r.byte_length as u64)
                        .ok_or(OVERFLOW)?,
                )
            };
            if direction == 1 {
                writers.push(Writer {
                    region: r.region_id,
                    lo: span.0,
                    hi: span.1,
                    entry: i,
                });
            }
        }
    }
    for (region, _) in &band_regions {
        if plain_regions.contains(region) {
            return Err(SLOT);
        }
    }
    writers.sort_unstable_by_key(|w| (w.region, w.lo, w.hi, w.entry));
    let mut prefix_max: Vec<u64> = Vec::with_capacity(writers.len());
    for (i, w) in writers.iter().enumerate() {
        prefix_max.push(if i > 0 && writers[i - 1].region == w.region {
            prefix_max[i - 1].max(w.hi)
        } else {
            w.hi
        });
    }
    if c.t_scaled_count() > 0 {
        for j in 0..c.range_count() {
            if c.range(j)?.first_rule == 1 {
                return Err(SLOT);
            }
        }
    }
    for i in 0..c.t_scaled_count() {
        let x = c.t_scaled(i)?;
        if x.direction != 0 {
            continue;
        }
        let e = t.entry(x.entry)?;
        let r = route_at(t.clause5, e, x.ordinal)?;
        let lo = x.offset_per_t;
        let hi = lo.checked_add(x.length_per_t as u64).ok_or(OVERFLOW)?;
        if !writers
            .iter()
            .any(|w| w.region == r.region_id && w.lo == lo && w.hi == hi)
        {
            return Err(SLOT);
        }
    }
    let band_writers: Vec<_> = writers
        .iter()
        .filter(|w| band_regions.iter().any(|(id, _)| *id == w.region))
        .collect();
    for i in 0..band_writers.len() {
        for j in i + 1..band_writers.len() {
            let a = band_writers[i];
            let b = band_writers[j];
            if a.region == b.region && a.lo < b.hi && b.lo < a.hi {
                return Err(SLOT);
            }
        }
    }
    // Global writer sets are template spans. For a T_SCALED route these are
    // coefficient intervals, as in Python's _WriterIndex.
    for i in 0..t.entries_per_position {
        let e = t.entry(i)?;
        if e.read_count >= 2 || e.write_count >= 2 {
            let mut ring_lcm = 1u32;
            for j in 0..e.read_count as u32 + e.write_count as u32 {
                let r = route_at(t.clause5, e, j as u16)?;
                let ring = position_geometry(&c, r.region_id)?.1;
                if ring > 0 {
                    ring_lcm = (ring_lcm / gcd(ring_lcm, ring))
                        .checked_mul(ring)
                        .ok_or(SLOT)?;
                }
            }
            if t.max_producer_delta as u32 + ring_lcm > 1024 {
                return Err(SLOT);
            }
        }
        for k in 0..e.read_count {
            let r = route_at(t.clause5, e, k)?;
            if r.read_class != 0 {
                continue;
            }
            let span = if let Some(x) = c.t_scaled_for(i, 0, k)? {
                (
                    x.offset_per_t,
                    x.offset_per_t
                        .checked_add(x.length_per_t as u64)
                        .ok_or(OVERFLOW)?,
                )
            } else {
                (
                    r.region_offset,
                    r.region_offset
                        .checked_add(r.byte_length as u64)
                        .ok_or(OVERFLOW)?,
                )
            };
            let hits = writer_hits(&writers, &prefix_max, r.region_id, span.0, span.1);
            let named = r.producer_entry != NO_PRODUCER;
            let (stride, ring) = position_geometry(&c, r.region_id)?;
            let d = r.producer_delta;
            let tw = r.producer_entry;
            if !named {
                if !hits.is_empty() {
                    return Err(SLOT);
                }
            } else if stride == 0 {
                if d == 0 {
                    let between: Vec<_> = hits
                        .iter()
                        .copied()
                        .filter(|w| tw <= *w && *w < i)
                        .collect();
                    if between != [tw] {
                        return Err(SLOT);
                    }
                    if ctx.wave(tw)? >= ctx.wave(i)? {
                        return Err(SLOT);
                    }
                    // PT1 §14: t's own in-place write is excluded. Every
                    // *other* writer between t_w and t must be wave-separated.
                    for w in hits.iter().copied().filter(|w| *w != tw && *w != i) {
                        if !(ctx.wave(w)? < ctx.wave(tw)? || ctx.wave(w)? > ctx.wave(i)?) {
                            return Err(SLOT);
                        }
                    }
                } else if d == 1 {
                    if tw < i || hits != [tw] || (tw != i && ctx.wave(i)? >= ctx.wave(tw)?) {
                        return Err(SLOT);
                    }
                } else {
                    return Err(SLOT);
                }
            } else if ring >= 2 {
                if !((d >= 1 && (d as u32) < ring) || (d == 0 && tw < i)) || hits != [tw] {
                    return Err(SLOT);
                }
                if d == 0 && ctx.wave(tw)? >= ctx.wave(i)? {
                    return Err(SLOT);
                }
            } else if d != 0 || hits != [tw] || ctx.wave(tw)? >= ctx.wave(i)? {
                return Err(SLOT);
            }
        }
        // Position-class overlap, including supplied and range reads. The
        // finite first-D+R/last reduction is omitted here: host checks every
        // actual position, which is stronger and simpler for small documents.
        for p in 0..t.position_count {
            let inst = t.instantiate_with(c, i, p)?;
            let mut read_spans = Vec::with_capacity(e.read_count as usize);
            let mut write_spans = Vec::with_capacity(e.write_count as usize);
            for j in 0..inst.route_count() {
                let r = inst.route(j as u16)?;
                let end = r
                    .effective_offset
                    .checked_add(r.byte_length as u64)
                    .ok_or(OVERFLOW)?;
                if r.direction == 0 {
                    read_spans.push((r.region_id, r.effective_offset, end));
                } else {
                    write_spans.push((r.region_id, r.effective_offset, end));
                }
            }
            for spans in [&mut read_spans, &mut write_spans] {
                spans.sort_unstable();
                if spans
                    .windows(2)
                    .any(|w| w[0].0 == w[1].0 && w[1].1 < w[0].2)
                {
                    return Err(SLOT);
                }
            }
        }
    }
    // A range family slot has a single writer, and the writer runs before its
    // consumer at every position. The declaration is bound by its family ID.
    for slot in ctx.family_slots {
        let producer = t.entry(slot.template_entry)?;
        let w = route_at(
            t.clause5,
            producer,
            producer.read_count + slot.write_ordinal,
        )?;
        let hits = writer_hits(
            &writers,
            &prefix_max,
            slot.region_id,
            w.region_offset,
            w.region_offset + w.byte_length as u64,
        );
        if hits != [slot.template_entry] {
            return Err(SLOT);
        }
        for j in 0..c.range_count() {
            let d = c.range(j)?;
            if d.family == slot.family && ctx.wave(slot.template_entry)? >= ctx.wave(d.entry)? {
                return Err(SLOT);
            }
        }
    }
    Ok(())
}

extern crate alloc;

#[cfg(test)]
mod captured_coordinate_tests {
    use super::*;

    #[test]
    fn captured_first_document_coordinates() {
        let Ok(root) = std::env::var("BASANOS_PT1_TEMPLATE_ROOT") else {
            return;
        };
        let routes = std::fs::read(format!("{root}/clause5-routes-v2.bin")).unwrap();
        let geometry = std::fs::read(format!("{root}/clause12-closure-geometry-v2.bin")).unwrap();
        let n = decode_clause5(&routes).unwrap();
        let c = decode_clause12_v2(&geometry).unwrap();
        assert_eq!(n, c.entries_per_position);
        let t = Template {
            clause5: &routes,
            clause12: &geometry,
            position_count: c.position_count,
            prompt_positions: c.prompt_positions,
            max_producer_delta: c.max_producer_delta,
            entries_per_position: n,
            leaf_storage_mode: c.leaf_storage_mode,
        };
        // Coordinates come from the retained position-0 runner facts.
        assert_eq!(
            t.coordinate(0).unwrap(),
            EntryCoordinate {
                segment: 0,
                local: 0,
                operation_ordinal: 0
            }
        );
        assert_eq!(
            t.coordinate(2574).unwrap(),
            EntryCoordinate {
                segment: 4,
                local: 165,
                operation_ordinal: 85
            }
        );
        assert_eq!(t.entry(2574).unwrap().kernel_index, 6);
        assert_eq!(
            t.coordinate(28037).unwrap(),
            EntryCoordinate {
                segment: 33,
                local: 3242,
                operation_ordinal: 804
            }
        );
        assert_eq!(t.coordinate(n), Err(MALFORMED));
    }
}

#[cfg(test)]
mod pxr1_tests {
    use super::*;

    fn unhex(raw: &str) -> Vec<u8> {
        raw.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("bad hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn row(index: u32, start: u32) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&index.to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[12..16].copy_from_slice(&start.to_le_bytes());
        out
    }

    fn write(offset: u64, length: u32, producer: u32) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..2].copy_from_slice(&7u16.to_le_bytes());
        out[2] = 1;
        out[4..12].copy_from_slice(&offset.to_le_bytes());
        out[12..16].copy_from_slice(&length.to_le_bytes());
        out[16..20].copy_from_slice(&producer.to_le_bytes());
        out
    }

    fn fixture() -> Vec<u8> {
        let writes = [write(0, 16, 0), write(32, 8, 1)];
        let leaves = [
            hash(&[
                ROUTE_DOMAIN,
                &0u32.to_le_bytes(),
                &1u16.to_le_bytes(),
                &0u16.to_le_bytes(),
                &1u16.to_le_bytes(),
                &writes[0],
            ]),
            hash(&[
                ROUTE_DOMAIN,
                &1u32.to_le_bytes(),
                &1u16.to_le_bytes(),
                &0u16.to_le_bytes(),
                &1u16.to_le_bytes(),
                &writes[1],
            ]),
        ];
        let root = node(&leaves[0], &leaves[1]);
        let mut out = vec![0u8; 160];
        out[0..4].copy_from_slice(&2u32.to_le_bytes());
        out[4..8].copy_from_slice(&2u32.to_le_bytes());
        out[8..40].copy_from_slice(&root);
        out[40..72].copy_from_slice(&hash(&[ROUTE_DOMAIN]));
        out[72..76].copy_from_slice(&160u32.to_le_bytes());
        out[76..78].copy_from_slice(&1u16.to_le_bytes());
        out[78..80].copy_from_slice(&1u16.to_le_bytes());
        out[80..96].copy_from_slice(&row(0, 0));
        out[96..112].copy_from_slice(&row(1, 1));
        out[112..136].copy_from_slice(&writes[0]);
        out[136..160].copy_from_slice(&writes[1]);
        out.extend(unhex(concat!(
            "5058523101002000070008000300000000000000020000002000000040000000",
            "0000000002000000000000000000000000000000000000001000000000000000",
            "0200000001000000010000000000000020000000000000000800000000000000"
        )));
        out
    }

    #[test]
    fn pxr1_clause5_extension_is_v4_only_and_matches_python_golden() {
        let routes = fixture();
        assert_eq!(route_header(&routes), Err(MALFORMED));
        assert_eq!(decode_clause5(&routes), Err(MALFORMED));
        assert_eq!(decode_clause5_v4(&routes), Ok(2));
        let (_, _, pxr) = route_header_v4(&routes).unwrap();
        let pxr = pxr.unwrap();
        assert_eq!(pxr.region_id, 7);
        assert_eq!(pxr.token_count, 3);
        assert_eq!(pxr.row_count, 2);
        assert_eq!(
            pxr.find(2),
            Ok((
                Pxr1Row {
                    first_token: 2,
                    token_count: 1,
                    producer_entry: 1,
                    producer_write_ordinal: 0,
                    region_offset: 32,
                    byte_length: 8
                },
                0,
            ))
        );
        assert_eq!(route_header_v4(&routes).unwrap().0, 2);
    }

    #[test]
    fn pxr1_rejects_reserved_bits_and_write_ordinal_255() {
        let routes = fixture();
        let mut malformed = routes.clone();
        malformed[160 + 12..160 + 14].copy_from_slice(&255u16.to_le_bytes());
        assert_eq!(route_header_v4(&malformed), Err(MALFORMED));
        let mut reserved = routes;
        reserved[160 + 14] = 1;
        assert_eq!(route_header_v4(&reserved), Err(MALFORMED));
    }
}
