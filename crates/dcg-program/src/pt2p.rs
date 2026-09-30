//! PT2P: position-parametric windowed-attention route program (PT1 spec §17,
//! revision 11, PROPOSED). A faithful port of `basanos.dcg.pt2_parametric`.
//!
//! The document commits the rev7 base triple (clause 5, a PTG4 geometry
//! envelope with no window rows and no ESG4 tail, and the payload table) once,
//! plus the `PWR1` window program. Any entry `(p, t)` is derived in closed
//! form. All views borrow their input; the only heap use is one row per base
//! segment and per program layer (never proportional to entries), so the
//! same code runs natively and inside SBF.
//!
//! Every index is computed in checked `u64` and refused with 598 on overflow
//! or on a value that does not fit its wire width.
use crate::position_template::{
    self as pt, Clause12, InstantiatedRoute, Route, NO_PRODUCER, OVERFLOW, PT2_MANIFEST,
    PT2_PRODUCER, PT2_ROUTE_SET,
};

pub const PROGRAM_MAGIC: &[u8; 4] = b"PWR1";
pub const PROGRAM_DOMAIN: &[u8] = b"basanos/dcg-pt2-parametric-window-program/1";
pub const CLAUSE12_V4_MAGIC: &[u8; 4] = b"PT2P";
pub const DESCRIPTOR_DOMAIN: &[u8] = b"basanos/dcg-pt2p-first-document-draft-descriptor/1";
pub const SEGMENT_DOMAIN: &[u8] = b"basanos/dcg-hclosure-segment-table/2";
pub const OPERATION_DOMAIN: &[u8] = b"basanos/dcg-hclosure-operation-table/2";
pub const PROGRAM_HEADER: usize = 136;
pub const LAYER_ROW: usize = 24;
pub const CLAUSE12_V4_BYTES: usize = 43;
pub const GENERATED_PAYLOAD: usize = 44;

pub const FORM_27W: u16 = 40;
pub const FORM_28E: u16 = 41;
pub const FORM_28N: u16 = 42;
pub const FORM_29W: u16 = 43;
pub const FORM_29C: u16 = 44;
pub const FORM_28M: u16 = 45;
pub const FORM_28S: u16 = 46;
const OLD_SCORES: u16 = 27;
const OLD_SOFTMAX: u16 = 28;
const OLD_PV: u16 = 29;
const READ_WITNESSED: u8 = 0;
const READ_SUPPLIED: u8 = 2;
const READ_CLOSURE_ROOT: u8 = 3;
/// `fanin >= 2` and `n < 2^32` bound every tree to 32 levels.
const MAX_LEVELS: usize = 32;

fn u16_at(b: &[u8], i: usize, code: u32) -> Result<u16, u32> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2).ok_or(code)?.try_into().unwrap(),
    ))
}
fn u32_at(b: &[u8], i: usize, code: u32) -> Result<u32, u32> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4).ok_or(code)?.try_into().unwrap(),
    ))
}
fn add(a: u64, b: u64) -> Result<u64, u32> {
    a.checked_add(b).ok_or(OVERFLOW)
}
fn sub(a: u64, b: u64) -> Result<u64, u32> {
    a.checked_sub(b).ok_or(OVERFLOW)
}
fn mul(a: u64, b: u64) -> Result<u64, u32> {
    a.checked_mul(b).ok_or(OVERFLOW)
}
fn to_u32(x: u64) -> Result<u32, u32> {
    u32::try_from(x).map_err(|_| OVERFLOW)
}
fn to_u16(x: u64) -> Result<u16, u32> {
    u16::try_from(x).map_err(|_| OVERFLOW)
}

// ------------------------------------------------------------------ PWR1

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerRule {
    pub segment_id: u16,
    pub scores_op: u16,
    pub softmax_op: u16,
    pub pv_op: u16,
    pub k_family: u16,
    pub v_family: u16,
    pub lm_region: u16,
    pub se_region: u16,
    pub nu_region: u16,
}

/// The committed `PWR1` program (136 + 24·L bytes).
#[derive(Clone, Copy, Debug)]
pub struct Program<'a> {
    pub raw: &'a [u8],
    pub window_start: u32,
    pub window: u64,
    pub heads: u64,
    pub kv_heads: u64,
    pub head_dim: u64,
    pub fanin: u64,
    pub score_heads: u64,
    pub softmax_heads: u64,
    pub inv_sqrt: i64,
    pub lut_region: u16,
    pub layer_count: u32,
    pub lut_bytes: u32,
}

impl<'a> Program<'a> {
    /// Canonical decode: magic, version 1, reserved bytes zero, `pv_heads = 1`,
    /// exact EOF and zero layer-row reserved words. Anything else is 602.
    pub fn decode(raw: &'a [u8]) -> Result<Self, u32> {
        let e = PT2_MANIFEST;
        if raw.len() < PROGRAM_HEADER
            || &raw[..4] != PROGRAM_MAGIC
            || raw[4] != 1
            || raw[5] != 0
            || raw[22] != 1
            || raw[23] != 0
        {
            return Err(e);
        }
        let count = u16_at(raw, 34, e)? as usize;
        if raw.len() != PROGRAM_HEADER + count * LAYER_ROW {
            return Err(e);
        }
        for i in 0..count {
            let at = PROGRAM_HEADER + i * LAYER_ROW;
            if raw[at + 18..at + 24] != [0; 6] {
                return Err(e);
            }
        }
        Ok(Self {
            raw,
            window_start: u32_at(raw, 6, e)?,
            window: u16_at(raw, 10, e)? as u64,
            heads: u16_at(raw, 12, e)? as u64,
            kv_heads: u16_at(raw, 14, e)? as u64,
            head_dim: u16_at(raw, 16, e)? as u64,
            fanin: u16_at(raw, 18, e)? as u64,
            score_heads: raw[20] as u64,
            softmax_heads: raw[21] as u64,
            inv_sqrt: i64::from_le_bytes(raw[24..32].try_into().unwrap()),
            lut_region: u16_at(raw, 32, e)?,
            layer_count: count as u32,
            lut_bytes: u32_at(raw, 36, e)?,
        })
    }

    pub fn base_digest(&self, kind: usize) -> &'a [u8] {
        &self.raw[40 + 32 * kind..72 + 32 * kind]
    }

    pub fn layer(&self, i: u32) -> Result<LayerRule, u32> {
        if i >= self.layer_count {
            return Err(PT2_MANIFEST);
        }
        let at = PROGRAM_HEADER + i as usize * LAYER_ROW;
        let f = |k: usize| u16_at(self.raw, at + 2 * k, PT2_MANIFEST);
        Ok(LayerRule {
            segment_id: f(0)?,
            scores_op: f(1)?,
            softmax_op: f(2)?,
            pv_op: f(3)?,
            k_family: f(4)?,
            v_family: f(5)?,
            lm_region: f(6)?,
            se_region: f(7)?,
            nu_region: f(8)?,
        })
    }

    /// `SHA256("basanos/dcg-pt2-parametric-window-program/1" | PWR1)`.
    pub fn digest(&self) -> [u8; 32] {
        crate::hash::sha256(&[PROGRAM_DOMAIN, self.raw])
    }
}

/// Clause-12 version 4: `4 | "PT2P" | position_count:u32 | segment_count:u16 | program_sha256`.
pub fn encode_clause12_v4(
    position_count: u32,
    segment_count: u16,
    program_sha256: &[u8; 32],
) -> [u8; 43] {
    let mut out = [0u8; 43];
    out[0] = 4;
    out[1..5].copy_from_slice(CLAUSE12_V4_MAGIC);
    out[5..9].copy_from_slice(&position_count.to_le_bytes());
    out[9..11].copy_from_slice(&segment_count.to_le_bytes());
    out[11..43].copy_from_slice(program_sha256);
    out
}

/// Decode clause-12 v4; with `program` the digest must match it. 602 otherwise.
pub fn decode_clause12_v4(
    raw: &[u8],
    program: Option<&Program<'_>>,
) -> Result<(u32, u16, [u8; 32]), u32> {
    if raw.len() != CLAUSE12_V4_BYTES || raw[0] != 4 || &raw[1..5] != CLAUSE12_V4_MAGIC {
        return Err(PT2_MANIFEST);
    }
    let positions = u32_at(raw, 5, PT2_MANIFEST)?;
    let segments = u16_at(raw, 9, PT2_MANIFEST)?;
    let digest: [u8; 32] = raw[11..43].try_into().unwrap();
    if positions == 0 || segments == 0 || digest == [0; 32] {
        return Err(PT2_MANIFEST);
    }
    if let Some(g) = program {
        if g.digest() != digest {
            return Err(PT2_MANIFEST);
        }
    }
    Ok((positions, segments, digest))
}

/// `SHA256(descriptor domain | clause12_v4[43] | definition_sha256[32])`.
pub fn descriptor_digest(clause12_v4: &[u8; 43], definition_sha256: &[u8; 32]) -> [u8; 32] {
    crate::hash::sha256(&[DESCRIPTOR_DOMAIN, clause12_v4, definition_sha256])
}

/// The clause-12 v2 base inside a PT2P base geometry: a PTG4 envelope with no
/// window rows and an empty ESG4 tail (603 otherwise). Bounded header check;
/// the v2 bytes are validated by the PT1S seal.
pub fn ptg4_base(geometry: &[u8]) -> Result<&[u8], u32> {
    if geometry.len() < 17 || &geometry[..5] != b"\x04PTG4" {
        return Err(PT2_ROUTE_SET);
    }
    let base_len = u32_at(geometry, 5, PT2_ROUTE_SET)? as usize;
    if u32_at(geometry, 9, PT2_ROUTE_SET)? != 0
        || u32_at(geometry, 13, PT2_ROUTE_SET)? != 0
        || 17usize.checked_add(base_len) != Some(geometry.len())
    {
        return Err(PT2_ROUTE_SET);
    }
    Ok(&geometry[17..])
}

// ------------------------------------------------------------------ shapes

#[derive(Clone, Copy, Debug)]
pub struct Levels {
    w: [u32; MAX_LEVELS],
    pub len: usize,
}
impl Levels {
    /// Widths of the successive `fanin`-ary tree levels above `n` leaves.
    fn new(n: u64, fanin: u64, include_single: bool) -> Result<Self, u32> {
        let mut out = Levels {
            w: [0; MAX_LEVELS],
            len: 0,
        };
        if fanin < 2 || n == 0 {
            return Err(PT2_MANIFEST);
        }
        if n == 1 {
            if include_single {
                out.w[0] = 1;
                out.len = 1;
            }
            return Ok(out);
        }
        let mut n = n;
        while n > 1 {
            n = add(n, fanin - 1)? / fanin;
            if out.len == MAX_LEVELS {
                return Err(OVERFLOW);
            }
            out.w[out.len] = to_u32(n)?;
            out.len += 1;
        }
        Ok(out)
    }
    /// Widths of the `fanin`-ary levels above `n` leaves (`pt2_parametric.levels`).
    pub fn of(n: u64, fanin: u64, include_single: bool) -> Result<Self, u32> {
        Self::new(n, fanin, include_single)
    }
    pub fn get(&self, i: usize) -> u64 {
        self.w[i] as u64
    }
    pub fn prefix(&self, level: usize) -> u64 {
        self.w[..level.min(self.len)]
            .iter()
            .map(|&x| x as u64)
            .sum()
    }
    pub fn sum(&self) -> u64 {
        self.prefix(self.len)
    }
}

/// Closed-form position class `n = floor(p/W) + 1`.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub n: u64,
    pub red: Levels,
    pub comb: Levels,
    /// New entry counts of the (scores, softmax, attn_pv) operations.
    pub counts: [u64; 3],
}
impl Shape {
    fn slot(&self, levels: &Levels, level: usize, node: u64) -> Result<u64, u32> {
        add(add(self.n, levels.prefix(level))?, node)
    }
}

// ------------------------------------------------------------------ items

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Form {
    pub kind: u16,
    pub layer: u32,
    pub h0: u64,
    pub h1: u64,
    pub window: u64,
    pub level: u64,
    pub node: u64,
    pub fin: bool,
}

/// Entry `t` at `p`: a surviving base entry (by its OLD base index) or a
/// generated form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    Base(u32),
    Form(Form),
}

/// A located entry with its route counts. `base` is the old clause-5 row.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub position: u32,
    pub index: u32,
    pub item: Item,
    pub kernel_index: u16,
    pub read_count: u16,
    pub write_count: u16,
    base: Option<pt::TemplateEntry>,
}
impl Entry {
    pub fn route_count(&self) -> u32 {
        self.read_count as u32 + self.write_count as u32
    }
    pub fn old_index(&self) -> Option<u32> {
        match self.item {
            Item::Base(o) => Some(o),
            _ => None,
        }
    }
}

/// A §16.1 window binding of a generated class-3 read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowBind {
    pub family: u16,
    pub first: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug)]
struct SegInfo {
    base_start: u32,
    base_count: u32,
    ops_at: u32,
    nops: u16,
    layer: u32, // u32::MAX: not replaced
}

#[derive(Clone, Copy, Debug)]
struct LayerInfo {
    rule: LayerRule,
    seg: u32,
    ops: [u16; 3],
    op_start: [u32; 3], // global base index of each replaced op
    base_first: [u32; 3],
    base_count: [u32; 3],
    sc_region: u16,
    pr_region: u16,
    k_region: u16,
    v_region: u16,
}

/// The PT2P view over the base triple and a decoded program.
pub struct Pt2p<'a> {
    pub routes: &'a [u8],
    pub base_v2: &'a [u8],
    pub c: Clause12<'a>,
    pub payloads: &'a [u8],
    /// `n + 1` LE u32 payload row offsets (the PT1S seal index), if available.
    payload_index: Option<&'a [u8]>,
    pub g: Program<'a>,
    pub base_entries: u32,
    pub position_count: u32,
    pub segment_count: u16,
    segs: Vec<SegInfo>,
    layers: Vec<LayerInfo>,
}

impl<'a> Pt2p<'a> {
    /// Bind a base triple and a decoded program. Performs the bounded
    /// structural checks needed for closed-form arithmetic (602): parameter
    /// domain, layer rows naming distinct base segments and ordered in-range
    /// operations, and the regions of the replaced operations. The per-entry
    /// kind, class and family checks of §17.2 are `check_program`.
    pub fn new(
        routes: &'a [u8],
        geometry: &'a [u8],
        payloads: &'a [u8],
        payload_index: Option<&'a [u8]>,
        g: Program<'a>,
    ) -> Result<Self, u32> {
        let base_v2 = ptg4_base(geometry)?;
        let (c, _) = pt::clause12_layout(base_v2).map_err(|_| PT2_ROUTE_SET)?;
        // Revision 8 PT2P can bind the PXR1 extension. Revision 7 keeps its
        // original v3-only route parser and refuses every extension.
        let n = if cfg!(feature = "revision-8") {
            pt::route_header_v4_shallow(routes)
                .map_err(|_| PT2_ROUTE_SET)?
                .0
        } else {
            pt::route_header(routes).map_err(|_| PT2_ROUTE_SET)?.0
        };
        if n != c.entries_per_position {
            return Err(PT2_ROUTE_SET);
        }
        if let Some(index) = payload_index {
            if index.len() < 4 * (n as usize + 1) {
                return Err(PT2_ROUTE_SET);
            }
        }
        let h = g.heads;
        if !(g.window_start <= c.position_count
            && g.window >= 1
            && g.fanin >= 2
            && h >= 1
            && g.score_heads >= 1
            && g.softmax_heads >= 1
            && h % g.score_heads == 0
            && h % g.softmax_heads == 0
            && g.softmax_heads % g.score_heads == 0
            && g.kv_heads >= 1
            && h % g.kv_heads == 0
            && g.lut_bytes > 0
            && g.layer_count >= 1)
        {
            return Err(PT2_MANIFEST);
        }
        let nseg = c.segment_count as usize;
        let mut segs = Vec::with_capacity(nseg);
        let mut ops_at = 59usize.checked_add(nseg * 43).ok_or(OVERFLOW)?;
        let mut start = 0u32;
        for s in 0..nseg {
            let row = base_v2
                .get(59 + 43 * s..59 + 43 * (s + 1))
                .ok_or(PT2_ROUTE_SET)?;
            let nops = u16_at(row, 5, PT2_ROUTE_SET)?;
            let count = u32_at(row, 7, PT2_ROUTE_SET)?;
            segs.push(SegInfo {
                base_start: start,
                base_count: count,
                ops_at: to_u32(ops_at as u64)?,
                nops,
                layer: u32::MAX,
            });
            start = start.checked_add(count).ok_or(OVERFLOW)?;
            ops_at = ops_at.checked_add(12 * nops as usize).ok_or(OVERFLOW)?;
        }
        if start != n || ops_at > base_v2.len() {
            return Err(PT2_ROUTE_SET);
        }
        let mut p = Self {
            routes,
            base_v2,
            c,
            payloads,
            payload_index,
            g,
            base_entries: n,
            position_count: c.position_count,
            segment_count: c.segment_count,
            segs,
            layers: Vec::with_capacity(g.layer_count as usize),
        };
        for li in 0..g.layer_count {
            let rule = g.layer(li)?;
            let mut found = None;
            for s in 0..nseg {
                if u16_at(p.base_v2, 59 + 43 * s, PT2_ROUTE_SET)? == rule.segment_id {
                    found = Some(s);
                    break;
                }
            }
            let s = found.ok_or(PT2_MANIFEST)?;
            if p.segs[s].layer != u32::MAX {
                return Err(PT2_MANIFEST);
            }
            let ops = [rule.scores_op, rule.softmax_op, rule.pv_op];
            if !(ops[0] < ops[1] && ops[1] < ops[2] && ops[2] < p.segs[s].nops) {
                return Err(PT2_MANIFEST);
            }
            let mut info = LayerInfo {
                rule,
                seg: s as u32,
                ops,
                op_start: [0; 3],
                base_first: [0; 3],
                base_count: [0; 3],
                sc_region: 0,
                pr_region: 0,
                k_region: 0,
                v_region: 0,
            };
            for phase in 0..3 {
                let (_, _, first, count) = p.op(s, ops[phase] as usize)?;
                info.base_first[phase] = first;
                info.base_count[phase] = count;
                info.op_start[phase] = p.segs[s].base_start.checked_add(first).ok_or(OVERFLOW)?;
            }
            let scores0 = p.nth_kind(&info, 0, OLD_SCORES, 0)?.ok_or(PT2_MANIFEST)?;
            let softmax0 = p.nth_kind(&info, 1, OLD_SOFTMAX, 0)?.ok_or(PT2_MANIFEST)?;
            let pv0 = p.nth_kind(&info, 2, OLD_PV, 0)?.ok_or(PT2_MANIFEST)?;
            if scores0.read_count < 2
                || scores0.write_count < 1
                || softmax0.write_count < 1
                || pv0.read_count < 2
                || pv0.write_count < 1
            {
                return Err(PT2_MANIFEST);
            }
            info.sc_region = p.base_route(scores0, scores0.read_count)?.region_id;
            info.k_region = p.base_route(scores0, 1)?.region_id;
            info.pr_region = p.base_route(softmax0, softmax0.read_count)?.region_id;
            info.v_region = p.base_route(pv0, 1)?.region_id;
            p.segs[s].layer = li;
            p.layers.push(info);
        }
        Ok(p)
    }

    /// Base operation locator `(ordinal, local_op, first_local, count)`.
    fn op(&self, s: usize, k: usize) -> Result<(u16, u16, u32, u32), u32> {
        let at = self.segs[s].ops_at as usize + 12 * k;
        let row = self.base_v2.get(at..at + 12).ok_or(PT2_ROUTE_SET)?;
        Ok((
            u16_at(row, 0, PT2_ROUTE_SET)?,
            u16_at(row, 2, PT2_ROUTE_SET)?,
            u32_at(row, 4, PT2_ROUTE_SET)?,
            u32_at(row, 8, PT2_ROUTE_SET)?,
        ))
    }

    fn base_entry(&self, old: u32) -> Result<pt::TemplateEntry, u32> {
        if old >= self.base_entries {
            return Err(PT2_PRODUCER);
        }
        pt::entry_at(self.routes, old).map_err(|_| PT2_ROUTE_SET)
    }
    fn base_route(&self, e: pt::TemplateEntry, ordinal: u16) -> Result<Route, u32> {
        pt::route_at(self.routes, e, ordinal).map_err(|_| PT2_ROUTE_SET)
    }

    /// The `k`-th entry of kernel `kind` in replaced operation `phase`.
    fn nth_kind(
        &self,
        l: &LayerInfo,
        phase: usize,
        kind: u16,
        k: u64,
    ) -> Result<Option<pt::TemplateEntry>, u32> {
        let mut seen = 0u64;
        for i in 0..l.base_count[phase] {
            let e = self.base_entry(l.op_start[phase] + i)?;
            if e.kernel_index == kind {
                if seen == k {
                    return Ok(Some(e));
                }
                seen += 1;
            }
        }
        Ok(None)
    }

    /// §17.2 per-entry program checks against the base (602).
    pub fn check_program(&self) -> Result<(), u32> {
        let g = &self.g;
        let h = g.heads;
        let want = [h / g.score_heads, h / g.softmax_heads, h];
        for l in &self.layers {
            for (phase, kind) in [OLD_SCORES, OLD_SOFTMAX, OLD_PV].into_iter().enumerate() {
                let mut seen = 0u64;
                for i in 0..l.base_count[phase] {
                    let e = self.base_entry(l.op_start[phase] + i)?;
                    if e.kernel_index == kind {
                        seen += 1;
                        if phase == 0 {
                            if e.read_count < 1 {
                                return Err(PT2_MANIFEST);
                            }
                            let q = self.base_route(e, 0)?;
                            if q.producer_delta != 0 || q.read_class != READ_WITNESSED {
                                return Err(PT2_MANIFEST);
                            }
                        }
                    }
                }
                if seen != want[phase] {
                    return Err(PT2_MANIFEST);
                }
            }
            let scores0 = self.nth_kind(l, 0, OLD_SCORES, 0)?.ok_or(PT2_MANIFEST)?;
            let pv0 = self.nth_kind(l, 2, OLD_PV, 0)?.ok_or(PT2_MANIFEST)?;
            for (e, family, region) in [
                (scores0, l.rule.k_family, l.k_region),
                (pv0, l.rule.v_family, l.v_region),
            ] {
                let r = self.base_route(e, 1)?;
                // decls for this entry: exactly one row naming `family`.
                let first = self.c.range_for(e.index, 0).map_err(|_| PT2_MANIFEST)?;
                let second = self.c.range_for(e.index, 1).map_err(|_| PT2_MANIFEST)?;
                let stride = self
                    .c
                    .region_position(region)
                    .map_err(|_| PT2_MANIFEST)?
                    .map_or(0, |x| x.stride);
                if r.read_class != READ_CLOSURE_ROOT
                    || first.map(|d| d.family) != Some(family)
                    || second.is_some()
                    || stride == 0
                {
                    return Err(PT2_MANIFEST);
                }
            }
            let ids = [l.rule.lm_region, l.rule.se_region, l.rule.nu_region];
            if ids[0] == ids[1]
                || ids[0] == ids[2]
                || ids[1] == ids[2]
                || ids.contains(&g.lut_region)
            {
                return Err(PT2_MANIFEST);
            }
            for id in ids {
                if self
                    .c
                    .region_position(id)
                    .map_err(|_| PT2_MANIFEST)?
                    .is_some()
                {
                    return Err(PT2_MANIFEST);
                }
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- closed form

    pub fn n_of(&self, p: u32) -> u64 {
        p as u64 / self.g.window + 1
    }

    pub fn shape(&self, p: u32) -> Result<Option<Shape>, u32> {
        if p < self.g.window_start {
            return Ok(None);
        }
        let g = &self.g;
        let n = self.n_of(p);
        let red = Levels::new(n, g.fanin, false)?;
        let comb = Levels::new(n, g.fanin, true)?;
        let (r, c) = (red.sum(), comb.sum());
        let h = g.heads;
        let counts = [
            add(mul(h / g.score_heads, n)?, mul(h, r)?)?,
            add(mul(mul(2, h / g.softmax_heads)?, n)?, mul(h, r)?)?,
            add(mul(h, n)?, mul(h, c)?)?,
        ];
        Ok(Some(Shape {
            n,
            red,
            comb,
            counts,
        }))
    }

    fn layer_plus_minus(&self, shape: &Shape, l: &LayerInfo) -> (u64, u64) {
        let plus = shape.counts.iter().sum::<u64>();
        let minus = l.base_count.iter().map(|&x| x as u64).sum::<u64>();
        (plus, minus)
    }

    fn seg_new_count(&self, shape: &Shape, s: usize) -> Result<u64, u32> {
        let seg = &self.segs[s];
        if seg.layer == u32::MAX {
            return Ok(seg.base_count as u64);
        }
        let (plus, minus) = self.layer_plus_minus(shape, &self.layers[seg.layer as usize]);
        add(sub(seg.base_count as u64, minus)?, plus)
    }

    fn seg_new_start(&self, shape: &Shape, s: usize) -> Result<u64, u32> {
        let mut plus = 0u64;
        let mut minus = 0u64;
        for l in &self.layers {
            if (l.seg as usize) < s {
                let (a, b) = self.layer_plus_minus(shape, l);
                plus = add(plus, a)?;
                minus = add(minus, b)?;
            }
        }
        sub(add(self.segs[s].base_start as u64, plus)?, minus)
    }

    fn op_new_first(
        &self,
        shape: &Shape,
        l: &LayerInfo,
        k: usize,
        base_first: u32,
    ) -> Result<u64, u32> {
        let mut at = base_first as u64;
        for phase in 0..3 {
            if (l.ops[phase] as usize) < k {
                at = add(sub(at, l.base_count[phase] as u64)?, shape.counts[phase])?;
            }
        }
        Ok(at)
    }

    pub fn entry_count(&self, p: u32) -> Result<u32, u32> {
        match self.shape(p)? {
            None => Ok(self.base_entries),
            Some(shape) => {
                let mut total = self.base_entries as u64;
                for l in &self.layers {
                    let (a, b) = self.layer_plus_minus(&shape, l);
                    total = sub(add(total, a)?, b)?;
                }
                to_u32(total)
            }
        }
    }

    /// Per-position segment rows `(segment_id, entry_count)` in base order.
    pub fn segment_row(&self, p: u32, s: usize) -> Result<(u16, u32), u32> {
        let id = u16_at(self.base_v2, 59 + 43 * s, PT2_ROUTE_SET)?;
        match self.shape(p)? {
            None => Ok((id, self.segs[s].base_count)),
            Some(shape) => Ok((id, to_u32(self.seg_new_count(&shape, s)?)?)),
        }
    }

    /// The 43-byte segment descriptor of segment `s` at `p`.
    pub fn segment_descriptor(&self, p: u32, s: usize, out: &mut [u8; 43]) -> Result<(), u32> {
        let row = self
            .base_v2
            .get(59 + 43 * s..59 + 43 * (s + 1))
            .ok_or(PT2_ROUTE_SET)?;
        out.copy_from_slice(row);
        let shape = match self.shape(p)? {
            None => return Ok(()),
            Some(x) => x,
        };
        let seg = self.segs[s];
        if seg.layer == u32::MAX {
            return Ok(());
        }
        let l = &self.layers[seg.layer as usize];
        out[7..11].copy_from_slice(&to_u32(self.seg_new_count(&shape, s)?)?.to_le_bytes());
        let mut ops = Vec::with_capacity(12 * seg.nops as usize);
        for k in 0..seg.nops as usize {
            let (ordinal, local, first, count) = self.op(s, k)?;
            let (first, count) = self.op_new(&shape, l, k, first, count)?;
            ops.extend_from_slice(&ordinal.to_le_bytes());
            ops.extend_from_slice(&local.to_le_bytes());
            ops.extend_from_slice(&first.to_le_bytes());
            ops.extend_from_slice(&count.to_le_bytes());
        }
        let root =
            crate::hash::sha256(&[OPERATION_DOMAIN, &row[0..2], &seg.nops.to_le_bytes(), &ops]);
        out[11..43].copy_from_slice(&root);
        Ok(())
    }

    fn op_new(
        &self,
        shape: &Shape,
        l: &LayerInfo,
        k: usize,
        first: u32,
        count: u32,
    ) -> Result<(u32, u32), u32> {
        let count = match l.ops.iter().position(|&x| x as usize == k) {
            Some(phase) => shape.counts[phase],
            None => count as u64,
        };
        Ok((
            to_u32(self.op_new_first(shape, l, k, first)?)?,
            to_u32(count)?,
        ))
    }

    /// `SHA256(segment-table domain | u16 count | 43-byte descriptors)` at `p`,
    /// with per-position operation locators (Python `segment_table_root` of the
    /// geometry `ParametricPT2.geometry` would emit).
    pub fn segment_table_root(&self, p: u32) -> Result<[u8; 32], u32> {
        if self.shape(p)?.is_none() {
            return self
                .base_v2
                .get(19..51)
                .ok_or(PT2_ROUTE_SET)
                .map(|x| x.try_into().unwrap());
        }
        let nseg = self.segment_count as usize;
        let mut rows = Vec::with_capacity(43 * nseg);
        let mut d = [0u8; 43];
        for s in 0..nseg {
            self.segment_descriptor(p, s, &mut d)?;
            rows.extend_from_slice(&d);
        }
        Ok(crate::hash::sha256(&[
            SEGMENT_DOMAIN,
            &self.segment_count.to_le_bytes(),
            &rows,
        ]))
    }

    /// Index at position `q` of base entry `old`; `None` if retired there.
    pub fn old_to_new(&self, old: u32, q: u32) -> Result<Option<u32>, u32> {
        if old >= self.base_entries {
            return Err(PT2_PRODUCER);
        }
        let shape = match self.shape(q)? {
            None => return Ok(Some(old)),
            Some(x) => x,
        };
        let s = self.base_segment_of(old);
        let seg = self.segs[s];
        let local = old - seg.base_start;
        if seg.layer == u32::MAX {
            return Ok(Some(to_u32(add(
                self.seg_new_start(&shape, s)?,
                local as u64,
            )?)?));
        }
        let l = &self.layers[seg.layer as usize];
        // bisect_right over the base op firsts.
        let mut k = 0usize;
        for j in 0..seg.nops as usize {
            if self.op(s, j)?.2 <= local {
                k = j;
            } else {
                break;
            }
        }
        if let Some(phase) = l.ops.iter().position(|&x| x as usize == k) {
            if phase != 2 {
                return Ok(None);
            }
            let e = self.base_entry(old)?;
            if e.kernel_index != OLD_PV {
                return Ok(None);
            }
            let mut head = 0u64;
            for i in l.op_start[2]..old {
                if self.base_entry(i)?.kernel_index == OLD_PV {
                    head += 1;
                }
            }
            return Ok(Some(to_u32(self.final_29c(&shape, l, s, head)?)?));
        }
        let (_, _, first, _) = self.op(s, k)?;
        let at = add(
            add(
                self.seg_new_start(&shape, s)?,
                self.op_new_first(&shape, l, k, first)?,
            )?,
            (local - first) as u64,
        )?;
        Ok(Some(to_u32(at)?))
    }

    /// bisect_right(base_seg_start, old) - 1.
    fn base_segment_of(&self, old: u32) -> usize {
        let (mut lo, mut hi) = (0usize, self.segs.len());
        while lo < hi {
            let m = (lo + hi) / 2;
            if self.segs[m].base_start <= old {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        lo.saturating_sub(1)
    }

    fn final_29c(&self, shape: &Shape, l: &LayerInfo, s: usize, head: u64) -> Result<u64, u32> {
        let h = self.g.heads;
        let base = add(
            self.seg_new_start(shape, s)?,
            self.op_new_first(shape, l, l.ops[2] as usize, l.base_first[2])?,
        )?;
        add(
            add(
                add(base, mul(h, shape.n)?)?,
                mul(h, sub(shape.comb.sum(), 1)?)?,
            )?,
            head,
        )
    }

    /// Entry `t` at `p` (closed form; `p` itself is not range-checked here).
    pub fn locate(&self, p: u32, t: u32) -> Result<Item, u32> {
        let shape = match self.shape(p)? {
            None => {
                if t >= self.base_entries {
                    return Err(PT2_ROUTE_SET);
                }
                return Ok(Item::Base(t));
            }
            Some(x) => x,
        };
        let t64 = t as u64;
        let mut cursor = 0u64;
        for s in 0..self.segs.len() {
            let count = self.seg_new_count(&shape, s)?;
            if t64 < add(cursor, count)? {
                let seg = self.segs[s];
                let local = t64 - cursor;
                if seg.layer == u32::MAX {
                    return Ok(Item::Base(to_u32(add(seg.base_start as u64, local)?)?));
                }
                let li = seg.layer as usize;
                let l = &self.layers[li];
                let mut first_new = 0u64;
                for k in 0..seg.nops as usize {
                    let (_, _, base_first, base_count) = self.op(s, k)?;
                    let phase = l.ops.iter().position(|&x| x as usize == k);
                    let count = match phase {
                        Some(ph) => shape.counts[ph],
                        None => base_count as u64,
                    };
                    if local < add(first_new, count)? {
                        let j = local - first_new;
                        return match phase {
                            None => Ok(Item::Base(to_u32(add(
                                add(seg.base_start as u64, base_first as u64)?,
                                j,
                            )?)?)),
                            Some(ph) => self.form_at(&shape, li as u32, ph, j).map(Item::Form),
                        };
                    }
                    first_new = add(first_new, count)?;
                }
                return Err(PT2_ROUTE_SET);
            }
            cursor = add(cursor, count)?;
        }
        Err(PT2_ROUTE_SET)
    }

    fn tree_node(levels: &Levels, mut k: u64) -> Result<(u64, u64), u32> {
        for level in 0..levels.len {
            if k < levels.get(level) {
                return Ok((level as u64, k));
            }
            k -= levels.get(level);
        }
        Err(PT2_ROUTE_SET)
    }

    fn form_at(&self, shape: &Shape, li: u32, phase: usize, j: u64) -> Result<Form, u32> {
        let g = &self.g;
        let (h, n, sg, smg) = (g.heads, shape.n, g.score_heads, g.softmax_heads);
        let f = |kind, h0: u64, h1: u64, window, level, node, fin| Form {
            kind,
            layer: li,
            h0,
            h1,
            window,
            level,
            node,
            fin,
        };
        if phase == 0 {
            let a = mul(h / sg, n)?;
            if j < a {
                let (i, h0) = (j / (h / sg), j % (h / sg));
                return Ok(f(FORM_27W, h0 * sg, h0 * sg + sg, i, 0, 0, false));
            }
            let (level, node) = Self::tree_node(&shape.red, (j - a) / h)?;
            let hh = (j - a) % h;
            return Ok(f(FORM_28M, hh, hh + 1, 0, level, node, false));
        }
        if phase == 1 {
            let a = mul(h / smg, n)?;
            if j < a {
                let (i, h0) = (j / (h / smg), j % (h / smg));
                return Ok(f(FORM_28E, h0 * smg, h0 * smg + smg, i, 0, 0, false));
            }
            let j = j - a;
            let r = mul(h, shape.red.sum())?;
            if j < r {
                let (level, node) = Self::tree_node(&shape.red, j / h)?;
                return Ok(f(FORM_28S, j % h, j % h + 1, 0, level, node, false));
            }
            let j = j - r;
            let (i, h0) = (j / (h / smg), j % (h / smg));
            return Ok(f(FORM_28N, h0 * smg, h0 * smg + smg, i, 0, 0, false));
        }
        let a = mul(h, n)?;
        if j < a {
            return Ok(f(FORM_29W, j % h, j % h + 1, j / h, 0, 0, false));
        }
        let (level, node) = Self::tree_node(&shape.comb, (j - a) / h)?;
        let hh = (j - a) % h;
        let fin = level as usize == shape.comb.len - 1 && shape.comb.get(level as usize) == 1;
        Ok(f(FORM_29C, hh, hh + 1, 0, level, node, fin))
    }

    /// Inverse of `form_at`: the index at `p` of a generated form.
    pub fn form_index(
        &self,
        shape: &Shape,
        li: u32,
        kind: u16,
        head: u64,
        window: u64,
        level: u64,
        node: u64,
    ) -> Result<u64, u32> {
        let g = &self.g;
        let (h, n, sg, smg) = (g.heads, shape.n, g.score_heads, g.softmax_heads);
        let l = self.layers.get(li as usize).ok_or(PT2_MANIFEST)?;
        let phase = match kind {
            FORM_27W | FORM_28M => 0,
            FORM_28E | FORM_28S | FORM_28N => 1,
            FORM_29W | FORM_29C => 2,
            _ => return Err(PT2_ROUTE_SET),
        };
        let s = l.seg as usize;
        let base = add(
            self.seg_new_start(shape, s)?,
            self.op_new_first(shape, l, l.ops[phase] as usize, l.base_first[phase])?,
        )?;
        let lv = level as usize;
        let x = match kind {
            FORM_27W => add(mul(window, h / sg)?, head / sg)?,
            FORM_28M => add(
                add(mul(h / sg, n)?, mul(add(shape.red.prefix(lv), node)?, h)?)?,
                head,
            )?,
            FORM_28E => add(mul(window, h / smg)?, head / smg)?,
            FORM_28S => add(
                add(mul(h / smg, n)?, mul(add(shape.red.prefix(lv), node)?, h)?)?,
                head,
            )?,
            FORM_28N => add(
                add(
                    add(mul(h / smg, n)?, mul(h, shape.red.sum())?)?,
                    mul(window, h / smg)?,
                )?,
                head / smg,
            )?,
            FORM_29W => add(mul(window, h)?, head)?,
            _ => add(
                add(mul(h, n)?, mul(add(shape.comb.prefix(lv), node)?, h)?)?,
                head,
            )?,
        };
        add(base, x)
    }

    // -------------------------------------------------------------- entries

    /// Entry `(p, t)`; refuses `p >= position_count` (603).
    pub fn entry(&self, p: u32, t: u32) -> Result<Entry, u32> {
        if p >= self.position_count {
            return Err(PT2_ROUTE_SET);
        }
        self.entry_any(p, t)
    }

    fn entry_any(&self, p: u32, t: u32) -> Result<Entry, u32> {
        let item = self.locate(p, t)?;
        match item {
            Item::Base(old) => {
                let e = self.base_entry(old)?;
                Ok(Entry {
                    position: p,
                    index: t,
                    item,
                    kernel_index: e.kernel_index,
                    read_count: e.read_count,
                    write_count: e.write_count,
                    base: Some(e),
                })
            }
            Item::Form(f) => {
                let g = &self.g;
                let width = |levels: &Levels| -> Result<u64, u32> {
                    let n = self.n_of(p);
                    let width = if f.level == 0 {
                        n
                    } else {
                        levels.get(f.level as usize - 1)
                    };
                    let a = mul(f.node, g.fanin)?;
                    Ok(add(a, g.fanin)?.min(width).saturating_sub(a))
                };
                let (reads, writes) = match f.kind {
                    FORM_27W => (2, 1 + (f.h1 - f.h0)),
                    FORM_28M | FORM_28S => {
                        let shape = self.shape(p)?.ok_or(PT2_ROUTE_SET)?;
                        (width(&shape.red)?, 1)
                    }
                    FORM_29C => {
                        let shape = self.shape(p)?.ok_or(PT2_ROUTE_SET)?;
                        (width(&shape.comb)?, 1)
                    }
                    FORM_28E => (
                        add(add((f.h1 - f.h0).div_ceil(g.score_heads), f.h1 - f.h0)?, 1)?,
                        f.h1 - f.h0,
                    ),
                    FORM_28N => (
                        add(
                            add((f.h1 - f.h0).div_ceil(g.score_heads), mul(2, f.h1 - f.h0)?)?,
                            1,
                        )?,
                        f.h1 - f.h0,
                    ),
                    _ => (2, 1),
                };
                let (reads, writes) = (to_u16(reads)?, to_u16(writes)?);
                if reads as u32 + writes as u32 > u16::MAX as u32 {
                    return Err(OVERFLOW);
                }
                Ok(Entry {
                    position: p,
                    index: t,
                    item,
                    kernel_index: f.kind,
                    read_count: reads,
                    write_count: writes,
                    base: None,
                })
            }
        }
    }

    fn scalar(&self, rid: u16, slot: u64, head: u64, producer: u64) -> Result<Route, u32> {
        Ok(Route {
            region_id: rid,
            direction: 0,
            read_class: READ_WITNESSED,
            region_offset: mul(add(mul(slot, self.g.heads)?, head)?, 8)?,
            byte_length: 8,
            producer_entry: to_u32(producer)?,
            producer_delta: 0,
            flags: 0,
        })
    }

    fn row(
        &self,
        rid: u16,
        direction: u8,
        read_class: u8,
        offset: u64,
        length: u64,
        producer: u64,
    ) -> Result<Route, u32> {
        Ok(Route {
            region_id: rid,
            direction,
            read_class,
            region_offset: offset,
            byte_length: to_u32(length)?,
            producer_entry: if producer == NO_PRODUCER as u64 {
                NO_PRODUCER
            } else {
                to_u32(producer)?
            },
            producer_delta: 0,
            flags: 0,
        })
    }

    fn stride(&self, rid: u16) -> Result<u64, u32> {
        Ok(self
            .c
            .region_position(rid)
            .map_err(|_| PT2_ROUTE_SET)?
            .map_or(0, |r| r.stride))
    }

    /// The clause-5 route record of `(e, ordinal)` as the concrete PT2 route
    /// set at `p` holds it (producers remapped, writes naming `e.index`), plus
    /// the §16.1 window binding of a generated class-3 read.
    pub fn raw_route(&self, e: &Entry, ordinal: u16) -> Result<(Route, Option<WindowBind>), u32> {
        if ordinal as u32 >= e.route_count() {
            return Err(PT2_ROUTE_SET);
        }
        let p = e.position;
        let form = match e.item {
            Item::Base(_) => {
                let b = e.base.ok_or(PT2_ROUTE_SET)?;
                let mut r = self.base_route(b, ordinal)?;
                if p >= self.g.window_start {
                    if ordinal < b.read_count {
                        if r.producer_entry != NO_PRODUCER && p >= r.producer_delta as u32 {
                            r.producer_entry = self
                                .old_to_new(r.producer_entry, p - r.producer_delta as u32)?
                                .ok_or(PT2_PRODUCER)?;
                        }
                    } else {
                        r.producer_entry = e.index;
                    }
                }
                return Ok((r, None));
            }
            Item::Form(f) => f,
        };
        let g = &self.g;
        let shape = self.shape(p)?.ok_or(PT2_ROUTE_SET)?;
        let (h, w, d, sg, smg) = (
            g.heads,
            g.window,
            g.head_dim,
            g.score_heads,
            g.softmax_heads,
        );
        let l = self.layers.get(form.layer as usize).ok_or(PT2_MANIFEST)?;
        let rule = l.rule;
        let (i, h0, h1) = (form.window, form.h0, form.h1);
        let index = e.index as u64;
        let fi = |kind: u16, head: u64, window: u64, level: u64, node: u64| {
            self.form_index(&shape, form.layer, kind, head, window, level, node)
        };
        let write = |rid: u16, offset: u64, length: u64| self.row(rid, 1, 0, offset, length, index);
        let read = |rid: u16, offset: u64, length: u64, producer: u64| {
            self.row(rid, 0, READ_WITNESSED, offset, length, producer)
        };
        let kv_window = |rid: u16, family: u16| -> Result<(Route, Option<WindowBind>), u32> {
            let first = mul(i, w)?;
            let end = add(mul(add(i, 1)?, w)?, 0)?.min(p as u64 + 1);
            let stride = self.stride(rid)?;
            let r = self.row(
                rid,
                0,
                READ_CLOSURE_ROOT,
                mul(first, stride)?,
                mul(sub(end, first)?, stride)?,
                NO_PRODUCER as u64,
            )?;
            Ok((
                r,
                Some(WindowBind {
                    family,
                    first: to_u32(first)?,
                    end: to_u32(end)?,
                }),
            ))
        };
        let root = |rid: u16, head: u64, leaf: u16, tree: u16, group: u64| -> Result<Route, u32> {
            if shape.n == 1 {
                return self.scalar(rid, 0, head, fi(leaf, head / group * group, 0, 0, 0)?);
            }
            let top = shape.red.len - 1;
            self.scalar(
                rid,
                shape.slot(&shape.red, top, 0)?,
                head,
                fi(tree, head, 0, top as u64, 0)?,
            )
        };
        let reads = e.read_count;
        let (dir_read, k) = if ordinal < reads {
            (true, ordinal as u64)
        } else {
            (false, (ordinal - reads) as u64)
        };
        let out = match form.kind {
            FORM_27W => {
                if dir_read && k == 0 {
                    let scores = self
                        .nth_kind(l, 0, OLD_SCORES, h0 / sg)?
                        .ok_or(PT2_MANIFEST)?;
                    let mut q = self.base_route(scores, 0)?;
                    if q.producer_entry != NO_PRODUCER {
                        q.producer_entry =
                            self.old_to_new(q.producer_entry, p)?.ok_or(PT2_PRODUCER)?;
                    }
                    (q, None)
                } else if dir_read {
                    return kv_window(l.k_region, rule.k_family);
                } else if k == 0 {
                    (
                        write(
                            l.sc_region,
                            mul(mul(add(mul(i, h)?, h0)?, w)?, 8)?,
                            mul(mul(h1 - h0, w)?, 8)?,
                        )?,
                        None,
                    )
                } else {
                    (
                        write(rule.lm_region, mul(add(mul(i, h)?, h0 + k - 1)?, 8)?, 8)?,
                        None,
                    )
                }
            }
            FORM_28M | FORM_28S | FORM_29C => {
                let levels = if form.kind == FORM_29C {
                    &shape.comb
                } else {
                    &shape.red
                };
                let rid = match form.kind {
                    FORM_28M => rule.lm_region,
                    FORM_28S => rule.se_region,
                    _ => rule.nu_region,
                };
                let group = match form.kind {
                    FORM_28M => sg,
                    FORM_28S => smg,
                    _ => 1,
                };
                let leaf = match form.kind {
                    FORM_28M => FORM_27W,
                    FORM_28S => FORM_28E,
                    _ => FORM_29W,
                };
                if dir_read {
                    let child = add(mul(form.node, g.fanin)?, k)?;
                    let (producer, slot) = if form.level == 0 {
                        (fi(leaf, h0 / group * group, child, 0, 0)?, child)
                    } else {
                        (
                            fi(form.kind, h0, 0, form.level - 1, child)?,
                            shape.slot(levels, form.level as usize - 1, child)?,
                        )
                    };
                    if form.kind == FORM_29C {
                        (
                            read(
                                rid,
                                mul(mul(add(mul(slot, h)?, h0)?, d)?, 8)?,
                                mul(d, 8)?,
                                producer,
                            )?,
                            None,
                        )
                    } else {
                        (self.scalar(rid, slot, h0, producer)?, None)
                    }
                } else {
                    let slot = shape.slot(levels, form.level as usize, form.node)?;
                    if form.kind == FORM_29C && form.fin {
                        let pv = self.nth_kind(l, 2, OLD_PV, h0)?.ok_or(PT2_MANIFEST)?;
                        let mut out = self.base_route(pv, pv.read_count)?;
                        out.producer_entry = e.index;
                        (out, None)
                    } else if form.kind == FORM_29C {
                        (
                            write(rid, mul(mul(add(mul(slot, h)?, h0)?, d)?, 8)?, mul(d, 8)?)?,
                            None,
                        )
                    } else {
                        (write(rid, mul(add(mul(slot, h)?, h0)?, 8)?, 8)?, None)
                    }
                }
            }
            FORM_28E | FORM_28N => {
                let span = h1 - h0;
                let sc_reads = span.div_ceil(sg);
                if dir_read && k < sc_reads {
                    let hh = h0 + k * sg;
                    (
                        read(
                            l.sc_region,
                            mul(mul(add(mul(i, h)?, hh)?, w)?, 8)?,
                            mul(mul(sg, w)?, 8)?,
                            fi(FORM_27W, hh, i, 0, 0)?,
                        )?,
                        None,
                    )
                } else if dir_read && k < sc_reads + span {
                    (
                        root(rule.lm_region, h0 + k - sc_reads, FORM_27W, FORM_28M, sg)?,
                        None,
                    )
                } else if dir_read && form.kind == FORM_28N && k < sc_reads + 2 * span {
                    (
                        root(
                            rule.se_region,
                            h0 + k - sc_reads - span,
                            FORM_28E,
                            FORM_28S,
                            smg,
                        )?,
                        None,
                    )
                } else if dir_read {
                    (
                        self.row(
                            g.lut_region,
                            0,
                            READ_SUPPLIED,
                            0,
                            g.lut_bytes as u64,
                            NO_PRODUCER as u64,
                        )?,
                        None,
                    )
                } else if form.kind == FORM_28E {
                    (
                        write(rule.se_region, mul(add(mul(i, h)?, h0 + k)?, 8)?, 8)?,
                        None,
                    )
                } else {
                    (
                        write(
                            l.pr_region,
                            mul(mul(add(mul(i, h)?, h0 + k)?, w)?, 8)?,
                            mul(w, 8)?,
                        )?,
                        None,
                    )
                }
            }
            FORM_29W => {
                if dir_read && k == 0 {
                    (
                        read(
                            l.pr_region,
                            mul(mul(add(mul(i, h)?, h0)?, w)?, 8)?,
                            mul(w, 8)?,
                            fi(FORM_28N, h0 / smg * smg, i, 0, 0)?,
                        )?,
                        None,
                    )
                } else if dir_read {
                    return kv_window(l.v_region, rule.v_family);
                } else {
                    (
                        write(
                            rule.nu_region,
                            mul(mul(add(mul(i, h)?, h0)?, d)?, 8)?,
                            mul(d, 8)?,
                        )?,
                        None,
                    )
                }
            }
            _ => return Err(PT2_ROUTE_SET),
        };
        Ok(out)
    }

    /// One instantiated route, identical to `InstantiatedEntry::route_pt2` over
    /// the concrete PT2 route set at `p` with the source position's set for
    /// named producers and the position's window bindings. Side tables are
    /// looked up by the OLD base index; generated forms have none.
    pub fn route(&self, e: &Entry, ordinal: u16) -> Result<InstantiatedRoute, u32> {
        let (raw, bind) = self.raw_route(e, ordinal)?;
        let c = &self.c;
        let p = e.position;
        let direction = if ordinal < e.read_count { 0u8 } else { 1u8 };
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
        let old = e.old_index();
        let x = match old {
            Some(o) => c.t_scaled_for(o, direction, k)?,
            None => None,
        };
        if x.is_some() != (raw.flags & 2 != 0) {
            return Err(PT2_ROUTE_SET);
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
            if let Some(b) = bind {
                // GeometryV4::instantiate_window.
                if stride == 0
                    || raw.producer_entry != NO_PRODUCER
                    || raw.producer_delta != 0
                    || raw.flags != 0
                    || b.first >= b.end
                    || b.end > p.checked_add(1).ok_or(PT2_ROUTE_SET)?
                    || raw.region_offset
                        != (b.first as u64).checked_mul(stride).ok_or(PT2_ROUTE_SET)?
                    || raw.byte_length as u64
                        != ((b.end - b.first) as u64)
                            .checked_mul(stride)
                            .ok_or(PT2_ROUTE_SET)?
                {
                    return Err(PT2_PRODUCER);
                }
                out.effective_offset = raw.region_offset;
                out.byte_length = raw.byte_length;
                out.read_class = 3;
                out.binding_kind = 2;
                out.range_first = b.first;
                out.range_end = b.end;
                out.family_ordinal = b.family;
                return Ok(out);
            }
            let o = old.ok_or(PT2_ROUTE_SET)?;
            let b = e.base.ok_or(PT2_ROUTE_SET)?;
            let mut c3 = 0;
            for j in 0..k {
                if self.base_route(b, j)?.read_class == 3 {
                    c3 += 1;
                }
            }
            let decl = c.range_for(o, c3)?.ok_or(pt::SLOT)?;
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
        if let Some(o) = old {
            if let Some(ps) = c.prompt_for(o, k)? {
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
            out.producer_write_ordinal = self.matching_write(e, k, raw, q)?;
        } else if named {
            let initial_slot = if stride == 0 {
                0
            } else if ring >= 2 {
                ((p as u64 + ring as u64 - (raw.producer_delta as u64 % ring as u64)) % ring as u64)
                    as u32
            } else {
                return Err(pt::SLOT);
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

    /// `matching_write_cross` against the producer's routes at position `q`.
    fn matching_write(&self, reader: &Entry, k: u16, r: Route, q: u32) -> Result<u8, u32> {
        let producer = self
            .entry_any(q, r.producer_entry)
            .map_err(|_| PT2_PRODUCER)?;
        let read_x = if r.flags & 2 != 0 {
            match reader.old_index() {
                Some(o) => self.c.t_scaled_for(o, 0, k)?,
                None => None,
            }
        } else {
            None
        };
        let mut found = None;
        for j in 0..producer.write_count {
            let (w, _) = self.raw_route(&producer, producer.read_count + j)?;
            if w.region_id != r.region_id
                || w.region_offset != r.region_offset
                || (w.flags & 2) != (r.flags & 2)
            {
                continue;
            }
            let equal = if let Some(rx) = read_x {
                let wx = match producer.old_index() {
                    Some(o) => self.c.t_scaled_for(o, 1, j)?,
                    None => None,
                }
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

    /// `attention_t` as `Template::instantiate_with` computes it over the
    /// concrete set: from the entry's first range row or T_SCALED rows (old
    /// index); generated forms carry neither.
    pub fn attention_t(&self, e: &Entry) -> Result<Option<u32>, u32> {
        let o = match e.old_index() {
            Some(o) => o,
            None => return Ok(None),
        };
        let p = e.position;
        let first = self.c.range_for(o, 0)?;
        Ok(match first {
            Some(r) => Some(
                p + 1
                    - if r.first_rule == 0 {
                        0
                    } else {
                        p.saturating_sub(r.window)
                    },
            ),
            None if self.c.has_scaled_entry(o)? => Some(p + 1),
            None => None,
        })
    }

    /// Unpatched base payload row body of old entry `old`.
    pub fn base_payload(&self, old: u32) -> Result<&'a [u8], u32> {
        let (at, end) = match self.payload_index {
            Some(index) => (
                u32_at(index, 4 * old as usize, PT2_ROUTE_SET)? as usize,
                u32_at(index, 4 * (old as usize + 1), PT2_ROUTE_SET)? as usize,
            ),
            None => return Err(PT2_ROUTE_SET),
        };
        let row = self.payloads.get(at..end).ok_or(PT2_ROUTE_SET)?;
        if row.len() < 6
            || u32_at(row, 0, PT2_ROUTE_SET)? != old
            || 6 + u16_at(row, 4, PT2_ROUTE_SET)? as usize != row.len()
        {
            return Err(PT2_ROUTE_SET);
        }
        Ok(&row[6..])
    }

    /// The payload length of `e` (base row length or 44).
    pub fn payload_len(&self, e: &Entry) -> Result<usize, u32> {
        match e.item {
            Item::Base(o) => Ok(self.base_payload(o)?.len()),
            Item::Form(_) => Ok(GENERATED_PAYLOAD),
        }
    }

    /// Write the payload of `e` into `out` (exactly `payload_len` bytes). With
    /// `patched` the PT1 patch rows of the OLD base entry are applied at `p`
    /// (the instantiation stream); without it the bytes are the PT2 payload
    /// table row (the committed route-set bytes).
    pub fn payload(&self, e: &Entry, patched: bool, out: &mut [u8]) -> Result<(), u32> {
        let p = e.position;
        let f = match e.item {
            Item::Base(o) => {
                let raw = self.base_payload(o)?;
                if out.len() != raw.len() {
                    return Err(PT2_ROUTE_SET);
                }
                out.copy_from_slice(raw);
                if patched {
                    self.patch(o, p, out)?;
                }
                return Ok(());
            }
            Item::Form(f) => f,
        };
        if out.len() != GENERATED_PAYLOAD {
            return Err(PT2_ROUTE_SET);
        }
        let g = &self.g;
        let windowed = matches!(f.kind, FORM_27W | FORM_28E | FORM_28N | FORM_29W);
        let length = if windowed {
            g.window.min(sub(p as u64 + 1, mul(f.window, g.window)?)?)
        } else {
            1
        };
        let n = self.n_of(p);
        let mut at = 0usize;
        let mut put = |b: &[u8]| {
            out[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        };
        put(&1u16.to_le_bytes());
        put(&f.kind.to_le_bytes());
        put(&(p + 1).to_le_bytes());
        put(&to_u16(g.window)?.to_le_bytes());
        put(&to_u16(length)?.to_le_bytes());
        put(&to_u32(if windowed { f.window } else { f.node })?.to_le_bytes());
        put(&to_u16(f.h0)?.to_le_bytes());
        put(&to_u16(f.h1)?.to_le_bytes());
        put(&to_u16(g.heads)?.to_le_bytes());
        put(&to_u16(g.kv_heads)?.to_le_bytes());
        put(&to_u16(g.head_dim)?.to_le_bytes());
        put(&(f.fin as u16).to_le_bytes());
        put(&g.inv_sqrt.to_le_bytes());
        put(&to_u32(n)?.to_le_bytes());
        put(&to_u16(if windowed { 0 } else { f.level })?.to_le_bytes());
        put(&0u16.to_le_bytes());
        Ok(())
    }

    /// `InstantiatedEntry::patch_payload` keyed by the old base index.
    fn patch(&self, old: u32, p: u32, out: &mut [u8]) -> Result<(), u32> {
        let c = &self.c;
        let (mut lo, mut hi) = (0, c.patch_count());
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if c.patch(m)?.entry < old {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        for i in lo..c.patch_count() {
            let r = c.patch(i)?;
            if r.entry > old {
                break;
            }
            let value = match r.rule {
                0 => p as u64 + 1,
                1 => p as u64,
                2 => r
                    .base
                    .checked_add((p as u64).checked_mul(r.stride).ok_or(OVERFLOW)?)
                    .ok_or(OVERFLOW)?,
                _ => return Err(pt::MALFORMED),
            };
            if r.width < 8 && value >= (1u64 << (8 * r.width)) {
                return Err(OVERFLOW);
            }
            let at = r.offset as usize;
            out.get_mut(at..at + r.width as usize)
                .ok_or(pt::MALFORMED)?
                .copy_from_slice(&value.to_le_bytes()[..r.width as usize]);
        }
        Ok(())
    }

    /// `(first index at p, entry count)` of replaced operation `phase` of layer `li`.
    pub fn replaced_op(&self, p: u32, li: u32, phase: usize) -> Result<(u64, u64), u32> {
        let shape = self.shape(p)?.ok_or(PT2_ROUTE_SET)?;
        let l = self.layers.get(li as usize).ok_or(PT2_MANIFEST)?;
        let first = add(
            self.seg_new_start(&shape, l.seg as usize)?,
            self.op_new_first(&shape, l, l.ops[phase] as usize, l.base_first[phase])?,
        )?;
        Ok((first, shape.counts[phase]))
    }

    /// The base (old) index of the `k`-th kind-`kind` entry in replaced op `phase`.
    pub fn replaced_base_entry(
        &self,
        li: u32,
        phase: usize,
        kind: u16,
        k: u64,
    ) -> Result<Option<u32>, u32> {
        let l = self.layers.get(li as usize).ok_or(PT2_MANIFEST)?;
        Ok(self.nth_kind(l, phase, kind, k)?.map(|e| e.index))
    }

    pub fn layer_count(&self) -> u32 {
        self.layers.len() as u32
    }

    /// True when base entry `old` lies inside the scores, softmax or attn_pv
    /// operation of a `PWR1` layer (the retired set `R` of the unified format,
    /// `docs/spec/dcg-unified-v1.md` §3.3; such entries exist only while
    /// `p < window_start`).
    pub fn is_replaced(&self, old: u32) -> bool {
        self.layers.iter().any(|l| {
            (0..3).any(|phase| {
                old >= l.op_start[phase] && old - l.op_start[phase] < l.base_count[phase]
            })
        })
    }

    /// Clause-5 record of base (old) entry `old`.
    pub fn base_entry_record(&self, old: u32) -> Result<pt::TemplateEntry, u32> {
        self.base_entry(old)
    }

    /// Clause-5 route record `ordinal` of a base entry (no instantiation).
    pub fn base_route_record(&self, e: pt::TemplateEntry, ordinal: u16) -> Result<Route, u32> {
        self.base_route(e, ordinal)
    }

    /// Payload row length of base entry `old` from the PT1S payload index
    /// (row = `old:u32 | len:u16 | body`); needs the index.
    pub fn base_payload_len(&self, old: u32) -> Result<usize, u32> {
        let index = self.payload_index.ok_or(PT2_ROUTE_SET)?;
        if old >= self.base_entries {
            return Err(PT2_PRODUCER);
        }
        let at = u32_at(index, 4 * old as usize, PT2_ROUTE_SET)? as usize;
        let end = u32_at(index, 4 * (old as usize + 1), PT2_ROUTE_SET)? as usize;
        end.checked_sub(at)
            .and_then(|n| n.checked_sub(6))
            .ok_or(PT2_ROUTE_SET)
    }

    /// `(segment_id, local, operation_ordinal)` of entry `t` at `p`: the
    /// `Template::coordinate` of the concrete per-position geometry (segment
    /// rows and operation locators at `p`), in closed form.
    pub fn coordinate(&self, p: u32, t: u32) -> Result<pt::EntryCoordinate, u32> {
        if p >= self.position_count {
            return Err(PT2_ROUTE_SET);
        }
        let shape = self.shape(p)?;
        let mut cursor = 0u64;
        for s in 0..self.segs.len() {
            let seg = self.segs[s];
            let count = match &shape {
                None => seg.base_count as u64,
                Some(x) => self.seg_new_count(x, s)?,
            };
            if (t as u64) < add(cursor, count)? {
                let local = to_u32(t as u64 - cursor)?;
                let id = u16_at(self.base_v2, 59 + 43 * s, PT2_ROUTE_SET)?;
                for k in 0..seg.nops as usize {
                    let (ordinal, _, first, n) = self.op(s, k)?;
                    let (first, n) = match &shape {
                        Some(x) if seg.layer != u32::MAX => {
                            self.op_new(x, &self.layers[seg.layer as usize], k, first, n)?
                        }
                        _ => (first, n),
                    };
                    if local >= first && (local as u64) < add(first as u64, n as u64)? {
                        return Ok(pt::EntryCoordinate {
                            segment: id,
                            local,
                            operation_ordinal: ordinal,
                        });
                    }
                }
                return Err(pt::SLOT);
            }
            cursor = add(cursor, count)?;
        }
        Err(PT2_ROUTE_SET)
    }

    /// Entry index at `p` of `(segment_id, local)`; refuses an unknown
    /// segment or `local >= entries(p, segment)` (603).
    pub fn entry_index(&self, p: u32, segment: u16, local: u32) -> Result<u32, u32> {
        if p >= self.position_count {
            return Err(PT2_ROUTE_SET);
        }
        let mut first = 0u64;
        for s in 0..self.segs.len() {
            let (id, count) = self.segment_row(p, s)?;
            if id == segment {
                if local >= count {
                    return Err(PT2_ROUTE_SET);
                }
                return to_u32(add(first, local as u64)?);
            }
            first = add(first, count as u64)?;
        }
        Err(PT2_ROUTE_SET)
    }
}

/// 40-byte instantiated route wire (`put_route` in `pt1_onchain`).
pub fn route_wire(r: &InstantiatedRoute) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0] = r.direction;
    out[1] = r.read_class;
    out[2] = r.binding_kind;
    out[3] = r.source_supplied as u8 | ((r.initial_content as u8) << 1);
    out[4..6].copy_from_slice(&r.ordinal.to_le_bytes());
    out[6..8].copy_from_slice(&r.region_id.to_le_bytes());
    out[8..16].copy_from_slice(&r.effective_offset.to_le_bytes());
    out[16..20].copy_from_slice(&r.byte_length.to_le_bytes());
    out[20..24].copy_from_slice(&r.producer_position.to_le_bytes());
    out[24..28].copy_from_slice(&r.producer_entry.to_le_bytes());
    out[28] = r.producer_write_ordinal;
    out[30..32].copy_from_slice(&r.family_ordinal.to_le_bytes());
    out[32..36].copy_from_slice(&r.range_first.to_le_bytes());
    out[36..40].copy_from_slice(&r.range_end.to_le_bytes());
    out
}

// ------------------------------------------------------------------ host materializer

#[cfg(not(target_os = "solana"))]
pub mod host {
    //! Materialize PT2's concrete `(clause5, geometry v4, payloads)` triple at
    //! `p` for byte parity with the enumerated emission. Host only.
    use super::*;

    const ROUTE_DOMAIN: &[u8] = b"basanos/dcg-route-entry/1";

    fn route_record(r: &Route) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..2].copy_from_slice(&r.region_id.to_le_bytes());
        b[2] = r.direction;
        b[3] = r.read_class;
        b[4..12].copy_from_slice(&r.region_offset.to_le_bytes());
        b[12..16].copy_from_slice(&r.byte_length.to_le_bytes());
        b[16..20].copy_from_slice(&r.producer_entry.to_le_bytes());
        b[20..22].copy_from_slice(&r.producer_delta.to_le_bytes());
        b[22..24].copy_from_slice(&r.flags.to_le_bytes());
        b
    }

    /// Survivor remap of a base side-table row keyed by `old`.
    fn survivor(x: &Pt2p<'_>, old: u32, p: u32) -> Result<Option<u32>, u32> {
        Ok(match x.old_to_new(old, p)? {
            Some(new) if x.locate(p, new)? == Item::Base(old) => Some(new),
            _ => None,
        })
    }

    pub fn route_set(
        x: &Pt2p<'_>,
        geometry: &[u8],
        p: u32,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), u32> {
        let n = x.entry_count(p)?;
        if x.shape(p)?.is_none() {
            let mut payloads = Vec::new();
            for t in 0..n {
                let body = x.base_payload(t)?;
                payloads.extend_from_slice(&t.to_le_bytes());
                payloads.extend_from_slice(&(body.len() as u16).to_le_bytes());
                payloads.extend_from_slice(body);
            }
            return Ok((x.routes.to_vec(), geometry.to_vec(), payloads));
        }
        let mut rows = Vec::new();
        let mut records = Vec::new();
        let mut payloads = Vec::new();
        let mut windows = Vec::new();
        let mut frontier = [[0u8; 32]; 32];
        let mut running = 0u32;
        for t in 0..n {
            let e = x.entry(p, t)?;
            let first_record = records.len();
            for k in 0..e.route_count() as u16 {
                let (r, bind) = x.raw_route(&e, k)?;
                records.extend_from_slice(&route_record(&r));
                if let Some(b) = bind {
                    windows.extend_from_slice(&t.to_le_bytes());
                    windows.extend_from_slice(&k.to_le_bytes());
                    windows.extend_from_slice(&b.family.to_le_bytes());
                    windows.extend_from_slice(&b.first.to_le_bytes());
                    windows.extend_from_slice(&b.end.to_le_bytes());
                }
            }
            rows.extend_from_slice(&t.to_le_bytes());
            rows.extend_from_slice(&e.kernel_index.to_le_bytes());
            rows.extend_from_slice(&e.read_count.to_le_bytes());
            rows.extend_from_slice(&e.write_count.to_le_bytes());
            rows.extend_from_slice(&0u16.to_le_bytes());
            rows.extend_from_slice(&running.to_le_bytes());
            running += e.route_count();
            let leaf = crate::hash::sha256(&[
                ROUTE_DOMAIN,
                &t.to_le_bytes(),
                &e.kernel_index.to_le_bytes(),
                &e.read_count.to_le_bytes(),
                &e.write_count.to_le_bytes(),
                &records[first_record..],
            ]);
            pt::route_frontier_push(&mut frontier, t, leaf)?;
            let mut body = vec![0u8; x.payload_len(&e)?];
            x.payload(&e, false, &mut body)?;
            payloads.extend_from_slice(&t.to_le_bytes());
            payloads.extend_from_slice(&(body.len() as u16).to_le_bytes());
            payloads.extend_from_slice(&body);
        }
        let mut clause5 = Vec::with_capacity(80 + rows.len() + records.len());
        clause5.extend_from_slice(&n.to_le_bytes());
        clause5.extend_from_slice(&running.to_le_bytes());
        clause5.extend_from_slice(&pt::route_frontier_root(&frontier, n)?);
        clause5.extend_from_slice(&crate::hash::sha256(&[ROUTE_DOMAIN]));
        clause5.extend_from_slice(&[0; 8]);
        clause5.extend_from_slice(&rows);
        clause5.extend_from_slice(&records);

        // Clause-12 v2 at p: per-position segments/locators, survivor side tables.
        let c = &x.c;
        let b = x.base_v2;
        let nseg = x.segment_count as usize;
        let mut segs = Vec::new();
        let mut ops = Vec::new();
        let mut max_seg = 0u32;
        let mut d = [0u8; 43];
        for s in 0..nseg {
            x.segment_descriptor(p, s, &mut d)?;
            max_seg = max_seg.max(u32::from_le_bytes(d[7..11].try_into().unwrap()));
            segs.extend_from_slice(&d);
            let shape = x.shape(p)?.unwrap();
            let seg = x.segs[s];
            for k in 0..seg.nops as usize {
                let (ordinal, local, first, count) = x.op(s, k)?;
                let (first, count) = if seg.layer == u32::MAX {
                    (first, count)
                } else {
                    x.op_new(&shape, &x.layers[seg.layer as usize], k, first, count)?
                };
                ops.extend_from_slice(&ordinal.to_le_bytes());
                ops.extend_from_slice(&local.to_le_bytes());
                ops.extend_from_slice(&first.to_le_bytes());
                ops.extend_from_slice(&count.to_le_bytes());
            }
        }
        let mut g = Vec::new();
        g.push(2u8);
        g.extend_from_slice(&c.position_count.to_le_bytes());
        g.extend_from_slice(&x.segment_count.to_le_bytes());
        g.extend_from_slice(&c.operation_count.to_le_bytes());
        g.extend_from_slice(&n.to_le_bytes());
        g.extend_from_slice(&max_seg.to_le_bytes());
        g.extend_from_slice(&crate::hash::sha256(&[
            SEGMENT_DOMAIN,
            &x.segment_count.to_le_bytes(),
            &segs,
        ]));
        g.extend_from_slice(&b[51..59]);
        g.extend_from_slice(&segs);
        g.extend_from_slice(&ops);
        // v2 block: find it in the base after the ops tables.
        let v2_at = 59 + 43 * nseg + ops.len();
        let v2 = &b[v2_at..v2_at + 24];
        let region_bytes = 16 * c.region_count() as usize;
        let tables_at = v2_at + 24 + region_bytes;
        let widths = [24usize, 16, 24, 24];
        let counts = [
            c.prompt_switch_count(),
            c.range_count(),
            c.t_scaled_count(),
            c.patch_count(),
        ];
        let mut kept: [Vec<u8>; 4] = Default::default();
        let mut at = tables_at;
        for table in 0..4 {
            for i in 0..counts[table] as usize {
                let row = &b[at + i * widths[table]..at + (i + 1) * widths[table]];
                let old = u32::from_le_bytes(row[0..4].try_into().unwrap());
                if let Some(new) = survivor(x, old, p)? {
                    kept[table].extend_from_slice(&new.to_le_bytes());
                    kept[table].extend_from_slice(&row[4..]);
                }
            }
            at += counts[table] as usize * widths[table];
        }
        g.extend_from_slice(&v2[0..8]);
        g.extend_from_slice(&v2[8..10]);
        g.extend_from_slice(&((kept[0].len() / 24) as u16).to_le_bytes());
        g.extend_from_slice(&((kept[1].len() / 16) as u32).to_le_bytes());
        g.extend_from_slice(&((kept[2].len() / 24) as u32).to_le_bytes());
        g.extend_from_slice(&((kept[3].len() / 24) as u32).to_le_bytes());
        g.extend_from_slice(&b[v2_at + 24..tables_at]);
        for t in &kept {
            g.extend_from_slice(t);
        }
        let mut geometry_out = Vec::new();
        geometry_out.extend_from_slice(b"\x04PTG4");
        geometry_out.extend_from_slice(&(g.len() as u32).to_le_bytes());
        geometry_out.extend_from_slice(&((windows.len() / 16) as u32).to_le_bytes());
        geometry_out.extend_from_slice(&0u32.to_le_bytes());
        geometry_out.extend_from_slice(&g);
        geometry_out.extend_from_slice(&windows);
        Ok((clause5, geometry_out, payloads))
    }
}
