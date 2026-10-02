// SPDX-License-Identifier: GPL-3.0-only
//! DCGG graph and DCPL plan v2 decoding (profile 1, format version 1).
//!
//! A port of the normative refusal behavior of `python/dcg/graph/v2.py`
//! (`decode_graph`, `decode_plan`) for on-chain use: the same checks in the
//! same order, so a malformed input is refused with the same stable code as
//! the reference. `lower` turns a decoded graph and plan into the program's
//! executable step table. `no_std` + `alloc`; the same source runs on the host
//! and in the SBF image.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

pub const MAX_GRAPH_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PLAN_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NODES: u64 = 4096;
pub const MAX_REGIONS: u64 = 256;
pub const MAX_EDGES: u64 = 16_384;
pub const MAX_PORTS: u64 = 16_384;
pub const MAX_RANK: u64 = 8;
pub const MAX_PORT_BYTES: u64 = 1024 * 1024;
pub const MAX_KERNEL_PARAMETER_BYTES: usize = 64 * 1024;
pub const MAX_PLAN_STEPS: u64 = 16_384;
pub const MAX_OPENING_BYTES: u32 = 4096;
pub const ROOT_PARENT: u32 = 0xFFFF_FFFF;
pub const MODE_CONSENSUS: u32 = 0x434F_4E53;
pub const MODE_OPTIMISTIC: u32 = 0x4F50_5449;
pub const SCHEME_SHA256_MERKLE: u32 = 2;
pub const LAYOUT_FULL_TRACE: u32 = 1;
pub const LAYOUT_CHECKPOINTED_STATE: u32 = 2;
pub const PLAN_HEADER: usize = 162;
pub const GRAPH_HEADER: usize = 32;

/// Stable refusal codes; `name()` matches the reference's `.code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Code {
    Truncated = 1,
    TrailingBytes,
    Magic,
    Version,
    Flags,
    BodyLength,
    Reserved,
    NodeCount,
    PortCount,
    EdgeCount,
    RegionCount,
    StepCount,
    SegmentCount,
    GraphByteLimit,
    PlanByteLimit,
    Presence,
    StateFields,
    ParameterLimit,
    ParameterFields,
    RankLimit,
    Direction,
    ScalarType,
    Alignment,
    Dimension,
    Overflow,
    PortByteLength,
    PortByteLimit,
    PortMaxTooSmall,
    UnknownMode,
    UnknownScheme,
    UnknownLayout,
    Order,
    Duplicate,
    RegionRoot,
    RegionIdReserved,
    RegionParent,
    RegionCycle,
    RegionDepth,
    NodeRegion,
    EmptyRegion,
    PortNode,
    PortLayout,
    EdgePort,
    EdgeLayout,
    InputMultipleSources,
    InputPort,
    InputUnbound,
    OutputUndeclared,
    OutputPort,
    GraphCycle,
    Ordinals,
    StepRegion,
    StepAbi,
    RegionStepCount,
    SegmentRegion,
    SegmentEmpty,
    SegmentScheme,
    SegmentRange,
    SegmentMembership,
    RegionSegmentCount,
    SegmentIds,
    SegmentCoverage,
    BoundaryRegion,
    BoundaryDirection,
    CursorSchema,
    TranslationUnsupported,
    OpeningLimit,
    CostScope,
    CostReference,
    CostCoverage,
    // Lowering (not reference codes): the plan is valid but outside the
    // program's executable subset.
    LowerGraphId,
    LowerKernel,
    LowerShape,
    LowerSource,
    EndpointCount,
}

impl Code {
    pub fn name(self) -> &'static str {
        use Code::*;
        match self {
            Truncated => "TRUNCATED",
            TrailingBytes => "TRAILING_BYTES",
            Magic => "MAGIC",
            Version => "VERSION",
            Flags => "FLAGS",
            BodyLength => "BODY_LENGTH",
            Reserved => "RESERVED",
            NodeCount => "NODE_COUNT",
            PortCount => "PORT_COUNT",
            EdgeCount => "EDGE_COUNT",
            RegionCount => "REGION_COUNT",
            StepCount => "STEP_COUNT",
            SegmentCount => "SEGMENT_COUNT",
            GraphByteLimit => "GRAPH_BYTE_LIMIT",
            PlanByteLimit => "PLAN_BYTE_LIMIT",
            Presence => "PRESENCE",
            StateFields => "STATE_FIELDS",
            ParameterLimit => "PARAMETER_LIMIT",
            ParameterFields => "PARAMETER_FIELDS",
            RankLimit => "RANK_LIMIT",
            Direction => "DIRECTION",
            ScalarType => "SCALAR_TYPE",
            Alignment => "ALIGNMENT",
            Dimension => "DIMENSION",
            Overflow => "OVERFLOW",
            PortByteLength => "PORT_BYTE_LENGTH",
            PortByteLimit => "PORT_BYTE_LIMIT",
            PortMaxTooSmall => "PORT_MAX_TOO_SMALL",
            UnknownMode => "UNKNOWN_MODE",
            UnknownScheme => "UNKNOWN_SCHEME",
            UnknownLayout => "UNKNOWN_LAYOUT",
            Order => "ORDER",
            Duplicate => "DUPLICATE",
            RegionRoot => "REGION_ROOT",
            RegionIdReserved => "REGION_ID_RESERVED",
            RegionParent => "REGION_PARENT",
            RegionCycle => "REGION_CYCLE",
            RegionDepth => "REGION_DEPTH",
            NodeRegion => "NODE_REGION",
            EmptyRegion => "EMPTY_REGION",
            PortNode => "PORT_NODE",
            PortLayout => "PORT_LAYOUT",
            EdgePort => "EDGE_PORT",
            EdgeLayout => "EDGE_LAYOUT",
            InputMultipleSources => "INPUT_MULTIPLE_SOURCES",
            InputPort => "INPUT_PORT",
            InputUnbound => "INPUT_UNBOUND",
            OutputUndeclared => "OUTPUT_UNDECLARED",
            OutputPort => "OUTPUT_PORT",
            GraphCycle => "GRAPH_CYCLE",
            Ordinals => "ORDINALS",
            StepRegion => "STEP_REGION",
            StepAbi => "STEP_ABI",
            RegionStepCount => "REGION_STEP_COUNT",
            SegmentRegion => "SEGMENT_REGION",
            SegmentEmpty => "SEGMENT_EMPTY",
            SegmentScheme => "SEGMENT_SCHEME",
            SegmentRange => "SEGMENT_RANGE",
            SegmentMembership => "SEGMENT_MEMBERSHIP",
            RegionSegmentCount => "REGION_SEGMENT_COUNT",
            SegmentIds => "SEGMENT_IDS",
            SegmentCoverage => "SEGMENT_COVERAGE",
            BoundaryRegion => "BOUNDARY_REGION",
            BoundaryDirection => "BOUNDARY_DIRECTION",
            CursorSchema => "CURSOR_SCHEMA",
            TranslationUnsupported => "TRANSLATION_UNSUPPORTED",
            OpeningLimit => "OPENING_LIMIT",
            CostScope => "COST_SCOPE",
            CostReference => "COST_REFERENCE",
            CostCoverage => "COST_COVERAGE",
            LowerGraphId => "LOWER_GRAPH_ID",
            LowerKernel => "LOWER_KERNEL",
            LowerShape => "LOWER_SHAPE",
            LowerSource => "LOWER_SOURCE",
            EndpointCount => "ENDPOINT_COUNT",
        }
    }
}

type R<T> = Result<T, Code>;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn fixed(&mut self, width: usize) -> R<&'a [u8]> {
        if self.remaining() < width {
            return Err(Code::Truncated);
        }
        let start = self.pos;
        self.pos += width;
        Ok(&self.data[start..self.pos])
    }
    fn uint(&mut self, width: usize) -> R<u64> {
        let b = self.fixed(width)?;
        let mut v = 0u64;
        for (i, x) in b.iter().enumerate() {
            v |= (*x as u64) << (8 * i);
        }
        Ok(v)
    }
    fn u8(&mut self) -> R<u8> {
        Ok(self.uint(1)? as u8)
    }
    fn u16(&mut self) -> R<u16> {
        Ok(self.uint(2)? as u16)
    }
    fn u32(&mut self) -> R<u32> {
        Ok(self.uint(4)? as u32)
    }
    fn u64(&mut self) -> R<u64> {
        self.uint(8)
    }
    fn blob(&mut self) -> R<&'a [u8]> {
        let n = self.u32()? as usize;
        self.fixed(n)
    }
    fn record(&mut self) -> R<Reader<'a>> {
        let n = self.u32()? as usize;
        Ok(Reader::new(self.fixed(n)?))
    }
    fn finish(&self) -> R<()> {
        if self.remaining() != 0 {
            return Err(Code::TrailingBytes);
        }
        Ok(())
    }
}

/// Strictly increasing keys: ORDER if not sorted, DUPLICATE if equal keys.
fn strictly_sorted<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> R<()> {
    let mut dup = false;
    for w in items.windows(2) {
        match key(&w[0]).cmp(&key(&w[1])) {
            core::cmp::Ordering::Greater => return Err(Code::Order),
            core::cmp::Ordering::Equal => dup = true,
            _ => {}
        }
    }
    if dup {
        return Err(Code::Duplicate);
    }
    Ok(())
}

fn mode_ok(id: u32, v: u16) -> R<()> {
    if (id == MODE_CONSENSUS || id == MODE_OPTIMISTIC) && v == 1 {
        Ok(())
    } else {
        Err(Code::UnknownMode)
    }
}
fn scheme_ok(id: u32, v: u16) -> R<()> {
    if id == SCHEME_SHA256_MERKLE && v == 1 {
        Ok(())
    } else {
        Err(Code::UnknownScheme)
    }
}
fn layout_ok(id: u32, v: u16) -> R<()> {
    if (id == LAYOUT_FULL_TRACE || id == LAYOUT_CHECKPOINTED_STATE) && v == 1 {
        Ok(())
    } else {
        Err(Code::UnknownLayout)
    }
}

fn scalar_width(t: u8) -> Option<u64> {
    match t {
        1 | 2 | 9 => Some(1),
        3 | 4 => Some(2),
        5 | 6 => Some(4),
        7 | 8 => Some(8),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct Node<'a> {
    pub node_id: u32,
    pub kernel_id: &'a [u8],
    pub semantic_version: u16,
    pub abi_version: u16,
    pub region_id: u32,
    pub state_schema_id: u32,
    pub state_schema_version: u16,
    pub max_state_bytes: u32,
    pub parameter_layout_id: u32,
    pub parameter_layout_version: u16,
    pub parameters: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct Port {
    pub node_id: u32,
    pub direction: u8,
    pub port_id: u16,
    pub layout_id: u32,
    pub layout_version: u16,
    pub scalar_type: u8,
    pub alignment: u16,
    pub byte_length: u32,
    pub max_byte_length: u32,
    pub dimensions: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub source_node: u32,
    pub source_port: u16,
    pub destination_node: u32,
    pub destination_port: u16,
}

#[derive(Clone, Debug)]
pub struct Region {
    pub region_id: u32,
    pub parent_region_id: u32,
    pub mode_id: u32,
    pub mode_version: u16,
    pub scheme_id: u32,
    pub scheme_version: u16,
    pub layout_id: u32,
    pub layout_version: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub external_id: u32,
    pub node_id: u32,
    pub port_id: u16,
}

#[derive(Debug)]
pub struct Graph<'a> {
    pub nodes: Vec<Node<'a>>,
    pub ports: Vec<Port>,
    pub edges: Vec<Edge>,
    pub regions: Vec<Region>,
    pub inputs: Vec<Endpoint>,
    pub outputs: Vec<Endpoint>,
}

fn port_shape(p: &Port) -> R<()> {
    if p.direction > 1 {
        return Err(Code::Direction);
    }
    let width = scalar_width(p.scalar_type).ok_or(Code::ScalarType)?;
    if p.dimensions.len() as u64 > MAX_RANK {
        return Err(Code::RankLimit);
    }
    if p.alignment == 0 || p.alignment & (p.alignment - 1) != 0 {
        return Err(Code::Alignment);
    }
    let mut product: u64 = 1;
    for d in &p.dimensions {
        if *d == 0 {
            return Err(Code::Dimension);
        }
        product *= *d as u64;
        if product > u32::MAX as u64 {
            return Err(Code::Overflow);
        }
    }
    let expected = product * width;
    if expected > u32::MAX as u64 || expected != p.byte_length as u64 {
        return Err(Code::PortByteLength);
    }
    if p.byte_length as u64 > MAX_PORT_BYTES || p.max_byte_length as u64 > MAX_PORT_BYTES {
        return Err(Code::PortByteLimit);
    }
    if p.max_byte_length < p.byte_length {
        return Err(Code::PortMaxTooSmall);
    }
    Ok(())
}

fn node_fields(n: &Node) -> R<()> {
    if n.semantic_version == 0 || n.abi_version == 0 {
        return Err(Code::Version);
    }
    let state_present = n.state_schema_id != 0 || n.state_schema_version != 0 || n.max_state_bytes != 0;
    if state_present && !(n.state_schema_id != 0 && n.state_schema_version != 0 && n.max_state_bytes != 0) {
        return Err(Code::StateFields);
    }
    let parameter_present = !n.parameters.is_empty();
    if parameter_present && !(n.parameter_layout_id != 0 && n.parameter_layout_version != 0) {
        return Err(Code::ParameterFields);
    }
    if !parameter_present && (n.parameter_layout_id != 0 || n.parameter_layout_version != 0) {
        return Err(Code::ParameterFields);
    }
    if n.parameters.len() > MAX_KERNEL_PARAMETER_BYTES {
        return Err(Code::ParameterLimit);
    }
    Ok(())
}

fn decode_node<'a>(r: &mut Reader<'a>) -> R<Node<'a>> {
    let mut q = r.record()?;
    let node_id = q.u32()?;
    let kernel_id = q.fixed(16)?;
    let semantic_version = q.u16()?;
    let abi_version = q.u16()?;
    let region_id = q.u32()?;
    let state_present = q.u8()?;
    if state_present > 1 {
        return Err(Code::Presence);
    }
    let state_schema_id = q.u32()?;
    let state_schema_version = q.u16()?;
    let max_state_bytes = q.u32()?;
    let parameter_layout_id = q.u32()?;
    let parameter_layout_version = q.u16()?;
    let plen = q.u32()? as usize;
    let parameters = q.fixed(plen)?;
    q.finish()?;
    let any_state = state_schema_id != 0 || state_schema_version != 0 || max_state_bytes != 0;
    if state_present == 0 && any_state {
        return Err(Code::StateFields);
    }
    if state_present == 1 && !(state_schema_id != 0 && state_schema_version != 0 && max_state_bytes != 0) {
        return Err(Code::StateFields);
    }
    if parameters.len() > MAX_KERNEL_PARAMETER_BYTES {
        return Err(Code::ParameterLimit);
    }
    if !parameters.is_empty() != (parameter_layout_id != 0 && parameter_layout_version != 0) {
        return Err(Code::ParameterFields);
    }
    if parameters.is_empty() && (parameter_layout_id != 0 || parameter_layout_version != 0) {
        return Err(Code::ParameterFields);
    }
    Ok(Node {
        node_id,
        kernel_id,
        semantic_version,
        abi_version,
        region_id,
        state_schema_id,
        state_schema_version,
        max_state_bytes,
        parameter_layout_id,
        parameter_layout_version,
        parameters,
    })
}

fn decode_port(r: &mut Reader) -> R<Port> {
    let mut q = r.record()?;
    let node_id = q.u32()?;
    let direction = q.u8()?;
    let port_id = q.u16()?;
    let layout_id = q.u32()?;
    let layout_version = q.u16()?;
    let scalar_type = q.u8()?;
    let rank = q.u8()? as u64;
    let alignment = q.u16()?;
    let reserved = q.u16()?;
    let byte_length = q.u32()?;
    let max_byte_length = q.u32()?;
    if reserved != 0 {
        return Err(Code::Reserved);
    }
    if rank > MAX_RANK {
        return Err(Code::RankLimit);
    }
    let mut dimensions = Vec::with_capacity(rank as usize);
    for _ in 0..rank {
        dimensions.push(q.u32()?);
    }
    q.finish()?;
    let port = Port {
        node_id,
        direction,
        port_id,
        layout_id,
        layout_version,
        scalar_type,
        alignment,
        byte_length,
        max_byte_length,
        dimensions,
    };
    port_shape(&port)?;
    Ok(port)
}

fn decode_edge(r: &mut Reader) -> R<Edge> {
    let mut q = r.record()?;
    let e = Edge { source_node: q.u32()?, source_port: q.u16()?, destination_node: q.u32()?, destination_port: q.u16()? };
    q.finish()?;
    Ok(e)
}

fn decode_region(r: &mut Reader) -> R<Region> {
    let mut q = r.record()?;
    let region = Region {
        region_id: q.u32()?,
        parent_region_id: q.u32()?,
        mode_id: q.u32()?,
        mode_version: q.u16()?,
        scheme_id: q.u32()?,
        scheme_version: q.u16()?,
        layout_id: q.u32()?,
        layout_version: q.u16()?,
    };
    for _ in 0..3 {
        q.blob()?;
    }
    q.finish()?;
    Ok(region)
}

fn decode_endpoint(r: &mut Reader) -> R<Endpoint> {
    let mut q = r.record()?;
    let external_id = q.u32()?;
    let node_id = q.u32()?;
    let port_id = q.u16()?;
    let reserved = q.u16()?;
    q.finish()?;
    if reserved != 0 {
        return Err(Code::Reserved);
    }
    Ok(Endpoint { external_id, node_id, port_id })
}

fn find<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K, want: &K) -> Option<usize> {
    items.binary_search_by(|x| key(x).cmp(want)).ok()
}

/// Region-tree checks shared by DCGG and DCPL: unique root at zero with the
/// sentinel parent, known parents, no cycle, depth at most eight.
fn region_tree(ids: &[(u32, u32)]) -> R<()> {
    // `ids` is sorted by region id (checked by the caller).
    let get = |id: u32| ids.binary_search_by(|x| x.0.cmp(&id)).ok().map(|i| ids[i]);
    match get(0) {
        Some((_, parent)) if parent == ROOT_PARENT => {}
        _ => return Err(Code::RegionRoot),
    }
    if ids.iter().filter(|(_, p)| *p == ROOT_PARENT).count() != 1 {
        return Err(Code::RegionRoot);
    }
    Ok(())
}

fn region_walk(ids: &[(u32, u32)]) -> R<()> {
    let get = |id: u32| ids.binary_search_by(|x| x.0.cmp(&id)).ok().map(|i| ids[i]);
    for &(rid, parent) in ids {
        let _ = parent;
        let mut current = get(rid).unwrap();
        let mut seen: Vec<u32> = Vec::new();
        let mut depth = 1;
        while current.0 != 0 {
            if seen.contains(&current.0) {
                return Err(Code::RegionCycle);
            }
            seen.push(current.0);
            current = get(current.1).ok_or(Code::RegionParent)?;
            depth += 1;
            if depth > 8 {
                return Err(Code::RegionDepth);
            }
        }
    }
    Ok(())
}

fn validate_graph(g: &Graph) -> R<()> {
    if g.nodes.is_empty() || g.nodes.len() as u64 > MAX_NODES {
        return Err(Code::NodeCount);
    }
    if g.ports.len() as u64 > MAX_PORTS {
        return Err(Code::PortCount);
    }
    if g.edges.len() as u64 > MAX_EDGES {
        return Err(Code::EdgeCount);
    }
    if g.regions.is_empty() || g.regions.len() as u64 > MAX_REGIONS {
        return Err(Code::RegionCount);
    }
    if g.inputs.len() > u16::MAX as usize || g.outputs.len() > u16::MAX as usize {
        return Err(Code::EndpointCount);
    }
    strictly_sorted(&g.nodes, |n| n.node_id)?;
    strictly_sorted(&g.ports, |p| (p.node_id, p.direction, p.port_id))?;
    strictly_sorted(&g.edges, |e| (e.destination_node, e.destination_port, e.source_node, e.source_port))?;
    strictly_sorted(&g.regions, |r| r.region_id)?;
    strictly_sorted(&g.inputs, |i| i.external_id)?;
    strictly_sorted(&g.outputs, |o| o.external_id)?;

    let ids: Vec<(u32, u32)> = g.regions.iter().map(|r| (r.region_id, r.parent_region_id)).collect();
    region_tree(&ids)?;
    for r in &g.regions {
        if r.region_id == ROOT_PARENT {
            return Err(Code::RegionIdReserved);
        }
        if r.region_id != 0 && find(&ids, |x| x.0, &r.parent_region_id).is_none() {
            return Err(Code::RegionParent);
        }
        if r.region_id != 0 && r.parent_region_id == r.region_id {
            return Err(Code::RegionCycle);
        }
        mode_ok(r.mode_id, r.mode_version)?;
        scheme_ok(r.scheme_id, r.scheme_version)?;
        layout_ok(r.layout_id, r.layout_version)?;
    }
    region_walk(&ids)?;

    for n in &g.nodes {
        if find(&ids, |x| x.0, &n.region_id).is_none() {
            return Err(Code::NodeRegion);
        }
        if n.parameters.len() > MAX_KERNEL_PARAMETER_BYTES {
            return Err(Code::ParameterLimit);
        }
        node_fields(n)?;
    }
    for r in &g.regions {
        let has_node = g.nodes.iter().any(|n| n.region_id == r.region_id);
        let has_child = g.regions.iter().any(|c| c.region_id != 0 && c.parent_region_id == r.region_id);
        if !has_node && !has_child {
            return Err(Code::EmptyRegion);
        }
    }
    for p in &g.ports {
        if find(&g.nodes, |n| n.node_id, &p.node_id).is_none() {
            return Err(Code::PortNode);
        }
        port_shape(p)?;
        if p.layout_id == 0 || p.layout_version == 0 {
            return Err(Code::PortLayout);
        }
    }
    let port = |node: u32, dir: u8, id: u16| find(&g.ports, |p| (p.node_id, p.direction, p.port_id), &(node, dir, id)).map(|i| &g.ports[i]);

    // (node, port) keys of supplied inputs and used outputs.
    let mut supplied: Vec<(u32, u16)> = Vec::new();
    let mut used: Vec<(u32, u16)> = Vec::new();
    let mut adjacency: Vec<(u32, u32)> = Vec::new();
    for e in &g.edges {
        let (src, dst) = match (port(e.source_node, 1, e.source_port), port(e.destination_node, 0, e.destination_port)) {
            (Some(s), Some(d)) => (s, d),
            _ => return Err(Code::EdgePort),
        };
        if (src.layout_id, src.layout_version, src.scalar_type, &src.dimensions, src.byte_length, src.alignment)
            != (dst.layout_id, dst.layout_version, dst.scalar_type, &dst.dimensions, dst.byte_length, dst.alignment)
        {
            return Err(Code::EdgeLayout);
        }
        let key = (e.destination_node, e.destination_port);
        if supplied.contains(&key) {
            return Err(Code::InputMultipleSources);
        }
        supplied.push(key);
        used.push((e.source_node, e.source_port));
        if !adjacency.contains(&(e.source_node, e.destination_node)) {
            adjacency.push((e.source_node, e.destination_node));
        }
    }
    let mut external: Vec<(u32, u16)> = Vec::new();
    for i in &g.inputs {
        let key = (i.node_id, i.port_id);
        if port(i.node_id, 0, i.port_id).is_none() {
            return Err(Code::InputPort);
        }
        if supplied.contains(&key) || external.contains(&key) {
            return Err(Code::InputMultipleSources);
        }
        external.push(key);
        supplied.push(key);
    }
    for p in &g.ports {
        let key = (p.node_id, p.port_id);
        if p.direction == 0 && !supplied.contains(&key) {
            return Err(Code::InputUnbound);
        }
        if p.direction == 1 && !used.contains(&key) && !g.outputs.iter().any(|o| (o.node_id, o.port_id) == key) {
            return Err(Code::OutputUndeclared);
        }
    }
    for o in &g.outputs {
        if port(o.node_id, 1, o.port_id).is_none() {
            return Err(Code::OutputPort);
        }
    }
    // Kahn's algorithm over distinct node-to-node arcs.
    let mut indegree: Vec<u32> = g.nodes.iter().map(|n| adjacency.iter().filter(|a| a.1 == n.node_id).count() as u32).collect();
    let mut ready: Vec<usize> = (0..g.nodes.len()).filter(|i| indegree[*i] == 0).collect();
    let mut visited = 0;
    while let Some(i) = ready.pop() {
        visited += 1;
        let id = g.nodes[i].node_id;
        for a in adjacency.iter().filter(|a| a.0 == id) {
            let j = find(&g.nodes, |n| n.node_id, &a.1).ok_or(Code::EdgePort)?;
            indegree[j] -= 1;
            if indegree[j] == 0 {
                ready.push(j);
            }
        }
    }
    if visited != g.nodes.len() {
        return Err(Code::GraphCycle);
    }
    Ok(())
}

pub fn decode_graph(data: &[u8]) -> R<Graph<'_>> {
    if data.len() > MAX_GRAPH_BYTES {
        return Err(Code::GraphByteLimit);
    }
    let mut r = Reader::new(data);
    if r.fixed(4)? != b"DCGG" {
        return Err(Code::Magic);
    }
    if r.u16()? != 1 {
        return Err(Code::Version);
    }
    if r.u16()? != 0 {
        return Err(Code::Flags);
    }
    let body_length = r.u32()? as usize;
    let node_count = r.u32()? as u64;
    let port_count = r.u32()? as u64;
    let edge_count = r.u32()? as u64;
    let region_count = r.u16()? as u64;
    let input_count = r.u16()?;
    let output_count = r.u16()?;
    if r.u16()? != 0 {
        return Err(Code::Reserved);
    }
    if body_length != r.remaining() {
        return Err(Code::BodyLength);
    }
    if !(1..=MAX_NODES).contains(&node_count) {
        return Err(Code::NodeCount);
    }
    if port_count > MAX_PORTS {
        return Err(Code::PortCount);
    }
    if edge_count > MAX_EDGES {
        return Err(Code::EdgeCount);
    }
    if !(1..=MAX_REGIONS).contains(&region_count) {
        return Err(Code::RegionCount);
    }
    let mut g = Graph {
        nodes: Vec::with_capacity(node_count as usize),
        ports: Vec::new(),
        edges: Vec::new(),
        regions: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    for _ in 0..node_count {
        g.nodes.push(decode_node(&mut r)?);
    }
    for _ in 0..port_count {
        g.ports.push(decode_port(&mut r)?);
    }
    for _ in 0..edge_count {
        g.edges.push(decode_edge(&mut r)?);
    }
    for _ in 0..region_count {
        g.regions.push(decode_region(&mut r)?);
    }
    for _ in 0..input_count {
        g.inputs.push(decode_endpoint(&mut r)?);
    }
    for _ in 0..output_count {
        g.outputs.push(decode_endpoint(&mut r)?);
    }
    r.finish()?;
    validate_graph(&g)?;
    Ok(g)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortRef {
    pub node_id: u32,
    pub direction: u8,
    pub port_id: u16,
}

#[derive(Clone, Debug)]
pub struct RegionPlan {
    pub region_id: u32,
    pub parent_region_id: u32,
    pub mode_id: u32,
    pub mode_version: u16,
    pub scheme_id: u32,
    pub scheme_version: u16,
    pub layout_id: u32,
    pub layout_version: u16,
    pub direct_step_count: u32,
    pub segment_count: u32,
}

#[derive(Clone, Debug)]
pub struct Step {
    pub ordinal: u64,
    pub region_id: u32,
    pub segment_id: u32,
    pub node_id: u32,
    pub kernel_step: u32,
    pub decomposition_id: u32,
    pub decomposition_version: u16,
    pub inputs: Vec<PortRef>,
    pub outputs: Vec<PortRef>,
}

#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub region_id: u32,
    pub segment_id: u32,
    pub first_step: u64,
    pub step_count: u32,
    pub root_scheme_id: u32,
    pub root_scheme_version: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Boundary {
    pub source_region: u32,
    pub destination_region: u32,
    pub source: PortRef,
    pub destination: PortRef,
    pub layout_id: u32,
    pub layout_version: u16,
    pub scheme_id: u32,
    pub scheme_version: u16,
    pub cursor_schema_id: u32,
    pub cursor_schema_version: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Cost {
    pub scope_kind: u8,
    pub region_id: u32,
    pub step_ordinal: u64,
    pub max_opening_bytes: u32,
}

#[derive(Debug)]
pub struct Plan<'a> {
    pub graph_id: &'a [u8],
    pub app_image_id: &'a [u8],
    pub kernel_manifest_root: &'a [u8],
    pub regions: Vec<RegionPlan>,
    pub steps: Vec<Step>,
    pub segments: Vec<Segment>,
    pub boundaries: Vec<Boundary>,
    pub translation_count: u32,
    pub costs: Vec<Cost>,
}

fn port_ref(q: &mut Reader) -> R<PortRef> {
    Ok(PortRef { node_id: q.u32()?, direction: q.u8()?, port_id: q.u16()? })
}

fn validate_plan(p: &Plan) -> R<()> {
    if p.regions.is_empty() || p.regions.len() as u64 > MAX_REGIONS {
        return Err(Code::RegionCount);
    }
    if p.steps.is_empty() || p.steps.len() as u64 > MAX_PLAN_STEPS {
        return Err(Code::StepCount);
    }
    if p.segments.len() as u64 > MAX_PLAN_STEPS {
        return Err(Code::SegmentCount);
    }
    strictly_sorted(&p.regions, |r| r.region_id)?;
    strictly_sorted(&p.steps, |s| s.ordinal)?;
    strictly_sorted(&p.segments, |s| (s.region_id, s.segment_id))?;
    strictly_sorted(&p.boundaries, |b| (b.source_region, b.destination_region, b.source, b.destination))?;
    strictly_sorted(&p.costs, |c| (c.scope_kind, c.region_id, c.step_ordinal))?;

    let ids: Vec<(u32, u32)> = p.regions.iter().map(|r| (r.region_id, r.parent_region_id)).collect();
    let known = |id: u32| find(&ids, |x| x.0, &id).is_some();
    region_tree(&ids)?;
    for r in &p.regions {
        if r.region_id == ROOT_PARENT {
            return Err(Code::RegionIdReserved);
        }
        if r.region_id != 0 && !known(r.parent_region_id) {
            return Err(Code::RegionParent);
        }
        mode_ok(r.mode_id, r.mode_version)?;
        scheme_ok(r.scheme_id, r.scheme_version)?;
        layout_ok(r.layout_id, r.layout_version)?;
    }
    region_walk(&ids)?;

    for (i, s) in p.steps.iter().enumerate() {
        if s.ordinal != i as u64 {
            return Err(Code::Ordinals);
        }
    }
    let mut node_kernel_steps: Vec<(u32, u32)> = Vec::new();
    for s in &p.steps {
        if !known(s.region_id) {
            return Err(Code::StepRegion);
        }
        if s.decomposition_id == 0 || s.decomposition_version == 0 {
            return Err(Code::StepAbi);
        }
        if node_kernel_steps.contains(&(s.node_id, s.kernel_step)) {
            return Err(Code::Duplicate);
        }
        node_kernel_steps.push((s.node_id, s.kernel_step));
        strictly_sorted(&s.inputs, |r| *r)?;
        strictly_sorted(&s.outputs, |r| *r)?;
        if s.inputs.iter().any(|r| r.direction != 0) || s.outputs.iter().any(|r| r.direction != 1) {
            return Err(Code::Direction);
        }
    }
    for r in &p.regions {
        if r.direct_step_count as usize != p.steps.iter().filter(|s| s.region_id == r.region_id).count() {
            return Err(Code::RegionStepCount);
        }
    }
    let n = p.steps.len() as u64;
    let mut covered: Vec<u64> = Vec::new();
    for g in &p.segments {
        let region = find(&p.regions, |r| r.region_id, &g.region_id).map(|i| &p.regions[i]).ok_or(Code::SegmentRegion)?;
        if g.step_count == 0 {
            return Err(Code::SegmentEmpty);
        }
        if (g.root_scheme_id, g.root_scheme_version) != (region.scheme_id, region.scheme_version) {
            return Err(Code::SegmentScheme);
        }
        if g.first_step + g.step_count as u64 > n {
            return Err(Code::SegmentRange);
        }
        for ordinal in g.first_step..g.first_step + g.step_count as u64 {
            let s = &p.steps[ordinal as usize];
            if (s.region_id, s.segment_id) != (g.region_id, g.segment_id) {
                return Err(Code::SegmentMembership);
            }
            covered.push(ordinal);
        }
    }
    for r in &p.regions {
        let local: Vec<u32> = p.segments.iter().filter(|g| g.region_id == r.region_id).map(|g| g.segment_id).collect();
        if r.segment_count as usize != local.len() {
            return Err(Code::RegionSegmentCount);
        }
        if local.iter().enumerate().any(|(i, id)| *id != i as u32) {
            return Err(Code::SegmentIds);
        }
    }
    covered.sort_unstable();
    if covered.len() as u64 != n || covered.iter().enumerate().any(|(i, o)| *o != i as u64) {
        return Err(Code::SegmentCoverage);
    }
    for s in &p.steps {
        if !p.segments.iter().any(|g| {
            g.region_id == s.region_id
                && g.segment_id == s.segment_id
                && g.first_step <= s.ordinal
                && s.ordinal < g.first_step + g.step_count as u64
        }) {
            return Err(Code::SegmentMembership);
        }
    }
    for b in &p.boundaries {
        if !known(b.source_region) || !known(b.destination_region) || b.source_region == b.destination_region {
            return Err(Code::BoundaryRegion);
        }
        if b.source.direction != 1 || b.destination.direction != 0 {
            return Err(Code::BoundaryDirection);
        }
        layout_ok(b.layout_id, b.layout_version)?;
        scheme_ok(b.scheme_id, b.scheme_version)?;
        if (b.cursor_schema_id != 0) != (b.cursor_schema_version != 0) {
            return Err(Code::CursorSchema);
        }
    }
    if p.translation_count != 0 {
        return Err(Code::TranslationUnsupported);
    }
    let mut cost_steps: Vec<u64> = Vec::new();
    let mut cost_regions: Vec<u32> = Vec::new();
    let mut run_costs = 0;
    for c in &p.costs {
        match c.scope_kind {
            1 => {
                if !known(c.region_id) || c.step_ordinal >= n {
                    return Err(Code::CostReference);
                }
                if p.steps[c.step_ordinal as usize].region_id != c.region_id {
                    return Err(Code::CostReference);
                }
                cost_steps.push(c.step_ordinal);
            }
            2 => {
                if !known(c.region_id) || c.step_ordinal != 0 {
                    return Err(Code::CostReference);
                }
                cost_regions.push(c.region_id);
            }
            3 => {
                if c.region_id != 0 || c.step_ordinal != 0 {
                    return Err(Code::CostReference);
                }
                run_costs += 1;
            }
            _ => return Err(Code::CostScope),
        }
        if c.max_opening_bytes > MAX_OPENING_BYTES {
            return Err(Code::OpeningLimit);
        }
    }
    cost_steps.sort_unstable();
    cost_steps.dedup();
    cost_regions.sort_unstable();
    cost_regions.dedup();
    if cost_steps.len() as u64 != n || cost_regions.len() != p.regions.len() || run_costs != 1 {
        return Err(Code::CostCoverage);
    }
    Ok(())
}

pub fn decode_plan(data: &[u8]) -> R<Plan<'_>> {
    if data.len() > MAX_PLAN_BYTES {
        return Err(Code::PlanByteLimit);
    }
    let mut r = Reader::new(data);
    if r.fixed(4)? != b"DCPL" {
        return Err(Code::Magic);
    }
    if r.u16()? != 1 {
        return Err(Code::Version);
    }
    if r.u16()? != 0 {
        return Err(Code::Flags);
    }
    let body_length = r.u32()? as usize;
    let graph_id = r.fixed(32)?;
    let _compiler = r.fixed(16)?;
    let _versions = r.fixed(6)?;
    let _ruleset = r.fixed(6)?;
    let app_image_id = r.fixed(32)?;
    let kernel_manifest_root = r.fixed(32)?;
    let region_count = r.u16()? as u64;
    let step_count = r.u32()? as u64;
    let segment_count = r.u32()? as u64;
    let boundary_count = r.u32()?;
    let translation_count = r.u32()?;
    let cost_count = r.u32()?;
    let compiler_parameter_length = r.u32()? as usize;
    if !(1..=MAX_REGIONS).contains(&region_count) {
        return Err(Code::RegionCount);
    }
    if !(1..=MAX_PLAN_STEPS).contains(&step_count) {
        return Err(Code::StepCount);
    }
    if segment_count > MAX_PLAN_STEPS {
        return Err(Code::SegmentCount);
    }
    if body_length != r.remaining() {
        return Err(Code::BodyLength);
    }
    r.fixed(compiler_parameter_length)?;
    let mut p = Plan {
        graph_id,
        app_image_id,
        kernel_manifest_root,
        regions: Vec::with_capacity(region_count as usize),
        steps: Vec::with_capacity(step_count as usize),
        segments: Vec::new(),
        boundaries: Vec::new(),
        translation_count,
        costs: Vec::new(),
    };
    for _ in 0..region_count {
        let mut q = r.record()?;
        p.regions.push(RegionPlan {
            region_id: q.u32()?,
            parent_region_id: q.u32()?,
            mode_id: q.u32()?,
            mode_version: q.u16()?,
            scheme_id: q.u32()?,
            scheme_version: q.u16()?,
            layout_id: q.u32()?,
            layout_version: q.u16()?,
            direct_step_count: q.u32()?,
            segment_count: q.u32()?,
        });
        for _ in 0..3 {
            q.blob()?;
        }
        q.finish()?;
    }
    for _ in 0..step_count {
        let mut q = r.record()?;
        let ordinal = q.u64()?;
        let region_id = q.u32()?;
        let segment_id = q.u32()?;
        let node_id = q.u32()?;
        let kernel_step = q.u32()?;
        let decomposition_id = q.u32()?;
        let decomposition_version = q.u16()?;
        let n_in = q.u16()?;
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            inputs.push(port_ref(&mut q)?);
        }
        let n_out = q.u16()?;
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            outputs.push(port_ref(&mut q)?);
        }
        q.finish()?;
        p.steps.push(Step { ordinal, region_id, segment_id, node_id, kernel_step, decomposition_id, decomposition_version, inputs, outputs });
    }
    for _ in 0..segment_count {
        let mut q = r.record()?;
        p.segments.push(Segment {
            region_id: q.u32()?,
            segment_id: q.u32()?,
            first_step: q.u64()?,
            step_count: q.u32()?,
            root_scheme_id: q.u32()?,
            root_scheme_version: q.u16()?,
        });
        q.finish()?;
    }
    for _ in 0..boundary_count {
        let mut q = r.record()?;
        let source_region = q.u32()?;
        let destination_region = q.u32()?;
        let source = port_ref(&mut q)?;
        let destination = port_ref(&mut q)?;
        p.boundaries.push(Boundary {
            source_region,
            destination_region,
            source,
            destination,
            layout_id: q.u32()?,
            layout_version: q.u16()?,
            scheme_id: q.u32()?,
            scheme_version: q.u16()?,
            cursor_schema_id: q.u32()?,
            cursor_schema_version: q.u16()?,
        });
        q.finish()?;
    }
    for _ in 0..translation_count {
        let mut q = r.record()?;
        q.fixed(4 + 2 + 4 + 2 + 16 + 2 + 2 + 4 + 2 + 4 + 2 + 4 + 4 + 8 + 2)?;
        let max_opening = q.u32()?;
        q.finish()?;
        let _ = max_opening;
    }
    for _ in 0..cost_count {
        let mut q = r.record()?;
        let scope_kind = q.u8()?;
        let region_id = q.u32()?;
        let step_ordinal = q.u64()?;
        let _max_cu = q.u64()?;
        let _max_accounts = q.u16()?;
        for _ in 0..8 {
            q.u32()?;
        }
        let max_opening_bytes = q.u32()?;
        q.finish()?;
        p.costs.push(Cost { scope_kind, region_id, step_ordinal, max_opening_bytes });
    }
    r.finish()?;
    validate_plan(&p)?;
    Ok(p)
}

/// The executable step table of the DCG graph_v2 program:
/// `n_inputs:u16 n_steps:u16` then per step `kernel:u16 n:u8 refs:u16*n`,
/// where a ref is a cell index (graph inputs first, by external id, then one
/// output cell per step, by ordinal).
///
/// `kernel_code` maps a node's `(kernel_id, semantic_version, abi_version)` to
/// the image's registered kernel code. Lowering refuses what the program
/// cannot execute: a step with other than one output, a node with more than
/// one step, or an input whose producer is not an earlier step.
pub fn lower(g: &Graph, p: &Plan, kernel_code: impl Fn(&[u8], u16, u16) -> Option<u16>) -> R<Vec<u8>> {
    let n_inputs = g.inputs.len();
    if n_inputs > u16::MAX as usize || p.steps.len() > u16::MAX as usize {
        return Err(Code::LowerShape);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(n_inputs as u16).to_le_bytes());
    out.extend_from_slice(&(p.steps.len() as u16).to_le_bytes());
    // Output cell of each (node, output port), filled in ordinal order.
    let mut produced: Vec<(u32, u16, u16)> = Vec::new();
    for s in &p.steps {
        let node = find(&g.nodes, |n| n.node_id, &s.node_id).map(|i| &g.nodes[i]).ok_or(Code::LowerShape)?;
        if s.kernel_step != 0 || s.outputs.len() != 1 || s.inputs.len() > 255 {
            return Err(Code::LowerShape);
        }
        let code = kernel_code(node.kernel_id, node.semantic_version, node.abi_version).ok_or(Code::LowerKernel)?;
        out.extend_from_slice(&code.to_le_bytes());
        out.push(s.inputs.len() as u8);
        for input in &s.inputs {
            if input.node_id != s.node_id {
                return Err(Code::LowerShape);
            }
            let cell = if let Some(i) = g.inputs.iter().position(|e| (e.node_id, e.port_id) == (input.node_id, input.port_id)) {
                i as u16
            } else {
                let e = g
                    .edges
                    .iter()
                    .find(|e| (e.destination_node, e.destination_port) == (input.node_id, input.port_id))
                    .ok_or(Code::LowerSource)?;
                produced
                    .iter()
                    .find(|(n, port, _)| (*n, *port) == (e.source_node, e.source_port))
                    .map(|(_, _, cell)| *cell)
                    .ok_or(Code::LowerSource)?
            };
            out.extend_from_slice(&cell.to_le_bytes());
        }
        let o = s.outputs[0];
        if o.node_id != s.node_id {
            return Err(Code::LowerShape);
        }
        produced.push((o.node_id, o.port_id, (n_inputs as u64 + s.ordinal) as u16));
    }
    Ok(out)
}
