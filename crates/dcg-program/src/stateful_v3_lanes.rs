// SPDX-License-Identifier: GPL-3.0-only

//! Stateful v3 render lanes (design `docs/design/stateful-session-lanes-v1.md`
//! §10). A session declares up to `MAX_LANES` lanes at open. A publication on
//! lane `k` captures the state at cursor `c` into the lane's workspace (the
//! only step that reads the state, and `ADVANCE` waits while it is open),
//! renders from that workspace alone into the lane's scratch, and commits the
//! scratch to the session's shared views, newest cursor only. Render steps
//! write only the lane's own accounts and read no session or state account,
//! so they overlap the next advance and the other lanes.

use super::*;
use crate::kernel::LanePhase;

pub const MAX_LANES: usize = 4;
pub const OP_CREATE: u8 = 4;
pub const OP_GROW: u8 = 5;
pub const OP_CAPTURE_BEGIN: u8 = 6;
pub const OP_CAPTURE_RUN: u8 = 7;
pub const OP_CAPTURE_END: u8 = 8;
pub const OP_RUN: u8 = 9;
pub const OP_COMMIT: u8 = 10;
pub const OP_ABORT: u8 = 11;
pub const OP_FIRST: u8 = OP_CREATE;
pub const OP_LAST: u8 = OP_ABORT;

pub const KIND_LANE: u8 = 8;
pub const KIND_LANE_WORKSPACE: u8 = 9;
pub const KIND_LANE_SCRATCH: u8 = 10;
pub const LANE_SEED: &[u8] = b"dcg-lane-v3";
pub const LANE_MAGIC: &[u8; 4] = b"DLN3";
pub const LANE_BYTES: usize = 512;
/// Lane workspace and scratch view roles: `WORKSPACE_ROLE_BASE + k`,
/// `SCRATCH_ROLE_BASE + k`.
pub const WORKSPACE_ROLE_BASE: u8 = 0xE0;
pub const SCRATCH_ROLE_BASE: u8 = 0xE8;

const IDLE: u8 = 0;
const CAPTURING: u8 = 1;
const RENDERING: u8 = 2;

// Lane record layout (512 bytes):
// 0 magic, 4 version:u16, 6 kind, 7 lane, 8 session[32], 40 authority[32],
// 72 status, 73 bump, 74 view_count, 75 zero,
// 76 captured:u32, 80 capture_cursor:u32, 84 capture_total:u32,
// 88 render_cursor:u32, 92 render_total:u32, 96 compute_units:u32,
// 100 workspace[32], 132 scratch[32], 164 resource[32], 196 commitment[32],
// 228 resource schema id:u32, 232 version:u16, 234 kernel id[16],
// 250 semantic:u16, 252 abi:u16, 254 zero[2],
// 256 views: 16 x (role:u8 source_offset:u32 len:u32), 400 zero.
const L_VIEWS: usize = 256;
const L_VIEW_BYTES: usize = 9;
const L_END: usize = L_VIEWS + MAX_VIEW_OUTPUTS * L_VIEW_BYTES;

pub fn is_lane_kind(kind: u8) -> bool {
    matches!(kind, KIND_LANE | KIND_LANE_WORKSPACE | KIND_LANE_SCRATCH)
}

pub fn lane_pda(program: &Pubkey, session: &Pubkey, lane: u8) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[LANE_SEED, session.as_ref(), &[lane]], program);
    (*bump.address(), bump)
}

#[derive(Clone, Debug)]
struct Lane {
    lane: u8,
    session: Pubkey,
    authority: Pubkey,
    status: u8,
    bump: u8,
    captured: u32,
    capture_cursor: u32,
    capture_total: u32,
    render_cursor: u32,
    render_total: u32,
    compute_units: u32,
    workspace: Pubkey,
    scratch: Pubkey,
    resource: Pubkey,
    commitment: [u8; 32],
    resource_schema: VersionedId,
    kernel_id: KernelId,
    semantic_version: u16,
    abi_version: u16,
    views: Vec<ViewMeta>,
}

impl Lane {
    fn reset(&mut self) {
        self.status = IDLE;
        self.captured = 0;
        self.capture_cursor = 0;
        self.capture_total = 0;
        self.render_cursor = 0;
        self.render_total = 0;
        self.compute_units = 0;
        self.resource = Pubkey::default();
        self.commitment = [0; 32];
        self.resource_schema = VersionedId { id: 0, version: 0 };
        self.kernel_id = KernelId([0; 16]);
        self.semantic_version = 0;
        self.abi_version = 0;
        self.views.clear();
    }
}

fn key_at(raw: &[u8], at: usize) -> Pubkey {
    Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
}

fn encode_lane(account: &AccountInfo, l: &Lane) -> ProgramResult {
    let mut raw = account.try_borrow_mut_data()?;
    if raw.len() != LANE_BYTES {
        return Err(refusal(REFUSAL_LANE));
    }
    raw.fill(0);
    raw[..4].copy_from_slice(LANE_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_LANE;
    raw[7] = l.lane;
    raw[8..40].copy_from_slice(l.session.as_ref());
    raw[40..72].copy_from_slice(l.authority.as_ref());
    raw[72] = l.status;
    raw[73] = l.bump;
    raw[74] = l.views.len() as u8;
    put_u32(&mut raw, 76, l.captured);
    put_u32(&mut raw, 80, l.capture_cursor);
    put_u32(&mut raw, 84, l.capture_total);
    put_u32(&mut raw, 88, l.render_cursor);
    put_u32(&mut raw, 92, l.render_total);
    put_u32(&mut raw, 96, l.compute_units);
    raw[100..132].copy_from_slice(l.workspace.as_ref());
    raw[132..164].copy_from_slice(l.scratch.as_ref());
    raw[164..196].copy_from_slice(l.resource.as_ref());
    raw[196..228].copy_from_slice(&l.commitment);
    put_u32(&mut raw, 228, l.resource_schema.id);
    put_u16(&mut raw, 232, l.resource_schema.version);
    raw[234..250].copy_from_slice(&l.kernel_id.0);
    put_u16(&mut raw, 250, l.semantic_version);
    put_u16(&mut raw, 252, l.abi_version);
    for (i, v) in l.views.iter().enumerate() {
        let at = L_VIEWS + i * L_VIEW_BYTES;
        raw[at] = v.role;
        put_u32(&mut raw, at + 1, v.source_offset);
        put_u32(&mut raw, at + 5, v.len);
    }
    Ok(())
}

/// Decode and authenticate a lane record: program-owned, at its PDA (from
/// the session key and lane index it records, with its stored bump), and
/// well-formed. The record authenticates itself, so lane renders need no
/// session account.
fn checked_lane(program: &Pubkey, account: &AccountInfo, writable: bool) -> Result<Lane, ProgramError> {
    check_program_owned(account, program, writable)?;
    let raw = account.try_borrow_data()?;
    if raw.len() != LANE_BYTES
        || &raw[..4] != LANE_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_LANE
        || raw[7] as usize >= MAX_LANES
        || raw[72] > RENDERING
        || raw[74] as usize > MAX_VIEW_OUTPUTS
        || raw[75] != 0
        || raw[254..256] != [0; 2]
        || raw[L_END..].iter().any(|b| *b != 0)
    {
        return Err(refusal(REFUSAL_LANE));
    }
    let session = key_at(&raw, 8);
    let lane = raw[7];
    expect_derived_with_bump(
        account,
        program,
        &[LANE_SEED, session.as_ref(), &[lane]],
        raw[73],
        AccountKind::exact(LANE_MAGIC, LANE_BYTES).with_version(4, WIRE_VERSION as u16).with_bump(73),
        RoleFlags { writable, signer: false },
    )
    .map_err(|_| refusal(REFUSAL_LANE))?;
    let view_count = raw[74] as usize;
    let views = (0..view_count)
        .map(|i| {
            let at = L_VIEWS + i * L_VIEW_BYTES;
            ViewMeta { role: raw[at], source_offset: u32_at(&raw, at + 1), len: u32_at(&raw, at + 5), source_cursor: 0 }
        })
        .collect();
    let l = Lane {
        lane,
        session,
        authority: key_at(&raw, 40),
        status: raw[72],
        bump: raw[73],
        captured: u32_at(&raw, 76),
        capture_cursor: u32_at(&raw, 80),
        capture_total: u32_at(&raw, 84),
        render_cursor: u32_at(&raw, 88),
        render_total: u32_at(&raw, 92),
        compute_units: u32_at(&raw, 96),
        workspace: key_at(&raw, 100),
        scratch: key_at(&raw, 132),
        resource: key_at(&raw, 164),
        commitment: raw[196..228].try_into().expect("fixed width"),
        resource_schema: VersionedId { id: u32_at(&raw, 228), version: u16_at(&raw, 232) },
        kernel_id: KernelId(raw[234..250].try_into().expect("fixed width")),
        semantic_version: u16_at(&raw, 250),
        abi_version: u16_at(&raw, 252),
        views,
    };
    if l.capture_cursor > l.capture_total || l.render_cursor > l.render_total {
        return Err(refusal(REFUSAL_LANE));
    }
    Ok(l)
}

/// A lane's workspace or scratch: a v3 view-shaped child at its PDA, bound
/// to the lane record's session and authority. Returns its declared length.
fn lane_child(program: &Pubkey, account: &AccountInfo, l: &Lane, kind: u8, writable: bool) -> Result<u32, ProgramError> {
    check_program_owned(account, program, writable)?;
    let (role, expected) = match kind {
        KIND_LANE_WORKSPACE => (WORKSPACE_ROLE_BASE + l.lane, l.workspace),
        KIND_LANE_SCRATCH => (SCRATCH_ROLE_BASE + l.lane, l.scratch),
        _ => return Err(refusal(REFUSAL_LANE)),
    };
    expect_keyed(
        account,
        program,
        &expected,
        AccountKind::variable(VIEW_MAGIC, CHILD_HEADER_BYTES + 1, ACCOUNT_MAX_BYTES).with_version(4, WIRE_VERSION as u16),
        RoleFlags { writable, signer: false },
    )
    .map_err(|_| refusal(REFUSAL_LANE))?;
    let raw = account.try_borrow_data()?;
    let len = u32_at(&raw, 108);
    if raw[6] != kind
        || raw[7] != role
        || raw[8..40] != l.session.to_bytes()
        || raw[40..72] != l.authority.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|b| *b != 0)
        || len == 0
        || u32_at(&raw, 116) != len
        || raw.len() != CHILD_HEADER_BYTES + len as usize
    {
        return Err(refusal(REFUSAL_LANE));
    }
    Ok(len)
}

fn lane_and_cursor(data: &[u8], len: usize) -> Result<(u8, u32), ProgramError> {
    exact_data(data, len)?;
    Ok((data[3], u32_at(data, 4)))
}

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    check_unique(accounts)?;
    if data.len() < 4 || data[3] as usize >= MAX_LANES {
        return Err(ProgramError::InvalidInstructionData);
    }
    match data[2] {
        OP_CREATE => create(program, accounts, data, kernel),
        OP_GROW => grow(program, accounts, data, kernel),
        OP_CAPTURE_BEGIN => capture_begin(program, accounts, data, kernel),
        OP_CAPTURE_RUN => capture_run(program, accounts, data, kernel),
        OP_CAPTURE_END => capture_end(program, accounts, data, kernel),
        OP_RUN => run(program, accounts, data, kernel),
        OP_COMMIT => commit(program, accounts, data, kernel),
        OP_ABORT => abort(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// The authority's active lane session, refusing lane indices it did not declare.
fn lane_session(
    program: &Pubkey,
    authority: &AccountInfo,
    session_account: &AccountInfo,
    writable: bool,
    kernel: &dyn StatefulKernel,
    lane: u8,
) -> Result<Session, ProgramError> {
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let session = checked_session_from(program, session_account, writable, kernel, Some(authority.key))?;
    if authority.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if lane >= session.lanes {
        return Err(refusal(REFUSAL_LANE));
    }
    Ok(session)
}

fn create_child<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    session_account: &AccountInfo<'a>,
    session: &Session,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    kind: u8,
    role: u8,
    len: u32,
) -> ProgramResult {
    let (expected, bump) = view_pda(program, session_account.key, role);
    if target.key != &expected {
        return Err(refusal(REFUSAL_LANE));
    }
    create_pda(
        program,
        payer,
        target,
        system,
        &[VIEW_SEED, session_account.key.as_ref(), &[role]],
        bump,
        CHILD_HEADER_BYTES + len.min(CHILD_GROW_BYTES) as usize,
    )?;
    let mut raw = target.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(VIEW_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = kind;
    raw[7] = role;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(session.authority.as_ref());
    put_u32(&mut raw, 108, len);
    put_u32(&mut raw, 112, u32::MAX);
    put_u32(&mut raw, 116, len.min(CHILD_GROW_BYTES));
    Ok(())
}

/// 4 CREATE: [payer(s,w), authority(s), session(w), lane(w), workspace(w),
/// scratch(w), system] lane:u8 workspace_len:u32 scratch_len:u32.
fn create(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    exact_data(data, 12)?;
    let [payer, authority, session_account, lane_account, workspace, scratch, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let k = data[3];
    if !payer.is_signer || !payer.is_writable || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = lane_session(program, authority, session_account, true, kernel, k)?;
    let (ws_len, scratch_len) = (u32_at(data, 4), u32_at(data, 8));
    if session.status != STATUS_ACTIVE
        || !session.state_initialized
        || ws_len < kernel.lane_capture_bytes()
        || ws_len > kernel.max_view_workspace_bytes()
        || ws_len > MAX_VIEW_BYTES
        || scratch_len == 0
        || scratch_len > MAX_SCRATCH_BYTES
        || kernel.lane_capture_phase_bytes() == 0
    {
        return Err(refusal(REFUSAL_LANE));
    }
    let (expected, bump) = lane_pda(program, session_account.key, k);
    if lane_account.key != &expected {
        return Err(refusal(REFUSAL_LANE));
    }
    create_pda(program, payer, lane_account, system, &[LANE_SEED, session_account.key.as_ref(), &[k]], bump, LANE_BYTES)?;
    create_child(program, payer, session_account, &session, workspace, system, KIND_LANE_WORKSPACE, WORKSPACE_ROLE_BASE + k, ws_len)?;
    create_child(program, payer, session_account, &session, scratch, system, KIND_LANE_SCRATCH, SCRATCH_ROLE_BASE + k, scratch_len)?;
    let mut l = Lane {
        lane: k,
        session: *session_account.key,
        authority: session.authority,
        status: IDLE,
        bump: bump.value(),
        captured: 0,
        capture_cursor: 0,
        capture_total: 0,
        render_cursor: 0,
        render_total: 0,
        compute_units: 0,
        workspace: *workspace.key,
        scratch: *scratch.key,
        resource: Pubkey::default(),
        commitment: [0; 32],
        resource_schema: VersionedId { id: 0, version: 0 },
        kernel_id: KernelId([0; 16]),
        semantic_version: 0,
        abi_version: 0,
        views: Vec::new(),
    };
    l.reset();
    encode_lane(lane_account, &l)?;
    session.child_count = session.child_count.checked_add(3).ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    store_session(session_account, &session)
}

/// 5 GROW: [payer(s,w), session, lane, target(w), system] lane:u8. Grows the
/// lane's workspace or scratch toward its declared length while idle.
fn grow(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    exact_data(data, 4)?;
    let [payer, session_account, lane_account, target, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let session = checked_session(program, session_account, false, kernel)?;
    let l = checked_lane(program, lane_account, false)?;
    if l.session != *session_account.key || l.lane != data[3] || session.status != STATUS_ACTIVE || l.status != IDLE {
        return Err(refusal(REFUSAL_LANE));
    }
    let kind = if target.key == &l.workspace {
        KIND_LANE_WORKSPACE
    } else if target.key == &l.scratch {
        KIND_LANE_SCRATCH
    } else {
        return Err(refusal(REFUSAL_LANE));
    };
    check_program_owned(target, program, true)?;
    let (len, allocated) = {
        let raw = target.try_borrow_data()?;
        let role = if kind == KIND_LANE_WORKSPACE { WORKSPACE_ROLE_BASE } else { SCRATCH_ROLE_BASE } + l.lane;
        if raw.len() < CHILD_HEADER_BYTES || &raw[..4] != VIEW_MAGIC || raw[6] != kind || raw[7] != role || raw[8..40] != l.session.to_bytes() {
            return Err(refusal(REFUSAL_LANE));
        }
        (u32_at(&raw, 108), u32_at(&raw, 116))
    };
    let next = grow_child_data(payer, target, system, len, allocated)?;
    put_u32(&mut target.try_borrow_mut_data()?, 116, next);
    Ok(())
}

/// 6 CAPTURE_BEGIN: [authority(s), session(w), lane(w), views...(r)]
/// lane:u8 cursor:u32 compute:u32. Opens a capture of the state at `cursor`
/// on an idle lane, and records the binding and the views' layout.
fn capture_begin(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    exact_data(data, 12)?;
    let [authority, session_account, lane_account, views @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (k, c) = (data[3], u32_at(data, 4));
    let declared = u32_at(data, 8);
    let mut session = lane_session(program, authority, session_account, true, kernel, k)?;
    let mut l = checked_lane(program, lane_account, true)?;
    if l.session != *session_account.key || l.lane != k {
        return Err(refusal(REFUSAL_LANE));
    }
    if session.status != STATUS_ACTIVE || session.phase != PHASE_NONE || !session.state_initialized {
        return Err(refusal(REFUSAL_LIVE));
    }
    if l.status != IDLE {
        return Err(refusal(REFUSAL_LANE));
    }
    // Two lanes never capture the same cursor; captures move forward. An
    // aborted capture forfeits its cursor until the next advance.
    if session.cursor != c || c.checked_add(1).is_none_or(|next| next <= session.last_captured) {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    phase_declaration(kernel, declared)?;
    // The shared views, in role order; their layout is fixed for this
    // publication and replayed by the lane's renders and commit.
    let mut metas = Vec::with_capacity(session.view_count as usize);
    let mut at = 0usize;
    for role in 0..MAX_VIEW_OUTPUTS {
        if session.view_keys[role] == Pubkey::default() {
            continue;
        }
        let account = views.get(at).ok_or(ProgramError::NotEnoughAccountKeys)?;
        metas.push(view_meta(program, account, session_account, &session, role as u8, false, kernel)?);
        at += 1;
    }
    if at != views.len() || metas.is_empty() {
        return Err(refusal(REFUSAL_VIEW));
    }
    let total = total_view_bytes(&metas)?;
    session.capture_mask |= 1 << k;
    session.last_captured = c + 1;
    l.status = CAPTURING;
    l.captured = c;
    l.capture_cursor = 0;
    l.capture_total = kernel.lane_capture_bytes();
    l.render_cursor = 0;
    l.render_total = total;
    l.compute_units = declared;
    l.resource = session.resource_key;
    l.commitment = session.resource_commitment;
    l.resource_schema = session.resource_schema;
    let m = kernel.manifest();
    l.kernel_id = m.id;
    l.semantic_version = m.semantic_version;
    l.abi_version = m.abi_version;
    l.views = metas;
    encode_lane(lane_account, &l)?;
    store_session(session_account, &session)
}

/// 7 CAPTURE_RUN: the v3 publication account prefix (primary state first if
/// the session has one; authority; session(r); resource; the other state
/// spans), then lane(w), lane workspace(w). lane:u8 cursor:u32
/// capture_cursor:u32 compute:u32 [phases:u8]. Reads the state at the
/// captured cursor and writes only the lane.
fn capture_run(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    let phases = match data.len() {
        16 => 1u32,
        17 if (1..=64).contains(&data[16]) => data[16] as u32,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    let (k, c) = (data[3], u32_at(data, 4));
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account) = if primary_layout { (&accounts[1], &accounts[2]) } else { (&accounts[0], &accounts[1]) };
    let session = lane_session(program, authority, session_account, false, kernel, k)?;
    if primary_layout != session.primary_state || session.status != STATUS_ACTIVE {
        return Err(refusal(REFUSAL_LIVE));
    }
    let [prefix @ .., lane_account, workspace] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut l = checked_lane(program, lane_account, true)?;
    if l.session != *session_account.key || l.lane != k || l.status != CAPTURING || l.captured != c {
        return Err(refusal(REFUSAL_LANE));
    }
    // The capture bit holds the cursor; this is a defensive restatement.
    if session.cursor != c || session.capture_mask & (1 << k) == 0 {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    if u32_at(data, 8) != l.capture_cursor || l.capture_cursor >= l.capture_total {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    if u32_at(data, 12) != l.compute_units {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    // The prefix is the v3 publication layout without views, workspace or scratch.
    let session_index = usize::from(session.primary_state) + 1;
    let resource_index = (session.resource_key != Pubkey::default()).then_some(session_index + 1);
    let tail = session_index + 1 + usize::from(resource_index.is_some());
    let state_count = session.state_span_count as usize;
    let state_accounts: Vec<AccountInfo> = if session.primary_state {
        core::iter::once(prefix[0].clone()).chain(prefix.get(tail..).unwrap_or(&[]).iter().cloned()).collect()
    } else {
        prefix.get(tail..).unwrap_or(&[]).to_vec()
    };
    if state_accounts.len() != state_count || prefix.len() != tail + state_count - usize::from(session.primary_state) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if session.primary_state && prefix[0].key != &session.state_keys[0] {
        return Err(refusal(REFUSAL_STATE));
    }
    let state_metas = validate_state_set(program, session_account, &session, &state_accounts, validate_kernel(kernel)?, false, c)?;
    let resource_guard = match resource_index {
        Some(i) => {
            checked_resource(program, &prefix[i], session_account, &session, true, false)?;
            Some(prefix[i].try_borrow_data()?)
        }
        None => None,
    };
    let resources: Vec<AccountSpan<'_>> = match (resource_index, resource_guard.as_ref()) {
        (Some(i), Some(raw)) => vec![AccountSpan {
            key: prefix[i].key.to_bytes(),
            owner: prefix[i].owner.to_bytes(),
            is_signer: false,
            is_writable: false,
            schema: session.resource_schema,
            offset: 0,
            data: &raw[RESOURCE_HEADER_BYTES..RESOURCE_HEADER_BYTES + u32_at(raw, 72) as usize],
        }],
        _ => Vec::new(),
    };
    let ws_len = lane_child(program, workspace, &l, KIND_LANE_WORKSPACE, true)?;
    if ws_len < l.capture_total {
        return Err(refusal(REFUSAL_LANE));
    }
    let guards = state_accounts.iter().map(AccountInfo::try_borrow_data).collect::<Result<Vec<_>, _>>()?;
    let state: Vec<AccountSpan<'_>> = state_accounts
        .iter()
        .zip(guards.iter())
        .zip(state_metas.iter())
        .enumerate()
        .map(|(index, ((account, raw), meta))| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: meta.schema,
            offset: meta.offset,
            data: if session.primary_state && index == 0 {
                &raw[..meta.len as usize]
            } else {
                &raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + meta.len as usize]
            },
        })
        .collect();
    {
        let mut ws = workspace.try_borrow_mut_data()?;
        if l.capture_cursor == 0 {
            // Bytes past the capture would otherwise carry over from earlier
            // renders on this lane; a render sees only the captured state and
            // zeros (review M2).
            ws[CHILD_HEADER_BYTES + l.capture_total as usize..CHILD_HEADER_BYTES + ws_len as usize].fill(0);
        }
        for _ in 0..phases {
            let left = l.capture_total - l.capture_cursor;
            if left == 0 {
                break;
            }
            let len = left.min(kernel.lane_capture_phase_bytes());
            let phase = LanePhase { state_cursor: c, lane: k, offset: l.capture_cursor, len, compute_units: l.compute_units };
            let payload = &mut ws[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + ws_len as usize];
            kernel
                .capture_lane_phase(phase, &state, &resources, &l.commitment, payload)
                .map_err(|_| refusal(REFUSAL_KERNEL))?;
            l.capture_cursor += len;
        }
        put_u32(&mut ws, 112, c);
    }
    encode_lane(lane_account, &l)
}

/// 8 CAPTURE_END: [authority(s), session(w), lane(w)] lane:u8 cursor:u32.
/// Closes a complete capture; the state may advance again.
fn capture_end(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    let (k, c) = lane_and_cursor(data, 8)?;
    let [authority, session_account, lane_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut session = lane_session(program, authority, session_account, true, kernel, k)?;
    let mut l = checked_lane(program, lane_account, true)?;
    if l.session != *session_account.key || l.lane != k || l.status != CAPTURING || session.status != STATUS_ACTIVE {
        return Err(refusal(REFUSAL_LANE));
    }
    if l.captured != c || l.capture_cursor != l.capture_total || session.capture_mask & (1 << k) == 0 {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    session.capture_mask &= !(1 << k);
    l.status = RENDERING;
    encode_lane(lane_account, &l)?;
    store_session(session_account, &session)
}

/// 9 RUN_PHASE: [lane workspace(w), authority(s), lane(w), lane scratch(w),
/// resource?] lane:u8 cursor:u32 render_cursor:u32 compute:u32 [phases:u8].
/// The lane workspace is first (the invocation's base address). No session
/// or state account is read, so a render also runs after halt; it writes
/// only lane accounts, and nothing publishes after halt (commit refuses).
fn run(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    let phases = match data.len() {
        16 => 1u32,
        17 if (1..=64).contains(&data[16]) => data[16] as u32,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    let (k, c) = (data[3], u32_at(data, 4));
    let (workspace, authority, lane_account, scratch, rest) = match accounts {
        [w, a, l, s, rest @ ..] => (w, a, l, s, rest),
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    let mut l = checked_lane(program, lane_account, true)?;
    if !authority.is_signer || authority.key != &l.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let m = kernel.manifest();
    if l.lane != k || l.status != RENDERING || l.captured != c || l.kernel_id != m.id || l.semantic_version != m.semantic_version || l.abi_version != m.abi_version {
        return Err(refusal(REFUSAL_LANE));
    }
    if u32_at(data, 8) != l.render_cursor || l.render_cursor >= l.render_total {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    let declared = u32_at(data, 12);
    phase_declaration(kernel, declared)?;
    if declared != l.compute_units {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let ws_len = lane_child(program, workspace, &l, KIND_LANE_WORKSPACE, true)?;
    let scratch_len = lane_child(program, scratch, &l, KIND_LANE_SCRATCH, true)?;
    if scratch_len < l.render_total {
        return Err(refusal(REFUSAL_LANE));
    }
    let resource_guard = match (l.resource != Pubkey::default(), rest) {
        (false, []) => None,
        (true, [resource]) => {
            checked_resource_bound(program, resource, &l.session, &l.resource, &l.commitment, true, false)?;
            Some((resource, resource.try_borrow_data()?))
        }
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    let resources: Vec<AccountSpan<'_>> = match resource_guard.as_ref() {
        Some((account, raw)) => vec![AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: false,
            is_writable: false,
            schema: l.resource_schema,
            offset: 0,
            data: &raw[RESOURCE_HEADER_BYTES..RESOURCE_HEADER_BYTES + u32_at(raw, 72) as usize],
        }],
        None => Vec::new(),
    };
    let mut ws = workspace.try_borrow_mut_data()?;
    if u32_at(&ws, 112) != c {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    let mut sc = scratch.try_borrow_mut_data()?;
    for _ in 0..phases {
        let left = l.render_total - l.render_cursor;
        if left == 0 {
            break;
        }
        let count = left.min(kernel.max_view_phase_bytes());
        let start = l.render_cursor;
        let end = start + count;
        let (header, payload) = ws.split_at_mut(CHILD_HEADER_BYTES);
        let payload = &mut payload[..ws_len as usize];
        let mut base = 0u32;
        for view in &l.views {
            let view_end = base.checked_add(view.len).ok_or_else(|| refusal(REFUSAL_VIEW))?;
            let (from, to) = (start.max(base), end.min(view_end));
            if from < to {
                let request = ViewPhase {
                    state_cursor: c,
                    role: view.role,
                    source_offset: view.source_offset,
                    output_offset: from - base,
                    compute_units: declared,
                };
                let at = CHILD_HEADER_BYTES + from as usize;
                let output = &mut sc[at..at + (to - from) as usize];
                let before: [u8; CHILD_HEADER_BYTES] = (&*header).try_into().map_err(|_| refusal(REFUSAL_KERNEL))?;
                let written = kernel
                    .render_lane_phase(request, &resources, &l.commitment, header, payload, output)
                    .map_err(|_| refusal(REFUSAL_KERNEL))?;
                if header != before.as_slice() || written != (to - from) as usize {
                    return Err(refusal(REFUSAL_KERNEL));
                }
            }
            base = view_end;
        }
        l.render_cursor = end;
    }
    put_u32(&mut sc, 112, c);
    drop(sc);
    drop(ws);
    encode_lane(lane_account, &l)
}

/// 10 COMMIT: [authority(s), session(r), lane(w), lane scratch(r), views(w)...]
/// lane:u8 cursor:u32. Copies the rendered bytes into the shared views and
/// stamps them with the captured cursor, newest only (2341).
fn commit(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    let (k, c) = lane_and_cursor(data, 8)?;
    let [authority, session_account, lane_account, scratch, views @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let session = lane_session(program, authority, session_account, false, kernel, k)?;
    let mut l = checked_lane(program, lane_account, true)?;
    if l.session != *session_account.key || l.lane != k || l.status != RENDERING || session.status != STATUS_ACTIVE {
        return Err(refusal(REFUSAL_LANE));
    }
    if l.captured != c || l.render_cursor != l.render_total {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    lane_child(program, scratch, &l, KIND_LANE_SCRATCH, false)?;
    if views.len() != l.views.len() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // The views must be the set captured (review M1): a view created since
    // capture begin would be left unstamped, so the lane aborts instead.
    if session.view_count as usize != l.views.len() {
        return Err(refusal(REFUSAL_VIEW));
    }
    let sc = scratch.try_borrow_data()?;
    if u32_at(&sc, 112) != c {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    let mut metas = Vec::with_capacity(views.len());
    for (account, want) in views.iter().zip(&l.views) {
        let meta = view_meta(program, account, session_account, &session, want.role, true, kernel)?;
        if meta.len != want.len || meta.source_offset != want.source_offset {
            return Err(refusal(REFUSAL_VIEW));
        }
        if meta.source_cursor != u32::MAX && meta.source_cursor >= c {
            return Err(refusal(REFUSAL_STALE_PUBLICATION));
        }
        metas.push(meta);
    }
    let mut at = CHILD_HEADER_BYTES;
    for (account, meta) in views.iter().zip(&metas) {
        let n = meta.len as usize;
        let mut raw = account.try_borrow_mut_data()?;
        raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + n].copy_from_slice(&sc[at..at + n]);
        put_u32(&mut raw, 112, c);
        at += n;
    }
    drop(sc);
    l.reset();
    encode_lane(lane_account, &l)
}

/// 11 ABORT: [authority(s), session(w), lane(w)] lane:u8 cursor:u32. Returns
/// a capturing or rendering lane to idle, clearing its capture bit.
fn abort(program: &Pubkey, accounts: &[AccountInfo], data: &[u8], kernel: &dyn StatefulKernel) -> ProgramResult {
    let (k, c) = lane_and_cursor(data, 8)?;
    let [authority, session_account, lane_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut session = lane_session(program, authority, session_account, true, kernel, k)?;
    let mut l = checked_lane(program, lane_account, true)?;
    if l.session != *session_account.key || l.lane != k || l.status == IDLE {
        return Err(refusal(REFUSAL_LANE));
    }
    if l.captured != c {
        return Err(refusal(REFUSAL_LANE_CURSOR));
    }
    session.capture_mask &= !(1 << k);
    l.reset();
    encode_lane(lane_account, &l)?;
    store_session(session_account, &session)
}

/// Close a lane record, workspace or scratch of a halted session (called by
/// `close_child` after its halt and refund checks).
pub(super) fn close_lane_child(
    program: &Pubkey,
    session_account: &AccountInfo,
    session: &mut Session,
    target: &AccountInfo,
    refund: &AccountInfo,
) -> ProgramResult {
    let (kind, role) = {
        let raw = target.try_borrow_data()?;
        if raw.len() < 72 || raw[8..40] != session_account.key.to_bytes() || raw[40..72] != session.authority.to_bytes() {
            return Err(refusal(REFUSAL_SESSION));
        }
        (raw[6], raw[7])
    };
    let expected = match kind {
        KIND_LANE if (role as usize) < MAX_LANES => lane_pda(program, session_account.key, role).0,
        KIND_LANE_WORKSPACE if role.wrapping_sub(WORKSPACE_ROLE_BASE) < MAX_LANES as u8 => view_pda(program, session_account.key, role).0,
        KIND_LANE_SCRATCH if role.wrapping_sub(SCRATCH_ROLE_BASE) < MAX_LANES as u8 => view_pda(program, session_account.key, role).0,
        _ => return Err(refusal(REFUSAL_SESSION)),
    };
    if target.key != &expected {
        return Err(refusal(REFUSAL_SESSION));
    }
    session.child_count = session.child_count.checked_sub(1).ok_or_else(|| refusal(REFUSAL_SESSION))?;
    store_session(session_account, session)?;
    drain_to_refund(target, refund)
}
