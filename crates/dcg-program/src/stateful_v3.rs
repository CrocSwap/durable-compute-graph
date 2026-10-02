// SPDX-License-Identifier: GPL-3.0-only

//! Stateful workload wire v3. It preserves a v1 session's identity across
//! bounded stream growth, authenticates an optional initial resource through
//! the statically linked kernel, and stages multi-account views in resumable
//! phases before one atomic publication transaction.

use crate::account_provenance::{
    create_derived_account, expect_derived, expect_derived_with_bump, expect_keyed, AccountKind,
    CanonicalBump, RoleFlags,
};
use crate::kernel::{
    AccountSpan, InitializationPhase, KernelId, ModeId, StateSchema, StateSpanMut, StatefulKernel,
    TransitionDisposition, VersionedId, ViewAbi, ViewPhase, MAX_DECLARED_KERNEL_COMPUTE_UNITS,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

pub const WIRE_VERSION: u8 = 3;
pub const MAX_STATE_SPANS: usize = 8;
pub const MAX_VIEW_OUTPUTS: usize = 16;
pub const MAX_STREAM_WINDOW: u32 = 64;
pub const MAX_STREAM_GROWTH_SLOTS: u32 = 512;
pub const MAX_STREAM_CAPACITY: u32 = (10 * 1024 * 1024 - 128) / 16;
pub const MAX_COMMAND_BYTES: usize = 8;
pub const MAX_STEPS_PER_ADVANCE: u8 = 8;
pub const MAX_ENGINE_STATE_BYTES: u32 = 10_000_000;
pub const MAX_VIEW_BYTES: u32 = 10 * 1024 * 1024 - 128;
pub const MAX_SCRATCH_BYTES: u32 = 4_000_000;
pub const CHILD_GROW_BYTES: u32 = 8_192;
pub const STATE_OP_GROW: u8 = 0xFE;
pub const STATE_OP_INITIALIZE: u8 = 0xFF;
pub const VIEW_OP_GROW: u8 = 0xFE;
pub const KIND_SESSION: u8 = 0;
pub const KIND_STREAM: u8 = 1;
pub const KIND_STATE: u8 = 2;
pub const KIND_VIEW: u8 = 3;
pub const KIND_SCRATCH: u8 = 4;
pub const VIEW_SNAPSHOT: u8 = 0;
pub const VIEW_STRIP_0: u8 = 1;
pub const VIEW_STRIP_7: u8 = 8;
pub const SCRATCH_ROLE: u8 = u8::MAX;
pub const WORKSPACE_ROLE: u8 = u8::MAX - 1;
pub const KIND_WORKSPACE: u8 = 5;
pub const KIND_RESOURCE: u8 = 6;
pub const KIND_ANCHOR: u8 = 7;
pub const STATE_OP_BEGIN_INITIALIZE: u8 = 0xFC;
pub const STATE_OP_RUN_INITIALIZE: u8 = 0xFD;
pub const ANCHOR_OP_BEGIN: u8 = 0xFE;
pub const ANCHOR_OP_CHUNK: u8 = 0xFD;
pub const ANCHOR_OP_FINISH: u8 = 0xFC;
pub const ANCHOR_OP_ABORT: u8 = 0xFB;
pub const RESOURCE_CHUNK_TAG: u8 = 240;
pub const RESOURCE_GROW_OP: u8 = 0xFE;
pub const RESOURCE_CHUNK_BYTES: u32 = 65_536;
pub const ANCHOR_CHUNK_BYTES: u32 = 65_536;

pub const REFUSAL_MALFORMED: u32 = 2_321;
pub const REFUSAL_AUTHORITY: u32 = 2_322;
pub const REFUSAL_ALIAS: u32 = 2_323;
pub const REFUSAL_SESSION: u32 = 2_324;
pub const REFUSAL_LIVE: u32 = 2_325;
pub const REFUSAL_RESOURCE: u32 = 2_326;
pub const REFUSAL_DUPLICATE_SLOT: u32 = 2_327;
pub const REFUSAL_BACKPRESSURE: u32 = 2_328;
pub const REFUSAL_CURSOR: u32 = 2_329;
pub const REFUSAL_INPUT_GAP: u32 = 2_330;
pub const REFUSAL_STATE: u32 = 2_331;
pub const REFUSAL_VIEW: u32 = 2_332;
pub const REFUSAL_REFUND: u32 = 2_333;
pub const REFUSAL_KERNEL: u32 = 2_334;
pub const REFUSAL_PHASE_CURSOR: u32 = 2_335;
pub const REFUSAL_PHASE_STATE_CHANGED: u32 = 2_336;
pub const REFUSAL_INITIALIZATION: u32 = 2_337;

const SESSION_BYTES: usize = 1_280;
const SESSION_MAGIC: &[u8; 4] = b"DSS3";
const SESSION_SEED: &[u8] = b"dcg-session-v3";
const STREAM_SEED: &[u8] = b"dcg-input-v3";
const STATE_SEED: &[u8] = b"dcg-state-v3";
const VIEW_SEED: &[u8] = b"dcg-view-v3";
const CHILD_HEADER_BYTES: usize = 128;
const STREAM_MAGIC: &[u8; 4] = b"DSB3";
const STATE_MAGIC: &[u8; 4] = b"DSE3";
const VIEW_MAGIC: &[u8; 4] = b"DVW3";
const SLOT_BYTES: usize = 16;
const ACCOUNT_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const MODE_CONSENSUS_V3: ModeId = VersionedId {
    id: 0x434f_4e53,
    version: 3,
};
const STATUS_ACTIVE: u8 = 1;
const STATUS_HALTED: u8 = 2;
const POLICY_INDEXED: u8 = 0;
const POLICY_APPEND: u8 = 1;
const PHASE_NONE: u8 = 0;
const PHASE_VIEW_PUBLICATION: u8 = 1;
const PHASE_INITIALIZATION: u8 = 2;
const PHASE_STATE_ANCHOR: u8 = 3;
const RESOURCE_SEED: &[u8] = b"dcg-resource-v3";
const ANCHOR_SEED: &[u8] = b"dcg-anchor-v3";
const RESOURCE_HEADER_BYTES: usize = 128;
const ANCHOR_ACCOUNT_BYTES: usize = 160;
const RESOURCE_MAGIC: &[u8; 4] = b"DRS3";
const ANCHOR_MAGIC: &[u8; 4] = b"DAN3";
const RESOURCE_BITMAP_AT: usize = 88;
const RESOURCE_ALLOCATED_AT: usize = 112;
pub(crate) const HALT_BEFORE_RUNTIME_CHECK_BYTES: usize = 8 * 1024;

#[derive(Debug)]
struct Session {
    id: u64,
    bump: u8,
    status: u8,
    policy: u8,
    command_width: u8,
    max_steps: u8,
    capacity: u32,
    authority: Pubkey,
    writer: Pubkey,
    kernel_id: KernelId,
    semantic_version: u16,
    abi_version: u16,
    mode: ModeId,
    cursor: u32,
    frontier: u32,
    child_count: u16,
    state_span_count: u8,
    state_initialized: bool,
    view_count: u8,
    stream_root: [u8; 32],
    input_root: [u8; 32],
    anchor_cursor: u32,
    state_anchor: [u8; 32],
    state_bytes: u32,
    self_key: Pubkey,
    stream_key: Pubkey,
    state_keys: Vec<Pubkey>,
    view_keys: Vec<Pubkey>,
    scratch_key: Pubkey,
    workspace_key: Pubkey,
    resource_key: Pubkey,
    resource_schema: VersionedId,
    resource_commitment: [u8; 32],
    phase: u8,
    phase_state_cursor: u32,
    phase_cursor: u32,
    phase_total: u32,
    phase_compute_units: u32,
    primary_state: bool,
    state_schema: VersionedId,
    state_lengths: Vec<u32>,
    halt_reason: u32,
    halt_cursor: u32,
    last_advance_start: u32,
}

#[derive(Clone, Copy, Debug)]
struct StateSpanMeta {
    schema: VersionedId,
    index: u8,
    count: u8,
    offset: u32,
    len: u32,
    before_cursor: u32,
    after_cursor: u32,
    total_len: u32,
}

#[derive(Clone, Copy, Debug)]
struct ViewMeta {
    role: u8,
    source_offset: u32,
    len: u32,
    source_cursor: u32,
}

#[derive(Clone, Copy, Debug)]
struct ResourceMeta {
    len: u32,
    chunks: u32,
    received: u32,
    allocated: u32,
}

#[derive(Clone, Copy, Debug)]
struct AnchorMeta {
    open: bool,
    cursor: u32,
    total: u32,
    progress: u32,
    input_root: [u8; 32],
    accumulator: [u8; 32],
}

struct PublicationAccounts<'a> {
    state_metas: Vec<StateSpanMeta>,
    state_accounts: Vec<AccountInfo<'a>>,
    view_start: usize,
    view_metas: Vec<ViewMeta>,
    resource_index: Option<usize>,
    workspace_index: usize,
    workspace_meta: ViewMeta,
    scratch_index: usize,
    scratch_meta: ViewMeta,
}

fn refusal(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn exact_data(data: &[u8], len: usize) -> ProgramResult {
    if data.len() == len {
        Ok(())
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

fn check_unique(accounts: &[AccountInfo]) -> ProgramResult {
    for (index, left) in accounts.iter().enumerate() {
        if accounts[index + 1..]
            .iter()
            .any(|right| left.key == right.key)
        {
            return Err(refusal(REFUSAL_ALIAS));
        }
    }
    Ok(())
}

fn check_program_owned(account: &AccountInfo, program: &Pubkey, writable: bool) -> ProgramResult {
    if account.owner != program || (writable && !account.is_writable) {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed width"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed width"))
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn session_pda(program: &Pubkey, authority: &Pubkey, id: u64) -> (Pubkey, CanonicalBump) {
    let id = id.to_le_bytes();
    let bump = CanonicalBump::find(&[SESSION_SEED, authority.as_ref(), &id], program);
    (*bump.address(), bump)
}

fn resource_pda(program: &Pubkey, session: &Pubkey) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[RESOURCE_SEED, session.as_ref()], program);
    (*bump.address(), bump)
}

fn anchor_pda(program: &Pubkey, session: &Pubkey) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[ANCHOR_SEED, session.as_ref()], program);
    (*bump.address(), bump)
}

fn resource_chunks(len: u32) -> u32 {
    len.div_ceil(RESOURCE_CHUNK_BYTES)
}

fn resource_leaf(index: u32, total_len: u32, bytes: &[u8]) -> [u8; 32] {
    crate::hash::sha256(&[
        b"dcg/resource-chunk/1",
        &index.to_le_bytes(),
        &total_len.to_le_bytes(),
        bytes,
    ])
}

fn verify_resource_proof(
    mut node: [u8; 32],
    mut index: u32,
    mut width: u32,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    let mut proof_index = 0usize;
    while width > 1 {
        let sibling = index ^ 1;
        let sibling_hash = if sibling < width {
            let Some(value) = proof.get(proof_index) else {
                return false;
            };
            proof_index += 1;
            *value
        } else {
            node
        };
        node = if index & 1 == 0 {
            crate::hash::sha256(&[b"dcg/resource-node/1", &node, &sibling_hash])
        } else {
            crate::hash::sha256(&[b"dcg/resource-node/1", &sibling_hash, &node])
        };
        index >>= 1;
        width = width.div_ceil(2);
    }
    proof_index == proof.len() && &node == expected_root
}

fn checked_resource(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    require_sealed: bool,
    writable: bool,
) -> Result<ResourceMeta, ProgramError> {
    check_program_owned(account, program, writable)?;
    if session.resource_key == Pubkey::default() {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    expect_keyed(
        account,
        program,
        &session.resource_key,
        AccountKind::variable(RESOURCE_MAGIC, RESOURCE_HEADER_BYTES, ACCOUNT_MAX_BYTES)
            .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_RESOURCE))?;
    let raw = account.try_borrow_data()?;
    if session.resource_key == Pubkey::default()
        || raw.len() < RESOURCE_HEADER_BYTES
        || &raw[..4] != RESOURCE_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_RESOURCE
        || raw[7] != 0
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.resource_commitment
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let len = u32_at(&raw, 72);
    let chunk_size = u32_at(&raw, 76);
    let chunks = u32_at(&raw, 80);
    let received = u32_at(&raw, 84);
    let allocated = u32_at(&raw, RESOURCE_ALLOCATED_AT);
    let expected_chunks = resource_chunks(len);
    let bitmap_bytes = chunks.div_ceil(8) as usize;
    let bitmap_end = RESOURCE_BITMAP_AT + bitmap_bytes;
    if len == 0
        || len as usize > ACCOUNT_MAX_BYTES - RESOURCE_HEADER_BYTES
        || chunk_size != RESOURCE_CHUNK_BYTES
        || chunks == 0
        || chunks != expected_chunks
        || bitmap_bytes > RESOURCE_HEADER_BYTES - RESOURCE_BITMAP_AT
        || allocated == 0
        || allocated > len
        || raw.len() != RESOURCE_HEADER_BYTES + allocated as usize
        || raw[bitmap_end..RESOURCE_ALLOCATED_AT]
            .iter()
            .any(|byte| *byte != 0)
        || raw[RESOURCE_ALLOCATED_AT + 4..RESOURCE_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let bitmap = &raw[RESOURCE_BITMAP_AT..RESOURCE_BITMAP_AT + bitmap_bytes];
    let mut bit_count = 0u32;
    for index in 0..chunks {
        if bitmap[index as usize / 8] & (1 << (index & 7)) != 0 {
            bit_count += 1;
        }
    }
    if bit_count != received || (require_sealed && received != chunks) {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    Ok(ResourceMeta {
        len,
        chunks,
        received,
        allocated,
    })
}

fn initialize_resource_header(
    account: &AccountInfo,
    session_account: &AccountInfo,
    commitment: &[u8; 32],
    len: u32,
    allocated: u32,
) -> ProgramResult {
    let chunks = resource_chunks(len);
    let mut raw = account.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(RESOURCE_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_RESOURCE;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(commitment);
    put_u32(&mut raw, 72, len);
    put_u32(&mut raw, 76, RESOURCE_CHUNK_BYTES);
    put_u32(&mut raw, 80, chunks);
    put_u32(&mut raw, RESOURCE_ALLOCATED_AT, allocated);
    Ok(())
}

fn grow_resource(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [payer, authority, session_account, resource, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION
        || data[2] != RESOURCE_GROW_OP
        || !payer.is_signer
        || !payer.is_writable
        || !authority.is_signer
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let session =
        checked_session_from(program, session_account, false, kernel, Some(authority.key))?;
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_NONE
        || session.state_initialized
        || authority.key != &session.authority
        || session.resource_key == Pubkey::default()
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let meta = checked_resource(program, resource, session_account, &session, false, true)?;
    let next = meta
        .allocated
        .saturating_add(CHILD_GROW_BYTES)
        .min(meta.len);
    if next <= meta.allocated || u32_at(data, 3) != next {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let old_len = resource.data_len();
    let new_len = RESOURCE_HEADER_BYTES + next as usize;
    if old_len != RESOURCE_HEADER_BYTES + meta.allocated as usize
        || new_len - old_len > CHILD_GROW_BYTES as usize
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let required = Rent::get()?.minimum_balance(new_len);
    let top_up = required.saturating_sub(resource.lamports());
    if top_up != 0 {
        invoke(
            &system_instruction::transfer(payer.key, resource.key, top_up),
            &[payer.clone(), resource.clone(), system.clone()],
        )?;
    }
    resource.realloc(new_len, true)?;
    let mut raw = resource.try_borrow_mut_data()?;
    raw[old_len..new_len].fill(0);
    put_u32(&mut raw, RESOURCE_ALLOCATED_AT, next);
    Ok(())
}

fn upload_resource_chunk(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data.len() < 7 || data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [authority, session_account, resource, source] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer || source.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_NONE
        || session.state_initialized
        || session.resource_key == Pubkey::default()
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let meta = checked_resource(program, resource, session_account, &session, false, true)?;
    if meta.received == meta.chunks {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let index = u32_at(data, 2);
    let proof_count = data[6] as usize;
    if index >= meta.chunks || data.len() != 7 + proof_count * 32 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let offset = index
        .checked_mul(RESOURCE_CHUNK_BYTES)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    let chunk_len = (meta.len - offset).min(RESOURCE_CHUNK_BYTES) as usize;
    let source_raw = source.try_borrow_data()?;
    let source_end = (offset as usize)
        .checked_add(chunk_len)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    if source_raw.len() < source_end || meta.allocated < source_end as u32 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let proof: Vec<[u8; 32]> = data[7..]
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("fixed width"))
        .collect();
    let leaf = resource_leaf(index, meta.len, &source_raw[offset as usize..source_end]);
    if !verify_resource_proof(
        leaf,
        index,
        meta.chunks,
        &proof,
        &session.resource_commitment,
    ) {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let mut raw = resource.try_borrow_mut_data()?;
    let bitmap_byte = RESOURCE_BITMAP_AT + index as usize / 8;
    let mask = 1u8 << (index & 7);
    if raw[bitmap_byte] & mask != 0 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    raw[RESOURCE_HEADER_BYTES + offset as usize..RESOURCE_HEADER_BYTES + source_end]
        .copy_from_slice(&source_raw[offset as usize..source_end]);
    raw[bitmap_byte] |= mask;
    put_u32(&mut raw, 84, meta.received + 1);
    Ok(())
}

fn stream_pda(program: &Pubkey, session: &Pubkey) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[STREAM_SEED, session.as_ref()], program);
    (*bump.address(), bump)
}

fn state_pda(program: &Pubkey, session: &Pubkey, index: u8) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[STATE_SEED, session.as_ref(), &[index]], program);
    (*bump.address(), bump)
}

fn view_pda(program: &Pubkey, session: &Pubkey, role: u8) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(&[VIEW_SEED, session.as_ref(), &[role]], program);
    (*bump.address(), bump)
}

fn validate_kernel(kernel: &dyn StatefulKernel) -> Result<StateSchema, ProgramError> {
    let manifest = kernel.manifest();
    let Some(schema) = manifest.state else {
        return Err(refusal(REFUSAL_RESOURCE));
    };
    if manifest.semantic_version == 0
        || manifest.abi_version == 0
        || manifest.input.alignment == 0
        || manifest.output.alignment == 0
        || manifest.resources.max_input_bytes == 0
        || manifest.resources.max_output_bytes == 0
        || manifest.resources.max_state_bytes == 0
        || manifest.resources.max_operations == 0
        || manifest.resources.max_compute_units == 0
        || manifest.resources.max_compute_units > MAX_DECLARED_KERNEL_COMPUTE_UNITS
        || schema.max_bytes == 0
        || schema.max_bytes > manifest.resources.max_state_bytes
        || schema.max_bytes > MAX_ENGINE_STATE_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    Ok(schema)
}

fn encode_session(account: &AccountInfo, session: &Session) -> ProgramResult {
    let mut raw = account.try_borrow_mut_data()?;
    if raw.len() != SESSION_BYTES {
        return Err(refusal(REFUSAL_SESSION));
    }
    raw.fill(0);
    raw[..4].copy_from_slice(SESSION_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = session.status;
    raw[7] = session.policy;
    raw[8] = session.command_width;
    raw[9] = session.max_steps;
    put_u32(&mut raw, 10, session.capacity);
    put_u64(&mut raw, 14, session.id);
    raw[22..54].copy_from_slice(session.authority.as_ref());
    raw[54..86].copy_from_slice(session.writer.as_ref());
    raw[86..102].copy_from_slice(&session.kernel_id.0);
    put_u16(&mut raw, 102, session.semantic_version);
    put_u16(&mut raw, 104, session.abi_version);
    put_u32(&mut raw, 106, session.mode.id);
    put_u16(&mut raw, 110, session.mode.version);
    put_u32(&mut raw, 112, session.cursor);
    put_u32(&mut raw, 116, session.frontier);
    put_u16(&mut raw, 120, session.child_count);
    raw[122] = session.state_span_count;
    raw[123] = session.view_count;
    raw[124..156].copy_from_slice(&session.stream_root);
    raw[156..188].copy_from_slice(&session.input_root);
    put_u32(&mut raw, 188, session.anchor_cursor);
    raw[192..224].copy_from_slice(&session.state_anchor);
    put_u32(&mut raw, 224, session.state_bytes);
    raw[228..260].copy_from_slice(session.self_key.as_ref());
    raw[260..292].copy_from_slice(session.stream_key.as_ref());
    for (index, key) in session.state_keys.iter().enumerate() {
        let at = 292 + index * 32;
        raw[at..at + 32].copy_from_slice(key.as_ref());
    }
    for (index, key) in session.view_keys.iter().enumerate() {
        let at = 548 + index * 32;
        raw[at..at + 32].copy_from_slice(key.as_ref());
    }
    raw[1060..1092].copy_from_slice(session.scratch_key.as_ref());
    raw[1092..1124].copy_from_slice(session.resource_key.as_ref());
    put_u32(&mut raw, 1124, session.resource_schema.id);
    put_u16(&mut raw, 1128, session.resource_schema.version);
    raw[1132..1164].copy_from_slice(&session.resource_commitment);
    raw[1164] = session.phase;
    put_u32(&mut raw, 1166, session.phase_state_cursor);
    put_u32(&mut raw, 1170, session.phase_cursor);
    put_u32(&mut raw, 1174, session.phase_total);
    put_u32(&mut raw, 1178, session.phase_compute_units);
    raw[1182] = u8::from(session.state_initialized);
    put_u32(&mut raw, 1183, session.state_schema.id);
    put_u16(&mut raw, 1187, session.state_schema.version);
    raw[1189] = u8::from(session.primary_state);
    raw[1190..1222].copy_from_slice(session.workspace_key.as_ref());
    for (index, len) in session.state_lengths.iter().enumerate() {
        put_u32(&mut raw, 1222 + index * 4, *len);
    }
    put_u32(&mut raw, 1254, session.halt_reason);
    put_u32(&mut raw, 1258, session.halt_cursor);
    raw[1262] = session.bump;
    put_u32(&mut raw, 1263, session.last_advance_start);
    Ok(())
}

fn decode_session(raw: &[u8]) -> Result<Session, ProgramError> {
    if raw.len() != SESSION_BYTES {
        return Err(refusal(REFUSAL_SESSION));
    }
    let view_keys: Vec<Pubkey> = (0..MAX_VIEW_OUTPUTS)
        .map(|index| {
            let at = 548 + index * 32;
            Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
        })
        .collect();
    let view_count = view_keys
        .iter()
        .filter(|key| **key != Pubkey::default())
        .count();
    if raw.len() != SESSION_BYTES
        || &raw[..4] != SESSION_MAGIC
        || u16_at(raw, 4) != WIRE_VERSION as u16
        || raw[1130..1132] != [0; 2]
        || raw[1165] != 0
        || raw[1164] > PHASE_STATE_ANCHOR
        || raw[1182] > 1
        || raw[1189] > 1
        || raw[1267..].iter().any(|byte| *byte != 0)
        || !matches!(raw[6], STATUS_ACTIVE | STATUS_HALTED)
        || !matches!(raw[7], POLICY_INDEXED | POLICY_APPEND)
        || raw[8] == 0
        || raw[8] as usize > MAX_COMMAND_BYTES
        || raw[9] == 0
        || raw[9] > MAX_STEPS_PER_ADVANCE
        || u32_at(raw, 10) < 2
        || u32_at(raw, 10) > MAX_STREAM_CAPACITY
        || raw[122] as usize > MAX_STATE_SPANS
        || raw[123] as usize != view_count
        || raw[123] as usize > MAX_VIEW_OUTPUTS
        || u32_at(raw, 112) > u32_at(raw, 116)
        || u32_at(raw, 1263) > u32_at(raw, 112)
        || u32_at(raw, 116) > u32_at(raw, 10)
        || u32_at(raw, 188) > u32_at(raw, 112)
        || u32_at(raw, 224) > MAX_ENGINE_STATE_BYTES
        || raw[1164] == PHASE_NONE
            && (u32_at(raw, 1170) != 0 || u32_at(raw, 1174) != 0 || u32_at(raw, 1178) != 0)
        || raw[1164] != PHASE_NONE
            && (u32_at(raw, 1170) > u32_at(raw, 1174)
                || u32_at(raw, 1174) == 0
                || u32_at(raw, 1178) == 0
                || u32_at(raw, 1178) as u64 > MAX_DECLARED_KERNEL_COMPUTE_UNITS)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    let resource_key = Pubkey::new_from_array(raw[1092..1124].try_into().expect("fixed width"));
    let resource_schema = VersionedId {
        id: u32_at(raw, 1124),
        version: u16_at(raw, 1128),
    };
    let resource_commitment: [u8; 32] = raw[1132..1164].try_into().expect("fixed width");
    let state_schema = VersionedId {
        id: u32_at(raw, 1183),
        version: u16_at(raw, 1187),
    };
    let state_lengths: Vec<u32> = (0..MAX_STATE_SPANS)
        .map(|index| u32_at(raw, 1222 + index * 4))
        .collect();
    let state_length_sum = state_lengths[..raw[122] as usize]
        .iter()
        .try_fold(0u32, |sum, len| sum.checked_add(*len))
        .ok_or_else(|| refusal(REFUSAL_SESSION))?;
    if (resource_key == Pubkey::default()
        && (resource_commitment != [0; 32]
            || resource_schema.id != 0
            || resource_schema.version != 0))
        || (resource_key != Pubkey::default()
            && (resource_commitment == [0; 32]
                || resource_schema.id == 0
                || resource_schema.version == 0))
        || state_schema.id == 0
        || state_schema.version == 0
        || state_lengths[raw[122] as usize..]
            .iter()
            .any(|len| *len != 0)
        || (raw[122] == 0 && state_length_sum != 0)
        || (raw[122] != 0
            && (state_lengths[..raw[122] as usize]
                .iter()
                .any(|len| *len == 0)
                || state_length_sum != u32_at(raw, 224)))
        || (raw[6] == STATUS_ACTIVE && (u32_at(raw, 1254) != 0 || u32_at(raw, 1258) != 0))
        || (raw[6] == STATUS_HALTED && u32_at(raw, 1258) != u32_at(raw, 112))
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(Session {
        id: u64_at(raw, 14),
        bump: raw[1262],
        status: raw[6],
        policy: raw[7],
        command_width: raw[8],
        max_steps: raw[9],
        capacity: u32_at(raw, 10),
        authority: Pubkey::new_from_array(raw[22..54].try_into().expect("fixed width")),
        writer: Pubkey::new_from_array(raw[54..86].try_into().expect("fixed width")),
        kernel_id: KernelId(raw[86..102].try_into().expect("fixed width")),
        semantic_version: u16_at(raw, 102),
        abi_version: u16_at(raw, 104),
        mode: VersionedId {
            id: u32_at(raw, 106),
            version: u16_at(raw, 110),
        },
        cursor: u32_at(raw, 112),
        frontier: u32_at(raw, 116),
        child_count: u16_at(raw, 120),
        state_span_count: raw[122],
        state_initialized: raw[1182] == 1,
        view_count: raw[123],
        stream_root: raw[124..156].try_into().expect("fixed width"),
        input_root: raw[156..188].try_into().expect("fixed width"),
        anchor_cursor: u32_at(raw, 188),
        state_anchor: raw[192..224].try_into().expect("fixed width"),
        state_bytes: u32_at(raw, 224),
        self_key: Pubkey::new_from_array(raw[228..260].try_into().expect("fixed width")),
        stream_key: Pubkey::new_from_array(raw[260..292].try_into().expect("fixed width")),
        state_keys: (0..MAX_STATE_SPANS)
            .map(|index| {
                let at = 292 + index * 32;
                Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
            })
            .collect(),
        view_keys,
        scratch_key: Pubkey::new_from_array(raw[1060..1092].try_into().expect("fixed width")),
        workspace_key: Pubkey::new_from_array(raw[1190..1222].try_into().expect("fixed width")),
        resource_key,
        resource_schema,
        resource_commitment,
        phase: raw[1164],
        phase_state_cursor: u32_at(raw, 1166),
        phase_cursor: u32_at(raw, 1170),
        phase_total: u32_at(raw, 1174),
        phase_compute_units: u32_at(raw, 1178),
        primary_state: raw[1189] == 1,
        state_schema,
        state_lengths,
        halt_reason: u32_at(raw, 1254),
        halt_cursor: u32_at(raw, 1258),
        last_advance_start: u32_at(raw, 1263),
    })
}

fn checked_session(
    program: &Pubkey,
    account: &AccountInfo,
    writable: bool,
    kernel: &dyn StatefulKernel,
) -> Result<Session, ProgramError> {
    checked_session_from(program, account, writable, kernel, None)
}

fn checked_session_from(
    program: &Pubkey,
    account: &AccountInfo,
    writable: bool,
    kernel: &dyn StatefulKernel,
    independent_authority: Option<&Pubkey>,
) -> Result<Session, ProgramError> {
    check_program_owned(account, program, writable)?;
    let raw = account.try_borrow_data()?;
    let session = decode_session(&raw)?;
    let authority = independent_authority.unwrap_or(&session.authority);
    if independent_authority.is_some_and(|key| key != &session.authority) {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let id = session.id.to_le_bytes();
    expect_derived_with_bump(
        account,
        program,
        &[SESSION_SEED, authority.as_ref(), &id],
        session.bump,
        AccountKind::exact(SESSION_MAGIC, SESSION_BYTES)
            .with_version(4, WIRE_VERSION as u16)
            .with_bump(1262),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_SESSION))?;
    if account.key != &session.self_key
        || session.kernel_id != kernel.manifest().id
        || session.semantic_version != kernel.manifest().semantic_version
        || session.abi_version != kernel.manifest().abi_version
        || session.mode != MODE_CONSENSUS_V3
        || kernel
            .manifest()
            .state
            .is_none_or(|schema| schema.id != session.state_schema)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(session)
}

fn store_session(account: &AccountInfo, session: &Session) -> ProgramResult {
    encode_session(account, session)
}

fn create_pda<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: CanonicalBump,
    data_len: usize,
) -> ProgramResult {
    if data_len > ACCOUNT_MAX_BYTES {
        return Err(refusal(REFUSAL_SESSION));
    }
    create_derived_account(
        program, payer, target, system, seeds, bump, data_len, data_len,
    )
    .map_err(|_| refusal(REFUSAL_SESSION))
}

fn open_session(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    check_unique(accounts)?;
    exact_data(data, 178)?;
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data[177] > 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let primary_state = data[177] == 1;
    let resource_key = Pubkey::new_from_array(data[107..139].try_into().expect("fixed width"));
    let resource_schema = VersionedId {
        id: u32_at(data, 139),
        version: u16_at(data, 143),
    };
    let resource_commitment: [u8; 32] = data[145..177].try_into().expect("fixed width");
    let (payer, authority, session_account, resource_account, resource_copy, system) =
        match accounts {
            [payer, authority, session, system] if resource_key == Pubkey::default() => {
                (payer, authority, session, None, None, system)
            }
            [payer, authority, session, resource, copy, system]
                if resource_key != Pubkey::default() =>
            {
                (
                    payer,
                    authority,
                    session,
                    Some(resource),
                    Some(copy),
                    system,
                )
            }
            _ => return Err(ProgramError::NotEnoughAccountKeys),
        };
    if !payer.is_signer
        || !payer.is_writable
        || !authority.is_signer
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if let (Some(resource), Some(copy)) = (resource_account, resource_copy) {
        let (expected_copy, _) = resource_pda(program, session_account.key);
        if resource.key != &resource_key
            || resource.is_writable
            || resource.data_is_empty()
            || resource.data_len() > ACCOUNT_MAX_BYTES - RESOURCE_HEADER_BYTES
            || copy.key != &expected_copy
            || *system.key != system_program::id()
        {
            return Err(refusal(REFUSAL_RESOURCE));
        }
    } else if resource_commitment != [0; 32]
        || resource_schema != (VersionedId { id: 0, version: 0 })
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let schema = validate_kernel(kernel)?;
    let id = u64_at(data, 2);
    let policy = data[10];
    let width = data[11];
    let capacity = u32_at(data, 12);
    let max_steps = data[16];
    let kernel_id = KernelId(data[17..33].try_into().expect("fixed width"));
    let semantic = u16_at(data, 33);
    let abi = u16_at(data, 35);
    let mode = VersionedId {
        id: u32_at(data, 37),
        version: u16_at(data, 41),
    };
    let stream_root: [u8; 32] = data[43..75].try_into().expect("fixed width");
    let requested_writer = Pubkey::new_from_array(data[75..107].try_into().expect("fixed width"));
    let writer = if policy == POLICY_INDEXED {
        *authority.key
    } else {
        requested_writer
    };
    let manifest = kernel.manifest();
    let input_limit =
        (manifest.resources.max_input_bytes as usize).min(manifest.input.max_bytes as usize);
    let compute_bound = manifest
        .resources
        .max_compute_units
        .checked_mul(max_steps as u64);
    if session_account.owner != &system_program::id()
        || session_account.lamports() != 0
        || !session_account.data_is_empty()
        || kernel_id != manifest.id
        || semantic != manifest.semantic_version
        || abi != manifest.abi_version
        || mode != MODE_CONSENSUS_V3
        || !manifest.modes.contains(&mode)
        || !matches!(policy, POLICY_INDEXED | POLICY_APPEND)
        || width == 0
        || width as usize > MAX_COMMAND_BYTES
        || width as usize > input_limit
        || capacity < 2
        || capacity > MAX_STREAM_CAPACITY
        || max_steps == 0
        || max_steps > MAX_STEPS_PER_ADVANCE
        || max_steps as u32 > manifest.resources.max_operations
        || compute_bound.is_none_or(|bound| bound > MAX_DECLARED_KERNEL_COMPUTE_UNITS)
        || (policy == POLICY_INDEXED && requested_writer != Pubkey::default())
        || (policy == POLICY_APPEND && requested_writer == Pubkey::default())
        || (resource_key != Pubkey::default()
            && (resource_schema.id == 0
                || resource_schema.version == 0
                || resource_commitment == [0; 32]))
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let (expected, bump) = session_pda(program, authority.key, id);
    if session_account.key != &expected {
        return Err(refusal(REFUSAL_SESSION));
    }
    let id_bytes = id.to_le_bytes();
    create_pda(
        program,
        payer,
        session_account,
        system,
        &[SESSION_SEED, authority.key.as_ref(), &id_bytes],
        bump,
        SESSION_BYTES,
    )?;
    if let (Some(resource), Some(copy)) = (resource_account, resource_copy) {
        let len = resource.data_len() as u32;
        let allocated = len.min(CHILD_GROW_BYTES);
        create_pda(
            program,
            payer,
            copy,
            system,
            &[RESOURCE_SEED, session_account.key.as_ref()],
            resource_pda(program, session_account.key).1,
            RESOURCE_HEADER_BYTES + allocated as usize,
        )?;
        initialize_resource_header(copy, session_account, &resource_commitment, len, allocated)?;
    }
    let resource_key = resource_copy.map_or(Pubkey::default(), |account| *account.key);
    encode_session(
        session_account,
        &Session {
            id,
            bump: bump.value(),
            status: STATUS_ACTIVE,
            policy,
            command_width: width,
            max_steps,
            capacity,
            authority: *authority.key,
            writer,
            kernel_id,
            semantic_version: semantic,
            abi_version: abi,
            mode,
            cursor: 0,
            frontier: 0,
            child_count: u16::from(resource_key != Pubkey::default()),
            state_span_count: 0,
            state_initialized: false,
            view_count: 0,
            stream_root,
            input_root: stream_root,
            anchor_cursor: 0,
            state_anchor: [0; 32],
            state_bytes: 0,
            self_key: *session_account.key,
            stream_key: Pubkey::default(),
            state_keys: vec![Pubkey::default(); MAX_STATE_SPANS],
            view_keys: vec![Pubkey::default(); MAX_VIEW_OUTPUTS],
            scratch_key: Pubkey::default(),
            resource_key,
            resource_schema,
            resource_commitment,
            phase: PHASE_NONE,
            phase_state_cursor: 0,
            phase_cursor: 0,
            phase_total: 0,
            phase_compute_units: 0,
            primary_state,
            state_schema: schema.id,
            state_lengths: vec![0; MAX_STATE_SPANS],
            workspace_key: Pubkey::default(),
            halt_reason: 0,
            halt_cursor: 0,
            last_advance_start: 0,
        },
    )
}

fn stream_pda_check(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    writable: bool,
) -> ProgramResult {
    check_program_owned(account, program, writable)?;
    if session.stream_key == Pubkey::default() {
        return Err(refusal(REFUSAL_SESSION));
    }
    expect_keyed(
        account,
        program,
        &session.stream_key,
        AccountKind::exact(
            STREAM_MAGIC,
            CHILD_HEADER_BYTES + session.capacity as usize * SLOT_BYTES,
        )
        .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_SESSION))?;
    let raw = account.try_borrow_data()?;
    let expected_len = CHILD_HEADER_BYTES + session.capacity as usize * SLOT_BYTES;
    if raw.len() != expected_len
        || &raw[..4] != STREAM_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STREAM
        || raw[7] != STATUS_ACTIVE
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.stream_root
        || u32_at(&raw, 72) != session.capacity
        || u32_at(&raw, 76) != session.cursor
        || u32_at(&raw, 80) != session.frontier
        || u32_at(&raw, 84) as usize != SLOT_BYTES
        || raw[88..120] != session.writer.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(())
}

fn create_stream(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 3)?;
    let [payer, session_account, stream, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != 0 || !payer.is_signer || !payer.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE || session.stream_key != Pubkey::default() {
        return Err(refusal(REFUSAL_LIVE));
    }
    let (expected, bump) = stream_pda(program, session_account.key);
    if stream.key != &expected || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_SESSION));
    }
    let len = CHILD_HEADER_BYTES + session.capacity as usize * SLOT_BYTES;
    create_pda(
        program,
        payer,
        stream,
        system,
        &[STREAM_SEED, session_account.key.as_ref()],
        bump,
        len,
    )?;
    let mut raw = stream.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(STREAM_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_STREAM;
    raw[7] = STATUS_ACTIVE;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(&session.stream_root);
    put_u32(&mut raw, 72, session.capacity);
    put_u32(&mut raw, 76, session.cursor);
    put_u32(&mut raw, 80, session.frontier);
    put_u32(&mut raw, 84, SLOT_BYTES as u32);
    raw[88..120].copy_from_slice(session.writer.as_ref());
    drop(raw);
    session.stream_key = *stream.key;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    store_session(session_account, &session)
}

fn grow_stream(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [payer, session_account, stream, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != 1 || !payer.is_signer || !payer.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE || session.cursor != session.capacity {
        return Err(refusal(REFUSAL_BACKPRESSURE));
    }
    stream_pda_check(program, stream, session_account, &session, true)?;
    let new_capacity = u32_at(data, 3);
    let delta = new_capacity
        .checked_sub(session.capacity)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    let new_len = CHILD_HEADER_BYTES + new_capacity as usize * SLOT_BYTES;
    if *system.key != system_program::id()
        || new_capacity > MAX_STREAM_CAPACITY
        || delta == 0
        || delta > MAX_STREAM_GROWTH_SLOTS
        || new_len > ACCOUNT_MAX_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let required = Rent::get()?.minimum_balance(new_len);
    let top_up = required.saturating_sub(stream.lamports());
    if top_up != 0 {
        invoke(
            &system_instruction::transfer(payer.key, stream.key, top_up),
            &[payer.clone(), stream.clone(), system.clone()],
        )?;
    }
    let old_len = stream.data_len();
    stream.realloc(new_len, true)?;
    {
        let mut raw = stream.try_borrow_mut_data()?;
        raw[old_len..new_len].fill(0);
        put_u32(&mut raw, 72, new_capacity);
    }
    session.capacity = new_capacity;
    store_session(session_account, &session)
}

fn create_state(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data.len() < 7 || data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [payer, session_account, remainder @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut session = checked_session(program, session_account, true, kernel)?;
    let count = data[2] as usize;
    if count == 0 || count > MAX_STATE_SPANS || data.len() != 3 + count * 4 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let schema = validate_kernel(kernel)?;
    let resource_count = usize::from(session.resource_key != Pubkey::default());
    if remainder.len() != resource_count + count + 1 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (resource_accounts, after_resource) = remainder.split_at(resource_count);
    let (state_accounts, system_items) = after_resource.split_at(count);
    let [system] = system_items else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !payer.is_signer || !payer.is_writable || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if session.status != STATUS_ACTIVE || session.state_span_count != 0 {
        return Err(refusal(REFUSAL_STATE));
    }
    if resource_count == 1 {
        let resource = &resource_accounts[0];
        checked_resource(program, resource, session_account, &session, false, false)?;
    } else if session.resource_key != Pubkey::default() {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let mut lengths = Vec::with_capacity(count);
    let mut total = 0u32;
    for index in 0..count {
        let len = u32_at(data, 3 + index * 4);
        if len == 0 {
            return Err(refusal(REFUSAL_RESOURCE));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
        lengths.push(len);
    }
    if total > schema.max_bytes
        || total > kernel.manifest().resources.max_state_bytes
        || total > MAX_ENGINE_STATE_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let mut offset = 0u32;
    for (index, (account, len)) in state_accounts.iter().zip(lengths.iter()).enumerate() {
        let (expected, bump) = state_pda(program, session_account.key, index as u8);
        if account.key != &expected {
            return Err(refusal(REFUSAL_STATE));
        }
        let initial_len = (*len).min(CHILD_GROW_BYTES) as usize;
        let header_len = if session.primary_state && index == 0 {
            0
        } else {
            CHILD_HEADER_BYTES
        };
        create_pda(
            program,
            payer,
            account,
            system,
            &[STATE_SEED, session_account.key.as_ref(), &[index as u8]],
            bump,
            header_len + initial_len,
        )?;
        let mut raw = account.try_borrow_mut_data()?;
        raw.fill(0);
        if header_len != 0 {
            raw[..4].copy_from_slice(STATE_MAGIC);
            put_u16(&mut raw, 4, WIRE_VERSION as u16);
            raw[6] = KIND_STATE;
            raw[8..40].copy_from_slice(session_account.key.as_ref());
            raw[40..72].copy_from_slice(session.authority.as_ref());
            put_u32(&mut raw, 72, schema.id.id);
            put_u16(&mut raw, 76, schema.id.version);
            raw[78] = index as u8;
            raw[79] = count as u8;
            put_u32(&mut raw, 80, offset);
            put_u32(&mut raw, 84, *len);
            put_u32(&mut raw, 96, total);
            put_u32(&mut raw, 100, initial_len as u32);
        }
        drop(raw);
        session.state_keys[index] = *account.key;
        session.state_lengths[index] = *len;
        offset = offset
            .checked_add(*len)
            .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    }
    session.state_span_count = count as u8;
    session.state_initialized = false;
    session.state_bytes = total;
    session.child_count = session
        .child_count
        .checked_add(count as u16)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    store_session(session_account, &session)
}

fn grow_child_data<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    desired: u32,
    allocated: u32,
) -> Result<u32, ProgramError> {
    if !payer.is_signer || !payer.is_writable || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if allocated >= desired
        || target.data_len() != CHILD_HEADER_BYTES + allocated as usize
        || desired > (ACCOUNT_MAX_BYTES - CHILD_HEADER_BYTES) as u32
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let next = desired.min(allocated.saturating_add(CHILD_GROW_BYTES));
    let old_len = target.data_len();
    let new_len = CHILD_HEADER_BYTES + next as usize;
    let required = Rent::get()?.minimum_balance(new_len);
    let top_up = required.saturating_sub(target.lamports());
    if top_up != 0 {
        invoke(
            &system_instruction::transfer(payer.key, target.key, top_up),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    target.realloc(new_len, true)?;
    let mut raw = target.try_borrow_mut_data()?;
    raw[old_len..new_len].fill(0);
    Ok(next)
}

fn grow_state(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 4)?;
    let [payer, session_account, state, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != STATE_OP_GROW {
        return Err(ProgramError::InvalidInstructionData);
    }
    let session = checked_session(program, session_account, false, kernel)?;
    let index = data[3] as usize;
    if session.status != STATUS_ACTIVE
        || session.state_initialized
        || session.phase != PHASE_NONE
        || index >= session.state_span_count as usize
        || session.state_span_count == 0
        || session.state_keys[index] != *state.key
    {
        return Err(refusal(REFUSAL_STATE));
    }
    check_program_owned(state, program, true)?;
    let schema = validate_kernel(kernel)?;
    let state_kind = if session.primary_state && index == 0 {
        let len = session.state_lengths[index] as usize;
        AccountKind::variable(b"", len.min(CHILD_GROW_BYTES as usize), len)
    } else {
        AccountKind::variable(STATE_MAGIC, CHILD_HEADER_BYTES + 1, ACCOUNT_MAX_BYTES)
            .with_version(4, WIRE_VERSION as u16)
    };
    if session.state_keys[index] == Pubkey::default() {
        return Err(refusal(REFUSAL_STATE));
    }
    expect_keyed(
        state,
        program,
        &session.state_keys[index],
        state_kind,
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_STATE))?;
    let raw = state.try_borrow_data()?;
    let headerless = session.primary_state && index == 0;
    if schema.id != session.state_schema {
        return Err(refusal(REFUSAL_STATE));
    }
    let (desired, allocated) = if headerless {
        (session.state_lengths[index], raw.len() as u32)
    } else {
        if raw.len() < CHILD_HEADER_BYTES
            || &raw[..4] != STATE_MAGIC
            || u16_at(&raw, 4) != WIRE_VERSION as u16
            || raw[6] != KIND_STATE
            || raw[78] as usize != index
            || raw[79] as usize != session.state_span_count as usize
            || raw[8..40] != session_account.key.to_bytes()
            || raw[40..72] != session.authority.to_bytes()
            || u32_at(&raw, 72) != schema.id.id
            || u16_at(&raw, 76) != schema.id.version
            || raw[104..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
            || u32_at(&raw, 96) != session.state_bytes
        {
            return Err(refusal(REFUSAL_STATE));
        }
        (u32_at(&raw, 84), u32_at(&raw, 100))
    };
    drop(raw);
    if headerless {
        grow_headerless_state(payer, state, system, desired, allocated)?;
        return Ok(());
    }
    let next = grow_child_data(payer, state, system, desired, allocated)?;
    put_u32(&mut state.try_borrow_mut_data()?, 100, next);
    Ok(())
}

fn grow_headerless_state<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    desired: u32,
    allocated: u32,
) -> Result<u32, ProgramError> {
    if !payer.is_signer
        || !payer.is_writable
        || !target.is_writable
        || *system.key != system_program::id()
        || target.data_len() != allocated as usize
        || allocated >= desired
        || desired as usize > ACCOUNT_MAX_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let next = desired.min(allocated.saturating_add(CHILD_GROW_BYTES));
    let new_len = next as usize;
    let required = Rent::get()?.minimum_balance(new_len);
    let top_up = required.saturating_sub(target.lamports());
    if top_up != 0 {
        invoke(
            &system_instruction::transfer(payer.key, target.key, top_up),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    target.realloc(new_len, true)?;
    Ok(next)
}

fn initialize_state(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 3)?;
    if data[1] != WIRE_VERSION || data[2] != STATE_OP_INITIALIZE {
        return Err(ProgramError::InvalidInstructionData);
    }
    let primary_layout = accounts.first().is_some_and(|account| !account.is_signer);
    let (authority, session_account, remainder) = if primary_layout {
        if accounts.len() < 3 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        (&accounts[1], &accounts[2], &accounts[3..])
    } else {
        let [authority, session_account, remainder @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        (authority, session_account, remainder)
    };
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    check_unique(accounts)?;
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    let count = session.state_span_count as usize;
    let resource_count = usize::from(session.resource_key != Pubkey::default());
    if !authority.is_signer
        || authority.key != &session.authority
        || primary_layout != session.primary_state
        || session.status != STATUS_ACTIVE
        || session.state_initialized
        || session.phase != PHASE_NONE
        || count == 0
        || remainder.len() != resource_count + count - usize::from(primary_layout)
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let (resource_accounts, state_tail) = remainder.split_at(resource_count);
    let state_accounts: Vec<AccountInfo> = if primary_layout {
        core::iter::once(accounts[0].clone())
            .chain(state_tail.iter().cloned())
            .collect()
    } else {
        state_tail.to_vec()
    };
    if state_accounts.len() != count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let resource_meta = if resource_count == 1 {
        Some(checked_resource(
            program,
            &resource_accounts[0],
            session_account,
            &session,
            true,
            false,
        )?)
    } else {
        None
    };
    let schema = validate_kernel(kernel)?;
    let mut offset = 0u32;
    for (index, account) in state_accounts.iter().enumerate() {
        let meta = state_meta(
            program,
            account,
            session_account,
            &session,
            schema,
            index,
            true,
        )?;
        if meta.index as usize != index
            || meta.count as usize != count
            || meta.offset != offset
            || meta.before_cursor != 0
            || meta.after_cursor != 0
            || meta.total_len != session.state_bytes
        {
            return Err(refusal(REFUSAL_STATE));
        }
        offset = offset
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_STATE))?;
    }
    if offset != session.state_bytes {
        return Err(refusal(REFUSAL_STATE));
    }
    let resource_guards = resource_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
    let resource_spans: Vec<AccountSpan<'_>> = resource_accounts
        .iter()
        .zip(resource_guards.iter())
        .zip(resource_meta.iter())
        .map(|((account, raw), meta)| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: session.resource_schema,
            offset: 0,
            data: &raw[RESOURCE_HEADER_BYTES..RESOURCE_HEADER_BYTES + meta.len as usize],
        })
        .collect();
    let mut guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_mut_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut spans = Vec::with_capacity(count);
    offset = 0;
    for (index, guard) in guards.iter_mut().enumerate() {
        let len = session.state_lengths[index];
        let header_len = if session.primary_state && index == 0 {
            0
        } else {
            CHILD_HEADER_BYTES
        };
        spans.push(StateSpanMut {
            key: state_accounts[index].key.to_bytes(),
            owner: state_accounts[index].owner.to_bytes(),
            schema: schema.id,
            offset,
            data: &mut guard[header_len..header_len + len as usize],
        });
        offset += len;
    }
    let bind = kernel.bind_invocation_state(&mut spans);
    let init = if bind.is_ok() {
        kernel.initial_state_spans_with_resources(
            &resource_spans,
            &session.resource_commitment,
            &mut spans,
        )
    } else {
        Err(crate::kernel::KernelError::Refused)
    };
    kernel.unbind_invocation_state();
    let written = init.map_err(|_| refusal(REFUSAL_KERNEL))?;
    if written != session.state_bytes as usize {
        return Err(refusal(REFUSAL_KERNEL));
    }
    drop(spans);
    drop(guards);
    drop(resource_spans);
    drop(resource_guards);
    session.state_initialized = true;
    store_session(session_account, &session)
}

fn initialization_declaration(kernel: &dyn StatefulKernel, declared: u32) -> ProgramResult {
    let bytes = kernel.max_initialization_phase_bytes();
    let compute = kernel.initialization_phase_compute_units();
    if bytes == 0
        || bytes > 65_536
        || compute == 0
        || compute as u64 > MAX_DECLARED_KERNEL_COMPUTE_UNITS
        || declared != compute
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    Ok(())
}

fn begin_initialization(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 11)?;
    let [authority, session_account, remainder @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != STATE_OP_BEGIN_INITIALIZE || !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if session.resource_key == Pubkey::default() {
        if !remainder.is_empty() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
    } else {
        let [resource] = remainder else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        checked_resource(program, resource, session_account, &session, true, false)?;
    }
    let declared = u32_at(data, 7);
    initialization_declaration(kernel, declared)?;
    if session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.state_initialized
        || session.state_span_count == 0
        || session.phase != PHASE_NONE
        || u32_at(data, 3) != session.state_bytes
    {
        return Err(refusal(REFUSAL_INITIALIZATION));
    }
    session.phase = PHASE_INITIALIZATION;
    session.phase_state_cursor = session.cursor;
    session.phase_cursor = 0;
    session.phase_total = session.state_bytes;
    session.phase_compute_units = declared;
    store_session(session_account, &session)
}

fn run_initialization(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 11)?;
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account, remainder, state0) = if primary_layout {
        (
            &accounts[1],
            &accounts[2],
            &accounts[3..],
            Some(accounts[0].clone()),
        )
    } else {
        (&accounts[0], &accounts[1], &accounts[2..], None)
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != STATE_OP_RUN_INITIALIZE || !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if primary_layout != session.primary_state {
        return Err(refusal(REFUSAL_STATE));
    }
    if session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.state_initialized
        || session.phase != PHASE_INITIALIZATION
        || session.phase_state_cursor != session.cursor
    {
        return Err(refusal(REFUSAL_INITIALIZATION));
    }
    if u32_at(data, 3) != session.phase_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let declared = u32_at(data, 7);
    initialization_declaration(kernel, declared)?;
    if declared != session.phase_compute_units {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let count = session.state_span_count as usize;
    let resource_count = usize::from(session.resource_key != Pubkey::default());
    if remainder.len() != resource_count + count - usize::from(primary_layout) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (resource_accounts, state_tail) = remainder.split_at(resource_count);
    let state_accounts: Vec<AccountInfo> = if let Some(state0) = state0 {
        core::iter::once(state0)
            .chain(state_tail.iter().cloned())
            .collect()
    } else {
        state_tail.to_vec()
    };
    if state_accounts.len() != count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let resource_meta = if resource_count == 1 {
        Some(checked_resource(
            program,
            &resource_accounts[0],
            session_account,
            &session,
            true,
            false,
        )?)
    } else {
        None
    };
    let schema = validate_kernel(kernel)?;
    let mut offset = 0u32;
    for (index, account) in state_accounts.iter().enumerate() {
        let meta = state_meta(
            program,
            account,
            session_account,
            &session,
            schema,
            index,
            true,
        )?;
        if meta.index as usize != index
            || meta.count as usize != count
            || meta.offset != offset
            || meta.before_cursor != 0
            || meta.after_cursor != 0
            || meta.total_len != session.state_bytes
        {
            return Err(refusal(REFUSAL_STATE));
        }
        offset = offset
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_STATE))?;
    }
    if offset != session.state_bytes {
        return Err(refusal(REFUSAL_STATE));
    }
    let resource_guards = resource_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
    let resource_spans: Vec<AccountSpan<'_>> = resource_accounts
        .iter()
        .zip(resource_guards.iter())
        .zip(resource_meta.iter())
        .map(|((account, raw), meta)| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: session.resource_schema,
            offset: 0,
            data: &raw[RESOURCE_HEADER_BYTES..RESOURCE_HEADER_BYTES + meta.len as usize],
        })
        .collect();
    let mut guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_mut_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut spans = Vec::with_capacity(count);
    offset = 0;
    for (index, guard) in guards.iter_mut().enumerate() {
        let len = session.state_lengths[index] as usize;
        let header_len = if session.primary_state && index == 0 {
            0
        } else {
            CHILD_HEADER_BYTES
        };
        spans.push(StateSpanMut {
            key: state_accounts[index].key.to_bytes(),
            owner: state_accounts[index].owner.to_bytes(),
            schema: session.state_schema,
            offset,
            data: &mut guard[header_len..header_len + len],
        });
        offset += len as u32;
    }
    let left = session
        .phase_total
        .checked_sub(session.phase_cursor)
        .ok_or_else(|| refusal(REFUSAL_PHASE_CURSOR))?;
    if left == 0 {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let expected = left.min(kernel.max_initialization_phase_bytes()) as usize;
    let phase = InitializationPhase {
        cursor: session.phase_cursor,
        total_bytes: session.phase_total,
        compute_units: declared,
    };
    let bind = kernel.bind_invocation_state(&mut spans);
    let result = if bind.is_ok() {
        kernel.initialize_state_phase(
            phase,
            &resource_spans,
            &session.resource_commitment,
            &mut spans,
        )
    } else {
        Err(crate::kernel::KernelError::Refused)
    };
    kernel.unbind_invocation_state();
    let written = result.map_err(|_| refusal(REFUSAL_KERNEL))?;
    if written != expected {
        return Err(refusal(REFUSAL_KERNEL));
    }
    drop(spans);
    drop(guards);
    drop(resource_spans);
    drop(resource_guards);
    session.phase_cursor = session
        .phase_cursor
        .checked_add(written as u32)
        .ok_or_else(|| refusal(REFUSAL_PHASE_CURSOR))?;
    if session.phase_cursor == session.phase_total {
        session.state_initialized = true;
        clear_phase(&mut session);
    }
    store_session(session_account, &session)
}

fn grow_view(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 4)?;
    let [payer, session_account, view, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != VIEW_OP_GROW {
        return Err(ProgramError::InvalidInstructionData);
    }
    let session = checked_session(program, session_account, false, kernel)?;
    let role = data[3];
    if session.status != STATUS_ACTIVE || !session.state_initialized || session.phase != PHASE_NONE
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let (kind, expected_key) = if role == SCRATCH_ROLE {
        (KIND_SCRATCH, session.scratch_key)
    } else if role == WORKSPACE_ROLE {
        (KIND_WORKSPACE, session.workspace_key)
    } else if (role as usize) < MAX_VIEW_OUTPUTS {
        (KIND_VIEW, session.view_keys[role as usize])
    } else {
        return Err(refusal(REFUSAL_VIEW));
    };
    if expected_key == Pubkey::default() {
        return Err(refusal(REFUSAL_VIEW));
    }
    check_program_owned(view, program, true)?;
    expect_keyed(
        view,
        program,
        &expected_key,
        AccountKind::variable(VIEW_MAGIC, CHILD_HEADER_BYTES + 1, ACCOUNT_MAX_BYTES)
            .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable: true,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_VIEW))?;
    let raw = view.try_borrow_data()?;
    if raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != VIEW_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != kind
        || raw[7] != role
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let len = u32_at(&raw, 108);
    let allocated = u32_at(&raw, 116);
    if len == 0
        || raw.len() != CHILD_HEADER_BYTES + allocated as usize
        || allocated > len
        || (kind == KIND_SCRATCH && len > MAX_SCRATCH_BYTES)
        || (kind == KIND_WORKSPACE
            && (len > kernel.max_view_workspace_bytes() || len > MAX_VIEW_BYTES))
        || (kind == KIND_VIEW && len > MAX_VIEW_BYTES)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    if kind == KIND_VIEW {
        let abi_id: [u8; 32] = raw[72..104].try_into().expect("fixed width");
        let source_offset = u32_at(&raw, 104);
        let source_end = source_offset
            .checked_add(len)
            .ok_or_else(|| refusal(REFUSAL_VIEW))?;
        if source_end > session.state_bytes
            || !kernel
                .view_abis()
                .iter()
                .any(|abi| abi.role == role && abi.id == abi_id && len <= abi.max_bytes)
        {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else if kind == KIND_WORKSPACE && (raw[72..104] != [0; 32] || u32_at(&raw, 104) != 0) {
        return Err(refusal(REFUSAL_VIEW));
    }
    drop(raw);
    let next = grow_child_data(payer, view, system, len, allocated)?;
    put_u32(&mut view.try_borrow_mut_data()?, 116, next);
    Ok(())
}

fn state_meta(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    schema: StateSchema,
    index: usize,
    writable: bool,
) -> Result<StateSpanMeta, ProgramError> {
    check_program_owned(account, program, writable)?;
    if index >= MAX_STATE_SPANS {
        return Err(refusal(REFUSAL_STATE));
    }
    if session.state_keys[index] == Pubkey::default() {
        return Err(refusal(REFUSAL_STATE));
    }
    let kind = if session.primary_state && index == 0 {
        AccountKind::exact(b"", session.state_lengths[0] as usize)
    } else {
        AccountKind::variable(STATE_MAGIC, CHILD_HEADER_BYTES + 1, ACCOUNT_MAX_BYTES)
            .with_version(4, WIRE_VERSION as u16)
    };
    expect_keyed(
        account,
        program,
        &session.state_keys[index],
        kind,
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_STATE))?;
    let raw = account.try_borrow_data()?;
    if session.primary_state && index == 0 {
        let len = session.state_lengths[0];
        if schema.id != session.state_schema || len == 0 || raw.len() != len as usize {
            return Err(refusal(REFUSAL_STATE));
        }
        return Ok(StateSpanMeta {
            schema: session.state_schema,
            index: 0,
            count: session.state_span_count,
            offset: 0,
            len,
            before_cursor: session.last_advance_start,
            after_cursor: session.cursor,
            total_len: session.state_bytes,
        });
    }
    if raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != STATE_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STATE
        || raw[7] != 0
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || schema.id != session.state_schema
        || u32_at(&raw, 72) != session.state_schema.id
        || u16_at(&raw, 76) != session.state_schema.version
        || raw[78] as usize != index
        || raw[79] as usize != session.state_span_count as usize
        || u32_at(&raw, 88) > u32_at(&raw, 92)
        || u32_at(&raw, 96) != session.state_bytes
        || raw[104..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let offset = u32_at(&raw, 80);
    let len = u32_at(&raw, 84);
    let total_len = u32_at(&raw, 96);
    let allocated_len = u32_at(&raw, 100);
    let end = offset
        .checked_add(len)
        .ok_or_else(|| refusal(REFUSAL_STATE))?;
    if len == 0
        || end > total_len
        || allocated_len != len
        || len != session.state_lengths[index]
        || raw.len() != CHILD_HEADER_BYTES + allocated_len as usize
    {
        return Err(refusal(REFUSAL_STATE));
    }
    Ok(StateSpanMeta {
        schema: schema.id,
        index: index as u8,
        count: session.state_span_count,
        offset,
        len,
        before_cursor: u32_at(&raw, 88),
        after_cursor: u32_at(&raw, 92),
        total_len,
    })
}

fn validate_state_set(
    program: &Pubkey,
    session_account: &AccountInfo,
    session: &Session,
    accounts: &[AccountInfo],
    schema: StateSchema,
    writable: bool,
    expected_cursor: u32,
) -> Result<Vec<StateSpanMeta>, ProgramError> {
    if !session.state_initialized
        || accounts.len() != session.state_span_count as usize
        || accounts.is_empty()
        || accounts.len() > MAX_STATE_SPANS
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let mut result = Vec::with_capacity(accounts.len());
    let mut offset = 0u32;
    let mut before = None;
    for (index, account) in accounts.iter().enumerate() {
        let meta = state_meta(
            program,
            account,
            session_account,
            session,
            schema,
            index,
            writable,
        )?;
        if meta.index as usize != index
            || meta.count as usize != accounts.len()
            || meta.offset != offset
            || meta.after_cursor != expected_cursor
            || meta.total_len != session.state_bytes
            || before.is_some_and(|value| value != meta.before_cursor)
        {
            return Err(refusal(REFUSAL_STATE));
        }
        before = Some(meta.before_cursor);
        offset = offset
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_STATE))?;
        result.push(meta);
    }
    if offset != session.state_bytes {
        return Err(refusal(REFUSAL_STATE));
    }
    Ok(result)
}

fn create_view(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 43)?;
    let [payer, session_account, view, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !payer.is_signer || !payer.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
        || !session.state_initialized
        || session.state_span_count == 0
        || session.stream_key == Pubkey::default()
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let role = data[2];
    let abi_id: [u8; 32] = data[3..35].try_into().expect("fixed width");
    let source_offset = u32_at(data, 35);
    let len = u32_at(data, 39);
    if len == 0
        || len > MAX_VIEW_BYTES
        || role as usize >= MAX_VIEW_OUTPUTS
        || session.view_keys[role as usize] != Pubkey::default()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let abi: Option<ViewAbi> = kernel
        .view_abis()
        .iter()
        .copied()
        .find(|abi| abi.role == role && abi.id == abi_id);
    let Some(abi) = abi else {
        return Err(refusal(REFUSAL_VIEW));
    };
    let source_end = source_offset
        .checked_add(len)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    if len > abi.max_bytes
        || source_end > session.state_bytes
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let (expected, bump) = view_pda(program, session_account.key, role);
    if view.key != &expected {
        return Err(refusal(REFUSAL_VIEW));
    }
    create_pda(
        program,
        payer,
        view,
        system,
        &[VIEW_SEED, session_account.key.as_ref(), &[role]],
        bump,
        CHILD_HEADER_BYTES + len.min(CHILD_GROW_BYTES) as usize,
    )?;
    let mut raw = view.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(VIEW_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_VIEW;
    raw[7] = role;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(session.authority.as_ref());
    raw[72..104].copy_from_slice(&abi_id);
    put_u32(&mut raw, 104, source_offset);
    put_u32(&mut raw, 108, len);
    put_u32(&mut raw, 112, u32::MAX);
    put_u32(&mut raw, 116, len.min(CHILD_GROW_BYTES));
    session.view_keys[role as usize] = *view.key;
    session.view_count = session
        .view_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    drop(raw);
    store_session(session_account, &session)
}

fn create_scratch(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 43)?;
    let [payer, session_account, scratch, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || data[2] != SCRATCH_ROLE || !payer.is_signer || !payer.is_writable
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
        || !session.state_initialized
        || session.state_span_count == 0
        || session.view_count == 0
        || session.scratch_key != Pubkey::default()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let abi_id: [u8; 32] = data[3..35].try_into().expect("fixed width");
    let source_offset = u32_at(data, 35);
    let len = u32_at(data, 39);
    if abi_id != [0; 32]
        || source_offset != 0
        || len == 0
        || len > MAX_SCRATCH_BYTES
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let (expected, bump) = view_pda(program, session_account.key, SCRATCH_ROLE);
    if scratch.key != &expected {
        return Err(refusal(REFUSAL_VIEW));
    }
    create_pda(
        program,
        payer,
        scratch,
        system,
        &[VIEW_SEED, session_account.key.as_ref(), &[SCRATCH_ROLE]],
        bump,
        CHILD_HEADER_BYTES + len.min(CHILD_GROW_BYTES) as usize,
    )?;
    let mut raw = scratch.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(VIEW_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_SCRATCH;
    raw[7] = SCRATCH_ROLE;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(session.authority.as_ref());
    put_u32(&mut raw, 108, len);
    put_u32(&mut raw, 112, u32::MAX);
    put_u32(&mut raw, 116, len.min(CHILD_GROW_BYTES));
    session.scratch_key = *scratch.key;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    drop(raw);
    store_session(session_account, &session)
}

fn create_workspace(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [payer, session_account, workspace, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION
        || data[2] != WORKSPACE_ROLE
        || !payer.is_signer
        || !payer.is_writable
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    let len = u32_at(data, 3);
    let limit = kernel.max_view_workspace_bytes();
    // A workspace is a view payload; publication scratch has its own smaller
    // cap and should not constrain workspace-backed engine state.
    if session.status != STATUS_ACTIVE
        || !session.state_initialized
        || session.workspace_key != Pubkey::default()
        || len == 0
        || len > limit
        || len > MAX_VIEW_BYTES
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let (expected, bump) = view_pda(program, session_account.key, WORKSPACE_ROLE);
    if workspace.key != &expected {
        return Err(refusal(REFUSAL_VIEW));
    }
    create_pda(
        program,
        payer,
        workspace,
        system,
        &[VIEW_SEED, session_account.key.as_ref(), &[WORKSPACE_ROLE]],
        bump,
        CHILD_HEADER_BYTES + len.min(CHILD_GROW_BYTES) as usize,
    )?;
    let mut raw = workspace.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(VIEW_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_WORKSPACE;
    raw[7] = WORKSPACE_ROLE;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(session.authority.as_ref());
    put_u32(&mut raw, 108, len);
    put_u32(&mut raw, 112, u32::MAX);
    put_u32(&mut raw, 116, len.min(CHILD_GROW_BYTES));
    session.workspace_key = *workspace.key;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    drop(raw);
    store_session(session_account, &session)
}

fn view_meta(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    role: u8,
    writable: bool,
    kernel: &dyn StatefulKernel,
) -> Result<ViewMeta, ProgramError> {
    check_program_owned(account, program, writable)?;
    let (kind, expected_key) = if role == SCRATCH_ROLE {
        (KIND_SCRATCH, session.scratch_key)
    } else if role == WORKSPACE_ROLE {
        (KIND_WORKSPACE, session.workspace_key)
    } else if (role as usize) < MAX_VIEW_OUTPUTS {
        (KIND_VIEW, session.view_keys[role as usize])
    } else {
        return Err(refusal(REFUSAL_VIEW));
    };
    if expected_key == Pubkey::default() {
        return Err(refusal(REFUSAL_VIEW));
    }
    expect_keyed(
        account,
        program,
        &expected_key,
        AccountKind::variable(VIEW_MAGIC, CHILD_HEADER_BYTES + 1, ACCOUNT_MAX_BYTES)
            .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_VIEW))?;
    let raw = account.try_borrow_data()?;
    if raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != VIEW_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != kind
        || raw[7] != role
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let abi_id: [u8; 32] = raw[72..104].try_into().expect("fixed width");
    let source_offset = u32_at(&raw, 104);
    let len = u32_at(&raw, 108);
    let allocated_len = u32_at(&raw, 116);
    if len == 0 || allocated_len != len || raw.len() != CHILD_HEADER_BYTES + allocated_len as usize
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    if kind == KIND_SCRATCH {
        if abi_id != [0; 32] || len > MAX_SCRATCH_BYTES || source_offset != 0 {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else if kind == KIND_WORKSPACE {
        if abi_id != [0; 32]
            || len > kernel.max_view_workspace_bytes()
            || len > MAX_VIEW_BYTES
            || source_offset != 0
        {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else {
        let found = kernel
            .view_abis()
            .iter()
            .any(|abi| abi.role == role && abi.id == abi_id && len <= abi.max_bytes);
        let end = source_offset
            .checked_add(len)
            .ok_or_else(|| refusal(REFUSAL_VIEW))?;
        if !found || len > MAX_VIEW_BYTES || end > session.state_bytes {
            return Err(refusal(REFUSAL_VIEW));
        }
    }
    Ok(ViewMeta {
        role,
        source_offset,
        len,
        source_cursor: u32_at(&raw, 112),
    })
}

fn write_input(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data.len() < 7 || data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [writer, session_account, stream] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !writer.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
        || writer.key != &session.writer
        || session.stream_key == Pubkey::default()
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    stream_pda_check(program, stream, session_account, &session, true)?;
    let sequence = u32_at(data, 2);
    let width = data[6] as usize;
    if width != session.command_width as usize || data.len() != 7 + width {
        return Err(refusal(REFUSAL_MALFORMED));
    }
    if sequence < session.cursor
        || sequence >= session.capacity
        || sequence - session.cursor >= MAX_STREAM_WINDOW
    {
        return Err(refusal(REFUSAL_BACKPRESSURE));
    }
    let next_frontier = match session.policy {
        POLICY_INDEXED => session.frontier.max(sequence.saturating_add(1)),
        POLICY_APPEND if sequence == session.frontier => sequence
            .checked_add(1)
            .ok_or_else(|| refusal(REFUSAL_BACKPRESSURE))?,
        POLICY_APPEND => return Err(refusal(REFUSAL_CURSOR)),
        _ => return Err(refusal(REFUSAL_SESSION)),
    };
    if next_frontier.saturating_sub(session.cursor) > MAX_STREAM_WINDOW {
        return Err(refusal(REFUSAL_BACKPRESSURE));
    }
    let slot_at = CHILD_HEADER_BYTES + sequence as usize * SLOT_BYTES;
    if stream.try_borrow_data()?[slot_at + 4] != 0 {
        return Err(refusal(REFUSAL_DUPLICATE_SLOT));
    }
    {
        let mut raw = stream.try_borrow_mut_data()?;
        put_u32(&mut raw, slot_at, sequence);
        raw[slot_at + 4] = 1;
        raw[slot_at + 8..slot_at + 8 + width].copy_from_slice(&data[7..]);
        put_u32(&mut raw, 80, next_frontier);
    }
    session.frontier = next_frontier;
    store_session(session_account, &session)
}

fn read_slot(
    stream: &AccountInfo,
    session: &Session,
    sequence: u32,
) -> Result<Vec<u8>, ProgramError> {
    let slot_at = CHILD_HEADER_BYTES + sequence as usize * SLOT_BYTES;
    let raw = stream.try_borrow_data()?;
    if raw.len() < slot_at + SLOT_BYTES
        || u32_at(&raw, slot_at) != sequence
        || raw[slot_at + 4] != 1
        || raw[slot_at + 5..slot_at + 8] != [0; 3]
        || raw[slot_at + 8 + session.command_width as usize..slot_at + SLOT_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_INPUT_GAP));
    }
    Ok(raw[slot_at + 8..slot_at + 8 + session.command_width as usize].to_vec())
}

fn advance(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (actor, session_account, stream, state_accounts): (
        &AccountInfo,
        &AccountInfo,
        &AccountInfo,
        Vec<AccountInfo>,
    ) = if primary_layout {
        if accounts.len() < 4 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        (
            &accounts[1],
            &accounts[2],
            &accounts[3],
            core::iter::once(accounts[0].clone())
                .chain(accounts[4..].iter().cloned())
                .collect(),
        )
    } else {
        (
            &accounts[0],
            &accounts[1],
            &accounts[2],
            accounts[3..].to_vec(),
        )
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !actor.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(actor.key))?;
    if primary_layout != session.primary_state {
        return Err(refusal(REFUSAL_STATE));
    }
    if session.status != STATUS_ACTIVE || actor.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if session.phase != PHASE_NONE {
        return Err(refusal(REFUSAL_LIVE));
    }
    let expected_cursor = u32_at(data, 2);
    let steps = data[6];
    if session.cursor != expected_cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    if steps == 0 || steps > session.max_steps || steps > MAX_STEPS_PER_ADVANCE {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let total_compute = kernel
        .manifest()
        .resources
        .max_compute_units
        .checked_mul(steps as u64)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    if total_compute > MAX_DECLARED_KERNEL_COMPUTE_UNITS {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    if session.stream_key == Pubkey::default() || session.state_span_count == 0 {
        return Err(refusal(REFUSAL_STATE));
    }
    stream_pda_check(program, stream, session_account, &session, true)?;
    let end_cursor = expected_cursor
        .checked_add(steps as u32)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    if end_cursor > session.capacity || end_cursor > session.frontier {
        return Err(refusal(REFUSAL_INPUT_GAP));
    }
    let schema = validate_kernel(kernel)?;
    let metas = validate_state_set(
        program,
        session_account,
        &session,
        &state_accounts,
        schema,
        true,
        expected_cursor,
    )?;
    let mut commands = Vec::with_capacity(steps as usize);
    for seq in expected_cursor..end_cursor {
        commands.push(read_slot(stream, &session, seq)?);
    }
    let output_len = (kernel.manifest().output.max_bytes as usize)
        .min(kernel.manifest().resources.max_output_bytes as usize);
    if output_len == 0 || output_len > 65_536 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let mut guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_mut_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut spans: Vec<StateSpanMut<'_>> = Vec::with_capacity(state_accounts.len());
    for (index, guard) in guards.iter_mut().enumerate() {
        spans.push(StateSpanMut {
            key: state_accounts[index].key.to_bytes(),
            owner: state_accounts[index].owner.to_bytes(),
            schema: metas[index].schema,
            offset: metas[index].offset,
            data: if session.primary_state && index == 0 {
                &mut guard[..metas[index].len as usize]
            } else {
                &mut guard[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + metas[index].len as usize]
            },
        });
    }
    let bind = kernel.bind_invocation_state(&mut spans);
    let mut committed_steps = 0u8;
    let mut halt_reason = None;
    let state_bytes = spans
        .iter()
        .try_fold(0usize, |total, span| total.checked_add(span.data.len()))
        .ok_or_else(|| refusal(REFUSAL_STATE))?;
    // SBF's default heap is 32 KiB and its allocator does not reclaim Vec
    // allocations during an instruction. Reuse one bounded snapshot buffer;
    // above the cap, HaltBefore immutability is a kernel obligation.
    let mut before_halt_guard =
        (state_bytes <= HALT_BEFORE_RUNTIME_CHECK_BYTES).then(|| vec![0u8; state_bytes]);
    let transition_result = if bind.is_ok() {
        (|| {
            let mut output = vec![0u8; output_len];
            for command in &commands {
                if let Some(snapshot) = before_halt_guard.as_mut() {
                    let mut offset = 0;
                    for span in &spans {
                        let end = offset + span.data.len();
                        snapshot[offset..end].copy_from_slice(span.data);
                        offset = end;
                    }
                }
                output.fill(0);
                let outcome = kernel
                    .transition_spans_with_outcome(command, &mut spans, &mut output)
                    .map_err(|_| refusal(REFUSAL_KERNEL))?;
                if outcome.output_bytes > output_len {
                    return Err(refusal(REFUSAL_KERNEL));
                }
                match outcome.disposition {
                    TransitionDisposition::Continue => committed_steps += 1,
                    TransitionDisposition::HaltBefore { reason } => {
                        if reason == 0 {
                            return Err(refusal(REFUSAL_KERNEL));
                        }
                        let mut offset = 0;
                        if before_halt_guard.as_ref().is_some_and(|before| {
                            spans.iter().any(|span| {
                                let end = offset + span.data.len();
                                let changed = before[offset..end] != span.data[..];
                                offset = end;
                                changed
                            })
                        }) {
                            return Err(refusal(REFUSAL_KERNEL));
                        }
                        halt_reason = Some(reason);
                        break;
                    }
                    TransitionDisposition::HaltAfter { reason } => {
                        if reason == 0 {
                            return Err(refusal(REFUSAL_KERNEL));
                        }
                        committed_steps += 1;
                        halt_reason = Some(reason);
                        break;
                    }
                }
            }
            Ok(())
        })()
    } else {
        Err(refusal(REFUSAL_KERNEL))
    };
    kernel.unbind_invocation_state();
    transition_result?;
    drop(spans);
    drop(guards);
    let final_cursor = expected_cursor
        .checked_add(committed_steps as u32)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    session.last_advance_start = expected_cursor;
    for (index, account) in state_accounts.iter().enumerate() {
        let mut raw = account.try_borrow_mut_data()?;
        if !(session.primary_state && index == 0) {
            put_u32(&mut raw, 88, expected_cursor);
            put_u32(&mut raw, 92, final_cursor);
        }
        if metas[index].before_cursor > expected_cursor {
            return Err(refusal(REFUSAL_STATE));
        }
    }
    {
        let mut raw = stream.try_borrow_mut_data()?;
        put_u32(&mut raw, 76, final_cursor);
    }
    session.cursor = final_cursor;
    let mut input_root = if session.input_root == [0; 32] {
        session.stream_root
    } else {
        session.input_root
    };
    for (index, command) in commands.iter().take(committed_steps as usize).enumerate() {
        let sequence = expected_cursor + index as u32;
        input_root = crate::hash::sha256(&[
            b"dcg/input-chain/2",
            &input_root,
            &sequence.to_le_bytes(),
            command,
        ]);
    }
    session.input_root = input_root;
    if let Some(reason) = halt_reason {
        session.status = STATUS_HALTED;
        session.halt_reason = reason;
        session.halt_cursor = final_cursor;
    }
    store_session(session_account, &session)
}

fn parse_publication_accounts<'a>(
    program: &Pubkey,
    session: &Session,
    accounts: &[AccountInfo<'a>],
    outputs_writable: bool,
    workspace_writable: bool,
    scratch_writable: bool,
    kernel: &dyn StatefulKernel,
) -> Result<PublicationAccounts<'a>, ProgramError> {
    let state_count = session.state_span_count as usize;
    if state_count == 0
        || session.view_count == 0
        || session.workspace_key == Pubkey::default()
        || session.scratch_key == Pubkey::default()
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let primary_offset = usize::from(session.primary_state);
    let actor_index = primary_offset;
    let session_index = actor_index + 1;
    let resource_index = (session.resource_key != Pubkey::default()).then_some(session_index + 1);
    let state_tail_start = session_index + 1 + usize::from(resource_index.is_some());
    if accounts.len() <= session_index {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let state_start = if session.primary_state {
        0
    } else {
        state_tail_start
    };
    let state_accounts: Vec<AccountInfo> = if session.primary_state {
        core::iter::once(
            accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?
                .clone(),
        )
        .chain(
            accounts
                .get(state_tail_start..state_tail_start + state_count - 1)
                .ok_or(ProgramError::NotEnoughAccountKeys)?
                .iter()
                .cloned(),
        )
        .collect()
    } else {
        accounts
            .get(state_start..state_start + state_count)
            .ok_or(ProgramError::NotEnoughAccountKeys)?
            .to_vec()
    };
    let view_start = if session.primary_state {
        state_tail_start + state_count - 1
    } else {
        state_start + state_count
    };
    let workspace_index = view_start + session.view_count as usize;
    let scratch_index = workspace_index + 1;
    if accounts.len() != scratch_index + 1
        || !accounts[actor_index].is_signer
        || accounts[session_index].key != &session.self_key
        || (session.primary_state && accounts[0].key != &session.state_keys[0])
    {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if let Some(index) = resource_index {
        let resource = &accounts[index];
        checked_resource(
            program,
            resource,
            &accounts[session_index],
            session,
            true,
            false,
        )?;
    }
    let state_metas = validate_state_set(
        program,
        &accounts[session_index],
        session,
        &state_accounts,
        validate_kernel(kernel)?,
        false,
        session.cursor,
    )?;
    let mut view_metas = Vec::with_capacity(session.view_count as usize);
    let mut total = 0u32;
    let mut account_index = view_start;
    for role in 0..MAX_VIEW_OUTPUTS {
        let expected = session.view_keys[role];
        if expected == Pubkey::default() {
            continue;
        }
        let meta = view_meta(
            program,
            &accounts[account_index],
            &accounts[session_index],
            session,
            role as u8,
            outputs_writable,
            kernel,
        )?;
        if meta.source_cursor != u32::MAX && meta.source_cursor > session.cursor {
            return Err(refusal(REFUSAL_VIEW));
        }
        total = total
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_VIEW))?;
        view_metas.push(meta);
        account_index += 1;
    }
    let workspace_meta = view_meta(
        program,
        &accounts[workspace_index],
        &accounts[session_index],
        session,
        WORKSPACE_ROLE,
        workspace_writable,
        kernel,
    )?;
    let scratch_meta = view_meta(
        program,
        &accounts[scratch_index],
        &accounts[session_index],
        session,
        SCRATCH_ROLE,
        scratch_writable,
        kernel,
    )?;
    if total > scratch_meta.len {
        return Err(refusal(REFUSAL_VIEW));
    }
    Ok(PublicationAccounts {
        state_metas,
        state_accounts,
        view_start,
        view_metas,
        resource_index,
        workspace_index,
        workspace_meta,
        scratch_index,
        scratch_meta,
    })
}

/// Convert the additive workspace-first RUN_PHASE account order into the
/// canonical order used by the existing v3 validators. The runtime's first
/// account data address is fixed for some engines; the workspace occupies it
/// while all committed state remains read-only later in the message.
fn normalize_workspace_first_accounts<'a>(
    session: &Session,
    accounts: &[AccountInfo<'a>],
) -> Result<Vec<AccountInfo<'a>>, ProgramError> {
    if !session.primary_state || accounts.len() < 4 || accounts[0].key != &session.workspace_key {
        return Err(refusal(REFUSAL_VIEW));
    }
    let resource_count = usize::from(session.resource_key != Pubkey::default());
    let state_start = 3usize
        .checked_add(resource_count)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    let state_count = session.state_span_count as usize;
    let view_count = session.view_count as usize;
    if state_count == 0 || state_count > MAX_STATE_SPANS || view_count > MAX_VIEW_OUTPUTS {
        return Err(refusal(REFUSAL_VIEW));
    }
    let state_end = state_start
        .checked_add(state_count)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    let view_end = state_end
        .checked_add(view_count)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    let expected_accounts = view_end
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    if accounts.len() != expected_accounts
        || accounts[1].key != &session.authority
        || accounts[2].key != &session.self_key
    {
        return Err(refusal(REFUSAL_VIEW));
    }

    let mut normalized = Vec::with_capacity(accounts.len());
    normalized.push(accounts[state_start].clone());
    normalized.push(accounts[1].clone());
    normalized.push(accounts[2].clone());
    if resource_count == 1 {
        normalized.push(accounts[3].clone());
    }
    normalized.extend(accounts[state_start + 1..state_end].iter().cloned());
    normalized.extend(accounts[state_end..view_end].iter().cloned());
    normalized.push(accounts[0].clone());
    normalized.push(accounts[view_end].clone());
    Ok(normalized)
}

fn phase_declaration(kernel: &dyn StatefulKernel, declared: u32) -> ProgramResult {
    let limit = kernel.view_phase_compute_units();
    let bytes = kernel.max_view_phase_bytes();
    if limit == 0
        || limit as u64 > MAX_DECLARED_KERNEL_COMPUTE_UNITS
        || declared != limit
        || bytes == 0
        || bytes > MAX_SCRATCH_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    Ok(())
}

fn clear_phase(session: &mut Session) {
    session.phase = PHASE_NONE;
    session.phase_state_cursor = 0;
    session.phase_cursor = 0;
    session.phase_total = 0;
    session.phase_compute_units = 0;
}

fn total_view_bytes(metas: &[ViewMeta]) -> Result<u32, ProgramError> {
    metas.iter().try_fold(0u32, |total, meta| {
        total
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_VIEW))
    })
}

fn publish_operation(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let Some(operation) = data.get(2).copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if data.get(1) != Some(&WIRE_VERSION) {
        return Err(ProgramError::InvalidInstructionData);
    }
    match operation {
        0 => begin_view_phase(program, accounts, data, kernel),
        1 => run_view_phase(program, accounts, data, kernel),
        2 => commit_view_phase(program, accounts, data, kernel),
        3 => abort_view_phase(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod workspace_first_account_tests {
    use super::*;

    fn key(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn fixture_session(keys: &[Pubkey; 7]) -> Session {
        Session {
            id: 1,
            bump: 0,
            status: STATUS_ACTIVE,
            policy: POLICY_INDEXED,
            command_width: 0,
            max_steps: 1,
            capacity: 0,
            authority: keys[1],
            writer: Pubkey::default(),
            kernel_id: KernelId([0; 16]),
            semantic_version: 1,
            abi_version: 1,
            mode: ModeId { id: 0, version: 1 },
            cursor: 0,
            frontier: 0,
            child_count: 0,
            state_span_count: 1,
            state_initialized: true,
            view_count: 1,
            stream_root: [0; 32],
            input_root: [0; 32],
            anchor_cursor: 0,
            state_anchor: [0; 32],
            state_bytes: 0,
            self_key: keys[2],
            stream_key: Pubkey::default(),
            state_keys: vec![Pubkey::default(); MAX_STATE_SPANS],
            view_keys: vec![Pubkey::default(); MAX_VIEW_OUTPUTS],
            scratch_key: keys[6],
            workspace_key: keys[0],
            resource_key: keys[3],
            resource_schema: VersionedId { id: 0, version: 1 },
            resource_commitment: [0; 32],
            phase: PHASE_VIEW_PUBLICATION,
            phase_state_cursor: 0,
            phase_cursor: 0,
            phase_total: 1,
            phase_compute_units: 1,
            primary_state: true,
            state_schema: VersionedId { id: 0, version: 1 },
            state_lengths: vec![0; MAX_STATE_SPANS],
            halt_reason: 0,
            halt_cursor: 0,
            last_advance_start: 0,
        }
    }

    #[test]
    fn workspace_first_normalization_refuses_bad_positions_counts_and_empty_state() {
        let keys = [key(1), key(2), key(3), key(4), key(5), key(6), key(7)];
        let owner = key(250);
        let mut lamports = [0u64; 7];
        let mut data = vec![Vec::new(); 7];
        let accounts: Vec<AccountInfo> = keys
            .iter()
            .zip(lamports.iter_mut())
            .zip(data.iter_mut())
            .map(|((key, lamports), data)| {
                AccountInfo::new(
                    key,
                    false,
                    false,
                    lamports,
                    data.as_mut_slice(),
                    &owner,
                    false,
                    0,
                )
            })
            .collect();
        let mut session = fixture_session(&keys);

        let normalized = normalize_workspace_first_accounts(&session, &accounts).unwrap();
        let normalized_keys: Vec<Pubkey> = normalized.iter().map(|account| *account.key).collect();
        assert_eq!(
            normalized_keys,
            vec![keys[4], keys[1], keys[2], keys[3], keys[5], keys[0], keys[6]]
        );

        let mut wrong_authority_position = accounts.clone();
        wrong_authority_position.swap(1, 4);
        assert!(matches!(
            normalize_workspace_first_accounts(&session, &wrong_authority_position),
            Err(ProgramError::Custom(REFUSAL_VIEW))
        ));

        let mut wrong_session_position = accounts.clone();
        wrong_session_position.swap(2, 4);
        assert!(matches!(
            normalize_workspace_first_accounts(&session, &wrong_session_position),
            Err(ProgramError::Custom(REFUSAL_VIEW))
        ));

        let mut wrong_account_count = accounts.clone();
        wrong_account_count.pop();
        assert!(matches!(
            normalize_workspace_first_accounts(&session, &wrong_account_count),
            Err(ProgramError::Custom(REFUSAL_VIEW))
        ));

        session.state_span_count = 0;
        assert!(matches!(
            normalize_workspace_first_accounts(&session, &accounts),
            Err(ProgramError::Custom(REFUSAL_VIEW))
        ));
    }
}

fn begin_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 11)?;
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account) = if primary_layout {
        (&accounts[1], &accounts[2])
    } else {
        (&accounts[0], &accounts[1])
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if primary_layout != session.primary_state
        || session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.phase != PHASE_NONE
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    let expected_cursor = u32_at(data, 3);
    let declared = u32_at(data, 7);
    if session.cursor != expected_cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    phase_declaration(kernel, declared)?;
    let parsed =
        parse_publication_accounts(program, &session, accounts, false, true, true, kernel)?;
    let total = total_view_bytes(&parsed.view_metas)?;
    if parsed.scratch_meta.len < total
        || parsed.workspace_meta.len < kernel.max_view_workspace_bytes()
        || parsed
            .state_metas
            .iter()
            .any(|meta| meta.after_cursor != expected_cursor)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    {
        let mut workspace = accounts[parsed.workspace_index].try_borrow_mut_data()?;
        if kernel.clear_view_workspace_on_begin() {
            workspace[CHILD_HEADER_BYTES..].fill(0);
        }
        put_u32(&mut workspace, 112, expected_cursor);
    }
    session.phase = PHASE_VIEW_PUBLICATION;
    session.phase_state_cursor = expected_cursor;
    session.phase_cursor = 0;
    session.phase_total = total;
    session.phase_compute_units = declared;
    store_session(session_account, &session)
}

fn render_phase_chunk(
    state_metas: &[StateSpanMeta],
    state_accounts: &[AccountInfo],
    primary_state: bool,
    view_metas: &[ViewMeta],
    resources: &[AccountSpan<'_>],
    commitment: &[u8; 32],
    mut workspace_header: Option<&mut [u8]>,
    workspace: &mut [u8],
    chunk_start: u32,
    chunk: &mut [u8],
    state_cursor: u32,
    compute_units: u32,
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
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
            data: if primary_state && index == 0 {
                &raw[..meta.len as usize]
            } else {
                &raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + meta.len as usize]
            },
        })
        .collect();
    let chunk_end = chunk_start
        .checked_add(chunk.len() as u32)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    let mut view_base = 0u32;
    for view in view_metas {
        let view_end = view_base
            .checked_add(view.len)
            .ok_or_else(|| refusal(REFUSAL_VIEW))?;
        let from = chunk_start.max(view_base);
        let to = chunk_end.min(view_end);
        if from < to {
            let local = from - view_base;
            let target = (from - chunk_start) as usize;
            let len = (to - from) as usize;
            let request = ViewPhase {
                state_cursor,
                role: view.role,
                source_offset: view.source_offset,
                output_offset: local,
                compute_units,
            };
            let output = &mut chunk[target..target + len];
            let rendered = if let Some(header) = workspace_header.as_deref_mut() {
                let header_before: [u8; CHILD_HEADER_BYTES] =
                    header.try_into().map_err(|_| refusal(REFUSAL_KERNEL))?;
                let rendered = kernel.render_view_phase_with_workspace_header(
                    request, &state, resources, commitment, header, workspace, output,
                );
                if header != header_before.as_slice() {
                    return Err(refusal(REFUSAL_KERNEL));
                }
                rendered
            } else {
                kernel.render_view_phase_with_resources(
                    request, &state, resources, commitment, workspace, output,
                )
            };
            let written = rendered.map_err(|_| refusal(REFUSAL_KERNEL))?;
            if written != len {
                return Err(refusal(REFUSAL_KERNEL));
            }
        }
        view_base = view_end;
    }
    if view_base < chunk_end {
        return Err(refusal(REFUSAL_VIEW));
    }
    Ok(())
}

fn run_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    // Optional trailing `phases: u8` (1..=64): run that many consecutive view
    // phases in one instruction so the accounts are deserialized once. The
    // 11-byte form is one phase, as before.
    let phases = match data.len() {
        11 => 1u32,
        12 if (1..=64).contains(&data[11]) => data[11] as u32,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account) = if primary_layout {
        (&accounts[1], &accounts[2])
    } else {
        (&accounts[0], &accounts[1])
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if primary_layout != session.primary_state
        || session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.phase != PHASE_VIEW_PUBLICATION
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    if session.cursor != session.phase_state_cursor {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    if u32_at(data, 3) != session.phase_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let declared = u32_at(data, 7);
    phase_declaration(kernel, declared)?;
    if declared != session.phase_compute_units {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let workspace_first = accounts[0].key == &session.workspace_key;
    if workspace_first && !kernel.view_workspace_at_account_base() {
        return Err(refusal(REFUSAL_VIEW));
    }
    let normalized_accounts = workspace_first
        .then(|| normalize_workspace_first_accounts(&session, accounts))
        .transpose()?;
    let accounts = normalized_accounts.as_deref().unwrap_or(accounts);
    let parsed =
        parse_publication_accounts(program, &session, accounts, false, true, true, kernel)?;
    if parsed
        .state_metas
        .iter()
        .any(|meta| meta.after_cursor != session.phase_state_cursor)
    {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    let left = session
        .phase_total
        .checked_sub(session.phase_cursor)
        .ok_or_else(|| refusal(REFUSAL_PHASE_CURSOR))?;
    if left == 0 {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let _ = left;
    let resource_guards = parsed
        .resource_index
        .map(|index| accounts[index].try_borrow_data())
        .transpose()?;
    let resources: Vec<AccountSpan<'_>> = match (parsed.resource_index, resource_guards.as_ref()) {
        (Some(index), Some(raw)) => vec![AccountSpan {
            key: accounts[index].key.to_bytes(),
            owner: accounts[index].owner.to_bytes(),
            is_signer: accounts[index].is_signer,
            is_writable: accounts[index].is_writable,
            schema: session.resource_schema,
            offset: 0,
            data: &raw[RESOURCE_HEADER_BYTES..RESOURCE_HEADER_BYTES + u32_at(raw, 72) as usize],
        }],
        _ => Vec::new(),
    };
    {
        let workspace = &accounts[parsed.workspace_index];
        let mut workspace_raw = workspace.try_borrow_mut_data()?;
        let workspace_len = parsed.workspace_meta.len as usize;
        if workspace_raw.len() != CHILD_HEADER_BYTES + workspace_len
            || u32_at(&workspace_raw, 112) != session.phase_state_cursor
        {
            return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
        }
        let scratch = &accounts[parsed.scratch_index];
        let mut scratch_raw = scratch.try_borrow_mut_data()?;
        for _ in 0..phases {
        let left = session.phase_total - session.phase_cursor;
        if left == 0 {
            break;
        }
        let count = left.min(kernel.max_view_phase_bytes()) as usize;
        let stage_start = CHILD_HEADER_BYTES + session.phase_cursor as usize;
        let stage_end = stage_start + count;
        let mut workspace_header = None;
        let workspace_payload = if workspace_first {
            let (header, payload) = workspace_raw.split_at_mut(CHILD_HEADER_BYTES);
            workspace_header = Some(header);
            &mut payload[..workspace_len]
        } else {
            &mut workspace_raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + workspace_len]
        };
        render_phase_chunk(
            &parsed.state_metas,
            &parsed.state_accounts,
            session.primary_state,
            &parsed.view_metas,
            &resources,
            &session.resource_commitment,
            workspace_header,
            workspace_payload,
            session.phase_cursor,
            &mut scratch_raw[stage_start..stage_end],
            session.phase_state_cursor,
            declared,
            kernel,
        )?;
        put_u32(&mut scratch_raw, 112, session.phase_state_cursor);
        session.phase_cursor += count as u32;
        }
    }
    store_session(session_account, &session)
}

fn commit_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 15)?;
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account) = if primary_layout {
        (&accounts[1], &accounts[2])
    } else {
        (&accounts[0], &accounts[1])
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if primary_layout != session.primary_state
        || session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.phase != PHASE_VIEW_PUBLICATION
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    if session.cursor != session.phase_state_cursor || u32_at(data, 3) != session.phase_state_cursor
    {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    if u32_at(data, 7) != session.phase_cursor || session.phase_cursor != session.phase_total {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let declared = u32_at(data, 11);
    phase_declaration(kernel, declared)?;
    if declared != session.phase_compute_units {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let parsed =
        parse_publication_accounts(program, &session, accounts, true, false, false, kernel)?;
    if parsed
        .state_metas
        .iter()
        .any(|meta| meta.after_cursor != session.phase_state_cursor)
        || parsed.scratch_meta.len < session.phase_total
    {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    let workspace = &accounts[parsed.workspace_index];
    if u32_at(&workspace.try_borrow_data()?, 112) != session.phase_state_cursor {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    let scratch = &accounts[parsed.scratch_index];
    let scratch_raw = scratch.try_borrow_data()?;
    if u32_at(&scratch_raw, 112) != session.phase_state_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let mut at = 0usize;
    for (index, meta) in parsed.view_metas.iter().enumerate() {
        let account = &accounts[parsed.view_start + index];
        let count = meta.len as usize;
        let mut raw = account.try_borrow_mut_data()?;
        raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + count].copy_from_slice(
            &scratch_raw[CHILD_HEADER_BYTES + at..CHILD_HEADER_BYTES + at + count],
        );
        put_u32(&mut raw, 112, session.phase_state_cursor);
        at += count;
    }
    drop(scratch_raw);
    clear_phase(&mut session);
    store_session(session_account, &session)
}

fn abort_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [authority, session_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if session.status != STATUS_ACTIVE
        || authority.key != &session.authority
        || session.phase != PHASE_VIEW_PUBLICATION
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    if u32_at(data, 3) != session.phase_state_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    clear_phase(&mut session);
    store_session(session_account, &session)
}

fn halt_session(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 6)?;
    let [authority, session_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if authority.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if session.status != STATUS_ACTIVE || u32_at(data, 2) != session.cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    session.status = STATUS_HALTED;
    session.halt_reason = 0;
    session.halt_cursor = session.cursor;
    clear_phase(&mut session);
    store_session(session_account, &session)
}

fn drain_to_refund(source: &AccountInfo, refund: &AccountInfo) -> ProgramResult {
    if !source.is_writable || !refund.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let source_lamports = source.lamports();
    let new_refund = refund
        .lamports()
        .checked_add(source_lamports)
        .ok_or_else(|| refusal(REFUSAL_REFUND))?;
    **refund.try_borrow_mut_lamports()? = new_refund;
    **source.try_borrow_mut_lamports()? = 0;
    source.realloc(0, false)?;
    source.assign(&system_program::id());
    Ok(())
}

fn close_child(
    program: &Pubkey,
    session_account: &AccountInfo,
    target: &AccountInfo,
    refund: &AccountInfo,
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(refund.key))?;
    if session.status != STATUS_HALTED {
        return Err(refusal(REFUSAL_LIVE));
    }
    if refund.key != &session.authority {
        return Err(refusal(REFUSAL_REFUND));
    }
    check_program_owned(target, program, true)?;
    let (primary_pda, _) = state_pda(program, session_account.key, 0);
    let (anchor_address, _) = anchor_pda(program, session_account.key);
    let is_headerless_primary = session.primary_state
        && session.state_span_count > 0
        && target.key == &primary_pda
        && target.key == &session.state_keys[0];
    let is_anchor = target.key == &anchor_address;
    let raw = target.try_borrow_data()?;
    let (kind, role, state_index, authority_bound) = if is_headerless_primary {
        if raw.len() != session.state_lengths[0] as usize {
            return Err(refusal(REFUSAL_SESSION));
        }
        (KIND_STATE, 0, 0, true)
    } else if is_anchor {
        (KIND_ANCHOR, 0, 0, true)
    } else {
        if raw.len() < CHILD_HEADER_BYTES || raw[8..40] != session_account.key.to_bytes() {
            return Err(refusal(REFUSAL_SESSION));
        }
        let kind = raw[6];
        let role = raw[7];
        let state_index = raw[78] as usize;
        let authority_bound = match kind {
            KIND_STREAM => {
                raw[40..72] == session.stream_root && raw[88..120] == session.writer.to_bytes()
            }
            KIND_RESOURCE => raw[40..72] == session.resource_commitment,
            KIND_ANCHOR => true,
            _ => raw[40..72] == session.authority.to_bytes(),
        };
        (kind, role, state_index, authority_bound)
    };
    let expected = match kind {
        KIND_STREAM => {
            let (key, _) = stream_pda(program, session_account.key);
            if session.stream_key == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_STATE if state_index < MAX_STATE_SPANS => {
            let (key, _) = state_pda(program, session_account.key, state_index as u8);
            if session.state_keys[state_index] == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_VIEW if (role as usize) < MAX_VIEW_OUTPUTS => {
            let (key, _) = view_pda(program, session_account.key, role);
            if session.view_keys[role as usize] == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_SCRATCH => {
            let (key, _) = view_pda(program, session_account.key, SCRATCH_ROLE);
            if session.scratch_key == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_WORKSPACE => {
            let (key, _) = view_pda(program, session_account.key, WORKSPACE_ROLE);
            if session.workspace_key == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_RESOURCE => {
            let (key, _) = resource_pda(program, session_account.key);
            if session.resource_key == key {
                key
            } else {
                Pubkey::default()
            }
        }
        KIND_ANCHOR => anchor_pda(program, session_account.key).0,
        _ => return Err(refusal(REFUSAL_SESSION)),
    };
    if target.key != &expected
        || expected == Pubkey::default()
        || (!is_headerless_primary && raw[8..40] != session_account.key.to_bytes())
        || !authority_bound
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    if kind == KIND_STATE
        && (session.state_span_count == 0 || state_index + 1 != session.state_span_count as usize)
    {
        return Err(refusal(REFUSAL_STATE));
    }
    drop(raw);
    if kind == KIND_ANCHOR {
        checked_anchor(program, target, session_account, true)?;
    }
    match kind {
        KIND_STREAM => session.stream_key = Pubkey::default(),
        KIND_STATE => {
            let span_len = session.state_lengths[state_index];
            session.state_bytes = session
                .state_bytes
                .checked_sub(span_len)
                .ok_or_else(|| refusal(REFUSAL_STATE))?;
            session.state_keys[state_index] = Pubkey::default();
            session.state_lengths[state_index] = 0;
            session.state_span_count = session
                .state_span_count
                .checked_sub(1)
                .ok_or_else(|| refusal(REFUSAL_STATE))?;
        }
        KIND_VIEW => {
            session.view_keys[role as usize] = Pubkey::default();
            session.view_count = session
                .view_count
                .checked_sub(1)
                .ok_or_else(|| refusal(REFUSAL_VIEW))?;
        }
        KIND_SCRATCH => session.scratch_key = Pubkey::default(),
        KIND_WORKSPACE => session.workspace_key = Pubkey::default(),
        KIND_RESOURCE => {
            session.resource_key = Pubkey::default();
            session.resource_schema = VersionedId { id: 0, version: 0 };
            session.resource_commitment = [0; 32];
        }
        KIND_ANCHOR => {}
        _ => unreachable!(),
    }
    session.child_count = session
        .child_count
        .checked_sub(1)
        .ok_or_else(|| refusal(REFUSAL_SESSION))?;
    store_session(session_account, &session)?;
    drain_to_refund(target, refund)
}

fn close_session(
    program: &Pubkey,
    session_account: &AccountInfo,
    refund: &AccountInfo,
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let session = checked_session_from(program, session_account, true, kernel, Some(refund.key))?;
    if session.status != STATUS_HALTED
        || session.child_count != 0
        || session.stream_key != Pubkey::default()
        || session.state_span_count != 0
        || session.view_count != 0
        || session.scratch_key != Pubkey::default()
        || session.workspace_key != Pubkey::default()
        || session.resource_key != Pubkey::default()
        || session.phase != PHASE_NONE
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    if refund.key != &session.authority {
        return Err(refusal(REFUSAL_REFUND));
    }
    drain_to_refund(session_account, refund)
}

fn close_account(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 3)?;
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[2];
    if kind == KIND_SESSION {
        let [session, refund] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        check_unique(accounts)?;
        close_session(program, session, refund, kernel)
    } else {
        let [session, target, refund] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        check_unique(accounts)?;
        let primary_state = kind == KIND_STATE
            && checked_session_from(program, session, false, kernel, Some(refund.key))
                .is_ok_and(|decoded| decoded.primary_state && target.key == &decoded.state_keys[0]);
        let anchor_account =
            kind == KIND_ANCHOR && checked_anchor(program, target, session, false).is_ok();
        if !primary_state
            && !anchor_account
            && target.try_borrow_data()?.get(6).copied() != Some(kind)
        {
            return Err(refusal(REFUSAL_SESSION));
        }
        close_child(program, session, target, refund, kernel)
    }
}

fn checked_anchor(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    writable: bool,
) -> Result<AnchorMeta, ProgramError> {
    check_program_owned(account, program, writable)?;
    expect_derived(
        account,
        program,
        &[ANCHOR_SEED, session_account.key.as_ref()],
        AccountKind::exact(ANCHOR_MAGIC, ANCHOR_ACCOUNT_BYTES).with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_SESSION))?;
    let raw = account.try_borrow_data()?;
    if raw.len() != ANCHOR_ACCOUNT_BYTES
        || &raw[..4] != ANCHOR_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || !matches!(raw[6], 0 | 1)
        || raw[7] != 0
        || raw[8..40] != session_account.key.to_bytes()
        || raw[116..].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(AnchorMeta {
        open: raw[6] == 1,
        cursor: u32_at(&raw, 40),
        total: u32_at(&raw, 44),
        progress: u32_at(&raw, 48),
        input_root: raw[52..84].try_into().expect("fixed width"),
        accumulator: raw[84..116].try_into().expect("fixed width"),
    })
}

fn write_anchor(
    account: &AccountInfo,
    session_account: &AccountInfo,
    meta: AnchorMeta,
) -> ProgramResult {
    let mut raw = account.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(ANCHOR_MAGIC);
    put_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = u8::from(meta.open);
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    put_u32(&mut raw, 40, meta.cursor);
    put_u32(&mut raw, 44, meta.total);
    put_u32(&mut raw, 48, meta.progress);
    raw[52..84].copy_from_slice(&meta.input_root);
    raw[84..116].copy_from_slice(&meta.accumulator);
    Ok(())
}

fn begin_anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let [payer, authority, session_account, stream, anchor_account, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    let state_count = accounts.len().saturating_sub(6);
    if !payer.is_signer
        || !payer.is_writable
        || !authority.is_signer
        || *rest.last().unwrap().key != system_program::id()
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let system = rest.last().unwrap();
    let state_accounts = &rest[..rest.len() - 1];
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    let cursor = u32_at(data, 3);
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_NONE
        || !session.state_initialized
        || cursor != session.cursor
        || session.anchor_cursor > cursor
        || state_accounts.len() != state_count
    {
        return Err(refusal(REFUSAL_CURSOR));
    }
    stream_pda_check(program, stream, session_account, &session, false)?;
    let schema = validate_kernel(kernel)?;
    validate_state_set(
        program,
        session_account,
        &session,
        state_accounts,
        schema,
        false,
        cursor,
    )?;
    let input_root = if session.input_root == [0; 32] {
        session.stream_root
    } else {
        session.input_root
    };
    let schema_id = schema.id.id.to_le_bytes();
    let schema_version = schema.id.version.to_le_bytes();
    let cursor_bytes = cursor.to_le_bytes();
    let total_bytes = session.state_bytes.to_le_bytes();
    let mut initial = crate::hash::Parts::new();
    initial
        .push(b"dcg/state-anchor-init/3")
        .push(&session.state_anchor)
        .push(&input_root)
        .push(&session.kernel_id.0)
        .push(&schema_id)
        .push(&schema_version)
        .push(&cursor_bytes)
        .push(&total_bytes);
    let (expected, bump) = anchor_pda(program, session_account.key);
    if anchor_account.key != &expected || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_SESSION));
    }
    if anchor_account.owner == &system_program::id()
        && anchor_account.lamports() == 0
        && anchor_account.data_is_empty()
    {
        create_pda(
            program,
            payer,
            anchor_account,
            system,
            &[ANCHOR_SEED, session_account.key.as_ref()],
            bump,
            ANCHOR_ACCOUNT_BYTES,
        )?;
        session.child_count = session
            .child_count
            .checked_add(1)
            .ok_or_else(|| refusal(REFUSAL_SESSION))?;
    } else {
        let previous = checked_anchor(program, anchor_account, session_account, true)?;
        if previous.open {
            return Err(refusal(REFUSAL_LIVE));
        }
    }
    write_anchor(
        anchor_account,
        session_account,
        AnchorMeta {
            open: true,
            cursor,
            total: session.state_bytes,
            progress: 0,
            input_root,
            accumulator: initial.finish(),
        },
    )?;
    session.phase = PHASE_STATE_ANCHOR;
    session.phase_state_cursor = cursor;
    session.phase_cursor = 0;
    session.phase_total = session.state_bytes;
    session.phase_compute_units = ANCHOR_CHUNK_BYTES;
    store_session(session_account, &session)
}

fn run_anchor_chunk(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 11)?;
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let [authority, session_account, stream, anchor_account, state_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    let cursor = u32_at(data, 3);
    let offset = u32_at(data, 7);
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_STATE_ANCHOR
        || cursor != session.phase_state_cursor
        || session.cursor != cursor
        || offset != session.phase_cursor
    {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    stream_pda_check(program, stream, session_account, &session, false)?;
    let anchor = checked_anchor(program, anchor_account, session_account, true)?;
    if !anchor.open
        || anchor.cursor != cursor
        || anchor.total != session.phase_total
        || anchor.progress != offset
        || anchor.progress >= anchor.total
    {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let schema = validate_kernel(kernel)?;
    let metas = validate_state_set(
        program,
        session_account,
        &session,
        state_accounts,
        schema,
        false,
        cursor,
    )?;
    let count = (anchor.total - offset).min(ANCHOR_CHUNK_BYTES);
    let end = offset
        .checked_add(count)
        .ok_or_else(|| refusal(REFUSAL_STATE))?;
    let guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut digest = crate::hash::Parts::new();
    let offset_bytes = offset.to_le_bytes();
    digest
        .push(b"dcg/state-anchor-chunk/3")
        .push(&anchor.accumulator)
        .push(&offset_bytes);
    let mut covered = 0u32;
    for (index, (raw, meta)) in guards.iter().zip(metas.iter()).enumerate() {
        let span_end = meta
            .offset
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_STATE))?;
        let from = offset.max(meta.offset);
        let to = end.min(span_end);
        if from < to {
            let header_len = if session.primary_state && index == 0 {
                0
            } else {
                CHILD_HEADER_BYTES
            };
            let local_from = header_len + (from - meta.offset) as usize;
            let local_to = local_from + (to - from) as usize;
            digest.push(&raw[local_from..local_to]);
            covered += to - from;
        }
    }
    if covered != count {
        return Err(refusal(REFUSAL_STATE));
    }
    write_anchor(
        anchor_account,
        session_account,
        AnchorMeta {
            progress: end,
            accumulator: digest.finish(),
            ..anchor
        },
    )?;
    session.phase_cursor = end;
    store_session(session_account, &session)
}

fn finish_anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [authority, session_account, anchor_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    let cursor = u32_at(data, 3);
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_STATE_ANCHOR
        || session.cursor != cursor
        || session.phase_state_cursor != cursor
        || session.phase_cursor != session.phase_total
    {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let anchor = checked_anchor(program, anchor_account, session_account, true)?;
    if !anchor.open
        || anchor.cursor != cursor
        || anchor.total != session.phase_total
        || anchor.progress != anchor.total
    {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let schema = validate_kernel(kernel)?;
    let schema_id = schema.id.id.to_le_bytes();
    let schema_version = schema.id.version.to_le_bytes();
    session.state_anchor = crate::hash::sha256(&[
        b"dcg/state-anchor-chunked/3",
        &anchor.accumulator,
        &anchor.input_root,
        &session.kernel_id.0,
        &schema_id,
        &schema_version,
        &cursor.to_le_bytes(),
        &anchor.total.to_le_bytes(),
    ]);
    session.input_root = anchor.input_root;
    session.anchor_cursor = cursor;
    clear_phase(&mut session);
    write_anchor(
        anchor_account,
        session_account,
        AnchorMeta {
            open: false,
            ..anchor
        },
    )?;
    store_session(session_account, &session)
}

fn abort_anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let [authority, session_account, anchor_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if session.status != STATUS_ACTIVE
        || session.phase != PHASE_STATE_ANCHOR
        || u32_at(data, 3) != session.phase_state_cursor
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    let anchor = checked_anchor(program, anchor_account, session_account, true)?;
    if !anchor.open || anchor.progress != session.phase_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    write_anchor(
        anchor_account,
        session_account,
        AnchorMeta {
            open: false,
            ..anchor
        },
    )?;
    clear_phase(&mut session);
    store_session(session_account, &session)
}

fn anchor_one_shot(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    check_unique(accounts)?;
    let primary_layout = !accounts[0].is_signer;
    let (authority, session_account, stream, state_accounts) = if primary_layout {
        (
            &accounts[1],
            &accounts[2],
            &accounts[3],
            core::iter::once(accounts[0].clone())
                .chain(accounts[4..].iter().cloned())
                .collect::<Vec<_>>(),
        )
    } else {
        (
            &accounts[0],
            &accounts[1],
            &accounts[2],
            accounts[3..].to_vec(),
        )
    };
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session =
        checked_session_from(program, session_account, true, kernel, Some(authority.key))?;
    if session.status != STATUS_ACTIVE || session.phase != PHASE_NONE || !session.state_initialized
    {
        return Err(refusal(REFUSAL_LIVE));
    }
    if primary_layout != session.primary_state {
        return Err(refusal(REFUSAL_STATE));
    }
    let cursor = u32_at(data, 2);
    if cursor != session.cursor
        || session.anchor_cursor > cursor
        || session.state_bytes > ANCHOR_CHUNK_BYTES
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    stream_pda_check(program, stream, session_account, &session, false)?;
    let schema = validate_kernel(kernel)?;
    let metas = validate_state_set(
        program,
        session_account,
        &session,
        &state_accounts,
        schema,
        false,
        cursor,
    )?;
    let guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut parts = crate::hash::Parts::new();
    let schema_id = schema.id.id.to_le_bytes();
    let schema_version = schema.id.version.to_le_bytes();
    let cursor_bytes = cursor.to_le_bytes();
    parts
        .push(b"dcg/state-anchor-one-shot/3")
        .push(&session.kernel_id.0)
        .push(&schema_id)
        .push(&schema_version)
        .push(&cursor_bytes)
        .push(&session.input_root);
    for (index, (raw, meta)) in guards.iter().zip(metas.iter()).enumerate() {
        let header_len = if session.primary_state && index == 0 {
            0
        } else {
            CHILD_HEADER_BYTES
        };
        parts.push(&raw[header_len..header_len + meta.len as usize]);
    }
    session.anchor_cursor = cursor;
    session.state_anchor = parts.finish();
    store_session(session_account, &session)
}

fn anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data.len() == 6 {
        return anchor_one_shot(program, accounts, data, kernel);
    }
    let Some(operation) = data.get(2).copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match operation {
        ANCHOR_OP_BEGIN => begin_anchor(program, accounts, data, kernel),
        ANCHOR_OP_CHUNK => run_anchor_chunk(program, accounts, data, kernel),
        ANCHOR_OP_FINISH => finish_anchor(program, accounts, data, kernel),
        ANCHOR_OP_ABORT => abort_anchor(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Process stateful wire v3 using one statically linked application kernel.
pub fn process_with_kernel(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if data.get(1) != Some(&WIRE_VERSION) {
        return Err(ProgramError::InvalidInstructionData);
    }
    if tag == RESOURCE_CHUNK_TAG {
        return if data.get(2) == Some(&RESOURCE_GROW_OP) {
            grow_resource(program, accounts, data, kernel)
        } else {
            upload_resource_chunk(program, accounts, data, kernel)
        };
    }
    match tag {
        crate::stateful::TAG_OPEN_SESSION => open_session(program, accounts, data, kernel),
        crate::stateful::TAG_CREATE_STREAM if data.get(2) == Some(&0) => {
            create_stream(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STREAM if data.get(2) == Some(&1) => {
            grow_stream(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE if data.get(2) == Some(&STATE_OP_GROW) => {
            grow_state(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE if data.get(2) == Some(&STATE_OP_BEGIN_INITIALIZE) => {
            begin_initialization(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE if data.get(2) == Some(&STATE_OP_RUN_INITIALIZE) => {
            run_initialization(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE if data.get(2) == Some(&STATE_OP_INITIALIZE) => {
            initialize_state(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE => create_state(program, accounts, data, kernel),
        crate::stateful::TAG_CREATE_VIEW
            if data.len() == 4 && data.get(2) == Some(&VIEW_OP_GROW) =>
        {
            grow_view(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_VIEW if data.get(2) == Some(&SCRATCH_ROLE) => {
            create_scratch(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_VIEW
            if data.len() == 7 && data.get(2) == Some(&WORKSPACE_ROLE) =>
        {
            create_workspace(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_VIEW => create_view(program, accounts, data, kernel),
        crate::stateful::TAG_WRITE_INPUT => write_input(program, accounts, data, kernel),
        crate::stateful::TAG_ADVANCE => advance(program, accounts, data, kernel),
        crate::stateful::TAG_PUBLISH_VIEWS => publish_operation(program, accounts, data, kernel),
        crate::stateful::TAG_HALT_SESSION => halt_session(program, accounts, data, kernel),
        crate::stateful::TAG_CLOSE_ACCOUNT => close_account(program, accounts, data, kernel),
        crate::stateful::TAG_ANCHOR => anchor(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
