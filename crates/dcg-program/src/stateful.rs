// SPDX-License-Identifier: GPL-3.0-only

//! Versioned stateful-workload account adapter.
//!
//! This module deliberately has no Doom formats or pointers. Applications
//! statically supply a `StatefulKernel`; the adapter binds a session, an
//! append-only input stream, schema-bound state spans, declared output views,
//! and an explicit optional anchor to that kernel's exact semantic/ABI/mode
//! identity. Instruction tags 230..=239 are reserved by the test application
//! adapter and are outside revision 8's dispatch table.

use crate::account_provenance::{create_derived_account, expect_derived, AccountKind, RoleFlags};
use crate::kernel::{
    KernelId, ModeId, StateSchema, StateSpanMut, StatefulKernel, VersionedId, ViewAbi,
    MAX_DECLARED_KERNEL_COMPUTE_UNITS,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent, system_instruction, system_program,
    sysvar::Sysvar,
};

pub const TAG_OPEN_SESSION: u8 = 230;
pub const TAG_CREATE_STREAM: u8 = 231;
pub const TAG_CREATE_STATE: u8 = 232;
pub const TAG_CREATE_VIEW: u8 = 233;
pub const TAG_WRITE_INPUT: u8 = 234;
pub const TAG_ADVANCE: u8 = 235;
pub const TAG_PUBLISH_VIEWS: u8 = 236;
pub const TAG_HALT_SESSION: u8 = 237;
pub const TAG_CLOSE_ACCOUNT: u8 = 238;
pub const TAG_ANCHOR: u8 = 239;

pub const WIRE_VERSION: u8 = 1;
pub const MODE_CONSENSUS_V1: ModeId = VersionedId {
    id: 0x434f_4e53,
    version: 1,
};

pub const MAX_STATE_SPANS: usize = 8;
pub const MAX_STREAM_CAPACITY: u16 = 64;
pub const MAX_COMMAND_BYTES: usize = 8;
pub const MAX_STEPS_PER_ADVANCE: u8 = 8;
pub const MAX_VIEW_BYTES: u32 = 4_096;
pub const MAX_SCRATCH_BYTES: u32 = 8_192;
pub const MAX_ENGINE_STATE_BYTES: u32 = 10_000_000;

const SESSION_BYTES: usize = 672;
const SESSION_MAGIC: &[u8; 4] = b"DSS1";
const SESSION_SEED: &[u8] = b"dcg-session-v1";
const STREAM_SEED: &[u8] = b"dcg-input-v1";
const STATE_SEED: &[u8] = b"dcg-state-v1";
const VIEW_SEED: &[u8] = b"dcg-view-v1";
const CHILD_HEADER_BYTES: usize = 128;
const STREAM_MAGIC: &[u8; 4] = b"DSB1";
const STATE_MAGIC: &[u8; 4] = b"DSE1";
const VIEW_MAGIC: &[u8; 4] = b"DVW1";
const SLOT_BYTES: usize = 16;

pub const POLICY_INDEXED: u8 = 0;
pub const POLICY_APPEND: u8 = 1;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_HALTED: u8 = 2;
pub const KIND_SESSION: u8 = 0;
pub const KIND_STREAM: u8 = 1;
pub const KIND_STATE: u8 = 2;
pub const KIND_VIEW_COUNTER: u8 = 3;
pub const KIND_VIEW_TOTAL: u8 = 4;
pub const KIND_SCRATCH: u8 = 5;

const RESOURCE_STREAM: u8 = 1 << 0;
const RESOURCE_VIEW_COUNTER: u8 = 1 << 1;
const RESOURCE_VIEW_TOTAL: u8 = 1 << 2;
const RESOURCE_SCRATCH: u8 = 1 << 3;
const VIEW_FLAG: u8 = 1;
const SCRATCH_FLAG: u8 = 2;

pub const REFUSAL_MALFORMED: u32 = 2_301;
pub const REFUSAL_AUTHORITY: u32 = 2_302;
pub const REFUSAL_ALIAS: u32 = 2_303;
pub const REFUSAL_SESSION: u32 = 2_304;
pub const REFUSAL_LIVE: u32 = 2_305;
pub const REFUSAL_RESOURCE: u32 = 2_306;
pub const REFUSAL_DUPLICATE_SLOT: u32 = 2_307;
pub const REFUSAL_BACKPRESSURE: u32 = 2_308;
pub const REFUSAL_CURSOR: u32 = 2_309;
pub const REFUSAL_INPUT_GAP: u32 = 2_310;
pub const REFUSAL_STATE: u32 = 2_311;
pub const REFUSAL_VIEW: u32 = 2_312;
pub const REFUSAL_REFUND: u32 = 2_313;
pub const REFUSAL_KERNEL: u32 = 2_314;

#[derive(Clone, Copy, Debug)]
struct Session {
    id: u64,
    status: u8,
    policy: u8,
    command_width: u8,
    max_steps: u8,
    capacity: u16,
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
    resource_flags: u8,
    stream_root: [u8; 32],
    input_root: [u8; 32],
    anchor_cursor: u32,
    state_anchor: [u8; 32],
    state_bytes: u32,
    self_key: Pubkey,
    stream_key: Pubkey,
    state_keys: [Pubkey; MAX_STATE_SPANS],
    view_keys: [Pubkey; 3],
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
    flags: u8,
    abi_id: [u8; 32],
    source_offset: u32,
    len: u32,
    source_cursor: u32,
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

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed width"))
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed width"))
}

fn write_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn session_pda(program: &Pubkey, authority: &Pubkey, id: u64) -> (Pubkey, u8) {
    let id_bytes = id.to_le_bytes();
    Pubkey::find_program_address(&[SESSION_SEED, authority.as_ref(), &id_bytes], program)
}

fn stream_pda(program: &Pubkey, session: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[STREAM_SEED, session.as_ref()], program)
}

fn state_pda(program: &Pubkey, session: &Pubkey, index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[STATE_SEED, session.as_ref(), &[index]], program)
}

fn view_pda(program: &Pubkey, session: &Pubkey, role: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VIEW_SEED, session.as_ref(), &[role]], program)
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
    write_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = session.status;
    raw[7] = session.policy;
    raw[8] = session.command_width;
    raw[9] = session.max_steps;
    write_u16(&mut raw, 10, session.capacity);
    write_u64(&mut raw, 12, session.id);
    raw[20..52].copy_from_slice(session.authority.as_ref());
    raw[52..84].copy_from_slice(session.writer.as_ref());
    raw[84..100].copy_from_slice(&session.kernel_id.0);
    write_u16(&mut raw, 100, session.semantic_version);
    write_u16(&mut raw, 102, session.abi_version);
    write_u32(&mut raw, 104, session.mode.id);
    write_u16(&mut raw, 108, session.mode.version);
    write_u32(&mut raw, 112, session.cursor);
    write_u32(&mut raw, 116, session.frontier);
    write_u16(&mut raw, 120, session.child_count);
    raw[122] = session.state_span_count;
    raw[123] = session.resource_flags;
    raw[124..156].copy_from_slice(&session.stream_root);
    raw[156..188].copy_from_slice(&session.input_root);
    write_u32(&mut raw, 188, session.anchor_cursor);
    raw[192..224].copy_from_slice(&session.state_anchor);
    write_u32(&mut raw, 224, session.state_bytes);
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
    Ok(())
}

fn decode_session(raw: &[u8]) -> Result<Session, ProgramError> {
    if raw.len() != SESSION_BYTES
        || &raw[..4] != SESSION_MAGIC
        || read_u16(raw, 4) != WIRE_VERSION as u16
        || raw[110..112] != [0, 0]
        || raw[644..].iter().any(|byte| *byte != 0)
        || !matches!(raw[6], STATUS_ACTIVE | STATUS_HALTED)
        || !matches!(raw[7], POLICY_INDEXED | POLICY_APPEND)
        || raw[8] == 0
        || raw[8] as usize > MAX_COMMAND_BYTES
        || raw[9] == 0
        || raw[9] > MAX_STEPS_PER_ADVANCE
        || read_u16(raw, 10) < 2
        || read_u16(raw, 10) > MAX_STREAM_CAPACITY
        || raw[122] as usize > MAX_STATE_SPANS
        || raw[123]
            & !(RESOURCE_STREAM | RESOURCE_VIEW_COUNTER | RESOURCE_VIEW_TOTAL | RESOURCE_SCRATCH)
            != 0
        || read_u32(raw, 112) > read_u32(raw, 116)
        || read_u32(raw, 116) > read_u16(raw, 10) as u32
        || read_u32(raw, 188) > read_u32(raw, 112)
        || read_u32(raw, 224) > MAX_ENGINE_STATE_BYTES
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(Session {
        id: read_u64(raw, 12),
        status: raw[6],
        policy: raw[7],
        command_width: raw[8],
        max_steps: raw[9],
        capacity: read_u16(raw, 10),
        authority: Pubkey::new_from_array(raw[20..52].try_into().expect("fixed width")),
        writer: Pubkey::new_from_array(raw[52..84].try_into().expect("fixed width")),
        kernel_id: KernelId(raw[84..100].try_into().expect("fixed width")),
        semantic_version: read_u16(raw, 100),
        abi_version: read_u16(raw, 102),
        mode: VersionedId {
            id: read_u32(raw, 104),
            version: read_u16(raw, 108),
        },
        cursor: read_u32(raw, 112),
        frontier: read_u32(raw, 116),
        child_count: read_u16(raw, 120),
        state_span_count: raw[122],
        resource_flags: raw[123],
        stream_root: raw[124..156].try_into().expect("fixed width"),
        input_root: raw[156..188].try_into().expect("fixed width"),
        anchor_cursor: read_u32(raw, 188),
        state_anchor: raw[192..224].try_into().expect("fixed width"),
        state_bytes: read_u32(raw, 224),
        self_key: Pubkey::new_from_array(raw[228..260].try_into().expect("fixed width")),
        stream_key: Pubkey::new_from_array(raw[260..292].try_into().expect("fixed width")),
        state_keys: core::array::from_fn(|index| {
            let at = 292 + index * 32;
            Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
        }),
        view_keys: core::array::from_fn(|index| {
            let at = 548 + index * 32;
            Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
        }),
    })
}

fn checked_session(
    program: &Pubkey,
    account: &AccountInfo,
    writable: bool,
    kernel: &dyn StatefulKernel,
) -> Result<Session, ProgramError> {
    check_program_owned(account, program, writable)?;
    let raw = account.try_borrow_data()?;
    let session = decode_session(&raw)?;
    let id = session.id.to_le_bytes();
    expect_derived(
        account,
        program,
        &[SESSION_SEED, session.authority.as_ref(), &id],
        AccountKind::exact(SESSION_MAGIC, SESSION_BYTES),
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
        || session.mode != MODE_CONSENSUS_V1
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
    bump: u8,
    data_len: usize,
) -> ProgramResult {
    create_derived_account(
        program, payer, target, system, seeds, bump, data_len, data_len,
    )
    .map_err(|_| refusal(REFUSAL_SESSION))
}

fn checked_session_status(session: &Session, active_only: bool) -> ProgramResult {
    if active_only && session.status != STATUS_ACTIVE {
        return Err(refusal(REFUSAL_LIVE));
    }
    Ok(())
}

fn checked_stream(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    writable: bool,
) -> ProgramResult {
    check_program_owned(account, program, writable)?;
    expect_derived(
        account,
        program,
        &[STREAM_SEED, session_account.key.as_ref()],
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
    if account.key != &session.stream_key
        || raw.len() != expected_len
        || &raw[..4] != STREAM_MAGIC
        || read_u16(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STREAM
        || raw[7] != STATUS_ACTIVE
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.stream_root
        || read_u16(&raw, 72) != session.capacity
        || raw[74] != session.policy
        || raw[75] != session.command_width
        || read_u32(&raw, 76) != session.cursor
        || read_u32(&raw, 80) != session.frontier
        || read_u32(&raw, 84) as usize != SLOT_BYTES
        || raw[88..120] != session.writer.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
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
    let index_seed = [index as u8];
    expect_derived(
        account,
        program,
        &[STATE_SEED, session_account.key.as_ref(), &index_seed],
        AccountKind::variable(STATE_MAGIC, CHILD_HEADER_BYTES + 1, 10 * 1024 * 1024)
            .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_STATE))?;
    let raw = account.try_borrow_data()?;
    if index >= MAX_STATE_SPANS
        || account.key != &session.state_keys[index]
        || raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != STATE_MAGIC
        || read_u16(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STATE
        || raw[7] != 0
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || read_u32(&raw, 72) != schema.id.id
        || read_u16(&raw, 76) != schema.id.version
        || raw[78] as usize != index
        || raw[79] as usize != session.state_span_count as usize
        || read_u32(&raw, 88) > read_u32(&raw, 92)
        || read_u32(&raw, 96) != session.state_bytes
        || raw[100..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let offset = read_u32(&raw, 80);
    let len = read_u32(&raw, 84);
    let total_len = read_u32(&raw, 96);
    let end = offset
        .checked_add(len)
        .ok_or_else(|| refusal(REFUSAL_STATE))?;
    if len == 0 || end > total_len || raw.len() != CHILD_HEADER_BYTES + len as usize {
        return Err(refusal(REFUSAL_STATE));
    }
    Ok(StateSpanMeta {
        schema: schema.id,
        index: index as u8,
        count: session.state_span_count,
        offset,
        len,
        before_cursor: read_u32(&raw, 88),
        after_cursor: read_u32(&raw, 92),
        total_len,
    })
}

fn view_meta(
    program: &Pubkey,
    account: &AccountInfo,
    session_account: &AccountInfo,
    session: &Session,
    role: u8,
    writable: bool,
) -> Result<ViewMeta, ProgramError> {
    check_program_owned(account, program, writable)?;
    let view_index = match role {
        KIND_VIEW_COUNTER => 0,
        KIND_VIEW_TOTAL => 1,
        KIND_SCRATCH => 2,
        _ => return Err(refusal(REFUSAL_VIEW)),
    };
    let role_seed = [role];
    expect_derived(
        account,
        program,
        &[VIEW_SEED, session_account.key.as_ref(), &role_seed],
        AccountKind::variable(
            VIEW_MAGIC,
            CHILD_HEADER_BYTES + 1,
            CHILD_HEADER_BYTES + MAX_SCRATCH_BYTES as usize,
        )
        .with_version(4, WIRE_VERSION as u16),
        RoleFlags {
            writable,
            signer: false,
        },
    )
    .map_err(|_| refusal(REFUSAL_VIEW))?;
    let raw = account.try_borrow_data()?;
    if account.key != &session.view_keys[view_index]
        || raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != VIEW_MAGIC
        || read_u16(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != role
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || raw[120..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let flags = raw[7];
    let abi_id: [u8; 32] = raw[72..104].try_into().expect("fixed width");
    let source_offset = read_u32(&raw, 104);
    let len = read_u32(&raw, 108);
    if len == 0 || raw.len() != CHILD_HEADER_BYTES + len as usize {
        return Err(refusal(REFUSAL_VIEW));
    }
    let source_cursor = read_u32(&raw, 112);
    if role == KIND_SCRATCH {
        if flags != SCRATCH_FLAG || abi_id != [0; 32] {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else if flags != VIEW_FLAG || abi_id == [0; 32] {
        return Err(refusal(REFUSAL_VIEW));
    }
    Ok(ViewMeta {
        role,
        flags,
        abi_id,
        source_offset,
        len,
        source_cursor,
    })
}

fn open_session(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 105)?;
    let [payer, authority, session_account, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    let _schema = validate_kernel(kernel)?;
    if data[1] != WIRE_VERSION
        || !payer.is_signer
        || !payer.is_writable
        || !authority.is_signer
        || *system.key != system_program::id()
    {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let id = read_u64(data, 2);
    let policy = data[10];
    let width = data[11];
    let capacity = read_u16(data, 12);
    let max_steps = data[14];
    let kernel_id = KernelId(data[15..31].try_into().expect("fixed width"));
    let semantic = read_u16(data, 31);
    let abi = read_u16(data, 33);
    let mode = VersionedId {
        id: read_u32(data, 35),
        version: read_u16(data, 39),
    };
    let stream_root: [u8; 32] = data[41..73].try_into().expect("fixed width");
    let requested_writer = Pubkey::new_from_array(data[73..105].try_into().expect("fixed width"));
    let writer = if policy == POLICY_INDEXED {
        *authority.key
    } else {
        requested_writer
    };
    let manifest = kernel.manifest();
    let limit =
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
        || mode != MODE_CONSENSUS_V1
        || !manifest.modes.contains(&mode)
        || !matches!(policy, POLICY_INDEXED | POLICY_APPEND)
        || width == 0
        || width as usize > MAX_COMMAND_BYTES
        || width as usize > limit
        || capacity < 2
        || capacity > MAX_STREAM_CAPACITY
        || max_steps == 0
        || max_steps > MAX_STEPS_PER_ADVANCE
        || max_steps as u32 > manifest.resources.max_operations
        || compute_bound.is_none_or(|bound| bound > MAX_DECLARED_KERNEL_COMPUTE_UNITS)
        || (policy == POLICY_INDEXED && requested_writer != Pubkey::default())
        || (policy == POLICY_APPEND && requested_writer == Pubkey::default())
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
    encode_session(
        session_account,
        &Session {
            id,
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
            child_count: 0,
            state_span_count: 0,
            resource_flags: 0,
            stream_root,
            input_root: [0; 32],
            anchor_cursor: 0,
            state_anchor: [0; 32],
            state_bytes: 0,
            self_key: *session_account.key,
            stream_key: Pubkey::default(),
            state_keys: [Pubkey::default(); MAX_STATE_SPANS],
            view_keys: [Pubkey::default(); 3],
        },
    )
}

fn create_stream(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 2)?;
    let [payer, session_account, stream, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !payer.is_signer || !payer.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    checked_session_status(&session, true)?;
    if session.resource_flags & RESOURCE_STREAM != 0 {
        return Err(refusal(REFUSAL_SESSION));
    }
    let (expected, bump) = stream_pda(program, session_account.key);
    if stream.key != &expected {
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
    write_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = KIND_STREAM;
    raw[7] = STATUS_ACTIVE;
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(&session.stream_root);
    write_u16(&mut raw, 72, session.capacity);
    raw[74] = session.policy;
    raw[75] = session.command_width;
    write_u32(&mut raw, 84, SLOT_BYTES as u32);
    raw[88..120].copy_from_slice(session.writer.as_ref());
    drop(raw);
    session.resource_flags |= RESOURCE_STREAM;
    session.stream_key = *stream.key;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
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
    let schema = validate_kernel(kernel)?;
    let count = data[2] as usize;
    if count == 0 || count > MAX_STATE_SPANS || data.len() != 3 + count * 4 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    if remainder.len() != count + 1 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (span_accounts, system_items) = remainder.split_at(count);
    let [system] = system_items else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !payer.is_signer || !payer.is_writable || *system.key != system_program::id() {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    checked_session_status(&session, true)?;
    if session.state_span_count != 0 {
        return Err(refusal(REFUSAL_STATE));
    }
    let mut lengths = Vec::with_capacity(count);
    let mut total = 0u32;
    for index in 0..count {
        let len = read_u32(data, 3 + index * 4);
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
    for (index, (account, len)) in span_accounts.iter().zip(lengths.iter()).enumerate() {
        let (expected, bump) = state_pda(program, session_account.key, index as u8);
        if account.key != &expected {
            return Err(refusal(REFUSAL_STATE));
        }
        let account_len = CHILD_HEADER_BYTES + *len as usize;
        create_pda(
            program,
            payer,
            account,
            system,
            &[STATE_SEED, session_account.key.as_ref(), &[index as u8]],
            bump,
            account_len,
        )?;
        let mut raw = account.try_borrow_mut_data()?;
        raw.fill(0);
        raw[..4].copy_from_slice(STATE_MAGIC);
        write_u16(&mut raw, 4, WIRE_VERSION as u16);
        raw[6] = KIND_STATE;
        raw[8..40].copy_from_slice(session_account.key.as_ref());
        raw[40..72].copy_from_slice(session.authority.as_ref());
        write_u32(&mut raw, 72, schema.id.id);
        write_u16(&mut raw, 76, schema.id.version);
        raw[78] = index as u8;
        raw[79] = count as u8;
        write_u32(&mut raw, 80, offset);
        write_u32(&mut raw, 84, *len);
        write_u32(&mut raw, 96, total);
        drop(raw);
        session.state_keys[index] = *account.key;
        offset = offset
            .checked_add(*len)
            .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    }

    let mut guards = Vec::with_capacity(count);
    for account in span_accounts {
        guards.push(account.try_borrow_mut_data()?);
    }
    let mut spans: Vec<StateSpanMut<'_>> = Vec::with_capacity(count);
    let mut offset = 0u32;
    for (index, guard) in guards.iter_mut().enumerate() {
        let len = lengths[index];
        spans.push(StateSpanMut {
            key: span_accounts[index].key.to_bytes(),
            owner: span_accounts[index].owner.to_bytes(),
            schema: schema.id,
            offset,
            data: &mut guard[CHILD_HEADER_BYTES..],
        });
        offset += len;
    }
    let written = kernel
        .initial_state_spans(&mut spans)
        .map_err(|_| refusal(REFUSAL_KERNEL))?;
    if written != total as usize {
        return Err(refusal(REFUSAL_KERNEL));
    }
    drop(spans);
    drop(guards);

    session.state_span_count = count as u8;
    session.state_bytes = total;
    session.child_count = session
        .child_count
        .checked_add(count as u16)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    store_session(session_account, &session)
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
    checked_session_status(&session, true)?;
    if session.state_span_count == 0 || session.resource_flags & RESOURCE_STREAM == 0 {
        return Err(refusal(REFUSAL_STATE));
    }
    let role = data[2];
    if !matches!(role, KIND_VIEW_COUNTER | KIND_VIEW_TOTAL | KIND_SCRATCH) {
        return Err(refusal(REFUSAL_VIEW));
    }
    let flag = match role {
        KIND_VIEW_COUNTER => RESOURCE_VIEW_COUNTER,
        KIND_VIEW_TOTAL => RESOURCE_VIEW_TOTAL,
        KIND_SCRATCH => RESOURCE_SCRATCH,
        _ => unreachable!(),
    };
    if session.resource_flags & flag != 0 {
        return Err(refusal(REFUSAL_VIEW));
    }
    let abi_id: [u8; 32] = data[3..35].try_into().expect("fixed width");
    let source_offset = read_u32(data, 35);
    let len = read_u32(data, 39);
    if len == 0 {
        return Err(refusal(REFUSAL_VIEW));
    }
    if role == KIND_SCRATCH {
        if abi_id != [0; 32] || source_offset != 0 || len > MAX_SCRATCH_BYTES {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else {
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
        if len > abi.max_bytes || len > MAX_VIEW_BYTES || source_end > session.state_bytes {
            return Err(refusal(REFUSAL_VIEW));
        }
    }
    if *system.key != system_program::id() {
        return Err(refusal(REFUSAL_SESSION));
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
        CHILD_HEADER_BYTES + len as usize,
    )?;
    let mut raw = view.try_borrow_mut_data()?;
    raw.fill(0);
    raw[..4].copy_from_slice(VIEW_MAGIC);
    write_u16(&mut raw, 4, WIRE_VERSION as u16);
    raw[6] = role;
    raw[7] = if role == KIND_SCRATCH {
        SCRATCH_FLAG
    } else {
        VIEW_FLAG
    };
    raw[8..40].copy_from_slice(session_account.key.as_ref());
    raw[40..72].copy_from_slice(session.authority.as_ref());
    raw[72..104].copy_from_slice(&abi_id);
    write_u32(&mut raw, 104, source_offset);
    write_u32(&mut raw, 108, len);
    write_u32(&mut raw, 112, u32::MAX);
    session.resource_flags |= flag;
    let view_index = match role {
        KIND_VIEW_COUNTER => 0,
        KIND_VIEW_TOTAL => 1,
        KIND_SCRATCH => 2,
        _ => unreachable!(),
    };
    session.view_keys[view_index] = *view.key;
    session.child_count = session
        .child_count
        .checked_add(1)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    drop(raw);
    store_session(session_account, &session)
}

fn write_input(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data.len() < 7 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [writer, session_account, stream] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !writer.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    checked_session_status(&session, true)?;
    if session.resource_flags & RESOURCE_STREAM == 0 || writer.key != &session.writer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    checked_stream(program, stream, session_account, &session, true)?;
    let sequence = read_u32(data, 2);
    let width = data[6] as usize;
    if width != session.command_width as usize || data.len() != 7 + width {
        return Err(refusal(REFUSAL_MALFORMED));
    }
    if sequence < session.cursor || sequence >= session.capacity as u32 {
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
    let lead = next_frontier
        .checked_sub(session.cursor)
        .ok_or_else(|| refusal(REFUSAL_BACKPRESSURE))?;
    if lead > (session.capacity / 2) as u32 {
        return Err(refusal(REFUSAL_BACKPRESSURE));
    }
    let slot_at = CHILD_HEADER_BYTES + sequence as usize * SLOT_BYTES;
    {
        let raw = stream.try_borrow_data()?;
        if raw[slot_at + 4] != 0 {
            return Err(refusal(REFUSAL_DUPLICATE_SLOT));
        }
    }
    {
        let mut raw = stream.try_borrow_mut_data()?;
        write_u32(&mut raw, slot_at, sequence);
        raw[slot_at + 4] = 1;
        raw[slot_at + 8..slot_at + 8 + width].copy_from_slice(&data[7..]);
        write_u32(&mut raw, 80, next_frontier);
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
        || read_u32(&raw, slot_at) != sequence
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

fn validate_state_set(
    program: &Pubkey,
    session_account: &AccountInfo,
    session: &Session,
    state_accounts: &[AccountInfo],
    schema: StateSchema,
    writable: bool,
    expected_cursor: u32,
) -> Result<Vec<StateSpanMeta>, ProgramError> {
    if state_accounts.len() != session.state_span_count as usize
        || state_accounts.is_empty()
        || state_accounts.len() > MAX_STATE_SPANS
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let mut metas = Vec::with_capacity(state_accounts.len());
    let mut next_offset = 0u32;
    let mut transition_start = None;
    for (index, account) in state_accounts.iter().enumerate() {
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
            || meta.count as usize != state_accounts.len()
            || meta.offset != next_offset
            || meta.after_cursor != expected_cursor
            || meta.total_len != session.state_bytes
            || transition_start.is_some_and(|before| before != meta.before_cursor)
        {
            return Err(refusal(REFUSAL_STATE));
        }
        transition_start = Some(meta.before_cursor);
        next_offset = meta
            .offset
            .checked_add(meta.len)
            .ok_or_else(|| refusal(REFUSAL_STATE))?;
        metas.push(meta);
    }
    if next_offset != session.state_bytes {
        return Err(refusal(REFUSAL_STATE));
    }
    Ok(metas)
}

fn advance(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 7)?;
    let Some(actor) = accounts.first() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let Some(session_account) = accounts.get(1) else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let Some(stream) = accounts.get(2) else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data[1] != WIRE_VERSION || !actor.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    checked_session_status(&session, true)?;
    if actor.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let expected_cursor = read_u32(data, 2);
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
    if session.resource_flags & RESOURCE_STREAM == 0 || session.state_span_count == 0 {
        return Err(refusal(REFUSAL_STATE));
    }
    checked_stream(program, stream, session_account, &session, true)?;
    let end_cursor = expected_cursor
        .checked_add(steps as u32)
        .ok_or_else(|| refusal(REFUSAL_RESOURCE))?;
    if end_cursor > session.capacity as u32 || end_cursor > session.frontier {
        return Err(refusal(REFUSAL_INPUT_GAP));
    }
    let state_accounts = &accounts[3..];
    check_unique(accounts)?;
    let schema = validate_kernel(kernel)?;
    let lengths = validate_state_set(
        program,
        session_account,
        &session,
        state_accounts,
        schema,
        true,
        expected_cursor,
    )?;
    let mut commands = Vec::with_capacity(steps as usize);
    for sequence in expected_cursor..end_cursor {
        commands.push(read_slot(stream, &session, sequence)?);
    }
    let output_limit = (kernel.manifest().output.max_bytes as usize)
        .min(kernel.manifest().resources.max_output_bytes as usize);
    if output_limit == 0 || output_limit > 4_096 {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let mut guards = Vec::with_capacity(state_accounts.len());
    for account in state_accounts {
        guards.push(account.try_borrow_mut_data()?);
    }
    let mut spans: Vec<StateSpanMut<'_>> = Vec::with_capacity(state_accounts.len());
    for (index, guard) in guards.iter_mut().enumerate() {
        spans.push(StateSpanMut {
            key: state_accounts[index].key.to_bytes(),
            owner: state_accounts[index].owner.to_bytes(),
            schema: VersionedId {
                id: lengths[index].schema.id,
                version: lengths[index].schema.version,
            },
            offset: lengths[index].offset,
            data: &mut guard[CHILD_HEADER_BYTES..],
        });
    }
    let mut output = vec![0u8; output_limit];
    for command in &commands {
        output.fill(0);
        let written = kernel
            .transition_spans(command, &mut spans, &mut output)
            .map_err(|_| refusal(REFUSAL_KERNEL))?;
        if written > output_limit {
            return Err(refusal(REFUSAL_KERNEL));
        }
    }
    drop(spans);
    drop(guards);

    for (index, account) in state_accounts.iter().enumerate() {
        let mut raw = account.try_borrow_mut_data()?;
        write_u32(&mut raw, 88, expected_cursor);
        write_u32(&mut raw, 92, end_cursor);
        if lengths[index].before_cursor > expected_cursor {
            return Err(refusal(REFUSAL_STATE));
        }
    }
    {
        let mut raw = stream.try_borrow_mut_data()?;
        write_u32(&mut raw, 76, end_cursor);
    }
    session.cursor = end_cursor;
    store_session(session_account, &session)
}

fn copy_state_range(
    state_accounts: &[AccountInfo],
    metas: &[StateSpanMeta],
    offset: u32,
    len: u32,
) -> Result<Vec<u8>, ProgramError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    if len == 0 || metas.last().is_none_or(|meta| end > meta.total_len) {
        return Err(refusal(REFUSAL_VIEW));
    }
    let mut output = vec![0u8; len as usize];
    for (account, meta) in state_accounts.iter().zip(metas) {
        let span_end = meta.offset + meta.len;
        let copy_start = offset.max(meta.offset);
        let copy_end = end.min(span_end);
        if copy_start >= copy_end {
            continue;
        }
        let source_start = CHILD_HEADER_BYTES + (copy_start - meta.offset) as usize;
        let target_start = (copy_start - offset) as usize;
        let count = (copy_end - copy_start) as usize;
        let raw = account.try_borrow_data()?;
        output[target_start..target_start + count]
            .copy_from_slice(&raw[source_start..source_start + count]);
    }
    Ok(output)
}

fn validate_view_declaration(kernel: &dyn StatefulKernel, meta: &ViewMeta) -> ProgramResult {
    if meta.role == KIND_SCRATCH {
        if meta.flags != SCRATCH_FLAG || meta.abi_id != [0; 32] {
            return Err(refusal(REFUSAL_VIEW));
        }
    } else {
        let found = kernel
            .view_abis()
            .iter()
            .any(|abi| abi.role == meta.role && abi.id == meta.abi_id && meta.len <= abi.max_bytes);
        if meta.flags != VIEW_FLAG || !found || meta.len > MAX_VIEW_BYTES {
            return Err(refusal(REFUSAL_VIEW));
        }
    }
    Ok(())
}

fn publish_views(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 6)?;
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let Some(session_account) = accounts.first() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let session = checked_session(program, session_account, false, kernel)?;
    let expected_cursor = read_u32(data, 2);
    if expected_cursor != session.cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    if session.resource_flags & (RESOURCE_VIEW_COUNTER | RESOURCE_VIEW_TOTAL | RESOURCE_SCRATCH)
        != (RESOURCE_VIEW_COUNTER | RESOURCE_VIEW_TOTAL | RESOURCE_SCRATCH)
        || session.state_span_count == 0
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let n = session.state_span_count as usize;
    if accounts.len() != 1 + n + 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    check_unique(accounts)?;
    let state_accounts = &accounts[1..1 + n];
    let metas = validate_state_set(
        program,
        session_account,
        &session,
        state_accounts,
        validate_kernel(kernel)?,
        false,
        expected_cursor,
    )?;
    let output_counter = &accounts[1 + n];
    let output_total = &accounts[2 + n];
    let scratch = &accounts[3 + n];
    let counter_meta = view_meta(
        program,
        output_counter,
        session_account,
        &session,
        KIND_VIEW_COUNTER,
        true,
    )?;
    let total_meta = view_meta(
        program,
        output_total,
        session_account,
        &session,
        KIND_VIEW_TOTAL,
        true,
    )?;
    let scratch_meta = view_meta(
        program,
        scratch,
        session_account,
        &session,
        KIND_SCRATCH,
        true,
    )?;
    validate_view_declaration(kernel, &counter_meta)?;
    validate_view_declaration(kernel, &total_meta)?;
    validate_view_declaration(kernel, &scratch_meta)?;
    if [counter_meta, total_meta, scratch_meta]
        .iter()
        .any(|view| view.source_cursor != u32::MAX && view.source_cursor > expected_cursor)
    {
        return Err(refusal(REFUSAL_VIEW));
    }
    let counter = copy_state_range(
        state_accounts,
        &metas,
        counter_meta.source_offset,
        counter_meta.len,
    )?;
    let total = copy_state_range(
        state_accounts,
        &metas,
        total_meta.source_offset,
        total_meta.len,
    )?;
    let staged_len = counter
        .len()
        .checked_add(total.len())
        .ok_or_else(|| refusal(REFUSAL_VIEW))?;
    if staged_len > scratch_meta.len as usize {
        return Err(refusal(REFUSAL_VIEW));
    }
    {
        let mut raw = scratch.try_borrow_mut_data()?;
        let at = CHILD_HEADER_BYTES;
        raw[at..at + counter.len()].copy_from_slice(&counter);
        raw[at + counter.len()..at + staged_len].copy_from_slice(&total);
        write_u32(&mut raw, 112, expected_cursor);
    }
    {
        let mut raw = output_counter.try_borrow_mut_data()?;
        raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + counter.len()].copy_from_slice(&counter);
        write_u32(&mut raw, 112, expected_cursor);
    }
    {
        let mut raw = output_total.try_borrow_mut_data()?;
        raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + total.len()].copy_from_slice(&total);
        write_u32(&mut raw, 112, expected_cursor);
    }
    Ok(())
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
    let mut session = checked_session(program, session_account, true, kernel)?;
    if authority.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if session.status != STATUS_ACTIVE || read_u32(data, 2) != session.cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    session.status = STATUS_HALTED;
    store_session(session_account, &session)
}

fn close_child(
    program: &Pubkey,
    session_account: &AccountInfo,
    target: &AccountInfo,
    refund: &AccountInfo,
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_HALTED {
        return Err(refusal(REFUSAL_LIVE));
    }
    if refund.key != &session.authority {
        return Err(refusal(REFUSAL_REFUND));
    }
    check_program_owned(target, program, true)?;
    let raw = target.try_borrow_data()?;
    if raw.len() < CHILD_HEADER_BYTES || raw[8..40] != session_account.key.to_bytes() {
        return Err(refusal(REFUSAL_SESSION));
    }
    let kind = raw[6];
    let state_index = raw[78] as usize;
    let mut bit = 0u8;
    let expected_key = match kind {
        KIND_STREAM => {
            bit = RESOURCE_STREAM;
            session.stream_key
        }
        KIND_STATE => {
            if state_index >= MAX_STATE_SPANS {
                return Err(refusal(REFUSAL_STATE));
            }
            session.state_keys[state_index]
        }
        KIND_VIEW_COUNTER => {
            bit = RESOURCE_VIEW_COUNTER;
            session.view_keys[0]
        }
        KIND_VIEW_TOTAL => {
            bit = RESOURCE_VIEW_TOTAL;
            session.view_keys[1]
        }
        KIND_SCRATCH => {
            bit = RESOURCE_SCRATCH;
            session.view_keys[2]
        }
        _ => return Err(refusal(REFUSAL_SESSION)),
    };
    let child_authority = Pubkey::new_from_array(raw[40..72].try_into().expect("fixed width"));
    drop(raw);
    if target.key != &expected_key
        || expected_key == Pubkey::default()
        || (kind != KIND_STREAM && child_authority != session.authority)
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    if session.child_count == 0 {
        return Err(refusal(REFUSAL_SESSION));
    }
    if kind == KIND_STATE {
        if session.state_span_count == 0 {
            return Err(refusal(REFUSAL_STATE));
        }
        session.state_keys[state_index] = Pubkey::default();
        session.state_span_count -= 1;
    } else {
        if session.resource_flags & bit == 0 {
            return Err(refusal(REFUSAL_SESSION));
        }
        session.resource_flags &= !bit;
        match kind {
            KIND_STREAM => session.stream_key = Pubkey::default(),
            KIND_VIEW_COUNTER => session.view_keys[0] = Pubkey::default(),
            KIND_VIEW_TOTAL => session.view_keys[1] = Pubkey::default(),
            KIND_SCRATCH => session.view_keys[2] = Pubkey::default(),
            _ => unreachable!(),
        }
    }
    session.child_count -= 1;
    store_session(session_account, &session)?;
    drain_to_refund(target, refund)
}

fn close_session(
    session_account: &AccountInfo,
    refund: &AccountInfo,
    kernel: &dyn StatefulKernel,
    program: &Pubkey,
) -> ProgramResult {
    let session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_HALTED || session.child_count != 0 || session.resource_flags != 0 {
        return Err(refusal(REFUSAL_LIVE));
    }
    if refund.key != &session.authority {
        return Err(refusal(REFUSAL_REFUND));
    }
    drain_to_refund(session_account, refund)
}

fn drain_to_refund(source: &AccountInfo, refund: &AccountInfo) -> ProgramResult {
    if !source.is_writable || !refund.is_writable {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let source_lamports = source.lamports();
    let refund_lamports = refund.lamports();
    let new_refund = refund_lamports
        .checked_add(source_lamports)
        .ok_or_else(|| refusal(REFUSAL_REFUND))?;
    **refund.try_borrow_mut_lamports()? = new_refund;
    **source.try_borrow_mut_lamports()? = 0;
    source.realloc(0, false)?;
    source.assign(&system_program::id());
    Ok(())
}

fn close_account(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    if data.len() != 3 || data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[2];
    match kind {
        KIND_SESSION => {
            let [session_account, refund] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            check_unique(accounts)?;
            close_session(session_account, refund, kernel, program)
        }
        _ => {
            let [session_account, target, refund] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            check_unique(accounts)?;
            let raw = target.try_borrow_data()?;
            if raw.len() < CHILD_HEADER_BYTES || raw[6] != kind {
                return Err(refusal(REFUSAL_SESSION));
            }
            drop(raw);
            close_child(program, session_account, target, refund, kernel)
        }
    }
}

fn anchor(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 6)?;
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let Some(session_account) = accounts.first() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let Some(stream) = accounts.get(1) else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut session = checked_session(program, session_account, true, kernel)?;
    let expected_cursor = read_u32(data, 2);
    if expected_cursor != session.cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    let n = session.state_span_count as usize;
    if n == 0 || accounts.len() != n + 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let state_accounts = &accounts[2..];
    check_unique(accounts)?;
    checked_stream(program, stream, session_account, &session, false)?;
    let schema = validate_kernel(kernel)?;
    let metas = validate_state_set(
        program,
        session_account,
        &session,
        state_accounts,
        schema,
        false,
        expected_cursor,
    )?;
    if session.anchor_cursor > expected_cursor {
        return Err(refusal(REFUSAL_STATE));
    }
    let mut input_root = if session.input_root == [0; 32] {
        session.stream_root
    } else {
        session.input_root
    };
    for sequence in session.anchor_cursor..expected_cursor {
        let command = read_slot(stream, &session, sequence)?;
        input_root = crate::hash::sha256(&[
            b"dcg/input-chain/1",
            &input_root,
            &sequence.to_le_bytes(),
            &command,
        ]);
    }
    let schema_id_bytes = schema.id.id.to_le_bytes();
    let schema_version_bytes = schema.id.version.to_le_bytes();
    let cursor_bytes = expected_cursor.to_le_bytes();
    let mut state_guards = Vec::with_capacity(state_accounts.len());
    for account in state_accounts {
        state_guards.push(account.try_borrow_data()?);
    }
    let mut parts = crate::hash::Parts::new();
    parts
        .push(b"dcg/state-anchor/1")
        .push(&session.kernel_id.0)
        .push(&schema_id_bytes)
        .push(&schema_version_bytes)
        .push(&cursor_bytes);
    for (raw, meta) in state_guards.iter().zip(metas.iter()) {
        parts.push(&raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + meta.len as usize]);
    }
    let state_anchor = parts.finish();
    drop(parts);
    drop(state_guards);
    session.input_root = input_root;
    session.anchor_cursor = expected_cursor;
    session.state_anchor = state_anchor;
    store_session(session_account, &session)
}

/// Invoke the protocol-v1 stateful account adapter with a statically linked
/// application kernel. The surrounding application chooses the kernel and
/// instruction tags; there is no dynamic loading or CPI to an engine.
fn process_v1_with_kernel(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match tag {
        TAG_OPEN_SESSION => open_session(program, accounts, data, kernel),
        TAG_CREATE_STREAM => create_stream(program, accounts, data, kernel),
        TAG_CREATE_STATE => create_state(program, accounts, data, kernel),
        TAG_CREATE_VIEW => create_view(program, accounts, data, kernel),
        TAG_WRITE_INPUT => write_input(program, accounts, data, kernel),
        TAG_ADVANCE => advance(program, accounts, data, kernel),
        TAG_PUBLISH_VIEWS => publish_views(program, accounts, data, kernel),
        TAG_HALT_SESSION => halt_session(program, accounts, data, kernel),
        TAG_CLOSE_ACCOUNT => close_account(program, accounts, data, kernel),
        TAG_ANCHOR => anchor(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Explicit version-2 stateful adapter. The v1 handler remains available for
/// reproducing its original wire bytes; the dispatcher below selects the
/// version from the instruction data.
#[path = "stateful_v2.rs"]
pub mod v2;

/// Explicit stateful wire v3. It keeps v2 records available while adding
/// primary headerless state, committed-prefix halt, resource-backed views, and
/// resumable initialization.
#[path = "stateful_v3.rs"]
pub mod v3;

/// Invoke the version named in the instruction's wire-version byte.
pub fn process_with_kernel(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    match data.get(1).copied() {
        Some(2) => v2::process_with_kernel(program, accounts, data, kernel),
        Some(3) => v3::process_with_kernel(program, accounts, data, kernel),
        Some(WIRE_VERSION) => process_v1_with_kernel(program, accounts, data, kernel),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Composition seam for application entrypoints that already dispatch other
/// handlers. Stateful tags are handled by the supplied static kernel; every
/// other instruction is passed to `existing_handlers`. This is a processor
/// helper and intentionally defines no second Solana entrypoint.
pub fn process_with_kernel_or_else<F>(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
    existing_handlers: F,
) -> ProgramResult
where
    F: FnOnce(&Pubkey, &[AccountInfo], &[u8]) -> ProgramResult,
{
    if data.first().is_some_and(|tag| {
        (TAG_OPEN_SESSION..=TAG_ANCHOR).contains(tag) || *tag == v3::RESOURCE_CHUNK_TAG
    }) {
        process_with_kernel(program, accounts, data, kernel)
    } else {
        existing_handlers(program, accounts, data)
    }
}
