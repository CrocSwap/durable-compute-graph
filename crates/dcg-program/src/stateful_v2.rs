// SPDX-License-Identifier: GPL-3.0-only

//! Stateful workload wire v2. It preserves a v1 session's identity across
//! bounded stream growth, authenticates an optional initial resource through
//! the statically linked kernel, and stages multi-account views in resumable
//! phases before one atomic publication transaction.

use crate::kernel::{
    AccountSpan, KernelId, ModeId, StateSchema, StateSpanMut, StatefulKernel, VersionedId, ViewAbi,
    ViewPhase, MAX_DECLARED_KERNEL_COMPUTE_UNITS,
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

pub const WIRE_VERSION: u8 = 2;
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

const SESSION_BYTES: usize = 1_280;
const SESSION_MAGIC: &[u8; 4] = b"DSS2";
const SESSION_SEED: &[u8] = b"dcg-session-v2";
const STREAM_SEED: &[u8] = b"dcg-input-v2";
const STATE_SEED: &[u8] = b"dcg-state-v2";
const VIEW_SEED: &[u8] = b"dcg-view-v2";
const CHILD_HEADER_BYTES: usize = 128;
const STREAM_MAGIC: &[u8; 4] = b"DSB2";
const STATE_MAGIC: &[u8; 4] = b"DSE2";
const VIEW_MAGIC: &[u8; 4] = b"DVW2";
const SLOT_BYTES: usize = 16;
const ACCOUNT_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const MODE_CONSENSUS_V2: ModeId = VersionedId {
    id: 0x434f_4e53,
    version: 2,
};
const STATUS_ACTIVE: u8 = 1;
const STATUS_HALTED: u8 = 2;
const POLICY_INDEXED: u8 = 0;
const POLICY_APPEND: u8 = 1;
const PHASE_NONE: u8 = 0;
const PHASE_VIEW_PUBLICATION: u8 = 1;

#[derive(Clone, Copy, Debug)]
struct Session {
    id: u64,
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
    state_keys: [Pubkey; MAX_STATE_SPANS],
    view_keys: [Pubkey; MAX_VIEW_OUTPUTS],
    scratch_key: Pubkey,
    resource_key: Pubkey,
    resource_schema: VersionedId,
    resource_commitment: [u8; 32],
    phase: u8,
    phase_state_cursor: u32,
    phase_cursor: u32,
    phase_total: u32,
    phase_compute_units: u32,
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

fn session_pda(program: &Pubkey, authority: &Pubkey, id: u64) -> (Pubkey, u8) {
    let id = id.to_le_bytes();
    Pubkey::find_program_address(&[SESSION_SEED, authority.as_ref(), &id], program)
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
    Ok(())
}

fn decode_session(raw: &[u8]) -> Result<Session, ProgramError> {
    let view_keys: [Pubkey; MAX_VIEW_OUTPUTS] = core::array::from_fn(|index| {
        let at = 548 + index * 32;
        Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
    });
    let view_count = view_keys
        .iter()
        .filter(|key| **key != Pubkey::default())
        .count();
    if raw.len() != SESSION_BYTES
        || &raw[..4] != SESSION_MAGIC
        || u16_at(raw, 4) != WIRE_VERSION as u16
        || raw[1130..1132] != [0; 2]
        || raw[1165] != 0
        || raw[1164] > PHASE_VIEW_PUBLICATION
        || raw[1182] > 1
        || raw[1183..].iter().any(|byte| *byte != 0)
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
    if (resource_key == Pubkey::default()
        && (resource_commitment != [0; 32]
            || resource_schema.id != 0
            || resource_schema.version != 0))
        || (resource_key != Pubkey::default()
            && (resource_commitment == [0; 32]
                || resource_schema.id == 0
                || resource_schema.version == 0))
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(Session {
        id: u64_at(raw, 14),
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
        state_keys: core::array::from_fn(|index| {
            let at = 292 + index * 32;
            Pubkey::new_from_array(raw[at..at + 32].try_into().expect("fixed width"))
        }),
        view_keys,
        scratch_key: Pubkey::new_from_array(raw[1060..1092].try_into().expect("fixed width")),
        resource_key,
        resource_schema,
        resource_commitment,
        phase: raw[1164],
        phase_state_cursor: u32_at(raw, 1166),
        phase_cursor: u32_at(raw, 1170),
        phase_total: u32_at(raw, 1174),
        phase_compute_units: u32_at(raw, 1178),
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
    if account.key != &session.self_key
        || session.kernel_id != kernel.manifest().id
        || session.semantic_version != kernel.manifest().semantic_version
        || session.abi_version != kernel.manifest().abi_version
        || session.mode != MODE_CONSENSUS_V2
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    Ok(session)
}

#[inline(never)]
fn validate_session_identity(
    program: &Pubkey,
    account: &AccountInfo,
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    drop(checked_session(program, account, false, kernel)?);
    Ok(())
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
    if !payer.is_signer
        || !payer.is_writable
        || !target.is_writable
        || *system.key != system_program::id()
        || target.owner != &system_program::id()
        || target.lamports() != 0
        || !target.data_is_empty()
        || data_len > ACCOUNT_MAX_BYTES
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    let bump_seed = [bump];
    let mut signer_seeds = seeds.to_vec();
    signer_seeds.push(&bump_seed);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            target.key,
            Rent::get()?.minimum_balance(data_len),
            data_len as u64,
            program,
        ),
        &[payer.clone(), target.clone(), system.clone()],
        &[&signer_seeds],
    )?;
    Ok(())
}

fn open_session(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 177)?;
    if data[1] != WIRE_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let resource_key = Pubkey::new_from_array(data[107..139].try_into().expect("fixed width"));
    let resource_schema = VersionedId {
        id: u32_at(data, 139),
        version: u16_at(data, 143),
    };
    let resource_commitment: [u8; 32] = data[145..177].try_into().expect("fixed width");
    let (payer, authority, session_account, resource_account, system) = match accounts {
        [payer, authority, session, system] if resource_key == Pubkey::default() => {
            (payer, authority, session, None, system)
        }
        [payer, authority, session, resource, system] if resource_key != Pubkey::default() => {
            (payer, authority, session, Some(resource), system)
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
    if let Some(resource) = resource_account {
        if resource.key != &resource_key || resource.is_writable || resource.data_is_empty() {
            return Err(refusal(REFUSAL_RESOURCE));
        }
    } else if resource_commitment != [0; 32]
        || resource_schema != (VersionedId { id: 0, version: 0 })
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
    let _schema = validate_kernel(kernel)?;
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
        || mode != MODE_CONSENSUS_V2
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
            state_initialized: false,
            view_count: 0,
            stream_root,
            input_root: [0; 32],
            anchor_cursor: 0,
            state_anchor: [0; 32],
            state_bytes: 0,
            self_key: *session_account.key,
            stream_key: Pubkey::default(),
            state_keys: [Pubkey::default(); MAX_STATE_SPANS],
            view_keys: [Pubkey::default(); MAX_VIEW_OUTPUTS],
            scratch_key: Pubkey::default(),
            resource_key,
            resource_schema,
            resource_commitment,
            phase: PHASE_NONE,
            phase_state_cursor: 0,
            phase_cursor: 0,
            phase_total: 0,
            phase_compute_units: 0,
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
    let raw = account.try_borrow_data()?;
    let expected_len = CHILD_HEADER_BYTES + session.capacity as usize * SLOT_BYTES;
    if account.key != &session.stream_key
        || raw.len() != expected_len
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
        if resource.key != &session.resource_key || resource.is_writable || resource.data_is_empty()
        {
            return Err(refusal(REFUSAL_RESOURCE));
        }
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
        create_pda(
            program,
            payer,
            account,
            system,
            &[STATE_SEED, session_account.key.as_ref(), &[index as u8]],
            bump,
            CHILD_HEADER_BYTES + initial_len,
        )?;
        let mut raw = account.try_borrow_mut_data()?;
        raw.fill(0);
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
        drop(raw);
        session.state_keys[index] = *account.key;
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
    validate_session_identity(program, session_account, kernel)?;
    let index = data[3] as usize;
    let session_raw = session_account.try_borrow_data()?;
    let state_count = session_raw[122] as usize;
    let state_key_offset = 292 + index * 32;
    if session_raw[6] != STATUS_ACTIVE
        || session_raw[1182] != 0
        || session_raw[1164] != PHASE_NONE
        || index >= state_count
        || state_count == 0
        || session_raw[state_key_offset..state_key_offset + 32] != state.key.to_bytes()
    {
        return Err(refusal(REFUSAL_STATE));
    }
    check_program_owned(state, program, true)?;
    let schema = validate_kernel(kernel)?;
    let (expected, _) = state_pda(program, session_account.key, index as u8);
    let raw = state.try_borrow_data()?;
    if state.key != &expected
        || raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != STATE_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STATE
        || raw[78] as usize != index
        || raw[79] as usize != state_count
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session_raw[22..54]
        || u32_at(&raw, 72) != schema.id.id
        || u16_at(&raw, 76) != schema.id.version
        || raw[104..CHILD_HEADER_BYTES].iter().any(|byte| *byte != 0)
        || u32_at(&raw, 96) != u32_at(&session_raw, 224)
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let desired = u32_at(&raw, 84);
    let allocated = u32_at(&raw, 100);
    drop(raw);
    drop(session_raw);
    let next = grow_child_data(payer, state, system, desired, allocated)?;
    put_u32(&mut state.try_borrow_mut_data()?, 100, next);
    Ok(())
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
    let [authority, session_account, remainder @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    let mut session = checked_session(program, session_account, true, kernel)?;
    let count = session.state_span_count as usize;
    let resource_count = usize::from(session.resource_key != Pubkey::default());
    if !authority.is_signer
        || authority.key != &session.authority
        || session.status != STATUS_ACTIVE
        || session.state_initialized
        || count == 0
        || remainder.len() != resource_count + count
    {
        return Err(refusal(REFUSAL_STATE));
    }
    let (resource_accounts, state_accounts) = remainder.split_at(resource_count);
    if resource_count == 1
        && (resource_accounts[0].key != &session.resource_key
            || resource_accounts[0].is_writable
            || resource_accounts[0].data_is_empty())
    {
        return Err(refusal(REFUSAL_RESOURCE));
    }
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
        .map(|(account, raw)| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: session.resource_schema,
            offset: 0,
            data: raw,
        })
        .collect();
    let mut guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_mut_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut spans = Vec::with_capacity(count);
    offset = 0;
    for (index, guard) in guards.iter_mut().enumerate() {
        let len = u32_at(guard, 84);
        spans.push(StateSpanMut {
            key: state_accounts[index].key.to_bytes(),
            owner: state_accounts[index].owner.to_bytes(),
            schema: schema.id,
            offset,
            data: &mut guard[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + len as usize],
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
    } else if (role as usize) < MAX_VIEW_OUTPUTS {
        (KIND_VIEW, session.view_keys[role as usize])
    } else {
        return Err(refusal(REFUSAL_VIEW));
    };
    if expected_key == Pubkey::default() || view.key != &expected_key {
        return Err(refusal(REFUSAL_VIEW));
    }
    check_program_owned(view, program, true)?;
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
    let raw = account.try_borrow_data()?;
    if index >= MAX_STATE_SPANS
        || account.key != &session.state_keys[index]
        || raw.len() < CHILD_HEADER_BYTES
        || &raw[..4] != STATE_MAGIC
        || u16_at(&raw, 4) != WIRE_VERSION as u16
        || raw[6] != KIND_STATE
        || raw[7] != 0
        || raw[8..40] != session_account.key.to_bytes()
        || raw[40..72] != session.authority.to_bytes()
        || u32_at(&raw, 72) != schema.id.id
        || u16_at(&raw, 76) != schema.id.version
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
    let raw = account.try_borrow_data()?;
    let (kind, expected_key) = if role == SCRATCH_ROLE {
        (KIND_SCRATCH, session.scratch_key)
    } else if (role as usize) < MAX_VIEW_OUTPUTS {
        (KIND_VIEW, session.view_keys[role as usize])
    } else {
        return Err(refusal(REFUSAL_VIEW));
    };
    if expected_key == Pubkey::default()
        || account.key != &expected_key
        || raw.len() < CHILD_HEADER_BYTES
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
    let [actor, session_account, stream, state_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if data[1] != WIRE_VERSION || !actor.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE || actor.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
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
        state_accounts,
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
            data: &mut guard[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + metas[index].len as usize],
        });
    }
    let bind = kernel.bind_invocation_state(&mut spans);
    let transition_result = if bind.is_ok() {
        (|| {
            let mut output = vec![0u8; output_len];
            for command in &commands {
                output.fill(0);
                let written = kernel
                    .transition_spans(command, &mut spans, &mut output)
                    .map_err(|_| refusal(REFUSAL_KERNEL))?;
                if written > output_len {
                    return Err(refusal(REFUSAL_KERNEL));
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
    for (index, account) in state_accounts.iter().enumerate() {
        let mut raw = account.try_borrow_mut_data()?;
        put_u32(&mut raw, 88, expected_cursor);
        put_u32(&mut raw, 92, end_cursor);
        if metas[index].before_cursor > expected_cursor {
            return Err(refusal(REFUSAL_STATE));
        }
    }
    {
        let mut raw = stream.try_borrow_mut_data()?;
        put_u32(&mut raw, 76, end_cursor);
    }
    session.cursor = end_cursor;
    store_session(session_account, &session)
}

fn parse_publication_accounts<'a>(
    program: &Pubkey,
    session_account: &AccountInfo,
    session: &Session,
    accounts: &'a [AccountInfo],
    outputs_writable: bool,
    scratch_writable: bool,
    kernel: &dyn StatefulKernel,
) -> Result<(Vec<StateSpanMeta>, usize, Vec<ViewMeta>, usize, ViewMeta), ProgramError> {
    let state_count = session.state_span_count as usize;
    if state_count == 0 || session.view_count == 0 || session.scratch_key == Pubkey::default() {
        return Err(refusal(REFUSAL_VIEW));
    }
    let state_start = 2;
    let view_start = state_start + state_count;
    let scratch_index = view_start + session.view_count as usize;
    if accounts.len() != scratch_index + 1 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let state_accounts = &accounts[state_start..view_start];
    let state_metas = validate_state_set(
        program,
        session_account,
        session,
        state_accounts,
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
            session_account,
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
    let scratch_meta = view_meta(
        program,
        &accounts[scratch_index],
        session_account,
        session,
        SCRATCH_ROLE,
        scratch_writable,
        kernel,
    )?;
    if total > scratch_meta.len {
        return Err(refusal(REFUSAL_VIEW));
    }
    Ok((
        state_metas,
        view_start,
        view_metas,
        scratch_index,
        scratch_meta,
    ))
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

fn begin_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 11)?;
    let [authority, session_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
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
    let (state_metas, view_start, view_metas, _scratch_index, scratch_meta) =
        parse_publication_accounts(
            program,
            session_account,
            &session,
            accounts,
            false,
            true,
            kernel,
        )?;
    let total = total_view_bytes(&view_metas)?;
    let _ = view_start;
    if scratch_meta.len < total
        || state_metas
            .iter()
            .any(|meta| meta.after_cursor != expected_cursor)
    {
        return Err(refusal(REFUSAL_VIEW));
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
    view_metas: &[ViewMeta],
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
        .map(|((account, raw), meta)| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: meta.schema,
            offset: meta.offset,
            data: &raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + meta.len as usize],
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
            let written = kernel
                .render_view_phase(request, &state, &mut chunk[target..target + len])
                .map_err(|_| refusal(REFUSAL_KERNEL))?;
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
    exact_data(data, 11)?;
    let [authority, session_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
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
    let (state_metas, _view_start, view_metas, scratch_index, _scratch_meta) =
        parse_publication_accounts(
            program,
            session_account,
            &session,
            accounts,
            false,
            true,
            kernel,
        )?;
    let state_accounts = &accounts[2..2 + session.state_span_count as usize];
    if state_metas
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
    let count = left.min(kernel.max_view_phase_bytes()) as usize;
    let start = CHILD_HEADER_BYTES + session.phase_cursor as usize;
    let end = start + count;
    {
        let scratch = &accounts[scratch_index];
        let mut raw = scratch.try_borrow_mut_data()?;
        render_phase_chunk(
            state_metas.as_slice(),
            state_accounts,
            &view_metas,
            session.phase_cursor,
            &mut raw[start..end],
            session.phase_state_cursor,
            declared,
            kernel,
        )?;
        put_u32(&mut raw, 112, session.phase_state_cursor);
    }
    session.phase_cursor += count as u32;
    store_session(session_account, &session)
}

fn commit_view_phase(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    kernel: &dyn StatefulKernel,
) -> ProgramResult {
    exact_data(data, 15)?;
    let [authority, session_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    if !authority.is_signer {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    let mut session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_ACTIVE
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
    let (state_metas, view_start, view_metas, scratch_index, scratch_meta) =
        parse_publication_accounts(
            program,
            session_account,
            &session,
            accounts,
            true,
            true,
            kernel,
        )?;
    if state_metas
        .iter()
        .any(|meta| meta.after_cursor != session.phase_state_cursor)
        || scratch_meta.len < session.phase_total
    {
        return Err(refusal(REFUSAL_PHASE_STATE_CHANGED));
    }
    let scratch = &accounts[scratch_index];
    let scratch_raw = scratch.try_borrow_data()?;
    if u32_at(&scratch_raw, 112) != session.phase_state_cursor {
        return Err(refusal(REFUSAL_PHASE_CURSOR));
    }
    let mut at = 0usize;
    for (index, meta) in view_metas.iter().enumerate() {
        let account = &accounts[view_start + index];
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
    let mut session = checked_session(program, session_account, true, kernel)?;
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
    let mut session = checked_session(program, session_account, true, kernel)?;
    if authority.key != &session.authority {
        return Err(refusal(REFUSAL_AUTHORITY));
    }
    if session.status != STATUS_ACTIVE
        || u32_at(data, 2) != session.cursor
        || session.phase != PHASE_NONE
    {
        return Err(refusal(REFUSAL_CURSOR));
    }
    session.status = STATUS_HALTED;
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
    let role = raw[7];
    let state_index = raw[78] as usize;
    let authority_bound = if kind == KIND_STREAM {
        raw[40..72] == session.stream_root && raw[88..120] == session.writer.to_bytes()
    } else {
        raw[40..72] == session.authority.to_bytes()
    };
    let expected = match kind {
        KIND_STREAM => session.stream_key,
        KIND_STATE if state_index < MAX_STATE_SPANS => session.state_keys[state_index],
        KIND_VIEW if (role as usize) < MAX_VIEW_OUTPUTS => session.view_keys[role as usize],
        KIND_SCRATCH => session.scratch_key,
        _ => return Err(refusal(REFUSAL_SESSION)),
    };
    if target.key != &expected
        || expected == Pubkey::default()
        || raw[8..40] != session_account.key.to_bytes()
        || !authority_bound
    {
        return Err(refusal(REFUSAL_SESSION));
    }
    drop(raw);
    match kind {
        KIND_STREAM => session.stream_key = Pubkey::default(),
        KIND_STATE => {
            session.state_keys[state_index] = Pubkey::default();
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
    let session = checked_session(program, session_account, true, kernel)?;
    if session.status != STATUS_HALTED
        || session.child_count != 0
        || session.stream_key != Pubkey::default()
        || session.state_span_count != 0
        || session.view_count != 0
        || session.scratch_key != Pubkey::default()
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
        if target.try_borrow_data()?.get(6).copied() != Some(kind) {
            return Err(refusal(REFUSAL_SESSION));
        }
        close_child(program, session, target, refund, kernel)
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
    let [session_account, stream, state_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_unique(accounts)?;
    let mut session = checked_session(program, session_account, true, kernel)?;
    let cursor = u32_at(data, 2);
    if cursor != session.cursor || session.anchor_cursor > cursor {
        return Err(refusal(REFUSAL_CURSOR));
    }
    stream_pda_check(program, stream, session_account, &session, false)?;
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
    let mut input_root = if session.input_root == [0; 32] {
        session.stream_root
    } else {
        session.input_root
    };
    for sequence in session.anchor_cursor..cursor {
        let command = read_slot(stream, &session, sequence)?;
        input_root = crate::hash::sha256(&[
            b"dcg/input-chain/2",
            &input_root,
            &sequence.to_le_bytes(),
            &command,
        ]);
    }
    let guards = state_accounts
        .iter()
        .map(AccountInfo::try_borrow_data)
        .collect::<Result<Vec<_>, _>>()?;
    let mut parts = crate::hash::Parts::new();
    let schema_id = schema.id.id.to_le_bytes();
    let schema_version = schema.id.version.to_le_bytes();
    let cursor_bytes = cursor.to_le_bytes();
    parts
        .push(b"dcg/state-anchor/2")
        .push(&session.kernel_id.0)
        .push(&schema_id)
        .push(&schema_version)
        .push(&cursor_bytes);
    for (raw, meta) in guards.iter().zip(metas.iter()) {
        parts.push(&raw[CHILD_HEADER_BYTES..CHILD_HEADER_BYTES + meta.len as usize]);
    }
    session.input_root = input_root;
    session.anchor_cursor = cursor;
    session.state_anchor = parts.finish();
    store_session(session_account, &session)
}

/// Process stateful wire v2 using one statically linked application kernel.
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
        crate::stateful::TAG_CREATE_STATE if data.get(2) == Some(&STATE_OP_INITIALIZE) => {
            initialize_state(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_STATE => create_state(program, accounts, data, kernel),
        crate::stateful::TAG_CREATE_VIEW if data.get(2) == Some(&VIEW_OP_GROW) => {
            grow_view(program, accounts, data, kernel)
        }
        crate::stateful::TAG_CREATE_VIEW if data.get(2) == Some(&SCRATCH_ROLE) => {
            create_scratch(program, accounts, data, kernel)
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
