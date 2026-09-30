//! Bounded PT1 testnet bootstrap. The three byte accounts are immutable after
//! seal; a route-tree frontier and payload index make the large rev7 template
//! checkable without a single unbounded SBF instruction.
use crate::position_template as pt;
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

/// NOTE: 95/96/97 are dispatched to the closure-v2 DCM2 v2 bootstrap first in
/// `lib.rs`, so these three PT1S tags are shadowed in the combined image; use
/// the `pt2p_onchain::TAG_BASE_*` aliases (140/141/142) to reach them.
pub const TAG_INIT: u8 = 95;
pub const TAG_UPLOAD: u8 = 96;
pub const TAG_SEAL: u8 = 97;
pub const TAG_INSTANTIATE: u8 = 98;
pub const TAG_CHECK_ORDER: u8 = 99;
pub const TAG_INIT_VARIANT: u8 = 106;
pub const OFF_PAYLOAD_INDEX: usize = OFF_INDEX;
pub const PT1S_MAGIC: &[u8; 4] = MAGIC;
/// Fresh revision-8 base profile. Its byte-index and upload prefix match PT1S
/// v3; the distinct magic opts into PXR1 and its cursor-validated seal stage.
pub const PT1X_MAGIC: &[u8; 4] = b"PT1X";
const MAGIC: &[u8; 4] = b"PT1S";
const OUTPUT_MAGIC: &[u8; 4] = b"PT1O";
/// Marker for an exact PT1O reservation owned and written by tag 199. Unlike
/// a zero-filled account, this cannot be mistaken for a fresh DCR1 challenge.
pub const PT1X_OUTPUT_RESERVATION_MAGIC: &[u8; 4] = b"PT1R";
const OFF_FRONTIER: usize = 165;
const OFF_BITMAP: usize = OFF_FRONTIER + 32 * 32;
const OFF_INDEX: usize = OFF_BITMAP + 4096;
/// Compact state for the retained 28,041-entry K=10,240 PXR1 template,
/// including its two PXR1 decision entries and terminal payload-index offset.
pub const PT1X_MAX_STATE_BYTES: usize = OFF_INDEX + 4 * (28_041 + 1);
/// PT1X keeps one PT2S binding in the upload bitmap space after upload is
/// complete. Tag 142 clears that bitmap after upload and seals the route
/// frontier; tag 143 later writes the PT2S binding. This does not
/// move any PT1S-v3 fields or change the revision-7/tag-106 wire layout.
pub const PT1X_BOUND_PT2S_AT: usize = OFF_BITMAP;
pub const PT1X_PREFIX_BYTES: usize = PT1X_BOUND_PT2S_AT + 32;
/// Revision-8 PT1O header. The first 16 bytes retain the legacy fields; the
/// binding digest commits the output account to the exact template inputs and
/// requested entry interval before any output bytes follow.
pub const PT1X_OUTPUT_HEADER_BYTES: usize = 48;
pub const PT1X_OUTPUT_TRAILER_MAGIC: &[u8; 4] = b"PT1P";
pub const PT1X_OUTPUT_TRAILER_FIXED_BYTES: usize = 41;
/// The PT1O PDA uses its 32-byte binding as its sole seed, followed by Solana's
/// bump seed. The binding commits the program, five/six input keys, position,
/// first entry and count.
pub const TAG_CLOSE_PT1O: u8 = 198;
/// Revision-8 PT1O reservation grows by no more than the runtime's per-
/// instruction account-data limit.
pub const PT1X_OUTPUT_MAX_GROW_BYTES: usize = 10_240;
/// Tag-146 large outputs must be reserved first. Keep this distinct from
/// account-shape refusals so callers can distinguish missing reservation.
pub const PT1O_RESERVATION_REQUIRED: u32 = 605;
const UPLOAD_CHUNK: usize = 900;
const STATE_PXR1: u8 = 5;

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
pub fn is_template_magic(raw: &[u8]) -> bool {
    raw.get(..4)
        .is_some_and(|magic| magic == MAGIC || magic == PT1X_MAGIC)
}
pub fn is_pt1x(raw: &[u8]) -> bool {
    raw.get(..4) == Some(PT1X_MAGIC.as_slice())
}
pub fn is_sealed_template(raw: &[u8]) -> bool {
    raw.len() >= OFF_INDEX
        && (if is_pt1x(raw) {
            matches!(raw[4], 3 | 6)
        } else {
            raw.get(..4) == Some(MAGIC.as_slice()) && raw[4] == 3
        })
}

/// Bind the one revision-8 PT1X base to its one PT2S. This only touches upload
/// bitmap bytes after upload is complete; PT1S-v3 and tag-106 stay fixed.
pub fn bind_pt2s(
    raw: &mut [u8],
    pt2s: &Pubkey,
    authority: &Pubkey,
    keys: &[u8],
    lengths: &[u8],
) -> ProgramResult {
    if raw.len() < PT1X_PREFIX_BYTES
        || !is_pt1x(raw)
        || raw[4] != 3
        || &raw[5..37] != authority.as_ref()
        || &raw[37..133] != keys
        || &raw[133..145] != lengths
        || raw[PT1X_BOUND_PT2S_AT..PT1X_BOUND_PT2S_AT + 32] != [0; 32]
    {
        return Err(ProgramError::InvalidAccountData);
    }
    raw[PT1X_BOUND_PT2S_AT..PT1X_BOUND_PT2S_AT + 32].copy_from_slice(pt2s.as_ref());
    raw[4] = 6;
    Ok(())
}
fn u16_at(b: &[u8], at: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .unwrap(),
    ))
}
fn put_u32(b: &mut [u8], at: usize, x: u32) {
    b[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn owned<'s, 'a>(
    program: &Pubkey,
    accounts: &'s [AccountInfo<'a>],
    at: usize,
) -> Result<&'s AccountInfo<'a>, ProgramError> {
    let a = accounts.get(at).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if a.owner != program {
        return Err(ProgramError::IllegalOwner);
    }
    Ok(a)
}
fn state_key(s: &[u8], kind: usize) -> &[u8] {
    &s[37 + kind * 32..69 + kind * 32]
}
fn check_state(
    program: &Pubkey,
    accounts: &[AccountInfo],
    count: usize,
    writable: bool,
) -> Result<(), ProgramError> {
    if accounts.len() != count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let state = owned(program, accounts, 0)?;
    if state.is_writable != writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let s = state.try_borrow_data()?;
    if s.len() < OFF_INDEX || !is_template_magic(&s) {
        return Err(ProgramError::UninitializedAccount);
    }
    if cfg!(feature = "revision-8") && !is_pt1x(&s) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// PT2P base init (tag 140): as `init`, but each byte account must also sign.
/// A signature proves the initializer holds the fresh account's key, so a
/// second PT1S state cannot bind (and upload over) byte accounts that an
/// earlier state already sealed.
pub fn init_fresh(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if cfg!(feature = "revision-8") && data.first() == Some(&140) {
        init_pt1x(program, accounts, data)
    } else {
        if cfg!(feature = "revision-8") {
            return Err(ProgramError::InvalidInstructionData);
        }
        if accounts.len() != 5 {
            return Err(ProgramError::InvalidInstructionData);
        }
        if accounts[1..4].iter().any(|a| !a.is_signer) {
            return Err(ProgramError::MissingRequiredSignature);
        }
        init(program, accounts, data)
    }
}

/// Revision-8 PT1X tag 140. The state is a fresh program-owned allocation;
/// each base byte account is a fresh, zero-filled System Program allocation
/// signed by its keypair. Tag 140 assigns those allocations to this program
/// before recording their keys and lengths in PT1X.
fn init_pt1x(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 6 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = &accounts[0];
    let byte_accounts = [&accounts[1], &accounts[2], &accounts[3]];
    let authority = &accounts[4];
    let system = &accounts[5];
    if state.owner != program
        || !state.is_writable
        || !state.is_signer
        || !authority.is_signer
        || *system.key != system_program::ID
    {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if byte_accounts.iter().any(|a| !a.is_signer) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if byte_accounts
        .iter()
        .any(|a| !a.is_writable || a.owner != &system_program::ID || a.data_len() == 0)
        || state.key == authority.key
        || byte_accounts
            .iter()
            .any(|a| a.key == state.key || a.key == authority.key)
        || byte_accounts[0].key == byte_accounts[1].key
        || byte_accounts[0].key == byte_accounts[2].key
        || byte_accounts[1].key == byte_accounts[2].key
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut lengths = [0u32; 3];
    for (i, account) in byte_accounts.iter().enumerate() {
        lengths[i] = u32::try_from(account.data_len()).map_err(|_| err(pt::MALFORMED))?;
    }
    // The three accounts are still owned by System and each key signs this
    // assignment. A System-owned allocation is zero-filled by allocate/create
    // and cannot have its bytes written by another program; checking every
    // route, geometry and payload byte here costs more than tag 140's SBF CU
    // budget at the retained K=10,240 shape. Once assigned, PT1X binds each
    // key and length, and all readers validate that binding.
    {
        let current = state.try_borrow_data()?;
        if current.len() < OFF_INDEX + 4 || current.len() > PT1X_MAX_STATE_BYTES {
            return Err(ProgramError::InvalidAccountData);
        }
        if current.iter().any(|&byte| byte != 0) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }

    for account in byte_accounts {
        invoke(
            &system_instruction::assign(account.key, program),
            &[account.clone(), system.clone()],
        )?;
    }

    let mut state_data = state.try_borrow_mut_data()?;
    state_data[..4].copy_from_slice(PT1X_MAGIC);
    state_data[4] = 1;
    state_data[5..37].copy_from_slice(authority.key.as_ref());
    for (kind, account) in byte_accounts.iter().enumerate() {
        state_data[37 + kind * 32..69 + kind * 32].copy_from_slice(account.key.as_ref());
        put_u32(&mut state_data, 133 + kind * 4, lengths[kind]);
    }
    Ok(())
}

/// Bind one PT1O allocation to a PT1X input tuple and one instantiate request.
/// A fresh System Program account has no data; an existing program-owned
/// account must carry either tag 199's PT1R marker or the exact PT1O request
/// header this handler previously wrote.
pub fn validate_pt1x_output_binding(
    program: &Pubkey,
    output: &AccountInfo,
    system: &AccountInfo,
    binding: &[u8; 32],
    position: u32,
    first: u32,
) -> Result<bool, ProgramError> {
    let (expected, _) = pt1x_output_address(program, binding);
    if !output.is_writable || *system.key != system_program::ID || output.key != &expected {
        return Err(ProgramError::InvalidAccountData);
    }
    match output.owner {
        owner if owner == &system_program::ID => {
            if output.data_len() != 0 {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(true)
        }
        owner if owner == program => {
            let raw = output.try_borrow_data()?;
            if raw.len() >= 4 && raw[..4] == *PT1X_OUTPUT_RESERVATION_MAGIC {
                return Ok(false);
            }
            if raw.len() < PT1X_OUTPUT_HEADER_BYTES
                || raw[..4] != *OUTPUT_MAGIC
                || u32_at(&raw, 4)? != position
                || u32_at(&raw, 8)? != first
                || raw[16..48] != binding[..]
            {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(false)
        }
        _ => return Err(ProgramError::IllegalOwner),
    }
}

pub fn prepare_pt1x_output_pda<'a>(
    program: &Pubkey,
    output: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    binding: &[u8; 32],
    count: u32,
    stream_bytes: usize,
    required_bytes: usize,
    input_keys: &[&Pubkey],
    validated_fresh: bool,
) -> ProgramResult {
    if stream_bytes > u32::MAX as usize || required_bytes < PT1X_OUTPUT_HEADER_BYTES {
        return Err(ProgramError::InvalidAccountData);
    }
    if count == 0 || !(4..=6).contains(&input_keys.len()) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let metadata = pt1x_output_metadata(payer.key, count, input_keys);
    let metadata_at = PT1X_OUTPUT_HEADER_BYTES
        .checked_add(stream_bytes)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let metadata_end = metadata_at
        .checked_add(metadata.len())
        .ok_or(ProgramError::AccountDataTooSmall)?;
    if required_bytes < metadata_end {
        return Err(ProgramError::InvalidAccountData);
    }
    // A fresh PDA can still be created directly for small outputs. Larger
    // PT1Os must already have reached their exact size through tag 199.
    let allocation_bytes = required_bytes;
    // `instantiate` validates this binding before walking the PT2P entries.
    // Carry that result forward so fresh accounts, which are zero-filled by
    // the System Program in this instruction, need no byte scan.
    if validated_fresh {
        if allocation_bytes > PT1X_OUTPUT_MAX_GROW_BYTES {
            return Err(ProgramError::Custom(PT1O_RESERVATION_REQUIRED));
        }
        if !payer.is_signer
            || !payer.is_writable
            || payer.key == output.key
            || output.owner != &system_program::ID
            || output.data_len() != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let (expected, bump) = pt1x_output_address(program, binding);
        if output.key != &expected {
            return Err(ProgramError::InvalidAccountData);
        }
        let rent = Rent::get()?.minimum_balance(allocation_bytes);
        let space =
            u64::try_from(allocation_bytes).map_err(|_| ProgramError::AccountDataTooSmall)?;
        let bump_seed = [bump];
        let signer_seeds: &[&[u8]] = &[binding, &bump_seed];
        if output.lamports() == 0 {
            invoke_signed(
                &system_instruction::create_account(payer.key, output.key, rent, space, program),
                &[payer.clone(), output.clone(), system.clone()],
                &[signer_seeds],
            )?;
        } else {
            if output.lamports() < rent {
                invoke(
                    &system_instruction::transfer(payer.key, output.key, rent - output.lamports()),
                    &[payer.clone(), output.clone(), system.clone()],
                )?;
            }
            invoke_signed(
                &system_instruction::allocate(output.key, space),
                &[output.clone(), system.clone()],
                &[signer_seeds],
            )?;
            invoke_signed(
                &system_instruction::assign(output.key, program),
                &[output.clone(), system.clone()],
                &[signer_seeds],
            )?;
        }
    } else {
        let raw = output.try_borrow_data()?;
        if raw.len() != required_bytes {
            return Err(ProgramError::Custom(PT1O_RESERVATION_REQUIRED));
        }
        if raw[..4] == *PT1X_OUTPUT_RESERVATION_MAGIC {
            // Only tag 199 can write PT1R. It creates a zero-filled System
            // allocation and preserves this marker while growing it, so the
            // untouched body needs no scan here.
        } else if raw.len() < PT1X_OUTPUT_HEADER_BYTES
            || raw[..4] != *OUTPUT_MAGIC
            || u32_at(&raw, 12)? as usize != stream_bytes
        {
            return Err(ProgramError::Custom(PT1O_RESERVATION_REQUIRED));
        }
    }
    {
        let mut raw = output.try_borrow_mut_data()?;
        let reused = !validated_fresh && raw[..4] == *OUTPUT_MAGIC;
        let trailer = raw
            .get_mut(metadata_at..metadata_end)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        if reused && trailer != metadata.as_slice() {
            return Err(ProgramError::InvalidAccountData);
        }
        trailer.copy_from_slice(&metadata);
    }
    Ok(())
}

/// One step of revision-8 PT1O PDA reservation. The caller supplies the
/// already-validated binding and exact final size; each call advances an
/// existing allocation by at most 10,240 bytes, preserving PT1R in its prefix
/// while leaving every newly allocated byte zeroed.
pub fn reserve_pt1x_output_pda<'a>(
    program: &Pubkey,
    output: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    binding: &[u8; 32],
    required_bytes: usize,
) -> ProgramResult {
    if !cfg!(feature = "revision-8")
        || required_bytes == 0
        || !output.is_writable
        || !payer.is_writable
        || output.key == payer.key
        || *system.key != system_program::ID
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, bump) = pt1x_output_address(program, binding);
    if output.key != &expected {
        return Err(ProgramError::InvalidAccountData);
    }

    let current = output.data_len();
    let system_owned = output.owner == &system_program::ID;
    let next = match output.owner {
        owner if owner == &system_program::ID => {
            if current != 0 {
                return Err(ProgramError::InvalidAccountData);
            }
            required_bytes.min(PT1X_OUTPUT_MAX_GROW_BYTES)
        }
        owner if owner == program => {
            if current > required_bytes {
                return Err(ProgramError::InvalidAccountData);
            }
            let raw = output.try_borrow_data()?;
            if current == required_bytes {
                if raw.len() >= 4
                    && (raw[..4] == *PT1X_OUTPUT_RESERVATION_MAGIC || raw[..4] == *OUTPUT_MAGIC)
                {
                    return Ok(());
                }
                return Err(ProgramError::InvalidAccountData);
            }
            if raw.len() < 4 || raw[..4] != *PT1X_OUTPUT_RESERVATION_MAGIC {
                return Err(ProgramError::InvalidAccountData);
            }
            required_bytes.min(
                current
                    .checked_add(PT1X_OUTPUT_MAX_GROW_BYTES)
                    .ok_or(ProgramError::AccountDataTooSmall)?,
            )
        }
        _ => return Err(ProgramError::IllegalOwner),
    };
    let rent = Rent::get()?.minimum_balance(next);
    let space = u64::try_from(next).map_err(|_| ProgramError::AccountDataTooSmall)?;
    let bump_seed = [bump];
    let signer_seeds: &[&[u8]] = &[binding, &bump_seed];
    if output.owner == &system_program::ID {
        if output.lamports() == 0 {
            invoke_signed(
                &system_instruction::create_account(payer.key, output.key, rent, space, program),
                &[payer.clone(), output.clone(), system.clone()],
                &[signer_seeds],
            )?;
        } else {
            if output.lamports() < rent {
                invoke(
                    &system_instruction::transfer(payer.key, output.key, rent - output.lamports()),
                    &[payer.clone(), output.clone(), system.clone()],
                )?;
            }
            invoke_signed(
                &system_instruction::allocate(output.key, space),
                &[output.clone(), system.clone()],
                &[signer_seeds],
            )?;
            invoke_signed(
                &system_instruction::assign(output.key, program),
                &[output.clone(), system.clone()],
                &[signer_seeds],
            )?;
        }
    } else {
        if output.lamports() < rent {
            invoke(
                &system_instruction::transfer(payer.key, output.key, rent - output.lamports()),
                &[payer.clone(), output.clone(), system.clone()],
            )?;
        }
        output.realloc(next, true)?;
    }
    if system_owned {
        output.try_borrow_mut_data()?[..4].copy_from_slice(PT1X_OUTPUT_RESERVATION_MAGIC);
    }
    Ok(())
}

/// Close an unwritten PT1R reservation and return its rent to the PT1X
/// authority. Tag 200 calls this only after recomputing the full request size
/// from the same inputs as tag 146; partial reservations may be smaller.
pub fn close_pt1x_output_reservation<'a>(
    program: &Pubkey,
    output: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    binding: &[u8; 32],
    required_bytes: usize,
) -> ProgramResult {
    if output.owner != program
        || !output.is_writable
        || !payer.is_writable
        || output.key == payer.key
        || !payer.is_signer
        || output.data_len() > required_bytes
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let (expected, _) = pt1x_output_address(program, binding);
    if output.key != &expected {
        return Err(ProgramError::InvalidAccountData);
    }
    let raw = output.try_borrow_data()?;
    if raw.len() < 4 || raw[..4] != *PT1X_OUTPUT_RESERVATION_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(raw);
    crate::unified::result::drain(output, payer)?;
    Ok(())
}

/// Retained only for the legacy tag-98 handler, which revision 8 refuses at
/// dispatch. Revision-8 tag 146 uses `prepare_pt1x_output_pda`.
pub fn prepare_pt1x_output<'a>(
    program: &Pubkey,
    output: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    count: u32,
    stream_bytes: usize,
    required_bytes: usize,
    payer: &Pubkey,
    input_keys: &[&Pubkey],
    validated_fresh: bool,
) -> ProgramResult {
    if stream_bytes > u32::MAX as usize
        || required_bytes < PT1X_OUTPUT_HEADER_BYTES
        || count == 0
        || !(4..=6).contains(&input_keys.len())
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let metadata = pt1x_output_metadata(payer, count, input_keys);
    let metadata_at = PT1X_OUTPUT_HEADER_BYTES
        .checked_add(stream_bytes)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let metadata_end = metadata_at
        .checked_add(metadata.len())
        .ok_or(ProgramError::AccountDataTooSmall)?;
    if required_bytes < metadata_end || output.data_len() < required_bytes {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if validated_fresh {
        invoke(
            &system_instruction::assign(output.key, program),
            &[output.clone(), system.clone()],
        )?;
    } else if u32_at(&output.try_borrow_data()?, 12)? as usize != stream_bytes {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut raw = output.try_borrow_mut_data()?;
    let trailer = raw
        .get_mut(metadata_at..metadata_end)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    if !validated_fresh && trailer != metadata.as_slice() {
        return Err(ProgramError::InvalidAccountData);
    }
    trailer.copy_from_slice(&metadata);
    Ok(())
}

pub fn pt1x_output_metadata(payer: &Pubkey, count: u32, input_keys: &[&Pubkey]) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(PT1X_OUTPUT_TRAILER_FIXED_BYTES + 32 * input_keys.len());
    metadata.extend_from_slice(PT1X_OUTPUT_TRAILER_MAGIC);
    metadata.extend_from_slice(payer.as_ref());
    metadata.extend_from_slice(&count.to_le_bytes());
    metadata.push(input_keys.len() as u8);
    for key in input_keys {
        metadata.extend_from_slice(key.as_ref());
    }
    metadata
}

pub fn pt1x_output_address(program: &Pubkey, binding: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[binding], program)
}

/// Tag 198 closes one program-assigned PT1O and returns all lamports to the
/// PT1X authority recorded when tag 146 created its PT1P trailer. The metadata
/// keeps enough of the original input tuple to recheck the PT1O binding even
/// after tag 186 has closed the template accounts.
pub fn close_pt1x_output(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !cfg!(feature = "revision-8") || data != [TAG_CLOSE_PT1O] || accounts.len() != 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let output = &accounts[0];
    let payer = &accounts[1];
    if output.owner != program
        || !output.is_writable
        || !payer.is_writable
        || output.key == payer.key
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let raw = output.try_borrow_data()?;
    if raw.len() < PT1X_OUTPUT_HEADER_BYTES + PT1X_OUTPUT_TRAILER_FIXED_BYTES
        || raw[..4] != *OUTPUT_MAGIC
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let stream_bytes = u32_at(&raw, 12)? as usize;
    let trailer_at = PT1X_OUTPUT_HEADER_BYTES
        .checked_add(stream_bytes)
        .ok_or(ProgramError::InvalidAccountData)?;
    let fixed_end = trailer_at
        .checked_add(PT1X_OUTPUT_TRAILER_FIXED_BYTES)
        .ok_or(ProgramError::InvalidAccountData)?;
    let trailer = raw
        .get(trailer_at..fixed_end)
        .ok_or(ProgramError::InvalidAccountData)?;
    if trailer[..4] != *PT1X_OUTPUT_TRAILER_MAGIC || trailer[4..36] != payer.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    let count = u32_at(trailer, 36)?;
    let key_count = trailer[40] as usize;
    if count == 0 || !(5..=6).contains(&key_count) {
        return Err(ProgramError::InvalidAccountData);
    }
    let keys_end = fixed_end
        .checked_add(key_count * 32)
        .ok_or(ProgramError::InvalidAccountData)?;
    let key_bytes = raw
        .get(fixed_end..keys_end)
        .ok_or(ProgramError::InvalidAccountData)?;
    let keys = key_bytes
        .chunks_exact(32)
        .map(|chunk| Pubkey::new_from_array(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    let key_refs = keys.iter().collect::<Vec<_>>();
    let position = u32_at(&raw, 4)?;
    let first = u32_at(&raw, 8)?;
    let binding = pt1x_output_binding(program, &key_refs, position, first, count);
    let (expected, _) = pt1x_output_address(program, &binding);
    if binding != raw[16..48] || output.key != &expected {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(raw);
    crate::unified::result::drain(output, payer)?;
    Ok(())
}

pub fn pt1x_output_binding(
    program: &Pubkey,
    input_keys: &[&Pubkey],
    position: u32,
    first: u32,
    count: u32,
) -> [u8; 32] {
    let mut keys = Vec::with_capacity(input_keys.len() * 32);
    for key in input_keys {
        keys.extend_from_slice(key.as_ref());
    }
    crate::hash::sha256(&[
        b"basanos/pt1-output-binding/1",
        program.as_ref(),
        &keys,
        &position.to_le_bytes(),
        &first.to_le_bytes(),
        &count.to_le_bytes(),
    ])
}

/// Accounts: state(w), clause5(w), clause12(w), payload(w), authority(s).
/// All byte accounts are created fresh and program-owned by the caller.
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_with_magic(program, accounts, data, MAGIC)
}

fn init_with_magic(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    magic: &[u8; 4],
) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 5 {
        return Err(ProgramError::InvalidInstructionData);
    }
    for at in 0..4 {
        owned(program, accounts, at)?;
    }
    if !accounts[0].is_writable || !accounts[0].is_signer || !accounts[4].is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut state = accounts[0].try_borrow_mut_data()?;
    if magic == PT1X_MAGIC && state.len() > PT1X_MAX_STATE_BYTES {
        return Err(ProgramError::InvalidAccountData);
    }
    // For PT1X, check its compact state in place, but do not zero-scan the
    // multi-megabyte routes, geometry or payload accounts. This state is 117 KiB for the
    // retained 28,041-entry K=10,240 bundle. The zeroed bitmap and byte
    // counters make a bounded coverage proof: every accepted chunk starts on
    // a 900-byte boundary, has the exact expected length for that slot, and
    // maps to one unique bitmap bit. Uploads may land in any order; a duplicate
    // bit is accepted only for identical bytes and does not increment the
    // counter. Tag 142 requires the counter to equal the bound account's full
    // declared length. Because distinct fixed slots partition that length, an
    // equal sum means every slot (including the shorter final slot) was
    // written. This remains sound if allocated byte accounts did not begin
    // zeroed and avoids scanning or copying them.
    // The PT1S v3 initializer retains its original four-byte freshness check.
    if state.len() < OFF_INDEX + 4
        || state[..4] != [0; 4]
        || (magic == PT1X_MAGIC && state.iter().any(|&b| b != 0))
    {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    if accounts[1].key == accounts[2].key
        || accounts[1].key == accounts[3].key
        || accounts[2].key == accounts[3].key
        || accounts[0].key == accounts[1].key
        || accounts[0].key == accounts[2].key
        || accounts[0].key == accounts[3].key
    {
        return Err(ProgramError::InvalidAccountData);
    }
    state[..4].copy_from_slice(magic);
    state[4] = 1;
    state[5..37].copy_from_slice(accounts[4].key.as_ref());
    for kind in 0..3 {
        let len = u32::try_from(accounts[kind + 1].data_len()).map_err(|_| err(pt::MALFORMED))?;
        state[37 + kind * 32..69 + kind * 32].copy_from_slice(accounts[kind + 1].key.as_ref());
        put_u32(&mut state, 133 + kind * 4, len);
    }
    Ok(())
}

/// Clone the *bindings* of an already sealed template into an isolated test
/// state, changing only one byte account. The unchanged accounts are reused
/// read-only and their upload bits are complete. The changed account must be
/// a fresh signer-owned address and is uploaded normally before seal.
/// Accounts: new_state(w,s), sealed_state, routes, geom, payload, authority(s).
/// Data: tag | changed_kind:u8 (1 = geometry, 2 = payload).
pub fn init_variant(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if cfg!(feature = "revision-8") {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data.len() != 2 || !(data[1] == 1 || data[1] == 2) || accounts.len() != 6 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let kind = data[1] as usize;
    for at in 0..5 {
        owned(program, accounts, at)?;
    }
    if !accounts[0].is_writable
        || !accounts[0].is_signer
        || accounts[1].is_writable
        || !accounts[2 + kind].is_signer
        || !accounts[5].is_signer
    {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let old = accounts[1].try_borrow_data()?;
    if old.len() < OFF_INDEX
        || &old[..4] != MAGIC
        || old[4] != 3
        || &old[5..37] != accounts[5].key.as_ref()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut new = accounts[0].try_borrow_mut_data()?;
    if new.len() < old.len() || new[..4] != [0; 4] {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    new[..4].copy_from_slice(MAGIC);
    new[4] = 1;
    new[5..37].copy_from_slice(accounts[5].key.as_ref());
    for k in 0..3 {
        let candidate = &accounts[k + 2];
        let length = u32_at(&old, 133 + k * 4)?;
        if candidate.data_len() != length as usize
            || (k == kind && state_key(&old, k) == candidate.key.as_ref())
            || (k != kind && state_key(&old, k) != candidate.key.as_ref())
        {
            return Err(ProgramError::InvalidAccountData);
        }
        new[37 + k * 32..69 + k * 32].copy_from_slice(candidate.key.as_ref());
        put_u32(&mut new, 133 + k * 4, length);
        if k != kind {
            put_u32(&mut new, 145 + k * 4, length);
            let mut base = 0usize;
            for previous in 0..k {
                base += (u32_at(&old, 133 + previous * 4)? as usize).div_ceil(UPLOAD_CHUNK);
            }
            for bit_index in base..base + (length as usize).div_ceil(UPLOAD_CHUNK) {
                if bit_index >= 4096 * 8 {
                    return Err(ProgramError::AccountDataTooSmall);
                }
                new[OFF_BITMAP + bit_index / 8] |= 1 << (bit_index % 8);
            }
        }
    }
    Ok(())
}

/// Accounts: state(w), selected byte account(w), authority(s).
/// Data: tag | kind:u8 | offset:u32 | bytes. Exact 900-byte chunks can land
/// in any order; a bitmap makes retries idempotent and proves completeness.
pub fn upload(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 7 || accounts.len() != 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    check_state(program, accounts, 3, true)?;
    let kind = data[1] as usize;
    if kind >= 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let target = owned(program, accounts, 1)?;
    let authority = &accounts[2];
    if !target.is_writable || !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut state = accounts[0].try_borrow_mut_data()?;
    if state[4] != 1
        || state_key(&state, kind) != target.key.as_ref()
        || &state[5..37] != authority.key.as_ref()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let offset = u32_at(data, 2)?;
    let len = u32_at(&state, 133 + kind * 4)?;
    let end = offset
        .checked_add((data.len() - 6) as u32)
        .ok_or(err(pt::MALFORMED))?;
    if offset as usize % UPLOAD_CHUNK != 0
        || end > len
        || data.len() - 6 != (len as usize - offset as usize).min(UPLOAD_CHUNK)
    {
        return Err(err(pt::MALFORMED));
    }
    let mut bit_index = 0usize;
    for previous in 0..kind {
        bit_index += (u32_at(&state, 133 + previous * 4)? as usize).div_ceil(UPLOAD_CHUNK);
    }
    bit_index += offset as usize / UPLOAD_CHUNK;
    if bit_index >= 4096 * 8 {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let bit_at = OFF_BITMAP + bit_index / 8;
    let bit = 1u8 << (bit_index % 8);
    let mut out = target.try_borrow_mut_data()?;
    if state[bit_at] & bit != 0 {
        if out[offset as usize..end as usize] != data[6..] {
            return Err(err(pt::MALFORMED));
        }
        return Ok(());
    }
    out[offset as usize..end as usize].copy_from_slice(&data[6..]);
    state[bit_at] |= bit;
    let written = u32_at(&state, 145 + kind * 4)?;
    put_u32(
        &mut state,
        145 + kind * 4,
        written + (data.len() - 6) as u32,
    );
    Ok(())
}

fn bind_inputs(program: &Pubkey, accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    let state = owned(program, accounts, 0)?;
    let s = state.try_borrow_data()?;
    for kind in 0..3 {
        let account = owned(program, accounts, kind + 1)?;
        if state_key(&s, kind) != account.key.as_ref()
            || u32_at(&s, 133 + 4 * kind)? as usize != account.data_len()
        {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    Ok(())
}

/// The clause-12 v2 bytes of a PT1S geometry account: either the rev7 raw v2
/// string (unchanged), or a PTG4 envelope with zero window rows and an empty
/// ESG4 tail (the PT2P base, §17.1), unwrapped to its v2 base. Clause-12 v3
/// or v4 and any PTG4 with window rows or span groups refuse (603).
pub fn base_clause12(geom: &[u8]) -> Result<&[u8], ProgramError> {
    match geom.first() {
        Some(&3) => Err(err(pt::PT2_ROUTE_SET)),
        Some(&4) => crate::pt2p::ptg4_base(geom).map_err(err),
        _ => Ok(geom),
    }
}

fn template<'a>(
    routes: &'a [u8],
    geom: &'a [u8],
    allow_pxr1: bool,
) -> Result<(pt::Template<'a>, pt::Clause12<'a>), ProgramError> {
    // PT2 clause 12 names a position manifest and per-position route sets.
    // This legacy three-account state has only one route set and no manifest;
    // never reinterpret a v3 document as the uniform v2 template.
    let geom = base_clause12(geom)?;
    let (c, _) = pt::clause12_layout(geom).map_err(err)?;
    let n = if allow_pxr1 {
        pt::route_header_v4_shallow(routes).map_err(err)?.0
    } else {
        pt::route_header(routes).map_err(err)?.0
    };
    if n != c.entries_per_position {
        return Err(err(pt::MALFORMED));
    }
    Ok((
        pt::Template {
            clause5: routes,
            clause12: geom,
            position_count: c.position_count,
            prompt_positions: c.prompt_positions,
            max_producer_delta: c.max_producer_delta,
            entries_per_position: n,
            leaf_storage_mode: c.leaf_storage_mode,
        },
        c,
    ))
}

/// Validate a bounded PXR1 row slice after the route-table root has sealed.
/// State byte 4 names this phase and byte 157 is its row cursor. Every refusal
/// is explicit: malformed directory data is 580, an absent/non-invariant
/// region is 603, and a row that does not name its exact producer write is 604.
fn validate_pxr1_chunk(
    routes: &[u8],
    c: pt::Clause12<'_>,
    pxr: pt::Pxr1<'_>,
    first: u32,
    end: u32,
) -> Result<(), ProgramError> {
    if pxr.token_count != crate::kernels::decision::LOGITS_ROW_LENGTH as u32 {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    // Clause-12 stores only regions with nonzero position geometry. An absent
    // position row therefore means the default invariant (ring=0, stride=0).
    if c.region_position(pxr.region_id)
        .map_err(err)?
        .is_some_and(|region| region.ring != 0 || region.stride != 0)
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    for i in first..end {
        let row = pxr.row(i).map_err(err)?;
        let token_end = row
            .first_token
            .checked_add(row.token_count)
            .ok_or(err(pt::OVERFLOW))?;
        if i == 0 {
            if row.first_token != 0 {
                return Err(err(pt::MALFORMED));
            }
        } else {
            let previous = pxr.row(i - 1).map_err(err)?;
            let previous_token_end = previous
                .first_token
                .checked_add(previous.token_count)
                .ok_or(err(pt::OVERFLOW))?;
            let previous_byte_end = previous
                .region_offset
                .checked_add(previous.byte_length as u64)
                .ok_or(err(pt::OVERFLOW))?;
            if previous_token_end != row.first_token || previous_byte_end != row.region_offset {
                return Err(err(pt::PT2_ROUTE_SET));
            }
        }
        if token_end > pxr.token_count {
            return Err(err(pt::MALFORMED));
        }
        let producer =
            pt::entry_at(routes, row.producer_entry).map_err(|_| err(pt::PT2_PRODUCER))?;
        if row.producer_write_ordinal as u32 >= producer.write_count as u32 {
            return Err(err(pt::PT2_PRODUCER));
        }
        let route = pt::route_at(
            routes,
            producer,
            producer.read_count + row.producer_write_ordinal,
        )
        .map_err(err)?;
        if route.direction != 1
            || route.region_id != pxr.region_id
            || route.region_offset != row.region_offset
            || route.byte_length != row.byte_length
            || route.producer_entry != row.producer_entry
            || route.producer_delta != 0
            || route.flags != 0
        {
            return Err(err(pt::PT2_PRODUCER));
        }
    }
    if end == pxr.row_count {
        let last = pxr.row(end - 1).map_err(err)?;
        if last
            .first_token
            .checked_add(last.token_count)
            .ok_or(err(pt::OVERFLOW))?
            != pxr.token_count
        {
            return Err(err(pt::MALFORMED));
        }
    }
    Ok(())
}

/// Accounts: state(w), clause5, clause12, payload. Data: tag | count:u16.
/// Each call validates the next `count` entries and folds their route leaves.
pub fn seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 3 || !matches!(accounts.len(), 4 | 5) {
        return Err(ProgramError::InvalidInstructionData);
    }
    check_state(program, accounts, accounts.len(), true)?;
    bind_inputs(program, accounts)?;
    let count = u16_at(data, 1)? as u32;
    if count == 0 || count > 64 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let routes = accounts[1].try_borrow_data()?;
    let geom = accounts[2].try_borrow_data()?;
    let payload = accounts[3].try_borrow_data()?;
    let is_v4 = {
        let s = accounts[0].try_borrow_data()?;
        is_pt1x(&s)
    };
    if is_v4 {
        let state = accounts[0].try_borrow_data()?;
        let authority = accounts.get(4).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !authority.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if authority.key.as_ref() != &state[5..37]
            || (state[4] != 1 && state[PT1X_BOUND_PT2S_AT..PT1X_BOUND_PT2S_AT + 32] != [0; 32])
        {
            return Err(ProgramError::InvalidAccountData);
        }
    } else if accounts.len() != 4 {
        // The v3/tag-106 account form remains exactly as it was.
        return Err(ProgramError::InvalidInstructionData);
    }
    let (t, c) = template(&routes, &geom, is_v4)?;
    let records = if is_v4 {
        pt::route_header_v4_shallow(&routes).map_err(err)?.1
    } else {
        pt::route_header(&routes).map_err(err)?.1
    };
    let mut state = accounts[0].try_borrow_mut_data()?;
    if state[4] == 1 {
        for kind in 0..3 {
            if u32_at(&state, 145 + kind * 4)? != u32_at(&state, 133 + kind * 4)? {
                return Err(err(pt::MALFORMED));
            }
        }
        if is_v4 {
            // The upload bitmap has served its purpose. Reclaim it so PT1X can
            // bind its sole PT2S there after the route frontier is sealed.
            state[OFF_BITMAP..OFF_INDEX].fill(0);
        }
        if state.len() < OFF_INDEX + 4 * (t.entries_per_position as usize + 1) {
            return Err(ProgramError::AccountDataTooSmall);
        }
        state[4] = 2;
    }
    if state[4] == 2 {
        let (_, total) = pt::clause12_layout(base_clause12(&geom)?).map_err(err)?;
        let start = u32_at(&state, 157)?;
        let end = start
            .checked_add(count)
            .ok_or(err(pt::MALFORMED))?
            .min(total);
        for item in start..end {
            pt::validate_clause12_item(&c, item).map_err(err)?;
        }
        if end == total {
            state[4] = 4;
            put_u32(&mut state, 157, 0);
        } else {
            put_u32(&mut state, 157, end);
        }
        return Ok(());
    }
    if state[4] == STATE_PXR1 {
        let pxr = pt::route_header_v4_shallow(&routes)
            .map_err(err)?
            .2
            .ok_or(err(pt::PT2_ROUTE_SET))?;
        let start = u32_at(&state, 157)?;
        let end = start
            .checked_add(count)
            .ok_or(err(pt::MALFORMED))?
            .min(pxr.row_count);
        validate_pxr1_chunk(&routes, c, pxr, start, end)?;
        if end == pxr.row_count {
            state[4] = 3;
            put_u32(&mut state, 157, 0);
        } else {
            put_u32(&mut state, 157, end);
        }
        return Ok(());
    }
    if state[4] != 4 {
        return Err(ProgramError::InvalidAccountData);
    }
    let start = u32_at(&state, 157)?;
    let end = start
        .checked_add(count)
        .ok_or(err(pt::MALFORMED))?
        .min(t.entries_per_position);
    let mut running = u32_at(&state, 161)?;
    let mut payload_at = if start == 0 {
        0
    } else {
        u32_at(&state, OFF_INDEX + 4 * start as usize)?
    };
    let mut frontier = [[0u8; 32]; 32];
    for (i, slot) in frontier.iter_mut().enumerate() {
        slot.copy_from_slice(&state[OFF_FRONTIER + 32 * i..OFF_FRONTIER + 32 * (i + 1)]);
    }
    for i in start..end {
        let e = t.entry(i).map_err(err)?;
        let row_at = 80 + i as usize * 16;
        if e.index != i || e.route_start != running || routes[row_at + 10..row_at + 12] != [0; 2] {
            return Err(err(pt::MALFORMED));
        }
        if e.read_count as u32 + e.write_count as u32 > u16::MAX as u32 {
            return Err(err(pt::MALFORMED));
        }
        running = running
            .checked_add(e.read_count as u32 + e.write_count as u32)
            .ok_or(err(pt::MALFORMED))?;
        if running > records {
            return Err(err(pt::MALFORMED));
        }
        pt::seal_route_rules(&t, &c, e).map_err(err)?;
        for ordinal in 0..e.read_count + e.write_count {
            let r = pt::route_at(&routes, e, ordinal).map_err(err)?;
            let direction = if ordinal < e.read_count { 0 } else { 1 };
            let k = if direction == 0 {
                ordinal
            } else {
                ordinal - e.read_count
            };
            if r.direction != direction
                || r.read_class > 3
                || r.flags & !3 != 0
                || (r.byte_length == 0 && r.flags & 2 == 0)
                || (direction == 1 && r.read_class != 0)
                || ((r.flags & 2 != 0) != c.t_scaled_for(i, direction, k).map_err(err)?.is_some())
            {
                return Err(err(pt::MALFORMED));
            }
        }
        let p = payload
            .get(payload_at as usize..payload_at as usize + 6)
            .ok_or(err(pt::MALFORMED))?;
        if u32_at(p, 0)? != i {
            return Err(err(pt::MALFORMED));
        }
        payload_at = payload_at
            .checked_add(6 + u16_at(p, 4)? as u32)
            .ok_or(err(pt::MALFORMED))?;
        if payload_at as usize > payload.len() {
            return Err(err(pt::MALFORMED));
        }
        put_u32(
            &mut state,
            OFF_INDEX + 4 * i as usize,
            payload_at - 6 - u16_at(p, 4)? as u32,
        );
        pt::route_frontier_push(
            &mut frontier,
            i,
            pt::route_entry_hash(&routes, i).map_err(err)?,
        )
        .map_err(err)?;
    }
    for (i, slot) in frontier.iter().enumerate() {
        state[OFF_FRONTIER + 32 * i..OFF_FRONTIER + 32 * (i + 1)].copy_from_slice(slot);
    }
    put_u32(&mut state, 157, end);
    put_u32(&mut state, 161, running);
    put_u32(&mut state, OFF_INDEX + 4 * end as usize, payload_at);
    if end == t.entries_per_position {
        if running != records
            || payload_at as usize != payload.len()
            || pt::route_frontier_root(&frontier, end).map_err(err)? != routes[8..40]
        {
            return Err(err(pt::MALFORMED));
        }
        if is_v4
            && pt::route_header_v4_shallow(&routes)
                .map_err(err)?
                .2
                .is_some()
        {
            state[4] = STATE_PXR1;
            put_u32(&mut state, 157, 0);
        } else {
            state[4] = 3;
        }
    }
    Ok(())
}

fn put_route(out: &mut [u8], r: pt::InstantiatedRoute) {
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
    out[29] = 0;
    out[30..32].copy_from_slice(&r.family_ordinal.to_le_bytes());
    out[32..36].copy_from_slice(&r.range_first.to_le_bytes());
    out[36..40].copy_from_slice(&r.range_end.to_le_bytes());
}

/// Accounts: state, clause5, clause12, payload, output(w).
/// Data: tag | position:u32 | first_entry:u32 | count:u16. Output holds the
/// exact Python instantiation stream fragment for this entry interval.
pub fn instantiate(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 11 || !matches!(accounts.len(), 5 | 6) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state_account = owned(program, accounts, 0)?;
    let pt1x = {
        let raw = state_account.try_borrow_data()?;
        is_pt1x(&raw)
    };
    if cfg!(feature = "revision-8") && !pt1x {
        return Err(ProgramError::InvalidAccountData);
    }
    if pt1x {
        if !cfg!(feature = "revision-8")
            || accounts.len() != 6
            || *accounts[5].key != system_program::ID
            || state_account.is_writable
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let raw = state_account.try_borrow_data()?;
        if raw.len() < OFF_INDEX || !is_template_magic(&raw) {
            return Err(ProgramError::UninitializedAccount);
        }
    } else {
        check_state(program, accounts, 5, false)?;
    }
    bind_inputs(program, accounts)?;
    let state = accounts[0].try_borrow_data()?;
    if state[4] != 3 {
        return Err(ProgramError::InvalidAccountData);
    }
    let position = u32_at(data, 1)?;
    let start = u32_at(data, 5)?;
    let count = u16_at(data, 9)? as u32;
    if count == 0 || count > 64 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let routes = accounts[1].try_borrow_data()?;
    let geom = accounts[2].try_borrow_data()?;
    let payload = accounts[3].try_borrow_data()?;
    let (t, c) = template(&routes, &geom, is_pt1x(&state))?;
    let end = start.checked_add(count).ok_or(err(pt::MALFORMED))?;
    if position >= t.position_count || end > t.entries_per_position {
        return Err(err(pt::MALFORMED));
    }
    let output = &accounts[4];
    if pt1x
        && (!cfg!(feature = "revision-8")
            || accounts.len() != 6
            || *accounts[5].key != system_program::ID)
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !pt1x {
        owned(program, accounts, 4)?;
    }
    if !output.is_writable || accounts[..4].iter().any(|a| a.key == output.key) {
        return Err(ProgramError::InvalidAccountData);
    }
    let output_binding = if pt1x {
        let keys = [
            accounts[0].key,
            accounts[1].key,
            accounts[2].key,
            accounts[3].key,
        ];
        let binding = pt1x_output_binding(program, &keys, position, start, count);
        let fresh =
            validate_pt1x_output_binding(program, output, &accounts[5], &binding, position, start)?;
        Some((binding, fresh))
    } else {
        None
    };
    let mut stream_bytes = if start == 0 { 44usize } else { 0usize };
    for i in start..end {
        let entry = t.instantiate_with(c, i, position).map_err(err)?;
        let p_at = u32_at(&state, OFF_INDEX + 4 * i as usize)? as usize;
        let p_end = u32_at(&state, OFF_INDEX + 4 * (i + 1) as usize)? as usize;
        let row = payload.get(p_at..p_end).ok_or(err(pt::MALFORMED))?;
        if row.len() < 6 || u32_at(row, 0)? != i || 6 + u16_at(row, 4)? as usize != row.len() {
            return Err(err(pt::MALFORMED));
        }
        stream_bytes = stream_bytes
            .checked_add(14 + row.len() - 6 + 40 * entry.route_count() as usize)
            .ok_or(ProgramError::AccountDataTooSmall)?;
    }
    if let Some((_, fresh)) = output_binding {
        let keys = [
            accounts[0].key,
            accounts[1].key,
            accounts[2].key,
            accounts[3].key,
        ];
        let key_refs = keys.iter().copied().collect::<Vec<_>>();
        let payer = Pubkey::new_from_array(state[5..37].try_into().unwrap());
        prepare_pt1x_output(
            program,
            output,
            &accounts[5],
            count,
            stream_bytes,
            PT1X_OUTPUT_HEADER_BYTES
                + stream_bytes
                + PT1X_OUTPUT_TRAILER_FIXED_BYTES
                + 32 * key_refs.len(),
            &payer,
            &key_refs,
            fresh,
        )?;
    } else {
        if output.data_len() < 16 {
            return Err(ProgramError::AccountDataTooSmall);
        }
    }
    let mut out = output.try_borrow_mut_data()?;
    let mut at: usize = if pt1x { PT1X_OUTPUT_HEADER_BYTES } else { 16 };
    let mut write = |bytes: &[u8]| -> Result<(), ProgramError> {
        let end = at
            .checked_add(bytes.len())
            .ok_or(ProgramError::AccountDataTooSmall)?;
        out.get_mut(at..end)
            .ok_or(ProgramError::AccountDataTooSmall)?
            .copy_from_slice(bytes);
        at = end;
        Ok(())
    };
    if start == 0 {
        write(b"basanos/pt1-compiler-instantiation/1")?;
        write(&position.to_le_bytes())?;
        write(&t.entries_per_position.to_le_bytes())?;
    }
    for i in start..end {
        let entry = t.instantiate_with(c, i, position).map_err(err)?;
        let p_at = u32_at(&state, OFF_INDEX + 4 * i as usize)? as usize;
        let p_end = u32_at(&state, OFF_INDEX + 4 * (i + 1) as usize)? as usize;
        let row = payload.get(p_at..p_end).ok_or(err(pt::MALFORMED))?;
        if row.len() < 6 || u32_at(row, 0)? != i || 6 + u16_at(row, 4)? as usize != row.len() {
            return Err(err(pt::MALFORMED));
        }
        let p = &row[6..];
        let mut patched = vec![0u8; p.len()];
        entry.patch_payload(p, &mut patched).map_err(err)?;
        write(&i.to_le_bytes())?;
        write(&(entry.route_count() as u16).to_le_bytes())?;
        write(&entry.attention_t.unwrap_or(u32::MAX).to_le_bytes())?;
        write(&(p.len() as u32).to_le_bytes())?;
        write(&patched)?;
        for ordinal in 0..entry.route_count() {
            let route = entry.route(ordinal as u16).map_err(err)?;
            let mut wire = [0u8; 40];
            put_route(&mut wire, route);
            write(&wire)?;
        }
    }
    out[..4].copy_from_slice(OUTPUT_MAGIC);
    put_u32(&mut out, 4, position);
    put_u32(&mut out, 8, start);
    put_u32(
        &mut out,
        12,
        (at - if pt1x { PT1X_OUTPUT_HEADER_BYTES } else { 16 }) as u32,
    );
    if let Some((binding, _)) = output_binding {
        out[16..48].copy_from_slice(&binding);
    }
    Ok(())
}

/// Read-only execution-order probe: tag | position:u32 | position_count:u32 |
/// executed_position:u32. The consensus Execute path will call the same check.
pub fn check_order(data: &[u8]) -> ProgramResult {
    if data.len() != 13 {
        return Err(ProgramError::InvalidInstructionData);
    }
    pt::check_position_order(u32_at(data, 1)?, u32_at(data, 5)?, u32_at(data, 9)?).map_err(err)
}
