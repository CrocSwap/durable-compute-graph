// SPDX-License-Identifier: GPL-3.0-only

//! Revision-8 PT1X initialization and the binding-derived PT1O address.
//!
//! This extraction slice keeps setup record mechanics and omits plan execution,
//! model registration, and output production.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction, system_program,
};

const OFF_FRONTIER: usize = 165;
const OFF_BITMAP: usize = OFF_FRONTIER + 32 * 32;
const OFF_INDEX: usize = OFF_BITMAP + 4096;
pub const PT1X_MAX_STATE_BYTES: usize = OFF_INDEX + 4 * (28_041 + 1);
pub const PT1X_BOUND_PT2S_AT: usize = OFF_BITMAP;
pub const TAG_CLOSE_PT1O: u8 = 198;
pub const TAG_INIT_PT1X: u8 = 140;
pub const TAG_CLOSE_UNPUBLISHED_TEMPLATE: u8 = 197;
pub const PT1X_MAGIC: &[u8; 4] = b"PT1X";

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Tag 140: assign three fresh, signed system allocations to the program and
/// write their exact keys and lengths into a fresh PT1X state account.
pub fn init_fresh(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data != [TAG_INIT_PT1X] || accounts.len() != 6 {
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
    if byte_accounts.iter().any(|account| !account.is_signer) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if byte_accounts.iter().any(|account| {
        !account.is_writable || account.owner != &system_program::ID || account.data_len() == 0
    }) || state.key == authority.key
        || byte_accounts
            .iter()
            .any(|account| account.key == state.key || account.key == authority.key)
        || byte_accounts[0].key == byte_accounts[1].key
        || byte_accounts[0].key == byte_accounts[2].key
        || byte_accounts[1].key == byte_accounts[2].key
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut lengths = [0u32; 3];
    for (index, account) in byte_accounts.iter().enumerate() {
        lengths[index] = u32::try_from(account.data_len()).map_err(|_| err(580))?;
    }
    {
        let current = state.try_borrow_data()?;
        if current.len() < OFF_INDEX + 4 || current.len() > PT1X_MAX_STATE_BYTES {
            return Err(ProgramError::InvalidAccountData);
        }
        if current.iter().any(|byte| *byte != 0) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }

    for account in byte_accounts {
        invoke(
            &system_instruction::assign(account.key, program),
            &[account.clone(), system.clone()],
        )?;
    }

    let mut data = state.try_borrow_mut_data()?;
    data[..4].copy_from_slice(PT1X_MAGIC);
    data[4] = 1;
    data[5..37].copy_from_slice(authority.key.as_ref());
    for (kind, account) in byte_accounts.iter().enumerate() {
        data[37 + kind * 32..69 + kind * 32].copy_from_slice(account.key.as_ref());
        put_u32(&mut data, 133 + kind * 4, lengths[kind]);
    }
    Ok(())
}

pub fn pt1x_output_address(program: &Pubkey, binding: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[binding], program)
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
