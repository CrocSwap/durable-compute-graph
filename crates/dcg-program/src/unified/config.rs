// SPDX-License-Identifier: GPL-3.0-only

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

const CL_AUTHORITY: u32 = 582;
const CL_MALFORMED: u32 = 580;
const PLAN_BINDING: u32 = 785;

/// Tag 197 closes an unpublished PT1X base and refunds its recorded authority.
pub fn close_unpublished_template(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data != [197] {
        return Err(ProgramError::Custom(CL_MALFORMED));
    }
    let [authority, pt1x, routes, geometry, payloads] = accounts else {
        return Err(ProgramError::Custom(CL_MALFORMED));
    };
    if !authority.is_signer || !authority.is_writable {
        return Err(ProgramError::Custom(CL_AUTHORITY));
    }
    let (keys, lengths) = {
        let state = pt1x.try_borrow_data()?;
        if pt1x.owner != program
            || state.get(..4) != Some(b"PT1X")
            || state.len() < 5289
            || !(1..=5).contains(&state[4])
            || state[5..37] != authority.key.to_bytes()
            || state[1189..1221] != [0; 32]
        {
            return Err(ProgramError::Custom(CL_AUTHORITY));
        }
        (state[37..133].to_vec(), state[133..145].to_vec())
    };
    let bound = [routes, geometry, payloads];
    for index in 0..3 {
        if bound[index].owner != program
            || bound[index].key.as_ref() != &keys[index * 32..(index + 1) * 32]
            || bound[index].data_len()
                != u32::from_le_bytes(lengths[4 * index..4 * index + 4].try_into().unwrap())
                    as usize
            || !bound[index].is_writable
            || bound[index].key == authority.key
        {
            return Err(ProgramError::Custom(PLAN_BINDING));
        }
    }
    if !pt1x.is_writable || pt1x.key == authority.key {
        return Err(ProgramError::Custom(CL_MALFORMED));
    }
    for account in [pt1x, routes, geometry, payloads] {
        super::result::drain(account, authority)?;
    }
    Ok(())
}
