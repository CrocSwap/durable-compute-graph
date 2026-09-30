// SPDX-License-Identifier: GPL-3.0-only

use solana_program::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program,
};

pub(crate) fn drain<'a>(from: &AccountInfo<'a>, to: &AccountInfo<'a>) -> Result<u64, ProgramError> {
    if from.key == to.key {
        return Err(ProgramError::InvalidAccountData);
    }
    let amount = from.lamports();
    **to.try_borrow_mut_lamports()? = to
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::InvalidAccountData)?;
    **from.try_borrow_mut_lamports()? = 0;
    from.try_borrow_mut_data()?.fill(0);
    from.realloc(0, false)?;
    from.assign(&system_program::id());
    Ok(amount)
}

pub(crate) fn system_id() -> Pubkey {
    system_program::id()
}
