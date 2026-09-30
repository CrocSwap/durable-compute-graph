// SPDX-License-Identifier: GPL-3.0-only

//! Standalone DCG core test image.
//!
//! This source cut currently exposes portable commitment folding and the PT1X
//! create/unpublished-close lifecycle exercised by the retained property
//! harness. It is not the full Basanos revision-8 program image.

pub mod commit;
pub mod descriptor;
pub mod hash;
pub mod pt1_onchain;
pub mod unified;

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first().copied() {
        Some(140) => pt1_onchain::init_fresh(program_id, accounts, data),
        Some(197) => unified::config::close_unpublished_template(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
