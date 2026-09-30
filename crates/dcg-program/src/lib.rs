// SPDX-License-Identifier: GPL-3.0-only

//! Standalone DCG framework image. Generic record, proof, lifecycle, and
//! bounded SVM adapter modules live here. Applications provide kernels through
//! a compile-time manifest; this repository includes a tiny test kernel only.

pub(crate) mod closure_v2;
pub(crate) mod closure_v2_bootstrap;
pub mod closure_v2_response;
pub mod commit;
pub mod compatibility;
pub mod desc_upload;
pub mod descriptor;
pub mod envelope_seal;
pub mod hash;
pub mod kernel;
pub mod kernels;
pub mod position_template;
pub mod pt1_onchain;
pub mod pt2p;
pub mod pt2p_onchain;
pub mod root_only;
pub mod root_only_challenge;
pub mod root_only_sealed;
pub mod seal;
pub mod unified;

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Revision-8 allowlist adapter. The test kernel is not selected by wire data,
/// and generic code has no dynamic module loading or CPI dispatch path.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match tag {
        115 => closure_v2_response::begin(program_id, accounts, data),
        116 => closure_v2_response::grow(program_id, accounts, data),
        117 => closure_v2_response::write(program_id, accounts, data),
        118 => closure_v2_response::seal(program_id, accounts, data),
        125 => closure_v2_response::write_at(program_id, accounts, data),
        // These paths need the application's compiled kernel adapter. The
        // standalone test image contains only the tiny test kernel; Basanos
        // retains its historical dispatcher for those profile-specific rows.
        120..=124 | 126..=129 => Err(ProgramError::InvalidInstructionData),
        140 => pt1_onchain::init_fresh(program_id, accounts, data),
        141 => pt1_onchain::upload(program_id, accounts, data),
        142 => pt1_onchain::seal(program_id, accounts, data),
        143 => pt2p_onchain::init(program_id, accounts, data),
        144 => pt2p_onchain::hash(program_id, accounts, data),
        145 => pt2p_onchain::seal(program_id, accounts, data),
        146 => pt2p_onchain::instantiate(program_id, accounts, data),
        193 => pt2p_onchain::seal_pxr_chunk(program_id, accounts, data),
        198 => pt1_onchain::close_pt1x_output(program_id, accounts, data),
        199 => pt2p_onchain::reserve_pt1o(program_id, accounts, data),
        200 => pt2p_onchain::close_pt1o_reservation(program_id, accounts, data),
        131 | 132 | 156..=169 | 172..=178 | 185..=187 | 197 => {
            unified::process(program_id, accounts, data)
                .unwrap_or(Err(ProgramError::InvalidInstructionData))
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
