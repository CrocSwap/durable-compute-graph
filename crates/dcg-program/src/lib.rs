// SPDX-License-Identifier: GPL-3.0-only

//! Standalone DCG framework image. Generic record, proof, lifecycle, and
//! bounded SVM adapter modules live here. Applications provide kernels through
//! a compile-time manifest; this repository includes a tiny test kernel only.

#[cfg(feature = "sbf-real-lifecycle-test")]
pub mod closure_v2;
#[cfg(not(feature = "sbf-real-lifecycle-test"))]
pub(crate) mod closure_v2;
pub(crate) mod closure_v2_accounts;
#[cfg(feature = "legacy-hclosure-handlers")]
pub(crate) mod closure_v2_bootstrap;
pub mod closure_v2_response;
pub(crate) mod closure_v2_tree;
pub mod commit;
pub mod compatibility;
pub mod desc_upload;
pub mod descriptor;
pub mod envelope_seal;
pub mod hash;
pub mod kernel;
pub mod kernel_svm;
pub mod kernels;
pub mod position_template;
pub mod pt1_onchain;
pub mod pt2p;
pub mod pt2p_onchain;
pub mod root_only;
pub mod root_only_challenge;
pub mod root_only_sealed;
pub mod seal;
pub mod stateful;
#[cfg(feature = "sbf-real-lifecycle-test")]
pub mod stateful_test;
#[cfg(feature = "sbf-lifecycle-test")]
pub mod test_lifecycle;
pub mod unified;

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Revision-8 allowlist adapter using the application's statically compiled
/// manifest. Production app crates can call `process_instruction_with_manifest`
/// from their own entrypoint to select their compiled manifest.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    process_instruction_with_manifest(program_id, accounts, data, application_manifest())
}

/// Dispatch the frozen handler surface with one application-supplied static
/// manifest. This does not load code dynamically or change instruction bytes.
pub fn process_instruction_with_manifest(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static kernel::ApplicationManifest,
) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    #[cfg(feature = "sbf-lifecycle-test")]
    if (240..=250).contains(&tag) {
        return test_lifecycle::process(program_id, accounts, data);
    }
    #[cfg(feature = "sbf-real-lifecycle-test")]
    if (230..=239).contains(&tag) {
        return stateful_test::process(program_id, accounts, data);
    }
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
        146 => pt2p_onchain::instantiate_with_selector(
            program_id,
            accounts,
            data,
            manifest.decision_routes,
        ),
        193 => pt2p_onchain::seal_pxr_chunk(program_id, accounts, data),
        198 => pt1_onchain::close_pt1x_output(program_id, accounts, data),
        199 => pt2p_onchain::reserve_pt1o_with_selector(
            program_id,
            accounts,
            data,
            manifest.decision_routes,
        ),
        200 => pt2p_onchain::close_pt1o_reservation_with_selector(
            program_id,
            accounts,
            data,
            manifest.decision_routes,
        ),
        131 | 132 | 156..=169 | 172..=178 | 185..=187 | 197 => {
            unified::process_with_manifest(program_id, accounts, data, manifest)
                .unwrap_or(Err(ProgramError::InvalidInstructionData))
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(feature = "test-kernel")]
fn application_manifest() -> &'static kernel::ApplicationManifest {
    &kernel::test_kernel::MANIFEST_APP
}

#[cfg(not(feature = "test-kernel"))]
fn application_manifest() -> &'static kernel::ApplicationManifest {
    static EMPTY_KERNELS: [&'static dyn kernel::Kernel; 0] = [];
    static EMPTY_REPLAYS: [kernel::OptimisticReplayBinding; 0] = [];
    static EMPTY_FORMS: [kernel::LegacyFormBinding; 0] = [];
    static EMPTY_APPLICATION: kernel::ApplicationManifest = kernel::ApplicationManifest {
        application_id: b"dcg/empty-application/1",
        version: 1,
        kernels: &EMPTY_KERNELS,
        optimistic_replays: &EMPTY_REPLAYS,
        legacy_forms: &EMPTY_FORMS,
        require_legacy_form_binding: false,
        hooks: &compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &compatibility::REVISION8_COMPATIBILITY,
    };
    &EMPTY_APPLICATION
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
