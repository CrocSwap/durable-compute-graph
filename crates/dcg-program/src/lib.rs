// SPDX-License-Identifier: GPL-3.0-only

//! Standalone DCG framework image. Generic record, proof, lifecycle, and
//! bounded SVM adapter modules live here. Applications provide kernels through
//! a compile-time manifest; this repository includes a tiny test kernel only.

pub mod account_provenance;
/// Static application instruction registration and dispatch seam.
pub mod app_api;
#[cfg(feature = "sbf-real-lifecycle-test")]
pub mod closure_v2;
#[cfg(not(feature = "sbf-real-lifecycle-test"))]
pub mod closure_v2;
pub(crate) mod closure_v2_accounts;
#[cfg(feature = "legacy-hclosure-handlers")]
pub(crate) mod closure_v2_bootstrap;
/// Shared revision-8 dispute verifier used by the statically selected app
/// manifest. Application form execution remains behind the app API hooks.
pub mod closure_v2_generic;
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
pub mod region_commitment;
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
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if matches!(tag, 120..=124 | 126..=129) {
        return closure_v2_generic::process_generic_dispute_tag(
            program_id,
            accounts,
            data,
            application_program_manifest(),
        );
    }
    process_instruction_with_manifest(
        program_id,
        accounts,
        data,
        application_program_manifest().application_manifest(),
    )
}

#[cfg(feature = "test-kernel")]
fn application_program_manifest() -> &'static app_api::ApplicationProgramManifest {
    static NO_INSTRUCTIONS: [app_api::ApplicationInstruction; 0] = [];
    static TEST_APPLICATION: app_api::ApplicationProgramManifest =
        app_api::ApplicationProgramManifest::new_with_dispute_hooks(
            &kernel::test_kernel::MANIFEST_APP,
            &NO_INSTRUCTIONS,
            &kernel::test_kernel::DISPUTE_HOOKS,
            &kernel::test_kernel::DISPUTE_HOOKS,
        );
    &TEST_APPLICATION
}

#[cfg(not(feature = "test-kernel"))]
fn application_program_manifest() -> &'static app_api::ApplicationProgramManifest {
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
    static EMPTY_PROGRAM: app_api::ApplicationProgramManifest =
        app_api::ApplicationProgramManifest::new(&EMPTY_APPLICATION, &[]);
    &EMPTY_PROGRAM
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
    if (230..=239).contains(&tag) || tag == stateful::v3::RESOURCE_CHUNK_TAG {
        return stateful_test::process(program_id, accounts, data);
    }
    match tag {
        115 => closure_v2_response::begin(program_id, accounts, data),
        116 => closure_v2_response::grow(program_id, accounts, data),
        117 => closure_v2_response::write(program_id, accounts, data),
        118 => closure_v2_response::seal(program_id, accounts, data),
        125 => closure_v2_response::write_at(program_id, accounts, data),
        120..=124 | 126..=129 => {
            let application = app_api::ApplicationProgramManifest::new(manifest, &[]);
            closure_v2_generic::process_generic_dispute_tag(
                program_id,
                accounts,
                data,
                &application,
            )
        }
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
        131 | 132 | 156..=169 | 172..=178 | 183..=187 | 197 => {
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

#[cfg(test)]
mod application_manifest_tests {
    #[test]
    fn compiled_application_manifest_is_valid() {
        assert_eq!(super::application_manifest().validate(), Ok(()));
    }

    #[cfg(feature = "revision-8")]
    #[test]
    fn revision8_tag_182_matches_basanos_unsupported_tag_result() {
        assert_eq!(
            super::process_instruction(&solana_program::pubkey::Pubkey::new_unique(), &[], &[182]),
            Err(solana_program::program_error::ProgramError::InvalidInstructionData)
        );
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// Upward bump allocator over the SBF heap region, capped at the largest heap
/// frame a transaction may request (256 KiB). The SDK default grows downward
/// from a fixed 32 KiB top, so a larger declared length would fault every
/// transaction that keeps the default frame. Growing upward, allocations that
/// fit in 32 KiB behave as before under any frame; only a transaction whose
/// allocations pass 32 KiB must request a larger frame (the generic dispute
/// executor requests 256 KiB), and otherwise faults at the frame edge. The
/// runtime zeroes the heap per transaction, so the cursor word starts at 0.
/// Memory is never freed, as with the SDK allocator.
#[cfg(all(target_os = "solana", feature = "custom-heap", not(feature = "no-entrypoint")))]
mod upward_heap {
    use core::alloc::{GlobalAlloc, Layout};

    const START: usize = solana_program::entrypoint::HEAP_START_ADDRESS as usize;
    const LENGTH: usize = 256 * 1024;

    struct UpwardBump;

    unsafe impl GlobalAlloc for UpwardBump {
        #[inline]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let cursor = START as *mut usize;
            let first = START + core::mem::size_of::<usize>();
            let at = if *cursor == 0 { first } else { *cursor };
            let Some(aligned) = at.checked_add(layout.align() - 1).map(|v| v & !(layout.align() - 1))
            else { return core::ptr::null_mut() };
            match aligned.checked_add(layout.size()) {
                Some(end) if end <= START + LENGTH => {
                    *cursor = end;
                    aligned as *mut u8
                }
                _ => core::ptr::null_mut(),
            }
        }
        #[inline]
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: UpwardBump = UpwardBump;
}

