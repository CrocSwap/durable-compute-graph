//! Unified document format v1 (ESL2), `docs/spec/dcg-unified-v1.md`
//! revision 3: a sealed PT2P plan (PT2S) admitted class by class against a
//! frozen DRP2 registry (DEA2), a ROOT_ONLY document that lands only position
//! roots (DCM2 v5, DPR2, DFS2), the version-3 incremental document
//! commitment, per-run dispute terms (DDT1) and a DCR1 v5 challenge path with
//! convict at every fix-point.
//!
//! The Python mirror `src/basanos/dcg/unified_v1.py` and the golden
//! `tests/golden/dcg/unified_v1.json` define every encoding byte for byte;
//! the tests in this module reproduce them.
//!
//! Revision 4 (the builder interface): the trusted roles in a config account
//! (`config`), the DRB1 run binding in the descriptor and header, the DCR2 v4
//! result record with proven outputs, derived challenge-record addresses,
//! DLE1 events, CloseDocumentV5 and one ruling procedure.
//!
//! Revision 7 also links the RS1 summary respond (tags 170/171/179-181,
//! `crate::rs1_summary`, revision 5). The revision-8 image omits that module
//! and refuses its legacy instruction tags and DCR1 v5 accounts. The
//! STORED_PAGES counter changes of revision 4 §7.9 (N6) await the user.

pub mod address;
pub mod admission;
pub mod bond;
pub mod challenge;
pub mod classes;
pub mod config;
pub mod document;
pub mod events;
pub mod plan;
pub mod registry;
pub mod result;
pub mod rsp1;
pub mod terms;

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Envelope epoch of the re-key image (ESL1 epochs 1-3 are `envelope_seal`).
pub const EPOCH: u32 = 4;

pub const TAG_REGISTRY_CREATE: u8 = 156;
pub const TAG_REGISTRY_WRITE: u8 = 157;
pub const TAG_REGISTRY_FREEZE: u8 = 158;
pub const TAG_ADMISSION_BEGIN: u8 = 159;
pub const TAG_ADMISSION_STEP: u8 = 160;
pub const TAG_UNIFIED_INIT: u8 = 161;
pub const TAG_LAND_POSITION_ROOTS: u8 = 162;
pub const TAG_REVEAL_POSITION: u8 = 163;
pub const TAG_SELECT_SEGMENT: u8 = 164;
pub const TAG_FINALIZE_DOCUMENT: u8 = 165;
pub const TAG_CHALLENGE_LEAF: u8 = 166;
pub const TAG_CHALLENGE_POSITION: u8 = 167;
pub const TAG_REVEAL: u8 = 168;
pub const TAG_DESCEND: u8 = 169;
/// Reserved for the RS1 summary disputes (spec §8.3); not dispatched here.
#[cfg(feature = "revision-7")]
pub use crate::rs1_summary::{TAG_CHALLENGE_SUMMARY, TAG_SUMMARY_LEAF_CHALLENGE};
/// CloseDocumentV5 (revision 4, spec §6.12).
pub const TAG_CLOSE_DOCUMENT: u8 = 172;
pub const TAG_REVEAL_FAMILY_TABLE: u8 = 173;
/// CloseResponseV5 (revision 6, spec §7.4): drain a ruled record's DRU1 to
/// the executor.
pub const TAG_CLOSE_RESPONSE: u8 = 182;
pub const TAG_CLOSE_RESULT: u8 = 185;
/// `CloseTemplateV5` (revision 8, spec §1.7): one instruction closes a template.
pub const TAG_CLOSE_TEMPLATE: u8 = 186;
pub const TAG_CLOSE_UNPUBLISHED_TEMPLATE: u8 = config::TAG_CLOSE_UNPUBLISHED_TEMPLATE;
/// `RetryBondSettlementV5` (revision 8, spec §1.4): the only caller of the
/// cause-4 route and the only exit from a bond escrow.
pub const TAG_RETRY_BOND_SETTLEMENT: u8 = 187;
pub use config::{
    CONFIG_AUTHORITY, TAG_CONFIG_INIT, TAG_CONFIG_SET, TAG_TEMPLATE_SEAL, TEMPLATE_SEAL,
};
pub use document::RUN_BINDING;
pub use result::{OUTPUT_PROOF, RESULT_STATE, TAG_ATTEST_OUTPUT, TAG_RESOLVE_RESULT};

// ESL1 codes 770-784 keep their meaning (`envelope_seal`); 785-791 are new.
pub use crate::envelope_seal::{
    ADMISSION_STATE, FORM_ABSENT, OVER_CU, REGISTRY_ACCOUNT, REGISTRY_AUTHORITY, REGISTRY_EPOCH,
    REGISTRY_ROOT, REGISTRY_STATE, RESPOND_LIMIT, ROW_CAPABILITY, ROW_MALFORMED, SHAPE_BOUND,
    WITHDRAW_ONLY,
};
pub const PLAN_BINDING: u32 = 785;
pub const WITNESS_DOMAIN: u32 = 786;
pub const RANGE_BOUND: u32 = 787;
pub const APPEND_ORDER: u32 = 788;
pub const REVEAL_MISMATCH: u32 = 789;
pub const REVEAL_ORDER: u32 = 790;
pub const DISPUTE_TERMS: u32 = 791;
pub const SETTLEMENT_PROGRAM: u32 = 798;

// Closure / SM1 codes reused by the spec (§9).
pub const CL_MALFORMED: u32 = 580;
pub const CL_COORDINATE: u32 = 581;
pub const CL_AUTHORITY: u32 = 582;
pub const CL_ROOT: u32 = 583;
pub const CL_PATH: u32 = 586;
pub const CL_MISSING: u32 = 591;
pub const CL_AFTER_FINAL: u32 = 592;
pub const CL_OVERFLOW: u32 = 598;
// DCR1 record codes (reused).
pub const DCR1_BAD: u32 = 730;
pub const DCR1_AUTH: u32 = 731;
pub const DCR1_PHASE: u32 = 733;
pub const DCR1_PROOF: u32 = 734;
pub const DCR1_DEADLINE: u32 = 736;
pub const DCR1_INCOMPLETE: u32 = 741;
/// Application-manifest lookup failed for a selected legacy form.
pub const APP_KERNEL_UNAVAILABLE: u32 = 799;
/// An app kernel replay rejected the committed output at a fix-point.
pub const APP_KERNEL_MISMATCH: u32 = 800;

/// Codes that, returned by the per-instance check at a fix-point, convict.
pub const CONVICT_CODES: [u32; 10] = [
    FORM_ABSENT,
    WITHDRAW_ONLY,
    OVER_CU,
    SHAPE_BOUND,
    RESPOND_LIMIT,
    WITNESS_DOMAIN,
    RANGE_BOUND,
    crate::kernels::decision::ERR_OPTION_RANGE,
    APP_KERNEL_UNAVAILABLE,
    APP_KERNEL_MISMATCH,
];

pub(crate) fn no(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn application_hooks(
    manifest: Option<&'static crate::kernel::ApplicationManifest>,
) -> &'static dyn crate::compatibility::ApplicationHooks {
    manifest
        .map(|app| app.hooks)
        .unwrap_or(&crate::compatibility::REVISION8_COMPATIBILITY)
}

pub(crate) fn u16_at(b: &[u8], at: usize, code: u32) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(no(code))?
            .try_into()
            .map_err(|_| no(code))?,
    ))
}
pub(crate) fn u32_at(b: &[u8], at: usize, code: u32) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(no(code))?
            .try_into()
            .map_err(|_| no(code))?,
    ))
}
pub(crate) fn u64_at(b: &[u8], at: usize, code: u32) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or(no(code))?
            .try_into()
            .map_err(|_| no(code))?,
    ))
}
pub(crate) fn d32(b: &[u8], at: usize, code: u32) -> Result<[u8; 32], ProgramError> {
    b.get(at..at + 32)
        .ok_or(no(code))?
        .try_into()
        .map_err(|_| no(code))
}

/// Tags 156-169, 172-178, 182, 185-187, plus the v5 branches of tags
/// 131/132 (settle, timeout). `None` leaves the instruction to the rest of the
/// program. Tag 186 is the revision-8 template close.
#[cfg(feature = "revision-7")]
pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Option<ProgramResult> {
    process_inner(program, accounts, data, None)
}

/// Revision-8 application-dispatch entry. The supplied manifest is compiled
/// into the caller's image; only the tag-169 fix-point path consumes it.
pub fn process_with_manifest(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static crate::kernel::ApplicationManifest,
) -> Option<ProgramResult> {
    process_inner(program, accounts, data, Some(manifest))
}

#[cfg(feature = "revision-7")]
fn process_inner(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: Option<&'static crate::kernel::ApplicationManifest>,
) -> Option<ProgramResult> {
    Some(match data.first().copied()? {
        TAG_REGISTRY_CREATE => registry::create(program, accounts, data),
        TAG_REGISTRY_WRITE => registry::write(program, accounts, data),
        TAG_REGISTRY_FREEZE => registry::freeze(program, accounts, data),
        TAG_ADMISSION_BEGIN => admission::begin(program, accounts, data),
        TAG_ADMISSION_STEP => admission::step_with_manifest(program, accounts, data, manifest),
        TAG_UNIFIED_INIT => {
            document::init_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_LAND_POSITION_ROOTS => document::land_position_roots_with_hooks(
            program,
            accounts,
            data,
            application_hooks(manifest),
        ),
        TAG_FINALIZE_DOCUMENT => {
            document::finalize_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_REVEAL_POSITION => {
            challenge::reveal_position_with_manifest(program, accounts, data, manifest)
        }
        TAG_SELECT_SEGMENT => {
            challenge::select_segment_with_manifest(program, accounts, data, manifest)
        }
        TAG_CHALLENGE_LEAF => {
            challenge::challenge_leaf_with_manifest(program, accounts, data, manifest)
        }
        TAG_CHALLENGE_POSITION => {
            challenge::challenge_position_with_manifest(program, accounts, data, manifest)
        }
        TAG_REVEAL => challenge::reveal_with_manifest(program, accounts, data, manifest),
        TAG_DESCEND => challenge::descend_with_manifest(program, accounts, data, manifest),
        TAG_REVEAL_FAMILY_TABLE => challenge::reveal_family_table(program, accounts, data),
        TAG_CLOSE_RESPONSE => challenge::close_response(program, accounts, data),
        TAG_CLOSE_RESULT => {
            result::close_result_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_RETRY_BOND_SETTLEMENT => {
            bond::retry_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        crate::root_only_challenge::TAG_SETTLE if challenge::is_v5_record(accounts) => {
            challenge::settle_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        crate::root_only_challenge::TAG_TIMEOUT if challenge::is_v5_record(accounts) => {
            challenge::timeout_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_CLOSE_DOCUMENT => {
            result::close_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_CONFIG_INIT => config::init(program, accounts, data),
        TAG_CONFIG_SET => config::set_authority(program, accounts, data),
        TAG_TEMPLATE_SEAL => {
            config::template_seal_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_ATTEST_OUTPUT => {
            result::attest_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_RESOLVE_RESULT => {
            result::resolve_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        _ => return None,
    })
}

/// The revision-8 dispatch table has no revision-7 handler path. It recognizes
/// a revision-7 DCR1 only to refuse it at tags 131/132; the same numbers remain
/// available to the distinct root-only challenge module for its own records.
#[cfg(feature = "revision-8")]
pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Option<ProgramResult> {
    process_inner(program, accounts, data, None)
}

#[cfg(feature = "revision-8")]
fn process_inner(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: Option<&'static crate::kernel::ApplicationManifest>,
) -> Option<ProgramResult> {
    let tag = data.first().copied()?;
    if matches!(
        tag,
        crate::root_only_challenge::TAG_SETTLE | crate::root_only_challenge::TAG_TIMEOUT
    ) {
        if challenge::is_revision7_record(accounts) {
            return Some(Err(no(DCR1_BAD)));
        }
        if challenge::is_revision8_record(accounts) {
            return Some(if tag == crate::root_only_challenge::TAG_SETTLE {
                challenge::settle_with_hooks(program, accounts, data, application_hooks(manifest))
            } else {
                challenge::timeout_with_hooks(program, accounts, data, application_hooks(manifest))
            });
        }
    }
    Some(match tag {
        TAG_REGISTRY_CREATE => registry::create(program, accounts, data),
        TAG_REGISTRY_WRITE => registry::write(program, accounts, data),
        TAG_REGISTRY_FREEZE => registry::freeze(program, accounts, data),
        TAG_ADMISSION_BEGIN => admission::begin(program, accounts, data),
        TAG_ADMISSION_STEP => admission::step_with_manifest(program, accounts, data, manifest),
        TAG_UNIFIED_INIT => {
            document::init_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_LAND_POSITION_ROOTS => document::land_position_roots_with_hooks(
            program,
            accounts,
            data,
            application_hooks(manifest),
        ),
        TAG_FINALIZE_DOCUMENT => {
            document::finalize_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_REVEAL_POSITION => {
            challenge::reveal_position_with_manifest(program, accounts, data, manifest)
        }
        TAG_SELECT_SEGMENT => {
            challenge::select_segment_with_manifest(program, accounts, data, manifest)
        }
        TAG_CHALLENGE_LEAF => {
            challenge::challenge_leaf_with_manifest(program, accounts, data, manifest)
        }
        TAG_CHALLENGE_POSITION => {
            challenge::challenge_position_with_manifest(program, accounts, data, manifest)
        }
        TAG_REVEAL => challenge::reveal_with_manifest(program, accounts, data, manifest),
        TAG_DESCEND => challenge::descend_with_manifest(program, accounts, data, manifest),
        TAG_REVEAL_FAMILY_TABLE => challenge::reveal_family_table(program, accounts, data),
        // CloseResponseV5 is a revision-7-only path. Claim its tag so it cannot
        // fall through to the legacy root-only dispatcher, but do not link the
        // revision-7 reader into the revision-8 image.
        TAG_CLOSE_RESPONSE => Err(no(DCR1_BAD)),
        TAG_CLOSE_RESULT => {
            result::close_result_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_RETRY_BOND_SETTLEMENT => {
            bond::retry_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_CLOSE_DOCUMENT => {
            result::close_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_CLOSE_TEMPLATE => config::close_template(program, accounts, data),
        TAG_CLOSE_UNPUBLISHED_TEMPLATE => {
            config::close_unpublished_template(program, accounts, data)
        }
        TAG_CONFIG_INIT => config::init(program, accounts, data),
        TAG_CONFIG_SET => config::set_authority(program, accounts, data),
        TAG_TEMPLATE_SEAL => {
            config::template_seal_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_ATTEST_OUTPUT => {
            result::attest_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        TAG_RESOLVE_RESULT => {
            result::resolve_with_hooks(program, accounts, data, application_hooks(manifest))
        }
        _ => return None,
    })
}
