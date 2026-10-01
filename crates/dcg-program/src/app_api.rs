//! Static application instruction registration around the DCG core
//! dispatcher.
//!
//! Applications provide a sorted, compile-time table. DCG-owned revision-8
//! tags always go through [`crate::process_instruction_with_manifest`] first;
//! an application entry cannot shadow them. The application identity is
//! committed separately by [`ApplicationProgramManifest::identity_digest`].
//!
//! ```compile_fail
//! // Duplicate application tags are rejected during const evaluation.
//! const _: () = dcg_program::app_api::validate_application_tags(&[42, 42]);
//! ```
//!
//! ```compile_fail
//! // Tag 125 belongs to DCG's revision-8 core dispatcher.
//! const _: () = dcg_program::app_api::validate_application_tags(&[125]);
//! ```
//!
//! ```compile_fail,E0080
//! use dcg_program::{
//!     app_api::{ApplicationAccountRule, ApplicationInstruction, ApplicationProgramManifest},
//!     compatibility::REVISION8_COMPATIBILITY,
//!     kernel::{ApplicationManifest, LegacyFormBinding, OptimisticReplayBinding},
//! };
//! static KERNELS: [&'static dyn dcg_program::kernel::Kernel; 0] = [];
//! static REPLAYS: [OptimisticReplayBinding; 0] = [];
//! static FORMS: [LegacyFormBinding; 0] = [];
//! static APP: ApplicationManifest = ApplicationManifest {
//!     application_id: b"compile-fail-app", version: 1, kernels: &KERNELS,
//!     optimistic_replays: &REPLAYS, legacy_forms: &FORMS,
//!     require_legacy_form_binding: false, hooks: &REVISION8_COMPATIBILITY,
//!     decision_routes: &REVISION8_COMPATIBILITY,
//! };
//! fn preflight(_: dcg_program::app_api::ApplicationAccountCheckContext<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! fn handler(_: dcg_program::app_api::ApplicationInstructionContext<'_>,
//!     _: &dcg_program::app_api::CheckedApplicationAccounts<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! static RULES: [ApplicationAccountRule; 0] = [];
//! static INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
//!     125, "illegal/core-shadow", 1, &RULES, preflight, handler)];
//! static INVALID: ApplicationProgramManifest = ApplicationProgramManifest::new(&APP, &INSTRUCTIONS);
//! ```
//!
//! ```compile_fail,E0080
//! use dcg_program::{
//!     account_provenance::{AccountKind, RoleFlags},
//!     app_api::{ApplicationAccountIdentity, ApplicationAccountRule, ApplicationInstruction,
//!         ApplicationProgramManifest, ApplicationSeed},
//!     compatibility::REVISION8_COMPATIBILITY,
//!     kernel::{ApplicationManifest, LegacyFormBinding, OptimisticReplayBinding},
//! };
//! static KERNELS: [&'static dyn dcg_program::kernel::Kernel; 0] = [];
//! static REPLAYS: [OptimisticReplayBinding; 0] = [];
//! static FORMS: [LegacyFormBinding; 0] = [];
//! static APP: ApplicationManifest = ApplicationManifest {
//!     application_id: b"compile-fail-app", version: 1, kernels: &KERNELS,
//!     optimistic_replays: &REPLAYS, legacy_forms: &FORMS,
//!     require_legacy_form_binding: false, hooks: &REVISION8_COMPATIBILITY,
//!     decision_routes: &REVISION8_COMPATIBILITY,
//! };
//! fn preflight(_: dcg_program::app_api::ApplicationAccountCheckContext<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! fn handler(_: dcg_program::app_api::ApplicationInstructionContext<'_>,
//!     _: &dcg_program::app_api::CheckedApplicationAccounts<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! static SEEDS: [ApplicationSeed; 1] = [ApplicationSeed::Literal(b"missing-app-id")];
//! static RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
//!     0, ApplicationAccountIdentity::ProgramPda {
//!         seeds: &SEEDS, kind: AccountKind::exact(b"APP1", 4),
//!     }, RoleFlags { writable: false, signer: false })];
//! static INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
//!     42, "example/missing-prefix", 1, &RULES, preflight, handler)];
//! static INVALID: ApplicationProgramManifest = ApplicationProgramManifest::new(&APP, &INSTRUCTIONS);
//! ```
//!
//! ```compile_fail,E0080
//! use dcg_program::{
//!     account_provenance::{AccountKind, RoleFlags},
//!     app_api::{ApplicationAccountIdentity, ApplicationAccountRule, ApplicationInstruction,
//!         ApplicationKeySource, ApplicationProgramManifest},
//!     compatibility::REVISION8_COMPATIBILITY,
//!     kernel::{ApplicationManifest, LegacyFormBinding, OptimisticReplayBinding},
//! };
//! static KERNELS: [&'static dyn dcg_program::kernel::Kernel; 0] = [];
//! static REPLAYS: [OptimisticReplayBinding; 0] = [];
//! static FORMS: [LegacyFormBinding; 0] = [];
//! static APP: ApplicationManifest = ApplicationManifest {
//!     application_id: b"compile-fail-app", version: 1, kernels: &KERNELS,
//!     optimistic_replays: &REPLAYS, legacy_forms: &FORMS,
//!     require_legacy_form_binding: false, hooks: &REVISION8_COMPATIBILITY,
//!     decision_routes: &REVISION8_COMPATIBILITY,
//! };
//! fn preflight(_: dcg_program::app_api::ApplicationAccountCheckContext<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! fn handler(_: dcg_program::app_api::ApplicationInstructionContext<'_>,
//!     _: &dcg_program::app_api::CheckedApplicationAccounts<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! static RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
//!     0, ApplicationAccountIdentity::ProgramKey {
//!         source: ApplicationKeySource::InstructionData { offset: 1 },
//!         kind: AccountKind::exact(b"APP1", 4),
//!     }, RoleFlags { writable: false, signer: false })];
//! static INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
//!     42, "example/instruction-key", 1, &RULES, preflight, handler)];
//! static INVALID: ApplicationProgramManifest = ApplicationProgramManifest::new(&APP, &INSTRUCTIONS);
//! ```
//!
//! ```compile_fail,E0080
//! use dcg_program::{
//!     account_provenance::{AccountKind, RoleFlags},
//!     app_api::{ApplicationAccountIdentity, ApplicationAccountRule, ApplicationInstruction,
//!         ApplicationProgramManifest, ApplicationSeed},
//!     compatibility::REVISION8_COMPATIBILITY,
//!     kernel::{ApplicationManifest, LegacyFormBinding, OptimisticReplayBinding},
//! };
//! static KERNELS: [&'static dyn dcg_program::kernel::Kernel; 0] = [];
//! static REPLAYS: [OptimisticReplayBinding; 0] = [];
//! static FORMS: [LegacyFormBinding; 0] = [];
//! static APP: ApplicationManifest = ApplicationManifest {
//!     application_id: b"compile-fail-app", version: 1, kernels: &KERNELS,
//!     optimistic_replays: &REPLAYS, legacy_forms: &FORMS,
//!     require_legacy_form_binding: false, hooks: &REVISION8_COMPATIBILITY,
//!     decision_routes: &REVISION8_COMPATIBILITY,
//! };
//! fn preflight(_: dcg_program::app_api::ApplicationAccountCheckContext<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! fn handler(_: dcg_program::app_api::ApplicationInstructionContext<'_>,
//!     _: &dcg_program::app_api::CheckedApplicationAccounts<'_, '_>) -> solana_program::entrypoint::ProgramResult { Ok(()) }
//! static SEEDS: [ApplicationSeed; 1] = [ApplicationSeed::ApplicationId];
//! static RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
//!     0, ApplicationAccountIdentity::ProgramPda {
//!         seeds: &SEEDS, kind: AccountKind::exact(b"DCR1", 4),
//!     }, RoleFlags { writable: false, signer: false })];
//! static INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
//!     42, "example/core-magic", 1, &RULES, preflight, handler)];
//! static INVALID: ApplicationProgramManifest = ApplicationProgramManifest::new(&APP, &INSTRUCTIONS);
//! static EMPTY_MAGIC_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
//!     0, ApplicationAccountIdentity::ProgramPda {
//!         seeds: &SEEDS, kind: AccountKind::exact(b"", 4),
//!     }, RoleFlags { writable: false, signer: false })];
//! static EMPTY_MAGIC_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
//!     43, "example/empty-magic", 1, &EMPTY_MAGIC_RULES, preflight, handler)];
//! static INVALID_EMPTY_MAGIC: ApplicationProgramManifest = ApplicationProgramManifest::new(&APP, &EMPTY_MAGIC_INSTRUCTIONS);
//! ```

use crate::{
    account_provenance::{
        expect_derived, expect_derived_with_bump, expect_keyed, expect_system_derived_role,
        AccountKind, RoleFlags,
    },
    hash::sha256,
    kernel::ApplicationManifest,
    process_instruction_with_manifest,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Tags dispatched by DCG's selected revision-8 core.
///
/// The application dispute/replay family (120–124 and 126–129) is omitted so
/// an application can register those handlers. Tag 125 remains core-owned.
/// Test-only workload tags are not part of this wire-revision set.
pub const CORE_INSTRUCTION_TAGS_REVISION_8: &[u8] = &[
    115, 116, 117, 118, 125, 131, 132, 140, 141, 142, 143, 144, 145, 146, 156, 157, 158, 159, 160,
    161, 162, 163, 164, 165, 166, 167, 168, 169, 172, 173, 174, 175, 176, 177, 178, 183, 184, 185,
    186, 187, 193, 197, 198, 199, 200,
];

/// Whether `tag` belongs to the DCG revision-8 core dispatcher.
pub const fn is_core_instruction_tag_revision_8(tag: u8) -> bool {
    #[cfg(feature = "sbf-lifecycle-test")]
    if tag >= 240 && tag <= 250 {
        return true;
    }
    #[cfg(feature = "sbf-real-lifecycle-test")]
    if (tag >= 230 && tag <= 239) || tag == crate::stateful::v3::RESOURCE_CHUNK_TAG {
        return true;
    }
    let mut low = 0usize;
    let mut high = CORE_INSTRUCTION_TAGS_REVISION_8.len();
    while low < high {
        let middle = low + (high - low) / 2;
        let candidate = CORE_INSTRUCTION_TAGS_REVISION_8[middle];
        if candidate == tag {
            return true;
        }
        if candidate < tag {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    false
}

/// Const-time table validation used by [`ApplicationProgramManifest::new`].
///
/// Tags must be in strictly ascending order, which rejects duplicates and
/// gives the identity digest one canonical table order. An application tag
/// may not overlap the DCG revision-8 core set.
///
/// This function is public so applications can get the same compile-time
/// diagnostics when validating a tag list before constructing entries.
pub const fn validate_application_tags(tags: &[u8]) {
    let mut i = 0usize;
    while i < tags.len() {
        let tag = tags[i];
        if is_core_instruction_tag_revision_8(tag) {
            panic!("application instruction tag overlaps the DCG revision-8 core set");
        }
        if i > 0 && tags[i - 1] >= tag {
            panic!("application instruction tags must be strictly sorted and unique");
        }
        i += 1;
    }
}

/// Invocation metadata passed to an application's handler.
///
/// Raw accounts are intentionally omitted here. The handler receives them
/// through [`CheckedApplicationAccounts`] after the preflight callback passes.
#[derive(Clone, Copy)]
pub struct ApplicationInstructionContext<'accounts> {
    pub program_id: &'accounts Pubkey,
    pub tag: u8,
    pub data: &'accounts [u8],
}

/// Untrusted input passed only to an application's preflight callback.
///
/// `accounts` preserves the invocation's original order. Preflight parses the
/// complete instruction and checks its tag-specific accounts before it
/// returns success.
#[derive(Clone, Copy)]
pub struct ApplicationAccountCheckContext<'accounts, 'info> {
    pub program_id: &'accounts Pubkey,
    pub tag: u8,
    pub data: &'accounts [u8],
    pub accounts: &'accounts [AccountInfo<'info>],
}

/// A seed component for an app PDA. Account-key sources must refer to an
/// earlier account entry that has already passed its own declared rule.
#[derive(Clone, Copy)]
pub enum ApplicationSeed {
    /// The manifest's application id. App PDA rules must use this as seed 0.
    ApplicationId,
    Literal(&'static [u8]),
    AccountKey(usize),
    InstructionData {
        offset: usize,
        length: usize,
    },
}

/// A DCG-owned revision-8 record validated by DCG's own read-only reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationCoreRecordKind {
    DocumentV8,
    ChallengeV8,
}

/// Authenticated source for a key-based app account rule.
#[derive(Clone, Copy)]
pub enum ApplicationKeySource {
    Fixed(&'static Pubkey),
    AccountKey(usize),
    InstructionData {
        offset: usize,
    },
    /// The target itself, accepted only when its rule requires a signer.
    SignerSelf,
}

/// Exact identity and owner policy for one app instruction account.
#[derive(Clone, Copy)]
pub enum ApplicationAccountIdentity {
    ProgramPda {
        seeds: &'static [ApplicationSeed],
        kind: AccountKind,
    },
    ProgramKey {
        source: ApplicationKeySource,
        kind: AccountKind,
    },
    SystemPda {
        seeds: &'static [ApplicationSeed],
        allow_prefunded: bool,
    },
    ExactKey {
        source: ApplicationKeySource,
        owner: Option<&'static Pubkey>,
        executable: bool,
    },
    /// A core record is checked by DCG's reader with a read-only role.
    CoreRecord { kind: ApplicationCoreRecordKind },
    /// The closure-v2 DRU1 PDA, whose canonical bump is committed at byte 219
    /// of an earlier, read-only validated DCR1 v5/v6 record.
    StoredBumpPda { challenge_account_index: usize },
}

/// Complete address, role, and alias contract for one ordered app account.
#[derive(Clone, Copy)]
pub struct ApplicationAccountRule {
    pub account_index: usize,
    pub identity: ApplicationAccountIdentity,
    pub role: RoleFlags,
    /// Repeated writable keys are refused unless both entries name the same
    /// explicit alias group. Read-only duplicates are harmless.
    pub alias_group: Option<u8>,
}

impl ApplicationAccountRule {
    pub const fn new(
        account_index: usize,
        identity: ApplicationAccountIdentity,
        role: RoleFlags,
    ) -> Self {
        Self {
            account_index,
            identity,
            role,
            alias_group: None,
        }
    }

    pub const fn with_alias_group(mut self, alias_group: u8) -> Self {
        self.alias_group = Some(alias_group);
        self
    }
}

fn account_key_source(
    source: ApplicationKeySource,
    current_index: usize,
    account: &AccountInfo,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
    validated: &[bool],
    role: RoleFlags,
) -> Result<Pubkey, ProgramError> {
    match source {
        ApplicationKeySource::Fixed(key) => Ok(*key),
        ApplicationKeySource::AccountKey(index) => {
            if index >= current_index || !validated.get(index).copied().unwrap_or(false) {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok(*accounts[index].key)
        }
        ApplicationKeySource::InstructionData { offset } => {
            let key_end = offset
                .checked_add(32)
                .ok_or(ProgramError::InvalidInstructionData)?;
            let bytes: [u8; 32] = instruction_data
                .get(offset..key_end)
                .ok_or(ProgramError::InvalidInstructionData)?
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            Ok(Pubkey::new_from_array(bytes))
        }
        ApplicationKeySource::SignerSelf => {
            if !role.signer || !account.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            Ok(*account.key)
        }
    }
}

fn account_seeds(
    seeds: &'static [ApplicationSeed],
    current_index: usize,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
    validated: &[bool],
    application_id: &'static [u8],
) -> Result<Vec<Vec<u8>>, ProgramError> {
    seeds
        .iter()
        .map(|seed| match seed {
            ApplicationSeed::ApplicationId => Ok(application_id.to_vec()),
            ApplicationSeed::Literal(bytes) => Ok(bytes.to_vec()),
            ApplicationSeed::AccountKey(index) => {
                if *index >= current_index || !validated.get(*index).copied().unwrap_or(false) {
                    return Err(ProgramError::InvalidAccountData);
                }
                Ok(accounts[*index].key.to_bytes().to_vec())
            }
            ApplicationSeed::InstructionData { offset, length } => {
                let end = offset
                    .checked_add(*length)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                Ok(instruction_data
                    .get(*offset..end)
                    .ok_or(ProgramError::InvalidInstructionData)?
                    .to_vec())
            }
        })
        .collect()
}

const CORE_ACCOUNT_MAGICS: &[&[u8]] = &[
    b"DCR1", b"DRU1", b"DCM2", b"DPR2", b"DFS2", b"DCR2", b"DCRZ", b"DRP2", b"DEA2", b"DCF1",
    b"DTA1", b"DTU1", b"DSE1", b"DCO1", b"DHR2", b"DLP2", b"DSH2", b"DSC1", b"DSR1", b"DSR2",
    b"DCD1", b"BDG1", b"DEA1", b"DRP1", b"ESG4", b"PXR1", b"PT1O", b"PT1P", b"PT1R", b"PT1S",
    b"PT1X", b"PT2P", b"PT2S", b"PWR1", b"DPL1", b"DFT1", b"BDS2", b"DSB1", b"DSE2", b"DSS1",
    b"DVW1", b"DSB2", b"DSS2", b"DVW2", b"DAN3", b"DRS3", b"DSB3", b"DSE3", b"DSS3", b"DVW3",
    b"ARI1", b"ARW1", b"RWP1", b"BSS1", b"DEV2", b"DLE1", b"DDT1", b"DDT2", b"DRB1",
];

const fn app_magic_overlaps_core(magic: &[u8]) -> bool {
    let mut i = 0usize;
    while i < CORE_ACCOUNT_MAGICS.len() {
        let core = CORE_ACCOUNT_MAGICS[i];
        let shared = if magic.len() < core.len() {
            magic.len()
        } else {
            core.len()
        };
        let mut j = 0usize;
        let mut same_prefix = true;
        while j < shared {
            if magic[j] != core[j] {
                same_prefix = false;
                break;
            }
            j += 1;
        }
        if same_prefix {
            return true;
        }
        i += 1;
    }
    false
}

const fn validate_app_kind(kind: AccountKind) {
    if kind.magic.is_empty() {
        panic!("application program-owned account rules require a non-empty magic");
    }
    if app_magic_overlaps_core(kind.magic) {
        panic!("application account magic overlaps a DCG core record magic");
    }
}

const fn validate_app_seeds(application_id: &'static [u8], seeds: &[ApplicationSeed]) {
    if application_id.is_empty() || application_id.len() > 32 {
        panic!("application id used as a PDA prefix must contain 1..=32 bytes");
    }
    if seeds.is_empty() {
        panic!("application PDA seeds must start with the application id");
    }
    match seeds[0] {
        ApplicationSeed::ApplicationId => {}
        _ => panic!("application PDA seeds must start with the application id"),
    }
    let mut i = 1usize;
    while i < seeds.len() {
        if matches!(seeds[i], ApplicationSeed::ApplicationId) {
            panic!("the application id may appear only as the first PDA seed");
        }
        i += 1;
    }
}

const fn validate_application_rules(
    application_id: &'static [u8],
    rules: &[ApplicationAccountRule],
) {
    let mut i = 0usize;
    while i < rules.len() {
        let rule = rules[i];
        if rule.account_index != i {
            panic!("application account rules must cover accounts in order");
        }
        match rule.identity {
            ApplicationAccountIdentity::ProgramPda { seeds, kind } => {
                validate_app_seeds(application_id, seeds);
                validate_app_kind(kind);
            }
            ApplicationAccountIdentity::ProgramKey { source, kind } => {
                if matches!(source, ApplicationKeySource::InstructionData { .. }) {
                    panic!("ProgramKey cannot take its key from instruction data");
                }
                validate_app_kind(kind);
            }
            ApplicationAccountIdentity::SystemPda { seeds, .. } => {
                validate_app_seeds(application_id, seeds);
            }
            ApplicationAccountIdentity::ExactKey { .. } => {}
            ApplicationAccountIdentity::CoreRecord { kind } => {
                if rule.role.writable || rule.role.signer {
                    panic!("core-record application rules are read-only");
                }
                let _ = kind;
            }
            ApplicationAccountIdentity::StoredBumpPda {
                challenge_account_index,
            } => {
                if challenge_account_index >= i {
                    panic!("stored-bump PDA source must be an earlier account");
                }
                match rules[challenge_account_index].identity {
                    ApplicationAccountIdentity::CoreRecord {
                        kind: ApplicationCoreRecordKind::ChallengeV8,
                    } => {}
                    _ => panic!("stored-bump PDA source must be a validated DCR1 core record"),
                }
            }
        }
        i += 1;
    }
}

fn validate_application_account_rules(
    program_id: &Pubkey,
    instruction_data: &[u8],
    accounts: &[AccountInfo],
    rules: &'static [ApplicationAccountRule],
    application_id: &'static [u8],
) -> ProgramResult {
    if rules.len() != accounts.len() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut validated = vec![false; accounts.len()];
    for (index, rule) in rules.iter().enumerate() {
        if rule.account_index != index {
            return Err(ProgramError::InvalidAccountData);
        }
        let account = &accounts[index];
        if (rule.role.writable && !account.is_writable) || (rule.role.signer && !account.is_signer)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        for previous in 0..index {
            if accounts[previous].key == account.key
                && (accounts[previous].is_writable || account.is_writable)
                && (rule.alias_group.is_none() || rule.alias_group != rules[previous].alias_group)
            {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        match rule.identity {
            ApplicationAccountIdentity::ProgramPda { seeds, kind } => {
                let values = account_seeds(
                    seeds,
                    index,
                    accounts,
                    instruction_data,
                    &validated,
                    application_id,
                )?;
                let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
                expect_derived(account, program_id, &refs, kind, rule.role)?;
            }
            ApplicationAccountIdentity::ProgramKey { source, kind } => {
                if matches!(source, ApplicationKeySource::InstructionData { .. }) {
                    return Err(ProgramError::InvalidAccountData);
                }
                let expected = account_key_source(
                    source,
                    index,
                    account,
                    accounts,
                    instruction_data,
                    &validated,
                    rule.role,
                )?;
                expect_keyed(account, program_id, &expected, kind, rule.role)?;
            }
            ApplicationAccountIdentity::SystemPda {
                seeds,
                allow_prefunded,
            } => {
                let values = account_seeds(
                    seeds,
                    index,
                    accounts,
                    instruction_data,
                    &validated,
                    application_id,
                )?;
                let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
                expect_system_derived_role(account, program_id, &refs, rule.role, allow_prefunded)?;
            }
            ApplicationAccountIdentity::ExactKey {
                source,
                owner,
                executable,
            } => {
                let expected = account_key_source(
                    source,
                    index,
                    account,
                    accounts,
                    instruction_data,
                    &validated,
                    rule.role,
                )?;
                if account.key != &expected
                    || account.owner == program_id
                    || owner.is_some_and(|owner| account.owner != owner)
                    || account.executable != executable
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ApplicationAccountIdentity::CoreRecord { kind } => {
                if rule.role.writable
                    || rule.role.signer
                    || account.is_writable
                    || account.is_signer
                {
                    return Err(ProgramError::InvalidAccountData);
                }
                match kind {
                    ApplicationCoreRecordKind::DocumentV8 => {
                        crate::unified::document::document_v8_stored(
                            program_id,
                            account,
                            None,
                            false,
                            crate::unified::DCR1_AUTH,
                        )?;
                    }
                    ApplicationCoreRecordKind::ChallengeV8 => {
                        crate::unified::challenge::validate_v8_readonly(program_id, account)?;
                    }
                }
            }
            ApplicationAccountIdentity::StoredBumpPda {
                challenge_account_index,
            } => {
                if challenge_account_index >= index
                    || !validated
                        .get(challenge_account_index)
                        .copied()
                        .unwrap_or(false)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
                let challenge = &accounts[challenge_account_index];
                let response_bump = challenge
                    .try_borrow_data()?
                    .get(crate::unified::challenge::RESPONSE_BUMP_AT)
                    .copied()
                    .ok_or(ProgramError::InvalidAccountData)?;
                let kind = AccountKind::variable(
                    b"DRU1",
                    crate::closure_v2_response::HEADER,
                    crate::closure_v2_response::HEADER + crate::closure_v2_response::MAX_BODY,
                )
                .with_version(4, 1);
                expect_derived_with_bump(
                    account,
                    program_id,
                    &[b"dcg-hcl-response", challenge.key.as_ref()],
                    response_bump,
                    kind,
                    rule.role,
                )?;
            }
        }
        validated[index] = true;
    }
    Ok(())
}

/// Borrowed account view passed to a handler only after its preflight returns
/// success.
///
/// The view preserves account order and exposes the original references.
/// Every account passed the app entry's static provenance and role rules.
pub struct CheckedApplicationAccounts<'accounts, 'info> {
    accounts: &'accounts [AccountInfo<'info>],
}

impl<'accounts, 'info> CheckedApplicationAccounts<'accounts, 'info> {
    fn after_provenance(context: &ApplicationAccountCheckContext<'accounts, 'info>) -> Self {
        Self {
            accounts: context.accounts,
        }
    }

    /// Number of accounts in the original invocation order.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the invocation supplied no accounts.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Borrow an account by its original position.
    pub fn get(&self, index: usize) -> Option<&'accounts AccountInfo<'info>> {
        self.accounts.get(index)
    }

    /// Iterate over accounts in their original order.
    pub fn iter(&self) -> core::slice::Iter<'accounts, AccountInfo<'info>> {
        self.accounts.iter()
    }
}

/// Preflight callback for a statically registered application instruction.
pub type ApplicationPreflight =
    for<'accounts, 'info> fn(ApplicationAccountCheckContext<'accounts, 'info>) -> ProgramResult;

/// Handler callback invoked after the entry's preflight returns success.
pub type ApplicationHandler = for<'accounts, 'info> fn(
    ApplicationInstructionContext<'accounts>,
    &CheckedApplicationAccounts<'accounts, 'info>,
) -> ProgramResult;

/// One statically linked application instruction and its semantic identity.
#[derive(Clone, Copy)]
pub struct ApplicationInstruction {
    /// Wire instruction tag owned by this application.
    pub tag: u8,
    /// Stable application-defined handler identifier.
    pub handler_id: &'static str,
    /// Semantic handler version; increment when behavior changes.
    pub handler_version: u16,
    /// Static per-account address and role contract, covering every account
    /// position supplied to this instruction.
    pub account_rules: &'static [ApplicationAccountRule],
    /// Tag-specific parsing and account preflight.
    pub preflight: ApplicationPreflight,
    /// Handler called only after preflight succeeds.
    pub handler: ApplicationHandler,
}

impl ApplicationInstruction {
    /// Define one application instruction entry.
    pub const fn new(
        tag: u8,
        handler_id: &'static str,
        handler_version: u16,
        account_rules: &'static [ApplicationAccountRule],
        preflight: ApplicationPreflight,
        handler: ApplicationHandler,
    ) -> Self {
        if handler_id.is_empty() {
            panic!("application instruction handler id must not be empty");
        }
        if handler_version == 0 {
            panic!("application instruction handler version must be non-zero");
        }
        Self {
            tag,
            handler_id,
            handler_version,
            account_rules,
            preflight,
            handler,
        }
    }
}

fn encode_usize(value: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

fn encode_seeds(seeds: &[ApplicationSeed], out: &mut Vec<u8>) {
    out.extend_from_slice(&(seeds.len() as u32).to_le_bytes());
    for seed in seeds {
        match seed {
            ApplicationSeed::ApplicationId => out.push(3),
            ApplicationSeed::Literal(bytes) => {
                out.push(0);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            ApplicationSeed::AccountKey(index) => {
                out.push(1);
                encode_usize(*index, out);
            }
            ApplicationSeed::InstructionData { offset, length } => {
                out.push(2);
                encode_usize(*offset, out);
                encode_usize(*length, out);
            }
        }
    }
}

fn encode_key_source(source: ApplicationKeySource, out: &mut Vec<u8>) {
    match source {
        ApplicationKeySource::Fixed(key) => {
            out.push(0);
            out.extend_from_slice(key.as_ref());
        }
        ApplicationKeySource::AccountKey(index) => {
            out.push(1);
            encode_usize(index, out);
        }
        ApplicationKeySource::InstructionData { offset } => {
            out.push(2);
            encode_usize(offset, out);
        }
        ApplicationKeySource::SignerSelf => out.push(3),
    }
}

fn encode_kind(kind: AccountKind, out: &mut Vec<u8>) {
    out.extend_from_slice(&(kind.magic.len() as u32).to_le_bytes());
    out.extend_from_slice(kind.magic);
    encode_usize(kind.min_len, out);
    encode_usize(kind.max_len, out);
    match kind.bump_offset {
        Some(offset) => {
            out.push(1);
            encode_usize(offset, out);
        }
        None => out.push(0),
    }
    match kind.version {
        Some((offset, version)) => {
            out.push(1);
            encode_usize(offset, out);
            out.extend_from_slice(&version.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn encode_application_account_rule(rule: &ApplicationAccountRule) -> Vec<u8> {
    let mut out = Vec::new();
    encode_usize(rule.account_index, &mut out);
    out.push(u8::from(rule.role.writable));
    out.push(u8::from(rule.role.signer));
    match rule.alias_group {
        Some(group) => {
            out.push(1);
            out.push(group);
        }
        None => out.push(0),
    }
    match rule.identity {
        ApplicationAccountIdentity::ProgramPda { seeds, kind } => {
            out.push(0);
            encode_seeds(seeds, &mut out);
            encode_kind(kind, &mut out);
        }
        ApplicationAccountIdentity::ProgramKey { source, kind } => {
            out.push(1);
            encode_key_source(source, &mut out);
            encode_kind(kind, &mut out);
        }
        ApplicationAccountIdentity::SystemPda {
            seeds,
            allow_prefunded,
        } => {
            out.push(2);
            encode_seeds(seeds, &mut out);
            out.push(u8::from(allow_prefunded));
        }
        ApplicationAccountIdentity::ExactKey {
            source,
            owner,
            executable,
        } => {
            out.push(3);
            encode_key_source(source, &mut out);
            match owner {
                Some(owner) => {
                    out.push(1);
                    out.extend_from_slice(owner.as_ref());
                }
                None => out.push(0),
            }
            out.push(u8::from(executable));
        }
        ApplicationAccountIdentity::CoreRecord { kind } => {
            out.push(4);
            out.push(match kind {
                ApplicationCoreRecordKind::DocumentV8 => 0,
                ApplicationCoreRecordKind::ChallengeV8 => 1,
            });
        }
        ApplicationAccountIdentity::StoredBumpPda {
            challenge_account_index,
        } => {
            out.push(5);
            encode_usize(challenge_account_index, &mut out);
        }
    }
    out
}

/// Static application manifest paired with a canonical instruction table.
///
/// Fields are private so a normal static value must pass the const validator.
pub struct ApplicationProgramManifest {
    application: &'static ApplicationManifest,
    instructions: &'static [ApplicationInstruction],
}

impl ApplicationProgramManifest {
    /// Construct a manifest from a static application manifest and array.
    ///
    /// The array form lets Rust evaluate duplicate and core-overlap checks at
    /// compile time while preserving a static slice for the dispatcher.
    pub const fn new<const N: usize>(
        application: &'static ApplicationManifest,
        instructions: &'static [ApplicationInstruction; N],
    ) -> Self {
        let mut tags = [0u8; N];
        let mut i = 0usize;
        while i < N {
            tags[i] = instructions[i].tag;
            validate_application_rules(application.application_id, instructions[i].account_rules);
            i += 1;
        }
        validate_application_tags(&tags);
        Self {
            application,
            instructions,
        }
    }

    /// The existing kernel/form manifest wrapped by this program manifest.
    pub const fn application_manifest(&self) -> &'static ApplicationManifest {
        self.application
    }

    /// The canonical ascending static instruction table.
    pub const fn instructions(&self) -> &'static [ApplicationInstruction] {
        self.instructions
    }

    /// Versioned identity for the assembled application program contract.
    ///
    /// It commits the app id/version digest, the existing form-to-kernel
    /// admission digest, each canonical `(tag, handler id, version)` row, and
    /// every ordered account rule. Function pointers are intentionally
    /// excluded: behavior changes must change the stable handler id's semantic
    /// version or the app version.
    pub fn identity_digest(&self) -> [u8; 32] {
        let application_identity = self.application.identity_digest();
        let kernel_form_identity = self.application.admission_identity_digest();
        let instruction_count = (self.instructions.len() as u32).to_le_bytes();
        let mut digest = sha256(&[
            b"dcg/application-program-manifest/3",
            &application_identity,
            &kernel_form_identity,
            &instruction_count,
        ]);
        for instruction in self.instructions {
            let handler_id = instruction.handler_id.as_bytes();
            let handler_id_length = (handler_id.len() as u32).to_le_bytes();
            digest = sha256(&[
                b"dcg/application-program-instruction/2",
                &digest,
                &[instruction.tag],
                &handler_id_length,
                handler_id,
                &instruction.handler_version.to_le_bytes(),
            ]);
            for rule in instruction.account_rules {
                let encoded = encode_application_account_rule(rule);
                digest = sha256(&[b"dcg/application-program-account-rule/1", &digest, &encoded]);
            }
        }
        digest
    }
}

/// Dispatch through DCG core first, then the selected application's table.
///
/// A core-owned tag is sent to the compatibility dispatcher unchanged. For a
/// non-core tag, the sorted app table is searched; unmatched tags fall back to
/// the core dispatcher so feature-gated and future core routes keep working.
pub fn process_instruction_with_application(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &'static ApplicationProgramManifest,
) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };

    if is_core_instruction_tag_revision_8(tag) {
        return process_instruction_with_manifest(
            program_id,
            accounts,
            data,
            manifest.application_manifest(),
        );
    }

    let instructions = manifest.instructions();
    let Ok(index) = instructions.binary_search_by_key(&tag, |instruction| instruction.tag) else {
        return process_instruction_with_manifest(
            program_id,
            accounts,
            data,
            manifest.application_manifest(),
        );
    };
    let instruction = &instructions[index];
    validate_application_account_rules(
        program_id,
        data,
        accounts,
        instruction.account_rules,
        manifest.application_manifest().application_id,
    )?;
    let account_check_context = ApplicationAccountCheckContext {
        program_id,
        tag,
        data,
        accounts,
    };
    (instruction.preflight)(account_check_context)?;
    let checked_accounts = CheckedApplicationAccounts::after_provenance(&account_check_context);
    let context = ApplicationInstructionContext {
        program_id,
        tag,
        data,
    };
    (instruction.handler)(context, &checked_accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use syn::{Expr, Lit, Pat};

    const APP_TAG: u8 = 120;
    const PREFLIGHT_MARK: usize = 1;
    const HANDLER_MARK: usize = 2;
    static ORDER: AtomicUsize = AtomicUsize::new(0);
    static PDA_ORDER: AtomicUsize = AtomicUsize::new(0);
    static ROLE_ORDER: AtomicUsize = AtomicUsize::new(0);
    static EMPTY_KERNELS: [&'static dyn crate::kernel::Kernel; 0] = [];
    static EMPTY_REPLAYS: [crate::kernel::OptimisticReplayBinding; 0] = [];
    static EMPTY_FORMS: [crate::kernel::LegacyFormBinding; 0] = [];
    static TEST_APPLICATION: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg/app-api-test/1",
        version: 1,
        kernels: &EMPTY_KERNELS,
        optimistic_replays: &EMPTY_REPLAYS,
        legacy_forms: &EMPTY_FORMS,
        require_legacy_form_binding: false,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

    fn preflight(context: ApplicationAccountCheckContext<'_, '_>) -> ProgramResult {
        assert_eq!(context.tag, APP_TAG);
        assert_eq!(context.data, &[APP_TAG, 7]);
        assert!(context.accounts.is_empty());
        ORDER.store(PREFLIGHT_MARK, Ordering::SeqCst);
        Ok(())
    }

    fn handler(
        context: ApplicationInstructionContext<'_>,
        checked: &CheckedApplicationAccounts<'_, '_>,
    ) -> ProgramResult {
        assert_eq!(ORDER.load(Ordering::SeqCst), PREFLIGHT_MARK);
        assert_eq!(context.tag, APP_TAG);
        assert!(checked.is_empty());
        ORDER.store(HANDLER_MARK, Ordering::SeqCst);
        Err(ProgramError::Custom(0xDC01))
    }

    fn role_preflight(_: ApplicationAccountCheckContext<'_, '_>) -> ProgramResult {
        ROLE_ORDER.store(PREFLIGHT_MARK, Ordering::SeqCst);
        Ok(())
    }

    fn role_handler(
        _: ApplicationInstructionContext<'_>,
        _: &CheckedApplicationAccounts<'_, '_>,
    ) -> ProgramResult {
        ROLE_ORDER.store(HANDLER_MARK, Ordering::SeqCst);
        Err(ProgramError::Custom(0xDC04))
    }

    fn pda_preflight(_: ApplicationAccountCheckContext<'_, '_>) -> ProgramResult {
        PDA_ORDER.store(PREFLIGHT_MARK, Ordering::SeqCst);
        Ok(())
    }

    fn pda_handler(
        _: ApplicationInstructionContext<'_>,
        _: &CheckedApplicationAccounts<'_, '_>,
    ) -> ProgramResult {
        PDA_ORDER.store(HANDLER_MARK, Ordering::SeqCst);
        Ok(())
    }

    fn core_shadow_preflight(_: ApplicationAccountCheckContext<'_, '_>) -> ProgramResult {
        Err(ProgramError::Custom(0xDC02))
    }

    fn core_shadow_handler(
        _: ApplicationInstructionContext<'_>,
        _: &CheckedApplicationAccounts<'_, '_>,
    ) -> ProgramResult {
        Err(ProgramError::Custom(0xDC03))
    }

    static NO_RULES: [ApplicationAccountRule; 0] = [];
    static APP_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        APP_TAG,
        "example/dispatch-test",
        1,
        &NO_RULES,
        preflight,
        handler,
    )];
    static APP_PROGRAM: ApplicationProgramManifest =
        ApplicationProgramManifest::new(&TEST_APPLICATION, &APP_INSTRUCTIONS);
    fn app_program() -> &'static ApplicationProgramManifest {
        &APP_PROGRAM
    }

    static APP_INSTRUCTIONS_V2: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        APP_TAG,
        "example/dispatch-test",
        2,
        &NO_RULES,
        preflight,
        handler,
    )];
    static APP_PROGRAM_V2: ApplicationProgramManifest =
        ApplicationProgramManifest::new(&TEST_APPLICATION, &APP_INSTRUCTIONS_V2);
    fn app_program_v2() -> &'static ApplicationProgramManifest {
        &APP_PROGRAM_V2
    }

    static SHADOW_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        125,
        "example/illegal-shadow",
        1,
        &NO_RULES,
        core_shadow_preflight,
        core_shadow_handler,
    )];

    fn dispatcher_handler_tags() -> Vec<u8> {
        fn literal(expr: &Expr) -> Option<u8> {
            let Expr::Lit(expr) = expr else { return None };
            let Lit::Int(value) = &expr.lit else {
                return None;
            };
            value.base10_parse().ok()
        }
        fn pattern_tags(pattern: &Pat, out: &mut Vec<u8>) {
            match pattern {
                Pat::Lit(lit) => {
                    if let Lit::Int(value) = &lit.lit {
                        if let Ok(tag) = value.base10_parse() {
                            out.push(tag);
                        }
                    }
                }
                Pat::Range(range) => {
                    let (Some(start), Some(end)) = (&range.start, &range.end) else {
                        return;
                    };
                    let (Some(start), Some(end)) = (literal(start), literal(end)) else {
                        return;
                    };
                    let exclusive_end = match &range.limits {
                        syn::RangeLimits::Closed(_) => end.saturating_add(1),
                        syn::RangeLimits::HalfOpen(_) => end,
                    };
                    out.extend(start..exclusive_end);
                }
                Pat::Or(or) => {
                    for case in &or.cases {
                        pattern_tags(case, out);
                    }
                }
                _ => {}
            }
        }
        struct DispatchMatch(Vec<u8>);
        impl<'ast> syn::visit::Visit<'ast> for DispatchMatch {
            fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
                if matches!(node.expr.as_ref(), Expr::Path(path) if path.path.is_ident("tag")) {
                    for arm in &node.arms {
                        let is_explicit_invalid = matches!(arm.body.as_ref(), Expr::Call(call)
                            if matches!(call.func.as_ref(), Expr::Path(path) if path.path.is_ident("Err"))
                            && call.args.iter().any(|arg| matches!(arg, Expr::Path(path)
                                if path.path.segments.last().is_some_and(|segment| segment.ident == "InvalidInstructionData"))));
                        if !is_explicit_invalid {
                            pattern_tags(&arm.pat, &mut self.0);
                        }
                    }
                }
                syn::visit::visit_expr_match(self, node);
            }
        }
        let syntax = syn::parse_file(include_str!("lib.rs")).expect("lib.rs parses");
        let function = syntax
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function)
                    if function.sig.ident == "process_instruction_with_manifest" =>
                {
                    Some(function)
                }
                _ => None,
            })
            .expect("core dispatcher exists");
        let mut found = DispatchMatch(Vec::new());
        syn::visit::Visit::visit_block(&mut found, &function.block);
        found.0.sort_unstable();
        found.0.dedup();
        found.0
    }

    #[test]
    fn revision8_core_tag_set_is_sorted_and_matches_the_dispatch_surface() {
        assert_eq!(
            CORE_INSTRUCTION_TAGS_REVISION_8,
            dispatcher_handler_tags().as_slice()
        );
        assert!(CORE_INSTRUCTION_TAGS_REVISION_8
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        for tag in CORE_INSTRUCTION_TAGS_REVISION_8 {
            assert!(is_core_instruction_tag_revision_8(*tag));
        }
        for tag in 120..=124 {
            assert!(!is_core_instruction_tag_revision_8(tag));
        }
        for tag in 126..=129 {
            assert!(!is_core_instruction_tag_revision_8(tag));
        }
    }

    #[test]
    fn empty_app_manifest_preserves_every_existing_revision8_dispatch_result() {
        static EMPTY_INSTRUCTIONS: [ApplicationInstruction; 0] = [];
        static EMPTY_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &EMPTY_INSTRUCTIONS);
        let program_id = Pubkey::new_unique();
        for tag in 0u8..=u8::MAX {
            let data = [tag];
            assert_eq!(
                process_instruction_with_application(&program_id, &[], &data, &EMPTY_PROGRAM),
                crate::process_instruction_with_manifest(
                    &program_id,
                    &[],
                    &data,
                    crate::application_manifest()
                ),
                "dispatch changed for tag {tag}"
            );
        }
        assert_eq!(
            process_instruction_with_application(&program_id, &[], &[], &EMPTY_PROGRAM),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn app_dispatch_runs_preflight_before_handler_and_uses_the_checked_view() {
        ORDER.store(0, Ordering::SeqCst);
        let result = process_instruction_with_application(
            &Pubkey::new_unique(),
            &[],
            &[APP_TAG, 7],
            app_program(),
        );
        assert_eq!(result, Err(ProgramError::Custom(0xDC01)));
        assert_eq!(ORDER.load(Ordering::SeqCst), HANDLER_MARK);
    }

    #[test]
    fn unknown_application_tag_is_refused() {
        let result =
            process_instruction_with_application(&Pubkey::new_unique(), &[], &[121], app_program());
        assert_eq!(result, Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn a_core_tag_routes_to_dcg_even_if_an_internal_manifest_is_forged() {
        // External construction goes through `new`, which const-rejects this
        // overlap. This forged in-module value exercises the runtime
        // core-first defense independently.
        static FORGED: ApplicationProgramManifest = ApplicationProgramManifest {
            application: &TEST_APPLICATION,
            instructions: &SHADOW_INSTRUCTIONS,
        };
        let program_id = Pubkey::new_unique();
        let data = [125];
        let expected = crate::process_instruction_with_manifest(
            &program_id,
            &[],
            &data,
            crate::application_manifest(),
        );
        let actual = process_instruction_with_application(&program_id, &[], &data, &FORGED);
        assert_eq!(actual, expected);
        assert_ne!(actual, Err(ProgramError::Custom(0xDC02)));
        assert_ne!(actual, Err(ProgramError::Custom(0xDC03)));
    }

    #[test]
    fn declared_account_roles_run_before_application_preflight() {
        static SIGNER_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
            0,
            ApplicationAccountIdentity::ExactKey {
                source: ApplicationKeySource::SignerSelf,
                owner: None,
                executable: false,
            },
            RoleFlags {
                writable: false,
                signer: true,
            },
        )];
        static SIGNER_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
            APP_TAG,
            "example/dispatch-test",
            1,
            &SIGNER_RULES,
            role_preflight,
            role_handler,
        )];
        static SIGNER_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &SIGNER_INSTRUCTIONS);
        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 1;
        let mut data = [];
        let account = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        ROLE_ORDER.store(0, Ordering::SeqCst);
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[account],
                &[APP_TAG, 7],
                &SIGNER_PROGRAM,
            ),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(ROLE_ORDER.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn program_pda_provenance_runs_before_application_preflight() {
        static PDA_SEEDS: [ApplicationSeed; 2] = [
            ApplicationSeed::ApplicationId,
            ApplicationSeed::Literal(b"dispatch-test-pda"),
        ];
        static PDA_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
            0,
            ApplicationAccountIdentity::ProgramPda {
                seeds: &PDA_SEEDS,
                kind: AccountKind::exact(b"APP1", 4),
            },
            RoleFlags {
                writable: true,
                signer: false,
            },
        )];
        static PDA_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
            APP_TAG,
            "example/dispatch-test",
            1,
            &PDA_RULES,
            pda_preflight,
            pda_handler,
        )];
        static PDA_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &PDA_INSTRUCTIONS);

        let program_id = Pubkey::new_unique();
        let (key, _) = Pubkey::find_program_address(
            &[TEST_APPLICATION.application_id, b"dispatch-test-pda"],
            &program_id,
        );
        let wrong_owner = Pubkey::new_unique();
        let mut lamports = 1;
        let mut data = *b"APP1";
        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &wrong_owner,
            false,
            0,
        );

        PDA_ORDER.store(0, Ordering::SeqCst);
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[account],
                &[APP_TAG, 7],
                &PDA_PROGRAM,
            ),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(PDA_ORDER.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_key_rules_refuse_accounts_owned_by_the_dcg_program() {
        static EXACT_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
            0,
            ApplicationAccountIdentity::ExactKey {
                source: ApplicationKeySource::SignerSelf,
                owner: None,
                executable: false,
            },
            RoleFlags {
                writable: false,
                signer: true,
            },
        )];
        static EXACT_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
            APP_TAG,
            "example/exact-key-test",
            1,
            &EXACT_RULES,
            role_preflight,
            role_handler,
        )];
        static EXACT_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &EXACT_INSTRUCTIONS);

        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let mut lamports = 1;
        let mut data = [];
        let account = AccountInfo::new(
            &key,
            true,
            false,
            &mut lamports,
            &mut data,
            &program_id,
            false,
            0,
        );
        ROLE_ORDER.store(0, Ordering::SeqCst);
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[account],
                &[APP_TAG, 7],
                &EXACT_PROGRAM,
            ),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(ROLE_ORDER.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn program_key_runtime_guard_refuses_instruction_data_sources() {
        static PROGRAM_KEY_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
            0,
            ApplicationAccountIdentity::ProgramKey {
                source: ApplicationKeySource::InstructionData { offset: 1 },
                kind: AccountKind::exact(b"APP1", 4),
            },
            RoleFlags {
                writable: false,
                signer: false,
            },
        )];
        static PROGRAM_KEY_INSTRUCTIONS: [ApplicationInstruction; 1] =
            [ApplicationInstruction::new(
                APP_TAG,
                "example/program-key-runtime-test",
                1,
                &PROGRAM_KEY_RULES,
                pda_preflight,
                pda_handler,
            )];
        // The const constructor rejects this rule. This forged in-module value
        // pins the dispatcher's runtime guard independently.
        static FORGED_PROGRAM_KEY_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest {
                application: &TEST_APPLICATION,
                instructions: &PROGRAM_KEY_INSTRUCTIONS,
            };

        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 1;
        let mut data = *b"APP1";
        let account = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        PDA_ORDER.store(0, Ordering::SeqCst);
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[account],
                &[APP_TAG, 7],
                &FORGED_PROGRAM_KEY_PROGRAM,
            ),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(PDA_ORDER.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn core_challenge_and_its_stored_bump_response_are_checked_read_only() {
        static DISPUTE_RULES: [ApplicationAccountRule; 2] = [
            ApplicationAccountRule::new(
                0,
                ApplicationAccountIdentity::CoreRecord {
                    kind: ApplicationCoreRecordKind::ChallengeV8,
                },
                RoleFlags {
                    writable: false,
                    signer: false,
                },
            ),
            ApplicationAccountRule::new(
                1,
                ApplicationAccountIdentity::StoredBumpPda {
                    challenge_account_index: 0,
                },
                RoleFlags {
                    writable: false,
                    signer: false,
                },
            ),
        ];
        static DISPUTE_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
            APP_TAG,
            "example/dispute-account-test",
            1,
            &DISPUTE_RULES,
            pda_preflight,
            pda_handler,
        )];
        static DISPUTE_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &DISPUTE_INSTRUCTIONS);

        let program_id = Pubkey::new_unique();
        let descriptor = [9u8; 32];
        let challenger = Pubkey::new_unique();
        let nonce = 17u32.to_le_bytes();
        let (challenge_key, challenge_bump) = Pubkey::find_program_address(
            &[
                crate::unified::address::CHALLENGE_SEED,
                &descriptor,
                challenger.as_ref(),
                &nonce,
            ],
            &program_id,
        );
        let (response_key, response_bump) = Pubkey::find_program_address(
            &[b"dcg-hcl-response", challenge_key.as_ref()],
            &program_id,
        );
        let mut challenge_lamports = 1;
        let mut challenge_data = vec![0u8; crate::unified::challenge::SIZE];
        challenge_data[..4].copy_from_slice(b"DCR1");
        challenge_data[4] = crate::unified::challenge::PHASE_RESPOND;
        challenge_data[6..8].copy_from_slice(&crate::unified::challenge::VERSION.to_le_bytes());
        challenge_data[8..40].copy_from_slice(challenger.as_ref());
        challenge_data[72..104].copy_from_slice(&descriptor);
        challenge_data[crate::unified::challenge::PT2P_MODE_AT] = 1;
        challenge_data[140..144].copy_from_slice(&nonce);
        challenge_data[crate::unified::challenge::RECORD_BUMP_AT] = challenge_bump;
        challenge_data[crate::unified::challenge::RECORD_BUMP_MARKER_AT] = 1;
        challenge_data[crate::unified::challenge::RESPONSE_BUMP_STAGED_AT] = response_bump;
        challenge_data[crate::unified::challenge::RESPONSE_BUMP_AT] = response_bump;
        let challenge_account = AccountInfo::new(
            &challenge_key,
            false,
            false,
            &mut challenge_lamports,
            &mut challenge_data,
            &program_id,
            false,
            0,
        );
        let original_challenge = challenge_account.try_borrow_data().unwrap().to_vec();

        let mut response_lamports = 1;
        let mut response_data = vec![0u8; crate::closure_v2_response::HEADER];
        response_data[..4].copy_from_slice(b"DRU1");
        response_data[4..6].copy_from_slice(&1u16.to_le_bytes());
        let response_account = AccountInfo::new(
            &response_key,
            false,
            false,
            &mut response_lamports,
            &mut response_data,
            &program_id,
            false,
            0,
        );
        let mut writable_challenge = challenge_account.clone();
        writable_challenge.is_writable = true;
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[writable_challenge, response_account.clone()],
                &[APP_TAG, 7],
                &DISPUTE_PROGRAM,
            ),
            Err(ProgramError::InvalidAccountData),
            "a handler cannot receive a writable core challenge through a read-only rule"
        );
        PDA_ORDER.store(0, Ordering::SeqCst);
        assert_eq!(
            process_instruction_with_application(
                &program_id,
                &[challenge_account.clone(), response_account],
                &[APP_TAG, 7],
                &DISPUTE_PROGRAM,
            ),
            Ok(())
        );
        assert_eq!(PDA_ORDER.load(Ordering::SeqCst), HANDLER_MARK);
        assert_eq!(
            challenge_account.try_borrow_data().unwrap().as_ref(),
            original_challenge
        );
    }

    #[cfg(feature = "sbf-lifecycle-test")]
    #[test]
    fn lifecycle_workload_tags_are_classified_as_core() {
        assert!((240..=250).all(is_core_instruction_tag_revision_8));
    }

    #[cfg(feature = "sbf-real-lifecycle-test")]
    #[test]
    fn real_lifecycle_workload_tags_are_classified_as_core() {
        assert!((230..=239).all(is_core_instruction_tag_revision_8));
        assert!(is_core_instruction_tag_revision_8(
            crate::stateful::v3::RESOURCE_CHUNK_TAG
        ));
    }

    #[test]
    fn program_identity_commits_handler_semantic_version() {
        let app_program = app_program();
        let app_program_v2 = app_program_v2();
        assert_ne!(
            app_program.identity_digest(),
            app_program_v2.identity_digest()
        );
        assert_eq!(app_program.identity_digest(), app_program.identity_digest());
    }

    #[test]
    fn account_rules_are_committed_by_the_application_identity() {
        static READ_RULES: [ApplicationAccountRule; 1] = [ApplicationAccountRule::new(
            0,
            ApplicationAccountIdentity::ExactKey {
                source: ApplicationKeySource::SignerSelf,
                owner: None,
                executable: false,
            },
            RoleFlags {
                writable: false,
                signer: true,
            },
        )];
        static WITH_READ_RULE: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
            APP_TAG,
            "example/dispatch-test",
            1,
            &READ_RULES,
            preflight,
            handler,
        )];
        static RULE_PROGRAM: ApplicationProgramManifest =
            ApplicationProgramManifest::new(&TEST_APPLICATION, &WITH_READ_RULE);
        assert_ne!(
            app_program().identity_digest(),
            RULE_PROGRAM.identity_digest()
        );
    }
}
