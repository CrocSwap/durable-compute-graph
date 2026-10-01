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

use crate::{hash::sha256, kernel::ApplicationManifest, process_instruction_with_manifest};
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

/// Borrowed account view passed to a handler only after its preflight returns
/// success.
///
/// The view preserves account order and exposes the original references. The
/// tag-specific preflight owns seed, role, bounds, and alias checks until the
/// shared address-rule helper from `dcg-address-rule-fix` is available.
pub struct CheckedApplicationAccounts<'accounts, 'info> {
    accounts: &'accounts [AccountInfo<'info>],
}

impl<'accounts, 'info> CheckedApplicationAccounts<'accounts, 'info> {
    fn after_preflight(context: &ApplicationAccountCheckContext<'accounts, 'info>) -> Self {
        // TODO(dcg-address-rule-fix): call the shared account-address rule
        // helper here before constructing this view. Keep that helper's final
        // signature in its owning change; do not mirror a guessed signature.
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
            preflight,
            handler,
        }
    }
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
    /// admission digest, and each canonical `(tag, handler id, version)` row.
    /// Function pointers are intentionally excluded: behavior changes must
    /// change the stable handler id's semantic version or the app version.
    pub fn identity_digest(&self) -> [u8; 32] {
        let application_identity = self.application.identity_digest();
        let kernel_form_identity = self.application.admission_identity_digest();
        let instruction_count = (self.instructions.len() as u32).to_le_bytes();
        let mut digest = sha256(&[
            b"dcg/application-program-manifest/1",
            &application_identity,
            &kernel_form_identity,
            &instruction_count,
        ]);
        for instruction in self.instructions {
            let handler_id = instruction.handler_id.as_bytes();
            let handler_id_length = (handler_id.len() as u32).to_le_bytes();
            digest = sha256(&[
                b"dcg/application-program-instruction/1",
                &digest,
                &[instruction.tag],
                &handler_id_length,
                handler_id,
                &instruction.handler_version.to_le_bytes(),
            ]);
        }
        digest
    }
}

/// Dispatch through DCG core first, then the selected application's table.
///
/// A core-owned tag is sent to the compatibility dispatcher unchanged. For a
/// non-core tag, the sorted app table is searched; unknown tags and empty data
/// return `InvalidInstructionData`.
pub fn process_instruction_with_application(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: &ApplicationProgramManifest,
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
        return Err(ProgramError::InvalidInstructionData);
    };
    let instruction = &instructions[index];
    let account_check_context = ApplicationAccountCheckContext {
        program_id,
        tag,
        data,
        accounts,
    };
    (instruction.preflight)(account_check_context)?;
    let checked_accounts = CheckedApplicationAccounts::after_preflight(&account_check_context);
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

    const APP_TAG: u8 = 120;
    const PREFLIGHT_MARK: usize = 1;
    const HANDLER_MARK: usize = 2;
    static ORDER: AtomicUsize = AtomicUsize::new(0);

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

    fn core_shadow_preflight(_: ApplicationAccountCheckContext<'_, '_>) -> ProgramResult {
        Err(ProgramError::Custom(0xDC02))
    }

    fn core_shadow_handler(
        _: ApplicationInstructionContext<'_>,
        _: &CheckedApplicationAccounts<'_, '_>,
    ) -> ProgramResult {
        Err(ProgramError::Custom(0xDC03))
    }

    static APP_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        APP_TAG,
        "example/dispatch-test",
        1,
        preflight,
        handler,
    )];
    fn app_program() -> ApplicationProgramManifest {
        ApplicationProgramManifest::new(crate::application_manifest(), &APP_INSTRUCTIONS)
    }

    static APP_INSTRUCTIONS_V2: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        APP_TAG,
        "example/dispatch-test",
        2,
        preflight,
        handler,
    )];
    fn app_program_v2() -> ApplicationProgramManifest {
        ApplicationProgramManifest::new(crate::application_manifest(), &APP_INSTRUCTIONS_V2)
    }

    static SHADOW_INSTRUCTIONS: [ApplicationInstruction; 1] = [ApplicationInstruction::new(
        125,
        "example/illegal-shadow",
        1,
        core_shadow_preflight,
        core_shadow_handler,
    )];

    #[test]
    fn revision8_core_tag_set_is_sorted_and_matches_the_dispatch_surface() {
        assert_eq!(
            CORE_INSTRUCTION_TAGS_REVISION_8,
            &[
                115, 116, 117, 118, 125, 131, 132, 140, 141, 142, 143, 144, 145, 146, 156, 157,
                158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 172, 173, 174, 175,
                176, 177, 178, 183, 184, 185, 186, 187, 193, 197, 198, 199, 200,
            ]
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
        let empty_program =
            ApplicationProgramManifest::new(crate::application_manifest(), &EMPTY_INSTRUCTIONS);
        let program_id = Pubkey::new_unique();
        for tag in 0u8..=u8::MAX {
            let data = [tag];
            assert_eq!(
                process_instruction_with_application(&program_id, &[], &data, &empty_program),
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
            process_instruction_with_application(&program_id, &[], &[], &empty_program),
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
            &app_program(),
        );
        assert_eq!(result, Err(ProgramError::Custom(0xDC01)));
        assert_eq!(ORDER.load(Ordering::SeqCst), HANDLER_MARK);
    }

    #[test]
    fn unknown_application_tag_is_refused() {
        let result = process_instruction_with_application(
            &Pubkey::new_unique(),
            &[],
            &[121],
            &app_program(),
        );
        assert_eq!(result, Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn a_core_tag_routes_to_dcg_even_if_an_internal_manifest_is_forged() {
        // External construction goes through `new`, which const-rejects this
        // overlap. This forged in-module value exercises the runtime
        // core-first defense independently.
        let forged = ApplicationProgramManifest {
            application: crate::application_manifest(),
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
        let actual = process_instruction_with_application(&program_id, &[], &data, &forged);
        assert_eq!(actual, expected);
        assert_ne!(actual, Err(ProgramError::Custom(0xDC02)));
        assert_ne!(actual, Err(ProgramError::Custom(0xDC03)));
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
}
