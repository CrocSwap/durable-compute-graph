// SPDX-License-Identifier: GPL-3.0-only

//! Compile-time kernel and resolution-backend contracts.
//!
//! Kernel execution semantics live here; a resolution backend owns the
//! lifecycle that accepts or disputes a committed result. Applications link
//! both into their image through a static manifest. This module contains no
//! SVM account types and defines no graph or sweep wire format.

use crate::hash;

/// A versioned identifier. The value and its version are independently
/// committed by the application manifest.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionedId {
    pub id: u32,
    pub version: u16,
}

/// A resolution mode's protocol identity. Mode IDs are extensible and carry
/// their own version; kernels may support several modes.
pub type ModeId = VersionedId;

/// A commitment scheme has independent identity and version.
pub type CommitmentScheme = VersionedId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortLayout {
    pub id: VersionedId,
    pub max_bytes: u32,
    pub alignment: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSchema {
    pub id: VersionedId,
    pub max_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_input_bytes: u32,
    pub max_output_bytes: u32,
    pub max_state_bytes: u32,
    pub max_operations: u32,
    pub max_compute_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelManifest {
    pub id: KernelId,
    pub semantic_version: u16,
    pub abi_version: u16,
    pub input: PortLayout,
    pub output: PortLayout,
    /// `None` means the kernel is stateless. Stateful methods are optional
    /// traits, so a stateless kernel never has to invent state operations.
    pub state: Option<StateSchema>,
    pub resources: ResourceLimits,
    pub modes: &'static [ModeId],
}

/// A region of account data selected by the application's compiled SVM
/// adapter. The adapter authenticates the account and bounds before a kernel
/// receives this view. `schema` identifies the region layout independently of
/// the kernel's semantic and ABI versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSpan<'a> {
    pub key: [u8; 32],
    pub owner: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
    pub schema: VersionedId,
    pub offset: u32,
    pub data: &'a [u8],
}

impl AccountSpan<'_> {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The owner rule for a statically declared account span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanOwner {
    Program,
    Exact([u8; 32]),
}

/// A static account/region selection belonging to a legacy form adapter.
/// Account indices refer to the five PT2S/route/geometry/registry/PT1S
/// accounts passed to the revision-8 fix-point adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSpanBinding {
    pub account_index: u8,
    /// `None` uses the account key already authenticated by the lifecycle
    /// handler. Applications may pin a more specific key when appropriate.
    pub key: Option<[u8; 32]>,
    pub owner: SpanOwner,
    pub is_signer: bool,
    pub is_writable: bool,
    pub schema: VersionedId,
    pub offset: u32,
    pub length: u32,
}

/// Application-selected bridge from one frozen revision-8 form row to an
/// exact compiled kernel identity. This is app-image configuration; it adds
/// no fields to a revision-8 document or instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyFormBinding {
    pub machine_selector: Option<u8>,
    pub form_id: u16,
    pub kernel_id: KernelId,
    pub semantic_version: u16,
    pub abi_version: u16,
    pub mode: ModeId,
    /// Input spans come first; the final span contains the claimed output.
    pub input_span_count: u8,
    pub spans: &'static [AccountSpanBinding],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelError {
    InputTooLarge,
    OutputTooSmall,
    StateTooLarge,
    InvalidInput,
    Refused,
}

/// A deterministic computation over authenticated byte operands. The caller
/// supplies only bytes that the selected execution profile has authenticated.
pub trait Kernel: Sync {
    fn manifest(&self) -> &'static KernelManifest;
    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError>;

    /// Multi-account kernels may override this method. A pure byte kernel
    /// keeps the convenient single-slice implementation by default.
    fn execute_spans(
        &self,
        inputs: &[AccountSpan<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let [input] = inputs else {
            return Err(KernelError::InvalidInput);
        };
        if input.schema != self.manifest().input.id {
            return Err(KernelError::InvalidInput);
        }
        self.execute(input.data, output)
    }
}

/// Optional state-transition contract. Consensus-only kernels may implement
/// this without advertising or implementing optimistic replay.
pub trait StatefulKernel: Kernel {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError>;
    fn transition(
        &self,
        input: &[u8],
        prior_state: &[u8],
        output: &mut [u8],
        next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError>;
}

/// Optional optimistic replay. It is separate from statefulness and from the
/// backend's challenge lifecycle.
pub trait OptimisticReplay: Kernel {
    /// Repeat the kernel identity on the replay vtable so SBF callers never
    /// need a trait-object upcast to call the inherited `Kernel::manifest`.
    fn replay_manifest(&self) -> &'static KernelManifest;

    fn replay(
        &self,
        input: &[u8],
        prior_state: &[u8],
        claimed_output: &[u8],
        claimed_state: &[u8],
    ) -> Result<bool, KernelError>;

    /// Account-span convenience for adapters that authenticate account
    /// identity, role, and schema before invoking the replay implementation.
    fn replay_spans(
        &self,
        inputs: &[AccountSpan<'_>],
        claimed_output: &[u8],
        claimed_state: &[u8],
    ) -> Result<bool, KernelError> {
        let [input] = inputs else {
            return Err(KernelError::InvalidInput);
        };
        if input.schema != self.replay_manifest().input.id {
            return Err(KernelError::InvalidInput);
        }
        self.replay(input.data, &[], claimed_output, claimed_state)
    }
}

/// A statically linked replay implementation bound to one advertised mode.
/// The kernel identity comes from `replay.replay_manifest()` so a descriptor cannot
/// select a different implementation by changing an untrusted numeric kind.
#[repr(C)]
pub struct OptimisticReplayBinding {
    pub mode: ModeId,
    pub replay: &'static dyn OptimisticReplay,
}

pub struct ApplicationManifest {
    pub application_id: &'static [u8],
    pub version: u16,
    pub kernels: &'static [&'static dyn Kernel],
    pub optimistic_replays: &'static [OptimisticReplayBinding],
    /// Optional app-selected mappings from revision-8 form rows to kernels.
    /// An empty list leaves the historical adapter's behavior unchanged.
    pub legacy_forms: &'static [LegacyFormBinding],
    /// When true, a form without an explicit app mapping is refused rather
    /// than handled by the historical profile adapter.
    pub require_legacy_form_binding: bool,
}

impl ApplicationManifest {
    /// Resolve only an exact semantic and ABI version from this compiled-in
    /// application registry. There is no runtime loading path.
    pub fn resolve(
        &self,
        id: KernelId,
        semantic_version: u16,
        abi_version: u16,
    ) -> Option<&'static dyn Kernel> {
        self.kernels.iter().copied().find(|kernel| {
            let m = kernel.manifest();
            m.id == id && m.semantic_version == semantic_version && m.abi_version == abi_version
        })
    }

    pub fn supports_mode(
        &self,
        id: KernelId,
        semantic_version: u16,
        abi_version: u16,
        mode: ModeId,
    ) -> bool {
        self.kernels.iter().any(|kernel| {
            let m = kernel.manifest();
            m.id == id
                && m.semantic_version == semantic_version
                && m.abi_version == abi_version
                && m.modes.contains(&mode)
        })
    }

    /// Resolve replay only when this application image compiled the exact
    /// kernel ABI and explicitly bound it to the requested versioned mode.
    pub fn resolve_optimistic_replay(
        &self,
        id: KernelId,
        semantic_version: u16,
        abi_version: u16,
        mode: ModeId,
    ) -> Option<&'static OptimisticReplayBinding> {
        let bindings: &'static [OptimisticReplayBinding] = self.optimistic_replays;
        let mut index = 0;
        while index < bindings.len() {
            let binding = bindings.get(index)?;
            let m = binding.replay.replay_manifest();
            if binding.mode.id != mode.id
                || binding.mode.version != mode.version
                || m.id != id
                || m.semantic_version != semantic_version
                || m.abi_version != abi_version
            {
                index += 1;
                continue;
            }
            for advertised in m.modes.iter() {
                if advertised.id == mode.id && advertised.version == mode.version {
                    return Some(binding);
                }
            }
            index += 1;
        }
        None
    }

    /// Resolve an app binding, preferring an exact machine selector over a
    /// machine-neutral binding. Duplicate bindings are rejected by
    /// `validate`, so this order is deterministic.
    pub fn resolve_legacy_form(
        &self,
        machine_selector: u8,
        form_id: u16,
    ) -> Option<&'static LegacyFormBinding> {
        self.legacy_forms
            .iter()
            .find(|binding| {
                binding.machine_selector == Some(machine_selector) && binding.form_id == form_id
            })
            .or_else(|| {
                self.legacy_forms.iter().find(|binding| {
                    binding.machine_selector.is_none() && binding.form_id == form_id
                })
            })
    }

    /// Re-execute a historical form only through the exact identity and mode
    /// selected by this app's static manifest. `spans` has already been
    /// formed by the SVM adapter after account checks and alias validation.
    pub fn replay_legacy_form(
        &self,
        binding: &LegacyFormBinding,
        spans: &[AccountSpan<'_>],
    ) -> Result<bool, ManifestRunError> {
        let expected_spans = binding.spans.len();
        let input_count = binding.input_span_count as usize;
        if input_count == 0 || expected_spans != input_count + 1 || spans.len() != expected_spans {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        let replay = self
            .resolve_optimistic_replay(
                binding.kernel_id,
                binding.semantic_version,
                binding.abi_version,
                binding.mode,
            )
            .ok_or(ManifestRunError::KernelUnavailable)?;
        let kernel = self
            .resolve(
                binding.kernel_id,
                binding.semantic_version,
                binding.abi_version,
            )
            .ok_or(ManifestRunError::KernelUnavailable)?;
        let manifest = kernel.manifest();
        let replay_manifest = replay.replay.replay_manifest();
        if replay_manifest.id != manifest.id
            || replay_manifest.semantic_version != manifest.semantic_version
            || replay_manifest.abi_version != manifest.abi_version
        {
            return Err(ManifestRunError::KernelUnavailable);
        }
        if !manifest.modes.contains(&binding.mode) {
            return Err(ManifestRunError::ModeUnsupported);
        }
        if manifest.input.alignment == 0 {
            return Err(ManifestRunError::InputAlignment);
        }
        let input_limit =
            (manifest.input.max_bytes as usize).min(manifest.resources.max_input_bytes as usize);
        let mut total_input = 0usize;
        for span in &spans[..input_count] {
            if span.schema != manifest.input.id {
                return Err(ManifestRunError::SpanSchema);
            }
            if span.is_empty() || span.len() % manifest.input.alignment as usize != 0 {
                return Err(ManifestRunError::InputAlignment);
            }
            total_input = total_input
                .checked_add(span.len())
                .ok_or(ManifestRunError::InputLimit)?;
        }
        if total_input > input_limit {
            return Err(ManifestRunError::InputLimit);
        }
        let claimed = spans.last().ok_or(ManifestRunError::InvalidSpanCount)?;
        if claimed.schema != manifest.output.id
            || claimed.len()
                > (manifest.output.max_bytes as usize)
                    .min(manifest.resources.max_output_bytes as usize)
        {
            return Err(ManifestRunError::SpanSchema);
        }
        replay
            .replay
            .replay_spans(&spans[..input_count], claimed.data, &[])
            .map_err(ManifestRunError::Kernel)
    }

    /// Run one already-authenticated byte transition through a kernel that
    /// this image compiled in. SVM adapters authenticate and bound operands
    /// before calling this method.
    pub fn execute(
        &self,
        id: KernelId,
        semantic_version: u16,
        abi_version: u16,
        mode: ModeId,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ManifestRunError> {
        let kernel = self
            .resolve(id, semantic_version, abi_version)
            .ok_or(ManifestRunError::KernelUnavailable)?;
        let m = kernel.manifest();
        if !m.modes.contains(&mode) {
            return Err(ManifestRunError::ModeUnsupported);
        }
        if input.len() > m.input.max_bytes as usize
            || input.len() > m.resources.max_input_bytes as usize
        {
            return Err(ManifestRunError::InputLimit);
        }
        if m.input.alignment == 0 || input.len() % m.input.alignment as usize != 0 {
            return Err(ManifestRunError::InputAlignment);
        }
        let output_limit = (m.output.max_bytes as usize).min(m.resources.max_output_bytes as usize);
        if output.len() < output_limit {
            return Err(ManifestRunError::OutputBufferTooSmall);
        }
        let written = kernel
            .execute(input, &mut output[..output_limit])
            .map_err(ManifestRunError::Kernel)?;
        if written > output_limit {
            return Err(ManifestRunError::InvalidOutputLength);
        }
        Ok(written)
    }

    /// Reject duplicate semantic identities at application startup or in a
    /// build-time manifest check.
    pub fn validate(&self) -> Result<(), ManifestError> {
        for (i, left) in self.kernels.iter().enumerate() {
            let a = left.manifest();
            for right in self.kernels.iter().skip(i + 1) {
                let b = right.manifest();
                if a.id == b.id
                    && a.semantic_version == b.semantic_version
                    && a.abi_version == b.abi_version
                {
                    return Err(ManifestError::DuplicateKernel(a.id));
                }
            }
            if a.modes.is_empty() {
                return Err(ManifestError::NoModes(a.id));
            }
            if a.input.alignment == 0 || a.output.alignment == 0 {
                return Err(ManifestError::InvalidAlignment(a.id));
            }
            if a.resources.max_input_bytes > a.input.max_bytes
                || a.resources.max_output_bytes > a.output.max_bytes
                || a.state
                    .is_some_and(|state| a.resources.max_state_bytes > state.max_bytes)
            {
                return Err(ManifestError::ResourceExceedsLayout(a.id));
            }
            for (mode_index, mode) in a.modes.iter().enumerate() {
                if a.modes
                    .iter()
                    .skip(mode_index + 1)
                    .any(|other| other == mode)
                {
                    return Err(ManifestError::DuplicateMode(a.id, *mode));
                }
            }
        }
        for (i, binding) in self.optimistic_replays.iter().enumerate() {
            let replay_manifest = binding.replay.replay_manifest();
            let registered = self.kernels.iter().any(|kernel| {
                let m = kernel.manifest();
                m.id == replay_manifest.id
                    && m.semantic_version == replay_manifest.semantic_version
                    && m.abi_version == replay_manifest.abi_version
            });
            if !registered {
                return Err(ManifestError::ReplayNotRegistered(replay_manifest.id));
            }
            let mode_advertised = self.kernels.iter().any(|kernel| {
                let m = kernel.manifest();
                m.id == replay_manifest.id
                    && m.semantic_version == replay_manifest.semantic_version
                    && m.abi_version == replay_manifest.abi_version
                    && m.modes.contains(&binding.mode)
            });
            if !mode_advertised {
                return Err(ManifestError::ReplayModeUnsupported(
                    replay_manifest.id,
                    binding.mode,
                ));
            }
            if self.optimistic_replays.iter().skip(i + 1).any(|other| {
                let m = other.replay.replay_manifest();
                other.mode == binding.mode
                    && m.id == replay_manifest.id
                    && m.semantic_version == replay_manifest.semantic_version
                    && m.abi_version == replay_manifest.abi_version
            }) {
                return Err(ManifestError::DuplicateReplay(
                    replay_manifest.id,
                    binding.mode,
                ));
            }
        }
        for (i, binding) in self.legacy_forms.iter().enumerate() {
            if binding.form_id == 0
                || binding.input_span_count == 0
                || binding.spans.len() != binding.input_span_count as usize + 1
            {
                return Err(ManifestError::InvalidLegacyForm(binding.form_id));
            }
            if self.legacy_forms.iter().skip(i + 1).any(|other| {
                other.machine_selector == binding.machine_selector
                    && other.form_id == binding.form_id
            }) {
                return Err(ManifestError::DuplicateLegacyForm(binding.form_id));
            }
            let Some(kernel) = self.resolve(
                binding.kernel_id,
                binding.semantic_version,
                binding.abi_version,
            ) else {
                return Err(ManifestError::LegacyKernelUnavailable(binding.form_id));
            };
            let kernel_manifest = kernel.manifest();
            if !kernel_manifest.modes.contains(&binding.mode)
                || self
                    .resolve_optimistic_replay(
                        binding.kernel_id,
                        binding.semantic_version,
                        binding.abi_version,
                        binding.mode,
                    )
                    .is_none()
            {
                return Err(ManifestError::LegacyModeUnsupported(binding.form_id));
            }
            for (index, span) in binding.spans.iter().enumerate() {
                let expected_schema = if index < binding.input_span_count as usize {
                    kernel_manifest.input.id
                } else {
                    kernel_manifest.output.id
                };
                let max_bytes = if index < binding.input_span_count as usize {
                    (kernel_manifest.input.max_bytes as usize)
                        .min(kernel_manifest.resources.max_input_bytes as usize)
                } else {
                    (kernel_manifest.output.max_bytes as usize)
                        .min(kernel_manifest.resources.max_output_bytes as usize)
                };
                if span.schema != expected_schema
                    || span.length == 0
                    || span.length as usize > max_bytes
                    || span.offset.checked_add(span.length).is_none()
                {
                    return Err(ManifestError::InvalidLegacyForm(binding.form_id));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    DuplicateKernel(KernelId),
    NoModes(KernelId),
    InvalidAlignment(KernelId),
    ResourceExceedsLayout(KernelId),
    DuplicateMode(KernelId, ModeId),
    ReplayNotRegistered(KernelId),
    ReplayModeUnsupported(KernelId, ModeId),
    DuplicateReplay(KernelId, ModeId),
    InvalidLegacyForm(u16),
    DuplicateLegacyForm(u16),
    LegacyKernelUnavailable(u16),
    LegacyModeUnsupported(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestRunError {
    KernelUnavailable,
    ModeUnsupported,
    InputLimit,
    InputAlignment,
    OutputBufferTooSmall,
    InvalidOutputLength,
    Kernel(KernelError),
    InvalidSpanCount,
    SpanSchema,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub scheme: CommitmentScheme,
    pub digest: [u8; 32],
}

impl Commitment {
    /// A utility commitment for the current revision-8 SHA-256 profile. New
    /// profiles select a different versioned scheme explicitly.
    pub fn sha256(bytes: &[u8]) -> Self {
        Self {
            scheme: SHA256_SCHEME,
            digest: hash::sha256(&[bytes]),
        }
    }
}

pub const SHA256_SCHEME: CommitmentScheme = VersionedId { id: 1, version: 1 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionStatus {
    Pending,
    Final,
    Refuted,
    TimedOut,
}

/// Backend protocol versions own admission and state transitions. This trait
/// has no assumptions about who receives bonds or how a chain stores state.
pub trait ResolutionBackend {
    type State;
    type Transition;
    type Error;

    fn mode(&self) -> ModeId;
    fn start(&self, claimed_output: Commitment) -> Result<Self::State, Self::Error>;
    fn advance(
        &self,
        state: &mut Self::State,
        transition: Self::Transition,
    ) -> Result<ResolutionStatus, Self::Error>;
}

/// A closed-registry compatibility row contains the old image's application
/// registration metadata, but no model implementation. The Basanos adapter
/// supplies the matching compiled kernel functions at its image boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedRegistryRow {
    pub machine_name: Option<&'static [u8]>,
    pub form_id: u16,
    pub geometry_bytes: u16,
    pub profile_bytes: u16,
    pub closure_execute: bool,
    pub private_supply_freeze: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryInheritance {
    pub machine_name: &'static [u8],
    pub base_machine_name: &'static [u8],
    pub excluded_forms: &'static [u16],
}

pub struct ClosedRegistryAdapter<'a> {
    rows: &'a [ClosedRegistryRow],
    inheritance: &'a [RegistryInheritance],
}

impl<'a> ClosedRegistryAdapter<'a> {
    pub const fn new(
        rows: &'a [ClosedRegistryRow],
        inheritance: &'a [RegistryInheritance],
    ) -> Self {
        Self { rows, inheritance }
    }

    /// Reproduces the old lookup order: machine-specific rows win, while
    /// machine-neutral rows serve only as fallbacks.
    pub fn resolve(&self, machine: &[u8], form_id: u16) -> Option<&'a ClosedRegistryRow> {
        self.resolve_at_depth(machine, form_id, 0)
    }

    fn resolve_at_depth(
        &self,
        machine: &[u8],
        form_id: u16,
        depth: usize,
    ) -> Option<&'a ClosedRegistryRow> {
        let exact = self
            .rows
            .iter()
            .find(|row| row.form_id == form_id && row.machine_name == Some(machine));
        if exact.is_some() {
            return exact;
        }
        if depth < self.inheritance.len() {
            if let Some(rule) = self
                .inheritance
                .iter()
                .find(|rule| rule.machine_name == machine)
            {
                let has_override = self.rows.iter().any(|row| {
                    row.form_id == form_id && row.machine_name == Some(rule.machine_name)
                });
                if !has_override && !rule.excluded_forms.contains(&form_id) {
                    if let Some(inherited) =
                        self.resolve_at_depth(rule.base_machine_name, form_id, depth + 1)
                    {
                        return Some(inherited);
                    }
                }
            }
        }
        self.rows
            .iter()
            .find(|row| row.form_id == form_id && row.machine_name.is_none())
    }

    pub fn admits_private_supply_freeze(&self, machine: &[u8]) -> bool {
        self.rows.iter().any(|row| {
            row.private_supply_freeze
                && self
                    .resolve(machine, row.form_id)
                    .is_some_and(|resolved| core::ptr::eq(resolved, row))
        })
    }

    pub fn rows(&self) -> &'a [ClosedRegistryRow] {
        self.rows
    }
}

#[cfg(feature = "test-kernel")]
pub mod test_kernel {
    use super::*;

    pub const MODE_CONSENSUS_V1: ModeId = VersionedId {
        id: 0x434f_4e53,
        version: 1,
    };
    pub const MODE_OPTIMISTIC_V1: ModeId = VersionedId {
        id: 0x4f50_5449,
        version: 1,
    };
    static MODES: [ModeId; 2] = [MODE_CONSENSUS_V1, MODE_OPTIMISTIC_V1];

    pub struct ByteSum {
        _marker: u8,
    }

    static MANIFEST: KernelManifest = KernelManifest {
        id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        input: PortLayout {
            id: VersionedId { id: 1, version: 1 },
            max_bytes: 64,
            alignment: 1,
        },
        output: PortLayout {
            id: VersionedId { id: 2, version: 1 },
            max_bytes: 8,
            alignment: 1,
        },
        state: None,
        resources: ResourceLimits {
            max_input_bytes: 64,
            max_output_bytes: 8,
            max_state_bytes: 0,
            max_operations: 64,
            max_compute_units: 10_000,
        },
        modes: &MODES,
    };

    impl Kernel for ByteSum {
        fn manifest(&self) -> &'static KernelManifest {
            &MANIFEST
        }
        fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
            if input.len() > MANIFEST.resources.max_input_bytes as usize {
                return Err(KernelError::InputTooLarge);
            }
            if output.len() < 8 {
                return Err(KernelError::OutputTooSmall);
            }
            let sum = input
                .iter()
                .try_fold(0u64, |acc, b| acc.checked_add(*b as u64))
                .ok_or(KernelError::InvalidInput)?;
            output[..8].copy_from_slice(&sum.to_le_bytes());
            Ok(8)
        }
    }

    pub static BYTE_SUM: ByteSum = ByteSum { _marker: 0 };
    impl OptimisticReplay for ByteSum {
        fn replay_manifest(&self) -> &'static KernelManifest {
            &MANIFEST
        }

        fn replay(
            &self,
            input: &[u8],
            prior_state: &[u8],
            claimed_output: &[u8],
            claimed_state: &[u8],
        ) -> Result<bool, KernelError> {
            if !prior_state.is_empty() || !claimed_state.is_empty() {
                return Err(KernelError::InvalidInput);
            }
            let mut expected = [0u8; 8];
            self.execute(input, &mut expected)?;
            Ok(claimed_output == expected)
        }
    }

    pub static KERNELS: [&'static dyn Kernel; 1] = [&BYTE_SUM];
    pub static REPLAY_BINDINGS: [OptimisticReplayBinding; 1] = [OptimisticReplayBinding {
        mode: MODE_OPTIMISTIC_V1,
        replay: &BYTE_SUM,
    }];
    pub static BYTE_SUM_SPANS: [AccountSpanBinding; 2] = [
        AccountSpanBinding {
            account_index: 4,
            key: None,
            owner: SpanOwner::Program,
            is_signer: false,
            is_writable: false,
            schema: VersionedId { id: 1, version: 1 },
            offset: 0,
            length: 3,
        },
        AccountSpanBinding {
            account_index: 4,
            key: None,
            owner: SpanOwner::Program,
            is_signer: false,
            is_writable: false,
            schema: VersionedId { id: 2, version: 1 },
            offset: 3,
            length: 8,
        },
    ];
    pub static BYTE_SUM_LEGACY_FORMS: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 22,
        kernel_id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        mode: MODE_OPTIMISTIC_V1,
        input_span_count: 1,
        spans: &BYTE_SUM_SPANS,
    }];
    // The extracted real-handler SBF fixture descends into the retained
    // compiler-v1 Form-256 row. Its three-byte PT2S cursor and eight-byte
    // geometry reserved field are both zero, so the same ByteSum replay has
    // a byte-exact honest answer without changing the retained plan artifact.
    // This second binding exists only in the dedicated SBF lifecycle image.
    #[cfg(feature = "sbf-real-lifecycle-test")]
    pub static BYTE_SUM_FORM_256_SPANS: [AccountSpanBinding; 2] = [
        AccountSpanBinding {
            account_index: 0,
            key: None,
            owner: SpanOwner::Program,
            is_signer: false,
            is_writable: false,
            schema: VersionedId { id: 1, version: 1 },
            offset: 184,
            length: 3,
        },
        AccountSpanBinding {
            account_index: 2,
            key: None,
            owner: SpanOwner::Program,
            is_signer: false,
            is_writable: false,
            schema: VersionedId { id: 2, version: 1 },
            offset: 9,
            length: 8,
        },
    ];
    #[cfg(feature = "sbf-real-lifecycle-test")]
    pub static BYTE_SUM_FORM_256_BINDING: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 256,
        kernel_id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        mode: MODE_OPTIMISTIC_V1,
        input_span_count: 1,
        spans: &BYTE_SUM_FORM_256_SPANS,
    }];
    #[cfg(feature = "sbf-real-lifecycle-test")]
    pub static BYTE_SUM_REAL_LIFECYCLE_FORMS: [LegacyFormBinding; 2] = [
        BYTE_SUM_LEGACY_FORMS[0],
        BYTE_SUM_FORM_256_BINDING[0],
    ];
    pub static MANIFEST_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-test-app/1",
        version: 1,
        kernels: &KERNELS,
        optimistic_replays: &REPLAY_BINDINGS,
        #[cfg(feature = "sbf-real-lifecycle-test")]
        legacy_forms: &BYTE_SUM_REAL_LIFECYCLE_FORMS,
        #[cfg(not(feature = "sbf-real-lifecycle-test"))]
        legacy_forms: &BYTE_SUM_LEGACY_FORMS,
        require_legacy_form_binding: true,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-kernel")]
    #[test]
    fn static_application_manifest_resolves_exact_semantic_and_abi_versions() {
        use test_kernel::{BYTE_SUM, MODE_CONSENSUS_V1, MODE_OPTIMISTIC_V1};
        let m = &test_kernel::MANIFEST_APP;
        assert_eq!(m.validate(), Ok(()));
        let kernel = m.resolve(KernelId(*b"dcg-test-sum-v1\0"), 1, 1).unwrap();
        assert_eq!(kernel.manifest().id, BYTE_SUM.manifest().id);
        let mut output = [0u8; 8];
        assert_eq!(
            m.execute(
                KernelId(*b"dcg-test-sum-v1\0"),
                1,
                1,
                MODE_CONSENSUS_V1,
                &[1, 2, 3, 250],
                &mut output,
            ),
            Ok(8)
        );
        assert_eq!(u64::from_le_bytes(output), 256);
        assert_eq!(
            m.resolve_optimistic_replay(BYTE_SUM.manifest().id, 1, 1, MODE_OPTIMISTIC_V1)
                .unwrap()
                .replay
                .replay(&[1, 2, 3, 250], &[], &output, &[]),
            Ok(true)
        );
        assert_eq!(
            m.resolve_optimistic_replay(BYTE_SUM.manifest().id, 1, 1, MODE_OPTIMISTIC_V1)
                .unwrap()
                .replay
                .replay(&[1, 2, 3, 250], &[], &[0; 8], &[]),
            Ok(false)
        );
        assert!(m
            .resolve_optimistic_replay(BYTE_SUM.manifest().id, 1, 1, MODE_CONSENSUS_V1)
            .is_none());
        assert!(m.supports_mode(BYTE_SUM.manifest().id, 1, 1, MODE_CONSENSUS_V1));
        assert!(!m.supports_mode(BYTE_SUM.manifest().id, 1, 2, MODE_CONSENSUS_V1));
        assert!(m.resolve(BYTE_SUM.manifest().id, 2, 1).is_none());
        assert!(m.resolve(BYTE_SUM.manifest().id, 1, 2).is_none());
        assert!(m
            .resolve(KernelId(*b"dcg-missing-v1\0\0"), 1, 1)
            .is_none());
        assert_eq!(
            m.execute(
                BYTE_SUM.manifest().id,
                1,
                1,
                VersionedId { id: 99, version: 1 },
                &[1],
                &mut output,
            ),
            Err(ManifestRunError::ModeUnsupported)
        );
        assert_eq!(
            m.execute(
                BYTE_SUM.manifest().id,
                1,
                1,
                MODE_CONSENSUS_V1,
                &[0; 65],
                &mut output
            ),
            Err(ManifestRunError::InputLimit)
        );

        let binding = m.resolve_legacy_form(1, 22).unwrap();
        let input = [1u8, 2, 3];
        let claimed = 6u64.to_le_bytes();
        let spans = [
            AccountSpan {
                key: [4; 32],
                owner: [5; 32],
                is_signer: false,
                is_writable: false,
                schema: VersionedId { id: 1, version: 1 },
                offset: 0,
                data: &input,
            },
            AccountSpan {
                key: [4; 32],
                owner: [5; 32],
                is_signer: false,
                is_writable: false,
                schema: VersionedId { id: 2, version: 1 },
                offset: 3,
                data: &claimed,
            },
        ];
        assert_eq!(m.replay_legacy_form(binding, &spans), Ok(true));
        let bad_claim = 7u64.to_le_bytes();
        let mut bad_spans = spans;
        bad_spans[1].data = &bad_claim;
        assert_eq!(m.replay_legacy_form(binding, &bad_spans), Ok(false));

        let mut wrong_abi = *binding;
        wrong_abi.abi_version = 2;
        assert_eq!(
            m.replay_legacy_form(&wrong_abi, &spans),
            Err(ManifestRunError::KernelUnavailable)
        );
        let mut unknown_id = *binding;
        unknown_id.kernel_id = KernelId([0xFF; 16]);
        assert_eq!(
            m.replay_legacy_form(&unknown_id, &spans),
            Err(ManifestRunError::KernelUnavailable)
        );
        assert!(m.resolve_legacy_form(2, 22).is_none());

        #[cfg(feature = "sbf-real-lifecycle-test")]
        {
            let replay = m.resolve_legacy_form(1, 256).unwrap();
            assert_eq!(replay.kernel_id, BYTE_SUM.manifest().id);
            assert_eq!((replay.semantic_version, replay.abi_version), (1, 1));
            assert!(m.resolve_legacy_form(2, 256).is_none());
            assert_eq!(m.validate(), Ok(()));
        }
    }

    #[cfg(all(test, feature = "sbf-real-lifecycle-test"))]
    #[test]
    fn form_256_test_app_binding_uses_the_declared_zero_spans() {
        let binding = test_kernel::MANIFEST_APP.resolve_legacy_form(1, 256).unwrap();
        assert_eq!(binding.input_span_count, 1);
        assert_eq!(binding.spans.len(), 2);
        assert_eq!(
            (
                binding.spans[0].account_index,
                binding.spans[0].offset,
                binding.spans[0].length,
            ),
            (0, 184, 3)
        );
        assert_eq!(
            (
                binding.spans[1].account_index,
                binding.spans[1].offset,
                binding.spans[1].length,
            ),
            (2, 9, 8)
        );
    }

    #[test]
    fn closed_registry_bounds_inheritance_cycles_and_keeps_version_axes_independent() {
        let row = ClosedRegistryRow {
            machine_name: Some(b"base"),
            form_id: 7,
            geometry_bytes: 4,
            profile_bytes: 2,
            closure_execute: false,
            private_supply_freeze: false,
        };
        let rows = [row];
        let excluded: &'static [u16] = &[];
        let inheritance = [
            RegistryInheritance {
                machine_name: b"child",
                base_machine_name: b"base",
                excluded_forms: &excluded,
            },
            RegistryInheritance {
                machine_name: b"base",
                base_machine_name: b"child",
                excluded_forms: &excluded,
            },
        ];
        let registry = ClosedRegistryAdapter::new(&rows, &inheritance);
        assert_eq!(registry.resolve(b"child", 7), Some(&rows[0]));
        assert_eq!(registry.resolve(b"child", 8), None);
    }
}
