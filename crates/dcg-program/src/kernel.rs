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
pub trait OptimisticReplay: StatefulKernel {
    fn replay(
        &self,
        input: &[u8],
        prior_state: &[u8],
        claimed_output: &[u8],
        claimed_state: &[u8],
    ) -> Result<bool, KernelError>;
}

pub struct ApplicationManifest {
    pub application_id: &'static [u8],
    pub version: u16,
    pub kernels: &'static [&'static dyn Kernel],
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

    pub struct ByteSum;

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

    pub static BYTE_SUM: ByteSum = ByteSum;
    pub static KERNELS: [&'static dyn Kernel; 1] = [&BYTE_SUM];
    pub static MANIFEST_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-test-app/1",
        version: 1,
        kernels: &KERNELS,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-kernel")]
    #[test]
    fn static_application_manifest_resolves_exact_semantic_and_abi_versions() {
        use test_kernel::{ByteSum, MODE_CONSENSUS_V1};
        let m = &test_kernel::MANIFEST_APP;
        assert_eq!(m.validate(), Ok(()));
        let kernel = m.resolve(KernelId(*b"dcg-test-sum-v1\0"), 1, 1).unwrap();
        assert_eq!(kernel.manifest().id, ByteSum.manifest().id);
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
        assert!(m.supports_mode(ByteSum.manifest().id, 1, 1, MODE_CONSENSUS_V1));
        assert!(!m.supports_mode(ByteSum.manifest().id, 1, 2, MODE_CONSENSUS_V1));
        assert!(m.resolve(ByteSum.manifest().id, 2, 1).is_none());
        assert!(m.resolve(ByteSum.manifest().id, 1, 2).is_none());
        assert_eq!(
            m.execute(
                ByteSum.manifest().id,
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
                ByteSum.manifest().id,
                1,
                1,
                MODE_CONSENSUS_V1,
                &[0; 65],
                &mut output
            ),
            Err(ManifestRunError::InputLimit)
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
