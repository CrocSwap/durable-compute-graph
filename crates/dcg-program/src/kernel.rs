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

/// Highest compute budget a single kernel invocation may declare for the
/// current SVM transaction profile. Multi-step callers multiply this checked
/// ceiling by their declared operation count before starting a transition.
pub const MAX_DECLARED_KERNEL_COMPUTE_UNITS: u64 = 1_400_000;

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

/// One input slice opened from a challenged ROOT_ONLY leaf preimage. The leaf
/// digest and its position proof authenticate these bytes before replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayInputSpan<'a> {
    pub schema: VersionedId,
    pub data: &'a [u8],
}

/// App-declared input slice ABI for one replay witness. Its bytes come from
/// the disputed leaf preimage, not fixed template offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayInputLayout {
    pub schema: VersionedId,
    pub max_bytes: u32,
}

/// A mutable, invocation-local state region authenticated by the stateful SVM
/// adapter. `data` borrows account bytes for this call; the borrow is never
/// serialized into an engine-state account.
#[derive(Debug)]
pub struct StateSpanMut<'a> {
    pub key: [u8; 32],
    pub owner: [u8; 32],
    pub schema: VersionedId,
    /// Offset in the kernel's canonical state byte string.
    pub offset: u32,
    pub data: &'a mut [u8],
}

impl StateSpanMut<'_> {
    /// Address of the first engine byte in this span. The adapter constructs
    /// `data` after removing its account header, so this is the actual
    /// invocation-local span address. Kernels may bind it for the duration of
    /// a callback, but must never serialize or retain it after that callback.
    pub fn data_address(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

/// A bounded publication phase over one declared output view. `source_offset`
/// is in the canonical state byte string; `output_offset` is in this view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewPhase {
    pub state_cursor: u32,
    pub role: u8,
    pub source_offset: u32,
    pub output_offset: u32,
    pub compute_units: u32,
}

/// Result of one stateful v3 transition callback. `HaltBefore` leaves the
/// current command unconsumed and requires the kernel to leave state unchanged.
/// `HaltAfter` commits the current command's state and consumes that command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionDisposition {
    Continue,
    HaltBefore { reason: u32 },
    HaltAfter { reason: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionOutcome {
    pub output_bytes: usize,
    pub disposition: TransitionDisposition,
}

/// Bounded, resumable initialization of a canonical state value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializationPhase {
    pub cursor: u32,
    pub total_bytes: u32,
    pub compute_units: u32,
}

/// A statically bound, versioned output ABI that a stateful application may
/// expose as a view. `role` is application data, while the view's wire role
/// and lifetime are enforced by the DCG adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewAbi {
    pub role: u8,
    pub id: [u8; 32],
    pub max_bytes: u32,
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
    /// Coordinate-specific inputs opened from the challenged leaf preimage.
    pub input_spans: &'static [ReplayInputLayout],
    /// Exact output width required by this form/kernel ABI.
    pub claimed_output_bytes: u16,
}

/// App-owned preimage carried alongside a challenged ROOT_ONLY leaf digest.
/// Wire: `ARW1 | version:u16=1 | span_count:u8 | 0 | output_len:u16 | 0:u16`,
/// then `schema_id:u32 | schema_version:u16 | length:u16 | bytes` per span,
/// then exactly `output_len` claimed-output bytes.
pub struct CommittedReplayWitness<'a> {
    pub raw: &'a [u8],
    pub inputs: Vec<ReplayInputSpan<'a>>,
    pub claimed_output: &'a [u8],
}

impl<'a> CommittedReplayWitness<'a> {
    pub const HEADER_BYTES: usize = 12;
    pub const SPAN_HEADER_BYTES: usize = 8;
    pub const MAX_SPANS: usize = 16;
    pub const MAX_WITNESS_BYTES: usize = 900;

    pub fn decode(raw: &'a [u8]) -> Result<Self, ManifestRunError> {
        if raw.len() < Self::HEADER_BYTES
            || raw.len() > Self::MAX_WITNESS_BYTES
            || raw[..4] != *b"ARW1"
            || u16::from_le_bytes([raw[4], raw[5]]) != 1
            || raw[7] != 0
            || raw[10..12] != [0; 2]
        {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        let count = raw[6] as usize;
        if count == 0 || count > Self::MAX_SPANS {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        let output_len = u16::from_le_bytes([raw[8], raw[9]]) as usize;
        let mut at = Self::HEADER_BYTES;
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let end = at
                .checked_add(Self::SPAN_HEADER_BYTES)
                .ok_or(ManifestRunError::InvalidSpanCount)?;
            let header = raw.get(at..end).ok_or(ManifestRunError::InvalidSpanCount)?;
            let schema = VersionedId {
                id: u32::from_le_bytes(header[0..4].try_into().unwrap()),
                version: u16::from_le_bytes(header[4..6].try_into().unwrap()),
            };
            let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            if len == 0 {
                return Err(ManifestRunError::SpanSchema);
            }
            let end = end
                .checked_add(len)
                .ok_or(ManifestRunError::InvalidSpanCount)?;
            let bytes = raw
                .get(at + Self::SPAN_HEADER_BYTES..end)
                .ok_or(ManifestRunError::InvalidSpanCount)?;
            inputs.push(ReplayInputSpan {
                schema,
                data: bytes,
            });
            at = end;
        }
        let end = at
            .checked_add(output_len)
            .ok_or(ManifestRunError::InvalidSpanCount)?;
        if output_len == 0 || end != raw.len() {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        Ok(Self {
            raw,
            inputs,
            claimed_output: &raw[at..end],
        })
    }
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

    /// Initialise a canonical state value split over authenticated account
    /// spans. Large stateful kernels override this method to write in place
    /// without flattening the state into a temporary allocation. The account
    /// data borrows are invocation-local and are rolled back by the SVM
    /// transaction if any later step refuses.
    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        let _ = spans;
        Err(KernelError::Refused)
    }

    /// Initialise state from the resource accounts committed by the session
    /// authority. The adapter authenticates the account keys and passes the
    /// committed schema and digest. The application kernel must validate the
    /// resource bytes against `commitment` (or validate its own bounded
    /// inclusion proof) before using them. The default accepts only sessions
    /// with no external resource.
    fn initial_state_spans_with_resources(
        &self,
        resources: &[AccountSpan<'_>],
        commitment: &[u8; 32],
        spans: &mut [StateSpanMut<'_>],
    ) -> Result<usize, KernelError> {
        if !resources.is_empty() || *commitment != [0; 32] {
            return Err(KernelError::Refused);
        }
        self.initial_state_spans(spans)
    }

    /// Maximum bytes staged by one deterministic view-publication phase.
    /// Returning zero disables phased publication for this kernel.
    fn max_view_phase_bytes(&self) -> u32 {
        0
    }

    /// Static compute declaration required on every phase instruction. It is
    /// checked against the SVM transaction ceiling; it is not a CU estimate.
    fn view_phase_compute_units(&self) -> u32 {
        0
    }

    /// Render one bounded part of a view into invocation-local output bytes.
    /// The adapter supplies authenticated state slices and the view ABI/range.
    /// The default implementation copies that range from canonical state.
    fn render_view_phase(
        &self,
        phase: ViewPhase,
        state: &[AccountSpan<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let start = phase
            .source_offset
            .checked_add(phase.output_offset)
            .ok_or(KernelError::InvalidInput)?;
        let end = start
            .checked_add(output.len() as u32)
            .ok_or(KernelError::InvalidInput)?;
        let mut copied = 0usize;
        for span in state {
            let span_end = span
                .offset
                .checked_add(span.data.len() as u32)
                .ok_or(KernelError::InvalidInput)?;
            let from = start.max(span.offset);
            let to = end.min(span_end);
            if from >= to {
                continue;
            }
            let source = (from - span.offset) as usize;
            let target = (from - start) as usize;
            let len = (to - from) as usize;
            output[target..target + len].copy_from_slice(&span.data[source..source + len]);
            copied += len;
        }
        if copied != output.len() {
            return Err(KernelError::InvalidInput);
        }
        Ok(copied)
    }

    /// Bind invocation-local engine state immediately before state callbacks.
    /// A C adapter can use `StateSpanMut::data_address()` here to rebind its
    /// context pointer; the address excludes the DCG account header.
    fn bind_invocation_state(&self, _spans: &mut [StateSpanMut<'_>]) -> Result<(), KernelError> {
        Ok(())
    }

    /// Clear any pointer installed by `bind_invocation_state` after the
    /// callback. No pointer may be stored in a committed account.
    fn unbind_invocation_state(&self) {}

    /// Apply one deterministic transition to a versioned, split state. A
    /// caller may invoke this at most `manifest().resources.max_operations`
    /// times in one transaction. The runtime persists the bytes atomically
    /// with the cursor update.
    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let _ = (input, state, output);
        Err(KernelError::Refused)
    }

    /// Stateful wire v3 transition hook. Existing kernels keep v2 behavior
    /// through this default adapter. A halt result commits the prefix ending
    /// at the callback's declared boundary and records its reason atomically.
    fn transition_spans_with_outcome(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        self.transition_spans(input, state, output)
            .map(|output_bytes| TransitionOutcome {
                output_bytes,
                disposition: TransitionDisposition::Continue,
            })
    }

    /// Largest deterministic state-initialization chunk accepted per call.
    fn max_initialization_phase_bytes(&self) -> u32 {
        65_536
    }

    /// Static CU declaration required on phased initialization calls.
    fn initialization_phase_compute_units(&self) -> u32 {
        self.manifest().resources.max_compute_units as u32
    }

    /// Write the exact logical state byte range beginning at `phase.cursor`.
    /// The callback must use only session-authenticated resources and must
    /// write exactly `min(max_initialization_phase_bytes, remaining)` bytes.
    fn initialize_state_phase(
        &self,
        _phase: InitializationPhase,
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        _state: &mut [StateSpanMut<'_>],
    ) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }

    /// Maximum declared mutable renderer workspace. Zero disables v3 view
    /// rendering for this kernel.
    fn max_view_workspace_bytes(&self) -> u32 {
        0
    }

    /// Render with the session's read-only authenticated resources and its
    /// declared writable workspace. The default retains resource-free v2
    /// rendering behavior.
    fn render_view_phase_with_resources(
        &self,
        phase: ViewPhase,
        state: &[AccountSpan<'_>],
        resources: &[AccountSpan<'_>],
        commitment: &[u8; 32],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        if !resources.is_empty() || *commitment != [0; 32] || !workspace.is_empty() {
            return Err(KernelError::Refused);
        }
        self.render_view_phase(phase, state, output)
    }

    /// The output ABIs this application image permits for state views.
    /// Unknown ABI ids are refused when a view account is declared.
    fn view_abis(&self) -> &'static [ViewAbi] {
        &[]
    }
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

    /// Replay coordinate-specific inputs opened from a challenged ROOT_ONLY
    /// leaf preimage. Multi-span applications may override this method.
    fn replay_input_spans(
        &self,
        inputs: &[ReplayInputSpan<'_>],
        claimed_output: &[u8],
    ) -> Result<bool, KernelError> {
        let [input] = inputs else {
            return Err(KernelError::InvalidInput);
        };
        if input.schema != self.replay_manifest().input.id {
            return Err(KernelError::InvalidInput);
        }
        self.replay(input.data, &[], claimed_output, &[])
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
    /// than handled by the historical profile adapter. Admission checks this
    /// before a document can rely on the mapping.
    pub require_legacy_form_binding: bool,
    /// App-selected revision-8 policy hooks.
    pub hooks: &'static dyn crate::compatibility::ApplicationHooks,
    /// App-selected typed-decision route producer. Kept as a separate trait
    /// object so the pinned SBF Rust toolchain does not need trait upcasting.
    pub decision_routes: &'static dyn crate::compatibility::DecisionRouteSelector,
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

    /// Whether admission may rely on the app binding for this machine/form
    /// pair. Required mappings fail closed when the registry has no machine
    /// selector or the app did not bind the selected form.
    pub fn admits_legacy_form(&self, machine_selector: Option<u8>, form_id: u16) -> bool {
        !self.require_legacy_form_binding
            || machine_selector
                .is_some_and(|machine| self.resolve_legacy_form(machine, form_id).is_some())
    }

    /// Re-execute a historical form only through the exact identity and mode
    /// selected by this app's static manifest. Inputs and output are opened
    /// from the coordinate-specific ROOT_ONLY leaf preimage.
    pub fn replay_legacy_form(
        &self,
        binding: &LegacyFormBinding,
        inputs: &[ReplayInputSpan<'_>],
        claimed_output: &[u8],
    ) -> Result<bool, ManifestRunError> {
        if binding.input_spans.is_empty() || inputs.len() != binding.input_spans.len() {
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
        if manifest.input.alignment == 0 || manifest.output.alignment == 0 {
            return Err(ManifestRunError::InputAlignment);
        }
        let input_limit =
            (manifest.input.max_bytes as usize).min(manifest.resources.max_input_bytes as usize);
        let mut total_input = 0usize;
        for (layout, span) in binding.input_spans.iter().zip(inputs) {
            if span.schema != layout.schema
                || span.schema != manifest.input.id
                || span.data.is_empty()
                || span.data.len() > layout.max_bytes as usize
            {
                return Err(ManifestRunError::InvalidCommittedInput);
            }
            if span.data.len() % manifest.input.alignment as usize != 0 {
                return Err(ManifestRunError::InvalidCommittedInput);
            }
            total_input = total_input
                .checked_add(span.data.len())
                .ok_or(ManifestRunError::InputLimit)?;
        }
        if total_input > input_limit {
            return Err(ManifestRunError::InvalidCommittedInput);
        }
        let output_limit =
            (manifest.output.max_bytes as usize).min(manifest.resources.max_output_bytes as usize);
        if claimed_output.len() != binding.claimed_output_bytes as usize
            || claimed_output.len() > output_limit
        {
            return Err(ManifestRunError::ClaimedOutputLength);
        }
        replay
            .replay
            .replay_input_spans(inputs, claimed_output)
            .map_err(ManifestRunError::Kernel)
    }

    /// Stable app-image identity used by app-specific replay leaves and the
    /// versioned ruling record.
    pub fn identity_digest(&self) -> [u8; 32] {
        hash::sha256(&[
            b"dcg/application-manifest/1",
            self.application_id,
            &self.version.to_le_bytes(),
        ])
    }

    /// 64-byte ARI1 identity written only to the new app-replay DCR1 record
    /// version. Revision-8 DCR1 v5 bytes remain untouched on the compatibility
    /// path.
    pub fn ruling_identity(&self, binding: &LegacyFormBinding) -> [u8; 64] {
        let mut out = [0; 64];
        out[..4].copy_from_slice(b"ARI1");
        out[4..36].copy_from_slice(&self.identity_digest());
        out[36..52].copy_from_slice(&binding.kernel_id.0);
        out[52..54].copy_from_slice(&binding.semantic_version.to_le_bytes());
        out[54..56].copy_from_slice(&binding.abi_version.to_le_bytes());
        out[56..60].copy_from_slice(&binding.mode.id.to_le_bytes());
        out[60..62].copy_from_slice(&binding.mode.version.to_le_bytes());
        out[62..64].copy_from_slice(&binding.form_id.to_le_bytes());
        out
    }

    /// App-specific leaf commitment for the exact coordinate and canonical
    /// witness. The enclosing revision-8 ROOT_ONLY segment/position proofs
    /// commit this digest into the document's landed position root.
    pub fn replay_leaf_digest(
        &self,
        binding: &LegacyFormBinding,
        descriptor: &[u8; 32],
        position: u32,
        segment: u16,
        local: u32,
        witness: &[u8],
    ) -> [u8; 32] {
        let mut coordinate = [0; 10];
        coordinate[..4].copy_from_slice(&position.to_le_bytes());
        coordinate[4..6].copy_from_slice(&segment.to_le_bytes());
        coordinate[6..].copy_from_slice(&local.to_le_bytes());
        let identity = self.ruling_identity(binding);
        crate::closure_v2::hash(
            b"app-replay-leaf/1",
            &[descriptor, &coordinate, &identity[4..], witness],
        )
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
                if a.id == b.id {
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
            if a.resources.max_operations == 0
                || a.resources.max_compute_units == 0
                || a.resources.max_compute_units > MAX_DECLARED_KERNEL_COMPUTE_UNITS
            {
                return Err(ManifestError::InvalidComputeLimit(a.id));
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
        if self.application_id.is_empty()
            || (self.require_legacy_form_binding && self.legacy_forms.is_empty())
        {
            return Err(ManifestError::MissingRequiredFormBindings);
        }
        for (i, binding) in self.legacy_forms.iter().enumerate() {
            if binding.form_id == 0
                || binding.input_spans.is_empty()
                || binding.claimed_output_bytes == 0
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
            let input_limit = (kernel_manifest.input.max_bytes as usize)
                .min(kernel_manifest.resources.max_input_bytes as usize);
            let output_limit = (kernel_manifest.output.max_bytes as usize)
                .min(kernel_manifest.resources.max_output_bytes as usize);
            if binding.claimed_output_bytes as usize > output_limit
                || binding.input_spans.iter().any(|span| {
                    span.schema != kernel_manifest.input.id
                        || span.max_bytes == 0
                        || span.max_bytes as usize > input_limit
                })
            {
                return Err(ManifestError::InvalidLegacyForm(binding.form_id));
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
    InvalidComputeLimit(KernelId),
    DuplicateMode(KernelId, ModeId),
    ReplayNotRegistered(KernelId),
    ReplayModeUnsupported(KernelId, ModeId),
    DuplicateReplay(KernelId, ModeId),
    InvalidLegacyForm(u16),
    DuplicateLegacyForm(u16),
    LegacyKernelUnavailable(u16),
    LegacyModeUnsupported(u16),
    MissingRequiredFormBindings,
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
    InvalidCommittedInput,
    ClaimedOutputLength,
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
    pub static BYTE_SUM_INPUTS: [ReplayInputLayout; 1] = [ReplayInputLayout {
        schema: VersionedId { id: 1, version: 1 },
        max_bytes: 64,
    }];
    pub static BYTE_SUM_LEGACY_FORMS: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 22,
        kernel_id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        mode: MODE_OPTIMISTIC_V1,
        input_spans: &BYTE_SUM_INPUTS,
        claimed_output_bytes: 8,
    }];
    #[cfg(feature = "sbf-real-lifecycle-test")]
    pub static BYTE_SUM_FORM_256_BINDING: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 256,
        kernel_id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        mode: MODE_OPTIMISTIC_V1,
        input_spans: &BYTE_SUM_INPUTS,
        claimed_output_bytes: 8,
    }];
    #[cfg(feature = "sbf-real-lifecycle-test")]
    pub static BYTE_SUM_REAL_LIFECYCLE_FORMS: [LegacyFormBinding; 2] =
        [BYTE_SUM_LEGACY_FORMS[0], BYTE_SUM_FORM_256_BINDING[0]];
    #[cfg(feature = "sbf-unbound-form-test")]
    pub static BYTE_SUM_UNBOUND_FORM_TEST: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: u16::MAX,
        kernel_id: KernelId(*b"dcg-test-sum-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        mode: MODE_OPTIMISTIC_V1,
        input_spans: &BYTE_SUM_INPUTS,
        claimed_output_bytes: 8,
    }];
    pub static MANIFEST_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-test-app/1",
        version: 1,
        kernels: &KERNELS,
        optimistic_replays: &REPLAY_BINDINGS,
        #[cfg(feature = "sbf-unbound-form-test")]
        legacy_forms: &BYTE_SUM_UNBOUND_FORM_TEST,
        #[cfg(all(
            feature = "sbf-real-lifecycle-test",
            not(feature = "sbf-unbound-form-test")
        ))]
        legacy_forms: &BYTE_SUM_REAL_LIFECYCLE_FORMS,
        #[cfg(all(
            not(feature = "sbf-real-lifecycle-test"),
            not(feature = "sbf-unbound-form-test")
        ))]
        legacy_forms: &BYTE_SUM_LEGACY_FORMS,
        require_legacy_form_binding: true,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVALID_LIMIT_ID: KernelId = KernelId([0xB7; 16]);
    static INVALID_LIMIT_MODES: [ModeId; 1] = [ModeId { id: 1, version: 1 }];
    static INVALID_LIMIT_KERNEL_MANIFEST: KernelManifest = KernelManifest {
        id: INVALID_LIMIT_ID,
        semantic_version: 1,
        abi_version: 1,
        input: PortLayout {
            id: VersionedId { id: 1, version: 1 },
            max_bytes: 1,
            alignment: 1,
        },
        output: PortLayout {
            id: VersionedId { id: 2, version: 1 },
            max_bytes: 1,
            alignment: 1,
        },
        state: None,
        resources: ResourceLimits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_state_bytes: 0,
            max_operations: 1,
            max_compute_units: MAX_DECLARED_KERNEL_COMPUTE_UNITS + 1,
        },
        modes: &INVALID_LIMIT_MODES,
    };
    struct InvalidLimitKernel;
    impl Kernel for InvalidLimitKernel {
        fn manifest(&self) -> &'static KernelManifest {
            &INVALID_LIMIT_KERNEL_MANIFEST
        }

        fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
            Err(KernelError::Refused)
        }
    }
    static INVALID_LIMIT_KERNELS: [&dyn Kernel; 1] = [&InvalidLimitKernel];
    static INVALID_LIMIT_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-invalid-limit-test/1",
        version: 1,
        kernels: &INVALID_LIMIT_KERNELS,
        optimistic_replays: &[],
        legacy_forms: &[],
        require_legacy_form_binding: false,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

    #[test]
    fn manifest_rejects_over_budget_kernel_compute_declarations() {
        assert_eq!(
            INVALID_LIMIT_APP.validate(),
            Err(ManifestError::InvalidComputeLimit(INVALID_LIMIT_ID))
        );
    }

    #[cfg(feature = "test-kernel")]
    #[test]
    fn manifest_rejects_duplicate_kernel_ids() {
        static DUPLICATE_KERNELS: [&'static dyn Kernel; 2] =
            [&test_kernel::BYTE_SUM, &test_kernel::BYTE_SUM];
        static DUPLICATE_APP: ApplicationManifest = ApplicationManifest {
            application_id: b"dcg-duplicate-kernel-test/1",
            version: 1,
            kernels: &DUPLICATE_KERNELS,
            optimistic_replays: &[],
            legacy_forms: &[],
            require_legacy_form_binding: false,
            hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
            decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
        };
        assert_eq!(
            DUPLICATE_APP.validate(),
            Err(ManifestError::DuplicateKernel(
                test_kernel::BYTE_SUM.manifest().id
            ))
        );
    }

    #[cfg(feature = "test-kernel")]
    #[test]
    fn static_application_manifest_resolves_exact_semantic_and_abi_versions() {
        use test_kernel::{BYTE_SUM, MODE_CONSENSUS_V1, MODE_OPTIMISTIC_V1};
        let m = &test_kernel::MANIFEST_APP;
        assert_eq!(m.validate(), Ok(()));
        #[cfg(not(feature = "sbf-unbound-form-test"))]
        assert!(m.admits_legacy_form(Some(1), 256));
        #[cfg(not(feature = "sbf-unbound-form-test"))]
        assert!(!m.admits_legacy_form(Some(1), 257));
        #[cfg(not(feature = "sbf-unbound-form-test"))]
        assert!(!m.admits_legacy_form(None, 256));
        #[cfg(feature = "sbf-unbound-form-test")]
        {
            assert!(!m.admits_legacy_form(Some(1), 22));
            assert!(!m.admits_legacy_form(Some(1), 256));
            assert!(m.admits_legacy_form(Some(1), u16::MAX));
        }
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
        assert!(m.resolve(KernelId(*b"dcg-missing-v1\0\0"), 1, 1).is_none());
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

        #[cfg(not(feature = "sbf-unbound-form-test"))]
        let binding = m.resolve_legacy_form(1, 22).unwrap();
        #[cfg(feature = "sbf-unbound-form-test")]
        let binding = &test_kernel::BYTE_SUM_LEGACY_FORMS[0];
        let input = [1u8, 2, 3];
        let claimed = 6u64.to_le_bytes();
        let inputs = [ReplayInputSpan {
            schema: VersionedId { id: 1, version: 1 },
            data: &input,
        }];
        assert_eq!(m.replay_legacy_form(binding, &inputs, &claimed), Ok(true));
        let bad_claim = 7u64.to_le_bytes();
        assert_eq!(
            m.replay_legacy_form(binding, &inputs, &bad_claim),
            Ok(false)
        );

        let mut wrong_abi = *binding;
        wrong_abi.abi_version = 2;
        assert_eq!(
            m.replay_legacy_form(&wrong_abi, &inputs, &claimed),
            Err(ManifestRunError::KernelUnavailable)
        );
        let mut unknown_id = *binding;
        unknown_id.kernel_id = KernelId([0xFF; 16]);
        assert_eq!(
            m.replay_legacy_form(&unknown_id, &inputs, &claimed),
            Err(ManifestRunError::KernelUnavailable)
        );
        assert!(m.resolve_legacy_form(2, 22).is_none());

        #[cfg(all(
            feature = "sbf-real-lifecycle-test",
            not(feature = "sbf-unbound-form-test")
        ))]
        {
            let replay = m.resolve_legacy_form(1, 256).unwrap();
            assert_eq!(replay.kernel_id, BYTE_SUM.manifest().id);
            assert_eq!((replay.semantic_version, replay.abi_version), (1, 1));
            assert!(m.resolve_legacy_form(2, 256).is_none());
            assert_eq!(m.validate(), Ok(()));
        }
    }

    #[cfg(all(
        test,
        feature = "sbf-real-lifecycle-test",
        not(feature = "sbf-unbound-form-test")
    ))]
    #[test]
    fn form_256_test_app_binding_uses_coordinate_leaf_inputs() {
        let binding = test_kernel::MANIFEST_APP
            .resolve_legacy_form(1, 256)
            .unwrap();
        assert_eq!(binding.input_spans.len(), 1);
        assert_eq!(
            binding.input_spans[0].schema,
            VersionedId { id: 1, version: 1 }
        );
        assert_eq!(binding.input_spans[0].max_bytes, 64);
        assert_eq!(binding.claimed_output_bytes, 8);
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
