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

/// Transaction ceiling minus the measured worst-case tag-184 adapter cost
/// and the configured safety margin. A replay kernel declaring more cannot
/// be selected for an admitted app-bound document.
pub const APP_REPLAY_MEASURED_OVERHEAD_CU: u64 = 45_573;
pub const APP_REPLAY_CU_MARGIN: u64 = 25_000;
pub const MAX_TRANSACTION_COMPUTE_UNITS: u64 = 1_400_000;
pub const MAX_DECLARED_KERNEL_COMPUTE_UNITS: u64 =
    MAX_TRANSACTION_COMPUTE_UNITS - APP_REPLAY_MEASURED_OVERHEAD_CU - APP_REPLAY_CU_MARGIN;

/// Behaviours a kernel promises beyond its ports and modes (design
/// `session-reject-and-ring-v1.md` §2.1). A bit set; unknown bits are refused
/// by `ApplicationManifest::validate`. Turning a bit on changes the kernel's
/// promised computation, so it is a semantic-version change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelCapabilities(pub u32);

impl KernelCapabilities {
    pub const NONE: Self = Self(0);
    /// The kernel may answer a well-formed stateful input with
    /// `TransitionDisposition::Reject`: the input is consumed and state is
    /// unchanged. Sessions and templates binding such a kernel are marked
    /// rejectable ahead of time.
    pub const REJECTS_INPUT: Self = Self(1);
    pub const KNOWN: u32 = Self::REJECTS_INPUT.0;

    pub const fn rejects_input(self) -> bool {
        self.0 & Self::REJECTS_INPUT.0 != 0
    }
}

/// Whether a 16-byte kernel id names a built-in v2.1 reduction or kernel
/// (`sumchunk_i32/v1`, `identity_i32/v1`, ... padded with NULs).
pub fn is_builtin_kernel_name(id: &[u8; 16]) -> bool {
    let end = id.iter().position(|b| *b == 0).unwrap_or(id.len());
    if id[end..].iter().any(|b| *b != 0) {
        return false;
    }
    let name = &id[..end];
    dcg_disputes::reductions::lookup(id).is_some()
        || (1..=255u16).any(|k| dcg_kernels::info(k).is_some_and(|i| i.name.as_bytes() == name))
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
    /// Declared capabilities (`KernelCapabilities::NONE` for most kernels).
    pub capabilities: KernelCapabilities,
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

/// Route selected for one replay input span. `offset..offset+length` is the
/// committed producer output slice that the witness input must open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayRouteBinding {
    pub ordinal: u16,
    pub offset: u32,
    pub length: u32,
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

/// One bounded capture call into a lane workspace (lanes §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanePhase {
    pub state_cursor: u32,
    pub lane: u8,
    pub offset: u32,
    pub len: u32,
    pub compute_units: u32,
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
/// `Reject` consumes the command without changing state or writing output; it
/// is allowed only for a kernel declaring `KernelCapabilities::REJECTS_INPUT`
/// in a session opened as rejectable, and refused otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionDisposition {
    Continue,
    HaltBefore { reason: u32 },
    HaltAfter { reason: u32 },
    Reject { code: u32 },
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
    /// Optional one-to-one route bindings for those inputs. A nonempty input
    /// list must bind every span to a plan route before replay can rule.
    pub input_routes: &'static [ReplayRouteBinding],
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
    /// Optional RWP1 producer-route opening carried after the output bytes.
    pub extension: &'a [u8],
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
        if count > Self::MAX_SPANS {
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
        if output_len == 0 || end > raw.len() {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        let extension = &raw[end..];
        if !extension.is_empty() && !extension.starts_with(b"RWP1") {
            return Err(ManifestRunError::InvalidSpanCount);
        }
        Ok(Self {
            raw,
            inputs,
            claimed_output: &raw[at..end],
            extension,
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

    /// An LX1 machine factory (design `v2.1-lazy-expansion.md` §8). Only
    /// kernels that are LX1 machines override this.
    #[cfg(feature = "graph-v21")]
    fn lx_machine(&self) -> Option<&dyn crate::disputes_v21::lx::LxFactory> {
        None
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

    /// Whether a view publication may keep its session-bound workspace bytes
    /// between BEGIN_PHASE and later publications. The default clears the
    /// payload at each begin. Kernels that preserve it must overwrite every
    /// byte they rely on before reading it in a new publication.
    fn clear_view_workspace_on_begin(&self) -> bool {
        true
    }

    /// Opt in to the additive RUN_PHASE account layout that places the
    /// writable workspace account first. This lets a fixed-address engine
    /// use the workspace as its invocation-local context while all committed
    /// state accounts remain read-only later in the account list.
    fn view_workspace_at_account_base(&self) -> bool {
        false
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

    /// Render when RUN_PHASE places the whole writable workspace account at
    /// the invocation's first-account address. `workspace_header` is the
    /// authenticated 128-byte DCG child header; `workspace` is its declared
    /// payload. The default preserves the ordinary resource/workspace API.
    /// An opted-in kernel may borrow the header temporarily, but must restore
    /// all DCG header bytes before returning. The processor checks the entire
    /// 128-byte header around every callback and refuses if any byte changed.
    fn render_view_phase_with_workspace_header(
        &self,
        phase: ViewPhase,
        state: &[AccountSpan<'_>],
        resources: &[AccountSpan<'_>],
        commitment: &[u8; 32],
        workspace_header: &mut [u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let _ = workspace_header;
        self.render_view_phase_with_resources(
            phase, state, resources, commitment, workspace, output,
        )
    }

    /// Lanes (design `stateful-session-lanes-v1.md` §10): the bytes one
    /// capture writes into a lane workspace. Zero (the default) disables
    /// lanes for this kernel.
    fn lane_capture_bytes(&self) -> u32 {
        0
    }

    /// Largest capture chunk per call; must be nonzero when lanes are enabled.
    fn lane_capture_phase_bytes(&self) -> u32 {
        0
    }

    /// Capture `[phase.offset, phase.offset + phase.len)` of the lane's
    /// workspace from the committed state at `phase.state_cursor`, writing
    /// every byte of that range and nothing outside it. The state cannot
    /// advance while a capture is open. The program zeroes the workspace past
    /// `lane_capture_bytes` at the first call, so a render may rely only on
    /// captured bytes, zeros, and what earlier render calls of the same
    /// publication wrote. The capture's compute is declared with
    /// `view_phase_compute_units`.
    fn capture_lane_phase(
        &self,
        _phase: LanePhase,
        _state: &[AccountSpan<'_>],
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        _workspace: &mut [u8],
    ) -> Result<(), KernelError> {
        Err(KernelError::Refused)
    }

    /// Render one bounded part of a view from a lane workspace alone: no
    /// state account is passed, because the state may already be at a later
    /// cursor. `workspace_header` is the lane workspace's 128-byte DCG header
    /// (the account is first, at the invocation's base address); the
    /// processor refuses if any header byte changes.
    fn render_lane_phase(
        &self,
        _phase: ViewPhase,
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        _workspace_header: &mut [u8],
        _workspace: &mut [u8],
        _output: &mut [u8],
    ) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
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
        if inputs.is_empty() && self.accepts_empty_input_spans() {
            return self.replay(&[], &[], claimed_output, &[]);
        }
        let [input] = inputs else {
            return Err(KernelError::InvalidInput);
        };
        if input.schema != self.replay_manifest().input.id {
            return Err(KernelError::InvalidInput);
        }
        self.replay(input.data, &[], claimed_output, &[])
    }

    /// Explicit opt-in for bindings with no input spans. The default
    /// `replay_input_spans` implementation requires exactly one span, so a
    /// replay that handles `[]` must override this capability alongside that
    /// method. Manifest validation refuses zero-span bindings otherwise.
    fn accepts_empty_input_spans(&self) -> bool {
        false
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

/// How revision 8's tag 160 admitted a class bound to an app kernel. Retired
/// with revision 8: no route reads it, but `Attested` still changes
/// `admission_identity_digest`. Removed in the next release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionScan {
    /// Every instance of the class is checked on chain for an opening the
    /// tag-184 adapter accepts. Cost grows with positions × bound classes.
    Full,
    /// The class is admitted on its registry checks alone; the sealed
    /// template is trusted to be openable and is verified off chain. A
    /// coordinate that cannot be opened rules a challenge neutral, so a lie
    /// there is not convicted. DEA2 records this with flag bit 2.
    Attested,
}

pub struct ApplicationManifest {
    pub application_id: &'static [u8],
    pub version: u16,
    pub kernels: &'static [&'static dyn Kernel],
    pub optimistic_replays: &'static [OptimisticReplayBinding],
    /// Retired with revision 8: must be empty (`validate` refuses a binding).
    /// Still committed by `admission_identity_digest`, so existing identities
    /// do not move. Removed in the next release.
    #[deprecated(note = "revision 8 is retired; leave empty")]
    pub legacy_forms: &'static [LegacyFormBinding],
    /// Retired with revision 8: must be false. Removed in the next release.
    #[deprecated(note = "revision 8 is retired; leave false")]
    pub require_legacy_form_binding: bool,
    /// Retired with revision 8 (tag 160's admission scan); no route reads it.
    /// An attested value still changes `admission_identity_digest`. Removed in
    /// the next release.
    #[deprecated(note = "revision 8 is retired; no route reads it")]
    pub admission_scan: AdmissionScan,
    /// Retired with revision 8; no route reads it. Removed in the next release.
    #[deprecated(note = "revision 8 is retired; no route reads it")]
    pub hooks: &'static dyn crate::compatibility::ApplicationHooks,
    /// Retired with revision 8; no route reads it. Removed in the next release.
    #[deprecated(note = "revision 8 is retired; no route reads it")]
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

    /// Stable app-image identity used by app-specific replay leaves and the
    /// versioned ruling record.
    pub fn identity_digest(&self) -> [u8; 32] {
        hash::sha256(&[
            b"dcg/application-manifest/1",
            self.application_id,
            &self.version.to_le_bytes(),
        ])
    }

    /// Identity frozen into app-bound DCM2 records at UnifiedInit. This also
    /// commits the static form-to-kernel table, so adding or removing a form
    /// after admission cannot silently switch a pending leaf to different
    /// replay semantics. Kernel implementation upgrades must increment either
    /// the app or kernel semantic version.
    pub fn admission_identity_digest(&self) -> [u8; 32] {
        let mut digest = hash::sha256(&[
            b"dcg/application-admission/1",
            &(self.application_id.len() as u32).to_le_bytes(),
            self.application_id,
            &self.version.to_le_bytes(),
            &[self.require_legacy_form_binding as u8],
            &(self.legacy_forms.len() as u32).to_le_bytes(),
        ]);
        for binding in self.legacy_forms {
            let selector = binding.machine_selector.unwrap_or(0);
            let selector_present = [binding.machine_selector.is_some() as u8];
            digest = hash::sha256(&[
                b"dcg/application-admission-form/1",
                &digest,
                &selector_present,
                &[selector],
                &binding.form_id.to_le_bytes(),
                &binding.kernel_id.0,
                &binding.semantic_version.to_le_bytes(),
                &binding.abi_version.to_le_bytes(),
                &binding.mode.id.to_le_bytes(),
                &binding.mode.version.to_le_bytes(),
                &binding.claimed_output_bytes.to_le_bytes(),
                &(binding.input_spans.len() as u32).to_le_bytes(),
            ]);
            for span in binding.input_spans {
                digest = hash::sha256(&[
                    b"dcg/application-admission-span/1",
                    &digest,
                    &span.schema.id.to_le_bytes(),
                    &span.schema.version.to_le_bytes(),
                    &span.max_bytes.to_le_bytes(),
                ]);
            }
            digest = hash::sha256(&[
                b"dcg/application-admission-routes/1",
                &digest,
                &(binding.input_routes.len() as u32).to_le_bytes(),
            ]);
            for route in binding.input_routes {
                digest = hash::sha256(&[
                    b"dcg/application-admission-route/1",
                    &digest,
                    &route.ordinal.to_le_bytes(),
                    &route.offset.to_le_bytes(),
                    &route.length.to_le_bytes(),
                ]);
            }
        }
        // A full-scan manifest keeps its historical digest; an attested one
        // commits that choice, so a document records which admission it had.
        if self.admission_scan == AdmissionScan::Attested {
            digest = hash::sha256(&[b"dcg/application-admission-attested/1", &digest]);
        }
        digest
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
            if is_builtin_kernel_name(&a.id.0) {
                return Err(ManifestError::BuiltinKernelCollision(a.id));
            }
            // Only stateful transitions can reject; a stateless (replay) kernel
            // with the bit would make the rev-8 admission digest silent about it.
            if a.capabilities.0 & !KernelCapabilities::KNOWN != 0
                || (a.capabilities.rejects_input() && a.state.is_none())
            {
                return Err(ManifestError::InvalidCapabilities(a.id));
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
        if self.application_id.is_empty() {
            return Err(ManifestError::MissingRequiredFormBindings);
        }
        // Revision-8 form bindings are retired: a manifest may not declare
        // or require them.
        if let Some(binding) = self.legacy_forms.first() {
            return Err(ManifestError::InvalidLegacyForm(binding.form_id));
        }
        if self.require_legacy_form_binding {
            return Err(ManifestError::MissingRequiredFormBindings);
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
    /// An unknown capability bit, or `REJECTS_INPUT` on a stateless kernel.
    InvalidCapabilities(KernelId),
    /// An application kernel whose id names a built-in reduction or kernel:
    /// the v2.1 STEP replay would resolve the built-in instead (R2 review A-M1).
    BuiltinKernelCollision(KernelId),
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

#[cfg(any(feature = "test-kernel", feature = "example-kernels"))]
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
            max_bytes: 256,
            alignment: 1,
        },
        state: None,
        resources: ResourceLimits {
            max_input_bytes: 64,
            max_output_bytes: 256,
            max_state_bytes: 0,
            max_operations: 64,
            max_compute_units: 10_000,
        },
        modes: &MODES,
        capabilities: crate::kernel::KernelCapabilities::NONE,
    };

    impl Kernel for ByteSum {
        fn manifest(&self) -> &'static KernelManifest {
            &MANIFEST
        }
        fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
            if input.len() > MANIFEST.resources.max_input_bytes as usize {
                return Err(KernelError::InputTooLarge);
            }
            if input.is_empty() {
                if output.len() < 256 {
                    return Err(KernelError::OutputTooSmall);
                }
                output[..256].fill(0);
                output[..3].copy_from_slice(&[1, 2, 3]);
                return Ok(256);
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
            if input.is_empty() {
                let mut expected = [0u8; 256];
                self.execute(input, &mut expected)?;
                return Ok(claimed_output == expected);
            }
            let mut expected = [0u8; 8];
            self.execute(input, &mut expected)?;
            Ok(claimed_output == expected)
        }

        fn replay_input_spans(
            &self,
            inputs: &[ReplayInputSpan<'_>],
            claimed_output: &[u8],
        ) -> Result<bool, KernelError> {
            match inputs {
                [] => self.replay(&[], &[], claimed_output, &[]),
                [input] if input.schema == MANIFEST.input.id => {
                    self.replay(input.data, &[], claimed_output, &[])
                }
                _ => Err(KernelError::InvalidInput),
            }
        }

        fn accepts_empty_input_spans(&self) -> bool {
            true
        }
    }

    /// SHA-256 over its input spans in order: a generic stand-in with the
    /// semantics of Basanos form 22 (`window_leaf`), so the v2.1 app-kernel
    /// replay path can be tested with real captured operands. Not optimistic
    /// in revision 8; tag 227 STEP resolves it by id and versions.
    pub struct Sha256Concat {
        _marker: u8,
    }

    static SHA_MANIFEST: KernelManifest = KernelManifest {
        id: KernelId(*b"dcg-test-sha-v1\0"),
        semantic_version: 1,
        abi_version: 1,
        input: PortLayout {
            id: VersionedId { id: 3, version: 1 },
            max_bytes: 65_536,
            alignment: 1,
        },
        output: PortLayout {
            id: VersionedId { id: 4, version: 1 },
            max_bytes: 32,
            alignment: 1,
        },
        state: None,
        resources: ResourceLimits {
            max_input_bytes: 65_536,
            max_output_bytes: 32,
            max_state_bytes: 0,
            max_operations: 1,
            max_compute_units: 100_000,
        },
        modes: &SHA_MODES,
        capabilities: crate::kernel::KernelCapabilities::NONE,
    };
    static SHA_MODES: [ModeId; 1] = [MODE_STEP_V21];

    impl Kernel for Sha256Concat {
        fn manifest(&self) -> &'static KernelManifest {
            &SHA_MANIFEST
        }
        fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
            self.execute_spans(
                &[AccountSpan {
                    key: [0; 32],
                    owner: [0; 32],
                    is_signer: false,
                    is_writable: false,
                    schema: SHA_MANIFEST.input.id,
                    offset: 0,
                    data: input,
                }],
                output,
            )
        }
        fn execute_spans(&self, inputs: &[AccountSpan<'_>], output: &mut [u8]) -> Result<usize, KernelError> {
            let total = inputs.iter().try_fold(0usize, |n, s| n.checked_add(s.data.len()));
            if inputs.is_empty() || total.is_none_or(|n| n == 0 || n > SHA_MANIFEST.resources.max_input_bytes as usize) {
                return Err(KernelError::InvalidInput);
            }
            if output.len() < 32 {
                return Err(KernelError::OutputTooSmall);
            }
            let parts: Vec<&[u8]> = inputs.iter().map(|s| s.data).collect();
            output[..32].copy_from_slice(&crate::hash::sha256(&parts));
            Ok(32)
        }
    }

    pub static SHA256_CONCAT: Sha256Concat = Sha256Concat { _marker: 0 };

    #[cfg(not(feature = "graph-v21"))]
    pub static KERNELS: [&'static dyn Kernel; 2] = [&BYTE_SUM, &SHA256_CONCAT];
    #[cfg(feature = "graph-v21")]
    pub static KERNELS: [&'static dyn Kernel; 3] =
        [&BYTE_SUM, &SHA256_CONCAT, &crate::disputes_v21::lx::toy::TOY_KERNEL];
    /// The alpha shared program's manifest: the example kernels only, with no
    /// replay or revision-8 form bindings (owner 10-05, R2 review B-M2).
    #[cfg(feature = "example-kernels")]
    pub static ALPHA_MANIFEST_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-alpha/1",
        version: 1,
        kernels: &KERNELS,
        optimistic_replays: &[],
        legacy_forms: &[],
        require_legacy_form_binding: false,
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };
    pub static REPLAY_BINDINGS: [OptimisticReplayBinding; 1] = [OptimisticReplayBinding {
        mode: MODE_OPTIMISTIC_V1,
        replay: &BYTE_SUM,
    }];
    pub static MANIFEST_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-test-app/1",
        version: 1,
        kernels: &KERNELS,
        optimistic_replays: &REPLAY_BINDINGS,
        legacy_forms: &[],
        require_legacy_form_binding: false,
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-kernel")]
    static ALIGNMENT_PROBE_MODE: ModeId = ModeId { id: 77, version: 1 };
    #[cfg(feature = "test-kernel")]
    static ALIGNMENT_PROBE_MANIFEST: KernelManifest = KernelManifest {
        id: KernelId([0xA7; 16]),
        semantic_version: 1,
        abi_version: 1,
        input: PortLayout {
            id: VersionedId { id: 1, version: 1 },
            max_bytes: 64,
            alignment: 4,
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
            max_operations: 1,
            max_compute_units: 10_000,
        },
        modes: &[ALIGNMENT_PROBE_MODE],
        capabilities: crate::kernel::KernelCapabilities::NONE,
    };
    #[cfg(feature = "test-kernel")]
    struct AlignmentProbe {
        accepts_empty: bool,
    }
    #[cfg(feature = "test-kernel")]
    impl Kernel for AlignmentProbe {
        fn manifest(&self) -> &'static KernelManifest {
            &ALIGNMENT_PROBE_MANIFEST
        }

        fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
            Ok(0)
        }
    }
    #[cfg(feature = "test-kernel")]
    impl OptimisticReplay for AlignmentProbe {
        fn replay_manifest(&self) -> &'static KernelManifest {
            &ALIGNMENT_PROBE_MANIFEST
        }

        fn replay(
            &self,
            input: &[u8],
            prior_state: &[u8],
            _claimed_output: &[u8],
            claimed_state: &[u8],
        ) -> Result<bool, KernelError> {
            Ok(input.is_empty() && prior_state.is_empty() && claimed_state.is_empty())
        }

        fn accepts_empty_input_spans(&self) -> bool {
            self.accepts_empty
        }
    }
    #[cfg(feature = "test-kernel")]
    static ALIGNMENT_PROBE: AlignmentProbe = AlignmentProbe {
        accepts_empty: false,
    };
    #[cfg(feature = "test-kernel")]
    static EMPTY_INPUT_PROBE: AlignmentProbe = AlignmentProbe {
        accepts_empty: true,
    };
    #[cfg(feature = "test-kernel")]
    static ALIGNMENT_PROBE_KERNELS: [&'static dyn Kernel; 1] = [&ALIGNMENT_PROBE];
    #[cfg(feature = "test-kernel")]
    static ALIGNMENT_PROBE_REPLAYS: [OptimisticReplayBinding; 1] = [OptimisticReplayBinding {
        mode: ALIGNMENT_PROBE_MODE,
        replay: &ALIGNMENT_PROBE,
    }];

    #[cfg(feature = "test-kernel")]
    static ZERO_INPUT_BINDING: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 701,
        kernel_id: KernelId([0xA7; 16]),
        semantic_version: 1,
        abi_version: 1,
        mode: ALIGNMENT_PROBE_MODE,
        input_spans: &[],
        input_routes: &[],
        claimed_output_bytes: 8,
    }];
    #[cfg(feature = "test-kernel")]
    static ZERO_INPUT_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-zero-span-test/1",
        version: 1,
        kernels: &ALIGNMENT_PROBE_KERNELS,
        optimistic_replays: &ALIGNMENT_PROBE_REPLAYS,
        legacy_forms: &ZERO_INPUT_BINDING,
        require_legacy_form_binding: true,
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

    #[cfg(feature = "test-kernel")]
    static ZERO_INPUT_APP_ATTESTED: ApplicationManifest = ApplicationManifest {
        admission_scan: AdmissionScan::Attested,
        ..ZERO_INPUT_APP_FIELDS
    };
    #[cfg(feature = "test-kernel")]
    const ZERO_INPUT_APP_FIELDS: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-zero-span-test/1",
        version: 1,
        kernels: &ALIGNMENT_PROBE_KERNELS,
        optimistic_replays: &ALIGNMENT_PROBE_REPLAYS,
        legacy_forms: &ZERO_INPUT_BINDING,
        require_legacy_form_binding: true,
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

    /// A full-scan manifest keeps the identity digest it had before
    /// `AdmissionScan` existed (pinned), and attested admission changes it.
    #[cfg(feature = "test-kernel")]
    #[test]
    fn attested_admission_is_part_of_the_identity() {
        let full = ZERO_INPUT_APP.admission_identity_digest();
        let hex: String = full.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "8ab3b659b49a5d1502c5f32010d47288fdb3a08ca3ca5df44813d53f93fb50cc");
        assert_eq!(full, ZERO_INPUT_APP_FIELDS.admission_identity_digest());
        assert_ne!(full, ZERO_INPUT_APP_ATTESTED.admission_identity_digest());
    }

    #[cfg(feature = "test-kernel")]
    static MISALIGNED_INPUT_SPANS: [ReplayInputLayout; 1] = [ReplayInputLayout {
        schema: VersionedId { id: 1, version: 1 },
        max_bytes: 64,
    }];
    #[cfg(feature = "test-kernel")]
    static MISALIGNED_INPUT_ROUTES: [ReplayRouteBinding; 1] = [ReplayRouteBinding {
        ordinal: 7,
        offset: 0,
        length: 3,
    }];
    #[cfg(feature = "test-kernel")]
    static MISALIGNED_INPUT_BINDING: [LegacyFormBinding; 1] = [LegacyFormBinding {
        machine_selector: Some(1),
        form_id: 702,
        kernel_id: KernelId([0xA7; 16]),
        semantic_version: 1,
        abi_version: 1,
        mode: ALIGNMENT_PROBE_MODE,
        input_spans: &MISALIGNED_INPUT_SPANS,
        input_routes: &MISALIGNED_INPUT_ROUTES,
        claimed_output_bytes: 8,
    }];
    #[cfg(feature = "test-kernel")]
    static MISALIGNED_INPUT_APP: ApplicationManifest = ApplicationManifest {
        application_id: b"dcg-misaligned-route-test/1",
        version: 1,
        kernels: &ALIGNMENT_PROBE_KERNELS,
        optimistic_replays: &ALIGNMENT_PROBE_REPLAYS,
        legacy_forms: &MISALIGNED_INPUT_BINDING,
        require_legacy_form_binding: true,
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

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
        capabilities: crate::kernel::KernelCapabilities::NONE,
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
        admission_scan: AdmissionScan::Full,
        hooks: &crate::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &crate::compatibility::REVISION8_COMPATIBILITY,
    };

    /// Capability bits (design session-reject-and-ring-v1 §2.1): an unknown
    /// bit, or REJECTS_INPUT on a stateless kernel, is refused.
    fn capability_app(caps: KernelCapabilities, stateful: bool) -> Result<(), ManifestError> {
        struct CapKernel(&'static KernelManifest);
        impl Kernel for CapKernel {
            fn manifest(&self) -> &'static KernelManifest {
                self.0
            }
            fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
                Err(KernelError::Refused)
            }
        }
        let manifest: &'static KernelManifest = Box::leak(Box::new(KernelManifest {
            id: KernelId([0xC4; 16]),
            resources: ResourceLimits { max_compute_units: 1_000, max_state_bytes: 0, ..INVALID_LIMIT_KERNEL_MANIFEST.resources },
            state: stateful.then_some(StateSchema { id: VersionedId { id: 3, version: 1 }, max_bytes: 16 }),
            capabilities: caps,
            ..INVALID_LIMIT_KERNEL_MANIFEST
        }));
        let kernels: &'static [&'static dyn Kernel] = Box::leak(Box::new([&*Box::leak(Box::new(CapKernel(manifest))) as &dyn Kernel]));
        ApplicationManifest { kernels, ..INVALID_LIMIT_APP }.validate()
    }

    #[cfg(feature = "example-kernels")]
    #[test]
    fn the_alpha_manifest_validates() {
        assert_eq!(test_kernel::ALPHA_MANIFEST_APP.validate(), Ok(()));
    }

    #[test]
    fn manifest_refuses_app_kernels_named_like_builtins() {
        static BUILTIN_NAMED: KernelManifest = KernelManifest {
            id: KernelId(*b"identity_i32/v1\0"),
            ..INVALID_LIMIT_KERNEL_MANIFEST
        };
        struct Named;
        impl Kernel for Named {
            fn manifest(&self) -> &'static KernelManifest {
                &BUILTIN_NAMED
            }
            fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
                Err(KernelError::Refused)
            }
        }
        static KERNELS: [&dyn Kernel; 1] = [&Named];
        let app = ApplicationManifest { kernels: &KERNELS, ..INVALID_LIMIT_APP };
        assert_eq!(app.validate(), Err(ManifestError::BuiltinKernelCollision(KernelId(*b"identity_i32/v1\0"))));
        assert!(is_builtin_kernel_name(b"sumchunk_i32/v1\0"));
        assert!(!is_builtin_kernel_name(b"dcg-counter-v1\0\0"));
    }

    #[test]
    fn manifest_checks_capability_bits() {
        let id = KernelId([0xC4; 16]);
        assert_eq!(capability_app(KernelCapabilities::NONE, false), Ok(()));
        assert_eq!(capability_app(KernelCapabilities::REJECTS_INPUT, true), Ok(()));
        assert_eq!(capability_app(KernelCapabilities::REJECTS_INPUT, false), Err(ManifestError::InvalidCapabilities(id)));
        assert_eq!(capability_app(KernelCapabilities(2), true), Err(ManifestError::InvalidCapabilities(id)));
    }

    #[test]
    fn manifest_rejects_over_budget_kernel_compute_declarations() {
        assert_eq!(
            INVALID_LIMIT_APP.validate(),
            Err(ManifestError::InvalidComputeLimit(INVALID_LIMIT_ID))
        );
    }

    #[cfg(feature = "test-kernel")]
    #[test]
    fn manifest_refuses_retired_legacy_form_bindings() {
        // Revision 8 is retired: any legacy form binding, or requiring one,
        // is refused.
        assert_eq!(
            ZERO_INPUT_APP.validate(),
            Err(ManifestError::InvalidLegacyForm(701))
        );
        assert_eq!(
            MISALIGNED_INPUT_APP.validate(),
            Err(ManifestError::InvalidLegacyForm(702))
        );
        let requires = ApplicationManifest {
            legacy_forms: &[],
            ..ZERO_INPUT_APP
        };
        assert_eq!(requires.validate(), Err(ManifestError::MissingRequiredFormBindings));
        assert_eq!(test_kernel::MANIFEST_APP.validate(), Ok(()));
    }

    #[cfg(feature = "test-kernel")]
    #[test]
    fn default_empty_input_replay_calls_kernel_with_empty_bytes() {
        assert!(EMPTY_INPUT_PROBE
            .replay_input_spans(&[], &[])
            .expect("the opt-in default adapter replays empty bytes"));
        assert_eq!(
            ALIGNMENT_PROBE.replay_input_spans(&[], &[]),
            Err(KernelError::InvalidInput),
            "an empty-input kernel without the opt-in still refuses"
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
            admission_scan: AdmissionScan::Full,
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
        let kernel = m.resolve(KernelId(*b"dcg-test-sum-v1\0"), 1, 1).unwrap();
        assert_eq!(kernel.manifest().id, BYTE_SUM.manifest().id);
        let mut output = [0u8; 256];
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
        assert_eq!(u64::from_le_bytes(output[..8].try_into().unwrap()), 256);
        assert_eq!(
            m.resolve_optimistic_replay(BYTE_SUM.manifest().id, 1, 1, MODE_OPTIMISTIC_V1)
                .unwrap()
                .replay
                .replay(&[1, 2, 3, 250], &[], &output[..8], &[]),
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
    }
}

// Kept at the end of the file: items added for feature-gated code must not
// shift the line numbers (panic locations) of code in the default image.
/// The mode a kernel advertises to replay a DCG v2.1 STEP claim (tag 227):
/// `"STEP"`, version 1. A manifest kernel without it is not a STEP kernel.
pub const MODE_STEP_V21: ModeId = VersionedId { id: 0x5354_4550, version: 1 };
