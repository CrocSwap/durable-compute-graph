// SPDX-License-Identifier: GPL-3.0-only

//! Small statically linked application kernel for the stateful SBF mechanics
//! test. It is a two-value counter, not a Doom or model adapter.

use crate::{
    kernel::{
        AccountSpan, InitializationPhase, Kernel, KernelError, KernelId, KernelManifest,
        PortLayout, ResourceLimits, StateSchema, StateSpanMut, StatefulKernel,
        TransitionDisposition, TransitionOutcome, VersionedId, ViewAbi, ViewPhase,
        MAX_DECLARED_KERNEL_COMPUTE_UNITS,
    },
    stateful,
    stateful::v2 as stateful_v2,
};
use core::sync::atomic::{AtomicPtr, Ordering};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

pub const COUNTER_SCHEMA: VersionedId = VersionedId {
    id: 0x434e_5452,
    version: 1,
};
pub const VALUE_VIEW_ABI: [u8; 32] = [0x41; 32];
pub const TOTAL_VIEW_ABI: [u8; 32] = [0x42; 32];
const INPUT_LAYOUT: VersionedId = VersionedId {
    id: 0x494e_5054,
    version: 1,
};
const OUTPUT_LAYOUT: VersionedId = VersionedId {
    id: 0x4f55_5450,
    version: 1,
};
const CONSENSUS_MODE: VersionedId = stateful::MODE_CONSENSUS_V1;
static MODES: [VersionedId; 1] = [CONSENSUS_MODE];
static VIEWS: [ViewAbi; 2] = [
    ViewAbi {
        role: stateful::KIND_VIEW_COUNTER,
        id: VALUE_VIEW_ABI,
        max_bytes: 8,
    },
    ViewAbi {
        role: stateful::KIND_VIEW_TOTAL,
        id: TOTAL_VIEW_ABI,
        max_bytes: 8,
    },
];
static MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-counter-v1\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout {
        id: INPUT_LAYOUT,
        max_bytes: 8,
        alignment: 1,
    },
    output: PortLayout {
        id: OUTPUT_LAYOUT,
        max_bytes: 16,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: COUNTER_SCHEMA,
        max_bytes: 16,
    }),
    resources: ResourceLimits {
        max_input_bytes: 8,
        max_output_bytes: 16,
        max_state_bytes: 16,
        max_operations: 8,
        // Designed per transition; the adapter checks max_steps times this
        // ceiling against the transaction's 1.4M-CU budget.
        max_compute_units: 80_000,
    },
    modes: &MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

pub struct CounterKernel;

impl Kernel for CounterKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &MANIFEST
    }

    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for CounterKernel {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
        if output.len() < 16 {
            return Err(KernelError::OutputTooSmall);
        }
        output[..16].fill(0);
        Ok(16)
    }

    fn transition(
        &self,
        input: &[u8],
        prior_state: &[u8],
        output: &mut [u8],
        next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        if input.len() != 1 || prior_state.len() != 16 || output.len() < 16 || next_state.len() < 16
        {
            return Err(KernelError::InvalidInput);
        }
        let value = u64::from_le_bytes(prior_state[..8].try_into().unwrap());
        let total = u64::from_le_bytes(prior_state[8..16].try_into().unwrap());
        let next_value = value
            .checked_add(input[0] as u64)
            .ok_or(KernelError::Refused)?;
        let next_total = total.checked_add(next_value).ok_or(KernelError::Refused)?;
        next_state[..8].copy_from_slice(&next_value.to_le_bytes());
        next_state[8..16].copy_from_slice(&next_total.to_le_bytes());
        output[..8].copy_from_slice(&next_value.to_le_bytes());
        output[8..16].copy_from_slice(&next_total.to_le_bytes());
        Ok((16, 16))
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        if spans.len() != 2
            || spans[0].schema != COUNTER_SCHEMA
            || spans[1].schema != COUNTER_SCHEMA
            || spans[0].offset != 0
            || spans[0].data.len() != 8
            || spans[1].offset != 8
            || spans[1].data.len() != 8
        {
            return Err(KernelError::InvalidInput);
        }
        spans[0].data.fill(0);
        spans[1].data.fill(0);
        Ok(16)
    }

    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        if input.len() != 1
            || state.len() != 2
            || state[0].schema != COUNTER_SCHEMA
            || state[1].schema != COUNTER_SCHEMA
            || state[0].offset != 0
            || state[0].data.len() != 8
            || state[1].offset != 8
            || state[1].data.len() != 8
            || output.len() < 16
        {
            return Err(KernelError::InvalidInput);
        }
        let value = u64::from_le_bytes(state[0].data.try_into().unwrap());
        let total = u64::from_le_bytes(state[1].data.try_into().unwrap());
        let next_value = value
            .checked_add(input[0] as u64)
            .ok_or(KernelError::Refused)?;
        let next_total = total.checked_add(next_value).ok_or(KernelError::Refused)?;
        state[0].data.copy_from_slice(&next_value.to_le_bytes());
        state[1].data.copy_from_slice(&next_total.to_le_bytes());
        output[..8].copy_from_slice(&next_value.to_le_bytes());
        output[8..16].copy_from_slice(&next_total.to_le_bytes());
        Ok(16)
    }

    fn view_abis(&self) -> &'static [ViewAbi] {
        &VIEWS
    }
}

pub static COUNTER: CounterKernel = CounterKernel;

static V3_COUNTER_MODES: [VersionedId; 1] = [crate::stateful::v3::MODE_CONSENSUS_V3];
static V3_COUNTER_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-counter-v1\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout {
        id: INPUT_LAYOUT,
        max_bytes: 8,
        alignment: 1,
    },
    output: PortLayout {
        id: OUTPUT_LAYOUT,
        max_bytes: 16,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: COUNTER_SCHEMA,
        max_bytes: 16,
    }),
    resources: ResourceLimits {
        max_input_bytes: 8,
        max_output_bytes: 16,
        max_state_bytes: 16,
        max_operations: 8,
        max_compute_units: 80_000,
    },
    modes: &V3_COUNTER_MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

pub struct V3CounterKernel;

impl Kernel for V3CounterKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &V3_COUNTER_MANIFEST
    }

    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
        COUNTER.execute(input, output)
    }
}

impl StatefulKernel for V3CounterKernel {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
        COUNTER.initial_state(output)
    }

    fn transition(
        &self,
        input: &[u8],
        prior_state: &[u8],
        output: &mut [u8],
        next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        COUNTER.transition(input, prior_state, output, next_state)
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        COUNTER.initial_state_spans(spans)
    }

    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        COUNTER.transition_spans(input, state, output)
    }

    fn view_abis(&self) -> &'static [ViewAbi] {
        COUNTER.view_abis()
    }
}

pub static V3_COUNTER: V3CounterKernel = V3CounterKernel;

/// Commands the reject test kernels treat specially (design
/// `session-reject-and-ring-v1.md` §5): `REJECT` is rejected with code 7;
/// `REJECT_DIRTY` changes state and then rejects; `REJECT_ZERO` rejects with
/// code 0. Anything else is the counter's ordinary transition.
pub const V3_REJECT_COMMAND: u8 = 0xEE;
pub const V3_REJECT_DIRTY_COMMAND: u8 = 0xED;
pub const V3_REJECT_ZERO_COMMAND: u8 = 0xEC;
pub const V3_REJECT_CODE: u32 = 7;
/// Halt commands of the reject kernels, to mix rejection with halts in one
/// `ADVANCE`: `HALT_BEFORE` leaves the command unconsumed, `HALT_AFTER`
/// applies it (+1) and halts.
pub const V3_REJECT_HALT_BEFORE_COMMAND: u8 = 0xEB;
pub const V3_REJECT_HALT_AFTER_COMMAND: u8 = 0xEA;
pub const V3_REJECT_HALT_REASON: u32 = 0xBEEF;

fn reject_counter_transition(
    input: &[u8],
    state: &mut [StateSpanMut<'_>],
    output: &mut [u8],
) -> Result<TransitionOutcome, KernelError> {
    let reject = |code| Ok(TransitionOutcome { output_bytes: 0, disposition: TransitionDisposition::Reject { code } });
    match input.first() {
        Some(&V3_REJECT_COMMAND) => reject(V3_REJECT_CODE),
        Some(&V3_REJECT_ZERO_COMMAND) => reject(0),
        Some(&V3_REJECT_DIRTY_COMMAND) => {
            COUNTER.transition_spans(&[1], state, output)?;
            reject(V3_REJECT_CODE)
        }
        Some(&V3_REJECT_HALT_BEFORE_COMMAND) => Ok(TransitionOutcome {
            output_bytes: 0,
            disposition: TransitionDisposition::HaltBefore { reason: V3_REJECT_HALT_REASON },
        }),
        Some(&V3_REJECT_HALT_AFTER_COMMAND) => COUNTER.transition_spans(&[1], state, output).map(|output_bytes| TransitionOutcome {
            output_bytes,
            disposition: TransitionDisposition::HaltAfter { reason: V3_REJECT_HALT_REASON },
        }),
        _ => COUNTER.transition_spans(input, state, output).map(|output_bytes| TransitionOutcome {
            output_bytes,
            disposition: TransitionDisposition::Continue,
        }),
    }
}

/// The v3 lane counter declaring `REJECTS_INPUT` (lanes, views and capture as
/// `V3_LANE_COUNTER`): sessions binding it must open with the rejectable
/// feature.
pub struct V3RejectCounterKernel;

static V3_REJECT_COUNTER_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-rejctr-v1\0\0\0"),
    capabilities: crate::kernel::KernelCapabilities::REJECTS_INPUT,
    ..V3_LANE_COUNTER_MANIFEST
};

/// A counter that rejects without declaring the capability: every `Reject`
/// it returns must be refused.
pub struct V3UndeclaredRejectKernel;

static V3_UNDECLARED_REJECT_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-undrej-v1\0\0\0"),
    ..V3_LANE_COUNTER_MANIFEST
};

macro_rules! reject_counter_kernel {
    ($kernel:ty, $manifest:expr) => {
        reject_counter_kernel!($kernel, $manifest, reject_counter_transition);
    };
    ($kernel:ty, $manifest:expr, $transition:path) => {
        impl Kernel for $kernel {
            fn manifest(&self) -> &'static KernelManifest {
                &$manifest
            }
            fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
                V3_LANE_COUNTER.execute(input, output)
            }
        }
        impl StatefulKernel for $kernel {
            fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
                V3_LANE_COUNTER.initial_state(output)
            }
            fn transition(
                &self,
                input: &[u8],
                prior_state: &[u8],
                output: &mut [u8],
                next_state: &mut [u8],
            ) -> Result<(usize, usize), KernelError> {
                V3_LANE_COUNTER.transition(input, prior_state, output, next_state)
            }
            fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
                V3_LANE_COUNTER.initial_state_spans(spans)
            }
            fn transition_spans_with_outcome(
                &self,
                input: &[u8],
                state: &mut [StateSpanMut<'_>],
                output: &mut [u8],
            ) -> Result<TransitionOutcome, KernelError> {
                $transition(input, state, output)
            }
            fn view_abis(&self) -> &'static [ViewAbi] {
                V3_LANE_COUNTER.view_abis()
            }
            fn max_view_phase_bytes(&self) -> u32 {
                V3_LANE_COUNTER.max_view_phase_bytes()
            }
            fn view_phase_compute_units(&self) -> u32 {
                V3_LANE_COUNTER.view_phase_compute_units()
            }
            fn max_view_workspace_bytes(&self) -> u32 {
                V3_LANE_COUNTER.max_view_workspace_bytes()
            }
            fn lane_capture_bytes(&self) -> u32 {
                V3_LANE_COUNTER.lane_capture_bytes()
            }
            fn lane_capture_phase_bytes(&self) -> u32 {
                V3_LANE_COUNTER.lane_capture_phase_bytes()
            }
            fn capture_lane_phase(
                &self,
                phase: crate::kernel::LanePhase,
                state: &[AccountSpan<'_>],
                resources: &[AccountSpan<'_>],
                commitment: &[u8; 32],
                workspace: &mut [u8],
            ) -> Result<(), KernelError> {
                V3_LANE_COUNTER.capture_lane_phase(phase, state, resources, commitment, workspace)
            }
            fn render_lane_phase(
                &self,
                phase: ViewPhase,
                resources: &[AccountSpan<'_>],
                commitment: &[u8; 32],
                workspace_header: &mut [u8],
                workspace: &mut [u8],
                output: &mut [u8],
            ) -> Result<usize, KernelError> {
                V3_LANE_COUNTER.render_lane_phase(phase, resources, commitment, workspace_header, workspace, output)
            }
        }
    };
}

reject_counter_kernel!(V3RejectCounterKernel, V3_REJECT_COUNTER_MANIFEST);
reject_counter_kernel!(V3UndeclaredRejectKernel, V3_UNDECLARED_REJECT_MANIFEST);

/// The lane counter declaring `ACCEPTS_TICKS` (v0.3.0 item 2): a tick (the
/// empty command) adds 1; any other command is the counter's ordinary step.
pub struct V3TickCounterKernel;

static V3_TICK_COUNTER_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-tickctr-v1\0\0"),
    capabilities: crate::kernel::KernelCapabilities::ACCEPTS_TICKS,
    ..V3_LANE_COUNTER_MANIFEST
};

fn tick_counter_transition(
    input: &[u8],
    state: &mut [StateSpanMut<'_>],
    output: &mut [u8],
) -> Result<TransitionOutcome, KernelError> {
    COUNTER
        .transition_spans(if input.is_empty() { &[1] } else { input }, state, output)
        .map(|output_bytes| TransitionOutcome { output_bytes, disposition: TransitionDisposition::Continue })
}

reject_counter_kernel!(V3TickCounterKernel, V3_TICK_COUNTER_MANIFEST, tick_counter_transition);

pub static V3_TICK_COUNTER: V3TickCounterKernel = V3TickCounterKernel;

/// Ticks on a rejectable session with halts: the rejecting counter plus
/// `ACCEPTS_TICKS`, where a tick adds 1 and halts after when the value
/// reaches a multiple of 10 (`V3_REJECT_HALT_REASON`).
pub struct V3TickRejectKernel;

static V3_TICK_REJECT_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-tickrej-v1\0\0"),
    capabilities: crate::kernel::KernelCapabilities(
        crate::kernel::KernelCapabilities::REJECTS_INPUT.0 | crate::kernel::KernelCapabilities::ACCEPTS_TICKS.0,
    ),
    ..V3_LANE_COUNTER_MANIFEST
};

fn tick_reject_transition(
    input: &[u8],
    state: &mut [StateSpanMut<'_>],
    output: &mut [u8],
) -> Result<TransitionOutcome, KernelError> {
    if !input.is_empty() {
        return reject_counter_transition(input, state, output);
    }
    let output_bytes = COUNTER.transition_spans(&[1], state, output)?;
    let value = state
        .first()
        .and_then(|span| span.data.get(..8))
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or(KernelError::InvalidInput)?;
    let disposition = if value % 10 == 0 {
        TransitionDisposition::HaltAfter { reason: V3_REJECT_HALT_REASON }
    } else {
        TransitionDisposition::Continue
    };
    Ok(TransitionOutcome { output_bytes, disposition })
}

reject_counter_kernel!(V3TickRejectKernel, V3_TICK_REJECT_MANIFEST, tick_reject_transition);

pub static V3_TICK_REJECT: V3TickRejectKernel = V3TickRejectKernel;

/// Call-depth probe (v0.3.0): a transition that recurses `command[0]` frames
/// below itself before stepping the counter. Run through ADVANCE on SBF, the
/// deepest command that succeeds tells how many of the 64 call frames the
/// runtime uses before the kernel's callback.
pub struct V3DepthProbeKernel;

static V3_DEPTH_PROBE_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-depth-v1\0\0\0\0"),
    ..V3_LANE_COUNTER_MANIFEST
};

#[inline(never)]
fn depth_probe_recurse(n: u8, acc: u64) -> u64 {
    if n == 0 {
        return core::hint::black_box(acc);
    }
    // Not a tail call: the addition after the call keeps each frame live.
    core::hint::black_box(depth_probe_recurse(core::hint::black_box(n - 1), acc.wrapping_mul(31).wrapping_add(n as u64)))
        .wrapping_add(1)
}

fn depth_probe_transition(
    input: &[u8],
    state: &mut [StateSpanMut<'_>],
    output: &mut [u8],
) -> Result<TransitionOutcome, KernelError> {
    let n = *input.first().ok_or(KernelError::InvalidInput)?;
    let _ = depth_probe_recurse(n, 7);
    COUNTER
        .transition_spans(&[1], state, output)
        .map(|output_bytes| TransitionOutcome { output_bytes, disposition: TransitionDisposition::Continue })
}

reject_counter_kernel!(V3DepthProbeKernel, V3_DEPTH_PROBE_MANIFEST, depth_probe_transition);

pub static V3_DEPTH_PROBE: V3DepthProbeKernel = V3DepthProbeKernel;

pub static V3_REJECT_COUNTER: V3RejectCounterKernel = V3RejectCounterKernel;
pub static V3_UNDECLARED_REJECT: V3UndeclaredRejectKernel = V3UndeclaredRejectKernel;

/// The v3 counter declaring `READS_RESOURCE` (v0.3.0 item 1): a 1-byte
/// command adds `command + resource[value % len]` to the value, then the value
/// to the total, refusing on overflow or an empty resource. The kernel kit's
/// example of a resource-reading transition (`counter_mirrors.py`).
pub struct V3ResourceCounterKernel;

static V3_RESOURCE_COUNTER_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-rsctr-v1\0\0\0\0"),
    capabilities: crate::kernel::KernelCapabilities::READS_RESOURCE,
    ..V3_COUNTER_MANIFEST
};

impl Kernel for V3ResourceCounterKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &V3_RESOURCE_COUNTER_MANIFEST
    }
    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for V3ResourceCounterKernel {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
        COUNTER.initial_state(output)
    }
    fn transition(&self, _: &[u8], _: &[u8], _: &mut [u8], _: &mut [u8]) -> Result<(usize, usize), KernelError> {
        Err(KernelError::Refused)
    }
    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        COUNTER.initial_state_spans(spans)
    }
    /// The resource is read by transitions, not by initialization.
    fn initial_state_spans_with_resources(
        &self,
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        spans: &mut [StateSpanMut<'_>],
    ) -> Result<usize, KernelError> {
        COUNTER.initial_state_spans(spans)
    }
    fn transition_spans_with_resources(
        &self,
        input: &[u8],
        resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        let [resource] = resources else {
            return Err(KernelError::InvalidInput);
        };
        let total: usize = state.iter().map(|span| span.data.len()).sum();
        if input.len() != 1 || total != 16 || output.len() < 16 || resource.data.is_empty() {
            return Err(KernelError::InvalidInput);
        }
        let mut flat = [0u8; 16];
        let mut at = 0;
        for span in state.iter() {
            flat[at..at + span.data.len()].copy_from_slice(span.data);
            at += span.data.len();
        }
        let value = u64::from_le_bytes(flat[..8].try_into().unwrap());
        let total_sum = u64::from_le_bytes(flat[8..].try_into().unwrap());
        let read = resource.data[(value % resource.data.len() as u64) as usize] as u64;
        let value = value.checked_add(input[0] as u64 + read).ok_or(KernelError::Refused)?;
        let total_sum = total_sum.checked_add(value).ok_or(KernelError::Refused)?;
        flat[..8].copy_from_slice(&value.to_le_bytes());
        flat[8..].copy_from_slice(&total_sum.to_le_bytes());
        at = 0;
        for span in state.iter_mut() {
            let len = span.data.len();
            span.data.copy_from_slice(&flat[at..at + len]);
            at += len;
        }
        output[..16].copy_from_slice(&flat);
        Ok(TransitionOutcome { output_bytes: 16, disposition: TransitionDisposition::Continue })
    }
}

pub static V3_RESOURCE_COUNTER: V3ResourceCounterKernel = V3ResourceCounterKernel;


/// The v3 counter with render lanes (design `stateful-session-lanes-v1.md`
/// §10): a capture copies the 16 state bytes into the lane workspace in
/// 8-byte calls; a lane render serves each view's bytes from that copy, so a
/// published view shows the state at the captured cursor even after later
/// advances.
pub struct V3LaneCounterKernel;

static V3_LANE_COUNTER_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-lanectr-v1\0\0"),
    ..V3_COUNTER_MANIFEST
};
pub const V3_LANE_CAPTURE_BYTES: u32 = 16;
pub const V3_LANE_WORKSPACE_BYTES: u32 = 64;

impl Kernel for V3LaneCounterKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &V3_LANE_COUNTER_MANIFEST
    }

    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
        COUNTER.execute(input, output)
    }
}

impl StatefulKernel for V3LaneCounterKernel {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
        COUNTER.initial_state(output)
    }

    fn transition(
        &self,
        input: &[u8],
        prior_state: &[u8],
        output: &mut [u8],
        next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        COUNTER.transition(input, prior_state, output, next_state)
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        COUNTER.initial_state_spans(spans)
    }

    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        COUNTER.transition_spans(input, state, output)
    }

    fn view_abis(&self) -> &'static [ViewAbi] {
        COUNTER.view_abis()
    }

    fn max_view_phase_bytes(&self) -> u32 {
        6 // smaller than a view, so render chunks cross view boundaries
    }

    fn view_phase_compute_units(&self) -> u32 {
        100_000
    }

    fn max_view_workspace_bytes(&self) -> u32 {
        V3_LANE_WORKSPACE_BYTES
    }

    fn lane_capture_bytes(&self) -> u32 {
        V3_LANE_CAPTURE_BYTES
    }

    fn lane_capture_phase_bytes(&self) -> u32 {
        8
    }

    fn capture_lane_phase(
        &self,
        phase: crate::kernel::LanePhase,
        state: &[AccountSpan<'_>],
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        workspace: &mut [u8],
    ) -> Result<(), KernelError> {
        let (from, to) = (phase.offset as usize, (phase.offset + phase.len) as usize);
        if to > V3_LANE_CAPTURE_BYTES as usize || workspace.len() < to {
            return Err(KernelError::InvalidInput);
        }
        for span in state {
            let (a, b) = (span.offset as usize, span.offset as usize + span.data.len());
            let (lo, hi) = (from.max(a), to.min(b));
            if lo < hi {
                workspace[lo..hi].copy_from_slice(&span.data[lo - a..hi - a]);
            }
        }
        // Only the declared range is written (lanes review L5); the program
        // stamps the captured cursor in the workspace header.
        Ok(())
    }

    fn render_lane_phase(
        &self,
        phase: ViewPhase,
        _resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        _workspace_header: &mut [u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let start = (phase.source_offset + phase.output_offset) as usize;
        let end = start + output.len();
        if end > V3_LANE_CAPTURE_BYTES as usize {
            return Err(KernelError::InvalidInput);
        }
        output.copy_from_slice(&workspace[start..end]);
        Ok(output.len())
    }
}

pub static V3_LANE_COUNTER: V3LaneCounterKernel = V3LaneCounterKernel;

pub const WORKLOAD_RESOURCE_KEY: [u8; 32] = [0xC1; 32];
pub const WORKLOAD_RESOURCE_SCHEMA: VersionedId = VersionedId {
    id: 0x5253_5243,
    version: 1,
};
pub const WORKLOAD_RESOURCE_BYTES: &[u8] = b"dcg-stateful-v2-resource-input";
pub const WORKLOAD_SNAPSHOT_BYTES: u32 = 1_048_768;
pub const WORKLOAD_STRIP_BYTES: u32 = 8_128;
pub const WORKLOAD_VIEW_BYTES: u32 = WORKLOAD_SNAPSHOT_BYTES + 8 * WORKLOAD_STRIP_BYTES;
pub const WORKLOAD_STATE_BYTES: u32 = 16 + WORKLOAD_VIEW_BYTES;
pub const WORKLOAD_PHASE_COMPUTE_UNITS: u32 = 1_000_000;
pub const WORKLOAD_PHASE_BYTES: u32 = 65_536;
pub const WORKLOAD_SNAPSHOT_ABI: [u8; 32] = [0x60; 32];
pub const WORKLOAD_STRIP_ABIS: [[u8; 32]; 8] = [
    [0x61; 32], [0x62; 32], [0x63; 32], [0x64; 32], [0x65; 32], [0x66; 32], [0x67; 32], [0x68; 32],
];

static WORKLOAD_VIEWS: [ViewAbi; 9] = [
    ViewAbi {
        role: stateful_v2::VIEW_SNAPSHOT,
        id: WORKLOAD_SNAPSHOT_ABI,
        max_bytes: WORKLOAD_SNAPSHOT_BYTES,
    },
    ViewAbi {
        role: 1,
        id: WORKLOAD_STRIP_ABIS[0],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 2,
        id: WORKLOAD_STRIP_ABIS[1],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 3,
        id: WORKLOAD_STRIP_ABIS[2],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 4,
        id: WORKLOAD_STRIP_ABIS[3],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 5,
        id: WORKLOAD_STRIP_ABIS[4],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 6,
        id: WORKLOAD_STRIP_ABIS[5],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 7,
        id: WORKLOAD_STRIP_ABIS[6],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
    ViewAbi {
        role: 8,
        id: WORKLOAD_STRIP_ABIS[7],
        max_bytes: WORKLOAD_STRIP_BYTES,
    },
];
static WORKLOAD_MODES: [VersionedId; 1] = [stateful_v2::MODE_CONSENSUS_V2];
static WORKLOAD_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-scale-v2\0\0\0\0"),
    semantic_version: 1,
    abi_version: 2,
    input: PortLayout {
        id: INPUT_LAYOUT,
        max_bytes: 1,
        alignment: 1,
    },
    output: PortLayout {
        id: OUTPUT_LAYOUT,
        max_bytes: 16,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: VersionedId {
            id: 0x5343_414c,
            version: 2,
        },
        max_bytes: WORKLOAD_STATE_BYTES,
    }),
    resources: ResourceLimits {
        max_input_bytes: 1,
        max_output_bytes: 16,
        max_state_bytes: WORKLOAD_STATE_BYTES,
        max_operations: 8,
        max_compute_units: 100_000,
    },
    modes: &WORKLOAD_MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

// Keep the engine address on this invocation's kernel value. `process` creates
// one value for the duration of an invocation, so the pointer never enters a
// committed account or process-global storage.
pub struct ScaledWorkloadKernel {
    invocation_context: AtomicPtr<u8>,
}

impl ScaledWorkloadKernel {
    const fn new() -> Self {
        Self {
            invocation_context: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

impl Kernel for ScaledWorkloadKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &WORKLOAD_MANIFEST
    }

    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for ScaledWorkloadKernel {
    fn initial_state(&self, _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }

    fn transition(
        &self,
        _input: &[u8],
        _prior_state: &[u8],
        _output: &mut [u8],
        _next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        Err(KernelError::Refused)
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        if spans.len() != 2
            || spans[0].offset != 0
            || spans[0].data.len() != 16
            || spans[1].offset != 16
            || spans[1].data.len() != WORKLOAD_VIEW_BYTES as usize
        {
            return Err(KernelError::InvalidInput);
        }
        spans[0].data.fill(0);
        // New state PDAs are system-created zeroed accounts. Avoid touching
        // the full 1.1 MB output region merely to write the zero value again.
        Ok(WORKLOAD_STATE_BYTES as usize)
    }

    fn initial_state_spans_with_resources(
        &self,
        resources: &[AccountSpan<'_>],
        commitment: &[u8; 32],
        spans: &mut [StateSpanMut<'_>],
    ) -> Result<usize, KernelError> {
        let [resource] = resources else {
            return Err(KernelError::Refused);
        };
        if resource.key != WORKLOAD_RESOURCE_KEY
            || resource.schema != WORKLOAD_RESOURCE_SCHEMA
            || resource.owner != [0xD9; 32]
            || crate::hash::sha256(&[resource.data]) != *commitment
            || resource.data != WORKLOAD_RESOURCE_BYTES
        {
            return Err(KernelError::Refused);
        }
        let written = self.initial_state_spans(spans)?;
        spans[1].data[..resource.data.len()].copy_from_slice(resource.data);
        Ok(written)
    }

    fn bind_invocation_state(&self, spans: &mut [StateSpanMut<'_>]) -> Result<(), KernelError> {
        let Some(context) = spans.first_mut() else {
            return Err(KernelError::InvalidInput);
        };
        if context.offset != 0 || context.data.len() != 16 {
            return Err(KernelError::InvalidInput);
        }
        let address = context.data_address() as usize;
        if address == 0 {
            return Err(KernelError::Refused);
        }
        self.invocation_context
            .store(address as *mut u8, Ordering::Relaxed);
        Ok(())
    }

    fn unbind_invocation_state(&self) {
        self.invocation_context
            .store(core::ptr::null_mut(), Ordering::Relaxed);
    }

    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        if input.len() != 1
            || state.len() != 2
            || state[0].offset != 0
            || state[0].data.len() != 16
            || state[1].offset != 16
            || state[1].data.len() != WORKLOAD_VIEW_BYTES as usize
            || output.len() < 16
            || self.invocation_context.load(Ordering::Relaxed) != state[0].data.as_mut_ptr()
        {
            return Err(KernelError::InvalidInput);
        }
        let value = u64::from_le_bytes(state[0].data[..8].try_into().unwrap());
        let total = u64::from_le_bytes(state[0].data[8..16].try_into().unwrap());
        let next_value = value
            .checked_add(input[0] as u64)
            .ok_or(KernelError::Refused)?;
        let next_total = total.checked_add(next_value).ok_or(KernelError::Refused)?;
        state[0].data[..8].copy_from_slice(&next_value.to_le_bytes());
        state[0].data[8..16].copy_from_slice(&next_total.to_le_bytes());
        output[..8].copy_from_slice(&next_value.to_le_bytes());
        output[8..16].copy_from_slice(&next_total.to_le_bytes());
        Ok(16)
    }

    fn view_abis(&self) -> &'static [ViewAbi] {
        &WORKLOAD_VIEWS
    }

    fn max_view_phase_bytes(&self) -> u32 {
        WORKLOAD_PHASE_BYTES
    }

    fn view_phase_compute_units(&self) -> u32 {
        WORKLOAD_PHASE_COMPUTE_UNITS
    }
}

pub const SCALED_WORKLOAD: ScaledWorkloadKernel = ScaledWorkloadKernel::new();

pub const V3_FIXED_STATE_LEN: u32 = 10_000_000;
pub const V3_RESOURCE_KEY: [u8; 32] = [0xE7; 32];
pub const V3_RESOURCE_OWNER: [u8; 32] = [0xD9; 32];
pub const V3_RESOURCE_SCHEMA: VersionedId = VersionedId {
    id: 0x5741_4431,
    version: 1,
};
pub const V3_STATE_SCHEMA: VersionedId = VersionedId {
    id: 0x444f_4f4d,
    version: 1,
};
pub const V3_VIEW_ABI: [u8; 32] = [0xB3; 32];
pub const V3_HALT_REASON: u32 = 0xD00D;
pub const V3_FIXED_STATE_ADDRESS: usize = 0x4000_00060;
pub const V3_INIT_PHASE_BYTES: u32 = 65_536;
pub const V3_INIT_COMPUTE_UNITS: u32 = (MAX_DECLARED_KERNEL_COMPUTE_UNITS * 9 / 10) as u32;
pub const V3_HALT_AFTER_REASON: u32 = 0xD00E;
pub const V3_VIEW_WORKSPACE_BYTES: u32 = 64;
const V3_VIEW_ROLE: u8 = 0;

static V3_MODES: [VersionedId; 1] = [crate::stateful::v3::MODE_CONSENSUS_V3];
static V3_VIEWS: [ViewAbi; 1] = [ViewAbi {
    role: V3_VIEW_ROLE,
    id: V3_VIEW_ABI,
    max_bytes: 32,
}];
static V3_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-fixed-v3\0\0\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout {
        id: VersionedId {
            id: 0x494e_5054,
            version: 3,
        },
        max_bytes: 1,
        alignment: 1,
    },
    output: PortLayout {
        id: VersionedId {
            id: 0x4f55_5450,
            version: 3,
        },
        max_bytes: 8,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: V3_STATE_SCHEMA,
        max_bytes: V3_FIXED_STATE_LEN,
    }),
    resources: ResourceLimits {
        max_input_bytes: 1,
        max_output_bytes: 8,
        max_state_bytes: V3_FIXED_STATE_LEN,
        max_operations: 8,
        max_compute_units: 100_000,
    },
    modes: &V3_MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

static V3_WORKSPACE_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-ws-v3\0\0\0\0\0\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout {
        id: VersionedId {
            id: 0x494e_5054,
            version: 3,
        },
        max_bytes: 1,
        alignment: 1,
    },
    output: PortLayout {
        id: VersionedId {
            id: 0x4f55_5450,
            version: 3,
        },
        max_bytes: 8,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: V3_STATE_SCHEMA,
        max_bytes: V3_FIXED_STATE_LEN,
    }),
    resources: ResourceLimits {
        max_input_bytes: 1,
        max_output_bytes: 8,
        max_state_bytes: V3_FIXED_STATE_LEN,
        max_operations: 8,
        max_compute_units: 100_000,
    },
    modes: &V3_MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

/// The fixed engine with `READS_RESOURCE`: every transition reads the sealed
/// resource at a state-chosen offset (v0.3.0 item 1).
static V3_RESOURCE_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-rsrc-v3\0\0\0\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout {
        id: VersionedId {
            id: 0x494e_5054,
            version: 3,
        },
        max_bytes: 1,
        alignment: 1,
    },
    output: PortLayout {
        id: VersionedId {
            id: 0x4f55_5450,
            version: 3,
        },
        max_bytes: 8,
        alignment: 1,
    },
    state: Some(StateSchema {
        id: V3_STATE_SCHEMA,
        max_bytes: V3_FIXED_STATE_LEN,
    }),
    resources: ResourceLimits {
        max_input_bytes: 1,
        max_output_bytes: 8,
        max_state_bytes: V3_FIXED_STATE_LEN,
        max_operations: 8,
        max_compute_units: 100_000,
    },
    modes: &V3_MODES,
    capabilities: crate::kernel::KernelCapabilities::READS_RESOURCE,
};

/// Small Rust engine used by the SBF test. It rejects any state pointer except
/// the legacy account-0 data address and exposes resource-backed rendering.
pub struct V3FixedAddressKernel {
    context: AtomicPtr<u8>,
    workspace_first: bool,
    reads_resource: bool,
}

impl V3FixedAddressKernel {
    pub const fn new() -> Self {
        Self {
            context: AtomicPtr::new(core::ptr::null_mut()),
            workspace_first: false,
            reads_resource: false,
        }
    }

    pub const fn workspace_first() -> Self {
        Self {
            context: AtomicPtr::new(core::ptr::null_mut()),
            workspace_first: true,
            reads_resource: false,
        }
    }

    /// The workspace-first engine with `READS_RESOURCE`: transitions add the
    /// input and the resource byte at `value % resource_len` to the counter
    /// (a data-dependent read), with the same halt and refusal commands.
    pub const fn reading_resource() -> Self {
        Self {
            context: AtomicPtr::new(core::ptr::null_mut()),
            workspace_first: true,
            reads_resource: true,
        }
    }

    fn check_fixed_address(&self, state: &mut [StateSpanMut<'_>]) -> Result<(), KernelError> {
        let Some(primary) = state.first_mut() else {
            return Err(KernelError::InvalidInput);
        };
        let full_state = primary.data.len() == V3_FIXED_STATE_LEN as usize
            && primary.data_address() as usize == V3_FIXED_STATE_ADDRESS;
        let small_test_state = primary.data.len() == 1_280
            || primary.data.len() == crate::stateful::v3::HALT_BEFORE_RUNTIME_CHECK_BYTES;
        if primary.offset != 0 || !(full_state || small_test_state) {
            return Err(KernelError::Refused);
        }
        Ok(())
    }

    fn transition_one(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        self.transition_one_reading(input, state, output, None)
    }

    /// The fixed engine's v3 outcome: 0xEE halts before, 0xED changes state
    /// and halts before (refused at or below the snapshot cap), 0xEF steps
    /// and halts after, anything else steps.
    fn fixed_outcome(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
        resource: Option<&[u8]>,
    ) -> Result<TransitionOutcome, KernelError> {
        self.check_fixed_address(state)?;
        if self.context.load(Ordering::Relaxed) != state[0].data.as_mut_ptr() {
            return Err(KernelError::Refused);
        }
        if input == [0xEE] {
            return Ok(TransitionOutcome {
                output_bytes: 0,
                disposition: TransitionDisposition::HaltBefore {
                    reason: V3_HALT_REASON,
                },
            });
        }
        if input == [0xED] {
            state[0].data[0] ^= 1;
            return Ok(TransitionOutcome {
                output_bytes: 0,
                disposition: TransitionDisposition::HaltBefore {
                    reason: V3_HALT_REASON,
                },
            });
        }
        let written = self.transition_one_reading(input, state, output, resource)?;
        Ok(TransitionOutcome {
            output_bytes: written,
            disposition: if input == [0xEF] {
                TransitionDisposition::HaltAfter {
                    reason: V3_HALT_AFTER_REASON,
                }
            } else {
                TransitionDisposition::Continue
            },
        })
    }

    /// One counter step; with a resource, the byte at `value % len` is added
    /// as well.
    fn transition_one_reading(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
        resource: Option<&[u8]>,
    ) -> Result<usize, KernelError> {
        if input.len() != 1 || output.len() < 8 {
            return Err(KernelError::InvalidInput);
        }
        self.check_fixed_address(state)?;
        if self.context.load(Ordering::Relaxed) != state[0].data.as_mut_ptr() {
            return Err(KernelError::Refused);
        }
        if input[0] == 0xEE {
            return Err(KernelError::Refused);
        }
        let at = state[0].data.len() - 8;
        let value = u64::from_le_bytes(state[0].data[at..at + 8].try_into().unwrap());
        let read = match resource {
            Some(bytes) if bytes.is_empty() => return Err(KernelError::InvalidInput),
            Some(bytes) => bytes[(value % bytes.len() as u64) as usize] as u64,
            None => 0,
        };
        let next = value
            .checked_add(input[0] as u64 + read)
            .ok_or(KernelError::Refused)?;
        state[0].data[at..at + 8].copy_from_slice(&next.to_le_bytes());
        output[..8].copy_from_slice(&next.to_le_bytes());
        Ok(8)
    }
}

impl Kernel for V3FixedAddressKernel {
    fn manifest(&self) -> &'static KernelManifest {
        if self.reads_resource {
            &V3_RESOURCE_MANIFEST
        } else if self.workspace_first {
            &V3_WORKSPACE_MANIFEST
        } else {
            &V3_MANIFEST
        }
    }

    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for V3FixedAddressKernel {
    fn initial_state(&self, _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }

    fn transition(
        &self,
        _input: &[u8],
        _prior_state: &[u8],
        _output: &mut [u8],
        _next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        Err(KernelError::Refused)
    }

    fn initial_state_spans(&self, _spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }

    fn transition_spans(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        self.transition_one(input, state, output)
    }

    fn transition_spans_with_outcome(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        if self.reads_resource {
            return Err(KernelError::Refused);
        }
        self.fixed_outcome(input, state, output, None)
    }

    fn transition_spans_with_resources(
        &self,
        input: &[u8],
        resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        let [resource] = resources else {
            return Err(KernelError::Refused);
        };
        if !self.reads_resource
            || resource.schema != V3_RESOURCE_SCHEMA
            || resource.owner != V3_RESOURCE_OWNER
            || resource.is_writable
        {
            return Err(KernelError::Refused);
        }
        self.fixed_outcome(input, state, output, Some(resource.data))
    }

    fn bind_invocation_state(&self, state: &mut [StateSpanMut<'_>]) -> Result<(), KernelError> {
        self.check_fixed_address(state)?;
        self.context
            .store(state[0].data.as_mut_ptr(), Ordering::Relaxed);
        Ok(())
    }

    fn unbind_invocation_state(&self) {
        self.context.store(core::ptr::null_mut(), Ordering::Relaxed);
    }

    fn max_initialization_phase_bytes(&self) -> u32 {
        V3_INIT_PHASE_BYTES
    }

    fn initialization_phase_compute_units(&self) -> u32 {
        V3_INIT_COMPUTE_UNITS
    }

    fn initialize_state_phase(
        &self,
        phase: InitializationPhase,
        resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        state: &mut [StateSpanMut<'_>],
    ) -> Result<usize, KernelError> {
        let [resource] = resources else {
            return Err(KernelError::Refused);
        };
        let session_shape_fixture = state.len() == 1
            && state[0].data.len() == 1_280
            && resource.data.len() == 1_280
            && resource.data.starts_with(b"DSS3");
        if !session_shape_fixture {
            self.check_fixed_address(state)?;
        }
        if resource.schema != V3_RESOURCE_SCHEMA
            || resource.owner != V3_RESOURCE_OWNER
            || resource.is_writable
        {
            return Err(KernelError::Refused);
        }
        if resource.data.first() == Some(&0xEE) {
            return Err(KernelError::Refused);
        }
        let end = phase
            .cursor
            .checked_add(self.max_initialization_phase_bytes())
            .unwrap_or(phase.total_bytes)
            .min(phase.total_bytes);
        if phase.cursor >= phase.total_bytes || end <= phase.cursor {
            return Err(KernelError::InvalidInput);
        }
        let mut written = 0usize;
        for span in state.iter_mut() {
            let span_end = span
                .offset
                .checked_add(span.data.len() as u32)
                .ok_or(KernelError::InvalidInput)?;
            let from = phase.cursor.max(span.offset);
            let to = end.min(span_end);
            if from >= to {
                continue;
            }
            let destination = (from - span.offset) as usize;
            let len = (to - from) as usize;
            let resource_end = to.min(resource.data.len() as u32);
            span.data[destination..destination + len].fill(0);
            if from < resource_end {
                let source_len = (resource_end - from) as usize;
                span.data[destination..destination + source_len]
                    .copy_from_slice(&resource.data[from as usize..from as usize + source_len]);
            }
            written += len;
        }
        if session_shape_fixture && phase.cursor == 0 {
            state[0].data[228..260].copy_from_slice(&state[0].key);
        }
        Ok(written)
    }

    fn max_view_phase_bytes(&self) -> u32 {
        if self.workspace_first {
            16
        } else {
            32
        }
    }

    fn view_phase_compute_units(&self) -> u32 {
        500_000
    }

    fn max_view_workspace_bytes(&self) -> u32 {
        V3_VIEW_WORKSPACE_BYTES
    }

    fn clear_view_workspace_on_begin(&self) -> bool {
        !self.workspace_first
    }

    fn view_workspace_at_account_base(&self) -> bool {
        self.workspace_first
    }

    fn view_abis(&self) -> &'static [ViewAbi] {
        &V3_VIEWS
    }

    fn render_view_phase_with_resources(
        &self,
        phase: ViewPhase,
        state: &[AccountSpan<'_>],
        resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let [primary] = state else {
            return Err(KernelError::Refused);
        };
        let [resource] = resources else {
            return Err(KernelError::Refused);
        };
        if primary.offset != 0
            || primary.data.len() != V3_FIXED_STATE_LEN as usize
            || primary.data.as_ptr() as usize != V3_FIXED_STATE_ADDRESS
            || resource.schema != V3_RESOURCE_SCHEMA
            || resource.owner != V3_RESOURCE_OWNER
            || resource.is_writable
            || workspace.len() != V3_VIEW_WORKSPACE_BYTES as usize
            || phase.role != V3_VIEW_ROLE
            || phase.output_offset != 0
            || output.len() != 32
            || resource.data.len() < output.len()
        {
            return Err(KernelError::Refused);
        }
        workspace[0] = workspace[0].wrapping_add(1);
        workspace[1..5].copy_from_slice(&phase.state_cursor.to_le_bytes());
        output.copy_from_slice(&resource.data[..32]);
        Ok(output.len())
    }

    fn render_view_phase_with_workspace_header(
        &self,
        phase: ViewPhase,
        state: &[AccountSpan<'_>],
        resources: &[AccountSpan<'_>],
        _commitment: &[u8; 32],
        workspace_header: &mut [u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, KernelError> {
        let [primary] = state else {
            return Err(KernelError::Refused);
        };
        let [resource] = resources else {
            return Err(KernelError::Refused);
        };
        if !self.workspace_first
            || workspace_header.len() != 128
            || workspace_header.as_mut_ptr() as usize != V3_FIXED_STATE_ADDRESS
            || primary.offset != 0
            || primary.data.len() != 1_280
            || !primary.is_writable
            || resource.schema != V3_RESOURCE_SCHEMA
            || resource.owner != V3_RESOURCE_OWNER
            || resource.is_writable
            || workspace.len() != V3_VIEW_WORKSPACE_BYTES as usize
            || phase.role != V3_VIEW_ROLE
            || phase.source_offset != 0
            || phase.output_offset > 16
            || output.len() != 16
            || phase.output_offset + output.len() as u32 > resource.data.len() as u32
        {
            return Err(KernelError::Refused);
        }

        if phase.output_offset == 0 {
            let mut saved_header = [0u8; 128];
            saved_header.copy_from_slice(workspace_header);
            workspace_header[..4].copy_from_slice(b"TEMP");
            workspace_header.copy_from_slice(&saved_header);
        } else {
            // Deliberate contract violation. The processor must refuse this
            // callback and transaction rollback must restore the header.
            workspace_header[0] ^= 1;
        }
        workspace[0] = workspace[0].wrapping_add(1);
        workspace[1..5].copy_from_slice(&phase.state_cursor.to_le_bytes());
        let start = phase.output_offset as usize;
        output.copy_from_slice(&resource.data[start..start + output.len()]);
        Ok(output.len())
    }
}

pub const V3_FIXED_ENGINE: V3FixedAddressKernel = V3FixedAddressKernel::new();
pub const V3_WORKSPACE_ENGINE: V3FixedAddressKernel = V3FixedAddressKernel::workspace_first();
pub const V3_RESOURCE_ENGINE: V3FixedAddressKernel = V3FixedAddressKernel::reading_resource();

fn test_session_kernel_id(accounts: &[AccountInfo]) -> Option<KernelId> {
    for account in accounts {
        let raw = account.try_borrow_data().ok()?;
        // A lane render carries no session; its lane record names the kernel.
        if raw.len() == crate::stateful::v3::lanes::LANE_BYTES && &raw[..4] == b"DLN3" {
            return Some(KernelId(raw[234..250].try_into().ok()?));
        }
        if raw.len() != 1_280 || &raw[..4] != b"DSS3" {
            continue;
        }
        // This feature-only dispatcher deliberately routes a session-shaped
        // primary image to its declared test kernel. The v3 processor must
        // authenticate the account address itself before it trusts that image.
        return Some(KernelId(raw[86..102].try_into().ok()?));
    }
    None
}

// --- mode results v1: a large halting state for seals --------------------------------------

/// Halt reason of [`V3_BIG_SEAL`].
pub const V3_BIG_SEAL_HALT_REASON: u32 = 0x5EA1;
/// Its halt command: applied, then the kernel halts.
pub const V3_BIG_SEAL_HALT_COMMAND: u8 = 0xFF;
/// Its two state spans (80,000 bytes in all), so a seal's first 64 KiB chunk
/// crosses the span boundary and its last chunk is short.
pub const V3_BIG_SEAL_SPAN_BYTES: u32 = 40_000;

static V3_BIG_SEAL_MANIFEST: KernelManifest = KernelManifest {
    id: KernelId(*b"dcg-bigseal-v1\0\0"),
    semantic_version: 1,
    abi_version: 1,
    input: PortLayout { id: INPUT_LAYOUT, max_bytes: 1, alignment: 1 },
    output: PortLayout { id: OUTPUT_LAYOUT, max_bytes: 16, alignment: 1 },
    state: Some(StateSchema {
        id: VersionedId { id: 0x4249_4753, version: 1 },
        max_bytes: 2 * V3_BIG_SEAL_SPAN_BYTES,
    }),
    resources: ResourceLimits {
        max_input_bytes: 1,
        max_output_bytes: 16,
        max_state_bytes: 2 * V3_BIG_SEAL_SPAN_BYTES,
        max_operations: 8,
        max_compute_units: 80_000,
    },
    modes: &V3_COUNTER_MODES,
    capabilities: crate::kernel::KernelCapabilities::NONE,
};

/// A test kernel with an 80,000-byte state that halts on a command (mode
/// results v1 seal tests): state bytes 0..8 count the steps; each step
/// writes its command byte at a position that moves through both spans;
/// `V3_BIG_SEAL_HALT_COMMAND` is applied and halts the session.
pub struct V3BigSealKernel;

impl Kernel for V3BigSealKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &V3_BIG_SEAL_MANIFEST
    }

    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for V3BigSealKernel {
    fn initial_state(&self, _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }

    fn transition(&self, _: &[u8], _: &[u8], _: &mut [u8], _: &mut [u8]) -> Result<(usize, usize), KernelError> {
        Err(KernelError::Refused)
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        let n = V3_BIG_SEAL_SPAN_BYTES as usize;
        if spans.len() != 2 || spans[0].data.len() != n || spans[1].data.len() != n || spans[1].offset != n as u32 {
            return Err(KernelError::InvalidInput);
        }
        for span in spans.iter_mut() {
            span.data.fill(0);
        }
        Ok(2 * n)
    }

    fn transition_spans_with_outcome(
        &self,
        input: &[u8],
        state: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        let n = V3_BIG_SEAL_SPAN_BYTES as usize;
        let (&[command], [a, b]) = (input, state) else {
            return Err(KernelError::InvalidInput);
        };
        let steps = u64::from_le_bytes(a.data[..8].try_into().unwrap());
        let at = 8 + (steps as usize * 7_919) % (2 * n - 8);
        if at < n { a.data[at] = command } else { b.data[at - n] = command }
        a.data[..8].copy_from_slice(&(steps + 1).to_le_bytes());
        let _ = output;
        let disposition = if command == V3_BIG_SEAL_HALT_COMMAND {
            TransitionDisposition::HaltAfter { reason: V3_BIG_SEAL_HALT_REASON }
        } else {
            TransitionDisposition::Continue
        };
        Ok(TransitionOutcome { output_bytes: 0, disposition })
    }
}

pub static V3_BIG_SEAL: V3BigSealKernel = V3BigSealKernel;

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.get(1) == Some(&crate::stateful::v3::WIRE_VERSION) {
        let kernel_id = if data.first() == Some(&stateful::TAG_OPEN_SESSION) {
            data.get(17..33)
                .and_then(|raw| raw.try_into().ok())
                .map(KernelId)
        } else {
            test_session_kernel_id(accounts)
        };
        if kernel_id == Some(V3_FIXED_ENGINE.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_FIXED_ENGINE)
        } else if kernel_id == Some(V3_WORKSPACE_ENGINE.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_WORKSPACE_ENGINE)
        } else if kernel_id == Some(V3_BIG_SEAL.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_BIG_SEAL)
        } else if kernel_id == Some(V3_DEPTH_PROBE.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_DEPTH_PROBE)
        } else if kernel_id == Some(V3_TICK_REJECT.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_TICK_REJECT)
        } else if kernel_id == Some(V3_TICK_COUNTER.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_TICK_COUNTER)
        } else if kernel_id == Some(V3_RESOURCE_COUNTER.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_RESOURCE_COUNTER)
        } else if kernel_id == Some(V3_RESOURCE_ENGINE.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_RESOURCE_ENGINE)
        } else if kernel_id == Some(V3_LANE_COUNTER.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_LANE_COUNTER)
        } else if kernel_id == Some(V3_REJECT_COUNTER.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_REJECT_COUNTER)
        } else if kernel_id == Some(V3_UNDECLARED_REJECT.manifest().id) {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_UNDECLARED_REJECT)
        } else {
            crate::stateful::v3::process_with_kernel(program, accounts, data, &V3_COUNTER)
        }
    } else if data.get(1) == Some(&stateful_v2::WIRE_VERSION) {
        let kernel = ScaledWorkloadKernel::new();
        stateful::process_with_kernel_or_else(program, accounts, data, &kernel, |_, _, _| {
            Err(solana_program::program_error::ProgramError::InvalidInstructionData)
        })
    } else {
        stateful::process_with_kernel_or_else(program, accounts, data, &COUNTER, |_, _, _| {
            Err(solana_program::program_error::ProgramError::InvalidInstructionData)
        })
    }
}

#[cfg(feature = "kernel-conform-entry")]
/// The kernel kit's same-source reference for the v3 test counters
/// (`kernel_kit::conformance::serve_account_request`, tag `CONFORM_TAG`):
/// the same kernels `dcg-kernel-conform` serves natively.
pub fn conform(program: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    static STATEFUL: [&'static dyn StatefulKernel; 6] = [
        &V3_COUNTER,
        &V3_LANE_COUNTER,
        &V3_REJECT_COUNTER,
        &V3_UNDECLARED_REJECT,
        &V3_RESOURCE_COUNTER,
        &V3_TICK_COUNTER,
    ];
    let registry = crate::kernel_kit::conformance::Registry { app: None, stateful: &STATEFUL };
    crate::kernel_kit::conformance::serve_account_request(&registry, program, accounts)
}

