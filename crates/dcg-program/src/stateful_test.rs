// SPDX-License-Identifier: GPL-3.0-only

//! Small statically linked application kernel for the stateful SBF mechanics
//! test. It is a two-value counter, not a Doom or model adapter.

use crate::{
    kernel::{
        AccountSpan, Kernel, KernelError, KernelId, KernelManifest, PortLayout, ResourceLimits,
        StateSchema, StateSpanMut, StatefulKernel, VersionedId, ViewAbi,
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

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.get(1) == Some(&stateful_v2::WIRE_VERSION) {
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
