// SPDX-License-Identifier: GPL-3.0-only

//! Small statically linked application kernel for the stateful SBF mechanics
//! test. It is a two-value counter, not a Doom or model adapter.

use crate::{
    kernel::{
        Kernel, KernelError, KernelId, KernelManifest, PortLayout, ResourceLimits, StateSchema,
        StateSpanMut, StatefulKernel, VersionedId, ViewAbi,
    },
    stateful,
};
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

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    stateful::process_with_kernel(program, accounts, data, &COUNTER)
}
