// SPDX-License-Identifier: GPL-3.0-only

//! A template application program embedding the DCG stateful runtime (alpha
//! plan C0). One kernel, `dcg-tally-v1`: each 1-byte input adds its value to
//! a running sum and counts it; the input 0 is rejected (consumed, state
//! unchanged, code 1). Copy this crate, replace the kernel, keep the
//! entrypoint. See `docs/session-quickstart.md`.

use dcg_program::kernel::{
    Kernel, KernelError, KernelManifest, StateSpanMut, StatefulKernel, TransitionDisposition, TransitionOutcome,
    VersionedId,
};
use dcg_program::kernel_kit::KernelDecl;
use dcg_program::stateful::v3::MODE_CONSENSUS_V3;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

/// Input layout `TALI` v1, state schema `TALS` v1.
pub const INPUT_LAYOUT: VersionedId = VersionedId { id: 0x5441_4c49, version: 1 };
pub const OUTPUT_LAYOUT: VersionedId = VersionedId { id: 0x5441_4c4f, version: 1 };
pub const STATE_SCHEMA: VersionedId = VersionedId { id: 0x5441_4c53, version: 1 };
/// The reject code for the input 0.
pub const REJECT_ZERO: u32 = 1;
pub const STATE_BYTES: usize = 16;

static MODES: [VersionedId; 1] = [MODE_CONSENSUS_V3];
pub static MANIFEST: KernelManifest = KernelDecl::new("dcg-tally-v1", 1, 1)
    .input(INPUT_LAYOUT, 1)
    .output(OUTPUT_LAYOUT, 16)
    .state(STATE_SCHEMA, STATE_BYTES as u32)
    .compute(50_000, 8)
    .modes(&MODES)
    .rejects_input()
    .build();

pub struct Tally;
pub static TALLY: Tally = Tally;

/// One tally step on the canonical state bytes `count:u64 | sum:u64` (LE).
fn step(input: &[u8], state: &mut [u8; STATE_BYTES]) -> Result<TransitionOutcome, KernelError> {
    let [value] = input else { return Err(KernelError::InvalidInput) };
    if *value == 0 {
        return Ok(TransitionOutcome { output_bytes: 0, disposition: TransitionDisposition::Reject { code: REJECT_ZERO } });
    }
    let count = u64::from_le_bytes(state[..8].try_into().unwrap()).checked_add(1).ok_or(KernelError::Refused)?;
    let sum = u64::from_le_bytes(state[8..].try_into().unwrap())
        .checked_add(u64::from(*value))
        .ok_or(KernelError::Refused)?;
    state[..8].copy_from_slice(&count.to_le_bytes());
    state[8..].copy_from_slice(&sum.to_le_bytes());
    Ok(TransitionOutcome { output_bytes: STATE_BYTES, disposition: TransitionDisposition::Continue })
}

/// The state's logical bytes, gathered from its spans (any split).
fn gather(spans: &[StateSpanMut<'_>]) -> Result<[u8; STATE_BYTES], KernelError> {
    let mut out = [0u8; STATE_BYTES];
    let mut at = 0usize;
    for span in spans {
        if span.schema != STATE_SCHEMA || span.offset as usize != at || at + span.data.len() > STATE_BYTES {
            return Err(KernelError::InvalidInput);
        }
        out[at..at + span.data.len()].copy_from_slice(span.data);
        at += span.data.len();
    }
    if at != STATE_BYTES {
        return Err(KernelError::StateTooLarge);
    }
    Ok(out)
}

fn scatter(state: &[u8; STATE_BYTES], spans: &mut [StateSpanMut<'_>]) {
    let mut at = 0usize;
    for span in spans {
        let n = span.data.len();
        span.data.copy_from_slice(&state[at..at + n]);
        at += n;
    }
}

impl Kernel for Tally {
    fn manifest(&self) -> &'static KernelManifest {
        &MANIFEST
    }
    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused) // stateful only
    }
}

impl StatefulKernel for Tally {
    fn initial_state(&self, output: &mut [u8]) -> Result<usize, KernelError> {
        let out = output.get_mut(..STATE_BYTES).ok_or(KernelError::OutputTooSmall)?;
        out.fill(0);
        Ok(STATE_BYTES)
    }

    fn transition(
        &self,
        input: &[u8],
        prior_state: &[u8],
        output: &mut [u8],
        next_state: &mut [u8],
    ) -> Result<(usize, usize), KernelError> {
        let mut state: [u8; STATE_BYTES] = prior_state.try_into().map_err(|_| KernelError::InvalidInput)?;
        let outcome = step(input, &mut state)?;
        if outcome.disposition != TransitionDisposition::Continue || output.len() < STATE_BYTES || next_state.len() < STATE_BYTES {
            return Err(KernelError::Refused); // the flat v1/v2 form has no reject
        }
        output[..STATE_BYTES].copy_from_slice(&state);
        next_state[..STATE_BYTES].copy_from_slice(&state);
        Ok((STATE_BYTES, STATE_BYTES))
    }

    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        gather(spans)?; // checks the layout
        scatter(&[0; STATE_BYTES], spans);
        Ok(STATE_BYTES)
    }

    fn transition_spans_with_outcome(
        &self,
        input: &[u8],
        spans: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        let mut state = gather(spans)?;
        let outcome = step(input, &mut state)?;
        if outcome.disposition == TransitionDisposition::Continue {
            output.get_mut(..STATE_BYTES).ok_or(KernelError::OutputTooSmall)?.copy_from_slice(&state);
            scatter(&state, spans);
        }
        Ok(outcome)
    }
}

/// The program: every instruction goes to the DCG stateful v3 runtime with
/// this application's kernel.
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    dcg_program::stateful::v3::process_with_kernel(program_id, accounts, data, &TALLY)
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
