// SPDX-License-Identifier: GPL-3.0-only

//! Mode composition with mode results v1 (design
//! `docs/design/mode-results-v1.md`): a consensus session whose every input is
//! a verified output of a FINAL optimistic (v2.1) run.
//!
//! The kernel, `dcg-importsum-v1`, adds each 4-byte input (an `i32`) to a
//! running sum and counts it. The program routes every DCG stateful v3
//! instruction to the runtime except the raw `WRITE_INPUT`, which it refuses.
//! Inputs enter only through [`TAG_IMPORT`]: the program reads the run's
//! result (`read_run_result`, CPI-free), requires the template it trusts and
//! a least challenge window, opens the named output against the run's out
//! tree, checks the value bytes against it, and only then writes those bytes
//! into the session's input stream. So the session's state is a consensus
//! computation over optimistic results, and its security basis is the union
//! of both: chain execution here, and the run's challenge window, bonds and
//! an honest challenger there.
//!
//! What the example leaves to an application: it does not stop the same
//! output being imported twice (a kernel that must count each output once
//! records the run id and index it has seen, or the importer keys inputs by
//! them), and it trusts one template by id.

use dcg_program::kernel::{
    Kernel, KernelError, KernelManifest, StateSpanMut, StatefulKernel, TransitionDisposition, TransitionOutcome,
    VersionedId,
};
use dcg_program::kernel_kit::KernelDecl;
use dcg_program::result::{self, ResultError, ResultRequirements};
use dcg_program::stateful::{self as sw, v3};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey};

/// The program that holds the optimistic runs this app imports from.
pub const RUN_HOST: Pubkey = Pubkey::new_from_array([0xD6; 32]);
/// The template id whose FINAL runs this app trusts (the Hello Graph golden
/// template in the tests; an application pins its own).
pub const TRUSTED_TEMPLATE_ID: [u8; 32] = [
    0x75, 0x25, 0x2c, 0xb6, 0xd1, 0xbc, 0xd3, 0xf5, 0x49, 0x53, 0x7a, 0xd3, 0x92, 0x1c, 0x03, 0xa0, 0xbe, 0x89, 0x32,
    0xd1, 0xe0, 0x8a, 0x5c, 0x7c, 0xbf, 0x6c, 0xb2, 0xe8, 0x4b, 0x85, 0x5c, 0x1a,
];
/// The least challenge window (slots) this app accepts for an imported run.
pub const MIN_CHALLENGE_WINDOW: u64 = 750;

/// IMPORT: `[TAG_IMPORT, sequence:u32, index:u64, value_ref[55], value[4], path[32 x]]`;
/// accounts `[authority(s), session(w), stream(w), run, template]`.
pub const TAG_IMPORT: u8 = 200;
/// Import refusals: `IMPORT_ERROR_BASE + ResultError`, and `IMPORT_ERROR_BASE
/// + 100` for value bytes that are not the output's.
pub const IMPORT_ERROR_BASE: u32 = 0x4900;
pub const VALUE_BYTES: usize = 4;

pub const INPUT_LAYOUT: VersionedId = VersionedId { id: 0x494d_5049, version: 1 };
pub const OUTPUT_LAYOUT: VersionedId = VersionedId { id: 0x494d_504f, version: 1 };
pub const STATE_SCHEMA: VersionedId = VersionedId { id: 0x494d_5053, version: 1 };
pub const STATE_BYTES: usize = 16;

static MODES: [VersionedId; 1] = [v3::MODE_CONSENSUS_V3];
pub static MANIFEST: KernelManifest = KernelDecl::new("dcg-importsum-v1", 1, 1)
    .input(INPUT_LAYOUT, VALUE_BYTES as u32)
    .output(OUTPUT_LAYOUT, 16)
    .state(STATE_SCHEMA, STATE_BYTES as u32)
    .compute(50_000, 8)
    .modes(&MODES)
    .build();

pub struct ImportSum;
pub static IMPORT_SUM: ImportSum = ImportSum;

/// State `count:u64 | sum:i64` (LE) in its spans, in order.
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

impl Kernel for ImportSum {
    fn manifest(&self) -> &'static KernelManifest {
        &MANIFEST
    }
    fn execute(&self, _input: &[u8], _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
}

impl StatefulKernel for ImportSum {
    fn initial_state(&self, _output: &mut [u8]) -> Result<usize, KernelError> {
        Err(KernelError::Refused)
    }
    fn transition(&self, _: &[u8], _: &[u8], _: &mut [u8], _: &mut [u8]) -> Result<(usize, usize), KernelError> {
        Err(KernelError::Refused)
    }
    fn initial_state_spans(&self, spans: &mut [StateSpanMut<'_>]) -> Result<usize, KernelError> {
        gather(spans)?;
        scatter(&[0; STATE_BYTES], spans);
        Ok(STATE_BYTES)
    }
    fn transition_spans_with_outcome(
        &self,
        input: &[u8],
        spans: &mut [StateSpanMut<'_>],
        output: &mut [u8],
    ) -> Result<TransitionOutcome, KernelError> {
        let value: [u8; VALUE_BYTES] = input.try_into().map_err(|_| KernelError::InvalidInput)?;
        let mut state = gather(spans)?;
        let count = u64::from_le_bytes(state[..8].try_into().unwrap()).checked_add(1).ok_or(KernelError::Refused)?;
        let sum = i64::from_le_bytes(state[8..].try_into().unwrap())
            .checked_add(i64::from(i32::from_le_bytes(value)))
            .ok_or(KernelError::Refused)?;
        state[..8].copy_from_slice(&count.to_le_bytes());
        state[8..].copy_from_slice(&sum.to_le_bytes());
        scatter(&state, spans);
        output.get_mut(..STATE_BYTES).ok_or(KernelError::OutputTooSmall)?.copy_from_slice(&state);
        Ok(TransitionOutcome { output_bytes: STATE_BYTES, disposition: TransitionDisposition::Continue })
    }
}

fn import(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [authority, session, stream, run, template] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let fail = |e: ResultError| ProgramError::Custom(IMPORT_ERROR_BASE + e as u32);
    let body = data.get(1..).ok_or(ProgramError::InvalidInstructionData)?;
    let head = 4 + 8 + 55 + VALUE_BYTES;
    if body.len() < head || (body.len() - head) % 32 != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let sequence: [u8; 4] = body[..4].try_into().unwrap();
    let index = u64::from_le_bytes(body[4..12].try_into().unwrap());
    let value_ref: [u8; 55] = body[12..67].try_into().unwrap();
    let value = &body[67..head];
    let path: Vec<[u8; 32]> = body[head..].chunks_exact(32).map(|c| c.try_into().unwrap()).collect();

    // The run: FINAL, the trusted template, a long enough challenge window.
    let r = result::read_run_result(&RUN_HOST, run, template).map_err(fail)?;
    r.require(&ResultRequirements {
        mode: Some(result::MODE_OPTIMISTIC),
        template_id: Some(TRUSTED_TEMPLATE_ID),
        min_challenge_window: Some(MIN_CHALLENGE_WINDOW),
        ..Default::default()
    })
    .map_err(fail)?;
    // The output and its bytes.
    r.open_output(index, &value_ref, &path).map_err(fail)?;
    if !result::plain_value_matches(&value_ref, value) {
        return Err(ProgramError::Custom(IMPORT_ERROR_BASE + 100));
    }
    // Only now does the value enter the session's stream: the runtime's own
    // WRITE_INPUT checks (authority, policy, window) still apply.
    let mut write = vec![sw::TAG_WRITE_INPUT, v3::WIRE_VERSION];
    write.extend_from_slice(&sequence);
    write.push(VALUE_BYTES as u8);
    write.extend_from_slice(value);
    v3::process_with_kernel(program_id, &[authority.clone(), session.clone(), stream.clone()], &write, &IMPORT_SUM)
}

/// The program: imports, and every other v3 instruction except a raw write.
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match data.first() {
        Some(&TAG_IMPORT) => import(program_id, accounts, data),
        Some(&sw::TAG_WRITE_INPUT) => Err(ProgramError::InvalidInstructionData),
        _ => v3::process_with_kernel(program_id, accounts, data, &IMPORT_SUM),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
