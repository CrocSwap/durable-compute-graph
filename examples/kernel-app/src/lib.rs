// SPDX-License-Identifier: GPL-3.0-only

//! A template application program for DCG optimistic mode (alpha plan
//! criterion 5): DCG's v2.1 disputes (tag 227) with one application STEP
//! kernel, `ex-polyhash-v1`. A dispute over a step of this kernel is ruled by
//! replaying the kernel in this program. Copy the crate, replace the kernel,
//! keep the entrypoint. See `docs/kernel-app.md`.

use dcg_program::compatibility::REVISION8_COMPATIBILITY;
use dcg_program::kernel::{
    AccountSpan, AdmissionScan, ApplicationManifest, Kernel, KernelError, KernelManifest, LegacyFormBinding,
    OptimisticReplayBinding, VersionedId, MODE_STEP_V21,
};
use dcg_program::kernel_kit::KernelDecl;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey};

pub const INPUT_LAYOUT: VersionedId = VersionedId { id: 0x4850_4c45, version: 1 };
pub const OUTPUT_LAYOUT: VersionedId = VersionedId { id: 0x4850_4c4f, version: 1 };
pub const MAX_INPUT_BYTES: u32 = 4_096;
/// 2^61 - 1, a Mersenne prime.
pub const MODULUS: u64 = (1 << 61) - 1;

static MODES: [VersionedId; 1] = [MODE_STEP_V21];
pub static MANIFEST: KernelManifest = KernelDecl::new("ex-polyhash-v1", 1, 1)
    .input(INPUT_LAYOUT, MAX_INPUT_BYTES)
    .output(OUTPUT_LAYOUT, 8)
    .compute(200_000, 1)
    .modes(&MODES)
    .build();

/// `ex-polyhash-v1`: over its input spans in order (1 to 4,096 bytes in all),
/// h = h * 257 + byte + 1 (mod 2^61 - 1), starting from 0; output h as u64 LE.
pub struct PolyHash;
pub static POLYHASH: PolyHash = PolyHash;

impl Kernel for PolyHash {
    fn manifest(&self) -> &'static KernelManifest {
        &MANIFEST
    }

    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
        self.execute_spans(
            &[AccountSpan {
                key: [0; 32],
                owner: [0; 32],
                is_signer: false,
                is_writable: false,
                schema: INPUT_LAYOUT,
                offset: 0,
                data: input,
            }],
            output,
        )
    }

    fn execute_spans(&self, inputs: &[AccountSpan<'_>], output: &mut [u8]) -> Result<usize, KernelError> {
        let total: usize = inputs.iter().map(|s| s.data.len()).sum();
        if inputs.is_empty() || total == 0 || total > MAX_INPUT_BYTES as usize {
            return Err(KernelError::InvalidInput);
        }
        if output.len() < 8 {
            return Err(KernelError::OutputTooSmall);
        }
        let mut h: u64 = 0;
        for span in inputs {
            for &b in span.data {
                h = ((h as u128 * 257 + b as u128 + 1) % MODULUS as u128) as u64;
            }
        }
        output[..8].copy_from_slice(&h.to_le_bytes());
        Ok(8)
    }
}

static KERNELS: [&'static dyn Kernel; 1] = [&POLYHASH];
static NO_REPLAYS: [OptimisticReplayBinding; 0] = [];
static NO_FORMS: [LegacyFormBinding; 0] = [];

/// The application's kernel manifest: the kernels its disputes may replay.
// The legacy fields are deprecated (revision 8 retired); they go next release.
#[allow(deprecated)]
pub static APPLICATION: ApplicationManifest = ApplicationManifest {
    application_id: b"dcg-example-kernel-app/1",
    version: 1,
    kernels: &KERNELS,
    optimistic_replays: &NO_REPLAYS,
    legacy_forms: &NO_FORMS,
    require_legacy_form_binding: false,
    admission_scan: AdmissionScan::Full,
    hooks: &REVISION8_COMPATIBILITY,
    decision_routes: &REVISION8_COMPATIBILITY,
};

/// The program: tag 227 (DCG v2.1 disputes) with this application's kernels;
/// every other instruction is refused.
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    dcg_program::touch_runtime_marker();
    match data.first() {
        Some(227) => dcg_program::disputes_v21::process(program_id, accounts, data, &APPLICATION),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
