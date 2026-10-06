//! Every account address of the unified format, in one place (spec §1).
//!
//! | account | seeds |
//! |---|---|
//! | DRP2 | `"dcg-envelope-registry-pt2" \| EPOCH:u32 \| registry_id:u32` |
//! | DEA2 | `"dcg-envelope-admission-v2" \| registry[32] \| PT2S[32] \| P:u32` |
//! | DCM2 v5 | `"dcg-hcl-document" \| descriptor` |
//! | DPR2 | `"dcg-hcl-positions" \| descriptor` |
//! | DFS2 | `"dcg-hcl-family-slots" \| descriptor` |
//! | DCR2 v3 | `"dcg-hcl-result" \| descriptor` |
//! | DRU1 | `"dcg-hcl-response" \| DCR1` (`closure_v2_response`) |
//!
//! DCR1 records are challenger-created (not PDAs), as v3/v4.

use super::EPOCH;
use crate::account_provenance::CanonicalBump;
use solana_program::pubkey::Pubkey;

fn canonical(program: &Pubkey, seeds: &[&[u8]]) -> (Pubkey, CanonicalBump) {
    let bump = CanonicalBump::find(seeds, program);
    (*bump.address(), bump)
}

pub const CONFIG_SEED: &[u8] = b"dcg-config";
pub const TEMPLATE_SEAL_SEED: &[u8] = b"dcg-template-seal";
/// Revision 8's DTU1 (spec §1.7): the per-template use counter, keyed on the
/// sealed PT2S and its digest, exactly as the DTA1 approval is.
pub const TEMPLATE_USE_SEED: &[u8] = b"dcg-template-use";
pub const CHALLENGE_SEED: &[u8] = b"dcg-unified-challenge";
pub const REGISTRY_SEED: &[u8] = b"dcg-envelope-registry-pt2";
pub const ADMISSION_SEED: &[u8] = b"dcg-envelope-admission-v2";
pub const DOCUMENT_SEED: &[u8] = b"dcg-hcl-document";
pub const POSITIONS_SEED: &[u8] = b"dcg-hcl-positions";
pub const FAMILY_SLOTS_SEED: &[u8] = b"dcg-hcl-family-slots";
pub const RESULT_SEED: &[u8] = b"dcg-hcl-result";
pub const SETTLEMENT_ESCROW_SEED: &[u8] = b"dcg-hcl-settlement";
/// Revision 8's **bond escrow** (spec §1.4, D12): the one account a seized
/// pot waits in, on both routes that can seize one. Keyed on the **descriptor**
/// rather than on the DCR2 key, so a reader derives it from DCR2 8..40 alone.
/// Distinct from [`SETTLEMENT_ESCROW_SEED`], which revision 7's challenge route
/// still derives and no revision-8 document ever creates.
pub const BOND_ESCROW_SEED: &[u8] = b"dcg-hcl-bond-escrow";

pub fn config(program: &Pubkey) -> (Pubkey, CanonicalBump) {
    canonical(program, &[CONFIG_SEED])
}
pub fn template_seal(
    program: &Pubkey,
    pt2s: &Pubkey,
    pt2s_sha256: &[u8; 32],
) -> (Pubkey, CanonicalBump) {
    canonical(program, &[TEMPLATE_SEAL_SEED, pt2s.as_ref(), pt2s_sha256])
}
pub fn template_use(
    program: &Pubkey,
    pt2s: &Pubkey,
    pt2s_sha256: &[u8; 32],
) -> (Pubkey, CanonicalBump) {
    canonical(program, &[TEMPLATE_USE_SEED, pt2s.as_ref(), pt2s_sha256])
}
pub fn challenge(
    program: &Pubkey,
    descriptor: &[u8; 32],
    challenger: &Pubkey,
    nonce: u32,
) -> (Pubkey, CanonicalBump) {
    canonical(
        program,
        &[
            CHALLENGE_SEED,
            descriptor,
            challenger.as_ref(),
            &nonce.to_le_bytes(),
        ],
    )
}
pub fn registry(program: &Pubkey, registry_id: u32) -> (Pubkey, CanonicalBump) {
    canonical(
        program,
        &[
            REGISTRY_SEED,
            &EPOCH.to_le_bytes(),
            &registry_id.to_le_bytes(),
        ],
    )
}
pub fn admission(
    program: &Pubkey,
    registry: &Pubkey,
    pt2s: &Pubkey,
    positions: u32,
) -> (Pubkey, CanonicalBump) {
    canonical(
        program,
        &[
            ADMISSION_SEED,
            registry.as_ref(),
            pt2s.as_ref(),
            &positions.to_le_bytes(),
        ],
    )
}
pub fn document(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, CanonicalBump) {
    canonical(program, &[DOCUMENT_SEED, descriptor])
}
pub fn positions(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, CanonicalBump) {
    canonical(program, &[POSITIONS_SEED, descriptor])
}
pub fn family_slots(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, CanonicalBump) {
    canonical(program, &[FAMILY_SLOTS_SEED, descriptor])
}
pub fn result(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, CanonicalBump) {
    canonical(program, &[RESULT_SEED, descriptor])
}
pub fn settlement_escrow(program: &Pubkey, challenge: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SETTLEMENT_ESCROW_SEED, challenge.as_ref()], program)
}
/// The revision-8 bond escrow (spec §1.4). The seed is constant-length and the
/// descriptor is exactly 32 bytes, so the "max seed length" bump is 1 for any
/// program, as it is for every other PDA here.
pub fn bond_escrow(program: &Pubkey, descriptor: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[BOND_ESCROW_SEED, descriptor], program)
}
