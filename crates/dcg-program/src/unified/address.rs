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

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;

    /// The shared seeds agree with the closure-v2 derivations the older
    /// documents use (a v5 document keeps DCM2, DPR2 and DCR2 seeds).
    #[test]
    fn document_seeds_are_the_closure_v2_ones() {
        let program = Pubkey::new_from_array([7; 32]);
        let d = [9u8; 32];
        let assert_matches_legacy = |actual: (Pubkey, CanonicalBump), legacy: (Pubkey, u8)| {
            assert_eq!(actual.0, legacy.0);
            assert_eq!(actual.1.value(), legacy.1);
        };
        assert_matches_legacy(
            document(&program, &d),
            crate::closure_v2::document_address(&program, &d),
        );
        assert_matches_legacy(
            positions(&program, &d),
            crate::closure_v2::position_page_address(&program, &d),
        );
        assert_matches_legacy(
            result(&program, &d),
            crate::closure_v2::result_address(&program, &d),
        );
        assert_eq!(REGISTRY_SEED.len(), 25);
        assert_ne!(REGISTRY_SEED, crate::envelope_seal::REGISTRY_SEED);
    }

    /// Every PDA of spec §16.4 reproduces the golden `addresses` vector.
    #[test]
    fn addresses_match_the_golden() {
        use crate::unified::classes::tests::{golden, unhex};
        let g = golden();
        let a = &g["addresses"];
        let key = |v: &serde_json::Value| -> Pubkey { v.as_str().unwrap().parse().unwrap() };
        let want = |name: &str| -> (Pubkey, u8) {
            let row = &a[name];
            (
                row[0].as_str().unwrap().parse().unwrap(),
                row[1].as_u64().unwrap() as u8,
            )
        };
        let assert_canonical = |actual: (Pubkey, CanonicalBump), expected: (Pubkey, u8)| {
            assert_eq!(actual.0, expected.0);
            assert_eq!(actual.1.value(), expected.1);
        };
        let program = key(&a["program"]);
        let descriptor: [u8; 32] = unhex(g["dpd2"]["digest"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_canonical(config(&program), want("config"));
        assert_canonical(registry(&program, 1), want("registry"));
        assert_canonical(document(&program, &descriptor), want("document"));
        assert_canonical(positions(&program, &descriptor), want("positions"));
        assert_canonical(family_slots(&program, &descriptor), want("family_slots"));
        assert_canonical(result(&program, &descriptor), want("result"));
        let (challenge_key, _) = challenge(
            &program,
            &descriptor,
            &key(&a["challenger"]),
            a["nonce"].as_u64().unwrap() as u32,
        );
        assert_eq!(challenge_key, want("challenge").0);
        assert_eq!(
            settlement_escrow(&program, &challenge_key),
            want("settlement_escrow")
        );
        let loader = solana_program::bpf_loader_upgradeable::id();
        assert_eq!(
            Pubkey::find_program_address(&[program.as_ref()], &loader),
            want("programdata")
        );
    }

    /// The bond escrow's seeds (spec §1.4) are the committed ones, and it is
    /// **not** revision 7's challenge escrow: one document, one account, one
    /// exit, whichever of the two routes that escrow got there first.
    #[test]
    fn the_bond_escrow_is_keyed_on_the_descriptor() {
        let program = Pubkey::new_from_array([7; 32]);
        let challenge = Pubkey::new_from_array([11; 32]);
        let d = [9u8; 32];
        assert_eq!(
            bond_escrow(&program, &d),
            Pubkey::find_program_address(&[BOND_ESCROW_SEED, d.as_ref()], &program)
        );
        assert_ne!(
            bond_escrow(&program, &d),
            settlement_escrow(&program, &challenge)
        );
        // A different document, a different escrow: this is per document.
        assert_ne!(
            bond_escrow(&program, &d),
            bond_escrow(&program, &[10u8; 32])
        );
        assert_eq!(BOND_ESCROW_SEED, b"dcg-hcl-bond-escrow");
        assert_ne!(BOND_ESCROW_SEED, SETTLEMENT_ESCROW_SEED);
    }
}
