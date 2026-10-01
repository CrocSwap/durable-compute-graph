//! Pure revisioned commitments for the contents of a region.
//!
//! This module deliberately contains no account access, instruction handling,
//! PDA derivation, or DRS1 lifecycle logic. Its encodings match Basanos's
//! `region_seal::region_content_seed` and `region_seal::fold_account` byte for
//! byte. The shared vectors are in
//! `tests/golden/dcg/lifecycle/region_content_v1.tsv`.

use crate::hash::sha256;

/// Domain separator for the v1 region-content fold.
pub const REGION_CONTENT_DOMAIN_V1: &[u8] = b"basanos/dcg-region-content/1";

/// Seed a region-content fold from its identity and declared geometry.
///
/// Integer fields are encoded little-endian, in the order
/// `region_id:u16 | region_byte_length:u64 | account_count:u32`.
pub fn seed_v1(region_id: u16, region_byte_length: u64, account_count: u32) -> [u8; 32] {
    sha256(&[
        REGION_CONTENT_DOMAIN_V1,
        &region_id.to_le_bytes(),
        &region_byte_length.to_le_bytes(),
        &account_count.to_le_bytes(),
    ])
}

/// Fold one account-content digest into a running region-content commitment.
///
/// Integer fields are encoded little-endian, in the order
/// `running | region_offset:u64 | account_byte_length:u64 | content_digest`.
pub fn fold_account_v1(
    running: &[u8; 32],
    region_offset: u64,
    account_byte_length: u64,
    account_content_digest: &[u8; 32],
) -> [u8; 32] {
    sha256(&[
        REGION_CONTENT_DOMAIN_V1,
        running,
        &region_offset.to_le_bytes(),
        &account_byte_length.to_le_bytes(),
        account_content_digest,
    ])
}
