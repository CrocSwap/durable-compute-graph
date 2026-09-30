//! SHA-256, through the SBF syscall on chain and `sha2` off it.
//!
//! Every digest in this crate is `sha256(part_0 | part_1 | ...)`, and the two
//! implementations produce the same bytes -- SHA-256 is SHA-256. What differs
//! is the cost, and the difference is not a detail:
//!
//! *Measured*, DCG step 4a: with `sha2`'s software SHA-256 compiled into the
//! SBF image, sealing a 52,572-byte / 166-entry fly segment exhausted a
//! **1,399,850-CU** meter inside `Descriptor::validate`. The same document
//! seals well inside the meter through `sol_sha256`. A software block
//! compression on sBPF is ~2,000 CU; the syscall is 85 CU plus one per two
//! bytes. At 373,260 bytes -- the 20-window prefix -- that is the difference
//! between roughly 190,000 CU and roughly 23,000,000.
//!
//! So this module exists, and `sha2` is linked only for the host.

/// The most parts any one digest in this crate concatenates: the descriptor
/// digest's tag, its five committed header fields (version, flags, id,
/// total_bytes, `header_digest`), plus ten clause digests (v2; the v1
/// descriptor digest had no `header_digest` and used one fewer part).
pub const MAX_PARTS: usize = 16;

/// `sha256` over the concatenation of `parts`.
#[inline]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        solana_program::hash::hashv(parts).to_bytes()
    }
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }
}

/// A fixed-capacity part list, so a digest can be built without allocating.
pub struct Parts<'a> {
    parts: [&'a [u8]; MAX_PARTS],
    count: usize,
}

impl<'a> Parts<'a> {
    pub const fn new() -> Self {
        Self {
            parts: [&[]; MAX_PARTS],
            count: 0,
        }
    }

    /// Append one part. Silently ignoring an overflow would change a digest,
    /// so this saturates loudly in debug and is unreachable by construction:
    /// every caller in this crate appends a fixed number of parts below
    /// [`MAX_PARTS`].
    #[inline]
    pub fn push(&mut self, part: &'a [u8]) -> &mut Self {
        debug_assert!(self.count < MAX_PARTS, "digest part overflow");
        if self.count < MAX_PARTS {
            self.parts[self.count] = part;
            self.count += 1;
        }
        self
    }

    #[inline]
    pub fn finish(&self) -> [u8; 32] {
        sha256(&self.parts[..self.count])
    }
}

impl Default for Parts<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_part_list_is_the_concatenation() {
        let mut parts = Parts::new();
        parts.push(b"abc").push(b"def");
        assert_eq!(parts.finish(), sha256(&[b"abcdef"]));
        assert_eq!(Parts::new().finish(), sha256(&[]));
    }

    #[test]
    fn the_empty_hash_is_the_known_constant() {
        // `sha256("")`, so a future syscall swap cannot quietly change what
        // this module means.
        assert_eq!(
            sha256(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}
