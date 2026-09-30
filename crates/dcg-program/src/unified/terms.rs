//! DDT2: every run term of one run. **Revision 7** (`docs/spec/dcg-unified-v1.md`
//! §6.8) is the 96-byte `version = 1` block below and stays normative for a
//! revision-7 document; **revision 8** (`docs/spec/dcg-unified-v8.md` §1.1) is
//! the 136-byte `version = 2` block, which appends the abandonment window and
//! reads byte 42 as the mandatory conviction-bond policy.
//!
//! ```text
//! revision 7, 96 bytes
//!  0 "DDT2" | 4 version:u16 = 1 | 6 reserved:u16 = 0
//!  8 challenge_window_slots:u64 | 16 response_window_slots:u64
//! 24 challenger_bond_lamports:u64 | 32 executor_bond_lamports:u64
//! 40 executor_reward_bps:u16 | 42 reserved[6] = 0
//! 48 settlement_program[32] | 80 custom_settle_window_slots:u64
//! 88 result_retention_slots:u64 | 96 end
//!
//! revision 8, 136 bytes
//!  0 "DDT2" | 4 version:u16 = 2 | 6 reserved:u16 = 0
//!  8 challenge_window_slots:u64 | 16 response_window_slots:u64
//! 24 challenger_bond_lamports:u64 | 32 executor_bond_lamports:u64
//! 40 executor_reward_bps:u16 | 42 bond_policy_kind:u8 | 43 reserved:u8 = 0
//! 44 bond_slasher_bps:u16 | 46 reserved[2] = 0
//! 48 settlement_program[32] | 80 custom_settle_window_slots:u64
//! 88 result_retention_slots:u64 | 96 bond_remainder[32]
//! 128 abandon_after_slots:u64 | 136 end
//! ```
//!
//! The program enforces only mechanical floors (spec §6.8 and §1.1): a
//! challenge can open at least one slot after finalize, one response round
//! fits the response window, no window can overflow a `u64` deadline, the
//! reward share is a share, a custom program has a nonzero opportunity
//! window (and the built-in rule has none), and the retention is at least
//! one slot. Revision 8 adds five more, all in the same decoder and all
//! refused `791`: a policy must exist, the slasher share is a share, the
//! remainder account is nonzero under either kind, the kind agrees with the
//! settlement program and the slasher share, a CUSTOM bond can fund its own
//! escrow, and the abandonment window is at least its stated minimum.
//! `executor_reward_bps` is dead on a revision-8 document (spec §1.1): it is
//! still encoded, bounded and compared, and read by no revision-8 instruction.
//! Bonds are otherwise free `u64` values; a zero bond is admitted.

use super::{CL_OVERFLOW, DISPUTE_TERMS};

pub const TERMS_BYTES: usize = 96;
pub const TERMS_VERSION: u16 = 1;
/// Mechanical cap on every window and on the retention: `slot + window`
/// never overflows `u64`.
pub const WINDOW_CAP: u64 = 1 << 62;
/// Cap on `custom_settle_window_slots` (review finding 5): before this
/// deadline settle tries only the custom route, and the challenger's own
/// record bond is paid in that transaction, so a failing program must not
/// hold it longer than 7 days: 604,800 s at Fogo's 40 ms slot (M1029
/// measured 40.157 ms) = 15,120,000 slots.
pub const CUSTOM_SETTLE_WINDOW_CAP: u64 = 15_120_000;
pub const BPS_DENOMINATOR: u64 = 10_000;
/// Lamports per byte-year of rent under this document's own rent model
/// (ProgramTest's default rent: 3,480 x 2 years), used by every minimum-balance
/// rule in revision 8 (§1.1 check 11, §1.4's credit rule).
pub const RENT_LAMPORTS_PER_BYTE_YEAR: u64 = 6_960;
/// The fewest slots in which the longest single honest round can land (spec
/// §6.8). **Open** until the epoch-4 census measures `C_round`; until then
/// the structural minimum 1, as the host mirror checks.
pub const ROUND_FLOOR_SLOTS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub challenge_window_slots: u64,
    pub response_window_slots: u64,
    pub challenger_bond_lamports: u64,
    pub executor_bond_lamports: u64,
    pub executor_reward_bps: u16,
    pub settlement_program: [u8; 32],
    pub custom_settle_window_slots: u64,
    pub result_retention_slots: u64,
}

impl Terms {
    /// Canonical decode plus the mechanical checks; 791 on any failure.
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != TERMS_BYTES
            || raw[..4] != *b"DDT2"
            || u16::from_le_bytes([raw[4], raw[5]]) != TERMS_VERSION
            || raw[6..8] != [0; 2]
            || raw[42..48] != [0; 6]
        {
            return Err(DISPUTE_TERMS);
        }
        let u64_at = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let terms = Terms {
            challenge_window_slots: u64_at(8),
            response_window_slots: u64_at(16),
            challenger_bond_lamports: u64_at(24),
            executor_bond_lamports: u64_at(32),
            executor_reward_bps: u16::from_le_bytes([raw[40], raw[41]]),
            settlement_program: raw[48..80].try_into().unwrap(),
            custom_settle_window_slots: u64_at(80),
            result_retention_slots: u64_at(88),
        };
        terms.check(ROUND_FLOOR_SLOTS)?;
        Ok(terms)
    }

    /// The only checks the program applies to a term (spec §6.8), in order.
    pub fn check(&self, round_floor_slots: u64) -> Result<(), u32> {
        let custom = self.settlement_program != [0; 32];
        if !(1..=WINDOW_CAP).contains(&self.challenge_window_slots)
            || !(round_floor_slots.max(1)..=WINDOW_CAP).contains(&self.response_window_slots)
            || self.executor_reward_bps as u64 > BPS_DENOMINATOR
            || custom != (self.custom_settle_window_slots != 0)
            || (custom
                && !(1..=CUSTOM_SETTLE_WINDOW_CAP).contains(&self.custom_settle_window_slots))
            || !(1..=WINDOW_CAP).contains(&self.result_retention_slots)
        {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; TERMS_BYTES] {
        let mut out = [0u8; TERMS_BYTES];
        out[..4].copy_from_slice(b"DDT2");
        out[4..6].copy_from_slice(&TERMS_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.challenge_window_slots.to_le_bytes());
        out[16..24].copy_from_slice(&self.response_window_slots.to_le_bytes());
        out[24..32].copy_from_slice(&self.challenger_bond_lamports.to_le_bytes());
        out[32..40].copy_from_slice(&self.executor_bond_lamports.to_le_bytes());
        out[40..42].copy_from_slice(&self.executor_reward_bps.to_le_bytes());
        out[48..80].copy_from_slice(&self.settlement_program);
        out[80..88].copy_from_slice(&self.custom_settle_window_slots.to_le_bytes());
        out[88..96].copy_from_slice(&self.result_retention_slots.to_le_bytes());
        out
    }
}

// ------------------------------------------------------------------ DDT2 v2

/// Revision 8 (spec §1.1): the 136-byte block. The only *appended* field is
/// `abandon_after_slots` at 128, so every offset above it keeps the value
/// revision 8's other three streams already read.
pub const TERMS_BYTES_V2: usize = 136;
pub const TERMS_VERSION_V2: u16 = 2;
/// `bond_policy_kind` (spec §1.1 byte 42). Zero is refused 791: a document
/// with no policy has not disposed of its bond (D10).
pub const BOND_POLICY_NONE: u8 = 0;
pub const BOND_POLICY_STANDARD: u8 = 1;
pub const BOND_POLICY_CUSTOM: u8 = 2;
/// The bond escrow is 0 bytes, system-owned (spec §1.4), so under this
/// document's rent model it is rent-exempt at `minimum_balance(0)`.
pub const BOND_ESCROW_BYTES: usize = 0;
/// `(128 + 0) x 6,960 = 890,880` lamports. The only floor on the bond
/// anywhere, and it exists only on the route that escrows (§1.1 check 11).
pub const BOND_ESCROW_RENT_EXEMPT: u64 = 128 * RENT_LAMPORTS_PER_BYTE_YEAR;
/// §1.1's **structural** production-grace floor, and the only one DCG keeps:
/// `abandon_after_slots` is a `u64` window and a **zero** window would make row
/// 2 of the close fire in the document's own init slot, so any third party
/// holding the fee could close an in-progress document at once. One slot is the
/// whole bound. **The grace a document should actually get is its template's
/// `min_abandon_after_slots`** (§1.7), because the cost of a window that is too
/// short falls on the executor's work and the cost of one that is too long falls
/// on the template owner's rent -- two different parties, so the number is one
/// of theirs. It was 2,592,000 as a protocol constant and is withdrawn as one
/// (the user, 2026-09-26: "DCG sets no default durations").
pub const ABANDON_AFTER_SLOTS_FLOOR: u64 = 1;
/// The number of round deadlines one challenge can take, **derived** (spec
/// §1.1): revision 7 §7.8 derives 9 for the longest position dispute at height
/// 12 "plus the replay", and revision 7 imposes no cap on the count ("the
/// program imposes neither"), so what bounds it is the committed tree height.
/// It is the one window-shaped number DCG still keeps, because it is in no
/// record and no template can choose it: it counts deadlines a protocol
/// computes rather than durations anybody picks.
pub const CHALLENGE_ROUNDS_MAX: u64 = 10;

/// `minimum_balance(len) = (128 + len) x 6,960` (spec §1.4's credit rule).
/// The one rent model this document uses, for the escrow and for every
/// lamport credit a settlement makes.
pub const fn minimum_balance(data_len: usize) -> u64 {
    (128 + data_len as u64) * RENT_LAMPORTS_PER_BYTE_YEAR
}

/// A lamport credit is executed iff it leaves the destination at or above
/// `minimum_balance(len(destination))` (spec §1.4). A destination that fails
/// is **skipped, never refused**: the amount stays in the source account,
/// where the close's own drain sends it anyway, so nothing is stranded and no
/// route can be blocked by a wallet.
pub fn credit(destination_lamports: u64, destination_data_len: usize, amount: u64) -> Option<u64> {
    destination_lamports
        .checked_add(amount)
        .filter(|b| *b >= minimum_balance(destination_data_len))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms2 {
    pub challenge_window_slots: u64,
    pub response_window_slots: u64,
    pub challenger_bond_lamports: u64,
    pub executor_bond_lamports: u64,
    /// Dead on a revision-8 document (spec §1.1): encoded, bounded, compared
    /// at bind, read by no revision-8 instruction.
    pub executor_reward_bps: u16,
    pub bond_policy_kind: u8,
    pub bond_slasher_bps: u16,
    pub settlement_program: [u8; 32],
    pub custom_settle_window_slots: u64,
    pub result_retention_slots: u64,
    pub bond_remainder: [u8; 32],
    pub abandon_after_slots: u64,
}

impl Terms2 {
    /// Canonical decode plus the mechanical checks; 791 on any failure.
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != TERMS_BYTES_V2
            || raw[..4] != *b"DDT2"
            || u16::from_le_bytes([raw[4], raw[5]]) != TERMS_VERSION_V2
            || raw[6..8] != [0; 2]
            || raw[43] != 0
            || raw[46..48] != [0; 2]
        {
            return Err(DISPUTE_TERMS);
        }
        let u64_at = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let terms = Terms2 {
            challenge_window_slots: u64_at(8),
            response_window_slots: u64_at(16),
            challenger_bond_lamports: u64_at(24),
            executor_bond_lamports: u64_at(32),
            executor_reward_bps: u16::from_le_bytes([raw[40], raw[41]]),
            bond_policy_kind: raw[42],
            bond_slasher_bps: u16::from_le_bytes([raw[44], raw[45]]),
            settlement_program: raw[48..80].try_into().unwrap(),
            custom_settle_window_slots: u64_at(80),
            result_retention_slots: u64_at(88),
            bond_remainder: raw[96..128].try_into().unwrap(),
            abandon_after_slots: u64_at(128),
        };
        terms.check(ROUND_FLOOR_SLOTS)?;
        Ok(terms)
    }

    /// The only checks the program applies to a term **on its own** (spec
    /// §1.1), in order: revision 7's list 1-6 unchanged (byte 42 is no longer
    /// reserved and the length is 136), then 7-12. Every check is a property of
    /// the 136 bytes and nothing outside them.
    ///
    /// **Checks 13-16 are gone, and this is the user's decision of 2026-09-26**
    /// — the four protocol-wide caps and the lifetime clamp's constant are not
    /// DCG's to set. What replaces them is `check_template`, which needs the
    /// template, and the two deadline writers' clamp, which reads the template's
    /// own lifetime limit. A decoder on its own is therefore **permissive again**
    /// (`2^62` on the two windows, revision 7's own bound, rather than the
    /// cap this branch carried), and that is sound for one reason: **init is the
    /// only admission path**, it always runs `check_template` in the same
    /// transaction, and DDT2 is hashed into the descriptor, so no document can
    /// exist whose terms were not compared against its template's limits.
    pub fn check(&self, round_floor_slots: u64) -> Result<(), u32> {
        let custom = self.settlement_program != [0; 32];
        // 1-6: revision 7's mechanical bounds.
        if !(1..=WINDOW_CAP).contains(&self.challenge_window_slots)
            || !(round_floor_slots.max(1)..=WINDOW_CAP).contains(&self.response_window_slots)
            || self.executor_reward_bps as u64 > BPS_DENOMINATOR
            || custom != (self.custom_settle_window_slots != 0)
            || (custom
                && !(1..=CUSTOM_SETTLE_WINDOW_CAP).contains(&self.custom_settle_window_slots))
            || !(1..=WINDOW_CAP).contains(&self.result_retention_slots)
        {
            return Err(DISPUTE_TERMS);
        }
        // 7-11: the policy, its shares and its escrow floor.
        let kind = self.bond_policy_kind;
        if kind == BOND_POLICY_NONE
            || kind > BOND_POLICY_CUSTOM
            || self.bond_slasher_bps as u64 > BPS_DENOMINATOR
            || self.bond_remainder == [0; 32]
            || (kind == BOND_POLICY_CUSTOM) != custom
            || (kind == BOND_POLICY_CUSTOM && self.bond_slasher_bps != 0)
            || (kind == BOND_POLICY_CUSTOM
                && self.executor_bond_lamports != 0
                && self.executor_bond_lamports < BOND_ESCROW_RENT_EXEMPT)
        {
            return Err(DISPUTE_TERMS);
        }
        // 12: the structural grace floor, one slot. The grace itself is the
        // template's (`min_abandon_after_slots`, checked in `check_template`).
        if !(ABANDON_AFTER_SLOTS_FLOOR..=WINDOW_CAP).contains(&self.abandon_after_slots) {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    /// **Checks 17-20, the per-template comparison, refused 791** (spec §1.1,
    /// `UnifiedInit` step 2c'). Every magnitude in these four compares belongs
    /// to the template's owner, so this is the whole of what DCG enforces about
    /// a document's windows: **it may not exceed them**.
    ///
    /// 17. `min_abandon_after_slots <= abandon_after_slots <=
    ///     max_abandon_after_slots` -- the grace is the template's choice, in
    ///     both directions;
    /// 18. `challenge_window_slots <= max_challenge_window_slots`;
    /// 19. `response_window_slots <= max_response_window_slots`;
    /// 20. `abandon_after_slots <= max_document_lifetime_slots` -- **the one
    ///     relation between a term and the lifetime**, and it is load-bearing
    ///     rather than tidy: it is what makes the finalize budget's subtraction
    ///     `lifetime - abandon_after_slots` non-negative, so `clamped_abandon_
    ///     deadline` and `attest_budget_ceiling` cannot underflow at tags 162
    ///     and 165, which is what the old pair of equal `2^27` constants used to
    ///     guarantee.
    ///
    /// **The code is 791, not a new one.** The question is one question -- *are
    /// these terms admissible for this document?* -- and 791 is the code every
    /// other admission of a term answers with, in the same transaction, on the
    /// same record. §3's rule is that an existing code is reused rather than
    /// reallocated, and there is nothing here a caller could act on differently.
    pub fn check_template(&self, limits: &super::config::TemplateLimits) -> Result<(), u32> {
        if !(limits.min_abandon_after_slots..=limits.max_abandon_after_slots)
            .contains(&self.abandon_after_slots)
            || self.challenge_window_slots > limits.max_challenge_window_slots
            || self.response_window_slots > limits.max_response_window_slots
            || self.abandon_after_slots > limits.max_document_lifetime_slots
        {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; TERMS_BYTES_V2] {
        let mut out = [0u8; TERMS_BYTES_V2];
        out[..4].copy_from_slice(b"DDT2");
        out[4..6].copy_from_slice(&TERMS_VERSION_V2.to_le_bytes());
        out[8..16].copy_from_slice(&self.challenge_window_slots.to_le_bytes());
        out[16..24].copy_from_slice(&self.response_window_slots.to_le_bytes());
        out[24..32].copy_from_slice(&self.challenger_bond_lamports.to_le_bytes());
        out[32..40].copy_from_slice(&self.executor_bond_lamports.to_le_bytes());
        out[40..42].copy_from_slice(&self.executor_reward_bps.to_le_bytes());
        out[42] = self.bond_policy_kind;
        out[44..46].copy_from_slice(&self.bond_slasher_bps.to_le_bytes());
        out[48..80].copy_from_slice(&self.settlement_program);
        out[80..88].copy_from_slice(&self.custom_settle_window_slots.to_le_bytes());
        out[88..96].copy_from_slice(&self.result_retention_slots.to_le_bytes());
        out[96..128].copy_from_slice(&self.bond_remainder);
        out[128..136].copy_from_slice(&self.abandon_after_slots.to_le_bytes());
        out
    }

    /// The production deadline of spec §1.3, checked add: `start +
    /// abandon_after_slots` never overflows a `u64`. This is the **unclamped**
    /// form, which is the one `UnifiedInit` writes -- check 20 keeps the window
    /// at or below the template's lifetime limit, so `min(start + window,
    /// init_slot + lifetime)` cannot bind at init and the clamp needs no read
    /// of the template there.
    ///
    /// **The overflow code is 598, not 791.** The refusal table's 598 row
    /// names tags 161, 162 and 165 for exactly these two adds, and the
    /// challenge deadline's own add one line above `abandon_deadline`'s call
    /// site already answers 598; a deadline overflow arriving as `DISPUTE_TERMS`
    /// would report a *terms* defect for an *arithmetic* one. Unreachable for a
    /// document admitted under a template whose limits satisfy
    /// `TemplateLimits::check`, and stated anyway so the two implementations say
    /// one thing.
    pub fn abandon_deadline(&self, start: u64) -> Result<u64, u32> {
        start
            .checked_add(self.abandon_after_slots)
            .ok_or(CL_OVERFLOW)
    }

    /// **`init_slot`, derived (spec §1.3).** DCM2 v7 has no init-slot
    /// field and none may be added — the record's length is frozen at
    /// `2,182 + 4·option_count` — so the two writers of `abandon_deadline`
    /// after init recover it as `DCM2[144] − DCM2[184]`: `dispute_deadline` is
    /// written at init as `init_slot + challenge_window_slots` and `DCM2[184]`
    /// is that window, a checked add of a positive term, so the subtraction is
    /// exact. It is only ever read while the document is **unfinalized**, which
    /// is exactly when both writers run (tag 162 and tag 165 both refuse flag 2
    /// with 592 before they read anything), and finalize is the only writer of
    /// 144 — so no read can see a rewritten 144.
    pub fn init_slot(dispute_deadline: u64, challenge_window_slots: u64) -> Option<u64> {
        dispute_deadline.checked_sub(challenge_window_slots)
    }

    /// **The attestation budget's ceiling, finalize's 736 (ii)** (spec §1.3
    /// (ii)(b)): `init_slot + lifetime_max − abandon_after_slots`, the last
    /// slot at which a finalize still leaves one full grace window for the
    /// attestations that follow it.
    ///
    /// `lifetime_max` is **the template's** `max_document_lifetime_slots`, read
    /// from DTU1 at the same call, and the subtraction is checked for the same
    /// reason the add is: check 20 is what makes it non-negative, and a reader
    /// that cannot see the record's history defends the arithmetic anyway and
    /// answers 791 — the code that check answers with, because the
    /// inconsistency it would catch is the very relation check 20 states.
    pub fn attest_budget_ceiling(&self, init_slot: u64, lifetime_max: u64) -> Result<u64, u32> {
        let head = init_slot.checked_add(lifetime_max).ok_or(CL_OVERFLOW)?;
        head.checked_sub(self.abandon_after_slots)
            .ok_or(DISPUTE_TERMS)
    }

    /// The **clamped** production deadline every write after init uses
    /// (`spec §1.3 (ii)(c)`): `min(slot + abandon_after_slots, init_slot +
    /// lifetime_max)`, both adds checked (**598**, as in
    /// `abandon_deadline`). The `min` is total and never saturates.
    ///
    /// **`lifetime_max` is the template's own limit**, from DTU1 at the same
    /// call. It was a protocol constant at `1 << 27` and the user withdrew that
    /// on 2026-09-26: the ceiling is the template owner's number, and it is read
    /// from the record the document was admitted under, so a document's
    /// production budget cannot change while the document lives.
    pub fn clamped_abandon_deadline(
        &self,
        slot: u64,
        init_slot: u64,
        lifetime_max: u64,
    ) -> Result<u64, u32> {
        let forward = self.abandon_deadline(slot)?;
        let ceiling = init_slot.checked_add(lifetime_max).ok_or(CL_OVERFLOW)?;
        Ok(forward.min(ceiling))
    }
}

/// The built-in route's split of the settlement pot (spec §7.4):
/// `winner = floor(pot * bps / 10,000)` in `u128`, the rest burned.
pub fn executor_bond_split(bond: u64, reward_bps: u16) -> (u64, u64) {
    let reward = (bond as u128 * reward_bps.min(10_000) as u128 / BPS_DENOMINATOR as u128) as u64;
    (reward, bond - reward)
}

/// Revision 8's `bond_split` (spec §1.4), the same `floor` with
/// `bond_slasher_bps`, and the same `u128` intermediate: `slasher +
/// remainder == pot` in every case and no float, no 32-bit intermediate.
/// The no-winner row is `bps = 0`, which the caller selects by reading
/// `conviction_winner` (D11): a conviction with no recorded winner pays
/// `(0, pot)`.
pub fn bond_split(pot: u64, slasher_bps: u16, winner_recorded: bool) -> (u64, u64) {
    if !winner_recorded {
        return (0, pot);
    }
    executor_bond_split(pot, slasher_bps)
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use crate::unified::classes::tests::{golden, unhex};

    fn vector() -> Terms {
        Terms {
            challenge_window_slots: 90_000,
            response_window_slots: 45_000,
            challenger_bond_lamports: 1_000_000,
            executor_bond_lamports: 5_000_000,
            executor_reward_bps: 5_000,
            settlement_program: [0; 32],
            custom_settle_window_slots: 0,
            result_retention_slots: 2_592_000,
        }
    }

    #[test]
    fn ddt2_matches_the_golden_vector() {
        let g = golden();
        let raw = unhex(g["ddt2"]["default_hex"].as_str().unwrap());
        let t = Terms::decode(&raw).unwrap();
        assert_eq!(t, vector());
        assert_eq!(t.encode().to_vec(), raw);
        let custom = Terms::decode(&unhex(g["ddt2"]["custom_hex"].as_str().unwrap())).unwrap();
        assert_ne!(custom.settlement_program, [0; 32]);
        assert_eq!(
            custom.encode().to_vec(),
            unhex(g["ddt2"]["custom_hex"].as_str().unwrap())
        );
        let split = &g["ddt2"]["built_in_split"];
        assert_eq!(
            executor_bond_split(t.executor_bond_lamports, t.executor_reward_bps),
            (split[0].as_u64().unwrap(), split[1].as_u64().unwrap())
        );
        assert_eq!(g["ddt2"]["window_cap"].as_u64().unwrap(), WINDOW_CAP);
    }

    /// Spec §6.8: every mechanical refusal is 791, every policy value (zero
    /// bonds, zero reward, one-slot windows and retention) is admitted.
    #[test]
    fn ddt2_mechanical_floors_refuse_and_policy_values_pass() {
        let base = vector();
        let refused = |t: Terms| Terms::decode(&t.encode()) == Err(DISPUTE_TERMS);
        assert!(refused(Terms {
            challenge_window_slots: 0,
            ..base
        }));
        assert!(refused(Terms {
            challenge_window_slots: WINDOW_CAP + 1,
            ..base
        }));
        assert!(refused(Terms {
            response_window_slots: 0,
            ..base
        }));
        assert!(refused(Terms {
            response_window_slots: WINDOW_CAP + 1,
            ..base
        }));
        assert!(refused(Terms {
            executor_reward_bps: 10_001,
            ..base
        }));
        assert!(refused(Terms {
            result_retention_slots: 0,
            ..base
        }));
        assert!(refused(Terms {
            result_retention_slots: WINDOW_CAP + 1,
            ..base
        }));
        // Program set <=> custom window set.
        assert!(refused(Terms {
            settlement_program: [7; 32],
            ..base
        }));
        assert!(refused(Terms {
            custom_settle_window_slots: 9,
            ..base
        }));
        let custom = Terms {
            settlement_program: [7; 32],
            custom_settle_window_slots: 9,
            ..base
        };
        assert_eq!(Terms::decode(&custom.encode()), Ok(custom));
        assert!(refused(Terms {
            custom_settle_window_slots: CUSTOM_SETTLE_WINDOW_CAP + 1,
            ..custom
        }));
        let at_cap = Terms {
            custom_settle_window_slots: CUSTOM_SETTLE_WINDOW_CAP,
            ..custom
        };
        assert_eq!(Terms::decode(&at_cap.encode()), Ok(at_cap));
        assert_eq!(
            Terms {
                response_window_slots: 6,
                ..base
            }
            .check(7),
            Err(DISPUTE_TERMS)
        );
        assert_eq!(
            Terms {
                response_window_slots: 7,
                ..base
            }
            .check(7),
            Ok(())
        );
        let mut raw = base.encode();
        raw[..4].copy_from_slice(b"DDT1");
        assert_eq!(Terms::decode(&raw), Err(DISPUTE_TERMS));
        let mut raw = base.encode();
        raw[4] = 2;
        assert_eq!(Terms::decode(&raw), Err(DISPUTE_TERMS));
        for at in [6usize, 7, 42, 47] {
            let mut raw = base.encode();
            raw[at] = 1;
            assert_eq!(
                Terms::decode(&raw),
                Err(DISPUTE_TERMS),
                "reserved byte {at}"
            );
        }
        assert_eq!(Terms::decode(&base.encode()[..95]), Err(DISPUTE_TERMS));
        let mut long = base.encode().to_vec();
        long.push(0);
        assert_eq!(Terms::decode(&long), Err(DISPUTE_TERMS));
        let free = Terms {
            challenge_window_slots: 1,
            response_window_slots: 1,
            challenger_bond_lamports: 0,
            executor_bond_lamports: 0,
            executor_reward_bps: 0,
            result_retention_slots: 1,
            ..base
        };
        assert_eq!(Terms::decode(&free.encode()), Ok(free));
        let caps = Terms {
            challenge_window_slots: WINDOW_CAP,
            response_window_slots: WINDOW_CAP,
            challenger_bond_lamports: u64::MAX,
            executor_bond_lamports: u64::MAX,
            executor_reward_bps: 10_000,
            settlement_program: [0xff; 32],
            custom_settle_window_slots: CUSTOM_SETTLE_WINDOW_CAP,
            result_retention_slots: WINDOW_CAP,
        };
        assert_eq!(Terms::decode(&caps.encode()), Ok(caps));
        assert_eq!(executor_bond_split(u64::MAX, 10_000), (u64::MAX, 0));
        assert_eq!(
            executor_bond_split(u64::MAX, 1),
            (u64::MAX / 10_000, u64::MAX - u64::MAX / 10_000)
        );
    }
}
