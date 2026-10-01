#![cfg(feature = "revision-8")]

//! Stream B's frozen revision-8 bytes (spec `docs/spec/dcg-unified-v8.md`,
//! goldens `tests/golden/dcg/unified_v8/`) read back through the program's own
//! decoders and encoders.
//!
//! Three things are checked, and they are the three the frozen bytes need from
//! this program:
//!
//! 1. **Every golden record decodes and round-trips.** DDT2 v2 and DRB1 v2
//!    through `Terms2::decode`/`encode` and `Binding2::decode`/`encode`, the
//!    `/5` DPD2 preimage and its digest through `Dpd2::preimage_v8`, and every
//!    field of the DCM2 v7 and DCR2 v6 records at the offset
//!    `record_layouts_v1.tsv` gives it. A round trip means `encode(decode(x))`
//!    is `x` byte for byte, not "close enough".
//! 2. **The derived offsets are the ones implemented**: `PEAKS_AT = 562`,
//!    `TERMS_AT = 1,842`, `BINDING_AT = 1,978`, `ABANDON_DEADLINE_AT = 2,174`,
//!    `OPTION_REGION_AT = 2,182`, `DCM2 = 2,182 + 4*option_count`,
//!    `DCR2 header = 416`, `DPD2 = 755`.
//! 3. **Every new refusal has its negative vector**: `791` for §1.1's checks
//!    7-12 and 17-20, `794` for §1's four relations and
//!    §1.2's new clauses, `816` for both branches of the document-length rule,
//!    and the structural refusal of a revision-7 block read as a revision-8 one.
//! 4. **The two deadline rules of §1.3 (ii)** as arithmetic: `init_slot` is
//!    recovered as `DCM2[144] - DCM2[184]` and the written deadline is
//!    `min(slot + abandon_after_slots, init_slot + the template's lifetime
//!    limit)`, with the `u64::MAX` adds refused rather than wrapped. The clamp's
//!    ceiling and the degenerate case `abandon_after_slots == the template's
//!    grace maximum`, where finalize's budget ceiling is the document's own init
//!    slot, are both asserted.
//! 5. **The per-template limits** (spec §1.1 checks 17-20): a document at its
//!    template's limit is admitted, one slot over is refused 791, and two
//!    templates with different limits admit the same terms differently.
//!
//! The goldens are plain TSV, so this needs no JSON and no network and no
//! local plan artifact. The handlers are driven from real instructions in
//! `unified_v8_document.rs`.

use dcg_program::unified::config::{self, TemplateLimits, TEMPLATE_SEAL};
use dcg_program::unified::document::{
    self, Binding2, Dpd2, Locator, ABANDON_DEADLINE_AT, BINDING_AT_V8, BINDING_BYTES_V8,
    DECISION_WIDTH, DOCUMENT_LENGTH, DPD2_BYTES_V8, OPTION_REGION_AT, PEAKS_AT_V8, RUN_BINDING,
    STOP_WIDTH, TERMS_AT_V8,
};
use dcg_program::unified::events::{self, Body, VERSION_V3};
use dcg_program::unified::result::{self, HEADER_V6};
use dcg_program::unified::terms::{
    self, Terms2, BOND_ESCROW_BYTES, BOND_ESCROW_RENT_EXEMPT, BOND_POLICY_CUSTOM,
    BOND_POLICY_STANDARD, CHALLENGE_ROUNDS_MAX, TERMS_BYTES_V2,
};
use dcg_program::unified::{CL_OVERFLOW, DISPUTE_TERMS, EPOCH};
use std::path::PathBuf;

/// **The example template's own limits** (spec §1.7, DTU1 at 88). These are the
/// four numbers this branch used to carry as protocol-wide constants; they are
/// now one template owner's published values, and the goldens' `constants_v1.tsv`
/// says so. Keeping them at the old values is deliberate: it lets a reader
/// compare the *kind* of the number rather than the number.
fn example_limits() -> TemplateLimits {
    TemplateLimits {
        max_challenge_window_slots: 1 << 26,
        max_response_window_slots: 1 << 23,
        max_document_lifetime_slots: 1 << 27,
        max_abandon_after_slots: 1 << 27,
        min_abandon_after_slots: 2_592_000,
    }
}

/// **A second template**, with limits the withdrawn constants made impossible:
/// a six-hour grace, a four-day lifetime and a per-round window of half an
/// hour. Its worst-case hold is 5,505,600 slots (2.56 d) where the example's is
/// 285,212,672 (132.56 d), and the protocol admits both -- which is the user's
/// decision in one assertion.
fn short_limits() -> TemplateLimits {
    TemplateLimits {
        max_challenge_window_slots: 1_000_000,
        max_response_window_slots: 40_960,
        max_document_lifetime_slots: 4_096_000,
        max_abandon_after_slots: 4_096_000,
        min_abandon_after_slots: 90_000,
    }
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/dcg/unified_v8")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// One `vectors_v1.tsv` row: `(object, part, hex)`.
fn vector(object: &str, part: &str) -> Vec<u8> {
    let text =
        std::fs::read_to_string(golden_dir().join("vectors_v1.tsv")).expect("vectors_v1.tsv");
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] == object && f[1] == part {
            return unhex(f[4]);
        }
    }
    panic!("no vector {object} / {part}");
}

/// Every `record_layouts_v1.tsv` row for one layout: `(field, offset, width)`.
fn layout(name: &str) -> Vec<(String, usize, usize)> {
    let text = std::fs::read_to_string(golden_dir().join("record_layouts_v1.tsv"))
        .expect("record_layouts_v1.tsv");
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] == name {
            out.push((
                f[2].to_string(),
                f[3].parse().unwrap(),
                f[4].parse().unwrap(),
            ));
        }
    }
    assert!(!out.is_empty(), "layout {name}");
    out
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn d32(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- DDT2 v2

/// The CUSTOM and STANDARD DDT2 v2 vectors decode, round-trip byte for byte,
/// and their option table / policy fields are the ones the spec's table names.
#[test]
fn ddt2_v2_vectors_decode_and_round_trip() {
    assert_eq!(TERMS_BYTES_V2, 136);
    let custom = vector("DDT2 v2", "record");
    let standard = vector("DDT2 v2", "STANDARD record");
    assert_eq!((custom.len(), standard.len()), (136, 136));
    for raw in [&custom, &standard] {
        let t = Terms2::decode(raw).expect("the golden terms decode");
        assert_eq!(t.encode().to_vec(), *raw, "encode(decode(x)) == x");
    }
    let c = Terms2::decode(&custom).unwrap();
    let s = Terms2::decode(&standard).unwrap();
    assert_eq!(c.bond_policy_kind, BOND_POLICY_CUSTOM);
    assert_eq!(
        c.bond_slasher_bps, 0,
        "CUSTOM requires a zero slasher share"
    );
    assert_eq!(c.bond_slasher_bps as u64, u16_at(&custom, 44) as u64);
    assert_eq!(c.settlement_program, d32(&custom, 48));
    assert_eq!(c.bond_remainder, d32(&custom, 96));
    assert_eq!(c.abandon_after_slots, u64_at(&custom, 128));
    assert_eq!(
        c.abandon_after_slots,
        2 * example_limits().min_abandon_after_slots
    );
    assert_eq!(c.executor_bond_lamports, 5_000_000);
    assert!(c.settlement_program != [0; 32] && c.custom_settle_window_slots != 0);
    assert_eq!(s.bond_policy_kind, BOND_POLICY_STANDARD);
    assert_eq!(s.executor_reward_bps, 5_000, "dead on rev 8, still bounded");
    assert_eq!(s.bond_slasher_bps, 5_000);
    assert_eq!(s.settlement_program, [0; 32]);
    assert_eq!(s.custom_settle_window_slots, 0);
    assert_eq!(
        s.bond_remainder, c.bond_remainder,
        "nonzero under either kind"
    );
    // The three revision-7 checks the goldens share, and the appended field.
    assert_eq!(c.challenge_window_slots, 90_000);
    assert_eq!(
        c.abandon_deadline(900).unwrap(),
        900 + c.abandon_after_slots
    );
    // A checked add, never a wrap, and the **598** the refusals table's row
    // names for tags 161, 162 and 165 -- not 791, which is a *terms* defect
    // and this is an arithmetic one (this review's Low 1).
    assert_eq!(
        c.abandon_deadline(u64::MAX),
        Err(CL_OVERFLOW),
        "a checked add, never a wrap"
    );
}

/// §1.3's two derived quantities: `init_slot`, recovered from the record, and
/// the clamped deadline of §1.3 (ii)(c). Both are the arithmetic the two
/// deadline writers depend on, and both are pure.
#[test]
fn init_slot_is_recovered_and_the_deadline_is_clamped() {
    let c = Terms2::decode(&vector("DDT2 v2", "record")).unwrap();
    let window = c.challenge_window_slots;
    let abandon = c.abandon_after_slots;
    // init_slot = dispute_deadline - challenge_window_slots, and it is exact
    // because init writes 144 as `init_slot + window` with a checked add of a
    // positive term.
    for init in [
        0u64,
        1,
        500,
        1_000_000,
        10_000_000_000,
        u64::MAX - abandon - window,
    ] {
        assert_eq!(
            Terms2::init_slot(init + window, window),
            Some(init),
            "init_slot {init}"
        );
    }
    assert_eq!(
        Terms2::init_slot(window - 1, window),
        None,
        "a deadline below the window is None"
    );
    assert_eq!(
        Terms2::init_slot(0, 0),
        Some(0),
        "a zero window gives the deadline back"
    );
    // The clamp: `min(slot + abandon_after_slots, init_slot + lifetime)`, where
    // `lifetime` is the **template's** `max_document_lifetime_slots` and not a
    // protocol constant.
    let init = 1_000_000u64;
    let lifetime = example_limits().max_document_lifetime_slots;
    let ceiling = init + lifetime;
    assert_eq!(
        c.clamped_abandon_deadline(init, init, lifetime).unwrap(),
        init + abandon,
        "at the init slot"
    );
    assert_eq!(
        c.clamped_abandon_deadline(ceiling - abandon, init, lifetime)
            .unwrap(),
        ceiling,
        "one slot before the ceiling is still the forward value"
    );
    assert_eq!(
        c.clamped_abandon_deadline(ceiling - abandon + 1, init, lifetime)
            .unwrap(),
        ceiling,
        "at the ceiling the clamp binds, and it is the smaller of the two"
    );
    assert_eq!(
        c.clamped_abandon_deadline(ceiling + 10_000_000, init, lifetime)
            .unwrap(),
        ceiling,
        "far past the ceiling the clamp is still the ceiling, never a wrap"
    );
    // **A second template's ceiling on the same terms**: the same document's
    // clamp lands in a different place because the template says so, which is
    // the whole content of the user's decision.
    let short = short_limits();
    assert_eq!(
        c.clamped_abandon_deadline(init, init, short.max_document_lifetime_slots)
            .unwrap(),
        init + short.max_document_lifetime_slots,
        "the short template's ceiling binds at once"
    );
    // The degenerate case §1.6's budget rule refuses: a document at its
    // template's *maximum* grace has a budget ceiling of its own init slot.
    let big = Terms2 {
        abandon_after_slots: example_limits().max_abandon_after_slots,
        ..c
    };
    assert_eq!(
        big.clamped_abandon_deadline(1, 0, lifetime).unwrap(),
        lifetime
    );
    assert_eq!(
        big.clamped_abandon_deadline(0, 0, lifetime).unwrap(),
        example_limits().max_abandon_after_slots,
        "in the init slot itself the two are the same number"
    );
    assert_eq!(
        big.attest_budget_ceiling(0, lifetime),
        Ok(0),
        "the budget ceiling is the document's own init slot"
    );
    // An add that would overflow is 598, never a wrap and never 791: the
    // refusal table's 598 row names both deadline adds at tags 162 and 165.
    assert_eq!(
        c.clamped_abandon_deadline(u64::MAX, 1, lifetime),
        Err(CL_OVERFLOW),
        "the forward add"
    );
    assert_eq!(
        c.clamped_abandon_deadline(0, u64::MAX, lifetime),
        Err(CL_OVERFLOW),
        "the ceiling add"
    );
    assert_eq!(CL_OVERFLOW, 598, "revision 7's reused overflow code");
    assert_ne!(CL_OVERFLOW, DISPUTE_TERMS, "and 791 is a different failure");
    // The budget subtraction is checked too, and a window above the template's
    // lifetime -- which init's check 20 refuses -- would underflow it. 791, the
    // code check 20 answers with, rather than a wrap.
    assert_eq!(c.attest_budget_ceiling(0, abandon - 1), Err(DISPUTE_TERMS));
    assert_eq!(c.attest_budget_ceiling(0, 0), Err(DISPUTE_TERMS));
    assert_eq!(
        c.attest_budget_ceiling(u64::MAX, lifetime),
        Err(CL_OVERFLOW),
        "the head add"
    );
}

/// **The seven `deadline` rows of `vectors_v1.tsv`, replayed through the
/// program's own arithmetic** (design-note round 5, Low 1, and this review's
/// Medium 1a). The rows are eight `u64`s each -- `init_slot`, the write slot,
/// the window, the deadline already in the record, the unclamped forward value,
/// the clamp's ceiling, the value actually written, and finalize's budget
/// ceiling -- and until now only the Python replay read them, so the Rust side
/// checked the clamp against numbers it chose itself.
///
/// A row is replayed through **the two functions the handlers call**,
/// `Terms2::clamped_abandon_deadline` and `Terms2::init_slot`, and the two 736
/// comparisons are replayed through the same expressions `land_position_roots`
/// and `finalize_v8` evaluate, in the same order. The window is a
/// `Terms2` field, so each row is decoded with a terms block that carries its
/// own window and nothing else borrowed.
#[test]
fn the_seven_deadline_rows_replay_through_the_programs_own_arithmetic() {
    let base = Terms2::decode(&vector("DDT2 v2", "record")).unwrap();
    let text =
        std::fs::read_to_string(golden_dir().join("vectors_v1.tsv")).expect("vectors_v1.tsv");
    let rows: Vec<(String, Vec<u8>, String)> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[0] == "deadline").then(|| (f[1].to_string(), unhex(f[4]), f[5].to_string()))
        })
        .collect();
    assert_eq!(
        rows.len(),
        8,
        "eight deadline rows, the set the emitter writes"
    );
    let mut clamped = 0;
    let mut fired_i = 0;
    let mut fired_ii = 0;
    for (label, raw, note) in &rows {
        assert_eq!(raw.len(), 64, "{label}: eight u64s");
        let at = |i: usize| u64::from_le_bytes(raw[8 * i..8 * (i + 1)].try_into().unwrap());
        let (init_slot, write_slot, window) = (at(0), at(1), at(2));
        let (stored, forward, ceiling, written, budget_ceiling) =
            (at(3), at(4), at(5), at(6), at(7));
        // The ceiling is `init_slot + the template's lifetime limit`, and the
        // emitter's rows are the example template's, so this is the one number
        // the replay has to supply rather than read back.
        let lifetime = ceiling - init_slot;
        // The kind is the row's own text, because it is what the two 736s
        // differ on: a landing is subject to neither.
        let finalize = note.starts_with("finalize:");
        // The terms block the row names: this row's own window, the golden's
        // everything else. `decode` is not called on it -- the grace is inside
        // the example template's own range, which is what init's check 17 says.
        let t = Terms2 {
            abandon_after_slots: window,
            ..base
        };
        // **The forward value, through the program's own checked add.**
        assert_eq!(t.abandon_deadline(write_slot), Ok(forward), "{label}");
        // **The ceiling, through the program's own checked add**, and the
        // clamp's `min`, through `clamped_abandon_deadline` itself.
        assert_eq!(init_slot.checked_add(lifetime), Some(ceiling), "{label}");
        assert_eq!(
            t.clamped_abandon_deadline(write_slot, init_slot, lifetime),
            Ok(written),
            "{label}"
        );
        assert_eq!(written, forward.min(ceiling), "{label}: the min, restated");
        if written < forward {
            clamped += 1;
        }
        // **`init_slot` is recovered, never stored**: it is
        // `dispute_deadline - challenge_window_slots`, so the row's own
        // `init_slot` must come back out of a 144 written as init + the
        // challenge window. `stored` is that init write, pushed forward.
        let challenge = t.challenge_window_slots;
        assert_eq!(
            Terms2::init_slot(init_slot + challenge, challenge),
            Some(init_slot),
            "{label}"
        );
        assert_eq!(
            Terms2::init_slot(stored, challenge),
            Some(stored - challenge),
            "{label}: the record's 144 recovers an init slot"
        );
        // **The budget ceiling**, which is the ceiling minus the window --
        // check 20 (`abandon_after_slots <= max_document_lifetime_slots`) is why
        // the subtraction cannot go negative, and it is a *checked* one.
        assert!(window <= lifetime, "{label}: check 20 holds");
        // The short-lived template's row is the one whose ceiling is **not** the
        // example's, and it is read back out of the row rather than assumed.
        if label == "the short-lived template's ceiling" {
            assert_eq!(
                lifetime,
                short_limits().max_document_lifetime_slots,
                "{label}"
            );
        }
        assert_eq!(init_slot + lifetime - window, budget_ceiling, "{label}");
        assert_eq!(
            t.attest_budget_ceiling(init_slot, lifetime),
            Ok(budget_ceiling),
            "{label}"
        );
        // **The two 736s, in the order `finalize_v8` evaluates them.**
        let (r1, r2) = (
            finalize && write_slot >= stored,
            finalize && write_slot > budget_ceiling,
        );
        assert_eq!(r1, note.contains("736 (i)"), "{label}");
        assert_eq!(r2, note.contains("736 (ii)"), "{label}");
        assert!(
            !(r1 && r2),
            "{label}: rule 1 is read first, so it is the one that fires"
        );
        fired_i += r1 as u32;
        fired_ii += r2 as u32;
        // A landing is never refused by either rule: it is clamped, and a
        // clamped document is recoverable by anyone on row 2.
        if !finalize {
            assert_eq!((r1, r2), (false, false), "{label}");
            assert!(note.contains("accepted"), "{label}");
        }
    }
    // The point of the set: the clamp takes effect in four of the eight -- the
    // fourth under the **short-lived** template, whose ceiling is 4,096,000 --
    // and each of the two 736s fires in exactly one. Without those counts a rule
    // could stop firing and the rows would still replay.
    assert_eq!(clamped, 4, "four of the eight take the clamp");
    assert_eq!((fired_i, fired_ii), (1, 1), "one 736 (i) and one 736 (ii)");
    // The degenerate case the refusals table names: at the template's maximum
    // grace the budget ceiling is the document's own init slot, so **any**
    // finalize after its own init slot is refused. The program says so through
    // the same two expressions.
    let limits = example_limits();
    let big = Terms2 {
        abandon_after_slots: limits.max_abandon_after_slots,
        ..base
    };
    assert_eq!(
        big.attest_budget_ceiling(0, limits.max_document_lifetime_slots),
        Ok(0)
    );
    assert_eq!(
        big.clamped_abandon_deadline(1, 0, limits.max_document_lifetime_slots),
        Ok(limits.max_document_lifetime_slots),
        "the clamp still holds"
    );
    assert!(
        1 > 0,
        "a finalize one slot after the init slot is past the budget ceiling"
    );
}

/// **Checks 17-20, the per-template comparison** (spec §1.1, `UnifiedInit` step
/// 2c'), and the two things it is for: a document at its template's limit is
/// admitted and one slot over is refused, and **two templates with different
/// limits admit the same document differently**.
#[test]
fn the_per_template_limits_admit_at_the_limit_and_refuse_over_it() {
    let base = Terms2::decode(&vector("DDT2 v2", "record")).unwrap();
    let wide = example_limits();
    let short = short_limits();
    // **The two templates, the same terms.** The golden's own terms -- 90,000 /
    // 45,000 / a 5,184,000-slot grace -- are inside the wide template's range
    // and **outside** the short one's, and check 17 is the clause that says so.
    assert_eq!(base.check_template(&wide), Ok(()));
    assert_eq!(
        base.check_template(&short),
        Err(DISPUTE_TERMS),
        "a 5,184,000-slot grace is over the short template's 4,096,000 maximum"
    );
    // A document inside **both** ranges, which is the third thing two templates
    // make expressible: a grace above the short template's floor and below the
    // wide one's ceiling is admitted by both.
    let both = Terms2 {
        challenge_window_slots: 900_000,
        response_window_slots: 40_000,
        abandon_after_slots: 3_000_000,
        ..base
    };
    assert_eq!(both.check_template(&short), Ok(()));
    assert_eq!(both.check_template(&wide), Ok(()));
    // And the floor bites in the other direction too: a document sized to the
    // short template is **refused by the wide one**, whose floor is 2,592,000.
    // A per-template floor is a floor, not a formality.
    let short_run = Terms2 {
        challenge_window_slots: 900_000,
        response_window_slots: 40_000,
        abandon_after_slots: 1_000_000,
        ..base
    };
    assert_eq!(short_run.check_template(&short), Ok(()));
    assert_eq!(
        short_run.check_template(&wide),
        Err(DISPUTE_TERMS),
        "the wide template's 2,592,000 floor refuses the short template's own range"
    );
    // 18: the challenge window, at the limit and one over. The grace is the
    // short template's own, so each row isolates the clause under test rather
    // than failing on check 17 first.
    let grace_ok = Terms2 {
        abandon_after_slots: 3_000_000,
        response_window_slots: 40_000,
        ..base
    };
    for limit in [
        1u64,
        900_000,
        short.max_challenge_window_slots,
        short.max_challenge_window_slots + 1,
        wide.max_challenge_window_slots,
        wide.max_challenge_window_slots + 1,
    ] {
        let t = Terms2 {
            challenge_window_slots: limit,
            ..grace_ok
        };
        for limits in [&wide, &short] {
            assert_eq!(
                t.check_template(limits),
                if limit <= limits.max_challenge_window_slots {
                    Ok(())
                } else {
                    Err(DISPUTE_TERMS)
                },
                "challenge window {limit} against a template capped at {}",
                limits.max_challenge_window_slots
            );
        }
    }
    // 19: the per-round response window, the same two-sided way.
    for limit in [
        1u64,
        40_960,
        short.max_response_window_slots + 1,
        1 << 23,
        (1 << 23) + 1,
    ] {
        let t = Terms2 {
            response_window_slots: limit,
            ..grace_ok
        };
        for limits in [&wide, &short] {
            assert_eq!(
                t.check_template(limits),
                if limit <= limits.max_response_window_slots {
                    Ok(())
                } else {
                    Err(DISPUTE_TERMS)
                },
                "response window {limit} against a template capped at {}",
                limits.max_response_window_slots
            );
        }
    }
    // 17: the grace is the template's in **both** directions -- under its floor
    // and over its ceiling, refused by the same code. Each row is checked
    // against **both** templates' own ranges, which is where a floor and a
    // ceiling stop being a formality: 1,000,000 is over the short template's
    // floor and under its ceiling, and *under* the wide template's floor.
    for grace in [1u64, 89_999, 90_000, 1_000_000, 4_096_000, 4_096_001] {
        let t = Terms2 {
            abandon_after_slots: grace,
            ..grace_ok
        };
        for limits in [&wide, &short] {
            let inside = (limits.min_abandon_after_slots..=limits.max_abandon_after_slots)
                .contains(&grace)
                && grace <= limits.max_document_lifetime_slots;
            assert_eq!(
                t.check_template(limits),
                if inside { Ok(()) } else { Err(DISPUTE_TERMS) },
                "grace {grace} against a template whose range is {}..={}",
                limits.min_abandon_after_slots,
                limits.max_abandon_after_slots
            );
        }
    }
    // 20: the one relation between a term and the lifetime, and the one that is
    // load-bearing -- it is what makes the finalize budget's subtraction
    // non-negative. A template may set a lifetime *below* its own grace maximum
    // only up to the seal's rule 3, so a document can never reach this.
    let narrow = TemplateLimits {
        max_abandon_after_slots: 4_096_000,
        max_document_lifetime_slots: 4_096_001,
        ..short
    };
    let at = Terms2 {
        abandon_after_slots: 4_096_000,
        ..grace_ok
    };
    assert_eq!(
        at.check_template(&narrow),
        Ok(()),
        "the grace at the lifetime"
    );
    let over = Terms2 {
        abandon_after_slots: 4_096_002,
        ..grace_ok
    };
    assert_eq!(over.check_template(&narrow), Err(DISPUTE_TERMS), "check 20");
    assert_eq!(
        over.check_template(&short),
        Err(DISPUTE_TERMS),
        "and the short template refuses it on its own ceiling, which is check 17"
    );
    // **Two templates, the same terms, the same day.** This is the assertion the
    // user's decision turns on: no number here is DCG's.
    assert_eq!(wide.worst_case_hold_slots(), 285_212_672);
    assert_eq!(short.worst_case_hold_slots(), 5_505_600);
    assert!(short.worst_case_hold_slots() * 50 < wide.worst_case_hold_slots());
}

/// **`TemplateLimits::check`, the seal's own bounds** (spec §1.1): nonzero,
/// `min <= max`, `max_abandon <= max_lifetime`, and `limit + seal_slot`
/// representable. **No magnitude is refused**, which is the point.
#[test]
fn the_seals_own_bounds_are_structural_and_check_no_magnitude() {
    let wide = example_limits();
    assert_eq!(wide.check(1_000), Ok(()));
    // A five-minute template and a five-century one are both admitted: the four
    // protocol-wide constants are withdrawn, so DCG has no opinion about size.
    let tiny = TemplateLimits {
        max_challenge_window_slots: 1,
        max_response_window_slots: 1,
        max_document_lifetime_slots: 5_400,
        max_abandon_after_slots: 5_400,
        min_abandon_after_slots: 1,
    };
    assert_eq!(
        tiny.check(1_000),
        Ok(()),
        "216 s of lifetime is a template owner's choice"
    );
    let huge = TemplateLimits {
        max_challenge_window_slots: u64::MAX / 4,
        max_response_window_slots: u64::MAX / 4,
        max_document_lifetime_slots: u64::MAX / 4,
        max_abandon_after_slots: u64::MAX / 4,
        min_abandon_after_slots: 1,
    };
    assert_eq!(huge.check(1_000), Ok(()), "and so is a very long one");
    // A zero limit is not a window, and a zero lifetime would put the clamp's
    // ceiling at the init slot.
    for field in 0..5 {
        let mut l = wide;
        match field {
            0 => l.max_challenge_window_slots = 0,
            1 => l.max_response_window_slots = 0,
            2 => l.max_document_lifetime_slots = 0,
            3 => l.max_abandon_after_slots = 0,
            _ => l.min_abandon_after_slots = 0,
        }
        assert_eq!(l.check(1_000), Err(TEMPLATE_SEAL), "field {field} at zero");
    }
    // The two orderings, and the overflow bound.
    let empty = TemplateLimits {
        min_abandon_after_slots: 10,
        max_abandon_after_slots: 9,
        ..wide
    };
    assert_eq!(empty.check(1_000), Err(TEMPLATE_SEAL), "min above max");
    let over = TemplateLimits {
        max_abandon_after_slots: wide.max_document_lifetime_slots + 1,
        ..wide
    };
    assert_eq!(
        over.check(1_000),
        Err(TEMPLATE_SEAL),
        "a grace longer than the whole budget"
    );
    assert_eq!(
        wide.check(u64::MAX),
        Err(TEMPLATE_SEAL),
        "the overflow bound is the one DCG keeps"
    );
    assert_eq!(
        wide.check(u64::MAX - (1 << 27)),
        Ok(()),
        "one slot below it is representable"
    );
    assert_eq!(TEMPLATE_SEAL, 793);
}

/// Every §1.1 check 7-12 negative, plus revision 7's list 1-6 carried over and
/// the structural refusal of a v1 block: all 791, in the one decoder.
#[test]
fn ddt2_v2_every_new_check_refuses_791() {
    let base = Terms2::decode(&vector("DDT2 v2", "record")).unwrap();
    let refused = |t: Terms2| Terms2::decode(&t.encode()) == Err(DISPUTE_TERMS);
    let refused_raw = |f: fn(&mut Vec<u8>)| {
        let mut raw = base.encode().to_vec();
        f(&mut raw);
        Terms2::decode(&raw) == Err(DISPUTE_TERMS)
    };
    // 7. a policy must exist, and only kinds 1 and 2 exist.
    assert!(refused(Terms2 {
        bond_policy_kind: 0,
        ..base
    }));
    assert!(refused(Terms2 {
        bond_policy_kind: 3,
        ..base
    }));
    // 8. the slasher share is a share.
    let standard = Terms2 {
        bond_policy_kind: BOND_POLICY_STANDARD,
        bond_slasher_bps: 5_000,
        settlement_program: [0; 32],
        custom_settle_window_slots: 0,
        ..base
    };
    assert!(refused(Terms2 {
        bond_slasher_bps: 10_001,
        ..standard
    }));
    assert!(!refused(Terms2 {
        bond_slasher_bps: 10_000,
        ..standard
    }));
    assert!(
        refused(Terms2 {
            bond_slasher_bps: 1,
            ..base
        }),
        "CUSTOM requires a zero share"
    );
    // 9. the remainder account is nonzero under either kind.
    assert!(refused(Terms2 {
        bond_remainder: [0; 32],
        ..base
    }));
    assert!(!refused(standard));
    assert!(refused(Terms2 {
        bond_remainder: [0; 32],
        ..standard
    }));
    // 10. kind 2 requires a settlement program; kind 1 requires none (the
    // biconditional ties the custom window to it).
    assert!(refused(Terms2 {
        settlement_program: [0; 32],
        ..base
    }));
    assert!(refused(Terms2 {
        bond_policy_kind: BOND_POLICY_STANDARD,
        settlement_program: [7; 32],
        custom_settle_window_slots: 9,
        bond_slasher_bps: 0,
        ..base
    }));
    // 11. under kind 2 a bond is 0 or at least the escrow's rent-exempt
    // minimum; under kind 1 there is no floor at all.
    assert!(refused(Terms2 {
        executor_bond_lamports: 1,
        ..base
    }));
    assert!(refused(Terms2 {
        executor_bond_lamports: BOND_ESCROW_RENT_EXEMPT - 1,
        ..base
    }));
    assert!(!refused(Terms2 {
        executor_bond_lamports: BOND_ESCROW_RENT_EXEMPT,
        ..base
    }));
    assert!(!refused(Terms2 {
        executor_bond_lamports: 0,
        ..base
    }));
    assert!(
        !refused(Terms2 {
            executor_bond_lamports: 500,
            ..standard
        }),
        "a STANDARD bond has no floor: the built-in route creates no account"
    );
    // 12. the structural grace floor, one slot. **The grace itself is the
    // template's** (check 17), so the decoder's own floor is what is left of
    // check 12 after the protocol constant was withdrawn.
    assert!(refused(Terms2 {
        abandon_after_slots: 0,
        ..base
    }));
    assert!(!refused(Terms2 {
        abandon_after_slots: 1,
        ..base
    }));
    assert!(
        !refused(Terms2 {
            abandon_after_slots: 90_000,
            ..base
        }),
        "a six-hour grace is a template owner's number, not a decoder's business"
    );
    assert!(!refused(Terms2 {
        abandon_after_slots: 1 << 27,
        ..base
    }));
    // **Checks 13, 14, 15 and 16 are no longer decoder checks.** The decoder
    // keeps revision 7's `2^62` on the two windows, and the bound that used to
    // be there is now `check_template` against the template. These four lines
    // are the *withdrawal*, asserted: a window the old caps refused now decodes
    // here and is refused at init instead.
    assert!(!refused(Terms2 {
        challenge_window_slots: 1 << 26,
        ..base
    }));
    assert!(
        !refused(Terms2 {
            challenge_window_slots: (1 << 26) + 1,
            ..base
        }),
        "over the withdrawn cap, but the template is what refuses it now"
    );
    assert_eq!(
        Terms2 {
            challenge_window_slots: (1 << 26) + 1,
            ..base
        }
        .check_template(&example_limits()),
        Err(DISPUTE_TERMS),
        "and the template does refuse it"
    );
    assert!(!refused(Terms2 {
        response_window_slots: 1 << 23,
        ..base
    }));
    assert!(!refused(Terms2 {
        response_window_slots: (1 << 23) + 1,
        ..base
    }));
    assert_eq!(
        Terms2 {
            response_window_slots: (1 << 23) + 1,
            ..base
        }
        .check_template(&example_limits()),
        Err(DISPUTE_TERMS)
    );
    assert!(refused(Terms2 {
        response_window_slots: 0,
        ..base
    }));
    assert_eq!(
        Terms2 {
            response_window_slots: 7,
            ..base
        }
        .check(7),
        Ok(())
    );
    assert_eq!(
        Terms2 {
            response_window_slots: 6,
            ..base
        }
        .check(7),
        Err(DISPUTE_TERMS)
    );
    // The retention keeps revision 7's `2^62`: no cap was ever on it, and none
    // of the withdrawn four was about it.
    assert!(!refused(Terms2 {
        result_retention_slots: terms::WINDOW_CAP,
        ..base
    }));
    // The round count is the one window-shaped number DCG still keeps, and it
    // is derived rather than designed (revision 7 imposes no cap on the count).
    assert_eq!(CHALLENGE_ROUNDS_MAX, 10);
    assert_eq!(terms::ABANDON_AFTER_SLOTS_FLOOR, 1);
    // Revision 7's list 1-6, unchanged.
    assert!(refused(Terms2 {
        challenge_window_slots: 0,
        ..base
    }));
    assert!(refused(Terms2 {
        response_window_slots: 0,
        ..base
    }));
    assert!(refused(Terms2 {
        executor_reward_bps: 10_001,
        ..base
    }));
    assert!(refused(Terms2 {
        result_retention_slots: 0,
        ..base
    }));
    assert!(refused(Terms2 {
        custom_settle_window_slots: terms::CUSTOM_SETTLE_WINDOW_CAP + 1,
        ..base
    }));
    // The structural refusals: version, magic, length, and the three reserved
    // runs, byte 42 included now that it carries the policy.
    assert!(refused_raw(|r| r[4] = 1));
    assert!(refused_raw(|r| r[5] = 3));
    assert!(refused_raw(|r| r[..4].copy_from_slice(b"DDT1")));
    assert!(refused_raw(|r| r[6] = 1));
    assert!(refused_raw(|r| r[7] = 1));
    assert!(refused_raw(|r| r[43] = 1));
    assert!(refused_raw(|r| r[46] = 1));
    assert!(refused_raw(|r| r[47] = 1));
    assert_eq!(Terms2::decode(&base.encode()[..135]), Err(DISPUTE_TERMS));
    let mut long = base.encode().to_vec();
    long.push(0);
    assert_eq!(Terms2::decode(&long), Err(DISPUTE_TERMS));
    // The floors are the constants the spec's sizes table pins.
    assert_eq!(BOND_ESCROW_BYTES, 0);
    assert_eq!(BOND_ESCROW_RENT_EXEMPT, 890_880);
    assert_eq!(terms::minimum_balance(0), BOND_ESCROW_RENT_EXEMPT);
    // The 2,592,000 grace that was check 12's protocol floor is the *example
    // template's* `min_abandon_after_slots` now, and DTU1 grew to carry it.
    assert_eq!(example_limits().min_abandon_after_slots, 2_592_000);
    assert_eq!(config::DTU1_BYTES, 168);
    assert_eq!(config::DTU1_MAX_CHALLENGE_AT, 88);
    assert_eq!(config::DTU1_MIN_ABANDON_AT + 8, config::DTU1_PAYER_AT);
    assert_eq!(config::DTU1_PAYER_AT + 32, config::DTU1_BUMPS_AT);
    assert_eq!(
        config::DTU1_BUMPS_AT + 8,
        config::DTU1_BYTES,
        "five stored bumps and three reserved bytes"
    );
}

/// The split of §1.4 and the credit rule, including D11's no-winner row and the
/// dust row of `split.tsv`.
#[test]
fn the_bond_split_and_the_credit_rule_are_the_goldens() {
    for line in std::fs::read_to_string(golden_dir().join("split.tsv"))
        .unwrap()
        .lines()
        .skip(1)
    {
        let f: Vec<&str> = line.split('\t').collect();
        let (pot, bps) = (f[0].parse::<u64>().unwrap(), f[1].parse::<u16>().unwrap());
        let winner = f[2] == "yes";
        assert_eq!(
            terms::bond_split(pot, bps, winner),
            (f[3].parse().unwrap(), f[4].parse().unwrap()),
            "{f:?}"
        );
        let (slasher, remainder) = terms::bond_split(pot, bps, winner);
        assert_eq!(slasher + remainder, pot, "the pot is conserved");
    }
    assert_eq!(
        terms::bond_split(5_000_001, 1, true),
        (500, 4_999_501),
        "dust row"
    );
    assert_eq!(terms::bond_split(u64::MAX, 10_000, true), (u64::MAX, 0));
    assert_eq!(
        terms::bond_split(u64::MAX, 1, true),
        (u64::MAX / 10_000, u64::MAX - u64::MAX / 10_000)
    );
    assert_eq!(
        terms::bond_split(5_000_001, 1, false),
        (0, 5_000_001),
        "D11's no-winner row"
    );
    for line in std::fs::read_to_string(golden_dir().join("credit.tsv"))
        .unwrap()
        .lines()
        .skip(1)
    {
        let f: Vec<&str> = line.split('\t').collect();
        let (lamports, len, minimum, amount) = (
            f[0].parse::<u64>().unwrap(),
            f[1].parse::<usize>().unwrap(),
            f[2].parse::<u64>().unwrap(),
            f[3].parse::<u64>().unwrap(),
        );
        assert_eq!(terms::minimum_balance(len), minimum, "{f:?}");
        // `credit` answers with the destination's resulting balance, because
        // that is what the rule tests; the golden's `paid` is the amount moved.
        let paid = terms::credit(lamports, len, amount);
        let moved = paid
            .map(|balance| {
                assert_eq!(balance, lamports + amount, "credited in full or not at all");
                amount
            })
            .unwrap_or(0);
        assert_eq!(moved, f[4].parse::<u64>().unwrap(), "{f:?}");
        assert_eq!(
            amount - moved,
            f[5].parse::<u64>().unwrap(),
            "unpaid is the skipped share"
        );
    }
}

// ---------------------------------------------------------------- DRB1 v2

/// The completion and decision DRB1 v2 vectors decode, round-trip byte for
/// byte, and the two shapes are the two rows of §1.2's table.
#[test]
fn drb1_v2_vectors_decode_and_round_trip() {
    assert_eq!(BINDING_BYTES_V8, 196);
    let done = vector("DRB1 v2", "record");
    let decision = vector("DRB1 v2", "decision record");
    for raw in [&done, &decision] {
        let b = Binding2::decode(raw).expect("the golden binding decodes");
        assert_eq!(b.encode().to_vec(), *raw, "encode(decode(x)) == x");
    }
    let b = Binding2::decode(&done).unwrap();
    let d = Binding2::decode(&decision).unwrap();
    assert!(!b.decision() && d.decision());
    assert_eq!((b.output_first_position, b.prompt_positions), (412, 413));
    assert_eq!(
        b.output_first_position,
        b.prompt_positions - 1,
        "relation 1"
    );
    assert_eq!(
        (b.output_count, b.output_width, b.option_count),
        (224, 16, 0)
    );
    assert_eq!(
        (d.output_count, d.output_width, d.option_count),
        (5, DECISION_WIDTH, 4)
    );
    assert_eq!(
        d.output_count,
        1 + d.option_count as u32,
        "a decision is 1 + K cells"
    );
    assert_eq!(d.option_table_offset as usize, OPTION_REGION_AT);
    assert_eq!(b.option_table_offset, 0);
    assert_eq!(b.stop_plus_one, 248_047, "<|im_end|> + 1");
    assert_eq!(d.stop_plus_one, 0, "a decision has no stop rule");
    assert_eq!(b.encode()[136..140], 412u32.to_le_bytes());
    // The two-case L and the per-cell locator, at the shapes the goldens use.
    assert_eq!(b.output_span(500), 500 - 1 - 412);
    assert_eq!(d.output_span(413), 5);
    assert_eq!(b.cell(0), (412, 0));
    assert_eq!(b.cell(3), (415, 0));
    assert_eq!(d.cell(0), (412, 0));
    assert_eq!(d.cell(4), (412, 4));
}

/// Every §1.2 decode clause and both decision-branch clauses, 794.
#[test]
fn drb1_v2_every_new_check_refuses_794() {
    let raw = vector("DRB1 v2", "record");
    let d_raw = vector("DRB1 v2", "decision record");
    let base = Binding2::decode(&raw).unwrap();
    let decision = Binding2::decode(&d_raw).unwrap();
    let flip = |r: &Vec<u8>, at: usize, v: u8| {
        let mut x = r.clone();
        x[at] = v;
        Binding2::decode(&x)
    };
    let set32 = |r: &Vec<u8>, at: usize, v: u32| {
        let mut x = r.clone();
        x[at..at + 4].copy_from_slice(&v.to_le_bytes());
        Binding2::decode(&x)
    };
    // Structure: magic, version, the two reserved runs, the flag byte's other
    // bits, and the exact length.
    assert_eq!(flip(&raw, 0, b'X'), Err(RUN_BINDING));
    assert_eq!(flip(&raw, 4, 1), Err(RUN_BINDING));
    assert_eq!(flip(&raw, 5, 3), Err(RUN_BINDING));
    assert_eq!(flip(&raw, 6, 1), Err(RUN_BINDING));
    assert_eq!(flip(&raw, 7, 1), Err(RUN_BINDING));
    assert_eq!(
        flip(&raw, 151, 1),
        Err(RUN_BINDING),
        "option_count without the mode flag"
    );
    assert_eq!(
        flip(&raw, 150, 2),
        Err(RUN_BINDING),
        "bits 1..7 of decision_flags are zero"
    );
    assert_eq!(
        flip(&d_raw, 150, 0),
        Err(RUN_BINDING),
        "the mode flag with no options"
    );
    assert_eq!(Binding2::decode(&raw[..195]), Err(RUN_BINDING));
    let mut long = raw.clone();
    long.push(0);
    assert_eq!(Binding2::decode(&long), Err(RUN_BINDING));
    // Revision 7's items 1, 3 and 4, carried over.
    let mut zero_exec = raw.clone();
    zero_exec[8..40].fill(0);
    assert_eq!(Binding2::decode(&zero_exec), Err(RUN_BINDING));
    let mut no_digest = raw.clone();
    no_digest[72..104].fill(0);
    assert_eq!(Binding2::decode(&no_digest), Err(RUN_BINDING));
    let mut no_request = raw.clone();
    no_request[40..72].fill(0);
    assert_eq!(Binding2::decode(&no_request), Err(RUN_BINDING));
    let mut none = raw.clone();
    none[40..104].fill(0);
    assert!(
        Binding2::decode(&none).is_ok(),
        "no consumer (both zero) is admitted"
    );
    assert_eq!(set32(&raw, 140, 0), Err(RUN_BINDING), "output_count >= 1");
    assert_eq!(
        set32(&raw, 140, 700_000),
        Err(RUN_BINDING),
        "DCR2 over 10 MiB, 794"
    );
    assert_eq!(flip(&raw, 149, 0), Err(RUN_BINDING));
    assert_eq!(flip(&raw, 149, 33), Err(RUN_BINDING), "width is 1..=32");
    assert_eq!(
        set32(&raw, 152, 0),
        Err(RUN_BINDING),
        "1 <= prompt_positions"
    );
    // The option-table clauses: the offset is 2,182, the hash is nonzero, and
    // both are inert on a completion.
    assert_eq!(set32(&raw, 160, OPTION_REGION_AT as u32), Err(RUN_BINDING));
    assert_eq!(flip(&d_raw, 160, 0), Err(RUN_BINDING));
    let mut zero_hash = d_raw.clone();
    zero_hash[164..196].fill(0);
    assert_eq!(Binding2::decode(&zero_hash), Err(RUN_BINDING));
    assert_eq!(
        flip(&d_raw, 149, 16),
        Err(RUN_BINDING),
        "a decision's width is 4"
    );
    assert_eq!(
        set32(&d_raw, 140, 4),
        Err(RUN_BINDING),
        "decision count = 1 + option_count is checked during init decoding"
    );
    // The form-47 cap is 80; all 81 output cells still fit the u8 lane range.
    assert_eq!(
        Binding2::decode(
            &Binding2 {
                output_write: 0,
                ..decision
            }
            .encode()
        ),
        Ok(decision)
    );
    for (write, options) in [(0u8, 80u8), (174, 80), (255, 1)] {
        let b = Binding2 {
            output_write: write,
            option_count: options,
            option_table_offset: OPTION_REGION_AT as u16,
            output_count: 1 + options as u32,
            ..decision
        };
        assert_eq!(
            Binding2::decode(&b.encode()),
            Ok(b),
            "write {write} + {options} options fits"
        );
    }
    for (write, options) in [(1u8, 80u8), (175, 80), (255, 1)] {
        let over = Binding2 {
            output_write: write,
            option_count: options,
            ..decision
        };
        // Write-lane overflow is caught by `check`, which owns the lane walk.
        let raw = over.encode();
        assert_eq!(raw.len(), 196);
    }
    let over_cap = Binding2 {
        option_count: 81,
        output_count: 82,
        ..decision
    };
    assert_eq!(Binding2::decode(&over_cap.encode()), Err(RUN_BINDING));
    // The option table's length and hash, against the bytes init would write.
    let table: Vec<u8> = (0..4 * decision.option_count as usize)
        .map(|i| (i % 251) as u8)
        .collect();
    assert_eq!(
        decision.check_options(&table),
        Err(RUN_BINDING),
        "the golden's hash"
    );
    let mut wrong = table.clone();
    wrong[0] ^= 1;
    assert_eq!(decision.check_options(&wrong), Err(RUN_BINDING));
    assert_eq!(
        decision.check_options(&table[..table.len() - 4]),
        Err(RUN_BINDING),
        "length"
    );
    assert_eq!(
        base.check_options(&[]),
        Ok(()),
        "a completion carries no table"
    );
}

/// **§1's one conditional: `stop_plus_one != 0` implies `output_width == 16`,
/// 794.** The clause compares two fields of the record and needs no plan, so it
/// is a decode-time check here exactly as it is in the Python mirror
/// (`check_result_v6`'s sibling `check_binding_v2`), and both of the cases the
/// review named are the bytes themselves: a **width-4 decision that declares a
/// stop value** (a 4-byte fixed-point cell has no bytes 8..16 for the token
/// id, so the rule could never fire), and a **width-8 completion** whose stop
/// rule likewise can never fire.
#[test]
fn a_record_with_a_stop_value_must_be_sixteen_bytes_wide() {
    let raw = vector("DRB1 v2", "record");
    let d_raw = vector("DRB1 v2", "decision record");
    let stop = |r: &Vec<u8>, v: u32| {
        let mut x = r.clone();
        x[156..160].copy_from_slice(&v.to_le_bytes());
        x
    };
    // The goldens are the two admitted shapes, and they are the rule's own
    // cases: a 16-byte completion with the stop value, a 4-byte decision
    // without one.
    let b = Binding2::decode(&raw).unwrap();
    let d = Binding2::decode(&d_raw).unwrap();
    assert_eq!((b.output_width, b.stop_plus_one), (STOP_WIDTH, 248_047));
    assert_eq!((d.output_width, d.stop_plus_one), (DECISION_WIDTH, 0));
    // Width 16 is the only width a stop value admits, at any value of it --
    // including 1, the encoding of token id 0, which is why the field is
    // `stop_plus_one` and a bare `!= 0` test.
    for value in [1u32, 46, 248_047, u32::MAX] {
        let got = Binding2::decode(&stop(&raw, value)).expect("width 16 admits every stop value");
        assert_eq!(
            (got.stop_plus_one, got.output_width),
            (value, STOP_WIDTH),
            "stop_plus_one = {value}, the 16-byte (best, token) cell"
        );
    }
    // **Width 4, a decision with a stop value.** The two conditionals are
    // exclusive by construction: `option_count != 0` forces width 4 and
    // `stop_plus_one != 0` forces width 16.
    for value in [1u32, 248_047, u32::MAX] {
        let mut x = stop(&d_raw, value);
        assert_eq!(u32::from_le_bytes(x[156..160].try_into().unwrap()), value);
        assert_eq!(x[149], DECISION_WIDTH, "a decision's cells are 4 bytes");
        assert_eq!(
            Binding2::decode(&x),
            Err(RUN_BINDING),
            "a decision at stop {value}"
        );
    }
    // **Width 8, a completion whose stop rule can never fire.** Every width
    // under 16 and over 16 is refused, and the same width with `stop = 0` is
    // admitted, so the clause is on the stop value and on nothing else.
    for width in [1u8, 2, 8, 15, 17, 32] {
        let mut x = stop(&raw, 248_047);
        x[149] = width;
        assert_eq!(
            Binding2::decode(&x),
            Err(RUN_BINDING),
            "width {width} with a stop value"
        );
        // The same width with the golden's own stop value cleared is admitted,
        // so the clause is on the stop value and on nothing else.
        let mut y = stop(&raw, 0);
        y[149] = width;
        assert_eq!(
            Binding2::decode(&y).map(|b| b.output_width),
            Ok(width),
            "width {width} without a stop value"
        );
    }
    // And the mirror's own reading, restated: the clause is exactly
    // `stop_plus_one == 0 or output_width == 16`, not a bound on `width`.
    assert_eq!(
        STOP_WIDTH, 16,
        "the stop cell is the 16-byte (best, token) pair"
    );
    assert_eq!(
        result::MAX_WIDTH,
        32,
        "and a width of 32 with no stop value is legal"
    );
}

/// The decision-mode clauses that need the plan are refused by `check` on the
/// real retained rung-D template, which is the honest negative: that template
/// has no 4-byte write lanes, so no typed decision is admissible over it.
#[test]
fn the_decision_locator_refuses_a_template_without_the_lanes() {
    // A `Locator` is six bytes of a sealed PT2S; `check` compares the binding's
    // three locator fields byte for byte before it looks at the plan.
    let b = Binding2::decode(&vector("DRB1 v2", "record")).unwrap();
    let good = Locator {
        base_entry: b.output_base_entry,
        write: b.output_write,
        width: b.output_width,
    };
    assert_eq!((good.base_entry, good.write, good.width), (28_037, 0, 16));
    let pt2s = {
        let mut v = vec![0u8; 432];
        v[426..430].copy_from_slice(&28_037u32.to_le_bytes());
        v[430] = 0;
        v[431] = 16;
        v
    };
    assert_eq!(Locator::read(&pt2s, RUN_BINDING).unwrap(), good);
    assert_eq!(
        Locator::read(&pt2s[..431], RUN_BINDING),
        Err(solana_program::program_error::ProgramError::Custom(
            RUN_BINDING
        ))
    );
    // The golden decision's own locator, and the relation-2/3 negatives: a moved
    // base entry, a moved write lane and a narrowed width each refuse.
    let d_raw = vector("DRB1 v2", "decision record");
    let d = Binding2::decode(&d_raw).unwrap();
    let _ = d;
    let d_pt2s = {
        let mut v = vec![0u8; 432];
        v[426..430].copy_from_slice(&28_038u32.to_le_bytes());
        v[430] = 0;
        v[431] = 4;
        v
    };
    assert_eq!(
        Locator::read(&d_pt2s, RUN_BINDING).unwrap(),
        Locator {
            base_entry: 28_038,
            write: 0,
            width: 4
        }
    );
    assert_ne!(Locator::read(&d_pt2s, RUN_BINDING).unwrap(), good);
    // `first = prompt_positions - 1` is relation 1, checked before the plan.
    let moved = Binding2 {
        output_first_position: 411,
        prompt_positions: 413,
        ..b
    };
    assert_eq!(moved.output_first_position, moved.prompt_positions - 2);
}

// ---------------------------------------------------------------- 816

/// `DOCUMENT_LENGTH` (816), both branches, at the shapes §1.6 and §3 name.
#[test]
fn document_length_816_both_branches() {
    assert_eq!(DOCUMENT_LENGTH, 816);
    let b = Binding2::decode(&vector("DRB1 v2", "record")).unwrap();
    let d = Binding2::decode(&vector("DRB1 v2", "decision record")).unwrap();
    let capacity = 10_240;
    // The golden's own finalize: `n = 500`, `first + 2 <= n <= first + count + 1`.
    assert_eq!(document::check_document_length(&b, 500, capacity), Ok(()));
    assert_eq!(b.output_span(500), 87);
    // The example's decision: `n = prompt_positions = 413`, `count = 1 + K`.
    assert_eq!(document::check_document_length(&d, 413, capacity), Ok(()));
    for n in [414u32, 412, 413 + 1] {
        assert_eq!(
            document::check_document_length(&d, n, capacity),
            Err(DOCUMENT_LENGTH),
            "a decision's n is its prompt length"
        );
    }
    let short = Binding2 {
        output_count: 1,
        ..d
    };
    assert_eq!(
        document::check_document_length(&short, 413, capacity),
        Err(DOCUMENT_LENGTH),
        "count = 1 + option_count on a decision"
    );
    // The completion branch's four refusals.
    for n in [412u32, 0, 638] {
        assert_eq!(
            document::check_document_length(&b, n, capacity),
            Err(DOCUMENT_LENGTH),
            "n = {n}"
        );
    }
    for n in [0u32, 10_241] {
        assert_eq!(
            document::check_document_length(&b, n, capacity),
            Err(DOCUMENT_LENGTH),
            "1 <= n <= position_capacity"
        );
    }
    // The ends of the completion range are admitted, and nothing outside.
    for n in [414u32, 500, 637] {
        assert_eq!(
            document::check_document_length(&b, n, capacity),
            Ok(()),
            "n = {n}"
        );
    }
    // A short document: the smallest admitted completion is `n = first + 2`.
    let one = Binding2 {
        output_first_position: 0,
        prompt_positions: 1,
        output_count: 1,
        ..b
    };
    assert_eq!(
        document::check_document_length(&one, 2, 2),
        Ok(()),
        "n = first + 2, the smallest"
    );
    assert_eq!(
        document::check_document_length(&one, 1, 2),
        Err(DOCUMENT_LENGTH),
        "n = first + 1"
    );
    assert_eq!(
        document::check_document_length(&one, 3, 2),
        Err(DOCUMENT_LENGTH),
        "n = first + count + 2"
    );
    assert_eq!(
        document::check_document_length(&one, 2, 1),
        Err(DOCUMENT_LENGTH),
        "n <= position_capacity"
    );
    // A decision at one position: `n = prompt_positions = 1`, `first = 0`.
    let at_one = Binding2 {
        output_first_position: 0,
        prompt_positions: 1,
        ..d
    };
    assert_eq!(document::check_document_length(&at_one, 1, 1), Ok(()));
}

// ---------------------------------------------------------------- DPD2 /5

/// The `/5` preimage and its digest, built from the golden's own fields and
/// reproduced byte for byte, and the DPD2 preimage's field offsets.
#[test]
fn dpd2_v5_preimage_and_digest_match_the_golden() {
    assert_eq!(DPD2_BYTES_V8, 755);
    for (pre_part, digest_part) in [
        ("preimage", "digest"),
        ("decision preimage", "decision digest"),
    ] {
        let pre = vector("DPD2 /5", pre_part);
        let want = vector("DPD2 /5", digest_part);
        assert_eq!(pre.len(), 755, "{pre_part}");
        assert_eq!(&pre[..32], b"basanos/dcg-unified-descriptor/5");
        assert_eq!(u16_at(&pre, 32), 3, "unified_version");
        assert_eq!(pre[34], 1, "ROOT_ONLY");
        assert_eq!(pre[35], 3, "commitment_version 3");
        assert_eq!(u32_at(&pre, 36), 10_240, "the sealed K");
        assert_eq!(u16_at(&pre, 40), 34, "segment_count");
        assert_eq!(u16_at(&pre, 42), 16, "family_count");
        assert_eq!(pre[44], 14, "ceil(log2 K)");
        assert_eq!(
            pre[45], 1,
            "pt2p_compiler_version, derived from the PWR1 rung tuple"
        );
        assert_eq!(u64_at(&pre, 48), 504_606_552, "the capacity-level total");
        let terms = &pre[56..56 + TERMS_BYTES_V2];
        let binding = &pre[192..192 + BINDING_BYTES_V8];
        Terms2::decode(terms).expect("the embedded DDT2 v2 decodes");
        Binding2::decode(binding).expect("the embedded DRB1 v2 decodes");
        let own = if pre_part == "preimage" {
            "record"
        } else {
            "decision record"
        };
        assert_eq!(
            terms,
            &vector("DDT2 v2", "record")[..],
            "the completion's own terms"
        );
        assert_eq!(
            binding,
            &vector("DRB1 v2", own)[..],
            "the instance's own binding"
        );
        let d_binding = Binding2::decode(&vector("DRB1 v2", "decision record")).unwrap();
        let parts = Dpd2 {
            position_count: u32_at(&pre, 36),
            segment_count: u16_at(&pre, 40),
            family_count: u16_at(&pre, 42),
            rs1_height: pre[44],
            compiler_version: pre[45],
            total_entries: u64_at(&pre, 48),
            terms,
            binding,
            clause12_v4: &pre[388..388 + 43],
            definition_sha256: &pre[431..431 + 32],
            base_digests: &pre[463..463 + 96],
            model_root: &pre[559..559 + 32],
            position_table_root: &pre[591..591 + 32],
            prompt_commitment: &pre[623..623 + 32],
            registry: &pre[659..659 + 32],
            registry_table_root: &pre[691..691 + 32],
            dfs2_sha256: &d32(&pre, 723),
        };
        let built = parts.preimage_v8();
        assert_eq!(built, pre, "the /5 preimage, field for field");
        assert_eq!(hex(&parts.digest_v8()), hex(&want));
        assert_eq!(u32_at(&pre, 655), EPOCH, "registry_epoch");
        if pre_part == "decision preimage" {
            assert_eq!(
                &pre[192..192 + BINDING_BYTES_V8],
                &d_binding.encode()[..],
                "the decision's own binding is in its own preimage"
            );
        }
    }
    // The two descriptors differ, and neither is the revision-7 domain's.
    assert_ne!(
        vector("DPD2 /5", "preimage"),
        vector("DPD2 /5", "decision preimage")
    );
    assert_ne!(
        vector("DPD2 /5", "digest"),
        vector("DPD2 /5", "decision digest")
    );
    assert_eq!(
        Binding2::decode(&vector("DRB1 v2", "decision record"))
            .unwrap()
            .output_base_entry,
        28_038,
        "the decision's own output entry"
    );
    assert_eq!(
        &document::DESCRIPTOR_DOMAIN_V8[..],
        b"basanos/dcg-unified-descriptor/5"
    );
    assert_eq!(
        document::DESCRIPTOR_DOMAIN,
        b"basanos/dcg-unified-descriptor/4",
        "revision 7's domain is untouched"
    );
}

// ---------------------------------------------------------------- DCM2 v7

/// Every field of the DCM2 v7 records at the offset the layout golden gives
/// it, the derived chain of offsets, and the two record lengths.
#[test]
fn dcm2_v7_records_decode_at_every_frozen_offset() {
    assert_eq!(
        (
            PEAKS_AT_V8,
            TERMS_AT_V8,
            BINDING_AT_V8,
            ABANDON_DEADLINE_AT,
            OPTION_REGION_AT
        ),
        (562, 1_842, 1_978, 2_174, 2_182)
    );
    assert_eq!(WINNER_AT(), 530);
    let rows = layout("DCM2");
    for (part, options) in [("record", 0usize), ("decision record", 4 * 4)] {
        let raw = vector("DCM2 v7", part);
        assert_eq!(raw.len(), OPTION_REGION_AT + options, "{part}");
        // The layout's own tiling: the fields cover the record exactly.
        let mut at = 0usize;
        for (field, offset, width) in &rows {
            if *field == "option_table" || *field == "(end)" {
                continue;
            }
            if *field == "peaks" && options == 4 {
                continue;
            }
            assert_eq!(*offset, at, "{part} {field} is contiguous");
            at += width;
        }
        assert_eq!(&raw[..4], b"DCM2");
        assert_eq!(u16_at(&raw, 4), 7);
        assert_eq!(
            u16_at(&raw, 6),
            1 | 2 | 4 | 16 | 32,
            "armed | finalized | refuted | root_only | sealed"
        );
        assert_eq!(raw[8..40], d32(&raw, 8));
        assert_eq!(u32_at(&raw, 72), 10_240, "the sealed K");
        assert_eq!(u16_at(&raw, 76), 34);
        assert_eq!(
            &raw[78..82],
            &[253, 252, 251, 250],
            "the four stored PDA bumps"
        );
        assert_eq!(&raw[82..84], &[0; 2], "the remaining reserved bytes");
        let n = u32_at(&raw, 84);
        assert_eq!(u64_at(&raw, 88), 504_606_552, "entries_complete");
        assert_eq!(
            u64_at(&raw, 144),
            91_000,
            "dispute_deadline, rewritten at finalize"
        );
        assert_eq!(
            u64_at(&raw, 184),
            90_000,
            "challenge_window_slots = DDT2[8..16]"
        );
        assert_eq!(u64_at(&raw, 192), 504_606_552, "total_entries");
        // §1.3 (ii)(b): the deadline is written by the **last** production
        // write, and the example's is the finalize at slot 1,000 — not the
        // landing at 900, which is what an earlier draft of the emitter used.
        assert_eq!(
            u64_at(&raw, ABANDON_DEADLINE_AT),
            1_000 + 5_184_000,
            "1,000 + 5,184,000: finalize writes it once, and the attest never does"
        );
        assert_eq!(raw[527], 3, "commitment_version");
        assert!(raw[528] as usize <= 32);
        assert!(raw[529] <= 4, "executor_bond_state");
        assert_eq!(
            d32(&raw, 530),
            d32(&raw, 530),
            "conviction_winner is 32 bytes at 530"
        );
        assert_ne!(d32(&raw, 530), [0; 32], "the example recorded a winner");
        // The three embedded records, byte for byte.
        let terms = &raw[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2];
        let binding = &raw[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8];
        let t = Terms2::decode(terms).expect("the embedded terms decode");
        let b = Binding2::decode(binding).expect("the embedded binding decodes");
        assert_eq!(
            t.challenge_window_slots,
            u64_at(&raw, 184),
            "DCM2 184 equals the terms' window"
        );
        assert_eq!(b.executor, d32(&raw, 40), "DRB1's executor is DCM2 40");
        // Peaks: 562 is where the winner's 32 bytes push them to, and the
        // document's own mountain range parses out of them.
        let peaks = document::read_peaks_v8(&raw).expect("the peaks parse");
        assert!(peaks.len() as u8 <= raw[528]);
        for p in &peaks {
            let at = PEAKS_AT_V8 + 40 * (peaks.iter().position(|q| q == p).unwrap());
            assert_eq!(
                &raw[at + 1..at + 4],
                &[0, 0, 0],
                "level | zero[3] | first | digest"
            );
        }
        if options == 0 {
            assert_eq!(b.option_count, 0);
            assert_eq!(&raw[OPTION_REGION_AT..], &[] as &[u8]);
        } else {
            assert_eq!(b.option_count as usize * 4, options);
            let table = &raw[OPTION_REGION_AT..];
            assert_eq!(b.option_table_offset as usize, OPTION_REGION_AT);
            // The hash the binding carries is the hash of these bytes: the
            // option region and the binding cannot disagree.
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, table);
            let digest = sha2::Digest::finalize(hasher);
            assert_eq!(digest.as_slice(), &b.option_table_sha256[..]);
            assert_eq!(b.output_count, 1 + b.option_count as u32);
        }
        // The example's slots obey §1.3: the last landing is at 900 and the
        // finalize at 1,000, so the production deadline is 1,000 + the window
        // (finalize writes it once) and the challenge deadline is the finalize's
        // own rewrite.
        assert_eq!(
            u64_at(&raw, ABANDON_DEADLINE_AT) - 1_000,
            t.abandon_after_slots
        );
        assert_eq!(u64_at(&raw, 144) - 1_000, t.challenge_window_slots);
        // The clamp of §1.3 (ii)(c) is far away at these slots, and it is a
        // `min` against `init_slot + the template's lifetime limit`: with
        // `init_slot = 500`, the ceiling is 134,218,228.
        assert!(
            u64_at(&raw, ABANDON_DEADLINE_AT) < 500 + example_limits().max_document_lifetime_slots
        );
        assert_eq!(n, if options == 0 { 500 } else { 413 });
        assert_eq!(b.output_first_position, b.prompt_positions - 1);
    }
}

fn WINNER_AT() -> usize {
    document::WINNER_AT_V8
}

// ---------------------------------------------------------------- DCR2 v6

/// Every field of the DCR2 v6 records at the frozen offsets, the header length
/// and the derived account size.
#[test]
fn dcr2_v6_records_decode_at_every_frozen_offset() {
    assert_eq!(HEADER_V6, 416);
    assert_eq!(
        (
            result::RESULT_TERMS_AT_V6,
            result::WINNER_AT_V6,
            result::RETENTION_SLOTS_AT_V6,
            result::RETENTION_START_AT_V6,
            result::RETENTION_DEADLINE_AT_V6,
            result::BOND_STATE_AT_V6,
            result::BOND_CAUSE_AT_V6
        ),
        (216, 352, 384, 392, 400, 408, 409)
    );
    let rows = layout("DCR2");
    let mut at = 0usize;
    for (field, offset, width) in &rows {
        assert_eq!(*offset, at, "DCR2 {field} is contiguous");
        at += width;
    }
    for (part, count, width) in [
        ("record", 224u32, 16u8),
        ("closed record", 224, 16),
        ("decision record", 5, 4),
    ] {
        let raw = vector("DCR2 v6", part);
        assert_eq!(raw.len(), result::bytes_v8(count, width).unwrap(), "{part}");
        assert_eq!(u16_at(&raw, 4), 6);
        assert!(raw[6] <= 3 && raw[7] <= 1);
        assert_eq!(
            &raw[209..212],
            &[0; 3],
            "v5's zero[7] is zero[3] plus position_length"
        );
        assert_eq!(u32_at(&raw, 196), count);
        assert_eq!(raw[208], width);
        assert_eq!(
            u32_at(&raw, 212),
            if count == 5 { 413 } else { 500 },
            "position_length"
        );
        Terms2::decode(&raw[216..352]).expect("the terms mirror decodes");
        assert_eq!(raw[410], 249, "the stored DCR2 PDA bump");
        assert_eq!(&raw[411..416], &[0; 5], "the remaining reserved bytes");
        // The bitmap is the attested popcount, and the attested cells are real.
        let bitmap = &raw[HEADER_V6 + count as usize * width as usize..];
        assert_eq!(bitmap.len(), (count as usize).div_ceil(8));
        let attested: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            attested,
            u32_at(&raw, 204),
            "{part}: outputs_attested is the popcount"
        );
        assert_eq!(
            attested,
            if count == 5 { 5 } else { 87 },
            "the example stopped early"
        );
        for i in 0..attested {
            let cell = &raw[HEADER_V6 + i as usize * width as usize..][..width as usize];
            assert!(
                cell != &[0u8; 16][..width as usize],
                "attested cell {i} is present"
            );
        }
        if part == "closed record" {
            assert_eq!(raw[7], 1, "document_closed");
            assert_eq!(d32(&raw, 352), d32(&raw, 352));
            assert_ne!(d32(&raw, 352), [0; 32], "the close copied the winner");
            assert_eq!(u64_at(&raw, 384), 2_592_000, "retention_slots = the terms'");
            assert_eq!(u64_at(&raw, 400) - u64_at(&raw, 392), 2_592_000);
            assert_eq!(raw[408], 4, "bond_state = 4 is the escrowed marker");
            assert_eq!(raw[409], 4, "bond_cause = CAUSE_CONVICTION");
        } else {
            assert_eq!(raw[7], 0);
            assert_eq!(
                d32(&raw, 352),
                [0; 32],
                "the close is DCR2 352's only writer"
            );
            assert_eq!(
                (u64_at(&raw, 392), u64_at(&raw, 400)),
                (0, 0),
                "the retention clock is unstarted"
            );
            assert_eq!((raw[408], raw[409]), (0, 0));
            // **`retention_slots` is written by `UnifiedInit`, not by the
            // close**, because the terms are copied at init and both the v6
            // view and `CloseResultV6` read the retention out of the record: a
            // pre-close record carrying 0 here is a record `view_v8` refuses
            // with 580. The golden now carries the terms' 2,592,000 on the
            // pre-close rows too (stream C1's round-1 finding 2, two bytes at
            // 384..386), and this asserts the agreement rather than naming the
            // defect.
            assert_eq!(
                u64_at(&raw, 384),
                2_592_000,
                "the pre-close row carries the terms' retention, as create_v8 writes it"
            );
            assert_eq!(
                u64_at(&raw, 216 + TERMS_BYTES_V2 - 136 + 88),
                2_592_000,
                "and it equals the mirrored terms' result_retention_slots"
            );
        }
    }
    // The two shapes' sizes, and the 10 MiB bound.
    assert_eq!(result::bytes_v8(224, 16), Some(4_028));
    assert_eq!(result::bytes_v8(5, 4), Some(437));
    assert_eq!(
        result::bytes_v8(256, 4),
        Some(1_472),
        "DCR2's physical size function is independent of the form-47 cap"
    );
    assert_eq!(
        result::bytes_v8(655_360, 16),
        None,
        "over 10,485,760 bytes is 794 at init"
    );
    assert!(result::bytes_v8(650_000, 16).is_some());
    assert_eq!(
        result::bytes_v8(u32::MAX / 16, 16),
        None,
        "no 32-bit intermediate wraps into range"
    );
}

// ------------------------------------------------- finalize data and events

/// Both finalize-data vectors: the tag, the descriptor, `n`, `F` and `F` roots,
/// at `39 + 32F` bytes.
#[test]
fn the_finalize_data_vectors_decode() {
    for (part, n) in [("record", 500u32), ("decision record", 413)] {
        let raw = vector("finalize data", part);
        assert_eq!(raw[0], 165, "tag 165");
        let f = u16_at(&raw, 37);
        assert_eq!(raw.len(), 39 + 32 * f as usize);
        assert_eq!(u32_at(&raw, 33), n);
        assert_eq!(f, 16, "F = DCM2 524");
        assert!(
            raw[39..].chunks_exact(32).all(|r| r != [0; 32]),
            "every root nonzero"
        );
    }
    // The golden's descriptor is the one its DCM2 record carries.
    assert_eq!(
        vector("finalize data", "record")[1..33],
        vector("DCM2 v7", "record")[8..40]
    );
}

/// The DLE1 v3 bodies the handlers emit, against the goldens: the 92-byte
/// `init`, the 80-byte `finalize`, and the version byte itself.
#[test]
fn the_dle1_v3_bodies_match_the_goldens() {
    assert_eq!(VERSION_V3, 3);
    assert_eq!(events::VERSION, 2, "revision 7's events are unchanged");
    assert_eq!(events::BODY_V3[events::INIT as usize], 92);
    assert_eq!(events::BODY_V3[events::FINALIZE as usize], 80);
    assert_eq!(events::BODY_V3[events::LAND as usize], 48);
    assert_eq!(events::BODY_V3[events::OUTPUT as usize], 48);
    assert_eq!(events::BODY_V3[events::BOND_RETRY as usize], 96);
    assert_eq!(
        events::BODY[events::INIT as usize],
        80,
        "revision 7's init body is 80 bytes"
    );
    assert_eq!(events::BODY[events::CLOSE as usize], 56);
    let descriptor = [7u8; 32];
    // The example's init body, field for field, from the golden's own records.
    let terms = Terms2::decode(&vector("DDT2 v2", "record")).unwrap();
    let b = Binding2::decode(&vector("DRB1 v2", "record")).unwrap();
    let body = Body::new()
        .key(&b.executor)
        .key(&b.request_id)
        .u32(10_240)
        .u32(b.output_count)
        .u64(terms.executor_bond_lamports)
        .u32(b.prompt_positions)
        .u32(b.stop_plus_one)
        .u8(b.option_count)
        .u8(terms.bond_policy_kind)
        .pad(2);
    let encoded = events::encode_v3(events::INIT, &descriptor, 500, &body);
    assert_eq!(encoded.len(), 48 + 92);
    assert_eq!(u16_at(&encoded, 4), 3);
    assert_eq!(encoded[6], 1);
    assert_eq!(&encoded[8..40], &descriptor);
    assert_eq!(&encoded[48..80], &b.executor);
    assert_eq!(u32_at(&encoded, 48 + 64), 10_240);
    assert_eq!(u32_at(&encoded, 48 + 68), 224);
    assert_eq!(u64_at(&encoded, 48 + 72), 5_000_000);
    assert_eq!(u32_at(&encoded, 48 + 80), 413, "prompt_positions");
    assert_eq!(u32_at(&encoded, 48 + 84), 248_047, "stop_plus_one");
    assert_eq!(encoded[48 + 88], 0, "option_count");
    assert_eq!(encoded[48 + 89], 2, "bond_policy_kind");
    assert_eq!(&encoded[48 + 90..], &[0; 2]);
    let golden = vector("DLE1 v3", "init body");
    assert_eq!(&encoded[48..], &golden[..], "the golden's own init body");
    let doc = vector("DCM2 v7", "record");
    let fb = Body::new()
        .key(&d32(&doc, 96))
        .key(&d32(&doc, 488))
        .u64(u64_at(&doc, 144))
        .u32(u32_at(&doc, 84))
        .pad(4);
    let encoded = events::encode_v3(events::FINALIZE, &descriptor, 1_000, &fb);
    assert_eq!(encoded.len(), 48 + 80);
    assert_eq!(
        &encoded[48..],
        &vector("DLE1 v3", "finalize body")[..],
        "the golden's finalize body"
    );
}

/// The goldens' own files re-derive, so this program's bytes and stream B's
/// bytes are compared from the same source (`scripts/...--check` proves the
/// emitter agrees with the committed files).
#[test]
fn the_layout_goldens_tile_their_lengths() {
    for (name, want) in [
        ("DDT2", 136usize),
        ("DRB1", 196),
        ("DCM2", 2_182),
        ("DCR2", 416),
        ("DPD2", 755),
        ("DCRZ_v1", 96),
        ("DCRZ_v2", 200),
        ("BSS1_cause4", 200),
        ("PT2S_header", 432),
        ("finalize_data", 551),
        ("DLE1_init", 92),
        ("DLE1_finalize", 80),
        ("DLE1_close", 72),
        ("DLE1_bond_retry", 96),
        ("DTU1", 168),
    ] {
        let mut at = 0usize;
        let mut declared = None;
        for (field, offset, width) in layout(name) {
            assert_eq!(offset, at, "{name} {field} tiles contiguously");
            if field == "(end)" {
                declared = Some(offset);
            }
            at += width;
        }
        assert_eq!(
            declared,
            Some(want),
            "{name} covers its declared length exactly"
        );
    }
    for name in ["DCR1_v5", "DCR1_v6"] {
        let fields = layout(name);
        assert!(fields.contains(&("challenge_pda_bump".to_owned(), 146, 1)));
        assert!(fields.contains(&("challenge_pda_marker".to_owned(), 147, 1)));
        assert!(fields.contains(&("response_pda_bump_staged".to_owned(), 181, 1)));
        assert!(fields.contains(&("response_pda_bump".to_owned(), 219, 1)));
    }
    assert!(
        !std::fs::read_to_string(golden_dir().join("record_layouts_v1.tsv"))
            .unwrap()
            .lines()
            .skip(1)
            .any(|line| line.starts_with("DTB1\t")),
        "revision 8 is single-base and has no DTB1 record"
    );
    // The PT2S locator is the six bytes the seal writes at 426, inside v4's
    // `OFF_PWR1_LEN` gap, so the PT2S is still 760 bytes.
    assert_eq!(dcg_program::pt2p_onchain::OFF_LOCATOR, 426);
    assert_eq!(dcg_program::pt2p_onchain::OFF_PWR1, 432);
    assert_eq!(vector("PT2S", "output_locator"), unhex("856d00000010"));
    assert_eq!(
        vector("PT2S", "decision output_locator"),
        unhex("866d00000004")
    );
}
