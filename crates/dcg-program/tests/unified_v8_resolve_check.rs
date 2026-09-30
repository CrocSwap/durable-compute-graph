#![cfg(feature = "revision-8")]

//! `result::resolve_check` — the revision-8 FINAL condition, in output indices
//! (spec `docs/spec/dcg-unified-v8.md` §1.6's tag-178 row, §1.2's stop rule,
//! and §1.3 (iv) for the close's re-use of it).
//!
//! This is the clause in isolation: crafted DCR2 byte images and DRB1 v2
//! blocks, no accounts and no plan, so the whole matrix of `L`, `count` and the
//! stop value's position is reachable. The handler that calls it, over real
//! accounts, is in `unified_v8_document.rs`.
//!
//! Four things are checked, and they are the four the clause is:
//!
//! 1. **`L` is two-cased and comes from the binding**: `1 + option_count` for a
//!    decision, `n - 1 - first` for a completion, with `1 <= L <= count`.
//! 2. **The stop rule, in output indices, on a completion only.** A cell is
//!    the stop value iff the little-endian u64 at its bytes `8..16`, plus one,
//!    equals `stop_plus_one`; `stop_plus_one = 0` disables the rule; clause 1
//!    (`ran long`) finds no stop value in `[0, L-2)` and is **vacuous at
//!    `L = 1`**; clause 2 (`stopped early`) wants the stop value at `L-1`
//!    **unless `L = count`**.
//! 3. **The partial bitmap.** `outputs_attested = L` and the bitmap is exactly
//!    `[0, L)` — the counting clause is what makes the stop rule sound, because
//!    an unset bit would otherwise be read as an attested all-zero cell.
//! 4. **The already-FINAL skip**: a record whose status is `FINAL` is not
//!    re-evaluated, so a close may not pay for the check twice. It returns
//!    `AlreadyFinal` on a record that would otherwise be **violated** and on
//!    one that would otherwise be **refused**, which is the whole claim.
//!
//! Every `Binding2` here is built and then round-tripped through the program's
//! own `encode`/`decode`, so no case below can rest on a binding the program
//! would have refused at init.

use dcg_program::unified::document::{
    Binding2, BINDING_BYTES_V8, DECISION_MODE, DECISION_WIDTH, OPTION_REGION_AT, STOP_WIDTH,
};
use dcg_program::unified::result::{self, Verdict, HEADER_V6};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

const RESULT_STATE: u32 = 796;
const CL_MALFORMED: u32 = 580;
const RUN_BINDING: u32 = 794;
const CL_OVERFLOW: u32 = 598;

/// The Qwen chat stop token the design note names (248046), plus one.
const STOP: u32 = 248_047;

/// A completion binding: `first = prompt_positions - 1`, `count` outputs of
/// 16 bytes at the plan's own output write, `stop_plus_one` as given.
fn completion(first: u32, count: u32, stop_plus_one: u32) -> Binding2 {
    let b = Binding2 {
        executor: [1u8; 32],
        request_id: [2u8; 32],
        consumer_digest: [2u8; 32],
        seed: [0; 32],
        output_first_position: first,
        output_count: count,
        output_base_entry: 28_037,
        output_write: 0,
        output_width: STOP_WIDTH,
        decision_flags: 0,
        option_count: 0,
        prompt_positions: first + 1,
        stop_plus_one,
        option_table_offset: 0,
        option_table_sha256: [0; 32],
    };
    Binding2::decode(&b.encode()).expect("a completion binding the program would accept")
}

/// A decision binding: `option_count = k`, `count = 1 + k`, width 4, bit 0
/// set, and `stop_plus_one = 0` because a decision generates nothing.
fn decision(n: u32, k: u8) -> Binding2 {
    let b = Binding2 {
        executor: [1u8; 32],
        request_id: [2u8; 32],
        consumer_digest: [2u8; 32],
        seed: [0; 32],
        output_first_position: n - 1,
        output_count: 1 + k as u32,
        output_base_entry: 28_037,
        output_write: 0,
        output_width: DECISION_WIDTH,
        decision_flags: DECISION_MODE,
        option_count: k,
        prompt_positions: n,
        stop_plus_one: 0,
        option_table_offset: OPTION_REGION_AT as u16,
        option_table_sha256: [9u8; 32],
    };
    Binding2::decode(&b.encode()).expect("a decision binding the program would accept")
}

/// A DCR2 v6 image: the 416-byte header, `count` cells of the binding's width,
/// and the `ceil(count/8)`-byte LSB-first bitmap with `[0, attested)` set.
/// `token_at` names, for each output index, the token id its cell's bytes
/// `8..16` carries; an index it does not name gets a non-stop token.
///
/// **Only the attested cells are written.** The cells of `[attested, count)`
/// stay zero, which is the state the attest leaves them in and what §2.6's
/// "an unset bit requires 16 zero bytes" consumer rule checks. A decision's
/// cells are 4 bytes, so there is no token field in them at all and the width
/// decides which shape is written — the same exclusivity §1.2's two
/// conditionals give.
fn record(b: &Binding2, token_at: &[(u32, u64)], attested: u32) -> Vec<u8> {
    let (count, w) = (b.output_count as usize, b.output_width as usize);
    let full = result::bytes_v8(b.output_count, b.output_width).expect("a sized record");
    let mut raw = vec![0u8; full];
    raw[..4].copy_from_slice(b"DCR2");
    raw[4..6].copy_from_slice(&6u16.to_le_bytes());
    raw[6] = result::STATUS_PENDING;
    raw[8..40].copy_from_slice(&Pubkey::new_unique().to_bytes());
    raw[196..200].copy_from_slice(&b.output_count.to_le_bytes());
    raw[200..204].copy_from_slice(&b.output_first_position.to_le_bytes());
    raw[204..208].copy_from_slice(&attested.to_le_bytes());
    raw[208] = b.output_width;
    raw[216..216 + 136].copy_from_slice(&[0u8; 136]);
    let cells_at = HEADER_V6;
    for i in 0..count.min(attested as usize) {
        let cell = &mut raw[cells_at + i * w..cells_at + (i + 1) * w];
        let token = token_at
            .iter()
            .find(|(j, _)| *j as usize == i)
            .map(|(_, t)| *t)
            .unwrap_or(0x_00ff_ffff);
        if w >= 16 {
            // A plausible `(best, token)` pair: `best` is -1 (argmax 0), the
            // token is the u64 at bytes 8..16, and the high four bytes of that
            // u64 are zero, which is the shape a real 16-byte cell has.
            cell[0..8].copy_from_slice(&(-1i64).to_le_bytes());
            cell[8..16].copy_from_slice(&token.to_le_bytes());
        } else {
            // A decision cell is one 4-byte fixed-point value.
            cell.copy_from_slice(&token.to_le_bytes()[..w]);
        }
    }
    for i in 0..attested as usize {
        raw[cells_at + count * w + i / 8] |= 1 << (i % 8);
    }
    raw
}

/// The clause, with the codes it refuses on named.
fn check(b: &Binding2, n: u32, raw: &[u8]) -> Result<Verdict, u32> {
    let count = u32::from_le_bytes(raw[196..200].try_into().unwrap());
    let attested = u32::from_le_bytes(raw[204..208].try_into().unwrap());
    let status = raw[6];
    result::resolve_check(b, n, count, attested, status, raw).map_err(|e| match e {
        ProgramError::Custom(code) => code,
        other => panic!("{other:?}"),
    })
}

/// **The honest completion, at several `L`.** `first = 29` and `count = 50`
/// over an 80-position template is the retained run's own shape, so `L` runs
/// from the two-output minimum (`n = first + 2`) to `L = count`. A document
/// that used every output it asked for carries no stop value at all (clause
/// 2's escape); one that stopped short carries it at `L-1` and nowhere else.
#[test]
fn the_honest_completion_is_final_at_several_l() {
    let b = completion(29, 50, STOP);
    for l in [2u32, 3, 8, 17, 49, 50] {
        let n = 29 + l + 1;
        assert_eq!(b.output_span(n), l, "L = n - 1 - first at n = {n}");
        // Stopped early: the stop value at `L-1`, nowhere before it.
        let raw = record(&b, &[(l - 1, (STOP - 1) as u64)], l);
        assert_eq!(
            check(&b, n, &raw),
            Ok(Verdict::Final),
            "stopped early at L = {l}"
        );
        // Ran to the declared end: clause 2's escape at `L = count`, so no
        // output needs to be the stop value.
        if l == 50 {
            let raw = record(&b, &[], l);
            assert_eq!(
                check(&b, n, &raw),
                Ok(Verdict::Final),
                "L = count escapes clause 2"
            );
        }
    }
    // The same document with the opt-out, where **no** cell is the stop value
    // and the rule is off.
    let off = completion(29, 50, 0);
    let n = 29 + 20 + 1;
    let raw = record(&off, &[(5, (STOP - 1) as u64)], 20);
    assert_eq!(
        check(&off, n, &raw),
        Ok(Verdict::Final),
        "stop_plus_one = 0 disables the rule"
    );
}

/// **A document whose only generated token is the stop value is legal**
/// (`L = 1`, `count > 1`): clause 1 is vacuous over an empty range and clause
/// 2 is satisfied, which is the case a "no output before the last" phrasing
/// would have convicted.
#[test]
fn clause_one_is_vacuous_at_l_equals_one() {
    let b = completion(29, 50, STOP);
    let n = 29 + 2;
    assert_eq!(b.output_span(n), 1);
    let raw = record(&b, &[(0, (STOP - 1) as u64)], 1);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Final),
        "L = 1 with the stop value at output 0"
    );
    // And at `L = 1` with `count = 1`, where clause 2's escape also holds.
    let one = completion(29, 1, STOP);
    let raw = record(&one, &[(0, 7)], 1);
    assert_eq!(
        check(&one, n, &raw),
        Ok(Verdict::Final),
        "L = count = 1 needs no stop value"
    );
}

/// **The two convictions, one per clause.** Clause 1 fires on a stop value at
/// any index in `[0, L-2)`; clause 2 fires when `L < count` and `L-1` is not
/// the stop value. Both are `Violated`, which the handler turns into flag 4,
/// `challenger_wins + 1` and `status = 2` — never a refusal.
#[test]
fn the_two_clauses_each_convict() {
    let b = completion(29, 50, STOP);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    assert_eq!(l, 20);
    // Clause 1: the stop value in the middle, at `j = 9 < L-1 = 19`.
    for j in [0u32, 1, 9, 17, 18] {
        let raw = record(&b, &[(j, (STOP - 1) as u64), (l - 1, (STOP - 1) as u64)], l);
        assert_eq!(
            check(&b, n, &raw),
            Ok(Verdict::Violated),
            "clause 1 at output {j}"
        );
    }
    // Clause 2: `L = 20 < count = 50` and output 19 is something else.
    for token in [0u64, 1, 248_045, 248_047, 1 << 40, u64::MAX] {
        let raw = record(&b, &[(l - 1, token)], l);
        assert_eq!(
            check(&b, n, &raw),
            Ok(Verdict::Violated),
            "clause 2 when output {l} - 1 carries token {token}"
        );
    }
    // The mirror of clause 2: at `L = count` the same cell is legal.
    let full = completion(29, 50, STOP);
    let n_full = 29 + 50 + 1;
    let raw = record(&full, &[(49, 0)], 50);
    assert_eq!(
        check(&full, n_full, &raw),
        Ok(Verdict::Final),
        "L = count: clause 2 escaped"
    );
}

/// **Stop id 0 is expressible**, which is why the binding carries `stop + 1`:
/// a cell whose token is 0 with `stop_plus_one = 1` is the stop value, and
/// `stop_plus_one = 0` means *no stop value at all* rather than token 0.
#[test]
fn stop_id_zero_is_expressible_and_zero_means_no_rule() {
    let b = completion(29, 50, 1);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    // Token 0 at `L-1` and nowhere else: the stop value, so legal.
    let raw = record(&b, &[(l - 1, 0)], l);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Final),
        "token 0 at L-1 with stop_plus_one = 1"
    );
    // Token 0 in the middle: clause 1 fires, so the id is really being read.
    let raw = record(&b, &[(3, 0), (l - 1, 0)], l);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Violated),
        "token 0 at output 3"
    );
    // `stop_plus_one = 0` is the opt-out, **not** "token 0 is the stop value":
    // a document that declares no stop value is never convicted by token 0.
    let off = completion(29, 50, 0);
    let raw = record(&off, &[(3, 0)], l);
    assert_eq!(
        check(&off, n, &raw),
        Ok(Verdict::Final),
        "the opt-out ignores every token"
    );
}

/// **The decision document has no stop rule**, because it generates nothing
/// (§1.2): `outputs_attested = 1 + option_count` is the whole of its
/// condition. The 80-option cap is the shape that proves it, and it is
/// 4-byte cells throughout, so there is no `8..16` to read in the first place.
#[test]
fn a_decision_document_has_no_stop_rule() {
    for k in [1u8, 4, 7, 8, 80] {
        let b = decision(413, k);
        let l = b.output_span(413);
        assert_eq!(l, 1 + k as u32, "L = 1 + option_count");
        assert_eq!(
            b.output_count, l,
            "and count = 1 + option_count by 816, so L = count"
        );
        // No cell carries anything resembling a token: 4-byte cells.
        let raw = record(&b, &[(0, 0), (1, u64::MAX)], l);
        assert_eq!(
            check(&b, 413, &raw),
            Ok(Verdict::Final),
            "a decision at K = {k} is FINAL"
        );
        // One output short is a refusal, not a conviction: the decision case
        // has no clause to fall through to.
        let raw = record(&b, &[], l - 1);
        assert_eq!(
            check(&b, 413, &raw),
            Err(RESULT_STATE),
            "K = {k} with L-1 attested is 796"
        );
    }
    // **A decision cannot smuggle a stop value in.** `stop_plus_one != 0` with a
    // 4-byte cell is refused by `Binding2::decode` (794), so the two
    // conditionals of §1.2 are exclusive by construction and the resolve can
    // never be asked to read bytes `8..16` of a decision cell.
    let b = decision(413, 4);
    let mut encoded = b.encode();
    encoded[156..160].copy_from_slice(&STOP.to_le_bytes());
    assert_eq!(
        Binding2::decode(&encoded).err(),
        Some(RUN_BINDING),
        "a decision with a declared stop value is 794 at the binding"
    );
    // And a *completion* that tried the decision branch is refused the same
    // way, from the other side: bit 0 set with `option_count = 0`.
    let mut encoded = completion(412, 5, 0).encode();
    encoded[150] = DECISION_MODE;
    assert_eq!(
        Binding2::decode(&encoded).err(),
        Some(RUN_BINDING),
        "bit 0 set with option_count = 0 is 794"
    );
}

/// **The partial bitmap.** `outputs_attested = L` is the counting clause; the
/// bitmap must then be exactly `[0, L)`. Every case below is a **refusal**
/// (796), not a verdict, because a bitmap that is not `[0, L)` means the record
/// does not say what it claims to say.
///
/// The important one is the second: with `stop_plus_one = 1` an **unattested**
/// cell is 16 zero bytes, whose token is 0, which *is* the stop value — so
/// without the bitmap clause the stop rule would read an unattested cell and
/// convict an honest document.
#[test]
fn the_partial_bitmap_rule() {
    let b = completion(29, 50, STOP);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    let cells = 50 * 16;
    let bitmap_at = HEADER_V6 + cells;
    let mut raw = record(&b, &[(l - 1, (STOP - 1) as u64)], l);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Final),
        "the honest bitmap is FINAL"
    );
    // The bits of `[0, L)` really are the ones the rule wants, and the rest of
    // the region really is zero. **This is the property §2.6 calls the
    // consumer's**, and it is asserted here rather than scanned on chain: no
    // verdict reads a cell of `[L, count)`, and scanning `163,824` bytes of
    // them at `L = 1, count = 10,240` would be the largest term in the clause
    // for no change of answer.
    assert_eq!(
        raw[bitmap_at + l as usize / 8] & !(0xffu8 >> (8 - l % 8)),
        0,
        "no bit at or above L"
    );
    for i in l as usize..50 {
        assert!(
            raw[HEADER_V6 + i * 16..HEADER_V6 + (i + 1) * 16]
                .iter()
                .all(|b| *b == 0),
            "the trailing cell {i} is the zero cell a consumer requires"
        );
    }

    // (1) `outputs_attested` disagreeing with the bitmap in either direction.
    for attested in [l - 1, l + 1, 0, 49] {
        let mut raw = raw.clone();
        raw[204..208].copy_from_slice(&attested.to_le_bytes());
        assert_eq!(
            check(&b, n, &raw),
            Err(RESULT_STATE),
            "attested = {attested} at L = {l}"
        );
    }
    // (2) A clear bit **inside** `[0, L)` with the count still right, and the
    // cell of that output zeroed: the honest document this clause exists to
    // save. `stop_plus_one = 1`, so an *unattested* cell is 16 zero bytes
    // whose token is 0, which is the declared stop value — without the bitmap
    // clause the stop rule reads that cell and convicts. Both halves of the
    // pair are below, and they differ in one bit.
    let one = completion(29, 50, 1);
    let mut raw = record(&one, &[(l - 1, 0)], l);
    raw[HEADER_V6 + 4 * 16..HEADER_V6 + 5 * 16].fill(0);
    // Same bytes, bit 4 set: the bitmap is exactly `[0, L)`, the cell is read,
    // and output 4 is a stop value before the last one, so clause 1 fires.
    assert_eq!(
        check(&one, n, &raw),
        Ok(Verdict::Violated),
        "an attested output 4 that is the stop value"
    );
    raw[bitmap_at] &= !(1 << 4);
    assert_eq!(
        check(&one, n, &raw),
        Err(RESULT_STATE),
        "the same cell, unattested: 796, not a conviction"
    );
    // (3) A set bit at or above `L`, which is the other way to have a
    // partially filled bitmap that does not match.
    for j in [l, l + 1, 49] {
        let mut raw = raw.clone();
        raw[bitmap_at + j as usize / 8] |= 1 << (j % 8);
        raw[204..208].copy_from_slice(&(l + 1).to_le_bytes());
        assert_eq!(
            check(&one, n, &raw),
            Err(RESULT_STATE),
            "a set bit at {j} >= L"
        );
    }
    // (4) A **nonzero padding bit** in the last byte: nothing ever sets it, and
    // the clause's byte-exact comparison refuses it.
    let mut raw = raw.clone();
    let last = (50 - 1) / 8;
    raw[bitmap_at + last] |= 0b1000_0000;
    raw[204..208].copy_from_slice(&l.to_le_bytes());
    assert_eq!(
        check(&b, n, &raw),
        Err(RESULT_STATE),
        "a nonzero padding bit"
    );
    // (5) `L = 0` and `L > count` are refusals, not verdicts: the question has
    // no answer. `n = first + 1` is the `L = 0` case finalize refuses with 816.
    let zero = completion(29, 50, STOP);
    let raw = record(&zero, &[], 0);
    assert_eq!(
        check(&zero, 29 + 1, &raw),
        Err(RESULT_STATE),
        "n = first + 1 is 796"
    );
    // `L > count` cannot reach the handler (816 refuses it) and `count` is the
    // binding's own, so this case is driven by a record whose header count was
    // narrowed: the clause compares the two and refuses rather than reading
    // past the cells.
    let mut raw = record(&zero, &[], 0);
    raw[196..200].copy_from_slice(&10u32.to_le_bytes());
    raw[204..208].copy_from_slice(&40u32.to_le_bytes());
    assert_eq!(
        check(&zero, 29 + 60 + 1, &raw),
        Err(RESULT_STATE),
        "L > count is 796"
    );
}

/// **The already-FINAL skip.** A record whose status is `FINAL` is not
/// re-evaluated, and it must not be: §1.3 (iv) has the close run this same
/// clause, and a close of a document a separate `ResolveResultV5` already
/// resolved must not pay for it a second time. The three cases below are the
/// claim — a record that would be **violated** and one that would be
/// **refused** both return `AlreadyFinal` and read nothing.
#[test]
fn the_already_final_skip_is_a_real_skip() {
    let b = completion(29, 50, STOP);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    // (1) A record that would be convicted.
    let mut raw = record(&b, &[(4, (STOP - 1) as u64), (l - 1, (STOP - 1) as u64)], l);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Violated),
        "without the skip this is convicted"
    );
    raw[6] = result::STATUS_FINAL;
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::AlreadyFinal),
        "already FINAL is skipped"
    );
    // (2) A record that would be **refused** (nothing attested, `L = 20`): the
    // skip fires before the counting clause, not after it.
    let mut raw = record(&b, &[], 0);
    assert_eq!(check(&b, n, &raw), Err(RESULT_STATE));
    raw[6] = result::STATUS_FINAL;
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::AlreadyFinal),
        "the skip precedes the count"
    );
    // (3) A record that would be `L = 0`: also skipped.
    let mut raw = record(&b, &[], 0);
    assert_eq!(check(&b, 29 + 1, &raw), Err(RESULT_STATE));
    raw[6] = result::STATUS_FINAL;
    assert_eq!(check(&b, 29 + 1, &raw), Ok(Verdict::AlreadyFinal));
    // REFUTED and SETTLED are **not** FINAL and are not skipped, so a
    // re-resolve of a REFUTED record still runs the clause. (The handler
    // refuses a non-PENDING record with 796 before it gets here; this is the
    // clause's own answer, which is what the close's row-1 branch reads.)
    for status in [
        result::STATUS_PENDING,
        result::STATUS_REFUTED,
        result::STATUS_SETTLED,
    ] {
        let mut raw = record(&b, &[], 0);
        raw[6] = status;
        assert_eq!(
            check(&b, n, &raw),
            Err(RESULT_STATE),
            "status {status} is not skipped"
        );
    }
}

/// **A cell that cannot carry the declared stop token never matches**, which is
/// the point of the u64 comparison: a token id above `2^32 - 1`, or a cell
/// whose high bit is set, is not a token the document could have declared.
#[test]
fn a_token_above_u32_never_matches() {
    let b = completion(29, 50, 1);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    // `stop_plus_one = 1` means token 0. Every other u64 is not the stop value.
    for token in [
        1u64,
        255,
        65_535,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) + 1,
    ] {
        let raw = record(&b, &[(l - 1, token)], l);
        assert_eq!(
            check(&b, n, &raw),
            Ok(Verdict::Violated),
            "token {token:#x} is not token 0"
        );
    }
    // And the one that is.
    let raw = record(&b, &[(l - 1, 0)], l);
    assert_eq!(check(&b, n, &raw), Ok(Verdict::Final));
}

/// **A record too short to hold the cells or the bitmap is malformed** (580),
/// not a verdict. The handler's `view_v8` catches this first; the clause is
/// total on the same bytes so a caller that re-uses it cannot read past the
/// record.
#[test]
fn a_short_record_is_malformed() {
    let b = completion(29, 50, STOP);
    let n = 29 + 20 + 1;
    let l = b.output_span(n);
    let raw = record(&b, &[(l - 1, (STOP - 1) as u64)], l);
    let full = raw.len();
    // Cut inside the cells (the stop loop's range) and inside the bitmap.
    for cut in [
        HEADER_V6 + 8,
        HEADER_V6 + 19 * 16,
        HEADER_V6 + 50 * 16,
        full - 1,
    ] {
        assert_eq!(
            check(&b, n, &raw[..cut]),
            Err(CL_MALFORMED),
            "a {cut}-byte record"
        );
    }
    // The boundary cases that are **not** malformed.
    assert_eq!(check(&b, n, &raw[..full]), Ok(Verdict::Final));
    assert_eq!(raw.len(), result::bytes_v8(50, 16).unwrap());
    assert_eq!(raw.len(), 416 + 50 * 16 + (50 + 7) / 8);
}

/// **The clause is total over the bytes it is given and holds the frozen
/// geometry**: `HEADER_V6 = 416` is the v6 header the outputs start at (the
/// round-3 Medium 2 correction of round 1's stale 336/400), and the record is
/// `416 + count*width + ceil(count/8)`.
#[test]
fn the_frozen_geometry_is_the_one_the_clause_reads() {
    assert_eq!(HEADER_V6, 416);
    // `bytes_v8` is a **size** function: it bounds the record at init and says
    // nothing about the count itself, which `Binding2::decode` requires to be
    // nonzero with a 794.
    assert_eq!(result::bytes_v8(0, 0), Some(416));
    assert_eq!(
        result::bytes_v8(10_240, 16),
        Some(416 + 10_240 * 16 + 10_240 / 8)
    );
    assert_eq!(
        result::bytes_v8(65_536, 160),
        None,
        "past the 10,485,760-byte cap"
    );
    // The cell is 16 bytes, and the token is the u64 at its bytes 8..16.
    let b = completion(29, 3, STOP);
    let n = 29 + 3 + 1;
    let _ = n;
    let raw = record(&b, &[(2, (STOP - 1) as u64)], 3);
    let cell2 = HEADER_V6 + 2 * 16;
    assert_eq!(
        &raw[cell2 + 8..cell2 + 12],
        &(STOP - 1u32).to_le_bytes(),
        "the cell's token is the u64 at its bytes 8..16, low half"
    );
    assert!(
        raw[cell2 + 12..cell2 + 16].iter().all(|b| *b == 0),
        "and the high half of a real cell is zero"
    );
    assert_eq!(
        &raw[cell2..cell2 + 8],
        &(-1i64).to_le_bytes(),
        "and `best` is bytes 0..8"
    );
    // A cell that carries the stop token in the **high half** of the u64 is not
    // the stop value — `2^32 + token` cannot equal a u32 `stop_plus_one` — and
    // the comparison is on all eight bytes, not four. Shown where it changes
    // the answer: a document that stopped at `L = 2 < count = 3`.
    let two = completion(29, 3, STOP);
    let n2 = 29 + 2 + 1;
    let raw = record(&two, &[(1, (STOP - 1) as u64)], 2);
    assert_eq!(
        check(&two, n2, &raw),
        Ok(Verdict::Final),
        "the stop value at L-1 = 1"
    );
    let mut high = raw.clone();
    high[HEADER_V6 + 16 + 12] = 1;
    assert_eq!(
        check(&two, n2, &high),
        Ok(Verdict::Violated),
        "the high half of the u64 is read"
    );
    // A binding that is not a DRB1 v2 block never reaches the clause: the
    // handler's `Binding2::decode` refuses it with 794 first, and this is the
    // same call the tests above round-trip through.
    let mut bad = b.encode();
    bad[4..6].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        Binding2::decode(&bad).err(),
        Some(RUN_BINDING),
        "a DRB1 v1 block is 794"
    );
    assert_eq!(BINDING_BYTES_V8, 196);
}

/// **The one arithmetic the clause does itself.** `stop_plus_one` is a u32 and
/// the comparison is a u64 add, so `stop + 1` cannot wrap into a match and a
/// cell of `u64::MAX` is not the stop value of any u32 `stop_plus_one`. This is
/// asserted on the values rather than the record, because the record-level
/// cases are the two tests above.
#[test]
fn the_stop_comparison_cannot_wrap() {
    for stop in [0u32, 1, 2, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
        assert_ne!(u64::MAX.checked_add(1), Some(stop as u64));
        // The largest value that *is* the stop value of `stop` is `stop - 1`.
        if stop > 0 {
            assert_eq!((stop as u64 - 1).checked_add(1), Some(stop as u64));
        }
    }
    // And the two values a wrapping add could have confused: `stop_plus_one = 0`
    // is the opt-out, so it is never a comparison operand at all, and the
    // handler's clause is only entered when `stop_plus_one != 0`.
    let b = completion(29, 3, 0);
    let n = 29 + 3 + 1;
    let raw = record(&b, &[(0, u64::MAX), (2, u64::MAX)], 3);
    assert_eq!(
        check(&b, n, &raw),
        Ok(Verdict::Final),
        "the opt-out reads nothing"
    );
    let _ = CL_OVERFLOW;
}
