//! DCR1 version 5: challenges on a unified (DCM2 v5) document (spec §7).
//!
//! The 8,192-byte record keeps the v3/v4 header (`root_only_challenge`):
//! ```text
//!   0 "DCR1" | 4 phase | 5 winner (1 executor, 2 challenger) | 6 version:u16 = 5
//!   8 challenger[32] | 40 executor[32] | 72 descriptor[32] | 104 leaf[32]
//! 136 local:u32 | 140 response_len:u32 (advisory since revision 6; the
//!   executor-declared DRU1 total governs the respond path) | 144 PT2P
//!   source = 1 | 145 machine:u8 (revision 6.1: the DRP2 replay machine
//!   bound at open, 1 A16, 2 V7) | 148 deadline:u64
//! 156 position:u32 | 160 segment:u16 | 162 bond:u64 | 170 t:u32 | 174 form:u16
//! ```
//! Phases: 1 respond, 2 sealed, 3 ruled, 4 settled, 5 executor reveals a
//! segment descent round, 6 challenger descends, 7 executor reveals a
//! position's segment roots, 8 challenger selects a segment. Position-reveal
//! staging (phases 7-8): 176 staged:u16 | 178 S:u16 | 180 verified:u8 |
//! 192 roots. Family-table reveal (phase 1): 3072 verified:u8 | 3074 staged:u16
//! | 3080 roots. DEV2 at 7040..7104; path length 7167; leaf path 7168..8192.
//!
//! Every per-round deadline is `now + response_window_slots` (DCM2 1,832);
//! only the opening deadline (DCM2 144, set at finalize) uses the challenge
//! window. A fix-point (166, 168 with k = 0, 169 at height 0) evaluates the
//! per-instance check and convicts instead of refusing (spec §7.3).

use super::classes::instance_shape;
use super::document::{
    self, BOND_HELD, BOND_PAID, FLAG_FINAL, FLAG_REFUTED, RESPONSE_WINDOW_AT, TERMS_AT,
    TERMS_AT_V8, WINNER_AT_V8,
};
use super::events::{self, Body};
use super::registry::{self, find_row, HEADER as DRP2_HEADER};
use super::terms::{
    executor_bond_split, Terms, Terms2, BOND_POLICY_CUSTOM, TERMS_BYTES, TERMS_BYTES_V2,
};
use super::{
    address, d32, no, plan, u16_at, u32_at, u64_at, CL_AUTHORITY, CL_COORDINATE, CL_OVERFLOW,
    CL_PATH, DCR1_AUTH, DCR1_BAD, DCR1_DEADLINE, DCR1_PHASE, DCR1_PROOF, PLAN_BINDING,
    REGISTRY_ROOT, REVEAL_MISMATCH, REVEAL_ORDER, SETTLEMENT_PROGRAM,
};
use crate::closure_v2::{self as h, Node};
use crate::hash;
use crate::pt2p::Pt2p;
use crate::root_only as r;
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    incinerator,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

pub const VERSION: u16 = 5;
pub const SIZE: usize = 8_192;
pub const HEADER: usize = 176;
pub const PATH_START: usize = SIZE - 32 * 32;
pub const PATH_LEN_AT: usize = PATH_START - 1;
pub const DEV2_AT: usize = 7_040;
pub const REVEAL_STAGED_AT: usize = 176;
pub const REVEAL_COUNT_AT: usize = 178;
pub const REVEAL_VERIFIED_AT: usize = 180;
pub const REVEAL_ROOTS_AT: usize = 192;
pub const FTR_AT: usize = 3_072;
pub const FTR_ROOTS_AT: usize = FTR_AT + 8;
pub const PT2P_MODE_AT: usize = 144;
/// Replay machine selector (`registry::machine_selector`), written at open
/// (revision 6.1); 146..148 stay zero.
pub const MACHINE_AT: usize = 145;
pub const PHASE_RESPOND: u8 = 1;
pub const PHASE_SEALED: u8 = 2;
pub const PHASE_RULED: u8 = 3;
pub const PHASE_SETTLED: u8 = 4;
pub const PHASE_REVEAL: u8 = 5;
pub const PHASE_DESCEND: u8 = 6;
pub const PHASE_POSITION_REVEAL: u8 = 7;
pub const PHASE_SELECT: u8 = 8;
pub const OUTCOME_ADMITTED: u8 = 1;
pub const OUTCOME_CONVICTED: u8 = 2;

fn now() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

/// True when account 0 is a DCR1 v5 record (tag 131/132 dispatch).
#[cfg(feature = "revision-7")]
pub fn is_v5_record(accounts: &[AccountInfo]) -> bool {
    accounts
        .first()
        .and_then(|a| a.try_borrow_data().ok())
        .is_some_and(|raw| {
            raw.len() == SIZE && raw[..4] == *b"DCR1" && raw[6..8] == VERSION.to_le_bytes()
        })
}

/// Revision 8 does not link the revision-7 settle or timeout handlers. It only
/// recognizes their DCR1 v5 account here so tags 131/132 can be refused before
/// the same numeric tags fall through to the distinct legacy root-only module.
#[cfg(feature = "revision-8")]
pub fn is_revision7_record(accounts: &[AccountInfo]) -> bool {
    is_revision5_record(accounts) && !has_revision8_document(accounts)
}

/// Whether tags 131/132 carry a v8 DCR1 with its required DCM2 v7 account.
#[cfg(feature = "revision-8")]
pub fn is_revision8_record(accounts: &[AccountInfo]) -> bool {
    is_revision5_record(accounts) && has_revision8_document(accounts)
}

#[cfg(feature = "revision-8")]
fn is_revision5_record(accounts: &[AccountInfo]) -> bool {
    accounts
        .first()
        .and_then(|a| a.try_borrow_data().ok())
        .is_some_and(|raw| {
            raw.len() == SIZE && raw[..4] == *b"DCR1" && raw[6..8] == 5u16.to_le_bytes()
        })
}

#[cfg(feature = "revision-8")]
fn has_revision8_document(accounts: &[AccountInfo]) -> bool {
    accounts.iter().skip(1).any(|account| {
        account.try_borrow_data().ok().is_some_and(|raw| {
            raw.len() >= 6 && raw[..4] == *b"DCM2" && raw[4..6] == 7u16.to_le_bytes()
        })
    })
}

/// A writable, program-owned DCR1 v5 in `phase` (731 wrong account, 733 phase).
#[cfg(feature = "revision-7")]
fn record(program: &Pubkey, account: &AccountInfo, phase: Option<u8>) -> ProgramResult {
    if account.owner != program || !account.is_writable || account.data_len() != SIZE {
        return Err(no(DCR1_AUTH));
    }
    let raw = account.try_borrow_data()?;
    if raw[..4] != *b"DCR1" || raw[6..8] != VERSION.to_le_bytes() {
        return Err(no(DCR1_PHASE));
    }
    if phase.is_some_and(|p| raw[4] != p) {
        return Err(no(DCR1_PHASE));
    }
    // A summary record (144 = 2) is not this module's outside settle (§8.3.11
    // item 4; the RS1 module owns its phases 9-11).
    if phase.is_some_and(|p| p != PHASE_RULED) && raw[PT2P_MODE_AT] != 1 {
        return Err(no(DCR1_PHASE));
    }
    Ok(())
}

/// Revision-8 DCR1 stores its open nonce at 140..144 so readers can rederive
/// the challenge PDA. Revision 7 continues to use record() unchanged.
fn record_v8(program: &Pubkey, account: &AccountInfo, phase: Option<u8>) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    record(program, account, phase)?;
    #[cfg(feature = "revision-8")]
    {
        if account.owner != program || !account.is_writable || account.data_len() != SIZE {
            return Err(no(DCR1_AUTH));
        }
        let raw = account.try_borrow_data()?;
        if raw[..4] != *b"DCR1"
            || raw[6..8] != VERSION.to_le_bytes()
            || phase.is_some_and(|p| raw[4] != p)
            || (phase.is_some_and(|p| p != PHASE_RULED) && raw[PT2P_MODE_AT] != 1)
        {
            return Err(no(DCR1_PHASE));
        }
    }
    let raw = account.try_borrow_data()?;
    let descriptor = d32(&raw, 72, DCR1_BAD)?;
    let challenger = Pubkey::new_from_array(d32(&raw, 8, DCR1_BAD)?);
    let nonce = u32_at(&raw, 140, DCR1_BAD)?;
    if *account.key != address::challenge(program, &descriptor, &challenger, nonce).0 {
        return Err(no(DCR1_AUTH));
    }
    Ok(())
}

#[cfg(feature = "revision-8")]
fn record(program: &Pubkey, account: &AccountInfo, phase: Option<u8>) -> ProgramResult {
    record_v8(program, account, phase)
}

/// The record's document: a DCM2 v5 at the descriptor's PDA (731).
#[cfg(feature = "revision-7")]
fn record_document(
    program: &Pubkey,
    raw: &[u8],
    doc: &AccountInfo,
    writable: bool,
) -> ProgramResult {
    let descriptor = d32(raw, 72, DCR1_BAD)?;
    document::document(program, doc, Some(&descriptor), writable, DCR1_AUTH)?;
    if doc.try_borrow_data()?[40..72] != raw[40..72] {
        return Err(no(DCR1_AUTH));
    }
    Ok(())
}

/// The revision-8 round tags bind their DCR1 to a DCM2 v7. Keep this reader
/// explicit: the legacy build's `document()` accepts only DCM2 v6.
#[cfg(feature = "revision-8")]
fn record_document(
    program: &Pubkey,
    raw: &[u8],
    doc: &AccountInfo,
    writable: bool,
) -> ProgramResult {
    let descriptor = d32(raw, 72, DCR1_BAD)?;
    document::document_v8(program, doc, Some(&descriptor), writable, DCR1_AUTH)?;
    if doc.try_borrow_data()?[40..72] != raw[40..72] {
        return Err(no(DCR1_AUTH));
    }
    Ok(())
}

#[cfg(feature = "revision-7")]
fn response_deadline(doc: &AccountInfo) -> Result<u64, ProgramError> {
    let window = u64_at(&doc.try_borrow_data()?, RESPONSE_WINDOW_AT, DCR1_BAD)?;
    now()?.checked_add(window).ok_or(no(DCR1_DEADLINE))
}

/// The DDT2 v2 block moved with DCM2 v7. Every revision-8 round uses this
/// offset, including the rounds shared with the revision-7 challenge machine.
#[cfg(feature = "revision-8")]
fn response_deadline(doc: &AccountInfo) -> Result<u64, ProgramError> {
    let data = doc.try_borrow_data()?;
    let terms = Terms2::decode(&data[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]).map_err(no)?;
    now()?
        .checked_add(terms.response_window_slots)
        .ok_or(no(DCR1_DEADLINE))
}

/// PT2S and base accounts named by DCM2 v5 (785); DRP2 frozen at its recorded
/// root (774) when given.
fn bind_plan(
    program: &Pubkey,
    doc: &[u8],
    pt2s: &AccountInfo,
    routes: &AccountInfo,
    geometry: &AccountInfo,
    drp2: Option<&AccountInfo>,
) -> ProgramResult {
    if pt2s.key.as_ref() != &doc[200..232] {
        return Err(no(PLAN_BINDING));
    }
    plan::bind_pt2s(program, pt2s, routes, geometry, None)?;
    if hash::sha256(&[&pt2s.try_borrow_data()?]) != doc[232..264] {
        return Err(no(PLAN_BINDING));
    }
    if let Some(d) = drp2 {
        if d.key.as_ref() != &doc[360..392] {
            return Err(no(REGISTRY_ROOT));
        }
        registry::frozen(program, d, Some(&doc[392..424]))?;
    }
    Ok(())
}

// ------------------------------------------------------------------ SPP1 and trees

/// Fold `path` from leaf `index` of a `count`-leaf duplicate-last tree of
/// `kind` and `scope` (closure_v2 revision 3 nodes); `None` if the path has the
/// wrong length or a carried duplicate sibling is not the node itself.
pub fn dl_fold(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    count: u32,
    index: u32,
    value: &[u8; 32],
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= count || path.len() != r::path_height(count).ok()? as usize {
        return None;
    }
    let (mut index, mut width, mut span) = (index, count, 1u32);
    let mut node = Node {
        digest: *value,
        first: index,
        end: index + 1,
    };
    for (level, digest) in path.iter().enumerate() {
        let sib = index ^ 1;
        let sibling = if sib >= width {
            if *digest != node.digest {
                return None;
            }
            node
        } else {
            let first = sib.checked_mul(span)?;
            Node {
                digest: *digest,
                first,
                end: first.saturating_add(span).min(count),
            }
        };
        let height = (level + 1) as u8;
        node = if index % 2 == 0 {
            h::parent(descriptor, kind, scope, height, node, sibling)
        } else {
            h::parent(descriptor, kind, scope, height, sibling, node)
        };
        index /= 2;
        width = width.div_ceil(2);
        span = span.checked_mul(2)?;
    }
    Some(node.digest)
}

/// Position root of `p` (closure_v2 revision 3) from a segment tree root.
fn wrap_position(
    descriptor: &[u8; 32],
    p: u32,
    segments: u16,
    table_root: &[u8],
    tree: &[u8; 32],
) -> [u8; 32] {
    h::hash(
        b"position-root/2",
        &[
            descriptor,
            &p.to_le_bytes(),
            &segments.to_le_bytes(),
            table_root,
            tree,
            &[1],
        ],
    )
}

/// SPP1 (spec §7.6): `ordinal:u16 | path_count:u8 | 0:u8 | table_root[32] |
/// sibling[path_count][32]`. Returns `(ordinal, table_root, path, bytes used)`.
pub fn decode_spp1(raw: &[u8]) -> Result<(u16, [u8; 32], Vec<[u8; 32]>, usize), u32> {
    if raw.len() < 36 || raw[3] != 0 {
        return Err(DCR1_BAD);
    }
    let n = raw[2] as usize;
    let used = 36 + 32 * n;
    if raw.len() < used {
        return Err(DCR1_BAD);
    }
    let path = raw[36..used]
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    Ok((
        u16::from_le_bytes([raw[0], raw[1]]),
        raw[4..36].try_into().unwrap(),
        path,
        used,
    ))
}

/// The position root an SPP1 proves for `segment_root` at leaf `ordinal`,
/// with the handler-derived `table_root` (789 when the proof names another;
/// `None` when the path does not fold).
pub fn spp1_position_root(
    descriptor: &[u8; 32],
    p: u32,
    segments: u16,
    segment_root: &[u8; 32],
    ordinal: u16,
    proof_table_root: &[u8; 32],
    path: &[[u8; 32]],
    table_root: &[u8; 32],
) -> Result<Option<[u8; 32]>, u32> {
    if proof_table_root != table_root {
        return Err(REVEAL_MISMATCH);
    }
    Ok(dl_fold(
        descriptor,
        2,
        p,
        segments as u32,
        ordinal as u32,
        segment_root,
        path,
    )
    .map(|tree| wrap_position(descriptor, p, segments, table_root, &tree)))
}

/// `(ordinal, entry_count)` of segment `segment` at `p`.
fn segment_ordinal(x: &Pt2p<'_>, p: u32, segment: u16) -> Result<(u16, u32), ProgramError> {
    for s in 0..x.segment_count as usize {
        let (id, n) = x.segment_row(p, s).map_err(|_| no(PLAN_BINDING))?;
        if id == segment {
            return Ok((s as u16, n));
        }
    }
    Err(no(CL_COORDINATE))
}

// ------------------------------------------------------------------ fix-point

/// DEV2 (64 bytes, spec §7.1).
pub fn encode_dev2(
    code: u32,
    row: Option<&registry::RowV2>,
    t: u32,
    form: u16,
    registry_root: &[u8],
) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..4].copy_from_slice(b"DEV2");
    out[4] = if code == 0 {
        OUTCOME_ADMITTED
    } else {
        OUTCOME_CONVICTED
    };
    if let Some(row) = row {
        out[5] = row.respond_path;
        out[6] = row.witness_kind;
        out[12..16].copy_from_slice(&row.execute_cu.to_le_bytes());
        out[16..20].copy_from_slice(&row.respond_cu.to_le_bytes());
    }
    out[8..12].copy_from_slice(&code.to_le_bytes());
    out[20..24].copy_from_slice(&t.to_le_bytes());
    out[24..26].copy_from_slice(&form.to_le_bytes());
    out[28..60].copy_from_slice(registry_root);
    out
}

/// The per-instance check at a fix-point `(p, segment, local)`. Accounts
/// `plan_accounts` = [PT2S, base routes, base geometry, DRP2, PT1S] as DCM2
/// names them. A coordinate that names no committed entry refuses (581);
/// otherwise the record is cleared from 176 to 7167, `t`, `form` and DEV2
/// are written, and a convict code rules for the challenger in the same
/// instruction (phase 3, winner 2, DCM2 refuted += 1, flag 4). Returns
/// `true` when admitted. The caller has already written leaf and local.
fn fix_point(
    program: &Pubkey,
    challenge: &Pubkey,
    raw: &mut [u8],
    doc: &AccountInfo,
    plan_accounts: &[AccountInfo],
    p: u32,
    segment: u16,
    local: u32,
) -> Result<bool, ProgramError> {
    let [pt2s, routes, geometry, drp2, pt1s] = plan_accounts else {
        return Err(no(DCR1_BAD));
    };
    let (t, form, code, row, root) = {
        let d = doc.try_borrow_data()?;
        bind_plan(program, &d, pt2s, routes, geometry, Some(drp2))?;
        let s = pt2s.try_borrow_data()?;
        let index_at = plan::bind_pt1s(program, pt2s, pt1s)?;
        let pt1 = pt1s.try_borrow_data()?;
        let (rb, gb) = (routes.try_borrow_data()?, geometry.try_borrow_data()?);
        let x = plan::view(&s, &rb, &gb, &[], Some(&pt1[index_at..]))?;
        let t = x
            .entry_index(p, segment, local)
            .map_err(|_| no(CL_COORDINATE))?;
        let c = x.coordinate(p, t).map_err(|_| no(CL_COORDINATE))?;
        if c.segment != segment || c.local != local {
            return Err(no(CL_COORDINATE));
        }
        let e = x.entry(p, t).map_err(|_| no(CL_COORDINATE))?;
        for k in 0..e.route_count() {
            x.route(&e, k as u16).map_err(|_| no(CL_COORDINATE))?;
        }
        let shape = instance_shape(&x, p, t).map_err(|_| no(PLAN_BINDING))?;
        let rows = drp2.try_borrow_data()?;
        let row = find_row(&rows[DRP2_HEADER..], e.kernel_index).map_err(no)?;
        let mut code = registry::check(row.as_ref(), &shape);
        // UnifiedInit now prevents new revision-8 records from carrying an
        // out-of-range option id. Keep the challenger fix-point for older or
        // otherwise already committed DCM2 records: a valid option-table hash
        // does not make an invalid id a valid decision input.
        if code == 0
            && cfg!(feature = "revision-8")
            && matches!(
                e.kernel_index,
                crate::kernels::decision::FORM_ID | crate::kernels::decision::GATHER_FORM_ID
            )
        {
            let count = d
                .get(crate::unified::document::BINDING_AT_V8 + 151)
                .copied()
                .ok_or(no(DCR1_BAD))? as usize;
            let end = crate::unified::document::OPTION_REGION_AT
                .checked_add(count.checked_mul(4).ok_or(no(DCR1_BAD))?)
                .ok_or(no(DCR1_BAD))?;
            if let Some(table) = d.get(crate::unified::document::OPTION_REGION_AT..end) {
                let options = table
                    .chunks_exact(4)
                    .map(|token| u32::from_le_bytes(token.try_into().unwrap()))
                    .collect::<Vec<_>>();
                if crate::kernels::decision::check_options(
                    &options,
                    crate::kernels::decision::LOGITS_ROW_LENGTH,
                )
                .is_err_and(|error| error.0 == crate::kernels::decision::ERR_OPTION_RANGE)
                {
                    code = crate::kernels::decision::ERR_OPTION_RANGE;
                }
            }
        }
        (t, e.kernel_index, code, row, d32(&d, 392, DCR1_BAD)?)
    };
    // Review R3: DEV2 lies inside the descent area; clear first, then write.
    raw[HEADER..PATH_LEN_AT].fill(0);
    raw[170..174].copy_from_slice(&t.to_le_bytes());
    raw[174..176].copy_from_slice(&form.to_le_bytes());
    raw[DEV2_AT..DEV2_AT + 64].copy_from_slice(&encode_dev2(code, row.as_ref(), t, form, &root));
    if code == 0 {
        return Ok(true);
    }
    debug_assert!(super::CONVICT_CODES.contains(&code));
    rule_for_document(program, challenge, raw, doc, 2, events::CAUSE_CONVICT, code)?;
    Ok(false)
}

/// RULE(winner) (spec §7.9): the one ruling procedure of every v5 path.
/// Phase 3 and the winner byte; for a challenger win, in the same
/// instruction, DCM2 132 `challenger_wins += 1` (598 on overflow) and flag 4;
/// an executor win changes no DCM2 byte. Logs the `RULING` event, which the
/// caller must leave as its last action.
#[cfg(feature = "revision-7")]
pub fn rule(
    challenge: &Pubkey,
    raw: &mut [u8],
    doc: &AccountInfo,
    winner: u8,
    cause: u8,
    code: u32,
) -> ProgramResult {
    let descriptor = d32(raw, 72, DCR1_BAD)?;
    let wins = if winner == 2 {
        if !doc.is_writable {
            return Err(no(DCR1_AUTH));
        }
        let terms = {
            let data = doc.try_borrow_data()?;
            Terms::decode(&data[TERMS_AT..TERMS_AT + TERMS_BYTES]).map_err(no)?
        };
        let mut d = doc.try_borrow_mut_data()?;
        let wins = u32_at(&d, 132, DCR1_BAD)?
            .checked_add(1)
            .ok_or(no(CL_OVERFLOW))?;
        d[132..136].copy_from_slice(&wins.to_le_bytes());
        let flags = u16_at(&d, 6, DCR1_BAD)? | FLAG_REFUTED;
        d[6..8].copy_from_slice(&flags.to_le_bytes());
        let deadline = if terms.settlement_program == [0; 32] {
            0
        } else {
            Clock::get()?
                .slot
                .checked_add(terms.custom_settle_window_slots)
                .ok_or(no(CL_OVERFLOW))?
        };
        raw[170..178].copy_from_slice(&deadline.to_le_bytes());
        wins
    } else {
        raw[170..178].fill(0);
        u32_at(&doc.try_borrow_data()?, 132, DCR1_BAD)?
    };
    raw[4] = PHASE_RULED;
    raw[5] = winner;
    raw[178] = cause;
    events::emit(
        events::RULING,
        &descriptor,
        Body::new()
            .key(challenge.as_ref())
            .u8(winner)
            .u8(cause)
            .pad(2)
            .u32(code)
            .u32(wins)
            .pad(4),
    );
    Ok(())
}

/// Revision 8's generic replay keeps the shared mainline version switch, but
/// its document reader admits only DCM2 v7. This refusal shim satisfies the
/// unreachable v6 arm without compiling revision 7's ruling behavior here.
#[cfg(feature = "revision-8")]
pub fn rule(
    _challenge: &Pubkey,
    _raw: &mut [u8],
    _doc: &AccountInfo,
    _winner: u8,
    _cause: u8,
    _code: u32,
) -> ProgramResult {
    Err(no(DCR1_AUTH))
}

/// Revision 8 RULE. DCR1[140..144] carries the nonce needed to rederive the
/// challenge PDA. Its settle-deadline bytes stay zero because the custom settle
/// window has no revision-8 meaning.
pub fn rule_v8(
    program: &Pubkey,
    challenge: &Pubkey,
    raw: &mut [u8],
    doc: &AccountInfo,
    winner: u8,
    cause: u8,
    code: u32,
) -> ProgramResult {
    let descriptor = d32(raw, 72, DCR1_BAD)?;
    let challenger = Pubkey::new_from_array(d32(raw, 8, DCR1_BAD)?);
    let nonce = u32_at(raw, 140, DCR1_BAD)?;
    if *challenge != address::challenge(program, &descriptor, &challenger, nonce).0 {
        return Err(no(DCR1_AUTH));
    }
    document::document_v8(program, doc, Some(&descriptor), winner == 2, DCR1_AUTH)?;
    if doc.try_borrow_data()?[40..72] != raw[40..72] {
        return Err(no(DCR1_AUTH));
    }
    let wins = if winner == 2 {
        let mut d = doc.try_borrow_mut_data()?;
        let wins = u32_at(&d, 132, DCR1_BAD)?
            .checked_add(1)
            .ok_or(no(CL_OVERFLOW))?;
        d[132..136].copy_from_slice(&wins.to_le_bytes());
        let flags = u16_at(&d, 6, DCR1_BAD)? | FLAG_REFUTED;
        d[6..8].copy_from_slice(&flags.to_le_bytes());
        if d[WINNER_AT_V8..WINNER_AT_V8 + 32] == [0; 32] {
            d[WINNER_AT_V8..WINNER_AT_V8 + 32].copy_from_slice(&raw[8..40]);
        }
        wins
    } else {
        u32_at(&doc.try_borrow_data()?, 132, DCR1_BAD)?
    };
    raw[170..178].fill(0);
    raw[4] = PHASE_RULED;
    raw[5] = winner;
    raw[178] = cause;
    events::emit(
        events::RULING,
        &descriptor,
        Body::new()
            .key(challenge.as_ref())
            .u8(winner)
            .u8(cause)
            .pad(2)
            .u32(code)
            .u32(wins)
            .pad(4),
    );
    Ok(())
}

pub(crate) fn rule_for_document(
    program: &Pubkey,
    challenge: &Pubkey,
    raw: &mut [u8],
    doc: &AccountInfo,
    winner: u8,
    cause: u8,
    code: u32,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        match document::revision(program, doc, DCR1_AUTH)? {
            6 => rule(challenge, raw, doc, winner, cause, code),
            7 => rule_v8(program, challenge, raw, doc, winner, cause, code),
            _ => Err(no(DCR1_AUTH)),
        }
    }
    #[cfg(feature = "revision-8")]
    {
        rule_v8(program, challenge, raw, doc, winner, cause, code)
    }
}

/// The `RESPOND` event of a round instruction (spec §16.5): `actor` 1
/// executor, 2 challenger.
pub fn respond_event(challenge: &Pubkey, raw: &[u8], tag: u8, actor: u8, from: u8) {
    let descriptor: [u8; 32] = raw[72..104].try_into().unwrap();
    let deadline = u64::from_le_bytes(raw[148..156].try_into().unwrap());
    events::emit(
        events::RESPOND,
        &descriptor,
        Body::new()
            .key(challenge.as_ref())
            .u8(tag)
            .u8(actor)
            .u8(from)
            .u8(raw[4])
            .pad(4)
            .u64(deadline),
    );
}

// ------------------------------------------------------------------ opening

/// Checks shared by 166 and 167 before any byte changes; returns
/// `(executor, bond, deadline, bump)`. The record is the PDA
/// `"dcg-unified-challenge" | descriptor | challenger | nonce` and fresh
/// (733, spec revision 4 §7.1). Revision 6 removed the challenger's advisory
/// response length from the tag 166 and 167 packet layouts; the respond path
/// uses the executor's DRU1-declared total.
#[cfg(feature = "revision-7")]
fn open_checks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    descriptor: &[u8; 32],
    position: u32,
    nonce: u32,
) -> Result<([u8; 32], u64, u64, u8), ProgramError> {
    let [record_acc, challenger, dcm2, dpr2, system, pt2s, routes, geometry, drp2, ..] = accounts
    else {
        return Err(no(DCR1_BAD));
    };
    if !record_acc.is_writable
        || !challenger.is_signer
        || !challenger.is_writable
        || !dcm2.is_writable
        || *system.key != system_program::ID
    {
        return Err(no(DCR1_BAD));
    }
    let (key, bump) = address::challenge(program, descriptor, challenger.key, nonce);
    // Revision 6: a pre-funded record address is topped up by `open_record`,
    // not refused; only a non-system or non-empty account is (733).
    if *record_acc.key != key
        || *record_acc.owner != system_program::ID
        || !record_acc.data_is_empty()
    {
        return Err(no(DCR1_PHASE));
    }
    document::document(program, dcm2, Some(descriptor), true, DCR1_AUTH)?;
    let d = dcm2.try_borrow_data()?;
    let p_count = u32_at(&d, 72, DCR1_BAD)?;
    document::positions(program, dpr2, descriptor, p_count, false, DCR1_AUTH)?;
    bind_plan(program, &d, pt2s, routes, geometry, Some(drp2))?;
    if u16_at(&d, 6, DCR1_BAD)? & FLAG_FINAL == 0 || d[40..72] == challenger.key.to_bytes() {
        return Err(no(DCR1_AUTH));
    }
    let now = now()?;
    if now > u64_at(&d, 144, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    if position >= p_count {
        return Err(no(CL_COORDINATE));
    }
    let terms = Terms::decode(&d[TERMS_AT..TERMS_AT + TERMS_BYTES]).map_err(no)?;
    let deadline = now
        .checked_add(terms.response_window_slots)
        .ok_or(no(DCR1_DEADLINE))?;
    Ok((
        d32(&d, 40, DCR1_BAD)?,
        terms.challenger_bond_lamports,
        deadline,
        bump,
    ))
}

/// Revision 8 opens against DCM2 v7 and DDT2 v2. Its challenge record and
/// shared fields keep the same offsets, but the terms block begins at 1,842.
#[cfg(feature = "revision-8")]
fn open_checks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    descriptor: &[u8; 32],
    position: u32,
    nonce: u32,
) -> Result<([u8; 32], u64, u64, u8), ProgramError> {
    let [record_acc, challenger, dcm2, dpr2, system, pt2s, routes, geometry, drp2, ..] = accounts
    else {
        return Err(no(DCR1_BAD));
    };
    if !record_acc.is_writable
        || !challenger.is_signer
        || !challenger.is_writable
        || !dcm2.is_writable
        || *system.key != system_program::ID
    {
        return Err(no(DCR1_BAD));
    }
    let (key, bump) = address::challenge(program, descriptor, challenger.key, nonce);
    if *record_acc.key != key
        || *record_acc.owner != system_program::ID
        || !record_acc.data_is_empty()
    {
        return Err(no(DCR1_PHASE));
    }
    document::document_v8(program, dcm2, Some(descriptor), true, DCR1_AUTH)?;
    let d = dcm2.try_borrow_data()?;
    let p_count = u32_at(&d, 72, DCR1_BAD)?;
    let positions_complete = u32_at(&d, 84, DCR1_BAD)?;
    document::positions(program, dpr2, descriptor, p_count, false, DCR1_AUTH)?;
    bind_plan(program, &d, pt2s, routes, geometry, Some(drp2))?;
    if u16_at(&d, 6, DCR1_BAD)? & FLAG_FINAL == 0 || d[40..72] == challenger.key.to_bytes() {
        return Err(no(DCR1_AUTH));
    }
    let now = now()?;
    if now > u64_at(&d, 144, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    // Revision 8 separates the template's capacity K (DCM2 72) from this
    // finalized document's landed length n (DCM2 84). Tag 167 may challenge
    // only a root that exists in the document.
    if position >= positions_complete {
        return Err(no(CL_COORDINATE));
    }
    let terms = Terms2::decode(&d[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]).map_err(no)?;
    let deadline = now
        .checked_add(terms.response_window_slots)
        .ok_or(no(DCR1_DEADLINE))?;
    Ok((
        d32(&d, 40, DCR1_BAD)?,
        terms.challenger_bond_lamports,
        deadline,
        bump,
    ))
}

/// Create the record (funded by the challenger), escrow the bond, write the
/// v5 header and `open_challenges += 1`.
#[allow(clippy::too_many_arguments)]
fn open_record(
    program: &Pubkey,
    accounts: &[AccountInfo],
    descriptor: &[u8; 32],
    nonce: u32,
    bump: u8,
    executor: &[u8; 32],
    position: u32,
    segment: u16,
    bond: u64,
    deadline: u64,
    phase: u8,
) -> ProgramResult {
    registry::create_pda(
        program,
        &accounts[1],
        &accounts[0],
        &accounts[4],
        &[
            address::CHALLENGE_SEED,
            descriptor,
            accounts[1].key.as_ref(),
            &nonce.to_le_bytes(),
            &[bump],
        ],
        SIZE,
        SIZE,
        DCR1_BAD,
        DCR1_PHASE,
    )?;
    if bond > 0 {
        invoke(
            &system_instruction::transfer(accounts[1].key, accounts[0].key, bond),
            &[
                accounts[1].clone(),
                accounts[0].clone(),
                accounts[4].clone(),
            ],
        )?;
    }
    // The replay machine is bound here, for every form (revision 6.1): the
    // DRP2 `open_checks` proved frozen at DCM2's registry root carries the
    // machine name its table root commits.
    let machine = registry::machine_selector(&accounts[8].try_borrow_data()?[56..120])
        .ok_or(no(REGISTRY_ROOT))?;
    let open = u32_at(&accounts[2].try_borrow_data()?, 128, DCR1_BAD)?
        .checked_add(1)
        .ok_or(no(CL_OVERFLOW))?;
    accounts[2].try_borrow_mut_data()?[128..132].copy_from_slice(&open.to_le_bytes());
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DCR1");
    raw[4] = phase;
    raw[6..8].copy_from_slice(&VERSION.to_le_bytes());
    raw[8..40].copy_from_slice(accounts[1].key.as_ref());
    raw[40..72].copy_from_slice(executor);
    raw[72..104].copy_from_slice(descriptor);
    raw[PT2P_MODE_AT] = 1;
    raw[MACHINE_AT] = machine;
    raw[148..156].copy_from_slice(&deadline.to_le_bytes());
    raw[156..160].copy_from_slice(&position.to_le_bytes());
    raw[160..162].copy_from_slice(&segment.to_le_bytes());
    raw[162..170].copy_from_slice(&bond.to_le_bytes());
    #[cfg(feature = "revision-7")]
    match document::revision(program, &accounts[2], DCR1_AUTH)? {
        6 => { /* Preserve revision 7's response_len bytes exactly. */ }
        7 => raw[140..144].copy_from_slice(&nonce.to_le_bytes()),
        _ => return Err(no(DCR1_AUTH)),
    }
    #[cfg(feature = "revision-8")]
    raw[140..144].copy_from_slice(&nonce.to_le_bytes());
    Ok(())
}

fn open_event(
    accounts: &[AccountInfo],
    descriptor: &[u8; 32],
    position: u32,
    kind: u8,
    deadline: u64,
    bond: u64,
) {
    events::emit(
        events::CHALLENGE_OPEN,
        descriptor,
        Body::new()
            .key(accounts[0].key.as_ref())
            .key(accounts[1].key.as_ref())
            .u32(position)
            .u8(kind)
            .pad(3)
            .u64(deadline)
            .u64(bond),
    );
}

/// tag 167 ChallengePositionV5: `descriptor[32] | position:u32 |
/// response_len:u32 | nonce:u32`. Accounts: DCR1 PDA(w), challenger(s,w),
/// DCM2(w), DPR2, system, PT2S, base routes, base geometry, DRP2. A reveal
/// demand on the landed position root: phase 7, staging `S` from DCM2 76.
pub fn challenge_position(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 9 || data.len() != 41 {
        return Err(no(DCR1_BAD));
    }
    let descriptor = d32(data, 1, DCR1_BAD)?;
    let position = u32_at(data, 33, DCR1_BAD)?;
    let nonce = u32_at(data, 37, DCR1_BAD)?;
    let (executor, bond, deadline, bump) =
        open_checks(program, accounts, &descriptor, position, nonce)?;
    let segments = u16_at(&accounts[2].try_borrow_data()?, 76, DCR1_BAD)?;
    open_record(
        program,
        accounts,
        &descriptor,
        nonce,
        bump,
        &executor,
        position,
        0,
        bond,
        deadline,
        PHASE_POSITION_REVEAL,
    )?;
    accounts[0].try_borrow_mut_data()?[REVEAL_COUNT_AT..REVEAL_COUNT_AT + 2]
        .copy_from_slice(&segments.to_le_bytes());
    open_event(accounts, &descriptor, position, 2, deadline, bond);
    Ok(())
}

/// tag 166 ChallengeLeafV5: `descriptor[32] | position:u32 | segment:u16 |
/// local:u32 | leaf[32] | height:u8 | sibling[height][32] |
/// SPP1 | nonce:u32`. Accounts: as 167 plus PT1S (the payload index of the
/// fix-point). The leaf path folds to the segment root (entry count and
/// height from `segment_row(p, s)`), the SPP1 folds it to the landed DPR2
/// root with the derived `segment_table_root(p)`; then the leaf is a
/// fix-point, which admits (CHALLENGE_OPEN) or convicts (RULING only).
pub fn challenge_leaf(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 10 || data.len() < 84 {
        return Err(no(DCR1_BAD));
    }
    let descriptor = d32(data, 1, DCR1_BAD)?;
    let position = u32_at(data, 33, DCR1_BAD)?;
    let segment = u16_at(data, 37, DCR1_BAD)?;
    let local = u32_at(data, 39, DCR1_BAD)?;
    let leaf = d32(data, 43, DCR1_BAD)?;
    let height = data[75] as usize;
    let spp1_at = 76 + 32 * height;
    if data.len() < spp1_at + 4 {
        return Err(no(DCR1_BAD));
    }
    let (ordinal, proof_table, spp1_path, used) =
        decode_spp1(&data[spp1_at..data.len() - 4]).map_err(no)?;
    if data.len() != spp1_at + used + 4 {
        return Err(no(DCR1_BAD));
    }
    let nonce = u32_at(data, data.len() - 4, DCR1_BAD)?;
    let path: Vec<[u8; 32]> = data[76..spp1_at]
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let (executor, bond, deadline, bump) =
        open_checks(program, accounts, &descriptor, position, nonce)?;
    // The leaf proof: segment root from the leaf path, position root from SPP1.
    {
        let d = accounts[2].try_borrow_data()?;
        let segments = u16_at(&d, 76, DCR1_BAD)?;
        let s = accounts[5].try_borrow_data()?;
        let (rb, gb) = (
            accounts[6].try_borrow_data()?,
            accounts[7].try_borrow_data()?,
        );
        #[cfg(feature = "revision-7")]
        let x = plan::view(&s, &rb, &gb, &[], None)?;
        #[cfg(feature = "revision-8")]
        let index_at = plan::bind_pt1s(program, &accounts[5], &accounts[9])?;
        #[cfg(feature = "revision-8")]
        let pt1 = accounts[9].try_borrow_data()?;
        #[cfg(feature = "revision-8")]
        let x = plan::view(&s, &rb, &gb, &[], Some(&pt1[index_at..]))?;
        let (want, entries) = segment_ordinal(&x, position, segment)?;
        if ordinal != want {
            return Err(no(CL_COORDINATE));
        }
        if local >= entries || leaf == [0; 32] {
            return Err(no(CL_COORDINATE));
        }
        if path.len() != r::path_height(entries)? as usize {
            return Err(no(CL_PATH));
        }
        let tree =
            dl_fold(&descriptor, 1, position, entries, local, &leaf, &path).ok_or(no(CL_PATH))?;
        let segment_root = h::hash(
            b"segment-root/2",
            &[
                &descriptor,
                &position.to_le_bytes(),
                &segment.to_le_bytes(),
                &entries.to_le_bytes(),
                &tree,
                &[1],
            ],
        );
        let table = x
            .segment_table_root(position)
            .map_err(|_| no(PLAN_BINDING))?;
        let landed = document::landed_root(&accounts[3], position, CL_PATH)?;
        let proven = spp1_position_root(
            &descriptor,
            position,
            segments,
            &segment_root,
            ordinal,
            &proof_table,
            &spp1_path,
            &table,
        )
        .map_err(no)?;
        if proven != Some(landed) {
            return Err(no(CL_PATH));
        }
    }
    open_record(
        program,
        accounts,
        &descriptor,
        nonce,
        bump,
        &executor,
        position,
        segment,
        bond,
        deadline,
        PHASE_RESPOND,
    )?;
    let admitted = {
        let mut raw = accounts[0].try_borrow_mut_data()?;
        raw[104..136].copy_from_slice(&leaf);
        raw[136..140].copy_from_slice(&local.to_le_bytes());
        raw[PATH_LEN_AT] = path.len() as u8;
        for (i, sibling) in path.iter().enumerate() {
            raw[PATH_START + 32 * i..PATH_START + 32 * (i + 1)].copy_from_slice(sibling);
        }
        let plan_accounts = [
            accounts[5].clone(),
            accounts[6].clone(),
            accounts[7].clone(),
            accounts[8].clone(),
            accounts[9].clone(),
        ];
        fix_point(
            program,
            accounts[0].key,
            &mut raw,
            &accounts[2],
            &plan_accounts,
            position,
            segment,
            local,
        )?
    };
    if admitted {
        open_event(accounts, &descriptor, position, 1, deadline, bond);
    }
    Ok(())
}

// ------------------------------------------------------------------ position reveal

/// tag 163 RevealPositionV5: `first:u16 | count:u8 | root[count][32]`.
/// Accounts: DCR1(w), executor(s), DCM2, DPR2, PT2S, base routes, base
/// geometry. The completing chunk must reproduce the landed DPR2 root with
/// the on-chain `segment_table_root(p)` (789); a refusal changes nothing.
pub fn reveal_position(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 7
        || data.len() < 4
        || data[3] == 0
        || data.len() != 4 + 32 * data[3] as usize
    {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], Some(PHASE_POSITION_REVEAL))?;
    let first = u16_at(data, 1, DCR1_BAD)? as usize;
    let count = data[3] as usize;
    let chunk = &data[4..];
    let (descriptor, position, n, end) = {
        let raw = accounts[0].try_borrow_data()?;
        if !accounts[1].is_signer || raw[40..72] != accounts[1].key.to_bytes() {
            return Err(no(DCR1_AUTH));
        }
        if now()? > u64_at(&raw, 148, DCR1_BAD)? {
            return Err(no(DCR1_DEADLINE));
        }
        let n = u16_at(&raw, REVEAL_COUNT_AT, DCR1_BAD)? as usize;
        let staged = u16_at(&raw, REVEAL_STAGED_AT, DCR1_BAD)? as usize;
        if !(first == 0 || first == staged) || first + count > n {
            return Err(no(REVEAL_ORDER));
        }
        if chunk.chunks_exact(32).any(|c| c == [0; 32]) {
            return Err(no(REVEAL_MISMATCH));
        }
        record_document(program, &raw, &accounts[2], false)?;
        (
            d32(&raw, 72, DCR1_BAD)?,
            u32_at(&raw, 156, DCR1_BAD)?,
            n,
            first + count,
        )
    };
    let deadline = if end == n {
        let d = accounts[2].try_borrow_data()?;
        document::positions(
            program,
            &accounts[3],
            &descriptor,
            u32_at(&d, 72, DCR1_BAD)?,
            false,
            DCR1_AUTH,
        )?;
        bind_plan(program, &d, &accounts[4], &accounts[5], &accounts[6], None)?;
        let s = accounts[4].try_borrow_data()?;
        let (rb, gb) = (
            accounts[5].try_borrow_data()?,
            accounts[6].try_borrow_data()?,
        );
        let x = plan::view(&s, &rb, &gb, &[], None)?;
        let table = x
            .segment_table_root(position)
            .map_err(|_| no(PLAN_BINDING))?;
        let raw = accounts[0].try_borrow_data()?;
        let mut roots: Vec<[u8; 32]> = raw[REVEAL_ROOTS_AT..REVEAL_ROOTS_AT + 32 * first]
            .chunks_exact(32)
            .map(|c| c.try_into().unwrap())
            .collect();
        roots.extend(
            chunk
                .chunks_exact(32)
                .map(|c| -> [u8; 32] { c.try_into().unwrap() }),
        );
        let root = h::position_root(&descriptor, position, &table, &roots)?;
        if root != document::landed_root(&accounts[3], position, REVEAL_MISMATCH)? {
            return Err(no(REVEAL_MISMATCH));
        }
        Some(response_deadline(&accounts[2])?)
    } else {
        None
    };
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[REVEAL_ROOTS_AT + 32 * first..REVEAL_ROOTS_AT + 32 * end].copy_from_slice(chunk);
    raw[REVEAL_STAGED_AT..REVEAL_STAGED_AT + 2].copy_from_slice(&(end as u16).to_le_bytes());
    if let Some(deadline) = deadline {
        raw[REVEAL_VERIFIED_AT] = 1;
        raw[4] = PHASE_SELECT;
        raw[148..156].copy_from_slice(&deadline.to_le_bytes());
    }
    respond_event(
        accounts[0].key,
        &raw,
        super::TAG_REVEAL_POSITION,
        1,
        PHASE_POSITION_REVEAL,
    );
    Ok(())
}

/// tag 164 SelectSegmentV5: `ordinal:u16`. Accounts: DCR1(w), challenger(s),
/// DCM2, PT2S, base routes, base geometry. Enters the v4 segment descent at
/// the revealed root of `ordinal` (phase 5, executor opens).
pub fn select_segment(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 6 || data.len() != 3 {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], None)?;
    let ordinal = u16_at(data, 1, DCR1_BAD)?;
    let (position, root) = {
        let raw = accounts[0].try_borrow_data()?;
        if raw[4] != PHASE_SELECT || raw[REVEAL_VERIFIED_AT] != 1 {
            return Err(no(DCR1_PHASE));
        }
        if !accounts[1].is_signer || raw[8..40] != accounts[1].key.to_bytes() {
            return Err(no(DCR1_AUTH));
        }
        if now()? > u64_at(&raw, 148, DCR1_BAD)? {
            return Err(no(DCR1_DEADLINE));
        }
        if ordinal >= u16_at(&raw, REVEAL_COUNT_AT, DCR1_BAD)? {
            return Err(no(DCR1_PROOF));
        }
        record_document(program, &raw, &accounts[2], false)?;
        let at = REVEAL_ROOTS_AT + 32 * ordinal as usize;
        (u32_at(&raw, 156, DCR1_BAD)?, d32(&raw, at, DCR1_BAD)?)
    };
    let (segment_id, entries) = {
        let d = accounts[2].try_borrow_data()?;
        bind_plan(program, &d, &accounts[3], &accounts[4], &accounts[5], None)?;
        let s = accounts[3].try_borrow_data()?;
        let (rb, gb) = (
            accounts[4].try_borrow_data()?,
            accounts[5].try_borrow_data()?,
        );
        let x = plan::view(&s, &rb, &gb, &[], None)?;
        x.segment_row(position, ordinal as usize)
            .map_err(|_| no(PLAN_BINDING))?
    };
    let deadline = response_deadline(&accounts[2])?;
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[HEADER..PATH_LEN_AT].fill(0);
    raw[160..162].copy_from_slice(&segment_id.to_le_bytes());
    raw[HEADER + 32..HEADER + 36].copy_from_slice(&0u32.to_le_bytes());
    raw[HEADER + 36..HEADER + 40].copy_from_slice(&entries.to_le_bytes());
    raw[HEADER + 40] = r::path_height(entries)?;
    raw[HEADER + 48..HEADER + 80].copy_from_slice(&root);
    raw[4] = PHASE_REVEAL;
    raw[148..156].copy_from_slice(&deadline.to_le_bytes());
    respond_event(
        accounts[0].key,
        &raw,
        super::TAG_SELECT_SEGMENT,
        2,
        PHASE_SELECT,
    );
    Ok(())
}

// ------------------------------------------------------------------ segment descent

/// tag 168 RevealV5 (data as tag 113): `k | [tree_root32 on the opening
/// round] | k digests`. Accounts: DCR1(w), executor(s), DCM2; the `k = 0`
/// fix-point of a one-entry segment adds PT2S, base routes, base geometry,
/// DRP2, PT1S, with DCM2 writable.
pub fn reveal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 3 | 8) || data.len() < 2 || data[1] > 16 || !accounts[1].is_signer
    {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], Some(PHASE_REVEAL))?;
    let raw = accounts[0].try_borrow_data()?;
    if raw[40..72] != accounts[1].key.to_bytes() {
        return Err(no(DCR1_AUTH));
    }
    if now()? > u64_at(&raw, 148, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    let descriptor = d32(&raw, 72, DCR1_BAD)?;
    let position = u32_at(&raw, 156, DCR1_BAD)?;
    let segment = u16_at(&raw, 160, DCR1_BAD)?;
    let first = u32_at(&raw, HEADER + 32, DCR1_BAD)?;
    let end = u32_at(&raw, HEADER + 36, DCR1_BAD)?;
    let height = raw[HEADER + 40];
    let opening = raw[HEADER..HEADER + 32] == [0; 32];
    let k = data[1] as usize;
    let digests_at = if opening { 34 } else { 2 };
    let fix = k == 0;
    if data.len() != digests_at + 32 * k
        || (fix && !(opening && height == 0))
        || accounts.len() != if fix { 8 } else { 3 }
    {
        return Err(no(DCR1_BAD));
    }
    let current: [u8; 32] = if opening {
        let tree = d32(data, 2, DCR1_BAD)?;
        let wrapped = h::hash(
            b"segment-root/2",
            &[
                &descriptor,
                &position.to_le_bytes(),
                &segment.to_le_bytes(),
                &end.to_le_bytes(),
                &tree,
                &[1],
            ],
        );
        if tree == [0; 32] || raw[HEADER + 48..HEADER + 80] != wrapped {
            return Err(no(DCR1_PROOF));
        }
        tree
    } else {
        d32(&raw, HEADER, DCR1_BAD)?
    };
    record_document(program, &raw, &accounts[2], fix)?;
    let deadline = response_deadline(&accounts[2])?;
    if fix {
        drop(raw);
        let mut raw = accounts[0].try_borrow_mut_data()?;
        raw[4] = PHASE_RESPOND;
        raw[104..136].copy_from_slice(&current);
        raw[136..140].copy_from_slice(&0u32.to_le_bytes());
        raw[PATH_LEN_AT] = 0;
        raw[148..156].copy_from_slice(&deadline.to_le_bytes());
        if fix_point(
            program,
            accounts[0].key,
            &mut raw,
            &accounts[2],
            &accounts[3..8],
            position,
            segment,
            0,
        )? {
            respond_event(accounts[0].key, &raw, super::TAG_REVEAL, 1, PHASE_REVEAL);
        }
        return Ok(());
    }
    let descendants: Vec<[u8; 32]> = data[digests_at..]
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let child_height = r::verify_reveal(
        &descriptor,
        position,
        first,
        end,
        height,
        &current,
        &descendants,
    )?;
    drop(raw);
    let mut raw = accounts[0].try_borrow_mut_data()?;
    raw[4] = PHASE_DESCEND;
    raw[148..156].copy_from_slice(&deadline.to_le_bytes());
    raw[HEADER..HEADER + 32].copy_from_slice(&current);
    raw[HEADER + 41] = child_height;
    raw[HEADER + 42] = k as u8;
    raw[HEADER + 48..HEADER + 48 + 32 * k].copy_from_slice(&data[digests_at..]);
    respond_event(accounts[0].key, &raw, super::TAG_REVEAL, 1, PHASE_REVEAL);
    Ok(())
}

/// tag 169 DescendV5 (data as tag 114): the chosen distinct descendant.
/// Accounts: DCR1(w), challenger(s), DCM2; reaching `child_height = 0` is a
/// fix-point and adds PT2S, base routes, base geometry, DRP2, PT1S, with
/// DCM2 writable.
pub fn descend(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !matches!(accounts.len(), 3 | 8) || data.len() != 2 || !accounts[1].is_signer {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], Some(PHASE_DESCEND))?;
    let raw = accounts[0].try_borrow_data()?;
    if raw[8..40] != accounts[1].key.to_bytes() {
        return Err(no(DCR1_AUTH));
    }
    if now()? > u64_at(&raw, 148, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    let count = raw[HEADER + 42] as usize;
    let choice = data[1] as usize;
    if choice >= count {
        return Err(no(DCR1_PROOF));
    }
    let child_height = raw[HEADER + 41];
    let fix = child_height == 0;
    if accounts.len() != if fix { 8 } else { 3 } {
        return Err(no(DCR1_BAD));
    }
    let span = 1u32
        .checked_shl(child_height as u32)
        .ok_or(no(DCR1_PROOF))?;
    let parent_first = u32_at(&raw, HEADER + 32, DCR1_BAD)?;
    let parent_end = u32_at(&raw, HEADER + 36, DCR1_BAD)?;
    let first = parent_first
        .checked_add((choice as u32).checked_mul(span).ok_or(no(DCR1_PROOF))?)
        .ok_or(no(DCR1_PROOF))?;
    let end = first
        .checked_add(span)
        .ok_or(no(DCR1_PROOF))?
        .min(parent_end);
    let digest = d32(&raw, HEADER + 48 + 32 * choice, DCR1_PROOF)?;
    let descriptor = d32(&raw, 72, DCR1_BAD)?;
    let position = u32_at(&raw, 156, DCR1_BAD)?;
    let segment = u16_at(&raw, 160, DCR1_BAD)?;
    let current = d32(&raw, HEADER, DCR1_BAD)?;
    let height = raw[HEADER + 40];
    let descendants: Vec<[u8; 32]> = raw[HEADER + 48..HEADER + 48 + 32 * count]
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let chunk = r::reveal_path_chunk(
        &descriptor,
        position,
        parent_first,
        parent_end,
        height,
        &current,
        &descendants,
        choice,
    )?;
    let old_len = raw[PATH_LEN_AT] as usize;
    let new_len = old_len + chunk.len();
    if new_len > 32 {
        return Err(no(DCR1_PROOF));
    }
    let old_path = raw[PATH_START..PATH_START + 32 * old_len].to_vec();
    record_document(program, &raw, &accounts[2], fix)?;
    let deadline = response_deadline(&accounts[2])?;
    drop(raw);
    let mut raw = accounts[0].try_borrow_mut_data()?;
    for (i, sibling) in chunk.iter().enumerate() {
        raw[PATH_START + 32 * i..PATH_START + 32 * (i + 1)].copy_from_slice(sibling);
    }
    raw[PATH_START + 32 * chunk.len()..PATH_START + 32 * new_len].copy_from_slice(&old_path);
    raw[PATH_LEN_AT] = new_len as u8;
    raw[148..156].copy_from_slice(&deadline.to_le_bytes());
    if fix {
        raw[4] = PHASE_RESPOND;
        raw[104..136].copy_from_slice(&digest);
        raw[136..140].copy_from_slice(&first.to_le_bytes());
        if fix_point(
            program,
            accounts[0].key,
            &mut raw,
            &accounts[2],
            &accounts[3..8],
            position,
            segment,
            first,
        )? {
            respond_event(accounts[0].key, &raw, super::TAG_DESCEND, 2, PHASE_DESCEND);
        }
        return Ok(());
    }
    raw[HEADER..HEADER + 32].copy_from_slice(&digest);
    raw[HEADER + 32..HEADER + 36].copy_from_slice(&first.to_le_bytes());
    raw[HEADER + 36..HEADER + 40].copy_from_slice(&end.to_le_bytes());
    raw[HEADER + 40] = child_height;
    raw[HEADER + 42] = 0;
    raw[HEADER + 48..HEADER + 48 + 32 * count].fill(0);
    raw[4] = PHASE_REVEAL;
    respond_event(accounts[0].key, &raw, super::TAG_DESCEND, 2, PHASE_DESCEND);
    Ok(())
}

// ------------------------------------------------------------------ family-table reveal

/// tag 173 RevealFamilyTableV5 (any signer): `first:u8 | count:u8 |
/// root[count][32]`. Accounts: DCR1(w), signer(s), DCM2. Phase 1, FTR not
/// verified; the completing chunk must hash to DCM2 488 (789).
pub fn reveal_family_table(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 3
        || data.len() < 3
        || data[2] == 0
        || data.len() != 3 + 32 * data[2] as usize
        || !accounts[1].is_signer
    {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], None)?;
    let (first, count) = (data[1] as usize, data[2] as usize);
    let chunk = &data[3..];
    let mut raw = accounts[0].try_borrow_mut_data()?;
    if raw[4] != PHASE_RESPOND || raw[FTR_AT] != 0 {
        return Err(no(DCR1_PHASE));
    }
    if now()? > u64_at(&raw, 148, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    record_document(program, &raw, &accounts[2], false)?;
    let d = accounts[2].try_borrow_data()?;
    let f = u16_at(&d, 524, DCR1_BAD)? as usize;
    let staged = u16_at(&raw, FTR_AT + 2, DCR1_BAD)? as usize;
    if !(first == 0 || first == staged) || first + count > f {
        return Err(no(REVEAL_ORDER));
    }
    if chunk.chunks_exact(32).any(|c| c == [0; 32]) {
        return Err(no(REVEAL_MISMATCH));
    }
    let end = first + count;
    if end == f {
        let mut roots = raw[FTR_ROOTS_AT..FTR_ROOTS_AT + 32 * first].to_vec();
        roots.extend_from_slice(chunk);
        let descriptor = d32(&raw, 72, DCR1_BAD)?;
        if document::family_table_digest(&descriptor, &roots) != d[488..520] {
            return Err(no(REVEAL_MISMATCH));
        }
    }
    raw[FTR_ROOTS_AT + 32 * first..FTR_ROOTS_AT + 32 * end].copy_from_slice(chunk);
    raw[FTR_AT + 2..FTR_AT + 4].copy_from_slice(&(end as u16).to_le_bytes());
    if end == f {
        raw[FTR_AT] = 1;
    }
    let actor = if raw[40..72] == accounts[1].key.to_bytes() {
        1
    } else if raw[8..40] == accounts[1].key.to_bytes() {
        2
    } else {
        0
    };
    respond_event(
        accounts[0].key,
        &raw,
        super::TAG_REVEAL_FAMILY_TABLE,
        actor,
        PHASE_RESPOND,
    );
    Ok(())
}

// ------------------------------------------------------------------ timeout, settle

/// tag 132 on DCR1 v5. Accounts: DCR1(w), DCM2(w). A missed executor
/// deadline (phases 1, 2, 5, 7; summary 9, 11) rules for the challenger; a
/// missed challenger deadline (6, 8; summary 10) for the executor (RULE,
/// cause 3).
#[cfg(feature = "revision-7")]
pub fn timeout(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 2 {
        return Err(no(DCR1_BAD));
    }
    let revision = document::revision(program, &accounts[1], DCR1_AUTH)?;
    if revision == 7 {
        record_v8(program, &accounts[0], None)?;
    } else {
        record(program, &accounts[0], None)?;
    }
    let mut raw = accounts[0].try_borrow_mut_data()?;
    // A summary record (byte 144 = 2, spec §8.3.11 item 1) times out on the
    // RS1 module's phases 9-11 only; a PT2P record (144 = 1) on 1, 2, 5-8.
    let winner = match (raw[PT2P_MODE_AT], raw[4]) {
        (crate::rs1_summary::SOURCE_SUMMARY, phase) => {
            crate::rs1_summary::timeout_winner(phase).ok_or(no(DCR1_PHASE))?
        }
        (1, PHASE_RESPOND | PHASE_SEALED | PHASE_REVEAL | PHASE_POSITION_REVEAL) => 2,
        (1, PHASE_DESCEND | PHASE_SELECT) => 1,
        _ => return Err(no(DCR1_PHASE)),
    };
    if now()? <= u64_at(&raw, 148, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    if revision == 7 {
        record_document_v8(program, &raw, &accounts[1], true)?;
    } else {
        record_document(program, &raw, &accounts[1], true)?;
    }
    rule_for_document(
        program,
        accounts[0].key,
        &mut raw,
        &accounts[1],
        winner,
        events::CAUSE_TIMEOUT,
        0,
    )
}

#[cfg(feature = "revision-8")]
pub fn timeout(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 2 {
        return Err(no(DCR1_BAD));
    }
    document::revision(program, &accounts[1], DCR1_AUTH)?;
    record_v8(program, &accounts[0], None)?;
    let mut raw = accounts[0].try_borrow_mut_data()?;
    let winner = match (raw[PT2P_MODE_AT], raw[4]) {
        (1, PHASE_RESPOND | PHASE_SEALED | PHASE_REVEAL | PHASE_POSITION_REVEAL) => 2,
        (1, PHASE_DESCEND | PHASE_SELECT) => 1,
        _ => return Err(no(DCR1_PHASE)),
    };
    if now()? <= u64_at(&raw, 148, DCR1_BAD)? {
        return Err(no(DCR1_DEADLINE));
    }
    record_document_v8(program, &raw, &accounts[1], true)?;
    rule_for_document(
        program,
        accounts[0].key,
        &mut raw,
        &accounts[1],
        winner,
        events::CAUSE_TIMEOUT,
        0,
    )
}

#[cfg(feature = "revision-7")]
fn document_terms(dcm2: &AccountInfo) -> Result<(u8, Terms), ProgramError> {
    let data = dcm2.try_borrow_data()?;
    Ok((
        data[529],
        Terms::decode(&data[TERMS_AT..TERMS_AT + TERMS_BYTES]).map_err(no)?,
    ))
}

#[cfg(feature = "revision-7")]
fn require_bond_lamports(dcm2: &AccountInfo, bond: u64) -> ProgramResult {
    let floor = Rent::get()?.minimum_balance(document::DCM2_V6_BYTES);
    if dcm2.lamports() < floor.checked_add(bond).ok_or(no(CL_OVERFLOW))? {
        return Err(no(DCR1_PHASE));
    }
    Ok(())
}

#[cfg(feature = "revision-7")]
fn built_in_settlement(
    dcm2: &AccountInfo,
    winner: &AccountInfo,
    burn: &AccountInfo,
    terms: &Terms,
) -> Result<(u64, u64, u64), ProgramError> {
    let pot = terms.executor_bond_lamports;
    require_bond_lamports(dcm2, pot)?;
    let (winner_payout, burn_payout) = executor_bond_split(pot, terms.executor_reward_bps);
    **dcm2.try_borrow_mut_lamports()? -= pot;
    **winner.try_borrow_mut_lamports()? = winner
        .lamports()
        .checked_add(winner_payout)
        .ok_or(no(CL_OVERFLOW))?;
    **burn.try_borrow_mut_lamports()? = burn
        .lamports()
        .checked_add(burn_payout)
        .ok_or(no(CL_OVERFLOW))?;
    dcm2.try_borrow_mut_data()?[529] = BOND_PAID;
    Ok((pot, winner_payout, burn_payout))
}

/// The escrow must be the challenge's `"dcg-hcl-settlement"` PDA, writable,
/// system-owned and data-empty (it may hold pre-funded lamports, which then
/// join the pot the callee must pay out). Returns the PDA bump.
#[cfg(feature = "revision-7")]
fn validate_settlement_escrow(
    program: &Pubkey,
    escrow: &AccountInfo,
    challenge: &Pubkey,
) -> Result<u8, ProgramError> {
    let (key, bump) = address::settlement_escrow(program, challenge);
    if escrow.key != &key
        || !escrow.is_writable
        || escrow.owner != &system_program::ID
        || !escrow.data_is_empty()
    {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    Ok(bump)
}

/// Only an account's owner may debit it, so the callee must own the escrow
/// to pay the pot out: DCG signs for its PDA and assigns the data-empty
/// escrow to the settlement program for the callback (spec §7.4). It ends
/// with zero lamports, so the runtime removes it after the transaction.
/// Settle calls this before it moves any lamport, so the CPI boundary sees
/// balanced accounts on every runtime (the native test harness syncs only
/// the CPI's own accounts).
#[cfg(feature = "revision-7")]
fn assign_settlement_escrow<'a>(
    program: &Pubkey,
    record_acc: &AccountInfo<'a>,
    settlement_program: &AccountInfo<'a>,
    escrow: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
) -> ProgramResult {
    let bump = validate_settlement_escrow(program, escrow, record_acc.key)?;
    invoke_signed(
        &system_instruction::assign(escrow.key, settlement_program.key),
        &[escrow.clone(), system.clone()],
        &[&[
            address::SETTLEMENT_ESCROW_SEED,
            record_acc.key.as_ref(),
            &[bump],
        ]],
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "revision-7")]
fn custom_settlement<'a>(
    program: &Pubkey,
    record_acc: &AccountInfo<'a>,
    winner: &AccountInfo<'a>,
    loser: &AccountInfo<'a>,
    dcm2: &AccountInfo<'a>,
    burn: &AccountInfo<'a>,
    settlement_program: &AccountInfo<'a>,
    escrow: &AccountInfo<'a>,
    dcr2: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    descriptor: &[u8; 32],
    cause: u8,
    record_bond: u64,
    terms: &Terms,
) -> Result<(u64, u64, u64, u64), ProgramError> {
    if !settlement_program.executable
        || settlement_program.key.as_ref() != terms.settlement_program
        || *system.key != system_program::ID
        || loser.key.as_ref() != &dcm2.try_borrow_data()?[40..72]
    {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    super::result::view(program, dcr2, descriptor, false)?;
    if escrow.owner != settlement_program.key {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    let pot = terms.executor_bond_lamports;
    require_bond_lamports(dcm2, pot)?;
    **dcm2.try_borrow_mut_lamports()? -= pot;
    **escrow.try_borrow_mut_lamports()? =
        escrow.lamports().checked_add(pot).ok_or(no(CL_OVERFLOW))?;
    let (built_winner, built_burn) = executor_bond_split(pot, terms.executor_reward_bps);
    let mut data = [0u8; 200];
    data[..4].copy_from_slice(b"BSS1");
    data[4..6].copy_from_slice(&1u16.to_le_bytes());
    data[6] = 2;
    data[7] = cause;
    data[8..40].copy_from_slice(winner.key.as_ref());
    data[40..72].copy_from_slice(loser.key.as_ref());
    data[72..104].copy_from_slice(record_acc.key.as_ref());
    data[104..136].copy_from_slice(dcr2.key.as_ref());
    data[136..168].copy_from_slice(descriptor);
    data[168..176].copy_from_slice(&pot.to_le_bytes());
    data[176..184].copy_from_slice(&record_bond.to_le_bytes());
    data[184..192].copy_from_slice(&built_winner.to_le_bytes());
    data[192..200].copy_from_slice(&built_burn.to_le_bytes());
    let metas = vec![
        AccountMeta::new_readonly(*settlement_program.key, false),
        AccountMeta::new(*escrow.key, false),
        AccountMeta::new(*winner.key, false),
        AccountMeta::new(*loser.key, false),
        AccountMeta::new_readonly(*record_acc.key, false),
        AccountMeta::new_readonly(*dcr2.key, false),
        AccountMeta::new_readonly(*dcm2.key, false),
        AccountMeta::new(*burn.key, false),
        AccountMeta::new_readonly(*system.key, false),
    ];
    let starts = [winner.lamports(), loser.lamports(), burn.lamports()];
    invoke(
        &Instruction::new_with_bytes(*settlement_program.key, &data, metas),
        &[
            settlement_program.clone(),
            escrow.clone(),
            winner.clone(),
            loser.clone(),
            record_acc.clone(),
            dcr2.clone(),
            dcm2.clone(),
            burn.clone(),
            system.clone(),
        ],
    )?;
    if escrow.lamports() != 0
        || winner.lamports() < starts[0]
        || loser.lamports() < starts[1]
        || burn.lamports() < starts[2]
    {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    dcm2.try_borrow_mut_data()?[529] = BOND_PAID;
    Ok((
        pot,
        winner.lamports() - starts[0],
        loser.lamports() - starts[1],
        burn.lamports() - starts[2],
    ))
}

/// tag 131 ChallengeSettleV5, **reader-split on the DCM2 version** (spec §0,
/// exactly as at tags 177 and 178): a revision-7 record keeps the body below
/// byte for byte and a revision-8 record takes [`settle_v8`], which pays the
/// **document's own bond policy** (spec §1.4's third row) instead of
/// revision 7's built-in split.
///
/// **The version is asked only for a nine-account call, and that is the whole
/// trick.** Revision 7's list is seven metas (built-in) or eleven (custom), and
/// both lengths go straight to [`settle_v7`] with no new check, so no revision-7
/// call can reach a check it did not reach before and no revision-7 refusal code
/// moves. **Nine** is a length revision 7 never accepted: it refused it with 730
/// at the length test, and it still does, because a nine-account call on a
/// revision-7 record takes `settle_v7` and hits the same test.
#[cfg(feature = "revision-7")]
pub fn settle<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    if accounts.len() == 9 {
        if let Some(dcm2) = accounts.get(4) {
            if document::revision(program, dcm2, DCR1_BAD)? == 7 {
                return settle_v8(program, accounts, data);
            }
        }
    }
    settle_v7(program, accounts, data)
}

#[cfg(feature = "revision-8")]
pub fn settle<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    settle_v8(program, accounts, data)
}

/// tag 131 ChallengeSettleV5 (revision 7), unchanged byte for byte: the
/// built-in split with `executor_reward_bps`, the timed fallback to the built-in
/// route, and the CPI into the challenge's own `"dcg-hcl-settlement"` escrow.
#[cfg(feature = "revision-7")]
pub fn settle_v7<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || !matches!(accounts.len(), 7 | 11) {
        return Err(no(DCR1_BAD));
    }
    record(program, &accounts[0], Some(PHASE_RULED))?;
    let record_acc = &accounts[0];
    let response_acc = &accounts[1];
    let winner = &accounts[2];
    let executor = &accounts[3];
    let dcm2 = &accounts[4];
    let burn = &accounts[5];
    let challenger = &accounts[6];
    if !response_acc.is_writable
        || !winner.is_writable
        || !executor.is_writable
        || !dcm2.is_writable
        || !burn.is_writable
        || *burn.key != incinerator::ID
        || !challenger.is_writable
    {
        return Err(no(DCR1_AUTH));
    }
    let (bond, challenger_won, descriptor, cause, custom_deadline, terms) = {
        let raw = record_acc.try_borrow_data()?;
        let who = match raw[5] {
            1 => &raw[40..72],
            2 => &raw[8..40],
            _ => return Err(no(DCR1_PHASE)),
        };
        if winner.key.as_ref() != who
            || challenger.key.as_ref() != &raw[8..40]
            || executor.key.as_ref() != &raw[40..72]
            || !matches!(raw[178], 1..=3)
        {
            return Err(no(DCR1_AUTH));
        }
        record_document(program, &raw, dcm2, true)?;
        let terms = Terms::decode(&dcm2.try_borrow_data()?[TERMS_AT..TERMS_AT + TERMS_BYTES])
            .map_err(no)?;
        (
            u64_at(&raw, 162, DCR1_BAD)?,
            raw[5] == 2,
            d32(&raw, 72, DCR1_BAD)?,
            raw[178],
            u64_at(&raw, 170, DCR1_BAD)?,
            terms,
        )
    };
    let custom = terms.settlement_program != [0; 32];
    if custom != (accounts.len() == 11) {
        return Err(no(SETTLEMENT_PROGRAM));
    }
    if custom {
        let settlement_program = &accounts[7];
        let escrow = &accounts[8];
        let dcr2 = &accounts[9];
        let system = &accounts[10];
        let (escrow_key, _) = address::settlement_escrow(program, record_acc.key);
        if settlement_program.key.as_ref() != terms.settlement_program
            || escrow.key != &escrow_key
            || !escrow.is_writable
            || !dcr2.key.eq(&super::address::result(program, &descriptor).0)
            || *system.key != system_program::ID
        {
            return Err(no(SETTLEMENT_PROGRAM));
        }
    }
    let (response_key, _) = crate::closure_v2_response::address(program, record_acc.key);
    if response_acc.key != &response_key
        || (response_acc.owner != program
            && (*response_acc.owner != system_program::ID || !response_acc.data_is_empty()))
    {
        return Err(no(DCR1_AUTH));
    }
    let floor = Rent::get()?.minimum_balance(SIZE);
    if record_acc.lamports() < floor.checked_add(bond).ok_or(no(CL_OVERFLOW))? {
        return Err(no(DCR1_PHASE));
    }
    // Route (spec §7.4): the pot exists only on the first settled challenger
    // win; a nonzero program gets it before its deadline, the built-in rule
    // at or after it.
    let (state, _) = document_terms(dcm2)?;
    let route = if !(challenger_won && state == BOND_HELD) {
        0u8
    } else if !custom {
        1
    } else if now()? < custom_deadline {
        2
    } else {
        3
    };
    if route == 2 {
        if !accounts[7].executable {
            return Err(no(SETTLEMENT_PROGRAM));
        }
        assign_settlement_escrow(
            program,
            record_acc,
            &accounts[7],
            &accounts[8],
            &accounts[10],
        )?;
    }
    {
        let mut data = dcm2.try_borrow_mut_data()?;
        let open = u32_at(&data, 128, DCR1_BAD)?;
        if open == 0 {
            return Err(no(DCR1_PHASE));
        }
        data[128..132].copy_from_slice(&(open - 1).to_le_bytes());
    }
    **record_acc.try_borrow_mut_lamports()? -= bond;
    **winner.try_borrow_mut_lamports()? =
        winner.lamports().checked_add(bond).ok_or(no(CL_OVERFLOW))?;
    let (pot, winner_payout, loser_payout, burn_payout) = match route {
        2 => custom_settlement(
            program,
            record_acc,
            winner,
            executor,
            dcm2,
            burn,
            &accounts[7],
            &accounts[8],
            &accounts[9],
            &accounts[10],
            &descriptor,
            cause,
            bond,
            &terms,
        )?,
        1 | 3 => {
            let (pot, winner_payout, burn_payout) =
                built_in_settlement(dcm2, winner, burn, &terms)?;
            (pot, winner_payout, 0, burn_payout)
        }
        _ => (0, 0, 0, 0),
    };
    // No pot moved (an executor win or a later challenger win): route 1.
    let route = if route == 0 { 1 } else { route };
    record_acc.try_borrow_mut_data()?[4] = PHASE_SETTLED;
    super::result::drain(record_acc, challenger)?;
    if response_acc.owner == program {
        super::result::drain(response_acc, executor)?;
    }
    events::emit(
        events::SETTLE,
        &descriptor,
        Body::new()
            .key(record_acc.key.as_ref())
            .key(winner.key.as_ref())
            .u64(bond)
            .u64(pot)
            .u64(winner_payout)
            .u64(loser_payout)
            .u64(burn_payout)
            .u8(route)
            .pad(7),
    );
    Ok(())
}

/// The record's document: a **DCM2 v7** at the descriptor's PDA (731), the
/// revision-7 [`record_document`] with the record's own version.
fn record_document_v8(
    program: &Pubkey,
    raw: &[u8],
    doc: &AccountInfo,
    writable: bool,
) -> ProgramResult {
    let descriptor = d32(raw, 72, DCR1_BAD)?;
    document::document_v8(program, doc, Some(&descriptor), writable, DCR1_AUTH)?;
    if doc.try_borrow_data()?[40..72] != raw[40..72] {
        return Err(no(DCR1_AUTH));
    }
    Ok(())
}

/// DCM2's write-once `conviction_winner` (530), as it stands now.
fn ruling_winner_of(dcm2: &AccountInfo) -> Result<[u8; 32], ProgramError> {
    d32(&dcm2.try_borrow_data()?, WINNER_AT_V8, DCR1_BAD)
}

/// tag 131 ChallengeSettleV5 (**revision 8**, spec §1.6's row 131). Data: the
/// tag alone. **Nine accounts under either kind** -- revision 7's seven (DCR1
/// (w), the derived DRU1 PDA (w), the ruling winner (w), the record executor
/// (w), DCM2 (w), the incinerator (w), the record challenger (w)) plus, **under
/// `kind = 1`**, `policy_winner` (w) and `remainder` (w), and **under
/// `kind = 2`**, `bond_escrow` (w) and the system program (ro).
///
/// **What changed from revision 7 is the pot, and nothing else.** Revision 7's
/// `challenge::settle` built-in route is **not reachable on a revision-8
/// document**: this handler pays the document's own policy's two shares instead
/// of `⌊pot · executor_reward_bps / 10,000⌋` plus an incinerator burn, and under
/// CUSTOM it escrows the pot for tag 187 — the same per-document escrow a CUSTOM
/// close uses — and stops. **Neither route calls a settlement program**, and under
/// `kind = 2` neither makes any CPI at all: the pot's move into the escrow is a
/// direct lamport write, because a `system_instruction::transfer` out of a DCG
/// PDA is refused by the system program ([`super::bond::escrow_pot`] says why).
/// The timed fallback and the incinerator burn are withdrawn on a revision-8
/// record, and so is `executor_reward_bps` as an input: it is still encoded, still
/// bounded and still compared at bind, so a revision-7 terms block still settles
/// revision 7's way.
///
/// **The pot's two destinations are not the ruling winner and the incinerator.**
/// The recorded winner need not be the ruling winner of *this* challenge, and
/// `bond_remainder` is not the incinerator — those two metas are the whole of the
/// difference between the two account lists, and they are what
/// [`super::bond::standard_payout`] credits. The **incinerator stays in the
/// list** because §1.6's row is revision 7's seven plus two; it receives any
/// STANDARD residual the policy destinations cannot accept. A client that omits
/// it is refused 731 rather than quietly mispaying.
///
/// A **skipped** winner share is credited to `remainder` at a settle rather than
/// left in DCM2. If the combined remainder credit also fails, the still-uncreditable
/// amount goes to the incinerator. That keeps the later close from paying any bond
/// residual to the convict (spec §1.4's "where a skipped share goes").
pub fn settle_v8<'a>(program: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 9 {
        return Err(no(DCR1_BAD));
    }
    record_v8(program, &accounts[0], Some(PHASE_RULED))?;
    let record_acc = &accounts[0];
    let response_acc = &accounts[1];
    let winner = &accounts[2];
    let executor = &accounts[3];
    let dcm2 = &accounts[4];
    let burn = &accounts[5];
    let challenger = &accounts[6];
    // Under `kind = 1` the two extra metas are the split's destinations; under
    // `kind = 2` they are the escrow and the system program. The count is nine
    // either way, and which pair is present is read from the terms -- never from
    // the count (spec §1.6, and the re-review's Medium 6).
    let policy_winner = &accounts[7];
    let escrow_or_remainder = &accounts[8];
    if !response_acc.is_writable
        || !winner.is_writable
        || !executor.is_writable
        || !dcm2.is_writable
        || !burn.is_writable
        || *burn.key != incinerator::ID
        || !challenger.is_writable
        || !policy_winner.is_writable
    {
        return Err(no(DCR1_AUTH));
    }
    let (bond, challenger_won, descriptor, terms, bond_state, ruling_winner) = {
        let raw = record_acc.try_borrow_data()?;
        let who = match raw[5] {
            1 => &raw[40..72],
            2 => &raw[8..40],
            _ => return Err(no(DCR1_PHASE)),
        };
        if winner.key.as_ref() != who
            || challenger.key.as_ref() != &raw[8..40]
            || executor.key.as_ref() != &raw[40..72]
            || !matches!(raw[178], 1..=3)
        {
            return Err(no(DCR1_AUTH));
        }
        record_document_v8(program, &raw, dcm2, true)?;
        let doc = dcm2.try_borrow_data()?;
        let terms = Terms2::decode(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]).map_err(no)?;
        (
            u64_at(&raw, 162, DCR1_BAD)?,
            raw[5] == 2,
            d32(&raw, 72, DCR1_BAD)?,
            terms,
            doc[529],
            d32(&raw, 8, DCR1_BAD)?,
        )
    };
    let custom = terms.bond_policy_kind == BOND_POLICY_CUSTOM;
    if !custom && !escrow_or_remainder.is_writable {
        return Err(no(DCR1_AUTH));
    }
    // The pot's presence is discharged here, once: the document account must
    // hold its own rent-exempt minimum **at its own size** (a decision document
    // is longer than a completion's) plus the whole bond. This is the one line
    // §1.4's STANDARD route step 1 refers to.
    let live = super::bond::pot_is_live(challenger_won, bond_state);
    if live {
        let rent = Rent::get()?.minimum_balance(dcm2.data_len());
        if dcm2.lamports()
            < rent
                .checked_add(terms.executor_bond_lamports)
                .ok_or(no(CL_OVERFLOW))?
        {
            return Err(no(DCR1_PHASE));
        }
    }
    // **The winner is named before the destinations are checked**, because
    // D11's write-once happens here and the meta has to be *this* settle's
    // winner: checking first would accept an incinerator meta for a document
    // whose winner this instruction is about to record, and then pay the share
    // to the wrong account. A refusal after this write rolls the write back.
    let recorded = if live {
        let mut doc = dcm2.try_borrow_mut_data()?;
        super::bond::record_winner_if_unset(&mut doc, &ruling_winner);
        doc[WINNER_AT_V8..WINNER_AT_V8 + 32] != [0u8; 32]
    } else {
        d32(&dcm2.try_borrow_data()?, WINNER_AT_V8, DCR1_BAD)? != [0u8; 32]
    };
    if custom {
        // The escrow and the system program, checked by kind rather than by the
        // list's length; the escrow's own key, ownership and emptiness are
        // `validate_escrow`'s, and they run again at the funding call below.
        if *escrow_or_remainder.key != system_program::ID {
            return Err(no(DCR1_AUTH));
        }
    } else {
        let want = if recorded {
            ruling_winner_of(dcm2)?
        } else {
            incinerator::ID.to_bytes()
        };
        if policy_winner.key.as_ref() != want.as_slice()
            || escrow_or_remainder.key.as_ref() != terms.bond_remainder.as_slice()
        {
            return Err(no(CL_AUTHORITY));
        }
    }
    let (response_key, _) = crate::closure_v2_response::address(program, record_acc.key);
    if response_acc.key != &response_key
        || (response_acc.owner != program
            && (*response_acc.owner != system_program::ID || !response_acc.data_is_empty()))
    {
        return Err(no(DCR1_AUTH));
    }
    let floor = Rent::get()?.minimum_balance(SIZE);
    if record_acc.lamports() < floor.checked_add(bond).ok_or(no(CL_OVERFLOW))? {
        return Err(no(DCR1_PHASE));
    }
    let route = if !live {
        0
    } else if custom {
        super::bond::ROUTE_ESCROWED
    } else {
        super::bond::ROUTE_STANDARD
    };
    {
        let mut data = dcm2.try_borrow_mut_data()?;
        let open = u32_at(&data, 128, DCR1_BAD)?;
        if open == 0 {
            return Err(no(DCR1_PHASE));
        }
        data[128..132].copy_from_slice(&(open - 1).to_le_bytes());
    }
    **record_acc.try_borrow_mut_lamports()? -= bond;
    **winner.try_borrow_mut_lamports()? =
        winner.lamports().checked_add(bond).ok_or(no(CL_OVERFLOW))?;
    // The policy, in the order §1.4 gives.
    let (pot, winner_payout, remainder_payout, incinerator_payout) = if live {
        let bond_pot = terms.executor_bond_lamports;
        if custom {
            super::bond::validate_escrow(program, policy_winner, &descriptor)?;
            super::bond::escrow_pot(dcm2, policy_winner, bond_pot)?;
            super::bond::mark_escrowed(&mut dcm2.try_borrow_mut_data()?);
            (bond_pot, 0, 0, 0)
        } else {
            let (w, r, burned) = super::bond::standard_payout(
                dcm2,
                policy_winner,
                escrow_or_remainder,
                burn,
                bond_pot,
                terms.bond_slasher_bps,
                recorded,
            )?;
            super::bond::mark_paid(&mut dcm2.try_borrow_mut_data()?);
            (bond_pot, w, r, burned)
        }
    } else {
        (0, 0, 0, 0)
    };
    // No pot moved (an executor win or a later challenger win): route 1.
    let route = if route == 0 { 1 } else { route };
    record_acc.try_borrow_mut_data()?[4] = PHASE_SETTLED;
    super::result::drain(record_acc, challenger)?;
    if response_acc.owner == program {
        super::result::drain(response_acc, executor)?;
    }
    events::emit_v8(
        events::SETTLE,
        &descriptor,
        Body::new()
            .key(record_acc.key.as_ref())
            .key(winner.key.as_ref())
            .u64(bond)
            .u64(pot)
            .u64(winner_payout)
            .u64(remainder_payout)
            .u64(incinerator_payout)
            .u8(route)
            .pad(7),
    );
    Ok(())
}

/// tag 182 CloseResponseV5 (revision 6, spec §7.4): data the tag alone.
/// Accounts: DCR1 (read-only), DRU1 (w), executor (w). The record must be a
/// ruled (phase 3) v5 PT2P record; the DRU1 its bound response (staging or
/// sealed); the executor its record executor. Drains the DRU1 to the
/// executor, returning the rent the ruling stranded. Permissionless (the
/// destination is fixed to the record executor); call between RULE and
/// settle, since settle closes the record this checks. No event: no state
/// machine transition, and the lamport delta is the receipt.
#[cfg(feature = "revision-7")]
pub fn close_response(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 3 {
        return Err(no(DCR1_BAD));
    }
    let [record_acc, response_acc, executor] = accounts else {
        return Err(no(DCR1_BAD));
    };
    if !response_acc.is_writable || !executor.is_writable {
        return Err(no(DCR1_AUTH));
    }
    let record_executor = {
        let raw = record_acc.try_borrow_data()?;
        if record_acc.owner != program || raw.len() != SIZE {
            return Err(no(DCR1_AUTH));
        }
        if raw[..4] != *b"DCR1"
            || raw[6..8] != VERSION.to_le_bytes()
            || raw[4] != PHASE_RULED
            || raw[PT2P_MODE_AT] != 1
        {
            return Err(no(DCR1_PHASE));
        }
        d32(&raw, 40, DCR1_BAD)?
    };
    let (key, _) = crate::closure_v2_response::address(program, record_acc.key);
    if *response_acc.key != key || response_acc.owner != program {
        return Err(no(DCR1_AUTH));
    }
    {
        let raw = response_acc.try_borrow_data()?;
        if raw.len() < crate::closure_v2_response::HEADER
            || raw[..4] != *b"DRU1"
            || raw[4..6] != 1u16.to_le_bytes()
            || !matches!(u16_at(&raw, 6, DCR1_PHASE)?, 1 | 2)
            || raw[8..40] != record_acc.key.to_bytes()
            || raw[40..72] != record_executor
        {
            return Err(no(DCR1_PHASE));
        }
    }
    if executor.key.as_ref() != record_executor {
        return Err(no(DCR1_AUTH));
    }
    super::result::drain(response_acc, executor)?;
    Ok(())
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use crate::unified::classes::tests::{golden, unhex};

    fn d(v: &serde_json::Value) -> [u8; 32] {
        unhex(v.as_str().unwrap()).try_into().unwrap()
    }

    /// The golden SPP1 proofs (including the odd-last duplicate at ordinal 33
    /// of p = 79 and p = 0's base table) fold to the golden position roots;
    /// §12's SPP1 cheats do not.
    #[test]
    fn spp1_vectors_fold_and_cheats_miss() {
        let g = golden();
        let descriptor = d(&g["dpd2"]["digest"]);
        let roots: Vec<[u8; 32]> = g["dcm2_v6"]["position_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(d)
            .collect();
        for (p, key) in [(79u32, "79"), (0, "0")] {
            let v = &g["spp1"][key];
            let raw = unhex(v["spp1"].as_str().unwrap());
            let segment_root = d(&v["segment_root"]);
            let (ordinal, table, path, used) = decode_spp1(&raw).unwrap();
            assert_eq!(used, raw.len());
            assert_eq!(ordinal as u64, v["ordinal"].as_u64().unwrap());
            let derived = d(&g["segment_tables"][key]["root"]);
            let got = spp1_position_root(
                &descriptor,
                p,
                34,
                &segment_root,
                ordinal,
                &table,
                &path,
                &derived,
            );
            assert_eq!(got, Ok(Some(roots[p as usize])), "p = {p}");
            // Wrong derived table root: 789.
            assert_eq!(
                spp1_position_root(
                    &descriptor,
                    p,
                    34,
                    &segment_root,
                    ordinal,
                    &table,
                    &path,
                    &[7; 32]
                ),
                Err(REVEAL_MISMATCH)
            );
            // Another segment root, position or ordinal; a flipped sibling: no match.
            let miss = |sr: &[u8; 32], pp: u32, o: u16, pa: &[[u8; 32]]| {
                spp1_position_root(&descriptor, pp, 34, sr, o, &table, pa, &derived).unwrap()
                    != Some(roots[p as usize])
            };
            assert!(miss(&[9; 32], p, ordinal, &path));
            assert!(miss(&segment_root, p ^ 1, ordinal, &path));
            assert!(miss(&segment_root, p, ordinal ^ 1, &path));
            let mut flipped = path.clone();
            flipped[0][0] ^= 1;
            assert!(miss(&segment_root, p, ordinal, &flipped));
            assert!(miss(&segment_root, p, ordinal, &path[1..]));
            assert!(decode_spp1(&raw[..raw.len() - 1])
                .map(|x| x.3 != raw.len() - 1)
                .unwrap_or(true));
        }
        // The odd-last duplicate sibling is carried; replacing it misses.
        let v = &g["spp1"]["79"];
        let (ordinal, table, mut path, _) =
            decode_spp1(&unhex(v["spp1"].as_str().unwrap())).unwrap();
        path[1] = [5; 32];
        assert_eq!(
            spp1_position_root(
                &descriptor,
                79,
                34,
                &d(&v["segment_root"]),
                ordinal,
                &table,
                &path,
                &d(&g["segment_tables"]["79"]["root"])
            ),
            Ok(None)
        );
    }

    /// DEV2 encodes exactly as the golden's admitted and convicted records.
    #[test]
    fn dev2_vectors() {
        let g = golden();
        let rows = unhex(g["drp2"]["rows"].as_str().unwrap());
        let row = registry::find_row(&rows, 44).unwrap().unwrap();
        let root = unhex(g["drp2"]["table_root"].as_str().unwrap());
        let t = g["dcr1_v5"]["representative"][1].as_u64().unwrap() as u32;
        assert_eq!(
            encode_dev2(0, Some(&row), t, 44, &root).to_vec(),
            unhex(g["dcr1_v5"]["admitted_dev2"].as_str().unwrap())
        );
        assert_eq!(
            encode_dev2(super::super::SHAPE_BOUND, Some(&row), t, 44, &root).to_vec(),
            unhex(g["dcr1_v5"]["convicted_dev2"].as_str().unwrap())
        );
    }

    #[test]
    fn revision_eight_rule_records_the_first_conviction_and_zeros_the_deadline() {
        let program = Pubkey::new_unique();
        let descriptor = [0x42; 32];
        let executor = Pubkey::new_unique();
        let first_challenger = Pubkey::new_unique();
        let (doc_key, _) = address::document(&program, &descriptor);
        let mut doc_lamports = 10_000_000;
        let mut doc_data = vec![0; document::OPTION_REGION_AT];
        doc_data[..4].copy_from_slice(b"DCM2");
        doc_data[4..6].copy_from_slice(&7u16.to_le_bytes());
        doc_data[6..8]
            .copy_from_slice(&(document::FLAG_ROOT_ONLY | document::FLAG_SEALED).to_le_bytes());
        doc_data[8..40].copy_from_slice(&descriptor);
        doc_data[40..72].copy_from_slice(executor.as_ref());
        // Keep a CUSTOM policy and a nonzero old window encoded. Revision 8 RULE
        // does not read that window and leaves DCR1[170..178] zero.
        doc_data[TERMS_AT_V8 + 48] = 1;
        doc_data[TERMS_AT_V8 + 80..TERMS_AT_V8 + 88].copy_from_slice(&604_800u64.to_le_bytes());
        let doc_account = AccountInfo::new(
            &doc_key,
            false,
            true,
            &mut doc_lamports,
            &mut doc_data,
            &program,
            false,
            0,
        );

        let mut make_record = |challenger: &Pubkey, nonce: u32| {
            let mut raw = vec![0; SIZE];
            raw[..4].copy_from_slice(b"DCR1");
            raw[6..8].copy_from_slice(&VERSION.to_le_bytes());
            raw[8..40].copy_from_slice(challenger.as_ref());
            raw[40..72].copy_from_slice(executor.as_ref());
            raw[72..104].copy_from_slice(&descriptor);
            raw[140..144].copy_from_slice(&nonce.to_le_bytes());
            raw[170..178].fill(0xA5);
            let key = address::challenge(&program, &descriptor, challenger, nonce).0;
            (key, raw)
        };

        let (first_key, mut first_record) = make_record(&first_challenger, 7);
        rule_v8(
            &program,
            &first_key,
            &mut first_record,
            &doc_account,
            2,
            events::CAUSE_CONVICT,
            123,
        )
        .unwrap();
        assert_eq!(
            &first_record[170..178],
            &[0; 8],
            "the revision-8 settle deadline is unused"
        );
        assert_eq!(first_record[4], PHASE_RULED);
        assert_eq!(first_record[5], 2);
        {
            let doc = doc_account.try_borrow_data().unwrap();
            assert_eq!(u32_at(&doc, 132, DCR1_BAD).unwrap(), 1);
            assert_ne!(u16_at(&doc, 6, DCR1_BAD).unwrap() & FLAG_REFUTED, 0);
            assert_eq!(
                &doc[WINNER_AT_V8..WINNER_AT_V8 + 32],
                first_challenger.as_ref()
            );
        }

        let second_challenger = Pubkey::new_unique();
        let (second_key, mut second_record) = make_record(&second_challenger, 8);
        rule_v8(
            &program,
            &second_key,
            &mut second_record,
            &doc_account,
            2,
            events::CAUSE_CONVICT,
            124,
        )
        .unwrap();
        assert_eq!(&second_record[170..178], &[0; 8]);
        {
            let doc = doc_account.try_borrow_data().unwrap();
            assert_eq!(u32_at(&doc, 132, DCR1_BAD).unwrap(), 2);
            assert_eq!(
                &doc[WINNER_AT_V8..WINNER_AT_V8 + 32],
                first_challenger.as_ref(),
                "the first RULE-side challenger conviction is write-once"
            );
        }

        let (executor_key, mut executor_record) = make_record(&first_challenger, 9);
        rule_v8(
            &program,
            &executor_key,
            &mut executor_record,
            &doc_account,
            1,
            events::CAUSE_TIMEOUT,
            0,
        )
        .unwrap();
        assert_eq!(
            &executor_record[170..178],
            &[0; 8],
            "executor wins also keep the field zero"
        );
        assert_eq!(
            &doc_account.try_borrow_data().unwrap()[WINNER_AT_V8..WINNER_AT_V8 + 32],
            first_challenger.as_ref()
        );
    }
}
