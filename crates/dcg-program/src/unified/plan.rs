//! Account binding of the sealed PT2P plan a unified document is over.
//!
//! A PT2S (`pt2p_onchain`) is program-owned, sealed (`STATE_SEALED`) and
//! immutable after seal; it pins the keys and lengths of its three base
//! accounts and the PT1S whose phase-3 payload index the class shapes read.
//! Every refusal here is 785 (`PLAN_BINDING`).

use super::{no, u16_at, u32_at, PLAN_BINDING};
use crate::pt1_onchain;
use crate::pt2p::{self, Pt2p};
use crate::pt2p_onchain as S;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// A sealed PT2S with its base routes and geometry (and, when given, base
/// payloads) bound by key and length. Returns the PWR1 byte range.
pub fn bind_pt2s(
    program: &Pubkey,
    pt2s: &AccountInfo,
    routes: &AccountInfo,
    geometry: &AccountInfo,
    payloads: Option<&AccountInfo>,
) -> Result<core::ops::Range<usize>, ProgramError> {
    let s = pt2s.try_borrow_data()?;
    if pt2s.owner != program
        || routes.owner != program
        || geometry.owner != program
        || s.len() < S::OFF_PWR1
        || s[..4] != *S::MAGIC
        || s[S::OFF_STATE] != S::STATE_SEALED
        || s.len() != S::OFF_PWR1 + u16_at(&s, S::OFF_PWR1_LEN, PLAN_BINDING)? as usize
    {
        return Err(no(PLAN_BINDING));
    }
    let bound = |kind: usize, a: &AccountInfo| -> Result<bool, ProgramError> {
        Ok(
            a.key.as_ref() == &s[S::OFF_KEYS + 32 * kind..S::OFF_KEYS + 32 * (kind + 1)]
                && a.data_len() == u32_at(&s, S::OFF_LENGTHS + 4 * kind, PLAN_BINDING)? as usize,
        )
    };
    if !bound(0, routes)? || !bound(1, geometry)? {
        return Err(no(PLAN_BINDING));
    }
    if let Some(p) = payloads {
        if p.owner != program || !bound(2, p)? {
            return Err(no(PLAN_BINDING));
        }
    }
    Ok(S::OFF_PWR1..s.len())
}

/// The sealed PT1S or PT1X a PT2S names, in phase 3; returns the payload-index
/// offset. PT1X has one PT2S binding written by tag 143 and can therefore be
/// neither rebound by a stranger nor confused with another plan over the same
/// base. The legacy PT1S-v3 check is intentionally unchanged.
pub fn bind_pt1s(
    program: &Pubkey,
    pt2s: &AccountInfo,
    pt1s: &AccountInfo,
) -> Result<usize, ProgramError> {
    let s = pt2s.try_borrow_data()?;
    if pt2s.owner != program
        || s.len() < S::OFF_PWR1
        || s[..4] != *S::MAGIC
        || s[S::OFF_STATE] != S::STATE_SEALED
    {
        return Err(no(PLAN_BINDING));
    }
    let p = pt1s.try_borrow_data()?;
    if pt1s.owner != program
        || pt1s.key.as_ref() != &s[S::OFF_PT1S..S::OFF_PT1S + 32]
        || !pt1_onchain::is_sealed_template(&p)
        || p.len() < pt1_onchain::OFF_PAYLOAD_INDEX + 4
    {
        return Err(no(PLAN_BINDING));
    }
    if pt1_onchain::is_pt1x(&p) {
        if p[4] != 6
            || p[pt1_onchain::PT1X_BOUND_PT2S_AT..pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != pt2s.key.to_bytes()
            || p[5..37] != s[S::OFF_AUTHORITY..S::OFF_AUTHORITY + 32]
            || p[37..133] != s[S::OFF_KEYS..S::OFF_KEYS + 96]
            || p[133..145] != s[S::OFF_LENGTHS..S::OFF_LENGTHS + 12]
        {
            return Err(no(PLAN_BINDING));
        }
    }
    Ok(pt1_onchain::OFF_PAYLOAD_INDEX)
}

/// The PT2P view of a bound PT2S. Clause-12 v4 must decode against the PWR1
/// digest and name the base geometry's position and segment counts.
pub fn view<'a>(
    pt2s: &'a [u8],
    routes: &'a [u8],
    geometry: &'a [u8],
    payloads: &'a [u8],
    index: Option<&'a [u8]>,
) -> Result<Pt2p<'a>, ProgramError> {
    let g = pt2p::Program::decode(&pt2s[S::OFF_PWR1..]).map_err(|_| no(PLAN_BINDING))?;
    let (positions, segments, _) =
        pt2p::decode_clause12_v4(&pt2s[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43], Some(&g))
            .map_err(|_| no(PLAN_BINDING))?;
    let x = Pt2p::new(routes, geometry, payloads, index, g).map_err(|_| no(PLAN_BINDING))?;
    if x.position_count != positions || x.segment_count != segments {
        return Err(no(PLAN_BINDING));
    }
    Ok(x)
}

/// The pinned PT2P compiler version and the `PWR1` fields that identify it
/// (`pt2p_compiler.py` PROFILES): v1 rung-d `(35, 2, 4)`. Version 1 is the
/// only landing version of this image; compiler v2 is withdrawn (user rule,
/// 2026-09-25) and any other profile refuses.
pub fn compiler_version(g: &pt2p::Program<'_>) -> Option<u8> {
    profile_version(g.window_start, g.score_heads, g.softmax_heads)
}

/// `(window_start, score_heads, softmax_heads)` to the landing version.
fn profile_version(window_start: u32, score_heads: u64, softmax_heads: u64) -> Option<u8> {
    match (window_start, score_heads, softmax_heads) {
        (35, 2, 4) => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod compiler_version_tests {
    /// Compiler v1 lands; the withdrawn v2 profile `(0, 1, 4)` refuses.
    #[test]
    fn only_compiler_v1_lands() {
        assert_eq!(super::profile_version(35, 2, 4), Some(1));
        assert_eq!(super::profile_version(0, 1, 4), None);
        assert_eq!(super::profile_version(35, 2, 3), None);
    }
}
