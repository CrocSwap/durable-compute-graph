//! PT2P (§17, PROPOSED) on-chain seal, instantiation and manifest binding.
//!
//! The base triple lives in the three PT1S byte accounts and is uploaded and
//! sealed by the PT1S flow, reached through the `TAG_BASE_*` aliases below
//! (the PT1S tags 95/96/97 are shadowed by the DCM2 v2 bootstrap in this
//! image). A program-owned `PT2S` state then binds that sealed PT1S state,
//! stores the `PWR1` bytes, folds a flat SHA-256 of the three base accounts
//! in bounded calls, and seals clause-12 v4 plus a document descriptor.
//!
//! Every handler validates owners, keys, lengths and the state machine before
//! any mutation; a refusal leaves every byte unchanged.
use crate::closure_v2::{document_address, DCM2_V2_HEADER};
use crate::position_template as pt;
use crate::pt1_onchain;
use crate::pt2p::{self, Pt2p};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Aliases of `pt1_onchain::{init, upload, seal}` (same data and accounts).
pub const TAG_BASE_INIT: u8 = 140;
pub const TAG_BASE_UPLOAD: u8 = 141;
pub const TAG_BASE_SEAL: u8 = 142;
pub const TAG_INIT: u8 = 143;
pub const TAG_HASH: u8 = 144;
pub const TAG_SEAL: u8 = 145;
pub const TAG_INSTANTIATE: u8 = 146;
pub const TAG_BIND_MANIFEST: u8 = 147;
pub const TAG_RESERVE_PT1O: u8 = 199;
pub const TAG_CLOSE_PT1O_RESERVATION: u8 = 200;
/// Bounded continuation for a revision-8 PXR1 PT2S seal.
pub const TAG_SEAL_PXR_CHUNK: u8 = 193;

pub const MAGIC: &[u8; 4] = b"PT2S";

#[inline(always)]
fn profile_seal(label: &'static str) {
    #[cfg(feature = "pt2p-seal-profile")]
    {
        solana_program::msg!(label);
        solana_program::log::sol_log_compute_units();
    }
    #[cfg(not(feature = "pt2p-seal-profile"))]
    let _ = label;
}
pub const STATE_HASHING: u8 = 1;
pub const STATE_SEALED: u8 = 2;
pub const STATE_SEALING_PXR: u8 = 3;
pub const OFF_STATE: usize = 4;
pub const OFF_AUTHORITY: usize = 8;
pub const OFF_PT1S: usize = 40;
pub const OFF_KEYS: usize = 72;
pub const OFF_LENGTHS: usize = 168;
pub const OFF_CURSOR_KIND: usize = 180;
pub const OFF_CURSOR_BYTES: usize = 184;
pub const OFF_MIDSTATE: usize = 188;
pub const OFF_DIGESTS: usize = 220;
pub const OFF_CLAUSE12: usize = 316;
pub const OFF_DEFINITION: usize = 359;
pub const OFF_DESCRIPTOR: usize = 391;
pub const OFF_PWR1_LEN: usize = 424;
/// The six-byte `output_locator` a revision-8 template's seal writes:
/// `output_base_entry:u32 | output_write:u8 | output_width:u8` (spec §1.7).
/// Dead state before revision 8, so the PT2S stays 760 bytes.
pub const OFF_LOCATOR: usize = 426;
pub const OFF_PWR1: usize = 432;
/// Per-call SHA-256 block budget (64 bytes each), from measured SBF ProgramTest
/// CU (v1.51): ~6,857 CU per block plus ~50k fixed; 174 blocks measured at
/// 1,194,958 CU, under the 1.2M per-transaction target.
pub const MAX_HASH_BLOCKS: u16 = 174;
pub const MAX_INSTANTIATE: u32 = 64;
/// Recommended per-transaction PT1O batch for the retained compiler-v1 K=80 fixture.
/// The on-chain format maximum remains 64; see the revision-8 spec for the measured batch evidence.
pub const RECOMMENDED_INSTANTIATE_BATCH: u32 = 2;
pub const MAX_PXR_SEAL_ROWS: u16 = 64;
const OUTPUT_MAGIC: &[u8; 4] = b"PT1O";
const PT1S_OFF_INDEX: usize = pt1_onchain::OFF_PAYLOAD_INDEX;
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const FORM: u32 = 580;
const AUTHORITY: u32 = 582;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 SHA-256 block compression. The `sol_sha256` syscall is not
/// incremental, so a multi-megabyte flat digest folds one block at a time with
/// the midstate kept in account state. Rounds are unrolled over a 16-word
/// rolling schedule so no working variable is moved between rounds.
pub fn compress(state: &mut [u32; 8], block: &[u8]) {
    let block: &[u8; 64] = block.try_into().expect("64-byte block");
    let mut w = [0u32; 16];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $k:expr, $w:expr) => {
            let t1 = $h
                .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
                .wrapping_add(($e & $f) ^ (!$e & $g))
                .wrapping_add($k)
                .wrapping_add($w);
            let t2 = ($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
                .wrapping_add(($a & $b) ^ ($a & $c) ^ ($b & $c));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        };
    }
    macro_rules! schedule {
        ($i:expr) => {{
            let x = w[($i + 1) & 15];
            let y = w[($i + 14) & 15];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            w[$i & 15] = w[$i & 15]
                .wrapping_add(s0)
                .wrapping_add(w[($i + 9) & 15])
                .wrapping_add(s1);
            w[$i & 15]
        }};
    }
    macro_rules! eight {
        ($base:expr, $sched:expr) => {
            round!(
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                h,
                K[$base],
                if $sched {
                    schedule!($base)
                } else {
                    w[$base & 15]
                }
            );
            round!(
                h,
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                K[$base + 1],
                if $sched {
                    schedule!($base + 1)
                } else {
                    w[($base + 1) & 15]
                }
            );
            round!(
                g,
                h,
                a,
                b,
                c,
                d,
                e,
                f,
                K[$base + 2],
                if $sched {
                    schedule!($base + 2)
                } else {
                    w[($base + 2) & 15]
                }
            );
            round!(
                f,
                g,
                h,
                a,
                b,
                c,
                d,
                e,
                K[$base + 3],
                if $sched {
                    schedule!($base + 3)
                } else {
                    w[($base + 3) & 15]
                }
            );
            round!(
                e,
                f,
                g,
                h,
                a,
                b,
                c,
                d,
                K[$base + 4],
                if $sched {
                    schedule!($base + 4)
                } else {
                    w[($base + 4) & 15]
                }
            );
            round!(
                d,
                e,
                f,
                g,
                h,
                a,
                b,
                c,
                K[$base + 5],
                if $sched {
                    schedule!($base + 5)
                } else {
                    w[($base + 5) & 15]
                }
            );
            round!(
                c,
                d,
                e,
                f,
                g,
                h,
                a,
                b,
                K[$base + 6],
                if $sched {
                    schedule!($base + 6)
                } else {
                    w[($base + 6) & 15]
                }
            );
            round!(
                b,
                c,
                d,
                e,
                f,
                g,
                h,
                a,
                K[$base + 7],
                if $sched {
                    schedule!($base + 7)
                } else {
                    w[($base + 7) & 15]
                }
            );
        };
    }
    eight!(0, false);
    eight!(8, false);
    eight!(16, true);
    eight!(24, true);
    eight!(32, true);
    eight!(40, true);
    eight!(48, true);
    eight!(56, true);
    for (x, y) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *x = x.wrapping_add(y);
    }
}

fn err(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}
fn u16_at(b: &[u8], at: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .unwrap(),
    ))
}
fn put_u32(b: &mut [u8], at: usize, x: u32) {
    b[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn owned<'s, 'a>(
    program: &Pubkey,
    accounts: &'s [AccountInfo<'a>],
    at: usize,
) -> Result<&'s AccountInfo<'a>, ProgramError> {
    let a = accounts.get(at).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if a.owner != program {
        return Err(ProgramError::IllegalOwner);
    }
    Ok(a)
}

/// PT2S state bytes: magic, lifecycle, sizes and PWR1 length checked.
fn check_state(s: &[u8]) -> Result<usize, ProgramError> {
    if s.len() < OFF_PWR1 || &s[..4] != MAGIC {
        return Err(ProgramError::UninitializedAccount);
    }
    let len = u16_at(s, OFF_PWR1_LEN)? as usize;
    if s.len() != OFF_PWR1 + len {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(len)
}

/// The three base byte accounts at `accounts[at..at+3]` match the state.
fn bind_bytes(
    program: &Pubkey,
    s: &[u8],
    accounts: &[AccountInfo],
    at: usize,
) -> Result<(), ProgramError> {
    for kind in 0..3 {
        let a = owned(program, accounts, at + kind)?;
        if a.key.as_ref() != &s[OFF_KEYS + 32 * kind..OFF_KEYS + 32 * (kind + 1)]
            || u32_at(s, OFF_LENGTHS + 4 * kind)? as usize != a.data_len()
        {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    Ok(())
}

/// Seal-time PXR1 validation. The clause-5 write rows provide the region's
/// byte bound; the clause-12 region row proves that this bound is invariant
/// across positions. The final-position reference also confirms the producer
/// still precedes the gather and reducer after PT2P expansion.
fn validate_pxr1_routes<'a>(
    routes: &'a [u8],
    geometry: &[u8],
    x: &Pt2p<'_>,
) -> Result<Option<pt::Pxr1<'a>>, ProgramError> {
    profile_seal("PT2S-profile:pxr1-start");
    if !cfg!(feature = "revision-8") {
        return Ok(None);
    }
    let (_, _, pxr) = pt::route_header_v4(routes).map_err(err)?;
    // The PT1S bound by tag 143 already sealed the clause-5 Merkle root, and
    // tag 144 independently binds the complete routes bytes to PWR1. Rebuilding
    // that O(entries + routes) root here made tag 145 consume the transaction
    // budget on the 28k-entry retained plan before any PXR1 semantics ran.
    // `Pt2p::new` decodes the same committed entry count from that sealed route
    // header; use it to walk the optional extension without repeating the root.
    let entry_count = x.base_entries;
    profile_seal("PT2S-profile:pxr-header");
    let Some(pxr) = pxr else {
        for entry_index in 0..entry_count {
            let entry = pt::entry_at(routes, entry_index).map_err(err)?;
            if matches!(
                entry.kernel_index,
                crate::kernels::decision::FORM_ID | crate::kernels::decision::GATHER_FORM_ID
            ) {
                return Err(err(pt::PT2_ROUTE_SET));
            }
        }
        profile_seal("PT2S-profile:pxr-absent-scan-done");
        return Ok(None);
    };
    let base = pt2p::ptg4_base(geometry).map_err(err)?;
    let clause = pt::decode_clause12_v2(base).map_err(err)?;
    if pxr.token_count != crate::kernels::decision::LOGITS_ROW_LENGTH as u32
        || clause
            .region_position(pxr.region_id)
            .map_err(err)?
            .is_some_and(|region| region.ring != 0 || region.stride != 0)
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:pxr-header-geometry-done");

    let position = x
        .position_count
        .checked_sub(1)
        .ok_or(err(pt::PT2_ROUTE_SET))?;
    let count = x.entry_count(position).map_err(err)?;
    if count < 2 {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    let gather = x.entry(position, count - 2).map_err(err)?;
    let reducer = x.entry(position, count - 1).map_err(err)?;
    if gather.kernel_index != crate::kernels::decision::GATHER_FORM_ID
        || reducer.kernel_index != crate::kernels::decision::FORM_ID
        || (gather.read_count, gather.write_count) != (128, 1)
        || (reducer.read_count, reducer.write_count) != (2, 256)
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:gather-and-form-counts-done");
    let mut gather_payload = [0u8; 16];
    let mut reducer_payload = [0u8; 16];
    x.payload(&gather, false, &mut gather_payload)
        .map_err(err)?;
    x.payload(&reducer, false, &mut reducer_payload)
        .map_err(err)?;
    if gather_payload != [1, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:gather-payloads-done");
    profile_seal("PT2S-profile:gather-and-form-layout-done");
    let shape =
        crate::kernels::decision::decode_form_geometry(&reducer_payload).map_err(|e| err(e.0))?;
    if shape.option_region_id != u16::MAX
        || shape.logits_region_id != pxr.region_id
        || shape.logits_base_offset != pxr.row(0).map_err(err)?.region_offset
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:form-geometry-done");
    for ordinal in 0..128u16 {
        let route = x.route(&gather, ordinal).map_err(err)?;
        let (raw, _) = x.raw_route(&gather, ordinal).map_err(err)?;
        if route.direction != 0
            || route.region_id != pxr.region_id
            || route.effective_offset != ordinal as u64 * 8
            || route.byte_length != 8
            || route.read_class != 0
            || route.producer_entry != pt::NO_PRODUCER
            || raw.producer_delta != 0
            || raw.flags != 0
            || raw.region_id != pxr.region_id
            || raw.direction != 0
            || raw.read_class != 0
            || raw.region_offset != ordinal as u64 * 8
            || raw.byte_length != 8
            || raw.producer_entry != pt::NO_PRODUCER
        {
            return Err(err(pt::PT2_ROUTE_SET));
        }
    }
    let gather_write = x.route(&gather, gather.read_count).map_err(err)?;
    if gather_write.direction != 1
        || gather_write.effective_offset != 0
        || gather_write.byte_length != 128 * 8
        || gather_write.producer_entry != gather.index
        || gather_write.producer_position != position
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:gather-routes-done");
    let option_route = (0..reducer.read_count)
        .map(|ordinal| x.route(&reducer, ordinal).map_err(err))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|route| route.region_id == u16::MAX)
        .ok_or(err(pt::PT2_ROUTE_SET))?;
    let option_ordinal = (0..reducer.read_count)
        .find(|ordinal| {
            x.route(&reducer, *ordinal)
                .is_ok_and(|route| route.region_id == u16::MAX)
        })
        .ok_or(err(pt::PT2_ROUTE_SET))?;
    let (raw_option, _) = x.raw_route(&reducer, option_ordinal).map_err(err)?;
    if option_route.direction != 0
        || option_route.read_class != 2
        || option_route.binding_kind != 0
        || option_route.source_supplied
        || option_route.effective_offset != 0
        || option_route.byte_length != 128 * 4
        || option_route.producer_entry != pt::NO_PRODUCER
        || raw_option.direction != 0
        || raw_option.read_class != 2
        || raw_option.region_offset != 0
        || raw_option.byte_length != 128 * 4
        || raw_option.producer_entry != pt::NO_PRODUCER
        || raw_option.producer_delta != 0
        || raw_option.flags != 0
    {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:option-route-done");
    let mut saw_gather = false;
    for ordinal in 0..reducer.read_count {
        let route = x.route(&reducer, ordinal).map_err(err)?;
        if route.region_id == u16::MAX {
            continue;
        }
        saw_gather = route.direction == 0
            && route.read_class == 0
            && route.effective_offset == 0
            && route.byte_length == 128 * 8
            && route.region_id == gather_write.region_id
            && route.producer_entry == gather.index;
    }
    if !saw_gather {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    profile_seal("PT2S-profile:gather-reducer-routes-done");
    let mut output_region = None;
    for lane in 0..256u16 {
        let write = x.route(&reducer, reducer.read_count + lane).map_err(err)?;
        if write.direction != 1
            || write.byte_length != 4
            || write.effective_offset != lane as u64 * 4
            || write.producer_entry != reducer.index
            || write.producer_position != position
            || output_region.is_some_and(|region| region != write.region_id)
        {
            return Err(err(pt::PT2_ROUTE_SET));
        }
        output_region = Some(write.region_id);
    }
    profile_seal("PT2S-profile:output-routes-done");
    Ok(Some(pxr))
}

/// Validate one bounded PXR1 slice against the already sealed clause-5 bytes.
/// PT1X has already bound the route root and exact per-row producer writes.
/// PT2S independently checks token coverage, byte contiguity, and unique
/// producer/write ordering before permitting the plan seal to finish.
fn validate_pxr1_chunk(
    routes: &[u8],
    pxr: pt::Pxr1<'_>,
    first: u32,
    end: u32,
    x: &Pt2p<'_>,
    position: u32,
    first_gather: u32,
) -> Result<(), ProgramError> {
    if first >= end || end > pxr.row_count {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    for index in first..end {
        let row = pxr.row(index).map_err(err)?;
        let byte_end = row
            .region_offset
            .checked_add(row.byte_length as u64)
            .ok_or(err(pt::OVERFLOW))?;
        if index == 0 {
            if row.first_token != 0 {
                return Err(err(pt::MALFORMED));
            }
        } else {
            let previous = pxr.row(index - 1).map_err(err)?;
            if previous
                .first_token
                .checked_add(previous.token_count)
                .ok_or(err(pt::OVERFLOW))?
                != row.first_token
            {
                return Err(err(pt::MALFORMED));
            }
            if previous
                .region_offset
                .checked_add(previous.byte_length as u64)
                .ok_or(err(pt::OVERFLOW))?
                != row.region_offset
            {
                return Err(err(pt::PT2_ROUTE_SET));
            }
            if (previous.producer_entry, previous.producer_write_ordinal)
                >= (row.producer_entry, row.producer_write_ordinal)
            {
                return Err(err(pt::PT2_PRODUCER));
            }
        }
        let producer =
            pt::entry_at(routes, row.producer_entry).map_err(|_| err(pt::PT2_PRODUCER))?;
        if row.producer_write_ordinal as u32 >= producer.write_count as u32 {
            return Err(err(pt::PT2_PRODUCER));
        }
        let ordinal = producer
            .read_count
            .checked_add(row.producer_write_ordinal)
            .ok_or(err(pt::OVERFLOW))?;
        let write = pt::route_at(routes, producer, ordinal).map_err(err)?;
        if write.direction != 1
            || write.region_id != pxr.region_id
            || write.region_offset != row.region_offset
            || write.byte_length != row.byte_length
            || write.producer_entry != row.producer_entry
            || write.producer_delta != 0
            || write.flags != 0
        {
            return Err(err(pt::PT2_PRODUCER));
        }
        if x.is_replaced(row.producer_entry) {
            return Err(err(pt::PT2_PRODUCER));
        }
        let producer_index = x
            .old_to_new(row.producer_entry, position)
            .map_err(err)?
            .ok_or(err(pt::PT2_PRODUCER))?;
        if producer_index >= first_gather {
            return Err(err(pt::PT2_PRODUCER));
        }
        let producer = x.entry(position, producer_index).map_err(err)?;
        if row.producer_write_ordinal as u32 >= producer.write_count as u32 {
            return Err(err(pt::PT2_PRODUCER));
        }
        let expanded = x
            .route(&producer, producer.read_count + row.producer_write_ordinal)
            .map_err(err)?;
        if expanded.direction != 1
            || expanded.region_id != pxr.region_id
            || expanded.effective_offset != row.region_offset
            || expanded.byte_length != row.byte_length
            || expanded.producer_position != position
        {
            return Err(err(pt::PT2_PRODUCER));
        }
        if end == pxr.row_count
            && index + 1 == end
            && row
                .first_token
                .checked_add(row.token_count)
                .ok_or(err(pt::OVERFLOW))?
                != pxr.token_count
        {
            return Err(err(pt::MALFORMED));
        }
        let _ = byte_end;
    }
    Ok(())
}

/// tag 143. Accounts: pt2p_state(w,s), pt1s_state (sealed, state 3), authority(s).
/// Data: tag | PWR1 bytes. The state must be a fresh program-owned account of
/// exactly `432 + len(PWR1)` zero bytes.
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3
        || data.len() < 2
        || data[0] != TAG_INIT
        || data.len() - 1 > u16::MAX as usize
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = owned(program, accounts, 0)?;
    let pt1s = owned(program, accounts, 1)?;
    let authority = &accounts[2];
    if !state.is_writable || !state.is_signer || !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if state.key == pt1s.key {
        return Err(ProgramError::InvalidAccountData);
    }
    let pwr1 = &data[1..];
    let _g = pt2p::Program::decode(pwr1).map_err(err)?;
    let is_pt1x = {
        let p = pt1s.try_borrow_data()?;
        if cfg!(feature = "revision-8") && !pt1_onchain::is_pt1x(&p) {
            return Err(ProgramError::InvalidAccountData);
        }
        if !pt1_onchain::is_sealed_template(&p) {
            return Err(ProgramError::InvalidAccountData);
        }
        if pt1_onchain::is_pt1x(&p) {
            if p[4] != 3
                || pt1s.is_writable == false
                || &p[5..37] != authority.key.as_ref()
                || p[pt1_onchain::PT1X_BOUND_PT2S_AT..pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                    != [0; 32]
            {
                return Err(ProgramError::InvalidAccountData);
            }
            true
        } else {
            if cfg!(feature = "revision-8") {
                return Err(ProgramError::InvalidAccountData);
            }
            // Revision-7 PT1S and tag-106 bytes are left unchanged.
            if pt1s.is_writable {
                return Err(ProgramError::InvalidAccountData);
            }
            false
        }
    };
    let mut s = state.try_borrow_mut_data()?;
    if s.len() != OFF_PWR1 + pwr1.len() || s.iter().any(|&b| b != 0) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let bindings = {
        let p = pt1s.try_borrow_data()?;
        let keys: [u8; 96] = p[37..133].try_into().unwrap();
        let lengths: [u8; 12] = p[133..145].try_into().unwrap();
        (keys, lengths)
    };
    s[..4].copy_from_slice(MAGIC);
    s[OFF_STATE] = STATE_HASHING;
    s[OFF_AUTHORITY..OFF_AUTHORITY + 32].copy_from_slice(authority.key.as_ref());
    s[OFF_PT1S..OFF_PT1S + 32].copy_from_slice(pt1s.key.as_ref());
    s[OFF_KEYS..OFF_KEYS + 96].copy_from_slice(&bindings.0);
    s[OFF_LENGTHS..OFF_LENGTHS + 12].copy_from_slice(&bindings.1);
    s[OFF_CURSOR_KIND] = 0;
    for (i, word) in IV.iter().enumerate() {
        s[OFF_MIDSTATE + 4 * i..OFF_MIDSTATE + 4 * (i + 1)].copy_from_slice(&word.to_le_bytes());
    }
    s[OFF_PWR1_LEN..OFF_PWR1_LEN + 2].copy_from_slice(&(pwr1.len() as u16).to_le_bytes());
    s[OFF_PWR1..].copy_from_slice(pwr1);
    drop(s);
    if is_pt1x {
        let mut p = pt1s.try_borrow_mut_data()?;
        pt1_onchain::bind_pt2s(&mut p, state.key, authority.key, &bindings.0, &bindings.1)?;
    }
    Ok(())
}

/// tag 144. Accounts: pt2p_state(w), routes, geometry, payloads, authority(s).
/// Data: tag | blocks:u16 (1..=MAX_HASH_BLOCKS). Compresses up to `blocks`
/// 64-byte blocks of the current base account (routes, geometry, payloads in
/// that order); when the account's tail is reached it is padded and the flat
/// SHA-256 recorded, and the cursor moves to the next account.
pub fn hash(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 3 || accounts.len() != 5 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let blocks = u16_at(data, 1)?;
    if blocks == 0 || blocks > MAX_HASH_BLOCKS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = owned(program, accounts, 0)?;
    if !state.is_writable || !accounts[4].is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut s = state.try_borrow_mut_data()?;
    check_state(&s)?;
    bind_bytes(program, &s, accounts, 1)?;
    if s[OFF_STATE] != STATE_HASHING
        || &s[OFF_AUTHORITY..OFF_AUTHORITY + 32] != accounts[4].key.as_ref()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let kind = s[OFF_CURSOR_KIND] as usize;
    if kind >= 3 {
        return Err(err(FORM));
    }
    let bytes = accounts[1 + kind].try_borrow_data()?;
    let len = bytes.len();
    let mut at = u32_at(&s, OFF_CURSOR_BYTES)? as usize;
    let mut mid = [0u32; 8];
    for (i, word) in mid.iter_mut().enumerate() {
        *word = u32_at(&s, OFF_MIDSTATE + 4 * i)?;
    }
    let mut budget = blocks as usize;
    while budget > 0 && at + 64 <= len {
        compress(&mut mid, &bytes[at..at + 64]);
        at += 64;
        budget -= 1;
    }
    let tail = len - at;
    let pad_blocks = if tail < 56 { 1 } else { 2 };
    if at + 64 > len && budget >= pad_blocks {
        let mut last = [0u8; 128];
        last[..tail].copy_from_slice(&bytes[at..]);
        last[tail] = 0x80;
        let bits = (len as u64) * 8;
        let end = 64 * pad_blocks;
        last[end - 8..end].copy_from_slice(&bits.to_be_bytes());
        for b in 0..pad_blocks {
            compress(&mut mid, &last[64 * b..64 * (b + 1)]);
        }
        let off = OFF_DIGESTS + 32 * kind;
        for (i, word) in mid.iter().enumerate() {
            s[off + 4 * i..off + 4 * (i + 1)].copy_from_slice(&word.to_be_bytes());
        }
        mid = IV;
        at = 0;
        s[OFF_CURSOR_KIND] = kind as u8 + 1;
    }
    put_u32(&mut s, OFF_CURSOR_BYTES, at as u32);
    for (i, word) in mid.iter().enumerate() {
        s[OFF_MIDSTATE + 4 * i..OFF_MIDSTATE + 4 * (i + 1)].copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

/// The PT2P view over the state's program and the three base accounts.
fn view<'a>(
    pwr1: &'a [u8],
    routes: &'a [u8],
    geometry: &'a [u8],
    payloads: &'a [u8],
    index: Option<&'a [u8]>,
) -> Result<Pt2p<'a>, ProgramError> {
    let g = pt2p::Program::decode(pwr1).map_err(err)?;
    Pt2p::new(routes, geometry, payloads, index, g).map_err(err)
}

/// tag 145. Accounts: pt2p_state(w), routes, geometry, payloads, authority(s),
/// and, for PXR1 templates, the sealed PT1X state that holds its payload index.
/// Data: tag | definition_sha256:[32]. Write-once: requires all three flat
/// digests, compares them with PWR1 (603), runs the §17.2 program checks
/// (602), and stores clause-12 v4, the definition digest and the descriptor
/// `SHA256(descriptor domain | clause12_v4 | definition_sha256)`.
/// tag 145. Data: `definition[32]`, or for a revision-8 template
/// `definition[32] | output_base_entry:u32 | output_write:u8 |
/// output_width:u8` (39 bytes), which writes the `output_locator[6]` at byte
/// 426 that DRB1 v2 is checked against (spec §1.7). Those six bytes were dead
/// state, so the locator costs no account growth and a 33-byte seal produces
/// revision 7's bytes exactly, with 426..432 left zero.
///
/// **The only bound on the 39-byte locator is the width**, `1..=32`: it is a
/// cell width, so it is the same `MAX_WIDTH` the result and binding decoders
/// use, and the mirror's `OutputLocator` agrees. **`output_write` is not
/// bounded, and write 0 is legal** — a `u8` write ordinal whose only meaning
/// is "the `n`-th write at the entry", and the retained rung-D template's
/// honest locator is exactly `(28_037, write 0, width 16)`
/// (`tests/unified_v8_document.rs`). A `write == 0` refusal here had no rule
/// behind it and made the only real template in this tree unsealable, so the
/// honest path from a 39-byte seal through init to attest stopped at the seal.
/// `output_base_entry` is likewise unbounded here: whether the entry is live
/// and the write exists is `Binding2::check`'s question at init, against the
/// plan, and it is 794 there.
pub fn seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    profile_seal("PT2S-profile:seal-start");
    if (data.len() != 33 && data.len() != 39) || !(5..=6).contains(&accounts.len()) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = owned(program, accounts, 0)?;
    if !state.is_writable || !accounts[4].is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let definition: [u8; 32] = data[1..33].try_into().unwrap();
    let locator = (data.len() == 39).then(|| (u32_at(data, 33).unwrap(), data[37], data[38]));
    if let Some((_, _, width)) = locator {
        if !(1..=32).contains(&width) {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    let (c12, descriptor, pxr_rows) = {
        let s = state.try_borrow_data()?;
        check_state(&s)?;
        bind_bytes(program, &s, accounts, 1)?;
        if s[OFF_STATE] != STATE_HASHING
            || &s[OFF_AUTHORITY..OFF_AUTHORITY + 32] != accounts[4].key.as_ref()
        {
            return Err(ProgramError::InvalidAccountData);
        }
        if s[OFF_CURSOR_KIND] != 3 {
            return Err(err(pt::PT2_ROUTE_SET));
        }
        profile_seal("PT2S-profile:account-bind-done");
        let pwr1 = &s[OFF_PWR1..];
        let g = pt2p::Program::decode(pwr1).map_err(err)?;
        profile_seal("PT2S-profile:pwr1-decode-done");
        for kind in 0..3 {
            if &s[OFF_DIGESTS + 32 * kind..OFF_DIGESTS + 32 * (kind + 1)] != g.base_digest(kind) {
                return Err(err(pt::PT2_ROUTE_SET));
            }
        }
        profile_seal("PT2S-profile:base-digests-done");
        let routes = accounts[1].try_borrow_data()?;
        let geometry = accounts[2].try_borrow_data()?;
        let payloads = accounts[3].try_borrow_data()?;
        let has_pxr1 = pt::route_header_v4_shallow(&routes)
            .map_err(err)?
            .2
            .is_some();
        let pt1x_data = if accounts.len() == 6 {
            let pt1x = owned(program, accounts, 5)?;
            if pt1x.is_writable || pt1x.key.as_ref() != &s[OFF_PT1S..OFF_PT1S + 32] {
                return Err(ProgramError::InvalidAccountData);
            }
            let data = pt1x.try_borrow_data()?;
            if !pt1_onchain::is_pt1x(&data)
                || !pt1_onchain::is_sealed_template(&data)
                || data[4] != 6
                || data[pt1_onchain::PT1X_BOUND_PT2S_AT..pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                    != state.key.to_bytes()
                || &data[5..37] != &s[OFF_AUTHORITY..OFF_AUTHORITY + 32]
                || &data[37..133] != &s[OFF_KEYS..OFF_KEYS + 96]
                || &data[133..145] != &s[OFF_LENGTHS..OFF_LENGTHS + 12]
            {
                return Err(ProgramError::InvalidAccountData);
            }
            Some(data)
        } else {
            if has_pxr1 || accounts.len() != 5 {
                return Err(ProgramError::InvalidInstructionData);
            }
            None
        };
        let payload_index = pt1x_data.as_ref().map(|data| &data[PT1S_OFF_INDEX..]);
        let x = view(pwr1, &routes, &geometry, &payloads, payload_index)?;
        profile_seal("PT2S-profile:view-done");
        x.check_program().map_err(err)?;
        profile_seal("PT2S-profile:program-check-done");
        let pxr = validate_pxr1_routes(&routes, &geometry, &x)?;
        profile_seal("PT2S-profile:all-validation-done");
        let c12 = pt2p::encode_clause12_v4(x.position_count, x.segment_count, &g.digest());
        (
            c12,
            pt2p::descriptor_digest(&c12, &definition),
            pxr.map(|p| p.row_count),
        )
    };
    let mut s = state.try_borrow_mut_data()?;
    s[OFF_CLAUSE12..OFF_CLAUSE12 + 43].copy_from_slice(&c12);
    s[OFF_DEFINITION..OFF_DEFINITION + 32].copy_from_slice(&definition);
    s[OFF_DESCRIPTOR..OFF_DESCRIPTOR + 32].copy_from_slice(&descriptor);
    if let Some((base_entry, write, width)) = locator {
        s[OFF_LOCATOR..OFF_LOCATOR + 4].copy_from_slice(&base_entry.to_le_bytes());
        s[OFF_LOCATOR + 4] = write;
        s[OFF_LOCATOR + 5] = width;
    }
    if let Some(row_count) = pxr_rows {
        if row_count == 0 {
            return Err(err(pt::PT2_ROUTE_SET));
        }
        put_u32(&mut s, OFF_CURSOR_BYTES, 0);
        s[OFF_CURSOR_KIND] = 4;
        s[OFF_STATE] = STATE_SEALING_PXR;
        profile_seal("PT2S-profile:pxr-cursor-begin");
    } else {
        s[OFF_STATE] = STATE_SEALED;
        profile_seal("PT2S-profile:seal-finish");
    }
    Ok(())
}

/// tag 193. Accounts match tag 145: PT2S state(w), route/geometry/payload,
/// authority(s), sealed PT1X state(r). Data: tag | row_count:u16 (1..=64).
/// The persistent cursor is the row number in OFF_CURSOR_BYTES; the tag-145
/// begin call stores the descriptor and definition, and the last chunk alone
/// changes STATE_SEALING_PXR to STATE_SEALED.
pub fn seal_pxr_chunk(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 3 || accounts.len() != 6 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let count = u16_at(data, 1)?;
    if count == 0 || count > MAX_PXR_SEAL_ROWS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = owned(program, accounts, 0)?;
    if !state.is_writable || !accounts[4].is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (first, end, row_count) = {
        let s = state.try_borrow_data()?;
        check_state(&s)?;
        bind_bytes(program, &s, accounts, 1)?;
        if s[OFF_STATE] != STATE_SEALING_PXR
            || s[OFF_CURSOR_KIND] != 4
            || &s[OFF_AUTHORITY..OFF_AUTHORITY + 32] != accounts[4].key.as_ref()
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let pt1x = owned(program, accounts, 5)?;
        if pt1x.is_writable || pt1x.key.as_ref() != &s[OFF_PT1S..OFF_PT1S + 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        let p1 = pt1x.try_borrow_data()?;
        if !pt1_onchain::is_pt1x(&p1)
            || !pt1_onchain::is_sealed_template(&p1)
            || p1[4] != 6
            || p1[pt1_onchain::PT1X_BOUND_PT2S_AT..pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != state.key.to_bytes()
            || &p1[5..37] != &s[OFF_AUTHORITY..OFF_AUTHORITY + 32]
            || &p1[37..133] != &s[OFF_KEYS..OFF_KEYS + 96]
            || &p1[133..145] != &s[OFF_LENGTHS..OFF_LENGTHS + 12]
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let routes = accounts[1].try_borrow_data()?;
        let geometry = accounts[2].try_borrow_data()?;
        let payloads = accounts[3].try_borrow_data()?;
        let (_, _, pxr) = pt::route_header_v4_shallow(&routes).map_err(err)?;
        let pxr = pxr.ok_or(err(pt::PT2_ROUTE_SET))?;
        let x = view(
            &s[OFF_PWR1..],
            &routes,
            &geometry,
            &payloads,
            Some(&p1[PT1S_OFF_INDEX..]),
        )?;
        let position = x
            .position_count
            .checked_sub(1)
            .ok_or(err(pt::PT2_ROUTE_SET))?;
        let entry_count = x.entry_count(position).map_err(err)?;
        if entry_count < 2 {
            return Err(err(pt::PT2_ROUTE_SET));
        }
        let first_gather = entry_count - 2;
        let first = u32_at(&s, OFF_CURSOR_BYTES)?;
        if first >= pxr.row_count {
            return Err(err(pt::PT2_ROUTE_SET));
        }
        let end = first
            .checked_add(count as u32)
            .ok_or(err(pt::OVERFLOW))?
            .min(pxr.row_count);
        validate_pxr1_chunk(&routes, pxr, first, end, &x, position, first_gather)?;
        (first, end, pxr.row_count)
    };
    let mut s = state.try_borrow_mut_data()?;
    if s[OFF_STATE] != STATE_SEALING_PXR
        || s[OFF_CURSOR_KIND] != 4
        || u32_at(&s, OFF_CURSOR_BYTES)? != first
    {
        return Err(ProgramError::InvalidAccountData);
    }
    put_u32(&mut s, OFF_CURSOR_BYTES, end);
    if end == row_count {
        s[OFF_STATE] = STATE_SEALED;
        s[OFF_CURSOR_KIND] = 3;
        put_u32(&mut s, OFF_CURSOR_BYTES, 0);
    }
    Ok(())
}

fn sealed_state(s: &[u8]) -> Result<(), ProgramError> {
    check_state(s)?;
    if s[OFF_STATE] != STATE_SEALED {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    Ok(())
}

/// tag 146. Revision 7 keeps its six-account output form. Revision 8 PT1X
/// uses a binding-derived PT1O PDA, the System Program, and its recorded
/// authority as writable rent payer; an existing matching PT1O can be reused.
/// Revision-8 accounts are state, PT1X, routes, geometry, payloads, output,
/// optional DCM2, System Program, and PT1X authority signer.
/// Data: tag | position:u32 | first_entry:u32 | count:u16 (1..=64). Writes the
/// tag-98 stream (`PT1O` header; stream header naming `entry_count(p)` when
/// `first_entry == 0`) for entries `[first, first+count)` at `p`.
pub fn instantiate(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    instantiate_with_selector(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

/// tag 146 with the decision route selector supplied by the linking
/// application. The default dispatcher uses the revision-8 compatibility
/// selector, which refuses typed-decision selection without an app producer.
pub fn instantiate_with_selector(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    selector: &dyn crate::compatibility::DecisionRouteSelector,
) -> ProgramResult {
    instantiate_with_mode(program, accounts, data, InstantiateMode::Write, selector)
}

/// Revision-8 tag 199 reserves the PT1O address used by tag 146. It accepts
/// the same account list and request tuple, computes the exact serialized
/// output size, and performs one bounded growth step without writing output.
pub fn reserve_pt1o(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    reserve_pt1o_with_selector(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn reserve_pt1o_with_selector(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    selector: &dyn crate::compatibility::DecisionRouteSelector,
) -> ProgramResult {
    if !cfg!(feature = "revision-8") {
        return Err(ProgramError::InvalidInstructionData);
    }
    instantiate_with_mode(program, accounts, data, InstantiateMode::Reserve, selector)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InstantiateMode {
    Write,
    Reserve,
    CloseReservation,
}

fn instantiate_with_mode(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    mode: InstantiateMode,
    selector: &dyn crate::compatibility::DecisionRouteSelector,
) -> ProgramResult {
    if data.len() != 11 || !(6..=9).contains(&accounts.len()) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let expected_tag = match mode {
        InstantiateMode::Write => TAG_INSTANTIATE,
        InstantiateMode::Reserve => TAG_RESERVE_PT1O,
        InstantiateMode::CloseReservation => TAG_CLOSE_PT1O_RESERVATION,
    };
    if data[0] != expected_tag {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() >= 7 && !cfg!(feature = "revision-8") {
        return Err(ProgramError::InvalidInstructionData);
    }
    let state = owned(program, accounts, 0)?;
    let pt1s = owned(program, accounts, 1)?;
    let output = &accounts[5];
    let s = state.try_borrow_data()?;
    sealed_state(&s)?;
    if cfg!(feature = "revision-8") {
        if pt1s.key.as_ref() != &s[OFF_PT1S..OFF_PT1S + 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        let template = pt1s.try_borrow_data()?;
        if !pt1_onchain::is_pt1x(&template) {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    bind_bytes(program, &s, accounts, 2)?;
    if pt1s.key.as_ref() != &s[OFF_PT1S..OFF_PT1S + 32] {
        return Err(ProgramError::InvalidAccountData);
    }
    let position = u32_at(data, 1)?;
    let start = u32_at(data, 5)?;
    let count = u16_at(data, 9)? as u32;
    if count == 0 || count > MAX_INSTANTIATE {
        return Err(ProgramError::InvalidInstructionData);
    }
    let p1 = pt1s.try_borrow_data()?;
    let routes = accounts[2].try_borrow_data()?;
    let geometry = accounts[3].try_borrow_data()?;
    let payloads = accounts[4].try_borrow_data()?;
    if !pt1_onchain::is_sealed_template(&p1) {
        return Err(ProgramError::InvalidAccountData);
    }
    let pt1x = pt1_onchain::is_pt1x(&p1);
    if cfg!(feature = "revision-8") && !pt1x {
        return Err(ProgramError::InvalidAccountData);
    }
    let (system, document, rent_payer) = if pt1x {
        if !matches!(accounts.len(), 8 | 9) {
            return Err(ProgramError::InvalidInstructionData);
        }
        let system_at = accounts.len() - 2;
        let system = &accounts[system_at];
        if *system.key != solana_program::system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }
        (
            Some(system),
            if accounts.len() == 9 {
                Some(&accounts[6])
            } else {
                None
            },
            Some(&accounts[accounts.len() - 1]),
        )
    } else {
        if !matches!(accounts.len(), 6 | 7) {
            return Err(ProgramError::InvalidInstructionData);
        }
        (
            None,
            if accounts.len() == 7 {
                Some(&accounts[6])
            } else {
                None
            },
            None,
        )
    };
    if pt1x
        && (p1[4] != 6
            || p1[pt1_onchain::PT1X_BOUND_PT2S_AT..pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != state.key.to_bytes()
            || p1[5..37] != s[OFF_AUTHORITY..OFF_AUTHORITY + 32]
            || p1[37..133] != s[OFF_KEYS..OFF_KEYS + 96]
            || p1[133..145] != s[OFF_LENGTHS..OFF_LENGTHS + 12])
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if let Some(payer) = rent_payer {
        if payer.key.as_ref() != &p1[5..37] || !payer.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }
        if !payer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    let index = &p1[PT1S_OFF_INDEX..];
    let x = view(&s[OFF_PWR1..], &routes, &geometry, &payloads, Some(index))?;
    if position >= x.position_count {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    let total = x.entry_count(position).map_err(err)?;
    let end = start.checked_add(count).ok_or(err(pt::OVERFLOW))?;
    if end > total {
        return Err(err(pt::PT2_ROUTE_SET));
    }
    if !output.is_writable
        || accounts[..5].iter().any(|a| a.key == output.key)
        || rent_payer.is_some_and(|payer| payer.key == output.key)
        || document.is_some_and(|d| d.key == output.key)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let output_keys = if pt1x {
        if system.is_some_and(|system| system.key == output.key) {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut keys = vec![
            state.key,
            pt1s.key,
            accounts[2].key,
            accounts[3].key,
            accounts[4].key,
        ];
        if let Some(document) = document {
            keys.push(document.key);
        }
        Some(keys)
    } else {
        None
    };
    let output_binding = if let Some(keys) = &output_keys {
        let key_refs = keys.iter().copied().collect::<Vec<_>>();
        let binding = pt1_onchain::pt1x_output_binding(program, &key_refs, position, start, count);
        let (fresh, bump) = pt1_onchain::validate_pt1x_output_binding(
            program,
            output,
            system.unwrap(),
            &binding,
            position,
            start,
        )?;
        Some((binding, fresh, bump))
    } else {
        None
    };
    if let Some(system) = system {
        if system.key == output.key {
            return Err(ProgramError::InvalidAccountData);
        }
    } else {
        owned(program, accounts, 5)?;
    }
    let mut stream_bytes = if start == 0 { 44usize } else { 0usize };
    for t in start..end {
        let e = x.entry(position, t).map_err(err)?;
        let plen = x.payload_len(&e).map_err(err)?;
        let route_count = if cfg!(feature = "revision-8") && matches!(e.kernel_index, 47 | 48) {
            let document = document.ok_or(ProgramError::NotEnoughAccountKeys)?;
            crate::unified::document::document(program, document, None, false, pt::PT2_ROUTE_SET)?;
            let doc = document.try_borrow_data()?;
            if doc.get(200..232) != Some(state.key.as_ref())
                || doc.get(232..264) != Some(crate::hash::sha256(&[&s]).as_ref())
            {
                return Err(err(pt::PT2_ROUTE_SET));
            }
            selector
                .document_selected_routes(&x, e, &doc, &routes, None)?
                .ok_or(err(pt::PT2_ROUTE_SET))?
                .len()
        } else {
            e.route_count() as usize
        };
        stream_bytes = stream_bytes
            .checked_add(14 + plen + 40 * route_count)
            .ok_or(ProgramError::AccountDataTooSmall)?;
    }
    if let Some((binding, fresh, bump)) = output_binding {
        if stream_bytes > u32::MAX as usize {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let keys = output_keys.as_ref().unwrap();
        let key_refs = keys.iter().copied().collect::<Vec<_>>();
        let required_bytes = pt1_onchain::PT1X_OUTPUT_HEADER_BYTES
            .checked_add(stream_bytes)
            .and_then(|n| n.checked_add(pt1_onchain::PT1X_OUTPUT_TRAILER_FIXED_BYTES))
            .and_then(|n| n.checked_add(32 * keys.len()))
            .ok_or(ProgramError::AccountDataTooSmall)?;
        match mode {
            InstantiateMode::Reserve => {
                pt1_onchain::reserve_pt1x_output_pda(
                    program,
                    output,
                    system.unwrap(),
                    rent_payer.unwrap(),
                    &binding,
                    bump,
                    required_bytes,
                )?;
                return Ok(());
            }
            InstantiateMode::CloseReservation => {
                pt1_onchain::close_pt1x_output_reservation(
                    program,
                    output,
                    rent_payer.unwrap(),
                    &binding,
                    bump.value(),
                    required_bytes,
                )?;
                return Ok(());
            }
            InstantiateMode::Write => {}
        }
        if mode == InstantiateMode::Write {
            pt1_onchain::prepare_pt1x_output_pda(
                program,
                output,
                system.unwrap(),
                rent_payer.unwrap(),
                &binding,
                bump,
                count,
                stream_bytes,
                required_bytes,
                &key_refs,
                fresh,
            )?;
        }
    } else {
        if mode != InstantiateMode::Write {
            return Err(ProgramError::InvalidInstructionData);
        }
        if output.data_len() < 16 {
            return Err(ProgramError::AccountDataTooSmall);
        }
    }
    let mut out = output.try_borrow_mut_data()?;
    let payload_at = if pt1x {
        pt1_onchain::PT1X_OUTPUT_HEADER_BYTES
    } else {
        16
    };
    let mut at = payload_at;
    fn take<'o>(out: &'o mut [u8], at: &mut usize, n: usize) -> Result<&'o mut [u8], ProgramError> {
        let end = at.checked_add(n).ok_or(ProgramError::AccountDataTooSmall)?;
        let slice = out
            .get_mut(*at..end)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        *at = end;
        Ok(slice)
    }
    if start == 0 {
        take(&mut out, &mut at, 36)?.copy_from_slice(b"basanos/pt1-compiler-instantiation/1");
        take(&mut out, &mut at, 4)?.copy_from_slice(&position.to_le_bytes());
        take(&mut out, &mut at, 4)?.copy_from_slice(&total.to_le_bytes());
    }
    for t in start..end {
        let e = x.entry(position, t).map_err(err)?;
        let plen = x.payload_len(&e).map_err(err)?;
        let dynamic_routes = if cfg!(feature = "revision-8") && matches!(e.kernel_index, 47 | 48) {
            let document = document.ok_or(ProgramError::NotEnoughAccountKeys)?;
            crate::unified::document::document(program, document, None, false, pt::PT2_ROUTE_SET)?;
            let doc = document.try_borrow_data()?;
            if doc.get(200..232) != Some(state.key.as_ref())
                || doc.get(232..264) != Some(crate::hash::sha256(&[&s]).as_ref())
            {
                return Err(err(pt::PT2_ROUTE_SET));
            }
            selector
                .document_selected_routes(&x, e, &doc, &routes, None)?
                .ok_or(err(pt::PT2_ROUTE_SET))?
        } else {
            (0..e.route_count() as u16)
                .map(|k| x.route(&e, k).map_err(err))
                .collect::<Result<Vec<_>, _>>()?
        };
        take(&mut out, &mut at, 4)?.copy_from_slice(&t.to_le_bytes());
        take(&mut out, &mut at, 2)?.copy_from_slice(&(dynamic_routes.len() as u16).to_le_bytes());
        take(&mut out, &mut at, 4)?.copy_from_slice(
            &x.attention_t(&e)
                .map_err(err)?
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        take(&mut out, &mut at, 4)?.copy_from_slice(&(plen as u32).to_le_bytes());
        x.payload(&e, true, take(&mut out, &mut at, plen)?)
            .map_err(err)?;
        for r in &dynamic_routes {
            take(&mut out, &mut at, 40)?.copy_from_slice(&pt2p::route_wire(&r));
        }
    }
    out[..4].copy_from_slice(OUTPUT_MAGIC);
    put_u32(&mut out, 4, position);
    put_u32(&mut out, 8, start);
    put_u32(&mut out, 12, (at - payload_at) as u32);
    if let Some((binding, _, _)) = output_binding {
        out[16..48].copy_from_slice(&binding);
    }
    Ok(())
}

/// Tag 200 closes an exact, unwritten PT1R reservation before tag 146 writes it.
/// It recomputes the request size and accepts only the binding-derived PDA;
/// only the PT1X authority can receive its lamports.
pub fn close_pt1o_reservation(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    close_pt1o_reservation_with_selector(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn close_pt1o_reservation_with_selector(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    selector: &dyn crate::compatibility::DecisionRouteSelector,
) -> ProgramResult {
    if !cfg!(feature = "revision-8") {
        return Err(ProgramError::InvalidInstructionData);
    }
    instantiate_with_mode(
        program,
        accounts,
        data,
        InstantiateMode::CloseReservation,
        selector,
    )
}

/// tag 147. Accounts: authority(s), document(w), pt2p_state, routes, geometry, payloads.
/// Data: tag | position:u32. The DCM2 v2 manifest slot of `position` (layout of
/// closure-v2 bootstrap tag 96: `segment_table_root32 | (segment_id:u16,
/// entries:u32) * S`) is computed on chain from the sealed PT2P state. The
/// document PDA is derived from the sealed descriptor; authority, version,
/// unsealed-document and zero-slot (write-once) checks equal tag 96's.
pub fn bind_manifest(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 6 || data.len() != 5 {
        return Err(err(FORM));
    }
    let authority = &accounts[0];
    let document = &accounts[1];
    let state = owned(program, accounts, 2)?;
    let s = state.try_borrow_data()?;
    sealed_state(&s)?;
    bind_bytes(program, &s, accounts, 3)?;
    let descriptor: [u8; 32] = s[OFF_DESCRIPTOR..OFF_DESCRIPTOR + 32].try_into().unwrap();
    if !authority.is_signer
        || !document.is_writable
        || document.owner != program
        || *document.key != document_address(program, &descriptor).0
    {
        return Err(err(AUTHORITY));
    }
    let position = u32_at(data, 1)?;
    let routes = accounts[3].try_borrow_data()?;
    let geometry = accounts[4].try_borrow_data()?;
    let payloads = accounts[5].try_borrow_data()?;
    let x = view(&s[OFF_PWR1..], &routes, &geometry, &payloads, None)?;
    let (offset, stride) = {
        let doc = document.try_borrow_data()?;
        if doc.len() < DCM2_V2_HEADER
            || doc[..4] != *b"DCM2"
            || u16_at(&doc, 4)? != 2
            || u16_at(&doc, 6)? != 0
            || doc[8..40] != descriptor
            || doc[40..72] != authority.key.to_bytes()
        {
            return Err(err(FORM));
        }
        let positions = u32_at(&doc, 72)?;
        let count = u16_at(&doc, 76)? as usize;
        if position >= positions
            || positions != x.position_count
            || count != x.segment_count as usize
        {
            return Err(err(FORM));
        }
        let stride = 32 + 6 * count;
        let offset = DCM2_V2_HEADER + position as usize * stride;
        if doc.len() != DCM2_V2_HEADER + positions as usize * stride
            || doc[offset..offset + stride].iter().any(|&b| b != 0)
        {
            return Err(err(FORM));
        }
        (offset, stride)
    };
    let root = x.segment_table_root(position).map_err(err)?;
    let mut last: Option<u16> = None;
    let mut rows = [0u8; 6];
    let mut doc = document.try_borrow_mut_data()?;
    // Validate every row before the first write.
    for seg in 0..x.segment_count as usize {
        let (id, entries) = x.segment_row(position, seg).map_err(err)?;
        if entries == 0 || last.is_some_and(|previous| previous >= id) {
            return Err(err(FORM));
        }
        last = Some(id);
    }
    if root == [0; 32] {
        return Err(err(FORM));
    }
    doc[offset..offset + 32].copy_from_slice(&root);
    for seg in 0..x.segment_count as usize {
        let (id, entries) = x.segment_row(position, seg).map_err(err)?;
        rows[..2].copy_from_slice(&id.to_le_bytes());
        rows[2..].copy_from_slice(&entries.to_le_bytes());
        let at = offset + 32 + 6 * seg;
        doc[at..at + 6].copy_from_slice(&rows);
    }
    debug_assert_eq!(32 + 6 * x.segment_count as usize, stride);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn compress_matches_sha2_on_padded_messages() {
        use sha2::{Digest, Sha256};
        for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 1000] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
            let mut padded = msg.clone();
            padded.push(0x80);
            while padded.len() % 64 != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((len as u64) * 8).to_be_bytes());
            let mut state = super::IV;
            for block in padded.chunks(64) {
                super::compress(&mut state, block);
            }
            let got: Vec<u8> = state.iter().flat_map(|w| w.to_be_bytes()).collect();
            assert_eq!(got.as_slice(), Sha256::digest(&msg).as_slice(), "len {len}");
        }
    }
}
