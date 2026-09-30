//! The unified document (spec §6): DPD2 descriptor, DFS2 family slot table,
//! DCM2 v5 header, UnifiedInit (161), LandPositionRoots (162) with the v3
//! mountain range, FinalizeDocumentV5 (165) and the DCR2 v4 durable result
//! (tags 177/178 attest and resolve, tag 172 close).
//!
//! DCM2 v5 (1,864 bytes, spec §6.3):
//! ```text
//!   0 "DCM2" | 4 version:u16 = 5 | 6 flags:u16 (1 armed, 2 finalized, 4 refuted,
//!     8 closed, 16 ROOT_ONLY, 32 sealed) | 8 descriptor[32] | 40 authority[32]
//!  72 P:u32 | 76 S:u16 | 78 zero[6] | 84 positions_complete:u32
//!  88 entries_complete:u64 | 96 document_root[32] | 128 open_challenges:u32
//! 132 refuted_positions:u32 | 136 finalize_slot:u64 | 144 dispute_deadline:u64
//! 152 prefix_root[32] | 184 challenge_window_slots:u64 | 192 total_entries:u64
//! 200 PT2S | 232 PT2S_sha256 | 264 model_root | 296 position_table_root
//! 328 prompt_commitment | 360 registry | 392 registry_table_root | 424 DEA2
//! 456 DFS2 | 488 family_table_digest | 520 registry_epoch:u32 | 524 F:u16
//! 526 H:u8 | 527 commitment_version:u8 = 3 | 528 peak_count:u8
//! 529 executor_bond_state:u8 | 530 zero[6] | 536 peaks[32] x 40 | 1816 DDT1[48]
//! ```
//!
//! **DPR2 growth (implementation framing).** A program may create at most
//! 10,240 bytes of account data through CPI, so a DPR2 larger than that
//! (`48 + 32·P > 10,240`, i.e. `P > 318`) is created at 10,240 bytes with
//! rent for its full size and LandPositionRoots grows it to cover each batch.
//! The spec's "DPR2 v1 as today" assumes a one-shot create (reported).

use super::address::{
    self, document as document_address, family_slots as family_slots_address,
    positions as position_page_address, result as result_address,
};
use super::classes::{self, rs1_height, summary_shape};
use super::events::{self, Body};
use super::registry::{self, find_row, HEADER as DRP2_HEADER};
use super::terms::{Terms, Terms2, TERMS_BYTES, TERMS_BYTES_V2};
use super::{
    admission, d32, no, plan, u16_at, u32_at, u64_at, ADMISSION_STATE, APPEND_ORDER,
    CL_AFTER_FINAL, CL_AUTHORITY, CL_COORDINATE, CL_MALFORMED, CL_MISSING, CL_OVERFLOW, CL_ROOT,
    DCR1_BAD, EPOCH, PLAN_BINDING, REGISTRY_ROOT,
};
use crate::hash;
use crate::pt2p::Pt2p;
use crate::pt2p_onchain as S;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, program::invoke,
    program_error::ProgramError, pubkey::Pubkey, system_instruction, sysvar::Sysvar,
};

/// Revision 4: 2,024 bytes (DRB1 at 1,864); revision 3's 1,864 is withdrawn.
/// **Revision 7's** header, and the only one a revision-7 handler reads: the
/// version field and this length are the reader split, so a revision-8 record
/// is refused structurally at each revision-7 call site (spec §3).
pub const DCM2_V6_BYTES: usize = 2_072;
pub const TERMS_AT: usize = 1_816;
pub const BINDING_AT: usize = 1_912;
pub const BINDING_BYTES: usize = 160;
pub const RUN_BINDING: u32 = 794;
/// DDT1 `response_window_slots` inside DCM2 (1,816 + 16).
pub const RESPONSE_WINDOW_AT: usize = TERMS_AT + 16;
pub const PEAKS_AT: usize = 536;
pub const PEAK_BYTES: usize = 40;
pub const PEAK_SLOTS: usize = 32;
/// Revision 8's header, `2,182 + 4*option_count` (spec §1.3). The five
/// offsets below are the derived chain, in order: `530 + 32 = 562`
/// (`conviction_winner`, D11) `= PEAKS_AT_V8`; `562 + 40*32 = 1,842 =
/// TERMS_AT_V8`; `1,842 + 136 = 1,978 = BINDING_AT_V8`; `1,978 + 196 = 2,174
/// = ABANDON_DEADLINE_AT`; `2,174 + 8 = 2,182 = OPTION_REGION_AT`.
pub const DCM2_V7_BYTES: usize = 2_182;
pub const WINNER_AT_V8: usize = 530;
pub const PEAKS_AT_V8: usize = 562;
pub const TERMS_AT_V8: usize = 1_842;
pub const BINDING_AT_V8: usize = 1_978;
pub const BINDING_BYTES_V8: usize = 196;
pub const ABANDON_DEADLINE_AT: usize = 2_174;
pub const OPTION_REGION_AT: usize = 2_182;
/// App-bound revision-8 documents append this fixed 64-byte ARI1 identity
/// after the ordinary option table. Non-app-bound DCM2 v7 bytes stay exact.
pub const APP_IDENTITY_BYTES: usize = 64;
/// The four descriptor PDA bumps needed by the revision-8 close. The six
/// formerly reserved bytes at 78..84 now hold DCM2, DPR2, DFS2 and bond-escrow
/// bumps followed by two zero bytes. DCR2 stores its own bump at 410.
pub const DCM2_BUMP_AT: usize = 78;
pub const DPR2_BUMP_AT: usize = 79;
pub const DFS2_BUMP_AT: usize = 80;
pub const BOND_ESCROW_BUMP_AT: usize = 81;
pub const PDA_BUMPS_RESERVED_AT: usize = 82;
/// `FinalizeDocumentV5`'s `DOCUMENT_LENGTH` (spec §3). The v8 form-47
/// single-reducer guard uses 823 because this finalize rule owns 816.
pub const DOCUMENT_LENGTH: u32 = 816;
/// Revision 8's first non-DCR1 use of revision 7's **736** (spec §3): "the
/// deadline this instruction owns has passed", the same meaning 736 carries
/// everywhere in revision 7, so the code is reused rather than reallocated.
/// `FinalizeDocumentV5` refuses it at or after `abandon_deadline`, and again
/// when a finalize would leave less than a full attestation budget.
pub const CL_DEADLINE: u32 = 736;
/// Revision 8's descriptor preimage: the `/5` domain, `unified_version = 3`,
/// 679 + 40 (DDT2 v2) + 36 (DRB1 v2) = 755. Nothing else in the preimage
/// moves (spec §1).
pub const DESCRIPTOR_DOMAIN_V8: &[u8] = b"basanos/dcg-unified-descriptor/5";
pub const UNIFIED_VERSION_V8: u16 = 3;
pub const DPD2_BYTES_V8: usize = 755;
pub const FLAG_ARMED: u16 = 1;
pub const FLAG_FINAL: u16 = 2;
pub const FLAG_REFUTED: u16 = 4;
pub const FLAG_ROOT_ONLY: u16 = 16;
pub const FLAG_SEALED: u16 = 32;
pub const BOND_NONE: u8 = 0;
pub const BOND_HELD: u8 = 1;
pub const BOND_PAID: u8 = 2;
pub const BOND_RETURNED: u8 = 3;
/// `BOND_ESCROWED` (spec §1.4). Written only by the two routes that escrow:
/// a CUSTOM `CloseDocumentV5` and a CUSTOM `ChallengeSettleV5`, both of which
/// land in stream C's later slices.
pub const BOND_ESCROWED: u8 = 4;
pub const DPR2_HEADER: usize = 48;
pub const DFS2_HEADER: usize = 48;
pub const MAX_FAMILIES: u16 = 24;
pub const MAX_SEGMENTS: u16 = 128;
/// Revision 4 (`/3`): the preimage carries DRB1 after DDT1 (631 bytes).
pub const DESCRIPTOR_DOMAIN: &[u8] = b"basanos/dcg-unified-descriptor/4";
pub const FAMILY_TABLE_DOMAIN: &[u8] = b"basanos/dcg-rs1-table/1";
pub const MMR_LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-incremental-leaf/1";
pub const MMR_NODE_DOMAIN: &[u8] = b"basanos/dcg-hclosure-incremental-node/1";
pub const MMR_DOCUMENT_DOMAIN: &[u8] = b"basanos/dcg-hclosure-incremental-document/1";
pub const DPD2_BYTES: usize = 679;
/// Largest data a program can allocate through CPI in one instruction.
const CPI_ALLOC: usize = 10_240;

// ------------------------------------------------------------------ DFS2

/// Plan-independent DFS2 body rules (spec §6.2): `1 <= F <= 24`, ordinals
/// strictly ascending, every slot list nonempty and strictly ascending by
/// `(base_entry, write_row_ordinal)`, exact EOF. Returns `(ordinal, region,
/// slots)` per family.
pub fn parse_family_body(body: &[u8]) -> Result<Vec<(u16, u16, &[u8])>, u32> {
    parse_families(&crate::root_only_sealed::families(body).map_err(|_| PLAN_BINDING)?)
}

/// The same rules over an already-parsed family list, for the revision-8
/// UnifiedInit, whose instruction data appends the option table after the
/// body and therefore splits the two apart first.
pub fn parse_families<'a>(
    fams: &[crate::root_only_sealed::Family<'a>],
) -> Result<Vec<(u16, u16, &'a [u8])>, u32> {
    if fams.is_empty() || fams.len() > MAX_FAMILIES as usize {
        return Err(PLAN_BINDING);
    }
    let mut out = Vec::with_capacity(fams.len());
    for f in fams {
        let mut previous: Option<(u32, u8)> = None;
        for slot in f.slots.chunks_exact(5) {
            let key = (u32::from_le_bytes(slot[..4].try_into().unwrap()), slot[4]);
            if previous.is_some_and(|p| p >= key) {
                return Err(PLAN_BINDING);
            }
            previous = Some(key);
        }
        out.push((f.ordinal, f.region, f.slots));
    }
    Ok(out)
}

/// Plan-dependent DFS2 rules: the families are exactly the `PWR1` K/V
/// families, and every slot is an existing write of a surviving base entry
/// into its family's region.
pub fn check_family_plan(x: &Pt2p<'_>, fams: &[(u16, u16, &[u8])]) -> Result<(), u32> {
    let mut wanted: Vec<u16> = Vec::with_capacity(2 * x.layer_count() as usize);
    for li in 0..x.layer_count() {
        let rule = x.g.layer(li)?;
        for f in [rule.k_family, rule.v_family] {
            if !wanted.contains(&f) {
                wanted.push(f);
            }
        }
    }
    if wanted.len() != fams.len() || fams.iter().any(|(o, _, _)| !wanted.contains(o)) {
        return Err(PLAN_BINDING);
    }
    for (_, region, slots) in fams {
        for slot in slots.chunks_exact(5) {
            let o = u32::from_le_bytes(slot[..4].try_into().unwrap());
            if o >= x.base_entries || x.is_replaced(o) {
                return Err(PLAN_BINDING);
            }
            let e = x.base_entry_record(o).map_err(|_| PLAN_BINDING)?;
            if slot[4] as u16 >= e.write_count {
                return Err(PLAN_BINDING);
            }
            let w = x
                .base_route_record(e, e.read_count + slot[4] as u16)
                .map_err(|_| PLAN_BINDING)?;
            if w.region_id != *region {
                return Err(PLAN_BINDING);
            }
        }
    }
    Ok(())
}

/// `SHA256("basanos/dcg-rs1-table/1" | descriptor | F:u16 | root_f x F)`.
pub fn family_table_digest(descriptor: &[u8; 32], roots: &[u8]) -> [u8; 32] {
    hash::sha256(&[
        FAMILY_TABLE_DOMAIN,
        descriptor,
        &((roots.len() / 32) as u16).to_le_bytes(),
        roots,
    ])
}

// ------------------------------------------------------------------ DRB1

/// DRB1 run binding (spec §6.10, revision 4): what one run is for.
/// ```text
///   0 "DRB1" | 4 version:u16 = 1 | 6 reserved:u16 | 8 executor[32]
///  40 request_id[32] | 72 consumer_digest[32] | 104 seed[32]
/// 136 output_first_position:u32 | 140 output_count:u32
/// 144 output_base_entry:u32 | 148 output_write:u8 | 149 output_width:u8
/// 150 reserved[10]
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub executor: [u8; 32],
    pub request_id: [u8; 32],
    pub consumer_digest: [u8; 32],
    pub seed: [u8; 32],
    pub output_first_position: u32,
    pub output_count: u32,
    pub output_base_entry: u32,
    pub output_write: u8,
    pub output_width: u8,
}

impl Binding {
    /// Decode plus the plan-independent checks (items 1, 3, 4 but `P`); 794.
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != BINDING_BYTES
            || raw[..4] != *b"DRB1"
            || raw[4..6] != 1u16.to_le_bytes()
            || raw[6..8] != [0; 2]
            || raw[150..160] != [0; 10]
        {
            return Err(RUN_BINDING);
        }
        let k = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().unwrap() };
        let w = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let b = Binding {
            executor: k(8),
            request_id: k(40),
            consumer_digest: k(72),
            seed: k(104),
            output_first_position: w(136),
            output_count: w(140),
            output_base_entry: w(144),
            output_write: raw[148],
            output_width: raw[149],
        };
        if b.executor == [0; 32]
            || (b.request_id == [0; 32]) != (b.consumer_digest == [0; 32])
            || b.output_count == 0
            || !(1..=super::result::MAX_WIDTH).contains(&b.output_width)
            || super::result::bytes(b.output_count, b.output_width).is_none()
        {
            return Err(RUN_BINDING);
        }
        Ok(b)
    }

    /// UnifiedInit step 2a against the signer and the plan (spec §6.10): the
    /// executor is the signer; outputs end by `P`; the output entry survives
    /// at every position and its write is a fixed, non-scaled write of
    /// exactly `output_width` bytes.
    pub fn check(&self, signer: &Pubkey, x: &Pt2p<'_>) -> Result<(), u32> {
        let end = self
            .output_first_position
            .checked_add(self.output_count)
            .ok_or(RUN_BINDING)?;
        if self.executor != signer.to_bytes() || end > x.position_count {
            return Err(RUN_BINDING);
        }
        let o = self.output_base_entry;
        if o >= x.base_entries || x.is_replaced(o) {
            return Err(RUN_BINDING);
        }
        let e = x.base_entry_record(o).map_err(|_| RUN_BINDING)?;
        if self.output_write as u16 >= e.write_count {
            return Err(RUN_BINDING);
        }
        let r = x
            .base_route_record(e, e.read_count + self.output_write as u16)
            .map_err(|_| RUN_BINDING)?;
        if r.flags & 2 != 0 || r.read_class == 3 || r.byte_length != self.output_width as u32 {
            return Err(RUN_BINDING);
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ DRB1 v2

/// The PT2S's `output_locator[6]` at byte 426 (spec §1.7), written by the
/// PT2S seal from two more instruction arguments and immutable thereafter.
/// These six bytes were dead state, so the locator costs no account growth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locator {
    pub base_entry: u32,
    pub write: u8,
    pub width: u8,
}

impl Locator {
    /// The locator of a sealed PT2S (426..432), or `code`.
    pub fn read(pt2s: &[u8], code: u32) -> Result<Self, ProgramError> {
        if pt2s.len() < S::OFF_LOCATOR + 6 {
            return Err(no(code));
        }
        Ok(Locator {
            base_entry: u32_at(pt2s, 426, code)?,
            write: pt2s[430],
            width: pt2s[431],
        })
    }
}

/// DRB1 v2, the shared run binding of revision 8 (spec §1.2). One record for
/// `prompt_positions`, the stop value and typed decisions' option fields.
/// ```text
///   0 "DRB1" | 4 version:u16 = 2 | 6 reserved:u16 = 0 | 8 executor[32]
///  40 request_id[32] | 72 consumer_digest[32] | 104 seed[32]
/// 136 output_first_position:u32 | 140 output_count:u32
/// 144 output_base_entry:u32 | 148 output_write:u8 | 149 output_width:u8
/// 150 decision_flags:u8 | 151 option_count:u8 | 152 prompt_positions:u32
/// 156 stop_plus_one:u32 | 160 option_table_offset:u16 | 162 reserved[2] = 0
/// 164 option_table_sha256[32] | 196 end
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding2 {
    pub executor: [u8; 32],
    pub request_id: [u8; 32],
    pub consumer_digest: [u8; 32],
    pub seed: [u8; 32],
    pub output_first_position: u32,
    pub output_count: u32,
    pub output_base_entry: u32,
    pub output_write: u8,
    pub output_width: u8,
    pub decision_flags: u8,
    pub option_count: u8,
    pub prompt_positions: u32,
    pub stop_plus_one: u32,
    pub option_table_offset: u16,
    pub option_table_sha256: [u8; 32],
}

/// `decision_flags` bit 0, the **only** difference between the two output
/// shapes and the same bit that already meant "this document is a typed
/// decision" (spec §1.2).
pub const DECISION_MODE: u8 = 1;
/// The decision cell width: a decision's cells are 4-byte fixed-point values.
pub const DECISION_WIDTH: u8 = 4;
/// The width a record that declares a stop value must have (spec §1's one
/// conditional, §1.2's field table at 149, and the 794 row of
/// `refusals_v1.tsv`): the stop rule's comparison cell is then exactly the
/// 16-byte `(best, token)` pair of §1.7, whose bytes `8..16` carry the token
/// id that `stop_plus_one` is that id plus one. The same number as
/// `tierc-oracle`'s `TOKEN_WIDTH`, which is the writer of these fields.
pub const STOP_WIDTH: u8 = 16;

impl Binding2 {
    /// Decode plus every plan-independent check of spec §1.2; 794. The first
    /// three template-binding relations and the two plan-dependent decision
    /// clauses are `check`, which needs the plan and the PT2S. Relation 4 and
    /// the decision count relation are record-only and are checked here.
    ///
    /// **`stop_plus_one != 0` implies `output_width == 16` lives here**, in the
    /// plan-independent half, because it compares two fields of the record and
    /// needs nothing else: it is spec §1's one conditional and §1.2's field
    /// table, and the Python mirror makes it in the same place. A record with a
    /// narrower or wider cell declares a stop value the stop rule can never
    /// find (`is_stop_value` reads bytes `8..16`), and a decision's 4-byte
    /// cells have no such bytes at all, so the two conditionals are exclusive by
    /// construction.
    pub fn decode(raw: &[u8]) -> Result<Self, u32> {
        if raw.len() != BINDING_BYTES_V8
            || raw[..4] != *b"DRB1"
            || raw[4..6] != 2u16.to_le_bytes()
            || raw[6..8] != [0; 2]
            || raw[162..164] != [0; 2]
            || raw[150] & !DECISION_MODE != 0
        {
            return Err(RUN_BINDING);
        }
        let k = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().unwrap() };
        let w = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let b = Binding2 {
            executor: k(8),
            request_id: k(40),
            consumer_digest: k(72),
            seed: k(104),
            output_first_position: w(136),
            output_count: w(140),
            output_base_entry: w(144),
            output_write: raw[148],
            output_width: raw[149],
            decision_flags: raw[150],
            option_count: raw[151],
            prompt_positions: w(152),
            stop_plus_one: w(156),
            option_table_offset: u16::from_le_bytes([raw[160], raw[161]]),
            option_table_sha256: k(164),
        };
        // `decision_flags` bit 0 is set exactly when `option_count != 0`: one
        // source of truth, as for `stop_plus_one != 0`.
        let decision = b.decision();
        if b.executor == [0; 32]
            || (b.request_id == [0; 32]) != (b.consumer_digest == [0; 32])
            || b.output_count == 0
            || !(1..=super::result::MAX_WIDTH).contains(&b.output_width)
            || b.prompt_positions == 0
            || decision != (b.option_count != 0)
            || (decision
                && (b.output_width != DECISION_WIDTH
                    || b.option_count as usize > crate::kernels::decision::MAX_OPTIONS_SINGLE
                    || b.option_table_offset as usize != OPTION_REGION_AT
                    || b.option_table_sha256 == [0; 32]
                    || b.output_count != 1 + b.option_count as u32))
            || (!decision && (b.option_table_offset != 0 || b.option_table_sha256 != [0; 32]))
            || (b.stop_plus_one != 0 && b.output_width != STOP_WIDTH)
            || super::result::bytes_v8(b.output_count, b.output_width).is_none()
        {
            return Err(RUN_BINDING);
        }
        Ok(b)
    }

    pub fn encode(&self) -> [u8; BINDING_BYTES_V8] {
        let mut out = [0u8; BINDING_BYTES_V8];
        out[..4].copy_from_slice(b"DRB1");
        out[4..6].copy_from_slice(&2u16.to_le_bytes());
        out[8..40].copy_from_slice(&self.executor);
        out[40..72].copy_from_slice(&self.request_id);
        out[72..104].copy_from_slice(&self.consumer_digest);
        out[104..136].copy_from_slice(&self.seed);
        out[136..140].copy_from_slice(&self.output_first_position.to_le_bytes());
        out[140..144].copy_from_slice(&self.output_count.to_le_bytes());
        out[144..148].copy_from_slice(&self.output_base_entry.to_le_bytes());
        out[148] = self.output_write;
        out[149] = self.output_width;
        out[150] = self.decision_flags;
        out[151] = self.option_count;
        out[152..156].copy_from_slice(&self.prompt_positions.to_le_bytes());
        out[156..160].copy_from_slice(&self.stop_plus_one.to_le_bytes());
        out[160..162].copy_from_slice(&self.option_table_offset.to_le_bytes());
        out[164..196].copy_from_slice(&self.option_table_sha256);
        out
    }

    pub fn decision(&self) -> bool {
        self.decision_flags & DECISION_MODE != 0
    }

    /// Exclusive position bound for spec §1 relation 4. A completion spans one
    /// position per output plus its prompt position; a decision needs only its
    /// single output position, which is also its final prompt position.
    fn required_position_end(&self) -> u64 {
        if self.decision() {
            self.output_first_position as u64 + 1
        } else {
            self.output_first_position as u64 + self.output_count as u64 + 1
        }
    }

    fn fits_position_capacity(&self, capacity: u32) -> bool {
        self.required_position_end() <= capacity as u64
    }

    /// The two-case `L` (spec §1.2 and §1.6): `1 + option_count` for a
    /// decision, `n - 1 - first` for a completion. Zero when the document is
    /// shorter than one output, which no finalize admits (816) and no attest
    /// can reach (`index < L`).
    pub fn output_span(&self, n: u32) -> u32 {
        if self.decision() {
            1 + self.option_count as u32
        } else {
            n.saturating_sub(1)
                .saturating_sub(self.output_first_position)
        }
    }

    /// The `(position, write)` of output `i`'s cell (spec §1.2): one position
    /// and consecutive write lanes under the mode flag, one write and
    /// consecutive positions otherwise.
    pub fn cell(&self, index: u32) -> (u32, u16) {
        if self.decision() {
            (
                self.output_first_position,
                self.output_write as u16 + index as u16,
            )
        } else {
            (self.output_first_position + index, self.output_write as u16)
        }
    }

    /// The option-table clauses of spec §1.2 against the `4*option_count`
    /// bytes UnifiedInit is about to write into DCM2's option region: the
    /// length, the offset already checked by `decode`, and the hash.
    pub fn check_options(&self, options: &[u8]) -> Result<(), u32> {
        if options.len() != 4 * self.option_count as usize {
            return Err(RUN_BINDING);
        }
        if self.option_count != 0 && hash::sha256(&[options]) != self.option_table_sha256 {
            return Err(RUN_BINDING);
        }
        // The table is also the input to the option-independent PXR1 resolver.
        // Refuse an id outside the committed logits row here, before any of
        // the derived gather routes can be instantiated. Keep the hash check
        // first so malformed bytes cannot be reported as a semantic id error.
        for token in options.chunks_exact(4) {
            let id = u32::from_le_bytes(token.try_into().unwrap());
            if id as usize >= crate::kernels::decision::LOGITS_ROW_LENGTH {
                return Err(crate::kernels::decision::ERR_OPTION_RANGE);
            }
        }
        Ok(())
    }

    /// UnifiedInit step 2a for revision 8 (spec §1's five relations, §1.2's
    /// check list and the three decision-branch clauses); 794.
    ///
    /// The first three relations are unconditional. Relation 4 is conditional:
    /// completions reserve one output position per count, while a typed decision
    /// writes all its cells at one position. A document that opts out of the
    /// stop rule must still bind `first` to its prompt and name the template's
    /// output write.
    pub fn check(&self, signer: &Pubkey, x: &Pt2p<'_>, locator: &Locator) -> Result<(), u32> {
        if self.executor != signer.to_bytes() {
            return Err(RUN_BINDING);
        }
        // UnifiedInit must leave enough prompt positions for every route's
        // producer_delta, before the template is instantiated at any route.
        if x.c.max_producer_delta as u32 > self.prompt_positions {
            return Err(RUN_BINDING);
        }
        // 1. `first = prompt_positions - 1`.
        if self.output_first_position != self.prompt_positions - 1 {
            return Err(RUN_BINDING);
        }
        // 2-3. the template's own locator, three byte-for-byte compares.
        if self.output_base_entry != locator.base_entry
            || self.output_write != locator.write
            || self.output_width != locator.width
        {
            return Err(RUN_BINDING);
        }
        // 4. A completion has one position per output; all decision cells are
        // writes at the same position, so its bound needs only that position.
        if !self.fits_position_capacity(x.position_count) {
            return Err(RUN_BINDING);
        }
        // Revision 7 §6.10's check 5, on its own terms: the output entry
        // survives, its write exists, is neither T-scaled nor a range route,
        // and its clause-5 length is exactly `output_width`.
        let o = self.output_base_entry;
        if o >= x.base_entries || x.is_replaced(o) {
            return Err(RUN_BINDING);
        }
        let e = x.base_entry_record(o).map_err(|_| RUN_BINDING)?;
        if self.output_write as u16 >= e.write_count {
            return Err(RUN_BINDING);
        }
        let r = x
            .base_route_record(e, e.read_count + self.output_write as u16)
            .map_err(|_| RUN_BINDING)?;
        if r.flags & 2 != 0 || r.read_class == 3 || r.byte_length != self.output_width as u32 {
            return Err(RUN_BINDING);
        }
        if !self.decision() {
            return Ok(());
        }
        // The two plan-dependent decision clauses: every write `output_write
        // + i` exists at `output_first_position` with width 4, and the last
        // write fits the u8 without wrapping onto lane 0. The plan-independent
        // count clause is in decode, before this plan walk.
        if self.output_write as u16 + self.option_count as u16 > u8::MAX as u16 {
            return Err(RUN_BINDING);
        }
        let t = x
            .old_to_new(o, self.output_first_position)
            .map_err(|_| RUN_BINDING)?
            .ok_or(RUN_BINDING)?;
        let entry = x
            .entry(self.output_first_position, t)
            .map_err(|_| RUN_BINDING)?;
        for i in 1..=self.option_count as u16 {
            let lane = e.read_count + self.output_write as u16 + i;
            // `x.route` is where the T-scaled and range-route properties are
            // enforced for a resolved position: an inconsistent scale flag or
            // a range read with a binding is `Err` here, and a write's
            // `read_class` is 0 by construction. What is left to ask at the
            // position is the lane's width.
            let route = x.route(&entry, lane).map_err(|_| RUN_BINDING)?;
            if route.direction != 1 || route.byte_length != DECISION_WIDTH as u32 {
                return Err(RUN_BINDING);
            }
        }
        Ok(())
    }
}

/// `FinalizeDocumentV5`'s `DOCUMENT_LENGTH` rule, 816 (spec §1.6 and §3):
/// a completion is `1 <= n <= position_capacity` and
/// `first + 2 <= n <= first + count + 1`; a decision is
/// `n = prompt_positions`, `first = n - 1` and `count = 1 + option_count`.
pub fn check_document_length(b: &Binding2, n: u32, position_capacity: u32) -> Result<(), u32> {
    if b.decision() {
        if n != b.prompt_positions
            || b.output_first_position != n - 1
            || b.output_count != 1 + b.option_count as u32
        {
            return Err(DOCUMENT_LENGTH);
        }
    } else if !(1..=position_capacity).contains(&n) {
        return Err(DOCUMENT_LENGTH);
    } else {
        let lo = b.output_first_position as u64 + 2;
        let hi = b.output_first_position as u64 + b.output_count as u64 + 1;
        if (n as u64) < lo || (n as u64) > hi {
            return Err(DOCUMENT_LENGTH);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ DPD2

/// The fields of the DPD2 preimage (spec §6.1) that are not read from PT2S.
pub struct Dpd2<'a> {
    pub position_count: u32,
    pub segment_count: u16,
    pub family_count: u16,
    pub rs1_height: u8,
    pub compiler_version: u8,
    pub total_entries: u64,
    pub terms: &'a [u8],
    pub binding: &'a [u8],
    pub clause12_v4: &'a [u8],
    pub definition_sha256: &'a [u8],
    pub base_digests: &'a [u8],
    pub model_root: &'a [u8],
    pub position_table_root: &'a [u8],
    pub prompt_commitment: &'a [u8],
    pub registry: &'a [u8],
    pub registry_table_root: &'a [u8],
    pub dfs2_sha256: &'a [u8; 32],
}

impl Dpd2<'_> {
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DPD2_BYTES);
        out.extend_from_slice(DESCRIPTOR_DOMAIN);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.push(1); // ROOT_ONLY
        out.push(3); // commitment version 3
        out.extend_from_slice(&self.position_count.to_le_bytes());
        out.extend_from_slice(&self.segment_count.to_le_bytes());
        out.extend_from_slice(&self.family_count.to_le_bytes());
        out.push(self.rs1_height);
        out.push(self.compiler_version);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.total_entries.to_le_bytes());
        for part in [
            self.terms,
            self.binding,
            self.clause12_v4,
            self.definition_sha256,
            self.base_digests,
            self.model_root,
            self.position_table_root,
            self.prompt_commitment,
        ] {
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&EPOCH.to_le_bytes());
        out.extend_from_slice(self.registry);
        out.extend_from_slice(self.registry_table_root);
        out.extend_from_slice(self.dfs2_sha256);
        out
    }
    pub fn digest(&self) -> [u8; 32] {
        hash::sha256(&[&self.preimage()])
    }
}

impl Dpd2<'_> {
    /// Revision 8's preimage (spec §1): the `/5` domain, `unified_version = 3`
    /// and the two widened records, 755 bytes. **Nothing else in the preimage
    /// moves** -- the field order and every other value are revision 7's.
    pub fn preimage_v8(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DPD2_BYTES_V8);
        out.extend_from_slice(DESCRIPTOR_DOMAIN_V8);
        out.extend_from_slice(&UNIFIED_VERSION_V8.to_le_bytes());
        out.push(1); // ROOT_ONLY
        out.push(3); // commitment version 3
        out.extend_from_slice(&self.position_count.to_le_bytes());
        out.extend_from_slice(&self.segment_count.to_le_bytes());
        out.extend_from_slice(&self.family_count.to_le_bytes());
        out.push(self.rs1_height);
        out.push(self.compiler_version);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.total_entries.to_le_bytes());
        for part in [
            self.terms,
            self.binding,
            self.clause12_v4,
            self.definition_sha256,
            self.base_digests,
            self.model_root,
            self.position_table_root,
            self.prompt_commitment,
        ] {
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&EPOCH.to_le_bytes());
        out.extend_from_slice(self.registry);
        out.extend_from_slice(self.registry_table_root);
        out.extend_from_slice(self.dfs2_sha256);
        out
    }
    pub fn digest_v8(&self) -> [u8; 32] {
        hash::sha256(&[&self.preimage_v8()])
    }
}

// ------------------------------------------------------------------ DCM2 v5 access

/// A DCM2 v5 at its PDA (580). With `descriptor` the PDA and header
/// descriptor must be that one; `writable` requires the account writable.
#[cfg(feature = "revision-7")]
pub fn document(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: Option<&[u8; 32]>,
    writable: bool,
    code: u32,
) -> Result<[u8; 32], ProgramError> {
    let raw = account.try_borrow_data()?;
    if account.owner != program
        || (writable && !account.is_writable)
        || raw.len() != DCM2_V6_BYTES
        || raw[..4] != *b"DCM2"
        || u16_at(&raw, 4, code)? != 6
        || u16_at(&raw, 6, code)? & (FLAG_ROOT_ONLY | FLAG_SEALED) != FLAG_ROOT_ONLY | FLAG_SEALED
    {
        return Err(no(code));
    }
    let d = d32(&raw, 8, code)?;
    if descriptor.is_some_and(|want| *want != d) || *account.key != document_address(program, &d).0
    {
        return Err(no(code));
    }
    Ok(d)
}

#[cfg(feature = "revision-8")]
pub fn document(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: Option<&[u8; 32]>,
    writable: bool,
    code: u32,
) -> Result<[u8; 32], ProgramError> {
    document_v8(program, account, descriptor, writable, code)
}

/// The DCM2 version at the account's PDA (owner, magic and `version:u16`
/// only). The reader split of spec §0: a handler asks which record it is
/// holding and takes that record's path, so no version is ever read out of
/// bytes that do not exist.
#[cfg(feature = "revision-7")]
pub fn revision(program: &Pubkey, account: &AccountInfo, code: u32) -> Result<u16, ProgramError> {
    let raw = account.try_borrow_data()?;
    if account.owner != program || raw.len() < 6 || raw[..4] != *b"DCM2" {
        return Err(no(code));
    }
    Ok(u16_at(&raw, 4, code)?)
}

#[cfg(feature = "revision-8")]
pub fn revision(program: &Pubkey, account: &AccountInfo, code: u32) -> Result<u16, ProgramError> {
    document_v8(program, account, None, false, code)?;
    Ok(7)
}

/// A DCM2 v7 at its PDA, the ROOT_ONLY and sealed bits set, and its header
/// descriptor equal to `descriptor` when one is named. The record's length is
/// checked against **its own** `option_count` claim at DRB1 v2 byte 151, so a
/// truncated or padded header is a malformed record rather than a silently
/// shorter one.
pub fn document_v8(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: Option<&[u8; 32]>,
    writable: bool,
    code: u32,
) -> Result<[u8; 32], ProgramError> {
    document_v8_inner(program, account, descriptor, writable, code, None)
}

/// The close uses the bump committed at init so an attacker cannot search
/// descriptors for a costly `find_program_address` path.
pub fn document_v8_with_bump(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: Option<&[u8; 32]>,
    writable: bool,
    code: u32,
    bump: u8,
) -> Result<[u8; 32], ProgramError> {
    document_v8_inner(program, account, descriptor, writable, code, Some(bump))
}

fn document_v8_inner(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: Option<&[u8; 32]>,
    writable: bool,
    code: u32,
    bump: Option<u8>,
) -> Result<[u8; 32], ProgramError> {
    let raw = account.try_borrow_data()?;
    let option_end = raw
        .get(BINDING_AT_V8 + 151)
        .and_then(|count| 4usize.checked_mul(*count as usize))
        .and_then(|options| OPTION_REGION_AT.checked_add(options));
    let identity_end = option_end.and_then(|end| end.checked_add(APP_IDENTITY_BYTES));
    let app_identity_present = option_end.is_some_and(|end| raw.len() == end + APP_IDENTITY_BYTES);
    let identity_valid = !app_identity_present
        || identity_end.is_some_and(|end| {
            raw.get(end - APP_IDENTITY_BYTES..end)
                .is_some_and(|identity| identity[..4] == *b"ARI1" && identity[36..] == [0; 28])
        });
    if account.owner != program
        || (writable && !account.is_writable)
        || raw.len() < OPTION_REGION_AT
        || raw[..4] != *b"DCM2"
        || u16_at(&raw, 4, code)? != 7
        || u16_at(&raw, 6, code)? & (FLAG_ROOT_ONLY | FLAG_SEALED) != FLAG_ROOT_ONLY | FLAG_SEALED
        || raw[PDA_BUMPS_RESERVED_AT..84] != [0; 2]
        || !(option_end == Some(raw.len()) || app_identity_present)
        || !identity_valid
    {
        return Err(no(code));
    }
    let d = d32(&raw, 8, code)?;
    let expected = if let Some(bump) = bump {
        Pubkey::create_program_address(&[address::DOCUMENT_SEED, &d, &[bump]], program)
            .map_err(|_| no(code))?
    } else {
        document_address(program, &d).0
    };
    if descriptor.is_some_and(|want| *want != d)
        || *account.key != expected
        || bump.is_some_and(|b| raw[DCM2_BUMP_AT] != b)
    {
        return Err(no(code));
    }
    Ok(d)
}

/// App-level ARI1 captured by UnifiedInit. Its digest commits the application
/// id/version and the complete static form-binding table; the binding-specific
/// suffix in each DCR1 ARI1 is filled at the challenged fix-point.
pub fn application_identity_v8(
    raw: &[u8],
) -> Result<Option<[u8; APP_IDENTITY_BYTES]>, ProgramError> {
    let option_count = *raw.get(BINDING_AT_V8 + 151).ok_or(no(DCR1_BAD))? as usize;
    let option_bytes = 4usize.checked_mul(option_count).ok_or(no(DCR1_BAD))?;
    let option_end = OPTION_REGION_AT
        .checked_add(option_bytes)
        .ok_or(no(DCR1_BAD))?;
    if raw.len() == option_end {
        return Ok(None);
    }
    if raw.len() != option_end + APP_IDENTITY_BYTES {
        return Err(no(DCR1_BAD));
    }
    let identity: [u8; APP_IDENTITY_BYTES] = raw[option_end..option_end + APP_IDENTITY_BYTES]
        .try_into()
        .map_err(|_| no(DCR1_BAD))?;
    if identity[..4] != *b"ARI1" || identity[36..] != [0; 28] {
        return Err(no(DCR1_BAD));
    }
    Ok(Some(identity))
}

/// The peak count byte of a DCM2 v7 (528), and its peaks at `PEAKS_AT_V8`.
pub fn read_peaks_v8(doc: &[u8]) -> Result<Vec<Peak>, ProgramError> {
    let n = doc[528] as usize;
    if n > PEAK_SLOTS {
        return Err(no(CL_MALFORMED));
    }
    (0..n)
        .map(|i| {
            let at = PEAKS_AT_V8 + PEAK_BYTES * i;
            Ok(Peak {
                level: doc[at],
                first: u32_at(doc, at + 4, CL_MALFORMED)?,
                digest: d32(doc, at + 8, CL_MALFORMED)?,
            })
        })
        .collect()
}

/// DPR2 of a v5 document: PDA, header, `P`; its length may still be growing.
pub fn positions(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    p_count: u32,
    writable: bool,
    code: u32,
) -> ProgramResult {
    let raw = account.try_borrow_data()?;
    if account.owner != program
        || (writable && !account.is_writable)
        || *account.key != position_page_address(program, descriptor).0
        || raw.len() < DPR2_HEADER
        || raw.len() > DPR2_HEADER + 32 * p_count as usize
        || raw[..4] != *b"DPR2"
        || u16_at(&raw, 4, code)? != 1
        || u16_at(&raw, 6, code)? != 0
        || raw[8..40] != *descriptor
        || u32_at(&raw, 40, code)? != p_count
        || u32_at(&raw, 44, code)? > p_count
    {
        return Err(no(code));
    }
    Ok(())
}

/// The close uses the DPR2 bump stored by UnifiedInit.
pub fn positions_with_bump(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    p_count: u32,
    writable: bool,
    code: u32,
    bump: u8,
) -> ProgramResult {
    positions_inner(
        program,
        account,
        descriptor,
        p_count,
        writable,
        code,
        Some(bump),
    )
}

fn positions_inner(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    p_count: u32,
    writable: bool,
    code: u32,
    bump: Option<u8>,
) -> ProgramResult {
    let raw = account.try_borrow_data()?;
    let expected = if let Some(bump) = bump {
        Pubkey::create_program_address(&[address::POSITIONS_SEED, descriptor, &[bump]], program)
            .map_err(|_| no(code))?
    } else {
        position_page_address(program, descriptor).0
    };
    if account.owner != program
        || (writable && !account.is_writable)
        || *account.key != expected
        || raw.len() < DPR2_HEADER
        || raw.len() > DPR2_HEADER + 32 * p_count as usize
        || raw[..4] != *b"DPR2"
        || u16_at(&raw, 4, code)? != 1
        || u16_at(&raw, 6, code)? != 0
        || raw[8..40] != *descriptor
        || u32_at(&raw, 40, code)? != p_count
        || u32_at(&raw, 44, code)? > p_count
    {
        return Err(no(code));
    }
    Ok(())
}

/// The landed position root of `p` (nonzero), or `code`.
pub fn landed_root(account: &AccountInfo, p: u32, code: u32) -> Result<[u8; 32], ProgramError> {
    let raw = account.try_borrow_data()?;
    let at = DPR2_HEADER + 32 * p as usize;
    if p >= u32_at(&raw, 44, code)? {
        return Err(no(code));
    }
    let root = d32(&raw, at, code)?;
    if root == [0; 32] {
        return Err(no(code));
    }
    Ok(root)
}

// ------------------------------------------------------------------ v3 mountain range

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peak {
    pub level: u8,
    pub first: u32,
    pub digest: [u8; 32],
}

pub fn read_peaks(doc: &[u8]) -> Result<Vec<Peak>, ProgramError> {
    let n = doc[528] as usize;
    if n > PEAK_SLOTS {
        return Err(no(CL_MALFORMED));
    }
    (0..n)
        .map(|i| {
            let at = PEAKS_AT + PEAK_BYTES * i;
            Ok(Peak {
                level: doc[at],
                first: u32_at(doc, at + 4, CL_MALFORMED)?,
                digest: d32(doc, at + 8, CL_MALFORMED)?,
            })
        })
        .collect()
}

/// Append position `count`'s root (fastexec-closure-v3 §3).
pub fn mmr_append(
    descriptor: &[u8; 32],
    count: u32,
    peaks: &mut Vec<Peak>,
    root: &[u8; 32],
) -> Result<(), u32> {
    if count == u32::MAX {
        return Err(CL_OVERFLOW);
    }
    let mut carry = Peak {
        level: 0,
        first: count,
        digest: hash::sha256(&[MMR_LEAF_DOMAIN, descriptor, &count.to_le_bytes(), root]),
    };
    while peaks.last().is_some_and(|p| p.level == carry.level) {
        let left = peaks.pop().unwrap();
        if left.first as u64 + (1u64 << left.level) != carry.first as u64 {
            return Err(CL_MALFORMED);
        }
        let level = carry.level + 1;
        carry = Peak {
            level,
            first: left.first,
            digest: hash::sha256(&[
                MMR_NODE_DOMAIN,
                descriptor,
                &left.first.to_le_bytes(),
                &[level],
                &left.digest,
                &carry.digest,
            ]),
        };
    }
    peaks.push(carry);
    Ok(())
}

/// The v3 prefix root after `count` appends over canonical `peaks`.
pub fn mmr_root(descriptor: &[u8; 32], count: u32, peaks: &[Peak]) -> Result<[u8; 32], u32> {
    if count == 0 || peaks.is_empty() || peaks.len() > PEAK_SLOTS {
        return Err(CL_MALFORMED);
    }
    let mut body = Vec::with_capacity(MMR_DOCUMENT_DOMAIN.len() + 37 + 37 * peaks.len());
    body.extend_from_slice(MMR_DOCUMENT_DOMAIN);
    body.extend_from_slice(descriptor);
    body.extend_from_slice(&count.to_le_bytes());
    body.push(peaks.len() as u8);
    let mut expected = 0u64;
    for p in peaks {
        if p.first as u64 != expected {
            return Err(CL_MALFORMED);
        }
        body.push(p.level);
        body.extend_from_slice(&p.first.to_le_bytes());
        body.extend_from_slice(&p.digest);
        expected += 1u64 << p.level;
    }
    if expected != count as u64 {
        return Err(CL_MALFORMED);
    }
    Ok(hash::sha256(&[&body]))
}

// ------------------------------------------------------------------ tag 161

/// tag 161 UnifiedInit. The reader split is **the terms block's own version
/// field** (spec §0): a revision-8 init carries DDT2 v2 at `data[1..137]`,
/// and anything else -- including a v1 terms block of revision 7's length --
/// is revision 7's path, byte for byte. Revision 8's data is
/// `terms[136] | binding[196] | model_root[32] | position_table_root[32] |
/// prompt_commitment[32] | family_count:u16 | dfs2_body |
/// option_table[4*option_count]`: the option table is appended after the
/// family body because the body is variable-length, and it has to arrive with
/// the instruction that writes DCM2's option region and hashes it into the
/// binding.
#[cfg(feature = "revision-7")]
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn init_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    init_with_manifest(program, accounts, data, hooks, None)
}

pub fn init_with_manifest(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
    manifest: Option<&'static crate::kernel::ApplicationManifest>,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = manifest;
        let _ = hooks;
        init_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        init_v8_with_application(program, accounts, data, hooks, manifest)
    }
}

/// tag 161 UnifiedInit (revision 7). Data: `terms[96] | binding[160] |
/// model_root[32] | position_table_root[32] | prompt_commitment[32] |
/// family_count:u16 | dfs2_body`. Accounts: executor(s,w), DCM2(w), DPR2(w),
/// DFS2(w), system, PT2S, base routes, base geometry, base payloads, DRP2,
/// DEA2, DTA1, DCR2(w). Steps in spec order, first refusal wins.
#[cfg(feature = "revision-7")]
pub fn init_v7(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    const FIXED: usize = 1 + TERMS_BYTES + BINDING_BYTES + 96 + 2;
    if accounts.len() != 13 || data.len() < FIXED {
        return Err(no(CL_MALFORMED));
    }
    let [executor, dcm2, dpr2, dfs2, system, pt2s, routes, geometry, payloads, drp2, dea2, dta1, dcr2] =
        accounts
    else {
        return Err(no(CL_MALFORMED));
    };
    // 1. The PT2S is sealed and its base accounts bind.
    plan::bind_pt2s(program, pt2s, routes, geometry, Some(payloads))?;
    let terms_raw = &data[1..1 + TERMS_BYTES];
    let binding_raw = &data[1 + TERMS_BYTES..1 + TERMS_BYTES + BINDING_BYTES];
    let at = 1 + TERMS_BYTES + BINDING_BYTES;
    let (model, table, prompt) = (
        &data[at..at + 32],
        &data[at + 32..at + 64],
        &data[at + 64..at + 96],
    );
    let family_count = u16_at(data, at + 96, CL_MALFORMED)?;
    let body = &data[FIXED..];
    // 2. The DDT1 block and the anchors.
    let terms = Terms::decode(terms_raw).map_err(no)?;
    if [model, table, prompt].iter().any(|a| **a == [0; 32]) {
        return Err(no(CL_MALFORMED));
    }
    let pt2s_key = pt2s.key.to_bytes();
    let (descriptor, p_count, s_count, h, total, pt2s_sha, reg_root, binding) = {
        let s = pt2s.try_borrow_data()?;
        let (r_bytes, g_bytes) = (routes.try_borrow_data()?, geometry.try_borrow_data()?);
        let x = plan::view(&s, &r_bytes, &g_bytes, &[], None)?;
        let (p_count, s_count) = (x.position_count, x.segment_count);
        let h = rs1_height(p_count);
        // 2a. The DRB1 run binding (794).
        let binding = Binding::decode(binding_raw).map_err(no)?;
        binding.check(executor.key, &x).map_err(no)?;
        if !executor.is_signer {
            return Err(no(RUN_BINDING));
        }
        // 2b. The template-seal approval of this exact PT2S (793).
        let pt2s_sha = hash::sha256(&[&s]);
        super::config::approved(program, dta1, pt2s.key, &pt2s_sha)?;
        // 3. Registry and admission record.
        let reg = registry::frozen(program, drp2, None)?;
        let adm = admission::view(program, dea2, true)?;
        if *dea2.key != address::admission(program, drp2.key, pt2s.key, p_count).0 || !adm.complete
        {
            return Err(no(ADMISSION_STATE));
        }
        if adm.registry != drp2.key.to_bytes() || adm.root != reg.root {
            return Err(no(REGISTRY_ROOT));
        }
        if adm.pt2s != pt2s_key
            || adm.pt2s_sha256 != pt2s_sha
            || adm.position_count != p_count
            || adm.n_max as u64 != x.n_of(p_count - 1)
            || adm.rs1_height != h
        {
            return Err(no(PLAN_BINDING));
        }
        // 4. The DFS2 body and the counts.
        let fams = parse_family_body(body).map_err(no)?;
        check_family_plan(&x, &fams).map_err(no)?;
        if fams.len() != family_count as usize || !(1..=MAX_SEGMENTS).contains(&s_count) {
            return Err(no(PLAN_BINDING));
        }
        // 5. The descriptor from the sealed plan; its PDAs, fresh.
        let version = plan::compiler_version(&x.g).ok_or(no(PLAN_BINDING))?;
        let total = classes::total_entries(&x).map_err(|_| no(PLAN_BINDING))?;
        let digests = &s[S::OFF_DIGESTS..S::OFF_DIGESTS + 96];
        for k in 0..3 {
            if digests[32 * k..32 * (k + 1)] != *x.g.base_digest(k) {
                return Err(no(PLAN_BINDING));
            }
        }
        let dfs2_sha = hash::sha256(&[body]);
        let descriptor = Dpd2 {
            position_count: p_count,
            segment_count: s_count,
            family_count,
            rs1_height: h,
            compiler_version: version,
            total_entries: total,
            terms: terms_raw,
            binding: binding_raw,
            clause12_v4: &s[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
            definition_sha256: &s[S::OFF_DEFINITION..S::OFF_DEFINITION + 32],
            base_digests: digests,
            model_root: model,
            position_table_root: table,
            prompt_commitment: prompt,
            registry: drp2.key.as_ref(),
            registry_table_root: &reg.root,
            dfs2_sha256: &dfs2_sha,
        }
        .digest();
        // Revision 6: a pre-funded target address is topped up by
        // `create_pda`, not refused; only a non-system or non-empty
        // account is (580).
        for (account, key) in [
            (dcm2, document_address(program, &descriptor).0),
            (dpr2, position_page_address(program, &descriptor).0),
            (dfs2, family_slots_address(program, &descriptor).0),
            (dcr2, result_address(program, &descriptor).0),
        ] {
            if *account.key != key
                || !account.data_is_empty()
                || *account.owner != solana_program::system_program::id()
            {
                return Err(no(CL_MALFORMED));
            }
        }
        // 6. The F summary classes.
        let rows_raw = drp2.try_borrow_data()?;
        let row = find_row(&rows_raw[DRP2_HEADER..], registry::FORM_RS1_SUMMARY).map_err(no)?;
        for (_, _, slots) in &fams {
            let shape = summary_shape(&x, slots).map_err(|_| no(PLAN_BINDING))?;
            let code = registry::check(row.as_ref(), &shape);
            if code != 0 {
                return Err(no(code));
            }
        }
        (
            descriptor, p_count, s_count, h, total, pt2s_sha, reg.root, binding,
        )
    };
    let (_, doc_bump) = document_address(program, &descriptor);
    let (_, pos_bump) = position_page_address(program, &descriptor);
    let (_, fam_bump) = family_slots_address(program, &descriptor);
    // 7. Create and write DCM2 v5, DPR2 and DFS2.
    let full_positions = DPR2_HEADER
        .checked_add(
            32usize
                .checked_mul(p_count as usize)
                .ok_or(no(CL_OVERFLOW))?,
        )
        .ok_or(no(CL_OVERFLOW))?;
    let dfs2_size = DFS2_HEADER + body.len();
    registry::create_pda(
        program,
        executor,
        dcm2,
        system,
        &[address::DOCUMENT_SEED, &descriptor, &[doc_bump]],
        DCM2_V6_BYTES,
        DCM2_V6_BYTES,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    registry::create_pda(
        program,
        executor,
        dpr2,
        system,
        &[address::POSITIONS_SEED, &descriptor, &[pos_bump]],
        full_positions.min(CPI_ALLOC),
        full_positions,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    registry::create_pda(
        program,
        executor,
        dfs2,
        system,
        &[address::FAMILY_SLOTS_SEED, &descriptor, &[fam_bump]],
        dfs2_size,
        dfs2_size,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    {
        let mut doc = dcm2.try_borrow_mut_data()?;
        doc[..4].copy_from_slice(b"DCM2");
        doc[4..6].copy_from_slice(&6u16.to_le_bytes());
        doc[6..8].copy_from_slice(&(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED).to_le_bytes());
        doc[8..40].copy_from_slice(&descriptor);
        doc[40..72].copy_from_slice(executor.key.as_ref());
        doc[72..76].copy_from_slice(&p_count.to_le_bytes());
        doc[76..78].copy_from_slice(&s_count.to_le_bytes());
        doc[184..192].copy_from_slice(&terms.challenge_window_slots.to_le_bytes());
        doc[192..200].copy_from_slice(&total.to_le_bytes());
        doc[200..232].copy_from_slice(&pt2s_key);
        doc[232..264].copy_from_slice(&pt2s_sha);
        doc[264..296].copy_from_slice(model);
        doc[296..328].copy_from_slice(table);
        doc[328..360].copy_from_slice(prompt);
        doc[360..392].copy_from_slice(drp2.key.as_ref());
        doc[392..424].copy_from_slice(&reg_root);
        doc[424..456].copy_from_slice(dea2.key.as_ref());
        doc[456..488].copy_from_slice(dfs2.key.as_ref());
        doc[520..524].copy_from_slice(&EPOCH.to_le_bytes());
        doc[524..526].copy_from_slice(&family_count.to_le_bytes());
        doc[526] = h;
        doc[527] = 3;
        doc[529] = if terms.executor_bond_lamports > 0 {
            BOND_HELD
        } else {
            BOND_NONE
        };
        doc[TERMS_AT..TERMS_AT + TERMS_BYTES].copy_from_slice(terms_raw);
        doc[BINDING_AT..BINDING_AT + BINDING_BYTES].copy_from_slice(binding_raw);
    }
    {
        let mut pos = dpr2.try_borrow_mut_data()?;
        pos[..4].copy_from_slice(b"DPR2");
        pos[4..6].copy_from_slice(&1u16.to_le_bytes());
        pos[8..40].copy_from_slice(&descriptor);
        pos[40..44].copy_from_slice(&p_count.to_le_bytes());
    }
    {
        let mut fam = dfs2.try_borrow_mut_data()?;
        fam[..4].copy_from_slice(b"DFS2");
        fam[4..6].copy_from_slice(&1u16.to_le_bytes());
        fam[8..40].copy_from_slice(&descriptor);
        fam[40..42].copy_from_slice(&family_count.to_le_bytes());
        fam[42] = h;
        fam[44..48].copy_from_slice(&(body.len() as u32).to_le_bytes());
        fam[DFS2_HEADER..].copy_from_slice(body);
    }
    // 8. The executor bond, on top of DCM2's rent-exempt minimum.
    if terms.executor_bond_lamports > 0 {
        invoke(
            &system_instruction::transfer(executor.key, dcm2.key, terms.executor_bond_lamports),
            &[executor.clone(), dcm2.clone(), system.clone()],
        )?;
    }
    // 9. The PENDING DCR2 v4 result record.
    super::result::create(
        program,
        executor,
        dcr2,
        system,
        &descriptor,
        terms_raw,
        &binding,
    )?;
    // 10. The INIT event, last.
    events::emit(
        events::INIT,
        &descriptor,
        Body::new()
            .key(executor.key.as_ref())
            .key(&binding.request_id)
            .u32(p_count)
            .u32(binding.output_count)
            .u64(terms.executor_bond_lamports),
    );
    Ok(())
}

/// tag 161 UnifiedInit for revision 8 (spec §1.6's row, §1.1's checks 7-12 and
/// 17-20 and
/// the one 794 beside them, §1's four init relations and the three
/// decision-branch clauses). Steps in spec order, first refusal wins, exactly
/// as revision 7's. **Fourteen metas**: revision 7's thirteen plus **DTU1**
/// (§1.7), whose one `documents + 1` is the last write of the instruction.
#[cfg(feature = "revision-8")]
pub fn init_v8(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    init_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn init_v8_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    init_v8_with_application(program, accounts, data, hooks, None)
}

#[cfg(feature = "revision-8")]
pub fn init_v8_with_application(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
    application: Option<&'static crate::kernel::ApplicationManifest>,
) -> ProgramResult {
    const FIXED: usize = 1 + TERMS_BYTES_V2 + BINDING_BYTES_V8 + 96 + 2;
    if accounts.len() != 14 || data.len() < FIXED {
        return Err(no(CL_MALFORMED));
    }
    let [executor, dcm2, dpr2, dfs2, system, pt2s, routes, geometry, payloads, drp2, dea2, dta1, dcr2, dtu1] =
        accounts
    else {
        return Err(no(CL_MALFORMED));
    };
    // This decision clause cannot depend on the plan. Refuse a result count
    // that can never satisfy finalize before binding or walking any template
    // accounts; Binding2::decode repeats the check for every record reader.
    let binding_at = 1 + TERMS_BYTES_V2;
    let option_count = data[binding_at + 151];
    if option_count as usize > crate::kernels::decision::MAX_OPTIONS_SINGLE {
        return Err(no(RUN_BINDING));
    }
    if option_count != 0 && u32_at(data, binding_at + 140, RUN_BINDING)? != 1 + option_count as u32
    {
        return Err(no(RUN_BINDING));
    }
    // 1. The PT2S is sealed and its base accounts bind.
    plan::bind_pt2s(program, pt2s, routes, geometry, Some(payloads))?;
    let terms_raw = &data[1..1 + TERMS_BYTES_V2];
    let binding_raw = &data[1 + TERMS_BYTES_V2..1 + TERMS_BYTES_V2 + BINDING_BYTES_V8];
    let at = 1 + TERMS_BYTES_V2 + BINDING_BYTES_V8;
    let (model, table, prompt) = (
        &data[at..at + 32],
        &data[at + 32..at + 64],
        &data[at + 64..at + 96],
    );
    let family_count = u16_at(data, at + 96, CL_MALFORMED)?;
    // 2. The DDT2 v2 block and the anchors.
    let terms = Terms2::decode_with(terms_raw, hooks).map_err(no)?;
    if [model, table, prompt].iter().any(|a| **a == [0; 32]) {
        return Err(no(CL_MALFORMED));
    }
    // The one 794 beside the terms decode, against the init signer: a policy
    // whose destination *is* the convict has not disposed of the bond.
    if terms.bond_remainder == executor.key.to_bytes() {
        return Err(no(RUN_BINDING));
    }
    // The DFS2 body, then the option table the binding hashes.
    let (fams_raw, body_len) =
        crate::root_only_sealed::families_prefix(&data[FIXED..]).map_err(|_| no(CL_MALFORMED))?;
    let body = &data[FIXED..FIXED + body_len];
    let options = &data[FIXED + body_len..];
    let pt2s_key = pt2s.key.to_bytes();
    let (
        descriptor,
        p_count,
        s_count,
        h,
        total,
        pt2s_sha,
        reg_root,
        binding,
        documents,
        app_identity,
    ) = {
        let s = pt2s.try_borrow_data()?;
        let (r_bytes, g_bytes) = (routes.try_borrow_data()?, geometry.try_borrow_data()?);
        let x = plan::view(&s, &r_bytes, &g_bytes, &[], None)?;
        let (p_count, s_count) = (x.position_count, x.segment_count);
        let h = rs1_height(p_count);
        // 2a. The DRB1 v2 run binding (794): decode, the option table's hash
        // and length, then the four relations and the three decision clauses
        // against the plan and the template's own locator.
        let binding = Binding2::decode(binding_raw).map_err(no)?;
        binding.check_options(options).map_err(no)?;
        let locator = Locator::read(&s, RUN_BINDING)?;
        binding.check(executor.key, &x, &locator).map_err(no)?;
        if !executor.is_signer {
            return Err(no(RUN_BINDING));
        }
        // 2b. The template-seal approval of this exact PT2S (793).
        let pt2s_sha = hash::sha256(&[&s]);
        super::config::approved(program, dta1, pt2s.key, &pt2s_sha)?;
        // 2c. The template's use counter (spec §1.7): DTU1 is the PDA of
        // `(PT2S, sha256)`, and state 0 is the only state that admits a
        // document -- 1 and 2 (retired, revoked) are 793 and 3 (closed) is 812.
        // The `documents + 1` is a checked add (598), because the field is a
        // `u32` and a template's live count is the one quantity nothing else
        // bounds.
        let (documents, limits) = super::config::template_use(program, dtu1, pt2s.key, &pt2s_sha)?;
        // 2c'. **The per-template limits, checks 17-20 (791).** This is the
        // whole of what DCG enforces about a document's windows: it may not
        // exceed the ones its template's owner published. The four protocol-wide
        // constants this branch carried are withdrawn (user, 2026-09-26), so
        // there is no number here that DCG chose, and the code is 791 because
        // the question is the same one the terms decode above just answered.
        // Check 20 is the load-bearing one: it is what makes the finalize
        // budget's subtraction non-negative at tag 165.
        terms.check_template(&limits).map_err(no)?;
        // 3. Registry and admission record.
        let reg = registry::frozen(program, drp2, None)?;
        let adm = admission::view(program, dea2, true)?;
        if *dea2.key != address::admission(program, drp2.key, pt2s.key, p_count).0 || !adm.complete
        {
            return Err(no(ADMISSION_STATE));
        }
        if adm.registry != drp2.key.to_bytes() || adm.root != reg.root {
            return Err(no(REGISTRY_ROOT));
        }
        if adm.pt2s != pt2s_key
            || adm.pt2s_sha256 != pt2s_sha
            || adm.position_count != p_count
            || adm.n_max as u64 != x.n_of(p_count - 1)
            || adm.rs1_height != h
        {
            return Err(no(PLAN_BINDING));
        }
        let app_identity = if adm.app_bound {
            let application = application.ok_or(no(super::APP_KERNEL_UNAVAILABLE))?;
            application
                .validate()
                .map_err(|_| no(super::APP_KERNEL_UNAVAILABLE))?;
            let mut identity = [0u8; APP_IDENTITY_BYTES];
            identity[..4].copy_from_slice(b"ARI1");
            identity[4..36].copy_from_slice(&application.admission_identity_digest());
            Some(identity)
        } else {
            None
        };
        // 4. The DFS2 body and the counts.
        let fams = parse_families(&fams_raw).map_err(no)?;
        check_family_plan(&x, &fams).map_err(no)?;
        if fams.len() != family_count as usize || !(1..=MAX_SEGMENTS).contains(&s_count) {
            return Err(no(PLAN_BINDING));
        }
        // 5. The `/5` descriptor from the sealed plan; its PDAs, fresh.
        let version = plan::compiler_version(&x.g).ok_or(no(PLAN_BINDING))?;
        let total = classes::total_entries(&x).map_err(|_| no(PLAN_BINDING))?;
        let digests = &s[S::OFF_DIGESTS..S::OFF_DIGESTS + 96];
        for k in 0..3 {
            if digests[32 * k..32 * (k + 1)] != *x.g.base_digest(k) {
                return Err(no(PLAN_BINDING));
            }
        }
        let dfs2_sha = hash::sha256(&[body]);
        let descriptor = Dpd2 {
            position_count: p_count,
            segment_count: s_count,
            family_count,
            rs1_height: h,
            compiler_version: version,
            total_entries: total,
            terms: terms_raw,
            binding: binding_raw,
            clause12_v4: &s[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
            definition_sha256: &s[S::OFF_DEFINITION..S::OFF_DEFINITION + 32],
            base_digests: digests,
            model_root: model,
            position_table_root: table,
            prompt_commitment: prompt,
            registry: drp2.key.as_ref(),
            registry_table_root: &reg.root,
            dfs2_sha256: &dfs2_sha,
        }
        .digest_v8();
        // Revision 6: a pre-funded target address is topped up by
        // `create_pda`, not refused; only a non-system or non-empty
        // account is (580).
        for (account, key) in [
            (dcm2, document_address(program, &descriptor).0),
            (dpr2, position_page_address(program, &descriptor).0),
            (dfs2, family_slots_address(program, &descriptor).0),
            (dcr2, result_address(program, &descriptor).0),
        ] {
            if *account.key != key
                || !account.data_is_empty()
                || *account.owner != solana_program::system_program::id()
            {
                return Err(no(CL_MALFORMED));
            }
        }
        // 6. The F summary classes.
        let rows_raw = drp2.try_borrow_data()?;
        let row = find_row(&rows_raw[DRP2_HEADER..], registry::FORM_RS1_SUMMARY).map_err(no)?;
        for (_, _, slots) in &fams {
            let shape = summary_shape(&x, slots).map_err(|_| no(PLAN_BINDING))?;
            let code = registry::check_with(row.as_ref(), &shape, hooks);
            if code != 0 {
                return Err(no(code));
            }
        }
        (
            descriptor,
            p_count,
            s_count,
            h,
            total,
            pt2s_sha,
            reg.root,
            binding,
            documents,
            app_identity,
        )
    };
    let option_end = OPTION_REGION_AT + 4 * binding.option_count as usize;
    let dcm2_bytes = option_end + app_identity.map_or(0, |_| APP_IDENTITY_BYTES);
    let (_, doc_bump) = document_address(program, &descriptor);
    let (_, pos_bump) = position_page_address(program, &descriptor);
    let (_, fam_bump) = family_slots_address(program, &descriptor);
    let (_, escrow_bump) = address::bond_escrow(program, &descriptor);
    // 7. Create and write DCM2 v7, DPR2 and DFS2.
    let full_positions = DPR2_HEADER
        .checked_add(
            32usize
                .checked_mul(p_count as usize)
                .ok_or(no(CL_OVERFLOW))?,
        )
        .ok_or(no(CL_OVERFLOW))?;
    let dfs2_size = DFS2_HEADER + body.len();
    registry::create_pda(
        program,
        executor,
        dcm2,
        system,
        &[address::DOCUMENT_SEED, &descriptor, &[doc_bump]],
        dcm2_bytes,
        dcm2_bytes,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    registry::create_pda(
        program,
        executor,
        dpr2,
        system,
        &[address::POSITIONS_SEED, &descriptor, &[pos_bump]],
        full_positions.min(CPI_ALLOC),
        full_positions,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    registry::create_pda(
        program,
        executor,
        dfs2,
        system,
        &[address::FAMILY_SLOTS_SEED, &descriptor, &[fam_bump]],
        dfs2_size,
        dfs2_size,
        CL_MALFORMED,
        CL_MALFORMED,
    )?;
    let now = Clock::get()?.slot;
    let dispute_deadline = now
        .checked_add(terms.challenge_window_slots)
        .ok_or(no(CL_OVERFLOW))?;
    let abandon_deadline = terms.abandon_deadline(now).map_err(no)?;
    {
        let mut doc = dcm2.try_borrow_mut_data()?;
        doc[..4].copy_from_slice(b"DCM2");
        doc[4..6].copy_from_slice(&7u16.to_le_bytes());
        doc[6..8].copy_from_slice(&(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED).to_le_bytes());
        doc[8..40].copy_from_slice(&descriptor);
        doc[40..72].copy_from_slice(executor.key.as_ref());
        doc[72..76].copy_from_slice(&p_count.to_le_bytes());
        doc[76..78].copy_from_slice(&s_count.to_le_bytes());
        doc[DCM2_BUMP_AT] = doc_bump;
        doc[DPR2_BUMP_AT] = pos_bump;
        doc[DFS2_BUMP_AT] = fam_bump;
        doc[BOND_ESCROW_BUMP_AT] = escrow_bump;
        // The CHALLENGE deadline, written at init (spec §1.6) and rewritten at
        // finalize; never the anyone-can-close deadline, which is 2,174.
        doc[144..152].copy_from_slice(&dispute_deadline.to_le_bytes());
        doc[184..192].copy_from_slice(&terms.challenge_window_slots.to_le_bytes());
        doc[192..200].copy_from_slice(&total.to_le_bytes());
        doc[200..232].copy_from_slice(&pt2s_key);
        doc[232..264].copy_from_slice(&pt2s_sha);
        doc[264..296].copy_from_slice(model);
        doc[296..328].copy_from_slice(table);
        doc[328..360].copy_from_slice(prompt);
        doc[360..392].copy_from_slice(drp2.key.as_ref());
        doc[392..424].copy_from_slice(&reg_root);
        doc[424..456].copy_from_slice(dea2.key.as_ref());
        doc[456..488].copy_from_slice(dfs2.key.as_ref());
        doc[520..524].copy_from_slice(&EPOCH.to_le_bytes());
        doc[524..526].copy_from_slice(&family_count.to_le_bytes());
        doc[526] = h;
        doc[527] = 3;
        doc[529] = if terms.executor_bond_lamports > 0 {
            BOND_HELD
        } else {
            BOND_NONE
        };
        doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2].copy_from_slice(terms_raw);
        doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8].copy_from_slice(binding_raw);
        // The PRODUCTION deadline (spec §1.3), pushed forward by every landing.
        doc[ABANDON_DEADLINE_AT..ABANDON_DEADLINE_AT + 8]
            .copy_from_slice(&abandon_deadline.to_le_bytes());
        doc[OPTION_REGION_AT..option_end].copy_from_slice(options);
        if let Some(identity) = app_identity {
            doc[option_end..option_end + APP_IDENTITY_BYTES].copy_from_slice(&identity);
        }
    }
    {
        let mut pos = dpr2.try_borrow_mut_data()?;
        pos[..4].copy_from_slice(b"DPR2");
        pos[4..6].copy_from_slice(&1u16.to_le_bytes());
        pos[8..40].copy_from_slice(&descriptor);
        pos[40..44].copy_from_slice(&p_count.to_le_bytes());
    }
    {
        let mut fam = dfs2.try_borrow_mut_data()?;
        fam[..4].copy_from_slice(b"DFS2");
        fam[4..6].copy_from_slice(&1u16.to_le_bytes());
        fam[8..40].copy_from_slice(&descriptor);
        fam[40..42].copy_from_slice(&family_count.to_le_bytes());
        fam[42] = h;
        fam[44..48].copy_from_slice(&(body.len() as u32).to_le_bytes());
        fam[DFS2_HEADER..].copy_from_slice(body);
    }
    // 8. The executor bond, on top of DCM2's rent-exempt minimum.
    if terms.executor_bond_lamports > 0 {
        invoke(
            &system_instruction::transfer(executor.key, dcm2.key, terms.executor_bond_lamports),
            &[executor.clone(), dcm2.clone(), system.clone()],
        )?;
    }
    // 9. The PENDING DCR2 v6 result record.
    super::result::create_v8_with_hooks(
        program,
        executor,
        dcr2,
        system,
        &descriptor,
        terms_raw,
        &binding,
        hooks,
    )?;
    // 9a. DTU1's one increment (spec §1.7). It is the **last** write, after
    // every account this instruction creates exists, so a document can never
    // exist without its template counting it.
    {
        let count = documents.checked_add(1).ok_or(no(CL_OVERFLOW))?;
        dtu1.try_borrow_mut_data()?[8..12].copy_from_slice(&count.to_le_bytes());
    }
    // 10. The INIT event, last: DLE1 v3's 92-byte body.
    events::emit_v8(
        events::INIT,
        &descriptor,
        Body::new()
            .key(executor.key.as_ref())
            .key(&binding.request_id)
            .u32(p_count)
            .u32(binding.output_count)
            .u64(terms.executor_bond_lamports)
            .u32(binding.prompt_positions)
            .u32(binding.stop_plus_one)
            .u8(binding.option_count)
            .u8(terms.bond_policy_kind)
            .pad(2),
    );
    Ok(())
}

// ------------------------------------------------------------------ tag 162

/// tag 162 LandPositionRoots. The reader split is the DCM2 version (spec §0);
/// revision 7's path is unchanged, and revision 8's adds the one difference
/// §1.6 names -- `abandon_deadline := slot + abandon_after_slots`, the
/// push-forward that makes the production window safe to be short. **The v8
/// branch is four metas**, revision 7's three plus DTU1: the clamp's ceiling is
/// the *template's* lifetime limit, and the template is the only place that
/// number lives (the user withdrew the protocol constant, 2026-09-26). The
/// lengths are per revision, so a revision-7 call still presents three.
pub fn land_position_roots(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    land_position_roots_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn land_position_roots_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        if accounts.len() != 3 {
            return Err(no(CL_MALFORMED));
        }
        land_position_roots_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        if accounts.len() != 4 {
            return Err(no(CL_MALFORMED));
        }
        land_position_roots_v8_with_hooks(program, accounts, data, hooks)
    }
}

/// **The template's own limits, for the two deadline writers** (tags 162 and
/// 165). The DTU1 address is derived from **DCM2's own** `PT2S` (200) and
/// `PT2S_sha256` (232), the two fields init wrote from the template it admitted
/// the document under, so a caller cannot substitute another template's limits:
/// the address is not an argument, it is a derivation, and a mismatch is 793
/// from the same view every other DTU1 read uses.
fn document_template_limits(
    program: &Pubkey,
    dtu1: &AccountInfo,
    doc: &[u8],
) -> Result<super::config::TemplateLimits, ProgramError> {
    let pt2s = Pubkey::try_from(&doc[200..232]).map_err(|_| no(CL_MALFORMED))?;
    let digest: [u8; 32] = doc[232..264].try_into().map_err(|_| no(CL_MALFORMED))?;
    super::config::template_limits(program, dtu1, &pt2s, &digest)
}

/// tag 162 LandPositionRoots (revision 7). Data `descriptor[32] | first:u32 |
/// count:u8 | root[count][32]`. Accounts: executor(s), DCM2(w), DPR2(w).
/// Checks in order, first refusal wins, a refusal changes nothing (spec §6.6).
#[cfg(feature = "revision-7")]
pub fn land_position_roots_v7(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // 1. count >= 1 and the exact length.
    if accounts.len() != 3
        || data.len() < 38
        || data[37] == 0
        || data.len() != 38 + 32 * data[37] as usize
    {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    let first = u32_at(data, 33, CL_MALFORMED)?;
    let count = data[37] as u32;
    // 2. PDAs and a v5 header.
    document(program, &accounts[1], Some(&descriptor), true, CL_MALFORMED)?;
    let (p_count, complete, flags, authority) = {
        let doc = accounts[1].try_borrow_data()?;
        (
            u32_at(&doc, 72, CL_MALFORMED)?,
            u32_at(&doc, 84, CL_MALFORMED)?,
            u16_at(&doc, 6, CL_MALFORMED)?,
            d32(&doc, 40, CL_MALFORMED)?,
        )
    };
    positions(
        program,
        &accounts[2],
        &descriptor,
        p_count,
        true,
        CL_MALFORMED,
    )?;
    // 3. signer = DCM2 authority.
    if !accounts[0].is_signer || accounts[0].key.to_bytes() != authority {
        return Err(no(CL_AUTHORITY));
    }
    // 4. not finalized; 5. append order; 6. range; 7. nonzero roots.
    if flags & FLAG_FINAL != 0 {
        return Err(no(CL_AFTER_FINAL));
    }
    if first != complete {
        return Err(no(APPEND_ORDER));
    }
    let end = first as u64 + count as u64;
    if end > p_count as u64 {
        return Err(no(CL_COORDINATE));
    }
    let roots = &data[38..];
    if roots.chunks_exact(32).any(|r| r == [0; 32]) {
        return Err(no(CL_ROOT));
    }
    let mut peaks = read_peaks(&accounts[1].try_borrow_data()?)?;
    for (i, root) in roots.chunks_exact(32).enumerate() {
        mmr_append(
            &descriptor,
            first + i as u32,
            &mut peaks,
            root.try_into().unwrap(),
        )
        .map_err(no)?;
    }
    let prefix = mmr_root(&descriptor, end as u32, &peaks).map_err(no)?;
    let need = DPR2_HEADER + 32 * end as usize;
    if accounts[2].data_len() < need {
        accounts[2].realloc(need, true)?;
    }
    {
        let mut pos = accounts[2].try_borrow_mut_data()?;
        pos[DPR2_HEADER + 32 * first as usize..need].copy_from_slice(roots);
        pos[44..48].copy_from_slice(&(end as u32).to_le_bytes());
    }
    {
        let mut doc = accounts[1].try_borrow_mut_data()?;
        doc[84..88].copy_from_slice(&(end as u32).to_le_bytes());
        doc[152..184].copy_from_slice(&prefix);
        doc[528] = peaks.len() as u8;
        doc[PEAKS_AT..PEAKS_AT + PEAK_BYTES * PEAK_SLOTS].fill(0);
        for (i, p) in peaks.iter().enumerate() {
            let at = PEAKS_AT + PEAK_BYTES * i;
            doc[at] = p.level;
            doc[at + 4..at + 8].copy_from_slice(&p.first.to_le_bytes());
            doc[at + 8..at + 40].copy_from_slice(&p.digest);
        }
    }
    events::emit(
        events::LAND,
        &descriptor,
        Body::new()
            .u32(first)
            .u32(count)
            .u32(end as u32)
            .pad(4)
            .key(&prefix),
    );
    Ok(())
}

/// tag 162 LandPositionRoots (revision 8): revision 7's checks in the same
/// order, the peaks at 562, and the one addition of spec §1.6 -- the
/// production deadline moves to `min(slot + abandon_after_slots, init_slot +
/// lifetime)`, where `lifetime` is **the template's** `max_document_
/// lifetime_slots` read from DTU1. Only the executor signs a landing, so only
/// the executor can push its own deadline, and the ceiling is not the
/// executor's to raise.
#[cfg(feature = "revision-8")]
pub fn land_position_roots_v8(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    land_position_roots_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn land_position_roots_v8_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    // 1. count >= 1 and the exact length.
    if accounts.len() != 4
        || data.len() < 38
        || data[37] == 0
        || data.len() != 38 + 32 * data[37] as usize
    {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    let first = u32_at(data, 33, CL_MALFORMED)?;
    let count = data[37] as u32;
    // 2. PDAs and a v7 header.
    document_v8(program, &accounts[1], Some(&descriptor), true, CL_MALFORMED)?;
    let (p_count, complete, flags, authority) = {
        let doc = accounts[1].try_borrow_data()?;
        (
            u32_at(&doc, 72, CL_MALFORMED)?,
            u32_at(&doc, 84, CL_MALFORMED)?,
            u16_at(&doc, 6, CL_MALFORMED)?,
            d32(&doc, 40, CL_MALFORMED)?,
        )
    };
    positions(
        program,
        &accounts[2],
        &descriptor,
        p_count,
        true,
        CL_MALFORMED,
    )?;
    // 3. signer = DCM2 authority.
    if !accounts[0].is_signer || accounts[0].key.to_bytes() != authority {
        return Err(no(CL_AUTHORITY));
    }
    // 4. not finalized; 5. append order; 6. range; 7. nonzero roots.
    if flags & FLAG_FINAL != 0 {
        return Err(no(CL_AFTER_FINAL));
    }
    if first != complete {
        return Err(no(APPEND_ORDER));
    }
    let end = first as u64 + count as u64;
    if end > p_count as u64 {
        return Err(no(CL_COORDINATE));
    }
    let roots = &data[38..];
    if roots.chunks_exact(32).any(|r| r == [0; 32]) {
        return Err(no(CL_ROOT));
    }
    let mut peaks = read_peaks_v8(&accounts[1].try_borrow_data()?)?;
    for (i, root) in roots.chunks_exact(32).enumerate() {
        mmr_append(
            &descriptor,
            first + i as u32,
            &mut peaks,
            root.try_into().unwrap(),
        )
        .map_err(no)?;
    }
    let prefix = mmr_root(&descriptor, end as u32, &peaks).map_err(no)?;
    let need = DPR2_HEADER + 32 * end as usize;
    if accounts[2].data_len() < need {
        accounts[2].realloc(need, true)?;
    }
    {
        let mut pos = accounts[2].try_borrow_mut_data()?;
        pos[DPR2_HEADER + 32 * first as usize..need].copy_from_slice(roots);
        pos[44..48].copy_from_slice(&(end as u32).to_le_bytes());
    }
    let abandon_deadline = {
        let doc = accounts[1].try_borrow_data()?;
        let terms = Terms2::decode_with(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2], hooks)
            .map_err(no)?;
        // The clamp of §1.3 (ii)(c), and `init_slot` derived as §1.3's
        // invariant paragraph states: `dispute_deadline − challenge_window`,
        // read from the record **before** this write. A landing is refused 592
        // when flag 2 is set, so the 144 this reads is the one init wrote.
        let window = u64_at(&doc, 184, CL_MALFORMED)?;
        let init_slot =
            Terms2::init_slot(u64_at(&doc, 144, CL_MALFORMED)?, window).ok_or(no(CL_MALFORMED))?;
        // The ceiling is the template's own lifetime limit, and the read is the
        // last check before the writes: it is 793 on a template record that is
        // not the one this document was admitted under, and it deliberately
        // ignores `state` (§1.7), because a document under a retired template
        // must still be able to land.
        let limits = document_template_limits(program, &accounts[3], &doc)?;
        terms
            .clamped_abandon_deadline(
                Clock::get()?.slot,
                init_slot,
                limits.max_document_lifetime_slots,
            )
            .map_err(no)?
    };
    {
        let mut doc = accounts[1].try_borrow_mut_data()?;
        doc[84..88].copy_from_slice(&(end as u32).to_le_bytes());
        doc[152..184].copy_from_slice(&prefix);
        doc[528] = peaks.len() as u8;
        doc[PEAKS_AT_V8..PEAKS_AT_V8 + PEAK_BYTES * PEAK_SLOTS].fill(0);
        for (i, p) in peaks.iter().enumerate() {
            let at = PEAKS_AT_V8 + PEAK_BYTES * i;
            doc[at] = p.level;
            doc[at + 4..at + 8].copy_from_slice(&p.first.to_le_bytes());
            doc[at + 8..at + 40].copy_from_slice(&p.digest);
        }
        doc[ABANDON_DEADLINE_AT..ABANDON_DEADLINE_AT + 8]
            .copy_from_slice(&abandon_deadline.to_le_bytes());
    }
    events::emit_v8(
        events::LAND,
        &descriptor,
        Body::new()
            .u32(first)
            .u32(count)
            .u32(end as u32)
            .pad(4)
            .key(&prefix),
    );
    Ok(())
}

// ------------------------------------------------------------------ tag 165

/// tag 165 FinalizeDocumentV5. The reader split is the DCM2 version; revision
/// 8's data gains the document length `n` (spec §1.6):
/// `descriptor[32] | n:u32 | F:u16 | root_f[F][32]`, `39 + 32F` bytes.
pub fn finalize(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    finalize_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn finalize_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        if accounts.len() != 3 {
            return Err(no(CL_MALFORMED));
        }
        finalize_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        if accounts.len() != 4 {
            return Err(no(CL_MALFORMED));
        }
        finalize_v8_with_hooks(program, accounts, data, hooks)
    }
}

/// tag 165 FinalizeDocumentV5 (revision 7). Data `descriptor[32] | F:u16 |
/// root_f[F][32]` in DFS2 family order. Accounts: executor(s), DCM2(w),
/// DCR2(w). Stores only the family table digest; `document_root :=
/// prefix_root`; DCR2 v4 40, 168 and 176 receive the root, the finalize slot
/// and the deadline.
#[cfg(feature = "revision-7")]
pub fn finalize_v7(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if accounts.len() != 3 || data.len() < 35 {
        return Err(no(CL_MALFORMED));
    }
    let f = u16_at(data, 33, CL_MALFORMED)? as usize;
    if data.len() != 35 + 32 * f {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    document(program, &accounts[1], Some(&descriptor), true, CL_MALFORMED)?;
    super::result::view(program, &accounts[2], &descriptor, true)?;
    let doc = accounts[1].try_borrow_data()?;
    if !accounts[0].is_signer || accounts[0].key.as_ref() != &doc[40..72] {
        return Err(no(CL_AUTHORITY));
    }
    let flags = u16_at(&doc, 6, CL_MALFORMED)?;
    if flags & FLAG_FINAL != 0 {
        return Err(no(CL_AFTER_FINAL));
    }
    if u32_at(&doc, 84, CL_MALFORMED)? != u32_at(&doc, 72, CL_MALFORMED)? {
        return Err(no(CL_MISSING));
    }
    if f != u16_at(&doc, 524, CL_MALFORMED)? as usize {
        return Err(no(CL_MALFORMED));
    }
    let roots = &data[35..];
    if roots.chunks_exact(32).any(|r| r == [0; 32]) {
        return Err(no(CL_ROOT));
    }
    super::result::check_for_finalize(program, &accounts[2], &doc, &descriptor)?;
    let now = Clock::get()?.slot;
    let window = u64_at(&doc, 184, CL_MALFORMED)?;
    let deadline = now.checked_add(window).ok_or(no(CL_OVERFLOW))?;
    let prefix = d32(&doc, 152, CL_MALFORMED)?;
    let total = u64_at(&doc, 192, CL_MALFORMED)?;
    let digest = family_table_digest(&descriptor, roots);
    drop(doc);
    {
        let mut doc = accounts[1].try_borrow_mut_data()?;
        doc[6..8].copy_from_slice(&(flags | FLAG_FINAL).to_le_bytes());
        doc[88..96].copy_from_slice(&total.to_le_bytes());
        doc[96..128].copy_from_slice(&prefix);
        doc[136..144].copy_from_slice(&now.to_le_bytes());
        doc[144..152].copy_from_slice(&deadline.to_le_bytes());
        doc[488..520].copy_from_slice(&digest);
    }
    {
        let mut out = accounts[2].try_borrow_mut_data()?;
        out[40..72].copy_from_slice(&prefix);
        out[168..176].copy_from_slice(&now.to_le_bytes());
        out[176..184].copy_from_slice(&deadline.to_le_bytes());
    }
    events::emit(
        events::FINALIZE,
        &descriptor,
        Body::new().key(&prefix).key(&digest).u64(deadline),
    );
    Ok(())
}

/// tag 165 FinalizeDocumentV5 (revision 8). Data `descriptor[32] | n:u32 |
/// F:u16 | root_f[F][32]`. Checks, in order (spec §1.6): exact length and PDAs
/// (580); signer = authority (582); not finalized (592); **`now <
/// abandon_deadline` (736)**; the attest budget of §1.3 (ii)(b) (736);
/// `positions_complete = n` (591); the two-case `L` of 816; `F` = DCM2 524
/// (580); every root nonzero (583); DCR2 v6 is PENDING, open, and mirrors DCM2
/// (580).
///
/// **Four metas**: revision 7's three plus **DTU1**. The two 736s and the
/// deadline this instruction writes are all measured against **the template's**
/// `max_document_lifetime_slots`, which is not in DCM2 (its length is frozen at
/// `2,182 + 4·option_count` and every offset is named in five places) and not a
/// constant (the user withdrew the protocol constant, 2026-09-26), so the
/// template is the one place the number can be read from and the reader derives
/// its address from DCM2 rather than taking it as an argument.
///
/// **The two 736s and the read order they need.** Every value the checks and
/// the writes derive is read from the record **as it stands before finalize's
/// own write**, because finalize is the only writer of both 144 and 2,174 and
/// there is no second finalize (592). So `init_slot := DCM2[144] − DCM2[184]`
/// is the init slot, and the two 736s read `abandon_deadline` (2,174) and the
/// clock. Read in the other order — rewrite 144 first, then clamp — an
/// implementation would get `finalize_slot + lifetime` and open row 3 at a
/// different slot, which is the consensus-sensitive mistake the round-5 Medium 1
/// names.
#[cfg(feature = "revision-8")]
pub fn finalize_v8(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    finalize_v8_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn finalize_v8_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    if accounts.len() != 4 || data.len() < 39 {
        return Err(no(CL_MALFORMED));
    }
    let f = u16_at(data, 37, CL_MALFORMED)? as usize;
    if data.len() != 39 + 32 * f {
        return Err(no(CL_MALFORMED));
    }
    let descriptor = d32(data, 1, CL_MALFORMED)?;
    let n = u32_at(data, 33, CL_MALFORMED)?;
    document_v8(program, &accounts[1], Some(&descriptor), true, CL_MALFORMED)?;
    let binding = {
        let doc = accounts[1].try_borrow_data()?;
        Binding2::decode(&doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8]).map_err(no)?
    };
    super::result::view_v8(program, &accounts[2], &descriptor, true)?;
    let doc = accounts[1].try_borrow_data()?;
    if !accounts[0].is_signer || accounts[0].key.as_ref() != &doc[40..72] {
        return Err(no(CL_AUTHORITY));
    }
    let flags = u16_at(&doc, 6, CL_MALFORMED)?;
    if flags & FLAG_FINAL != 0 {
        return Err(no(CL_AFTER_FINAL));
    }
    // The two deadline rules, both 736, both read before the write.
    let (now, new_abandon) = {
        let terms = Terms2::decode_with(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2], hooks)
            .map_err(no)?;
        let window = u64_at(&doc, 184, CL_MALFORMED)?;
        let init_slot =
            Terms2::init_slot(u64_at(&doc, 144, CL_MALFORMED)?, window).ok_or(no(CL_MALFORMED))?;
        let now = Clock::get()?.slot;
        // The template's lifetime limit, from the DTU1 this document was admitted
        // under. `state` is not read (§1.7): a document under a retired template
        // must still be able to finalize, or its rent is stranded by a
        // retirement rather than protected by one.
        let lifetime_max =
            document_template_limits(program, &accounts[3], &doc)?.max_document_lifetime_slots;
        // (b) rule 1: a document that has sat past its own production window
        // is no longer producible. It is closable on row 2 by anyone, with its
        // rent and its bond returned, so the refusal costs the executor
        // nothing — and it is what makes `finalize_slot <= init_slot +
        // lifetime` a bound rather than a hope.
        if now >= u64_at(&doc, ABANDON_DEADLINE_AT, CL_MALFORMED)? {
            return Err(no(CL_DEADLINE));
        }
        // (b) rule 2: a finalize that would leave less than a full attestation
        // budget is refused. The budget is `abandon_after_slots` from here, so
        // the clamp must not bind: `now <= init_slot + lifetime -
        // abandon_after_slots`. Check 20 keeps `abandon_after_slots` at or below
        // the template's lifetime limit, so the subtraction cannot go negative
        // (it is a checked one, and answers 791 rather than underflowing).
        // Refusing is strictly better for the executor than allowing it: the
        // alternative finalizes a document whose attestations cannot finish
        // before row 3 convicts it WITHHELD, and the row-2 close returns the
        // bond and the rent with no cause at all.
        if now
            > terms
                .attest_budget_ceiling(init_slot, lifetime_max)
                .map_err(no)?
        {
            return Err(no(CL_DEADLINE));
        }
        (
            now,
            terms
                .clamped_abandon_deadline(now, init_slot, lifetime_max)
                .map_err(no)?,
        )
    };
    if u32_at(&doc, 84, CL_MALFORMED)? != n {
        return Err(no(CL_MISSING));
    }
    // 816: the document length, both branches.
    check_document_length(&binding, n, u32_at(&doc, 72, CL_MALFORMED)?).map_err(no)?;
    if f != u16_at(&doc, 524, CL_MALFORMED)? as usize {
        return Err(no(CL_MALFORMED));
    }
    let roots = &data[39..];
    if roots.chunks_exact(32).any(|r| r == [0; 32]) {
        return Err(no(CL_ROOT));
    }
    super::result::check_for_finalize_v8_with_hooks(
        program,
        &accounts[2],
        &doc,
        &descriptor,
        &binding,
        hooks,
    )?;
    let window = u64_at(&doc, 184, CL_MALFORMED)?;
    let deadline = now.checked_add(window).ok_or(no(CL_OVERFLOW))?;
    let prefix = d32(&doc, 152, CL_MALFORMED)?;
    // `entries_complete`: the capacity-level total, copied from DCM2 192, which
    // is what revision 7's finalize writes and what this revision's own golden
    // carries at `n = 500`. Spec §1.3's field row says
    // `sum of entry_count(p) for p < n`, and that sum is **not computable**
    // here: tag 165's frozen account list is executor, DCM2 and DCR2, and none
    // of them carries the plan whose `entry_count` the sum is over. The prose
    // is the defect and the emitter now says `DCM2[192]`; the rule that was
    // *meant* — "the entries the document commits" — holds under both
    // readings, because the capacity-level total is the same number the
    // position table commits for the whole capacity.
    let total = u64_at(&doc, 192, CL_MALFORMED)?;
    let digest = family_table_digest(&descriptor, roots);
    drop(doc);
    {
        let mut doc = accounts[1].try_borrow_mut_data()?;
        // Flag 2 in the same write that records `n`: one source of truth, and
        // the bit every reader asks for (591 when clear).
        doc[6..8].copy_from_slice(&(flags | FLAG_FINAL).to_le_bytes());
        doc[88..96].copy_from_slice(&total.to_le_bytes());
        doc[96..128].copy_from_slice(&prefix);
        doc[136..144].copy_from_slice(&now.to_le_bytes());
        doc[144..152].copy_from_slice(&deadline.to_le_bytes());
        doc[488..520].copy_from_slice(&digest);
        // The **last** write of the production deadline, exactly once (spec
        // §1.3 (ii)(b)), clamped (c). The refusal above guarantees the clamp
        // does not bind, so this is `finalize_slot + abandon_after_slots`, and
        // `abandon_deadline` is still readable for the assertion below.
        doc[ABANDON_DEADLINE_AT..ABANDON_DEADLINE_AT + 8]
            .copy_from_slice(&new_abandon.to_le_bytes());
    }
    {
        let mut out = accounts[2].try_borrow_mut_data()?;
        out[40..72].copy_from_slice(&prefix);
        out[168..176].copy_from_slice(&now.to_le_bytes());
        out[176..184].copy_from_slice(&deadline.to_le_bytes());
        out[212..216].copy_from_slice(&n.to_le_bytes());
    }
    // The FINALIZE event last: DLE1 v3's 80-byte body.
    events::emit_v8(
        events::FINALIZE,
        &descriptor,
        Body::new()
            .key(&prefix)
            .key(&digest)
            .u64(deadline)
            .u32(n)
            .pad(4),
    );
    Ok(())
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use crate::unified::classes::tests::{golden, hex, rung_d, unhex, view, FAMILY_BODY};

    fn d(v: &serde_json::Value) -> [u8; 32] {
        unhex(v.as_str().unwrap()).try_into().unwrap()
    }

    #[test]
    fn relation_four_uses_one_position_for_a_decision_and_count_positions_for_completion() {
        let base = Binding2 {
            executor: [1; 32],
            request_id: [1; 32],
            consumer_digest: [1; 32],
            seed: [0; 32],
            output_first_position: 29,
            output_count: 50,
            output_base_entry: 0,
            output_write: 0,
            output_width: 4,
            decision_flags: 0,
            option_count: 0,
            prompt_positions: 30,
            stop_plus_one: 0,
            option_table_offset: 0,
            option_table_sha256: [0; 32],
        };
        let completion = base;
        assert!(completion.fits_position_capacity(80));
        assert!(!completion.fits_position_capacity(79));
        let decision = Binding2 {
            output_first_position: 29,
            output_count: 81,
            output_width: DECISION_WIDTH,
            decision_flags: DECISION_MODE,
            option_count: 80,
            option_table_offset: OPTION_REGION_AT as u16,
            option_table_sha256: [1; 32],
            ..base
        };
        assert!(decision.fits_position_capacity(30));
        assert!(!decision.fits_position_capacity(29));
        assert!(decision.fits_position_capacity(80));
    }

    #[test]
    fn revision8_option_table_checks_hash_then_logits_id_range() {
        let mut options = 17u32.to_le_bytes().to_vec();
        let binding = Binding2 {
            executor: [1; 32],
            request_id: [1; 32],
            consumer_digest: [1; 32],
            seed: [0; 32],
            output_first_position: 0,
            output_count: 2,
            output_base_entry: 0,
            output_write: 0,
            output_width: DECISION_WIDTH,
            decision_flags: DECISION_MODE,
            option_count: 1,
            prompt_positions: 1,
            stop_plus_one: 0,
            option_table_offset: OPTION_REGION_AT as u16,
            option_table_sha256: hash::sha256(&[&options]),
        };
        assert_eq!(binding.check_options(&options), Ok(()));
        let duplicate_options = [17u32.to_le_bytes(), 17u32.to_le_bytes()].concat();
        let duplicate_binding = Binding2 {
            option_count: 2,
            output_count: 3,
            option_table_sha256: hash::sha256(&[&duplicate_options]),
            ..binding
        };
        assert_eq!(
            duplicate_binding.check_options(&duplicate_options),
            Ok(()),
            "duplicate option ids preserve their slots and are not canonicalized away"
        );
        options
            .copy_from_slice(&(crate::kernels::decision::LOGITS_ROW_LENGTH as u32).to_le_bytes());
        let out_of_range = Binding2 {
            option_table_sha256: hash::sha256(&[&options]),
            ..binding
        };
        assert_eq!(
            out_of_range.check_options(&options),
            Err(crate::kernels::decision::ERR_OPTION_RANGE)
        );
        assert_eq!(
            binding.check_options(&17u32.to_le_bytes()),
            Ok(()),
            "length and hash still bind the exact table"
        );
        let wrong_hash = Binding2 {
            option_table_sha256: [9; 32],
            ..binding
        };
        assert_eq!(
            wrong_hash.check_options(&17u32.to_le_bytes()),
            Err(RUN_BINDING)
        );
        assert_eq!(binding.check_options(&[]), Err(RUN_BINDING));
    }

    /// The 631-byte DPD2 preimage and its digest reproduce the golden (the
    /// DRB1 and DDT1 vectors, the real rung-D plan fields).
    #[test]
    fn dpd2_preimage_and_digest_match_the_golden() {
        let g = golden();
        let f = &g["dpd2"]["fields"];
        let terms = unhex(g["ddt2"]["default_hex"].as_str().unwrap());
        let binding = unhex(g["drb1"]["hex"].as_str().unwrap());
        let body = unhex(FAMILY_BODY);
        let base: Vec<u8> = f["base_digests"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|v| unhex(v.as_str().unwrap()))
            .collect();
        let (model, table, prompt) = (
            d(&f["model_root"]),
            d(&f["position_table_root"]),
            d(&f["prompt_commitment"]),
        );
        let (registry, root) = (d(&f["registry"]), d(&f["registry_table_root"]));
        let clause12 = unhex(f["clause12_v4"].as_str().unwrap());
        let definition = d(&f["definition_sha256"]);
        let dfs2_sha = crate::hash::sha256(&[&body]);
        let p = Dpd2 {
            position_count: f["position_count"].as_u64().unwrap() as u32,
            segment_count: f["segment_count"].as_u64().unwrap() as u16,
            family_count: f["family_count"].as_u64().unwrap() as u16,
            rs1_height: 7,
            compiler_version: f["compiler_version"].as_u64().unwrap() as u8,
            total_entries: f["total_entries"].as_u64().unwrap(),
            terms: &terms,
            binding: &binding,
            clause12_v4: &clause12,
            definition_sha256: &definition,
            base_digests: &base,
            model_root: &model,
            position_table_root: &table,
            prompt_commitment: &prompt,
            registry: &registry,
            registry_table_root: &root,
            dfs2_sha256: &dfs2_sha,
        };
        let pre = p.preimage();
        assert_eq!(pre.len(), DPD2_BYTES);
        assert_eq!(hex(&pre), g["dpd2"]["preimage"].as_str().unwrap());
        assert_eq!(hex(&p.digest()), g["dpd2"]["digest"].as_str().unwrap());
    }

    /// DRB1 decodes (the rung-D TOKEN writer, 51 outputs of 16 bytes) and its
    /// plan check admits it; every §12 DRB1 cheat refuses 794.
    #[test]
    fn drb1_decodes_and_refuses_cheats() {
        let g = golden();
        let raw = unhex(g["drb1"]["hex"].as_str().unwrap());
        let b = Binding::decode(&raw).unwrap();
        assert_eq!(
            (
                b.output_base_entry,
                b.output_count,
                b.output_first_position,
                b.output_width
            ),
            (28_037, 51, 29, 16)
        );
        let flip = |at: usize, v: u8| {
            let mut r = raw.clone();
            r[at] = v;
            Binding::decode(&r)
        };
        assert_eq!(flip(0, b'X'), Err(RUN_BINDING));
        assert_eq!(flip(4, 2), Err(RUN_BINDING));
        assert_eq!(flip(6, 1), Err(RUN_BINDING));
        assert_eq!(flip(159, 1), Err(RUN_BINDING));
        assert_eq!(flip(149, 0), Err(RUN_BINDING));
        assert_eq!(flip(149, 33), Err(RUN_BINDING));
        let mut zero_exec = raw.clone();
        zero_exec[8..40].fill(0);
        assert_eq!(Binding::decode(&zero_exec), Err(RUN_BINDING));
        let mut no_digest = raw.clone();
        no_digest[72..104].fill(0);
        assert_eq!(Binding::decode(&no_digest), Err(RUN_BINDING));
        let mut no_request = raw.clone();
        no_request[40..72].fill(0);
        assert_eq!(Binding::decode(&no_request), Err(RUN_BINDING));
        let mut none = raw.clone();
        none[40..104].fill(0);
        assert!(
            Binding::decode(&none).is_ok(),
            "no consumer (both zero) is admitted"
        );
        let mut zero_out = raw.clone();
        zero_out[140..144].fill(0);
        assert_eq!(Binding::decode(&zero_out), Err(RUN_BINDING));
        let mut huge = raw.clone();
        huge[140..144].copy_from_slice(&700_000u32.to_le_bytes());
        assert_eq!(Binding::decode(&huge), Err(RUN_BINDING), "DCR2 over 10 MiB");
        let Some(r) = rung_d() else {
            eprintln!("SKIP: rung-D PT2P artifacts absent");
            return;
        };
        let x = view(&r);
        let signer = Pubkey::new_from_array(b.executor);
        assert_eq!(b.check(&signer, &x), Ok(()));
        assert_eq!(
            b.check(&Pubkey::new_from_array([3; 32]), &x),
            Err(RUN_BINDING),
            "executor != signer"
        );
        let past = Binding {
            output_count: 52,
            ..b
        };
        assert_eq!(past.check(&signer, &x), Err(RUN_BINDING), "outputs past P");
        let wide = Binding {
            output_width: 8,
            ..b
        };
        assert_eq!(
            wide.check(&signer, &x),
            Err(RUN_BINDING),
            "width differs from the write"
        );
        let retired = (0..x.base_entries).find(|&o| x.is_replaced(o)).unwrap();
        assert_eq!(
            Binding {
                output_base_entry: retired,
                ..b
            }
            .check(&signer, &x),
            Err(RUN_BINDING)
        );
        assert_eq!(
            Binding {
                output_write: 9,
                ..b
            }
            .check(&signer, &x),
            Err(RUN_BINDING)
        );
    }

    /// The v3 mountain range over the golden position roots reproduces every
    /// prefix root, including the batch ends of the landing vector.
    #[test]
    fn mmr_reproduces_the_golden_prefix_roots() {
        let g = golden();
        let descriptor = d(&g["dpd2"]["digest"]);
        let roots: Vec<[u8; 32]> = g["dcm2_v6"]["position_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(d)
            .collect();
        let prefixes: Vec<[u8; 32]> = g["dcm2_v6"]["prefix_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(d)
            .collect();
        let mut peaks = Vec::new();
        for (i, root) in roots.iter().enumerate() {
            mmr_append(&descriptor, i as u32, &mut peaks, root).unwrap();
            assert_eq!(
                mmr_root(&descriptor, i as u32 + 1, &peaks).unwrap(),
                prefixes[i],
                "prefix {i}"
            );
        }
        for row in g["land"]["prefix_at_batch"].as_array().unwrap() {
            let n = row[0].as_u64().unwrap() as usize;
            assert_eq!(hex(&prefixes[n - 1]), row[1].as_str().unwrap());
        }
        let roots_hex: Vec<u8> = g["dfs2"]["family_roots"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|v| unhex(v.as_str().unwrap()))
            .collect();
        assert_eq!(
            hex(&family_table_digest(&descriptor, &roots_hex)),
            g["dfs2"]["family_table_digest"].as_str().unwrap()
        );
    }

    /// DFS2 bodies: the rev7 table parses; §12's cheats refuse 785.
    #[test]
    fn dfs2_body_rules() {
        let body = unhex(FAMILY_BODY);
        assert_eq!(parse_family_body(&body).unwrap().len(), 16);
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(parse_family_body(&trailing).err(), Some(PLAN_BINDING));
        let mut swapped = body.clone();
        swapped[2] = 5;
        assert_eq!(parse_family_body(&swapped).err(), Some(PLAN_BINDING));
        // An empty slot list (family 0 with slot_count 0) refuses.
        let mut empty = body.clone();
        empty[6..8].copy_from_slice(&0u16.to_le_bytes());
        empty.drain(8..13);
        assert_eq!(parse_family_body(&empty).err(), Some(PLAN_BINDING));
        // A repeated slot refuses (family 0 given two equal slots).
        let mut repeated = body.clone();
        repeated[6..8].copy_from_slice(&2u16.to_le_bytes());
        let slot = repeated[8..13].to_vec();
        repeated.splice(13..13, slot);
        assert_eq!(parse_family_body(&repeated).err(), Some(PLAN_BINDING));
        let Some(r) = rung_d() else {
            eprintln!("SKIP: rung-D PT2P artifacts absent");
            return;
        };
        let x = view(&r);
        let fams = parse_family_body(&body).unwrap();
        assert_eq!(check_family_plan(&x, &fams), Ok(()));
        let mut region = body.clone();
        region[4] ^= 1;
        let fams = parse_family_body(&region).unwrap();
        assert_eq!(check_family_plan(&x, &fams), Err(PLAN_BINDING));
    }
}
