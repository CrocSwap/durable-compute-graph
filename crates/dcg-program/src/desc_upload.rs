//! Descriptor identity by address (lifecycle spec §3, dispatches 5.1 + 5.1b).
//!
//! Chunk arithmetic, PDA derivation, the resumable clause fold, the tag 5–8
//! instruction decodes, the 576-byte `DCD1` record per amendment A1
//! (`dcd1_layout_v1.tsv`, normative where the prose disagrees), and the
//! account-mutating handlers (`DescriptorOpen` creating `DCD1`,
//! `DescriptorAlloc` growing chunks, `DescriptorUpload` advancing the cursor
//! and the fold, `DescriptorFinish` setting the flags), wired in `lib.rs`.
//!
//! Refusal codes 310–328 live in [`crate::descriptor::err`], the one
//! registry, mirrored by `src/basanos/dcg/errors.py`. Of those, the pure
//! checks in this module raise 312, 313, 314, 315, 318 and 320, and the
//! handlers raise 311, 316, 317, 318, 319, 320, 321, 322, 326, 327 and 328.
//! Codes 323–325 are `Execute`'s chunk admission (dispatch 5.3); 310 retires
//! tag 1 outright (spec §3.4 "always refuses": v1's single-shot
//! `DescriptorSeal` no longer exists — see `lib.rs`), which removes the
//! image's only seal path until the seal transition (dispatch 5.2) lands.
//!
//! Two rules the handlers satisfy by construction rather than by refusal:
//! 313 has no carrier (no tag 5–8 field holds a `chunk_count`; `Open`
//! computes it), and 314 needs the finished digest (unknowable until
//! `Finish` recomputes it), so a wrong chunk address uploads fine and dies
//! at 321 — the spec's own "a liar's upload completes and then fails at
//! 321". 314 fires on chain at `Execute` (dispatch 5.3).

use solana_program::pubkey::Pubkey;

use crate::descriptor::{
    err, DcgError, BODY_START, CLAUSE_COUNT, DESC_FRAME_BYTES, DIRECTORY_ENTRY_BYTES,
    GRAMMAR_VERSION, HEADER_BYTES, TAG_CLAUSE, TAG_CLAUSE_FRAME, TAG_DESCRIPTOR, TAG_HEADER,
};
use crate::hash::{sha256, Parts};

// ---------------------------------------------------------------------------
// Constants. Pinned by tests/golden/dcg/lifecycle/constants_v1.tsv.
// ---------------------------------------------------------------------------

/// Seed of the `DCD1` index account: `["dcg-desc-index", descriptor_digest]`.
pub const SEED_DESC_INDEX: &[u8] = b"dcg-desc-index";
/// Seed of chunk `i`: `["dcg-desc", descriptor_digest, i:u16le]`.
pub const SEED_DESC_CHUNK: &[u8] = b"dcg-desc";

/// `DCD1` account size. The layout of these bytes is the spec gap named
/// above; only the size is pinned.
pub const DCD1_BYTES: usize = 576;
/// One descriptor chunk account. Fixed, so there is no chunk table.
pub const DESC_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
/// `chunk_count = ceil(total_bytes / DESC_CHUNK_BYTES)` lies in `1..=512`
/// for every admissible `total_bytes`.
pub const MAX_DESC_CHUNK_ACCOUNTS: u16 = 512;
/// `total_bytes` is a `u32` in `[BODY_START, 2^32)`: the registry's
/// `MAX_DESCRIPTOR_BYTES` is the top of the `u32` range.
pub const MAX_DESCRIPTOR_BYTES: u64 = u32::MAX as u64;
/// One CPI `create_account`/`allocate` step, `solana_program`'s
/// `MAX_PERMITTED_DATA_INCREASE`. Chunks are created and grown in steps of
/// at most this many bytes.
pub const MAX_CPI_ALLOCATION_BYTES: u64 = 10 * 1024;
/// `Execute` admits at most this many descriptor chunk accounts (§3.5).
pub const MAX_EXEC_DESC_CHUNKS: usize = 4;

pub const TAG_DESCRIPTOR_OPEN: u8 = 5;
pub const TAG_DESCRIPTOR_ALLOC: u8 = 6;
pub const TAG_DESCRIPTOR_UPLOAD: u8 = 7;
pub const TAG_DESCRIPTOR_FINISH: u8 = 8;

/// `[5] | total_bytes:u32 | descriptor_id[32] | grammar_version:u16`, exact.
pub const OPEN_INSTRUCTION_BYTES: usize = 1 + 4 + 32 + 2;
/// `[6] | chunk_index:u16 | grow_bytes:u32`, exact.
pub const ALLOC_INSTRUCTION_BYTES: usize = 1 + 2 + 4;
/// `[7] | offset:u64 | length:u32 | bytes`, exact.
pub const UPLOAD_HEADER_BYTES: usize = 1 + 8 + 4;
/// `[8]`, exact: `DescriptorFinish` takes no fields.
pub const FINISH_INSTRUCTION_BYTES: usize = 1;

// ---------------------------------------------------------------------------
// Chunk arithmetic. No table anywhere: index, address and exact length are
// arithmetic over total_bytes (§3.3).
// ---------------------------------------------------------------------------

/// `total_bytes` admissible for `DescriptorOpen` (312): `[BODY_START, 2^32)`.
#[inline]
pub fn check_total_bytes(total_bytes: u32) -> Result<(), DcgError> {
    if (total_bytes as usize) < BODY_START || (total_bytes as u64) > MAX_DESCRIPTOR_BYTES {
        return Err(DcgError(err::DESC_TOTAL_BYTES));
    }
    Ok(())
}

/// `ceil(total_bytes / DESC_CHUNK_BYTES)`, in `1..=512` on admissible input.
#[inline]
pub fn chunk_count(total_bytes: u32) -> u16 {
    let total = total_bytes as u64;
    ((total + DESC_CHUNK_BYTES - 1) / DESC_CHUNK_BYTES) as u16
}

/// The `DescriptorOpen` field must be the arithmetic one (313).
#[inline]
pub fn check_chunk_count(total_bytes: u32, chunk_count: u16) -> Result<(), DcgError> {
    if chunk_count != self::chunk_count(total_bytes) {
        return Err(DcgError(err::DESC_CHUNK_COUNT));
    }
    Ok(())
}

/// First byte of chunk `index`.
#[inline]
pub fn chunk_start(chunk_index: u16) -> u64 {
    chunk_index as u64 * DESC_CHUNK_BYTES
}

/// Exact length of chunk `index`: `min(8 MiB, total - start)` (315).
#[inline]
pub fn chunk_len(total_bytes: u32, chunk_index: u16) -> u64 {
    core::cmp::min(
        DESC_CHUNK_BYTES,
        total_bytes as u64 - chunk_start(chunk_index),
    )
}

/// Which chunk `offset` falls in.
#[inline]
pub fn chunk_index_at(offset: u64) -> u16 {
    (offset / DESC_CHUNK_BYTES) as u16
}

// ---------------------------------------------------------------------------
// PDA derivation. Canonical bump only, as provision::resolve_address refuses
// one (PROVISION_BUMP_NOT_CANONICAL = 279); a caller-supplied non-canonical
// bump derives a different address and is refused here as 314.
// ---------------------------------------------------------------------------

/// Seed tuple for the `DCD1` index, without the bump.
///
/// Injective in the digest by construction: the digest sits in a fixed-width
/// field after a fixed prefix, so two documents never share a seed preimage
/// and a shared address would be a SHA-256 collision.
pub fn desc_index_seeds(descriptor_digest: &[u8; 32]) -> ([u8; 14], [u8; 32]) {
    let mut prefix = [0u8; 14];
    prefix.copy_from_slice(SEED_DESC_INDEX);
    (prefix, *descriptor_digest)
}

/// Seed tuple for chunk `index`, without the bump. Injective in
/// `(digest, index)` the same way: the index sits in a fixed two-byte field.
pub fn desc_chunk_seeds(
    descriptor_digest: &[u8; 32],
    chunk_index: u16,
) -> ([u8; 8], [u8; 32], [u8; 2]) {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(SEED_DESC_CHUNK);
    (prefix, *descriptor_digest, chunk_index.to_le_bytes())
}

/// Address of chunk `index` under an explicit bump, or `None` on-curve.
pub fn create_desc_chunk_address(
    program_id: &Pubkey,
    descriptor_digest: &[u8; 32],
    chunk_index: u16,
    bump: u8,
) -> Option<Pubkey> {
    let (prefix, digest, index) = desc_chunk_seeds(descriptor_digest, chunk_index);
    let bump_seed = [bump];
    Pubkey::create_program_address(&[&prefix, &digest, &index, &bump_seed], program_id).ok()
}

/// Canonical address and bump of chunk `index`.
pub fn find_desc_chunk_address(
    program_id: &Pubkey,
    descriptor_digest: &[u8; 32],
    chunk_index: u16,
) -> (Pubkey, u8) {
    let (prefix, digest, index) = desc_chunk_seeds(descriptor_digest, chunk_index);
    Pubkey::find_program_address(&[&prefix, &digest, &index], program_id)
}

/// Address of the `DCD1` index under an explicit bump, or `None` on-curve.
pub fn create_desc_index_address(
    program_id: &Pubkey,
    descriptor_digest: &[u8; 32],
    bump: u8,
) -> Option<Pubkey> {
    let (prefix, digest) = desc_index_seeds(descriptor_digest);
    let bump_seed = [bump];
    Pubkey::create_program_address(&[&prefix, &digest, &bump_seed], program_id).ok()
}

/// Canonical address and bump of the `DCD1` index.
pub fn find_desc_index_address(program_id: &Pubkey, descriptor_digest: &[u8; 32]) -> (Pubkey, u8) {
    let (prefix, digest) = desc_index_seeds(descriptor_digest);
    Pubkey::find_program_address(&[&prefix, &digest], program_id)
}

/// The chunk account passed to `DescriptorAlloc`/`DescriptorUpload` is at
/// `PDA("dcg-desc", digest, index:u16le)` (314). Returns the canonical bump.
pub fn check_chunk_address(
    program_id: &Pubkey,
    descriptor_digest: &[u8; 32],
    chunk_index: u16,
    account: &Pubkey,
) -> Result<u8, DcgError> {
    let (derived, bump) = find_desc_chunk_address(program_id, descriptor_digest, chunk_index);
    if derived != *account {
        return Err(DcgError(err::DESC_CHUNK_ADDRESS));
    }
    Ok(bump)
}

// ---------------------------------------------------------------------------
// Upload and alloc spans. The cursor-equality rule (317), the sealed rule
// (319), the after-upload geometry freeze (316) and the authority rule (326)
// read DCD1 and belong to the blocked handlers; the overrun (318) and
// chunk-span (320) rules are pure over (offset, length, total).
// ---------------------------------------------------------------------------

/// Which chunk an `(offset, length)` write lands in. Refuses an overrun
/// (318) and a write crossing a chunk boundary or spanning chunks (320).
pub fn check_upload_span(offset: u64, length: u32, total_bytes: u32) -> Result<u16, DcgError> {
    let end = offset
        .checked_add(length as u64)
        .ok_or(DcgError(err::DESC_UPLOAD_OVERRUN))?;
    if end > total_bytes as u64 {
        return Err(DcgError(err::DESC_UPLOAD_OVERRUN));
    }
    if length == 0 {
        // Zero-length writes change nothing and fold nothing; they land in
        // the chunk the cursor names.
        return Ok(chunk_index_at(offset.min(total_bytes as u64)));
    }
    let first = chunk_index_at(offset);
    if chunk_index_at(end - 1) != first {
        return Err(DcgError(err::DESC_UPLOAD_SPAN));
    }
    Ok(first)
}

/// Growing chunk `index` from `current_len` by `grow_bytes` must land at or
/// below the arithmetic exact length (315). Overshoot can never become
/// exact, so it is refused now rather than at finish.
pub fn check_alloc_growth(
    total_bytes: u32,
    chunk_index: u16,
    current_len: u64,
    grow_bytes: u32,
) -> Result<u64, DcgError> {
    let exact = chunk_len(total_bytes, chunk_index);
    let grown = current_len
        .checked_add(grow_bytes as u64)
        .ok_or(DcgError(err::DESC_CHUNK_SIZE))?;
    if grown > exact {
        return Err(DcgError(err::DESC_CHUNK_SIZE));
    }
    Ok(grown)
}

// ---------------------------------------------------------------------------
// The resumable clause fold (§3.2). Frames are 1,024 bytes from the start of
// the clause; the carried state is exactly (clause_index:u8, frame_index:u32,
// running[32]). A frame never straddles a clause boundary, so each clause
// folds independently and the upload that completes a frame folds it once,
// in order, out of the bytes just written.
// ---------------------------------------------------------------------------

/// Fold state of one clause. `pending` holds the incomplete frame between
/// uploads; on chain this state (37 bytes of cursors plus at most 1,023
/// pending bytes) is what `DCD1` must persist across transactions — the
/// persistence is the blocked part, the fold math is here.
pub struct ClauseFold {
    clause_id: u16,
    clause_len: u32,
    frame_index: u32,
    running: [u8; 32],
    pending: [u8; DESC_FRAME_BYTES],
    pending_len: usize,
    consumed: u32,
}

impl ClauseFold {
    /// `running_0 = H(tag | id:u16le | length:u32le)`.
    pub fn new(clause_id: u16, clause_len: u32) -> Self {
        let running = sha256(&[
            TAG_CLAUSE_FRAME,
            &clause_id.to_le_bytes(),
            &clause_len.to_le_bytes(),
        ]);
        Self {
            clause_id,
            clause_len,
            frame_index: 0,
            running,
            pending: [0u8; DESC_FRAME_BYTES],
            pending_len: 0,
            consumed: 0,
        }
    }

    /// Bytes consumed so far.
    #[inline]
    pub fn consumed(&self) -> u32 {
        self.consumed
    }

    /// Feed uploaded bytes, folding every frame the write completes.
    pub fn feed(&mut self, mut bytes: &[u8]) {
        // Complete the pending partial frame first.
        if self.pending_len > 0 && !bytes.is_empty() {
            let take = core::cmp::min(DESC_FRAME_BYTES - self.pending_len, bytes.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            self.consumed += take as u32;
            bytes = &bytes[take..];
            if self.pending_len == DESC_FRAME_BYTES {
                self.fold_full_frame();
            }
        }
        // Whole frames straight out of the write.
        while bytes.len() >= DESC_FRAME_BYTES {
            let (frame, rest) = bytes.split_at(DESC_FRAME_BYTES);
            self.fold_frame(frame);
            self.consumed += DESC_FRAME_BYTES as u32;
            bytes = rest;
        }
        // The short tail waits for the next write (or `finish`).
        if !bytes.is_empty() {
            self.pending[..bytes.len()].copy_from_slice(bytes);
            self.pending_len = bytes.len();
            self.consumed += bytes.len() as u32;
        }
    }

    fn fold_full_frame(&mut self) {
        let frame = self.pending;
        self.pending_len = 0;
        self.fold_frame(&frame);
    }

    fn fold_frame(&mut self, frame: &[u8]) {
        let index = self.frame_index.to_le_bytes();
        let length = (frame.len() as u32).to_le_bytes();
        self.running = sha256(&[TAG_CLAUSE_FRAME, &self.running, &index, &length, frame]);
        self.frame_index += 1;
    }

    /// Close the chain: fold the short last frame when the clause length
    /// leaves one. A zero-length clause (or a length exactly on a frame
    /// boundary) folds nothing here, matching `clause_frame_chain`.
    pub fn finish(mut self) -> [u8; 32] {
        debug_assert_eq!(self.consumed, self.clause_len, "fold fed past its clause");
        if self.pending_len > 0 {
            let tail = self.pending;
            let length = self.pending_len;
            self.pending_len = 0;
            self.fold_frame(&tail[..length]);
        }
        let _ = self.clause_id;
        self.running
    }
}

/// `header_digest = sha256("basanos/dcg-header/2" | bytes[0..184))`.
pub fn fold_header(header: &[u8]) -> Result<[u8; 32], DcgError> {
    if header.len() != BODY_START {
        return Err(DcgError(err::TRUNCATED));
    }
    Ok(sha256(&[TAG_HEADER, header]))
}

/// The directory's ten `(offset, length)` pairs from the first 184 bytes —
/// what the first upload covering byte 184 captures into `DCD1.clause_end`,
/// so no later upload re-reads chunk 0 for clause boundaries.
pub fn parse_clause_ends(header: &[u8]) -> Result<[(u32, u32); CLAUSE_COUNT], DcgError> {
    if header.len() != BODY_START {
        return Err(DcgError(err::TRUNCATED));
    }
    let mut ends = [(0u32, 0u32); CLAUSE_COUNT];
    let mut cursor = BODY_START as u32;
    for index in 0..CLAUSE_COUNT {
        let base = HEADER_BYTES + index * DIRECTORY_ENTRY_BYTES;
        if u16::from_le_bytes([header[base], header[base + 1]]) as usize != index + 1 {
            return Err(DcgError(err::CLAUSE_ORDER));
        }
        if header[base + 2] != 0 || header[base + 3] != 0 {
            return Err(DcgError(err::NONZERO_RESERVED));
        }
        let offset = u32::from_le_bytes([
            header[base + 4],
            header[base + 5],
            header[base + 6],
            header[base + 7],
        ]);
        let length = u32::from_le_bytes([
            header[base + 8],
            header[base + 9],
            header[base + 10],
            header[base + 11],
        ]);
        if offset != cursor {
            return Err(DcgError(err::CLAUSE_LAYOUT));
        }
        cursor = offset
            .checked_add(length)
            .ok_or(DcgError(err::CLAUSE_LAYOUT))?;
        ends[index] = (offset, length);
    }
    Ok(ends)
}

// ---------------------------------------------------------------------------
// Instruction decodes. Byte layouts are §3.4, exact-EOF throughout, in the
// idiom of Instruction::decode. Malformed framing is InvalidInstructionData,
// as in lib.rs; refusal codes attach to rules, not to framing.
// ---------------------------------------------------------------------------

use solana_program::program_error::ProgramError;

/// `DescriptorOpen [5] | total_bytes:u32 | descriptor_id[32] |
/// grammar_version:u16`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenArgs {
    pub total_bytes: u32,
    pub descriptor_id: [u8; 32],
    pub grammar_version: u16,
}

/// `DescriptorAlloc [6] | chunk_index:u16 | grow_bytes:u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocArgs {
    pub chunk_index: u16,
    pub grow_bytes: u32,
}

/// `DescriptorUpload [7] | offset:u64 | length:u32 | bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadArgs<'a> {
    pub offset: u64,
    pub bytes: &'a [u8],
}

pub fn decode_open(data: &[u8]) -> Result<OpenArgs, ProgramError> {
    if data.len() != OPEN_INSTRUCTION_BYTES || data[0] != TAG_DESCRIPTOR_OPEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let total_bytes = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let mut descriptor_id = [0u8; 32];
    descriptor_id.copy_from_slice(&data[5..37]);
    let grammar_version = u16::from_le_bytes([data[37], data[38]]);
    Ok(OpenArgs {
        total_bytes,
        descriptor_id,
        grammar_version,
    })
}

pub fn decode_alloc(data: &[u8]) -> Result<AllocArgs, ProgramError> {
    if data.len() != ALLOC_INSTRUCTION_BYTES || data[0] != TAG_DESCRIPTOR_ALLOC {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(AllocArgs {
        chunk_index: u16::from_le_bytes([data[1], data[2]]),
        grow_bytes: u32::from_le_bytes([data[3], data[4], data[5], data[6]]),
    })
}

pub fn decode_upload(data: &[u8]) -> Result<UploadArgs<'_>, ProgramError> {
    if data.len() < UPLOAD_HEADER_BYTES || data[0] != TAG_DESCRIPTOR_UPLOAD {
        return Err(ProgramError::InvalidInstructionData);
    }
    let offset = u64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let length = u32::from_le_bytes([data[9], data[10], data[11], data[12]]) as usize;
    if data.len() != UPLOAD_HEADER_BYTES + length {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(UploadArgs {
        offset,
        bytes: &data[UPLOAD_HEADER_BYTES..],
    })
}

/// `DescriptorFinish [8]`: the tag alone, exact-EOF.
pub fn decode_finish(data: &[u8]) -> Result<(), ProgramError> {
    if data.len() != FINISH_INSTRUCTION_BYTES || data[0] != TAG_DESCRIPTOR_FINISH {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

/// `GRAMMAR_VERSION` the v2 upload path speaks. `DescriptorOpen` carries the
/// version as an instruction field; comparing it to this constant is the
/// `DescriptorOpen` handler's 328 check below.
pub fn open_grammar_version() -> u16 {
    GRAMMAR_VERSION
}

// ---------------------------------------------------------------------------
// The `DCD1` record (amendment A1, dispatch 5.1b). Every offset is
// `dcd1_layout_v1.tsv`, normative wherever the prose disagrees; every
// integer is little-endian; every reserved byte is zero forever. The
// `descriptor_digest` is deliberately NOT a field: it is the seed of this
// account's own address, checked by `DescriptorFinish` (321).
// ---------------------------------------------------------------------------

/// `DCD1` magic.
pub const DCD1_MAGIC: [u8; 4] = *b"DCD1";
/// `DCD1.version`, and the only document `grammar_version` admitted.
pub const DCD1_VERSION: u16 = 2;
/// `DCD1.flags` bit 0: `DescriptorFinish` succeeded.
pub const DCD1_FLAG_FINISHED: u16 = 1;
/// `DCD1.flags` bit 1: the chunk bytes are immutable forever.
pub const DCD1_FLAG_FROZEN: u16 = 2;

/// Field offsets into the 576-byte record, in `dcd1_layout_v1.tsv` order.
pub const DCD1_OFF_MAGIC: usize = 0;
pub const DCD1_OFF_VERSION: usize = 4;
pub const DCD1_OFF_FLAGS: usize = 6;
pub const DCD1_OFF_TOTAL_BYTES: usize = 8;
pub const DCD1_OFF_CHUNK_COUNT: usize = 12;
pub const DCD1_OFF_DOC_FLAGS: usize = 14;
pub const DCD1_OFF_UPLOAD_CURSOR: usize = 16;
pub const DCD1_OFF_FOLD_FRAME_INDEX: usize = 24;
pub const DCD1_OFF_FOLD_CLAUSE_CONSUMED: usize = 28;
pub const DCD1_OFF_DESCRIPTOR_ID: usize = 32;
pub const DCD1_OFF_AUTHORITY: usize = 64;
pub const DCD1_OFF_HEADER_DIGEST: usize = 96;
pub const DCD1_OFF_FOLD_RUNNING: usize = 128;
pub const DCD1_OFF_CLAUSE_END: usize = 160;
pub const DCD1_OFF_FOLD_CLAUSE: usize = 200;
pub const DCD1_OFF_RESERVED0: usize = 201;
pub const DCD1_OFF_CLAUSE_DIGEST: usize = 208;
pub const DCD1_OFF_RESERVED1: usize = 528;

/// The owned `DCD1` record. Decode is exact: 576 bytes, the magic, the
/// version, and zero reserved spans, or the account is not a `DCD1` this
/// program wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dcd1 {
    pub flags: u16,
    pub total_bytes: u32,
    pub chunk_count: u16,
    pub doc_flags: u16,
    pub upload_cursor: u64,
    pub fold_frame_index: u32,
    pub fold_clause_consumed: u32,
    pub descriptor_id: [u8; 32],
    pub authority: [u8; 32],
    pub header_digest: [u8; 32],
    pub fold_running: [u8; 32],
    pub clause_end: [u32; CLAUSE_COUNT],
    pub fold_clause: u8,
    pub clause_digest: [[u8; 32]; CLAUSE_COUNT],
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn bytes32_at(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[offset..offset + 32]);
    out
}

impl Dcd1 {
    /// A fresh record as `DescriptorOpen` writes it: geometry, identity and
    /// authority set, every cursor and every digest zero.
    pub fn init(total_bytes: u32, descriptor_id: [u8; 32], authority: [u8; 32]) -> Self {
        Self {
            flags: 0,
            total_bytes,
            chunk_count: chunk_count(total_bytes),
            doc_flags: 0,
            upload_cursor: 0,
            fold_frame_index: 0,
            fold_clause_consumed: 0,
            descriptor_id,
            authority,
            header_digest: [0u8; 32],
            fold_running: [0u8; 32],
            clause_end: [0u32; CLAUSE_COUNT],
            fold_clause: 0,
            clause_digest: [[0u8; 32]; CLAUSE_COUNT],
        }
    }

    /// Exact decode of the 576-byte image. A wrong magic, a wrong version or
    /// a nonzero reserved span is an account this program did not write;
    /// `DescriptorOpen` reports that shape as 311 (the derived address is
    /// program-owned or absent), and the other handlers never see it.
    pub fn decode(bytes: &[u8]) -> Result<Self, DcgError> {
        if bytes.len() != DCD1_BYTES {
            return Err(DcgError(err::DESC_OPEN_EXISTS));
        }
        if bytes[DCD1_OFF_MAGIC..DCD1_OFF_MAGIC + 4] != DCD1_MAGIC {
            return Err(DcgError(err::DESC_OPEN_EXISTS));
        }
        if u16_at(bytes, DCD1_OFF_VERSION) != DCD1_VERSION {
            return Err(DcgError(err::DESC_OPEN_EXISTS));
        }
        if bytes[DCD1_OFF_RESERVED0..DCD1_OFF_RESERVED0 + 7] != [0u8; 7]
            || bytes[DCD1_OFF_RESERVED1..DCD1_OFF_RESERVED1 + 48] != [0u8; 48]
        {
            return Err(DcgError(err::DESC_OPEN_EXISTS));
        }
        let mut clause_end = [0u32; CLAUSE_COUNT];
        for (index, end) in clause_end.iter_mut().enumerate() {
            *end = u32_at(bytes, DCD1_OFF_CLAUSE_END + index * 4);
        }
        let mut clause_digest = [[0u8; 32]; CLAUSE_COUNT];
        for (index, digest) in clause_digest.iter_mut().enumerate() {
            *digest = bytes32_at(bytes, DCD1_OFF_CLAUSE_DIGEST + index * 32);
        }
        Ok(Self {
            flags: u16_at(bytes, DCD1_OFF_FLAGS),
            total_bytes: u32_at(bytes, DCD1_OFF_TOTAL_BYTES),
            chunk_count: u16_at(bytes, DCD1_OFF_CHUNK_COUNT),
            doc_flags: u16_at(bytes, DCD1_OFF_DOC_FLAGS),
            upload_cursor: u64_at(bytes, DCD1_OFF_UPLOAD_CURSOR),
            fold_frame_index: u32_at(bytes, DCD1_OFF_FOLD_FRAME_INDEX),
            fold_clause_consumed: u32_at(bytes, DCD1_OFF_FOLD_CLAUSE_CONSUMED),
            descriptor_id: bytes32_at(bytes, DCD1_OFF_DESCRIPTOR_ID),
            authority: bytes32_at(bytes, DCD1_OFF_AUTHORITY),
            header_digest: bytes32_at(bytes, DCD1_OFF_HEADER_DIGEST),
            fold_running: bytes32_at(bytes, DCD1_OFF_FOLD_RUNNING),
            clause_end,
            fold_clause: bytes[DCD1_OFF_FOLD_CLAUSE],
            clause_digest,
        })
    }

    /// The 576-byte image, byte for byte per `dcd1_layout_v1.tsv`.
    pub fn encode(&self) -> [u8; DCD1_BYTES] {
        let mut out = [0u8; DCD1_BYTES];
        out[DCD1_OFF_MAGIC..DCD1_OFF_MAGIC + 4].copy_from_slice(&DCD1_MAGIC);
        out[DCD1_OFF_VERSION..DCD1_OFF_VERSION + 2].copy_from_slice(&DCD1_VERSION.to_le_bytes());
        out[DCD1_OFF_FLAGS..DCD1_OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        out[DCD1_OFF_TOTAL_BYTES..DCD1_OFF_TOTAL_BYTES + 4]
            .copy_from_slice(&self.total_bytes.to_le_bytes());
        out[DCD1_OFF_CHUNK_COUNT..DCD1_OFF_CHUNK_COUNT + 2]
            .copy_from_slice(&self.chunk_count.to_le_bytes());
        out[DCD1_OFF_DOC_FLAGS..DCD1_OFF_DOC_FLAGS + 2]
            .copy_from_slice(&self.doc_flags.to_le_bytes());
        out[DCD1_OFF_UPLOAD_CURSOR..DCD1_OFF_UPLOAD_CURSOR + 8]
            .copy_from_slice(&self.upload_cursor.to_le_bytes());
        out[DCD1_OFF_FOLD_FRAME_INDEX..DCD1_OFF_FOLD_FRAME_INDEX + 4]
            .copy_from_slice(&self.fold_frame_index.to_le_bytes());
        out[DCD1_OFF_FOLD_CLAUSE_CONSUMED..DCD1_OFF_FOLD_CLAUSE_CONSUMED + 4]
            .copy_from_slice(&self.fold_clause_consumed.to_le_bytes());
        out[DCD1_OFF_DESCRIPTOR_ID..DCD1_OFF_DESCRIPTOR_ID + 32]
            .copy_from_slice(&self.descriptor_id);
        out[DCD1_OFF_AUTHORITY..DCD1_OFF_AUTHORITY + 32].copy_from_slice(&self.authority);
        out[DCD1_OFF_HEADER_DIGEST..DCD1_OFF_HEADER_DIGEST + 32]
            .copy_from_slice(&self.header_digest);
        out[DCD1_OFF_FOLD_RUNNING..DCD1_OFF_FOLD_RUNNING + 32].copy_from_slice(&self.fold_running);
        for (index, end) in self.clause_end.iter().enumerate() {
            out[DCD1_OFF_CLAUSE_END + index * 4..DCD1_OFF_CLAUSE_END + index * 4 + 4]
                .copy_from_slice(&end.to_le_bytes());
        }
        out[DCD1_OFF_FOLD_CLAUSE] = self.fold_clause;
        for (index, digest) in self.clause_digest.iter().enumerate() {
            out[DCD1_OFF_CLAUSE_DIGEST + index * 32..DCD1_OFF_CLAUSE_DIGEST + index * 32 + 32]
                .copy_from_slice(digest);
        }
        out
    }

    /// `(start, length)` of clause `index` in document space, from the
    /// latched ends. Clause 1 starts at 184; clause `i + 1` at
    /// `clause_end[i]`.
    pub fn clause_span(&self, index: usize) -> (u32, u32) {
        let start = if index == 0 {
            BODY_START as u32
        } else {
            self.clause_end[index - 1]
        };
        (start, self.clause_end[index] - start)
    }

    /// Derived, never stored: `consumed - 1024 * frame_index`, in
    /// `[0, 1024)` always.
    pub fn pending_len(&self) -> u32 {
        self.fold_clause_consumed - DESC_FRAME_BYTES as u32 * self.fold_frame_index
    }

    /// Whether this upload must carry chunk `chunk_index - 1` as read-only
    /// account 3: the cursor sits at a chunk start past zero and the pending
    /// frame's bytes are the tail of the previous chunk (§3.4, amendment A1).
    pub fn needs_carry(&self) -> bool {
        self.upload_cursor > 0
            && self.upload_cursor % DESC_CHUNK_BYTES == 0
            && self.pending_len() != 0
    }

    pub fn finished(&self) -> bool {
        self.flags & DCD1_FLAG_FINISHED != 0
    }

    pub fn frozen(&self) -> bool {
        self.flags & DCD1_FLAG_FROZEN != 0
    }

    /// The descriptor digest, recomputed from the fields `DescriptorFinish`
    /// committed.  This is the SAME number `Descriptor::digest` computes over
    /// the whole document, but it is O(1): the header digest and the ten clause
    /// digests were folded from the uploaded bytes and the index address is
    /// derived from this value, so the digest is what the seal already proved.
    /// R2 (step-5 review §1): every post-seal handler binds by this digest
    /// rather than re-hashing the document.
    pub fn digest(&self) -> [u8; 32] {
        let version = DCD1_VERSION.to_le_bytes();
        let flags = self.doc_flags.to_le_bytes();
        let total = self.total_bytes.to_le_bytes();
        let mut parts = Parts::new();
        parts
            .push(TAG_DESCRIPTOR)
            .push(&version)
            .push(&flags)
            .push(&self.descriptor_id)
            .push(&total)
            .push(&self.header_digest);
        for digest in self.clause_digest.iter() {
            parts.push(digest);
        }
        parts.finish()
    }
}

// ---------------------------------------------------------------------------
// The four handlers (spec §3.4). Each takes the accounts in the spec's
// order; the instruction args arrive decoded. Errors are the registry
// codes, surfaced by `lib.rs` as `Custom(code)`.
// ---------------------------------------------------------------------------

use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};

fn refusal(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

/// Load `DCD1` for the upload-path handlers: program-owned, exactly
/// 576 bytes, and a record this program wrote.
fn load_dcd1(program_id: &Pubkey, account: &AccountInfo) -> Result<Dcd1, ProgramError> {
    if account.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let data = account.try_borrow_data()?;
    Dcd1::decode(&data).map_err(|error| refusal(error.0))
}

/// Read the `DCD1` record at its DERIVED address for one digest.
///
/// `load_dcd1` checks owner and shape only, which is right for the tag 5-8
/// handlers (the digest is not known until `Finish` recomputes it). Tag 19
/// provisions a chunk against a digest the caller names, so here the address
/// IS the check: a `DCD1` at any other address is not this digest's index.
pub fn read_index_record(
    program_id: &Pubkey,
    account: &AccountInfo,
    descriptor_digest: &[u8; 32],
) -> Result<Dcd1, ProgramError> {
    let (want, _) = find_desc_index_address(program_id, descriptor_digest);
    if want != *account.key {
        return Err(refusal(err::DESC_DIGEST_MISMATCH));
    }
    load_dcd1(program_id, account)
}

fn store_dcd1(account: &AccountInfo, record: &Dcd1) -> ProgramResult {
    let image = record.encode();
    let mut data = account.try_borrow_mut_data()?;
    if data.len() != DCD1_BYTES {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data.copy_from_slice(&image);
    Ok(())
}

fn check_authority(record: &Dcd1, signer: &Pubkey) -> Result<(), ProgramError> {
    if record.authority != signer.to_bytes() {
        return Err(refusal(err::DESC_AUTHORITY));
    }
    Ok(())
}

/// `DescriptorOpen [5]`: accounts 0 = `DCD1` (writable), 1 = payer
/// (signer, writable), 2 = system program. Creates the record, refusing an
/// existing one (311), a bad `total_bytes` (312), and a `grammar_version`
/// argument that is not 2 (328). The `chunk_count` stored is the arithmetic
/// one by construction (313 has no carrier); the derived address the record
/// will live at is verified only at `Finish` (321), when the digest exists.
pub fn process_open(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: OpenArgs,
) -> ProgramResult {
    if accounts.len() != 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (index, payer, _system) = (&accounts[0], &accounts[1], &accounts[2]);
    if !index.is_writable || !payer.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if index.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    {
        let data = index.try_borrow_data()?;
        if data.len() != DCD1_BYTES {
            return Err(ProgramError::AccountDataTooSmall);
        }
        // An existing record is program-owned bytes starting with the magic:
        // a second open at the same address. Anything else (zeroed, or a
        // foreign shape the program never writes) is refused the same way —
        // only this program writes `DCD1`, so a non-record at a derived
        // address is program error, not a re-open.
        if data[DCD1_OFF_MAGIC..DCD1_OFF_MAGIC + 4] == DCD1_MAGIC {
            return Err(refusal(err::DESC_OPEN_EXISTS));
        }
        if !data.iter().all(|byte| *byte == 0) {
            return Err(refusal(err::DESC_OPEN_EXISTS));
        }
    }
    check_total_bytes(args.total_bytes).map_err(|error| refusal(error.0))?;
    if args.grammar_version != DCD1_VERSION {
        return Err(refusal(err::DESC_OPEN_GRAMMAR_VERSION));
    }
    let record = Dcd1::init(args.total_bytes, args.descriptor_id, payer.key.to_bytes());
    debug_assert_eq!(record.chunk_count, chunk_count(args.total_bytes));
    store_dcd1(index, &record)?;
    let _ = program_id;
    Ok(())
}

/// `DescriptorAlloc [6]`: accounts 0 = `DCD1` (writable), 1 = the chunk
/// (writable), 2 = payer (signer, writable), 3 = system program. Grows chunk
/// `chunk_index` toward its exact arithmetic length in steps of at most
/// `MAX_CPI_ALLOCATION_BYTES`. Refuses any alloc once the first byte is
/// hashed (316), a zero or oversize step (327), and a grown length past the
/// exact one (315). The chunk address (314) is unverifiable before `Finish`
/// — the digest does not exist yet — so a wrong address uploads fine and
/// dies at 321.
pub fn process_alloc(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: AllocArgs,
) -> ProgramResult {
    if accounts.len() != 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (index, chunk, payer, _system) = (&accounts[0], &accounts[1], &accounts[2], &accounts[3]);
    if !index.is_writable || !chunk.is_writable || !payer.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let record = load_dcd1(program_id, index)?;
    check_authority(&record, payer.key)?;
    // The geometry is fixed before the first byte is hashed.
    if record.upload_cursor != 0 {
        return Err(refusal(err::DESC_ALLOC_AFTER_UPLOAD));
    }
    if args.grow_bytes == 0 || args.grow_bytes as u64 > MAX_CPI_ALLOCATION_BYTES {
        return Err(refusal(err::DESC_ALLOC_STEP));
    }
    if args.chunk_index >= record.chunk_count {
        return Err(refusal(err::DESC_CHUNK_SIZE));
    }
    let current_len = chunk.try_borrow_data()?.len() as u64;
    // The chunk account the geometry names is program-owned; anything else
    // cannot become exact and is refused as a wrong size now.
    if *chunk.owner != *program_id {
        return Err(refusal(err::DESC_CHUNK_SIZE));
    }
    let grown = check_alloc_growth(
        record.total_bytes,
        args.chunk_index,
        current_len,
        args.grow_bytes,
    )
    .map_err(|error| refusal(error.0))?;
    // GROW IT. Until M1046 this handler ended `let _ = grown; Ok(())` under a
    // comment claiming the system program reallocs "at account 3" -- it never
    // called it, the account at index 3 was bound as `_system` and unused, and
    // on chain the chunk stayed at its creation length while the instruction
    // reported success (measured: 1,809 CU, 0 bytes, on Fogo testnet). The gate
    // did not catch it because `lifecycle.rs` re-sized the chunk from the test
    // harness after tag 6.
    //
    // The chunk is this program's own account by the check above, so the growth
    // is the runtime's `realloc`, not a CPI: no system program, no signer, and
    // no transfer, because tag 19 paid rent for the chunk's FINAL length when
    // it created the account (`minimum_balance` is monotonic). `zero_init` is
    // true so the new bytes are zero rather than whatever the realloc region
    // held, which the fold depends on.
    chunk.realloc(grown as usize, true)?;
    if chunk.data_len() as u64 != grown {
        return Err(refusal(err::DESC_ALLOC_SIZE));
    }
    Ok(())
}

/// Seed `fold_running` for clause `index`: `H(TAG | id:u16le | len:u32le)`.
fn seed_running(record: &mut Dcd1, index: usize) {
    let (_, length) = record.clause_span(index);
    record.fold_running = sha256(&[
        TAG_CLAUSE_FRAME,
        &((index + 1) as u16).to_le_bytes(),
        &length.to_le_bytes(),
    ]);
    record.fold_frame_index = 0;
    record.fold_clause_consumed = 0;
}

/// Fold one complete frame out of `frame` into the running chain.
fn fold_frame(record: &mut Dcd1, frame: &[u8]) {
    let index = record.fold_frame_index.to_le_bytes();
    let length = (frame.len() as u32).to_le_bytes();
    record.fold_running = sha256(&[
        TAG_CLAUSE_FRAME,
        &record.fold_running,
        &index,
        &length,
        frame,
    ]);
    record.fold_frame_index += 1;
}

/// Latch clause `record.fold_clause`'s digest from its now-complete fold
/// chain, advance to the next clause and seed its chain (or, past the last
/// clause, zero the fold fields — there is nothing left to seed). The caller
/// guarantees `fold_clause_consumed == clause_len` and that any pending tail
/// frame has ALREADY been folded into `fold_running` (§3.4 step 3: "fold the
/// short tail if pending_len != 0, set clause_digest[fold_clause]" — the
/// folding itself is `feed_bytes`'s job, since only it holds the pending
/// bytes; this function only ever sees a clean `fold_running`).
fn close_one_clause(record: &mut Dcd1) {
    let index = record.fold_clause as usize;
    let (_, length) = record.clause_span(index);
    let running = record.fold_running;
    record.clause_digest[index] = sha256(&[
        TAG_CLAUSE,
        &((index + 1) as u16).to_le_bytes(),
        &length.to_le_bytes(),
        &running,
    ]);
    record.fold_clause += 1;
    if (record.fold_clause as usize) < CLAUSE_COUNT {
        seed_running(record, record.fold_clause as usize);
    } else {
        record.fold_running = [0u8; 32];
        record.fold_frame_index = 0;
        record.fold_clause_consumed = 0;
    }
}

/// Feed `data` (document bytes `[at, at + len)`, already verified against
/// the clause spans) into the clause(s) in progress, folding every
/// 1,024-byte frame the write completes AND the short final frame of any
/// clause this write closes — §3.4 step 3 in full, not just the
/// full-frame case. `frame_tail` carries the pending bytes read back out of
/// the chunk account when the frame in progress started in an earlier
/// write; on chain that re-read is the chunk account's own bytes, never a
/// stored copy. `pending` here is a LOCAL reconstruction of that same
/// invariant (bytes fed since the last fold, always `< DESC_FRAME_BYTES`
/// long): it is never persisted, only `fold_clause_consumed` is, and the
/// next call rebuilds it the same way from `frame_tail`.
fn feed_bytes(record: &mut Dcd1, mut data: &[u8], frame_tail: &[u8]) {
    let mut pending_len = record.pending_len() as usize;
    let mut pending = [0u8; DESC_FRAME_BYTES];
    if pending_len > 0 {
        pending[..pending_len].copy_from_slice(&frame_tail[frame_tail.len() - pending_len..]);
    }
    while !data.is_empty() && (record.fold_clause as usize) < CLAUSE_COUNT {
        let (_, clause_len) = record.clause_span(record.fold_clause as usize);
        let room = (clause_len - record.fold_clause_consumed) as usize;
        let take = room.min(DESC_FRAME_BYTES - pending_len).min(data.len());
        pending[pending_len..pending_len + take].copy_from_slice(&data[..take]);
        pending_len += take;
        record.fold_clause_consumed += take as u32;
        data = &data[take..];
        let clause_done = record.fold_clause_consumed == clause_len;
        if pending_len == DESC_FRAME_BYTES || clause_done {
            if pending_len > 0 {
                fold_frame(record, &pending[..pending_len]);
            }
            pending_len = 0;
        }
        if clause_done {
            close_one_clause(record);
        }
    }
    close_completed_zero_length_clauses(record);
}

/// Close every clause already exactly filled with no bytes still needed to
/// trigger the main loop's fold — a zero-length clause, or several in a row
/// (a run of zero-length clauses closes with no bytes at all). Never folds
/// anything: `pending_len` is always 0 on entry here by construction.
fn close_completed_zero_length_clauses(record: &mut Dcd1) {
    while (record.fold_clause as usize) < CLAUSE_COUNT {
        let (_, clause_len) = record.clause_span(record.fold_clause as usize);
        if record.fold_clause_consumed != clause_len {
            break;
        }
        close_one_clause(record);
    }
}

/// `DescriptorUpload [7]`: accounts 0 = `DCD1` (writable), 1 = the chunk
/// (writable), 2 = authority (signer), 3 = the carry chunk
/// (`chunk_index - 1`, read-only) present exactly when the pending frame
/// starts in the previous chunk. Writes `bytes` at `offset` — which must
/// equal the cursor (317) — and folds every frame the write completes out
/// of the bytes read back from the chunk account just written, so the chunk
/// plan is free and the digest does not depend on it.
pub fn process_upload(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    offset: u64,
    bytes: &[u8],
) -> ProgramResult {
    // The account list shape is framing: 3 accounts, or 4 when the pending
    // frame starts in the previous chunk.
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (index, chunk, authority) = (&accounts[0], &accounts[1], &accounts[2]);
    if !index.is_writable || !chunk.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut record = load_dcd1(program_id, index)?;
    check_authority(&record, authority.key)?;
    if record.finished() || record.frozen() {
        return Err(refusal(err::DESC_UPLOAD_SEALED));
    }
    if offset != record.upload_cursor {
        return Err(refusal(err::DESC_UPLOAD_CURSOR));
    }
    let length = bytes.len() as u64;
    if length > u32::MAX as u64 {
        return Err(refusal(err::DESC_UPLOAD_OVERRUN));
    }
    let chunk_index = check_upload_span(offset, length as u32, record.total_bytes)
        .map_err(|error| refusal(error.0))?;
    if *chunk.owner != *program_id {
        return Err(refusal(err::DESC_UPLOAD_SPAN));
    }
    let need_carry = record.needs_carry();
    if need_carry && accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !need_carry && accounts.len() != 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if need_carry && accounts[3].is_writable {
        // The carry chunk is read, never written.
        return Err(ProgramError::InvalidArgument);
    }
    // Write the bytes at the cursor: the write must land wholly inside the
    // passed chunk account at the chunk-relative offset.
    let chunk_relative = (offset - chunk_start(chunk_index)) as usize;
    let carry_bytes: Vec<u8> = if need_carry {
        let carry = &accounts[3];
        carry.try_borrow_data()?.to_vec()
    } else {
        Vec::new()
    };
    {
        let mut data = chunk.try_borrow_mut_data()?;
        if data.len() < chunk_relative + bytes.len() {
            return Err(refusal(err::DESC_UPLOAD_OVERRUN));
        }
        data[chunk_relative..chunk_relative + bytes.len()].copy_from_slice(bytes);
    }
    // Fold: the header capture on the upload covering byte 183, then the
    // body bytes in order, reading the pending frame back out of the chunk
    // account(s) just written.
    let new_cursor = offset + length;
    if !record_header_started(&record) {
        if new_cursor < BODY_START as u64 {
            record.upload_cursor = new_cursor;
            store_dcd1(index, &record)?;
            return Ok(());
        }
        // The upload covering byte 183: read the header back out of chunk 0
        // (the whole header is in chunk 0) and latch the directory.
        let header: Vec<u8> = {
            let data = chunk.try_borrow_data()?;
            if chunk_index == 0 {
                data[..BODY_START].to_vec()
            } else {
                // Unreachable: byte 183 is in chunk 0, and the cursor rule
                // forces the covering upload to start at or before it.
                return Err(refusal(err::DESC_UPLOAD_CURSOR));
            }
        };
        capture_header(&mut record, &header).map_err(|error| refusal(error.0))?;
        let body = &header[0..0]; // no body bytes from the header slice itself
        let _ = body;
        // Feed the body bytes of this write: everything past the header end
        // that this write carried, re-read from the chunk just written.
        let body_start_in_write = (BODY_START as u64).saturating_sub(offset) as usize;
        if body_start_in_write < bytes.len() {
            let from_chunk: Vec<u8> = {
                let data = chunk.try_borrow_data()?;
                let start = chunk_relative + body_start_in_write;
                data[start..start + (bytes.len() - body_start_in_write)].to_vec()
            };
            feed_bytes(&mut record, &from_chunk, &[]);
        }
        record.upload_cursor = new_cursor;
        store_dcd1(index, &record)?;
        return Ok(());
    }
    // Steady-state body upload.
    let pending = record.pending_len() as usize;
    let frame_tail: Vec<u8> = if pending > 0 {
        if need_carry {
            // The pending bytes are the tail of the previous chunk: the
            // last `pending` bytes of the carry account.
            if carry_bytes.len() < pending {
                return Err(refusal(err::DESC_DIGEST_MISMATCH));
            }
            carry_bytes[carry_bytes.len() - pending..].to_vec()
        } else {
            // The pending bytes end at the cursor, inside the chunk just
            // written: re-read them.
            let data = chunk.try_borrow_data()?;
            let end = chunk_relative;
            if end < pending {
                return Err(refusal(err::DESC_DIGEST_MISMATCH));
            }
            data[end - pending..end].to_vec()
        }
    } else {
        Vec::new()
    };
    {
        let from_chunk: Vec<u8> = {
            let data = chunk.try_borrow_data()?;
            data[chunk_relative..chunk_relative + bytes.len()].to_vec()
        };
        feed_bytes(&mut record, &from_chunk, &frame_tail);
    }
    record.upload_cursor = new_cursor;
    store_dcd1(index, &record)?;
    Ok(())
}

/// Whether the header has been captured yet: `clause_end[9]` is nonzero
/// exactly after the upload covering byte 183 latches the directory.
fn record_header_started(record: &Dcd1) -> bool {
    record.clause_end[CLAUSE_COUNT - 1] != 0
}

/// Latch `doc_flags`, the ten `clause_end`s and the first clause's seeded
/// chain from the 184 header bytes read back out of chunk 0.
fn capture_header(record: &mut Dcd1, header: &[u8]) -> Result<(), DcgError> {
    let ends = parse_clause_ends(header)?;
    record.header_digest = fold_header(header)?;
    record.doc_flags = u16_at(header, 6);
    for (index, (_, _)) in ends.iter().enumerate() {
        let (_, end_offset) = (ends[index].0, ends[index].0 + ends[index].1);
        record.clause_end[index] = end_offset;
    }
    record.fold_clause = 0;
    seed_running(record, 0);
    close_completed_zero_length_clauses(record);
    Ok(())
}

/// `DescriptorFinish [8]`: accounts 0 = `DCD1` (writable), 1 = authority
/// (signer). Requires a complete upload (322), closes the last clause's
/// chain, recomputes the digest per §3.2, and requires the derived index
/// address to equal account 0's key (321) — the address is the copy, and
/// checking it is the whole mechanism. Sets `finished` and `frozen`.
pub fn process_finish(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() != 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (index, authority) = (&accounts[0], &accounts[1]);
    if !index.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut record = load_dcd1(program_id, index)?;
    check_authority(&record, authority.key)?;
    if record.upload_cursor != record.total_bytes as u64 {
        return Err(refusal(err::DESC_NOT_FINISHED));
    }
    if (record.fold_clause as usize) != CLAUSE_COUNT {
        return Err(refusal(err::DESC_NOT_FINISHED));
    }
    // Assemble the digest exactly as `Descriptor::digest` does, from the
    // fields the resumable fold committed (`Dcd1::digest`).
    let computed = record.digest();
    let (derived, _) = find_desc_index_address(program_id, &computed);
    if derived != *index.key {
        return Err(refusal(err::DESC_DIGEST_MISMATCH));
    }
    record.flags |= DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN;
    store_dcd1(index, &record)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading a sealed document by address (the 5.4-5.7 integration seam).
// ---------------------------------------------------------------------------

/// A sealed document opened BY ADDRESS, without materialising it (R2).
///
/// `accounts[0]` is the `DCD1` index (read-only) and `accounts[1..1 +
/// chunk_count]` are its chunk accounts (read-only, ascending).  The chunk
/// data is borrowed, not copied: the guard vector keeps the borrows alive for
/// as long as this handle lives, and [`Self::chunk_slices`] hands the caller
/// the exact-length slices `Descriptor::from_chunks` reads.
///
/// The digest is NOT re-derived by hashing the document.  It is folded from
/// the fields `DescriptorFinish` committed to `DCD1` ([`Dcd1::digest`]), and
/// the `DCD1` address derives from it — the address is the copy, exactly as
/// `Execute` reads the sealed digest from `BDS2` (M1043).  Chunk identity is
/// then address + the `DCD1` frozen flag, never a second hash (314).
pub struct OpenedDescriptor<'a> {
    pub record: Dcd1,
    pub digest: [u8; 32],
    /// `1 + chunk_count`: the index at which the handler's `BDS2` (or other
    /// trailing) accounts begin.
    pub used: usize,
    guards: Vec<core::cell::Ref<'a, &'a mut [u8]>>,
}

impl OpenedDescriptor<'_> {
    pub fn total_bytes(&self) -> usize {
        self.record.total_bytes as usize
    }

    /// The passed chunks, ascending, each truncated to its exact arithmetic
    /// length (as `Execute` does), for `Descriptor::from_chunks`.
    pub fn chunk_slices(&self) -> Vec<&[u8]> {
        self.guards
            .iter()
            .enumerate()
            .map(|(position, guard)| {
                let exact = chunk_len(self.record.total_bytes, position as u16) as usize;
                &guard[..guard.len().min(exact)]
            })
            .collect()
    }
}

/// Load a finished and frozen descriptor by address (the 5.4-5.7 integration
/// seam), without concatenating or hashing it.
///
/// A document whose `DCD1` is not finished and frozen is 323: the seal
/// transition has not happened, so no lifecycle instruction past tag 11 may
/// read it.  A wrong index address is 321 ([`err::DESC_DIGEST_MISMATCH`]) and a
/// wrong chunk address is 314 ([`err::DESC_CHUNK_ADDRESS`]).  The caller
/// builds the `Descriptor` from [`OpenedDescriptor::chunk_slices`]; nothing in
/// this path is O(document).
/// Read and validate ONLY the `DCD1` index of a sealed descriptor: the record
/// and its digest, with the address, owner, length, and finished/frozen
/// checks `open_descriptor` makes, and no chunk accounts.
///
/// This is what a handler takes when it needs the document's IDENTITY
/// (digest, `total_bytes`, `chunk_count`) but not its BODY.  `close.rs`
/// kinds 6 and 7 are the only callers: §7 closes the chunks before the
/// `DCD1`, so by the time they run the chunk prefix cannot be supplied.
pub fn open_index(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> Result<(Dcd1, [u8; 32]), ProgramError> {
    let Some(index) = accounts.first() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if index.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let record = {
        let data = index.try_borrow_data()?;
        if data.len() != DCD1_BYTES {
            return Err(ProgramError::AccountDataTooSmall);
        }
        Dcd1::decode(&data).map_err(|error| refusal(error.0))?
    };
    if record.flags & (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
        != (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
    {
        return Err(refusal(err::DESC_NOT_SEALED));
    }
    let digest = record.digest();
    let (want_index, _) = find_desc_index_address(program_id, &digest);
    if want_index != *index.key {
        return Err(refusal(err::DESC_DIGEST_MISMATCH));
    }
    Ok((record, digest))
}

pub fn open_descriptor<'a, 'info>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'info>],
) -> Result<OpenedDescriptor<'a>, ProgramError> {
    let Some(index) = accounts.first() else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if index.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    // The `DCD1` may be writable when it is itself a close target (kind 7),
    // exactly as a chunk may be (kind 6, below): one key carries one
    // writability in a Solana message, and the close target must be writable.
    // No caller of `open_descriptor` writes the index -- the only handlers
    // that write a `DCD1` are `process_open`/`process_upload`/`process_finish`
    // in this module, and none of them opens a sealed descriptor -- so the
    // read is unaffected and the writability is not refused here.
    let record = {
        let data = index.try_borrow_data()?;
        if data.len() != DCD1_BYTES {
            return Err(ProgramError::AccountDataTooSmall);
        }
        Dcd1::decode(&data).map_err(|error| refusal(error.0))?
    };
    if record.flags & (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
        != (DCD1_FLAG_FINISHED | DCD1_FLAG_FROZEN)
    {
        return Err(refusal(err::DESC_NOT_SEALED));
    }
    let chunk_count = record.chunk_count as usize;
    if accounts.len() < 1 + chunk_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let digest = record.digest();
    let (want_index, _) = find_desc_index_address(program_id, &digest);
    if want_index != *index.key {
        return Err(refusal(err::DESC_DIGEST_MISMATCH));
    }
    let mut guards = Vec::with_capacity(chunk_count);
    for (position, chunk) in accounts[1..1 + chunk_count].iter().enumerate() {
        // A chunk may be writable when it is itself a close target (kind 6);
        // the descriptor read never writes it, so writability is not refused.
        let (want, _) = find_desc_chunk_address(program_id, &digest, position as u16);
        if want != *chunk.key {
            return Err(refusal(err::DESC_CHUNK_ADDRESS));
        }
        let exact = chunk_len(record.total_bytes, position as u16) as usize;
        let data = chunk.try_borrow_data()?;
        if data.len() < exact {
            return Err(refusal(err::DESC_DIGEST_MISMATCH));
        }
        guards.push(data);
    }
    Ok(OpenedDescriptor {
        record,
        digest,
        used: 1 + chunk_count,
        guards,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_bytes_bounds_are_the_spec_half_open_range() {
        assert!(check_total_bytes(184).is_ok());
        assert!(check_total_bytes(u32::MAX).is_ok());
        for bad in [0u32, 1, 183] {
            assert_eq!(check_total_bytes(bad).unwrap_err().0, err::DESC_TOTAL_BYTES);
        }
        // 26,741,228: the fly's measured whole-document size, admissible.
        assert!(check_total_bytes(26_741_228).is_ok());
    }

    #[test]
    fn chunk_counts_are_ceil_arithmetic() {
        assert_eq!(chunk_count(184), 1);
        assert_eq!(chunk_count(DESC_CHUNK_BYTES as u32), 1);
        assert_eq!(chunk_count(DESC_CHUNK_BYTES as u32 + 1), 2);
        // The registry's positive vector: 4 for 26,741,228.
        assert_eq!(chunk_count(26_741_228), 4);
        // The registry's negative vector: 3 and 5 are refused there.
        assert!(check_chunk_count(26_741_228, 4).is_ok());
        for bad in [3u16, 5] {
            assert_eq!(
                check_chunk_count(26_741_228, bad).unwrap_err().0,
                err::DESC_CHUNK_COUNT
            );
        }
        // The u32 range tops out at exactly 512 chunks.
        assert_eq!(chunk_count(u32::MAX), 512);
        assert!(check_chunk_count(u32::MAX, 512).is_ok());
        assert_eq!(
            check_chunk_count(u32::MAX, 511).unwrap_err().0,
            err::DESC_CHUNK_COUNT
        );
    }

    #[test]
    fn chunk_lengths_are_exact() {
        assert_eq!(chunk_len(184, 0), 184);
        assert_eq!(chunk_len(DESC_CHUNK_BYTES as u32 + 7, 0), DESC_CHUNK_BYTES);
        assert_eq!(chunk_len(DESC_CHUNK_BYTES as u32 + 7, 1), 7);
        assert_eq!(chunk_start(3), 3 * DESC_CHUNK_BYTES);
    }

    #[test]
    fn upload_spans_refuse_overrun_and_boundary_crossing() {
        // Exact end is accepted, in the chunk it lands in.
        assert_eq!(check_upload_span(0, 184, 26_741_228).unwrap(), 0);
        // One byte over is 318.
        assert_eq!(
            check_upload_span(26_741_228 - 10, 11, 26_741_228)
                .unwrap_err()
                .0,
            err::DESC_UPLOAD_OVERRUN
        );
        // A write straddling 8 MiB is 320.
        assert_eq!(
            check_upload_span(DESC_CHUNK_BYTES - 4, 8, (DESC_CHUNK_BYTES + 7) as u32)
                .unwrap_err()
                .0,
            err::DESC_UPLOAD_SPAN
        );
        // Arithmetic overflow on offset + length is an overrun, not a wrap.
        assert_eq!(
            check_upload_span(u64::MAX, 1, 26_741_228).unwrap_err().0,
            err::DESC_UPLOAD_OVERRUN
        );
    }

    #[test]
    fn alloc_growth_may_not_overshoot_exact() {
        let total = (DESC_CHUNK_BYTES + 7) as u32;
        assert_eq!(check_alloc_growth(total, 1, 0, 7).unwrap(), 7);
        assert_eq!(
            check_alloc_growth(total, 1, 0, 8).unwrap_err().0,
            err::DESC_CHUNK_SIZE
        );
        // One byte short of exact is a legal intermediate step.
        assert_eq!(
            check_alloc_growth(total, 0, 0, (DESC_CHUNK_BYTES - 1) as u32).unwrap(),
            DESC_CHUNK_BYTES - 1
        );
    }

    #[test]
    fn instruction_decodes_are_exact_eof() {
        let mut open = vec![TAG_DESCRIPTOR_OPEN];
        open.extend_from_slice(&26_741_228u32.to_le_bytes());
        open.extend_from_slice(&[9u8; 32]);
        open.extend_from_slice(&2u16.to_le_bytes());
        let args = decode_open(&open).unwrap();
        assert_eq!(args.total_bytes, 26_741_228);
        assert_eq!(args.descriptor_id, [9u8; 32]);
        assert_eq!(args.grammar_version, open_grammar_version());
        assert!(decode_open(&open[..open.len() - 1]).is_err());
        assert!(decode_open(&[&open[..], &[0u8]].concat()).is_err());
        assert!(decode_open(&open[1..]).is_err());

        let alloc = [TAG_DESCRIPTOR_ALLOC, 3, 0, 0x00, 0x28, 0x00, 0x00];
        let args = decode_alloc(&alloc).unwrap();
        assert_eq!((args.chunk_index, args.grow_bytes), (3, 0x2800));
        assert!(decode_alloc(&alloc[..6]).is_err());

        let mut upload = vec![TAG_DESCRIPTOR_UPLOAD];
        upload.extend_from_slice(&1024u64.to_le_bytes());
        upload.extend_from_slice(&3u32.to_le_bytes());
        upload.extend_from_slice(&[7u8; 3]);
        let args = decode_upload(&upload).unwrap();
        assert_eq!((args.offset, args.bytes), (1024, &[7u8; 3][..]));
        // Declared length and carried bytes must agree.
        let mut short = upload.clone();
        short.pop();
        assert!(decode_upload(&short).is_err());

        assert!(decode_finish(&[TAG_DESCRIPTOR_FINISH]).is_ok());
        assert!(decode_finish(&[TAG_DESCRIPTOR_FINISH, 0]).is_err());
        assert!(decode_finish(&[8u8]).is_ok());
    }

    #[test]
    fn the_streaming_fold_matches_the_whole_buffer_chain() {
        // Frame edges: exactly 1024, one over, one under, one byte, empty.
        for (clause_id, length) in [(1u16, 1024usize), (2, 1025), (3, 1023), (4, 1), (5, 0)] {
            let body: Vec<u8> = (0..length as u32).map(|i| (i % 251) as u8).collect();
            let whole = crate::descriptor::clause_frame_chain(clause_id, &body);
            // One shot.
            let mut fold = ClauseFold::new(clause_id, length as u32);
            fold.feed(&body);
            assert_eq!(fold.finish(), whole, "clause {clause_id} len {length}");
            // Byte by byte: every frame completes across feeds.
            let mut fold = ClauseFold::new(clause_id, length as u32);
            for byte in &body {
                fold.feed(core::slice::from_ref(byte));
            }
            assert_eq!(
                fold.finish(),
                whole,
                "clause {clause_id} len {length} streamed"
            );
            assert_eq!(fold_consumed_check(clause_id, &body), length as u32);
        }
    }

    fn fold_consumed_check(clause_id: u16, body: &[u8]) -> u32 {
        let mut fold = ClauseFold::new(clause_id, body.len() as u32);
        fold.feed(body);
        fold.consumed()
    }
}
