// SPDX-License-Identifier: GPL-3.0-only
//! The `Challenge` stage: a real tag-166 leaf challenge opened on an attested
//! output, and the executor's response upload (tags 115-118) against it.
//!
//! The challenge packet is built from a `Rekeyed` proof's own tail and paths,
//! so it opens exactly the leaf the executor attested.

use crate::chain::SYSTEM;
use crate::document::{Document, Rekeyed};
use crate::template::Template;
use dcg_program::closure_v2 as h;
use dcg_program::closure_v2_response as response;
use dcg_program::hash::sha256;
use dcg_program::unified::{address, challenge, TAG_ATTEST_OUTPUT, TAG_CHALLENGE_LEAF};
use solana_instruction::account_meta::AccountMeta;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";

/// An open challenge: its DCR1 record and the response account it binds.
#[derive(Clone, Copy, Debug)]
pub struct Challenge {
    pub record: Pubkey,
    pub response: Pubkey,
    pub nonce: u32,
}

impl Template {
    /// Tag 166's data opening the attested leaf of `proof` with `nonce`.
    pub fn challenge_leaf_packet(&self, doc: &Document, proof: &Rekeyed, nonce: u32) -> Vec<u8> {
        let packet = &proof.data;
        assert_eq!(packet[0], TAG_ATTEST_OUTPUT);
        let w = self.locator.width as usize;
        let tail_len = u16::from_le_bytes([packet[37 + w], packet[38 + w]]) as usize;
        let tail_at = 39 + w;
        let tail = &packet[tail_at..tail_at + tail_len];
        let height = packet[tail_at + tail_len] as usize;
        let path_at = tail_at + tail_len + 1;
        let path = &packet[path_at..path_at + 32 * height];
        let x = self.fixture.view();
        let te = x.old_to_new(self.locator.base_entry, proof.p).unwrap().expect("output base entry");
        let c = x.coordinate(proof.p, te).unwrap();
        let coordinate = h::Coordinate { position: proof.p, segment: c.segment, entry: c.local };
        let mut leaf = Vec::new();
        leaf.extend_from_slice(LEAF_DOMAIN);
        leaf.extend_from_slice(&doc.descriptor);
        leaf.extend_from_slice(&coordinate.bytes());
        leaf.extend_from_slice(tail);
        let leaf_hash = sha256(&[&leaf]);
        let spp1_at = path_at + 32 * height;
        let (_, _, _, spp1_len) = challenge::decode_spp1(&packet[spp1_at..]).unwrap();
        let mut out = vec![TAG_CHALLENGE_LEAF];
        out.extend_from_slice(&doc.descriptor);
        out.extend_from_slice(&proof.p.to_le_bytes());
        out.extend_from_slice(&c.segment.to_le_bytes());
        out.extend_from_slice(&c.local.to_le_bytes());
        out.extend_from_slice(&leaf_hash);
        out.push(height as u8);
        out.extend_from_slice(path);
        out.extend_from_slice(&packet[spp1_at..spp1_at + spp1_len]);
        out.extend_from_slice(&nonce.to_le_bytes());
        out
    }

    /// The challenger (the second identity) and its record for `nonce`.
    pub fn challenge_record(&self, doc: &Document, nonce: u32) -> Pubkey {
        address::challenge(&self.program, &doc.descriptor, &self.roles.signer.pubkey(), nonce).0
    }

    /// Tag 166's ten metas.
    pub fn challenge_leaf_metas(&self, doc: &Document, record: Pubkey) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(self.roles.signer.pubkey(), true),
            AccountMeta::new(doc.dcm2, false),
            AccountMeta::new_readonly(doc.dpr2, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(self.pt2s, false),
            AccountMeta::new_readonly(self.routes, false),
            AccountMeta::new_readonly(self.geometry, false),
            AccountMeta::new_readonly(self.drp2, false),
            AccountMeta::new_readonly(self.pt1x, false),
        ]
    }

    /// Send a tag-166 packet (possibly altered by the caller) as the challenger.
    pub async fn send_challenge_leaf(&mut self, doc: &Document, data: Vec<u8>) -> Result<(), TransactionError> {
        let nonce = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        let metas = self.challenge_leaf_metas(doc, self.challenge_record(doc, nonce));
        let signer = self.roles.signer.insecure_clone();
        self.chain.send(&signer, &[], data, metas).await
    }

    /// Open an honest leaf challenge on `proof` (166).
    pub async fn open_leaf_challenge(&mut self, doc: &Document, proof: &Rekeyed, nonce: u32) -> Challenge {
        let data = self.challenge_leaf_packet(doc, proof, nonce);
        self.send_challenge_leaf(doc, data).await.expect("an honest leaf challenge opens (166)");
        let record = self.challenge_record(doc, nonce);
        Challenge { record, response: response::address(&self.program, &record).0, nonce }
    }

    /// Tag 115's metas.
    pub fn response_begin_metas(&self, c: &Challenge) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(c.response, false),
            AccountMeta::new(self.roles.executor.pubkey(), true),
            AccountMeta::new_readonly(c.record, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]
    }

    /// Tags 116-118's metas.
    pub fn response_metas(&self, c: &Challenge) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(c.response, false),
            AccountMeta::new(self.roles.executor.pubkey(), true),
            AccountMeta::new_readonly(c.record, false),
        ]
    }

    /// Send one response-upload instruction as the executor.
    pub async fn send_response(&mut self, c: &Challenge, data: Vec<u8>) -> Result<(), TransactionError> {
        let metas = if data[0] == response::TAG_BEGIN { self.response_begin_metas(c) } else { self.response_metas(c) };
        let ex = self.roles.executor.insecure_clone();
        self.chain.send(&ex, &[], data, metas).await
    }

    /// Begin (115) a response of `total` bytes with `digest`.
    pub async fn response_begin(&mut self, c: &Challenge, total: u32, digest: [u8; 32]) -> Result<(), TransactionError> {
        let mut data = vec![response::TAG_BEGIN];
        data.extend_from_slice(&total.to_le_bytes());
        data.extend_from_slice(&digest);
        self.send_response(c, data).await
    }

    /// Grow (116) until the account holds the declared total.
    pub async fn response_grow_all(&mut self, c: &Challenge) -> usize {
        let mut grows = 0;
        loop {
            let raw = self.chain.data(c.response).await;
            let total = u32::from_le_bytes(raw[response::DECLARED_LEN_AT..response::DECLARED_LEN_AT + 4].try_into().unwrap());
            if raw.len() == response::HEADER + total as usize {
                return grows;
            }
            self.send_response(c, vec![response::TAG_GROW]).await.expect("grow (116)");
            grows += 1;
        }
    }

    /// Write (117) `bytes` at `offset`.
    pub async fn response_write(&mut self, c: &Challenge, offset: u32, bytes: &[u8]) -> Result<(), TransactionError> {
        let mut data = vec![response::TAG_WRITE];
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(bytes);
        self.send_response(c, data).await
    }

    /// Seal (118).
    pub async fn response_seal(&mut self, c: &Challenge) -> Result<(), TransactionError> {
        self.send_response(c, vec![response::TAG_SEAL]).await
    }

    /// The honest upload: begin, grow, write in 900-byte chunks, seal.
    pub async fn upload_response(&mut self, c: &Challenge, body: &[u8]) {
        self.response_begin(c, body.len() as u32, sha256(&[body])).await.expect("begin (115)");
        self.response_grow_all(c).await;
        for (i, chunk) in body.chunks(900).enumerate() {
            self.response_write(c, (i * 900) as u32, chunk).await.expect("write (117)");
        }
        self.response_seal(c).await.expect("seal (118)");
    }
}
