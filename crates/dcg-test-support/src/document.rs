// SPDX-License-Identifier: GPL-3.0-only
//! The `Document`, `Landed`, `Finalized` and `Attested` stages, by the real
//! instructions: UnifiedInit (161), land position roots (162), finalize
//! (163), attest output (177).
//!
//! The document's content is the retained rung-D executor run (K=80): its
//! position roots, attestation packets and family plan are real-run outputs
//! (rule 6). `rekey_with` re-derives an attestation honestly for another
//! descriptor or a chosen cell value: the leaf's write row, the segment fold
//! and the SPP1 are rebuilt over it, so the attest is a real proof.

use crate::chain::SYSTEM;
use crate::fixtures::{golden, unhex, FixtureKind};
use crate::template::{Template, EXAMPLE_LIMITS};
use dcg_program::closure_v2 as h;
use dcg_program::hash::sha256;
use dcg_program::pt2p_onchain as S;
use dcg_program::unified::classes::{rs1_height, total_entries};
use dcg_program::unified::document::{self, Binding2, Dpd2};
use dcg_program::unified::terms::{Terms2, BOND_POLICY_CUSTOM};
use dcg_program::unified::{address, challenge};
use dcg_program::unified::{TAG_ATTEST_OUTPUT, TAG_FINALIZE_DOCUMENT, TAG_LAND_POSITION_ROOTS, TAG_UNIFIED_INIT};
use solana_instruction::account_meta::AccountMeta;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

pub const ESCROW_FLOOR: u64 = 890_880;
pub const FAMILY_COUNT: u16 = 16;
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";
const LEAF_WRITE_COUNT_AT: usize = 143 - 69;
const LEAF_WRITES_AT: usize = 147 - 69;

/// The retained rung-D executor run over the K=80 template.
pub struct RungD {
    pub position_roots: Vec<[u8; 32]>,
    /// The tag-177 packets the executor attested, by output index.
    pub attestations: Vec<Vec<u8>>,
    pub family_body: Vec<u8>,
    pub family_roots: Vec<[u8; 32]>,
}

fn d32(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().unwrap()
}

impl RungD {
    pub fn load() -> RungD {
        let e = golden("unified_v1_executor_rung_d_80.json");
        let g = golden("unified_v7.json");
        let dfs2 = unhex(g["dfs2"]["hex"].as_str().unwrap());
        RungD {
            position_roots: e["positions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| d32(&unhex(p["position_root"].as_str().unwrap()), 0))
                .collect(),
            attestations: e["outputs"].as_array().unwrap().iter().map(|o| unhex(o["attestation"].as_str().unwrap())).collect(),
            family_body: dfs2[document::DFS2_HEADER..].to_vec(),
            family_roots: g["dfs2"]["family_roots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| d32(&unhex(r.as_str().unwrap()), 0))
                .collect(),
        }
    }
}

/// A document: its descriptor and the four accounts UnifiedInit created
/// (DCM2, DPR2, family slots, DCR2).
#[derive(Clone)]
pub struct Document {
    pub descriptor: [u8; 32],
    pub dcm2: Pubkey,
    pub dpr2: Pubkey,
    pub family_slots: Pubkey,
    pub dcr2: Pubkey,
    pub binding: Binding2,
    pub terms: Vec<u8>,
}

impl Document {
    pub fn created(&self) -> [Pubkey; 4] {
        [self.dcm2, self.dpr2, self.family_slots, self.dcr2]
    }
}

/// One re-derived attestation: the tag-177 data, the position root it
/// implies, the value and its position.
pub struct Rekeyed {
    pub data: Vec<u8>,
    pub root: [u8; 32],
    pub value: Vec<u8>,
    pub p: u32,
}

/// A 16-byte completion cell carrying `token` (the stop-rule tests' cells).
pub fn cell_with_token(token: u32) -> Vec<u8> {
    let mut cell = vec![0u8; 16];
    cell[0..8].copy_from_slice(&(-1i64).to_le_bytes());
    cell[8..16].copy_from_slice(&(token as u64).to_le_bytes());
    cell
}

impl Template {
    /// The CUSTOM terms the suites use: zero slasher share, nonzero remainder,
    /// a settlement program and window, twice the abandonment floor.
    pub fn default_terms(&self) -> Vec<u8> {
        Terms2 {
            challenge_window_slots: 90_000,
            response_window_slots: 45_000,
            challenger_bond_lamports: 1_000_000,
            executor_bond_lamports: ESCROW_FLOOR,
            executor_reward_bps: 0,
            bond_policy_kind: BOND_POLICY_CUSTOM,
            bond_slasher_bps: 0,
            settlement_program: [7u8; 32],
            custom_settle_window_slots: 604_800,
            result_retention_slots: 2_592_000,
            bond_remainder: [8u8; 32],
            abandon_after_slots: 2 * EXAMPLE_LIMITS.min_abandon_after_slots,
        }
        .encode()
        .to_vec()
    }

    /// A completion binding over this template's output locator.
    pub fn completion_binding(&self, first: u32, count: u32) -> Binding2 {
        Binding2 {
            executor: self.roles.executor.pubkey().to_bytes(),
            request_id: [5u8; 32],
            consumer_digest: [6u8; 32],
            seed: [0; 32],
            output_first_position: first,
            output_count: count,
            output_base_entry: self.locator.base_entry,
            output_write: self.locator.write,
            output_width: self.locator.width,
            decision_flags: 0,
            option_count: 0,
            prompt_positions: first + 1,
            stop_plus_one: 0,
            option_table_offset: 0,
            option_table_sha256: [0; 32],
        }
    }

    /// The document descriptor (DPD2) of `binding` and `terms` on this template.
    pub fn descriptor(&self, binding: &Binding2, terms: &[u8], family_body: &[u8]) -> [u8; 32] {
        let b = binding.encode();
        let total = total_entries(&self.fixture.view()).unwrap();
        Dpd2 {
            position_count: self.k,
            segment_count: self.segments,
            family_count: FAMILY_COUNT,
            rs1_height: rs1_height(self.k),
            compiler_version: 1,
            total_entries: total,
            terms,
            binding: &b,
            clause12_v4: &self.pt2s_image[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
            definition_sha256: &d32(&self.pt2s_image, S::OFF_DEFINITION),
            base_digests: &self.pt2s_image[S::OFF_DIGESTS..S::OFF_DIGESTS + 96],
            model_root: &[1u8; 32],
            position_table_root: &[2u8; 32],
            prompt_commitment: &[3u8; 32],
            registry: self.drp2.as_ref(),
            registry_table_root: &self.reg_root,
            dfs2_sha256: &sha256(&[family_body]),
        }
        .digest_v8()
    }

    /// UnifiedInit (161). The four created PDAs are funded by real System
    /// Program transfers first, as the permissionless path expects.
    pub async fn init_document(&mut self, binding: &Binding2, terms: &[u8], family_body: &[u8], options: &[u8]) -> Document {
        self.try_init_document(binding, terms, family_body, options).await.expect("UnifiedInit (161)")
    }

    /// UnifiedInit (161), returning the program's refusal instead of panicking.
    pub async fn try_init_document(
        &mut self,
        binding: &Binding2,
        terms: &[u8],
        family_body: &[u8],
        options: &[u8],
    ) -> Result<Document, TransactionError> {
        let descriptor = self.descriptor(binding, terms, family_body);
        let created = [
            address::document(&self.program, &descriptor).0,
            address::positions(&self.program, &descriptor).0,
            address::family_slots(&self.program, &descriptor).0,
            address::result(&self.program, &descriptor).0,
        ];
        let ex = self.roles.executor.insecure_clone();
        for key in created {
            self.chain.transfer(&ex, key, 50_000_000_000).await;
        }
        let mut data = vec![TAG_UNIFIED_INIT];
        data.extend_from_slice(terms);
        data.extend_from_slice(&binding.encode());
        for a in [[1u8; 32], [2u8; 32], [3u8; 32]] {
            data.extend_from_slice(&a);
        }
        data.extend_from_slice(&FAMILY_COUNT.to_le_bytes());
        data.extend_from_slice(family_body);
        data.extend_from_slice(options);
        let metas = vec![
            AccountMeta::new(ex.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[1], false),
            AccountMeta::new(created[2], false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(self.pt2s, false),
            AccountMeta::new_readonly(self.routes, false),
            AccountMeta::new_readonly(self.geometry, false),
            AccountMeta::new_readonly(self.payloads, false),
            AccountMeta::new_readonly(self.drp2, false),
            AccountMeta::new_readonly(self.dea2, false),
            AccountMeta::new_readonly(self.dta1, false),
            AccountMeta::new(created[3], false),
            AccountMeta::new(self.dtu1, false),
        ];
        self.chain.send(&ex, &[], data, metas).await?;
        Ok(Document {
            descriptor,
            dcm2: created[0],
            dpr2: created[1],
            family_slots: created[2],
            dcr2: created[3],
            binding: *binding,
            terms: terms.to_vec(),
        })
    }

    /// Land position roots (162) from `first`, in batches of 20.
    pub async fn land(&mut self, doc: &Document, first: u32, roots: &[[u8; 32]]) {
        let ex = self.roles.executor.insecure_clone();
        for (batch, chunk) in roots.chunks(20).enumerate() {
            let mut data = vec![TAG_LAND_POSITION_ROOTS];
            data.extend_from_slice(&doc.descriptor);
            data.extend_from_slice(&(first + 20 * batch as u32).to_le_bytes());
            data.push(chunk.len() as u8);
            for r in chunk {
                data.extend_from_slice(r);
            }
            let metas = vec![
                AccountMeta::new(ex.pubkey(), true),
                AccountMeta::new(doc.dcm2, false),
                AccountMeta::new(doc.dpr2, false),
                AccountMeta::new_readonly(self.dtu1, false),
            ];
            self.chain.send(&ex, &[], data, metas).await.expect("land position roots (162)");
        }
    }

    /// Finalize (163) at length `n` with the family roots.
    pub async fn finalize(&mut self, doc: &Document, n: u32, family_roots: &[[u8; 32]]) {
        let ex = self.roles.executor.insecure_clone();
        let mut data = vec![TAG_FINALIZE_DOCUMENT];
        data.extend_from_slice(&doc.descriptor);
        data.extend_from_slice(&n.to_le_bytes());
        data.extend_from_slice(&(family_roots.len() as u16).to_le_bytes());
        for r in family_roots {
            data.extend_from_slice(r);
        }
        let metas = vec![
            AccountMeta::new(ex.pubkey(), true),
            AccountMeta::new(doc.dcm2, false),
            AccountMeta::new(doc.dcr2, false),
            AccountMeta::new_readonly(self.dtu1, false),
        ];
        self.chain.send(&ex, &[], data, metas).await.expect("finalize (163)");
    }

    /// Tag 177's seven metas, signed by the permissionless prover.
    pub fn attest_metas(&self, prover: Pubkey, doc: &Document) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(prover, true),
            AccountMeta::new(doc.dcm2, false),
            AccountMeta::new(doc.dpr2, false),
            AccountMeta::new(doc.dcr2, false),
            AccountMeta::new_readonly(self.pt2s, false),
            AccountMeta::new_readonly(self.routes, false),
            AccountMeta::new_readonly(self.geometry, false),
        ]
    }

    /// Attest each re-derived output (177), signed by the second identity.
    pub async fn attest(&mut self, doc: &Document, proofs: &[Rekeyed]) {
        let prover = self.roles.signer.insecure_clone();
        let metas = self.attest_metas(prover.pubkey(), doc);
        for p in proofs {
            self.chain
                .send(&prover, &[], p.data.clone(), metas.clone())
                .await
                .unwrap_or_else(|e| panic!("attest (177) of output {}: {e:?}", u32::from_le_bytes(p.data[33..37].try_into().unwrap())));
        }
    }

    /// The whole honest completion path on the K=80 rung-D template: a
    /// binding at `first = 29`, outputs re-keyed with chosen tokens (others
    /// get a non-stop token), init, land, finalize at `n`, attest `[0, L)`.
    pub async fn attested_completion(
        &mut self,
        rung: &RungD,
        binding: &Binding2,
        n: u32,
        tokens: &[(u32, u32)],
        variant: u8,
    ) -> (Document, Vec<Rekeyed>) {
        assert_eq!(self.fixture.kind, FixtureKind::K80, "the rung-D run is the K=80 template's");
        let binding = Binding2 { request_id: [variant.max(1); 32], ..*binding };
        let first = binding.output_first_position;
        let l = binding.output_span(n);
        let terms = self.default_terms();
        let descriptor = self.descriptor(&binding, &terms, &rung.family_body);
        let proofs: Vec<Rekeyed> = (0..l)
            .map(|i| {
                let token = tokens.iter().find(|(j, _)| *j == i).map(|(_, t)| *t).unwrap_or(0x00ff_fffe);
                rekey_with(self, rung, &descriptor, i, first + i, cell_with_token(token))
            })
            .collect();
        let mut roots = rung.position_roots[..n as usize].to_vec();
        for p in &proofs {
            roots[p.p as usize] = p.root;
        }
        let doc = self.init_document(&binding, &terms, &rung.family_body, &[]).await;
        assert_eq!(doc.descriptor, descriptor);
        self.land(&doc, 0, &roots).await;
        self.finalize(&doc, n, &rung.family_roots).await;
        self.attest(&doc, &proofs).await;
        (doc, proofs)
    }
}

fn node_parent(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    height: u8,
    left: ([u8; 32], u32, u32),
    right: ([u8; 32], u32, u32),
) -> ([u8; 32], u32, u32) {
    let digest = h::hash(
        b"node/2",
        &[descriptor, &[kind], &scope.to_le_bytes(), &left.1.to_le_bytes(), &right.2.to_le_bytes(), &[height, 1], &left.0, &right.0],
    );
    (digest, left.1, right.2)
}

/// Re-key the duplicate-last siblings of a path for a new leaf value.
fn rekey_duplicates(descriptor: &[u8; 32], kind: u8, scope: u32, count: u32, index: u32, value: [u8; 32], path: &mut [[u8; 32]]) {
    let (mut index, mut width, mut span) = (index, count, 1u32);
    let mut node = (value, index, index + 1);
    for level in 0..path.len() {
        let sib = index ^ 1;
        let sibling = if sib >= width {
            path[level] = node.0;
            node
        } else {
            let first = sib.checked_mul(span).unwrap();
            (path[level], first, first.saturating_add(span).min(count))
        };
        node = if index % 2 == 0 {
            node_parent(descriptor, kind, scope, level as u8 + 1, node, sibling)
        } else {
            node_parent(descriptor, kind, scope, level as u8 + 1, sibling, node)
        };
        index /= 2;
        width = width.div_ceil(2);
        span *= 2;
    }
}

/// Re-derive output `index`'s attestation at position `p` for `descriptor`
/// with cell `value`, from the retained packet's tail and paths.
pub fn rekey_with(t: &Template, rung: &RungD, descriptor: &[u8; 32], index: u32, p: u32, value: Vec<u8>) -> Rekeyed {
    let packet = &rung.attestations[index as usize];
    assert_eq!(packet[0], TAG_ATTEST_OUTPUT, "the retained packet is a tag 177");
    let w = t.locator.width as usize;
    assert_eq!(value.len(), w, "the value is one cell at the document's width");
    let tail_len = u16::from_le_bytes([packet[37 + w], packet[38 + w]]) as usize;
    let tail_at = 39 + w;
    let height = packet[tail_at + tail_len] as usize;
    let path_at = tail_at + tail_len + 1;
    let mut path: Vec<[u8; 32]> =
        packet[path_at..path_at + 32 * height].chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
    let (ordinal, proof_table, spp1_path, _) =
        challenge::decode_spp1(&packet[path_at + 32 * height..]).expect("a self-delimiting SPP1");
    let mut spp1_path = spp1_path;
    let x = t.fixture.view();
    let te = x.old_to_new(t.locator.base_entry, p).unwrap().expect("the base entry is live at p");
    let e = x.entry(p, te).unwrap();
    let route = x.route(&e, e.read_count + t.locator.write as u16).unwrap();
    let c = x.coordinate(p, te).unwrap();
    let (mut entries, mut seg_ordinal) = (0u32, 0u16);
    for s in 0..x.segment_count as usize {
        let (id, n) = x.segment_row(p, s).unwrap();
        if id == c.segment {
            seg_ordinal = s as u16;
            entries = n;
        }
    }
    assert_eq!(ordinal, seg_ordinal, "the proof's ordinal is the plan's");
    let coordinate = h::Coordinate { position: p, segment: c.segment, entry: c.local };
    let digest = h::write_digest(descriptor, coordinate, route.region_id, route.effective_offset, &value).unwrap();
    let mut tail = packet[tail_at..tail_at + tail_len].to_vec();
    let writes = u16::from_le_bytes([tail[LEAF_WRITE_COUNT_AT], tail[LEAF_WRITE_COUNT_AT + 1]]) as usize;
    let mut seen = false;
    for i in 0..writes {
        let at = LEAF_WRITES_AT + 48 * i;
        if tail[at..at + 2] == route.region_id.to_le_bytes()
            && tail[at + 4..at + 8] == route.byte_length.to_le_bytes()
            && tail[at + 8..at + 16] == route.effective_offset.to_le_bytes()
        {
            tail[at + 16..at + 48].copy_from_slice(&digest);
            seen = true;
            break;
        }
    }
    assert!(seen, "the retained leaf carries this cell's own write row");
    let mut leaf = Vec::new();
    leaf.extend_from_slice(LEAF_DOMAIN);
    leaf.extend_from_slice(descriptor);
    leaf.extend_from_slice(&coordinate.bytes());
    leaf.extend_from_slice(&tail);
    let leaf_hash = sha256(&[&leaf]);
    rekey_duplicates(descriptor, 1, p, entries, c.local, leaf_hash, &mut path);
    let tree = challenge::dl_fold(descriptor, 1, p, entries, c.local, &leaf_hash, &path).expect("the re-keyed path folds");
    let segment_root = h::hash(
        b"segment-root/2",
        &[descriptor, &p.to_le_bytes(), &c.segment.to_le_bytes(), &entries.to_le_bytes(), &tree, &[1]],
    );
    rekey_duplicates(descriptor, 2, p, t.segments as u32, ordinal as u32, segment_root, &mut spp1_path);
    let root = challenge::spp1_position_root(
        descriptor,
        p,
        t.segments,
        &segment_root,
        ordinal,
        &proof_table,
        &spp1_path,
        &x.segment_table_root(p).unwrap(),
    )
    .unwrap()
    .expect("the re-keyed SPP1 folds");
    let mut data = vec![TAG_ATTEST_OUTPUT];
    data.extend_from_slice(descriptor);
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&value);
    data.extend_from_slice(&(tail.len() as u16).to_le_bytes());
    data.extend_from_slice(&tail);
    data.push(height as u8);
    for s in &path {
        data.extend_from_slice(s);
    }
    data.extend_from_slice(&ordinal.to_le_bytes());
    data.push(spp1_path.len() as u8);
    data.push(0);
    data.extend_from_slice(&proof_table);
    for s in &spp1_path {
        data.extend_from_slice(s);
    }
    Rekeyed { data, root, value, p }
}
