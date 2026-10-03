// SPDX-License-Identifier: GPL-3.0-only
//! Typed-decision documents on the F47 (compiler-v1, PXR1) template, by the
//! real instructions: UnifiedInit with an option table, land, finalize.

use crate::challenge::CommittedLeaf;
use crate::document::{Document, RungD};
use crate::fixtures::FixtureKind;
use crate::template::{f47_position, Template};
use dcg_program::hash::sha256;
use dcg_program::kernels::decision;
use dcg_program::unified::document::{Binding2, DECISION_MODE, OPTION_REGION_AT};
use solana_signer::Signer;

impl Template {
    /// The decision position (the last prompt position) and its form-47 entry.
    pub fn decision_entry(&self) -> (u32, u32) {
        let x = self.fixture.view();
        let position = f47_position();
        let entry = x.entry_count(position).unwrap() - 1;
        assert_eq!(x.entry(position, entry).unwrap().kernel_index, decision::FORM_ID);
        (position, entry)
    }

    /// A decision binding over `options` (u32 token ids) at the decision position.
    pub fn decision_binding(&self, options: &[u32], variant: u8) -> (Binding2, Vec<u8>) {
        let x = self.fixture.view();
        let (position, _) = self.decision_entry();
        let table: Vec<u8> = options.iter().flat_map(|o| o.to_le_bytes()).collect();
        let binding = Binding2 {
            executor: self.roles.executor.pubkey().to_bytes(),
            request_id: [variant.max(1); 32],
            consumer_digest: [6u8; 32],
            seed: [0; 32],
            output_first_position: position,
            output_count: 1 + options.len() as u32,
            output_base_entry: x.base_entries - 1,
            output_write: 0,
            output_width: 4,
            decision_flags: DECISION_MODE,
            option_count: options.len() as u8,
            prompt_positions: position + 1,
            stop_plus_one: 0,
            option_table_offset: OPTION_REGION_AT as u16,
            option_table_sha256: sha256(&[&table]),
        };
        (binding, table)
    }

    /// A finalized decision document over `options` whose decision position
    /// commits `leaf` at the form-47 entry; earlier positions carry the
    /// executor's own roots.
    pub async fn decision_document(&mut self, rung: &RungD, options: &[u32], leaf: [u8; 32], variant: u8) -> (Document, CommittedLeaf) {
        assert_eq!(self.fixture.kind, FixtureKind::F47, "a decision document needs the PXR1 template");
        let (binding, table) = self.decision_binding(options, variant);
        let terms = self.default_terms();
        let descriptor = self.descriptor(&binding, &terms, &rung.family_body);
        let (position, entry) = self.decision_entry();
        let committed = self.commit_leaf(&descriptor, position, entry, leaf);
        let mut roots: Vec<[u8; 32]> =
            (0..position).map(|i| rung.position_roots.get(i as usize).copied().unwrap_or_else(|| sha256(&[b"executor-root", &i.to_le_bytes()]))).collect();
        roots.push(committed.position_root);
        let doc = self.init_document(&binding, &terms, &rung.family_body, &table).await;
        assert_eq!(doc.descriptor, descriptor);
        self.land(&doc, 0, &roots).await;
        self.finalize(&doc, position + 1, &rung.family_roots).await;
        (doc, committed)
    }
}
