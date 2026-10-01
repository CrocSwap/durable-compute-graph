// SPDX-License-Identifier: GPL-3.0-only

//! Metadata-only adapter for the historical closed Basanos form registry.
//! Kernel code and producers remain in the application image. These rows let
//! migration tests compare the old lookup result without importing a model.

use crate::kernel::{ClosedRegistryAdapter, ClosedRegistryRow, RegistryInheritance};
use crate::unified::{
    config::{TemplateLimits, TEMPLATE_SEAL},
    registry::{RowV2, Shape, MAX_RS1_HEIGHT, POSITION_ROWS},
    terms::{
        Terms, Terms2, ABANDON_AFTER_SLOTS_FLOOR, BOND_ESCROW_RENT_EXEMPT, BOND_POLICY_CUSTOM,
        BOND_POLICY_NONE, BPS_DENOMINATOR, CUSTOM_SETTLE_WINDOW_CAP, WINDOW_CAP,
    },
    DISPUTE_TERMS, FORM_ABSENT, OVER_CU, RANGE_BOUND, RESPOND_LIMIT, SHAPE_BOUND, WITHDRAW_ONLY,
    WITNESS_DOMAIN,
};
use crate::{position_template::InstantiatedRoute, pt2p};
use solana_program::program_error::ProgramError;

/// Application-owned typed-decision selection for a route vector sealed in a
/// PT2S document. The standalone compatibility selector has no producer and
/// returns `None`; an application image can pass its own selector to the
/// `pt2p_onchain::instantiate_with_selector` adapter.
pub trait DecisionRouteSelector: Sync {
    fn document_selected_routes(
        &self,
        pt2p: &pt2p::Pt2p<'_>,
        entry: pt2p::Entry,
        document: &[u8],
        routes: &[u8],
        payload_override: Option<&[u8]>,
    ) -> Result<Option<Vec<InstantiatedRoute>>, ProgramError>;
}

/// Revision-8 record and admission policy hooks. The records own parsing and
/// byte encoding; an application supplies checks for terms, template limits,
/// and admitted registry classes. The core always applies its frozen
/// revision-8 checks before `check_terms2_template`; an application hook may
/// add refusals, but cannot widen the core's template window.
pub trait ApplicationHooks: Sync {
    fn check_terms_v1(&self, terms: &Terms, round_floor_slots: u64) -> Result<(), u32>;
    fn check_terms_v2(&self, terms: &Terms2, round_floor_slots: u64) -> Result<(), u32>;
    fn check_terms2_template(&self, terms: &Terms2, limits: &TemplateLimits) -> Result<(), u32>;
    fn check_template_limits(&self, limits: &TemplateLimits, seal_slot: u64) -> Result<(), u32>;
    fn check_registry_class(&self, row: Option<&RowV2>, shape: &Shape) -> u32;
}

/// Frozen revision-8 compatibility rules used by the current standalone
/// dispatcher. New application images can provide another implementation
/// without changing record encodings.
#[derive(Clone, Copy, Debug, Default)]
pub struct Revision8CompatibilityAdapter;

pub const REVISION8_COMPATIBILITY: Revision8CompatibilityAdapter = Revision8CompatibilityAdapter;

impl DecisionRouteSelector for Revision8CompatibilityAdapter {
    fn document_selected_routes(
        &self,
        _pt2p: &pt2p::Pt2p<'_>,
        _entry: pt2p::Entry,
        _document: &[u8],
        _routes: &[u8],
        _payload_override: Option<&[u8]>,
    ) -> Result<Option<Vec<InstantiatedRoute>>, ProgramError> {
        Ok(None)
    }
}

impl ApplicationHooks for Revision8CompatibilityAdapter {
    fn check_terms_v1(&self, terms: &Terms, round_floor_slots: u64) -> Result<(), u32> {
        let custom = terms.settlement_program != [0; 32];
        if !(1..=WINDOW_CAP).contains(&terms.challenge_window_slots)
            || !(round_floor_slots.max(1)..=WINDOW_CAP).contains(&terms.response_window_slots)
            || terms.executor_reward_bps as u64 > BPS_DENOMINATOR
            || custom != (terms.custom_settle_window_slots != 0)
            || (custom
                && !(1..=CUSTOM_SETTLE_WINDOW_CAP).contains(&terms.custom_settle_window_slots))
            || !(1..=WINDOW_CAP).contains(&terms.result_retention_slots)
        {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    fn check_terms_v2(&self, terms: &Terms2, round_floor_slots: u64) -> Result<(), u32> {
        let custom = terms.settlement_program != [0; 32];
        if !(1..=WINDOW_CAP).contains(&terms.challenge_window_slots)
            || !(round_floor_slots.max(1)..=WINDOW_CAP).contains(&terms.response_window_slots)
            || terms.executor_reward_bps as u64 > BPS_DENOMINATOR
            || custom != (terms.custom_settle_window_slots != 0)
            || (custom
                && !(1..=CUSTOM_SETTLE_WINDOW_CAP).contains(&terms.custom_settle_window_slots))
            || !(1..=WINDOW_CAP).contains(&terms.result_retention_slots)
        {
            return Err(DISPUTE_TERMS);
        }
        let kind = terms.bond_policy_kind;
        if kind == BOND_POLICY_NONE
            || kind > BOND_POLICY_CUSTOM
            || terms.bond_slasher_bps as u64 > BPS_DENOMINATOR
            || terms.bond_remainder == [0; 32]
            || (kind == BOND_POLICY_CUSTOM) != custom
            || (kind == BOND_POLICY_CUSTOM && terms.bond_slasher_bps != 0)
            || (kind == BOND_POLICY_CUSTOM
                && terms.executor_bond_lamports != 0
                && terms.executor_bond_lamports < BOND_ESCROW_RENT_EXEMPT)
        {
            return Err(DISPUTE_TERMS);
        }
        if !(ABANDON_AFTER_SLOTS_FLOOR..=WINDOW_CAP).contains(&terms.abandon_after_slots) {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    fn check_terms2_template(&self, terms: &Terms2, limits: &TemplateLimits) -> Result<(), u32> {
        if !(limits.min_abandon_after_slots..=limits.max_abandon_after_slots)
            .contains(&terms.abandon_after_slots)
            || terms.challenge_window_slots > limits.max_challenge_window_slots
            || terms.response_window_slots > limits.max_response_window_slots
            || terms.abandon_after_slots > limits.max_document_lifetime_slots
        {
            return Err(DISPUTE_TERMS);
        }
        Ok(())
    }

    fn check_template_limits(&self, limits: &TemplateLimits, seal_slot: u64) -> Result<(), u32> {
        for limit in [
            limits.max_challenge_window_slots,
            limits.max_response_window_slots,
            limits.max_document_lifetime_slots,
            limits.max_abandon_after_slots,
            limits.min_abandon_after_slots,
        ] {
            if limit == 0 || limit.checked_add(seal_slot).is_none() {
                return Err(TEMPLATE_SEAL);
            }
        }
        if limits.min_abandon_after_slots > limits.max_abandon_after_slots
            || limits.max_abandon_after_slots > limits.max_document_lifetime_slots
        {
            return Err(TEMPLATE_SEAL);
        }
        Ok(())
    }

    fn check_registry_class(&self, row: Option<&RowV2>, shape: &Shape) -> u32 {
        let Some(row) = row else { return FORM_ABSENT };
        if row.respond_path != crate::envelope_seal::RESPOND_GENERIC {
            return WITHDRAW_ONLY;
        }
        if !(1..=crate::envelope_seal::CU_LIMIT).contains(&row.execute_cu)
            || !(1..=crate::envelope_seal::CU_LIMIT).contains(&row.respond_cu)
        {
            return OVER_CU;
        }
        if shape.reads > profile_v1::RESPOND_MAX_READS as u64
            || shape.asserted
            || shape.payload > profile_v1::RESPOND_MAX_PAYLOAD as u64
            || shape.range_slots > profile_v1::MAX_RANGE_SLOTS as u64
            || (shape.form == profile_v1::LINEAR_FORM_ID
                && shape.write_bytes > profile_v1::RESPOND_MAX_LINEAR_OUTPUT as u64)
        {
            return RESPOND_LIMIT;
        }
        if shape.position >= row.position_limit
            || (row.witness_kind == crate::envelope_seal::WITNESS_POSITION_ROW
                && shape.position as u64 >= POSITION_ROWS)
        {
            return WITNESS_DOMAIN;
        }
        if shape.range_slots > row.max_range_slots as u64
            || shape.rs1_height > row.max_rs1_height
            || shape.rs1_height > MAX_RS1_HEIGHT
        {
            return RANGE_BOUND;
        }
        if shape.reads > row.max_reads as u64
            || shape.writes > row.max_writes as u64
            || shape.read_bytes > row.max_read_bytes as u64
            || shape.write_bytes > row.max_write_bytes as u64
            || shape.payload > row.max_payload_bytes as u64
        {
            return SHAPE_BOUND;
        }
        0
    }
}

const FLY: &[u8] = b"basanos/fly31-int-v3/1";
const ARGMAX: &[u8] = b"basanos/dcg-argmax-i64/2";
const SCORES: &[u8] = b"basanos/qwen35-4b-attention-scores/2";
const PT1: &[u8] = b"basanos/qwen35-4b-pt1/1";
const A16: &[u8] = b"basanos/qwen35-4b-a16/2";

/// All 37 entries from the old compiled `IMPLEMENTATIONS` table, in its
/// original order. Machine/form identity, geometry/profile lengths and the
/// two lifecycle capabilities are preserved; no execution function is moved.
pub static BASANOS_REV8_ROWS: [ClosedRegistryRow; 37] = [
    ClosedRegistryRow {
        machine_name: Some(FLY),
        form_id: 31,
        geometry_bytes: 24,
        profile_bytes: 80,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: None,
        form_id: 22,
        geometry_bytes: 0,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(ARGMAX),
        form_id: 2,
        geometry_bytes: 16,
        profile_bytes: 260,
        closure_execute: true,
        private_supply_freeze: true,
    },
    ClosedRegistryRow {
        machine_name: Some(SCORES),
        form_id: 1,
        geometry_bytes: 44,
        profile_bytes: 356,
        closure_execute: false,
        private_supply_freeze: true,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 4,
        geometry_bytes: 39,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: true,
    },
    ClosedRegistryRow {
        machine_name: Some(A16),
        form_id: 4,
        geometry_bytes: 39,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: true,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 40,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 41,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 42,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 43,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 44,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 45,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 46,
        geometry_bytes: 44,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 27,
        geometry_bytes: 44,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 28,
        geometry_bytes: 28,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 29,
        geometry_bytes: 36,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 5,
        geometry_bytes: 30,
        profile_bytes: 32,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 16,
        geometry_bytes: 55,
        profile_bytes: 40,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 22,
        geometry_bytes: 19,
        profile_bytes: 40,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 30,
        geometry_bytes: 66,
        profile_bytes: 40,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(A16),
        form_id: 30,
        geometry_bytes: 66,
        profile_bytes: 40,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 3,
        geometry_bytes: 29,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(A16),
        form_id: 3,
        geometry_bytes: 29,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 6,
        geometry_bytes: 18,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 11,
        geometry_bytes: 29,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 12,
        geometry_bytes: 22,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 1,
        geometry_bytes: 26,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 2,
        geometry_bytes: 32,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 10,
        geometry_bytes: 34,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 13,
        geometry_bytes: 30,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 47,
        geometry_bytes: 16,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 6,
        geometry_bytes: 18,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 17,
        geometry_bytes: 26,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 18,
        geometry_bytes: 42,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(A16),
        form_id: 18,
        geometry_bytes: 42,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 19,
        geometry_bytes: 26,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
    ClosedRegistryRow {
        machine_name: Some(PT1),
        form_id: 21,
        geometry_bytes: 30,
        profile_bytes: 0,
        closure_execute: false,
        private_supply_freeze: false,
    },
];

static A16_EXCLUDED: [u16; 2] = [3, 4];
static INHERITANCE: [RegistryInheritance; 1] = [RegistryInheritance {
    machine_name: A16,
    base_machine_name: PT1,
    excluded_forms: &A16_EXCLUDED,
}];

pub static BASANOS_REV8_REGISTRY: ClosedRegistryAdapter<'static> =
    ClosedRegistryAdapter::new(&BASANOS_REV8_ROWS, &INHERITANCE);

/// Minimal revision-8 profile metadata retained for wire-compatibility checks.
/// It does not link model implementations or typed-decision producers.
pub mod profile_v1 {
    pub const POSITION_ROWS: u64 = 32_768;
    pub const MAX_RANGE_SLOTS: usize = 64;
    pub const RESPOND_MAX_READS: usize = 128;
    pub const RESPOND_MAX_PAYLOAD: usize = 66;
    pub const RESPOND_MAX_LINEAR_OUTPUT: usize = 2_048;
    pub const LINEAR_FORM_ID: u16 = 4;

    pub fn supported_form(form: u16) -> bool {
        matches!(
            form,
            1 | 2
                | 3
                | 4
                | 5
                | 6
                | 10
                | 11
                | 12
                | 13
                | 16
                | 17
                | 18
                | 19
                | 21
                | 22
                | 27
                | 28
                | 29
                | 30
                | 47
                | 256
                | 40..=46
        ) || (form == 48 && cfg!(feature = "revision-8"))
    }

    pub fn witness_kind(form: u16) -> u8 {
        match form {
            LINEAR_FORM_ID | 1 => 1,
            5 => 2,
            2 | 10 | 13 | 16 | 18 | 19 | 21 | 28 | 30 => 3,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision8_rows_preserve_machine_form_geometry_and_profile_facts() {
        assert_eq!(BASANOS_REV8_REGISTRY.rows().len(), 37);

        let argmax = BASANOS_REV8_REGISTRY.resolve(ARGMAX, 2).unwrap();
        assert_eq!((argmax.geometry_bytes, argmax.profile_bytes), (16, 260));
        assert!(argmax.closure_execute && argmax.private_supply_freeze);

        let neutral_window_hash = BASANOS_REV8_REGISTRY
            .resolve(b"unknown-machine", 22)
            .unwrap();
        assert_eq!(neutral_window_hash.machine_name, None);
        assert_eq!(neutral_window_hash.geometry_bytes, 0);

        let a16_attention = BASANOS_REV8_REGISTRY.resolve(A16, 27).unwrap();
        assert_eq!(a16_attention.machine_name, Some(PT1));
        assert_eq!(
            (a16_attention.geometry_bytes, a16_attention.profile_bytes),
            (44, 32)
        );

        let a16_conv = BASANOS_REV8_REGISTRY.resolve(A16, 30).unwrap();
        assert_eq!(a16_conv.machine_name, Some(A16));
        assert_eq!((a16_conv.geometry_bytes, a16_conv.profile_bytes), (66, 40));

        assert!(BASANOS_REV8_REGISTRY.admits_private_supply_freeze(A16));
        assert!(!BASANOS_REV8_REGISTRY.admits_private_supply_freeze(b"unknown-machine"));
        assert_eq!(BASANOS_REV8_REGISTRY.resolve(A16, 999), None);
    }
}
