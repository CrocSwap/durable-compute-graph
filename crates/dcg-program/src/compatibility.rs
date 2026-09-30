// SPDX-License-Identifier: GPL-3.0-only

//! Metadata-only adapter for the historical closed Basanos form registry.
//! Kernel code and producers remain in the application image. These rows let
//! migration tests compare the old lookup result without importing a model.

use crate::kernel::{ClosedRegistryAdapter, ClosedRegistryRow, RegistryInheritance};

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
    use solana_program::program_error::ProgramError;

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
                | 48
                | 256
                | 40..=46
        )
    }

    pub fn witness_kind(form: u16) -> u8 {
        match form {
            LINEAR_FORM_ID | 1 => 1,
            5 => 2,
            2 | 10 | 13 | 16 | 18 | 19 | 21 | 28 | 30 => 3,
            _ => 0,
        }
    }

    /// The standalone image has no Basanos decision adapter. Ordinary sealed
    /// route vectors therefore pass through unchanged; a Basanos image can
    /// replace this hook with its compiled-in typed-decision selector.
    pub(crate) fn document_selected_routes(
        _pt2p: &crate::pt2p::Pt2p<'_>,
        _entry: crate::pt2p::Entry,
        _document: &[u8],
        _routes: &[u8],
        _payload_override: Option<&[u8]>,
    ) -> Result<Option<Vec<crate::position_template::InstantiatedRoute>>, ProgramError> {
        Ok(None)
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
