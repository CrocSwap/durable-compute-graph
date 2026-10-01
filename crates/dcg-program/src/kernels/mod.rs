// SPDX-License-Identifier: GPL-3.0-only

//! Revision-8 application-shape adapter. The model implementations and
//! producer logic remain in Basanos; this module keeps only the registration
//! facts that generic codecs need to preserve the existing wire behavior.

pub const MAX_EXEC_SPANS: usize = 16;

/// Machine selector retained by the compatibility adapter. The DeltaNet
/// implementation and profile remain in Basanos.
pub mod pt1_deltanet_core {
    pub const MACHINE_NAME_V7: &[u8] = b"basanos/qwen35-4b-a16/2";
}

pub mod decision {
    /// Existing Basanos typed-decision form IDs and limits, retained as an
    /// application adapter. The kernel that produces these forms is not here.
    pub const LOGITS_ROW_LENGTH: usize = 248_320;
    pub const FORM_ID: u16 = 47;
    pub const GATHER_FORM_ID: u16 = 48;
    pub const MAX_OPTIONS_SINGLE: usize = 80;
    pub const ERR_OPTION_RANGE: u32 = 813;
    /// Compiler-v1 Form-47 geometry version used by the revision-8 program.
    const FORM_GEOMETRY_VERSION: u16 = 2;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Refusal(pub u32);

    pub fn check_options(options: &[u32], logits: usize) -> Result<(), Refusal> {
        let mut previous = None;
        for &option in options {
            if option as usize >= logits || previous.is_some_and(|p| p >= option) {
                return Err(Refusal(ERR_OPTION_RANGE));
            }
            previous = Some(option);
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FormGeometry {
        pub option_capacity: usize,
        pub option_region_id: u16,
        pub logits_region_id: u16,
        pub logits_base_offset: u64,
    }

    /// Decode the Form-47 geometry bytes consumed by the existing descriptor
    /// admission path. This is the wire adapter only; it does not produce a
    /// decision or execute a kernel.
    pub fn decode_form_geometry(raw: &[u8]) -> Result<FormGeometry, Refusal> {
        if raw.len() != 16
            || u16::from_le_bytes([raw[0], raw[1]]) != FORM_GEOMETRY_VERSION
            || raw[3] != 0
        {
            return Err(Refusal(ERR_OPTION_RANGE));
        }
        let option_capacity = raw[2] as usize;
        let option_region_id = u16::from_le_bytes([raw[4], raw[5]]);
        let logits_region_id = u16::from_le_bytes([raw[6], raw[7]]);
        let logits_base_offset = u64::from_le_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| Refusal(ERR_OPTION_RANGE))?,
        );
        if option_capacity != 128
            || option_region_id != u16::MAX
            || logits_base_offset
                .checked_add((LOGITS_ROW_LENGTH * 8) as u64)
                .is_none()
        {
            return Err(Refusal(ERR_OPTION_RANGE));
        }
        Ok(FormGeometry {
            option_capacity,
            option_region_id,
            logits_region_id,
            logits_base_offset,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const COMPILER_V1_FORM47_GEOMETRY_V2: [u8; 16] = [
            0x02, 0x00, 0x80, 0x00, 0xff, 0xff, 0x07, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        #[test]
        fn form47_geometry_v2_compiler_golden_guard() {
            let decoded = decode_form_geometry(&COMPILER_V1_FORM47_GEOMETRY_V2)
                .expect("the compiler-v1 Form-47 geometry golden uses version 2");
            assert_eq!(
                decoded,
                FormGeometry {
                    option_capacity: 128,
                    option_region_id: u16::MAX,
                    logits_region_id: 7,
                    logits_base_offset: 16,
                }
            );

            let refuse = |raw: &[u8]| {
                assert_eq!(decode_form_geometry(raw), Err(Refusal(ERR_OPTION_RANGE)));
            };

            let mut wrong_version = COMPILER_V1_FORM47_GEOMETRY_V2;
            wrong_version[..2].copy_from_slice(&1u16.to_le_bytes());
            refuse(&wrong_version);

            let mut capacity_80 = COMPILER_V1_FORM47_GEOMETRY_V2;
            capacity_80[2] = 80;
            refuse(&capacity_80);

            let mut wrong_option_region = COMPILER_V1_FORM47_GEOMETRY_V2;
            wrong_option_region[4..6].copy_from_slice(&0u16.to_le_bytes());
            refuse(&wrong_option_region);

            refuse(&COMPILER_V1_FORM47_GEOMETRY_V2[..15]);
        }
    }
}
