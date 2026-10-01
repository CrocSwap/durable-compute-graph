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
    /// DRB1 v2 encodes the option count as `u8`; the arithmetic accepts every
    /// nonzero count representable by that field, independently of a form's
    /// tighter admission limit.
    pub const MAX_OPTIONS: usize = u8::MAX as usize;
    pub const ERR_OPTION_RANGE: u32 = 813;
    pub const ERR_OPTION_COUNT_ZERO: u32 = 814;
    pub const ERR_OPTION_COUNT_CAP: u32 = 815;
    /// Revision-selected Form-47 geometry version. Revision 7 retains the
    /// original version-1 bytes; revision 8 consumes compiler-v1 version 2.
    const FORM_GEOMETRY_VERSION: u16 = if cfg!(feature = "revision-8") { 2 } else { 1 };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Refusal(pub u32);

    pub fn check_options(options: &[u32], logits: usize) -> Result<(), Refusal> {
        if options.is_empty() {
            return Err(Refusal(ERR_OPTION_COUNT_ZERO));
        }
        if options.len() > MAX_OPTIONS {
            return Err(Refusal(ERR_OPTION_COUNT_CAP));
        }
        for &option in options {
            if option as usize >= logits {
                return Err(Refusal(ERR_OPTION_RANGE));
            }
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
            return Err(Refusal(crate::descriptor::err::EXEC_KERNEL_GEOMETRY));
        }
        let option_capacity = raw[2] as usize;
        let option_region_id = u16::from_le_bytes([raw[4], raw[5]]);
        let logits_region_id = u16::from_le_bytes([raw[6], raw[7]]);
        let logits_base_offset = u64::from_le_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| Refusal(crate::descriptor::err::EXEC_KERNEL_GEOMETRY))?,
        );
        if option_capacity != 128
            || option_region_id != u16::MAX
            || logits_base_offset
                .checked_add((LOGITS_ROW_LENGTH * 8) as u64)
                .is_none()
        {
            return Err(Refusal(crate::descriptor::err::EXEC_KERNEL_GEOMETRY));
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

        #[cfg(feature = "revision-8")]
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
                assert_eq!(
                    decode_form_geometry(raw),
                    Err(Refusal(crate::descriptor::err::EXEC_KERNEL_GEOMETRY))
                );
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

        #[cfg(not(feature = "revision-8"))]
        #[test]
        fn revision7_form47_geometry_uses_version_one() {
            let mut version_one = COMPILER_V1_FORM47_GEOMETRY_V2;
            version_one[..2].copy_from_slice(&1u16.to_le_bytes());
            assert!(decode_form_geometry(&version_one).is_ok());

            assert_eq!(
                decode_form_geometry(&COMPILER_V1_FORM47_GEOMETRY_V2),
                Err(Refusal(crate::descriptor::err::EXEC_KERNEL_GEOMETRY))
            );
        }

        #[test]
        fn option_table_order_and_duplicates_are_preserved() {
            assert_eq!(check_options(&[5, 3], 8), Ok(()));
            assert_eq!(check_options(&[17, 17], 18), Ok(()));
            assert_eq!(check_options(&[17, 17], 17), Err(Refusal(ERR_OPTION_RANGE)));
        }

        #[test]
        fn option_table_refuses_only_empty_oversized_and_out_of_row_inputs() {
            assert_eq!(check_options(&[], 18), Err(Refusal(ERR_OPTION_COUNT_ZERO)));
            assert_eq!(
                check_options(&vec![0; MAX_OPTIONS + 1], usize::MAX),
                Err(Refusal(ERR_OPTION_COUNT_CAP))
            );
            assert_eq!(check_options(&[5, 3], 5), Err(Refusal(ERR_OPTION_RANGE)));
        }
    }
}
