// SPDX-License-Identifier: GPL-3.0-only
//! Portable `no_std` kernel library for DCG v2 graphs. The same source runs on
//! the host and inside the SBF program image.
#![no_std]

pub mod add_i32;
pub mod identity_i32;

/// Stable kernel error codes (profile-1 assignment; the shared registry is OPEN).
pub const ERR_OVERFLOW: u16 = 1;
pub const ERR_BAD_INPUT: u16 = 2;
pub const ERR_UNKNOWN_KERNEL: u16 = 3;
pub const ERR_OUTPUT_CAPACITY: u16 = 4;

/// Registered kernel identities: (stable code, name, semantic version, abi version, input count).
pub const KERNEL_ADD_I32: u16 = 1;
pub const KERNEL_IDENTITY_I32: u16 = 2;

pub struct KernelInfo {
    pub code: u16,
    pub name: &'static str,
    pub semantic_version: u16,
    pub abi_version: u16,
    pub inputs: u8,
    pub input_bytes: u16,
    pub output_bytes: u16,
}

pub const REGISTRY: [KernelInfo; 2] = [
    KernelInfo { code: KERNEL_ADD_I32, name: "add_i32/v1", semantic_version: 1, abi_version: 1, inputs: 2, input_bytes: 4, output_bytes: 4 },
    KernelInfo { code: KERNEL_IDENTITY_I32, name: "identity_i32/v1", semantic_version: 1, abi_version: 1, inputs: 1, input_bytes: 4, output_bytes: 4 },
];

pub fn info(code: u16) -> Option<&'static KernelInfo> {
    REGISTRY.iter().find(|k| k.code == code)
}

/// Execute one registered kernel. Inputs are canonical byte strings; the
/// output is written into `out` and its length is returned.
pub fn execute(code: u16, inputs: &[&[u8]], out: &mut [u8]) -> Result<usize, u16> {
    let k = info(code).ok_or(ERR_UNKNOWN_KERNEL)?;
    if inputs.len() != k.inputs as usize || inputs.iter().any(|i| i.len() != k.input_bytes as usize) {
        return Err(ERR_BAD_INPUT);
    }
    if out.len() < k.output_bytes as usize {
        return Err(ERR_OUTPUT_CAPACITY);
    }
    match code {
        KERNEL_ADD_I32 => add_i32::run(inputs[0], inputs[1], out),
        KERNEL_IDENTITY_I32 => identity_i32::run(inputs[0], out),
        _ => Err(ERR_UNKNOWN_KERNEL),
    }
}
