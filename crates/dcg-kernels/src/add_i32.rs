// SPDX-License-Identifier: GPL-3.0-only
//! `add_i32/1`: checked signed 32-bit addition, little-endian.
use crate::ERR_OVERFLOW;

pub fn run(a: &[u8], b: &[u8], out: &mut [u8]) -> Result<usize, u16> {
    let a = i32::from_le_bytes([a[0], a[1], a[2], a[3]]);
    let b = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let sum = a.checked_add(b).ok_or(ERR_OVERFLOW)?;
    out[..4].copy_from_slice(&sum.to_le_bytes());
    Ok(4)
}
