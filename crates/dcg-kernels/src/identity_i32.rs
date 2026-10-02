// SPDX-License-Identifier: GPL-3.0-only
//! `identity_i32/1`: copies its canonical input exactly.

pub fn run(a: &[u8], out: &mut [u8]) -> Result<usize, u16> {
    out[..4].copy_from_slice(&a[..4]);
    Ok(4)
}
