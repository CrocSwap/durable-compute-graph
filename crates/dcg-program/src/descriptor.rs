// SPDX-License-Identifier: GPL-3.0-only

//! Shared error shape used by the DCG closure fold.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcgError(pub u32);
