// SPDX-License-Identifier: GPL-3.0-only

//! Portable DCG record commitment primitives.

pub mod fold;

pub mod err {
    pub const CLOSURE_FRONTIER: u32 = 459;
    pub const CLOSURE_ROOT_MISMATCH: u32 = 452;
    pub const CLOSURE_MEMBERSHIP: u32 = 457;
}

pub const COMMIT_FRONTIER_LEVELS: usize = 32;
pub const TAG_CLOSURE_NODE: &[u8] = b"basanos/dcg-closure-node/1";
pub const TAG_CLOSURE_ROOT: &[u8] = b"basanos/dcg-closure-root/1";
