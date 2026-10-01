// SPDX-License-Identifier: GPL-3.0-only

//! Compatibility façade for HClosure callers while modules move to the
//! reusable commitment and account helper boundaries.

#[cfg(feature = "sbf-real-lifecycle-test")]
pub use crate::closure_v2_accounts::*;
#[cfg(not(feature = "sbf-real-lifecycle-test"))]
pub(crate) use crate::closure_v2_accounts::*;

#[cfg(feature = "sbf-real-lifecycle-test")]
pub use crate::closure_v2_tree::*;
#[cfg(not(feature = "sbf-real-lifecycle-test"))]
pub(crate) use crate::closure_v2_tree::*;

/// Typed producer and finalized-leaf proof helpers used by the revision-8
/// application dispute adapter. These helpers validate every program-owned
/// account through the shared provenance gate before trusting its contents.
#[path = "closure_v2_proof.rs"]
pub mod proof;

#[cfg(feature = "revision-8")]
#[path = "closure_v2_generic.rs"]
mod generic_dispute;
