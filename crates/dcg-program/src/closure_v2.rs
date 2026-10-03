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
/// The leaf and node hashing a prover needs to build a real attestation
/// (used by `dcg-test-support`); public in every build.
pub use crate::closure_v2_tree::{hash, write_digest, Coordinate};

/// Typed producer and finalized-leaf proof helpers used by the revision-8
/// application dispute adapter. These helpers validate every program-owned
/// account through the shared provenance gate before trusting its contents.
#[path = "closure_v2_proof.rs"]
pub mod proof;

/// Revision-8 application dispute handlers. The shared state machine lives in
/// the program crate; application form and artifact semantics arrive through
/// the static app manifest.
pub use crate::closure_v2_generic::process_generic_dispute_tag;
