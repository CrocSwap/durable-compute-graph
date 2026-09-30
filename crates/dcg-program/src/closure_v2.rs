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
