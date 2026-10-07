// SPDX-License-Identifier: GPL-3.0-only

//! Deprecated placeholders for the retired revision-8 hooks.
//!
//! Revision 8 (the Basanos document lifecycle, tags 115-200) was removed after
//! v0.1.0-alpha. `ApplicationManifest` keeps its `hooks` and `decision_routes`
//! fields for one release so existing manifests compile unchanged; no route
//! reads them. The next release removes the fields and this module.

/// Marker for the retired typed-decision route selector. No route calls it.
#[deprecated(note = "revision 8 is retired; no route reads ApplicationManifest::decision_routes")]
pub trait DecisionRouteSelector: Sync {}

/// Marker for the retired revision-8 record and admission hooks. No route
/// calls it.
#[deprecated(note = "revision 8 is retired; no route reads ApplicationManifest::hooks")]
pub trait ApplicationHooks: Sync {}

/// The inert value existing manifests name for `hooks` and `decision_routes`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Revision8CompatibilityAdapter;

pub const REVISION8_COMPATIBILITY: Revision8CompatibilityAdapter = Revision8CompatibilityAdapter;

#[allow(deprecated)]
impl DecisionRouteSelector for Revision8CompatibilityAdapter {}
#[allow(deprecated)]
impl ApplicationHooks for Revision8CompatibilityAdapter {}
