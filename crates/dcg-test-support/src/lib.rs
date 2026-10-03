// SPDX-License-Identifier: GPL-3.0-only
//! A real-flow state builder for DCG program tests (design
//! `docs/design/test-support-v1.md`).
//!
//! Tests ask for a protocol state; the builder reaches it by sending the
//! instructions that create it. Nothing here writes program-owned account
//! bytes except [`snapshot`], which only reloads accounts a real run of this
//! builder produced and which a regeneration check compares byte for byte.
//!
//! - [`target`]: the program under test (DCG or an application image such as
//!   Basanos's hybrid; native processor or SBF image).
//! - [`chain`]: the test bank, funded actors and senders.
//! - [`fixtures`]: retained real-pipeline artifacts and registry rows.
//! - [`template`]: the `Template` stage (registry, PT1X/PT2S upload and seal,
//!   template seal, admission).
//! - [`snapshot`]: saved real-flow states for expensive stages.

pub mod chain;
pub mod decision;
pub mod challenge;
pub mod document;
pub mod fixtures;
pub mod snapshot;
pub mod target;
pub mod template;

pub use chain::{custom, Chain};
pub use challenge::{Challenge, CommittedLeaf};
pub use document::{Document, Rekeyed, RungD};
pub use fixtures::{Fixture, FixtureKind};
pub use target::Target;
pub use template::{Roles, Template, TemplateOptions};
