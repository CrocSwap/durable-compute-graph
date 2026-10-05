// SPDX-License-Identifier: GPL-3.0-only

//! The kernel-kit conformance server for this application's kernels.

use dcg_program::kernel_kit::conformance::{serve, Registry};
use dcg_session_app::TALLY;

fn main() -> std::io::Result<()> {
    let registry = Registry { app: None, stateful: &[&TALLY] };
    serve(&registry, std::io::stdin().lock(), std::io::stdout().lock())
}
