// SPDX-License-Identifier: GPL-3.0-only

//! The kernel-kit conformance server for this application's kernels.

use dcg_kernel_app::APPLICATION;
use dcg_program::kernel_kit::conformance::{serve, Registry};

fn main() -> std::io::Result<()> {
    serve(&Registry { app: Some(&APPLICATION), stateful: &[] }, std::io::stdin().lock(), std::io::stdout().lock())
}
