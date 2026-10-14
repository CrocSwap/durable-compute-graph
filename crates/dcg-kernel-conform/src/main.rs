// SPDX-License-Identifier: GPL-3.0-only

//! Conformance server for DCG's example kernels: the alpha manifest's STEP
//! kernels and the v3 test counters (plain, rejecting, rejecting without the
//! capability, reading the session resource, and
//! taking ticks). See `docs/kernel-kit.md`.

use dcg_program::kernel::test_kernel::ALPHA_MANIFEST_APP;
use dcg_program::kernel_kit::conformance::{serve, Registry};
use dcg_program::stateful_test::{V3_COUNTER, V3_LANE_COUNTER, V3_REJECT_COUNTER, V3_RESOURCE_COUNTER, V3_TICK_COUNTER, V3_UNDECLARED_REJECT};

fn main() -> std::io::Result<()> {
    let registry = Registry {
        app: Some(&ALPHA_MANIFEST_APP),
        stateful: &[&V3_COUNTER, &V3_LANE_COUNTER, &V3_REJECT_COUNTER, &V3_UNDECLARED_REJECT, &V3_RESOURCE_COUNTER, &V3_TICK_COUNTER],
    };
    serve(&registry, std::io::stdin().lock(), std::io::stdout().lock())
}
