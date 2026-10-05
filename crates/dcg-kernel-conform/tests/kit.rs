// SPDX-License-Identifier: GPL-3.0-only

//! The kernel kit's declaration builder reproduces the hand-written
//! manifests, and the conformance server answers as documented.

use dcg_program::kernel::test_kernel::{ALPHA_MANIFEST_APP, BYTE_SUM, MODE_CONSENSUS_V1, MODE_OPTIMISTIC_V1, SHA256_CONCAT};
use dcg_program::kernel::{Kernel, KernelManifest, VersionedId, MODE_STEP_V21};
use dcg_program::kernel_kit::conformance::{answer, hex, Registry};
use dcg_program::kernel_kit::KernelDecl;
use dcg_program::stateful::v3::MODE_CONSENSUS_V3;
use dcg_program::stateful_test::{V3_COUNTER, V3_REJECT_COUNTER, V3_UNDECLARED_REJECT};

static SHA: KernelManifest = KernelDecl::new("dcg-test-sha-v1", 1, 1)
    .input(VersionedId { id: 3, version: 1 }, 65_536)
    .output(VersionedId { id: 4, version: 1 }, 32)
    .compute(100_000, 1)
    .modes(&[MODE_STEP_V21])
    .build();

static SUM: KernelManifest = KernelDecl::new("dcg-test-sum-v1", 1, 1)
    .input(VersionedId { id: 1, version: 1 }, 64)
    .output(VersionedId { id: 2, version: 1 }, 256)
    .compute(10_000, 64)
    .modes(&[MODE_CONSENSUS_V1, MODE_OPTIMISTIC_V1])
    .build();

#[test]
fn decl_reproduces_hand_written_manifests() {
    assert_eq!(SHA, *SHA256_CONCAT.manifest());
    assert_eq!(SUM, *BYTE_SUM.manifest());
    let m = V3_REJECT_COUNTER.manifest();
    let decl = KernelDecl::new("dcg-rejctr-v1", 1, 1)
        .input(m.input.id, 8)
        .output(m.output.id, 16)
        .state(m.state.unwrap().id, 16)
        .compute(80_000, 8)
        .modes(&[MODE_CONSENSUS_V3])
        .rejects_input()
        .build();
    assert_eq!(decl, *m);
}

fn ask(line: &str) -> String {
    let registry = Registry {
        app: &ALPHA_MANIFEST_APP,
        stateful: &[&V3_COUNTER, &V3_REJECT_COUNTER, &V3_UNDECLARED_REJECT],
    };
    answer(&registry, line)
}

fn id(name: &str) -> String {
    let mut raw = [0u8; 16];
    raw[..name.len()].copy_from_slice(name.as_bytes());
    hex(&raw)
}

#[test]
fn server_answers() {
    let sha = id("dcg-test-sha-v1");
    assert_eq!(
        ask(&format!("step {sha} 1 1 6869")),
        "output 8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
    );
    assert_eq!(ask(&format!("step {sha} 1 1")), "refused InvalidInput");
    // The STEP mode filter: the byte-sum kernel is in the manifest but not a
    // STEP kernel, and another version names no kernel.
    assert_eq!(ask(&format!("step {} 1 1 01", id("dcg-test-sum-v1"))), "not-step");
    assert_eq!(ask(&format!("step {sha} 2 1 01")), "not-step");
    let rej = id("dcg-rejctr-v1");
    let zero = "0".repeat(32);
    assert_eq!(ask(&format!("init {rej} 1 1 8,8")), format!("state {zero}"));
    assert_eq!(ask(&format!("init {rej} 1 1 16")), "refused kernel InvalidInput");
    assert_eq!(ask(&format!("advance {rej} 1 1 1 8,8 {zero} ee")), format!("reject 7 - {zero} judged accepted"));
    // A plain session may not reject; a dirty reject and a zero code are refused.
    assert_eq!(ask(&format!("advance {rej} 1 1 0 8,8 {zero} ee")), format!("reject 7 - {zero} judged refused"));
    assert!(ask(&format!("advance {rej} 1 1 1 8,8 {zero} ed")).ends_with("judged refused"));
    assert!(ask(&format!("advance {rej} 1 1 1 8,8 {zero} ec")).ends_with("judged refused"));
    let undeclared = id("dcg-undrej-v1");
    assert_eq!(ask(&format!("advance {undeclared} 1 1 1 8,8 {zero} ee")), format!("reject 7 - {zero} judged refused"));
    assert_eq!(ask(&format!("advance {rej} 1 1 0 8,8 {zero} eb")), format!("halt_before 48879 - {zero} judged accepted"));
    let max = "ff".repeat(8) + &"00".repeat(8);
    assert_eq!(ask(&format!("advance {rej} 1 1 0 8,8 {max} 01")), "failed Refused judged refused");
    assert_eq!(ask(&format!("init {} 1 1 8,8", id("dcg-test-sha-v1"))), "not-stateful");
    assert!(ask("advance zz 1 1").starts_with("error "));
}
