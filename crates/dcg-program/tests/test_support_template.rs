//! The `dcg-test-support` Template stage reaches a sealed, admitted template
//! by real instructions alone (design docs/design/test-support-v1.md).

use dcg_program::pt2p_onchain as S;
use dcg_program::unified::config;
use dcg_test_support::template::Admission;
use dcg_test_support::{FixtureKind, Target, Template, TemplateOptions};
use solana_program_test::{processor, ProgramTest};
use solana_pubkey::Pubkey;
use std::path::PathBuf;

fn target() -> Target {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    Target::from_env(
        "BASANOS_DCG_V8_SBF",
        Pubkey::new_from_array([0x80; 32]),
        |id| ProgramTest::new("dcg_program", id, processor!(dcg_program::process_instruction)),
        &[src],
        "dcg_program",
    )
}

async fn check(kind: FixtureKind) {
    let Some(mut t) = Template::build(&target(), TemplateOptions::new(kind)).await else { return };
    let pt2s = t.chain.data(t.pt2s).await;
    assert_eq!(pt2s[S::OFF_STATE], S::STATE_SEALED);
    assert_eq!(&pt2s[S::OFF_LOCATOR..S::OFF_LOCATOR + 4], &t.locator.base_entry.to_le_bytes());
    assert_eq!(&pt2s[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43], &t.fixture.clause12[..], "clause-12 v4 recomputed");
    assert_eq!(dcg_program::hash::sha256(&[&pt2s]), t.pt2s_sha);
    let dtu1 = t.chain.data(t.dtu1).await;
    assert_eq!((&dtu1[..4], dtu1[6]), (&b"DTU1"[..], config::DTU1_STATE_LIVE));
    let drp2 = t.chain.data(t.drp2).await;
    assert_eq!(&drp2[..4], b"DRP2");
    let dea2 = t.chain.data(t.dea2).await;
    assert_eq!(&dea2[..4], b"DEA2");
    let flags = u16::from_le_bytes([dea2[6], dea2[7]]);
    assert_eq!(flags & 1, 1, "admission is complete");
    assert_eq!(u32::from_le_bytes(dea2[148..152].try_into().unwrap()), t.class_total, "every class admitted");
}

#[tokio::test(flavor = "multi_thread")]
async fn k80_template_by_real_instructions() {
    check(FixtureKind::K80).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn f47_template_by_real_instructions() {
    check(FixtureKind::F47).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_can_stop_after_begin() {
    let mut options = TemplateOptions::new(FixtureKind::K80);
    options.admission = Admission::Begun;
    let Some(mut t) = Template::build(&target(), options).await else { return };
    let dea2 = t.chain.data(t.dea2).await;
    assert_eq!(u32::from_le_bytes(dea2[148..152].try_into().unwrap()), 0, "no class admitted");
}

/// The regeneration check (owner decision 2026-10-02): a fresh real run of
/// the stage equals the saved snapshot byte for byte, and two fresh runs
/// equal each other. A mismatch means the program or builder changed and the
/// snapshot (or the key) is stale.
#[tokio::test(flavor = "multi_thread")]
async fn template_snapshots_regenerate_byte_for_byte() {
    use dcg_test_support::fixtures::Fixture;
    use dcg_test_support::snapshot::Snapshot;
    for kind in [FixtureKind::K80, FixtureKind::F47] {
        let target = target();
        let Some(fixture) = Fixture::load(kind) else { continue };
        let key = Template::snapshot_key(&target, &TemplateOptions::new(kind), &fixture);
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut t = Template::build(&target, TemplateOptions::new(kind)).await.unwrap();
            let keys = t.accounts();
            runs.push(Snapshot::capture(&mut t.chain, key, &keys).await);
        }
        assert_eq!(runs[0].differences(&runs[1]), Vec::<String>::new(), "{kind:?}: two real runs differ");
        match Snapshot::load(&key) {
            Some(saved) => assert_eq!(saved.differences(&runs[0]), Vec::<String>::new(), "{kind:?}: stale snapshot"),
            None => runs[0].save(),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_template_is_the_real_one() {
    // The first call may build and save; the second restores.
    for _ in 0..2 {
        let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
        let dea2 = t.chain.data(t.dea2).await;
        assert_eq!(u16::from_le_bytes([dea2[6], dea2[7]]) & 1, 1);
        assert_eq!(u32::from_le_bytes(dea2[148..152].try_into().unwrap()), t.class_total);
        assert_eq!(dcg_program::hash::sha256(&[&t.chain.data(t.pt2s).await]), t.pt2s_sha);
    }
}
