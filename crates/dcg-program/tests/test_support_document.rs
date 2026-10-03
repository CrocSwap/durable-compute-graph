//! The `dcg-test-support` Document, Landed, Finalized and Attested stages,
//! by real instructions on the K=80 rung-D template.

use dcg_program::unified::document::{FLAG_FINAL, FLAG_ROOT_ONLY, FLAG_SEALED};
use dcg_test_support::{FixtureKind, RungD, Target, Template, TemplateOptions};
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

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn init_land_finalize_by_real_instructions() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
    let rung = RungD::load();
    let binding = t.completion_binding(29, 50);
    let terms = t.default_terms();
    let doc = t.init_document(&binding, &terms, &rung.family_body, &[]).await;
    let dcm2 = t.chain.data(doc.dcm2).await;
    assert_eq!(&dcm2[..4], b"DCM2");
    assert_eq!(u32_at(&dcm2, 84), 0, "no position landed yet");
    t.land(&doc, 0, &rung.position_roots[..31]).await;
    assert_eq!(u32_at(&t.chain.data(doc.dcm2).await, 84), 31, "31 roots landed");
    t.finalize(&doc, 31, &rung.family_roots).await;
    let flags = u32_at(&t.chain.data(doc.dcm2).await, 6) as u16;
    assert_eq!(flags & (FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED), FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attested_completion_by_real_proofs() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
    let rung = RungD::load();
    let binding = t.completion_binding(29, 50);
    let (doc, proofs) = t.attested_completion(&rung, &binding, 31, &[], 81).await;
    assert_eq!(proofs.len(), 1, "L = 1 at n = 31");
    let dcr2 = t.chain.data(doc.dcr2).await;
    assert_eq!(u32_at(&dcr2, 204), 1, "every output of [0, L) is attested");
}
