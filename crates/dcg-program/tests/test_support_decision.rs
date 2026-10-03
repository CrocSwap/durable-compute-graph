//! Typed-decision documents on the F47 template, by real instructions, and
//! the fix-point's option-range conviction on a real tag-166 open.

use dcg_program::hash::sha256;
use dcg_program::kernels::decision::{ERR_OPTION_RANGE, LOGITS_ROW_LENGTH};
use dcg_program::unified::challenge;
use dcg_test_support::{custom, FixtureKind, RungD, Target, Template, TemplateOptions};

fn target() -> Target {
    dcg_test_support::dcg_program_target!()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn dev2_code(record: &[u8]) -> u32 {
    u32_at(record, challenge::DEV2_AT + 8)
}

/// Any executor-committed form-47 leaf: the fix-point's option check reads
/// the document's table, not the leaf.
fn some_leaf() -> [u8; 32] {
    sha256(&[b"executor decision leaf"])
}

#[tokio::test(flavor = "multi_thread")]
async fn a_decision_leaf_challenge_on_honest_options_is_admitted_for_response() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::F47)).await else { return };
    let rung = RungD::load();
    // Unsorted and duplicate ids are well-formed tables.
    let (doc, leaf) = t.decision_document(&rung, &[17, 5, 17], some_leaf(), 1).await;
    let c = t.open_committed_leaf(&doc, &leaf, 23).await.expect("a leaf challenge opens (166)");
    let record = t.chain.data(c.record).await;
    assert_eq!(record[4], challenge::PHASE_RESPOND, "DEV2 code {}", dev2_code(&record));
    assert_eq!(u32_at(&t.chain.data(doc.dcm2).await, 128), 1);
}

/// The current program never admits the table the conviction below needs.
#[cfg(not(feature = "test-legacy-unchecked-option-range"))]
#[tokio::test(flavor = "multi_thread")]
async fn init_refuses_an_option_outside_the_logits_row() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::F47)).await else { return };
    let rung = RungD::load();
    let (binding, table) = t.decision_binding(&[LOGITS_ROW_LENGTH as u32], 2);
    let terms = t.default_terms();
    let refusal = custom(t.try_init_document(&binding, &terms, &rung.family_body, &table).await.map(|_| ()));
    assert_eq!(refusal, ERR_OPTION_RANGE);
}

/// A document made by an older program (the legacy mode) carries an option
/// outside the logits row: the challenger's real open convicts the executor
/// at the fix-point with 813, in the same instruction.
#[cfg(feature = "test-legacy-unchecked-option-range")]
#[tokio::test(flavor = "multi_thread")]
async fn the_fix_point_convicts_a_legacy_document_with_an_option_outside_the_logits_row() {
    for swap_roles in [false, true] {
        let mut options = TemplateOptions::new(FixtureKind::F47);
        options.swap_roles = swap_roles;
        let Some(mut t) = Template::build_cached(&target(), options).await else { return };
        let rung = RungD::load();
        let (doc, leaf) = t.decision_document(&rung, &[LOGITS_ROW_LENGTH as u32], some_leaf(), 3).await;
        let c = t.open_committed_leaf(&doc, &leaf, 23).await.expect("a leaf challenge opens (166)");
        let record = t.chain.data(c.record).await;
        assert_eq!(record[4], challenge::PHASE_RULED, "swap_roles={swap_roles}");
        assert_eq!(record[5], 2, "the challenger wins; swap_roles={swap_roles}");
        assert_eq!(dev2_code(&record), ERR_OPTION_RANGE);
        let dcm2 = t.chain.data(doc.dcm2).await;
        assert_eq!(u32_at(&dcm2, 128), 1);
        assert_eq!(u32_at(&dcm2, 132), 1, "DCM2 counts one refuted output");
    }
}
