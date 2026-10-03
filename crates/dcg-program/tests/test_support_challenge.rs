//! The `dcg-test-support` Challenge stage and the response upload, by real
//! instructions: a challenger opens a leaf challenge (166) on a real
//! attestation, and the executor uploads its answer (115-118).

use dcg_program::closure_v2_response::{self as response, MAX_BODY};
use dcg_program::hash::sha256;
use dcg_program::unified::{challenge, CL_PATH};
use dcg_test_support::{custom, FixtureKind, RungD, Target, Template, TemplateOptions};
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

const BAD: u32 = 730;
const AUTH: u32 = 731;
const STATE: u32 = 733;
const PROOF: u32 = 734;

#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_challenge_opens_on_a_real_attestation_and_a_false_path_is_refused() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
    let rung = RungD::load();
    let binding = t.completion_binding(29, 50);
    let (doc, proofs) = t.attested_completion(&rung, &binding, 31, &[], 81).await;

    // The attacker: a challenger whose segment path does not open the landed root.
    let mut cheat = t.challenge_leaf_packet(&doc, &proofs[0], 12);
    cheat[76] ^= 1;
    assert_eq!(custom(t.send_challenge_leaf(&doc, cheat).await), CL_PATH);
    let rejected = t.challenge_record(&doc, 12);
    assert!(t.chain.account(rejected).await.is_none(), "no record is created");
    assert_eq!(u32_at(&t.chain.data(doc.dcm2).await, 128), 0, "the refusal opens nothing");

    let c = t.open_leaf_challenge(&doc, &proofs[0], 11).await;
    let dcr1 = t.chain.data(c.record).await;
    assert_eq!(dcr1[4], challenge::PHASE_RESPOND, "the honest class is admitted at fix-point");
    assert_eq!(u32_at(&dcr1, 140), 11, "the record keeps the open nonce");
    assert_eq!(dcr1[challenge::RESPONSE_BUMP_AT], response::address(&t.program, &c.record).1.value());
    assert_eq!(u32_at(&t.chain.data(doc.dcm2).await, 128), 1, "DCM2 counts one open challenge");
}

/// The executor uploads a maximum-size answer in 900-byte chunks. Exact
/// retries are no-ops; an altered retry, a skipped chunk, a write past the
/// end, an early seal and an oversize declaration are refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_maximum_response_uploads_in_chunks_with_retries() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
    let rung = RungD::load();
    let binding = t.completion_binding(29, 50);
    let (doc, proofs) = t.attested_completion(&rung, &binding, 31, &[], 81).await;
    let c = t.open_leaf_challenge(&doc, &proofs[0], 11).await;

    let body: Vec<u8> = (0..MAX_BODY).map(|i| (i * 31 + i / 977) as u8).collect();
    let digest = sha256(&[&body]);
    assert_eq!(custom(t.response_begin(&c, MAX_BODY as u32 + 1, digest).await), BAD, "over the body bound");
    assert_eq!(custom(t.response_begin(&c, MAX_BODY as u32, [0; 32]).await), BAD, "a zero digest");
    t.response_begin(&c, MAX_BODY as u32, digest).await.expect("begin (115)");
    assert_eq!(custom(t.response_begin(&c, MAX_BODY as u32, digest).await), AUTH, "a second begin: the response is no longer a system account");
    assert_eq!(custom(t.response_write(&c, 0, &body[..900]).await), STATE, "a write before the account has grown");
    let grows = t.response_grow_all(&c).await;
    assert_eq!(grows, (MAX_BODY - 0).div_ceil(10_240), "one grow per 10,240 bytes");
    assert_eq!(custom(t.response_seal(&c).await), PROOF, "an empty body does not seal");

    let chunks: Vec<&[u8]> = body.chunks(900).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let at = (i * 900) as u32;
        t.response_write(&c, at, chunk).await.unwrap_or_else(|e| panic!("write {i}: {e:?}"));
        if i == 3 {
            t.response_write(&c, at, chunk).await.expect("an exact retry is a no-op");
            t.response_write(&c, 0, chunks[0]).await.expect("an exact retry of an earlier chunk is a no-op");
            let mut altered = chunk.to_vec();
            altered[0] ^= 1;
            assert_eq!(custom(t.response_write(&c, at, &altered).await), STATE, "an altered retry");
            assert_eq!(custom(t.response_write(&c, at + 1800, chunks[5]).await), STATE, "a skipped chunk");
            assert_eq!(custom(t.response_seal(&c).await), PROOF, "a partial body does not seal");
        }
    }
    let past = MAX_BODY as u32 - 10;
    assert_eq!(custom(t.response_write(&c, past, &[0u8; 20]).await), STATE, "a write past the end");
    t.response_seal(&c).await.expect("the full body seals (118)");
    t.response_seal(&c).await.expect("sealing is idempotent");
    assert!(t.response_write(&c, 0, chunks[0]).await.is_err(), "a sealed body takes no writes");
    let raw = t.chain.data(c.response).await;
    assert_eq!(u32_at(&raw, 76) as usize, MAX_BODY);
    assert_eq!(&raw[response::HEADER..], &body[..]);
}

/// A body that does not match its declared digest never seals.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_with_the_wrong_digest_does_not_seal() {
    let Some(mut t) = Template::build_cached(&target(), TemplateOptions::new(FixtureKind::K80)).await else { return };
    let rung = RungD::load();
    let binding = t.completion_binding(29, 50);
    let (doc, proofs) = t.attested_completion(&rung, &binding, 31, &[], 81).await;
    let c = t.open_leaf_challenge(&doc, &proofs[0], 11).await;
    let body = vec![7u8; 2_000];
    let mut wrong = body.clone();
    wrong[1_999] = 8;
    t.response_begin(&c, 2_000, sha256(&[&wrong])).await.expect("begin (115)");
    t.response_grow_all(&c).await;
    t.response_write(&c, 0, &body[..900]).await.unwrap();
    t.response_write(&c, 900, &body[900..1800]).await.unwrap();
    t.response_write(&c, 1800, &body[1800..]).await.unwrap();
    assert_eq!(custom(t.response_seal(&c).await), PROOF);
}
