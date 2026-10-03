#![cfg(all(feature = "revision-8", feature = "sbf-real-lifecycle-test"))]

//! Revision 8's init, land, finalize, attest and **resolve**, driven from real
//! instructions (`docs/spec/dcg-unified-v8.md` §1.6) natively over the **real
//! retained rung-D template** (the PWR1 and base triple under
//! `BASANOS_PT2P_ROOT`). The suite's fixture configuration pairs that K=80
//! completion fixture with the compiler-v1 PXR1 fixture under
//! `BASANOS_PT2P_F47_ROOT` for the Form-47 and Form-48 cases. The real
//! K=10,240 admission case uses the separate retained rung-D fixture selected
//! by `BASANOS_PT2P_K10240_ROOT`; it does not use the 128-option F47 bundle.
//! The dispute
//! position defaults to the retained p=29 fixture and is selectable with
//! `BASANOS_PT2P_F47_POSITION` for the K=10,240 p=10,239 measurement. Both are selected in the
//! same test invocation so all completion and decision cases run together.
//! The F47/F48 dispute tests exercise the generic tag-120/121 dispute path
//! against the retained compiler-v1 PXR1 fixture.
//!
//! Real here: the template, the plan view, the registry (tags 156-158 over the
//! v7 golden's rows), the template seal (tag 176), the DFS2 body, the position
//! roots (the executor's own, from
//! `tests/golden/dcg/unified_v1_executor_rung_d_80.json`), and UnifiedInit,
//! LandPositionRoots, FinalizeDocumentV5, AttestOutputV5 and ResolveResultV5.
//!
//! **The honest attest and resolve paths run end to end here**, over a
//! *re-keyed* proof set: the leaf, the value, the coordinate, the write row, the
//! segment, the SPP1 and the plan's table root are the executor's own, and the
//! three things that commit the **revision-7** descriptor -- the leaf's `write/2`
//! digest, the segment tree's `node/2` parents and the `segment-root/2` wrap --
//! are recomputed over this document's `/5` descriptor, because no retained
//! proof commits a `/5` digest. Two of the twelve path entries and one of the
//! SPP1's are recomputed because the duplicate-last tree ties them to the leaf
//! itself; the other ten and the other SPP1 entries are the retained document's
//! own digests. `rekey_with` re-keys over a **chosen** cell value, which is what
//! puts a chosen token id in a chosen output and attests it honestly instead of
//! forging a record the attest never wrote.
//!
//! Crafted, and labelled where each is used:
//!
//! * **the admission record**: the v7 golden's own DEA2 image with its four
//!   instance fields (registry, root, PT2S, PT2S digest) repointed at this
//!   fixture, because the class walk over 28,807 classes is 113 tag-160 calls
//!   and is not this slice. Every field `admission::view` checks (length, PDA,
//!   popcount, `complete`) is the golden's.
//! * **DTU1**: the seal creates it in the spec (§1.7) and that creation is
//!   stream C4's slice, so the fixture lays the record down at the program's own
//!   derived address. `init` re-derives the address, so a substituted or
//!   malformed DTU1 is refused rather than read.
//! * **the deadline fixtures**: `craft` writes a DCM2 v7, DPR2 and DCR2 v6 at
//!   their derived addresses with a chosen `init_slot`, which is how the 736
//!   refusals and the lifetime clamp are driven. The resolve's window is opened
//!   by **setting the clock** (`past_deadline`) rather than by warping, because
//!   `warp_to_slot` roots the bank and a root verifies the accounts hash across
//!   the skipped slots, which a fixture that installs accounts with
//!   `set_account` cannot then satisfy.
//! * **`rev8_resolve_cu_at_l_10240`** writes a DCR2 with `count = L = 10,240`
//!   and every bit set, rather than attesting 10,240 outputs: 10,240
//!   transactions and 10,240 re-keyed proofs is not this slice, and the CU
//!   figure is about the clause's scan and not about how the cells got there.
//! * **typed decisions**: UnifiedInit and the honest tag-120/121/124 cases use
//!   the retained compiler-v1 PXR1 fixture with 4-byte lanes. The remaining
//!   decision finalize, attest and resolve cases also cover K = 1, 4, 7, 8 and
//!   128 over crafted records.
//!
//! `result::resolve_check` -- the clause itself, with no accounts and no plan --
//! is covered separately and exhaustively in `unified_v8_resolve_check.rs`.
//!
//! Set `BASANOS_PT2P_ROOT` to the K=80 emission and
//! `BASANOS_PT2P_F47_ROOT` to a compiler-v1 PXR1 emission for the
//! documented all-cases fixture configuration. Without the needed artifact a
//! case prints a clear `SKIP` notice and returns. `BASANOS_DCG_V8_SBF=1` with
//! `BPF_OUT_DIR` naming an SBF image runs the same tests against that image, and
//! is how the tag-178 CU figures were taken.

use dcg_program::closure_v2 as h;
use dcg_program::envelope_seal as envelope;
use dcg_program::hash::sha256;
use dcg_program::kernels::decision;
use dcg_program::position_template as pt;
use dcg_program::pt2p::{self, Pt2p};
use dcg_program::pt2p_onchain as S;
use dcg_program::unified::address;
use dcg_program::unified::admission;
use dcg_program::unified::challenge;
use dcg_program::unified::classes::{class_count, rs1_height, total_entries};
use dcg_program::unified::config::{self, TemplateLimits};
use solana_account::AccountSharedData;
use solana_program::incinerator;

/// **The fixture template's own five limits** (spec §1.7). The example
/// template's, which are the four protocol-wide constants this branch used to
/// carry, kept at the same magnitudes so the numbers in the tests below are the
/// numbers they were; the *kind* of the number is what changed.
const EXAMPLE_LIMITS: TemplateLimits = TemplateLimits {
    max_challenge_window_slots: 1 << 26,
    max_response_window_slots: 1 << 23,
    max_document_lifetime_slots: 1 << 27,
    max_abandon_after_slots: 1 << 27,
    min_abandon_after_slots: 2_592_000,
};

/// A second template, whose limits the withdrawn constants made impossible.
const SHORT_LIMITS: TemplateLimits = TemplateLimits {
    max_challenge_window_slots: 1_000_000,
    max_response_window_slots: 40_960,
    max_document_lifetime_slots: 4_096_000,
    max_abandon_after_slots: 4_096_000,
    min_abandon_after_slots: 90_000,
};
use dcg_program::unified::document::{
    self, Binding2, Dpd2, Locator, BINDING_AT_V8, BINDING_BYTES_V8, BOND_RETURNED, DECISION_MODE,
    DECISION_WIDTH, DPR2_HEADER, FLAG_ARMED, FLAG_FINAL, FLAG_REFUTED, FLAG_ROOT_ONLY, FLAG_SEALED,
    OPTION_REGION_AT, TERMS_AT_V8,
};
use dcg_program::unified::events;
use dcg_program::unified::registry;
use dcg_program::unified::result;
use dcg_program::unified::terms::{
    Terms2, BOND_POLICY_CUSTOM, BOND_POLICY_STANDARD, TERMS_BYTES_V2,
};

#[cfg(feature = "sbf-unbound-form-test")]
static PREVIOUS_APP_MANIFEST: dcg_program::kernel::ApplicationManifest =
    dcg_program::kernel::ApplicationManifest {
        application_id: b"dcg-test-app/1",
        version: 1,
        kernels: &dcg_program::kernel::test_kernel::KERNELS,
        optimistic_replays: &dcg_program::kernel::test_kernel::REPLAY_BINDINGS,
        legacy_forms: &dcg_program::kernel::test_kernel::BYTE_SUM_REAL_LIFECYCLE_FORMS,
        require_legacy_form_binding: true,
        admission_scan: dcg_program::kernel::AdmissionScan::Full,
        hooks: &dcg_program::compatibility::REVISION8_COMPATIBILITY,
        decision_routes: &dcg_program::compatibility::REVISION8_COMPATIBILITY,
    };
use dcg_program::unified::{
    SETTLEMENT_PROGRAM, TAG_ATTEST_OUTPUT, TAG_CHALLENGE_LEAF, TAG_CHALLENGE_POSITION,
    TAG_CLOSE_DOCUMENT, TAG_CLOSE_TEMPLATE, TAG_DESCEND, TAG_FINALIZE_DOCUMENT,
    TAG_LAND_POSITION_ROOTS, TAG_REGISTRY_CREATE, TAG_REGISTRY_FREEZE, TAG_REGISTRY_WRITE,
    TAG_RESOLVE_RESULT, TAG_REVEAL, TAG_REVEAL_FAMILY_TABLE, TAG_REVEAL_POSITION,
    TAG_SELECT_SEGMENT, TAG_TEMPLATE_SEAL, TAG_UNIFIED_INIT,
};
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SYSTEM: Pubkey = solana_program::system_program::ID;
const CL_MALFORMED: u32 = 580;
const CL_COORDINATE: u32 = 581;
const CL_AUTHORITY: u32 = 582;
const DCR1_AUTH_REFUSAL: u32 = 731;
const CL_ROOT: u32 = 583;
const CL_MISSING: u32 = 591;
const CL_AFTER_FINAL: u32 = 592;
const APPEND_ORDER: u32 = 788;
const DISPUTE_TERMS: u32 = 791;
const TEMPLATE_SEAL: u32 = 793;
const TEMPLATE_USED: u32 = 812;
const CL_DEADLINE: u32 = 736;
const CL_PATH: u32 = 586;
const DCR1_PHASE_REFUSAL: u32 = 733;
const FORM48_PROOF_REFUSAL: u32 = 734;
const RUN_BINDING: u32 = 794;
const OUTPUT_PROOF: u32 = 795;
const PLAN_BINDING: u32 = 785;
const DOCUMENT_LENGTH: u32 = 816;
const RESULT_STATE: u32 = 796;
const CL_OVERFLOW: u32 = 598;
const BOND_HELD: u8 = 1;
const BOND_NONE: u8 = 0;
/// §1.1 check 11's floor, and the same model as `minimum_balance(0)`.
const ESCROW_FLOOR: u64 = 890_880;

/// The label the CU print carries, set by the case about to send.
static LABEL: std::sync::Mutex<&'static str> = std::sync::Mutex::new("");

/// Label the next CU print, so a measured figure names the row it came from.
fn label(what: &'static str) {
    *LABEL.lock().unwrap_or_else(|e| e.into_inner()) = what;
}

/// The label in force, for the CU print.
fn current_label() -> String {
    LABEL.lock().unwrap_or_else(|e| e.into_inner()).to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn d32(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().unwrap()
}

fn v7_golden() -> serde_json::Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/dcg/unified_v7.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The retained K=10,240 census rows and digest used by the actual high-capacity
/// template. The v7 golden's registry is intentionally a refusal fixture with
/// position_limit=80 and cannot stand in for this admission path.
fn k10240_registry_rows() -> (Vec<u8>, [u8; 32]) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/dcg/rev8_census_registry_rows_v1.tsv");
    let text = std::fs::read_to_string(path).unwrap();
    let digest = text
        .lines()
        .find_map(|line| line.strip_prefix("# source_census_digest\t"))
        .map(|hex| unhex(hex).try_into().unwrap())
        .expect("the K=10,240 census digest");
    let mut rows = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let row_hex = line.split('\t').nth(5).expect("row_hex column");
        rows.extend_from_slice(&unhex(row_hex));
    }
    assert_eq!(rows.len() % registry::ROW_BYTES, 0);
    (rows, digest)
}

/// The measured compiler-v1 registry input retained with the typed-decision
/// fixture. Unlike the older frozen census golden, it includes the measured
/// Form-47 and Form-48 rows needed to drive the real tag-157/tag-160 path.
fn decision_registry_rows() -> (Vec<u8>, [u8; 32]) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/dcg/rev8_census_registry_rows_v2.tsv");
    let text = std::fs::read_to_string(path).expect("read the retained decision registry golden");
    let census: [u8; 32] = text
        .lines()
        .find_map(|line| line.strip_prefix("# source_census_digest\t"))
        .map(|hex| unhex(hex).try_into().expect("32-byte census digest"))
        .expect("decision census digest");
    let expected_census: [u8; 32] =
        unhex("349c5d5e0e94b632295432e6b471a9d5024289a9f4d1bea675abd6e31011b400")
            .try_into()
            .unwrap();
    assert_eq!(census, expected_census);
    let mut rows = Vec::new();
    let mut row_count = 0usize;
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let columns = line.split('\t').collect::<Vec<_>>();
        assert_eq!(columns.len(), 2, "form_id and row_hex columns");
        let row = unhex(columns[1]);
        assert_eq!(row.len(), registry::ROW_BYTES);
        assert_eq!(
            u16::from_le_bytes(row[..2].try_into().unwrap()),
            columns[0].parse::<u16>().expect("form id"),
            "form id column matches encoded row"
        );
        rows.extend_from_slice(&row);
        row_count += 1;
    }
    assert_eq!(row_count, 31, "the measured registry has 31 rows");
    let gather = registry::find_row(&rows, decision::GATHER_FORM_ID)
        .unwrap()
        .expect("measured Form-48 registry row");
    assert_eq!((gather.respond_path, gather.witness_kind), (1, 0));
    (rows, census)
}

/// The executor's own rung-D run: position roots, attest packets and the
/// revision-7 descriptor they commit.
fn executor() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/dcg/unified_v1_executor_rung_d_80.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn artifacts_at(root: PathBuf) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let read = |name: &str| std::fs::read(root.join(name)).ok();
    let routes = read("base-routes.bin")?;
    let geometry = read("base-geometry.bin")?;
    let payloads = read("base-payloads.bin")?;
    let pwr1 = read("program.bin")?;
    let clause12 = read("clause12-v4.bin").unwrap_or_else(|| {
        let g = pt2p::Program::decode(&pwr1).expect("compiler-v1 PWR1 decodes");
        let view = Pt2p::new(&routes, &geometry, &payloads, None, g.clone())
            .expect("compiler-v1 PT2P view decodes");
        pt2p::encode_clause12_v4(view.position_count, view.segment_count, &g.digest()).to_vec()
    });
    Some((routes, geometry, payloads, pwr1, clause12))
}

fn artifacts() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let root = std::env::var_os("BASANOS_PT2P_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(
        "/Users/colkitt/sith/toys/crypto/basanos/out/runs/dcg-pt2-parametric-window-routes-20260923/pt2p"));
    artifacts_at(root)
}

fn f47_artifacts() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let root = std::env::var_os("BASANOS_PT2P_F47_ROOT").map(PathBuf::from)?;
    let fixture = artifacts_at(root)
        .unwrap_or_else(|| panic!("BASANOS_PT2P_F47_ROOT points at an invalid PT2P fixture"));
    let pxr1 = pt::route_header_v4_shallow(&fixture.0)
        .expect("BASANOS_PT2P_F47_ROOT has a valid compiler-v1 route header")
        .2;
    assert!(
        pxr1.is_some(),
        "BASANOS_PT2P_F47_ROOT must carry a PXR1 decision tail"
    );
    Some(fixture)
}

fn k10240_artifacts() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    if let Some(root) = std::env::var_os("BASANOS_PT2P_K10240_ROOT") {
        return Some(artifacts_at(PathBuf::from(root)).unwrap_or_else(|| {
            panic!("BASANOS_PT2P_K10240_ROOT points at an invalid PT2P fixture")
        }));
    }
    artifacts_at(PathBuf::from(
        "/Users/colkitt/sith/toys/crypto/basanos/out/runs/rev8-k10240-template-2026-09-30/fixture/pt2p",
    ))
}

/// The compiler-v1 typed-decision position defaults to the retained K=35
/// fixture's last prompt position. The K=10,240 measurement pins this to 10,239.
fn f47_position() -> u32 {
    std::env::var("BASANOS_PT2P_F47_POSITION")
        .ok()
        .map(|value| value.parse().expect("BASANOS_PT2P_F47_POSITION is a u32"))
        .unwrap_or(29)
}

fn f47_measure_k_filter() -> Option<u8> {
    std::env::var("BASANOS_DCG_F47_ONLY_K")
        .ok()
        .map(|value| value.parse().expect("BASANOS_DCG_F47_ONLY_K is a u8"))
}

fn f47_compute_limit() -> u32 {
    std::env::var("BASANOS_DCG_F47_PROBE_LIMIT")
        .ok()
        .map(|value| value.parse().expect("BASANOS_DCG_F47_PROBE_LIMIT is a u32"))
        .unwrap_or(1_400_000)
}

fn f47_measure_roles() -> impl Iterator<Item = bool> {
    let role_count = if std::env::var_os("BASANOS_DCG_F47_DEFAULT_ROLE_ONLY").is_some() {
        1
    } else {
        2
    };
    [false, true].into_iter().take(role_count)
}

fn f47_document_roots(f: &Fix, position: u32, position_root: [u8; 32]) -> Vec<[u8; 32]> {
    let mut roots = (0..=position)
        .map(|index| {
            f.position_roots
                .get(index as usize)
                .copied()
                .unwrap_or_else(|| {
                    sha256(&[
                        b"basanos/rev8-g1-synthetic-position-root/1",
                        &index.to_le_bytes(),
                    ])
                })
        })
        .collect::<Vec<_>>();
    roots[position as usize] = position_root;
    roots
}

fn owned(program: &Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: (128 + data.len() as u64) * 6_960 + 7,
        data,
        owner: *program,
        executable: false,
        rent_epoch: 0,
    }
}

fn shared(account: Account) -> AccountSharedData {
    account.into()
}

/// A system-owned, empty, funded account: what a CPI needs to create a PDA, and
/// what every target account of `create_pda` must already be.
fn system_funded() -> Account {
    Account {
        lamports: 1_000_000_000_000,
        data: vec![],
        owner: SYSTEM,
        executable: false,
        rent_epoch: 0,
    }
}

/// Send one instruction, behind a ComputeBudget instruction so
/// `compute_units_consumed` is a number, and print it with the mode it was
/// measured in. **Measured-local:** these are the program-test figures, which
/// are the SBF ones when `BASANOS_DCG_V8_SBF=1` names an SBF image and the
/// native ones otherwise.
async fn send(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<(), TransactionError> {
    send_with_signers_mode(ctx, signer, &[], program, data, metas, true).await
}

async fn send_with_signers(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    extra_signers: &[&Keypair],
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<(), TransactionError> {
    send_with_signers_mode(ctx, signer, extra_signers, program, data, metas, true).await
}

async fn send_quiet(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    extra_signers: &[&Keypair],
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<(), TransactionError> {
    send_with_signers_mode(ctx, signer, extra_signers, program, data, metas, false).await
}

#[derive(Default)]
struct QuietSendCache {
    blockhash: Option<solana_program::hash::Hash>,
    uses: usize,
    nonce: u64,
}

async fn retry_with_fresh_blockhash<F>(
    ctx: &mut ProgramTestContext,
    cache: &mut QuietSendCache,
    data: &[u8],
    make_transaction: &F,
) -> Result<(), TransactionError>
where
    F: Fn(solana_program::hash::Hash) -> Transaction,
{
    cache.blockhash = Some(ctx.banks_client.get_latest_blockhash().await.unwrap());
    cache.uses = 0;
    let inner = ctx
        .banks_client
        .process_transaction_with_metadata(make_transaction(cache.blockhash.unwrap()))
        .await
        .unwrap_or_else(|error| {
            panic!("the banks client refused the refreshed transaction: {error:?}")
        });
    if matches!(data.first().copied(), Some(140..=147 | 156..=160 | 176)) {
        if let Some(metadata) = inner.metadata.as_ref() {
            eprintln!(
                "CU tag {} data {} cu {}",
                data[0],
                data.len(),
                metadata.compute_units_consumed
            );
        }
    }
    inner.result
}

/// Quiet setup sender that refreshes its recent blockhash every 32
/// transactions and gives each transaction a unique, near-maximum compute
/// limit. The budget does not change the program instruction; it prevents
/// identical tag-142/193 chunk messages from being rejected as already
/// processed (which would force ProgramTest to freeze and rehash all large
/// accounts to advance the bank). The short blockhash cadence keeps large
/// upload runs inside ProgramTest's recent-blockhash window.
async fn send_quiet_cached(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    extra_signers: &[&Keypair],
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    cache: &mut QuietSendCache,
) -> Result<(), TransactionError> {
    if cache.blockhash.is_none() || cache.uses >= 32 {
        cache.blockhash = Some(ctx.banks_client.get_latest_blockhash().await.unwrap());
        cache.uses = 0;
    }
    let nonce = cache.nonce;
    cache.nonce = cache
        .nonce
        .checked_add(1)
        .expect("quiet sender nonce overflow");
    // Tag 160's K=10,240 SBF path consumes nearly the full transaction cap.
    // Keep its requested budget at the protocol maximum; the transaction's
    // first/count fields already make each admission step unique.
    let compute_limit = if data.first() == Some(&160) {
        1_400_000
    } else {
        1_400_000 - (nonce % 100_000) as u32
    };
    let make_transaction = |blockhash| {
        let ixs = vec![
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                compute_limit,
            ),
            Instruction {
                program_id: program,
                accounts: metas.clone(),
                data: data.clone(),
            },
        ];
        let mut signers = vec![signer];
        signers.extend_from_slice(extra_signers);
        Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &signers, blockhash)
    };
    let mut result = match ctx
        .banks_client
        .process_transaction_with_metadata(make_transaction(cache.blockhash.unwrap()))
        .await
    {
        Ok(inner) => {
            if matches!(data.first().copied(), Some(140..=147 | 156..=160 | 176)) {
                if let Some(metadata) = inner.metadata.as_ref() {
                    eprintln!(
                        "CU tag {} data {} cu {}",
                        data[0],
                        data.len(),
                        metadata.compute_units_consumed
                    );
                }
            }
            inner.result
        }
        Err(error) if matches!(error.unwrap(), TransactionError::BlockhashNotFound) => {
            // Long SBF upload/hash walks can age a 32-transaction cache out of
            // the bank's recent-blockhash window. Refresh and retry once rather
            // than making a valid fixture depend on test-runner timing.
            retry_with_fresh_blockhash(ctx, cache, &data, &make_transaction).await
        }
        Err(error) => panic!("the banks client refused the cached transaction: {error:?}"),
    };
    if matches!(&result, Err(TransactionError::BlockhashNotFound)) {
        result = retry_with_fresh_blockhash(ctx, cache, &data, &make_transaction).await;
    }
    if matches!(&result, Err(TransactionError::AlreadyProcessed)) {
        let slot = ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        ctx.warp_to_slot(slot + 1).unwrap();
        cache.blockhash = Some(
            ctx.get_new_latest_blockhash()
                .await
                .expect("a fresh retry blockhash"),
        );
        cache.uses = 0;
        let inner = ctx
            .banks_client
            .process_transaction_with_metadata(make_transaction(cache.blockhash.unwrap()))
            .await
            .unwrap_or_else(|error| panic!("the banks client refused the retry: {error:?}"));
        if matches!(data.first().copied(), Some(140..=147 | 156..=160 | 176)) {
            if let Some(metadata) = inner.metadata.as_ref() {
                eprintln!(
                    "CU tag {} data {} cu {}",
                    data[0],
                    data.len(),
                    metadata.compute_units_consumed
                );
            }
        }
        result = inner.result;
    }
    cache.uses += 1;
    result
}

async fn send_with_signers_mode(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    extra_signers: &[&Keypair],
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    log_cu: bool,
) -> Result<(), TransactionError> {
    let tag = *data.first().unwrap_or(&0);
    let len = data.len();
    let case = current_label();
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    // The compute budget is what makes `compute_units_consumed` a number rather
    // than the unset default; `custom()` then reads the refusal off instruction
    // index 1, which is where the program's instruction sits.
    let ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        Instruction {
            program_id: program,
            accounts: metas,
            data,
        },
    ];
    let mut signers = vec![signer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &signers, blockhash);
    let out = ctx.banks_client.process_transaction_with_metadata(tx).await;
    let (mut result, mut compute_units) = match out {
        Ok(inner) => (
            inner.result,
            inner
                .metadata
                .as_ref()
                .map(|m| m.compute_units_consumed)
                .unwrap_or(0),
        ),
        Err(error) => panic!("the banks client refused the transaction: {error:?}"),
    };
    if matches!(&result, Err(TransactionError::AlreadyProcessed)) {
        // ProgramTest can hand back the same recent blockhash while its PoH
        // worker is between ticks. Advance one slot and retry this test-only
        // transaction so the refusal under test comes from the program.
        let slot = ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        ctx.warp_to_slot(slot + 1).unwrap();
        let blockhash = ctx
            .get_new_latest_blockhash()
            .await
            .expect("a retry blockhash");
        let retry =
            Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &signers, blockhash);
        let inner = ctx
            .banks_client
            .process_transaction_with_metadata(retry)
            .await
            .unwrap_or_else(|error| panic!("the banks client refused the retry: {error:?}"));
        result = inner.result;
        compute_units = inner
            .metadata
            .as_ref()
            .map(|m| m.compute_units_consumed)
            .unwrap_or(0);
    }
    let mode = if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
        "SBF"
    } else {
        "native"
    };
    if log_cu {
        eprintln!("CU tag {tag} data {len} cu {compute_units} mode {mode} label {case}");
    }
    result
}

/// The CU-returning form is used by the DPR2 close-slope census below. It runs
/// the same compute-budget instruction and captures the SBF metadata rather
/// than inferring it from an eprintln line.
async fn send_cu(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<u64, TransactionError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        Instruction {
            program_id: program,
            accounts: metas,
            data,
        },
    ];
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &[signer], blockhash);
    let first = ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap_or_else(|error| {
            panic!("the banks client refused the measured transaction: {error:?}")
        });
    let (mut result, mut compute_units) = (
        first.result,
        first
            .metadata
            .as_ref()
            .map(|m| m.compute_units_consumed)
            .unwrap_or(0),
    );
    if matches!(&result, Err(TransactionError::AlreadyProcessed)) {
        // A preceding negative control can submit the same instruction bytes
        // with the same recent blockhash. Advance one slot so the measured
        // happy path reaches the program instead of the replay filter.
        let slot = ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        ctx.warp_to_slot(slot + 1).unwrap();
        let retry_blockhash = ctx
            .get_new_latest_blockhash()
            .await
            .expect("a retry blockhash");
        let retry = Transaction::new_signed_with_payer(
            &ixs,
            Some(&signer.pubkey()),
            &[signer],
            retry_blockhash,
        );
        let retry_result = ctx
            .banks_client
            .process_transaction_with_metadata(retry)
            .await
            .unwrap_or_else(|error| {
                panic!("the banks client refused the measured retry: {error:?}")
            });
        result = retry_result.result;
        compute_units = retry_result
            .metadata
            .as_ref()
            .map(|m| m.compute_units_consumed)
            .unwrap_or(0);
    }
    result?;
    Ok(compute_units)
}

fn custom(result: Result<(), TransactionError>) -> u32 {
    match result {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => code,
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}

fn custom_or_zero(result: Result<(), TransactionError>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(error) => custom(Err(error)),
    }
}

// ------------------------------------------------------------------ builders

/// The revision-8 UnifiedInit data: `terms[136] | binding[196] | model_root |
/// position_table_root | prompt_commitment | family_count:u16 | dfs2_body |
/// option_table[4*option_count]`.
fn init_data(
    terms: &[u8],
    binding: &[u8],
    anchors: &[[u8; 32]; 3],
    family_count: u16,
    body: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let mut out = vec![TAG_UNIFIED_INIT];
    out.extend_from_slice(terms);
    out.extend_from_slice(binding);
    for a in anchors {
        out.extend_from_slice(a);
    }
    out.extend_from_slice(&family_count.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(options);
    out
}

fn land_data(descriptor: &[u8; 32], first: u32, roots: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![TAG_LAND_POSITION_ROOTS];
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&first.to_le_bytes());
    out.push(roots.len() as u8);
    for r in roots {
        out.extend_from_slice(r);
    }
    out
}

fn finalize_data(descriptor: &[u8; 32], n: u32, roots: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![TAG_FINALIZE_DOCUMENT];
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(roots.len() as u16).to_le_bytes());
    for r in roots {
        out.extend_from_slice(r);
    }
    out
}

/// A DCM2 v7 image, from the fields the handlers read. `option_count` decides
/// the length, exactly as `document_v8` requires.
fn dcm2_v7(
    program: &Pubkey,
    descriptor: &[u8; 32],
    authority: &[u8; 32],
    k: u32,
    n: u32,
    flags: u16,
    terms: &[u8],
    binding: &[u8],
    pt2s: &[u8; 32],
    pt2s_sha: &[u8; 32],
    dea2: &[u8; 32],
    drp2: &[u8; 32],
    reg_root: &[u8; 32],
    family_count: u16,
    deadline: u64,
    abandon: u64,
) -> Vec<u8> {
    let b = Binding2::decode(binding).expect("the fixture's binding decodes");
    let mut out = vec![0u8; OPTION_REGION_AT + 4 * b.option_count as usize];
    out[..4].copy_from_slice(b"DCM2");
    out[4..6].copy_from_slice(&7u16.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..40].copy_from_slice(descriptor);
    out[40..72].copy_from_slice(authority);
    out[72..76].copy_from_slice(&k.to_le_bytes());
    out[76..78].copy_from_slice(&34u16.to_le_bytes());
    out[document::DCM2_BUMP_AT] = address::document(program, descriptor).1.value();
    out[document::DPR2_BUMP_AT] = address::positions(program, descriptor).1.value();
    out[document::DFS2_BUMP_AT] = address::family_slots(program, descriptor).1.value();
    out[document::BOND_ESCROW_BUMP_AT] = address::bond_escrow(program, descriptor).1;
    out[84..88].copy_from_slice(&n.to_le_bytes());
    out[88..96].copy_from_slice(&(504_606_552u64).to_le_bytes());
    out[144..152].copy_from_slice(&deadline.to_le_bytes());
    out[184..192].copy_from_slice(&u64_at(terms, 8).to_le_bytes());
    out[192..200].copy_from_slice(&(504_606_552u64).to_le_bytes());
    out[200..232].copy_from_slice(pt2s);
    out[232..264].copy_from_slice(pt2s_sha);
    out[264..296].copy_from_slice(&[1u8; 32]);
    out[296..328].copy_from_slice(&[2u8; 32]);
    out[328..360].copy_from_slice(&[3u8; 32]);
    out[360..392].copy_from_slice(drp2);
    out[392..424].copy_from_slice(reg_root);
    out[424..456].copy_from_slice(dea2);
    out[456..488].copy_from_slice(&[4u8; 32]);
    out[520..524].copy_from_slice(&4u32.to_le_bytes());
    out[524..526].copy_from_slice(&family_count.to_le_bytes());
    out[526] = rs1_height(k);
    out[527] = 3;
    out[529] = if u64_at(terms, 32) > 0 {
        BOND_HELD
    } else {
        BOND_NONE
    };
    out[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2].copy_from_slice(terms);
    out[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8].copy_from_slice(binding);
    out[document::ABANDON_DEADLINE_AT..document::ABANDON_DEADLINE_AT + 8]
        .copy_from_slice(&abandon.to_le_bytes());
    out
}

/// A DCR2 v6 image, from the fields the handlers read. `attested` cells are
/// zero and the bitmap is empty; a caller that wants a half-attested record
/// writes its own.
fn dcr2_v6(program: &Pubkey, descriptor: &[u8; 32], binding: &Binding2, terms: &Terms2) -> Vec<u8> {
    let full = result::bytes_v8(binding.output_count, binding.output_width).unwrap();
    let mut out = vec![0u8; full];
    out[..4].copy_from_slice(b"DCR2");
    out[4..6].copy_from_slice(&6u16.to_le_bytes());
    out[8..40].copy_from_slice(descriptor);
    out[72..104].copy_from_slice(&binding.request_id);
    out[104..136].copy_from_slice(&binding.consumer_digest);
    out[136..168].copy_from_slice(&binding.executor);
    out[196..200].copy_from_slice(&binding.output_count.to_le_bytes());
    out[200..204].copy_from_slice(&binding.output_first_position.to_le_bytes());
    out[208] = binding.output_width;
    out[216..216 + TERMS_BYTES_V2].copy_from_slice(&terms.encode());
    out[384..392].copy_from_slice(&terms.result_retention_slots.to_le_bytes());
    out[result::RESULT_PDA_BUMP_AT_V6] = address::result(program, descriptor).1.value();
    out
}

/// A DPR2 image with `count` landed roots at their real values.
fn dpr2_image(descriptor: &[u8; 32], k: u32, roots: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![0u8; DPR2_HEADER + 32 * roots.len()];
    out[..4].copy_from_slice(b"DPR2");
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[8..40].copy_from_slice(descriptor);
    out[40..44].copy_from_slice(&k.to_le_bytes());
    out[44..48].copy_from_slice(&(roots.len() as u32).to_le_bytes());
    for (i, r) in roots.iter().enumerate() {
        out[DPR2_HEADER + 32 * i..DPR2_HEADER + 32 * (i + 1)].copy_from_slice(r);
    }
    out
}

/// A PT2S in `STATE_HASHING` with the three flat digests PWR1 commits already in
/// place: the image a real emission's own state carried at the moment the seal
/// ran. **Nothing from 316 on is written** -- the clause-12 v4, the definition
/// digest, the template descriptor and the six locator bytes are all the seal's,
/// and a fixture that lays them down itself never exercises tag 145 at all,
/// which is how the review's High 2 (`write == 0` refused) went unseen: the
/// retained template's own locator is `(28_037, write 0, 16)` and no test ever
/// sent a 39-byte seal.
fn hashing_pt2s(
    routes: &[u8],
    geometry: &[u8],
    payloads: &[u8],
    pwr1: &[u8],
    authority: Pubkey,
    keys: [Pubkey; 3],
) -> Vec<u8> {
    let mut out = vec![0u8; S::OFF_PWR1 + pwr1.len()];
    out[..4].copy_from_slice(S::MAGIC);
    out[S::OFF_STATE] = S::STATE_HASHING;
    out[S::OFF_AUTHORITY..S::OFF_AUTHORITY + 32].copy_from_slice(authority.as_ref());
    out[S::OFF_PT1S..S::OFF_PT1S + 32].copy_from_slice(&[1u8; 32]);
    for (i, key) in keys.into_iter().enumerate() {
        out[S::OFF_KEYS + 32 * i..S::OFF_KEYS + 32 * (i + 1)].copy_from_slice(key.as_ref());
    }
    for (i, len) in [routes.len(), geometry.len(), payloads.len()]
        .into_iter()
        .enumerate()
    {
        out[S::OFF_LENGTHS + 4 * i..S::OFF_LENGTHS + 4 * (i + 1)]
            .copy_from_slice(&(len as u32).to_le_bytes());
    }
    out[S::OFF_DIGESTS..S::OFF_DIGESTS + 96]
        .copy_from_slice(&[sha256(&[routes]), sha256(&[geometry]), sha256(&[payloads])].concat());
    out[S::OFF_CURSOR_KIND] = 3;
    out[S::OFF_PWR1_LEN..S::OFF_PWR1_LEN + 2].copy_from_slice(&(pwr1.len() as u16).to_le_bytes());
    out[S::OFF_PWR1..].copy_from_slice(pwr1);
    out
}

// ------------------------------------------------------------------ the fixture

/// Everything the tests share. Data only; the builders above take what they
/// need, so there is no method-borrow dance to get wrong.
struct Fix {
    ctx: ProgramTestContext,
    /// The lifecycle-v2 property path's quiet sender.
    lifecycle_v2_cache: QuietSendCache,
    program: Pubkey,
    executor: Keypair,
    signer: Keypair,
    pt2s: Pubkey,
    routes: Pubkey,
    geometry: Pubkey,
    payloads: Pubkey,
    drp2: Pubkey,
    dea2: Pubkey,
    dta1: Pubkey,
    dtu1: Pubkey,
    pt2s_image: Vec<u8>,
    pt2s_sha: [u8; 32],
    descriptor_v7: [u8; 32],
    position_roots: Vec<[u8; 32]>,
    attestations: Vec<Vec<u8>>,
    family_body: Vec<u8>,
    family_roots: Vec<[u8; 32]>,
    k: u32,
    segments: u16,
    /// A program-owned stand-in for the **PT1S index** account the PT2S names at
    /// `OFF_PT1S`, which tag 186 drains. A fresh key, so it is not the closer's
    /// account and not a funded system account.
    pt1s_index: Pubkey,
    /// Signer for the live template's payload resource, retained for the
    /// C3 self-key drain regression.
    payload_key: Keypair,
    reg_root: [u8; 32],
    total_entries: u64,
    locator: Locator,
    terms_raw: Vec<u8>,
    base_entry: u32,
    output_write: u8,
    output_width: u8,
    real_pda_funding: bool,
}

impl Fix {
    /// The 14 metas of UnifiedInit: revision 7's thirteen plus **DTU1**, whose
    /// `documents + 1` is the instruction's last write (spec §1.6, §1.7).
    fn init_metas(&self, created: [Pubkey; 4]) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[1], false),
            AccountMeta::new(created[2], false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(self.pt2s, false),
            AccountMeta::new_readonly(self.routes, false),
            AccountMeta::new_readonly(self.geometry, false),
            AccountMeta::new_readonly(self.payloads, false),
            AccountMeta::new_readonly(self.drp2, false),
            AccountMeta::new_readonly(self.dea2, false),
            AccountMeta::new_readonly(self.dta1, false),
            AccountMeta::new(created[3], false),
            AccountMeta::new(self.dtu1, false),
        ]
    }

    fn descriptor(&self, binding: &Binding2, terms_raw: &[u8], family_count: u16) -> [u8; 32] {
        let b = binding.encode();
        Dpd2 {
            position_count: self.k,
            segment_count: self.segments,
            family_count,
            rs1_height: rs1_height(self.k),
            compiler_version: 1,
            total_entries: self.total_entries,
            terms: terms_raw,
            binding: &b,
            clause12_v4: &self.pt2s_image[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
            definition_sha256: &d32(&self.pt2s_image, S::OFF_DEFINITION),
            base_digests: &self.pt2s_image[S::OFF_DIGESTS..S::OFF_DIGESTS + 96],
            model_root: &[1u8; 32],
            position_table_root: &[2u8; 32],
            prompt_commitment: &[3u8; 32],
            registry: self.drp2.as_ref(),
            registry_table_root: &self.reg_root,
            dfs2_sha256: &sha256(&[&self.family_body]),
        }
        .digest_v8()
    }

    /// The binding a completion document over this template declares.
    fn binding(&self, first: u32, count: u32) -> Binding2 {
        Binding2 {
            executor: self.executor.pubkey().to_bytes(),
            request_id: [5u8; 32],
            consumer_digest: [6u8; 32],
            seed: [0; 32],
            output_first_position: first,
            output_count: count,
            output_base_entry: self.base_entry,
            output_write: self.output_write,
            output_width: self.output_width,
            decision_flags: 0,
            option_count: 0,
            prompt_positions: first + 1,
            stop_plus_one: 0,
            option_table_offset: 0,
            option_table_sha256: [0; 32],
        }
    }

    /// The CUSTOM terms of §1.1: a zero slasher share, a nonzero remainder, a
    /// nonzero settlement program and window, and twice the abandonment floor.
    fn terms(&self) -> Vec<u8> {
        Terms2 {
            challenge_window_slots: 90_000,
            response_window_slots: 45_000,
            challenger_bond_lamports: 1_000_000,
            executor_bond_lamports: ESCROW_FLOOR,
            executor_reward_bps: 0,
            bond_policy_kind: BOND_POLICY_CUSTOM,
            bond_slasher_bps: 0,
            settlement_program: [7u8; 32],
            custom_settle_window_slots: 604_800,
            result_retention_slots: 2_592_000,
            bond_remainder: [8u8; 32],
            abandon_after_slots: 2 * EXAMPLE_LIMITS.min_abandon_after_slots,
        }
        .encode()
        .to_vec()
    }

    /// init, then land `n` real position roots, then finalize. The document's
    /// four created accounts are funded first so the CPIs can create them.
    async fn run_document(&mut self, binding: &Binding2, n: u32) -> ([u8; 32], [Pubkey; 4]) {
        self.run_document_with_options(binding, n, &[]).await
    }

    /// The same real UnifiedInit path with a binding-bound decision option table.
    async fn run_document_with_options(
        &mut self,
        binding: &Binding2,
        n: u32,
        options: &[u8],
    ) -> ([u8; 32], [Pubkey; 4]) {
        let roots = self.position_roots[..n as usize].to_vec();
        self.run_document_with_roots_and_options(binding, &roots, options)
            .await
    }

    /// init, then land exactly these roots. A caller that has re-keyed a
    /// position root lands that list rather than the retained one, and the
    /// finalize is the caller's, as it always was.
    async fn run_document_with_roots(
        &mut self,
        binding: &Binding2,
        roots: &[[u8; 32]],
    ) -> ([u8; 32], [Pubkey; 4]) {
        self.run_document_with_roots_and_options(binding, roots, &[])
            .await
    }

    async fn run_document_with_roots_and_options(
        &mut self,
        binding: &Binding2,
        roots: &[[u8; 32]],
        options: &[u8],
    ) -> ([u8; 32], [Pubkey; 4]) {
        let descriptor = self.descriptor(binding, &self.terms_raw, 16);
        let created = [
            address::document(&self.program, &descriptor).0,
            address::positions(&self.program, &descriptor).0,
            address::family_slots(&self.program, &descriptor).0,
            address::result(&self.program, &descriptor).0,
        ];
        // UnifiedInit funds the four PDAs to rent itself (and the pot into
        // DCM2), so nothing is pre-funded: the balances are the real ones.
        let metas = self.init_metas(created);
        let data = init_data(
            &self.terms_raw,
            &binding.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &self.family_body,
            options,
        );
        send(&mut self.ctx, &self.executor, self.program, data, metas)
            .await
            .expect("init");
        // Tag 162 encodes its batch count as u8. Keep the generated K=10,240
        // measurement on the same honest append path as the small fixture,
        // with bounded batches that do not wrap that count field.
        for (batch, batch_roots) in roots.chunks(20).enumerate() {
            let first = u32::try_from(batch * 20).expect("position batch offset fits u32");
            let data = land_data(&descriptor, first, batch_roots);
            send(
                &mut self.ctx,
                &self.executor,
                self.program,
                data,
                vec![
                    AccountMeta::new(self.executor.pubkey(), true),
                    AccountMeta::new(created[0], false),
                    AccountMeta::new(created[1], false),
                    AccountMeta::new_readonly(self.dtu1, false),
                ],
            )
            .await
            .expect("land");
        }
        (descriptor, created)
    }

    async fn finalize(&mut self, descriptor: &[u8; 32], created: [Pubkey; 4], n: u32) -> Vec<u8> {
        let document = self.account(created[0]).await;
        assert_eq!(
            u32_at(&document, 84),
            n,
            "finalize n matches landed position roots"
        );
        let data = finalize_data(descriptor, n, &self.family_roots);
        send(
            &mut self.ctx,
            &self.executor,
            self.program,
            data,
            vec![
                AccountMeta::new(self.executor.pubkey(), true),
                AccountMeta::new(created[0], false),
                AccountMeta::new(created[3], false),
                AccountMeta::new_readonly(self.dtu1, false),
            ],
        )
        .await
        .expect("finalize");
        self.account(created[0]).await
    }

    async fn account(&mut self, key: Pubkey) -> Vec<u8> {
        self.ctx
            .banks_client
            .get_account(key)
            .await
            .unwrap()
            .unwrap()
            .data
    }

    /// A real `UnifiedInit` over `binding`, and the code it refused with. The
    /// four PDAs are derived and funded first, so the only thing that can
    /// refuse is the binding, the terms or the plan -- not a missing account.
    /// `variant` makes the descriptor (and so the four PDAs) distinct per
    /// attempt, because a refused init writes nothing and a second attempt at
    /// the same descriptor would be a duplicate transaction.
    async fn init_refusal(&mut self, binding: &Binding2, variant: u8) -> u32 {
        let b = Binding2 {
            request_id: [variant; 32],
            ..*binding
        };
        let descriptor = self.descriptor(&b, &self.terms_raw, 16);
        let created = [
            address::document(&self.program, &descriptor).0,
            address::positions(&self.program, &descriptor).0,
            address::family_slots(&self.program, &descriptor).0,
            address::result(&self.program, &descriptor).0,
        ];
        let data = init_data(
            &self.terms_raw,
            &b.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &self.family_body,
            &[],
        );
        let metas = self.init_metas(created);
        let slot = self
            .ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        self.ctx.warp_to_slot(slot + 1).unwrap();
        custom(send(&mut self.ctx, &self.executor, self.program, data, metas).await)
    }
}

/// Pre-fund a system-owned, empty account so a CPI can create its PDA.
async fn fund(ctx: &mut ProgramTestContext, key: Pubkey) {
    if ctx.banks_client.get_account(key).await.unwrap().is_none() {
        ctx.set_account(&key, &shared(system_funded()));
    }
}

/// Fund an absent PDA with a real System Program transfer, as the permissionless
/// document path expects. This keeps the full lifecycle test free of test-bank
/// account replacement for protocol state.
async fn fund_system(ctx: &mut ProgramTestContext, payer: &Keypair, key: Pubkey, lamports: u64) {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let ix = solana_program::system_instruction::transfer(&payer.pubkey(), &key, lamports);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], blockhash);
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("System Program funds PDA");
}

/// Allocate a fresh program-owned account through the System Program, signed
/// by its keypair and funded by the recorded template authority.
async fn allocate_program_account(
    ctx: &mut ProgramTestContext,
    payer: &Keypair,
    account: &Keypair,
    owner: Pubkey,
    bytes: usize,
) {
    let lamports = solana_program::rent::Rent::default().minimum_balance(bytes);
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let create = solana_program::system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        lamports,
        bytes as u64,
        &owner,
    );
    let tx = Transaction::new_signed_with_payer(
        &[create],
        Some(&payer.pubkey()),
        &[payer, account],
        blockhash,
    );
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("System Program allocates the fresh program-owned account");
}

async fn upload_pt1x(
    ctx: &mut ProgramTestContext,
    authority: &Keypair,
    program: Pubkey,
    pt1x: &Keypair,
    byte_account_signers: [&Keypair; 3],
    byte_accounts: [Pubkey; 3],
    blobs: [&[u8]; 3],
    attacker: &Keypair,
    cache: &mut QuietSendCache,
) {
    let mut metas = vec![AccountMeta::new(pt1x.pubkey(), true)];
    metas.extend(
        byte_accounts
            .into_iter()
            .map(|key| AccountMeta::new(key, true)),
    );
    metas.push(AccountMeta::new_readonly(authority.pubkey(), true));
    let init_signers = [
        pt1x,
        byte_account_signers[0],
        byte_account_signers[1],
        byte_account_signers[2],
    ];
    send_quiet_cached(
        ctx,
        authority,
        &init_signers,
        program,
        vec![140],
        {
            metas.push(AccountMeta::new_readonly(SYSTEM, false));
            metas
        },
        cache,
    )
    .await
    .expect("PT1X init");
    let mut malformed = vec![141, 0];
    malformed.extend_from_slice(&1u32.to_le_bytes());
    malformed.extend_from_slice(&blobs[0][..900]);
    let malformed_result = send_quiet_cached(
        ctx,
        authority,
        &[],
        program,
        malformed,
        vec![
            AccountMeta::new(pt1x.pubkey(), false),
            AccountMeta::new(byte_accounts[0], false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        cache,
    )
    .await;
    assert_eq!(
        custom(malformed_result),
        dcg_program::position_template::MALFORMED,
        "an unaligned PT1X chunk refuses"
    );
    let mut attack = vec![141, 0];
    attack.extend_from_slice(&0u32.to_le_bytes());
    attack.extend_from_slice(&blobs[0][..900]);
    let attack_result = send_quiet_cached(
        ctx,
        authority,
        &[attacker],
        program,
        attack,
        vec![
            AccountMeta::new(pt1x.pubkey(), false),
            AccountMeta::new(byte_accounts[0], false),
            AccountMeta::new_readonly(attacker.pubkey(), true),
        ],
        cache,
    )
    .await;
    assert!(
        matches!(
            attack_result,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "a third party cannot write PT1X resources"
    );
    for kind in 0..3 {
        for (chunk, bytes) in blobs[kind].chunks(900).enumerate() {
            let mut data = vec![141, kind as u8];
            data.extend_from_slice(&u32::try_from(chunk * 900).unwrap().to_le_bytes());
            data.extend_from_slice(bytes);
            send_quiet_cached(
                ctx,
                authority,
                &[],
                program,
                data,
                vec![
                    AccountMeta::new(pt1x.pubkey(), false),
                    AccountMeta::new(byte_accounts[kind], false),
                    AccountMeta::new_readonly(authority.pubkey(), true),
                ],
                cache,
            )
            .await
            .expect("PT1X upload chunk");
        }
    }
}

async fn seal_pt1x(
    ctx: &mut ProgramTestContext,
    authority: &Keypair,
    program: Pubkey,
    pt1x: Pubkey,
    byte_accounts: [Pubkey; 3],
    routes: &[u8],
    attacker: &Keypair,
    cache: &mut QuietSendCache,
) {
    let n = u32::from_le_bytes(routes[..4].try_into().unwrap()) as usize;
    let attack_result = send_quiet_cached(
        ctx,
        authority,
        &[attacker],
        program,
        vec![142, 64, 0],
        vec![
            AccountMeta::new(pt1x, false),
            AccountMeta::new_readonly(byte_accounts[0], false),
            AccountMeta::new_readonly(byte_accounts[1], false),
            AccountMeta::new_readonly(byte_accounts[2], false),
            AccountMeta::new_readonly(attacker.pubkey(), true),
        ],
        cache,
    )
    .await;
    assert!(
        matches!(
            attack_result,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "a third party cannot advance the PT1X seal cursor"
    );
    let mut prefix = vec![0usize];
    for i in 0..n {
        let at = 80 + 16 * i + 6;
        let count = u16::from_le_bytes(routes[at..at + 2].try_into().unwrap()) as usize
            + u16::from_le_bytes(routes[at + 2..at + 4].try_into().unwrap()) as usize;
        prefix.push(prefix[i] + count);
    }
    loop {
        let state = ctx
            .banks_client
            .get_account(pt1x)
            .await
            .unwrap()
            .unwrap()
            .data;
        if state[4] == 3 {
            break;
        }
        let cursor = u32::from_le_bytes(state[157..161].try_into().unwrap()) as usize;
        let mut count = if state[4] == 4 {
            [
                (64usize, 245usize),
                (48, 245),
                (32, 100),
                (20, 200),
                (16, 220),
                (8, 245),
                (4, 245),
                (1, usize::MAX),
            ]
            .iter()
            .find(|(size, limit)| {
                cursor + size <= n && prefix[cursor + size] - prefix[cursor] <= *limit
            })
            .map_or(1, |item| item.0)
        } else if state[4] == 5 {
            64
        } else {
            16
        };
        loop {
            let data = vec![142, count as u8, (count >> 8) as u8];
            let result = send_quiet_cached(
                ctx,
                authority,
                &[],
                program,
                data,
                vec![
                    AccountMeta::new(pt1x, false),
                    AccountMeta::new_readonly(byte_accounts[0], false),
                    AccountMeta::new_readonly(byte_accounts[1], false),
                    AccountMeta::new_readonly(byte_accounts[2], false),
                    AccountMeta::new_readonly(authority.pubkey(), true),
                ],
                cache,
            )
            .await;
            match result {
                Ok(()) => break,
                Err(_) if count > 1 => count /= 2,
                Err(error) => panic!("PT1X seal phase {} at {cursor}: {error:?}", state[4]),
            }
        }
    }
}

async fn seal_pt2s(
    ctx: &mut ProgramTestContext,
    authority: &Keypair,
    pt2s: &Keypair,
    program: Pubkey,
    pt1x: Pubkey,
    byte_accounts: [Pubkey; 3],
    pwr1: &[u8],
    locator: Locator,
    attacker: &Keypair,
    cache: &mut QuietSendCache,
) {
    let mut data = vec![S::TAG_INIT];
    data.extend_from_slice(pwr1);
    let hijack = send_quiet_cached(
        ctx,
        authority,
        &[pt2s, attacker],
        program,
        data.clone(),
        vec![
            AccountMeta::new(pt2s.pubkey(), true),
            AccountMeta::new(pt1x, false),
            AccountMeta::new_readonly(attacker.pubkey(), true),
        ],
        cache,
    )
    .await;
    assert!(
        matches!(
            hijack,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "a third party cannot bind PT1X to its PT2S"
    );
    send_quiet_cached(
        ctx,
        authority,
        &[pt2s],
        program,
        data,
        vec![
            AccountMeta::new(pt2s.pubkey(), true),
            AccountMeta::new(pt1x, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        cache,
    )
    .await
    .expect("PT2S init binds PT1X");
    let mut attacker_hash = vec![S::TAG_HASH];
    attacker_hash.extend_from_slice(&S::MAX_HASH_BLOCKS.to_le_bytes());
    let attacker_hash_result = send_quiet_cached(
        ctx,
        authority,
        &[attacker],
        program,
        attacker_hash,
        vec![
            AccountMeta::new(pt2s.pubkey(), false),
            AccountMeta::new_readonly(byte_accounts[0], false),
            AccountMeta::new_readonly(byte_accounts[1], false),
            AccountMeta::new_readonly(byte_accounts[2], false),
            AccountMeta::new_readonly(attacker.pubkey(), true),
        ],
        cache,
    )
    .await;
    assert!(
        matches!(
            attacker_hash_result,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "a third party cannot advance PT2S hashing"
    );
    loop {
        let state = ctx
            .banks_client
            .get_account(pt2s.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data;
        if state[S::OFF_CURSOR_KIND] == 3 {
            break;
        }
        send_quiet_cached(
            ctx,
            authority,
            &[],
            program,
            vec![
                S::TAG_HASH,
                S::MAX_HASH_BLOCKS as u8,
                (S::MAX_HASH_BLOCKS >> 8) as u8,
            ],
            vec![
                AccountMeta::new(pt2s.pubkey(), false),
                AccountMeta::new_readonly(byte_accounts[0], false),
                AccountMeta::new_readonly(byte_accounts[1], false),
                AccountMeta::new_readonly(byte_accounts[2], false),
                AccountMeta::new_readonly(authority.pubkey(), true),
            ],
            cache,
        )
        .await
        .expect("PT2S hash chunk");
    }
    let mut data = vec![S::TAG_SEAL];
    data.extend_from_slice(&[9u8; 32]);
    data.extend_from_slice(&locator.base_entry.to_le_bytes());
    data.push(locator.write);
    data.push(locator.width);
    let seal_metas = vec![
        AccountMeta::new(pt2s.pubkey(), false),
        AccountMeta::new_readonly(byte_accounts[0], false),
        AccountMeta::new_readonly(byte_accounts[1], false),
        AccountMeta::new_readonly(byte_accounts[2], false),
        AccountMeta::new_readonly(authority.pubkey(), true),
        AccountMeta::new_readonly(pt1x, false),
    ];
    let mut attacker_seal_metas = seal_metas.clone();
    attacker_seal_metas[4] = AccountMeta::new_readonly(attacker.pubkey(), true);
    let attacker_seal = send_quiet_cached(
        ctx,
        authority,
        &[attacker],
        program,
        data.clone(),
        attacker_seal_metas,
        cache,
    )
    .await;
    assert!(
        matches!(
            attacker_seal,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "a third party cannot seal PT2S"
    );
    send_quiet_cached(
        ctx,
        authority,
        &[],
        program,
        data,
        seal_metas.clone(),
        cache,
    )
    .await
    .expect("PT2S seal begin");
    loop {
        let state = ctx
            .banks_client
            .get_account(pt2s.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data;
        if state[S::OFF_STATE] == S::STATE_SEALED {
            break;
        }
        assert_eq!(state[S::OFF_STATE], S::STATE_SEALING_PXR);
        let mut data = vec![S::TAG_SEAL_PXR_CHUNK];
        data.extend_from_slice(&S::MAX_PXR_SEAL_ROWS.to_le_bytes());
        send_quiet_cached(
            ctx,
            authority,
            &[],
            program,
            data,
            seal_metas.clone(),
            cache,
        )
        .await
        .expect("PT2S PXR1 seal chunk");
    }
}

async fn build() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, false, false, false, false, false).await
}
/// The K=80 template sealed (tag 176) with `limits` instead of the example's.
async fn build_with_limits(limits: TemplateLimits) -> Option<Fix> {
    build_from_template(false, false, false, false, limits).await
}
async fn build_f47() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, false, false, true, false, false).await
}
async fn build_honest_pt1x() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, true, false, false, true, false).await
}
async fn build_k10240_pre_admitted() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, false, false, false, true, false).await
}
async fn build_form48_admission_only() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, true, false, true, false, true).await
}

async fn build_with_swapped_roles() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, false, true, false, false, false).await
}
async fn build_f47_with_swapped_roles() -> Option<Fix> {
    build_with_pre_fix_seal_processor(false, false, true, true, false, false).await
}

#[cfg(feature = "test-rev8-before-payer-alias-fix")]

async fn build_before_payer_alias_fix() -> Option<Fix> {
    build_with_pre_fix_seal_processor(true, false, false, false, false, false).await
}

/// The fixture from the shared real-flow template stage (rule 6): config,
/// PT1X, PT2S seal, registry, template seal and admission all ran as real
/// instructions, restored from a byte-checked snapshot when one exists.
async fn build_from_template(
    swap_executor_and_challenger: bool,
    f47_fixture: bool,
    k10240_fixture: bool,
    admit_form48_only: bool,
    limits: TemplateLimits,
) -> Option<Fix> {
    use dcg_test_support::template::Admission;
    let kind = if k10240_fixture {
        dcg_test_support::FixtureKind::K10240
    } else if f47_fixture {
        dcg_test_support::FixtureKind::F47
    } else {
        dcg_test_support::FixtureKind::K80
    };
    let mut options = dcg_test_support::TemplateOptions::new(kind);
    options.swap_roles = swap_executor_and_challenger;
    if admit_form48_only {
        options.admission = Admission::Form48Only;
    }
    options.limits = limits;
    let target = dcg_test_support::dcg_program_target!();
    let t = dcg_test_support::Template::build_cached(&target, options).await?;
    let total = total_entries(&t.fixture.view()).unwrap();
    let g = v7_golden();
    let e = executor();
    let dfs2 = unhex(g["dfs2"]["hex"].as_str().unwrap());
    let rung = dcg_test_support::RungD::load();
    let terms_raw = Terms2 {
        challenge_window_slots: 90_000,
        response_window_slots: 45_000,
        challenger_bond_lamports: 1_000_000,
        executor_bond_lamports: ESCROW_FLOOR,
        executor_reward_bps: 0,
        bond_policy_kind: BOND_POLICY_CUSTOM,
        bond_slasher_bps: 0,
        settlement_program: [7u8; 32],
        custom_settle_window_slots: 604_800,
        result_retention_slots: 2_592_000,
        bond_remainder: [8u8; 32],
        abandon_after_slots: 2 * EXAMPLE_LIMITS.min_abandon_after_slots,
    }
    .encode()
    .to_vec();
    let locator = t.locator;
    Some(Fix {
        lifecycle_v2_cache: QuietSendCache::default(),
        ctx: t.chain.ctx,
        program: t.program,
        executor: t.roles.executor,
        signer: t.roles.signer,
        pt2s: t.pt2s,
        routes: t.routes,
        geometry: t.geometry,
        payloads: t.payloads,
        drp2: t.drp2,
        dea2: t.dea2,
        dta1: t.dta1,
        dtu1: t.dtu1,
        pt1s_index: t.pt1x,
        pt2s_image: t.pt2s_image,
        pt2s_sha: t.pt2s_sha,
        descriptor_v7: d32(&unhex(e["descriptor"].as_str().unwrap()), 0),
        position_roots: rung.position_roots,
        attestations: rung.attestations,
        family_body: dfs2[document::DFS2_HEADER..].to_vec(),
        family_roots: rung.family_roots,
        k: t.k,
        segments: t.segments,
        reg_root: t.reg_root,
        total_entries: total,
        locator,
        terms_raw,
        base_entry: locator.base_entry,
        output_write: locator.write,
        output_width: locator.width,
        real_pda_funding: true,
        payload_key: Keypair::new_from_array([0x87; 32]),
    })
}

async fn build_with_pre_fix_seal_processor(
    use_old_seal: bool,
    full_honest_setup: bool,
    swap_executor_and_challenger: bool,
    f47_fixture: bool,
    k10240_fixture: bool,
    admit_form48_only: bool,
) -> Option<Fix> {
    // Every fixture but the old-seal regression's named legacy processor
    // comes from the real-flow template stage.
    if !use_old_seal {
        let _ = full_honest_setup;
        return build_from_template(
            swap_executor_and_challenger,
            f47_fixture,
            k10240_fixture,
            admit_form48_only,
            EXAMPLE_LIMITS,
        )
        .await;
    }
    assert!(!admit_form48_only || (full_honest_setup && f47_fixture));
    let fixture = if k10240_fixture {
        k10240_artifacts()
    } else if f47_fixture {
        f47_artifacts()
    } else {
        artifacts()
    };
    let Some((routes, geometry, payloads, pwr1, clause12)) = fixture else {
        if f47_fixture {
            eprintln!("SKIP: Form-47/48 fixture is missing or invalid; set BASANOS_PT2P_F47_ROOT to the retained compiler-v1 PXR1 fixture");
        } else if k10240_fixture {
            eprintln!("SKIP: K=10,240 PT2P fixture is missing or invalid; set BASANOS_PT2P_K10240_ROOT to the retained rung-D fixture");
        } else {
            eprintln!("SKIP: retained PT2P emission is missing or invalid; set BASANOS_PT2P_ROOT to a retained emission");
        }
        return None;
    };
    let has_pxr1 = pt::route_header_v4_shallow(&routes)
        .expect("PT2P route header is valid")
        .2
        .is_some();
    let g = v7_golden();
    let e = executor();
    // Stable account identities keep SBF CU comparisons on the same fixture
    // across source revisions, including the tag-160 admission measurement.
    let program = Pubkey::new_from_array([0x80; 32]);
    let mut executor_kp = Keypair::new_from_array([0x81; 32]);
    let mut signer = Keypair::new_from_array([0x82; 32]);
    if swap_executor_and_challenger {
        std::mem::swap(&mut executor_kp, &mut signer);
    }
    let pt1x_kp = Keypair::new_from_array([0x83; 32]);
    let pt2s_kp = Keypair::new_from_array([0x84; 32]);
    let route_kp = Keypair::new_from_array([0x85; 32]);
    let geometry_kp = Keypair::new_from_array([0x86; 32]);
    let payload_kp = Keypair::new_from_array([0x87; 32]);
    let pt1s_index = if full_honest_setup {
        pt1x_kp.pubkey()
    } else {
        Pubkey::new_from_array([1u8; 32])
    };
    let pt2s = pt2s_kp.pubkey();
    let routes_key = route_kp.pubkey();
    let geometry_key = geometry_kp.pubkey();
    let payloads_key = payload_kp.pubkey();
    let g_prog = pt2p::Program::decode(&pwr1).unwrap();
    let mut payload_index = Vec::new();
    let mut payload_at = 0usize;
    while payload_at < payloads.len() {
        payload_index.extend_from_slice(&(payload_at as u32).to_le_bytes());
        payload_at +=
            6 + u16::from_le_bytes(payloads[payload_at + 4..payload_at + 6].try_into().unwrap())
                as usize;
    }
    payload_index.extend_from_slice(&(payload_at as u32).to_le_bytes());
    let (k, segments, base_entries, n_max, total, class_total) = {
        let view = Pt2p::new(
            &routes,
            &geometry,
            &payloads,
            Some(&payload_index),
            g_prog.clone(),
        )
        .unwrap();
        (
            view.position_count,
            view.segment_count,
            view.base_entries,
            view.n_of(view.position_count - 1),
            total_entries(&view).unwrap(),
            class_count(&view).unwrap(),
        )
    };
    let form48_class = if admit_form48_only {
        let view = Pt2p::new(
            &routes,
            &geometry,
            &payloads,
            Some(&payload_index),
            g_prog.clone(),
        )
        .unwrap();
        (0..class_total).find(|index| {
            let key = dcg_program::unified::classes::key_of(&view, *index).unwrap();
            dcg_program::unified::classes::class_shape(&view, key)
                .unwrap()
                .is_some_and(|shape| shape.form == decision::GATHER_FORM_ID)
        })
    } else {
        None
    };
    if admit_form48_only {
        assert!(
            form48_class.is_some(),
            "the retained compiler-v1 fixture has a Form-48 class"
        );
    }
    if k10240_fixture {
        assert_eq!(k, 10_240, "K=10,240 path uses the retained large template");
    }
    if k10240_fixture {
        // Fast local preflight of the exact admission walk. Keep a failing
        // class index and shape visible without spending minutes uploading
        // the PT1X fixture before finding a frozen-registry limit mismatch.
        let (mut preflight_rows, _) = if has_pxr1 {
            decision_registry_rows()
        } else {
            k10240_registry_rows()
        };
        for row in preflight_rows.chunks_exact_mut(registry::ROW_BYTES) {
            if u16::from_le_bytes(row[..2].try_into().unwrap()) == registry::FORM_RS1_SUMMARY {
                row[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
                row[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
                for field in [8usize, 12, 16, 40, 44, 48] {
                    row[field..field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                }
                row[20..24].copy_from_slice(&1_000_000u32.to_le_bytes());
                row[24..28].copy_from_slice(&1_000_000u32.to_le_bytes());
                row[37] = rs1_height(k);
            }
        }
        let view = Pt2p::new(
            &routes,
            &geometry,
            &payloads,
            Some(&payload_index),
            g_prog.clone(),
        )
        .unwrap();
        for i in 0..class_total {
            let key = dcg_program::unified::classes::key_of(&view, i).unwrap();
            let Some(shape) = dcg_program::unified::classes::class_shape(&view, key)
                .unwrap_or_else(|code| panic!("class {i} {key:?} shape failed: {code}"))
            else {
                continue;
            };
            let row = registry::find_row(&preflight_rows, shape.form).unwrap();
            if let Some(row) = row.as_ref() {
                assert!(shape.position < row.position_limit, "class {i}: {:?}", row);
            }
            let code = registry::check(row.as_ref(), &shape);
            assert_eq!(
                code, 0,
                "class {i} {key:?} failed admission: {shape:?}; row {row:?}"
            );
        }
    }
    // Compiler-v1's decision fixture places Form 47 last at the configured
    // prompt position. The retained rung-D template keeps its original locator.
    let (base_entry, output_write, output_width) = if has_pxr1 {
        let view = Pt2p::new(&routes, &geometry, &payloads, None, g_prog).unwrap();
        let position = f47_position();
        let entry_index = view.entry_count(position).unwrap() - 1;
        let entry = view.entry(position, entry_index).unwrap();
        assert_eq!(entry.kernel_index, 47);
        let route = view.route(&entry, entry.read_count).unwrap();
        let base_entry = view.base_entries - 1;
        assert_eq!(
            view.old_to_new(base_entry, position).unwrap(),
            Some(entry_index)
        );
        (
            base_entry,
            0,
            u8::try_from(route.byte_length).expect("4-byte Form 47 output"),
        )
    } else {
        (28_037u32, 0u8, 16u8)
    };
    let locator = Locator {
        base_entry,
        write: output_write,
        width: output_width,
    };
    // **The PT2S is left in `STATE_HASHING`, and the locator is not written into
    // it.** The six bytes at 426..432 are the seal's to write, and the honest
    // path into this file is the real tag-145 instruction: the genesis image
    // carries only what a real emission's own state carried at the seal, and
    // the instruction below does the rest. Everything downstream -- the DTA1
    // approval's address, the PT2S digest, the admission record, the DTU1
    // address, and the clause-12 and definition digests the descriptor commits
    // -- is then derived from the **sealed** account's own bytes.
    let pt2s_image = if full_honest_setup {
        vec![0u8; S::OFF_PWR1 + pwr1.len()]
    } else {
        hashing_pt2s(
            &routes,
            &geometry,
            &payloads,
            &pwr1,
            executor_kp.pubkey(),
            [routes_key, geometry_key, payloads_key],
        )
    };
    if !full_honest_setup {
        assert_eq!(
            &pt2s_image[S::OFF_CLAUSE12..S::OFF_PWR1_LEN],
            &[0u8; S::OFF_PWR1_LEN - S::OFF_CLAUSE12][..],
            "the pre-seal image carries nothing from 316 to 424: the seal writes all of it"
        );
        assert_eq!(
            &pt2s_image[S::OFF_LOCATOR..S::OFF_PWR1],
            &[0u8; 6][..],
            "and 426..432 is dead state -- the six locator bytes are the seal's to write"
        );
    }
    // **The SBF CU census path.** `BASANOS_DCG_V8_SBF=1` with `BPF_OUT_DIR`

    // pointing at a `build-sbf-reproducible.sh` output runs the same
    // instructions against the real SBF image, and the `cu` the `send` helper
    // prints is then the SBF figure rather than the native one. The image must
    // come from the documented wrapper (platform-tools v1.51), because an
    // ordinary host build is not an SBF build.
    let mut test = if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
        assert!(
            !use_old_seal,
            "the old-seal regression runs on the native processor"
        );
        let dir = std::env::var("BPF_OUT_DIR").expect("BPF_OUT_DIR names the SBF image directory");
        let elf = std::fs::read(std::path::Path::new(&dir).join("dcg_program.so")).unwrap();
        let data_address =
            solana_program::bpf_loader_upgradeable::get_program_data_address(&program);
        let mut program_state = 2u32.to_le_bytes().to_vec();
        program_state.extend_from_slice(data_address.as_ref());
        let mut data = 3u32.to_le_bytes().to_vec();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(1);
        data.extend_from_slice(executor_kp.pubkey().as_ref());
        data.extend_from_slice(&elf);
        let mut test = ProgramTest::default();
        test.prefer_bpf(true);
        test.add_genesis_account(
            program,
            Account {
                lamports: 1_000_000_000,
                data: program_state,
                owner: solana_program::bpf_loader_upgradeable::id(),
                executable: true,
                rent_epoch: 0,
            },
        );
        test.add_genesis_account(
            data_address,
            Account {
                lamports: 1_000_000_000_000,
                data,
                owner: solana_program::bpf_loader_upgradeable::id(),
                executable: false,
                rent_epoch: 0,
            },
        );
        eprintln!(
            "SBF image {} bytes, sha256 {}",
            elf.len(),
            sha256(&[&elf])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        test
    } else {
        let mut test = if use_old_seal {
            #[cfg(feature = "test-rev8-before-payer-alias-fix")]
            {
                ProgramTest::new(
                    "dcg_program",
                    program,
                    processor!(dcg_program::process_instruction_before_payer_alias_fix),
                )
            }
            #[cfg(not(feature = "test-rev8-before-payer-alias-fix"))]
            {
                panic!("the pre-fix seal processor requires its test-only feature");
            }
        } else {
            ProgramTest::new(
                "dcg_program",
                program,
                processor!(dcg_program::process_instruction),
            )
        };
        test.prefer_bpf(false);
        test
    };
    if std::env::var_os("BASANOS_DCG_F47_PROBE_LIMIT").is_some() {
        test.set_compute_max_units(u64::from(f47_compute_limit()));
    }
    test.add_account(executor_kp.pubkey(), system_funded());
    test.add_account(signer.pubkey(), system_funded());
    if full_honest_setup {
        // The full honest path allocates all template accounts through the
        // System Program after the bank starts; tag 140 and later instructions
        // write every PT1X/PT2S byte used by the test.
    } else {
        for key in [pt2s, routes_key, geometry_key, payloads_key] {
            test.add_account(key, system_funded());
        }
        test.add_account(pt2s, owned(&program, pt2s_image.clone()));
        // The test fixture's PT1X payload index is rebuilt from the retained
        // rows. Full-honest tests exercise tag 142's real writer instead.
        let payload_index = retained_payload_index(&payloads);
        assert_eq!(payload_index.len(), 4 * (base_entries as usize + 1));
        let mut pt1s_data =
            vec![0u8; dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + payload_index.len()];
        pt1s_data[..4].copy_from_slice(b"PT1X");
        pt1s_data[4] = 6;
        pt1s_data[5..37].copy_from_slice(executor_kp.pubkey().as_ref());
        for (i, key) in [routes_key, geometry_key, payloads_key]
            .into_iter()
            .enumerate()
        {
            pt1s_data[37 + 32 * i..69 + 32 * i].copy_from_slice(key.as_ref());
        }
        for (i, len) in [routes.len(), geometry.len(), payloads.len()]
            .into_iter()
            .enumerate()
        {
            pt1s_data[133 + 4 * i..137 + 4 * i].copy_from_slice(&(len as u32).to_le_bytes());
        }
        pt1s_data[dcg_program::pt1_onchain::PT1X_BOUND_PT2S_AT
            ..dcg_program::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
            .copy_from_slice(pt2s.as_ref());
        pt1s_data[dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX..].copy_from_slice(&payload_index);
        test.add_account(pt1s_index, owned(&program, pt1s_data));
        test.add_account(routes_key, owned(&program, routes.clone()));
        test.add_account(geometry_key, owned(&program, geometry.clone()));
        test.add_account(payloads_key, owned(&program, payloads.clone()));
    }
    // DCF1, the one account ConfigInit cannot write natively (it wants a
    // loader-v3 program account), as `unified_registry_machine.rs` does.
    let config_key = address::config(&program).0;
    let mut dcf1 = vec![0u8; config::CONFIG_BYTES];
    dcf1[..4].copy_from_slice(b"DCF1");
    dcf1[4..6].copy_from_slice(&1u16.to_le_bytes());
    for role in 0..3 {
        dcf1[8 + 32 * role..40 + 32 * role].copy_from_slice(executor_kp.pubkey().as_ref());
    }
    test.add_account(config_key, owned(&program, dcf1));
    let mut ctx = test.start_with_context().await;
    let mut cached_sender = QuietSendCache::default();
    if full_honest_setup {
        allocate_program_account(
            &mut ctx,
            &executor_kp,
            &pt1x_kp,
            program,
            dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4 * (base_entries as usize + 1),
        )
        .await;
        allocate_program_account(&mut ctx, &executor_kp, &route_kp, SYSTEM, routes.len()).await;
        allocate_program_account(&mut ctx, &executor_kp, &geometry_kp, SYSTEM, geometry.len())
            .await;
        allocate_program_account(&mut ctx, &executor_kp, &payload_kp, SYSTEM, payloads.len()).await;
        allocate_program_account(
            &mut ctx,
            &executor_kp,
            &pt2s_kp,
            program,
            S::OFF_PWR1 + pwr1.len(),
        )
        .await;
    }
    // **The template seal, by the real 39-byte instruction (tag 145).** The
    // locator is the retained template's own `(28_037, write 0, width 16)`, and
    // `write = 0` is the case the review found the seal refusing: it is the
    // only real template in this tree, its golden example binding declares
    // `output_write = 0`, and the mirror's `OutputLocator` admits it, so a
    // `write != 0` rule at the seal made the honest path from a seal through
    // init to attest unreachable. The instruction writes 316..432 -- the clause
    // -12 v4, the definition digest, the template descriptor and the six
    // locator bytes -- and every value below is read back out of the sealed
    // account rather than laid down here.
    let mut seal_data = vec![S::TAG_SEAL];
    seal_data.extend_from_slice(&[9u8; 32]);
    seal_data.extend_from_slice(&base_entry.to_le_bytes());
    seal_data.push(output_write);
    seal_data.push(output_width);
    assert_eq!(seal_data.len(), 39, "the revision-8 seal argument");
    let mut seal_metas = vec![
        AccountMeta::new(pt2s, false),
        AccountMeta::new_readonly(routes_key, false),
        AccountMeta::new_readonly(geometry_key, false),
        AccountMeta::new_readonly(payloads_key, false),
        AccountMeta::new(executor_kp.pubkey(), true),
    ];
    seal_metas.push(AccountMeta::new_readonly(pt1s_index, false));
    let mut pxr_seal_chunk_calls = 0usize;
    if full_honest_setup {
        upload_pt1x(
            &mut ctx,
            &executor_kp,
            program,
            &pt1x_kp,
            [&route_kp, &geometry_kp, &payload_kp],
            [routes_key, geometry_key, payloads_key],
            [&routes, &geometry, &payloads],
            &signer,
            &mut cached_sender,
        )
        .await;
        seal_pt1x(
            &mut ctx,
            &executor_kp,
            program,
            pt1s_index,
            [routes_key, geometry_key, payloads_key],
            &routes,
            &signer,
            &mut cached_sender,
        )
        .await;
        seal_pt2s(
            &mut ctx,
            &executor_kp,
            &pt2s_kp,
            program,
            pt1s_index,
            [routes_key, geometry_key, payloads_key],
            &pwr1,
            locator,
            &signer,
            &mut cached_sender,
        )
        .await;
    } else {
        send(
            &mut ctx,
            &executor_kp,
            program,
            seal_data,
            seal_metas.clone(),
        )
        .await
        .expect("the 39-byte template seal");
        if has_pxr1 {
            loop {
                let state = ctx
                    .banks_client
                    .get_account(pt2s)
                    .await
                    .unwrap()
                    .unwrap()
                    .data;
                if state[S::OFF_STATE] == S::STATE_SEALED {
                    break;
                }
                assert_eq!(state[S::OFF_STATE], S::STATE_SEALING_PXR);
                let mut chunk = vec![S::TAG_SEAL_PXR_CHUNK];
                chunk.extend_from_slice(&S::MAX_PXR_SEAL_ROWS.to_le_bytes());
                send(&mut ctx, &executor_kp, program, chunk, seal_metas.clone())
                    .await
                    .expect("the tag-193 PXR1 seal chunk");
                pxr_seal_chunk_calls += 1;
            }
            assert_eq!(
                pxr_seal_chunk_calls, 50,
                "the complete PXR1 seal cursor walk uses tag 193"
            );
            eprintln!("tag193 PXR1 seal cursor completed {pxr_seal_chunk_calls} chunks");
        }
    }
    let pt2s_image = ctx
        .banks_client
        .get_account(pt2s)
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(
        pt2s_image[S::OFF_STATE],
        S::STATE_SEALED,
        "the seal sealed the state"
    );
    assert_eq!(
        &pt2s_image[S::OFF_LOCATOR..S::OFF_LOCATOR + 4],
        &base_entry.to_le_bytes()
    );
    assert_eq!(pt2s_image[S::OFF_LOCATOR + 4], output_write);
    assert_eq!(pt2s_image[S::OFF_LOCATOR + 5], output_width);
    assert_eq!(
        &pt2s_image[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
        &clause12[..],
        "the seal recomputed the retained clause-12 v4 byte for byte"
    );
    assert_eq!(
        &pt2s_image[S::OFF_DEFINITION..S::OFF_DEFINITION + 32],
        &[9u8; 32][..]
    );
    assert_eq!(
        pt2s_image.len(),
        S::OFF_PWR1 + pwr1.len(),
        "the account did not grow"
    );
    let pt2s_sha = sha256(&[&pt2s_image]);
    // The registry, by real instructions over the v7 golden's rows.
    let (mut rows, census) = if has_pxr1 {
        decision_registry_rows()
    } else if k10240_fixture {
        k10240_registry_rows()
    } else {
        (
            unhex(g["drp2"]["rows"].as_str().unwrap()),
            unhex(g["drp2"]["census_digest"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
    };
    // **The v7 golden row set is the refusal variant.** Its summary row
    // (`form 0xF001`) is narrowed below the real plan's summary shapes -- an
    // out-of-range `execute_cu` (the golden's own 779 vector) and a
    // `max_rs1_height` under this plan's 7 -- because that row exists to make
    // the class walk refuse. The registry that admitted the revision-7 document
    // is not in this tree. The fixture lifts that one row's limit fields (never
    // its `form_id`, `respond_path` or `witness_kind`, which the program
    // capability-checks) so the summary-class check at init runs for real over
    // the real shapes. Every other row is the golden's byte for byte.
    for i in 0..rows.len() / registry::ROW_BYTES {
        let at = i * registry::ROW_BYTES;
        if u16::from_le_bytes(rows[at..at + 2].try_into().unwrap()) == registry::FORM_RS1_SUMMARY {
            rows[at + 4..at + 6].copy_from_slice(&u16::MAX.to_le_bytes());
            rows[at + 6..at + 8].copy_from_slice(&u16::MAX.to_le_bytes());
            for field in [8usize, 12, 16, 40, 44, 48] {
                rows[at + field..at + field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            // The two CU fields must be in 1..=CU_LIMIT (779), not maximal.
            for field in [20usize, 24] {
                rows[at + field..at + field + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
            }
            rows[at + 37] = rs1_height(k);
        }
    }
    let drp2 = address::registry(&program, 1).0;
    if full_honest_setup {
        fund_system(&mut ctx, &executor_kp, drp2, 50_000_000_000).await;
    } else {
        fund(&mut ctx, drp2).await;
    }
    let create = vec![
        AccountMeta::new(executor_kp.pubkey(), true),
        AccountMeta::new_readonly(config_key, false),
        AccountMeta::new(drp2, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ];
    let mut data = vec![TAG_REGISTRY_CREATE];
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&((rows.len() / registry::ROW_BYTES) as u32).to_le_bytes());
    data.extend_from_slice(&census);
    send_quiet_cached(
        &mut ctx,
        &executor_kp,
        &[],
        program,
        data,
        create,
        &mut cached_sender,
    )
    .await
    .unwrap();
    let rw = vec![
        AccountMeta::new(executor_kp.pubkey(), true),
        AccountMeta::new_readonly(config_key, false),
        AccountMeta::new(drp2, false),
    ];
    for (i, row) in rows.chunks_exact(registry::ROW_BYTES).enumerate() {
        let mut d = vec![TAG_REGISTRY_WRITE];
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&(i as u32).to_le_bytes());
        d.extend_from_slice(row);
        send_quiet_cached(
            &mut ctx,
            &executor_kp,
            &[],
            program,
            d,
            rw.clone(),
            &mut cached_sender,
        )
        .await
        .unwrap();
    }
    send_quiet_cached(
        &mut ctx,
        &executor_kp,
        &[],
        program,
        vec![TAG_REGISTRY_FREEZE, 1, 0, 0, 0],
        rw,
        &mut cached_sender,
    )
    .await
    .unwrap();
    let drp2_data = ctx
        .banks_client
        .get_account(drp2)
        .await
        .unwrap()
        .unwrap()
        .data;
    let reg_root = d32(&drp2_data, 152);
    assert_eq!(
        reg_root,
        registry::table_root(1, executor_kp.pubkey().as_ref(), &census, &rows)
    );
    // The template seal (tag 176), by the real revision-8 instruction: its
    // 42-byte action-1 form and eleven single-base metas.
    // The seal is what creates both new records, so everything downstream --
    // the DTU1 address, its five limits and its registry -- is read back out of
    // the accounts the instruction wrote rather than laid down here.
    let dta1 = address::template_seal(&program, &pt2s, &pt2s_sha).0;
    let dtu1 = address::template_use(&program, &pt2s, &pt2s_sha).0;
    let seal = vec![
        AccountMeta::new(executor_kp.pubkey(), true),
        AccountMeta::new_readonly(config_key, false),
        AccountMeta::new(dta1, false),
        AccountMeta::new_readonly(pt2s, false),
        AccountMeta::new(dtu1, false),
        AccountMeta::new_readonly(pt1s_index, false),
        AccountMeta::new_readonly(geometry_key, false),
        AccountMeta::new_readonly(routes_key, false),
        AccountMeta::new_readonly(payloads_key, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(drp2, false),
    ];
    let mut data = vec![TAG_TEMPLATE_SEAL, config::SEAL_APPROVED];
    for limit in [
        EXAMPLE_LIMITS.max_challenge_window_slots,
        EXAMPLE_LIMITS.max_response_window_slots,
        EXAMPLE_LIMITS.max_document_lifetime_slots,
        EXAMPLE_LIMITS.max_abandon_after_slots,
        EXAMPLE_LIMITS.min_abandon_after_slots,
    ] {
        data.extend_from_slice(&limit.to_le_bytes());
    }
    assert_eq!(
        data.len(),
        config::SEAL_DATA_APPROVE,
        "the revision-8 seal argument"
    );
    send_quiet_cached(
        &mut ctx,
        &executor_kp,
        &[],
        program,
        data,
        seal,
        &mut cached_sender,
    )
    .await
    .unwrap();
    // The DTU1 the seal wrote: live, no documents, the sealer as authority, the
    // registry the seal's own meta named, and the five limits it carried.
    let use_record = ctx
        .banks_client
        .get_account(dtu1)
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(use_record.len(), config::DTU1_BYTES);
    assert_eq!(
        (&use_record[..4], use_record[6], u32_at(&use_record, 8)),
        (&b"DTU1"[..], config::DTU1_STATE_LIVE, 0)
    );
    assert_eq!(
        use_record[config::DTU1_AUTHORITY_AT..config::DTU1_AUTHORITY_AT + 32],
        executor_kp.pubkey().to_bytes()
    );
    assert_eq!(
        use_record[config::DTU1_REGISTRY_AT..config::DTU1_REGISTRY_AT + 32],
        drp2.to_bytes()
    );
    for (i, limit) in [
        EXAMPLE_LIMITS.max_challenge_window_slots,
        EXAMPLE_LIMITS.max_response_window_slots,
        EXAMPLE_LIMITS.max_document_lifetime_slots,
        EXAMPLE_LIMITS.max_abandon_after_slots,
        EXAMPLE_LIMITS.min_abandon_after_slots,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            u64_at(&use_record, config::DTU1_MAX_CHALLENGE_AT + 8 * i),
            limit
        );
    }

    // The admission record: the golden's own image, repointed at this fixture.
    let dea2 = address::admission(&program, &drp2, &pt2s, k).0;
    let mut adm = unhex(g["dea2"]["complete"].as_str().unwrap());
    adm[4..6].copy_from_slice(&3u16.to_le_bytes());
    // This proof harness can use the retained compiler-v1 form-47 emission,
    // whose compact fixture has 35 positions, or the older 80-position rung-D
    // emission. Rebind the admission image to the artifact actually loaded.
    adm[136..140].copy_from_slice(&k.to_le_bytes());
    adm[156] = rs1_height(k);
    assert_eq!(u32_at(&adm, 136), k);
    if has_pxr1 {
        adm.resize(admission::bytes(class_total), 0);
        adm[140..144].copy_from_slice(&base_entries.to_le_bytes());
        adm[144..148].copy_from_slice(&(class_total - base_entries).to_le_bytes());
        adm[148..152].copy_from_slice(&class_total.to_le_bytes());
        adm[152..156].copy_from_slice(&u32::try_from(n_max).unwrap().to_le_bytes());
        adm[admission::HEADER..].fill(0xff);
        if class_total % 8 != 0 {
            *adm.last_mut().unwrap() &= (1u8 << (class_total % 8)) - 1;
        }
    } else {
        assert_eq!(u32_at(&adm, 140), base_entries);
        if k10240_fixture {
            // The K=10,240 retained compiler-v1 bundle has a different maximum
            // per-position entry count than the older capacity-80 fixture.
            adm[152..156].copy_from_slice(&u32::try_from(n_max).unwrap().to_le_bytes());
        } else {
            assert_eq!(u32_at(&adm, 152) as u64, n_max);
        }
    }
    adm[8..40].copy_from_slice(drp2.as_ref());
    adm[40..72].copy_from_slice(&reg_root);
    adm[72..104].copy_from_slice(pt2s.as_ref());
    adm[104..136].copy_from_slice(&pt2s_sha);
    adm[160..192].copy_from_slice(executor_kp.pubkey().as_ref());
    if full_honest_setup {
        send_quiet_cached(
            &mut ctx,
            &executor_kp,
            &[],
            program,
            vec![159],
            vec![
                AccountMeta::new(executor_kp.pubkey(), true),
                AccountMeta::new(dea2, false),
                AccountMeta::new_readonly(drp2, false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(routes_key, false),
                AccountMeta::new_readonly(geometry_key, false),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(dtu1, false),
            ],
            &mut cached_sender,
        )
        .await
        .expect("permissionless admission begins from the sealed PT1X/PT2S");
        let mut first = if admit_form48_only {
            form48_class.unwrap()
        } else {
            0
        };
        let admission_end = if admit_form48_only {
            first + 1
        } else {
            class_total
        };
        while first < admission_end {
            // Keep the historical 16-class transaction shape. The targeted
            // Form-48 regression admits exactly its measured class.
            let count = (admission_end - first).min(16) as u16;
            let mut step = vec![160];
            step.extend_from_slice(&first.to_le_bytes());
            step.extend_from_slice(&count.to_le_bytes());
            send_quiet_cached(
                &mut ctx,
                &executor_kp,
                &[],
                program,
                step,
                vec![
                    AccountMeta::new(dea2, false),
                    AccountMeta::new_readonly(drp2, false),
                    AccountMeta::new_readonly(pt2s, false),
                    AccountMeta::new_readonly(pt1s_index, false),
                    AccountMeta::new_readonly(routes_key, false),
                    AccountMeta::new_readonly(geometry_key, false),
                ],
                &mut cached_sender,
            )
            .await
            .expect("admission step checks compiler-v1 classes");
            first += count as u32;
        }
        // An attested app image admits its bound classes without the
        // position scan and says so in DEA2 (complete | app-bound | attested).
        #[cfg(feature = "sbf-attested-admission-test")]
        if !admit_form48_only {
            let record = ctx
                .banks_client
                .get_account(dea2)
                .await
                .unwrap()
                .expect("tag 160 completed admission")
                .data;
            assert_eq!(u16_at(&record, 6), 1 | 2 | 4, "attested app-bound admission is complete");
        }
    } else {
        ctx.set_account(&dea2, &shared(owned(&program, adm)));
    }
    let position_roots: Vec<[u8; 32]> = e["positions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| d32(&unhex(p["position_root"].as_str().unwrap()), 0))
        .collect();
    let attestations: Vec<Vec<u8>> = e["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| unhex(o["attestation"].as_str().unwrap()))
        .collect();
    let dfs2 = unhex(g["dfs2"]["hex"].as_str().unwrap());
    let family_roots: Vec<[u8; 32]> = g["dfs2"]["family_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| d32(&unhex(r.as_str().unwrap()), 0))
        .collect();
    let terms_raw = Terms2 {
        challenge_window_slots: 90_000,
        response_window_slots: 45_000,
        challenger_bond_lamports: 1_000_000,
        executor_bond_lamports: ESCROW_FLOOR,
        executor_reward_bps: 0,
        bond_policy_kind: BOND_POLICY_CUSTOM,
        bond_slasher_bps: 0,
        settlement_program: [7u8; 32],
        custom_settle_window_slots: 604_800,
        result_retention_slots: 2_592_000,
        bond_remainder: [8u8; 32],
        abandon_after_slots: 2 * EXAMPLE_LIMITS.min_abandon_after_slots,
    }
    .encode()
    .to_vec();
    Some(Fix {
        lifecycle_v2_cache: QuietSendCache::default(),
        ctx,
        program,
        executor: executor_kp,
        signer,
        pt2s,
        routes: routes_key,
        geometry: geometry_key,
        payloads: payloads_key,
        drp2,
        dea2,
        dta1,
        dtu1,
        pt1s_index,
        pt2s_image,
        pt2s_sha,
        descriptor_v7: d32(&unhex(e["descriptor"].as_str().unwrap()), 0),
        position_roots,
        attestations,
        family_body: dfs2[document::DFS2_HEADER..].to_vec(),
        family_roots,
        k,
        segments,
        reg_root,
        total_entries: total,
        locator,
        terms_raw,
        base_entry,
        output_write,
        output_width,
        real_pda_funding: full_honest_setup,
        payload_key: payload_kp,
    })
}

// ------------------------------------------------------------------- the tests

/// The honest path: UnifiedInit, LandPositionRoots over the executor's own roots
/// and FinalizeDocumentV5 at three document lengths -- `n = 31`, a mid value, and
/// `n = K` -- with every field the spec's table gives DCM2 v7 and DCR2 v6.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_init_land_and_finalize_at_three_lengths() {
    let Some(mut f) = build().await else { return };
    // Three lengths, three bindings and so three documents: `n = 31` (the
    // smallest a completion can finalize at with `first = 29`), a mid value, and `n = K`.
    for (variant, (n, first, count)) in [(31u32, 29u32, 50u32), (40, 29, 50), (f.k, 29, 50)]
        .into_iter()
        .enumerate()
    {
        let binding = Binding2 {
            request_id: [5 + variant as u8; 32],
            ..f.binding(first, count)
        };
        assert!(f.k >= 80, "the retained plan has 80 positions");
        let (descriptor, created) = f.run_document(&binding, n).await;
        let doc = f.account(created[0]).await;
        let dcr2 = f.account(created[3]).await;
        let terms = Terms2::decode(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]).unwrap();
        // The record init wrote, field for field, at the frozen offsets.
        // A completion has no option table: 2,182 bytes, plus ARI1 on an
        // app-bound template.
        assert_option_tail(&mut f, &doc, &[]).await;
        assert_eq!(&doc[..4], b"DCM2");
        assert_eq!(u32_at(&doc, 4) as u16, 7, "version 7");
        assert_eq!(
            u32_at(&doc, 6) as u16,
            FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED,
            "flags armed | root_only | sealed, and no new flag"
        );
        assert_eq!(&doc[8..40], &descriptor);
        assert_eq!(
            &doc[40..72],
            f.executor.pubkey().as_ref(),
            "authority is the init signer"
        );
        assert_eq!(u32_at(&doc, 72), f.k, "position_capacity is the sealed K");
        assert_eq!(u32_at(&doc, 76) as u16, f.segments);
        assert_eq!(u32_at(&doc, 84), n, "positions_complete is the landed n");
        assert_eq!(
            u32_at(&doc, 184),
            90_000,
            "challenge_window_slots = DDT2[8..16]"
        );
        assert_eq!(
            u64_at(&doc, 192),
            f.total_entries,
            "the capacity-level total"
        );
        assert_eq!(&doc[200..232], f.pt2s.as_ref());
        assert_eq!(&doc[232..264], &f.pt2s_sha);
        assert_eq!(&doc[360..392], f.drp2.as_ref());
        assert_eq!(&doc[392..424], &f.reg_root[..]);
        assert_eq!(&doc[424..456], f.dea2.as_ref());
        assert_eq!(u32_at(&doc, 520), 4, "registry_epoch");
        assert_eq!(u32_at(&doc, 524) as u16, 16, "family_count");
        assert_eq!(doc[526], rs1_height(f.k));
        assert_eq!(doc[527], 3);
        assert_eq!(doc[529], BOND_HELD, "a nonzero bond is held");
        assert_eq!(
            &doc[530..562],
            &[0u8; 32],
            "conviction_winner is zero at init"
        );
        assert!(doc[528] as usize <= 32, "peak_count");
        assert_eq!(
            &doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2],
            &f.terms_raw[..]
        );
        assert_eq!(
            &doc[BINDING_AT_V8..BINDING_AT_V8 + BINDING_BYTES_V8],
            &binding.encode()[..]
        );
        assert_eq!(
            u64_at(&doc, document::ABANDON_DEADLINE_AT),
            1 + terms.abandon_after_slots,
            "abandon_deadline = init_slot + abandon_after_slots"
        );
        // The DCR2 v6 init wrote.
        assert_eq!(dcr2.len(), result::bytes_v8(count, 16).unwrap());
        assert_eq!(&dcr2[..4], b"DCR2");
        assert_eq!(u32_at(&dcr2, 4) as u16, 6);
        assert_eq!(dcr2[6], 0, "PENDING");
        assert_eq!(dcr2[7], 0);
        assert_eq!(&dcr2[8..40], &descriptor);
        assert_eq!(&dcr2[136..168], f.executor.pubkey().as_ref());
        assert_eq!(u32_at(&dcr2, 196), count, "output_count");
        assert_eq!(u32_at(&dcr2, 200), first, "output_first_position");
        assert_eq!(u32_at(&dcr2, 204), 0, "outputs_attested");
        assert_eq!(dcr2[208], 16);
        assert_eq!(
            &dcr2[209..212],
            &[0; 3],
            "v5's zero[7] is zero[3] plus position_length"
        );
        assert_eq!(u32_at(&dcr2, 212), 0, "position_length is 0 until finalize");
        assert_eq!(&dcr2[216..352], &f.terms_raw[..], "the terms mirror");
        assert_eq!(
            &dcr2[352..384],
            &[0u8; 32],
            "the close is 352's only writer"
        );
        assert_eq!(
            u64_at(&dcr2, 384),
            2_592_000,
            "retention_slots from the terms"
        );
        assert_eq!((u64_at(&dcr2, 392), u64_at(&dcr2, 400)), (0, 0));
        assert_eq!((dcr2[408], dcr2[409]), (0, 0));
        // The landing pushed the production deadline forward and the peaks moved
        // to 562, then finalize set flag 2 and rewrote the challenge deadline.
        let doc = f.finalize(&descriptor, created, n).await;
        assert_eq!(
            u32_at(&doc, 6) as u16,
            FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
            "flag 2 is set by finalize"
        );
        assert_eq!(u32_at(&doc, 84), n);
        assert_eq!(
            &doc[96..128],
            &doc[152..184],
            "document_root := prefix_root"
        );
        assert_eq!(
            u64_at(&doc, 144),
            90_000 + 1,
            "dispute_deadline = finalize_slot + window"
        );
        assert_eq!(
            &doc[488..520],
            &document::family_table_digest(&descriptor, &{
                let mut roots = Vec::new();
                for r in &f.family_roots {
                    roots.extend_from_slice(r);
                }
                roots
            }),
            "family_table_digest"
        );
        let dcr2 = f.account(created[3]).await;
        assert_eq!(&dcr2[40..72], &doc[96..128], "DCR2 40 is the document root");
        assert_eq!(u32_at(&dcr2, 212), n, "DCR2 212 is the document length");
        assert_eq!(
            u64_at(&dcr2, 168) + 90_000,
            u64_at(&dcr2, 176),
            "the deadline moved with it"
        );
        // The two-case L at this n.
        let l = binding.output_span(n);
        assert!(
            l >= 1 && l <= binding.output_count,
            "1 <= L <= count at FINAL: L = {l}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rev8_refuses_revision7_unified_init_account_list_on_v8_template() {
    let Some(mut f) = build().await else { return };
    let created = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];
    let mut legacy = vec![TAG_UNIFIED_INIT];
    legacy.extend_from_slice(&[0u8; 96]); // revision-7 DDT1
    legacy.extend_from_slice(&[0u8; 160]); // revision-7 DRB1
    legacy.extend_from_slice(&[[1u8; 32], [2u8; 32], [3u8; 32]].concat());
    legacy.extend_from_slice(&16u16.to_le_bytes());
    legacy.extend_from_slice(&f.family_body);
    assert!(legacy.len() >= 1 + 96 + 160 + 96 + 2);
    let mut metas = f.init_metas(created);
    metas.truncate(13); // the revision-7 list has no DTU1 document counter
    assert_eq!(
        custom(send_fresh_with(&mut f.ctx, &f.executor, f.program, legacy, metas).await),
        CL_MALFORMED,
        "the revision-8 reader rejects the legacy instruction shape"
    );
    assert_eq!(
        u32_at(&f.account(f.dtu1).await, 8),
        0,
        "a legacy call did not create an uncounted document"
    );
}

/// 816 through the handler: `n == positions_complete` and the length itself is
/// out of range, which needs a document landed to `first + 1`. The other end
/// (`n > first + count + 1`) and the whole decision branch are pinned by
/// `document_length_816_both_branches` in `unified_v8_records.rs`, against the
/// same rule and the same vectors the B refusal table names.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_finalize_refuses_a_document_length_out_of_range() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, 1).await;
    let executor_key = f.executor.pubkey();
    let metas: Vec<AccountMeta> = vec![
        AccountMeta::new(executor_key, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[3], false),
        AccountMeta::new_readonly(f.dtu1, false),
    ];
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                finalize_data(&descriptor, 1, &f.family_roots),
                metas
            )
            .await
        ),
        DOCUMENT_LENGTH,
        "n = first + 1"
    );
}

/// Every refusal finalize and land name, on a real document.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_finalize_and_land_refusals() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, 40).await;
    let executor_key = f.executor.pubkey();
    // Four metas on revision 8: revision 7's three plus DTU1, whose lifetime
    // limit is the clamp's ceiling (spec §1.6).
    let metas = |created: [Pubkey; 4]| {
        vec![
            AccountMeta::new(executor_key, true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[3], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ]
    };
    // 591 first: `positions_complete = n` is checked before 816, so 816 needs
    // a document landed to a length that is itself out of range. `n = 41` is
    // that check.
    for n in [41u32, 0, 81] {
        let code = custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                finalize_data(&descriptor, n, &f.family_roots),
                metas(created),
            )
            .await,
        );
        assert_eq!(
            code, CL_MISSING,
            "n = {n} must equal positions_complete first"
        );
    }

    // 580: exact length, and F against DCM2 524.
    let mut bad = finalize_data(&descriptor, 40, &f.family_roots);
    bad.push(0);
    assert_eq!(
        custom(send(&mut f.ctx, &f.executor, f.program, bad, metas(created)).await),
        CL_MALFORMED
    );
    let mut few = finalize_data(&descriptor, 40, &f.family_roots);
    few[37..39].copy_from_slice(&15u16.to_le_bytes());
    assert_eq!(
        custom(send(&mut f.ctx, &f.executor, f.program, few, metas(created)).await),
        CL_MALFORMED,
        "F must equal DCM2 524"
    );
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                finalize_data(&descriptor, 40, &f.family_roots),
                metas(created)[..2].to_vec()
            )
            .await
        ),
        CL_MALFORMED,
        "a short account list"
    );
    // 583: a zero root.
    let mut zero = f.family_roots.clone();
    zero[3] = [0; 32];
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                finalize_data(&descriptor, 40, &zero),
                metas(created)
            )
            .await
        ),
        CL_ROOT
    );
    // 582: a signer that is not the authority.
    let mut wrong = metas(created);
    wrong[0] = AccountMeta::new(f.signer.pubkey(), true);
    let signer_pubkey = f.signer.pubkey();
    let signer_ref = &f.signer;
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                signer_ref,
                f.program,
                finalize_data(&descriptor, 40, &f.family_roots),
                wrong
            )
            .await
        ),
        CL_AUTHORITY
    );
    let _ = signer_pubkey;
    // The honest finalize, then 592.
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&descriptor, 40, &f.family_roots),
        metas(created),
    )
    .await
    .unwrap();
    // Flag 2 is now set, which is what makes the landing below 592 and what
    // makes a second finalize 592 (`finalize_v8` reads the same byte it wrote).
    let doc = f.account(created[0]).await;
    assert_eq!(
        u32_at(&doc, 6) as u16,
        FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED
    );
    assert_eq!(
        u32_at(&doc, 84),
        40,
        "positions_complete is the finalized n"
    );
    // Land, after finalize, is 592.
    let l1: Vec<AccountMeta> = vec![
        AccountMeta::new(executor_key, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[1], false),
        AccountMeta::new_readonly(f.dtu1, false),
    ];
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                land_data(&descriptor, 40, &f.position_roots[40..41]),
                l1
            )
            .await
        ),
        CL_AFTER_FINAL,
        "land after finalize"
    );
}

/// **A short account list is a refusal, not a panic.** Both deadline writers
/// settle the revision from `accounts[1]`, so the count has to be settled before
/// that read. Revision 7 did: it refused any list whose length was not three
/// with 580, first statement of the handler. The revision split moved the
/// length into the match arms, where a list of one account or none matches no
/// arm and the reader runs first -- so a caller that named fewer accounts than
/// the instruction needs took the program out of bounds. On a real document,
/// with data that would otherwise have been accepted, both tags and both short
/// lengths are 580.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_land_and_finalize_refuse_a_short_account_list_before_reading_one() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    // Thirty roots landed, so `positions_complete = 30` and both instructions below
    // are honest on the full list: the landing is `first = 30, count = 1` and the
    // finalize is `n = 31`.
    let (descriptor, created) = f.run_document(&binding, 30).await;
    let executor_key = f.executor.pubkey();
    let land = vec![
        AccountMeta::new(executor_key, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[1], false),
        AccountMeta::new_readonly(f.dtu1, false),
    ];
    let fin = vec![
        AccountMeta::new(executor_key, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[3], false),
        AccountMeta::new_readonly(f.dtu1, false),
    ];
    let land_roots = f.position_roots[30..31].to_vec();
    // Every prefix of the list, both tags: 0 and 1 accounts cannot hold a
    // document at all, and 2 and 3 are revision 7's count on a revision-7
    // document, so none of the four is a legal shape here. The full list is the
    // control, below: it lands and finalizes, so a 580 above is the account
    // count and not a stale document.
    for take in 0..land.len() {
        assert_eq!(
            custom(
                send(
                    &mut f.ctx,
                    &f.executor,
                    f.program,
                    land_data(&descriptor, 30, &land_roots),
                    land[..take].to_vec()
                )
                .await
            ),
            CL_MALFORMED,
            "tag 162 with {take} account(s)"
        );
        assert_eq!(
            custom(
                send(
                    &mut f.ctx,
                    &f.executor,
                    f.program,
                    finalize_data(&descriptor, 31, &f.family_roots),
                    fin[..take].to_vec()
                )
                .await
            ),
            CL_MALFORMED,
            "tag 165 with {take} account(s)"
        );
    }
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(&descriptor, 30, &land_roots),
        land,
    )
    .await
    .expect("the four-account landing is the honest one");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&descriptor, 31, &f.family_roots),
        fin,
    )
    .await
    .expect("the four-account finalize is the honest one");
    let doc = f.account(created[0]).await;
    assert_eq!(
        u32_at(&doc, 84),
        31,
        "positions_complete is the finalized n"
    );
    assert!(
        u32_at(&doc, 6) as u16 & FLAG_FINAL != 0,
        "the document is finalized"
    );
}

/// The land refusals and the push-forward, on a document of their own so the
/// finalize cases above cannot mask them.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_land_refusals_and_the_production_deadline() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, 2).await;
    let executor_key = f.executor.pubkey();
    let l2: Vec<AccountMeta> = vec![
        AccountMeta::new(executor_key, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[1], false),
        AccountMeta::new_readonly(f.dtu1, false),
    ];
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                land_data(&descriptor, 5, &f.position_roots[5..6]),
                l2.clone()
            )
            .await
        ),
        APPEND_ORDER,
        "first must equal positions_complete"
    );
    let mut over = f.position_roots[2..].to_vec();
    over.push(f.position_roots[79]);
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                land_data(&descriptor, 2, &over),
                l2.clone()
            )
            .await
        ),
        CL_COORDINATE,
        "first + count must stay within K"
    );
    let mut zero = f.position_roots.clone();
    zero[2] = [0; 32];
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                land_data(&descriptor, 2, &zero[2..3]),
                l2.clone()
            )
            .await
        ),
        CL_ROOT
    );
    let mut short = vec![TAG_LAND_POSITION_ROOTS];
    short.extend_from_slice(&descriptor);
    short.extend_from_slice(&2u32.to_le_bytes());
    short.push(0);
    assert_eq!(
        custom(send(&mut f.ctx, &f.executor, f.program, short, l2.clone()).await),
        CL_MALFORMED,
        "count >= 1"
    );
    // The push-forward: a landing moves the production deadline to slot + window.
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(&descriptor, 2, &f.position_roots[2..3]),
        l2,
    )
    .await
    .unwrap();
    let doc = f.account(created[0]).await;
    let terms = Terms2::decode(&doc[TERMS_AT_V8..TERMS_AT_V8 + TERMS_BYTES_V2]).unwrap();
    let slot = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert!(u64_at(&doc, document::ABANDON_DEADLINE_AT) >= slot + terms.abandon_after_slots - 2);
    assert!(u64_at(&doc, document::ABANDON_DEADLINE_AT) >= slot + terms.abandon_after_slots - 2);
    assert_eq!(u32_at(&doc, 84), 3, "positions_complete moved");
}

// ------------------------------------------------- the honest AttestOutputV5

/// The leaf preimage's own domain and offsets (spec §6.11, and the Python
/// mirror's `closure_v2_model.leaf`): `domain[27] | descriptor[32] |
/// coordinate[10] | tail`, the write count at 143 and the write rows at 147.
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";
const LEAF_WRITE_COUNT_AT: usize = 143 - 69;
const LEAF_WRITES_AT: usize = 147 - 69;

/// One attest packet, **re-keyed** to a revision-8 descriptor.
///
/// The retained packets are real: the executor's own leaf, path, SPP1, table
/// root and value, over the real rung-D plan. Three things in them commit the
/// **revision-7** descriptor, and no retained proof commits a `/5` digest:
/// the leaf's `write/2` digest, the segment tree's `node/2` parents and the
/// `segment-root/2` wrap. So the leaf's own write row is re-keyed (same region,
/// same offset, same length, same value, the digest recomputed over this
/// document's descriptor), the leaf is re-hashed, the segment root and the
/// position root are re-folded from the **retained** path and SPP1 siblings, and
/// the result is what the test lands at that position. Every plan-derived fact
/// the handler reads -- the coordinate, the entry, the write ordinal, the
/// route's region/offset/length, the segment's leaf count, the segment ordinal
/// and the segment table root -- comes from the sealed plan, not from the
/// fixture.
struct Rekeyed {
    data: Vec<u8>,
    root: [u8; 32],
    value: Vec<u8>,
    p: u32,
}

fn leaf_hash_of(leaf: &[u8]) -> [u8; 32] {
    sha256(&[leaf])
}

/// **The duplicate-last tree's self-referential siblings.** At every level whose
/// sibling index is past the width, the tree repeats the node the lower levels
/// just folded, and `dl_fold` checks that entry by equality. A re-keyed leaf
/// cannot reuse those entries -- and could not have reused them anyway, because
/// it changed the node they repeat. Every other sibling covers indices that
/// exclude this leaf, so those are the retained document's own digests and are
/// left alone. `path` is rewritten in place, over the same ranges `dl_fold`
/// uses.
fn rekey_duplicates(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    count: u32,
    index: u32,
    value: [u8; 32],
    path: &mut [[u8; 32]],
) {
    let (mut index, mut width, mut span) = (index, count, 1u32);
    let mut node = (value, index, index + 1);
    let mut rekeyed = 0;
    for level in 0..path.len() {
        let sib = index ^ 1;
        let sibling = if sib >= width {
            rekeyed += 1;
            path[level] = node.0;
            node
        } else {
            let first = sib.checked_mul(span).unwrap();
            (path[level], first, first.saturating_add(span).min(count))
        };
        node = if index % 2 == 0 {
            node_parent(descriptor, kind, scope, level as u8 + 1, node, sibling)
        } else {
            node_parent(descriptor, kind, scope, level as u8 + 1, sibling, node)
        };
        index /= 2;
        width = width.div_ceil(2);
        span *= 2;
    }
    assert!(
        rekeyed >= 1,
        "a leaf this far right duplicates at least one level"
    );
}

/// `node/2` with the ranges, the crate's own hash over its own layout:
/// `(left, right) = (digest, first, end)`, height counted from one.
fn node_parent(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    height: u8,
    left: ([u8; 32], u32, u32),
    right: ([u8; 32], u32, u32),
) -> ([u8; 32], u32, u32) {
    let digest = h::hash(
        b"node/2",
        &[
            descriptor,
            &[kind],
            &scope.to_le_bytes(),
            &left.1.to_le_bytes(),
            &right.2.to_le_bytes(),
            &[height, 1],
            &left.0,
            &right.0,
        ],
    );
    (digest, left.1, right.2)
}

fn rekey(f: &Fix, descriptor: &[u8; 32], index: u32, p: u32) -> Rekeyed {
    let w = f.output_width as usize;
    let value = f.attestations[index as usize][37..37 + w].to_vec();
    rekey_with(f, descriptor, index, p, value)
}

/// The same walk with a **chosen** cell value. The re-keying is over the value
/// as much as over the descriptor — the leaf's write row is `write/2` over the
/// value, so a different value is a different leaf and the fold, the segment
/// root and the SPP1 are rebuilt over it. That is what lets the stop-rule tests
/// put a chosen token id in a chosen output's cell and attest it honestly,
/// instead of forging a DCR2 the attest never wrote.
fn rekey_with(f: &Fix, descriptor: &[u8; 32], index: u32, p: u32, value: Vec<u8>) -> Rekeyed {
    let packet = &f.attestations[index as usize];
    assert_eq!(
        packet[0], TAG_ATTEST_OUTPUT,
        "the retained packet is a tag 177"
    );
    assert_eq!(u32_at(packet, 33), index);
    let w = f.output_width as usize;
    assert_eq!(
        value.len(),
        w,
        "the value is one cell at the document's width"
    );
    let tail_len = u16_at(packet, 37 + w) as usize;
    let tail_at = 39 + w;
    let tail = &packet[tail_at..tail_at + tail_len];
    let height = packet[tail_at + tail_len] as usize;
    let path_at = tail_at + tail_len + 1;
    let mut path: Vec<[u8; 32]> = packet[path_at..path_at + 32 * height]
        .chunks_exact(32)
        .map(|c| <[u8; 32]>::try_from(c).unwrap())
        .collect();
    let (ordinal, proof_table, spp1_path, _) =
        challenge::decode_spp1(&packet[path_at + 32 * height..]).expect("a self-delimiting SPP1");
    let mut spp1_path = spp1_path;
    // The plan facts, derived exactly as `attest_v8` derives them.
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let t = x
        .old_to_new(f.base_entry, p)
        .unwrap()
        .expect("the base entry is live at p");
    let e = x.entry(p, t).unwrap();
    let route = x.route(&e, e.read_count + f.output_write as u16).unwrap();
    let c = x.coordinate(p, t).unwrap();
    let (mut entries, mut seg_ordinal) = (0u32, 0u16);
    for s in 0..x.segment_count as usize {
        let (id, n) = x.segment_row(p, s).unwrap();
        if id == c.segment {
            seg_ordinal = s as u16;
            entries = n;
        }
    }
    assert_eq!(ordinal, seg_ordinal, "the proof's ordinal is the plan's");
    assert_eq!(
        proof_table.to_vec(),
        x.segment_table_root(p).unwrap().to_vec(),
        "the proof's table root is the plan's"
    );
    assert_eq!(
        route.byte_length as usize, w,
        "the lane is the document's width"
    );
    // Re-key the leaf's own write row: the same write, over this descriptor.
    let coordinate = h::Coordinate {
        position: p,
        segment: c.segment,
        entry: c.local,
    };
    let digest = h::write_digest(
        descriptor,
        coordinate,
        route.region_id,
        route.effective_offset,
        &value,
    )
    .unwrap();
    let mut row = [0u8; 48];
    row[0..2].copy_from_slice(&route.region_id.to_le_bytes());
    row[4..8].copy_from_slice(&route.byte_length.to_le_bytes());
    row[8..16].copy_from_slice(&route.effective_offset.to_le_bytes());
    row[16..48].copy_from_slice(&digest);
    let mut tail = tail.to_vec();
    let writes =
        u16::from_le_bytes([tail[LEAF_WRITE_COUNT_AT], tail[LEAF_WRITE_COUNT_AT + 1]]) as usize;
    assert_eq!(
        tail.len(),
        LEAF_WRITES_AT + 48 * writes,
        "the tail is its own length"
    );
    let mut seen = false;
    for i in 0..writes {
        let at = LEAF_WRITES_AT + 48 * i;
        if tail[at..at + 2] == row[0..2]
            && tail[at + 4..at + 8] == row[4..8]
            && tail[at + 8..at + 16] == row[8..16]
        {
            tail[at + 16..at + 48].copy_from_slice(&digest);
            seen = true;
            break;
        }
    }
    assert!(seen, "the retained leaf carries this cell's own write row");
    // The fold the handler will run, over the re-keyed leaf.
    let mut leaf = Vec::new();
    leaf.extend_from_slice(LEAF_DOMAIN);
    leaf.extend_from_slice(descriptor);
    leaf.extend_from_slice(&coordinate.bytes());
    leaf.extend_from_slice(&tail);
    let leaf_hash = leaf_hash_of(&leaf);
    // Leaf 3,242 of a 3,244-leaf segment duplicates at levels 2 and 4; every
    // other sibling is the retained document's own digest.
    rekey_duplicates(descriptor, 1, p, entries, c.local, leaf_hash, &mut path);
    let tree = challenge::dl_fold(descriptor, 1, p, entries, c.local, &leaf_hash, &path)
        .expect("the re-keyed path folds the re-keyed leaf");
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            descriptor,
            &p.to_le_bytes(),
            &c.segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    // The SPP1 tree duplicates the same way: segment 33 of 34 is the last one.
    rekey_duplicates(
        descriptor,
        2,
        p,
        f.segments as u32,
        ordinal as u32,
        segment_root,
        &mut spp1_path,
    );
    let root = challenge::spp1_position_root(
        descriptor,
        p,
        f.segments,
        &segment_root,
        ordinal,
        &proof_table,
        &spp1_path,
        &x.segment_table_root(p).unwrap(),
    )
    .unwrap()
    .expect("the re-keyed SPP1 folds the re-keyed segment root");
    // The instruction data, with the descriptor, the index, the value and the
    // tail replaced and the proof carried through unchanged.
    let mut data = Vec::new();
    data.push(TAG_ATTEST_OUTPUT);
    data.extend_from_slice(descriptor);
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&value);
    data.extend_from_slice(&(tail.len() as u16).to_le_bytes());
    data.extend_from_slice(&tail);
    data.push(height as u8);
    for s in &path {
        data.extend_from_slice(s);
    }
    // The SPP1 blob, rebuilt with the same header: `ordinal:u16 | count:u8 |
    // 0:u8 | table_root[32] | sibling[count][32]`.
    data.extend_from_slice(&ordinal.to_le_bytes());
    data.push(spp1_path.len() as u8);
    data.push(0);
    data.extend_from_slice(&proof_table);
    for s in &spp1_path {
        data.extend_from_slice(s);
    }
    Rekeyed {
        data,
        root,
        value,
        p,
    }
}

/// tag 177's seven metas: the permissionless prover (s), DCM2, DPR2, DCR2 and
/// the three plan accounts.
fn attest_metas(
    signer: Pubkey,
    template: (Pubkey, Pubkey, Pubkey),
    created: [Pubkey; 4],
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(signer, true),
        AccountMeta::new(created[0], false),
        AccountMeta::new(created[1], false),
        AccountMeta::new(created[3], false),
        AccountMeta::new_readonly(template.0, false),
        AccountMeta::new_readonly(template.1, false),
        AccountMeta::new_readonly(template.2, false),
    ]
}

/// **The honest path, end to end**: a real init, a real landing that carries the
/// re-keyed proof's position root, a real finalize, and a real
/// `AttestOutputV5` that discharges the proof. Everything the handler reads
/// about the plan is the sealed plan's own value.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_attest_output_end_to_end() {
    let Some(mut f) = build().await else { return };
    // The retained run: `first = 29`, outputs of 16 bytes at positions 29..79.
    // Revision 8's binding check is `first + count + 1 <= position_capacity`
    // (revision 7's was `first + count <= P`), so 51 outputs over 80 positions
    // is **not** admissible and the count is 50: `29 + 50 + 1 = 80`, which makes
    // `n = K` the largest legal finalize and `L = n - 1 - first = 50 = count`.
    let (first, count) = (29u32, 50u32);
    let binding = f.binding(first, count);
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let n = f.k;
    let proof = rekey(&f, &descriptor, 0, first);
    // Land the executor's own roots with the re-keyed root at the attested
    // position, then finalize at `n = K` (`first + 2 <= n <= first + count + 1`
    // is `31 <= 80 <= 81`, so 816 holds and `L = 50`).
    let mut roots = f.position_roots[..n as usize].to_vec();
    roots[proof.p as usize] = proof.root;
    let created = [
        address::document(&f.program, &descriptor).0,
        address::positions(&f.program, &descriptor).0,
        address::family_slots(&f.program, &descriptor).0,
        address::result(&f.program, &descriptor).0,
    ];
    let metas = f.init_metas(created);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        init_data(
            &f.terms_raw,
            &binding.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &f.family_body,
            &[],
        ),
        metas,
    )
    .await
    .expect("init");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(&descriptor, 0, &roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[1], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("land");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&descriptor, n, &f.family_roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[3], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("finalize");
    let doc = f.account(created[0]).await;
    let before = u64_at(&doc, document::ABANDON_DEADLINE_AT);
    // The attest. **Permissionless** (revision 7 §6.11), so the fixture's second
    // keypair signs it: that is the round-4 Medium 1 property, tested.
    let other = f.signer.pubkey();
    let metas = attest_metas(other, (f.pt2s, f.routes, f.geometry), created);
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        proof.data.clone(),
        metas.clone(),
    )
    .await
    .expect("attest");
    let dcr2 = f.account(created[3]).await;
    let l = binding.output_span(n);
    assert_eq!(l, 50, "L = n - 1 - first = count at n = K");
    let cell_at = result::HEADER_V6;
    assert_eq!(
        &dcr2[cell_at..cell_at + 16],
        &proof.value[..],
        "the attested value is the cell"
    );
    assert_eq!(u32_at(&dcr2, 204), 1, "outputs_attested");
    assert_eq!(
        dcr2[result::HEADER_V6 + count as usize * 16] & 1,
        1,
        "the bitmap's bit 0"
    );
    assert_eq!(&dcr2[8..40], &descriptor[..], "the record is the v8 one");
    // The round-4 rule (a): the attest writes **no** deadline. Revision 7 makes
    // tag 177 permissionless, so a write here would be a third party's.
    let doc = f.account(created[0]).await;
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        before,
        "AttestOutputV5 does not write abandon_deadline"
    );
    // 795 on a value the leaf does not carry, and 591 at `index = L`.
    let mut bad = proof.data.clone();
    let value_at = 37;
    bad[value_at] ^= 1;
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, bad, metas.clone()).await),
        OUTPUT_PROOF,
        "a value the leaf does not carry"
    );
    let mut late = proof.data.clone();
    late[33..37].copy_from_slice(&l.to_le_bytes());
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, late, metas.clone()).await),
        CL_MISSING,
        "index = L is 591"
    );
    // A second attest of the same index is 795: the bit is set. One slot is
    // warped first, so this is a **new** transaction and not a duplicate of the
    // one the banks client already processed.
    let slot = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    f.ctx.warp_to_slot(slot + 1).unwrap();
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.signer,
                f.program,
                proof.data.clone(),
                metas.clone()
            )
            .await
        ),
        OUTPUT_PROOF,
        "the bit is already set"
    );
}

/// **A stale descriptor and a wrong one are refused at the attest** (this
/// review's Medium 1b), with the codes the handler actually produces.
///
/// The refusals hold by construction, and the construction is the point:
///
/// * **A wrong descriptor is 580 at `document_v8`, the first check in
///   `attest_v8`.** The DCM2 account's key **is** `PDA(descriptor)` and the
///   record's own header carries the same 32 bytes, so naming a descriptor the
///   account is not derived from fails both halves of that check before the
///   flag, the record, the plan or the proof is read. A stale `/4` descriptor
///   is the same case: revision 7's descriptor is a different digest, so the
///   revision-8 record is at a different address, and a proof committed to it
///   is a proof about a document that does not exist.
/// * **A `/4`-committed packet against the `/5` document is 795 at the fold,
///   not 580 at the account.** The retained packet is real, and three of its
///   twelve digests commit the **revision-7** descriptor; the program rebuilds
///   the leaf, the segment root and the SPP1 over the descriptor the *record*
///   names, so a retained packet's own digests cannot satisfy the fold. This
///   is the case the re-keying in `rekey` exists to discharge, so it is also
///   the case that shows the re-keying is doing what it claims.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_attest_refuses_a_stale_or_wrong_descriptor() {
    let Some(mut f) = build().await else { return };
    let (first, count) = (29u32, 50u32);
    let binding = f.binding(first, count);
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let n = f.k;
    let proof = rekey(&f, &descriptor, 0, first);
    let mut roots = f.position_roots[..n as usize].to_vec();
    roots[proof.p as usize] = proof.root;
    let (descriptor, created) = f.run_document_with_roots(&binding, &roots).await;
    f.finalize(&descriptor, created, n).await;
    let metas = attest_metas(f.signer.pubkey(), (f.pt2s, f.routes, f.geometry), created);
    // The honest packet, once, so the refusals below are on a proven document
    // and not on a document that had nothing to prove.
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        proof.data.clone(),
        metas.clone(),
    )
    .await
    .expect("the honest attest");

    // The wrong-kind, second-instance and stale-bump images of DCM2, DPR2
    // and DCR2 are states only a program bug could write: unit tests of the
    // three readers (result::reader_gate_tests; owner decision 2026-10-02).

    // **The retained packet, unmodified.** Its twelve path entries and its
    // SPP1 siblings are the revision-7 document's own digests over the
    // revision-7 descriptor, and it is sent against the revision-8 record.
    let retained = f.attestations[0].clone();
    assert_eq!(retained[0], TAG_ATTEST_OUTPUT);
    assert_ne!(
        &retained[1..33],
        &descriptor[..],
        "the retained packet names the /4 descriptor"
    );
    assert_eq!(
        &f.descriptor_v7[..],
        &retained[1..33],
        "and it is the executor's own revision-7 digest"
    );
    let mut stale = retained.clone();
    // **A wrong descriptor, from every angle.** Each of these differs from the
    // record's header digest, so `document_v8`'s PDA and header compares fail.
    let mut wrong = retained.clone();
    wrong[1..33].copy_from_slice(&f.descriptor_v7);
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, wrong, metas.clone()).await),
        CL_MALFORMED,
        "the /4 descriptor is 580 at the record's PDA"
    );
    let mut flipped = proof.data.clone();
    flipped[1] ^= 1;
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, flipped, metas.clone()).await),
        CL_MALFORMED,
        "one flipped byte of the descriptor is 580"
    );
    let mut zeroed = proof.data.clone();
    zeroed[1..33].copy_from_slice(&[0u8; 32]);
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, zeroed, metas.clone()).await),
        CL_MALFORMED,
        "a zero descriptor is 580"
    );
    // The record is untouched by every one of those, and its own header still
    // names the descriptor the honest packet named.
    let doc = f.account(created[0]).await;
    assert_eq!(
        &doc[8..40],
        &descriptor[..],
        "a refused attest wrote nothing to DCM2"
    );
    assert_eq!(
        u32_at(&f.account(created[3]).await, 204),
        1,
        "and nothing to the record's count"
    );
    // **A `/4` packet re-keyed to this document's descriptor is 795 at the
    // fold.** This is the one that needed the code to be right rather than the
    // account check to be right: the leaf is rebuilt from the packet's own
    // (revision-7) write row, the segment root and the SPP1 are folded over
    // the **revision-8** descriptor, and the tree does not contain the leaf
    // the packet carries. `rekey` is exactly the same walk with the write row
    // replaced, which is why the honest packet above discharges and this one
    // cannot.
    stale[1..33].copy_from_slice(&descriptor);
    assert_eq!(
        custom(send(&mut f.ctx, &f.signer, f.program, stale, metas.clone()).await),
        OUTPUT_PROOF,
        "a retained /4 packet against the /5 record fails the fold with 795"
    );
    // **And the wrong account is refused even with the right descriptor.** The
    // document account's key *is* `PDA(descriptor)`, so the same well-formed
    // revision-8 record installed somewhere else fails `document_v8`'s address
    // compare with the same 580: the descriptor a packet names and the account
    // a caller supplies have to be the same document, and neither half of that
    // check is the proof's business.
    let doc = f.account(created[0]).await;
    assert_eq!(
        &doc[8..40],
        &descriptor[..],
        "the record's own header names the descriptor"
    );
    // The attacker's version: another real document, at its own address.
    let other = Binding2 {
        request_id: [0x77; 32],
        ..binding
    };
    let (_, other_created) = f.run_document(&other, n).await;
    let elsewhere = other_created[0];
    let mut wrong_account =
        attest_metas(f.signer.pubkey(), (f.pt2s, f.routes, f.geometry), created);
    wrong_account[1] = AccountMeta::new_readonly(elsewhere, false);
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.signer,
                f.program,
                proof.data.clone(),
                wrong_account
            )
            .await
        ),
        CL_MALFORMED,
        "another real document is 580: the key is PDA(descriptor)"
    );
    // The refused packets left the proven cell alone, and the honest cell is
    // still the value the re-keyed leaf committed.
    let dcr2 = f.account(created[3]).await;
    assert_eq!(
        u32_at(&dcr2, 204),
        1,
        "one attested output, from the honest packet only"
    );
    let at = result::HEADER_V6;
    assert_eq!(&dcr2[at..at + 16], &proof.value[..]);
}

/// The second and third outputs of the same run, so the path is not a
/// single-cell accident: each re-keys its own leaf and each is a real leaf of
/// the real segment.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_attest_three_outputs_of_one_run() {
    let Some(mut f) = build().await else { return };
    let (first, count) = (29u32, 50u32);
    let binding = f.binding(first, count);
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let n = f.k;
    let proofs: Vec<Rekeyed> = [0u32, 1, 7]
        .iter()
        .map(|i| rekey(&f, &descriptor, *i, first + *i))
        .collect();
    // Every position in [first, first + 8) is attested, so every one of those
    // positions' roots is a re-keyed root.
    let mut roots = f.position_roots[..n as usize].to_vec();
    for p in &proofs {
        roots[p.p as usize] = p.root;
    }
    let created = [
        address::document(&f.program, &descriptor).0,
        address::positions(&f.program, &descriptor).0,
        address::family_slots(&f.program, &descriptor).0,
        address::result(&f.program, &descriptor).0,
    ];
    let metas = f.init_metas(created);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        init_data(
            &f.terms_raw,
            &binding.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &f.family_body,
            &[],
        ),
        metas,
    )
    .await
    .expect("init");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(&descriptor, 0, &roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[1], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("land");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&descriptor, n, &f.family_roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[3], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("finalize");
    let other = f.signer.pubkey();
    let metas = attest_metas(other, (f.pt2s, f.routes, f.geometry), created);
    for p in &proofs {
        send(
            &mut f.ctx,
            &f.signer,
            f.program,
            p.data.clone(),
            metas.clone(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "attest of output {} at position {}: {e:?}",
                u32_at(&p.data, 33),
                p.p
            )
        });
    }
    let dcr2 = f.account(created[3]).await;
    assert_eq!(u32_at(&dcr2, 204), 3, "three attested outputs");
    for p in &proofs {
        let i = u32_at(&p.data, 33) as usize;
        let at = result::HEADER_V6 + 16 * i;
        assert_eq!(
            &dcr2[at..at + 16],
            &p.value[..],
            "cell {i} is the attested value"
        );
        assert_eq!(
            dcr2[result::HEADER_V6 + count as usize * 16 + i / 8] >> (i % 8) & 1,
            1,
            "bitmap bit {i}"
        );
        assert!(
            p.p >= first && p.p < n,
            "output {i} is a generated position"
        );
    }
}

// ------------------------------------- the deadlines: 736 and the lifetime clamp

/// A crafted document at a chosen `init_slot`, for the two deadline rules. The
/// three account addresses are derived from the descriptor, so the fixture
/// installs the images at their own PDAs; everything the handlers read is
/// written here, and the ones they check are the frozen offsets.
struct Crafted {
    dcm2: Pubkey,
    dpr2: Pubkey,
    dcr2: Pubkey,
    descriptor: [u8; 32],
}

impl Fix {
    /// A DCM2 v7 + DPR2 + DCR2 v6 for `binding`, with `init_slot` and the two
    /// deadlines written as the init instruction would have left them.
    async fn craft(
        &mut self,
        binding: &Binding2,
        n: u32,
        roots: &[[u8; 32]],
        init_slot: u64,
        descriptor: [u8; 32],
    ) -> Crafted {
        self.craft_with(binding, n, roots, init_slot, descriptor, &[])
            .await
    }

    /// The document by real instructions (rule 6): UnifiedInit over
    /// `binding` at the clock (moved forward to `init_slot` when that is
    /// ahead; a document is never created in the past), then LandPositionRoots
    /// over `roots`. Init funds the PDAs to rent itself, so balances are the
    /// real ones. `descriptor` is the binding's own when it matches; otherwise
    /// its bytes become the request id, so distinct values still give distinct
    /// documents. A document that already exists is only landed on.
    async fn craft_with(
        &mut self,
        binding: &Binding2,
        _n: u32,
        roots: &[[u8; 32]],
        init_slot: u64,
        descriptor: [u8; 32],
        options: &[u8],
    ) -> Crafted {
        let binding = if descriptor == self.descriptor(binding, &self.terms_raw, 16) {
            *binding
        } else {
            Binding2 {
                request_id: descriptor,
                ..*binding
            }
        };
        let descriptor = self.descriptor(&binding, &self.terms_raw, 16);
        let now = self
            .ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        if init_slot > now {
            self.ctx.warp_to_slot(init_slot).unwrap();
        }
        let created = [
            address::document(&self.program, &descriptor).0,
            address::positions(&self.program, &descriptor).0,
            address::family_slots(&self.program, &descriptor).0,
            address::result(&self.program, &descriptor).0,
        ];
        if self.ctx.banks_client.get_account(created[0]).await.unwrap().is_none() {
            assert_eq!(options.len(), 4 * binding.option_count as usize);
            let data = init_data(
                &self.terms_raw,
                &binding.encode(),
                &[[1u8; 32], [2u8; 32], [3u8; 32]],
                16,
                &self.family_body,
                options,
            );
            let metas = self.init_metas(created);
            send_fresh_with(&mut self.ctx, &self.executor, self.program, data, metas)
                .await
                .expect("init");
        }
        let landed = u32_at(&self.account(created[0]).await, 84) as usize;
        for (batch, chunk) in roots[landed.min(roots.len())..].chunks(20).enumerate() {
            let first = (landed + 20 * batch) as u32;
            let metas = vec![
                AccountMeta::new(self.executor.pubkey(), true),
                AccountMeta::new(created[0], false),
                AccountMeta::new(created[1], false),
                AccountMeta::new_readonly(self.dtu1, false),
            ];
            send_fresh_with(&mut self.ctx, &self.executor, self.program, land_data(&descriptor, first, chunk), metas)
                .await
                .expect("land position roots");
        }
        Crafted {
            dcm2: created[0],
            dpr2: created[1],
            dcr2: created[3],
            descriptor,
        }
    }

    /// PENDING MIGRATION (rule 6): the old hand-built DCM2/DPR2/DCR2 image,
    /// kept only for the three close tests that hand-set a conviction until a
    /// real-conviction helper replaces them (T7). Do not use in new tests.
    async fn craft_hand_built(
        &mut self,
        binding: &Binding2,
        n: u32,
        roots: &[[u8; 32]],
        init_slot: u64,
        descriptor: [u8; 32],
        options: &[u8],
    ) -> Crafted {
        let window = u64_at(&self.terms_raw, 8);
        let abandon = u64_at(&self.terms_raw, 128);
        let mut doc = dcm2_v7(
            &self.program,
            &descriptor,
            &self.executor.pubkey().to_bytes(),
            self.k,
            n,
            FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED,
            &self.terms_raw,
            &binding.encode(),
            &self.pt2s.to_bytes(),
            &self.pt2s_sha,
            &self.dea2.to_bytes(),
            &self.drp2.to_bytes(),
            &self.reg_root,
            16,
            init_slot + window,
            init_slot + abandon,
        );
        // The prefix root. `finalize` copies 152 to 96 and to DCR2 40 without
        // re-deriving it, so a fixture may leave any nonzero value here; this is
        // the one that the real landing of `roots` would leave, computed by the
        // crate's own mountain range from a fresh peak list.
        let mut peaks = Vec::new();
        for (i, r) in roots.iter().enumerate() {
            document::mmr_append(&descriptor, i as u32, &mut peaks, r).unwrap();
        }
        doc[528] = peaks.len() as u8;
        for (i, p) in peaks.iter().enumerate() {
            let at = document::PEAKS_AT_V8 + document::PEAK_BYTES * i;
            doc[at] = p.level;
            doc[at + 4..at + 8].copy_from_slice(&p.first.to_le_bytes());
            doc[at + 8..at + 40].copy_from_slice(&p.digest);
        }
        let prefix = document::mmr_root(&descriptor, n, &peaks).unwrap();
        doc[152..184].copy_from_slice(&prefix);
        assert_eq!(options.len(), 4 * binding.option_count as usize);
        doc[OPTION_REGION_AT..OPTION_REGION_AT + options.len()].copy_from_slice(options);
        let dcm2 = address::document(&self.program, &descriptor).0;
        let dpr2 = address::positions(&self.program, &descriptor).0;
        let dcr2 = address::result(&self.program, &descriptor).0;
        self.ctx
            .set_account(&dcm2, &shared(owned(&self.program, doc)));
        // The page is written a few positions longer than `n`, so a landing in
        // the clamp test does not have to realloc an account the fixture
        // funded at exactly its own length.
        let spare = (n as usize + 8).min(self.position_roots.len());
        let mut pos = dpr2_image(&descriptor, self.k, &self.position_roots[..spare]);
        pos[44..48].copy_from_slice(&n.to_le_bytes());
        self.ctx
            .set_account(&dpr2, &shared(owned(&self.program, pos)));
        let res = dcr2_v6(
            &self.program,
            &descriptor,
            binding,
            &Terms2::decode(&self.terms_raw).unwrap(),
        );
        self.ctx
            .set_account(&dcr2, &shared(owned(&self.program, res)));
        Crafted {
            dcm2,
            dpr2,
            dcr2,
            descriptor,
        }
    }

    /// **Four metas on both**, revision 7's three plus DTU1: the clamp's ceiling
    /// is the *template's* lifetime limit, and the template is the only place
    /// that number lives (spec §1.6, §1.7).
    fn fin_metas(&self, c: &Crafted) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.executor.pubkey(), true),
            AccountMeta::new(c.dcm2, false),
            AccountMeta::new(c.dcr2, false),
            AccountMeta::new_readonly(self.dtu1, false),
        ]
    }

    /// The slot a document's real UnifiedInit ran at: DCM2's challenge
    /// deadline less the window, as the program derives it.
    async fn init_slot(&mut self, c: &Crafted) -> u64 {
        u64_at(&self.account(c.dcm2).await, 144) - u64_at(&self.terms_raw, 8)
    }

    fn land_metas(&self, c: &Crafted) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.executor.pubkey(), true),
            AccountMeta::new(c.dcm2, false),
            AccountMeta::new(c.dpr2, false),
            AccountMeta::new_readonly(self.dtu1, false),
        ]
    }
}

/// **736 at finalize**, twice: past the production deadline, and past the
/// attestation budget. Both are refusals, so the record is unchanged by each.
///
/// The slots are the fixture's own rather than warped ones: a document whose
/// `abandon_deadline` is already behind the clock is one whose executor stopped
/// landing a window ago, and a document created at slot 0 with a grace equal to
/// **its template's** `max_document_lifetime_slots` has a budget ceiling of
/// `init_slot + lifetime - abandon_after_slots = init_slot`, which is check 20
/// (`abandon_after_slots <= max_document_lifetime_slots`) at its tightest. The
/// second case is the honest shape of the rule and the reason it is a refusal
/// rather than tooling guidance.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_finalize_refuses_a_late_document_with_736() {
    let Some(mut f) = build().await else { return };
    let n = 40u32;
    let roots = f.position_roots[..n as usize].to_vec();
    // (1) At or after the production deadline. `abandon_deadline` is in the
    // past, which is what a document whose executor stopped landing looks like
    // one window later.
    let binding = f.binding(29, 50);
    let window = u64_at(&f.terms_raw, 8);
    // One slot, once, before anything is installed: a bank only verifies its
    // accounts hash across the slots it skips, and a fixture that rewrites
    // accounts with `set_account` cannot then skip a range.
    let base = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    f.ctx.warp_to_slot(base + 1).unwrap();
    let now = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert!(now >= 1);
    let mut c = f.craft(&binding, n, &roots, 0, [30u8; 32]).await;
    // The record as init would have left it, then the window elapsed: 2174 is
    // rewritten to a slot already behind the clock.
    // A real clock move past the production deadline (no record patch).
    let abandon = u64_at(&f.account(c.dcm2).await, document::ABANDON_DEADLINE_AT);
    f.ctx.warp_to_slot(abandon + 1).unwrap();
    let metas = f.fin_metas(&c);
    assert_eq!(
        custom(
            send(
                &mut f.ctx,
                &f.executor,
                f.program,
                finalize_data(&c.descriptor, n, &f.family_roots),
                metas.clone()
            )
            .await
        ),
        CL_DEADLINE,
        "now >= abandon_deadline is 736"
    );
    let after = f.account(c.dcm2).await;
    assert_eq!(
        u32_at(&after, 6) as u16,
        FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED,
        "a refused finalize writes nothing, and flag 2 is still clear"
    );
    assert_eq!(
        u64_at(&after, document::ABANDON_DEADLINE_AT),
        abandon,
        "and the deadline is untouched"
    );
    assert_eq!(
        u64_at(&after, 144),
        f.init_slot(&c).await + window,
        "the challenge deadline is the init one"
    );
    // (2) A finalize that would leave less than a full attestation budget. The
    // maximum window is LIFETIME, so the ceiling is the init slot itself.
    let big = Terms2 {
        abandon_after_slots: EXAMPLE_LIMITS.max_document_lifetime_slots,
        ..Terms2::decode(&f.terms_raw).unwrap()
    };
    let mut f2 = Fix {
        lifecycle_v2_cache: QuietSendCache::default(),
        terms_raw: big.encode().to_vec(),
        ..f
    };
    let b2 = f2.binding(29, 50);
    let c2 = f2.craft(&b2, n, &roots, 0, [31u8; 32]).await;
    // A real clock move: the finalize runs one slot after the real init, so
    // the budget ceiling (the init slot itself) is behind it.
    let init2 = f2.init_slot(&c2).await;
    f2.ctx.warp_to_slot(init2 + 1).unwrap();
    let metas = f2.fin_metas(&c2);
    assert_eq!(
        custom(
            send(
                &mut f2.ctx,
                &f2.executor,
                f2.program,
                finalize_data(&c2.descriptor, n, &f2.family_roots),
                metas.clone()
            )
            .await
        ),
        CL_DEADLINE,
        "a finalize that would leave less than a full attestation budget is 736"
    );
    // (3) The same document with a window the budget can cover: legal, and the
    // deadline it writes is `finalize_slot + abandon_after_slots` with the clamp
    // not binding, which is what the refusal in (2) guarantees.
    let c3 = f2.craft(&binding, n, &roots, now, [32u8; 32]).await;
    let metas = f2.fin_metas(&c3);
    send(
        &mut f2.ctx,
        &f2.executor,
        f2.program,
        finalize_data(&c3.descriptor, n, &f2.family_roots),
        metas,
    )
    .await
    .expect("a finalize inside the budget");
    let doc = f2.account(c3.dcm2).await;
    let slot = f2
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert_eq!(
        u32_at(&doc, 6) as u16,
        FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED
    );
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        slot + EXAMPLE_LIMITS.max_document_lifetime_slots,
        "the finalize wrote finalize_slot + abandon_after_slots, and the clamp did not bind"
    );
    assert!(slot >= now);
    c = c3;
    let _ = c;
}

/// **The clamp, taking effect.** A document created at slot 0 with a grace
/// equal to its template's `max_document_lifetime_slots` has a ceiling of
/// `0 + that limit`, so a landing at the fixture's own slot is already past it:
/// the write is the clamp and not `slot + abandon_after_slots`, and the two
/// differ by `slot - init_slot`. The same number is what row 2 of the close
/// fires at, which is the one exit a clamped document has.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_land_clamps_the_production_deadline_to_the_lifetime() {
    let Some(mut f) = build().await else { return };
    let n = 2u32;
    let roots = f.position_roots[..n as usize].to_vec();
    let base = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    f.ctx.warp_to_slot(base + 1).unwrap();
    let slot = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert!(slot >= 1);
    // The template's maximum grace: the ceiling is `init_slot + the template's
    // max_document_lifetime_slots` and the forward write is `slot + the same
    // number`, so the clamp binds exactly when `slot > init_slot`.
    let big = Terms2 {
        abandon_after_slots: EXAMPLE_LIMITS.max_document_lifetime_slots,
        ..Terms2::decode(&f.terms_raw).unwrap()
    };
    let mut f = Fix {
        lifecycle_v2_cache: QuietSendCache::default(),
        terms_raw: big.encode().to_vec(),
        ..f
    };
    let binding = f.binding(29, 50);
    let c = f.craft(&binding, n, &roots, 0, [33u8; 32]).await;
    let init_slot = f.init_slot(&c).await;
    let ceiling = init_slot + EXAMPLE_LIMITS.max_document_lifetime_slots;
    // A real clock move: the landing runs one slot after the real init.
    f.ctx.warp_to_slot(init_slot + 1).unwrap();
    let slot = init_slot + 1;
    assert!(slot > init_slot, "the landing is past the document's init slot");
    let metas = f.land_metas(&c);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(
            &c.descriptor,
            n,
            &f.position_roots[n as usize..n as usize + 1],
        ),
        metas,
    )
    .await
    .expect("a landing past the lifetime ceiling");
    let doc = f.account(c.dcm2).await;
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        ceiling,
        "the landing was clamped to init_slot + the template's lifetime limit"
    );
    assert!(
        slot + EXAMPLE_LIMITS.max_document_lifetime_slots > ceiling,
        "and the unclamped value would have been larger by slot - init_slot"
    );
    // `init_slot` is recovered as `dispute_deadline - challenge_window_slots`,
    // and the landing did not touch 144, so the recovery is this document's own
    // init slot and not the slot the landing ran at.
    assert_eq!(
        u64_at(&doc, 144) - u64_at(&doc, 184),
        init_slot,
        "init_slot is recovered as dispute_deadline - challenge_window_slots"
    );
    assert_eq!(u32_at(&doc, 84), n + 1, "the landing landed");
    // A document created in the future has not reached its ceiling, and the same
    // landing writes the plain forward value.
    let c2 = f.craft(&binding, n, &roots, slot, [34u8; 32]).await;
    let metas = f.land_metas(&c2);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(
            &c2.descriptor,
            n,
            &f.position_roots[n as usize..n as usize + 1],
        ),
        metas,
    )
    .await
    .expect("a landing before the ceiling");
    let doc = f.account(c2.dcm2).await;
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        slot + EXAMPLE_LIMITS.max_document_lifetime_slots,
        "before the ceiling the write is slot + abandon_after_slots"
    );
    assert_eq!(
        u64_at(&doc, 144) - u64_at(&doc, 184),
        slot,
        "init_slot is recovered as dispute_deadline - challenge_window_slots"
    );
}

// ------------------------------------------------------- typed decisions at K

/// A decision binding over this template's declared fields, with `K` options.
/// The plan has no 4-byte write lane, so this binding is refused **794** at
/// init -- which is the honest answer and is asserted in
/// `unified_v8_records.rs` -- and the finalize and attest below are driven over
/// a crafted record, where no plan check applies to finalize.
fn decision_binding(executor: &[u8; 32], prompt_positions: u32, k: u8) -> (Binding2, Vec<u8>) {
    decision_binding_at(executor, prompt_positions, k, 28_037)
}

fn decision_binding_at(
    executor: &[u8; 32],
    prompt_positions: u32,
    k: u8,
    base_entry: u32,
) -> (Binding2, Vec<u8>) {
    let mut options = Vec::new();
    for j in 0..k as u32 {
        options.extend_from_slice(&(1_000u32 + j).to_le_bytes());
    }
    let b = Binding2 {
        executor: *executor,
        request_id: [5u8; 32],
        consumer_digest: [6u8; 32],
        seed: [0; 32],
        output_first_position: prompt_positions - 1,
        output_count: 1 + k as u32,
        output_base_entry: base_entry,
        output_write: 0,
        output_width: 4,
        decision_flags: DECISION_MODE,
        option_count: k,
        prompt_positions,
        stop_plus_one: 0,
        option_table_offset: OPTION_REGION_AT as u16,
        option_table_sha256: sha256(&[&options]),
    };
    (b, options)
}

#[tokio::test(flavor = "multi_thread")]
async fn unified_init_rejects_prompt_shorter_than_template_producer_delta() {
    let Some(mut f) = build_f47().await else {
        return;
    };
    let mut binding = f.binding(29, 2);
    binding.prompt_positions = 1;
    binding.output_first_position = 0;
    assert_eq!(f.init_refusal(&binding, 236).await, RUN_BINDING,
        "UnifiedInit refuses before route instantiation when prompt_positions is below the template maximum");
}

/// The compiler-v1 PXR1 decision lane accepts a complete option table through
/// UnifiedInit at each supported boundary count, including both read-key
/// boundary sizes around tag 120's 48-account limit. Tag 146 reaches the
/// Form-47 route and refuses with 603 while the app route selector is pending.
#[tokio::test(flavor = "multi_thread")]
async fn f47_compiler_v1_unified_init_accepts_option_counts_1_47_48_80() {
    let Some(mut f) = build_f47().await else {
        return;
    };
    assert_eq!(
        f.output_width, 4,
        "the compiler-v1 fixture seals a 4-byte decision lane"
    );
    assert_eq!(
        f.base_entry, 28_040,
        "Form 47 is the final compiler-v1 entry"
    );
    let (routes_image, geometry_image, payloads_image, pwr1, _) =
        f47_artifacts().expect("compiler-v1 Form-47 fixture");
    let payload_index = retained_payload_index(&payloads_image);
    let template = Pt2p::new(
        &routes_image,
        &geometry_image,
        &payloads_image,
        Some(&payload_index),
        pt2p::Program::decode(&pwr1).expect("compiler-v1 PWR1"),
    )
    .expect("compiler-v1 PT2P template");
    let output_entry = (0..template.entry_count(29).expect("position entry count"))
        .find(|entry| {
            !matches!(
                template
                    .entry(29, *entry)
                    .expect("template entry")
                    .kernel_index,
                47 | 48
            )
        })
        .expect("position has a non-decision entry");
    let n = 30u32;
    for (variant, k) in [1u8, 47, 48, 80].into_iter().enumerate() {
        let (mut binding, _) =
            decision_binding_at(&f.executor.pubkey().to_bytes(), n, k, f.base_entry);
        let mut options = Vec::with_capacity(k as usize * 4);
        for token in 0..k as u32 {
            options.extend_from_slice(&token.to_le_bytes());
        }
        binding.request_id = [80 + variant as u8; 32];
        binding.option_table_sha256 = sha256(&[&options]);
        let (descriptor, created) = f.run_document_with_options(&binding, n, &options).await;
        let doc = f.account(created[0]).await;
        assert_eq!(&doc[8..40], &descriptor);
        // The option table at K, then ARI1 exactly on an app-bound template.
        assert_option_tail(&mut f, &doc, &options).await;
        assert_eq!(
            f.account(created[3]).await.len(),
            result::bytes_v8(binding.output_count, 4).unwrap(),
            "DCR2 is 416 + 4(1+K) + bitmap at K = {k}"
        );
        // 816's decision branch pins n = prompt_positions from both sides.
        let fin_metas = vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[3], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ];
        for bad in [n + 1, 0] {
            assert_eq!(
                custom(
                    send_fresh_with(
                        &mut f.ctx,
                        &f.executor,
                        f.program,
                        finalize_data(&descriptor, bad, &f.family_roots),
                        fin_metas.clone(),
                    )
                    .await
                ),
                CL_MISSING,
                "n != positions_complete is 591 at K = {k}"
            );
        }
        let finalized = f.finalize(&descriptor, created, n).await;
        assert_eq!(
            u16_at(&finalized, 6),
            FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
            "UnifiedInit document finalizes at K = {k}"
        );
        let dcr2 = f.account(created[3]).await;
        assert_eq!(u32_at(&dcr2, 212), n, "DCR2 212 is the document length");
        assert_eq!(u32_at(&dcr2, 196), 1 + k as u32, "the record's count is 1 + K");
        assert_eq!(dcr2[208], 4, "the record's width is 4");
        if variant == 0 {
            let decision_entry = f.base_entry;
            assert_eq!(
                template.entry(29, decision_entry).unwrap().kernel_index,
                decision::FORM_ID
            );
            let decision_keys = [
                f.pt2s,
                f.pt1s_index,
                f.routes,
                f.geometry,
                f.payloads,
                created[0],
            ];
            let decision_key_refs = decision_keys.iter().collect::<Vec<_>>();
            let decision_binding = dcg_program::pt1_onchain::pt1x_output_binding(
                &f.program,
                &decision_key_refs,
                29,
                decision_entry,
                1,
            );
            let (decision_output, _) =
                dcg_program::pt1_onchain::pt1x_output_address(&f.program, &decision_binding);
            // A real System Program transfer funds the output PDA.
            fund_system(&mut f.ctx, &f.executor, decision_output, 1_000_000_000_000).await;
            let mut decision_data = vec![S::TAG_INSTANTIATE];
            decision_data.extend_from_slice(&29u32.to_le_bytes());
            decision_data.extend_from_slice(&decision_entry.to_le_bytes());
            decision_data.extend_from_slice(&1u16.to_le_bytes());
            assert_eq!(
                custom(
                    send_with_signers(
                        &mut f.ctx,
                        &f.executor,
                        &[],
                        f.program,
                        decision_data,
                        vec![
                            AccountMeta::new_readonly(f.pt2s, false),
                            AccountMeta::new_readonly(f.pt1s_index, false),
                            AccountMeta::new_readonly(f.routes, false),
                            AccountMeta::new_readonly(f.geometry, false),
                            AccountMeta::new_readonly(f.payloads, false),
                            AccountMeta::new(decision_output, false),
                            AccountMeta::new_readonly(created[0], false),
                            AccountMeta::new_readonly(SYSTEM, false),
                            AccountMeta::new(f.executor.pubkey(), true),
                        ],
                    )
                    .await
                ),
                603,
                "tag 146 on Form 47 remains pending the application route selector"
            );
        }
        // Tag 146 resolves a non-decision entry against the immutable
        // document; the Form-47 control above covers the pending app selector.
        {
            let entry = output_entry;
            let output_keys = [
                f.pt2s,
                f.pt1s_index,
                f.routes,
                f.geometry,
                f.payloads,
                created[0],
            ];
            let output_key_refs = output_keys.iter().collect::<Vec<_>>();
            let output_binding = dcg_program::pt1_onchain::pt1x_output_binding(
                &f.program,
                &output_key_refs,
                29,
                entry,
                1,
            );
            let (output, _) =
                dcg_program::pt1_onchain::pt1x_output_address(&f.program, &output_binding);
            fund_system(&mut f.ctx, &f.executor, output, 1_000_000_000_000).await;
            let mut data = vec![S::TAG_INSTANTIATE];
            data.extend_from_slice(&29u32.to_le_bytes());
            data.extend_from_slice(&entry.to_le_bytes());
            data.extend_from_slice(&1u16.to_le_bytes());
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[],
                f.program,
                data,
                vec![
                    AccountMeta::new_readonly(f.pt2s, false),
                    AccountMeta::new_readonly(f.pt1s_index, false),
                    AccountMeta::new_readonly(f.routes, false),
                    AccountMeta::new_readonly(f.geometry, false),
                    AccountMeta::new_readonly(f.payloads, false),
                    AccountMeta::new(output, false),
                    AccountMeta::new_readonly(created[0], false),
                    AccountMeta::new_readonly(SYSTEM, false),
                    AccountMeta::new(f.executor.pubkey(), true),
                ],
            )
            .await
            .expect("tag 146 PT1X output instantiation");
            let stream = f.account(output).await;
            assert_eq!(&stream[..4], b"PT1O");
            assert_eq!(u32_at(&stream, 4), 29);
            assert_eq!(u32_at(&stream, 8), entry);
            assert!(u32_at(&stream, 12) > 0);
        }
        eprintln!(
            "f47 compiler-v1 UnifiedInit finalized K={k} options_bytes={} descriptor={}",
            options.len(),
            descriptor
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}

/// UnifiedInit commits option order verbatim, including unsorted and repeated
/// ids. This test covers initialization; the F47/F48 SBF dispute paths below
/// exercise tags 120 and 121 against those option tables.
#[tokio::test(flavor = "multi_thread")]
async fn f47_unified_init_accepts_unsorted_and_duplicate_options_sbf() {
    if std::env::var_os("BASANOS_DCG_V8_SBF").is_none() {
        eprintln!("SKIP: this regression is intended for the release-SBF image (set BASANOS_DCG_V8_SBF=1 and BPF_OUT_DIR)");
        return;
    }
    let Some(mut f) = build_f47().await else {
        return;
    };
    assert_eq!(f.output_width, 4);
    assert_eq!(f.base_entry, 28_040);

    for (variant, options) in [vec![5u32, 3], vec![17u32, 17]].into_iter().enumerate() {
        let k = options.len() as u8;
        let n = 30u32;
        let (mut binding, _) =
            decision_binding_at(&f.executor.pubkey().to_bytes(), n, k, f.base_entry);
        binding.request_id = [90 + variant as u8; 32];
        let table = options
            .iter()
            .flat_map(|token| token.to_le_bytes())
            .collect::<Vec<_>>();
        binding.option_table_sha256 = sha256(&[&table]);

        let (descriptor, created) = f.run_document_with_options(&binding, n, &table).await;
        let doc = f.account(created[0]).await;
        assert_eq!(
            &doc[OPTION_REGION_AT..],
            table.as_slice(),
            "UnifiedInit preserves options {options:?} in order"
        );
        let finalized = f.finalize(&descriptor, created, n).await;
        assert_eq!(
            u16_at(&finalized, 6),
            FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
            "SBF UnifiedInit finalizes options {options:?}"
        );
        eprintln!("release-SBF UnifiedInit preserved options={options:?}");
    }
    eprintln!(
        "PENDING 2b: the SBF dispute continuation cannot reach tag 120 in the current dispatcher"
    );
}

/// Build a duplicate-last closure tree path while retaining the exact node
/// ranges used by `challenge::dl_fold`.
fn f47_tree_path(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    leaves: &[[u8; 32]],
    target: usize,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    #[derive(Clone, Copy)]
    struct Node {
        hash: [u8; 32],
        first: u32,
        end: u32,
    }
    let mut nodes = leaves
        .iter()
        .enumerate()
        .map(|(i, hash)| Node {
            hash: *hash,
            first: i as u32,
            end: i as u32 + 1,
        })
        .collect::<Vec<_>>();
    let mut at = target;
    let mut path = Vec::new();
    let mut height = 0u8;
    while nodes.len() > 1 {
        let sibling = at ^ 1;
        path.push(nodes.get(sibling).unwrap_or(&nodes[at]).hash);
        let next_height = height + 1;
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(Node {
                hash: h::hash(
                    b"node/2",
                    &[
                        descriptor,
                        &[kind],
                        &scope.to_le_bytes(),
                        &left.first.to_le_bytes(),
                        &right.end.to_le_bytes(),
                        &[next_height, 1],
                        &left.hash,
                        &right.hash,
                    ],
                ),
                first: left.first,
                end: right.end,
            });
        }
        at /= 2;
        nodes = next;
        height = next_height;
    }
    (path, nodes[0].hash)
}

/// Canonical level-first boundary hashes for a set of leaves in a duplicate-last
/// closure tree. Selected coordinates are sorted and unique.
fn f48_sparse_siblings(
    descriptor: &[u8; 32],
    kind: u8,
    scope: u32,
    leaves: &[[u8; 32]],
    selected: &[usize],
) -> Vec<[u8; 32]> {
    use std::collections::BTreeSet;

    #[derive(Clone, Copy)]
    struct Node {
        digest: [u8; 32],
        first: u32,
        end: u32,
    }
    let mut nodes = leaves
        .iter()
        .enumerate()
        .map(|(index, digest)| Node {
            digest: *digest,
            first: index as u32,
            end: index as u32 + 1,
        })
        .collect::<Vec<_>>();
    let mut active = selected.iter().copied().collect::<BTreeSet<_>>();
    assert!(!active.is_empty());
    assert_eq!(active.len(), selected.len());
    assert!(active.iter().all(|index| *index < leaves.len()));
    let mut siblings = Vec::new();
    let mut height = 0u8;
    while nodes.len() > 1 {
        let active_now = active.iter().copied().collect::<Vec<_>>();
        for index in &active_now {
            if *index & 1 == 0 {
                if !active.contains(&(*index + 1)) && *index + 1 < nodes.len() {
                    siblings.push(nodes[*index + 1].digest);
                }
            } else if !active.contains(&(*index - 1)) {
                siblings.push(nodes[*index - 1].digest);
            }
        }
        let next_height = height + 1;
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(Node {
                digest: h::hash(
                    b"node/2",
                    &[
                        descriptor,
                        &[kind],
                        &scope.to_le_bytes(),
                        &left.first.to_le_bytes(),
                        &right.end.to_le_bytes(),
                        &[next_height, 1],
                        &left.digest,
                        &right.digest,
                    ],
                ),
                first: left.first,
                end: right.end,
            });
        }
        nodes = next;
        active = active.into_iter().map(|index| index / 2).collect();
        height = next_height;
    }
    assert_eq!(active.len(), 1);
    siblings
}

fn f47_dcl2_preimage(
    descriptor: &[u8; 32],
    coordinate: h::Coordinate,
    operation: u16,
    form: u16,
    read_count: u16,
    input_root: [u8; 32],
    writes: &[Vec<u8>],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(b"basanos/dcg-hclosure-leaf/2".len() + 120 + 48 * writes.len());
    out.extend_from_slice(b"basanos/dcg-hclosure-leaf/2");
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&coordinate.position.to_le_bytes());
    out.extend_from_slice(&coordinate.segment.to_le_bytes());
    out.extend_from_slice(&coordinate.entry.to_le_bytes());
    out.extend_from_slice(&operation.to_le_bytes());
    out.extend_from_slice(&form.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // MODE_COMMIT
    out.extend_from_slice(&read_count.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&input_root);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&(writes.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    for row in writes {
        out.extend_from_slice(row);
    }
    out
}

fn f47_read_row(
    route: pt::InstantiatedRoute,
    kind: u8,
    bytes_digest: [u8; 32],
    producer_ref: [u8; 32],
) -> [u8; 120] {
    let mut row = [0u8; 120];
    row[0..2].copy_from_slice(&route.region_id.to_le_bytes());
    row[2] = route.read_class;
    row[3] = kind;
    row[8..16].copy_from_slice(&route.effective_offset.to_le_bytes());
    row[16..20].copy_from_slice(&route.byte_length.to_le_bytes());
    row[24..56].copy_from_slice(&bytes_digest);
    row[56..88].copy_from_slice(&producer_ref);
    row
}

fn f47_write_row(route: pt::InstantiatedRoute, digest: [u8; 32]) -> Vec<u8> {
    let mut row = vec![0u8; 48];
    row[0..2].copy_from_slice(&route.region_id.to_le_bytes());
    row[4..8].copy_from_slice(&route.byte_length.to_le_bytes());
    row[8..16].copy_from_slice(&route.effective_offset.to_le_bytes());
    row[16..48].copy_from_slice(&digest);
    row
}

fn f47_put_u16(dst: &mut [u8], at: usize, value: u16) {
    dst[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn f47_put_u32(dst: &mut [u8], at: usize, value: u32) {
    dst[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn source_commit() -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git is needed to label the F48 measurement receipt");
    assert!(output.status.success(), "git rev-parse HEAD failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn f47_put_u64(dst: &mut [u8], at: usize, value: u64) {
    dst[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn f47_gather_before(x: &Pt2p<'_>, position: u32, decision_entry: u32) -> u32 {
    (0..decision_entry)
        .rev()
        .find(|index| {
            x.entry(position, *index)
                .is_ok_and(|entry| entry.kernel_index == decision::GATHER_FORM_ID)
        })
        .expect("compiler-v1 decision has a preceding form-48 gather")
}

/// Host-side fixture synthesis for the typed-decision dispute cases. This
/// exact integer reducer only creates test witnesses; revision-8 execution
/// remains in the SBF handlers and the feature-built image contains no model.
fn fixture_decision_record(logits: &[i64]) -> Vec<u8> {
    const LUT_LEN: usize = 8_192;
    const PROB_ONE: u64 = 1 << 16;
    const LUT: &[u8] = include_bytes!("fixtures/qwen35_exp_lut.bin");
    assert!(!logits.is_empty() && logits.len() <= u8::MAX as usize);

    let scores = logits
        .iter()
        .map(|value| {
            let quotient = value >> 4;
            let remainder = (*value as u64) & 0x0f;
            if remainder >= 8 {
                quotient.checked_add(1).expect("rounded score fits i64")
            } else {
                quotient
            }
        })
        .collect::<Vec<_>>();
    let largest = *scores.iter().max().unwrap();
    let mut exps = Vec::with_capacity(scores.len());
    let mut total = 0u64;
    for score in &scores {
        let delta = (largest as u64).wrapping_sub(*score as u64);
        let index = delta.min((LUT_LEN - 1) as u64) as usize;
        let at = index * 8;
        let exp = u64::from_le_bytes(LUT[at..at + 8].try_into().unwrap());
        total = total
            .checked_add(exp)
            .expect("bounded fixture option count");
        exps.push(exp);
    }
    assert_ne!(total, 0);
    let mut chosen = 0usize;
    for index in 1..logits.len() {
        if logits[index] > logits[chosen] {
            chosen = index;
        }
    }
    let mut record = Vec::with_capacity(4 + exps.len() * 4);
    record.extend_from_slice(&(chosen as u32).to_le_bytes());
    for exp in exps {
        let probability = exp
            .checked_mul(PROB_ONE)
            .and_then(|numerator| numerator.checked_add(total / 2))
            .expect("bounded fixture probability");
        record.extend_from_slice(&(probability / total).to_le_bytes());
    }
    record
}

/// The compiler-v1 form-47 dispute fixture uses a committed form-48 output as
/// its producer write, with a finalized path through the real PT2P segment
/// table. The proof is synthetic data; the compiler routes and PXR1 directory
/// are the captured compiler-v1 fixture.
/// What a real tag-166 open on the Form-47 target leaf carries.
struct F47TargetOpen {
    segment: u16,
    local: u32,
    path: Vec<[u8; 32]>,
    spp1: Vec<u8>,
}

fn f47_honest_body(
    x: &Pt2p<'_>,
    descriptor: &[u8; 32],
    position: u32,
    decision_entry: u32,
    table: &[u8],
    logits: &[i64],
    wrong_option_write_order: bool,
    wrong_duplicate_probability: bool,
    test_kernel_output: bool,
    position_root_at: &mut [u8; 32],
) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], Vec<u8>, F47TargetOpen) {
    let gather_index = f47_gather_before(x, position, decision_entry);
    let gather_entry = x.entry(position, gather_index).unwrap();
    let target_entry = x.entry(position, decision_entry).unwrap();
    let gather_at = x.coordinate(position, gather_index).unwrap();
    let target_at = x.coordinate(position, decision_entry).unwrap();
    assert_eq!(gather_entry.kernel_index, decision::GATHER_FORM_ID);
    assert_eq!(target_entry.kernel_index, decision::FORM_ID);
    assert_eq!(
        (target_entry.read_count, target_entry.write_count),
        (2, 256)
    );

    let mut gathered = vec![0u8; 128 * 8];
    for (i, value) in logits.iter().enumerate() {
        gathered[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    let gather_output_route = x.route(&gather_entry, gather_entry.read_count).unwrap();
    let gather_coordinate = h::Coordinate {
        position,
        segment: gather_at.segment,
        entry: gather_at.local,
    };
    let gather_digest = h::write_digest(
        descriptor,
        gather_coordinate,
        gather_output_route.region_id,
        gather_output_route.effective_offset,
        &gathered,
    )
    .unwrap();
    let gather_write = f47_write_row(gather_output_route, gather_digest);
    let gather_preimage = f47_dcl2_preimage(
        descriptor,
        gather_coordinate,
        gather_at.operation_ordinal,
        decision::GATHER_FORM_ID,
        128,
        [0; 32],
        &[gather_write],
    );
    let gather_leaf = sha256(&[&gather_preimage]);

    let table_hash = sha256(&[table]);
    let target_coordinate = h::Coordinate {
        position,
        segment: target_at.segment,
        entry: target_at.local,
    };
    let mut read_rows = vec![[0u8; 120]; target_entry.read_count as usize];
    for ordinal in 0..target_entry.read_count {
        let mut route = x.route(&target_entry, ordinal).unwrap();
        if route.region_id == u16::MAX {
            route.byte_length = table.len() as u32;
            let table_ref = sha256(&[
                b"basanos/dcg-dcm2-option-table-route/1",
                &route.region_id.to_le_bytes(),
                &(table.len() as u32).to_le_bytes(),
                &table_hash,
            ]);
            let table_digest = sha256(&[
                b"basanos/dcg-hclosure-read-bytes/2",
                descriptor,
                &target_coordinate.bytes(),
                &route.region_id.to_le_bytes(),
                &route.effective_offset.to_le_bytes(),
                &(table.len() as u32).to_le_bytes(),
                table,
            ]);
            read_rows[ordinal as usize] = f47_read_row(route, 0, table_digest, table_ref);
        } else {
            let gather_read_digest = h::write_digest(
                descriptor,
                gather_coordinate,
                route.region_id,
                route.effective_offset,
                &gathered,
            )
            .unwrap();
            read_rows[ordinal as usize] = f47_read_row(route, 1, gather_read_digest, gather_leaf);
        }
    }
    let flat_rows = read_rows
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect::<Vec<_>>();
    let input_root = sha256(&[
        b"basanos/dcg-hclosure-input/2",
        descriptor,
        &target_coordinate.bytes(),
        &decision::FORM_ID.to_le_bytes(),
        &2u16.to_le_bytes(),
        &flat_rows,
    ]);

    let mut claimed = if test_kernel_output {
        let mut kernel_output = [0u8; 256];
        dcg_program::kernel::Kernel::execute(
            &dcg_program::kernel::test_kernel::BYTE_SUM,
            &gathered[..64],
            &mut kernel_output,
        )
        .expect("test ByteSum produces its replay word");
        let mut output = vec![0u8; 256 * 4];
        for lane in output.chunks_exact_mut(4) {
            lane.copy_from_slice(&kernel_output[..4]);
        }
        output
    } else {
        let result = fixture_decision_record(logits);
        let mut output = vec![0u8; 256 * 4];
        output[..result.len()].copy_from_slice(&result);
        output
    };
    if wrong_option_write_order {
        assert!(logits.len() >= 2);
        let first_probability = claimed[4..8].to_vec();
        claimed.copy_within(8..12, 4);
        claimed[8..12].copy_from_slice(&first_probability);
    }
    if wrong_duplicate_probability {
        assert!(table.len() >= 8);
        let duplicate0 = u32::from_le_bytes(table[0..4].try_into().unwrap());
        let duplicate1 = u32::from_le_bytes(table[4..8].try_into().unwrap());
        assert_eq!(duplicate0, duplicate1);
        claimed[8] ^= 1;
    }
    let mut write_rows = Vec::with_capacity(256);
    let mut write_bytes = Vec::with_capacity(256);
    for lane in 0..256 {
        let route = x
            .route(&target_entry, target_entry.read_count + lane as u16)
            .unwrap();
        let bytes = &claimed[lane * 4..lane * 4 + 4];
        let digest = h::write_digest(
            descriptor,
            target_coordinate,
            route.region_id,
            route.effective_offset,
            bytes,
        )
        .unwrap();
        write_rows.push(f47_write_row(route, digest));
        write_bytes.push(bytes.to_vec());
    }
    let target_preimage = f47_dcl2_preimage(
        descriptor,
        target_coordinate,
        target_at.operation_ordinal,
        decision::FORM_ID,
        2,
        input_root,
        &write_rows,
    );
    let target_leaf = sha256(&[&target_preimage]);

    let (gather_segment_ordinal, gather_segment_count) = (0..x.segment_count as usize)
        .find_map(|ordinal| {
            let row = x.segment_row(position, ordinal).ok()?;
            (row.0 == gather_at.segment).then_some((ordinal, row.1))
        })
        .expect("gather segment exists");
    let mut segment_leaves = (0..gather_segment_count as usize)
        .map(|i| sha256(&[b"f47-producer-sibling", &i.to_le_bytes()]))
        .collect::<Vec<_>>();
    segment_leaves[gather_at.local as usize] = gather_leaf;
    // The executor commits both the producer (Form-48) leaf and the target
    // (Form-47) leaf, so a real tag-166 open can name the target.
    let same_segment = target_at.segment == gather_at.segment;
    if same_segment {
        segment_leaves[target_at.local as usize] = target_leaf;
    }
    let (producer_path, producer_segment_tree_root) = f47_tree_path(
        descriptor,
        1,
        position,
        &segment_leaves,
        gather_at.local as usize,
    );
    let producer_segment_root = h::hash(
        b"segment-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &gather_at.segment.to_le_bytes(),
            &(gather_segment_count as u32).to_le_bytes(),
            &producer_segment_tree_root,
            &[1],
        ],
    );

    let mut segment_roots = (0..x.segment_count as usize)
        .map(|i| sha256(&[b"f47-segment-sibling", &i.to_le_bytes()]))
        .collect::<Vec<_>>();
    segment_roots[gather_segment_ordinal] = producer_segment_root;
    let (target_segment_ordinal, target_segment_count) = (0..x.segment_count as usize)
        .find_map(|ordinal| {
            let row = x.segment_row(position, ordinal).ok()?;
            (row.0 == target_at.segment).then_some((ordinal, row.1))
        })
        .expect("target segment exists");
    let target_path = if same_segment {
        f47_tree_path(descriptor, 1, position, &segment_leaves, target_at.local as usize).0
    } else {
        let mut leaves = (0..target_segment_count as usize)
            .map(|i| sha256(&[b"f47-target-sibling", &i.to_le_bytes()]))
            .collect::<Vec<_>>();
        leaves[target_at.local as usize] = target_leaf;
        let (path, tree) = f47_tree_path(descriptor, 1, position, &leaves, target_at.local as usize);
        segment_roots[target_segment_ordinal] = h::hash(
            b"segment-root/2",
            &[
                descriptor,
                &position.to_le_bytes(),
                &target_at.segment.to_le_bytes(),
                &(target_segment_count as u32).to_le_bytes(),
                &tree,
                &[1],
            ],
        );
        path
    };
    let (spp_path, _) = f47_tree_path(
        descriptor,
        2,
        position,
        &segment_roots,
        gather_segment_ordinal,
    );
    let table_root = x.segment_table_root(position).unwrap();
    let root = challenge::spp1_position_root(
        descriptor,
        position,
        x.segment_count,
        &producer_segment_root,
        gather_segment_ordinal as u16,
        &table_root,
        &spp_path,
        &table_root,
    )
    .unwrap()
    .unwrap();
    *position_root_at = root;
    let mut spp1 = Vec::with_capacity(36 + 32 * spp_path.len());
    spp1.extend_from_slice(&(gather_segment_ordinal as u16).to_le_bytes());
    spp1.push(spp_path.len() as u8);
    spp1.push(0);
    spp1.extend_from_slice(&table_root);
    for sibling in &spp_path {
        spp1.extend_from_slice(sibling);
    }

    let (target_spp_path, _) = f47_tree_path(
        descriptor,
        2,
        position,
        &segment_roots,
        target_segment_ordinal,
    );
    let mut target_spp1 = Vec::with_capacity(36 + 32 * target_spp_path.len());
    target_spp1.extend_from_slice(&(target_segment_ordinal as u16).to_le_bytes());
    target_spp1.push(target_spp_path.len() as u8);
    target_spp1.push(0);
    target_spp1.extend_from_slice(&table_root);
    for sibling in &target_spp_path {
        target_spp1.extend_from_slice(sibling);
    }
    let target_open = F47TargetOpen {
        segment: target_at.segment,
        local: target_at.local,
        path: target_path,
        spp1: target_spp1,
    };

    let mut producer_proof = Vec::new();
    producer_proof.extend_from_slice(&(gather_preimage.len() as u16).to_le_bytes());
    producer_proof.extend_from_slice(&gather_preimage);
    producer_proof.push(producer_path.len() as u8);
    for sibling in &producer_path {
        producer_proof.extend_from_slice(sibling);
    }
    producer_proof.extend_from_slice(&spp1);
    let mut read_sections = vec![Vec::new(); target_entry.read_count as usize];
    for ordinal in 0..target_entry.read_count {
        let route = x.route(&target_entry, ordinal).unwrap();
        let section = &mut read_sections[ordinal as usize];
        if route.region_id == u16::MAX {
            section.extend_from_slice(&(table.len() as u32).to_le_bytes());
            section.extend_from_slice(table);
            section.push(0);
        } else {
            section.extend_from_slice(&(gathered.len() as u32).to_le_bytes());
            section.extend_from_slice(&gathered);
            section.push(1);
            section.extend_from_slice(&producer_proof);
        }
    }
    let head = 28 + 4 * 2;
    let target_at_body = head;
    let rows_at = target_at_body + target_preimage.len();
    let mut cursor = rows_at + flat_rows.len();
    let section_offsets = read_sections
        .iter()
        .map(|section| {
            let at = cursor;
            cursor += section.len();
            at
        })
        .collect::<Vec<_>>();
    let mut body = vec![0u8; cursor];
    body[..4].copy_from_slice(b"DGR1");
    f47_put_u16(&mut body, 4, 1);
    f47_put_u16(&mut body, 6, 2);
    f47_put_u32(&mut body, 8, target_preimage.len() as u32);
    for (i, offset) in section_offsets.iter().enumerate() {
        f47_put_u32(&mut body, 28 + 4 * i, *offset as u32);
    }
    body[target_at_body..rows_at].copy_from_slice(&target_preimage);
    body[rows_at..rows_at + flat_rows.len()].copy_from_slice(&flat_rows);
    for (offset, section) in section_offsets.iter().zip(&read_sections) {
        body[*offset..*offset + section.len()].copy_from_slice(section);
    }
    (body, gather_preimage, target_leaf, root, claimed, target_open)
}

/// Give the retained Form-47 fixture a tiny app-owned descriptor and row
/// witness so tags 122/123 can exercise the test application before tag 124.
fn f47_test_hook_body(body: &[u8]) -> Vec<u8> {
    let read_count = usize::from(u16::from_le_bytes(body[6..8].try_into().unwrap()));
    assert_eq!(u16::from_le_bytes(body[4..6].try_into().unwrap()), 1);
    let old_head = 28 + 4 * read_count;
    let new_head = 36 + 4 * read_count;
    let core = b"DCGTEST-DESCRIPTOR/1";
    let weights = b"DCGTEST-ROWS/1";
    let copied = body.len() - old_head;
    let core_at = new_head + copied;
    let weights_at = core_at + core.len();
    let mut out = vec![0u8; body.len() + 8 + core.len() + weights.len()];
    out[..4].copy_from_slice(b"DGR1");
    f47_put_u16(&mut out, 4, 2);
    f47_put_u16(&mut out, 6, read_count as u16);
    out[8..12].copy_from_slice(&body[8..12]);
    for read in 0..read_count {
        let old_at = 28 + 4 * read;
        let offset = u32::from_le_bytes(body[old_at..old_at + 4].try_into().unwrap()) + 8;
        f47_put_u32(&mut out, 36 + 4 * read, offset);
    }
    out[new_head..new_head + copied].copy_from_slice(&body[old_head..]);
    f47_put_u32(&mut out, 12, core_at as u32);
    f47_put_u32(&mut out, 16, core.len() as u32);
    f47_put_u32(&mut out, 20, weights_at as u32);
    f47_put_u32(&mut out, 24, weights.len() as u32);
    out[core_at..weights_at].copy_from_slice(core);
    out[weights_at..].copy_from_slice(weights);
    out
}

/// A full form-48 responder body with one shared producer multiproof. The route
/// table and PXR1 directory are the captured compiler-v1 artifact; producer
/// bytes and unrelated Merkle leaves are deterministic synthetic values. The
/// caller can deliberately corrupt the gather write digest to exercise tag 124.
fn f48_honest_body(
    x: &Pt2p<'_>,
    routes: &[u8],
    descriptor: &[u8; 32],
    position: u32,
    gather_index: u32,
    table: &[u8],
    wrong_gather_write_digest: bool,
    position_root_at: &mut [u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    use std::collections::BTreeMap;

    let gather = x.entry(position, gather_index).unwrap();
    let gather_at = x.coordinate(position, gather_index).unwrap();
    assert_eq!(gather.kernel_index, decision::GATHER_FORM_ID);
    let option_count = table.len() / 4;
    assert!((1..=80).contains(&option_count));
    let (_, _, pxr) = pt::route_header_v4_shallow(routes).unwrap();
    let pxr = pxr.unwrap();

    let mut selected = Vec::with_capacity(option_count);
    let mut producer_coordinates = BTreeMap::<(u16, u32), (u32, Vec<u8>)>::new();
    for ordinal in 0..option_count {
        let token = u32::from_le_bytes(table[ordinal * 4..ordinal * 4 + 4].try_into().unwrap());
        let (pxr_row, _) = pxr.find(token).unwrap();
        let producer_index = x
            .old_to_new(pxr_row.producer_entry, position)
            .unwrap()
            .unwrap();
        assert!(producer_index < gather_index);
        let producer = x.entry(position, producer_index).unwrap();
        let declared = x
            .route(
                &producer,
                producer.read_count + pxr_row.producer_write_ordinal,
            )
            .unwrap();
        assert_eq!(
            (
                declared.direction,
                declared.region_id,
                declared.effective_offset,
                declared.byte_length,
                declared.producer_write_ordinal
            ),
            (
                1,
                pxr.region_id,
                pxr_row.region_offset,
                pxr_row.byte_length,
                pxr_row.producer_write_ordinal as u8
            )
        );
        let placeholder = x.route(&gather, ordinal as u16).unwrap();
        let route = pt::InstantiatedRoute {
            direction: 0,
            ordinal: ordinal as u16,
            region_id: pxr.region_id,
            effective_offset: declared.effective_offset,
            byte_length: declared.byte_length,
            read_class: 0,
            binding_kind: 1,
            source_supplied: false,
            initial_content: false,
            producer_position: position,
            producer_entry: producer_index,
            producer_write_ordinal: pxr_row.producer_write_ordinal as u8,
            range_first: 0,
            range_end: 0,
            family_ordinal: 0,
            template_offset: placeholder.template_offset,
        };
        let witness = vec![0u8; route.byte_length as usize];
        producer_coordinates
            .entry((
                x.coordinate(position, producer_index).unwrap().segment,
                x.coordinate(position, producer_index).unwrap().local,
            ))
            .or_insert((producer_index, witness.clone()));
        selected.push((route, witness, producer_index));
    }
    if option_count == 80 {
        assert_eq!(
            producer_coordinates.len(),
            option_count,
            "the K=80 CU case must cover 80 distinct PXR1 producer rows"
        );
    }

    let mut preimages = BTreeMap::<(u16, u32), Vec<u8>>::new();
    for ((segment, local), (producer_index, _)) in &producer_coordinates {
        let producer = x.entry(position, *producer_index).unwrap();
        let coordinate = h::Coordinate {
            position,
            segment: *segment,
            entry: *local,
        };
        let mut writes = Vec::with_capacity(producer.write_count as usize);
        for write_ordinal in 0..producer.write_count {
            let route = x
                .route(&producer, producer.read_count + write_ordinal)
                .unwrap();
            let bytes = vec![0u8; route.byte_length as usize];
            let digest = h::write_digest(
                descriptor,
                coordinate,
                route.region_id,
                route.effective_offset,
                &bytes,
            )
            .unwrap();
            writes.push(f47_write_row(route, digest));
        }
        let preimage = f47_dcl2_preimage(
            descriptor,
            coordinate,
            x.coordinate(position, *producer_index)
                .unwrap()
                .operation_ordinal,
            producer.kernel_index,
            producer.read_count,
            [0; 32],
            &writes,
        );
        preimages.insert((*segment, *local), preimage);
    }

    let gather_coordinate = h::Coordinate {
        position,
        segment: gather_at.segment,
        entry: gather_at.local,
    };
    let mut read_rows = Vec::with_capacity(option_count);
    let mut read_sections = Vec::with_capacity(option_count);
    for (route, witness, producer_index) in &selected {
        let producer_coordinate = x.coordinate(position, *producer_index).unwrap();
        let producer_preimage =
            &preimages[&(producer_coordinate.segment, producer_coordinate.local)];
        let producer_leaf = sha256(&[producer_preimage]);
        let digest = h::write_digest(
            descriptor,
            h::Coordinate {
                position,
                segment: producer_coordinate.segment,
                entry: producer_coordinate.local,
            },
            route.region_id,
            route.effective_offset,
            witness,
        )
        .unwrap();
        read_rows.push(f47_read_row(*route, 1, digest, producer_leaf));
    }
    let flat_rows = read_rows
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect::<Vec<_>>();
    let input_root = sha256(&[
        b"basanos/dcg-hclosure-input/2",
        descriptor,
        &gather_coordinate.bytes(),
        &decision::GATHER_FORM_ID.to_le_bytes(),
        &(option_count as u16).to_le_bytes(),
        &flat_rows,
    ]);
    let mut output = vec![0u8; 128 * 8];
    for (i, value) in output.chunks_exact_mut(8).enumerate() {
        value.copy_from_slice(&(i as i64).to_le_bytes());
    }
    let output_route = x.route(&gather, gather.read_count).unwrap();
    let mut output_digest = h::write_digest(
        descriptor,
        gather_coordinate,
        output_route.region_id,
        output_route.effective_offset,
        &output,
    )
    .unwrap();
    if wrong_gather_write_digest {
        output_digest[0] ^= 1;
    }
    let target_preimage = f47_dcl2_preimage(
        descriptor,
        gather_coordinate,
        gather_at.operation_ordinal,
        decision::GATHER_FORM_ID,
        option_count as u16,
        input_root,
        &[f47_write_row(output_route, output_digest)],
    );
    let target_leaf = sha256(&[&target_preimage]);

    let mut segment_leaves = BTreeMap::<u16, Vec<[u8; 32]>>::new();
    let mut segment_ordinals = BTreeMap::<u16, usize>::new();
    for ordinal in 0..x.segment_count as usize {
        let (segment, count) = x.segment_row(position, ordinal).unwrap();
        segment_ordinals.insert(segment, ordinal);
        segment_leaves.insert(
            segment,
            (0..count as usize)
                .map(|local| {
                    sha256(&[
                        b"f48-producer-sibling",
                        &segment.to_le_bytes(),
                        &(local as u32).to_le_bytes(),
                    ])
                })
                .collect(),
        );
    }
    for ((segment, local), preimage) in &preimages {
        segment_leaves.get_mut(segment).unwrap()[*local as usize] = sha256(&[preimage]);
    }
    segment_leaves.get_mut(&gather_at.segment).unwrap()[gather_at.local as usize] = target_leaf;
    let mut segment_roots = Vec::with_capacity(x.segment_count as usize);
    let mut segment_roots_by_id = BTreeMap::new();
    for ordinal in 0..x.segment_count as usize {
        let (segment, count) = x.segment_row(position, ordinal).unwrap();
        let leaves = &segment_leaves[&segment];
        let (_, tree) = f47_tree_path(descriptor, 1, position, leaves, 0);
        let root = h::hash(
            b"segment-root/2",
            &[
                descriptor,
                &position.to_le_bytes(),
                &segment.to_le_bytes(),
                &count.to_le_bytes(),
                &tree,
                &[1],
            ],
        );
        segment_roots.push(root);
        segment_roots_by_id.insert(segment, root);
    }
    let mut outer_roots = segment_roots;
    outer_roots[segment_ordinals[&gather_at.segment]] = segment_roots_by_id[&gather_at.segment];
    for (segment, _) in producer_coordinates.keys().copied() {
        let ordinal = segment_ordinals[&segment];
        outer_roots[ordinal] = segment_roots_by_id[&segment];
    }
    let table_root = x.segment_table_root(position).unwrap();
    let first_producer_segment = producer_coordinates.keys().next().unwrap().0;
    let (_, outer_tree) = f47_tree_path(
        descriptor,
        2,
        position,
        &outer_roots,
        segment_ordinals[&first_producer_segment],
    );
    *position_root_at = h::hash(
        b"position-root/2",
        &[
            descriptor,
            &position.to_le_bytes(),
            &x.segment_count.to_le_bytes(),
            &table_root,
            &outer_tree,
            &[1],
        ],
    );

    let mut unique_coordinates = producer_coordinates.keys().copied().collect::<Vec<_>>();
    unique_coordinates.sort_by_key(|(segment, local)| (segment_ordinals[segment], *local));
    let unique_index = unique_coordinates
        .iter()
        .enumerate()
        .map(|(index, coordinate)| (*coordinate, index as u16))
        .collect::<BTreeMap<_, _>>();
    let mut batch = vec![0u8; 12];
    batch[..4].copy_from_slice(b"F48M");
    f47_put_u16(&mut batch, 4, 1);
    f47_put_u16(&mut batch, 6, option_count as u16);
    let mut group_count = 0usize;
    let mut group_start = 0usize;
    while group_start < unique_coordinates.len() {
        let segment = unique_coordinates[group_start].0;
        let mut group_end = group_start + 1;
        while group_end < unique_coordinates.len() && unique_coordinates[group_end].0 == segment {
            group_end += 1;
        }
        group_count += 1;
        group_start = group_end;
    }
    f47_put_u16(&mut batch, 8, group_count as u16);
    f47_put_u16(&mut batch, 10, unique_coordinates.len() as u16);
    for (_, _, producer_index) in &selected {
        let coordinate = x.coordinate(position, *producer_index).unwrap();
        let mapped = unique_index[&(coordinate.segment, coordinate.local)];
        batch.extend_from_slice(&mapped.to_le_bytes());
    }
    let mut group_start = 0usize;
    let mut group_ordinals = Vec::with_capacity(group_count);
    while group_start < unique_coordinates.len() {
        let segment = unique_coordinates[group_start].0;
        let ordinal = segment_ordinals[&segment];
        let mut group_end = group_start + 1;
        while group_end < unique_coordinates.len() && unique_coordinates[group_end].0 == segment {
            group_end += 1;
        }
        group_ordinals.push(ordinal);
        batch.extend_from_slice(&(ordinal as u16).to_le_bytes());
        batch.extend_from_slice(&segment.to_le_bytes());
        batch.extend_from_slice(&((group_end - group_start) as u16).to_le_bytes());
        let mut selected_entries = Vec::with_capacity(group_end - group_start);
        for (leaf_segment, local) in &unique_coordinates[group_start..group_end] {
            let preimage = &preimages[&(*leaf_segment, *local)];
            batch.extend_from_slice(&position.to_le_bytes());
            batch.extend_from_slice(&leaf_segment.to_le_bytes());
            batch.extend_from_slice(&local.to_le_bytes());
            batch.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
            batch.extend_from_slice(preimage);
            selected_entries.push(*local as usize);
        }
        let siblings = f48_sparse_siblings(
            descriptor,
            1,
            position,
            &segment_leaves[&segment],
            &selected_entries,
        );
        batch.extend_from_slice(&(siblings.len() as u16).to_le_bytes());
        for sibling in &siblings {
            batch.extend_from_slice(sibling);
        }
        group_start = group_end;
    }
    let outer_siblings =
        f48_sparse_siblings(descriptor, 2, position, &outer_roots, &group_ordinals);
    batch.extend_from_slice(&(outer_siblings.len() as u16).to_le_bytes());
    for sibling in &outer_siblings {
        batch.extend_from_slice(sibling);
    }
    for (ordinal, (_, witness, _)) in selected.iter().enumerate() {
        let proof = if ordinal == 0 { batch.as_slice() } else { &[] };
        let mut section = Vec::with_capacity(5 + witness.len() + proof.len());
        section.extend_from_slice(&(witness.len() as u32).to_le_bytes());
        section.extend_from_slice(witness);
        section.push(1);
        section.extend_from_slice(proof);
        read_sections.push(section);
    }

    let head = 28 + 4 * option_count;
    let target_at = head;
    let rows_at = target_at + target_preimage.len();
    let mut cursor = rows_at + flat_rows.len();
    let section_offsets = read_sections
        .iter()
        .map(|section| {
            let at = cursor;
            cursor += section.len();
            at
        })
        .collect::<Vec<_>>();
    let mut body = vec![0u8; cursor];
    body[..4].copy_from_slice(b"DGR1");
    f47_put_u16(&mut body, 4, 1);
    f47_put_u16(&mut body, 6, option_count as u16);
    f47_put_u32(&mut body, 8, target_preimage.len() as u32);
    for (i, offset) in section_offsets.iter().enumerate() {
        f47_put_u32(&mut body, 28 + 4 * i, *offset as u32);
    }
    body[target_at..rows_at].copy_from_slice(&target_preimage);
    body[rows_at..rows_at + flat_rows.len()].copy_from_slice(&flat_rows);
    for (offset, section) in section_offsets.iter().zip(&read_sections) {
        body[*offset..*offset + section.len()].copy_from_slice(section);
    }
    (body, target_leaf)
}

async fn f47_measured_send(f: &mut Fix, data: Vec<u8>, metas: Vec<AccountMeta>, case: &str) -> u64 {
    let blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            f47_compute_limit(),
        ),
        solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
        Instruction {
            program_id: f.program,
            accounts: metas,
            data,
        },
    ];
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&f.executor.pubkey()),
        &[&f.executor],
        blockhash,
    );
    let result = f
        .ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    if let Err(error) = result.result {
        let consumed = result
            .metadata
            .as_ref()
            .map_or(0, |metadata| metadata.compute_units_consumed);
        let logs = result
            .metadata
            .as_ref()
            .map_or_else(String::new, |metadata| metadata.log_messages.join("\n"));
        panic!(
            "{case} failed at compute limit {} after {consumed} transaction CU: {error:?}\n{logs}",
            f47_compute_limit(),
        );
    }
    result.metadata.unwrap().compute_units_consumed
}

async fn f47_measured_refusal(
    f: &mut Fix,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    case: &str,
) -> u64 {
    let blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            f47_compute_limit(),
        ),
        solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
        Instruction {
            program_id: f.program,
            accounts: metas,
            data,
        },
    ];
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&f.executor.pubkey()),
        &[&f.executor],
        blockhash,
    );
    let result = f
        .ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    assert_eq!(
        result.result,
        Err(TransactionError::InstructionError(
            2,
            InstructionError::Custom(740)
        )),
        "{case} is refused by the test application's replay hook"
    );
    result
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.compute_units_consumed)
}

async fn f47_measured_custom_refusal(
    f: &mut Fix,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    code: u32,
    case: &str,
) -> u64 {
    let blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            f47_compute_limit(),
        ),
        solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
        Instruction {
            program_id: f.program,
            accounts: metas,
            data,
        },
    ];
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&f.executor.pubkey()),
        &[&f.executor],
        blockhash,
    );
    let result = f
        .ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    assert_eq!(
        result.result,
        Err(TransactionError::InstructionError(
            2,
            InstructionError::Custom(code)
        )),
        "{case} refuses with custom {code}"
    );
    result
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.compute_units_consumed)
}

/// Full compiler-v1 form-47 dispute response, including the producer write
/// preimage, DGR1 sections, and finalized segment/position proof paths.
/// A real tag-166 open by the challenger on the committed Form-47 target
/// leaf, then the executor's real response upload (115-118) of `body`.
/// Returns the DCR1 record and its DRU1 response.
async fn f47_open_and_respond(
    f: &mut Fix,
    created: [Pubkey; 4],
    descriptor: &[u8; 32],
    position: u32,
    target_leaf: [u8; 32],
    open: &F47TargetOpen,
    nonce: u32,
    body: &[u8],
) -> (Pubkey, Pubkey) {
    let mut packet = vec![TAG_CHALLENGE_LEAF];
    packet.extend_from_slice(descriptor);
    packet.extend_from_slice(&position.to_le_bytes());
    packet.extend_from_slice(&open.segment.to_le_bytes());
    packet.extend_from_slice(&open.local.to_le_bytes());
    packet.extend_from_slice(&target_leaf);
    packet.push(open.path.len() as u8);
    for sibling in &open.path {
        packet.extend_from_slice(sibling);
    }
    packet.extend_from_slice(&open.spp1);
    packet.extend_from_slice(&nonce.to_le_bytes());
    let record = address::challenge(&f.program, descriptor, &f.signer.pubkey(), nonce).0;
    let metas = challenge_leaf_metas(f, created, record);
    send_fresh_with(&mut f.ctx, &f.signer, f.program, packet, metas)
        .await
        .expect("the challenger opens the Form-47 leaf (166)");
    let opened = f.account(record).await;
    assert_eq!(opened[4], challenge::PHASE_RESPOND, "the honest option table is admitted at fix-point");

    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let executor = f.executor.insecure_clone();
    let begin_metas = vec![
        AccountMeta::new(response, false),
        AccountMeta::new(executor.pubkey(), true),
        AccountMeta::new_readonly(record, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ];
    let metas = vec![
        AccountMeta::new(response, false),
        AccountMeta::new(executor.pubkey(), true),
        AccountMeta::new_readonly(record, false),
    ];
    let mut begin = vec![dcg_program::closure_v2_response::TAG_BEGIN];
    begin.extend_from_slice(&(body.len() as u32).to_le_bytes());
    begin.extend_from_slice(&sha256(&[body]));
    send_fresh_with(&mut f.ctx, &executor, f.program, begin, begin_metas).await.expect("response begin (115)");
    while f.account(response).await.len() < dcg_program::closure_v2_response::HEADER + body.len() {
        send_fresh_with(&mut f.ctx, &executor, f.program, vec![dcg_program::closure_v2_response::TAG_GROW], metas.clone())
            .await
            .expect("response grow (116)");
    }
    for (i, chunk) in body.chunks(900).enumerate() {
        let mut write = vec![dcg_program::closure_v2_response::TAG_WRITE];
        write.extend_from_slice(&((i * 900) as u32).to_le_bytes());
        write.extend_from_slice(chunk);
        send_fresh_with(&mut f.ctx, &executor, f.program, write, metas.clone()).await.expect("response write (117)");
    }
    send_fresh_with(&mut f.ctx, &executor, f.program, vec![dcg_program::closure_v2_response::TAG_SEAL], metas)
        .await
        .expect("response seal (118)");
    (record, response)
}

async fn run_f47_dispute_at_owner_boundaries(role_swapped: bool) {
    let maybe = if role_swapped {
        build_f47_with_swapped_roles().await
    } else {
        build_f47().await
    };
    let Some(mut f) = maybe else { return };
    let receipt_dir = std::env::var_os("BASANOS_DCG_F47_RECEIPT").map(PathBuf::from);
    if let Some(dir) = &receipt_dir {
        std::fs::create_dir_all(dir).unwrap();
    }
    let (routes, geometry, payloads, pwr1, _) = f47_artifacts().unwrap();
    let program = pt2p::Program::decode(&pwr1).unwrap();
    let x = Pt2p::new(&routes, &geometry, &payloads, None, program).unwrap();
    let family_plan = document::parse_family_body(&f.family_body).unwrap();
    assert_eq!(
        document::check_family_plan(&x, &family_plan),
        Ok(()),
        "compiler-v1 artifact and retained DFS2 family plan agree"
    );
    let position = f47_position();
    assert!(
        position < f.k,
        "the decision position fits the compiler-v1 template"
    );
    let decision_entry = x.entry_count(position).unwrap() - 1;
    let base_decision_entry = x.base_entries - 1;
    assert_eq!(
        x.old_to_new(base_decision_entry, position).unwrap(),
        Some(decision_entry)
    );
    let mut receipt = Vec::new();
    let cases = [
        (1u8, false, false, false),
        (2, false, false, false),
        (47, false, false, false),
        (48, false, false, false),
        (64, false, false, false),
        (80, false, false, false),
        (2, false, true, false), // probability values committed to the wrong option lanes
        (2, true, false, true),  // duplicate ids must have equal probabilities
    ];
    for (variant, (k, duplicate, wrong_mapping, wrong_duplicate_probability)) in cases
        .into_iter()
        .enumerate()
        .filter(|(_, (k, _, _, _))| f47_measure_k_filter().is_none_or(|only| *k == only))
    {
        let (mut binding, _) = decision_binding_at(
            &f.executor.pubkey().to_bytes(),
            position + 1,
            k,
            base_decision_entry,
        );
        binding.request_id = [120 + variant as u8; 32];
        let options = if duplicate {
            vec![0u32, 0]
        } else {
            (0..k as u32).collect()
        };
        let table = options
            .iter()
            .flat_map(|token| token.to_le_bytes())
            .collect::<Vec<_>>();
        binding.option_table_sha256 = sha256(&[&table]);
        let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
        let logits = if duplicate {
            vec![4096, 4096]
        } else {
            (0..k as usize)
                .map(|i| ((k as i64) - i as i64) * 4096)
                .collect::<Vec<_>>()
        };
        let mut position_root = [0u8; 32];
        let (legacy_body, producer_preimage, target_leaf, root, _claimed, target_open) = f47_honest_body(
            &x,
            &descriptor,
            position,
            decision_entry,
            &table,
            &logits,
            wrong_mapping,
            wrong_duplicate_probability,
            !wrong_mapping && !wrong_duplicate_probability,
            &mut position_root,
        );
        let body = f47_test_hook_body(&legacy_body);
        assert_eq!(root, position_root);
        let roots = f47_document_roots(&f, position, position_root);
        let (descriptor, created) = f
            .run_document_with_roots_and_options(&binding, &roots, &table)
            .await;
        assert_eq!(descriptor, f.descriptor(&binding, &f.terms_raw, 16));
        f.finalize(&descriptor, created, position + 1).await;
        let finalized_doc = f.account(created[0]).await;
        assert_eq!(&finalized_doc[200..232], f.pt2s.as_ref());
        assert_eq!(&finalized_doc[232..264], &f.pt2s_sha);
        assert_option_tail(&mut f, &finalized_doc, &table).await;
        assert_eq!(
            &finalized_doc[BINDING_AT_V8 + 164..BINDING_AT_V8 + 196],
            &sha256(&[&table])
        );
        let pt1s_data = f.account(f.pt1s_index).await;
        assert!(dcg_program::pt1_onchain::is_sealed_template(&pt1s_data));
        let bound_view = dcg_program::unified::plan::view(
            &f.pt2s_image,
            &routes,
            &geometry,
            &payloads,
            Some(&pt1s_data[dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX..]),
        )
        .unwrap();
        assert_eq!(
            bound_view
                .entry(position, decision_entry)
                .unwrap()
                .read_count,
            2
        );

        // Real instructions only: the challenger opens the target leaf
        // (166) twice, and the executor answers one with the honest body and
        // the other with a body whose target leaf has one flipped byte.
        let challenger = f.signer.pubkey();
        let nonce = 0x4700_0000 + variant as u32;
        let (challenge_key, response_key) = f47_open_and_respond(
            &mut f, created, &descriptor, position, target_leaf, &target_open, nonce, &body,
        )
        .await;
        let (pt2s, pt1s_index, routes, geometry, payloads) =
            (f.pt2s, f.pt1s_index, f.routes, f.geometry, f.payloads);
        let cheat_nonce = nonce.wrapping_add(0x0100_0000);
        let mut cheated_body = body.clone();
        let read_count = u16::from_le_bytes(cheated_body[6..8].try_into().unwrap()) as usize;
        let target_at = 36 + 4 * read_count;
        assert!(target_at + LEAF_DOMAIN.len() < cheated_body.len());
        cheated_body[target_at + LEAF_DOMAIN.len()] ^= 1;
        let (cheat_challenge, cheat_response) = f47_open_and_respond(
            &mut f, created, &descriptor, position, target_leaf, &target_open, cheat_nonce, &cheated_body,
        )
        .await;
        let tag120_cheat_cu = f47_measured_custom_refusal(
            &mut f,
            vec![120],
            vec![
                AccountMeta::new(cheat_challenge, false),
                AccountMeta::new_readonly(cheat_response, false),
                AccountMeta::new_readonly(created[0], false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(pt1s_index, false),
                AccountMeta::new_readonly(routes, false),
                AccountMeta::new_readonly(geometry, false),
                AccountMeta::new_readonly(payloads, false),
            ],
            734,
            &format!("Form 47 K={k} role_swapped={role_swapped} tag120 forged target"),
        )
        .await;
        eprintln!("DCG_GENERIC_SBF_CU|120|forged-target|{tag120_cheat_cu}");
        let verify_target = f47_measured_send(
            &mut f,
            vec![120],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new_readonly(created[0], false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(pt1s_index, false),
                AccountMeta::new_readonly(routes, false),
                AccountMeta::new_readonly(geometry, false),
                AccountMeta::new_readonly(payloads, false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag120"),
        )
        .await;
        let verify_reads = f47_measured_send(
            &mut f,
            vec![121, 0, 0, 2, 0],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new_readonly(created[0], false),
                AccountMeta::new_readonly(created[1], false),
                AccountMeta::new_readonly(routes, false),
                AccountMeta::new_readonly(geometry, false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(created[2], false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag121"),
        )
        .await;
        let verify_anchor = f47_measured_send(
            &mut f,
            vec![122],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new_readonly(created[0], false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag122"),
        )
        .await;
        let verify_rows = f47_measured_send(
            &mut f,
            vec![123],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag123"),
        )
        .await;
        let execute = f47_measured_send(
            &mut f,
            vec![124],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new(created[0], false),
                AccountMeta::new_readonly(routes, false),
                AccountMeta::new_readonly(geometry, false),
                AccountMeta::new_readonly(pt2s, false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag124"),
        )
        .await;
        let expected_winner = if wrong_mapping || wrong_duplicate_probability {
            2
        } else {
            1
        };
        let ruled = f
            .ctx
            .banks_client
            .get_account(challenge_key)
            .await
            .unwrap()
            .expect("tag 124 preserves the DCR1 challenge for settlement")
            .data;
        assert_eq!(ruled[4], challenge::PHASE_RULED);
        assert_eq!(ruled[5], expected_winner, "tag 124's test-kernel ruling");
        let final_doc = f
            .ctx
            .banks_client
            .get_account(created[0])
            .await
            .unwrap()
            .expect("tag 124 preserves the DCM2 document for settlement")
            .data;
        assert_eq!(
            u16_at(&final_doc, 6) & FLAG_REFUTED,
            if expected_winner == 2 {
                FLAG_REFUTED
            } else {
                0
            }
        );
        let (bond_escrow, _) = address::bond_escrow(&f.program, &descriptor);
        fund_system(&mut f.ctx, &f.executor, bond_escrow, 1_000_000_000_000).await;
        let executor = f.executor.pubkey();
        let settlement_winner = if expected_winner == 2 {
            challenger
        } else {
            executor
        };
        let settle = f47_measured_send(
            &mut f,
            vec![dcg_program::root_only_challenge::TAG_SETTLE],
            vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new(response_key, false),
                AccountMeta::new(settlement_winner, false),
                AccountMeta::new(executor, false),
                AccountMeta::new(created[0], false),
                AccountMeta::new(incinerator::ID, false),
                AccountMeta::new(challenger, false),
                AccountMeta::new(bond_escrow, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            &format!("Form 47 K={k} role_swapped={role_swapped} tag131 settle"),
        )
        .await;
        assert!(
            f.ctx
                .banks_client
                .get_account(challenge_key)
                .await
                .unwrap()
                .is_none(),
            "tag 131 drains the settled DCR1 account"
        );
        let settled_doc = f.account(created[0]).await;
        // Tag 131 drops the settled challenge from DCM2's open count; the
        // forged-target challenge, whose response tag 120 refused, is still
        // open at RESPOND.
        assert_eq!(u32_at(&settled_doc, 128), 1, "tag 131 drops the settled challenge from the open count");
        assert_eq!(f.account(cheat_challenge).await[4], challenge::PHASE_RESPOND);
        eprintln!("DCG_GENERIC_SBF_CU|122|f47-test-hook|{verify_anchor}");
        eprintln!("DCG_GENERIC_SBF_CU|123|f47-test-hook|{verify_rows}");
        eprintln!(
            "DCG_GENERIC_SBF_CU|124|f47-test-hook-{}|{execute}",
            if expected_winner == 2 {
                "cheat"
            } else {
                "honest"
            }
        );
        eprintln!("DCG_GENERIC_SBF_CU|131|f47-settle|{settle}");
        let line = format!("role_swapped={role_swapped} K={k} tag120={verify_target} tag121={verify_reads} tag122={verify_anchor} tag123={verify_rows} tag124={execute} tag131={settle}");
        let mode = if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
            "release-SBF"
        } else {
            "native"
        };
        eprintln!("f47-full-path measured-{mode} {line}");
        receipt.push(line);
        if let Some(dir) = &receipt_dir {
            let role = if role_swapped { "swapped" } else { "default" };
            std::fs::write(
                dir.join(format!("producer-preimage-{role}-k{k}.bin")),
                &producer_preimage,
            )
            .unwrap();
            std::fs::write(dir.join(format!("dgr1-{role}-k{k}.bin")), &body).unwrap();
        }
    }
    if let Some(dir) = &receipt_dir {
        let role = if role_swapped { "swapped" } else { "default" };
        std::fs::write(
            dir.join(format!("full-path-cu-{role}.txt")),
            receipt.join("\n") + "\n",
        )
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn f47_full_dispute_tags_120_121_122_123_124_at_owner_boundaries() {
    for role_swapped in f47_measure_roles() {
        run_f47_dispute_at_owner_boundaries(role_swapped).await;
    }
}

/// Release-SBF baseline for the real form-48 tag-121 handler. This challenges
/// the gather itself, so the measured reads are its option-to-PXR1 producer
/// routes, including DGR1 parsing, route and witness checks, Merkle folds, and
/// DCR1 bitmap writes.
async fn run_f48_gather_at_owner_boundaries(role_swapped: bool) {
    let maybe = if role_swapped {
        build_f47_with_swapped_roles().await
    } else {
        build_f47().await
    };
    let Some(mut f) = maybe else { return };
    if std::env::var_os("BASANOS_DCG_V8_SBF").is_none() {
        eprintln!("SKIP: F48 dispute measurement requires the release-SBF image (set BASANOS_DCG_V8_SBF=1 and BPF_OUT_DIR)");
        return;
    }
    let receipt_dir = std::env::var_os("BASANOS_DCG_F48_RECEIPT").map(PathBuf::from);
    if let Some(dir) = &receipt_dir {
        std::fs::create_dir_all(dir).unwrap();
    }
    let (routes, geometry, payloads, pwr1, _) = f47_artifacts().unwrap();
    let program = pt2p::Program::decode(&pwr1).unwrap();
    let x = Pt2p::new(&routes, &geometry, &payloads, None, program).unwrap();
    let position = f47_position();
    assert!(
        position < f.k,
        "the decision position fits the compiler-v1 template"
    );
    let decision_entry = x.entry_count(position).unwrap() - 1;
    let base_decision_entry = x.base_entries - 1;
    assert_eq!(
        x.old_to_new(base_decision_entry, position).unwrap(),
        Some(decision_entry)
    );
    let gather_index = f47_gather_before(&x, position, decision_entry);
    let gather_at = x.coordinate(position, gather_index).unwrap();
    let mut samples = Vec::new();

    for (variant, k) in [1u8, 2, 47, 48, 64, 80]
        .into_iter()
        .enumerate()
        .filter(|(_, k)| f47_measure_k_filter().is_none_or(|only| *k == only))
    {
        let (mut binding, _) = decision_binding_at(
            &f.executor.pubkey().to_bytes(),
            position + 1,
            k,
            base_decision_entry,
        );
        binding.request_id = [180 + variant as u8; 32];
        // Keep the requested worst shape pinned: each option lands in a
        // different compiler-v1 PXR1 producer row (token = 1,940 * i).
        // This matters most at K=80, where the tag-121 CU path has 80
        // distinct producer leaves to authenticate.
        let options = (0..k as u32)
            .map(|i| i * 1_940)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        binding.option_table_sha256 = sha256(&[&options]);
        let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
        let mut position_root = [0u8; 32];
        let (body, target_leaf) = f48_honest_body(
            &x,
            &routes,
            &descriptor,
            position,
            gather_index,
            &options,
            true,
            &mut position_root,
        );
        let roots = f47_document_roots(&f, position, position_root);
        let (descriptor, created) = f
            .run_document_with_roots_and_options(&binding, &roots, &options)
            .await;
        f.finalize(&descriptor, created, position + 1).await;

        let challenger = f.signer.pubkey();
        let nonce = 0x4800_0000 + variant as u32;
        let (challenge_key, challenge_bump) =
            address::challenge(&f.program, &descriptor, &challenger, nonce);
        let (response_key, response_bump) =
            dcg_program::closure_v2_response::address(&f.program, &challenge_key);
        let mut state = vec![0u8; 8192];
        state[..4].copy_from_slice(b"DCR1");
        state[4] = 1;
        f47_put_u16(&mut state, 6, 5);
        state[8..40].copy_from_slice(challenger.as_ref());
        state[40..72].copy_from_slice(f.executor.pubkey().as_ref());
        state[72..104].copy_from_slice(&descriptor);
        state[104..136].copy_from_slice(&target_leaf);
        state[184..216].copy_from_slice(response_key.as_ref());
        f47_put_u32(&mut state, 136, gather_at.local);
        f47_put_u32(&mut state, 140, nonce);
        state[144] = 1;
        state[145] = registry::MACHINE_SELECTOR_A16;
        state[146] = challenge_bump.value();
        state[147] = 1;
        state[181] = response_bump.value();
        state[219] = response_bump.value();
        f47_put_u64(&mut state, 148, u64::MAX);
        f47_put_u32(&mut state, 156, position);
        f47_put_u16(&mut state, 160, gather_at.segment);
        f47_put_u32(&mut state, 170, gather_index);
        f47_put_u16(&mut state, 174, decision::GATHER_FORM_ID);
        f.ctx
            .set_account(&challenge_key, &shared(owned(&f.program, state)));
        let mut dru1 = vec![0u8; 128];
        dru1[..4].copy_from_slice(b"DRU1");
        f47_put_u16(&mut dru1, 4, 1);
        f47_put_u16(&mut dru1, 6, 2);
        dru1[8..40].copy_from_slice(challenge_key.as_ref());
        dru1[40..72].copy_from_slice(f.executor.pubkey().as_ref());
        f47_put_u32(&mut dru1, 72, body.len() as u32);
        f47_put_u32(&mut dru1, 76, body.len() as u32);
        dru1[80..112].copy_from_slice(&sha256(&[&body]));
        f47_put_u64(&mut dru1, 112, u64::MAX);
        dru1.extend_from_slice(&body);
        f.ctx
            .set_account(&response_key, &shared(owned(&f.program, dru1.clone())));

        let (pt2s, pt1s_index, routes_key, geometry_key, payloads_key) =
            (f.pt2s, f.pt1s_index, f.routes, f.geometry, f.payloads);
        let target_ix = Instruction {
            program_id: f.program,
            accounts: vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new_readonly(created[0], false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(pt1s_index, false),
                AccountMeta::new_readonly(routes_key, false),
                AccountMeta::new_readonly(geometry_key, false),
                AccountMeta::new_readonly(payloads_key, false),
            ],
            data: vec![120],
        };
        let target_blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
        let target_tx = Transaction::new_signed_with_payer(
            &[
                solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                    f47_compute_limit(),
                ),
                solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(
                    256 * 1024,
                ),
                target_ix,
            ],
            Some(&f.executor.pubkey()),
            &[&f.executor],
            target_blockhash,
        );
        let target_result = f
            .ctx
            .banks_client
            .process_transaction_with_metadata(target_tx)
            .await
            .unwrap();
        assert!(
            target_result.result.is_ok(),
            "tag 120 form 48 K={k}: {:?}",
            target_result.result
        );
        let tag120_cu = target_result.metadata.unwrap().compute_units_consumed;

        let data = vec![121, 0, 0, k, 0];
        let ix = Instruction {
            program_id: f.program,
            accounts: vec![
                AccountMeta::new(challenge_key, false),
                AccountMeta::new_readonly(response_key, false),
                AccountMeta::new_readonly(created[0], false),
                AccountMeta::new_readonly(created[1], false),
                AccountMeta::new_readonly(routes_key, false),
                AccountMeta::new_readonly(geometry_key, false),
                AccountMeta::new_readonly(pt2s, false),
                AccountMeta::new_readonly(created[2], false),
            ],
            data,
        };
        let blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[
                solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                    f47_compute_limit(),
                ),
                solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(
                    256 * 1024,
                ),
                ix.clone(),
            ],
            Some(&f.executor.pubkey()),
            &[&f.executor],
            blockhash,
        );
        let mut tag124_transaction_cu = None;
        if k == 80 {
            // Both an out-of-range read mapping and a segment ordinal outside
            // PT2S geometry refuse atomically; no read bit survives either.
            let section_at = u32::from_le_bytes(body[28..32].try_into().unwrap()) as usize;
            let first_witness_len =
                u32::from_le_bytes(body[section_at..section_at + 4].try_into().unwrap()) as usize;
            let envelope_at = section_at + 4 + first_witness_len + 1;
            assert_eq!(
                body.get(envelope_at..envelope_at + 4),
                Some(b"F48M".as_slice())
            );
            for (name, at) in [
                ("out-of-range mapping", envelope_at + 12),
                (
                    "out-of-range segment ordinal",
                    envelope_at + 12 + 2 * k as usize,
                ),
            ] {
                let mut malformed_body = body.clone();
                malformed_body[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
                let mut malformed_dru1 = dru1.clone();
                f47_put_u32(&mut malformed_dru1, 72, malformed_body.len() as u32);
                f47_put_u32(&mut malformed_dru1, 76, malformed_body.len() as u32);
                malformed_dru1[80..112].copy_from_slice(&sha256(&[&malformed_body]));
                malformed_dru1.truncate(128);
                malformed_dru1.extend_from_slice(&malformed_body);
                f.ctx
                    .set_account(&response_key, &shared(owned(&f.program, malformed_dru1)));
                let bad_blockhash = f.ctx.get_new_latest_blockhash().await.unwrap();
                let bad_tx = Transaction::new_signed_with_payer(
                    &[
                        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                            f47_compute_limit(),
                        ),
                        solana_compute_budget_interface::ComputeBudgetInstruction::request_heap_frame(
                            256 * 1024,
                        ),
                        ix.clone(),
                    ],
                    Some(&f.executor.pubkey()),
                    &[&f.executor],
                    bad_blockhash,
                );
                let malformed = f
                    .ctx
                    .banks_client
                    .process_transaction_with_metadata(bad_tx)
                    .await
                    .unwrap();
                let code = match malformed.result {
                    Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
                        code
                    }
                    Err(error) => {
                        panic!("malformed F48M {name} refused with {error:?}, expected custom 734")
                    }
                    Ok(()) => panic!("malformed F48M {name} unexpectedly passed"),
                };
                assert_eq!(
                    code, FORM48_PROOF_REFUSAL,
                    "malformed F48M {name} refusal code"
                );
                let after_refusal = f
                    .ctx
                    .banks_client
                    .get_account(challenge_key)
                    .await
                    .unwrap()
                    .unwrap()
                    .data;
                assert_eq!(
                    &after_refusal[348..356],
                    &[0; 8],
                    "low read bitmap is atomic"
                );
                assert_eq!(
                    &after_refusal[396..404],
                    &[0; 8],
                    "high read bitmap is atomic"
                );
                f.ctx
                    .set_account(&response_key, &shared(owned(&f.program, dru1.clone())));
            }
        }

        let outcome = f
            .ctx
            .banks_client
            .process_transaction_with_metadata(tx)
            .await
            .unwrap();
        let transaction_cu = outcome
            .metadata
            .as_ref()
            .map_or(0, |m| m.compute_units_consumed);
        let instruction_cu = outcome.metadata.as_ref().and_then(|metadata| {
            let prefix = format!("Program {} consumed ", f.program);
            metadata.log_messages.iter().find_map(|line| {
                line.strip_prefix(&prefix)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            })
        });
        let error = outcome.result.err().map(|error| format!("{error:?}"));
        if error.is_none() {
            let execute = f47_measured_refusal(
                &mut f,
                vec![124],
                vec![
                    AccountMeta::new(challenge_key, false),
                    AccountMeta::new_readonly(response_key, false),
                    AccountMeta::new(created[0], false),
                    AccountMeta::new_readonly(routes_key, false),
                    AccountMeta::new_readonly(geometry_key, false),
                    AccountMeta::new_readonly(pt2s, false),
                ],
                &format!("Form 48 K={k} role_swapped={role_swapped} tag124"),
            )
            .await;
            tag124_transaction_cu = Some(execute);
        } else {
            assert_eq!(
                f47_compute_limit(),
                1_400_000,
                "raised-limit runs must complete tag 121"
            );
            assert!(
                transaction_cu >= 1_399_000,
                "expected tag 121 to exhaust the 1.4M budget: {error:?}, consumed={transaction_cu}"
            );
            assert!(
                error
                    .as_deref()
                    .is_some_and(|value| value.contains("ProgramFailedToComplete")
                        || value.contains("ComputationalBudgetExceeded")),
                "expected the compute-budget refusal for Form 48 K={k}: {error:?}"
            );
        }
        let sample = serde_json::json!({
            "options": k, "tag120_transaction_cu": tag120_cu,
            "tag121_instruction_cu": instruction_cu, "tag121_transaction_cu": transaction_cu,
            "tag121_success": error.is_none(), "tag121_error": error,
            "tag124_transaction_cu": tag124_transaction_cu,
            "proof_bytes": body.len(), "form": 48, "position": position,
        });
        eprintln!("f48-gather-full-handler role_swapped={role_swapped} {sample}");
        samples.push(sample);
        if let Some(dir) = &receipt_dir {
            let role = if role_swapped { "swapped" } else { "default" };
            std::fs::write(dir.join(format!("f48-dgr1-{role}-k{k}.bin")), &body).unwrap();
        }
    }
    if let Some(dir) = &receipt_dir {
        let role = if role_swapped { "swapped" } else { "default" };
        let receipt = serde_json::json!({
            "schema": "basanos/rev8-f-proofs2-form48-tag121-multiproof/1",
            "identity_order": role,
            "image_sha256": std::fs::read(std::path::Path::new(&std::env::var("BPF_OUT_DIR").unwrap()).join("dcg_program.so"))
                .map(|b| format!("{}", sha256(&[&b]).iter().map(|v| format!("{v:02x}")).collect::<String>())).unwrap(),
            "source_commit": source_commit(),
            "samples": samples,
        });
        std::fs::write(
            dir.join(format!("form48-tag121-multiproof-{role}.json")),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn f48_gather_tag121_full_handler_at_owner_boundaries() {
    for role_swapped in f47_measure_roles() {
        run_f48_gather_at_owner_boundaries(role_swapped).await;
    }
}

/// **§1's one conditional at the handler, 794**: a record that declares a stop
/// value must be a 16-byte-output record, because the stop rule's comparison
/// cell is then exactly the 16-byte `(best, token)` pair of §1.7 whose bytes
/// `8..16` carry the token id. Two cases the review named, both driven through
/// a real `UnifiedInit` over the real sealed template:
///
/// * **a width-4 decision that declares a stop value** -- a typed decision's
///   cells are 4-byte fixed-point values and have no token id at all, so the
///   two conditionals are exclusive by construction;
/// * **a width-8 completion** whose stop rule can never fire.
///
/// Both were admitted by the round-2 program while the spec (§1, §1.2's field
/// table, and the 794 row of `refusals_v1.tsv`), the Python mirror and the
/// retained golden example's own binding all refuse them. The positive is here
/// too: the same binding with `stop_plus_one = 0` at width 4 and at width 8
/// initializes, so the clause is on the stop value and on nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_init_refuses_a_stop_value_that_the_cell_width_cannot_carry() {
    let Some(mut f) = build().await else { return };
    // The honest positive first: the fixture's own binding at the template's
    // width, with a stop value, initializes. This is the golden example's
    // shape -- `<|im_end|>` plus one against a 16-byte cell -- and it is the
    // path the retained example and the mirror both admit.
    let honest = Binding2 {
        stop_plus_one: 248_047,
        ..f.binding(29, 50)
    };
    assert_eq!(
        honest.output_width, 16,
        "the template's output lane is 16 bytes wide"
    );
    let (descriptor, created) = f.run_document(&honest, 2).await;
    let doc = f.account(created[0]).await;
    assert_eq!(
        &doc[BINDING_AT_V8 + 156..BINDING_AT_V8 + 160],
        &248_047u32.to_le_bytes(),
        "the record init wrote carries the stop value, and the width it admits it with is 16"
    );
    assert_eq!(&doc[8..40], &descriptor[..]);
    // The same binding with the stop value cleared is the same document.
    let quiet = Binding2 {
        stop_plus_one: 0,
        ..honest
    };
    assert_eq!(Binding2::decode(&quiet.encode()).unwrap(), quiet);
    // A variant: a different request id, so the descriptor and the four PDAs
    // are this attempt's own and the refusal cannot be a collision.
    let mut variant = 1u8;
    // **Width 4: a decision that declares a stop value.** The lane is the
    // template's own 16-byte one, so the only thing that can refuse this is
    // the width/stop clause; a decision whose locator is honest is refused
    // 794 on its own terms either way, which is why the *width* is what the
    // bytes below hold.
    let (decision, _options) = decision_binding(&f.executor.pubkey().to_bytes(), 30, 1);
    let decision_with_stop = Binding2 {
        stop_plus_one: 1,
        ..decision
    };
    assert_eq!(
        decision_with_stop.output_width, DECISION_WIDTH,
        "a decision's cells are 4 bytes"
    );
    assert_eq!(
        Binding2::decode(&decision_with_stop.encode()),
        Err(RUN_BINDING),
        "the decoder refuses it, which is the mirror's reading"
    );
    variant += 1;
    assert_eq!(
        f.init_refusal(&decision_with_stop, variant).await,
        RUN_BINDING,
        "a width-4 decision that declares a stop value is 794 at init"
    );
    // The same decision without the stop value reaches the plan and is refused
    // on **its own** clause -- the template has no 4-byte write lane -- which
    // is a different refusal from the one above and pins the difference.
    assert_eq!(
        Binding2::decode(&decision.encode()).map(|b| b.output_width),
        Ok(DECISION_WIDTH)
    );
    variant += 1;
    assert_eq!(
        f.init_refusal(&decision, variant).await,
        RUN_BINDING,
        "and without a stop value it is still 794, on the lane rather than the width"
    );
    // **Width 8, and then 4, 2 and 32 for the same reason:** a cell the stop
    // rule cannot read. The width must also equal the template's own, so the
    // locator compare would refuse these too -- but the clause under test is
    // checked at decode, before the plan and the PT2S are read at all, which
    // is what the decoder's own answer shows.
    for width in [8u8, 4, 2, 32] {
        let b = Binding2 {
            output_width: width,
            stop_plus_one: 46,
            ..f.binding(29, 50)
        };
        assert_eq!(
            Binding2::decode(&b.encode()),
            Err(RUN_BINDING),
            "width {width} with a stop value"
        );
        variant += 1;
        assert_eq!(
            f.init_refusal(&b, variant).await,
            RUN_BINDING,
            "a width-{width} record that declares a stop value is 794 at init"
        );
    }
    // The clause is on `stop_plus_one != 0` and not on the width by itself: the
    // same widths with no stop value decode, and width 16 decodes with every
    // value of the field, `1` and `u32::MAX` included.
    for (width, stop) in [(4u8, 0u32), (8, 0), (32, 0)] {
        let b = Binding2 {
            output_width: width,
            stop_plus_one: stop,
            ..f.binding(29, 50)
        };
        assert_eq!(
            Binding2::decode(&b.encode()).map(|d| d.output_width),
            Ok(width),
            "width {width} with no stop value is not this clause's business"
        );
    }
    for stop in [1u32, 46, 248_047, u32::MAX] {
        let b = Binding2 {
            stop_plus_one: stop,
            ..f.binding(29, 50)
        };
        assert_eq!(
            Binding2::decode(&b.encode()).map(|d| d.stop_plus_one),
            Ok(stop),
            "width 16 admits every stop value, 1 = token id 0 included"
        );
    }
}

/// The malformed-input test for revision 8's one new account, **DTU1**: the
/// PDA, the record, the state vocabulary and the increment.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_dtu1_malformed_inputs() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let n = 2u32;
    let (descriptor, created) = f.run_document(&binding, n).await;
    // The honest increment happened.
    let use_record = f.account(f.dtu1).await;
    assert_eq!(use_record.len(), config::DTU1_BYTES);
    assert_eq!(use_record[6], config::DTU1_STATE_LIVE);
    assert_eq!(u32_at(&use_record, 8), 1, "documents + 1 at init");
    // The malformed DTU1 images (wrong magic or version, a wrong stored bump,
    // reserved bytes, short or long, states 3 and 4, a full counter) are
    // states only a program bug could write: unit tests of the gate
    // (config::dtu1_gate_tests; owner decision 2026-10-02). What a caller can
    // do is below, by real instructions.
    let init_attempt = |f: &Fix, request: u8| {
        let binding = Binding2 {
            request_id: [request; 32],
            ..f.binding(29, 50)
        };
        let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
        let created = [
            address::document(&f.program, &descriptor).0,
            address::positions(&f.program, &descriptor).0,
            address::family_slots(&f.program, &descriptor).0,
            address::result(&f.program, &descriptor).0,
        ];
        let data = init_data(
            &f.terms_raw,
            &binding.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &f.family_body,
            &[],
        );
        (f.init_metas(created), data)
    };
    // An attacker substitutes an account it controls for DTU1: 793.
    let (mut metas, data) = init_attempt(&f, 1);
    let last = metas.len() - 1;
    metas[last] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_eq!(
        custom(send_fresh_with(&mut f.ctx, &f.executor, f.program, data, metas).await),
        TEMPLATE_SEAL,
        "a substituted DTU1 is 793"
    );
    // A missing meta is the account-count refusal, 580.
    let (metas, data) = init_attempt(&f, 2);
    assert_eq!(
        custom(send_fresh_with(&mut f.ctx, &f.executor, f.program, data, metas[..13].to_vec()).await),
        CL_MALFORMED,
        "thirteen metas is 580"
    );
    // The authority revokes the template (tag 176): no new document, 793.
    let config_key = address::config(&f.program).0;
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_TEMPLATE_SEAL, SEAL_REVOKED],
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(f.dta1, false),
            AccountMeta::new(f.pt2s, false),
            AccountMeta::new(f.dtu1, false),
        ],
    )
    .await
    .expect("the configured authority revokes the template");
    assert_eq!(f.account(f.dtu1).await[6], config::DTU1_STATE_REVOKED);
    let (metas, data) = init_attempt(&f, 3);
    assert_eq!(
        custom(send_fresh_with(&mut f.ctx, &f.executor, f.program, data, metas).await),
        TEMPLATE_SEAL,
        "a revoked template admits no new document, 793"
    );
    let _ = (descriptor, created);
}

/// **The per-template limits, driven from real instructions** (spec §1.1's
/// checks 17-20 and §1.3's clamp, the user's decision of 2026-09-26).
///
/// Four things, in one test because they are one rule seen from four sides:
///
/// 1. **At the limit is admitted and one slot over is refused, 791.** The
///    document's own terms are moved to each template's maximum in turn, so the
///    refusal is shown to be the *comparison* and not a constant somewhere.
/// 2. **Two templates with different limits admit the same terms differently**:
///    the golden's own 5,184,000-slot grace is inside the example template's
///    range and outside the short-lived one's, and the second template's
///    lifetime makes the same landing clamp where the first would not.
/// 3. **The clamp reads the template, not a constant**: a landing under the
///    short template writes `init_slot + 4,096,000`.
/// 4. A **retired** template still lets its live document land and finalize,
///    because `state` is deliberately not read by the two deadline writers.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_the_per_template_limits_bound_a_document_and_two_templates_differ() {
    let Some(mut f) = build().await else { return };
    let Some(mut fs) = build_with_limits(SHORT_LIMITS).await else { return };
    let n = 2u32;
    let roots = f.position_roots[..n as usize].to_vec();
    // Two real templates: their DTU1s carry exactly the limits each seal
    // approved.
    assert_eq!(TemplateLimits::from_dtu1(&f.account(f.dtu1).await), Ok(EXAMPLE_LIMITS));
    assert_eq!(TemplateLimits::from_dtu1(&fs.account(fs.dtu1).await), Ok(SHORT_LIMITS));
    let mut variant = 0u8;
    // A real init on template `$f`, and the code. Each template is sealed for
    // real with its own limits (rule 6): `f` with the example's, `fs` with
    // SHORT_LIMITS.
    macro_rules! init_with {
        ($f:ident, $terms:expr) => {{
            let terms = $terms;
            variant += 1;
            let binding = Binding2 {
                request_id: [variant; 32],
                ..$f.binding(29, 50)
            };
            let descriptor = $f.descriptor(&binding, &terms, 16);
            let created = [
                address::document(&$f.program, &descriptor).0,
                address::positions(&$f.program, &descriptor).0,
                address::family_slots(&$f.program, &descriptor).0,
                address::result(&$f.program, &descriptor).0,
            ];
            let metas = $f.init_metas(created);
            let data = init_data(
                &terms,
                &binding.encode(),
                &[[1u8; 32], [2u8; 32], [3u8; 32]],
                16,
                &$f.family_body,
                &[],
            );
            let slot = $f
                .ctx
                .banks_client
                .get_sysvar::<solana_program::clock::Clock>()
                .await
                .unwrap()
                .slot;
            $f.ctx.warp_to_slot(slot + 1).unwrap();
            // `None` is an admitted init and `Some(code)` is the refusal it
            // refused with, so one shape covers "at the limit is admitted" and
            // "one slot over is 791".
            (
                binding,
                descriptor,
                created,
                match send(&mut $f.ctx, &$f.executor, $f.program, data, metas).await {
                    Ok(()) => None,
                    Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
                        Some(code)
                    }
                    other => panic!("expected a success or a custom refusal, got {other:?}"),
                },
            )
        }};
    }
    let base = Terms2::decode(&f.terms_raw).unwrap();
    // (1) The grace at the example template's ceiling, and one slot over it.
    let at_max = Terms2 {
        abandon_after_slots: EXAMPLE_LIMITS.max_abandon_after_slots,
        ..base
    };
    let (_, _, _, code) = init_with!(f, at_max.encode().to_vec());
    assert_eq!(
        code, None,
        "a document AT its template's grace maximum is admitted"
    );
    let over = Terms2 {
        abandon_after_slots: EXAMPLE_LIMITS.max_abandon_after_slots + 1,
        ..base
    };
    let (_, _, _, code) = init_with!(f, over.encode().to_vec());
    assert_eq!(code, Some(DISPUTE_TERMS), "one slot OVER it is 791");
    // One slot under the template's **floor**, the same code: the grace is the
    // owner's in both directions, which is the whole of check 17.
    let under = Terms2 {
        abandon_after_slots: EXAMPLE_LIMITS.min_abandon_after_slots - 1,
        ..base
    };
    let (_, _, _, code) = init_with!(f, under.encode().to_vec());
    assert_eq!(code, Some(DISPUTE_TERMS), "one under the floor is 791 too");
    // (2) Two templates, the same terms. The golden's grace is inside the wide
    // one and over the short one's ceiling.
    let short_grace = Terms2 {
        abandon_after_slots: SHORT_LIMITS.max_abandon_after_slots + 1,
        ..base
    };
    let (_, _, _, code) = init_with!(fs, short_grace.encode().to_vec());
    assert_eq!(
        code,
        Some(DISPUTE_TERMS),
        "the short-lived template refuses what the wide one admits"
    );
    // A document sized to the short template -- its grace at the short
    // template's own maximum -- is admitted, and because the ceiling is
    // `init_slot + 4,096,000` the very first landing is already past it.
    let small = Terms2 {
        challenge_window_slots: 900_000,
        response_window_slots: 40_000,
        abandon_after_slots: SHORT_LIMITS.max_abandon_after_slots,
        ..base
    };
    let small_raw = small.encode().to_vec();
    let (binding, descriptor, _, code) =
        init_with!(fs, small_raw.clone());
    assert_eq!(
        code, None,
        "a document at the short template's grace maximum is admitted"
    );
    // `craft` builds the record from the fixture's own terms, so they are set to
    // the document's: the record under test must be the one init admitted.
    fs.terms_raw = small_raw.clone();
    let c = fs.craft(&binding, n, &roots, 0, descriptor).await;
    let slot = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert!(
        slot > 0,
        "the document is created at slot 0, so this landing is past its init"
    );
    let (metas, data) = (
        fs.land_metas(&c),
        land_data(
            &c.descriptor,
            n,
            &fs.position_roots[n as usize..n as usize + 1],
        ),
    );
    send(&mut fs.ctx, &fs.executor, fs.program, data, metas)
        .await
        .expect("a landing under the short template");
    let doc = fs.account(c.dcm2).await;
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        fs.init_slot(&c).await + SHORT_LIMITS.max_document_lifetime_slots,
        "THE CLAMP READS THE TEMPLATE: the ceiling is init_slot + 4,096,000"
    );
    assert!(
        slot + small.abandon_after_slots > SHORT_LIMITS.max_document_lifetime_slots,
        "and the forward value {} would have been larger, so the clamp bound",
        slot + small.abandon_after_slots
    );
    // The same document, the same slot, under the **wide** template: the same
    // program writes the plain forward value, because that template's ceiling is
    // 134,217,728 away. This is the user's decision in two assertions.
    f.terms_raw = small_raw.clone();
    let (binding, descriptor2, _, code) = init_with!(f, small_raw);
    assert_eq!(code, None, "and the same document under the wide template");
    let c2 = f.craft(&binding, n, &roots, 0, descriptor2).await;
    let (metas, data) = (
        f.land_metas(&c2),
        land_data(
            &c2.descriptor,
            n,
            &f.position_roots[n as usize..n as usize + 1],
        ),
    );
    send(&mut f.ctx, &f.executor, f.program, data, metas)
        .await
        .expect("a landing under the wide template");
    let doc = f.account(c2.dcm2).await;
    // The landing's own slot, which is one past the first landing's: each
    // transaction advances the clock, and the write is `slot + abandon`.
    let slot2 = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert_eq!(
        u64_at(&doc, document::ABANDON_DEADLINE_AT),
        slot2 + small.abandon_after_slots,
        "the wide template's ceiling is 134,217,728 away, so the write is the plain forward value"
    );
    // (4) A **retired** template: `state` is not read by the two deadline
    // writers, or a retirement would strand the rent it was meant to protect.
    let config_key = address::config(&f.program).0;
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_TEMPLATE_SEAL, SEAL_RETIRED],
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(f.dta1, false),
            AccountMeta::new(f.pt2s, false),
            AccountMeta::new(f.dtu1, false),
        ],
    )
    .await
    .expect("the authority retires the wide template (176)");
    let (metas, data) = (
        f.land_metas(&c2),
        land_data(
            &c2.descriptor,
            n + 1,
            &f.position_roots[n as usize + 1..n as usize + 2],
        ),
    );
    send(&mut f.ctx, &f.executor, f.program, data, metas)
        .await
        .expect("a retired template's live document still lands");
    // And the recorded worst case, the number a reader of the DTU1 computes.
    assert_eq!(EXAMPLE_LIMITS.worst_case_hold_slots(), 285_212_672);
    assert_eq!(SHORT_LIMITS.worst_case_hold_slots(), 5_505_600);
}

// -------------------------------------------- the 39-byte PT2S seal, by itself

/// tag 145's own test, over the real retained emission: the 39-byte seal
/// writes the locator at 426..432, `write = 0` is legal, the width is bounded
/// and nothing else about the locator is.
///
/// The review's High 2 was invisible because **no test sent a 39-byte seal at
/// all**: the fixture laid the six bytes down in the PT2S image itself. This
/// sends it, and the honest locator it carries is `(28_037, write 0, width 16)`
/// -- the retained rung-D template's own, the same one the golden example
/// binding and the v7 golden declare. The program used to refuse `write == 0`
/// with no rule behind it (the spec's §1.7 bounds the width and says nothing
/// about the write, and the mirror's `OutputLocator` admits 0), which made the
/// only real template in this tree unsealable.
///
/// The negatives are on their own PT2S accounts, because the seal is
/// write-once: a second seal on a sealed account would be refused for the
/// wrong reason.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_seal_writes_the_locator_and_bounds_only_the_width() {
    let Some((routes, geometry, payloads, pwr1, clause12)) = artifacts() else {
        eprintln!("needs_local_artifacts: the retained PT2P emission is absent");
        return;
    };
    let program = Pubkey::new_unique();
    let executor = Keypair::new();
    let (routes_key, geometry_key, payloads_key) = (
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    );
    let mut test = ProgramTest::new(
        "dcg_program",
        program,
        processor!(dcg_program::process_instruction),
    );
    test.prefer_bpf(false);
    for key in [executor.pubkey(), routes_key, geometry_key, payloads_key] {
        test.add_account(key, system_funded());
    }
    test.add_account(routes_key, owned(&program, routes.clone()));
    test.add_account(geometry_key, owned(&program, geometry.clone()));
    test.add_account(payloads_key, owned(&program, payloads.clone()));
    // One fresh, unsealed PT2S per case, all with the real emission's own bytes.
    let cases = 6u8;
    let mut pt2s_keys = Vec::new();
    for _ in 0..cases {
        let key = Pubkey::new_unique();
        test.add_account(
            key,
            owned(
                &program,
                hashing_pt2s(
                    &routes,
                    &geometry,
                    &payloads,
                    &pwr1,
                    executor.pubkey(),
                    [routes_key, geometry_key, payloads_key],
                ),
            ),
        );
        pt2s_keys.push(key);
    }
    let mut ctx = test.start_with_context().await;
    let data = |base_entry: u32, write: u8, width: u8| {
        let mut d = vec![S::TAG_SEAL];
        d.extend_from_slice(&[9u8; 32]);
        d.extend_from_slice(&base_entry.to_le_bytes());
        d.push(write);
        d.push(width);
        d
    };
    let seal = |pt2s: Pubkey| {
        vec![
            AccountMeta::new(pt2s, false),
            AccountMeta::new_readonly(routes_key, false),
            AccountMeta::new_readonly(geometry_key, false),
            AccountMeta::new_readonly(payloads_key, false),
            AccountMeta::new(executor.pubkey(), true),
        ]
    };
    // (1) **The honest locator: `write = 0`.**
    send(
        &mut ctx,
        &executor,
        program,
        data(28_037, 0, 16),
        seal(pt2s_keys[0]),
    )
    .await
    .expect("write 0 seals");
    let sealed = ctx
        .banks_client
        .get_account(pt2s_keys[0])
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(sealed[S::OFF_STATE], S::STATE_SEALED);
    assert_eq!(
        &sealed[S::OFF_LOCATOR..S::OFF_LOCATOR + 4],
        &28_037u32.to_le_bytes()
    );
    assert_eq!(
        sealed[S::OFF_LOCATOR + 4],
        0,
        "write ordinal 0 is the first write at the entry"
    );
    assert_eq!(sealed[S::OFF_LOCATOR + 5], 16);
    assert_eq!(
        &sealed[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
        &clause12[..],
        "the seal recomputed the retained clause-12 v4 from the plan"
    );
    assert_eq!(
        &sealed[S::OFF_DEFINITION..S::OFF_DEFINITION + 32],
        &[9u8; 32][..]
    );
    assert_eq!(
        sealed.len(),
        S::OFF_PWR1 + pwr1.len(),
        "the locator costs no account growth"
    );
    assert_eq!(&sealed[S::OFF_PWR1..], &pwr1[..], "the PWR1 is untouched");
    // The locator the document side then reads is the seal's own bytes, and
    // they are the template's honest lane.
    assert_eq!(
        Locator::read(&sealed, RUN_BINDING).unwrap(),
        Locator {
            base_entry: 28_037,
            write: 0,
            width: 16
        }
    );
    // (2) A write ordinal at the top of the `u8` is legal too: the seal does
    // not bound it, and whether that lane exists is `Binding2::check`'s
    // question at init, against the plan, where it is 794.
    send(
        &mut ctx,
        &executor,
        program,
        data(28_037, 255, 4),
        seal(pt2s_keys[1]),
    )
    .await
    .expect("write 255 seals");
    let sealed = ctx
        .banks_client
        .get_account(pt2s_keys[1])
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(
        (sealed[S::OFF_LOCATOR + 4], sealed[S::OFF_LOCATOR + 5]),
        (255, 4)
    );
    // (3) **The width is the only bound: 0 and 33 are refused**, and the
    // refusal is the instruction's own `InvalidInstructionData` rather than a
    // DCG code, because the seal is tag 145 and predates the C refusal table.
    for (i, width) in [(2usize, 0u8), (3, 33), (4, 255)] {
        let got = send(
            &mut ctx,
            &executor,
            program,
            data(28_037, 0, width),
            seal(pt2s_keys[i]),
        )
        .await;
        assert_eq!(
            refusal(got),
            "InvalidInstructionData",
            "width {width} is out of 1..=32"
        );
        // The refused seal wrote nothing at all: the state is still HASHING and
        // 426..432 is still the six dead bytes the revision-7 layout left.
        let s = ctx
            .banks_client
            .get_account(pt2s_keys[i])
            .await
            .unwrap()
            .unwrap()
            .data;
        assert_eq!(
            s[S::OFF_STATE],
            S::STATE_HASHING,
            "a refused seal is not a seal"
        );
        assert_eq!(&s[S::OFF_LOCATOR..S::OFF_PWR1], &[0u8; 6][..]);
    }
    // (4) **A 33-byte seal is revision 7's seal**, and it leaves 426..432 zero:
    // the six bytes were dead state, so a revision-8 PT2S with no locator is
    // byte for byte the revision-7 image and a revision-7 document over it is
    // unaffected.
    let short = {
        let mut d = vec![S::TAG_SEAL];
        d.extend_from_slice(&[9u8; 32]);
        d
    };
    assert_eq!(short.len(), 33);
    send(&mut ctx, &executor, program, short, seal(pt2s_keys[5]))
        .await
        .expect("the 33-byte seal");
    let sealed = ctx
        .banks_client
        .get_account(pt2s_keys[5])
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(sealed[S::OFF_STATE], S::STATE_SEALED);
    assert_eq!(
        &sealed[S::OFF_LOCATOR..S::OFF_PWR1],
        &[0u8; 6][..],
        "426..432 is left zero by a 33-byte seal"
    );
    assert_eq!(
        &sealed[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43],
        &clause12[..]
    );
    assert_eq!(
        Locator::read(&sealed, RUN_BINDING).unwrap(),
        Locator {
            base_entry: 0,
            write: 0,
            width: 0
        },
        "and so reads as zeros, which no revision-8 binding can equal: the width is 0"
    );
    // The lengths either side of 33 and 39 are not instruction data at all, and
    // the length check is the first statement of the handler, so a sealed
    // account is the right one to send them to.
    for total in [1usize, 32, 34, 38, 40] {
        let mut d = vec![S::TAG_SEAL];
        d.resize(total, 0);
        assert_eq!(
            refusal(send(&mut ctx, &executor, program, d, seal(pt2s_keys[0])).await),
            "InvalidInstructionData",
            "a {total}-byte seal argument"
        );
    }
    // The write-once property, on an account that has already sealed. A
    // different definition digest, so this is a new transaction and not a
    // duplicate of the one the banks client already processed.
    let mut again = data(28_037, 0, 16);
    again[1..33].copy_from_slice(&[8u8; 32]);
    assert_eq!(
        refusal(send(&mut ctx, &executor, program, again, seal(pt2s_keys[0])).await),
        "InvalidAccountData",
        "a second seal on a sealed PT2S"
    );
    // And the five-account list is frozen: four is not enough.
    assert_eq!(
        refusal(
            send(
                &mut ctx,
                &executor,
                program,
                data(28_037, 0, 16),
                seal(pt2s_keys[1])[..4].to_vec()
            )
            .await
        ),
        "InvalidInstructionData",
        "four metas"
    );
}

/// A `ProgramError` -- as opposed to a DCG refusal code -- read as the name the
/// runtime reports it under. tag 145 predates the C refusal table, so its
/// refusals are `ProgramError`s and not `Custom(_)`.
fn refusal(result: Result<(), TransactionError>) -> String {
    match result {
        Err(TransactionError::InstructionError(_, e)) => format!("{e:?}"),
        other => panic!("expected an instruction refusal, got {other:?}"),
    }
}

// ------------------------------------- tag 178: the resolve, `L` and the stop rule

/// The Qwen chat stop token the design note names (248046), plus one, and the
/// four-byte decision cell width the same note names.
const STOP_PLUS_ONE: u32 = 248_047;

/// A cell carrying `token` in its bytes `8..16` and `-1` in `0..8`, the shape a
/// real `(best, token)` output cell has.
fn cell_with_token(token: u32) -> Vec<u8> {
    let mut cell = vec![0u8; 16];
    cell[0..8].copy_from_slice(&(-1i64).to_le_bytes());
    cell[8..16].copy_from_slice(&(token as u64).to_le_bytes());
    cell
}

impl Fix {
    /// The same CUSTOM terms of §1.1 with a **chosen challenge window**, whose
    /// floor is one slot. The FINAL condition needs `now > dispute_deadline`
    /// and finalize writes `dispute_deadline = finalize_slot +
    /// challenge_window_slots`, so a one-slot window is what makes that one
    /// slot of warping away instead of 90,001. Nothing else moves: the terms
    /// are committed in the descriptor exactly as the fixture's own are.
    fn terms_window(&self, window: u64) -> Vec<u8> {
        let mut t = Terms2::decode(&self.terms_raw).unwrap();
        t.challenge_window_slots = window;
        t.response_window_slots = window;
        t.encode().to_vec()
    }

    /// The fixture's completion binding with a **declared stop value**. Every
    /// other field is the one the seal committed, so the only thing that
    /// changes against `binding` is the one number the stop rule reads.
    fn binding_stop(&self, first: u32, count: u32, stop_plus_one: u32) -> Binding2 {
        Binding2 {
            stop_plus_one,
            ..self.binding(first, count)
        }
    }

    /// tag 178's two metas: DCM2 read-only and DCR2 writable, which is
    /// revision 7's list and §1.6's "accounts unchanged". The conviction
    /// branch is the one path that needs DCM2 writable, and the negative for
    /// that is its own test.
    fn resolve_metas(&self, c: &Crafted) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(c.dcm2, false),
            AccountMeta::new(c.dcr2, false),
        ]
    }
}

/// One resolve sent against a crafted record, returning the code and asserting
/// that a **refused** resolve wrote nothing to the record. Every 796 and 580
/// below is checked against the account's bytes before and after, so a refusal
/// that half-applied would fail here rather than pass.
async fn refused_resolve(f: &mut Fix, dcr2: Pubkey, data: Vec<u8>, metas: Vec<AccountMeta>) -> u32 {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let before = f.account(dcr2).await;
    let code = match send_fresh(&mut f.ctx, &f.signer, f.program, data, metas).await {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => code,
        other => panic!("refusal #{seq}: expected a custom refusal, got {other:?}"),
    };
    let after = f.account(dcr2).await;
    assert_eq!(
        before, after,
        "refusal #{seq}: a refused resolve wrote nothing"
    );
    code
}

/// `send` with a **fresh blockhash**, which is what a run of otherwise
/// identical instructions needs: two resolves of the same document in the same
/// blockhash window are the same transaction, and the banks client answers
/// `AlreadyProcessed` rather than a DCG code. The blockhash is part of the
/// message, so a fresh one is a fresh signature and the refusals below are the
/// handler's own. Same compute budget, same CU print.
async fn send_fresh(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<(), TransactionError> {
    send_fresh_with(ctx, signer, program, data, metas).await
}

/// [`send_fresh`] with an explicit signing keypair, for a case whose metas name
/// a **different** signer from the fixture's second keypair (the seal's role can
/// be rotated, and then the rotated key signs).
async fn send_fresh_with(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<(), TransactionError> {
    // The signing key must be the metas' signer, and the message says so rather
    // than the runtime's `NotEnoughSigners` -- which names neither the tag nor
    // the index and cost an hour once.
    for (i, m) in metas.iter().enumerate() {
        if m.is_signer && m.pubkey != signer.pubkey() {
            panic!(
                "tag {}: the signing key is not the metas' signer at index {i}",
                data.first().unwrap_or(&0)
            );
        }
    }
    let tag = *data.first().unwrap_or(&0);
    let len = data.len();
    // The label is set by the case that is about to send, so a CU figure names
    // the row it was measured on -- four runs of twenty numbers is not a receipt.
    let case = current_label();
    let blockhash = ctx
        .get_new_latest_blockhash()
        .await
        .expect("a fresh blockhash");
    let ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        Instruction {
            program_id: program,
            accounts: metas,
            data,
        },
    ];
    let make_transaction = |blockhash| {
        Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &[signer], blockhash)
    };
    let mut out = ctx
        .banks_client
        .process_transaction_with_metadata(make_transaction(blockhash))
        .await;
    if matches!(&out, Ok(inner) if matches!(inner.result, Err(TransactionError::AlreadyProcessed)))
    {
        // The PoH worker can return the previous working bank's blockhash even
        // after get_new_latest_blockhash. Give this test-only retry a new slot
        // so an identical instruction reaches the handler instead of surfacing
        // the bank's duplicate-transaction guard as if it were a program error.
        let slot = ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        ctx.warp_to_slot(slot + 1).unwrap();
        let retry_blockhash = ctx
            .get_new_latest_blockhash()
            .await
            .expect("a retry blockhash");
        out = ctx
            .banks_client
            .process_transaction_with_metadata(make_transaction(retry_blockhash))
            .await;
    }
    if let Ok(meta) = &out {
        let mode = if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
            "SBF"
        } else {
            "native"
        };
        eprintln!(
            "CU tag {tag} data {len} cu {} mode {mode} label {case}",
            meta.metadata
                .as_ref()
                .map(|m| m.compute_units_consumed)
                .unwrap_or(0)
        );
    }
    match out {
        Ok(inner) => inner.result,
        Err(error) => panic!("the banks client refused the transaction: {error:?}"),
    }
}

/// Send a fresh instruction and return its decoded `Program data:` events.
/// Close-refund regressions must check the DLE1 body as well as balances: C1
/// corrupted the event field while the actual rent transfer still succeeded.
async fn send_fresh_events(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
) -> Result<Vec<Vec<u8>>, TransactionError> {
    for (i, m) in metas.iter().enumerate() {
        if m.is_signer && m.pubkey != signer.pubkey() {
            panic!(
                "tag {}: the signing key is not the metas' signer at index {i}",
                data.first().unwrap_or(&0)
            );
        }
    }
    let blockhash = ctx
        .get_new_latest_blockhash()
        .await
        .expect("a fresh blockhash");
    let ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        Instruction {
            program_id: program,
            accounts: metas,
            data,
        },
    ];
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&signer.pubkey()), &[signer], blockhash);
    // On this ProgramTest runtime the committed transaction metadata omits
    // `sol_log_data` entries, though they are printed to the test log. Simulate
    // the same signed message first so the C1 regression can inspect the DLE1
    // refund field, then commit it once.
    let simulated = ctx
        .banks_client
        .simulate_transaction(tx.clone())
        .await
        .expect("close event simulation");
    let events = simulated
        .simulation_details
        .map(|details| {
            details
                .logs
                .into_iter()
                .filter_map(|line| {
                    line.rsplit_once("data: ")
                        .map(|(_, encoded)| decode_base64(encoded))
                })
                .collect()
        })
        .unwrap_or_default();
    let out = ctx.banks_client.process_transaction_with_metadata(tx).await;
    match out {
        Ok(inner) => inner.result.map(|()| events),
        Err(error) => panic!("the banks client refused the transaction: {error:?}"),
    }
}

fn decode_base64(text: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!("invalid base64 event"),
    };
    let clean: Vec<u8> = text.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= (val(c) as u32) << (18 - 6 * i);
        }
        for i in 0..chunk.len() * 6 / 8 {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn close_event_refund(events: &[Vec<u8>]) -> Option<u64> {
    events
        .iter()
        .find(|event| {
            event.len() == 120
                && &event[..4] == b"DLE1"
                && u16_at(event, 4) == 3
                && event[6] == events::CLOSE
        })
        .map(|event| u64_at(event, 80))
}

fn assert_close_event_refund(events: &[Vec<u8>], expected: u64) {
    let refund = close_event_refund(events);
    if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
        assert_eq!(
            refund,
            Some(expected),
            "the SBF CLOSE event records the exact drain"
        );
    } else if let Some(refund) = refund {
        assert_eq!(
            refund, expected,
            "the native CLOSE event records the exact drain"
        );
    }
}

/// The two metas of §1.6's account list, for a named pair of accounts.
/// A document convicted for real (rule 6): a completion with a stop value at
/// output 4 of L = 10 (clause 1, "ran long"), every output attested, the
/// clock past its deadline, and a writable ResolveResultV5 that convicts it
/// (DCM2 flag 4, challenger_wins + 1, DCR2 REFUTED). Records no winner: the
/// stop-rule conviction leaves DCR2 352 to the challenge route.
async fn convicted_by_resolve(f: &mut Fix, request: u8) -> Crafted {
    let binding = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let tokens = vec![(4u32, STOP_PLUS_ONE - 1), (9u32, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(f, &binding, 40, &tokens, request).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(f, c.dcm2).await;
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        vec![AccountMeta::new(c.dcm2, false), AccountMeta::new(c.dcr2, false)],
    )
    .await
    .expect("the stop-rule conviction");
    assert_eq!(f.account(c.dcr2).await[6], result::STATUS_REFUTED);
    assert_ne!(u16_at(&f.account(c.dcm2).await, 6) & FLAG_REFUTED, 0);
    c
}

fn pair(dcm2: Pubkey, dcr2: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(dcm2, false),
        AccountMeta::new(dcr2, false),
    ]
}

fn resolve_data(descriptor: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![TAG_RESOLVE_RESULT];
    out.extend_from_slice(descriptor);
    out
}

/// A real revision-8 completion document, initialized, landed, finalized and
/// then **attested at every index of `[0, l)` through the handler** with a
/// chosen token id per output.
///
/// `tokens[i]` is the token id written into output `i`'s cell; an index the
/// slice does not name gets a non-stop token. `n` and `l` are the document's
/// own, and the caller has to pass a document the 816 relations admit, so this
/// asserts them rather than assuming them.
///
/// `variant` names the document: the descriptor is a function of the binding,
/// the terms and the family count and **not** of `n`, so two runs at different
/// `n` over one binding would be the same document and the second `init` would
/// be a duplicate at the same PDA. `request_id` carries the variant, exactly as
/// `init_refusal` does.
async fn attest_all(
    f: &mut Fix,
    binding: &Binding2,
    n: u32,
    tokens: &[(u32, u32)],
    variant: u8,
) -> ([u8; 32], [Pubkey; 4], Vec<Rekeyed>) {
    let binding = Binding2 {
        request_id: [variant.max(1); 32],
        ..*binding
    };
    let first = binding.output_first_position;
    let l = binding.output_span(n);
    assert!(
        l >= 1 && l <= binding.output_count,
        "the document declares L = {l}"
    );
    assert!(
        first + 2 <= n && n <= first + binding.output_count + 1,
        "816 at n = {n}: first = {first}, count = {}",
        binding.output_count
    );
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    // One re-keyed proof per output, each with its own value.
    let proofs: Vec<Rekeyed> = (0..l)
        .map(|i| {
            rekey_with(
                f,
                &descriptor,
                i,
                first + i,
                cell_with_token(
                    tokens
                        .iter()
                        .find(|(j, _)| *j == i)
                        .map(|(_, t)| *t)
                        .unwrap_or(0x_00ff_fffe),
                ),
            )
        })
        .collect();
    let mut roots = f.position_roots[..n as usize].to_vec();
    for p in &proofs {
        roots[p.p as usize] = p.root;
    }
    let created = [
        address::document(&f.program, &descriptor).0,
        address::positions(&f.program, &descriptor).0,
        address::family_slots(&f.program, &descriptor).0,
        address::result(&f.program, &descriptor).0,
    ];
    let (data, metas) = (
        init_data(
            &f.terms_raw,
            &binding.encode(),
            &[[1u8; 32], [2u8; 32], [3u8; 32]],
            16,
            &f.family_body,
            &[],
        ),
        f.init_metas(created),
    );
    send(&mut f.ctx, &f.executor, f.program, data, metas)
        .await
        .expect("init");
    // Both writers take DTU1 as their fourth meta on revision 8 (spec §1.6):
    // the clamp's ceiling is the template's own lifetime limit.
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        land_data(&descriptor, 0, &roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[1], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("land");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&descriptor, n, &f.family_roots),
        vec![
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new(created[3], false),
            AccountMeta::new_readonly(f.dtu1, false),
        ],
    )
    .await
    .expect("finalize");
    // The attest is permissionless, so the fixture's second keypair signs every
    // one of them: a challenger proving the outputs is the honest shape.
    let metas = attest_metas(f.signer.pubkey(), (f.pt2s, f.routes, f.geometry), created);
    for p in &proofs {
        send(
            &mut f.ctx,
            &f.signer,
            f.program,
            p.data.clone(),
            metas.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("attest of output {}: {e:?}", u32_at(&p.data, 33)));
    }
    let dcr2 = f.account(created[3]).await;
    assert_eq!(u32_at(&dcr2, 204), l, "every output of [0, L) is attested");
    (descriptor, created, proofs)
}

/// Put the clock one slot past the document's own `dispute_deadline`, which is
/// the first slot at which the FINAL condition can be asked.
///
/// **The clock is set rather than warped**, for the reason the file header
/// gives: `warp_to_slot` roots the bank and a root verifies the accounts hash
/// across the skipped slots, which a fixture that installs accounts with
/// `set_account` cannot then satisfy. `set_sysvar` moves the same clock with no
/// root, and it is read back through the runtime's sysvar cache, so the
/// program's own `Clock::get()` sees it. Every other field of the clock is the
/// bank's, and the document's deadline is the one its finalize wrote, so the
/// resolve is answering a real question about a real deadline.
async fn past_deadline(f: &mut Fix, dcm2: Pubkey) -> u64 {
    let deadline = u64_at(&f.account(dcm2).await, 144);
    let mut clock = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap();
    // Idempotent: a second call for a document whose deadline the clock is
    // already past leaves the clock where it is and still reports the slot the
    // resolve will read.
    let target = clock.slot.max(deadline + 1);
    if target != clock.slot {
        clock.slot = target;
        f.ctx.set_sysvar(&clock);
    }
    let seen = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    assert_eq!(
        seen, target,
        "the bank clock is where the resolve will read it"
    );
    assert!(seen > deadline, "{seen} is past the deadline {deadline}");
    seen
}

/// **The honest FINAL path, at three `n` and therefore three `L`.** A real
/// init, a real landing of the re-keyed position roots, a real finalize, `L`
/// real `AttestOutputV5` calls that discharge the proof, and a real
/// `ResolveResultV5` that writes FINAL.
///
/// The document declares `stop_plus_one`, so every one of these is a
/// *stop-rule* case and not only a counting case: the run carries
/// `first = 29`, `count = 50` over the 80-position template, and `L` runs from
/// `n - 1 - first = 1` (`n = 31`, the 816 minimum) to `L = 10` (`n = 40`).
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_is_final_on_an_honest_completion_at_several_n() {
    let Some(mut f) = build().await else { return };
    // A one-slot challenge window, so `now > dispute_deadline` is two slots.
    f.terms_raw = f.terms_window(1);
    for (i, (n, l)) in [(31u32, 1u32), (33, 3), (40, 10)].into_iter().enumerate() {
        let first = 29u32;
        let binding = f.binding_stop(first, 50, STOP_PLUS_ONE);
        // A document that **stopped early**: the stop token at output `L-1`
        // and nowhere before it, which is clause 2 met and clause 1 holding.
        let tokens: Vec<(u32, u32)> = vec![(l - 1, STOP_PLUS_ONE - 1)];
        let (descriptor, created, _) = attest_all(&mut f, &binding, n, &tokens, 30 + i as u8).await;
        let c = Crafted {
            dcm2: created[0],
            dpr2: created[1],
            dcr2: created[3],
            descriptor,
        };
        let before = past_deadline(&mut f, c.dcm2).await;
        let metas = f.resolve_metas(&c);
        send_fresh(
            &mut f.ctx,
            &f.signer,
            f.program,
            resolve_data(&descriptor),
            metas.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("resolve at n = {n}, L = {l}: {e:?}"));
        let dcr2 = f.account(created[3]).await;
        assert_eq!(
            dcr2[6],
            result::STATUS_FINAL,
            "status 1 FINAL at n = {n}, L = {l}"
        );
        assert_eq!(u64_at(&dcr2, 184), before, "status_slot := now");
        assert_eq!(
            u32_at(&dcr2, 192),
            0,
            "challenger_wins stays 0 on an honest FINAL"
        );
        assert_eq!(
            dcr2[6] != result::STATUS_REFUTED,
            true,
            "and it is not REFUTED"
        );
        // **The stop value landed where the rule looks for it**, in the cell
        // the attest wrote and in the position's own bytes 8..16.
        let cell =
            &dcr2[result::HEADER_V6 + (l as usize - 1) * 16..result::HEADER_V6 + l as usize * 16];
        assert_eq!(&cell[8..16], &(STOP_PLUS_ONE as u64 - 1).to_le_bytes());
        // And DCM2 is untouched apart from nothing: flag 4 is clear, so a later
        // close takes the honest branch.
        let doc = f.account(created[0]).await;
        assert_eq!(
            u16_at(&doc, 6) & FLAG_REFUTED,
            0,
            "an honest resolve sets no flag 4"
        );
        assert_eq!(u32_at(&doc, 132), 0, "and no challenger win");
    }
}

/// **A completion that stops early is FINAL, and one that ran past its stop is
/// convicted.** Both documents are real and both are attested by the handler;
/// they differ in one number — output `L-1`'s token — which is the whole
/// content of clause 2.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_convicts_a_stop_rule_violation_at_each_clause() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let first = 29u32;
    let (n, l) = (40u32, 10u32);
    // (1) **Clause 1, `ran long`**: a stop value at output 4, which is in
    // `[0, L-2) = [0, 9)`. The document claims L = 10, so it says it kept
    // generating after it had already stopped.
    let binding = f.binding_stop(first, 50, STOP_PLUS_ONE);
    let tokens = vec![(4u32, STOP_PLUS_ONE - 1), (l - 1, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, n, &tokens, 21).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let now = past_deadline(&mut f, c.dcm2).await;
    let metas = f.resolve_metas(&c);
    // The read-only DCM2 of §1.6's list cannot carry the conviction, which is
    // the account-list note on `resolve_v8`: **580**, and the record is
    // untouched.
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                resolve_data(&descriptor),
                metas.clone()
            )
            .await
        ),
        CL_MALFORMED,
        "a read-only DCM2 cannot convict"
    );
    let dcr2 = f.account(created[3]).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_PENDING,
        "the refused resolve wrote no status"
    );
    let doc = f.account(created[0]).await;
    assert_eq!(u16_at(&doc, 6) & FLAG_REFUTED, 0, "and no flag 4");
    assert_eq!(u32_at(&doc, 132), 0, "and no challenger win");
    // With DCM2 writable, as `RULE` requires, the same packet convicts.
    let writable = vec![
        AccountMeta::new(c.dcm2, false),
        AccountMeta::new(c.dcr2, false),
    ];
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        writable.clone(),
    )
    .await
    .expect("the conviction");
    let dcr2 = f.account(created[3]).await;
    let doc = f.account(created[0]).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_REFUTED,
        "status 2 REFUTED on a stop-rule violation"
    );
    assert_eq!(u64_at(&dcr2, 184), now, "status_slot := now");
    assert_eq!(u32_at(&dcr2, 192), 1, "DCR2 challenger_wins := 1");
    assert_eq!(
        u16_at(&doc, 6) & FLAG_REFUTED,
        FLAG_REFUTED,
        "DCM2 flag 4 is set"
    );
    assert_eq!(u32_at(&doc, 132), 1, "DCM2 challenger_wins += 1");
    // **`conviction_winner` is untouched**: a stop-rule conviction names nobody,
    // so DCR2 352 is 32 zero bytes and the tombstone carries no winner.
    assert_eq!(
        &dcr2[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32],
        &[0u8; 32],
        "a stop-rule conviction records no winner"
    );
    assert_eq!(
        &doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        &[0u8; 32],
        "and DCM2 530 is still zero: nothing named anybody"
    );
    // A second resolve is 796 and changes nothing: the "two stop violations on
    // one fault" case, which the status is not PENDING.
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                resolve_data(&descriptor),
                writable.clone()
            )
            .await
        ),
        RESULT_STATE,
        "a second resolve is 796"
    );
    let dcr2 = f.account(created[3]).await;
    let doc = f.account(created[0]).await;
    assert_eq!(u32_at(&dcr2, 192), 1, "challenger_wins stays at 1");
    assert_eq!(u32_at(&doc, 132), 1, "on DCM2 too");

    // (2) **Clause 2, `stopped early`**: `L = 10 < count = 50` and output 9 is
    // not the stop value. Nothing before it is a stop value either, so clause
    // 1 holds and clause 2 is the only one that can fire.
    let tokens = vec![(l - 1, 0x_00ff_fffeu32)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, n, &tokens, 11).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(&mut f, c.dcm2).await;
    let writable = vec![
        AccountMeta::new(c.dcm2, false),
        AccountMeta::new(c.dcr2, false),
    ];
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        writable,
    )
    .await
    .expect("the conviction");
    let dcr2 = f.account(created[3]).await;
    assert_eq!(dcr2[6], result::STATUS_REFUTED, "clause 2 convicts too");
    assert_eq!(u32_at(&dcr2, 192), 1);
    assert_eq!(
        &dcr2[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32],
        &[0u8; 32]
    );
}

/// **The opt-out and clause 2's escape**, both through the handler and both
/// with real attestations: a document that declares **no** stop value is FINAL
/// with any tokens at all, and a document that used every output it asked for
/// (`L = count`) is FINAL with no stop value in it.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_honours_the_opt_out_and_the_l_equals_count_escape() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let first = 29u32;
    // (1) `stop_plus_one = 0`: the rule is off, so the stop token appearing in
    // the middle of the outputs convicts nothing. `n = 33` gives `L = 3`.
    let off = f.binding_stop(first, 50, 0);
    let tokens = vec![(1u32, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &off, 33, &tokens, 12).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(&mut f, c.dcm2).await;
    let metas = f.resolve_metas(&c);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        metas,
    )
    .await
    .expect("the opt-out resolves FINAL");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_FINAL);

    // (2) `L = count = 50` at `n = 80`: clause 2's escape, so the last output
    // need not be the stop value. The document declares one, and does not use
    // it anywhere.
    let full = f.binding_stop(first, 50, STOP_PLUS_ONE);
    let (descriptor, created, _) = attest_all(&mut f, &full, 80, &[], 13).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(&mut f, c.dcm2).await;
    let metas = f.resolve_metas(&c);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        metas,
    )
    .await
    .expect("L = count resolves FINAL");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_FINAL);
    // The escape is the escape and not a gap: **the same document with
    // `L = 49 < count` is convicted**, because then output 48 has to be the stop
    // value and is not.
    let short = f.binding_stop(first, 50, STOP_PLUS_ONE);
    let (descriptor, created, _) = attest_all(&mut f, &short, 79, &[], 14).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(&mut f, c.dcm2).await;
    let writable = vec![
        AccountMeta::new(c.dcm2, false),
        AccountMeta::new(c.dcr2, false),
    ];
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        writable,
    )
    .await
    .expect("the conviction");
    assert_eq!(
        f.account(created[3]).await[6],
        result::STATUS_REFUTED,
        "one output short of count, the last output is not the stop value"
    );
}

/// **The decision document resolves FINAL at `L = 1 + option_count`**, over a
/// crafted record because the only sealed template in this tree has no 4-byte
/// write lane (the file header says so, and C1 measured it). Everything the
/// resolve reads is the program's own: the DRB1 v2 block, `positions_complete`,
/// the DCR2 v6 header, the five 4-byte cells and the five bitmap bits.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_is_final_on_a_decision_document() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    for k in [1u8, 4, 8, 80] {
        // `n = 30` is `first = 29` plus one, the smallest prompt this template's
        // own output lane can be a decision over; `L = 1 + K` does not move it.
        let n = 30u32;
        let (binding, options) = decision_binding(&f.executor.pubkey().to_bytes(), n, k);
        let l = binding.output_span(n);
        assert_eq!(l, 1 + k as u32, "L = 1 + option_count for a decision");
        assert_eq!(binding.output_count, l, "and count = L by 816");
        let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
        let roots = f.position_roots[..n as usize].to_vec();
        let c = f
            .craft_hand_built(&binding, n, &roots, 1, descriptor, &options)
            .await;
        // **A real `FinalizeDocumentV5`**, because the resolve's FINAL branch
        // reads DCM2 flag 2 and a crafted record does not carry it. 816's
        // decision branch is therefore exercised here too, over the real
        // handler: `n = prompt_positions`, `first = n - 1`, `count = 1 + K`.
        let fin = f.fin_metas(&c);
        send(
            &mut f.ctx,
            &f.executor,
            f.program,
            finalize_data(&descriptor, n, &f.family_roots),
            fin,
        )
        .await
        .unwrap_or_else(|e| panic!("a decision finalize at K = {k}: {e:?}"));
        assert_eq!(
            u16_at(&f.account(c.dcm2).await, 6) as u16,
            FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
            "flag 2 at K = {k}"
        );
        // **The five cells, the five bits and the counter**, written the way
        // `attest_v8` writes them. A decision's cells are 4-byte
        // fixed-point values, so there is no token field in them at all and
        // the stop rule has nothing to read — which is why it is not run.
        let mut res = f.account(c.dcr2).await;
        assert_eq!(
            res.len(),
            result::bytes_v8(binding.output_count, DECISION_WIDTH).unwrap(),
            "416 + 4(1+K) + ceil((1+K)/8)"
        );
        for i in 0..l {
            let at = result::HEADER_V6 + i as usize * DECISION_WIDTH as usize;
            res[at..at + 4].copy_from_slice(&(1_000_000u32 + i).to_le_bytes());
            res[result::HEADER_V6
                + binding.output_count as usize * DECISION_WIDTH as usize
                + i as usize / 8] |= 1 << (i % 8);
        }
        res[204..208].copy_from_slice(&l.to_le_bytes());
        f.ctx.set_account(&c.dcr2, &shared(owned(&f.program, res)));
        past_deadline(&mut f, c.dcm2).await;
        let metas = pair(c.dcm2, c.dcr2);
        send_fresh(
            &mut f.ctx,
            &f.signer,
            f.program,
            resolve_data(&descriptor),
            metas,
        )
        .await
        .unwrap_or_else(|e| panic!("a decision at K = {k} resolves: {e:?}"));
        let res = f.account(c.dcr2).await;
        assert_eq!(
            res[6],
            result::STATUS_FINAL,
            "a decision at K = {k} is FINAL at L = {l}"
        );
        // **One output short is a refusal, not a conviction.** A decision has
        // no clause to fall through to, so an incomplete one is 796.
        let mut res = f.account(c.dcr2).await;
        res[204..208].copy_from_slice(&(l - 1).to_le_bytes());
        f.ctx.set_account(&c.dcr2, &shared(owned(&f.program, res)));
        assert_eq!(
            custom(
                send_fresh(
                    &mut f.ctx,
                    &f.signer,
                    f.program,
                    resolve_data(&descriptor),
                    pair(c.dcm2, c.dcr2)
                )
                .await
            ),
            RESULT_STATE,
            "a decision with L-1 outputs attested is 796"
        );
        let _ = c;
    }
}

/// **Every new refusal of the revision-8 resolve, with its code**, over one
/// real document: a real init, landing, finalize and a full attestation at
/// `L = 3 < count = 50`, so each case below is a refusal *of a document that
/// otherwise resolves FINAL*.
///
/// The 796s are the clause's own: the FINAL condition is not met. The 580s are
/// the two accounts being something other than what the handler needs. The 794
/// is the DRB1 v2 block, which the resolve decodes with the same call init
/// does. The 598 is the checked `challenger_wins + 1`.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_refusals() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let first = 29u32;
    let binding = f.binding_stop(first, 50, STOP_PLUS_ONE);
    let (n, l) = (33u32, 3u32);
    let tokens = vec![(l - 1, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, n, &tokens, 11).await;
    let (dcm2, dcr2) = (created[0], created[3]);
    let base = pair(dcm2, dcr2);

    // **796, the window is not open**, in the order the handler reads them:
    // not past `dispute_deadline`, then a challenge still open, then DCM2
    // flag 2 clear (an unfinalized document, whose `positions_complete` is `n`
    // but whose FINAL condition is not the handler's to answer).
    assert_eq!(
        refused_resolve(&mut f, dcr2, resolve_data(&descriptor), base.clone()).await,
        RESULT_STATE,
        "now <= dispute_deadline is 796"
    );
    let good_doc = f.account(dcm2).await;
    assert_eq!(
        u16_at(&good_doc, 6) & FLAG_FINAL,
        FLAG_FINAL,
        "the fixture's document is finalized"
    );
    // An open challenge, for real: a second document whose first output the
    // challenger opens (166), past its deadline.
    let open_binding = Binding2 {
        request_id: [12u8; 32],
        ..binding
    };
    let (d_open, c_open, open_proofs) = attest_all(&mut f, &open_binding, n, &tokens, 12).await;
    let record = address::challenge(&f.program, &d_open, &f.signer.pubkey(), 41).0;
    let packet = challenge_leaf_packet(&f, &d_open, &open_proofs[0], 41);
    let metas = challenge_leaf_metas(&f, c_open, record);
    send_fresh(&mut f.ctx, &f.signer, f.program, packet, metas)
        .await
        .expect("the challenger opens a leaf challenge");
    assert_eq!(u32_at(&f.account(c_open[0]).await, 128), 1);
    past_deadline(&mut f, c_open[0]).await;
    assert_eq!(
        refused_resolve(&mut f, c_open[3], resolve_data(&d_open), pair(c_open[0], c_open[3])).await,
        RESULT_STATE,
        "an open challenge is 796"
    );
    // An unfinalized document, for real: landed to n, never finalized.
    let unfinal = Binding2 {
        request_id: [13u8; 32],
        ..binding
    };
    let (d_unfinal, c_unfinal) = f.run_document(&unfinal, n).await;
    past_deadline(&mut f, c_unfinal[0]).await;
    assert_eq!(
        refused_resolve(&mut f, c_unfinal[3], resolve_data(&d_unfinal), pair(c_unfinal[0], c_unfinal[3])).await,
        RESULT_STATE,
        "an unfinalized document is 796"
    );
    // The partial-bitmap clause (the counter either way, a clear bit inside
    // [0, L), a set bit at L, a padding bit, L > count), the checked
    // challenger_wins + 1 (598), and the malformed DCM2, DRB1 and DCR2 images
    // are states only a program bug could write: unit tests
    // (unified_v8_resolve_check.rs; result::reader_gate_tests;
    // document::drb1_decodes_and_refuses_cheats; owner decision 2026-10-02).
    past_deadline(&mut f, dcm2).await;

    // The attacker's DCM2: another real document passed in its place, 580.
    let elsewhere_binding = Binding2 {
        request_id: [14u8; 32],
        ..binding
    };
    let (_, c_else) = f.run_document(&elsewhere_binding, n).await;
    let mut metas = base.clone();
    metas[0] = AccountMeta::new_readonly(c_else[0], false);
    assert_eq!(
        refused_resolve(&mut f, dcr2, resolve_data(&descriptor), metas).await,
        CL_MALFORMED,
        "the account's key is PDA(descriptor)"
    );

    let good_res = f.account(dcr2).await;
    assert_eq!(
        good_res[4..6],
        6u16.to_le_bytes(),
        "the fixture's DCR2 is a v6"
    );
    // A caller's read-only DCR2 meta, 580.
    assert_eq!(
        refused_resolve(
            &mut f,
            dcr2,
            resolve_data(&descriptor),
            vec![
                AccountMeta::new_readonly(dcm2, false),
                AccountMeta::new_readonly(dcr2, false)
            ]
        )
        .await,
        CL_MALFORMED,
        "a read-only DCR2 is 580 at view_v8"
    );

    // **The data and the account list are the frozen ones**: 33 bytes, two
    // accounts, and the descriptor.
    assert_eq!(resolve_data(&descriptor).len(), 33);
    let mut long_data = resolve_data(&descriptor);
    long_data.push(0);
    assert_eq!(
        refused_resolve(&mut f, dcr2, long_data, base.clone()).await,
        CL_MALFORMED,
        "34 bytes is 580"
    );
    let mut wrong = resolve_data(&descriptor);
    wrong[1] ^= 1;
    assert_eq!(
        refused_resolve(&mut f, dcr2, wrong, base.clone()).await,
        CL_MALFORMED,
        "a wrong descriptor is 580"
    );
    assert_eq!(
        refused_resolve(&mut f, dcr2, vec![TAG_RESOLVE_RESULT], base.clone()).await,
        CL_MALFORMED,
        "an empty data buffer is 580"
    );
    let one = base[0].clone();
    let two = base[1].clone();
    assert_eq!(
        refused_resolve(&mut f, dcr2, resolve_data(&descriptor), vec![one.clone()]).await,
        CL_MALFORMED,
        "one account is 580"
    );
    assert_eq!(
        refused_resolve(
            &mut f,
            dcr2,
            resolve_data(&descriptor),
            vec![one.clone(), two.clone(), two.clone()]
        )
        .await,
        CL_MALFORMED,
        "three accounts is 580"
    );
    // And the untouched record resolves FINAL, which is what makes every 796
    // and 580 above a refusal of a resolvable document.
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        base.clone(),
    )
    .await
    .expect("the honest record resolves");
    assert_eq!(f.account(dcr2).await[6], result::STATUS_FINAL);
    // A resolved record does not resolve again, for real: 796 at FINAL.
    assert_eq!(
        refused_resolve(&mut f, dcr2, resolve_data(&descriptor), pair(dcm2, dcr2)).await,
        RESULT_STATE,
        "a record at status FINAL is 796"
    );
    // A really convicted document does not resolve again either: 796 at
    // REFUTED. Closed, SETTLED and half-grown records are the state gate's
    // unit test (result::reader_gate_tests): a closed record's DCM2 is gone,
    // so no real resolve reaches that branch.
    let convicted = convicted_by_resolve(&mut f, 16).await;
    assert_eq!(
        refused_resolve(
            &mut f,
            convicted.dcr2,
            resolve_data(&convicted.descriptor),
            pair(convicted.dcm2, convicted.dcr2)
        )
        .await,
        RESULT_STATE,
        "a record at status REFUTED is 796"
    );

}

/// **The skip the close needs, over real accounts.** A document that a separate
/// `ResolveResultV5` has already resolved FINAL is **not re-evaluated** by the
/// clause: the status is FINAL, so `resolve_check` answers `AlreadyFinal`
/// without reading a cell — including on a record whose cells have *since* been
/// made inconsistent, which is the strongest form of the claim.
///
/// The same record, taken back to PENDING, is convicted by the identical
/// clause, so the skip is the skip and not a weaker test.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_skips_a_record_that_is_already_final() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let first = 29u32;
    let binding = f.binding_stop(first, 50, STOP_PLUS_ONE);
    let (n, l) = (33u32, 3u32);
    let tokens = vec![(l - 1, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, n, &tokens, 41).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    past_deadline(&mut f, c.dcm2).await;
    let metas = f.resolve_metas(&c);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        metas.clone(),
    )
    .await
    .expect("the honest resolve");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_FINAL);

    // The clause, read straight off the landed record, says `AlreadyFinal`.
    let res = f.account(created[3]).await;
    let b = Binding2::decode(
        &f.account(created[0]).await
            [document::BINDING_AT_V8..document::BINDING_AT_V8 + BINDING_BYTES_V8],
    )
    .unwrap();
    assert_eq!(
        result::resolve_check(&b, n, u32_at(&res, 196), u32_at(&res, 204), res[6], &res),
        Ok(result::Verdict::AlreadyFinal)
    );

    // Now break the record in the way that would convict it, and ask again.
    // The handler refuses a non-PENDING record with 796, so the claim under
    // test is the **clause's**, which is what the close calls.
    let mut broken = res.clone();
    broken[result::HEADER_V6 + 8..result::HEADER_V6 + 16]
        .copy_from_slice(&(STOP_PLUS_ONE as u64 - 1).to_le_bytes());
    assert_eq!(
        result::resolve_check(
            &b,
            n,
            u32_at(&broken, 196),
            u32_at(&broken, 204),
            broken[6],
            &broken
        ),
        Ok(result::Verdict::AlreadyFinal),
        "the skip reads nothing, so a broken cell does not matter"
    );
    let mut pending = broken.clone();
    pending[6] = result::STATUS_PENDING;
    assert_eq!(
        result::resolve_check(
            &b,
            n,
            u32_at(&pending, 196),
            u32_at(&pending, 204),
            pending[6],
            &pending
        ),
        Ok(result::Verdict::Violated),
        "the same bytes, PENDING, are convicted"
    );
    // And the handler refuses a second resolve of the real FINAL record, so
    // nothing opens a second status write. (The broken bytes above are a state
    // only a program bug could write, so they stay off the bank: the clause's
    // own answers on them are the claim.)
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                resolve_data(&descriptor),
                metas
            )
            .await
        ),
        RESULT_STATE,
        "a second resolve of a FINAL record is 796"
    );
}

/// **The resolve at the capacity ceiling, `L = 10,240`, measured.** This is the
/// number §9.10's C1 Medium asks for: at `L = 10,240` the close pays the whole
/// of `ResolveResultV5` on top of its own work, and a fully attested document
/// that can never close has no exit at all (row 3 does not apply to it, because
/// row 3 is `outputs_attested < L`).
///
/// The record is **crafted**, and labelled: the honest attest of 10,240 outputs
/// is 10,240 transactions and 10,240 re-keyed proofs, which is not this slice.
/// Everything the resolve reads is the program's own and is the value the attest
/// would have left — `count = L = 10,240`, 16-byte cells, all `10,240` bitmap
/// bits, `outputs_attested = 10,240`, and a DRB1 v2 with `first = 29` and
/// `stop_plus_one` declared. `L = count`, so clause 2's escape applies and the
/// honest answer is FINAL; clause 1 still scans the whole `[0, L-1)`, which is
/// the term the arithmetic below is about.
///
/// **The CU this test reports has a run-to-run band, and only its differences
/// are stable.** One instruction is the first in its bank, so it pays the
/// program load, the account-data serialization and the blockhash work, and
/// those move with machine load: four runs of one image gave the `L = 10,240`
/// row as 235,333 / 238,333 / 233,833 / 236,833 CU. The **same-record** rows are
/// the measurement — one 165,536-byte record, one bitmap, only `L` varying — and
/// the clause's two terms come out of them exactly: **20.378 CU per 16-byte cell
/// compared** in all eight quotients, and **227,916 CU** for the whole clause at
/// the ceiling in all four runs. The `L = 1` and `L = 5,120` rows are there to
/// make that isolation possible, and the last row is the skip on the same
/// record. Design note §9.12 has the four runs and the arithmetic.
///
/// `send_fresh` prints the CU with the mode it was measured in, so the same test
/// is the native figure and — under `BASANOS_DCG_V8_SBF=1` with `BPF_OUT_DIR`
/// naming an SBF image — the SBF one.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_resolve_cu_at_l_10240() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let first = 29u32;
    // Two families of cases, because a single instruction is the first in its
    // bank and so pays the program load and the account serialization: only a
    // **same-record** pair isolates the clause. `(1, 10240)` and `(10240,
    // 10240)` share one 165,536-byte record, so the difference between them is
    // the stop-rule scan and nothing else. The smaller counts sweep the bitmap
    // term. The last case is the **already-FINAL skip** on the same record: the
    // figure a close pays when a separate `ResolveResultV5` has already run.
    for (l, count) in [
        (1u32, 1u32),
        (1, 10),
        (1, 100),
        (1, 1_000),
        (1, 10_240),
        (5_120, 10_240),
        (10_240, 10_240),
    ] {
        let binding = f.binding_stop(first, count, STOP_PLUS_ONE);
        // `L = n - 1 - first`, so `n` is the document's own length.
        let n = first + l + 1;
        assert_eq!(binding.output_span(n), l, "L = n - 1 - first");
        let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
        // A DCM2 v7 with the fields the resolve reads: flag 2, `n` at 84, no
        // open challenge at 128, and a `dispute_deadline` of 0 so the clock is
        // past it without a warp.
        let terms = Terms2::decode(&f.terms_raw).unwrap();
        let doc = dcm2_v7(
            &f.program,
            &descriptor,
            &f.executor.pubkey().to_bytes(),
            f.k,
            n,
            FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
            &f.terms_raw,
            &binding.encode(),
            &f.pt2s.to_bytes(),
            &f.pt2s_sha,
            &f.dea2.to_bytes(),
            &f.drp2.to_bytes(),
            &f.reg_root,
            16,
            0,
            0,
        );
        let dcm2 = address::document(&f.program, &descriptor).0;
        let dcr2 = address::result(&f.program, &descriptor).0;
        f.ctx.set_account(&dcm2, &shared(owned(&f.program, doc)));
        // The DCR2 v6 as `attest_v8` would have left it: `L` cells, `L` bits,
        // and the counter. The trailing cells of `[L, count)` stay zero, which
        // is the consumer's invariant and is asserted below.
        let mut res = dcr2_v6(&f.program, &descriptor, &binding, &terms);
        assert_eq!(res.len(), result::bytes_v8(count, 16).unwrap());
        let bitmap_at = result::HEADER_V6 + count as usize * 16;
        for i in 0..l as usize {
            let at = result::HEADER_V6 + i * 16;
            res[at..at + 8].copy_from_slice(&(-1i64).to_le_bytes());
            // **The declared stop value at `L-1` and nowhere else**, so the
            // document is honest: with `L < count` clause 2 wants it there, and
            // with `L = count` clause 2 is escaped and it makes no difference.
            let token = if i == l as usize - 1 {
                STOP_PLUS_ONE as u64 - 1
            } else {
                0x_00ff_fffe
            };
            res[at + 8..at + 16].copy_from_slice(&token.to_le_bytes());
            res[bitmap_at + i / 8] |= 1 << (i % 8);
        }
        res[204..208].copy_from_slice(&l.to_le_bytes());
        f.ctx.set_account(&dcr2, &shared(owned(&f.program, res)));
        let read = f.account(dcr2).await;
        for i in l as usize..count as usize {
            assert!(
                read[result::HEADER_V6 + i * 16..result::HEADER_V6 + (i + 1) * 16]
                    .iter()
                    .all(|b| *b == 0),
                "the trailing cell {i} of [L, count) is zero"
            );
        }
        let clock = f
            .ctx
            .banks_client
            .get_sysvar::<solana_program::clock::Clock>()
            .await
            .unwrap()
            .slot;
        assert!(clock > 0, "past the deadline of 0");
        let before = read.len();
        send_fresh(
            &mut f.ctx,
            &f.signer,
            f.program,
            resolve_data(&descriptor),
            pair(dcm2, dcr2),
        )
        .await
        .unwrap_or_else(|e| panic!("resolve at L = {l}, count = {count}: {e:?}"));
        let after = f.account(dcr2).await;
        assert_eq!(
            after[6],
            result::STATUS_FINAL,
            "L = {l} at count = {count} is FINAL"
        );
        assert_eq!(after.len(), before, "the record did not change size");
        eprintln!(
            "RESOLVE-CU L={l} count={count} width=16 record={before} cells={} bitmap={} skip=false",
            count as usize * 16,
            count.div_ceil(8)
        );
    }
    // **A record that is already FINAL, re-sent: the cost of a resolve the
    // handler REFUSES.** The handler's first test is "not PENDING", so this
    // instruction stops with 796 **before `resolve_check` runs at all** -- the
    // figure below is a refused resolve on the same 165,536-byte record, *not* a
    // measurement of the clause's `AlreadyFinal` skip. The clause's own answer on
    // these bytes is asserted immediately afterwards by calling `resolve_check`
    // directly (it is `AlreadyFinal`, on one compare, with no cell and no bitmap
    // byte read), and **the skip's cost inside a close is still unmeasured**:
    // pricing it needs a close, which is stream C4's slice. Design note §9.12
    // carries the correction and what it does and does not move.
    let (l, count) = (10_240u32, 10_240u32);
    let binding = f.binding_stop(first, count, STOP_PLUS_ONE);
    let n = first + l + 1;
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let terms = Terms2::decode(&f.terms_raw).unwrap();
    let doc = dcm2_v7(
        &f.program,
        &descriptor,
        &f.executor.pubkey().to_bytes(),
        f.k,
        n,
        FLAG_ARMED | FLAG_FINAL | FLAG_ROOT_ONLY | FLAG_SEALED,
        &f.terms_raw,
        &binding.encode(),
        &f.pt2s.to_bytes(),
        &f.pt2s_sha,
        &f.dea2.to_bytes(),
        &f.drp2.to_bytes(),
        &f.reg_root,
        16,
        0,
        0,
    );
    let dcm2 = address::document(&f.program, &descriptor).0;
    let dcr2 = address::result(&f.program, &descriptor).0;
    f.ctx.set_account(&dcm2, &shared(owned(&f.program, doc)));
    let mut res = dcr2_v6(&f.program, &descriptor, &binding, &terms);
    let bitmap_at = result::HEADER_V6 + count as usize * 16;
    for i in 0..l as usize {
        let at = result::HEADER_V6 + i * 16;
        res[at + 8..at + 16].copy_from_slice(&(STOP_PLUS_ONE as u64 - 1).to_le_bytes());
        res[bitmap_at + i / 8] |= 1 << (i % 8);
    }
    res[204..208].copy_from_slice(&l.to_le_bytes());
    res[6] = result::STATUS_FINAL;
    f.ctx.set_account(&dcr2, &shared(owned(&f.program, res)));
    let before = f.account(dcr2).await;
    // The handler refuses a non-PENDING record with 796, which is correct, so
    // **the figure above is that refusal** and the clause's verdict is read off
    // the same bytes by calling it directly, which is the assertion below.
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                resolve_data(&descriptor),
                pair(dcm2, dcr2)
            )
            .await
        ),
        RESULT_STATE,
        "a FINAL record is not re-resolved"
    );
    let raw = f.account(dcr2).await;
    assert_eq!(
        result::resolve_check(&binding, n, count, l, raw[6], &raw),
        Ok(result::Verdict::AlreadyFinal)
    );
    eprintln!(
        "RESOLVE-CU L={l} count={count} width=16 record={} cells={} bitmap={} skip=true",
        before.len(),
        count as usize * 16,
        count.div_ceil(8)
    );
}

// ============================ tag 176 and tag 172: the seal's new work and the close

/// The four new refusals this slice answers, and the three that are new codes
/// on an old instruction.
const CL_CLOSE: u32 = 599;
const CAUSE_CONVICTION: u8 = 4;
const CAUSE_WITHHELD: u8 = 5;
const REGISTRY_ACCOUNT: u32 = 770;
/// The revision-8 seal's actions, as this file drives them.
const SEAL_REVOKED: u8 = 2;
const SEAL_RETIRED: u8 = 3;

fn close_data(descriptor: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![TAG_CLOSE_DOCUMENT];
    out.extend_from_slice(descriptor);
    out
}

macro_rules! refused_here {
    ($f:ident, $data:expr, $metas:expr, $want:expr) => {
        match send_fresh(&mut $f.ctx, &$f.signer, $f.program, $data, $metas).await {
            Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
                assert_eq!(code, $want, "the wrong refusal code")
            }
            other => panic!("expected a custom refusal at {}, got {other:?}", line!()),
        }
    };
}

/// tag 172's **42-byte action-1** seal data, the five limits in the order
/// DTU1 stores them.
fn seal_data(action: u8, limits: &TemplateLimits) -> Vec<u8> {
    let mut out = vec![TAG_TEMPLATE_SEAL, action];
    if action == config::SEAL_APPROVED {
        out.extend_from_slice(&limits.encode());
        assert_eq!(out.len(), config::SEAL_DATA_APPROVE);
    } else {
        assert_eq!(out.len(), config::SEAL_DATA_ADMIN);
    }
    out
}

impl Fix {
    /// A tiny sealed PT2S used only to derive a different DTU1 address in a
    /// malformed-close case. It never passes a protocol handler.
    fn sealed_pt2s(
        &self,
        routes: &Pubkey,
        payloads: &Pubkey,
        capacity: u32,
        width: u8,
    ) -> (Pubkey, Vec<u8>) {
        let mut image = vec![0u8; S::OFF_PWR1];
        image[..4].copy_from_slice(S::MAGIC);
        image[S::OFF_STATE] = S::STATE_SEALED;
        image[S::OFF_AUTHORITY..S::OFF_AUTHORITY + 32]
            .copy_from_slice(self.executor.pubkey().as_ref());
        for (i, key) in [routes, &self.geometry, payloads].into_iter().enumerate() {
            image[S::OFF_KEYS + 32 * i..S::OFF_KEYS + 32 * (i + 1)].copy_from_slice(key.as_ref());
        }
        image[S::OFF_CLAUSE12..S::OFF_CLAUSE12 + 43]
            .copy_from_slice(&crate::pt2p::encode_clause12_v4(capacity, 7, &[3u8; 32]));
        image[S::OFF_PT1S..S::OFF_PT1S + 32].copy_from_slice(self.pt1s_index.as_ref());
        image[S::OFF_LOCATOR..S::OFF_LOCATOR + 4].copy_from_slice(&28_037u32.to_le_bytes());
        image[S::OFF_LOCATOR + 5] = width;
        (Pubkey::new_unique(), image)
    }

    /// The DFS2 the close checks (`owner`, derived key, writable) and nothing
    /// else: the close reads no family table. The honest image is built anyway,
    /// from the fixture's own body.
    async fn install_dfs2(&mut self, c: &Crafted) {
        let key = address::family_slots(&self.program, &c.descriptor).0;
        let mut fam = vec![0u8; document::DFS2_HEADER];
        fam[..4].copy_from_slice(b"DFS2");
        fam[4..6].copy_from_slice(&1u16.to_le_bytes());
        fam[8..40].copy_from_slice(&c.descriptor);
        fam[40..42].copy_from_slice(&16u16.to_le_bytes());
        fam[42] = 7;
        fam[44..48].copy_from_slice(&(self.family_body.len() as u32).to_le_bytes());
        fam.extend_from_slice(&self.family_body);
        self.ctx
            .set_account(&key, &shared(owned(&self.program, fam)));
    }

    /// tag 172's nine metas under the **CUSTOM** kind: the two kind-dependent
    /// metas are the bond escrow and the system program, and the payer is DCM2
    /// 40..72 (the fixture's executor, which is also the init signer).
    fn close_metas(&self, c: &Crafted, signer: Pubkey) -> Vec<AccountMeta> {
        let escrow = address::bond_escrow(&self.program, &c.descriptor).0;
        self.close_metas_slots(
            c,
            signer,
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(SYSTEM, false),
        )
    }

    /// tag 172's nine metas with the two kind-dependent slots given as whole
    /// `AccountMeta`s, because **their writability differs by kind**: under
    /// CUSTOM the tail is the system program (read-only) and under STANDARD it
    /// is the remainder destination (writable), and a read-only destination is
    /// refused 580 by the credit rule; a read-only CUSTOM escrow is 798.
    fn close_metas_slots(
        &self,
        c: &Crafted,
        signer: Pubkey,
        aux: AccountMeta,
        tail: AccountMeta,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(signer, true),
            AccountMeta::new(c.dcm2, false),
            AccountMeta::new(c.dpr2, false),
            AccountMeta::new(address::family_slots(&self.program, &c.descriptor).0, false),
            AccountMeta::new(c.dcr2, false),
            AccountMeta::new(self.executor.pubkey(), false),
            AccountMeta::new(self.dtu1, false),
            aux,
            tail,
            AccountMeta::new(incinerator::ID, false),
        ]
    }

    async fn lamports(&mut self, key: Pubkey) -> u64 {
        self.ctx
            .banks_client
            .get_account(key)
            .await
            .unwrap()
            .map(|a| a.lamports)
            .unwrap_or(0)
    }
}

/// Set the bank clock to an explicit slot, the way [`past_deadline`] sets it to
/// a computed one. The clock is a sysvar, so this moves it with no root and the
/// program's own `Clock::get()` sees it.
async fn clock_to(f: &mut Fix, slot: u64) -> u64 {
    let mut clock = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap();
    if clock.slot != slot {
        clock.slot = slot;
        f.ctx.set_sysvar(&clock);
    }
    f.ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot
}

/// PENDING MIGRATION (rule 6): see `Fix::craft_hand_built`.
/// A crafted document with the pot **funded on top of the rent**, which is the
/// shape `UnifiedInit` leaves (it transfers `executor_bond_lamports` over the
/// rent-exempt minimum), plus its DFS2.
async fn closable_hand_built(
    f: &mut Fix,
    binding: &Binding2,
    n: u32,
    roots: &[[u8; 32]],
    variant: u8,
) -> Crafted {
    let binding = Binding2 {
        request_id: [variant; 32],
        ..*binding
    };
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let c = f.craft_hand_built(&binding, n, roots, 0, descriptor, &[]).await;
    let pot = Terms2::decode(&f.terms_raw).unwrap().executor_bond_lamports;
    let doc = f.account(c.dcm2).await;
    f.ctx.set_account(
        &c.dcm2,
        &shared(Account {
            lamports: (128 + doc.len() as u64) * 6_960 + pot + 7,
            data: doc,
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    f.install_dfs2(&c).await;
    // A real `UnifiedInit` incremented the counter and no real close has run, so
    // a crafted document a close can act on is at one, not zero.
    let mut use_record = f.account(f.dtu1).await;
    use_record[8..12].copy_from_slice(&1u32.to_le_bytes());
    f.ctx
        .set_account(&f.dtu1, &shared(owned(&f.program, use_record)));
    c
}

/// A real document a close can act on: UnifiedInit (which transfers
/// `executor_bond_lamports` over the rent-exempt minimum, increments DTU1 and
/// writes the family slots) and LandPositionRoots.
async fn closable(
    f: &mut Fix,
    binding: &Binding2,
    n: u32,
    roots: &[[u8; 32]],
    variant: u8,
) -> Crafted {
    let binding = Binding2 {
        request_id: [variant; 32],
        ..*binding
    };
    let descriptor = f.descriptor(&binding, &f.terms_raw, 16);
    let c = f.craft(&binding, n, roots, 0, descriptor).await;
    // Real init transferred the pot, incremented DTU1 and wrote the family
    // slots; nothing is patched on top (rule 6).
    c
}

/// **The four honest closes, one per row of §1.3's table, each signed by a
/// stranger** — the fixture's second keypair, which is not the executor, not the
/// payer and not the template's authority. Every one of them pays the **recorded
/// payer** (DCM2 40..72) and not the closer, drops `DTU1.documents` by one, and
/// leaves DCR2 `document_closed = 1` with the retention clock started.
///
/// | row | document | status written | bond |
/// |---|---|---|---|
/// | 1 | finalized, the FINAL condition met | `SETTLED` (3) | returned |
/// | 1 | finalized, the stop rule violated | `REFUTED` (2) | the policy, `cause = 4` |
/// | 2 | unfinalized, past `abandon_deadline` | unchanged (`PENDING`) | returned |
/// | 3 | finalized, `outputs_attested < L` | **`WITHHELD` (4)** | the policy, `cause = 5` |
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_pays_the_payer_and_drops_the_counter_on_every_row() {
    let Some(mut f) = build().await else { return };
    let stranger = f.signer.pubkey();
    let payer = f.executor.pubkey();
    let first = 29u32;
    let binding = f.binding_stop(first, 50, STOP_PLUS_ONE);
    // --- Row 1, the FINAL condition met. A real document: real init, land,
    // finalize and three real attestations, with the stop token at `L-1` and
    // nowhere before it.
    let tokens: Vec<(u32, u32)> = vec![(2, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, 33, &tokens, 61).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    f.install_dfs2(&c).await;
    assert_eq!(
        u32_at(&f.account(f.dtu1).await, 8),
        1,
        "the real init incremented the counter"
    );
    let slot = past_deadline(&mut f, c.dcm2).await;
    let before = f.lamports(payer).await;
    let in_three = f.lamports(c.dcm2).await
        + f.lamports(c.dpr2).await
        + f.lamports(address::family_slots(&f.program, &descriptor).0)
            .await;
    let metas = f.close_metas(&c, stranger);
    label("row1-settled-check");
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&descriptor),
        metas.clone(),
    )
    .await
    .expect("row 1: a stranger closes an honest FINAL document");
    let dcr2 = f.account(c.dcr2).await;
    assert_eq!(dcr2[6], result::STATUS_SETTLED, "row 1 writes SETTLED");
    assert_eq!(dcr2[7], 1, "document_closed");
    assert_eq!(
        u64_at(&dcr2, result::RETENTION_START_AT_V6),
        slot,
        "retention_start := now"
    );
    assert_eq!(
        u64_at(&dcr2, result::RETENTION_DEADLINE_AT_V6),
        slot + 2_592_000
    );
    assert_eq!(
        dcr2[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32],
        [0u8; 32],
        "no winner"
    );
    assert_eq!(
        dcr2[result::BOND_STATE_AT_V6],
        BOND_RETURNED,
        "a SETTLED close returns the bond"
    );
    assert_eq!(
        dcr2[result::BOND_CAUSE_AT_V6],
        0,
        "and the policy did not run"
    );
    assert_eq!(
        u32_at(&f.account(f.dtu1).await, 8),
        0,
        "DTU1.documents fell by one"
    );
    assert_eq!(
        f.lamports(payer).await,
        before + in_three,
        "every lamport of DCM2, DPR2 and DFS2 came back to the payer"
    );
    assert!(
        f.ctx
            .banks_client
            .get_account(address::bond_escrow(&f.program, &descriptor).0)
            .await
            .unwrap()
            .is_none(),
        "a SETTLED close creates no escrow"
    );
    assert!(
        f.ctx
            .banks_client
            .get_account(c.dcm2)
            .await
            .unwrap()
            .is_none(),
        "DCM2 was drained to zero and the runtime removed it"
    );
    // A second close is 599 on the surviving DCR2, whatever else is gone -- and
    // DCM2 *is* gone, which is why this one cannot compare the records before
    // and after: the whole instruction refuses before it reads anything.
    let metas = f.close_metas(&c, stranger);
    refused_here!(f, close_data(&descriptor), metas, CL_CLOSE);

    // --- Row 1, the stop rule violated by clause 1: the stop value inside
    // `[0, L-2)`. The close convicts in its own transaction, and the observable
    // record of that is DCR2's status and the escrow.
    let tokens: Vec<(u32, u32)> = vec![(0, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, 33, &tokens, 63).await;
    let c2 = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    f.install_dfs2(&c2).await;
    let slot = past_deadline(&mut f, c2.dcm2).await;
    let payer_before = f.lamports(payer).await;
    let in_three = f.lamports(c2.dcm2).await
        + f.lamports(c2.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c2.descriptor).0)
            .await;
    let metas = f.close_metas(&c2, stranger);
    label("row1-convicted-escrow");
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&descriptor),
        metas,
    )
    .await
    .expect("row 1: the close convicts a stop-rule violation");
    let dcr2 = f.account(c2.dcr2).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_REFUTED,
        "a violation convicts inside the close"
    );
    assert_eq!(
        dcr2[result::BOND_STATE_AT_V6],
        document::BOND_ESCROWED,
        "the pot is escrowed"
    );
    assert_eq!(
        dcr2[result::BOND_CAUSE_AT_V6],
        CAUSE_CONVICTION,
        "cause 4, a conviction"
    );
    assert_eq!(u64_at(&dcr2, result::RETENTION_START_AT_V6), slot);
    let pot = Terms2::decode(&f.terms_raw).unwrap().executor_bond_lamports;
    let escrow = address::bond_escrow(&f.program, &descriptor).0;
    assert_eq!(
        f.lamports(escrow).await,
        pot,
        "the whole pot arrived in the escrow"
    );
    assert_eq!(
        f.lamports(payer).await,
        payer_before + in_three - pot,
        "the payer received the rent and not one lamport of the pot"
    );
    assert_eq!(u32_at(&f.account(f.dtu1).await, 8), 0);

    // --- Row 2: unfinalized and past its own production deadline. The status is
    // left exactly as revision 7 leaves it, and the bond returns.
    let roots = f.position_roots[..33].to_vec();
    let c3 = {
        let b = f.binding_stop(first, 50, STOP_PLUS_ONE);
        closable(&mut f, &b, 33, &roots, 64).await
    };
    clock_to(&mut f, 6_000_000).await;
    let payer_before = f.lamports(payer).await;
    let in_three = f.lamports(c3.dcm2).await
        + f.lamports(c3.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c3.descriptor).0)
            .await;
    let metas = f.close_metas(&c3, stranger);
    label("row2-unfinalized-returned");
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c3.descriptor),
        metas,
    )
    .await
    .expect("row 2: anyone closes an abandoned document");
    let dcr2 = f.account(c3.dcr2).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_PENDING,
        "row 2 leaves the status alone"
    );
    assert_eq!(dcr2[7], 1);
    assert_eq!(
        dcr2[result::BOND_STATE_AT_V6],
        BOND_RETURNED,
        "N10: the bond returns"
    );
    assert_eq!(dcr2[result::BOND_CAUSE_AT_V6], 0);
    assert_eq!(
        f.lamports(payer).await,
        payer_before + in_three,
        "every lamport came back"
    );
    assert_eq!(u32_at(&f.account(f.dtu1).await, 8), 0);

    // --- Row 3: finalized, unrefuted, and never fully attested. `WITHHELD`,
    // the policy, and cause 5.
    let c4 = {
        let b = f.binding_stop(first, 50, STOP_PLUS_ONE);
        closable(&mut f, &b, 33, &roots, 65).await
    };
    // A real finalize (no flag patch), then the clock past both of this
    // document's own deadlines.
    let metas = f.fin_metas(&c4);
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        finalize_data(&c4.descriptor, 33, &f.family_roots),
        metas,
    )
    .await
    .expect("row 3: a real finalize");
    let doc = f.account(c4.dcm2).await;
    let past = u64_at(&doc, 144).max(u64_at(&doc, document::ABANDON_DEADLINE_AT)) + 1;
    clock_to(&mut f, past).await;
    let payer_before = f.lamports(payer).await;
    let in_three = f.lamports(c4.dcm2).await
        + f.lamports(c4.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c4.descriptor).0)
            .await;
    let metas = f.close_metas(&c4, stranger);
    label("row3-withheld-escrow");
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c4.descriptor),
        metas.clone(),
    )
    .await
    .expect("row 3: a withheld document is closable");
    let dcr2 = f.account(c4.dcr2).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_WITHHELD,
        "row 3 writes WITHHELD, never SETTLED"
    );
    assert_eq!(dcr2[result::BOND_STATE_AT_V6], document::BOND_ESCROWED);
    assert_eq!(
        dcr2[result::BOND_CAUSE_AT_V6],
        CAUSE_WITHHELD,
        "cause 5, a withholding"
    );
    assert_eq!(
        dcr2[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32],
        [0u8; 32],
        "a document nobody attested was never convicted"
    );
    let pot = Terms2::decode(&f.terms_raw).unwrap().executor_bond_lamports;
    assert_eq!(
        f.lamports(address::bond_escrow(&f.program, &c4.descriptor).0)
            .await,
        pot
    );
    assert_eq!(
        f.lamports(payer).await,
        payer_before + in_three - pot,
        "the pot does not reach the payer"
    );
    assert_eq!(u32_at(&f.account(f.dtu1).await, 8), 0);
    refused_here!(f, close_data(&c4.descriptor), metas, CL_CLOSE);
}

/// One instruction sent with explicit metas, returning the custom code it
/// refused with. The file's other `refusal` helper renders a `ProgramError` by
/// name, which is what tag 145 needs and what a `Custom(_)` does not.
async fn refused_with(f: &mut Fix, data: Vec<u8>, metas: Vec<AccountMeta>) -> u32 {
    match send_fresh(&mut f.ctx, &f.signer, f.program, data, metas).await {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => code,
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}

/// The same, with the expectation in the message, so a failure names the case
/// (the panic carries the callee's line, which is not the call's).
async fn refused_as(f: &mut Fix, data: Vec<u8>, metas: Vec<AccountMeta>, want: u32) {
    match send_fresh(&mut f.ctx, &f.signer, f.program, data, metas).await {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => {
            assert_eq!(code, want, "the wrong refusal code")
        }
        other => panic!("expected a custom refusal, got {other:?}"),
    }
}

/// One close sent against a crafted document, returning the code it refused
/// with. **A refused close must write nothing**, so the two records the close
/// touches are compared before and after.
async fn refused_close(f: &mut Fix, c: &Crafted, signer: Pubkey, variant: u8) -> u32 {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let _ = variant;
    let (dcm2_before, dcr2_before, dtu1_before) = (
        f.account(c.dcm2).await,
        f.account(c.dcr2).await,
        f.account(f.dtu1).await,
    );
    let metas = f.close_metas(c, signer);
    let code = match send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        metas,
    )
    .await
    {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => code,
        other => panic!("refusal #{seq}: expected a custom refusal, got {other:?}"),
    };
    assert_eq!(
        dcm2_before,
        f.account(c.dcm2).await,
        "refusal #{seq}: DCM2 is untouched"
    );
    assert_eq!(
        dcr2_before,
        f.account(c.dcr2).await,
        "refusal #{seq}: DCR2 is untouched"
    );
    assert_eq!(
        dtu1_before,
        f.account(f.dtu1).await,
        "refusal #{seq}: the counter is untouched"
    );
    code
}

/// **The skip, and what it is worth.** A record that a real
/// `ResolveResultV5` has already made FINAL is closed with one output's cell
/// rewritten into a *violation* — which a re-evaluation would convict. The close
/// writes `SETTLED` anyway, because the clause's first statement is
/// `status == FINAL ⇒ AlreadyFinal` and no cell is read (spec §1.3 (iv)).
///
/// The comparison the clause's soundness rests on, stated as the test states it:
/// `L` is a function of `n` and of the DRB1 v2 block, finalize is refused 592
/// after flag 2 is set, and an attest only sets bits below `L` — so a record
/// that reached FINAL cannot stop satisfying the condition.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_skips_a_record_that_is_already_final() {
    let Some(mut f) = build().await else { return };
    f.terms_raw = f.terms_window(1);
    let binding = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let tokens: Vec<(u32, u32)> = vec![(2, STOP_PLUS_ONE - 1)];
    let (descriptor, created, _) = attest_all(&mut f, &binding, 33, &tokens, 71).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    // A real resolve first: the challenger's route, and the only thing that
    // writes `status = 1`.
    let slot = past_deadline(&mut f, c.dcm2).await;
    let metas = f.resolve_metas(&c);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        metas,
    )
    .await
    .expect("resolve");
    assert_eq!(f.account(c.dcr2).await[6], result::STATUS_FINAL);
    // The record's bytes with a violation forged into an **attested** cell:
    // output 0 becomes the stop value, which is clause 1 (a stop value in
    // `[0, L-2)` = `[0, 2)`). Only a program bug could write these bytes, so
    // they stay off the bank; the clause's answers on them are the claim, and
    // the close below runs on the real FINAL record.
    let mut dcr2 = f.account(c.dcr2).await;
    let cell = result::HEADER_V6;
    dcr2[cell + 8..cell + 16].copy_from_slice(&((STOP_PLUS_ONE - 1) as u64).to_le_bytes());
    // Without the skip this record convicts, which is the control: the same
    // clause over the same fields on a PENDING status.
    assert_eq!(
        result::resolve_check(&binding, 33, 50, 3, result::STATUS_PENDING, &dcr2),
        Ok(result::Verdict::Violated),
        "the control: a PENDING record with this cell convicts"
    );
    assert_eq!(
        result::resolve_check(&binding, 33, 50, 3, result::STATUS_FINAL, &dcr2),
        Ok(result::Verdict::AlreadyFinal),
        "and a FINAL one does not look at the cell"
    );
    let payer = f.executor.pubkey();
    let before = f.lamports(payer).await;
    let metas = f.close_metas(&c, f.signer.pubkey());
    label("row1-skip");
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&descriptor),
        metas,
    )
    .await
    .expect("the close of a FINAL record");
    let after = f.account(c.dcr2).await;
    assert_eq!(
        after[6],
        result::STATUS_SETTLED,
        "the skip, and SETTLED for a FINAL record"
    );
    assert_eq!(after[7], 1);
    assert_eq!(after[result::BOND_STATE_AT_V6], BOND_RETURNED);
    assert_eq!(u64_at(&after, result::RETENTION_START_AT_V6), slot);
    assert!(f.lamports(payer).await > before, "the rent came back");
    eprintln!("CLOSE-CU skip=true status=final");
}

/// **The STANDARD split, the credit rule's skip arm, and no escrow at all.**
///
/// The document is CUSTOM in every other test in this file, so the built-in
/// route would otherwise be unexercised. Here the terms are STANDARD with a
/// 1 basis-point slasher share and a recorded winner, and the two destinations are chosen
/// so that **one credit is payable and one is skipped**: the remainder
/// destination is pre-funded to the 0-byte rent-exempt minimum, and the winner
/// destination does not exist, so its 50,000-lamport share is below
/// `minimum_balance(0) = 890,880` and the credit rule skips it. The skipped
/// share joins the remainder payment.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_splits_a_standard_pot_and_skips_a_sub_floor_share() {
    let Some(mut f) = build().await else { return };
    let base = Terms2::decode(&f.terms_raw).unwrap();
    let remainder_key = Pubkey::new_unique();
    let pot = 50_000_000;
    f.terms_raw = Terms2 {
        bond_policy_kind: 1,
        bond_slasher_bps: 1,
        settlement_program: [0u8; 32],
        custom_settle_window_slots: 0,
        bond_remainder: remainder_key.to_bytes(),
        executor_bond_lamports: pot,
        ..base
    }
    .encode()
    .to_vec();
    let winner_key = Pubkey::new_unique();
    // The remainder destination exists and is rent-exempt; the winner's does not.
    f.ctx.set_account(
        &remainder_key,
        &shared(Account {
            lamports: ESCROW_FLOOR,
            data: vec![],
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        }),
    );
    // (the winner destination is deliberately left non-existent)
    let roots = f.position_roots[..33].to_vec();
    let c = {
        let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
        closable_hand_built(&mut f, &b, 33, &roots, 81).await
    };
    // A conviction: flag 4, and the recorded winner the slasher share is paid to.
    let mut doc = f.account(c.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32].copy_from_slice(winner_key.as_ref());
    {
        let lamports = f.lamports(c.dcm2).await;
        f.ctx.set_account(
            &c.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    clock_to(&mut f, 6_000_002).await;
    let payer = f.executor.pubkey();
    let payer_before = f.lamports(payer).await;
    let in_three = f.lamports(c.dcm2).await
        + f.lamports(c.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c.descriptor).0)
            .await;
    let metas = f.close_metas_slots(
        &c,
        f.signer.pubkey(),
        AccountMeta::new(winner_key, false),
        AccountMeta::new(remainder_key, false),
    );
    label("standard-split");
    let events = send_fresh_events(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        metas,
    )
    .await
    .expect("a STANDARD close");
    let dcr2 = f.account(c.dcr2).await;
    assert_eq!(
        dcr2[6],
        result::STATUS_REFUTED,
        "a refuted document closes REFUTED"
    );
    assert_eq!(
        dcr2[result::BOND_STATE_AT_V6],
        2,
        "BOND_PAID: the built-in route paid"
    );
    assert_eq!(dcr2[result::BOND_CAUSE_AT_V6], CAUSE_CONVICTION);
    assert_eq!(
        dcr2[result::WINNER_AT_V6..result::WINNER_AT_V6 + 32],
        winner_key.to_bytes(),
        "the close copies the recorded winner into DCR2, where tag 187 reads it"
    );
    assert_eq!(
        f.lamports(remainder_key).await,
        ESCROW_FLOOR + pot,
        "the remainder receives the skipped winner share too"
    );
    assert_eq!(
        f.lamports(winner_key).await,
        0,
        "the sub-floor winner share was skipped"
    );
    assert!(
        pot > in_three - pot,
        "the convicted pot is larger than the combined rent"
    );
    assert_eq!(
        f.lamports(payer).await,
        payer_before + in_three - pot,
        "the payer receives exactly the rent left after the bond left DCM2"
    );
    assert_close_event_refund(&events, in_three - pot);
    assert!(
        f.ctx
            .banks_client
            .get_account(address::bond_escrow(&f.program, &c.descriptor).0)
            .await
            .unwrap()
            .is_none(),
        "a STANDARD close never creates the escrow"
    );
    // C3's shared direct-lamport credit reaches the runtime's writable-account
    // guard: a read-only remainder is rejected atomically as
    // `UnbalancedInstruction`. CUSTOM escrow shape is checked by C3's validator
    // and retains its 798 refusal.
    let roots = f.position_roots[..33].to_vec();
    let b3 = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c3 = closable_hand_built(&mut f, &b3, 33, &roots, 83).await;
    let mut doc = f.account(c3.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32].copy_from_slice(winner_key.as_ref());
    {
        let lamports = f.lamports(c3.dcm2).await;
        f.ctx.set_account(
            &c3.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    let ro = f.close_metas_slots(
        &c3,
        f.signer.pubkey(),
        AccountMeta::new(winner_key, false),
        AccountMeta::new_readonly(remainder_key, false),
    );
    assert!(
        matches!(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                close_data(&c3.descriptor),
                ro
            )
            .await,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::UnbalancedInstruction | InstructionError::ReadonlyLamportChange
            ))
        ),
        "the runtime rejects a read-only remainder destination atomically"
    );
    // The no-winner row: with `conviction_winner` zero the slasher share is zero
    // and the whole pot is the remainder, and the `winner` meta must be the
    // incinerator rather than a destination of the caller's choosing.
    let roots = f.position_roots[..33].to_vec();
    let c2 = {
        let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
        closable_hand_built(&mut f, &b, 33, &roots, 82).await
    };
    let mut doc = f.account(c2.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    {
        let lamports = f.lamports(c2.dcm2).await;
        f.ctx.set_account(
            &c2.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    let bad = f.close_metas_slots(
        &c2,
        f.signer.pubkey(),
        AccountMeta::new(remainder_key, false),
        AccountMeta::new(remainder_key, false),
    );
    assert_eq!(
        refused_with(&mut f, close_data(&c2.descriptor), bad).await,
        CL_AUTHORITY,
        "a no-winner close may not name its own destination"
    );
    let good = f.close_metas_slots(
        &c2,
        f.signer.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder_key, false),
    );
    let remainder_before = f.lamports(remainder_key).await;
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c2.descriptor),
        good,
    )
    .await
    .expect("the no-winner close");
    assert_eq!(
        f.lamports(remainder_key).await,
        remainder_before + pot,
        "the whole pot"
    );
    assert_eq!(
        f.lamports(incinerator::ID).await,
        0,
        "and nothing at all to the slasher"
    );
}

/// A CUSTOM conviction also seizes a bond larger than the combined rent. The
/// close event's refund is the lamports actually drained after the pot moves to
/// escrow; it does not subtract the pot a second time.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_custom_close_refund_is_the_exact_post_escrow_drain() {
    let Some(mut f) = build().await else { return };
    let base = Terms2::decode(&f.terms_raw).unwrap();
    let pot = 50_000_000;
    f.terms_raw = Terms2 {
        executor_bond_lamports: pot,
        ..base
    }
    .encode()
    .to_vec();
    let roots = f.position_roots[..33].to_vec();
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, 119).await;
    let mut doc = f.account(c.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    {
        let lamports = f.lamports(c.dcm2).await;
        f.ctx.set_account(
            &c.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    clock_to(&mut f, 6_000_020).await;
    let payer = f.executor.pubkey();
    let before = f.lamports(payer).await;
    let total = f.lamports(c.dcm2).await
        + f.lamports(c.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c.descriptor).0)
            .await;
    assert!(
        pot > total - pot,
        "the committed bond exceeds all three accounts' rent"
    );
    let metas = f.close_metas(&c, f.signer.pubkey());
    let events = send_fresh_events(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        metas,
    )
    .await
    .expect("the custom close");
    assert_eq!(
        f.lamports(payer).await,
        before + total - pot,
        "the payer's exact increase is the post-escrow rent drain"
    );
    assert_close_event_refund(&events, total - pot);
    assert_eq!(
        f.lamports(address::bond_escrow(&f.program, &c.descriptor).0)
            .await,
        pot,
        "the full bond went to escrow"
    );
}

/// A STANDARD close never sends an uncreditable remainder back to the convict.
/// The policy destination is a data account whose rent floor exceeds the pot,
/// so C3's shared payout sends the full residual to the real incinerator.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_standard_close_burns_an_uncreditable_remainder() {
    let Some(mut f) = build().await else { return };
    let base = Terms2::decode(&f.terms_raw).unwrap();
    let pot = 50_000_000;
    let remainder = Pubkey::new_unique();
    f.terms_raw = Terms2 {
        bond_policy_kind: 1,
        bond_slasher_bps: 2_500,
        settlement_program: [0; 32],
        custom_settle_window_slots: 0,
        bond_remainder: remainder.to_bytes(),
        executor_bond_lamports: pot,
        ..base
    }
    .encode()
    .to_vec();
    f.ctx.set_account(
        &remainder,
        &shared(Account {
            lamports: 1,
            data: vec![0; 10_000],
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let roots = f.position_roots[..33].to_vec();
    let binding = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &binding, 33, &roots, 120).await;
    let mut doc = f.account(c.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    {
        let lamports = f.lamports(c.dcm2).await;
        f.ctx.set_account(
            &c.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    clock_to(&mut f, 6_000_021).await;
    let payer = f.executor.pubkey();
    let payer_before = f.lamports(payer).await;
    let burn_before = f.lamports(incinerator::ID).await;
    let total = f.lamports(c.dcm2).await
        + f.lamports(c.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c.descriptor).0)
            .await;
    let metas = f.close_metas_slots(
        &c,
        f.signer.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    );
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        metas,
    )
    .await
    .expect("the uncreditable remainder does not block close");
    assert_eq!(
        f.lamports(remainder).await,
        1,
        "an uncreditable destination receives nothing"
    );
    assert_eq!(
        f.lamports(incinerator::ID).await,
        burn_before + pot,
        "all uncreditable bond lamports reach incinerator::ID"
    );
    assert_eq!(
        f.lamports(payer).await,
        payer_before + total - pot,
        "the convicted executor receives rent only"
    );
}

/// Both STANDARD destinations are uncreditable: the winner share is below the
/// empty-account floor and the remainder is a rent-heavy program account. The
/// skipped share joins the remainder attempt, then the entire unpaid pot burns
/// to the real incinerator. The convict receives only the rent refund.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_standard_close_burns_every_uncreditable_share_away_from_the_convict() {
    let Some(mut f) = build().await else { return };
    let base = Terms2::decode(&f.terms_raw).unwrap();
    let pot = 500_000;
    let remainder = Pubkey::new_unique();
    let winner = Pubkey::new_unique();
    f.terms_raw = Terms2 {
        bond_policy_kind: 1,
        bond_slasher_bps: 2_500,
        settlement_program: [0; 32],
        custom_settle_window_slots: 0,
        bond_remainder: remainder.to_bytes(),
        executor_bond_lamports: pot,
        ..base
    }
    .encode()
    .to_vec();
    f.ctx.set_account(
        &remainder,
        &shared(Account {
            lamports: 1,
            data: vec![0; 10_000],
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let roots = f.position_roots[..33].to_vec();
    let binding = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &binding, 33, &roots, 121).await;
    let mut doc = f.account(c.dcm2).await;
    doc[6..8].copy_from_slice(
        &(FLAG_ARMED | FLAG_ROOT_ONLY | FLAG_SEALED | FLAG_FINAL | FLAG_REFUTED).to_le_bytes(),
    );
    doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32].copy_from_slice(winner.as_ref());
    {
        let lamports = f.lamports(c.dcm2).await;
        f.ctx.set_account(
            &c.dcm2,
            &shared(Account {
                lamports,
                data: doc,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    clock_to(&mut f, 6_000_030).await;

    let payer = f.executor.pubkey();
    let payer_before = f.lamports(payer).await;
    let burn_before = f.lamports(incinerator::ID).await;
    let remainder_before = f.lamports(remainder).await;
    let total = f.lamports(c.dcm2).await
        + f.lamports(c.dpr2).await
        + f.lamports(address::family_slots(&f.program, &c.descriptor).0)
            .await;
    assert!(
        total - pot > pot,
        "the rent exceeds this bond, isolating the payout rule"
    );
    let metas = f.close_metas_slots(
        &c,
        f.signer.pubkey(),
        AccountMeta::new(winner, false),
        AccountMeta::new(remainder, false),
    );
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        metas,
    )
    .await
    .expect("an uncreditable STANDARD split still closes");

    assert_eq!(
        f.lamports(payer).await,
        payer_before + total - pot,
        "the executor gets the document rent only"
    );
    assert_eq!(
        f.lamports(winner).await,
        0,
        "the sub-floor winner share was skipped"
    );
    assert_eq!(
        f.lamports(remainder).await,
        remainder_before,
        "the rent-heavy remainder could not receive the combined remainder"
    );
    assert_eq!(
        f.lamports(incinerator::ID).await,
        burn_before + pot,
        "the uncreditable residual is burned instead of being returned to the convict"
    );
}

/// **The refusals, one document each.** Every code the close can answer with on
/// a revision-8 record, and the shape that produces it. A refused close writes
/// nothing, which [`refused_close`] asserts for all of them.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_refusals() {
    let Some(mut f) = build().await else { return };
    let stranger = f.signer.pubkey();
    let roots = f.position_roots[..33].to_vec();
    let mut variant = 90u8;
    let mut next = move || {
        variant += 1;
        variant
    };
    // (1) **599, an early close.** The document is unfinalized and nowhere near
    // its production deadline, and revision 7's own code answers it.
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, next()).await;
    assert_eq!(
        refused_close(&mut f, &c, stranger, next()).await,
        CL_CLOSE,
        "before the deadline"
    );
    // (2) **582, the wrong rent recipient.** Anyone may close, but the rent goes
    // to DCM2 40..72 and the meta must be that account -- a stranger may not pay
    // the rent to itself.
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, next()).await;
    let payer = f.executor.pubkey();
    let payer_before = f.lamports(payer).await;
    let stranger_before = f.lamports(stranger).await;
    let mut metas = f.close_metas(&c, stranger);
    metas[5] = AccountMeta::new(stranger, false);
    clock_to(&mut f, 6_000_010).await;
    refused_here!(f, close_data(&c.descriptor), metas, CL_AUTHORITY);
    assert_eq!(
        f.lamports(payer).await,
        payer_before,
        "and the rent did not move"
    );
    // The caller paid its own transaction fee and nothing else: a permissionless
    // close never pays the closer.
    let stranger_after = f.lamports(stranger).await;
    assert!(
        stranger_after < stranger_before && stranger_before - stranger_after < 10_000,
        "the caller paid fees only: {stranger_before} -> {stranger_after}"
    );
    // (3) **793, a substituted DTU1.** The counter is validated at the PDA
    // derived from DCM2's own PT2S and its digest, so another template's
    // counter is refused rather than decremented.
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, next()).await;
    // An attacker substitutes an account it controls for DTU1, once the
    // document is past its own production deadline (a real clock move).
    let other = Pubkey::new_unique();
    let abandon = u64_at(&f.account(c.dcm2).await, document::ABANDON_DEADLINE_AT);
    clock_to(&mut f, abandon + 1).await;
    let mut metas = f.close_metas(&c, stranger);
    metas[6] = AccountMeta::new(other, false);
    refused_here!(f, close_data(&c.descriptor), metas, TEMPLATE_SEAL);
    // (4) A counter that reads zero is a state only a program bug could write:
    // config::dtu1_gate_tests::the_release_is_a_checked_sub_and_writes_nothing_at_zero.
    // (5) **580, a short account list.** Six metas is revision 7's shape and a
    // revision-8 record refuses it; eight and ten are not nine.
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, next()).await;
    for take in [6usize, 8] {
        let metas = f.close_metas(&c, stranger);
        refused_here!(
            f,
            close_data(&c.descriptor),
            metas[..take].to_vec(),
            CL_MALFORMED
        );
    }
    let mut extra = f.close_metas(&c, stranger);
    extra.push(AccountMeta::new(Pubkey::new_unique(), false));
    refused_here!(f, close_data(&c.descriptor), extra, CL_MALFORMED);
    // (6) **580, a wrong descriptor**, and **599** on a result account that is
    // already closed.
    let b = f.binding_stop(29, 50, STOP_PLUS_ONE);
    let c = closable(&mut f, &b, 33, &roots, next()).await;
    let foreign = f.close_metas(&c, stranger);
    refused_here!(f, close_data(&[9u8; 32]), foreign, CL_MALFORMED);
    // A record closed while its document is open is a state only a program
    // bug could write; the close refuses a closed record (599) by inspection.
    // (7) **582 on the two kind-dependent metas.** A CUSTOM document handed a
    // tail that is neither its escrow nor the system program. The count is ten
    // either way, which is the re-review's Medium 6: the key checks are what
    // catch a client that handed the wrong list.
    // A **conviction**, so the policy runs and the two key checks are reached at
    // all: on a row that does not escrow (1-on-SETTLED, 2) the close does not
    // look at the two kind-dependent metas, and that is deliberate and named.
    // A real one: a stop-rule resolve (no record patch).
    let c = convicted_by_resolve(&mut f, next()).await;
    let good = f.close_metas(&c, stranger);
    let mut wrong = good.clone();
    wrong[7] = AccountMeta::new(Pubkey::new_unique(), false);
    refused_here!(f, close_data(&c.descriptor), wrong, CL_AUTHORITY);
    let mut wrong = good.clone();
    wrong[8] = AccountMeta::new_readonly(Pubkey::new_unique(), false);
    refused_here!(f, close_data(&c.descriptor), wrong, CL_AUTHORITY);
    // (8) A read-only escrow has C3's validator refusal, 798. The close-side
    // 582 remains for a substituted escrow key, checked before shape validation.
    let mut ro = good.clone();
    ro[7] = AccountMeta::new_readonly(good[7].pubkey, false);
    refused_here!(f, close_data(&c.descriptor), ro, SETTLEMENT_PROGRAM);
    // Stale stored bumps on DCM2, DPR2 and DCR2 are states only a program bug
    // could write: result::reader_gate_tests.
    // And the honest list, once, on the same convicted document: it closes, and
    // the escrow is the document's own PDA.
    let pot = Terms2::decode(&f.terms_raw).unwrap().executor_bond_lamports;
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&c.descriptor),
        good,
    )
    .await
    .expect("the honest tail on a conviction");
    assert_eq!(
        f.lamports(address::bond_escrow(&f.program, &c.descriptor).0)
            .await,
        pot
    );
}

/// **A pre-funded escrow is a gift, not a lock.** Anyone may transfer lamports
/// to the public PDA address; the close reads its current balance and tops it
/// up with the pot. External callers cannot allocate or assign the PDA because
/// those system instructions require its signature, which only DCG can provide.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_escrows_past_a_prefunded_address() {
    let Some(mut f) = build().await else { return };
    let base = Terms2::decode(&f.terms_raw).unwrap();
    // Larger than the three real accounts' rent (a real document's DPR2 page
    // is bigger than the old hand-built one).
    let pot = 500_000_000;
    f.terms_raw = Terms2 {
        executor_bond_lamports: pot,
        ..base
    }
    .encode()
    .to_vec();
    let payer = f.executor.pubkey();
    // A 1-lamport deposit cannot be created by a transfer under current rent
    // rules, so the gift is the rent floor (the smallest real deposit).
    for (i, gift) in [ESCROW_FLOOR].into_iter().enumerate() {
        // A really convicted document (stop-rule resolve), no record patch.
        let c = convicted_by_resolve(&mut f, 95 + i as u8).await;
        let escrow = address::bond_escrow(&f.program, &c.descriptor).0;
        // A plain lamport deposit into a system-owned 0-byte account: what any
        // third party can do with a public address and a transfer.
        fund_system(&mut f.ctx, &f.executor, escrow, gift).await;
        clock_to(&mut f, 6_000_100 + i as u64).await;
        let payer_before = f.lamports(payer).await;
        let in_three = f.lamports(c.dcm2).await
            + f.lamports(c.dpr2).await
            + f.lamports(address::family_slots(&f.program, &c.descriptor).0)
                .await;
        assert!(
            pot > in_three - pot,
            "the CUSTOM bond is larger than all three rents"
        );
        let metas = f.close_metas(&c, f.signer.pubkey());
        let events = send_fresh_events(
            &mut f.ctx,
            &f.signer,
            f.program,
            close_data(&c.descriptor),
            metas,
        )
        .await
        .unwrap_or_else(|e| panic!("a pre-funded escrow of {gift} lamports: {e:?}"));
        assert_eq!(
            f.lamports(escrow).await,
            pot + gift,
            "the pot arrived and the gift stayed"
        );
        assert_eq!(
            f.account(c.dcr2).await[result::BOND_STATE_AT_V6],
            document::BOND_ESCROWED
        );
        assert_close_event_refund(&events, in_three - pot);
        assert!(
            f.lamports(payer).await > payer_before,
            "the rent was still refunded"
        );
    }
}

/// **Tag 176 on revision 8: what the seal creates, the three actions, the
/// re-approval equality, and the capacity bound.** Every case is a **fresh
/// PT2S**, because the two counters and the DTA1 are write-once per template and
/// a second approve on the same one is a different case (the re-approval).
///
/// The PT2S images here are laid down already sealed, with a **chosen capacity**
/// in their own clause-12 v4 block, because tag 145 recomputes that block from
/// the plan and the plan's capacity is 80: the CU bound is about the capacity,
/// and a plan of 80 positions can only ever be far under it.
/// Tag 186 requires the recorded authority in every DTU1 state and returns each
/// rent balance to the payee recorded for that resource.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_template_drains_single_base_and_refunds_recorded_payers() {
    let Some(mut f) = build().await else { return };

    let authority = f.executor.pubkey();
    let pt1x = f.pt1s_index;
    let pt2s = f.pt2s;
    let dta1 = f.dta1;
    let dtu1 = f.dtu1;
    let admission_data = f.account(f.dea2).await;
    let admission_payer = Pubkey::new_from_array(d32(&admission_data, 160));
    let sources = [
        dtu1, dta1, pt2s, pt1x, f.routes, f.geometry, f.payloads, f.dea2,
    ];
    let rent: u64 = {
        let mut sum = 0;
        for key in sources {
            sum += f.lamports(key).await;
        }
        sum
    };
    let mut metas = vec![AccountMeta::new(authority, true)];
    metas.extend(
        [dtu1, dta1, pt2s, pt1x, f.routes, f.geometry, f.payloads]
            .into_iter()
            .map(|key| AccountMeta::new(key, false)),
    );
    metas.extend(
        [authority, authority, authority]
            .into_iter()
            .map(|key| AccountMeta::new(key, false)),
    );
    metas.push(AccountMeta::new_readonly(f.drp2, false));
    metas.push(AccountMeta::new(f.dea2, false));
    metas.push(AccountMeta::new(admission_payer, false));
    metas.push(AccountMeta::new_readonly(SYSTEM, false));
    assert_eq!(metas.len(), 15);

    // A valid DEA2 under another registry cannot be created for this DTU1.
    let foreign_registry = Pubkey::new_unique();
    let foreign_admission = address::admission(&f.program, &foreign_registry, &pt2s, f.k).0;
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![159],
                vec![
                    AccountMeta::new(f.executor.pubkey(), true),
                    AccountMeta::new(foreign_admission, false),
                    AccountMeta::new_readonly(foreign_registry, false),
                    AccountMeta::new_readonly(pt2s, false),
                    AccountMeta::new_readonly(f.routes, false),
                    AccountMeta::new_readonly(f.geometry, false),
                    AccountMeta::new_readonly(SYSTEM, false),
                    AccountMeta::new_readonly(dtu1, false),
                ],
            )
            .await
        ),
        TEMPLATE_SEAL,
        "tag 159 refuses admission rent under a registry outside DTU1"
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(foreign_admission)
        .await
        .unwrap()
        .is_none());

    // Recipient substitutions are refused even when the recorded authority
    // closes. The failure is atomic and leaves all template rent in place.
    let mut attacker_metas = metas.clone();
    attacker_metas[8] = AccountMeta::new(f.signer.pubkey(), false);
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![TAG_CLOSE_TEMPLATE],
                attacker_metas
            )
            .await
        ),
        CL_AUTHORITY,
        "the caller cannot redirect the PT1X rent"
    );

    let stranger = f.signer.pubkey();
    let stranger_before = f.lamports(stranger).await;
    let mut stranger_metas = metas.clone();
    stranger_metas[0] = AccountMeta::new(stranger, true);
    let snapshot: Vec<(Pubkey, Vec<u8>, u64)> = {
        let mut before = Vec::new();
        for key in sources {
            before.push((key, f.account(key).await, f.lamports(key).await));
        }
        before
    };
    assert_eq!(
        custom(
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[&f.signer],
                f.program,
                vec![TAG_CLOSE_TEMPLATE],
                stranger_metas.clone(),
            )
            .await
        ),
        CL_AUTHORITY,
        "a stranger cannot close a LIVE template"
    );
    for (key, data, lamports) in &snapshot {
        assert_eq!(
            f.account(*key).await,
            *data,
            "a LIVE refusal preserves {key}"
        );
        assert_eq!(
            f.lamports(*key).await,
            *lamports,
            "a LIVE refusal preserves {key} rent"
        );
    }

    let config_key = address::config(&f.program).0;
    let admin_metas = || {
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(dta1, false),
            AccountMeta::new(pt2s, false),
            AccountMeta::new(dtu1, false),
        ]
    };
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_TEMPLATE_SEAL, config::SEAL_REVOKED],
        admin_metas(),
    )
    .await
    .expect("the recorded authority revokes the template");
    assert_eq!(f.account(dtu1).await[6], config::DTU1_STATE_REVOKED);
    assert_eq!(
        custom(
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[&f.signer],
                f.program,
                vec![TAG_CLOSE_TEMPLATE],
                stranger_metas.clone(),
            )
            .await
        ),
        CL_AUTHORITY,
        "a stranger cannot close a REVOKED template"
    );

    let mut approve = vec![TAG_TEMPLATE_SEAL, config::SEAL_APPROVED];
    let use_record = f.account(dtu1).await;
    approve.extend_from_slice(&use_record[config::DTU1_MAX_CHALLENGE_AT..128]);
    let approve_metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(config_key, false),
        AccountMeta::new(dta1, false),
        AccountMeta::new(pt2s, false),
        AccountMeta::new(dtu1, false),
        AccountMeta::new_readonly(pt1x, false),
        AccountMeta::new_readonly(f.geometry, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.payloads, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(f.drp2, false),
    ];
    send_fresh(&mut f.ctx, &f.executor, f.program, approve, approve_metas)
        .await
        .expect("the authority re-approves the revoked template");
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_TEMPLATE_SEAL, config::SEAL_RETIRED],
        admin_metas(),
    )
    .await
    .expect("the recorded authority retires the template");
    assert_eq!(f.account(dtu1).await[6], config::DTU1_STATE_RETIRED);
    assert_eq!(
        custom(
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[&f.signer],
                f.program,
                vec![TAG_CLOSE_TEMPLATE],
                stranger_metas,
            )
            .await
        ),
        CL_AUTHORITY,
        "a stranger cannot close a RETIRED template"
    );

    let pt1x_and_bytes_rent = f.lamports(pt1x).await
        + f.lamports(f.routes).await
        + f.lamports(f.geometry).await
        + f.lamports(f.payloads).await;
    let payee_refunds = [
        (metas[8].pubkey, pt1x_and_bytes_rent),
        (metas[9].pubkey, f.lamports(pt2s).await),
        (
            metas[10].pubkey,
            f.lamports(dta1).await + f.lamports(dtu1).await,
        ),
        (metas[13].pubkey, f.lamports(f.dea2).await),
    ];
    let mut payee_before = Vec::new();
    for (payee, _) in &payee_refunds {
        payee_before.push((*payee, f.lamports(*payee).await));
    }
    let before = f.lamports(authority).await;
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_CLOSE_TEMPLATE],
        metas,
    )
    .await
    .expect("the recorded authority closes a RETIRED template");
    for key in sources {
        assert!(
            f.ctx.banks_client.get_account(key).await.unwrap().is_none(),
            "closed template account {key} is drained"
        );
    }
    assert!(
        f.lamports(authority).await >= before + rent - 20_000,
        "PT1X, base, PT2S, DTA1, DTU1 and DEA2 rent return to their recorded payers"
    );
    for (index, (payee, expected)) in payee_refunds.iter().enumerate() {
        assert!(
            f.lamports(*payee).await >= payee_before[index].1 + (*expected).saturating_sub(20_000),
            "recorded payee {payee} receives its template rent"
        );
    }
    assert_eq!(
        f.lamports(stranger).await,
        stranger_before,
        "the stranger's balance receives no template rent"
    );
}

/// Tag 197 form (i) only releases a zero-length allocation to its own signed
/// address. PT1X byte accounts have nonzero size and are assigned only after
/// tag 140 binds them, so an all-zero payload prefix cannot make a live
/// resource eligible for this form or redirect its rent.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_tag197_zero_length_form_pins_refund_and_refuses_bound_payload() {
    let Some(mut f) = build().await else { return };
    let payer = f.executor.pubkey();

    let payload_before = f.account(f.payloads).await;
    let payload_lamports = f.lamports(f.payloads).await;
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(f.payloads, false),
                    AccountMeta::new(payer, false),
                ],
            )
            .await
        ),
        CL_AUTHORITY,
        "a live PT1X payload is never a zero-length orphan"
    );
    assert_eq!(f.account(f.payloads).await, payload_before);
    assert_eq!(f.lamports(f.payloads).await, payload_lamports);

    // C3's original self-key attack: even when the live template's own
    // payload key signs as the proposed closer/payee, a nonempty bound payload
    // is not an orphan and tag 197 cannot drain it.
    let payload_before = f.account(f.payloads).await;
    let payload_lamports = f.lamports(f.payloads).await;
    let payload_key = f.payload_key.pubkey();
    assert_eq!(
        custom(
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[&f.payload_key],
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                vec![
                    AccountMeta::new(payload_key, true),
                    AccountMeta::new(f.payloads, false),
                    AccountMeta::new(payload_key, false),
                ],
            )
            .await
        ),
        CL_AUTHORITY,
        "the live template payload's own key cannot authorize a drain"
    );
    assert_eq!(f.account(f.payloads).await, payload_before);
    assert_eq!(f.lamports(f.payloads).await, payload_lamports);

    // Program-owned accounts anyone can create through the System Program.
    let four_zero_kp = Keypair::new();
    let four_zero = four_zero_kp.pubkey();
    allocate_program_account(&mut f.ctx, &f.executor, &four_zero_kp, f.program, 4).await;
    let four_zero_before = f.account(four_zero).await;
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(four_zero, false),
                    AccountMeta::new(payer, false),
                ],
            )
            .await
        ),
        CL_AUTHORITY,
        "a four-byte zero prefix is not proof that an allocation is unbound"
    );
    assert_eq!(f.account(four_zero).await, four_zero_before);

    let wrong_refund = Pubkey::new_unique();
    let empty = Keypair::new();
    allocate_program_account(&mut f.ctx, &f.executor, &empty, f.program, 0).await;
    let empty_before = f.lamports(empty.pubkey()).await;
    assert_eq!(
        custom(
            send_with_signers(
                &mut f.ctx,
                &f.executor,
                &[&empty],
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                vec![
                    AccountMeta::new(empty.pubkey(), true),
                    AccountMeta::new(empty.pubkey(), false),
                    AccountMeta::new(wrong_refund, false),
                ],
            )
            .await
        ),
        CL_AUTHORITY,
        "form (i) cannot redirect an orphan's rent"
    );
    assert_eq!(f.lamports(empty.pubkey()).await, empty_before);

    let good_empty = Keypair::new();
    allocate_program_account(&mut f.ctx, &f.executor, &good_empty, f.program, 0).await;
    let good_rent = f.lamports(good_empty.pubkey()).await;
    let good_owner_before = f.account(good_empty.pubkey()).await;
    send_with_signers(
        &mut f.ctx,
        &f.executor,
        &[&good_empty],
        f.program,
        vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
        vec![
            AccountMeta::new(good_empty.pubkey(), true),
            AccountMeta::new(good_empty.pubkey(), false),
            AccountMeta::new(good_empty.pubkey(), false),
        ],
    )
    .await
    .expect("the zero-length allocation returns to its own recorded key");
    assert_eq!(f.lamports(good_empty.pubkey()).await, good_rent);
    assert_eq!(f.account(good_empty.pubkey()).await, good_owner_before);
    let account = f
        .ctx
        .banks_client
        .get_account(good_empty.pubkey())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        account.owner, SYSTEM,
        "released zero-data account returns to System"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rev8_template_retirement_is_irreversible() {
    let Some(mut f) = build().await else { return };
    let config_key = address::config(&f.program).0;
    let (executor, dta1, pt2s, dtu1) = (f.executor.pubkey(), f.dta1, f.pt2s, f.dtu1);
    let admin_metas = || {
        vec![
            AccountMeta::new(executor, true),
            AccountMeta::new_readonly(config_key, false),
            AccountMeta::new(dta1, false),
            AccountMeta::new(pt2s, false),
            AccountMeta::new(dtu1, false),
        ]
    };
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![TAG_TEMPLATE_SEAL, SEAL_RETIRED],
        admin_metas(),
    )
    .await
    .expect("the configured authority retires the template");
    assert_eq!(f.account(f.dtu1).await[6], config::DTU1_STATE_RETIRED);
    assert_eq!(
        f.init_refusal(&f.binding(29, 50), 9).await,
        TEMPLATE_SEAL,
        "a retired template admits no new document, 793"
    );

    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![TAG_TEMPLATE_SEAL, SEAL_REVOKED],
                admin_metas(),
            )
            .await
        ),
        TEMPLATE_SEAL,
        "retirement cannot transition into revocation"
    );
    assert_eq!(f.account(f.dtu1).await[6], config::DTU1_STATE_RETIRED);

    let mut approve = vec![TAG_TEMPLATE_SEAL, config::SEAL_APPROVED];
    let use_record = f.account(f.dtu1).await;
    approve.extend_from_slice(&use_record[config::DTU1_MAX_CHALLENGE_AT..128]);
    let approve_metas = vec![
        AccountMeta::new(f.executor.pubkey(), true),
        AccountMeta::new_readonly(config_key, false),
        AccountMeta::new(f.dta1, false),
        AccountMeta::new(f.pt2s, false),
        AccountMeta::new(f.dtu1, false),
        AccountMeta::new_readonly(f.pt1s_index, false),
        AccountMeta::new_readonly(f.geometry, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.payloads, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(f.drp2, false),
    ];
    assert_eq!(
        custom(send_fresh(&mut f.ctx, &f.executor, f.program, approve, approve_metas).await),
        TEMPLATE_SEAL,
        "retirement cannot be undone by approval"
    );
    assert_eq!(f.account(f.dtu1).await[6], config::DTU1_STATE_RETIRED);
}

/// An abandoned upload is reclaimable before PT2S publication. An attacker
/// cannot redirect rent, while the uploader can close the base and all 3 bytes.

#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_unpublished_pt1x_refuses_attacker_and_refunds_owner() {
    let Some(mut f) = build().await else { return };
    let authority = f.executor.pubkey();
    let pt1x = Keypair::new();
    let routes = Keypair::new();
    let geometry = Keypair::new();
    let payloads = Keypair::new();
    let state_bytes = dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4;
    let allocations = [
        (&pt1x, state_bytes, f.program),
        // Tag 140 takes ownership of the byte allocations itself. Each starts
        // as a zero-filled System-owned account with its keypair present.
        (&routes, 4, SYSTEM),
        (&geometry, 4, SYSTEM),
        (&payloads, 4, SYSTEM),
    ];
    let mut total_rent = 0u64;
    for (account, bytes, owner) in allocations {
        let rent = solana_program::rent::Rent::default().minimum_balance(bytes);
        total_rent += rent;
        let blockhash = f.ctx.banks_client.get_latest_blockhash().await.unwrap();
        let create = solana_program::system_instruction::create_account(
            &authority,
            &account.pubkey(),
            rent,
            bytes as u64,
            &owner,
        );
        let tx = Transaction::new_signed_with_payer(
            &[create],
            Some(&authority),
            &[&f.executor, account],
            blockhash,
        );
        f.ctx
            .banks_client
            .process_transaction(tx)
            .await
            .expect("real System Program allocation for abandoned PT1X setup");
    }
    let init_metas = vec![
        AccountMeta::new(pt1x.pubkey(), true),
        AccountMeta::new(routes.pubkey(), true),
        AccountMeta::new(geometry.pubkey(), true),
        AccountMeta::new(payloads.pubkey(), true),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(SYSTEM, false),
    ];
    send_with_signers(
        &mut f.ctx,
        &f.executor,
        &[&pt1x, &routes, &geometry, &payloads],
        f.program,
        vec![140],
        init_metas,
    )
    .await
    .expect("real tag 140 creates the abandonable PT1X binding");
    assert_eq!(f.account(pt1x.pubkey()).await[4], 1);
    let stranger = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, stranger.pubkey(), 1_000_000).await;
    let mut metas = vec![
        AccountMeta::new(stranger.pubkey(), true),
        AccountMeta::new(pt1x.pubkey(), false),
        AccountMeta::new(routes.pubkey(), false),
        AccountMeta::new(geometry.pubkey(), false),
        AccountMeta::new(payloads.pubkey(), false),
    ];
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &stranger,
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                metas.clone()
            )
            .await
        ),
        CL_AUTHORITY,
        "the in-progress authority alone can abandon and close PT1X"
    );
    let before = f.lamports(authority).await;
    metas[0] = AccountMeta::new(authority, true);
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
        metas,
    )
    .await
    .expect("uploader closes abandoned base");
    assert!(
        f.lamports(authority).await >= before + total_rent - 20_000,
        "the uploader receives every abandoned account balance"
    );
    for key in [
        pt1x.pubkey(),
        routes.pubkey(),
        geometry.pubkey(),
        payloads.pubkey(),
    ] {
        assert!(f.ctx.banks_client.get_account(key).await.unwrap().is_none());
    }
}

/// Tag 197's nine-account abandonment form also recovers a PT2S that was
/// initialized and bound before setup was abandoned. The account images here
/// are explicit program-owned close fixtures; the full PT1X/PT2S setup and
/// authority transitions are exercised without account overrides by the
/// K=10,240 honest-path test above.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_unpublished_bound_pt1x_and_pt2s_refunds_owner() {
    let Some(mut f) = build().await else { return };
    let authority = f.executor.pubkey();
    let pt1x = Keypair::new();
    let routes = Keypair::new();
    let geometry = Keypair::new();
    let payloads = Keypair::new();
    let pt2s = Keypair::new();
    let keys = [routes.pubkey(), geometry.pubkey(), payloads.pubkey()];
    let lengths = [4u32; 3];
    let pwr1 = f.pt2s_image[S::OFF_PWR1..].to_vec();
    let allocations = [
        (&pt1x, dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4),
        (&routes, 4),
        (&geometry, 4),
        (&payloads, 4),
        (&pt2s, S::OFF_PWR1 + pwr1.len()),
    ];
    for (account, bytes) in allocations {
        allocate_program_account(&mut f.ctx, &f.executor, account, f.program, bytes).await;
    }

    let mut pt1x_data = vec![0u8; dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4];
    pt1x_data[..4].copy_from_slice(dcg_program::pt1_onchain::PT1X_MAGIC);
    pt1x_data[4] = 6;
    pt1x_data[5..37].copy_from_slice(authority.as_ref());
    for (i, key) in keys.into_iter().enumerate() {
        pt1x_data[37 + 32 * i..69 + 32 * i].copy_from_slice(key.as_ref());
        pt1x_data[133 + 4 * i..137 + 4 * i].copy_from_slice(&lengths[i].to_le_bytes());
    }
    pt1x_data[dcg_program::pt1_onchain::PT1X_BOUND_PT2S_AT
        ..dcg_program::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
        .copy_from_slice(pt2s.pubkey().as_ref());

    let mut pt2s_data = vec![0u8; S::OFF_PWR1 + pwr1.len()];
    pt2s_data[..4].copy_from_slice(S::MAGIC);
    pt2s_data[S::OFF_STATE] = S::STATE_HASHING;
    pt2s_data[S::OFF_AUTHORITY..S::OFF_AUTHORITY + 32].copy_from_slice(authority.as_ref());
    pt2s_data[S::OFF_PT1S..S::OFF_PT1S + 32].copy_from_slice(pt1x.pubkey().as_ref());
    for (i, key) in keys.into_iter().enumerate() {
        pt2s_data[S::OFF_KEYS + 32 * i..S::OFF_KEYS + 32 * (i + 1)].copy_from_slice(key.as_ref());
        pt2s_data[S::OFF_LENGTHS + 4 * i..S::OFF_LENGTHS + 4 * (i + 1)]
            .copy_from_slice(&lengths[i].to_le_bytes());
    }
    pt2s_data[S::OFF_PWR1_LEN..S::OFF_PWR1_LEN + 2]
        .copy_from_slice(&(pwr1.len() as u16).to_le_bytes());
    pt2s_data[S::OFF_PWR1..].copy_from_slice(&pwr1);
    let digest = sha256(&[&pt2s_data]);
    let (approval, _) = address::template_seal(&f.program, &pt2s.pubkey(), &digest);
    let (use_record, _) = address::template_use(&f.program, &pt2s.pubkey(), &digest);

    for (key, data) in [(pt1x.pubkey(), pt1x_data), (pt2s.pubkey(), pt2s_data)] {
        let mut account = f.ctx.banks_client.get_account(key).await.unwrap().unwrap();
        account.data = data;
        account.owner = f.program;
        f.ctx.set_account(&key, &shared(account));
    }
    for key in keys {
        let mut account = f.ctx.banks_client.get_account(key).await.unwrap().unwrap();
        account.data = vec![key.to_bytes()[0]; 4];
        account.owner = f.program;
        f.ctx.set_account(&key, &shared(account));
    }
    let pda_rent = solana_program::rent::Rent::default().minimum_balance(0);
    for pda in [approval, use_record] {
        fund_system(&mut f.ctx, &f.executor, pda, pda_rent).await;
    }
    let sources = [
        pt1x.pubkey(),
        routes.pubkey(),
        geometry.pubkey(),
        payloads.pubkey(),
        pt2s.pubkey(),
        approval,
        use_record,
    ];
    let mut refund = 0u64;
    for key in sources {
        refund += f.lamports(key).await;
    }

    let mut metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(pt1x.pubkey(), false),
        AccountMeta::new(routes.pubkey(), false),
        AccountMeta::new(geometry.pubkey(), false),
        AccountMeta::new(payloads.pubkey(), false),
        AccountMeta::new(pt2s.pubkey(), false),
        AccountMeta::new(approval, false),
        AccountMeta::new(use_record, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ];
    let attacker = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, attacker.pubkey(), 1_000_000).await;
    metas[0] = AccountMeta::new(attacker.pubkey(), true);
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &attacker,
                f.program,
                vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
                metas.clone()
            )
            .await
        ),
        CL_AUTHORITY,
        "a stranger cannot cancel a bound PT1X/PT2S setup"
    );
    metas[0] = AccountMeta::new(authority, true);
    let before = f.lamports(authority).await;
    send_fresh(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![config::TAG_CLOSE_UNPUBLISHED_TEMPLATE],
        metas,
    )
    .await
    .expect("recorded authority closes the unpublished bound pair");
    let after = f.lamports(authority).await;
    assert!(after >= before + refund - 20_000,
        "PT1X, PT2S, all three base accounts and empty seal/use rent return to the uploader: before={before}, after={after}, refund={refund}");
    for key in [
        pt1x.pubkey(),
        routes.pubkey(),
        geometry.pubkey(),
        payloads.pubkey(),
        pt2s.pubkey(),
    ] {
        assert!(f.ctx.banks_client.get_account(key).await.unwrap().is_none());
    }
    assert_eq!(
        f.lamports(approval).await + f.lamports(use_record).await,
        0,
        "seal/use PDAs are emptied after their rent is returned"
    );
}

/// Exercise the envelope registry's extended PT1X account form using the real
/// sealed K=10,240 pair. The old seven-account form remains for PT1S v3.
async fn envelope_pt1x_admission_binding(f: &mut Fix) {
    let authority = Keypair::new_from_array([0xE5; 32]);
    assert_eq!(
        Some(authority.pubkey().to_bytes()),
        envelope::AUTHORITY,
        "the local test authority matches envelope_seal's compiled authority"
    );
    fund_system(&mut f.ctx, &f.executor, authority.pubkey(), 100_000_000).await;
    let registry_id = 0x5054_3158;
    let registry_key = envelope::registry_address(&f.program, registry_id).0;
    let admission_key = envelope::admission_address(&f.program, &registry_key, &f.pt1s_index).0;
    let census = [0x42; 32];
    let (respond_path, witness_kind) = envelope::compiled_capability(1);
    let row = envelope::Row {
        form_id: 1,
        respond_path,
        witness_kind,
        max_reads: u16::MAX,
        max_writes: u16::MAX,
        max_read_bytes: u32::MAX,
        max_write_bytes: u32::MAX,
        max_payload_bytes: u32::MAX,
        execute_cu: 1,
        respond_cu: 1,
        measured_position: 0,
        measured_entry: 0,
    };
    let mut create = vec![envelope::TAG_REGISTRY_CREATE];
    create.extend_from_slice(&registry_id.to_le_bytes());
    create.extend_from_slice(&1u32.to_le_bytes());
    create.extend_from_slice(&census);
    send_with_signers(
        &mut f.ctx,
        &f.executor,
        &[&authority],
        f.program,
        create,
        vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(registry_key, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
    .await
    .expect("create PT1X envelope registry");
    let mut write = vec![envelope::TAG_REGISTRY_WRITE];
    write.extend_from_slice(&registry_id.to_le_bytes());
    write.extend_from_slice(&0u32.to_le_bytes());
    write.extend_from_slice(&row.encode());
    send_with_signers(
        &mut f.ctx,
        &f.executor,
        &[&authority],
        f.program,
        write,
        vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new(registry_key, false),
        ],
    )
    .await
    .expect("write PT1X envelope registry row");
    let mut freeze = vec![envelope::TAG_REGISTRY_FREEZE];
    freeze.extend_from_slice(&registry_id.to_le_bytes());
    send_with_signers(
        &mut f.ctx,
        &f.executor,
        &[&authority],
        f.program,
        freeze,
        vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new(registry_key, false),
        ],
    )
    .await
    .expect("freeze PT1X envelope registry");

    let payer = f.executor.pubkey();
    let (state_key, routes_key, geometry_key, payload_key) =
        (f.pt1s_index, f.routes, f.geometry, f.payloads);
    let begin_metas = |include_pair: bool, pt2s: Pubkey| {
        let mut metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(admission_key, false),
            AccountMeta::new_readonly(registry_key, false),
            AccountMeta::new_readonly(state_key, false),
            AccountMeta::new_readonly(routes_key, false),
            AccountMeta::new_readonly(geometry_key, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        if include_pair {
            metas.push(AccountMeta::new_readonly(payload_key, false));
            metas.push(AccountMeta::new_readonly(pt2s, false));
        }
        metas
    };
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![envelope::TAG_ADMISSION_BEGIN],
                begin_metas(false, f.pt2s)
            )
            .await
        ),
        PLAN_BINDING,
        "PT1X cannot use the legacy PT1S account form"
    );
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![envelope::TAG_ADMISSION_BEGIN],
                begin_metas(true, Pubkey::new_unique())
            )
            .await
        ),
        PLAN_BINDING,
        "a different PT2S cannot admit the PT1X"
    );
    assert_eq!(
        custom(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                vec![envelope::TAG_ADMISSION_BEGIN],
                begin_metas(true, f.pt2s),
            )
            .await
        ),
        PLAN_BINDING,
        "revision 8 refuses DEA1 creation because tag 186 closes DTU1-bound DEA2"
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(admission_key)
        .await
        .unwrap()
        .is_none());
}

/// Complete compiler-v1 PT1X flow against the retained K=10,240 emission:
/// upload/seal the real base, seal PT2S, admit documents, then reach rulings
/// through both position and leaf challenge paths. This deliberately uses real
/// System Program transfers for account funding and real program instructions
/// for state; it never replaces protocol accounts through `set_account`.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_pt1x_full_honest_path_reaches_challenge_ruling() {
    if std::env::var_os("BASANOS_PT1X_FULL_E2E").is_none() {
        eprintln!("needs_local_artifacts: set BASANOS_PT1X_FULL_E2E=1 with the retained K=10,240 compiler-v1 bundle");
        return;
    }
    let Some(mut f) = build_honest_pt1x().await else {
        panic!("the retained K=10,240 compiler-v1 bundle is required");
    };
    assert_eq!(f.k, 10_240);
    // The extracted SBF image has no legacy tag-150 envelope dispatcher. This
    // copied harness skips that Basanos-only preflight and keeps the real 159/160
    // PT1X registry admission completed by build_honest_pt1x above.
    let binding = f.binding(29, 50);
    // The completion binding starts its output range at position 29, so the
    // shortest valid document has 31 positions (first + 2).
    let document_length = 31;
    assert!(f.position_roots.len() >= document_length as usize);
    let (descriptor, created) = f.run_document(&binding, document_length).await;
    let doc = f.finalize(&descriptor, created, document_length).await;
    assert_ne!(
        u16_at(&doc, 6) & FLAG_FINAL,
        0,
        "the real admission path finalized one document"
    );

    let nonce = 0x5054_3158;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
    let open_data = challenge_position_data(&descriptor, 0, nonce);
    let open_metas = challenge_position_metas(&f, created, record);
    send(&mut f.ctx, &f.signer, f.program, open_data, open_metas)
        .await
        .expect("PT1X-backed admission opens a position dispute");
    let opened = f.account(record).await;
    assert_eq!(opened[4], challenge::PHASE_POSITION_REVEAL);
    let response_deadline = u64_at(&opened, 148);
    clock_to(&mut f, response_deadline + 1).await;
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("timeout reaches the ruling handler");

    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 2, "challenger wins when executor does not reveal");
    assert_eq!(ruled[178], events::CAUSE_TIMEOUT);
    let doc = f.account(created[0]).await;
    assert_eq!(u16_at(&doc, 6) & FLAG_REFUTED, FLAG_REFUTED);

    // A second, distinct document reaches the leaf-open/fix-point path, which
    // binds the PT1X payload index as part of challenge admission.
    let leaf_binding = f.binding(29, 50);
    let (leaf_descriptor, leaf_created, proofs) =
        attest_all(&mut f, &leaf_binding, document_length, &[], 0x59).await;
    assert_eq!(proofs.len(), 1);
    let leaf_nonce = nonce + 1;
    let leaf_record =
        address::challenge(&f.program, &leaf_descriptor, &f.signer.pubkey(), leaf_nonce).0;
    let leaf_packet = challenge_leaf_packet(&f, &leaf_descriptor, &proofs[0], leaf_nonce);
    let leaf_metas = challenge_leaf_metas(&f, leaf_created, leaf_record);
    send(&mut f.ctx, &f.signer, f.program, leaf_packet, leaf_metas)
        .await
        .expect("PT1X-backed leaf proof passes challenge admission");
    let leaf_opened = f.account(leaf_record).await;
    assert_eq!(leaf_opened[4], challenge::PHASE_RESPOND);
    let leaf_deadline = u64_at(&leaf_opened, 148);
    clock_to(&mut f, leaf_deadline + 1).await;
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(leaf_record, false),
            AccountMeta::new(leaf_created[0], false),
        ],
    )
    .await
    .expect("leaf challenge timeout reaches the ruling handler");
    assert_eq!(
        f.account(leaf_record).await[4],
        challenge::PHASE_RULED,
        "the PT1X-backed leaf challenge reaches a ruling"
    );
}

/// A DCM2's tail after the binding: the option table exactly, then the
/// 64-byte ARI1 application identity if and only if the template's real
/// admission marked it app-bound (DEA2 flag bit 2).
async fn assert_option_tail(f: &mut Fix, doc: &[u8], options: &[u8]) {
    assert_eq!(&doc[OPTION_REGION_AT..OPTION_REGION_AT + options.len()], options, "the option table");
    let app_bound = u16_at(&f.account(f.dea2).await, 6) & 2 != 0;
    let identity = document::application_identity_v8(doc).expect("a well-formed DCM2 tail");
    assert_eq!(identity.is_some(), app_bound, "ARI1 is present exactly on an app-bound template's document");
}

fn retained_payload_index(payloads: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut expected = 0u32;
    while at < payloads.len() {
        assert_eq!(u32_at(payloads, at), expected, "retained payload row order");
        out.extend_from_slice(&(at as u32).to_le_bytes());
        let row_len = 6 + u16_at(payloads, at + 4) as usize;
        at = at.checked_add(row_len).expect("payload row offset");
        assert!(at <= payloads.len(), "retained payload row is in bounds");
        expected += 1;
    }
    out.extend_from_slice(&(at as u32).to_le_bytes());
    out
}

/// The record-only decision count relation is the cheapest init check: it runs
/// before template-account binding, and a document with the wrong count can
/// never pass tag 165's decision branch.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_init_refuses_an_over_cap_decision_before_plan_binding() {
    let Some(mut f) = build().await else { return };
    let mut wrong = f.binding(29, 128);
    wrong.output_width = DECISION_WIDTH;
    wrong.decision_flags = DECISION_MODE;
    wrong.option_count = 81;
    wrong.output_count = 82;
    wrong.option_table_offset = OPTION_REGION_AT as u16;
    wrong.option_table_sha256 = [1; 32];
    // A caller-substituted routes account would be a plan-binding refusal if
    // init reached it. The 80-option cap is enforced by the binding's 794
    // before plan binding.
    f.routes = Pubkey::new_unique();
    assert_eq!(f.init_refusal(&wrong, 73).await, document::RUN_BINDING);
}

/// A self-consistent duplicate-last segment tree used to drive the real
/// challenge descent. Its leaves are arbitrary committed values; the one
/// adversarial fact is the coordinate's class, which the on-chain fix-point
/// checks against the template's frozen DRP2 row.
#[derive(Clone, Copy)]
struct ChallengeNode {
    digest: [u8; 32],
    first: u32,
    end: u32,
}

fn challenge_tree(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
) -> Vec<Vec<ChallengeNode>> {
    challenge_tree_with_replay_leaf(descriptor, position, segment, entries, None)
}

fn challenge_tree_with_replay_leaf(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
    witness: Option<&[u8]>,
) -> Vec<Vec<ChallengeNode>> {
    let app_leaves = witness
        .map(|witness| vec![(entries - 1, 22, witness)])
        .unwrap_or_default();
    challenge_tree_with_app_leaves(descriptor, position, segment, entries, &app_leaves)
}

fn challenge_tree_with_app_leaves(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
    app_leaves: &[(u32, u16, &[u8])],
) -> Vec<Vec<ChallengeNode>> {
    challenge_tree_with_app_leaves_for(
        &dcg_program::kernel::test_kernel::MANIFEST_APP,
        descriptor,
        position,
        segment,
        entries,
        app_leaves,
    )
}

fn challenge_tree_with_app_leaves_for(
    app: &dcg_program::kernel::ApplicationManifest,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
    app_leaves: &[(u32, u16, &[u8])],
) -> Vec<Vec<ChallengeNode>> {
    let digests = app_leaves
        .iter()
        .map(|(local, form, witness)| {
            let binding = app.resolve_legacy_form(1, *form).unwrap();
            (
                *local,
                app.replay_leaf_digest(binding, descriptor, position, segment, *local, witness),
            )
        })
        .collect::<Vec<_>>();
    let mut level: Vec<ChallengeNode> = (0..entries)
        .map(|local| ChallengeNode {
            digest: digests
                .iter()
                .find_map(|(at, digest)| (*at == local).then_some(*digest))
                .unwrap_or_else(|| {
                    h::hash(
                        b"c5-challenge-leaf",
                        &[
                            descriptor,
                            &position.to_le_bytes(),
                            &segment.to_le_bytes(),
                            &local.to_le_bytes(),
                        ],
                    )
                }),
            first: local,
            end: local + 1,
        })
        .collect();
    let mut levels = vec![level.clone()];
    let mut height = 0u8;
    while level.len() > 1 {
        height += 1;
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(ChallengeNode {
                digest: h::hash(
                    b"node/2",
                    &[
                        descriptor,
                        &[1],
                        &position.to_le_bytes(),
                        &left.first.to_le_bytes(),
                        &right.end.to_le_bytes(),
                        &[height, 1],
                        &left.digest,
                        &right.digest,
                    ],
                ),
                first: left.first,
                end: right.end,
            });
        }
        level = next;
        levels.push(level.clone());
    }
    levels
}

fn challenge_tree_with_route_leaves(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    entries: u32,
    target_local: u32,
    target_witness: &[u8],
    producer_local: u32,
    producer_witness: &[u8],
) -> (Vec<Vec<ChallengeNode>>, Vec<u8>) {
    let app = &dcg_program::kernel::test_kernel::MANIFEST_APP;
    let target_binding = app.resolve_legacy_form(1, 22).unwrap();
    let producer_binding = app.resolve_legacy_form(1, 30).unwrap();
    let target_digest = app.replay_leaf_digest(
        target_binding,
        descriptor,
        position,
        segment,
        target_local,
        target_witness,
    );
    let producer_digest = app.replay_leaf_digest(
        producer_binding,
        descriptor,
        position,
        segment,
        producer_local,
        producer_witness,
    );
    let mut level: Vec<ChallengeNode> = (0..entries)
        .map(|local| ChallengeNode {
            digest: if local == target_local {
                target_digest
            } else if local == producer_local {
                producer_digest
            } else {
                h::hash(
                    b"c5-challenge-leaf",
                    &[
                        descriptor,
                        &position.to_le_bytes(),
                        &segment.to_le_bytes(),
                        &local.to_le_bytes(),
                    ],
                )
            },
            first: local,
            end: local + 1,
        })
        .collect();
    let mut levels = vec![level.clone()];
    let mut height = 0u8;
    while level.len() > 1 {
        height += 1;
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(ChallengeNode {
                digest: h::hash(
                    b"node/2",
                    &[
                        descriptor,
                        &[1],
                        &position.to_le_bytes(),
                        &left.first.to_le_bytes(),
                        &right.end.to_le_bytes(),
                        &[height, 1],
                        &left.digest,
                        &right.digest,
                    ],
                ),
                first: left.first,
                end: right.end,
            });
        }
        level = next;
        levels.push(level.clone());
    }
    let mut path = Vec::new();
    let mut index = producer_local as usize;
    for level in levels.iter().take(levels.len() - 1) {
        let sibling = if index ^ 1 < level.len() {
            index ^ 1
        } else {
            index
        };
        path.extend_from_slice(&level[sibling].digest);
        index /= 2;
    }
    let mut opened = target_witness.to_vec();
    opened.extend_from_slice(b"RWP1");
    opened.extend_from_slice(&7u16.to_le_bytes());
    opened.extend_from_slice(&producer_local.to_le_bytes());
    opened.push((path.len() / 32) as u8);
    opened.push(0);
    opened.extend_from_slice(&(producer_witness.len() as u16).to_le_bytes());
    opened.extend_from_slice(producer_witness);
    opened.extend_from_slice(&path);
    (levels, opened)
}

/// A locally committed segment tree on the retained rung-D plan. Its root is
/// landed into a real revision-8 document before the challenge is opened; the
/// leaves are mechanics fixtures and do not claim an inference result.
async fn commit_challenge_tree(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
) {
    commit_challenge_tree_with_witness(f, binding, p, ordinal, None).await
}

async fn commit_challenge_tree_with_witness(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
    witness: Option<&[u8]>,
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
) {
    let descriptor = f.descriptor(binding, &f.terms_raw, 16);
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let (segment, entries) = x.segment_row(p, ordinal).unwrap();
    let levels = challenge_tree_with_replay_leaf(&descriptor, p, segment, entries, witness);
    let tree = levels.last().unwrap()[0].digest;
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            &descriptor,
            &p.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    let table = x.segment_table_root(p).unwrap();
    let mut roots = (0..f.segments)
        .map(|i| {
            h::hash(
                b"c5-unselected-segment",
                &[&descriptor, &p.to_le_bytes(), &i.to_le_bytes()],
            )
        })
        .collect::<Vec<_>>();
    roots[ordinal] = segment_root;
    let position_root = h::position_root(&descriptor, p, &table, &roots).unwrap();
    let mut positions = f.position_roots[..f.k as usize].to_vec();
    positions[p as usize] = position_root;
    let (actual_descriptor, created) = f.run_document_with_roots(binding, &positions).await;
    assert_eq!(actual_descriptor, descriptor);
    f.finalize(&descriptor, created, f.k).await;
    (descriptor, created, roots, segment, entries - 1, levels)
}

/// A real app-bound challenge fixture for Form 256, the retained plan's
/// zero-route entry mapped to ByteSum in the focused SBF image. The tree
/// commits this exact coordinate-specific ARW1 leaf and UnifiedInit freezes
/// the app identity.
async fn commit_route_free_app_tree(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
    target_form: u16,
    witness: &[u8],
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
) {
    commit_route_free_app_tree_with_manifest(
        f,
        binding,
        p,
        ordinal,
        target_form,
        witness,
        &dcg_program::kernel::test_kernel::MANIFEST_APP,
        None,
    )
    .await
}

async fn commit_route_free_app_tree_with_manifest(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
    target_form: u16,
    witness: &[u8],
    app: &'static dcg_program::kernel::ApplicationManifest,
    saved_admission_digest: Option<[u8; 32]>,
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
) {
    // The template's real (attested) admission marked it app-bound.
    assert_ne!(
        u16_at(&f.account(f.dea2).await, 6) & 2,
        0,
        "real admission sets the DEA2 app-bound flag"
    );

    let descriptor = f.descriptor(binding, &f.terms_raw, 16);
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let (segment, entries) = x.segment_row(p, ordinal).unwrap();
    let target_local = (0..entries)
        .find(|&local| {
            let Ok(index) = x.entry_index(p, segment, local) else {
                return false;
            };
            x.entry(p, index)
                .is_ok_and(|entry| entry.kernel_index == target_form)
        })
        .expect("the selected segment contains the requested app form");
    let t = x.entry_index(p, segment, target_local).unwrap();
    assert_eq!(x.entry(p, t).unwrap().kernel_index, target_form);
    let levels = challenge_tree_with_app_leaves_for(
        app,
        &descriptor,
        p,
        segment,
        entries,
        &[(target_local, target_form, witness)],
    );
    let tree = levels.last().unwrap()[0].digest;
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            &descriptor,
            &p.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    let table = x.segment_table_root(p).unwrap();
    let mut roots = (0..f.segments)
        .map(|i| {
            h::hash(
                b"c5-unselected-segment",
                &[&descriptor, &p.to_le_bytes(), &i.to_le_bytes()],
            )
        })
        .collect::<Vec<_>>();
    roots[ordinal] = segment_root;
    let position_root = h::position_root(&descriptor, p, &table, &roots).unwrap();
    let mut positions = f.position_roots[..f.k as usize].to_vec();
    positions[p as usize] = position_root;
    let (actual_descriptor, created) = f.run_document_with_roots(binding, &positions).await;
    assert_eq!(actual_descriptor, descriptor);
    f.finalize(&descriptor, created, f.k).await;
    if let Some(identity_digest) = saved_admission_digest {
        let mut document = f.account(created[0]).await;
        let option_count = document[BINDING_AT_V8 + 151] as usize;
        let identity_at = OPTION_REGION_AT + 4 * option_count;
        assert_eq!(document.len(), identity_at + document::APP_IDENTITY_BYTES);
        document[identity_at..identity_at + 4].copy_from_slice(b"ARI1");
        document[identity_at + 4..identity_at + 36].copy_from_slice(&identity_digest);
        document[identity_at + 36..identity_at + 64].fill(0);
        let lamports = f.lamports(created[0]).await;
        f.ctx.set_account(
            &created[0],
            &shared(Account {
                lamports,
                data: document,
                owner: f.program,
                executable: false,
                rent_epoch: 0,
            }),
        );
    }
    let document = f.account(created[0]).await;
    let identity = document::application_identity_v8(&document)
        .unwrap()
        .expect("app-bound fixture stores an ARI1 identity");
    assert_eq!(
        &identity[4..36],
        &app.admission_identity_digest()[..],
        "the document freezes this SBF image's admission identity"
    );
    (descriptor, created, roots, segment, target_local, levels)
}

async fn commit_challenge_tree_with_route_witness(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
    target_local: u32,
    producer_local: u32,
    target_witness: &[u8],
    producer_witness: &[u8],
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
    Vec<u8>,
) {
    let fixture = artifacts().expect("the retained emission");
    commit_challenge_tree_with_route_witness_from_artifacts(
        f,
        binding,
        p,
        ordinal,
        target_local,
        producer_local,
        target_witness,
        producer_witness,
        fixture,
    )
    .await
}

async fn commit_challenge_tree_with_route_witness_from_artifacts(
    f: &mut Fix,
    binding: &Binding2,
    p: u32,
    ordinal: usize,
    target_local: u32,
    producer_local: u32,
    target_witness: &[u8],
    producer_witness: &[u8],
    fixture: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
) -> (
    [u8; 32],
    [Pubkey; 4],
    Vec<[u8; 32]>,
    u16,
    u32,
    Vec<Vec<ChallengeNode>>,
    Vec<u8>,
) {
    // The template's real (attested) admission marked it app-bound.
    assert_ne!(
        u16_at(&f.account(f.dea2).await, 6) & 2,
        0,
        "real admission sets the DEA2 app-bound flag"
    );
    let descriptor = f.descriptor(binding, &f.terms_raw, 16);
    let (routes, geometry, payloads, pwr1, _) = fixture;
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let (segment, entries) = x.segment_row(p, ordinal).unwrap();
    let (levels, witness) = challenge_tree_with_route_leaves(
        &descriptor,
        p,
        segment,
        entries,
        target_local,
        target_witness,
        producer_local,
        producer_witness,
    );
    let tree = levels.last().unwrap()[0].digest;
    let segment_root = h::hash(
        b"segment-root/2",
        &[
            &descriptor,
            &p.to_le_bytes(),
            &segment.to_le_bytes(),
            &entries.to_le_bytes(),
            &tree,
            &[1],
        ],
    );
    let table = x.segment_table_root(p).unwrap();
    let mut roots = (0..f.segments)
        .map(|i| {
            h::hash(
                b"c5-unselected-segment",
                &[&descriptor, &p.to_le_bytes(), &i.to_le_bytes()],
            )
        })
        .collect::<Vec<_>>();
    roots[ordinal] = segment_root;
    let position_root = h::position_root(&descriptor, p, &table, &roots).unwrap();
    // The K=10,240 adapter measurement reuses the retained executor's 80
    // published roots as an 80-position completion over the larger template.
    let mut positions = f.position_roots.clone();
    assert!(
        (p as usize) < positions.len(),
        "challenge position is landed"
    );
    positions[p as usize] = position_root;
    let (actual_descriptor, created) = f.run_document_with_roots(binding, &positions).await;
    assert_eq!(actual_descriptor, descriptor);
    f.finalize(&descriptor, created, positions.len() as u32)
        .await;
    (
        descriptor,
        created,
        roots,
        segment,
        target_local,
        levels,
        witness,
    )
}

fn challenge_position_data(descriptor: &[u8; 32], p: u32, nonce: u32) -> Vec<u8> {
    let mut data = vec![TAG_CHALLENGE_POSITION];
    data.extend_from_slice(descriptor);
    data.extend_from_slice(&p.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    data
}

/// Find a descriptor/challenger nonce whose canonical bump search tries at
/// least 18 candidates. This reproduces the adversarial tag-184 address-search
/// case without depending on one test run's randomly generated signer.
fn ground_challenge_nonce(
    program: &Pubkey,
    descriptor: &[u8; 32],
    challenger: &Pubkey,
) -> (u32, u8) {
    for nonce in 0..2_000_000u32 {
        let (_, bump) = address::challenge(program, descriptor, challenger, nonce);
        let bump = bump.value();
        if bump <= 238 {
            return (nonce, bump);
        }
    }
    panic!("did not find a challenge nonce with at least 18 bump attempts");
}

/// Grind the user-chosen request id until its DCM2 descriptor has a costly
/// canonical bump search. The on-chain readers must use the bump stored at init
/// so that this chosen descriptor does not add variable address-search CU.
fn ground_document_descriptor(
    f: &Fix,
    binding: &mut Binding2,
    terms: &[u8],
    family_count: u16,
) -> ([u8; 32], u8, u32) {
    for candidate in 0..2_000_000u32 {
        let mut request_id = [0xa5; 32];
        request_id[..4].copy_from_slice(&candidate.to_le_bytes());
        binding.request_id = request_id;
        let descriptor = f.descriptor(binding, terms, family_count);
        let (_, bump) = address::document(&f.program, &descriptor);
        let bump = bump.value();
        if bump <= 238 {
            return (descriptor, bump, candidate + 1);
        }
    }
    panic!("did not find a descriptor with at least 18 bump attempts");
}

fn challenge_position_metas(f: &Fix, c: [Pubkey; 4], record: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(record, false),
        AccountMeta::new(f.signer.pubkey(), true),
        AccountMeta::new(c[0], false),
        AccountMeta::new_readonly(c[1], false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
        AccountMeta::new_readonly(f.drp2, false),
    ]
}

/// Drive the on-chain tag-163/164/168/169 position dispute through its final
/// fix-point, taking the tree branch containing `target_local` each time.
/// Returns the DCR1 PDA. Every normal round reads the real DCM2 v7; the final
/// tag 169 also reads the sealed plan and DRP2 class table.
async fn descend_position_challenge(
    f: &mut Fix,
    c: [Pubkey; 4],
    descriptor: &[u8; 32],
    roots: &[[u8; 32]],
    p: u32,
    ordinal: u16,
    segment: u16,
    target_local: u32,
    levels: &[Vec<ChallengeNode>],
    nonce: u32,
    stop_before_fixpoint: bool,
) -> Pubkey {
    descend_position_challenge_with_witness(
        f,
        c,
        descriptor,
        roots,
        p,
        ordinal,
        segment,
        target_local,
        levels,
        nonce,
        stop_before_fixpoint,
        None,
    )
    .await
}

async fn descend_position_challenge_with_witness(
    f: &mut Fix,
    c: [Pubkey; 4],
    descriptor: &[u8; 32],
    roots: &[[u8; 32]],
    p: u32,
    ordinal: u16,
    segment: u16,
    target_local: u32,
    levels: &[Vec<ChallengeNode>],
    nonce: u32,
    stop_before_fixpoint: bool,
    witness: Option<&[u8]>,
) -> Pubkey {
    let record = address::challenge(&f.program, descriptor, &f.signer.pubkey(), nonce).0;
    let open_metas = challenge_position_metas(f, c, record);
    label("challenge-open-position-167");
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(descriptor, p, nonce),
        open_metas,
    )
    .await
    .expect("tag 167 opens revision-8 challenge");

    if std::env::var_os("BASANOS_EXPECT_STORED_CHALLENGE_BUMP").is_some() {
        let opened = f.account(record).await;
        let (_, expected_bump) =
            address::challenge(&f.program, descriptor, &f.signer.pubkey(), nonce);
        assert_eq!(opened[challenge::RECORD_BUMP_AT], expected_bump.value());
        assert_eq!(opened[challenge::RECORD_BUMP_MARKER_AT], 1);
    }
    let opened = f.account(record).await;
    let (_, expected_response_bump) =
        dcg_program::closure_v2_response::address(&f.program, &record);
    assert_eq!(
        opened[challenge::RESPONSE_BUMP_STAGED_AT],
        expected_response_bump.value(),
        "tag 167 stores the canonical response bump"
    );

    let mut reveal_position = vec![TAG_REVEAL_POSITION, 0, 0, roots.len() as u8];
    for root in roots {
        reveal_position.extend_from_slice(root);
    }
    label("challenge-round-reveal-position-163");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        reveal_position,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(c[0], false),
            AccountMeta::new_readonly(c[1], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
        ],
    )
    .await
    .expect("tag 163 reveals roots");

    let mut select = vec![TAG_SELECT_SEGMENT];
    select.extend_from_slice(&ordinal.to_le_bytes());
    label("challenge-round-select-segment-164");
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        select,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.signer.pubkey(), true),
            AccountMeta::new_readonly(c[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
        ],
    )
    .await
    .expect("tag 164 selects segment");

    let entries = levels[0].len() as u32;
    let mut first = 0u32;
    let mut end = entries;
    let mut height = (levels.len() - 1) as u8;
    let mut opening = true;
    loop {
        let steps = height.min(4);
        let child_height = height - steps;
        let span = 1u32 << child_height;
        let count = end.div_ceil(span) - first / span;
        let children = &levels[child_height as usize]
            [(first / span) as usize..(first / span + count) as usize];
        let mut reveal = vec![TAG_REVEAL, count as u8];
        if opening {
            reveal.extend_from_slice(&levels.last().unwrap()[0].digest);
        }
        for child in children {
            reveal.extend_from_slice(&child.digest);
        }
        label("challenge-round-reveal-168");
        send(
            &mut f.ctx,
            &f.executor,
            f.program,
            reveal,
            vec![
                AccountMeta::new(record, false),
                AccountMeta::new(f.executor.pubkey(), true),
                AccountMeta::new_readonly(c[0], false),
            ],
        )
        .await
        .expect("tag 168 reveals a descent round");

        if stop_before_fixpoint && child_height == 0 {
            assert_eq!(f.account(record).await[4], challenge::PHASE_DESCEND);
            break;
        }
        let choice = (target_local - first) / span;
        let fix = child_height == 0;
        let mut descend = vec![TAG_DESCEND, choice as u8];
        if fix {
            if let Some(witness) = witness {
                descend.extend_from_slice(witness);
            }
        }
        let mut metas = vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.signer.pubkey(), true),
            AccountMeta::new(c[0], false),
        ];
        if fix {
            metas.extend([
                AccountMeta::new_readonly(f.pt2s, false),
                AccountMeta::new_readonly(f.routes, false),
                AccountMeta::new_readonly(f.geometry, false),
                AccountMeta::new_readonly(f.drp2, false),
                AccountMeta::new_readonly(f.pt1s_index, false),
            ]);
        }
        label("challenge-round-descend-rule-169");
        send(
            &mut f.ctx,
            &f.signer,
            f.program,
            std::mem::take(&mut descend),
            metas,
        )
        .await
        .expect("tag 169 descends; the final round also runs RULE");
        if fix {
            break;
        }
        first += choice * span;
        end = end.min(first + span);
        height = child_height;
        opening = false;
    }
    assert_eq!(
        segment,
        u16_at(&f.account(record).await, 160),
        "challenge segment stayed bound"
    );
    record
}

fn final_position_choice(levels: &[Vec<ChallengeNode>], target: u32) -> u8 {
    let mut first = 0u32;
    let mut height = (levels.len() - 1) as u8;
    loop {
        let child_height = height - height.min(4);
        let span = 1u32 << child_height;
        if child_height == 0 {
            return ((target - first) / span) as u8;
        }
        let choice = (target - first) / span;
        first += choice * span;
        height = child_height;
    }
}

fn app_replay_witness(schema_id: u32, input: &[u8], claimed_output: u64) -> Vec<u8> {
    let mut witness = Vec::with_capacity(12 + 8 + input.len() + 8);
    witness.extend_from_slice(b"ARW1");
    witness.extend_from_slice(&1u16.to_le_bytes());
    witness.push(1);
    witness.push(0);
    witness.extend_from_slice(&8u16.to_le_bytes());
    witness.extend_from_slice(&[0; 2]);
    witness.extend_from_slice(&schema_id.to_le_bytes());
    witness.extend_from_slice(&1u16.to_le_bytes());
    witness.extend_from_slice(&(input.len() as u16).to_le_bytes());
    witness.extend_from_slice(input);
    witness.extend_from_slice(&claimed_output.to_le_bytes());
    witness
}

fn app_route_producer_witness() -> Vec<u8> {
    app_route_producer_witness_with(&[1, 2, 3])
}

fn app_route_producer_witness_with(prefix: &[u8; 3]) -> Vec<u8> {
    let mut output = vec![0u8; 256];
    output[..3].copy_from_slice(prefix);
    let mut witness = Vec::with_capacity(12 + output.len());
    witness.extend_from_slice(b"ARW1");
    witness.extend_from_slice(&1u16.to_le_bytes());
    witness.push(0);
    witness.push(0);
    witness.extend_from_slice(&(output.len() as u16).to_le_bytes());
    witness.extend_from_slice(&[0; 2]);
    witness.extend_from_slice(&output);
    witness
}

fn app_route_producer_witness_padded(length: usize) -> Vec<u8> {
    let span_count = 16.min(length.saturating_sub(12 + 256) / 9);
    let fixed = 12 + span_count * 8 + 256;
    assert!(
        span_count > 0 && length >= fixed + span_count,
        "every producer span must be nonempty"
    );
    let input_bytes = length - fixed;
    let mut witness = Vec::with_capacity(length);
    witness.extend_from_slice(b"ARW1");
    witness.extend_from_slice(&1u16.to_le_bytes());
    witness.push(span_count as u8);
    witness.push(0);
    witness.extend_from_slice(&256u16.to_le_bytes());
    witness.extend_from_slice(&[0; 2]);
    let short = input_bytes / 16;
    let extra = input_bytes % 16;
    for span in 0..span_count {
        let span_len = short + if span < extra { 1 } else { 0 };
        witness.extend_from_slice(&1u32.to_le_bytes());
        witness.extend_from_slice(&1u16.to_le_bytes());
        witness.extend_from_slice(&(span_len as u16).to_le_bytes());
        witness.resize(witness.len() + span_len, span as u8);
    }
    let mut output = vec![0; 256];
    output[..3].copy_from_slice(&[1, 2, 3]);
    witness.extend_from_slice(&output);
    assert_eq!(witness.len(), length);
    witness
}

fn app_route_opening_900(path_height: u8) -> (Vec<u8>, Vec<u8>) {
    let producer_length = 855usize
        .checked_sub(32 * path_height as usize)
        .expect("RWP1 path fits in the 900-byte witness");
    let target = app_replay_witness(1, &[1, 2, 3], 6);
    let producer = app_route_producer_witness_padded(producer_length);
    assert_eq!(
        target.len() + 14 + producer.len() + 32 * path_height as usize,
        900
    );
    (target, producer)
}

async fn executor_opens_app_witness(f: &mut Fix, record: Pubkey, document: Pubkey, witness: &[u8]) {
    for (offset, chunk) in witness.chunks(400).enumerate() {
        let offset = offset * 400;
        let mut data = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
        data.extend_from_slice(&(witness.len() as u16).to_le_bytes());
        data.extend_from_slice(&(offset as u16).to_le_bytes());
        data.extend_from_slice(chunk);
        label("challenge-app-witness-stage-183");
        send(
            &mut f.ctx,
            &f.executor,
            f.program,
            data,
            vec![
                AccountMeta::new(record, false),
                AccountMeta::new(f.executor.pubkey(), true),
            ],
        )
        .await
        .expect("tag 183 stages the executor's opening");
    }
    let response_metas = vec![
        AccountMeta::new(record, false),
        AccountMeta::new(f.executor.pubkey(), true),
        AccountMeta::new(document, false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
        AccountMeta::new_readonly(f.drp2, false),
        AccountMeta::new_readonly(f.pt1s_index, false),
    ];
    // A corrupted DCM2 stored bump is a state only a program bug could write:
    // the DCM2 reader's unit test refuses it (result::reader_gate_tests).
    label("challenge-app-witness-respond-184");
    let compute_units = send_cu(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
        response_metas,
    )
    .await
    .expect("tag 184 authenticates and replays the executor's opening");
    eprintln!(
        "CU tag 184 data 1 cu {compute_units} mode {} label {}",
        if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() {
            "SBF"
        } else {
            "native"
        },
        current_label(),
    );
    if std::env::var_os("BASANOS_EXPECT_STORED_CHALLENGE_BUMP").is_some() {
        assert!(
            compute_units <= 1_329_427,
            "tag 184 adapter work must fit under the admitted kernel cap"
        );
    }
}

async fn settle_and_close_standard_app_challenge(
    f: &mut Fix,
    record: Pubkey,
    created: [Pubkey; 4],
    descriptor: [u8; 32],
    challenger_won: bool,
    terms: &Terms2,
) {
    let third_party = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, third_party.pubkey(), 1_000_000_000_000).await;
    let (response, response_bump) = dcg_program::closure_v2_response::address(&f.program, &record);
    let settled_record = f.account(record).await;
    assert_eq!(
        settled_record[dcg_program::unified::challenge::RESPONSE_BUMP_AT],
        response_bump.value(),
        "the response bump remains committed through replay"
    );
    assert_eq!(
        dcg_program::closure_v2_response::address_with_bump(
            &f.program,
            &record,
            settled_record[dcg_program::unified::challenge::RESPONSE_BUMP_AT]
        )
        .unwrap(),
        response,
        "the committed response bump derives the response PDA"
    );
    let record_before = f.lamports(record).await;
    let challenger_before = f.lamports(f.signer.pubkey()).await;
    let executor_before = f.lamports(f.executor.pubkey()).await;
    let document_before = f.lamports(created[0]).await;
    let winner = if challenger_won {
        f.signer.pubkey()
    } else {
        f.executor.pubkey()
    };
    let policy_winner = if challenger_won {
        f.signer.pubkey()
    } else {
        incinerator::ID
    };
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(winner, false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(policy_winner, false),
            AccountMeta::new(Pubkey::new_from_array(terms.bond_remainder), false),
        ],
    )
    .await
    .expect("tag 131 settles the app challenge");
    let record_rent = record_before - terms.challenger_bond_lamports;
    assert_eq!(f.lamports(record).await, 0);
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        challenger_before
            + record_rent
            + if challenger_won {
                terms.challenger_bond_lamports + terms.executor_bond_lamports
            } else {
                0
            }
    );
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        executor_before
            + if challenger_won {
                0
            } else {
                terms.challenger_bond_lamports
            }
    );
    assert_eq!(
        f.lamports(created[0]).await,
        document_before
            - if challenger_won {
                terms.executor_bond_lamports
            } else {
                0
            }
    );
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 0);

    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let dcm2_before_close = f.lamports(created[0]).await;
    let dpr2_before_close = f.lamports(created[1]).await;
    let dfs2_before_close = f.lamports(created[2]).await;
    let working_accounts_before_close = dcm2_before_close + dpr2_before_close + dfs2_before_close;
    let executor_before_close = f.lamports(f.executor.pubkey()).await;
    let incinerator_before_close = f.lamports(incinerator::ID).await;
    let close_bond_burned =
        if !challenger_won && f.account(created[0]).await[529] == document::BOND_HELD {
            terms.executor_bond_lamports
        } else {
            0
        };
    let document = f.account(created[0]).await;
    let deadline = u64_at(&document, 144).max(u64_at(&document, document::ABANDON_DEADLINE_AT)) + 1;
    clock_to(f, deadline).await;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    let close_metas = f.close_metas_slots(
        &c,
        third_party.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    );
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("tag 172 closes the settled app document");
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        executor_before_close + working_accounts_before_close - close_bond_burned
    );
    assert_eq!(
        f.lamports(incinerator::ID).await,
        incinerator_before_close + close_bond_burned,
        "tag 172 applies the withheld-document bond disposition"
    );
    assert_eq!(
        f.lamports(f.executor.pubkey()).await - executor_before_close
            + f.lamports(incinerator::ID).await
            - incinerator_before_close,
        working_accounts_before_close,
        "tag 172 accounts for every DCM2/DPR2/DFS2 lamport"
    );
    if close_bond_burned > 0 {
        assert_eq!(
            f.account(created[3]).await[6],
            result::STATUS_WITHHELD,
            "the unrefuted fixture has not completed result attestation"
        );
    }
    for key in created[..3].iter().copied() {
        assert_eq!(f.lamports(key).await, 0);
    }
}

async fn settle_and_close_neutral_app_challenge(
    f: &mut Fix,
    record: Pubkey,
    created: [Pubkey; 4],
    descriptor: [u8; 32],
    terms: &Terms2,
) {
    let third_party = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, third_party.pubkey(), 1_000_000_000_000).await;
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let record_before = f.lamports(record).await;
    let challenger_before = f.lamports(f.signer.pubkey()).await;
    let executor_before = f.lamports(f.executor.pubkey()).await;
    let document_before = f.lamports(created[0]).await;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(remainder, false),
        ],
    )
    .await
    .expect("tag 131 refunds a neutral app challenge");
    assert_eq!(f.lamports(record).await, 0);
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        challenger_before + record_before
    );
    assert_eq!(f.lamports(f.executor.pubkey()).await, executor_before);
    assert_eq!(f.lamports(created[0]).await, document_before);
    assert_eq!(f.account(created[0]).await[529], document::BOND_HELD);
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 0);

    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let document_lamports =
        f.lamports(created[0]).await + f.lamports(created[1]).await + f.lamports(created[2]).await;
    let executor_before_close = f.lamports(f.executor.pubkey()).await;
    let remainder_before_close = f.lamports(remainder).await;
    let incinerator_before_close = f.lamports(incinerator::ID).await;
    let document = f.account(created[0]).await;
    assert_eq!(
        &document[40..72],
        f.executor.pubkey().as_ref(),
        "the closed document's recorded payer is the executor"
    );
    let close_deadline =
        u64_at(&document, 144).max(u64_at(&document, document::ABANDON_DEADLINE_AT)) + 1;
    clock_to(f, close_deadline).await;
    let close_metas = f.close_metas_slots(
        &c,
        third_party.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    );
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("tag 172 closes after neutral settlement");
    let remainder_paid = f.lamports(remainder).await - remainder_before_close;
    let burned = f.lamports(incinerator::ID).await - incinerator_before_close;
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        executor_before_close + document_lamports - remainder_paid - burned
    );
    assert_eq!(remainder_paid + burned, terms.executor_bond_lamports);
    for key in created[..3].iter().copied() {
        assert_eq!(f.lamports(key).await, 0);
    }
}

fn challenge_leaf_packet(f: &Fix, descriptor: &[u8; 32], proof: &Rekeyed, nonce: u32) -> Vec<u8> {
    let packet = &proof.data;
    assert_eq!(packet[0], TAG_ATTEST_OUTPUT);
    let width = f.output_width as usize;
    let tail_len = u16_at(packet, 37 + width) as usize;
    let tail_at = 39 + width;
    let tail = &packet[tail_at..tail_at + tail_len];
    let height_at = tail_at + tail_len;
    let height = packet[height_at] as usize;
    let path_at = height_at + 1;
    let path = &packet[path_at..path_at + 32 * height];
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let t = x
        .old_to_new(f.base_entry, proof.p)
        .unwrap()
        .expect("output base entry");
    let coordinate = x.coordinate(proof.p, t).unwrap();
    let leaf_coordinate = h::Coordinate {
        position: proof.p,
        segment: coordinate.segment,
        entry: coordinate.local,
    };
    let mut leaf = Vec::new();
    leaf.extend_from_slice(LEAF_DOMAIN);
    leaf.extend_from_slice(descriptor);
    leaf.extend_from_slice(&leaf_coordinate.bytes());
    leaf.extend_from_slice(tail);
    let leaf_hash = leaf_hash_of(&leaf);
    let spp1_at = path_at + 32 * height;
    let (_, _, _, spp1_len) = challenge::decode_spp1(&packet[spp1_at..]).unwrap();
    let mut out = vec![TAG_CHALLENGE_LEAF];
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&proof.p.to_le_bytes());
    out.extend_from_slice(&coordinate.segment.to_le_bytes());
    out.extend_from_slice(&coordinate.local.to_le_bytes());
    out.extend_from_slice(&leaf_hash);
    out.push(height as u8);
    out.extend_from_slice(path);
    out.extend_from_slice(&packet[spp1_at..spp1_at + spp1_len]);
    out.extend_from_slice(&nonce.to_le_bytes());
    out
}

fn challenge_app_leaf_packet(
    f: &Fix,
    descriptor: &[u8; 32],
    roots: &[[u8; 32]],
    position: u32,
    ordinal: usize,
    segment: u16,
    local: u32,
    levels: &[Vec<ChallengeNode>],
    nonce: u32,
    witness: &[u8],
) -> Vec<u8> {
    let leaves = levels[0].iter().map(|node| node.digest).collect::<Vec<_>>();
    let (path, _) = f47_tree_path(descriptor, 1, position, &leaves, local as usize);
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let table_root = x.segment_table_root(position).unwrap();
    let (spp_path, _) = f47_tree_path(descriptor, 2, position, roots, ordinal);
    let mut out = vec![TAG_CHALLENGE_LEAF];
    out.extend_from_slice(descriptor);
    out.extend_from_slice(&position.to_le_bytes());
    out.extend_from_slice(&segment.to_le_bytes());
    out.extend_from_slice(&local.to_le_bytes());
    out.extend_from_slice(&leaves[local as usize]);
    out.push(path.len() as u8);
    for sibling in &path {
        out.extend_from_slice(sibling);
    }
    out.extend_from_slice(&(ordinal as u16).to_le_bytes());
    out.push(spp_path.len() as u8);
    out.push(0);
    out.extend_from_slice(&table_root);
    for sibling in &spp_path {
        out.extend_from_slice(sibling);
    }
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(witness);
    out
}

fn challenge_leaf_metas(f: &Fix, c: [Pubkey; 4], record: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(record, false),
        AccountMeta::new(f.signer.pubkey(), true),
        AccountMeta::new(c[0], false),
        AccountMeta::new_readonly(c[1], false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
        AccountMeta::new_readonly(f.drp2, false),
        AccountMeta::new_readonly(f.pt1s_index, false),
    ]
}

/// A real retained-rung-D output proof opens a revision-8 leaf challenge, and
/// the executor can answer the family-table round. A challenger that corrupts
/// the Merkle path is refused 586 before DCR1 creation or bond transfer.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_honest_leaf_challenge_uses_v7_document_reader_and_refuses_a_cheating_challenger() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created, proofs) = attest_all(&mut f, &binding, 31, &[], 81).await;
    assert_eq!(proofs.len(), 1);
    let honest = challenge_leaf_packet(&f, &descriptor, &proofs[0], 11);
    let mut cheat = challenge_leaf_packet(&f, &descriptor, &proofs[0], 12);
    cheat[76] ^= 1; // the first segment-path sibling no longer opens the landed root
    let rejected = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), 12).0;
    let rejected_metas = challenge_leaf_metas(&f, created, rejected);
    label("challenge-open-leaf-malformed-166");
    assert_eq!(
        custom(send_fresh(&mut f.ctx, &f.signer, f.program, cheat, rejected_metas).await),
        CL_PATH,
        "a false path is rejected before an open challenge is recorded"
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(rejected)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        u32_at(&f.account(created[0]).await, 128),
        0,
        "the refusal does not increment DCM2"
    );

    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), 11).0;
    let honest_metas = challenge_leaf_metas(&f, created, record);
    label("challenge-open-leaf-166");
    send(&mut f.ctx, &f.signer, f.program, honest, honest_metas)
        .await
        .expect("the retained attestation opens a challenge against DCM2 v7");
    let dcr1 = f.account(record).await;
    let (_, expected_response_bump) =
        dcg_program::closure_v2_response::address(&f.program, &record);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        expected_response_bump.value(),
        "tag 166 keeps the stable response bump through the fix-point scratch clear"
    );
    assert_eq!(
        dcr1[4],
        challenge::PHASE_RESPOND,
        "the honest class is admitted at fix-point"
    );
    assert_eq!(u32_at(&dcr1, 140), 11, "the v8 record keeps the open nonce");
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 1);

    // The compatibility response tags 115-118 read this revision-8 DCR1 and
    // its DRU1: the executor's honest upload, by real instructions. The record
    // gates' wrong-kind, second-instance and stale-identity refusals are
    // states only a program bug could write, so they are unit tests of the
    // readers (closure_v2_response::record_gate_tests; owner decision
    // 2026-10-02).
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let executor = f.executor.pubkey();
    let body = [1u8, 2, 3];
    let mut begin = vec![dcg_program::closure_v2_response::TAG_BEGIN];
    begin.extend_from_slice(&(body.len() as u32).to_le_bytes());
    begin.extend_from_slice(&sha256(&[&body]));
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        begin,
        vec![
            AccountMeta::new(response, false),
            AccountMeta::new(executor, true),
            AccountMeta::new_readonly(record, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
    .await
    .expect("tag 115 begins the honest DRU1 response");
    let write = [dcg_program::closure_v2_response::TAG_WRITE, 0, 0, 0, 0]
        .into_iter()
        .chain(body)
        .collect::<Vec<_>>();
    let response_metas = vec![
        AccountMeta::new(response, false),
        AccountMeta::new(executor, true),
        AccountMeta::new_readonly(record, false),
    ];
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::closure_v2_response::TAG_GROW],
        response_metas.clone(),
    )
    .await
    .expect("tag 116 grows the honest DRU1 response");
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        write,
        response_metas.clone(),
    )
    .await
    .expect("tag 117 writes the response body");
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::closure_v2_response::TAG_SEAL],
        response_metas,
    )
    .await
    .expect("tag 118 seals the response body");

    // Executor-side response, using the family-table round's real v8 reader.
    let mut reveal = vec![TAG_REVEAL_FAMILY_TABLE, 0, f.family_roots.len() as u8];
    for root in &f.family_roots {
        reveal.extend_from_slice(root);
    }
    label("challenge-round-family-table-173");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        reveal,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(created[0], false),
        ],
    )
    .await
    .expect("executor family-table response");
    let dcr1 = f.account(record).await;
    assert_eq!(
        dcr1[challenge::FTR_AT],
        1,
        "tag 173 verified the DCM2 v7 family digest"
    );
    assert_eq!(
        u16_at(&dcr1, challenge::FTR_AT + 2),
        f.family_roots.len() as u16
    );
}

/// The revision-8 opener rejects a malformed DCM2 and a real revision-7 DCM2
/// v6 account before creating the challenge record or escrowing a bond.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_challenge_open_refuses_malformed_and_revision7_documents() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, f.k).await;
    f.finalize(&descriptor, created, f.k).await;
    let data = challenge_position_data(&descriptor, 79, 31);
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), 31).0;
    let metas = challenge_position_metas(&f, created, record);
    let v8_doc = f.account(created[0]).await;

    let mut v7_doc = unhex(v7_golden()["dcm2_v6"]["finalized"].as_str().unwrap());
    v7_doc[8..40].copy_from_slice(&descriptor);
    f.ctx
        .set_account(&created[0], &shared(owned(&f.program, v7_doc)));
    assert_eq!(
        custom(send_fresh(&mut f.ctx, &f.signer, f.program, data, metas).await),
        731,
        "the revision-8 image refuses a genuine DCM2 v6 document"
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(record)
        .await
        .unwrap()
        .is_none());

    // A truncated DCM2 is a state only a program bug could write: the same
    // reader's unit test refuses it (result::reader_gate_tests). The v6 record
    // above is different: genuine revision-7 state from the retained golden,
    // kept until a named legacy mode can produce it.
    let _ = v8_doc;
}

/// Tag 167's coordinate is a landed position, bounded by this finalized
/// document's n at DCM2 84, not the template capacity K at DCM2 72.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_position_challenge_uses_document_length_not_capacity() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let (descriptor, created, _) = attest_all(&mut f, &binding, 31, &[], 81).await;
    let doc = f.account(created[0]).await;
    let (n, k) = (u32_at(&doc, 84), u32_at(&doc, 72));
    assert_eq!((n, k), (31, 80), "the fixture separates n from K");

    // The review's p=79 probe is the critical regression: it used to open,
    // leave the executor unable to reveal a landed root, and permit conviction.
    let probe_nonce = 55;
    let probe_record =
        address::challenge(&f.program, &descriptor, &f.signer.pubkey(), probe_nonce).0;
    let probe_metas = challenge_position_metas(&f, created, probe_record);
    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                challenge_position_data(&descriptor, 79, probe_nonce),
                probe_metas
            )
            .await
        ),
        CL_COORDINATE
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(probe_record)
        .await
        .unwrap()
        .is_none());

    let last_nonce = 56;
    let last_record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), last_nonce).0;
    let last_metas = challenge_position_metas(&f, created, last_record);
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(&descriptor, n - 1, last_nonce),
        last_metas,
    )
    .await
    .expect("p = n - 1 opens");
    assert_eq!(
        f.account(last_record).await[4],
        challenge::PHASE_POSITION_REVEAL
    );

    for (position, nonce) in [(n, 57), (k, 58)] {
        let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
        let metas = challenge_position_metas(&f, created, record);
        assert_eq!(
            custom_or_zero(
                send_fresh(
                    &mut f.ctx,
                    &f.signer,
                    f.program,
                    challenge_position_data(&descriptor, position, nonce),
                    metas
                )
                .await
            ),
            CL_COORDINATE,
            "p={position} is outside n={n}"
        );
        assert!(f
            .ctx
            .banks_client
            .get_account(record)
            .await
            .unwrap()
            .is_none());
    }
}

/// Permanent revision-8 refusal coverage for the opener and its first round.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_challenge_opener_refuses_wrong_phase_role_and_deadlines() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, 31).await;

    let before_finalize_nonce = 61;
    let before_finalize = address::challenge(
        &f.program,
        &descriptor,
        &f.signer.pubkey(),
        before_finalize_nonce,
    )
    .0;
    let before_finalize_metas = challenge_position_metas(&f, created, before_finalize);
    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                challenge_position_data(&descriptor, 30, before_finalize_nonce),
                before_finalize_metas
            )
            .await
        ),
        DCR1_AUTH_REFUSAL
    );

    f.finalize(&descriptor, created, 31).await;

    let executor_nonce = 62;
    let executor_record = address::challenge(
        &f.program,
        &descriptor,
        &f.executor.pubkey(),
        executor_nonce,
    )
    .0;
    let mut executor_metas = challenge_position_metas(&f, created, executor_record);
    executor_metas[1] = AccountMeta::new(f.executor.pubkey(), true);
    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.executor,
                f.program,
                challenge_position_data(&descriptor, 30, executor_nonce),
                executor_metas
            )
            .await
        ),
        DCR1_AUTH_REFUSAL
    );

    let valid_nonce = 63;
    let valid_record =
        address::challenge(&f.program, &descriptor, &f.signer.pubkey(), valid_nonce).0;
    let valid_metas = challenge_position_metas(&f, created, valid_record);
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(&descriptor, 3, valid_nonce),
        valid_metas,
    )
    .await
    .expect("valid tag 167 opens");

    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
                vec![
                    AccountMeta::new(valid_record, false),
                    AccountMeta::new(created[0], false)
                ]
            )
            .await
        ),
        CL_DEADLINE,
        "tag 132 is early before the response deadline"
    );

    let mut wrong_actor_reveal = vec![TAG_REVEAL_POSITION, 0, 0, f.segments as u8];
    for i in 0..f.segments {
        wrong_actor_reveal.extend_from_slice(&[i as u8 + 1; 32]);
    }
    let wrong_actor_metas = vec![
        AccountMeta::new(valid_record, false),
        AccountMeta::new(f.signer.pubkey(), true),
        AccountMeta::new_readonly(created[0], false),
        AccountMeta::new_readonly(created[1], false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
    ];
    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                wrong_actor_reveal,
                wrong_actor_metas
            )
            .await
        ),
        DCR1_AUTH_REFUSAL,
        "the challenger cannot sign the executor's tag 163"
    );

    let dispute_deadline = u64_at(&f.account(created[0]).await, 144);
    clock_to(&mut f, dispute_deadline + 1).await;
    let late_nonce = 64;
    let late_record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), late_nonce).0;
    let late_metas = challenge_position_metas(&f, created, late_record);
    assert_eq!(
        custom_or_zero(
            send_fresh(
                &mut f.ctx,
                &f.signer,
                f.program,
                challenge_position_data(&descriptor, 3, late_nonce),
                late_metas
            )
            .await
        ),
        CL_DEADLINE
    );
    assert!(f
        .ctx
        .banks_client
        .get_account(late_record)
        .await
        .unwrap()
        .is_none());
}

/// Replaying tag 164 after its first transition is a phase refusal (733).
#[tokio::test(flavor = "multi_thread")]
async fn rev8_replayed_segment_selection_refuses_phase() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let (descriptor, created, roots, _, _, _) =
        commit_challenge_tree(&mut f, &binding, 79, 0).await;
    let nonce = 65;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
    let open_metas = challenge_position_metas(&f, created, record);
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(&descriptor, 79, nonce),
        open_metas,
    )
    .await
    .expect("tag 167 opens");

    let mut reveal = vec![TAG_REVEAL_POSITION, 0, 0, roots.len() as u8];
    for root in &roots {
        reveal.extend_from_slice(root);
    }
    let reveal_metas = vec![
        AccountMeta::new(record, false),
        AccountMeta::new(f.executor.pubkey(), true),
        AccountMeta::new_readonly(created[0], false),
        AccountMeta::new_readonly(created[1], false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
    ];
    send(&mut f.ctx, &f.executor, f.program, reveal, reveal_metas)
        .await
        .expect("tag 163 reveals roots");

    let select = vec![dcg_program::unified::TAG_SELECT_SEGMENT, 0, 0];
    let select_metas = vec![
        AccountMeta::new(record, false),
        AccountMeta::new(f.signer.pubkey(), true),
        AccountMeta::new_readonly(created[0], false),
        AccountMeta::new_readonly(f.pt2s, false),
        AccountMeta::new_readonly(f.routes, false),
        AccountMeta::new_readonly(f.geometry, false),
    ];
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        select.clone(),
        select_metas.clone(),
    )
    .await
    .expect("first tag 164 selects the segment");
    assert_eq!(f.account(record).await[4], challenge::PHASE_REVEAL);
    let slot = f
        .ctx
        .banks_client
        .get_sysvar::<solana_program::clock::Clock>()
        .await
        .unwrap()
        .slot;
    f.ctx.warp_to_slot(slot + 1).unwrap();
    assert_eq!(
        custom_or_zero(send_fresh(&mut f.ctx, &f.signer, f.program, select, select_metas).await),
        DCR1_PHASE_REFUSAL
    );
}

/// A silent revision-8 executor loses after a position challenge. The executor's
/// STANDARD bond is smaller than an empty account's rent floor, so the
/// uncreditable remainder goes to the incinerator and never to the convict.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_position_challenge_rounds_convict_executor_and_burn_uncreditable_bond() {
    let Some(mut f) = build().await else { return };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = dcg_program::unified::terms::BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let binding = f.binding(29, 50);
    let (descriptor, created) = f.run_document(&binding, f.k).await;
    f.finalize(&descriptor, created, f.k).await;

    let nonce = 19u32;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
    let open_metas = challenge_position_metas(&f, created, record);
    label("challenge-open-position-167");
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(&descriptor, 79, nonce),
        open_metas,
    )
    .await
    .expect("the position challenge opens against the real DCM2 v7");
    assert_eq!(f.account(record).await[4], challenge::PHASE_POSITION_REVEAL);
    let response_deadline = u64_at(&f.account(record).await, 148);
    clock_to(&mut f, response_deadline + 1).await;
    label("challenge-timeout-executor-132");
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("tag 132 rules for the challenger after executor silence");
    let dcr1 = f.account(record).await;
    assert_eq!(
        dcr1[4],
        challenge::PHASE_RULED,
        "the missed reveal reached RULE"
    );
    assert_eq!(dcr1[5], 2, "the challenger wins against a silent executor");
    assert_eq!(dcr1[178], events::CAUSE_TIMEOUT);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        dcr1[challenge::RESPONSE_BUMP_STAGED_AT],
        "tag 132 commits the staged response bump when POSITION_REVEAL times out"
    );
    let (_, expected_response_bump) =
        dcg_program::closure_v2_response::address(&f.program, &record);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        expected_response_bump.value()
    );
    let doc = f.account(created[0]).await;
    assert_eq!(u16_at(&doc, 6) & FLAG_REFUTED, FLAG_REFUTED);
    assert_eq!(u32_at(&doc, 132), 1);
    assert_eq!(
        &doc[document::WINNER_AT_V8..document::WINNER_AT_V8 + 32],
        f.signer.pubkey().as_ref()
    );

    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    let before_challenger = f.lamports(f.signer.pubkey()).await;
    let record_rent_and_bond = f.lamports(record).await;
    let before_executor = f.lamports(f.executor.pubkey()).await;
    let before_doc = f.lamports(created[0]).await;
    let before_burn = f.lamports(incinerator::ID).await;
    label("challenge-rule-and-standard-settle-131");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(remainder, false),
        ],
    )
    .await
    .expect("tag 131 settles the convicted challenge");
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        before_challenger + record_rent_and_bond,
        "the challenge rent and its own bond return to the challenger who funded the record"
    );
    assert_eq!(
        f.lamports(record).await,
        0,
        "the challenge record is drained"
    );
    assert_eq!(
        f.lamports(incinerator::ID).await,
        before_burn + terms.executor_bond_lamports,
        "the uncreditable policy remainder is incinerated"
    );
    assert_eq!(
        f.lamports(created[0]).await,
        before_doc - terms.executor_bond_lamports
    );
    assert!(
        f.lamports(f.executor.pubkey()).await <= before_executor,
        "the convict receives none of the challenged bond"
    );
    assert_eq!(f.account(created[0]).await[529], document::BOND_PAID);

    // A third party may close the refuted document after its challenge window;
    // there are no open challenge records left after settle.
    let third_party = Keypair::new();
    f.ctx.set_account(
        &third_party.pubkey(),
        &shared(Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let close_metas = f.close_metas_slots(
        &c,
        third_party.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    );
    let rent_to_executor =
        f.lamports(created[0]).await + f.lamports(created[1]).await + f.lamports(created[2]).await;
    let before_close_executor = f.lamports(f.executor.pubkey()).await;
    let close_deadline = u64_at(&f.account(created[0]).await, 144) + 1;
    clock_to(&mut f, close_deadline).await;
    send(
        &mut f.ctx,
        &third_party,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("anyone may close the refuted document after the deadline");
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        before_close_executor + rent_to_executor,
        "document, position and family-record rent return to their recorded payer, not the closer"
    );
    for account in &created[..3] {
        assert_eq!(
            f.lamports(*account).await,
            0,
            "the rent-bearing account was drained"
        );
    }
    assert_eq!(f.account(created[3]).await[6], result::STATUS_REFUTED);
}

/// Both signing roles complete the position-reveal and segment-bisection
/// rounds on a committed revision-8 document, reaching an admitted fix-point.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_position_challenge_rounds_reach_an_admitted_fixpoint() {
    let Some(mut f) = build().await else { return };
    let mut binding = f.binding(29, 50);
    binding.request_id[0] = 4;
    let witness = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &witness).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        20,
        false,
        Some(&witness),
    )
    .await;
    #[cfg(feature = "test-kernel")]
    executor_opens_app_witness(&mut f, record, created[0], &witness).await;
    let dcr1 = f.account(record).await;
    #[cfg(feature = "test-kernel")]
    {
        assert_eq!(u16_at(&dcr1, 6), challenge::APP_REPLAY_VERSION);
        assert_eq!(dcr1[4], challenge::PHASE_RULED);
        assert_eq!(dcr1[5], 1, "the executor's opening defeats the challenger");
        assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
        assert_eq!(u32_at(&dcr1, challenge::DEV2_AT + 8), 0);
        assert_eq!(
            u32_at(&f.account(created[0]).await, 128),
            1,
            "the ruled challenge remains open until tag 131 settles it"
        );
    }
    #[cfg(not(feature = "test-kernel"))]
    {
        assert_eq!(dcr1[4], challenge::PHASE_RESPOND);
        assert_eq!(dcr1[5], 0, "an admitted fix-point does not select a winner");
        assert_eq!(
            u32_at(&dcr1, challenge::DEV2_AT + 8),
            0,
            "the frozen class admits the instance"
        );
        assert_eq!(u32_at(&f.account(created[0]).await, 128), 1);
    }
}

/// A valid but incorrect route-free output is convicted by the app replay
/// fast path. Tag 131 settles the STANDARD bond and tag 172 closes the doc.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_bytesum_wrong_output_rules_and_settles_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let binding = f.binding(29, 50);
    let witness = app_route_producer_witness_with(&[4, 5, 6]);
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &witness).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        90,
        false,
        Some(&witness),
    )
    .await;
    let dcr1 = f.account(record).await;
    assert_eq!(u16_at(&dcr1, 6), challenge::APP_REPLAY_VERSION);
    assert_eq!(
        dcr1[challenge::APP_IDENTITY_AT..challenge::APP_IDENTITY_AT + 4],
        *b"ARI1"
    );
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 2, "the executor loses a committed bad output");
    assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
    assert_eq!(
        u32_at(&dcr1, challenge::DEV2_AT + 8),
        800,
        "the incorrect ByteSum output is ruled against the executor"
    );
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        FLAG_REFUTED
    );

    // An identity upgrade cannot erase a recorded challenger win. Phase is
    // checked before the app-identity branch, and settlement must still pay
    // the winner already written by tag 169.
    let mut changed_document = f.account(created[0]).await;
    let app_identity = document::application_identity_v8(&changed_document)
        .unwrap()
        .expect("the challenged document is app-bound");
    let option_count = changed_document[document::BINDING_AT_V8 + 151] as usize;
    let identity_at = document::OPTION_REGION_AT + option_count * 4;
    assert_eq!(
        &changed_document[identity_at..identity_at + 64],
        &app_identity
    );
    changed_document[identity_at + 4] ^= 1;
    let document_lamports = f.lamports(created[0]).await;
    f.ctx.set_account(
        &created[0],
        &shared(Account {
            lamports: document_lamports,
            data: changed_document,
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let ruled_before_timeout = f.account(record).await;
    let refused_timeout = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await;
    assert!(matches!(
        refused_timeout,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(733)
        ))
    ));
    assert_eq!(f.account(record).await, ruled_before_timeout);

    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    let record_rent_and_bond = f.lamports(record).await;
    let before_challenger = f.lamports(f.signer.pubkey()).await;
    let before_doc = f.lamports(created[0]).await;
    label("challenge-rule-and-standard-settle-131");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(remainder, false),
        ],
    )
    .await
    .expect("tag 131 settles against the cheating executor");
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        before_challenger + record_rent_and_bond
    );
    assert_eq!(f.lamports(record).await, 0);
    assert_eq!(
        f.lamports(created[0]).await,
        before_doc - terms.executor_bond_lamports
    );
    assert_eq!(f.account(created[0]).await[529], document::BOND_PAID);

    let third_party = Keypair::new();
    f.ctx.set_account(
        &third_party.pubkey(),
        &shared(Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: SYSTEM,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let close_metas = f.close_metas_slots(
        &c,
        third_party.pubkey(),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    );
    let rent_to_executor =
        f.lamports(created[0]).await + f.lamports(created[1]).await + f.lamports(created[2]).await;
    let before_close_executor = f.lamports(f.executor.pubkey()).await;
    let close_deadline = u64_at(&f.account(created[0]).await, 144) + 1;
    clock_to(&mut f, close_deadline).await;
    label("document-close-refuted-172");
    send(
        &mut f.ctx,
        &third_party,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("tag 172 closes the settled refuted document");
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        before_close_executor + rent_to_executor
    );
    assert_eq!(f.lamports(created[0]).await, 0);
    assert_eq!(f.account(created[3]).await[6], result::STATUS_REFUTED);
}

/// A matching challenger fast-path witness with a correct route-free output
/// must not convict. The executor opens the same witness to defeat the
/// challenge.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_bytesum_matching_honest_fastpath_enters_respond_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let mut binding = f.binding(29, 50);
    binding.request_id[0] = 4;
    let committed = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &committed).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        95,
        false,
        Some(&committed),
    )
    .await;
    let pending = f.account(record).await;
    assert_eq!(pending[4], challenge::PHASE_RESPOND);
    assert_eq!(pending[5], 0, "honest replay does not punish the executor");

    executor_opens_app_witness(&mut f, record, created[0], &committed).await;
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 1, "the honest executor defeats the challenge");
    assert_eq!(ruled[178], events::CAUSE_APP_REPLAY);
    assert_eq!(u32_at(&ruled, challenge::DEV2_AT + 8), 0);
    assert_eq!(u32_at(&ruled, 170), u32_at(&ruled, challenge::DEV2_AT + 20));
    assert_eq!(u16_at(&ruled, 174), u16_at(&ruled, challenge::DEV2_AT + 24));
    assert_eq!(u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED, 0);

    // The identity change must not erase an already-recorded executor win.
    let mut changed_document = f.account(created[0]).await;
    let app_identity = document::application_identity_v8(&changed_document)
        .unwrap()
        .expect("the challenged document is app-bound");
    let option_count = changed_document[document::BINDING_AT_V8 + 151] as usize;
    let identity_at = document::OPTION_REGION_AT + option_count * 4;
    assert_eq!(
        &changed_document[identity_at..identity_at + 64],
        &app_identity
    );
    changed_document[identity_at + 4] ^= 1;
    let document_lamports = f.lamports(created[0]).await;
    f.ctx.set_account(
        &created[0],
        &shared(Account {
            lamports: document_lamports,
            data: changed_document,
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let ruled_before_timeout = f.account(record).await;
    let refused_timeout = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await;
    assert!(matches!(
        refused_timeout,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(733)
        ))
    ));
    assert_eq!(f.account(record).await, ruled_before_timeout);

    let second_response = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
        ],
    )
    .await;
    assert!(matches!(
        second_response,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(733)
        ))
    ));
    settle_and_close_standard_app_challenge(&mut f, record, created, descriptor, false, &terms)
        .await;
}

/// Tag 184's full staged-byte ceiling on the retained K=10,240 template. The
/// 900-byte RWP1 opens a valid route on this test kernel, while the padded
/// producer spans remain irrelevant to its committed output. This measures
/// the routed adapter and plan view, not general kernel runtime.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_app_respond_full_900_witness_k10240_sbf() {
    let Some(mut f) = build_k10240_pre_admitted().await else {
        eprintln!("needs_local_artifacts: retained K=10,240 PT2P fixture absent");
        return;
    };
    if f.k != 10_240 || std::env::var_os("BASANOS_DCG_V8_SBF").is_none() {
        eprintln!("needs_local_artifacts: set the K=10,240 PT2P root and SBF image");
        return;
    }
    let (routes, geometry, payloads, pwr1, _) =
        k10240_artifacts().expect("the retained K=10,240 emission");
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        None,
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let mut target = None;
    'positions: for position in 0..x.position_count.min(f.position_roots.len() as u32) {
        for ordinal in 0..x.segment_count as usize {
            let (segment, entries) = x.segment_row(position, ordinal).unwrap();
            for local in 0..entries {
                let Ok(index) = x.entry_index(position, segment, local) else {
                    continue;
                };
                let Ok(entry) = x.entry(position, index) else {
                    continue;
                };
                if entry.kernel_index != 22 || entry.read_count <= 7 {
                    continue;
                }
                let Ok(route) = x.route(&entry, 7) else {
                    continue;
                };
                let Ok(producer) = x.entry(position, route.producer_entry) else {
                    continue;
                };
                let Ok(coordinate) = x.coordinate(position, route.producer_entry) else {
                    continue;
                };
                if route.direction == 0
                    && route.byte_length == 256
                    && producer.kernel_index == 30
                    && coordinate.segment == segment
                    && coordinate.local < local
                {
                    target = Some((position, ordinal, segment, local, coordinate.local, entries));
                    break 'positions;
                }
            }
        }
    }
    let (position, ordinal, _target_segment, target_local, producer_local, entries) =
        target.expect("the K=10,240 plan has a bound Form-22 route from Form 30");
    let (consumer, producer) =
        app_route_opening_900(dcg_program::root_only::path_height(entries).unwrap());
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 10_000;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let mut binding = f.binding(29, 50);
    let (grounded_descriptor, document_bump, descriptor_attempts) =
        ground_document_descriptor(&f, &mut binding, &f.terms_raw, 16);
    let (descriptor, created, roots, segment, actual_target, levels, witness) =
        commit_challenge_tree_with_route_witness_from_artifacts(
            &mut f,
            &binding,
            position,
            ordinal,
            target_local,
            producer_local,
            &consumer,
            &producer,
            k10240_artifacts().expect("the retained K=10,240 emission"),
        )
        .await;
    assert_eq!(descriptor, grounded_descriptor);
    let doc_identity = document::application_identity_v8(&f.account(created[0]).await)
        .unwrap()
        .expect("the K=10,240 app-bound document stores ARI1");
    assert_eq!(
        &doc_identity[4..36],
        &dcg_program::kernel::test_kernel::MANIFEST_APP.admission_identity_digest(),
        "document and loaded SBF app identities agree before the fix-point"
    );
    assert_eq!(actual_target, target_local);
    assert_eq!(witness.len(), 900);
    let (nonce, bump) = ground_challenge_nonce(&f.program, &descriptor, &f.signer.pubkey());
    eprintln!(
        "tag-184 ground case descriptor={} document_bump={} descriptor_candidates={} nonce={} challenge_bump={} challenge_attempts={}",
        descriptor
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        document_bump,
        descriptor_attempts,
        nonce,
        bump,
        256 - bump as u16,
    );
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        position,
        ordinal as u16,
        segment,
        actual_target,
        &levels,
        nonce,
        false,
        Some(&witness),
    )
    .await;
    let descended = f.account(record).await;
    assert_eq!(
        descended[4],
        challenge::PHASE_RESPOND,
        "unexpected early rule: winner {}, cause {}, replay code {}",
        descended[5],
        descended[178],
        u32_at(&descended, challenge::DEV2_AT + 8),
    );
    if std::env::var_os("BASANOS_EXPECT_STORED_CHALLENGE_BUMP").is_some() {
        let original = f
            .ctx
            .banks_client
            .get_account(record)
            .await
            .unwrap()
            .expect("the challenge account remains open");
        let mut corrupt = original.clone();
        corrupt.data[challenge::RECORD_BUMP_AT] =
            corrupt.data[challenge::RECORD_BUMP_AT].wrapping_add(1);
        f.ctx
            .set_account(&record, &AccountSharedData::from(corrupt));
        let mut stage = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
        stage.extend_from_slice(&(witness.len() as u16).to_le_bytes());
        stage.extend_from_slice(&0u16.to_le_bytes());
        stage.push(witness[0]);
        assert_eq!(
            custom(
                send(
                    &mut f.ctx,
                    &f.executor,
                    f.program,
                    stage,
                    vec![
                        AccountMeta::new(record, false),
                        AccountMeta::new(f.executor.pubkey(), true),
                    ],
                )
                .await,
            ),
            DCR1_AUTH_REFUSAL,
            "a corrupted stored bump must fail before response bytes are read"
        );
        f.ctx
            .set_account(&record, &AccountSharedData::from(original));
    }
    label("challenge-app-witness-respond-184-full900-k10240");
    executor_opens_app_witness(&mut f, record, created[0], &witness).await;
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 1);
    assert_eq!(u32_at(&ruled, challenge::DEV2_AT + 8), 0);
}

/// A challenger who supplies a preimage that does not open the committed
/// route-free app leaf has not proved anything. The executor opens the
/// committed preimage in RESPOND and defeats the challenge.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_bytesum_malicious_challenger_loses_app_replay_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut binding = f.binding(29, 50);
    binding.request_id[0] = 2;
    let committed = app_route_producer_witness();
    let forged = app_route_producer_witness_with(&[4, 5, 6]);
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &committed).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        91,
        false,
        Some(&forged),
    )
    .await;
    executor_opens_app_witness(&mut f, record, created[0], &committed).await;
    let dcr1 = f.account(record).await;
    assert_eq!(u16_at(&dcr1, 6), challenge::APP_REPLAY_VERSION);
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 1, "the malicious challenger loses");
    assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
    assert_eq!(u32_at(&dcr1, challenge::DEV2_AT + 8), 0);
    assert_eq!(u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED, 0);
}

/// A malformed committed ARW1 leaf is admitted as a Merkle commitment, then
/// the executor is ruled out with code 799 when tag 184 cannot decode it.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_bytesum_malformed_committed_input_rules_executor_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 10_000;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let mut binding = f.binding(29, 50);
    binding.request_id[0] = 3;
    let mut malformed = app_route_producer_witness();
    malformed[10] = 1; // ARW1 reserved bytes must be zero.
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &malformed).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        92,
        false,
        Some(&malformed),
    )
    .await;
    executor_opens_app_witness(&mut f, record, created[0], &malformed).await;
    let dcr1 = f.account(record).await;
    assert_eq!(u16_at(&dcr1, 6), challenge::APP_REPLAY_VERSION);
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 2, "unreplayable committed input convicts executor");
    assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
    assert_eq!(u32_at(&dcr1, challenge::DEV2_AT + 8), 799);
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        FLAG_REFUTED
    );
    settle_and_close_standard_app_challenge(&mut f, record, created, descriptor, true, &terms)
        .await;
}

/// A committed incorrect route-free output still convicts the executor when
/// it opens the committed leaf in RESPOND.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_bytesum_fake_input_against_predecessor_loses_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let fake = app_route_producer_witness_with(&[4, 5, 6]);
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &fake).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        94,
        false,
        None,
    )
    .await;

    executor_opens_app_witness(&mut f, record, created[0], &fake).await;
    let dcr1 = f.account(record).await;
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 2, "the executor loses for fake predecessor bytes");
    assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
    assert_eq!(u32_at(&dcr1, challenge::DEV2_AT + 8), 800);
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        FLAG_REFUTED
    );
}

/// Form 22 selects route ordinal 7 from a multi-read plan entry. If the
/// challenger's opening does not reach a terminal replay ruling, the app-bound
/// challenge remains in RESPOND for the executor instead of being neutralized.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_multi_read_form_with_unresolved_opening_stays_in_respond_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let fake_output = [4, 5, 6];
    let consumer = app_replay_witness(1, &fake_output, 15);
    let producer = app_route_producer_witness_with(&fake_output);
    let (descriptor, created, roots, segment, _, levels, committed) =
        commit_challenge_tree_with_route_witness(
            &mut f, &binding, 79, 1, 235, 207, &consumer, &producer,
        )
        .await;

    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        235,
        &levels,
        114,
        false,
        Some(&committed),
    )
    .await;
    let ruling = f.account(record).await;
    assert_eq!(ruling[4], challenge::PHASE_RESPOND);
    assert_eq!(u16_at(&ruling, 6), challenge::APP_REPLAY_VERSION);
    assert_eq!(ruling[5], 0);
    assert_eq!(
        u32_at(&ruling, challenge::DEV2_AT + 8),
        challenge::OUTCOME_PENDING as u32
    );
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        0,
        "an unbound non-app coordinate does not refute the document"
    );
}

/// Distinct challenger PDAs may contest the same committed app leaf. Each
/// executor response is scoped to its own DCR1 record and uses the same proof.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_two_challengers_can_contest_the_same_app_leaf_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let committed = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &committed).await;

    let first_record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        117,
        false,
        Some(&committed),
    )
    .await;

    let first_challenger = std::mem::replace(&mut f.signer, Keypair::new());
    fund_system(&mut f.ctx, &f.executor, f.signer.pubkey(), 1_000_000_000_000).await;
    let second_record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        118,
        false,
        Some(&committed),
    )
    .await;
    f.signer = first_challenger;

    assert_ne!(first_record, second_record);
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 2);
    for record in [first_record, second_record] {
        assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);
        executor_opens_app_witness(&mut f, record, created[0], &committed).await;
        let ruled = f.account(record).await;
        assert_eq!(ruled[4], challenge::PHASE_RULED);
        assert_eq!(ruled[5], 1, "each honest replay defeats its challenge");
    }
}

/// Missing and malformed executor openings keep the fix-point in RESPOND.
/// Neither a random payload nor a well-formed ARW1 from another coordinate
/// rules against the executor; timeout then awards the challenger.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_app_respond_rejects_bad_openings_and_timeout_favors_challenger_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 10_000;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let binding = f.binding(29, 50);
    let committed = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &committed).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        93,
        false,
        None,
    )
    .await;
    let opened = f.account(record).await;
    assert_eq!(opened[4], challenge::PHASE_RESPOND);
    assert_eq!(opened[5], 0, "an unanswered fix-point has no winner");

    let wrong_signer = b"x";
    let mut wrong_signer_stage = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    wrong_signer_stage.extend_from_slice(&(wrong_signer.len() as u16).to_le_bytes());
    wrong_signer_stage.extend_from_slice(&0u16.to_le_bytes());
    wrong_signer_stage.extend_from_slice(wrong_signer);
    let wrong_signer_result = send_fresh_with(
        &mut f.ctx,
        &f.signer,
        f.program,
        wrong_signer_stage,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.signer.pubkey(), true),
        ],
    )
    .await;
    assert!(matches!(
        wrong_signer_result,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(731)
        ))
    ));

    let mut partial = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    partial.extend_from_slice(&(committed.len() as u16).to_le_bytes());
    partial.extend_from_slice(&0u16.to_le_bytes());
    partial.extend_from_slice(&committed[..10]);
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        partial,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await
    .expect("executor may begin staging at offset zero");
    let mut out_of_order = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    out_of_order.extend_from_slice(&(committed.len() as u16).to_le_bytes());
    out_of_order.extend_from_slice(&20u16.to_le_bytes());
    out_of_order.extend_from_slice(b"bad");
    let out_of_order_result = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        out_of_order,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await;
    assert!(matches!(
        out_of_order_result,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(788)
        ))
    ));
    let mut restart = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    restart.extend_from_slice(&(committed.len() as u16).to_le_bytes());
    restart.extend_from_slice(&0u16.to_le_bytes());
    restart.extend_from_slice(&committed[..10]);
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        restart,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await
    .expect("offset zero restarts and clears a partial candidate");

    let mut oversize = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    oversize.extend_from_slice(&901u16.to_le_bytes());
    oversize.extend_from_slice(&0u16.to_le_bytes());
    oversize.resize(5 + 901, 0xff);
    let oversize_result = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        oversize,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await;
    assert!(matches!(
        oversize_result,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(730)
        ))
    ));

    let mut wrong_output = committed.clone();
    *wrong_output.last_mut().unwrap() ^= 1;
    for bad_opening in [b"random-not-arw1".as_slice(), wrong_output.as_slice()] {
        let mut stage = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
        stage.extend_from_slice(&(bad_opening.len() as u16).to_le_bytes());
        stage.extend_from_slice(&0u16.to_le_bytes());
        stage.extend_from_slice(bad_opening);
        send_fresh_with(
            &mut f.ctx,
            &f.executor,
            f.program,
            stage,
            vec![
                AccountMeta::new(record, false),
                AccountMeta::new(f.executor.pubkey(), true),
            ],
        )
        .await
        .expect("tag 183 stages a bounded opening candidate");
        let response = send_fresh_with(
            &mut f.ctx,
            &f.executor,
            f.program,
            vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
            vec![
                AccountMeta::new(record, false),
                AccountMeta::new(f.executor.pubkey(), true),
                AccountMeta::new(created[0], false),
                AccountMeta::new_readonly(f.pt2s, false),
                AccountMeta::new_readonly(f.routes, false),
                AccountMeta::new_readonly(f.geometry, false),
                AccountMeta::new_readonly(f.drp2, false),
                AccountMeta::new_readonly(f.pt1s_index, false),
            ],
        )
        .await;
        assert!(matches!(
            response,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::Custom(730)
            ))
        ));
        assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);
    }

    let deadline = u64_at(&f.account(record).await, 148);
    clock_to(&mut f, deadline).await;
    let exact_deadline_opening = b"bad";
    let mut exact_stage = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    exact_stage.extend_from_slice(&(exact_deadline_opening.len() as u16).to_le_bytes());
    exact_stage.extend_from_slice(&0u16.to_le_bytes());
    exact_stage.extend_from_slice(exact_deadline_opening);
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        exact_stage,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await
    .expect("tag 183 accepts the exact deadline slot");
    let exact_response = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
        ],
    )
    .await;
    assert!(matches!(
        exact_response,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(730)
        ))
    ));
    let exact_timeout = send_fresh_with(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await;
    assert!(matches!(
        exact_timeout,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(736)
        ))
    ));
    clock_to(&mut f, deadline + 1).await;
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("an unanswered executor loses at timeout");
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 2);
    assert_eq!(ruled[178], events::CAUSE_TIMEOUT);
    let after_timeout_response = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
        ],
    )
    .await;
    assert!(matches!(
        after_timeout_response,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(733)
        ))
    ));
    settle_and_close_standard_app_challenge(&mut f, record, created, descriptor, true, &terms)
        .await;
}

/// A DCR1 app identity that no longer matches the running image cannot turn
/// timeout into an executor loss. The ruling is neutral and tag 131 refunds
/// the challenge bond before tag 172 closes the document.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_app_identity_change_during_respond_is_neutral_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let binding = f.binding(29, 50);
    let witness = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &witness).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        116,
        false,
        None,
    )
    .await;
    assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);
    // Simulate a new image identity while the turn is pending. The bytes are
    // otherwise a well-formed DCR1 v6 app record, so tag 132 exercises the
    // same identity comparison as an upgraded static manifest.
    let mut changed = f.account(record).await;
    assert_eq!(u16_at(&changed, 6), challenge::APP_REPLAY_VERSION);
    changed[challenge::APP_IDENTITY_AT + 4] ^= 1;
    let record_lamports = f.lamports(record).await;
    f.ctx.set_account(
        &record,
        &shared(Account {
            lamports: record_lamports,
            data: changed,
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let deadline = u64_at(&f.account(record).await, 148) + 1;
    clock_to(&mut f, deadline).await;
    send_fresh_with(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("identity mismatch times out neutrally");
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 0);
    assert_eq!(ruled[178], events::CAUSE_APP_IDENTITY_CHANGED);
    assert_eq!(
        u32_at(&ruled, challenge::DEV2_AT + 8),
        challenge::OUTCOME_IDENTITY_CHANGED as u32
    );
    assert_eq!(u32_at(&ruled, 170), u32_at(&ruled, challenge::DEV2_AT + 20));
    assert_eq!(u16_at(&ruled, 174), u16_at(&ruled, challenge::DEV2_AT + 24));
    assert_eq!(u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED, 0);
    assert_eq!(u32_at(&f.account(created[0]).await, 132), 0);
    settle_and_close_neutral_app_challenge(&mut f, record, created, descriptor, &terms).await;
}

/// A committed non-ARW1 preimage cannot be opened by a different executor
/// payload. The refusal leaves RESPOND open, and timeout awards the challenger.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_non_arw1_committed_leaf_executor_timeout_favors_challenger_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let invalid_preimage = b"committed-random-leaf";
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, invalid_preimage).await;
    let record = descend_position_challenge_with_witness(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        99,
        false,
        None,
    )
    .await;
    assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);

    let random = b"not-the-committed-leaf";
    let mut stage = vec![dcg_program::unified::TAG_STAGE_APP_WITNESS];
    stage.extend_from_slice(&(random.len() as u16).to_le_bytes());
    stage.extend_from_slice(&0u16.to_le_bytes());
    stage.extend_from_slice(random);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        stage,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
        ],
    )
    .await
    .expect("tag 183 stages the mismatching random opening");
    let response = send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::unified::TAG_RESPOND_APP_WITNESS],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
        ],
    )
    .await;
    assert!(matches!(
        response,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(730)
        ))
    ));
    assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);

    let deadline = u64_at(&f.account(record).await, 148) + 1;
    clock_to(&mut f, deadline).await;
    send_fresh_with(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("tag 132 awards the challenger after the executor cannot open the leaf");
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(ruled[5], 2);
    assert_eq!(ruled[178], events::CAUSE_TIMEOUT);
}

/// The empty compatibility image preserves its old exact data lengths for
/// tags 166, 168, and 169. A trailing replay witness is refused with 730; an
/// exact tag-169 retry enters RESPOND.
#[cfg(not(feature = "test-kernel"))]
#[tokio::test(flavor = "multi_thread")]
async fn rev8_empty_application_refuses_witness_tails_for_166_168_169_sbf() {
    assert!(std::env::var_os("BASANOS_DCG_V8_SBF").is_some());

    // Tag 166: a valid ROOT_ONLY challenge leaf plus any replay tail is not a
    // compatible legacy instruction when EMPTY_APPLICATION has no form map.
    let Some(mut leaf_fix) = build().await else {
        panic!("retained artifacts absent")
    };
    let leaf_binding = leaf_fix.binding(29, 50);
    let (leaf_descriptor, leaf_doc, proofs) =
        attest_all(&mut leaf_fix, &leaf_binding, 31, &[], 96).await;
    let leaf_nonce = 96;
    let mut leaf_data = challenge_leaf_packet(&leaf_fix, &leaf_descriptor, &proofs[0], leaf_nonce);
    leaf_data.extend_from_slice(&app_replay_witness(1, &[1, 2, 3], 6));
    let leaf_record = address::challenge(
        &leaf_fix.program,
        &leaf_descriptor,
        &leaf_fix.signer.pubkey(),
        leaf_nonce,
    )
    .0;
    let leaf_metas = challenge_leaf_metas(&leaf_fix, leaf_doc, leaf_record);
    let refused = send_fresh_with(
        &mut leaf_fix.ctx,
        &leaf_fix.signer,
        leaf_fix.program,
        leaf_data,
        leaf_metas,
    )
    .await;
    assert_eq!(custom(refused), 730, "tag 166 rejects replay tails");

    // Tag 168, k=0: start a real position challenge and select the segment.
    // The retained fixture has no singleton segment, so set only the state
    // discriminator needed to reach the empty-app length guard. The guard
    // runs before the deliberately absent tree proof is examined.
    let Some(mut zero_fix) = build().await else {
        panic!("retained artifacts absent")
    };
    let zero_binding = zero_fix.binding(29, 50);
    let (descriptor, created, roots, _segment, _target, _levels) =
        commit_challenge_tree(&mut zero_fix, &zero_binding, 79, 1).await;
    let nonce = 97;
    let record = address::challenge(
        &zero_fix.program,
        &descriptor,
        &zero_fix.signer.pubkey(),
        nonce,
    )
    .0;
    let zero_open_metas = challenge_position_metas(&zero_fix, created, record);
    send(
        &mut zero_fix.ctx,
        &zero_fix.signer,
        zero_fix.program,
        challenge_position_data(&descriptor, 79, nonce),
        zero_open_metas,
    )
    .await
    .expect("tag 167 opens the position challenge");
    let mut position_roots = vec![TAG_REVEAL_POSITION, 0, 0, roots.len() as u8];
    for root in &roots {
        position_roots.extend_from_slice(root);
    }
    send(
        &mut zero_fix.ctx,
        &zero_fix.executor,
        zero_fix.program,
        position_roots,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(zero_fix.executor.pubkey(), true),
            AccountMeta::new_readonly(created[0], false),
            AccountMeta::new_readonly(created[1], false),
            AccountMeta::new_readonly(zero_fix.pt2s, false),
            AccountMeta::new_readonly(zero_fix.routes, false),
            AccountMeta::new_readonly(zero_fix.geometry, false),
        ],
    )
    .await
    .expect("tag 163 reveals segment roots");
    let mut select = vec![TAG_SELECT_SEGMENT];
    select.extend_from_slice(&1u16.to_le_bytes());
    send(
        &mut zero_fix.ctx,
        &zero_fix.signer,
        zero_fix.program,
        select,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(zero_fix.signer.pubkey(), true),
            AccountMeta::new_readonly(created[0], false),
            AccountMeta::new_readonly(zero_fix.pt2s, false),
            AccountMeta::new_readonly(zero_fix.routes, false),
            AccountMeta::new_readonly(zero_fix.geometry, false),
        ],
    )
    .await
    .expect("tag 164 selects the segment");
    let mut raw = zero_fix.account(record).await;
    raw[challenge::HEADER + 40] = 0;
    zero_fix
        .ctx
        .set_account(&record, &shared(owned(&zero_fix.program, raw)));
    let witness = app_replay_witness(1, &[1, 2, 3], 6);
    let mut extended = vec![dcg_program::unified::TAG_REVEAL, 0];
    extended.extend_from_slice(&[0x6b; 32]);
    extended.extend_from_slice(&witness);
    let refused = send_fresh_with(
        &mut zero_fix.ctx,
        &zero_fix.executor,
        zero_fix.program,
        extended,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(zero_fix.executor.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(zero_fix.pt2s, false),
            AccountMeta::new_readonly(zero_fix.routes, false),
            AccountMeta::new_readonly(zero_fix.geometry, false),
            AccountMeta::new_readonly(zero_fix.drp2, false),
            AccountMeta::new_readonly(zero_fix.pt1s_index, false),
        ],
    )
    .await;
    assert!(matches!(
        refused,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::Custom(730)
        ))
    ));
    assert_eq!(zero_fix.account(record).await[4], challenge::PHASE_REVEAL);

    // Tag 169: a descended leaf rejects an appended fast-path witness on the
    // empty image, then the same exact two-byte command enters RESPOND.
    let Some(mut descend_fix) = build().await else {
        panic!("retained artifacts absent")
    };
    let descend_binding = descend_fix.binding(29, 50);
    let committed = app_replay_witness(1, &[1, 2, 3], 6);
    let producer = app_route_producer_witness();
    let (descriptor, created, roots, segment, target, levels, witness) =
        commit_challenge_tree_with_route_witness(
            &mut descend_fix,
            &descend_binding,
            79,
            1,
            235,
            207,
            &committed,
            &producer,
        )
        .await;
    let record = descend_position_challenge_with_witness(
        &mut descend_fix,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        98,
        true,
        None,
    )
    .await;
    let choice = final_position_choice(&levels, target);
    let mut extended = vec![TAG_DESCEND, choice];
    extended.extend_from_slice(&witness);
    let metas = vec![
        AccountMeta::new(record, false),
        AccountMeta::new(descend_fix.signer.pubkey(), true),
        AccountMeta::new(created[0], false),
        AccountMeta::new_readonly(descend_fix.pt2s, false),
        AccountMeta::new_readonly(descend_fix.routes, false),
        AccountMeta::new_readonly(descend_fix.geometry, false),
        AccountMeta::new_readonly(descend_fix.drp2, false),
        AccountMeta::new_readonly(descend_fix.pt1s_index, false),
    ];
    let refused = send_fresh_with(
        &mut descend_fix.ctx,
        &descend_fix.signer,
        descend_fix.program,
        extended,
        metas,
    )
    .await;
    assert_eq!(custom(refused), 730, "tag 169 rejects replay tails");
    send(
        &mut descend_fix.ctx,
        &descend_fix.signer,
        descend_fix.program,
        vec![TAG_DESCEND, choice],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(descend_fix.signer.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(descend_fix.pt2s, false),
            AccountMeta::new_readonly(descend_fix.routes, false),
            AccountMeta::new_readonly(descend_fix.geometry, false),
            AccountMeta::new_readonly(descend_fix.drp2, false),
            AccountMeta::new_readonly(descend_fix.pt1s_index, false),
        ],
    )
    .await
    .expect("the exact tag-169 instruction enters RESPOND");
    assert_eq!(
        descend_fix.account(record).await[4],
        challenge::PHASE_RESPOND
    );
}

/// The dedicated unbound-form SBF image maps only a test sentinel form. A real
/// registry class therefore refuses at admission tag 160 with 799, before a
/// document can depend on a replay kernel the app did not bind.
#[cfg(feature = "sbf-unbound-form-test")]
#[tokio::test(flavor = "multi_thread")]
async fn rev8_unbound_form_refuses_admission_on_sbf() {
    assert!(std::env::var_os("BASANOS_DCG_V8_SBF").is_some());
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut admission_state = f.account(f.dea2).await;
    let total = u32_at(&admission_state, 140) + u32_at(&admission_state, 144);
    assert!(total > 0);
    admission_state[6..8].fill(0);
    admission_state[148..152].fill(0);
    admission_state[admission::HEADER..].fill(0);
    f.ctx
        .set_account(&f.dea2, &shared(owned(&f.program, admission_state)));

    let mut first = 0;
    while first < total {
        let count = (total - first).min(admission::MAX_STEP as u32) as u16;
        let mut data = vec![160];
        data.extend_from_slice(&first.to_le_bytes());
        data.extend_from_slice(&count.to_le_bytes());
        let result = send(
            &mut f.ctx,
            &f.executor,
            f.program,
            data,
            vec![
                AccountMeta::new(f.dea2, false),
                AccountMeta::new_readonly(f.drp2, false),
                AccountMeta::new_readonly(f.pt2s, false),
                AccountMeta::new_readonly(f.pt1s_index, false),
                AccountMeta::new_readonly(f.routes, false),
                AccountMeta::new_readonly(f.geometry, false),
            ],
        )
        .await;
        match result {
            Err(error) => {
                assert_eq!(
                    custom(Err(error)),
                    dcg_program::unified::APP_KERNEL_UNAVAILABLE
                );
                assert_eq!(u32_at(&f.account(f.dea2).await, 148), first);
                return;
            }
            Ok(()) => first += count as u32,
        }
    }
    panic!("expected an unbound form to refuse before admission completed");
}

/// A saved app identity that differs from the current image ends neutrally at
/// a fix-point, even when the current image no longer binds that coordinate.
#[cfg(feature = "sbf-unbound-form-test")]
#[tokio::test(flavor = "multi_thread")]
async fn rev8_stale_manifest_neutralizes_non_app_fixpoint_on_sbf() {
    assert!(std::env::var_os("BASANOS_DCG_V8_SBF").is_some());
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let binding = f.binding(29, 50);
    let (descriptor, created, roots, segment, target, levels) =
        commit_challenge_tree(&mut f, &binding, 79, 1).await;
    // Represent a document admitted under a prior image whose static form
    // table differed. The selected challenge coordinate is not app-bound.
    let mut older_document = f.account(created[0]).await;
    let option_count = older_document[document::BINDING_AT_V8 + 151] as usize;
    let identity_at = document::OPTION_REGION_AT + 4 * option_count;
    assert_eq!(older_document.len(), identity_at);
    let mut previous_identity = [0; document::APP_IDENTITY_BYTES];
    previous_identity[..4].copy_from_slice(b"ARI1");
    previous_identity[4..36].fill(0x5a);
    older_document.extend_from_slice(&previous_identity);
    let document_lamports = f.lamports(created[0]).await;
    f.ctx.set_account(
        &created[0],
        &shared(Account {
            lamports: document_lamports,
            data: older_document,
            owner: f.program,
            executable: false,
            rent_epoch: 0,
        }),
    );
    let record = descend_position_challenge(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        100,
        true,
    )
    .await;
    assert!(target < levels[0].len() as u32);
    let before = f.account(record).await;
    assert_eq!(before[4], challenge::PHASE_DESCEND);
    assert_eq!(before[5], 0);
    let choice = final_position_choice(&levels, target);
    label("stale-manifest-non-app-fixpoint-169");
    send_fresh_with(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![TAG_DESCEND, choice],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.signer.pubkey(), true),
            AccountMeta::new(created[0], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
        ],
    )
    .await
    .expect("a stale saved app identity ends neutrally at the fix-point");
    let after = f.account(record).await;
    assert_eq!(after[4], challenge::PHASE_RULED);
    assert_eq!(
        after[5], 0,
        "the stale app identity cannot convict either role"
    );
    assert_eq!(u16_at(&after, 6), challenge::APP_REPLAY_VERSION);
    assert_eq!(after[178], events::CAUSE_APP_IDENTITY_CHANGED);
    assert_ne!(after, before, "tag 169 records a neutral identity ruling");
    assert_eq!(
        u32_at(&after, challenge::DEV2_AT + 8),
        challenge::OUTCOME_IDENTITY_CHANGED as u32
    );
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        0,
        "neutral identity handling leaves the honest executor unrefuted"
    );
    assert_eq!(u32_at(&f.account(created[0]).await, 132), 0);
}

/// The earlier app image admitted Form 256. This image has removed that
/// binding; its identity digest therefore changes, and a correct committed
/// ByteSum leaf must not be turned into an honest executor loss.
#[cfg(feature = "sbf-unbound-form-test")]
#[tokio::test(flavor = "multi_thread")]
async fn rev8_removed_app_binding_after_admission_is_neutral_on_sbf() {
    assert!(std::env::var_os("BASANOS_DCG_V8_SBF").is_some());
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let prior_app = &PREVIOUS_APP_MANIFEST;
    let current_app = &dcg_program::kernel::test_kernel::MANIFEST_APP;
    assert!(prior_app.resolve_legacy_form(1, 256).is_some());
    assert!(current_app.resolve_legacy_form(1, 256).is_none());

    let binding = f.binding(29, 50);
    let witness = app_route_producer_witness();
    let saved_identity = prior_app.admission_identity_digest();
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree_with_manifest(
            &mut f,
            &binding,
            79,
            1,
            256,
            &witness,
            prior_app,
            Some(saved_identity),
        )
        .await;
    let stored_identity = document::application_identity_v8(&f.account(created[0]).await)
        .unwrap()
        .expect("the admitted app document retains its old ARI1 identity");
    assert_eq!(&stored_identity[4..36], &saved_identity);

    let record = descend_position_challenge(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        118,
        false,
    )
    .await;
    let ruled = f.account(record).await;
    assert_eq!(ruled[4], challenge::PHASE_RULED);
    assert_eq!(
        ruled[5], 0,
        "the removed binding does not convict the executor"
    );
    assert_eq!(ruled[178], events::CAUSE_APP_IDENTITY_CHANGED);
    assert_eq!(
        u16_at(&f.account(created[0]).await, 6) & FLAG_REFUTED,
        0,
        "a correct app-format leaf remains unrefuted after binding removal"
    );
    settle_and_close_neutral_app_challenge(&mut f, record, created, descriptor, &terms).await;
}

/// Build the retained K=10,240 PT1X/PT2S fixture and real registry/admission
/// path. This isolates tags 159 and 160 from Basanos-only tag 150, so every
/// measured admission instruction is a DCG SBF instruction.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_pt1x_registry_and_admission_sbf() {
    let Some(mut f) = build_honest_pt1x().await else {
        panic!("retained K=10,240 artifacts absent")
    };
    assert_eq!(f.k, 10_240);
    let admission = f.account(f.dea2).await;
    assert_eq!(&admission[..4], b"DEA2");
    assert_eq!(u32_at(&admission, 136), f.k);
}

/// The retained compiler-v1 typed-decision capture supplies a measured
/// Form-48 row. Exercise its actual tag-157 write and matching tag-160 class
/// admission in ProgramTest.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_form48_registry_write_and_class_admission_program_test() {
    let Some(mut f) = build_form48_admission_only().await else {
        panic!("retained compiler-v1 typed-decision artifacts absent")
    };

    let registry_account = f.account(f.drp2).await;
    let row = registry::find_row(
        &registry_account[registry::HEADER..],
        decision::GATHER_FORM_ID,
    )
    .unwrap()
    .expect("tag 157 committed the Form-48 row");
    assert_eq!((row.respond_path, row.witness_kind), (1, 0));

    let (routes, geometry, payloads, program, _) =
        f47_artifacts().expect("retained compiler-v1 typed-decision artifacts");
    let payload_index = retained_payload_index(&payloads);
    let decoded_program = pt2p::Program::decode(&program).unwrap();
    let view = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        Some(&payload_index),
        decoded_program,
    )
    .unwrap();
    let form48_class = (0..class_count(&view).unwrap())
        .find(|index| {
            let key = dcg_program::unified::classes::key_of(&view, *index).unwrap();
            dcg_program::unified::classes::class_shape(&view, key)
                .unwrap()
                .is_some_and(|shape| shape.form == decision::GATHER_FORM_ID)
        })
        .expect("the retained compiler-v1 capture has a Form-48 admission class");
    let admission_account = f.account(f.dea2).await;
    let form48_bit = 1u8 << (form48_class % 8);
    assert_eq!(
        u32_at(&admission_account, 148),
        1,
        "tag 160 admitted one class"
    );
    assert_eq!(
        admission_account[admission::HEADER + form48_class as usize / 8] & form48_bit,
        form48_bit,
        "tag 160 set the Form-48 class bit"
    );
    assert_eq!(
        u16_at(&admission_account, 6) & 1,
        0,
        "this targeted run leaves other admission classes untouched"
    );
}

/// A timeout in SELECT can settle before tag 164 transfers the staged DRU1
/// bump, so tag 132 must make byte 219 usable by tag 131.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_select_timeout_preserves_response_bump_for_settlement_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let binding = f.binding(29, 50);
    let (descriptor, created, roots, _, _, _) =
        commit_challenge_tree(&mut f, &binding, 79, 0).await;
    let nonce = 121;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
    let position_metas = challenge_position_metas(&f, created, record);
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        challenge_position_data(&descriptor, 79, nonce),
        position_metas,
    )
    .await
    .expect("tag 167 opens the position challenge");

    let mut reveal = vec![TAG_REVEAL_POSITION, 0, 0, roots.len() as u8];
    for root in &roots {
        reveal.extend_from_slice(root);
    }
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        reveal,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(created[0], false),
            AccountMeta::new_readonly(created[1], false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
        ],
    )
    .await
    .expect("tag 163 completes the position reveal");
    let open = f.account(record).await;
    assert_eq!(open[4], challenge::PHASE_SELECT);
    clock_to(&mut f, u64_at(&open, 148) + 1).await;
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("tag 132 rules for the executor after SELECT silence");

    let dcr1 = f.account(record).await;
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 1);
    assert_eq!(dcr1[178], events::CAUSE_TIMEOUT);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        dcr1[challenge::RESPONSE_BUMP_STAGED_AT],
        "tag 132 commits the staged response bump when SELECT times out"
    );
    let (_, expected_response_bump) =
        dcg_program::closure_v2_response::address(&f.program, &record);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        expected_response_bump.value()
    );
    let third_party = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, third_party.pubkey(), 1_000_000_000_000).await;
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(Pubkey::new_from_array(terms.bond_remainder), false),
        ],
    )
    .await
    .expect("tag 131 settles the SELECT-timeout executor ruling");
    assert_eq!(f.lamports(record).await, 0);
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 0);
}

/// Tag 166's app replay fast path can rule immediately. Its open-time stable
/// DRU1 bump must remain available to tag 131 without a preceding tag 164.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_app_leaf_fast_conviction_settles_from_open_bump_sbf() {
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();

    let binding = f.binding(29, 50);
    let witness = app_route_producer_witness_with(&[4, 5, 6]);
    let (descriptor, created, roots, segment, target, levels) =
        commit_route_free_app_tree(&mut f, &binding, 79, 1, 256, &witness).await;
    let nonce = 122;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), nonce).0;
    let packet = challenge_app_leaf_packet(
        &f,
        &descriptor,
        &roots,
        79,
        1,
        segment,
        target,
        &levels,
        nonce,
        &witness,
    );
    let leaf_metas = challenge_leaf_metas(&f, created, record);
    send(&mut f.ctx, &f.signer, f.program, packet, leaf_metas)
        .await
        .expect("tag 166 fast replay convicts the executor");
    let dcr1 = f.account(record).await;
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 2);
    assert_eq!(dcr1[178], events::CAUSE_APP_REPLAY);
    let (_, expected_response_bump) =
        dcg_program::closure_v2_response::address(&f.program, &record);
    assert_eq!(
        dcr1[challenge::RESPONSE_BUMP_AT],
        expected_response_bump.value()
    );
    let third_party = Keypair::new();
    fund_system(&mut f.ctx, &f.executor, third_party.pubkey(), 1_000_000_000_000).await;
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let record_balance = f.lamports(record).await;
    let challenger_before = f.lamports(f.signer.pubkey()).await;
    send_fresh_with(
        &mut f.ctx,
        &third_party,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(Pubkey::new_from_array(terms.bond_remainder), false),
        ],
    )
    .await
    .expect("tag 131 settles the tag 166 fast conviction");
    assert_eq!(f.lamports(record).await, 0);
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        challenger_before + record_balance,
        "the settled challenge rent and bond return to the challenger"
    );
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 0);
}

/// Tag 146 checks the binding-derived PT1O address before assigning or writing
/// its output. Pin wrong-kind, second-instance and non-canonical-address
/// substitutions against that real handler, then complete the honest output
/// creation on the same PT1X/PT2S setup.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_pt1x_output_pda_provenance_sbf() {
    // Tag 146 consumes the sealed template and PT1X index, not DEA2's class
    // bitmap. Use the retained fixture setup here so the provenance matrix
    // does not repeat the unrelated 10,240-position admission walk.
    let Some(mut f) =
        build_with_pre_fix_seal_processor(false, false, false, false, true, false).await
    else {
        panic!("retained K=10,240 artifacts absent")
    };
    let (routes_image, geometry_image, payloads_image, pwr1, _) =
        k10240_artifacts().expect("retained K=10,240 compiler-v1 template");
    let payload_index = retained_payload_index(&payloads_image);
    let template = Pt2p::new(
        &routes_image,
        &geometry_image,
        &payloads_image,
        Some(&payload_index),
        pt2p::Program::decode(&pwr1).expect("compiler-v1 PWR1"),
    )
    .expect("PT2P template view");
    let position = 0;
    let first = (0..template
        .entry_count(position)
        .expect("position entry count"))
        .find(|entry_index| {
            !matches!(
                template.entry(position, *entry_index).unwrap().kernel_index,
                47 | 48
            )
        })
        .expect("position has an entry without a DCM2 dependency");
    let count = 1u16;
    let (program, executor_pubkey) = (f.program, f.executor.pubkey());
    let input_keys = [f.pt2s, f.pt1s_index, f.routes, f.geometry, f.payloads];
    let input_refs = input_keys.iter().collect::<Vec<_>>();
    let binding = dcg_program::pt1_onchain::pt1x_output_binding(
        &program,
        &input_refs,
        position,
        first,
        u32::from(count),
    );
    let (output, canonical_bump) =
        dcg_program::pt1_onchain::pt1x_output_address(&program, &binding);
    let data = || {
        [
            vec![S::TAG_INSTANTIATE],
            position.to_le_bytes().to_vec(),
            first.to_le_bytes().to_vec(),
            count.to_le_bytes().to_vec(),
        ]
        .concat()
    };
    let [pt2s, pt1x, routes, geometry, payloads] = input_keys;
    let metas_for = |output_key| {
        vec![
            AccountMeta::new_readonly(pt2s, false),
            AccountMeta::new_readonly(pt1x, false),
            AccountMeta::new_readonly(routes, false),
            AccountMeta::new_readonly(geometry, false),
            AccountMeta::new_readonly(payloads, false),
            AccountMeta::new(output_key, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new(executor_pubkey, true),
        ]
    };

    // A program-owned wrong-kind image at the PT1O address is a state only a
    // program bug could write (only the program assigns that PDA): the
    // account-provenance gate's unit tests refuse it. What a caller can do is
    // fund addresses, below, by real transfers.
    let other_binding = dcg_program::pt1_onchain::pt1x_output_binding(
        &program,
        &input_refs,
        position,
        first + 1,
        u32::from(count),
    );
    let (second_output, _) =
        dcg_program::pt1_onchain::pt1x_output_address(&program, &other_binding);
    assert_ne!(output, second_output);
    fund_system(&mut f.ctx, &f.executor, second_output, 1_000_000_000_000).await;
    let second_instance = send(
        &mut f.ctx,
        &f.executor,
        f.program,
        data(),
        metas_for(second_output),
    )
    .await;
    assert!(
        matches!(
            second_instance,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "tag 146 refuses a PT1O derived for another output tuple"
    );

    let stale_bump = (0u8..=u8::MAX)
        .find(|bump| {
            *bump != canonical_bump.value()
                && solana_program::pubkey::Pubkey::create_program_address(
                    &[&binding, &[*bump]],
                    &program,
                )
                .is_ok()
        })
        .expect("a non-canonical bump also derives an address");
    let noncanonical_output = solana_program::pubkey::Pubkey::create_program_address(
        &[&binding, &[stale_bump]],
        &program,
    )
    .unwrap();
    assert_ne!(output, noncanonical_output);
    fund_system(&mut f.ctx, &f.executor, noncanonical_output, 1_000_000_000_000).await;
    let stale = send(
        &mut f.ctx,
        &f.executor,
        program,
        data(),
        metas_for(noncanonical_output),
    )
    .await;
    assert!(
        matches!(
            stale,
            Err(TransactionError::InstructionError(
                _,
                InstructionError::InvalidAccountData
            ))
        ),
        "tag 146 refuses a non-canonical PT1O address planted at another key"
    );

    fund_system(&mut f.ctx, &f.executor, output, 1_000_000_000_000).await;
    send(&mut f.ctx, &f.executor, program, data(), metas_for(output))
        .await
        .expect("tag 146 creates the honest PT1O output");
    assert_eq!(&f.account(output).await[..4], b"PT1O");
}

/// The manifest-aware tag-160 walk admits a Form-22 class with multiple plan
/// reads when its selected ordinal 7 is present at every bound instance.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_multi_read_form_admits_selected_route_tag160_sbf() {
    assert!(std::env::var_os("BASANOS_DCG_V8_SBF").is_some());
    let Some(mut f) = build().await else {
        panic!("retained artifacts absent")
    };
    let (routes, geometry, payloads, pwr1, _) = artifacts().expect("the retained emission");
    let payload_index = retained_payload_index(&payloads);
    let x = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        Some(&payload_index),
        pt2p::Program::decode(&pwr1).unwrap(),
    )
    .unwrap();
    let form22_index = (0..class_count(&x).unwrap())
        .find(|&index| {
            let key = dcg_program::unified::classes::key_of(&x, index).unwrap();
            dcg_program::unified::classes::class_shape(&x, key)
                .unwrap()
                .is_some_and(|shape| shape.form == 22)
        })
        .expect("the retained plan has a Form-22 class");
    let key = dcg_program::unified::classes::key_of(&x, form22_index).unwrap();
    let shape = dcg_program::unified::classes::class_shape(&x, key)
        .unwrap()
        .expect("the Form-22 class has an instance");
    let index = x
        .old_to_new(form22_index, shape.position)
        .unwrap()
        .expect("the Form-22 representative exists");
    let entry = x.entry(shape.position, index).unwrap();
    assert!(
        entry.read_count > 1,
        "the selected plan entry has extra reads"
    );
    assert!(entry.read_count > 7, "manifest route ordinal 7 exists");
    assert!(x.route(&entry, 7).is_ok(), "route ordinal 7 is readable");

    let mut state = f.account(f.dea2).await;
    state[6..8].fill(0);
    state[148..152].fill(0);
    state[admission::HEADER..].fill(0);
    f.ctx
        .set_account(&f.dea2, &shared(owned(&f.program, state)));

    let mut data = vec![dcg_program::unified::TAG_ADMISSION_STEP];
    data.extend_from_slice(&form22_index.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    let result = send(
        &mut f.ctx,
        &f.executor,
        f.program,
        data,
        vec![
            AccountMeta::new(f.dea2, false),
            AccountMeta::new_readonly(f.drp2, false),
            AccountMeta::new_readonly(f.pt2s, false),
            AccountMeta::new_readonly(f.pt1s_index, false),
            AccountMeta::new_readonly(f.routes, false),
            AccountMeta::new_readonly(f.geometry, false),
        ],
    )
    .await;
    result.expect("a declared selected route does not reject other plan reads");
    let after = f.account(f.dea2).await;
    assert_eq!(u32_at(&after, 148), 1, "tag 160 admits the class");
    assert_ne!(
        after[admission::HEADER + form22_index as usize / 8] & (1 << (form22_index % 8)),
        0
    );
}

/// Full real admission to final result on the extracted SBF image: actual
/// PT1X/PT2S setup, registry and tag-159/160 admission, then tags 161/162/165,
/// 177, and 178 on the same K=10,240 template.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_pt1x_real_admission_to_resolve_sbf() {
    let Some(mut f) = build_honest_pt1x().await else {
        panic!("retained K=10,240 artifacts absent")
    };
    assert_eq!(f.k, 10_240);
    let binding = f.binding(29, 50);
    let (descriptor, created, proofs) = attest_all(&mut f, &binding, 31, &[], 0x77).await;
    assert_eq!(proofs.len(), 1);
    past_deadline(&mut f, created[0]).await;
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        pair(created[0], created[3]),
    )
    .await
    .expect("tag 178 resolves the fully attested K=10,240 document");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_FINAL);
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let close_metas = f.close_metas(&c, f.signer.pubkey());
    let before_payer = f.lamports(f.executor.pubkey()).await;
    let rent_refund =
        f.lamports(created[0]).await + f.lamports(created[1]).await + f.lamports(created[2]).await;
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("tag 172 closes the final document");
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        before_payer + rent_refund
    );
    assert_eq!(f.account(created[3]).await[6], result::STATUS_SETTLED);
}

/// A challenger who abandons the last descendant choice loses to the executor
/// under tag 132. This exercises the timeout after the executor has answered
/// every preceding position and tree round.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_timeout_refutes_a_challenger_who_stalls_in_descent() {
    let Some(mut f) = build().await else { return };
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let binding = f.binding(29, 50);
    let (descriptor, created, roots, segment, target, levels) =
        commit_challenge_tree(&mut f, &binding, 79, 0).await;
    let nonce = 21;
    let record = descend_position_challenge(
        &mut f,
        created,
        &descriptor,
        &roots,
        79,
        0,
        segment,
        target,
        &levels,
        nonce,
        true,
    )
    .await;
    let open_record = f.account(record).await;
    assert_eq!(open_record[4], challenge::PHASE_DESCEND);
    clock_to(&mut f, u64_at(&open_record, 148) + 1).await;
    label("challenge-timeout-stalled-challenger-132");
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(created[0], false),
        ],
    )
    .await
    .expect("the timeout rules for the executor after the challenger's missed descent");
    let dcr1 = f.account(record).await;
    assert_eq!(dcr1[4], challenge::PHASE_RULED);
    assert_eq!(dcr1[5], 1);
    assert_eq!(dcr1[178], events::CAUSE_TIMEOUT);
    let doc = f.account(created[0]).await;
    assert_eq!(u32_at(&doc, 132), 0);
    assert_eq!(u16_at(&doc, 6) & FLAG_REFUTED, 0);

    // Executor wins the round, so tag 131 returns the challenger's bond to
    // the executor and the challenge record's rent to its recorded payer.
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    let record_lamports = f.lamports(record).await;
    let challenge_rent = record_lamports
        .checked_sub(terms.challenger_bond_lamports)
        .unwrap();
    let before_executor = f.lamports(f.executor.pubkey()).await;
    let before_challenger = f.lamports(f.signer.pubkey()).await;
    let settler = Keypair::new();
    // Funded by the bank's own payer, a neutral party, so the executor's and
    // the challenger's balances stay exactly what the settlement leaves.
    let bank = f.ctx.payer.insecure_clone();
    fund_system(&mut f.ctx, &bank, settler.pubkey(), 1_000_000_000).await;
    let settle_metas = vec![
        AccountMeta::new(record, false),
        AccountMeta::new(response, false),
        AccountMeta::new(f.executor.pubkey(), false),
        AccountMeta::new(f.executor.pubkey(), false),
        AccountMeta::new(created[0], false),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(f.signer.pubkey(), false),
        AccountMeta::new(incinerator::ID, false),
        AccountMeta::new(remainder, false),
    ];
    send(
        &mut f.ctx,
        &settler,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        settle_metas,
    )
    .await
    .expect("tag 131 settles the executor win");
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        before_executor + terms.challenger_bond_lamports,
        "the challenger's bond is paid to the executor"
    );
    assert_eq!(
        f.lamports(f.signer.pubkey()).await,
        before_challenger + challenge_rent,
        "the record rent returns to the challenger who funded it"
    );
    assert_eq!(f.lamports(record).await, 0, "the settled record is drained");
}


// ------------------------------------------------- lifecycle-v2 property path
// Ported from the Basanos switchover copy (2026-10-02): DCG-core lifecycle
// behavior lives with DCG (rule 6).

#[derive(Clone, Debug, PartialEq, Eq)]
struct LifecycleV2AccountImage {
    lamports: u64,
    data: Vec<u8>,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
}

static LIFECYCLE_V2_TX_COUNT: AtomicU64 = AtomicU64::new(0);

static LIFECYCLE_V2_TOTAL_CU: AtomicU64 = AtomicU64::new(0);

static LIFECYCLE_V2_MAX_CU: AtomicU64 = AtomicU64::new(0);

static LIFECYCLE_V2_REFUSAL_PROBES: AtomicU64 = AtomicU64::new(0);

fn lifecycle_v2_record_cu(compute_units: u64) {
    LIFECYCLE_V2_TX_COUNT.fetch_add(1, Ordering::Relaxed);
    LIFECYCLE_V2_TOTAL_CU.fetch_add(compute_units, Ordering::Relaxed);
    let mut prior = LIFECYCLE_V2_MAX_CU.load(Ordering::Relaxed);
    while compute_units > prior {
        match LIFECYCLE_V2_MAX_CU.compare_exchange_weak(
            prior,
            compute_units,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => prior = actual,
        }
    }
}

fn lifecycle_v2_known_keys(f: &Fix, extra: &[Pubkey]) -> Vec<Pubkey> {
    let mut keys = vec![
        f.program,
        f.executor.pubkey(),
        f.pt2s,
        f.pt1s_index,
        f.routes,
        f.geometry,
        f.payloads,
        f.drp2,
        f.dea2,
        f.dta1,
        f.dtu1,
    ];
    keys.extend_from_slice(extra);
    keys.sort_unstable();
    keys.dedup();
    keys
}

async fn lifecycle_v2_snapshot(
    ctx: &mut ProgramTestContext,
    keys: &[Pubkey],
    fee_payer: Pubkey,
) -> Vec<(Pubkey, Option<LifecycleV2AccountImage>)> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys.iter().copied().filter(|key| *key != fee_payer) {
        let image = ctx.banks_client.get_account(key).await.unwrap().map(|account| {
            LifecycleV2AccountImage {
                lamports: account.lamports,
                data: account.data,
                owner: account.owner,
                executable: account.executable,
                rent_epoch: account.rent_epoch,
            }
        });
        out.push((key, image));
    }
    out
}

async fn lifecycle_v2_expect_refusal_unchanged(
    ctx: &mut ProgramTestContext,
    cache: &mut QuietSendCache,
    signer: &Keypair,
    extra_signers: &[&Keypair],
    program: Pubkey,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    keys: &[Pubkey],
    dispatcher_refusal: bool,
    label: &str,
) {
    LIFECYCLE_V2_REFUSAL_PROBES.fetch_add(1, Ordering::Relaxed);
    let before = lifecycle_v2_snapshot(ctx, keys, signer.pubkey()).await;
    let result = send_quiet_cached(ctx, signer, extra_signers, program, data, metas, cache).await;
    if dispatcher_refusal {
        assert!(
            matches!(result, Err(TransactionError::InstructionError(_, InstructionError::InvalidInstructionData))),
            "{label}: unsupported tag did not stop at the Rev 8 allowlist: {result:?}",
        );
    } else {
        assert!(result.is_err(), "{label}: closed state unexpectedly accepted reuse");
    }
    let after = lifecycle_v2_snapshot(ctx, keys, signer.pubkey()).await;
    assert_eq!(after, before, "{label}: refusal changed a tracked account");
}

async fn lifecycle_v2_probe_dispatch_refusal(f: &mut Fix, extra: &[Pubkey], label: &str) {
    if std::env::var_os("BASANOS_DCG_PREP_V2").is_none() {
        return;
    }
    let keys = lifecycle_v2_known_keys(f, extra);
    lifecycle_v2_expect_refusal_unchanged(
        &mut f.ctx,
        &mut f.lifecycle_v2_cache,
        &f.signer,
        &[],
        f.program,
        vec![201],
        vec![],
        &keys,
        true,
        label,
    )
    .await;
}

/// Seeded Rev 8 lifecycle-v2 scenario. The retained 80-position fixture matches
/// the proof packets already used by the document harness, while staying small
/// beside the 4B model artifacts. Fixture account images are setup inputs; the
/// lifecycle transitions below are instruction-produced.
#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_property_v2_generated_valid_paths() {
    if std::env::var_os("BASANOS_DCG_PREP_V2").is_none() {
        eprintln!("needs_local_artifacts: set BASANOS_DCG_PREP_V2=1 and BASANOS_PT2P_ROOT to run the Rev 8 lifecycle-v2 property path");
        return;
    }
    let started = std::time::Instant::now();
    let seed = std::env::var("BASANOS_DCG_PREP_SEED")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0x8deb_236c_0dc0_0001);
    LIFECYCLE_V2_TX_COUNT.store(0, Ordering::Relaxed);
    LIFECYCLE_V2_TOTAL_CU.store(0, Ordering::Relaxed);
    LIFECYCLE_V2_MAX_CU.store(0, Ordering::Relaxed);
    LIFECYCLE_V2_REFUSAL_PROBES.store(0, Ordering::Relaxed);

    let Some(mut f) = build().await else {
        panic!("BASANOS_DCG_PREP_V2 requires the retained 80-position PT2P fixture");
    };
    assert_eq!(f.k, 80, "the v2 fixture is the retained 80-position template");
    let mut completed = vec!["tag176 published retained PT1X/PT2S fixture".to_owned()];
    let dta1 = f.account(f.dta1).await;
    assert_eq!((&dta1[..4], dta1[6]), (b"DTA1".as_slice(), config::SEAL_APPROVED));
    assert_eq!(&f.account(f.dtu1).await[..4], b"DTU1");

    // PT1O path: reserve a bounded batch under tag 199, instantiate it with
    // tag 146, and close the written output with tag 198. The compact P=0
    // slice excludes the typed-decision entries, which require a document.
    let routes = f.account(f.routes).await;
    let geometry = f.account(f.geometry).await;
    let payloads = f.account(f.payloads).await;
    let pt1x_image = f.account(f.pt1s_index).await;
    let pwr1 = &f.pt2s_image[S::OFF_PWR1..];
    let view = Pt2p::new(
        &routes,
        &geometry,
        &payloads,
        Some(&pt1x_image[dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX..]),
        pt2p::Program::decode(pwr1).unwrap(),
    )
    .unwrap();
    let (output_position, output_count) = (0..f.k)
        .find_map(|position| {
            // Keep one measured-local SBF request comfortably below the
            // 1.4M-CU transaction limit while still crossing the 10 KiB
            // reservation boundary.
            let count = view.entry_count(position).ok()?.min(S::MAX_INSTANTIATE).min(36);
            if count == 0 {
                return None;
            }
            let safe = (0..count).all(|offset| {
                view.entry(position, offset)
                    .is_ok_and(|entry| !matches!(entry.kernel_index, 47 | 48))
            });
            safe.then_some((position, count))
        })
        .expect("the small fixture has a non-decision output slice");
    let mut stream_bytes = 44usize;
    for offset in 0..output_count {
        let entry = view.entry(output_position, offset).unwrap();
        stream_bytes = stream_bytes
            .checked_add(14 + view.payload_len(&entry).unwrap() + 40 * entry.route_count() as usize)
            .expect("PT1O stream size is bounded");
    }
    let output_required = dcg_program::pt1_onchain::PT1X_OUTPUT_HEADER_BYTES
        + stream_bytes
        + dcg_program::pt1_onchain::PT1X_OUTPUT_TRAILER_FIXED_BYTES
        + 5 * 32;
    assert!(
        output_required > dcg_program::pt1_onchain::PT1X_OUTPUT_MAX_GROW_BYTES,
        "the generated PT1O stream crosses the bounded tag-199 growth step",
    );
    let output_keys = [f.pt2s, f.pt1s_index, f.routes, f.geometry, f.payloads];
    let output_key_refs: [&Pubkey; 5] = [
        &output_keys[0],
        &output_keys[1],
        &output_keys[2],
        &output_keys[3],
        &output_keys[4],
    ];
    let output_binding = dcg_program::pt1_onchain::pt1x_output_binding(
        &f.program,
        &output_key_refs,
        output_position,
        0,
        output_count,
    );
    let (output, _) = dcg_program::pt1_onchain::pt1x_output_address(&f.program, &output_binding);
    let (pt2s_key, pt1x_key, routes_key, geometry_key, payloads_key, authority_key) =
        (f.pt2s, f.pt1s_index, f.routes, f.geometry, f.payloads, f.executor.pubkey());
    let pt1o_data = |tag: u8, position: u32, first: u32, count: u32| {
        let mut data = vec![tag];
        data.extend_from_slice(&position.to_le_bytes());
        data.extend_from_slice(&first.to_le_bytes());
        data.extend_from_slice(&(count as u16).to_le_bytes());
        data
    };
    let pt1o_metas = |output_key| vec![
        AccountMeta::new(pt2s_key, false),
        AccountMeta::new_readonly(pt1x_key, false),
        AccountMeta::new_readonly(routes_key, false),
        AccountMeta::new_readonly(geometry_key, false),
        AccountMeta::new_readonly(payloads_key, false),
        AccountMeta::new(output_key, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(authority_key, true),
    ];
    let mut cache = QuietSendCache::default();
    let mut reserve_steps = 0usize;
    let mut reserved_bytes = 0usize;
    while reserved_bytes < output_required {
        let old = reserved_bytes;
        let result = send_quiet_cached(
            &mut f.ctx,
            &f.signer,
            &[&f.executor],
            f.program,
            pt1o_data(199, output_position, 0, output_count),
            pt1o_metas(output),
            &mut cache,
        )
        .await;
        result.unwrap_or_else(|error| panic!("seed={seed:#x} PT1O reserve(199): {error:?}"));
        reserved_bytes = f
            .ctx
            .banks_client
            .get_account(output)
            .await
            .unwrap()
            .expect("tag 199 creates its output PDA")
            .data
            .len();
        let expected = if old == 0 {
            output_required.min(dcg_program::pt1_onchain::PT1X_OUTPUT_MAX_GROW_BYTES)
        } else {
            output_required.min(old + dcg_program::pt1_onchain::PT1X_OUTPUT_MAX_GROW_BYTES)
        };
        assert_eq!(reserved_bytes, expected, "tag 199 grows by one bounded reservation step");
        reserve_steps += 1;
        assert!(reserve_steps <= 32, "the test slice stays within bounded PT1O growth");
        lifecycle_v2_probe_dispatch_refusal(&mut f, &[output], "after tag 199 reserve step").await;
    }
    assert_eq!(reserve_steps, 2, "the PT1O stream needs two bounded tag-199 steps");
    assert_eq!(f.account(output).await[..4], *b"PT1R");
    completed.push(format!("tag199 reserve PT1O {reserve_steps} steps {reserved_bytes} bytes"));

    send_with_signers_mode(
        &mut f.ctx,
        &f.signer,
        &[&f.executor],
        f.program,
        pt1o_data(146, output_position, 0, output_count),
        pt1o_metas(output),
        true,
    )
    .await
    .unwrap_or_else(|error| panic!("seed={seed:#x} PT1O write(146): {error:?}"));
    let written = f.account(output).await;
    assert_eq!(&written[..4], b"PT1O");
    assert_eq!(written.len(), output_required);
    completed.push(format!("tag146 instantiate PT1O {} entries", output_count));
    lifecycle_v2_probe_dispatch_refusal(&mut f, &[output], "after tag 146 write").await;
    let output_rent = f.lamports(output).await;
    let executor_before_output_close = f.lamports(f.executor.pubkey()).await;
    send_with_signers_mode(
        &mut f.ctx,
        &f.signer,
        &[&f.executor],
        f.program,
        vec![dcg_program::pt1_onchain::TAG_CLOSE_PT1O],
        vec![AccountMeta::new(output, false), AccountMeta::new(f.executor.pubkey(), true)],
        true,
    )
    .await
    .expect("tag 198 closes the written PT1O to its recorded authority");
    assert_eq!(f.lamports(output).await, 0);
    assert_eq!(f.lamports(f.executor.pubkey()).await, executor_before_output_close + output_rent);
    completed.push("tag198 close written PT1O to recorded authority".to_owned());
    lifecycle_v2_probe_dispatch_refusal(&mut f, &[output], "after tag 198 close").await;

    // An unwritten PT1R follows its own close path and returns its exact rent.
    let reservation_position = (output_position + 1) % f.k;
    let reservation_binding = dcg_program::pt1_onchain::pt1x_output_binding(
        &f.program,
        &output_key_refs,
        reservation_position,
        0,
        1,
    );
    let (reservation, _) = dcg_program::pt1_onchain::pt1x_output_address(
        &f.program,
        &reservation_binding,
    );
    let reservation_metas = pt1o_metas(reservation);
    send_with_signers_mode(
        &mut f.ctx,
        &f.signer,
        &[&f.executor],
        f.program,
        pt1o_data(199, reservation_position, 0, 1),
        reservation_metas.clone(),
        true,
    )
    .await
    .expect("tag 199 reserves an unwritten PT1R");
    assert_eq!(&f.account(reservation).await[..4], b"PT1R");
    lifecycle_v2_probe_dispatch_refusal(&mut f, &[reservation], "after unwritten tag 199 reserve").await;
    let reservation_rent = f.lamports(reservation).await;
    let executor_before_reservation_close = f.lamports(f.executor.pubkey()).await;
    send_with_signers_mode(
        &mut f.ctx,
        &f.signer,
        &[&f.executor],
        f.program,
        pt1o_data(200, reservation_position, 0, 1),
        reservation_metas,
        true,
    )
    .await
    .expect("tag 200 closes only the unwritten reservation");
    assert_eq!(f.lamports(reservation).await, 0);
    assert_eq!(
        f.lamports(f.executor.pubkey()).await,
        executor_before_reservation_close + reservation_rent,
        "tag 200 refunds the recorded authority, not the fee payer",
    );
    completed.push("tag200 close unwritten reservation to recorded authority".to_owned());
    lifecycle_v2_probe_dispatch_refusal(&mut f, &[reservation], "after tag 200 close").await;

    // Document: actual UnifiedInit -> root landing -> finalize -> attest ->
    // resolve -> close -> retention cleanup. The one output is a re-keyed
    // compiler-v1 proof and the cell is mechanics data, not a model result.
    let output_first = 29;
    let output_count = 50;
    let document_n = output_first + 2;
    let binding = f.binding(output_first, output_count);
    let variant = ((seed % 250) + 1) as u8;
    let (descriptor, created, proofs) = attest_all(&mut f, &binding, document_n, &[], variant).await;
    assert_eq!(proofs.len(), 1);
    assert_eq!(f.account(created[3]).await[6], result::STATUS_PENDING);
    assert_eq!(u32_at(&f.account(created[3]).await, 204), 1);
    completed.push("tag161 init -> tag162 roots -> tag165 finalize -> tag177 attest".to_owned());
    past_deadline(&mut f, created[0]).await;
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&descriptor),
        pair(created[0], created[3]),
    )
    .await
    .expect("tag 178 resolves the fully attested completion");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_FINAL);
    completed.push("tag178 resolve final".to_owned());
    lifecycle_v2_probe_dispatch_refusal(&mut f, &created, "after final tag 178 resolve").await;

    let crafted = Crafted { dcm2: created[0], dpr2: created[1], dcr2: created[3], descriptor };
    let payer = f.executor.pubkey();
    let rent_refund = f.lamports(created[0]).await
        + f.lamports(created[1]).await
        + f.lamports(address::family_slots(&f.program, &descriptor).0).await;
    let payer_before_close = f.lamports(payer).await;
    let close_metas = f.close_metas(&crafted, f.signer.pubkey());
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&descriptor),
        close_metas,
    )
    .await
    .expect("tag 172 closes the final document");
    assert_eq!(f.account(created[3]).await[6], result::STATUS_SETTLED);
    assert_eq!(f.lamports(payer).await, payer_before_close + rent_refund);
    completed.push("tag172 close final document; rent returned to payer".to_owned());
    lifecycle_v2_probe_dispatch_refusal(&mut f, &created, "after final tag 172 close").await;

    let closed_binding = Binding2 { request_id: [variant.max(1); 32], ..binding };
    let closed_init = init_data(
        &f.terms_raw,
        &closed_binding.encode(),
        &[[1u8; 32], [2u8; 32], [3u8; 32]],
        16,
        &f.family_body,
        &[],
    );
    let closed_keys = lifecycle_v2_known_keys(&f, &created);
    let closed_metas = f.init_metas(created);
    lifecycle_v2_expect_refusal_unchanged(
        &mut f.ctx,
        &mut f.lifecycle_v2_cache,
        &f.executor,
        &[],
        f.program,
        closed_init.clone(),
        closed_metas.clone(),
        &closed_keys,
        false,
        "tag 161 cannot reuse a closed document",
    )
    .await;
    completed.push("closed document re-init refused without changing state".to_owned());
    let retention_deadline = u64_at(
        &f.account(created[3]).await,
        result::RETENTION_DEADLINE_AT_V6,
    );
    clock_to(&mut f, retention_deadline).await;
    let payer_before_cleanup = f.lamports(payer).await;
    let result_rent = f.lamports(created[3]).await
        - solana_program::rent::Rent::default().minimum_balance(result::TOMBSTONE_BYTES);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        {
            let mut data = vec![dcg_program::unified::TAG_CLOSE_RESULT];
            data.extend_from_slice(&descriptor);
            data
        },
        vec![
            AccountMeta::new(f.signer.pubkey(), true),
            AccountMeta::new(created[3], false),
            AccountMeta::new(payer, false),
        ],
    )
    .await
    .expect("tag 185 writes the retained result tombstone");
    assert_eq!(f.lamports(payer).await, payer_before_cleanup + result_rent);
    assert_eq!(&f.account(created[3]).await[..4], b"DCRZ");
    completed.push("tag185 retention cleanup to recorded executor".to_owned());
    lifecycle_v2_probe_dispatch_refusal(&mut f, &created, "after tag 185 retention cleanup").await;
    let closed_keys = lifecycle_v2_known_keys(&f, &created);
    lifecycle_v2_expect_refusal_unchanged(
        &mut f.ctx,
        &mut f.lifecycle_v2_cache,
        &f.executor,
        &[],
        f.program,
        closed_init,
        closed_metas,
        &closed_keys,
        false,
        "tag 161 cannot reuse a retained DCRZ tombstone",
    )
    .await;

    // Challenge: open a position dispute, reveal roots, select a segment,
    // bisect to a fix-point, answer the family-table round, time out the
    // unanswered response, settle it, close the refuted document, and clean up
    // the retained DCR2. Timeout is an honest protocol outcome for a stalled
    // executor response; it is not a fabricated successful inference.
    let mut terms = Terms2::decode(&f.terms_raw).unwrap();
    terms.executor_bond_lamports = 500_000;
    terms.bond_policy_kind = BOND_POLICY_STANDARD;
    terms.bond_slasher_bps = 0;
    terms.settlement_program = [0; 32];
    terms.custom_settle_window_slots = 0;
    f.terms_raw = terms.encode().to_vec();
    let challenge_binding = Binding2 {
        request_id: [variant.wrapping_add(1).max(1); 32],
        ..f.binding(output_first, output_count)
    };
    let challenge_position = output_first;
    let (challenge_descriptor, challenge_created, roots, segment, target, levels) =
        commit_challenge_tree(&mut f, &challenge_binding, challenge_position, 0).await;
    let nonce = seed as u32;
    let record = descend_position_challenge(
        &mut f,
        challenge_created,
        &challenge_descriptor,
        &roots,
        challenge_position,
        0,
        segment,
        target,
        &levels,
        nonce,
        false,
    )
    .await;
    assert_eq!(f.account(record).await[4], challenge::PHASE_RESPOND);
    completed.push("tag167 open -> tag163/164/168/169 position and tree response".to_owned());
    let mut family_reveal = vec![TAG_REVEAL_FAMILY_TABLE, 0, f.family_roots.len() as u8];
    for root in &f.family_roots {
        family_reveal.extend_from_slice(root);
    }
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        family_reveal,
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(f.executor.pubkey(), true),
            AccountMeta::new_readonly(challenge_created[0], false),
        ],
    )
    .await
    .expect("tag 173 responds with the committed family roots");
    assert_eq!(f.account(record).await[challenge::FTR_AT], 1);
    completed.push("tag173 family-table response".to_owned());
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &[record, challenge_created[0], challenge_created[1], challenge_created[2], challenge_created[3]],
        "after tag 173 family response",
    )
    .await;
    let response_deadline = u64_at(&f.account(record).await, 148);
    clock_to(&mut f, response_deadline + 1).await;
    send(
        &mut f.ctx,
        &f.signer,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_TIMEOUT],
        vec![AccountMeta::new(record, false), AccountMeta::new(challenge_created[0], false)],
    )
    .await
    .expect("tag 132 rules for the challenger after the missing proof response");
    assert_eq!(f.account(record).await[4], challenge::PHASE_RULED);
    assert_eq!(f.account(record).await[5], 2);
    assert_ne!(u16_at(&f.account(challenge_created[0]).await, 6) & FLAG_REFUTED, 0);
    assert_eq!(u32_at(&f.account(challenge_created[0]).await, 132), 1);
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &[record, challenge_created[0], challenge_created[1], challenge_created[2], challenge_created[3]],
        "after tag 132 timeout",
    )
    .await;
    let response = dcg_program::closure_v2_response::address(&f.program, &record).0;
    let remainder = Pubkey::new_from_array(terms.bond_remainder);
    send(
        &mut f.ctx,
        &f.executor,
        f.program,
        vec![dcg_program::root_only_challenge::TAG_SETTLE],
        vec![
            AccountMeta::new(record, false),
            AccountMeta::new(response, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.executor.pubkey(), false),
            AccountMeta::new(challenge_created[0], false),
            AccountMeta::new(incinerator::ID, false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(f.signer.pubkey(), false),
            AccountMeta::new(remainder, false),
        ],
    )
    .await
    .expect("tag 131 settles the challenged bond under the standard policy");
    assert!(f.ctx.banks_client.get_account(record).await.unwrap().is_none(),
        "tag 131 drains the settled challenge record");
    assert_eq!(u32_at(&f.account(challenge_created[0]).await, 128), 0,
        "tag 131 decrements the document's open-challenge count");
    completed.push("tag132 timeout rule -> tag131 settle".to_owned());
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &[record, response, challenge_created[0], challenge_created[1], challenge_created[2], challenge_created[3]],
        "after tag 131 settle",
    )
    .await;
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        resolve_data(&challenge_descriptor),
        pair(challenge_created[0], challenge_created[3]),
    )
    .await
    .expect("tag 178 resolves the ruled challenge as refuted");
    assert_eq!(f.account(challenge_created[3]).await[6], result::STATUS_REFUTED);
    completed.push("tag178 resolves the settled challenge as refuted".to_owned());
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &[challenge_created[0], challenge_created[1], challenge_created[2], challenge_created[3]],
        "after challenge tag 178 resolve",
    )
    .await;

    let challenge_crafted = Crafted {
        dcm2: challenge_created[0],
        dpr2: challenge_created[1],
        dcr2: challenge_created[3],
        descriptor: challenge_descriptor,
    };
    let close_slot = u64_at(&f.account(challenge_created[0]).await, 144)
        .max(u64_at(&f.account(challenge_created[0]).await, document::ABANDON_DEADLINE_AT))
        + 1;
    clock_to(&mut f, close_slot).await;
    let challenge_rent = f.lamports(challenge_created[0]).await
        + f.lamports(challenge_created[1]).await
        + f.lamports(address::family_slots(&f.program, &challenge_descriptor).0).await;
    let payer_before_challenge_close = f.lamports(payer).await;
    let challenge_close_metas = f.close_metas_slots(
        &challenge_crafted,
        f.signer.pubkey(),
        AccountMeta::new(f.signer.pubkey(), false),
        AccountMeta::new(remainder, false),
    );
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        close_data(&challenge_descriptor),
        challenge_close_metas,
    )
    .await
    .expect("tag 172 closes after the challenge settled and its deadline passed");
    assert_eq!(f.account(challenge_created[3]).await[6], result::STATUS_REFUTED);
    assert_eq!(f.lamports(payer).await, payer_before_challenge_close + challenge_rent);
    let challenge_retention = u64_at(
        &f.account(challenge_created[3]).await,
        result::RETENTION_DEADLINE_AT_V6,
    );
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &challenge_created,
        "after challenge tag 172 close",
    )
    .await;
    clock_to(&mut f, challenge_retention).await;
    let challenge_result_rent = f.lamports(challenge_created[3]).await
        - solana_program::rent::Rent::default().minimum_balance(result::TOMBSTONE_BYTES);
    let payer_before_challenge_cleanup = f.lamports(payer).await;
    let mut cleanup = vec![dcg_program::unified::TAG_CLOSE_RESULT];
    cleanup.extend_from_slice(&challenge_descriptor);
    send_fresh(
        &mut f.ctx,
        &f.signer,
        f.program,
        cleanup,
        vec![
            AccountMeta::new(f.signer.pubkey(), true),
            AccountMeta::new(challenge_created[3], false),
            AccountMeta::new(payer, false),
        ],
    )
    .await
    .expect("tag 185 cleans up the settled challenge result");
    assert_eq!(f.lamports(payer).await, payer_before_challenge_cleanup + challenge_result_rent);
    assert_eq!(&f.account(challenge_created[3]).await[..4], b"DCRZ");
    completed.push("tag185 challenge result cleanup".to_owned());
    lifecycle_v2_probe_dispatch_refusal(
        &mut f,
        &challenge_created,
        "after challenge tag 185 cleanup",
    )
    .await;

    let elapsed_ms = started.elapsed().as_millis();
    if std::env::var_os("BASANOS_DCG_PREP_LONG").is_none() {
        assert!(elapsed_ms < 120_000, "default lifecycle-v2 path exceeded two minutes: {elapsed_ms}ms");
    }
    let mode = if std::env::var_os("BASANOS_DCG_V8_SBF").is_some() { "sbf" } else { "native" };
    let summary = format!(
        "lifecycle_property_v2 seed={seed:#x} mode={mode} fixture=retained-k80-v3 steps={} interleaved_refusal_probes={} program_transactions={} programtest_cu_total={} programtest_cu_max={} elapsed_ms={elapsed_ms} reserve_steps={reserve_steps} reserved_bytes={reserved_bytes} output_required={output_required}",
        completed.len(),
        LIFECYCLE_V2_REFUSAL_PROBES.load(Ordering::Relaxed),
        LIFECYCLE_V2_TX_COUNT.load(Ordering::Relaxed),
        LIFECYCLE_V2_TOTAL_CU.load(Ordering::Relaxed),
        LIFECYCLE_V2_MAX_CU.load(Ordering::Relaxed),
    );
    eprintln!("{summary}");
    for step in &completed {
        eprintln!("lifecycle_property_v2_step {step}");
    }
    if let Some(receipt) = std::env::var_os("BASANOS_DCG_PREP_RECEIPT") {
        let path = PathBuf::from(receipt);
        std::fs::create_dir_all(path.parent().expect("receipt file has a parent")).unwrap();
        let mut text = format!("{summary}\n");
        for step in completed {
            text.push_str(&format!("step={step}\n"));
        }
        std::fs::write(path, text).unwrap();
    }
}

// ------------------------------------------------- T8 planted-bug survivors

/// Planted bug M6 survived (2026-10-03): nothing checked that real attested
/// admission records its scan. The standard-mode template's DEA2 is complete,
/// app-bound and attested, exactly.
#[tokio::test(flavor = "multi_thread")]
async fn real_attested_admission_records_complete_app_bound_and_attested() {
    let Some(mut f) = build().await else { return };
    assert_eq!(
        u16_at(&f.account(f.dea2).await, 6),
        1 | 2 | 4,
        "DEA2 flags: complete | app-bound | attested"
    );
}

/// Planted bug M4 survived (2026-10-03): nothing closed a finalized document
/// while a challenge was open. A real open challenge (166) holds the close
/// (599) even past the dispute and production deadlines; the document's
/// accounts are untouched.
#[tokio::test(flavor = "multi_thread")]
async fn rev8_close_waits_for_an_open_challenge() {
    let Some(mut f) = build().await else { return };
    let binding = f.binding(29, 50);
    let (descriptor, created, proofs) = attest_all(&mut f, &binding, 31, &[], 83).await;
    let record = address::challenge(&f.program, &descriptor, &f.signer.pubkey(), 51).0;
    let packet = challenge_leaf_packet(&f, &descriptor, &proofs[0], 51);
    let metas = challenge_leaf_metas(&f, created, record);
    send_fresh(&mut f.ctx, &f.signer, f.program, packet, metas)
        .await
        .expect("the challenger opens a leaf challenge");
    assert_eq!(u32_at(&f.account(created[0]).await, 128), 1);
    let doc = f.account(created[0]).await;
    let past = u64_at(&doc, 144).max(u64_at(&doc, document::ABANDON_DEADLINE_AT)) + 1;
    clock_to(&mut f, past).await;
    let c = Crafted {
        dcm2: created[0],
        dpr2: created[1],
        dcr2: created[3],
        descriptor,
    };
    let before = f.account(created[3]).await;
    let metas = f.close_metas(&c, f.signer.pubkey());
    assert_eq!(
        custom(send_fresh(&mut f.ctx, &f.signer, f.program, close_data(&descriptor), metas).await),
        CL_CLOSE,
        "an open challenge holds the close"
    );
    assert_eq!(f.account(created[3]).await, before, "the refused close wrote nothing");
}
