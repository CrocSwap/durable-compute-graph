// SPDX-License-Identifier: GPL-3.0-only
//! Retained real-pipeline artifacts (rule 6: test inputs come from real runs).

use dcg_program::kernels::decision;
use dcg_program::position_template as pt;
use dcg_program::pt2p::{self, Pt2p};
use dcg_program::unified::registry;
use std::path::PathBuf;

/// Which retained template emission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKind {
    /// The 80-position rung-D emission (`BASANOS_PT2P_ROOT`).
    K80,
    /// The compiler-v1 typed-decision emission with a PXR1 tail (`BASANOS_PT2P_F47_ROOT`).
    F47,
    /// The K=10,240 compiler-v1 emission (`BASANOS_PT2P_K10240_ROOT`).
    K10240,
}

/// A loaded emission: its four PT2P files and the clause-12 v4 bytes.
pub struct Fixture {
    pub kind: FixtureKind,
    pub root: PathBuf,
    pub routes: Vec<u8>,
    pub geometry: Vec<u8>,
    pub payloads: Vec<u8>,
    pub pwr1: Vec<u8>,
    pub clause12: Vec<u8>,
    /// The payload-row offsets (one per row, then the end), as tag 142
    /// writes them into PT1X; host-side class shapes need it.
    pub payload_index: Vec<u8>,
}

const DEFAULT_K80: &str = "out/runs/dcg-pt2-parametric-window-routes-20260923/pt2p";
const DEFAULT_F47: &str = "out/runs/rev8-f-integrate-2026-09-28/compiler-v1-position29";
const DEFAULT_K10240: &str = "out/runs/rev8-k10240-template-2026-09-30/fixture/pt2p";

/// The Basanos checkout that holds the retained emissions: `BASANOS_ROOT`, or
/// a `basanos` directory beside this repository.
pub fn basanos_root() -> PathBuf {
    std::env::var_os("BASANOS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../basanos")))
}

impl Fixture {
    /// Load an emission, or `None` (with a printed reason) when it is absent:
    /// suites skip rather than fail on a machine without the retained files.
    pub fn load(kind: FixtureKind) -> Option<Fixture> {
        let root = match kind {
            FixtureKind::K80 => std::env::var_os("BASANOS_PT2P_ROOT").map(PathBuf::from).unwrap_or_else(|| basanos_root().join(DEFAULT_K80)),
            FixtureKind::F47 => std::env::var_os("BASANOS_PT2P_F47_ROOT").map(PathBuf::from).unwrap_or_else(|| basanos_root().join(DEFAULT_F47)),
            FixtureKind::K10240 => std::env::var_os("BASANOS_PT2P_K10240_ROOT").map(PathBuf::from).unwrap_or_else(|| basanos_root().join(DEFAULT_K10240)),
        };
        let read = |name: &str| std::fs::read(root.join(name)).ok();
        let (Some(routes), Some(geometry), Some(payloads), Some(pwr1)) =
            (read("base-routes.bin"), read("base-geometry.bin"), read("base-payloads.bin"), read("program.bin"))
        else {
            eprintln!("SKIP: {kind:?} fixture missing at {}", root.display());
            return None;
        };
        let clause12 = read("clause12-v4.bin").unwrap_or_else(|| {
            let g = pt2p::Program::decode(&pwr1).expect("compiler-v1 PWR1 decodes");
            let view = Pt2p::new(&routes, &geometry, &payloads, None, g.clone()).expect("PT2P view decodes");
            pt2p::encode_clause12_v4(view.position_count, view.segment_count, &g.digest()).to_vec()
        });
        let payload_index = payload_index(&payloads);
        let fixture = Fixture { kind, root, routes, geometry, payloads, pwr1, clause12, payload_index };
        if kind == FixtureKind::F47 {
            assert!(fixture.has_pxr1(), "the F47 fixture must carry a PXR1 decision tail");
        }
        Some(fixture)
    }

    pub fn has_pxr1(&self) -> bool {
        pt::route_header_v4_shallow(&self.routes).expect("valid route header").2.is_some()
    }

    pub fn program(&self) -> pt2p::Program<'_> {
        pt2p::Program::decode(&self.pwr1).unwrap()
    }

    pub fn view(&self) -> Pt2p<'_> {
        Pt2p::new(&self.routes, &self.geometry, &self.payloads, None, self.program()).unwrap()
    }

    /// A view with the payload index (class shapes read payload rows).
    pub fn view_indexed(&self) -> Pt2p<'_> {
        Pt2p::new(&self.routes, &self.geometry, &self.payloads, Some(&self.payload_index), self.program()).unwrap()
    }

    /// The SHA-256 over the emission's files: part of every snapshot key.
    pub fn digest(&self) -> [u8; 32] {
        dcg_program::hash::sha256(&[&self.routes, &self.geometry, &self.payloads, &self.pwr1])
    }

    /// The registry rows and census digest this emission's template seals
    /// against, with the summary row's limits lifted for the plan's own
    /// summary shapes (see `rows_for_admission`).
    pub fn registry_rows(&self) -> (Vec<u8>, [u8; 32]) {
        let (mut rows, census) = if self.has_pxr1() {
            decision_registry_rows()
        } else if self.kind == FixtureKind::K10240 {
            k10240_registry_rows()
        } else {
            let g = golden("unified_v7.json");
            (
                unhex(g["drp2"]["rows"].as_str().unwrap()),
                unhex(g["drp2"]["census_digest"].as_str().unwrap()).try_into().unwrap(),
            )
        };
        let k = self.view().position_count;
        lift_summary_row(&mut rows, k);
        (rows, census)
    }
}

/// The retained golden JSON files under `tests/golden/dcg/`.
pub fn golden(name: &str) -> serde_json::Value {
    let path = golden_dir().join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))).unwrap()
}

pub fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/dcg")
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// The v7 golden's registry row set is a refusal variant: its summary row
/// (form 0xF001) is narrowed below real summary shapes. Lift only that row's
/// limit fields (never its form, respond path or witness kind) so the real
/// summary-class check at init runs over the real shapes.
fn lift_summary_row(rows: &mut [u8], k: u32) {
    for row in rows.chunks_exact_mut(registry::ROW_BYTES) {
        if u16::from_le_bytes(row[..2].try_into().unwrap()) == registry::FORM_RS1_SUMMARY {
            row[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
            row[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
            for field in [8usize, 12, 16, 40, 44, 48] {
                row[field..field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            for field in [20usize, 24] {
                row[field..field + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
            }
            row[37] = dcg_program::unified::classes::rs1_height(k);
        }
    }
}

fn tsv_rows(name: &str, row_column: usize) -> (Vec<u8>, [u8; 32]) {
    let text = std::fs::read_to_string(golden_dir().join(name)).unwrap();
    let census: [u8; 32] = text
        .lines()
        .find_map(|l| l.strip_prefix("# source_census_digest\t"))
        .map(|h| unhex(h).try_into().unwrap())
        .expect("census digest line");
    let mut rows = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        rows.extend_from_slice(&unhex(line.split('\t').nth(row_column).expect("row column")));
    }
    assert_eq!(rows.len() % registry::ROW_BYTES, 0);
    (rows, census)
}

/// The retained K=10,240 census rows.
pub fn k10240_registry_rows() -> (Vec<u8>, [u8; 32]) {
    tsv_rows("rev8_census_registry_rows_v1.tsv", 5)
}

/// The measured compiler-v1 registry with the Form-47 and Form-48 rows.
pub fn decision_registry_rows() -> (Vec<u8>, [u8; 32]) {
    let (rows, census) = tsv_rows("rev8_census_registry_rows_v2.tsv", 1);
    assert_eq!(rows.len() / registry::ROW_BYTES, 31, "the measured registry has 31 rows");
    let gather = registry::find_row(&rows, decision::GATHER_FORM_ID).unwrap().expect("Form-48 row");
    assert_eq!((gather.respond_path, gather.witness_kind), (1, 0));
    (rows, census)
}

/// The offset of each payload row (rows are `id:u32 | len:u16 | len bytes`,
/// in id order), then the end offset.
fn payload_index(payloads: &[u8]) -> Vec<u8> {
    let (mut out, mut at, mut expected) = (Vec::new(), 0usize, 0u32);
    while at < payloads.len() {
        assert_eq!(u32::from_le_bytes(payloads[at..at + 4].try_into().unwrap()), expected, "payload row order");
        out.extend_from_slice(&(at as u32).to_le_bytes());
        at += 6 + u16::from_le_bytes([payloads[at + 4], payloads[at + 5]]) as usize;
        assert!(at <= payloads.len(), "payload row in bounds");
        expected += 1;
    }
    out.extend_from_slice(&(at as u32).to_le_bytes());
    out
}
