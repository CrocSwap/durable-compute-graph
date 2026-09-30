//! DCG commit mode v1, step 6.2: the fold.
//!
//! `docs/spec/dcg-commit-v1.md` §3.2–§3.4 is normative;
//! `tests/golden/dcg/commit/fold_vectors_v1.tsv` is its executable half and
//! `chain/dcg-program/src/commit/fold.rs` reproduces every row of it here.
//! The Python mirror (`src/basanos/dcg/commit/fold.py`) is checked against the
//! same file in `tests/test_dcg_commit_fold.py`, so gate 3's cross-language
//! equality is both languages against one pinned vector.
//!
//! Pure: no account, no I/O, no clock, no handler.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use dcg_program::commit::fold::{
    check_closure_root, check_membership, check_tree_root, closure_root, max_proof_depth,
    membership_proof, membership_verify, node, tree_root_frontier, tree_root_reference, Frontier,
    Side, MAX_RECORD_PROOF_DEPTH,
};
use dcg_program::hash::sha256;

/// The synthetic leaf source `scripts/dcg_emit_commit_goldens.py` pins:
/// `sha256("basanos/dcg-vector-leaf/1" | index:u32le)`.
const VECTOR_LEAF_TAG: &[u8] = b"basanos/dcg-vector-leaf/1";

fn vector_leaf(index: u32) -> [u8; 32] {
    sha256(&[VECTOR_LEAF_TAG, &index.to_le_bytes()])
}

fn synthetic_leaves(count: usize) -> Vec<[u8; 32]> {
    (0..count as u32).map(vector_leaf).collect()
}

/// `sha256("basanos/dcg-vector-descriptor/1" | "commit-v1")`.
fn descriptor() -> [u8; 32] {
    sha256(&[b"basanos/dcg-vector-descriptor/1", b"commit-v1"])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Left => "left",
        Side::Right => "right",
    }
}

fn read_tsv(name: &str) -> Vec<Vec<String>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/dcg/commit")
        .join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

fn cases(rows: &[Vec<String>]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for row in rows {
        assert_eq!(row.len(), 3, "bad fold vector row: {row:?}");
        out.entry(row[0].clone()).or_default().insert(row[1].clone(), row[2].clone());
    }
    out
}

fn path_text(proof: &[(Side, [u8; 32])]) -> String {
    proof
        .iter()
        .map(|(side, digest)| format!("{}:{}", side_name(*side), hex(digest)))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn every_fold_vector_row_matches_the_fold_module() {
    let rows = read_tsv("fold_vectors_v1.tsv");
    let all = cases(&rows);
    let mut leaf_cases = 0;
    for (name, fields) in &all {
        if name == "binding" {
            continue;
        }
        leaf_cases += 1;
        let count: usize = fields["leaf_count"].parse().unwrap();
        let leaves = synthetic_leaves(count);
        let reference = tree_root_reference(&leaves).unwrap();
        let carried = tree_root_frontier(&leaves).unwrap();
        assert_eq!(hex(&reference), fields["tree_root"], "{name}: tree_root");
        assert_eq!(hex(&carried), fields["tree_root_frontier"], "{name}: frontier");
        assert_eq!(carried, reference, "{name}: frontier != reference");
        let root = closure_root(&descriptor(), 3, 5, count as u32, &reference);
        assert_eq!(hex(&root), fields["closure_root"], "{name}: closure_root");
        let index: usize = fields["proof_index"].parse().unwrap();
        let proof = membership_proof(&leaves, index).unwrap();
        assert_eq!(proof.len().to_string(), fields["proof_depth"], "{name}: depth");
        assert_eq!(path_text(&proof), fields["proof_path"], "{name}: path");
        assert_eq!(
            max_proof_depth(count as u32) as usize,
            proof.len(),
            "{name}: ceil(log2) depth"
        );
        assert_eq!(membership_verify(&leaves[index], &proof), reference, "{name}: verify");
    }
    assert_eq!(leaf_cases, 12, "fold_vectors_v1.tsv changed shape");
}

#[test]
fn closure_root_binds_document_family_window_and_count() {
    let all = cases(&read_tsv("fold_vectors_v1.tsv"));
    let binding = &all["binding"];
    let base = tree_root_reference(&synthetic_leaves(8)).unwrap();
    let expected = [
        ("base", closure_root(&descriptor(), 3, 5, 8, &base)),
        ("other_descriptor", closure_root(&sha256(&[b"other"]), 3, 5, 8, &base)),
        ("other_family", closure_root(&descriptor(), 4, 5, 8, &base)),
        ("other_window", closure_root(&descriptor(), 3, 6, 8, &base)),
        ("other_count", closure_root(&descriptor(), 3, 5, 9, &base)),
    ];
    let mut values = std::collections::HashSet::new();
    for (name, root) in expected {
        assert_eq!(hex(&root), binding[name], "{name}");
        values.insert(root);
    }
    assert_eq!(values.len(), 5, "a closure root is transferable");
}

#[test]
fn the_frontier_equals_the_reference_for_every_pinned_count() {
    let counts: Vec<usize> = (1..=64).chain([83, 256, 1_000, 4_096]).collect();
    for count in counts {
        let leaves = synthetic_leaves(count);
        assert_eq!(
            tree_root_frontier(&leaves),
            tree_root_reference(&leaves),
            "frontier != reference at {count} leaves"
        );
    }
}

#[test]
fn the_naive_bag_the_peaks_collapse_disagrees_at_three_leaves() {
    let three = synthetic_leaves(3);
    let mut frontier = Frontier::new();
    for leaf in &three {
        frontier.push(leaf).unwrap();
    }
    // "Bag the peaks": combine across levels without lifting by duplication.
    let mut carry: Option<[u8; 32]> = None;
    for level in 0..32 {
        if let Some(peak) = frontier.level(level) {
            carry = Some(match carry {
                None => *peak,
                Some(current) => node(peak, &current),
            });
        }
    }
    assert_ne!(
        carry.unwrap(),
        tree_root_reference(&three).unwrap(),
        "the wrong collapse must differ at three leaves"
    );
    // The right collapse is the reference.
    assert_eq!(frontier.collapse().unwrap(), tree_root_reference(&three).unwrap());
}

#[test]
fn a_swapped_or_truncated_proof_does_not_rebuild_the_root() {
    for count in [2usize, 3, 5, 9, 83, 256] {
        let leaves = synthetic_leaves(count);
        let root = tree_root_reference(&leaves).unwrap();
        let proof = membership_proof(&leaves, count / 2).unwrap();
        if count > 2 {
            let swapped: Vec<(Side, [u8; 32])> = proof
                .iter()
                .map(|(side, digest)| {
                    let flipped = match side {
                        Side::Left => Side::Right,
                        Side::Right => Side::Left,
                    };
                    (flipped, *digest)
                })
                .collect();
            assert_ne!(membership_verify(&leaves[count / 2], &swapped), root, "swapped {count}");
        }
        if !proof.is_empty() {
            let truncated = &proof[..proof.len() - 1];
            assert_ne!(membership_verify(&leaves[count / 2], truncated), root, "truncated {count}");
        }
    }
}

#[test]
fn the_frontier_occupancy_is_the_cursor_and_a_disagreement_is_459() {
    let leaves = synthetic_leaves(3);
    let mut frontier = Frontier::new();
    for leaf in &leaves {
        frontier.push(leaf).unwrap();
    }
    assert_eq!(frontier.leaf_cursor(), 3);
    assert_eq!(frontier.occupancy(), 0b11);
    frontier.check().unwrap();

    // A stored node at level 0 with a cursor of zero: 459, not a guess.
    let mut levels: [Option<[u8; 32]>; 32] = [None; 32];
    levels[0] = Some(vector_leaf(0));
    let inconsistent = Frontier::from_levels(levels, 0);
    assert_eq!(inconsistent.check().unwrap_err().0, 459);
    let mut to_push = inconsistent;
    assert_eq!(to_push.push(&vector_leaf(1)).unwrap_err().0, 459);
}

#[test]
fn a_wrong_tree_root_or_closure_root_is_452() {
    let leaves = synthetic_leaves(5);
    let root = tree_root_reference(&leaves).unwrap();
    let wrong = node(&root, &root);
    check_tree_root(&root, &root).unwrap();
    assert_eq!(check_tree_root(&wrong, &root).unwrap_err().0, 452);
    let declared = closure_root(&descriptor(), 3, 5, 5, &root);
    let other = closure_root(&descriptor(), 3, 6, 5, &root);
    check_closure_root(&declared, &declared).unwrap();
    assert_eq!(check_closure_root(&other, &declared).unwrap_err().0, 452);
}

#[test]
fn a_bad_membership_proof_is_457_and_the_depth_bound_is_32() {
    assert_eq!(MAX_RECORD_PROOF_DEPTH, 32);
    let leaves = synthetic_leaves(4);
    let root = tree_root_reference(&leaves).unwrap();
    let proof = membership_proof(&leaves, 2).unwrap();
    check_membership(&leaves[2], &proof, &root).unwrap();
    assert_eq!(check_membership(&leaves[1], &proof, &root).unwrap_err().0, 457);
    // A path deeper than the frontier bound is refused, even if it verifies.
    let too_deep: Vec<(Side, [u8; 32])> =
        std::iter::repeat((Side::Right, root)).take(MAX_RECORD_PROOF_DEPTH + 1).collect();
    assert_eq!(check_membership(&leaves[0], &too_deep, &root).unwrap_err().0, 457);
}
