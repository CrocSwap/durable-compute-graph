//! The Rust LX1 slot leaves and multi-proof fold reproduce the Python
//! reference (`scripts/disputes_v21_lx_goldens.py`).

use dcg_disputes::lx::{fold, slot_leaf};
use dcg_disputes::{Hash, Sha256};
use sha2::Digest;

struct Soft;
impl Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> Hash {
        let mut h = sha2::Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(s: &str) -> Hash {
    hex(s).try_into().unwrap()
}

fn cases() -> Vec<serde_json::Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/lx.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["cases"].as_array().unwrap().clone()
}

#[test]
fn slot_leaves_and_multiproofs_match_python() {
    let cases = cases();
    assert!(cases.len() >= 20);
    for c in &cases {
        let slots: Vec<u64> = c["slots"].as_array().unwrap().iter().map(|s| s.as_u64().unwrap()).collect();
        let values: Vec<Option<Vec<u8>>> = c["values"].as_array().unwrap().iter().map(|v| v.as_str().map(hex)).collect();
        let leaves: Vec<Hash> = c["leaves"].as_array().unwrap().iter().map(|v| h32(v.as_str().unwrap())).collect();
        for ((slot, value), want) in slots.iter().zip(&values).zip(&leaves) {
            assert_eq!(slot_leaf(&Soft, *slot as u32, value.as_deref()), *want, "slot {slot}");
        }
        let siblings: Vec<Hash> = c["siblings"].as_array().unwrap().iter().map(|v| h32(v.as_str().unwrap())).collect();
        let height = c["height"].as_u64().unwrap() as u16;
        let root = h32(c["root"].as_str().unwrap());
        let mut nodes: Vec<(u64, Hash)> = slots.iter().copied().zip(leaves.iter().copied()).collect();
        assert_eq!(fold(&Soft, height, &mut nodes, &siblings), Some(root));
        // A changed leaf moves the root; a missing or extra sibling is refused.
        let mut changed: Vec<(u64, Hash)> = slots.iter().copied().zip(leaves.iter().copied()).collect();
        changed[0].1[0] ^= 1;
        assert_ne!(fold(&Soft, height, &mut changed, &siblings), Some(root));
        if !siblings.is_empty() {
            let mut n: Vec<(u64, Hash)> = slots.iter().copied().zip(leaves.iter().copied()).collect();
            assert_eq!(fold(&Soft, height, &mut n, &siblings[1..]), None);
        }
        let mut extra = siblings.clone();
        extra.push([0; 32]);
        let mut n: Vec<(u64, Hash)> = slots.iter().copied().zip(leaves.iter().copied()).collect();
        assert_eq!(fold(&Soft, height, &mut n, &extra), None);
    }
}

#[test]
fn unsorted_or_out_of_range_slots_are_refused() {
    let leaf = [7u8; 32];
    assert_eq!(fold(&Soft, 3, &mut [(2, leaf), (1, leaf)], &[]), None);
    assert_eq!(fold(&Soft, 3, &mut [(1, leaf), (1, leaf)], &[]), None);
    assert_eq!(fold(&Soft, 3, &mut [(8, leaf)], &[[0; 32]; 3]), None);
    assert_eq!(fold(&Soft, 3, &mut [], &[]), None);
}

fn golden() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/lx.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn checkpoint_coordinates_match_python() {
    use dcg_disputes::lx::{checkpoint_count, checkpoint_position};
    let g = golden();
    for s in g["schedules"].as_array().unwrap() {
        let positions = s["positions"].as_u64().unwrap();
        let starts: Vec<u64> = s["starts"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        for (k, want) in s["checkpoints"].as_object().unwrap() {
            let k: u64 = k.parse().unwrap();
            let want: Vec<u64> = want.as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
            let n = checkpoint_count(positions, k).unwrap();
            let got: Vec<u64> = (0..n).map(|i| starts[checkpoint_position(positions, k, i).unwrap() as usize]).collect();
            assert_eq!(got, want, "positions {positions} k {k}");
            assert_eq!(checkpoint_position(positions, k, n), None);
        }
    }
    assert_eq!(checkpoint_count(9, 0), None);
}

#[test]
fn midpoint_coordinates_match_python() {
    use dcg_disputes::lx::midpoint_coordinates;
    let g = golden();
    for m in g["midpoints"].as_array().unwrap() {
        let (lo, hi, arity) = (m["lo"].as_u64().unwrap(), m["hi"].as_u64().unwrap(), m["arity"].as_u64().unwrap());
        let want: Vec<u64> = m["coordinates"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        let mut out = [0u64; 16];
        let n = midpoint_coordinates(lo, hi, arity, &mut out).unwrap();
        assert_eq!(&out[..n], &want[..], "lo {lo} hi {hi} arity {arity}");
        if n > 0 {
            assert_eq!(midpoint_coordinates(lo, hi, arity, &mut out[..n - 1]), None);
        }
    }
    let mut out = [0u64; 16];
    assert_eq!(midpoint_coordinates(5, 5, 16, &mut out), None);
    assert_eq!(midpoint_coordinates(6, 5, 16, &mut out), None);
    assert_eq!(midpoint_coordinates(0, 9, 1, &mut out), None);
}
