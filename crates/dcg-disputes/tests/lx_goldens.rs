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
