//! The Rust consensus bytes reproduce the Python reference's goldens.

use dcg_disputes::*;
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

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A full tree root over `leaves`, capacity 2^ceil(log2 max(n,1)), for the
/// golden comparison only.
fn root_of(tree: Tree, leaves: &[Hash]) -> Hash {
    let n = leaves.len().max(1);
    let height = usize::BITS - (n - 1).leading_zeros();
    let mut row: Vec<Hash> = leaves.to_vec();
    row.resize(1 << height, empty(&Soft, tree, 0));
    for l in 0..height {
        row = row.chunks(2).map(|p| node(&Soft, tree, l as u16, &p[0], &p[1])).collect();
    }
    row[0]
}

#[test]
fn empty_constants_and_tree_roots() {
    let v = vectors();
    for (name, tree) in [("step", Tree::Step), ("out", Tree::Out), ("chunk", Tree::Chunk), ("log", Tree::Log),
                         ("spec", Tree::Spec), ("list", Tree::List), ("lxstate", Tree::LxState),
                         ("lxcheckpoint", Tree::LxCheckpoint), ("lxconst", Tree::LxConst)] {
        for (l, want) in v["empty"][name].as_array().unwrap().iter().enumerate() {
            assert_eq!(empty(&Soft, tree, l as u16), h32(want.as_str().unwrap()), "{name} {l}");
        }
    }
    for (n, want) in v["trees"].as_object().unwrap() {
        let n: usize = n.parse().unwrap();
        let leaves: Vec<Hash> = (0..n).map(|i| [(i + 1) as u8; 32]).collect();
        assert_eq!(root_of(Tree::Step, &leaves), h32(want.as_str().unwrap()), "n={n}");
    }
}

#[test]
fn hello_run_root_spec_root_and_leaves() {
    let v = vectors();
    let hello = &v["hello"];
    let records: Vec<(u8, Vec<u8>)> = hello["spec_records"].as_array().unwrap().iter()
        .map(|r| (r[0].as_u64().unwrap() as u8, hex(r[1].as_str().unwrap()))).collect();
    let spec_leaves: Vec<Hash> = records.iter().map(|(t, r)| spec_leaf(&Soft, *t, r)).collect();
    assert_eq!(root_of(Tree::Spec, &spec_leaves), h32(hello["spec_root"].as_str().unwrap()));

    let leaves: Vec<Vec<u8>> = hello["leaves"].as_array().unwrap().iter().map(|x| hex(x.as_str().unwrap())).collect();
    let leaf_hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(&Soft, Some(l))).collect();
    let step_root = root_of(Tree::Step, &leaf_hashes);
    assert_eq!(step_root, h32(hello["step_root"].as_str().unwrap()));
    let outs: Vec<Hash> = hello["out_entries"].as_array().unwrap().iter().enumerate()
        .map(|(j, e)| out_leaf(&Soft, j as u64, Some(&hex(e.as_str().unwrap())))).collect();
    assert_eq!(root_of(Tree::Out, &outs), h32(hello["out_root"].as_str().unwrap()));
    let root_bytes: [u8; RUN_ROOT_BYTES] = hex(hello["run_root_bytes"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(run_root(&Soft, &root_bytes), h32(hello["run_root"].as_str().unwrap()));
    let rr = RunRoot(&root_bytes);
    assert_eq!(rr.step_root(), step_root);
    assert_eq!((rr.total_steps(), rr.total_outputs()), (2, 1));

    // Every honest leaf parses and matches its spec record (SHAPE rules for E).
    let plan_id = hex(hello["plan_id"].as_str().unwrap());
    let run_id = hex(hello["run_id"].as_str().unwrap());
    let steps: Vec<&Vec<u8>> = records.iter().filter(|(t, _)| *t == 8).map(|(_, r)| r).collect();
    for (k, leaf) in leaves.iter().enumerate() {
        let parsed = parse_leaf(leaf).expect("honest leaf parses");
        let spec = StepSpec(steps[k]);
        assert!(spec.valid());
        assert!(!shape_wrong(&parsed, &spec, &plan_id, &run_id, k as u64));
        // A truncated leaf is malformed.
        assert!(parse_leaf(&leaf[..leaf.len() - 1]).is_none());
    }
    // Leaf 1 (identity) reads leaf 0's output: EDGE bytes 7..55 agree.
    let consumer = parse_leaf(&leaves[1]).unwrap();
    let (kind, p, port, _, _) = StepSpec(steps[1]).input_producer(0);
    assert_eq!((kind, p), (1, 0));
    let producer = parse_leaf(&leaves[0]).unwrap();
    assert_eq!(consumer.input(0)[7..55], producer.output_port(port as u16).unwrap()[7..55]);
}

#[test]
fn structural_reveal_folds_to_the_root_and_rejects_wrong_sets() {
    let leaves: Vec<Hash> = (0..5u8).map(|i| [i + 1; 32]).collect();
    let root = root_of(Tree::Step, &leaves);
    // Height 3, depth 3: positions 0..5 pickable, 5..8 filled with EMPTY[0].
    let mut revealed: Vec<Option<Hash>> = leaves.iter().map(|l| Some(*l)).collect();
    revealed.extend([None, None, None]);
    assert_eq!(fold_reveal(&Soft, Tree::Step, 5, 3, 0, 3, &revealed), Some(root));
    let mut extra = revealed.clone();
    extra[5] = Some([9; 32]);
    assert_eq!(fold_reveal(&Soft, Tree::Step, 5, 3, 0, 3, &extra), None);
    let mut missing = revealed.clone();
    missing[4] = None;
    assert_eq!(fold_reveal(&Soft, Tree::Step, 5, 3, 0, 3, &missing), None);
    assert!(!pickable(5, 1, 3) && pickable(5, 1, 2));
}
