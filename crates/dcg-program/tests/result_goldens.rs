//! Mode results v1: the Rust `ResultRef` encoding, digest, seal and openings
//! reproduce the Python reference's goldens (`scripts/mode_result_goldens.py`,
//! `tests/golden/dcg/result/vectors.json`).

use dcg_program::result::{self as res, Body, ResultRef};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/result/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn reference(v: &serde_json::Value, name: &str) -> (ResultRef, Vec<u8>, Vec<u8>) {
    let entry = v["refs"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap();
    let encoded = hex(entry["encoded"].as_str().unwrap());
    let decoded = ResultRef::decode(&encoded).unwrap();
    (decoded, encoded, hex(entry["digest"].as_str().unwrap()))
}

#[test]
fn every_reference_round_trips_to_the_same_bytes_and_digest() {
    let v = vectors();
    for name in ["consensus", "optimistic", "lx"] {
        let (r, encoded, digest) = reference(&v, name);
        assert_eq!(r.encode().to_vec(), encoded, "{name}: encoding");
        assert_eq!(r.digest().to_vec(), digest, "{name}: digest");
    }
}

#[test]
fn the_seal_over_a_three_chunk_state_matches() {
    let v = vectors();
    let (r, _, _) = reference(&v, "consensus");
    let n = v["seal"]["state_len"].as_u64().unwrap() as u32;
    assert_eq!(v["seal"]["state_rule"], "(i * 31 + 7) % 251");
    let state: Vec<u8> = (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let Body::Consensus(c) = r.body else { panic!("consensus") };
    assert_eq!(res::seal_digest(&c, &state).to_vec(), hex(v["seal"]["seal"].as_str().unwrap()));
    assert_eq!(r.open_state(&state), Ok(()));
    let (a, b) = state.split_at(65_537);
    assert_eq!(r.open_state_spans(&[a, b]), Ok(()));
}

#[test]
fn the_out_tree_and_lx_openings_match() {
    let v = vectors();
    let (o, _, _) = reference(&v, "optimistic");
    let t = &v["out_tree"];
    assert_eq!(o.root.to_vec(), hex(t["root"].as_str().unwrap()));
    let index = t["index"].as_u64().unwrap();
    let r: [u8; 55] = hex(t["refs"][index as usize].as_str().unwrap()).try_into().unwrap();
    let path: Vec<[u8; 32]> = t["path"].as_array().unwrap().iter().map(|p| hex(p.as_str().unwrap()).try_into().unwrap()).collect();
    assert_eq!(o.open_output(index, &r, &path), Ok(()));
    assert!(res::plain_value_matches(&r, &hex(t["values"][index as usize].as_str().unwrap())));

    let (l, _, _) = reference(&v, "lx");
    let outputs: Vec<Option<Vec<u8>>> =
        v["lx_outputs"].as_array().unwrap().iter().map(|x| x.as_str().map(hex)).collect();
    let views: Vec<Option<&[u8]>> = outputs.iter().map(|o| o.as_deref()).collect();
    assert_eq!(l.open_lx_outputs(&views), Ok(()));
}
