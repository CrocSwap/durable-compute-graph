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
    for name in ["consensus", "optimistic", "lx", "tree"] {
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

/// Pipelines slice 1 C: a tree seal is the Python chunked-value digest, over
/// the state whole or split into spans anywhere, and its chunks open.
#[test]
fn the_tree_seal_matches_the_chunked_value_digest() {
    let v = vectors();
    let (r, _, _) = reference(&v, "tree");
    let t = &v["tree_seal"];
    let n = v["seal"]["state_len"].as_u64().unwrap() as u32;
    let state: Vec<u8> = (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let log2 = t["chunk_log2"].as_u64().unwrap() as u8;
    let Body::Consensus(c) = r.body else { panic!("consensus") };
    assert_eq!((r.scheme, c.chunk_log2), (res::SCHEME_STATE_TREE_V1, log2));
    assert_eq!(res::tree_seal_spans(&[&state], log2).to_vec(), hex(t["root"].as_str().unwrap()));
    assert_eq!(r.open_state(&state), Ok(()));
    for cut in [1, 1023, 1024, 65_536, 100_001] {
        let (a, b) = state.split_at(cut);
        assert_eq!(r.open_state_spans(&[a, b]), Ok(()), "split at {cut}");
    }
    let size = 1usize << log2;
    for o in t["openings"].as_array().unwrap() {
        let i = o["index"].as_u64().unwrap();
        let path: Vec<[u8; 32]> = o["path"].as_array().unwrap().iter().map(|p| hex(p.as_str().unwrap()).try_into().unwrap()).collect();
        let chunk = &state[i as usize * size..((i as usize + 1) * size).min(state.len())];
        assert_eq!(r.open_state_chunk(i, chunk, &path), Ok(()), "chunk {i}");
        let mut bad = chunk.to_vec();
        bad[0] ^= 1;
        assert_eq!(r.open_state_chunk(i, &bad, &path), Err(res::ResultError::Opening));
        assert_eq!(r.open_state_chunk(i, chunk, &path[1..]), Err(res::ResultError::Opening), "short path");
    }
    let mut changed = state.clone();
    changed[n as usize - 1] ^= 1;
    assert_eq!(r.open_state(&changed), Err(res::ResultError::Opening));
    // A tree seal's chunk size must be in range; a linear seal has none.
    let mut raw = r.encode();
    raw[112 + 33] = 5;
    assert!(ResultRef::decode(&raw).is_err());
    let (lin, _, _) = reference(&v, "consensus");
    let mut raw = lin.encode();
    raw[112 + 33] = 10;
    assert!(ResultRef::decode(&raw).is_err());
}

/// Pipelines slice 1 D: `DRQ1` requirements encode and digest as the Python
/// reference, and decoding refuses a wrong length.
#[test]
fn requirements_encode_as_the_python_reference() {
    let v = vectors();
    for q in v["requirements"].as_array().unwrap() {
        let raw = hex(q["encoded"].as_str().unwrap());
        let r = res::ResultRequirements::decode(&raw).unwrap();
        assert_eq!(r.encode(), raw);
        assert_eq!(r.digest().to_vec(), hex(q["digest"].as_str().unwrap()));
        let mut long = raw.clone();
        long.push(0);
        assert!(res::ResultRequirements::decode(&long).is_err());
        if raw.len() > 8 {
            assert!(res::ResultRequirements::decode(&raw[..raw.len() - 1]).is_err());
        }
    }
}

/// Pipelines slice 1 D: the Python import table encodes as the program's
/// `ImportSpec` records.
#[cfg(feature = "graph-v21")]
#[test]
fn import_specs_encode_as_the_python_reference() {
    use dcg_program::disputes_v21 as V;
    let v = vectors();
    let tail = hex(v["import_tail"].as_str().unwrap());
    assert_eq!(&tail[0..4], V::IMPORT_TAIL_MAGIC);
    assert_eq!((tail[4], &tail[5..8]), (2, &[0u8; 3][..]));
    let q = |i: usize| res::ResultRequirements::decode(&hex(v["requirements"][i]["encoded"].as_str().unwrap())).unwrap();
    let want = [
        V::ImportSpec { external_id: 5, scheme: res::SCHEME_OUT_TREE_V21, out_index: 3, requirements_digest: q(1).digest(), host: solana_program::pubkey::Pubkey::new_from_array([0xDA; 32]) },
        V::ImportSpec { external_id: 9, scheme: res::SCHEME_STATE_TREE_V1, out_index: 0, requirements_digest: q(2).digest(), host: solana_program::pubkey::Pubkey::new_from_array([0xDB; 32]) },
    ];
    for (i, spec) in want.iter().enumerate() {
        let raw = &tail[8 + V::IMPORT_SPEC_BYTES * i..8 + V::IMPORT_SPEC_BYTES * (i + 1)];
        assert_eq!(raw, &spec.encode()[..]);
        assert_eq!(V::ImportSpec::parse(raw), Some(*spec));
    }
}
