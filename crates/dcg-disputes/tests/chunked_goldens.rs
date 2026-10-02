//! The Rust chunked-kernel bytes reproduce the Python reference's goldens
//! (`tests/golden/dcg/disputes_v21/chunked.json`).

use dcg_disputes::blocks::{self, Block};
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

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/chunked.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn plan_blocks(p: &serde_json::Value) -> Vec<Block> {
    p["spec_records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r[0].as_u64() == Some(2))
        .map(|r| Block::parse(&hex(r[1].as_str().unwrap())).expect("BlockSpec parses"))
        .collect()
}

#[test]
fn block_records_parse_to_the_reference_fields_and_placement() {
    for p in vectors()["plans"].as_array().unwrap() {
        let blocks = plan_blocks(p);
        let mut end = 0u64;
        for (b, want) in blocks.iter().zip(p["blocks"].as_array().unwrap()) {
            let w: Vec<u64> = want.as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
            assert_eq!(
                (b.kind as u64, b.base, b.step_count, b.k as u64, b.body_len as u64, b.gate_entry as u64,
                 b.gate_port as u64, b.first_record, b.record_count, b.address_base, b.address_height as u64),
                (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10])
            );
            assert_eq!(b.derived_height(), b.address_height as u32);
            assert_eq!(blocks::place_after(end, b.derived_height()), Some(b.address_base));
            end = b.address_base + (1 << b.address_height);
        }
        assert_eq!(blocks::height_for(end), p["address_height"].as_u64().unwrap() as u32);
    }
}

#[test]
fn address_map_and_pickability_match() {
    for p in vectors()["plans"].as_array().unwrap() {
        let blocks = plan_blocks(p);
        let positions: Vec<u64> = p["positions"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
        for (k, &pos) in positions.iter().enumerate() {
            let b = blocks.iter().find(|b| b.contains(k as u64)).unwrap();
            assert_eq!(b.position_of(k as u64), pos, "{} ordinal {k}", p["name"]);
        }
        for (pos, want) in p["ordinal_at"].as_array().unwrap().iter().enumerate() {
            let got = blocks.iter().find_map(|b| b.ordinal_at(pos as u64));
            let want = want.as_i64().unwrap();
            assert_eq!(got.map(|v| v as i64).unwrap_or(-1), want, "{} position {pos}", p["name"]);
        }
        for (level, row) in p["pickable"].as_array().unwrap().iter().enumerate() {
            for (pos, c) in row.as_str().unwrap().chars().enumerate() {
                assert_eq!(blocks::pickable(&blocks, level as u32, pos as u64), c == '1',
                           "{} level {level} position {pos}", p["name"]);
            }
        }
    }
}

#[test]
fn generated_step_specs_match() {
    for p in vectors()["plans"].as_array().unwrap() {
        let blocks = plan_blocks(p);
        let records: Vec<Vec<u8>> =
            p["spec_records"].as_array().unwrap().iter().map(|r| hex(r[1].as_str().unwrap())).collect();
        let leaf_index: Vec<u64> =
            p["step_leaf_index"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
        for (k, want) in p["step_specs"].as_array().unwrap().iter().enumerate() {
            let want = hex(want.as_str().unwrap());
            let b = blocks.iter().find(|b| b.contains(k as u64)).unwrap();
            let (i, e) = b.split(k as u64);
            assert_eq!(b.first_record + e, leaf_index[k]);
            let stored = &records[leaf_index[k] as usize];
            let got = if b.kind == 1 {
                stored.clone()
            } else {
                let mut out = vec![0u8; stored.len()];
                assert!(blocks::generate(stored, b, i, &mut out));
                out
            };
            assert_eq!(got, want, "{} ordinal {k}", p["name"]);
            assert!(StepSpec(&got).valid());
        }
    }
}

#[test]
fn leaves_parse_and_shape_agrees_and_roots_match() {
    for p in vectors()["plans"].as_array().unwrap() {
        let blocks = plan_blocks(p);
        let height = p["address_height"].as_u64().unwrap() as u32;
        let run_root_bytes = hex(p["run_root_bytes"].as_str().unwrap());
        let plan_id = &run_root_bytes[0..32];
        let run_id = &run_root_bytes[32..64];
        let mut row = vec![empty(&Soft, Tree::Step, 0); 1 << height];
        for (k, leaf) in p["leaves"].as_array().unwrap().iter().enumerate() {
            let b = blocks.iter().find(|b| b.contains(k as u64)).unwrap();
            let raw = leaf.as_str().map(hex);
            if let Some(raw) = &raw {
                let parsed = parse_leaf(raw).expect("honest leaf parses");
                let spec = hex(p["step_specs"][k].as_str().unwrap());
                assert!(!shape_wrong(&parsed, &StepSpec(&spec), plan_id, run_id, k as u64), "{} {k}", p["name"]);
            }
            row[b.position_of(k as u64) as usize] = leaf_hash(&Soft, raw.as_deref());
        }
        for l in 0..height {
            row = row.chunks(2).map(|c| node(&Soft, Tree::Step, l as u16, &c[0], &c[1])).collect();
        }
        assert_eq!(row[0].to_vec(), hex(p["step_root"].as_str().unwrap()), "{}", p["name"]);
    }
}

#[test]
fn reduction_kernels_replay_as_the_reference() {
    for v in vectors()["kernels"].as_array().unwrap() {
        let kernel = hex(v["kernel"].as_str().unwrap());
        let inputs: Vec<Vec<u8>> = v["inputs"].as_array().unwrap().iter().map(|x| hex(x.as_str().unwrap())).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|x| x.as_slice()).collect();
        let prior = v["prior"].as_str().map(hex);
        let got = reductions::replay(&kernel, &refs, prior.as_deref());
        match v["outputs"].as_array() {
            None => assert!(got.is_none(), "{v}"),
            Some(outs) => {
                let r = got.expect("replays");
                assert_eq!(r.output_count, outs.len());
                for (i, o) in outs.iter().enumerate() {
                    assert_eq!(r.output(i), hex(o.as_str().unwrap()).as_slice());
                }
                assert_eq!(r.next().map(|x| x.to_vec()), v["next"].as_str().map(hex));
            }
        }
    }
}

#[test]
fn chunk_leaves_match() {
    for v in vectors()["chunk_leaf"].as_array().unwrap() {
        let got = chunk_leaf(&Soft, v["index"].as_u64().unwrap(), &hex(v["chunk"].as_str().unwrap()));
        assert_eq!(got.to_vec(), hex(v["leaf"].as_str().unwrap()));
    }
}
