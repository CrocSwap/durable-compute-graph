//! The frozen v2.0 graph/plan golden corpus, decoded by the Rust port.
use base64::Engine;
use dcg_wire::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/graph_plan_v2/");

fn rows(file: &str) -> Vec<Vec<String>> {
    std::fs::read_to_string(format!("{DIR}{file}"))
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn valid_graphs_decode() {
    for row in rows("graphs_v1.tsv") {
        let bytes = b64(&row[1]);
        if let Err(code) = decode_graph(&bytes) {
            panic!("{}: refused with {}", row[0], code.name());
        }
    }
}

#[test]
fn valid_plans_decode() {
    for row in rows("plans_v1.tsv") {
        let bytes = b64(&row[1]);
        if let Err(code) = decode_plan(&bytes) {
            panic!("{}: refused with {}", row[0], code.name());
        }
    }
}

#[test]
fn refusals_match_reference_codes() {
    let mut mismatches = Vec::new();
    let mut checked = 0;
    for row in rows("refusals_v1.tsv") {
        let bytes = b64(&row[3]);
        let got = match row[1].as_str() {
            "graph" => decode_graph(&bytes).err(),
            "plan" => decode_plan(&bytes).err(),
            _ => continue,
        };
        checked += 1;
        let got = got.map(Code::name).unwrap_or("ACCEPTED");
        if got != row[2] {
            mismatches.push(format!("{}: expected {}, got {}", row[0], row[2], got));
        }
    }
    assert_eq!(checked, 42);
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn hello_graph_lowers_to_the_trusted_table() {
    let g = b64(&rows("graphs_v1.tsv").into_iter().find(|r| r[0] == "minimal_two_level_add_identity").unwrap()[1]);
    let p = b64(&rows("plans_v1.tsv").into_iter().find(|r| r[0] == "minimal_two_level_add_identity").unwrap()[1]);
    let graph = decode_graph(&g).unwrap();
    let plan = decode_plan(&p).unwrap();
    let table = lower(&graph, &plan, |id, _, _| match id {
        b"add_i32/v1\0\0\0\0\0\0" => Some(1),
        b"identity_i32/v1\0" => Some(2),
        _ => None,
    })
    .unwrap();
    // python: tracing.trace(hello).step_table() = n_in 2, steps 2, add(0,1), identity(2)
    assert_eq!(table, [2, 0, 2, 0, 1, 0, 2, 0, 0, 1, 0, 2, 0, 1, 2, 0]);
}
