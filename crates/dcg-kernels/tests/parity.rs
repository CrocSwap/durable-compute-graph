//! Host side of the host/SBF parity vectors (stage-2 acceptance).
//!
//! `tests/vectors/parity-v1.json` lists Hello Graph runs `identity(add(a, b))`
//! with the host's output or refusal. `scripts/kernel_parity.py` runs the same
//! inputs through the SBF consensus handler (tag 215) and compares. Regenerate
//! with `DCG_WRITE_VECTORS=1 cargo test -p dcg-kernels --test parity`.
use dcg_kernels::*;

const CASES: &[(&str, i32, i32)] = &[
    ("ordinary", 20, 22),
    ("negative", -7, 3),
    ("zero-sum", i32::MIN + 1, i32::MAX),
    ("max-edge", i32::MAX - 1, 1),
    ("min-edge", i32::MIN + 1, -1),
    ("min-plus-max", i32::MIN, i32::MAX),
    ("overflow-up", i32::MAX, 1),
    ("overflow-down", i32::MIN, -1),
];

fn host(a: i32, b: i32) -> String {
    let mut sum = [0u8; 4];
    if let Err(code) = execute(KERNEL_ADD_I32, &[&a.to_le_bytes(), &b.to_le_bytes()], &mut sum) {
        return format!("{{\"refusal\": {code}, \"step\": 0}}");
    }
    let mut out = [0u8; 4];
    match execute(KERNEL_IDENTITY_I32, &[&sum], &mut out) {
        Ok(_) => format!("{{\"trace\": [{}, {}]}}", i32::from_le_bytes(sum), i32::from_le_bytes(out)),
        Err(code) => format!("{{\"refusal\": {code}, \"step\": 1}}"),
    }
}

#[test]
fn parity_vectors_match_checked_in_file() {
    let mut rows = Vec::new();
    for (name, a, b) in CASES {
        rows.push(format!("  {{\"name\": \"{name}\", \"inputs\": [{a}, {b}], \"host\": {}}}", host(*a, *b)));
    }
    let text = format!("[\n{}\n]\n", rows.join(",\n"));
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/parity-v1.json");
    if std::env::var("DCG_WRITE_VECTORS").is_ok() {
        std::fs::write(path, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
}

#[test]
fn malformed_inputs_are_refused_on_host() {
    let mut out = [0u8; 4];
    assert_eq!(execute(KERNEL_ADD_I32, &[&[1u8, 2, 3]], &mut out), Err(ERR_BAD_INPUT));
    assert_eq!(execute(KERNEL_ADD_I32, &[&[0u8; 4], &[0u8; 5]], &mut out), Err(ERR_BAD_INPUT));
    assert_eq!(execute(KERNEL_IDENTITY_I32, &[&[0u8; 4]], &mut [0u8; 3]), Err(ERR_OUTPUT_CAPACITY));
    assert_eq!(execute(0, &[], &mut out), Err(ERR_UNKNOWN_KERNEL));
}
