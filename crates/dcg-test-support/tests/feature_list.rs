//! `PROGRAM_FEATURES` (and so `program_features!`) names every dcg-program feature.

#[test]
fn the_feature_list_matches_the_program_manifest() {
    let toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../dcg-program/Cargo.toml")).unwrap();
    let section = toml.split("[features]").nth(1).unwrap();
    let section = section.split("\n[").next().unwrap();
    let names: Vec<&str> = section
        .lines()
        .filter_map(|l| l.split_once('=').map(|(n, _)| n.trim()))
        .filter(|n| !n.is_empty() && !n.starts_with('#') && *n != "default")
        .collect();
    assert_eq!(names, dcg_test_support::target::PROGRAM_FEATURES);
}
