// SPDX-License-Identifier: GPL-3.0-only

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const PORTABLE_VECTORS: &[(&str, &str)] = &[
    (
        "commit/fold_vectors_v1.tsv",
        "389b22af527fc0ec614a1f08954ea46591d0a437b4dc4c2965e8d8a11c272333",
    ),
];

#[test]
fn portable_vectors_match_the_frozen_bytes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/dcg");
    for (relative, expected) in PORTABLE_VECTORS {
        let path = root.join(relative);
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        let actual = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(&actual, expected, "golden bytes changed: {relative}");
    }
}
