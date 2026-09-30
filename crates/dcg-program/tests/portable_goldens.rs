// SPDX-License-Identifier: GPL-3.0-only

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const PORTABLE_VECTORS: &[(&str, &str)] = &[
    (
        "commit/fold_vectors_v1.tsv",
        "389b22af527fc0ec614a1f08954ea46591d0a437b4dc4c2965e8d8a11c272333",
    ),
    (
        "unified_v8/sizes_v1.tsv",
        "0c88f2a9b4023b8cdac429eb7b0e3cc48fe22fc3e16713ec25fed3ae208625c1",
    ),
    (
        "unified_v8/refusals_v1.tsv",
        "9a8f61a87ceedb7978cfdcc32deadb26b018cbd76e827a958617289c7a773c13",
    ),
    (
        "unified_v8/constants_v1.tsv",
        "ad7bdc2e213eb26838c40b5f1d88c8b4798a9d6e3111e44cf495820085c0b412",
    ),
    (
        "unified_v8/vectors_v1.tsv",
        "b2578866926acdd0f561c0244168b453d7b613b07b6b71f6929c363c4eddb59d",
    ),
    (
        "unified_v8/record_layouts_v1.tsv",
        "bbeb702b6f2100990ac73b209da612d09463d27ada5420d7f01a0959b415add3",
    ),
    (
        "unified_v8/credit.tsv",
        "be34490a86fcc592600068e25004df87c6e08d7bf6159926e09d6db08bd22748",
    ),
    (
        "unified_v8/split.tsv",
        "e6564b0188dfe38fd116ab75395e147cb66642252eb2e6700451bec81da265ef",
    ),
];

#[test]
fn revision_8_portable_vectors_match_the_frozen_bytes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/dcg");
    for (relative, expected) in PORTABLE_VECTORS {
        let path = root.join(relative);
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        let actual = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(&actual, expected, "golden bytes changed: {relative}");
    }
}
