SPDX-License-Identifier: MIT

The `crates/dcg-program/vendor/` directory is derived from
curve25519-dalek 3.2.0 and retains its upstream BSD 3-Clause `LICENSE` and
copyright notices. The vendored source contains the narrow compatibility patch
already present in the Basanos revision-8 source tree: unused by-value table
constructors are removed for the SBF verifier. All attribution in the vendor
tree is preserved.
