#!/bin/sh
# Reproducible build of the DCG alpha shared-program image (owner 10-05):
# `--features alpha-image` (tag 227 v2.1 + LX1, example kernels; no test or
# v2.0 routes). Builds twice (locked dependencies) into separate target dirs
# and refuses unless the two images are byte-identical. Both builds use this
# checkout path on this machine; cross-machine reproducibility is not shown
# here; writes OUT/receipt.json with the commit, tree,
# features, platform-tools version and sha256.
#
#   scripts/build-alpha-image.sh OUT_DIR
set -eu
OUT=${1:?usage: $0 OUT_DIR}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TOOLS=v1.51
FEATURES=alpha-image
# Every build input: the crates, the workspace manifest and lockfile, and the
# pinned toolchain (re-review L5).
if [ -n "$(git -C "$ROOT" status --porcelain -- crates Cargo.toml Cargo.lock rust-toolchain.toml)" ]; then
    echo "build inputs have uncommitted changes; commit before a reproducible build" >&2
    exit 2
fi
mkdir -p "$OUT/a" "$OUT/b"
for pass in a b; do
    TARGET=$(mktemp -d "${TMPDIR:-/tmp}/dcg-alpha-$pass.XXXXXX")
    CARGO_TARGET_DIR="$TARGET" cargo build-sbf --tools-version "$TOOLS" \
        --manifest-path "$ROOT/crates/dcg-program/Cargo.toml" --features "$FEATURES" \
        --sbf-out-dir "$OUT/$pass" -- --locked >"$OUT/build-$pass.log" 2>&1
    rm -rf "$TARGET"
done
A=$(shasum -a 256 "$OUT/a/dcg_program.so" | cut -d' ' -f1)
B=$(shasum -a 256 "$OUT/b/dcg_program.so" | cut -d' ' -f1)
if [ "$A" != "$B" ]; then
    echo "the two builds differ: $A vs $B" >&2
    exit 1
fi
cp "$OUT/a/dcg_program.so" "$OUT/dcg_program.so"
cat >"$OUT/receipt.json" <<JSON
{
 "schema": "dcg/alpha-image-build/1",
 "commit": "$(git -C "$ROOT" rev-parse HEAD)",
 "tree": "$(git -C "$ROOT" rev-parse HEAD^{tree})",
 "features": "$FEATURES",
 "platform_tools": "$TOOLS",
 "bytes": $(wc -c <"$OUT/dcg_program.so" | tr -d ' '),
 "sha256": "$A"
}
JSON
echo "alpha image $A ($(wc -c <"$OUT/dcg_program.so" | tr -d ' ') bytes), two builds equal"
