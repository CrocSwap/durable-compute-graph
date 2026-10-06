#!/bin/sh
# Build the session app's program image and write a receipt with its sha256
# and DCG runtime version (alpha plan C0).
#
#   ./build.sh OUT_DIR          # PYTHON=path/to/venv/python if python3 lacks DCG's packages
#
# The image is named after the package in Cargo.toml (dashes become
# underscores), so a renamed copy of this template builds unchanged.
set -eu
OUT=${1:?usage: $0 OUT_DIR}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
NAME=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$HERE/Cargo.toml" | head -1 | tr - _)
IMAGE="$OUT/$NAME.so"
# DCG's Python package, when this copy is inside a DCG checkout.
TOP=$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || true)
PYPATH=""
if [ -n "$TOP" ] && [ -d "$TOP/python/dcg" ]; then PYPATH="$TOP/python"; fi
mkdir -p "$OUT"
cargo build-sbf --tools-version v1.51 --manifest-path "$HERE/Cargo.toml" --sbf-out-dir "$OUT" -- --locked >"$OUT/build.log" 2>&1
SHA=$(shasum -a 256 "$IMAGE" | cut -d' ' -f1)
RUNTIME=$(PYTHONPATH="$PYPATH" "${PYTHON:-python3}" -m dcg.runtime "$IMAGE")
cat >"$OUT/receipt.json" <<JSON
{
 "image": "$NAME.so",
 "bytes": $(wc -c <"$IMAGE" | tr -d ' '),
 "sha256": "$SHA",
 "runtime": "$RUNTIME",
 "commit": "$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)"
}
JSON
echo "$NAME.so $SHA ($RUNTIME)"
