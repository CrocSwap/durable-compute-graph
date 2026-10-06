#!/bin/sh
# Build the session app's program image and write a receipt with its sha256
# and DCG runtime version (alpha plan C0).
#
#   ./build.sh OUT_DIR          # PYTHON=path/to/venv/python if python3 lacks solders
set -eu
OUT=${1:?usage: $0 OUT_DIR}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
mkdir -p "$OUT"
cargo build-sbf --tools-version v1.51 --manifest-path "$HERE/Cargo.toml" --sbf-out-dir "$OUT" -- --locked >"$OUT/build.log" 2>&1
SHA=$(shasum -a 256 "$OUT/dcg_session_app.so" | cut -d' ' -f1)
RUNTIME=$(PYTHONPATH="$HERE/../../python" "${PYTHON:-python3}" -m dcg.runtime "$OUT/dcg_session_app.so")
cat >"$OUT/receipt.json" <<JSON
{
 "image": "dcg_session_app.so",
 "bytes": $(wc -c <"$OUT/dcg_session_app.so" | tr -d ' '),
 "sha256": "$SHA",
 "runtime": "$RUNTIME",
 "commit": "$(git -C "$HERE" rev-parse HEAD)"
}
JSON
echo "dcg_session_app.so $SHA ($RUNTIME)"
