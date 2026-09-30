#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_dir"
: "${CARGO_TARGET_DIR:=/private/tmp/dcg-extract-target}"
export CARGO_TARGET_DIR
cargo test --locked --profile fasttest --all-targets
