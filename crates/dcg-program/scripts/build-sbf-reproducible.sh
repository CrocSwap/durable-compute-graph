#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Standalone SBF wrapper with a fixed staging path, stack-frame guard, and
# optional image digest gate. DCG_SBF_SDK must name the pinned platform-tools
# SDK directory; a tools-version flag alone is not a toolchain pin.
set -eu

CARGO_BUILD_SBF=${DCG_CARGO_BUILD_SBF:-cargo-build-sbf}
SBF_TOOLS_VERSION=${DCG_SBF_TOOLS_VERSION:-v1.51}
SBF_SDK=${DCG_SBF_SDK:-}
if [ -z "$SBF_SDK" ] || [ ! -d "$SBF_SDK" ]; then
    echo "set DCG_SBF_SDK to the pinned platform-tools SDK directory" >&2
    exit 2
fi
case "$CARGO_BUILD_SBF" in
    /*) [ -x "$CARGO_BUILD_SBF" ] || { echo "cargo-build-sbf is not executable: $CARGO_BUILD_SBF" >&2; exit 2; } ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd -P)
STAGING_NAME=${DCG_SBF_STAGING_NAME:-dcg-sbf-program-v1}
case "$STAGING_NAME" in
    */*|.|..|'') echo "invalid staging name: $STAGING_NAME" >&2; exit 2 ;;
esac
STAGING_DIR=/private/tmp/$STAGING_NAME
LOCK_DIR=${STAGING_DIR}.lock
if [ -L "$STAGING_DIR" ]; then
    echo "refusing symlinked staging path: $STAGING_DIR" >&2
    exit 2
fi
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "reproducible SBF staging path is already in use: $LOCK_DIR" >&2
    exit 75
fi

staging_created=0
BUILD_LOG=$(mktemp "${TMPDIR:-/tmp}/dcg-sbf-build.XXXXXX")
BUILD_STATUS_FILE="$BUILD_LOG.status"
cleanup() {
    if [ "$staging_created" -eq 1 ]; then
        find "$STAGING_DIR" -depth -delete 2>/dev/null || true
    fi
    rm -f "$BUILD_LOG" "$BUILD_STATUS_FILE" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

if [ -e "$STAGING_DIR" ]; then
    echo "reproducible SBF staging path already exists: $STAGING_DIR" >&2
    exit 2
fi
mkdir "$STAGING_DIR"
staging_created=1
cp -R "$REPO_DIR"/. "$STAGING_DIR"/
cd "$STAGING_DIR/crates/dcg-program"

EXPECT_SHA256=
SBF_OUT_DIR=
remaining=$#
while [ "$remaining" -gt 0 ]; do
    argument=$1
    shift
    remaining=$((remaining - 1))
    case "$argument" in
        --expect-sha256)
            [ "$remaining" -gt 0 ] || { echo "--expect-sha256 needs a digest" >&2; exit 2; }
            EXPECT_SHA256=$1
            shift
            remaining=$((remaining - 1))
            ;;
        --expect-sha256=*) EXPECT_SHA256=${argument#--expect-sha256=} ;;
        --sbf-out-dir)
            [ "$remaining" -gt 0 ] || { echo "--sbf-out-dir needs a directory" >&2; exit 2; }
            SBF_OUT_DIR=$1
            shift
            remaining=$((remaining - 1))
            set -- "$@" "$argument" "$SBF_OUT_DIR"
            ;;
        --sbf-out-dir=*)
            SBF_OUT_DIR=${argument#--sbf-out-dir=}
            set -- "$@" "$argument"
            ;;
        *) set -- "$@" "$argument" ;;
    esac
done
case "$EXPECT_SHA256" in
    '') ;;
    *[!0-9a-fA-F]*) echo "--expect-sha256 is not a hex digest" >&2; exit 2 ;;
esac
if [ -n "$EXPECT_SHA256" ] && [ "${#EXPECT_SHA256}" -ne 64 ]; then
    echo "--expect-sha256 must contain 64 hex characters" >&2
    exit 2
fi

{
    if "$CARGO_BUILD_SBF" --sbf-sdk "$SBF_SDK" --tools-version "$SBF_TOOLS_VERSION" --skip-tools-install "$@" 2>&1; then
        echo 0 >"$BUILD_STATUS_FILE"
    else
        echo $? >"$BUILD_STATUS_FILE"
    fi
} | tee "$BUILD_LOG"
build_status=$(cat "$BUILD_STATUS_FILE" 2>/dev/null || echo 1)
case "$build_status" in ''|*[!0-9]*) build_status=1 ;; esac
[ "$build_status" -eq 0 ] || exit "$build_status"

if grep -q \
    -e 'Stack offset of' \
    -e 'overwrites values in the frame' \
    -e 'overflows the maximum allowed frame space by accessing an offset' \
    "$BUILD_LOG"; then
    echo "SBF stack-frame overflow detected; refusing the linked image." >&2
    grep -n \
        -e 'Stack offset of' \
        -e 'overwrites values in the frame' \
        -e 'overflows the maximum allowed frame space by accessing an offset' \
        "$BUILD_LOG" >&2
    exit 3
fi

if [ -n "$EXPECT_SHA256" ]; then
    if [ -n "$SBF_OUT_DIR" ] && [ -d "$SBF_OUT_DIR" ]; then
        search=$SBF_OUT_DIR
    else
        search=${CARGO_TARGET_DIR:-$STAGING_DIR/target}/sbf-solana-solana/release
    fi
    images=$(find "$search" -maxdepth 1 -name '*.so' -type f 2>/dev/null | sort)
    count=$(printf '%s\n' "$images" | grep -c . || true)
    [ "$count" -eq 1 ] || { echo "image gate expected one .so in $search, found $count" >&2; exit 4; }
    image=$images
    if command -v sha256sum >/dev/null 2>&1; then
        found=$(sha256sum "$image" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        found=$(shasum -a 256 "$image" | cut -d' ' -f1)
    else
        echo "image gate cannot find sha256sum or shasum" >&2
        exit 4
    fi
    [ "$found" = "$EXPECT_SHA256" ] || { echo "image digest mismatch: expected $EXPECT_SHA256, built $found" >&2; exit 4; }
    echo "IMAGE GATE: ok, $image is $found"
fi
