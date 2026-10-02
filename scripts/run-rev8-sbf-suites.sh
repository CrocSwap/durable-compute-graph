#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Build and run the revision-8 SBF test targets against their matching images.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
WORKTREE_DIR=$(CDPATH= cd -- "$REPO_DIR/.." && pwd -P)
RUN_ROOT=${DCG_REV8_RECEIPT_DIR:-"$WORKTREE_DIR/out/runs/dcg-r8-test-hardening-2026-10-01/revision8-sbf"}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/private/tmp/basanos-dcg-r8-test-hardening-target}
DCG_SBF_SDK=${DCG_SBF_SDK:-/private/tmp/basanos-sbf-sdk-v151-20260920}
DCG_SBF_TOOLS_VERSION=${DCG_SBF_TOOLS_VERSION:-v1.51}
BUILD_SCRIPT="$REPO_DIR/crates/dcg-program/scripts/build-sbf-reproducible.sh"
BASANOS_ROOT=/Users/colkitt/sith/toys/crypto/basanos

K80_ROOT=${BASANOS_PT2P_ROOT:-"$BASANOS_ROOT/out/runs/dcg-pt2-parametric-window-routes-20260923/pt2p"}
F47_ROOT=${BASANOS_PT2P_F47_ROOT:-"$BASANOS_ROOT/out/runs/rev8-typed-decision-2026-09-30/fixture-decision/pt2p"}
K10240_PLAIN_ROOT="$BASANOS_ROOT/out/runs/rev8-k10240-template-2026-09-30/fixture/pt2p"
K10240_DECISION_ROOT=${BASANOS_PT2P_K10240_ROOT:-"$BASANOS_ROOT/out/runs/rev8-g1-f47-2-2026-09-29/fixture/f47-k10240-v1"}
F47_POSITION=${BASANOS_PT2P_F47_POSITION:-29}

mkdir -p "$RUN_ROOT"
SUMMARY="$RUN_ROOT/summary.txt"
: >"$SUMMARY"
failed=0

run_logged() {
    name=$1
    shift
    log="$RUN_ROOT/$name.log"
    if "$@" >"$log" 2>&1; then
        printf 'PASS %s\n' "$name" | tee -a "$SUMMARY"
    else
        status=$?
        printf 'FAIL %s (exit %s)\n' "$name" "$status" | tee -a "$SUMMARY"
        tail -80 "$log"
        failed=1
        return 1
    fi
}

check_pt2p() {
    label=$1
    root=$2
    for artifact in base-routes.bin base-geometry.bin base-payloads.bin program.bin; do
        if [ ! -f "$root/$artifact" ]; then
            printf 'missing %s fixture artifact: %s/%s\n' "$label" "$root" "$artifact" >&2
            return 1
        fi
    done
}

check_pt2p K80 "$K80_ROOT" || exit 2
check_pt2p Form-47 "$F47_ROOT" || exit 2
check_pt2p K10240-plain "$K10240_PLAIN_ROOT" || exit 2
if check_pt2p K10240-decision "$K10240_DECISION_ROOT" >/dev/null 2>&1; then
    decision_k10240_available=1
else
    decision_k10240_available=0
    printf 'UNVERIFIED missing K=10,240 typed-decision PT2P fixture: %s\n' \
        "$K10240_DECISION_ROOT" | tee -a "$SUMMARY"
    failed=1
fi

is_attested() {
    case " $ATTESTED_TESTS " in *" $1 "*) return 0 ;; esac
    return 1
}
image_for() {
    if is_attested "$1"; then printf '%s' "$ATTESTED_IMAGE"; else printf '%s' "$APP_IMAGE"; fi
}
features_for() {
    if is_attested "$1"; then printf 'sbf-attested-admission-test'; else printf 'sbf-real-lifecycle-test'; fi
}

DEFAULT_IMAGE="$RUN_ROOT/default"
APP_IMAGE="$RUN_ROOT/sbf-real-lifecycle-test"
UNBOUND_IMAGE="$RUN_ROOT/sbf-unbound-form-test"
ATTESTED_IMAGE="$RUN_ROOT/sbf-attested-admission-test"
# Full-size (K=10,240) app-bound admission is attested: a full per-position
# scan does not fit (owner decision 2026-10-02; app-bound-replay-v1 §1.1).
# These tests run on the attested app image and are skipped on the
# full-scan one.
ATTESTED_TESTS="rev8_pt1x_full_honest_path_reaches_challenge_ruling rev8_pt1x_registry_and_admission_sbf rev8_pt1x_real_admission_to_resolve_sbf"

if run_logged default-image-build env \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    DCG_SBF_SDK="$DCG_SBF_SDK" \
    DCG_SBF_TOOLS_VERSION="$DCG_SBF_TOOLS_VERSION" \
    DCG_SBF_STAGING_NAME=dcg-r8-test-hardening-default \
    "$BUILD_SCRIPT" --sbf-out-dir "$DEFAULT_IMAGE"; then
    run_logged default-image-template-limits env \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        BASANOS_DCG_V8_SBF=1 \
        BPF_OUT_DIR="$DEFAULT_IMAGE" \
        BASANOS_PT2P_ROOT="$K80_ROOT" \
        cargo test --locked --offline --profile fasttest -p dcg-program \
            --features sbf-real-lifecycle-test --test unified_v8_document \
            rev8_the_per_template_limits_bound_a_document_and_two_templates_differ -- --exact --nocapture || true
else
    failed=1
fi

if run_logged app-image-build env \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    DCG_SBF_SDK="$DCG_SBF_SDK" \
    DCG_SBF_TOOLS_VERSION="$DCG_SBF_TOOLS_VERSION" \
    DCG_SBF_STAGING_NAME=dcg-r8-test-hardening-app \
    "$BUILD_SCRIPT" --features sbf-real-lifecycle-test --sbf-out-dir "$APP_IMAGE"; then
    run_logged unified-v8-document-app-k10240-plain env \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        BASANOS_DCG_V8_SBF=1 \
        BASANOS_PT1X_FULL_E2E=1 \
        BASANOS_PT2P_ROOT="$K80_ROOT" \
        BASANOS_PT2P_F47_ROOT="$F47_ROOT" \
        BASANOS_PT2P_K10240_ROOT="$K10240_PLAIN_ROOT" \
        BASANOS_PT2P_F47_POSITION="$F47_POSITION" \
        BASANOS_DCG_F47_RECEIPT="$RUN_ROOT/form47-receipt-plain" \
        BASANOS_DCG_F48_RECEIPT="$RUN_ROOT/form48-receipt-plain" \
        BPF_OUT_DIR="$APP_IMAGE" \
        cargo test --locked --offline --profile fasttest -p dcg-program \
            --features sbf-real-lifecycle-test --test unified_v8_document -- --nocapture \
            --skip rev8_pt1x_full_honest_path_reaches_challenge_ruling \
            --skip rev8_pt1x_registry_and_admission_sbf \
            --skip rev8_pt1x_real_admission_to_resolve_sbf

    run_logged attested-app-image-build env \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        DCG_SBF_SDK="$DCG_SBF_SDK" \
        DCG_SBF_TOOLS_VERSION="$DCG_SBF_TOOLS_VERSION" \
        DCG_SBF_STAGING_NAME=dcg-r8-test-hardening-attested \
        "$BUILD_SCRIPT" --features sbf-attested-admission-test --sbf-out-dir "$ATTESTED_IMAGE"

    for test_name in \
        rev8_pt1x_full_honest_path_reaches_challenge_ruling \
        rev8_pt1x_registry_and_admission_sbf \
        rev8_pt1x_real_admission_to_resolve_sbf \
        rev8_app_respond_full_900_witness_k10240_sbf \
        rev8_pt1x_output_pda_provenance_sbf; do
        run_logged "k10240-plain-$test_name" env \
            CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            BASANOS_DCG_V8_SBF=1 \
            BASANOS_PT1X_FULL_E2E=1 \
            BASANOS_PT2P_ROOT="$K10240_PLAIN_ROOT" \
            BASANOS_PT2P_F47_ROOT="$F47_ROOT" \
            BASANOS_PT2P_K10240_ROOT="$K10240_PLAIN_ROOT" \
            BASANOS_PT2P_F47_POSITION="$F47_POSITION" \
            BPF_OUT_DIR="$(image_for "$test_name")" \
            cargo test --locked --offline --profile fasttest -p dcg-program \
                --features "$(features_for "$test_name")" --test unified_v8_document \
                "$test_name" -- --exact --nocapture || true
    done

    if [ "$decision_k10240_available" -eq 1 ]; then
        # The retained G1 fixture places Form 47 at the final K=10,240 position.
        for test_name in \
            rev8_pt1x_full_honest_path_reaches_challenge_ruling \
            rev8_pt1x_registry_and_admission_sbf \
            rev8_pt1x_real_admission_to_resolve_sbf \
            rev8_app_respond_full_900_witness_k10240_sbf \
            rev8_pt1x_output_pda_provenance_sbf; do
            run_logged "k10240-decision-$test_name" env \
                CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
                BASANOS_DCG_V8_SBF=1 \
                BASANOS_PT1X_FULL_E2E=1 \
                BASANOS_PT2P_ROOT="$K10240_DECISION_ROOT" \
                BASANOS_PT2P_F47_ROOT="$K10240_DECISION_ROOT" \
                BASANOS_PT2P_K10240_ROOT="$K10240_DECISION_ROOT" \
                BASANOS_PT2P_F47_POSITION=10239 \
                BPF_OUT_DIR="$(image_for "$test_name")" \
                cargo test --locked --offline --profile fasttest -p dcg-program \
                    --features "$(features_for "$test_name")" --test unified_v8_document \
                    "$test_name" -- --exact --nocapture || true
        done
    fi
else
    failed=1
fi

if run_logged unbound-form-image-build env \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    DCG_SBF_SDK="$DCG_SBF_SDK" \
    DCG_SBF_TOOLS_VERSION="$DCG_SBF_TOOLS_VERSION" \
    DCG_SBF_STAGING_NAME=dcg-r8-test-hardening-unbound \
    "$BUILD_SCRIPT" --features sbf-unbound-form-test --sbf-out-dir "$UNBOUND_IMAGE"; then
    for test_name in \
        rev8_unbound_form_refuses_admission_on_sbf \
        rev8_stale_manifest_neutralizes_non_app_fixpoint_on_sbf \
        rev8_removed_app_binding_after_admission_is_neutral_on_sbf; do
        run_logged "unbound-$test_name" env \
            CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            BASANOS_DCG_V8_SBF=1 \
            BASANOS_PT2P_ROOT="$K80_ROOT" \
            BPF_OUT_DIR="$UNBOUND_IMAGE" \
            cargo test --locked --offline --profile fasttest -p dcg-program \
                --features sbf-unbound-form-test --test unified_v8_document \
                "$test_name" -- --exact --nocapture || true
    done
else
    failed=1
fi

python3 - "$RUN_ROOT" <<'PY'
from pathlib import Path
import sys

for generated_keypair in Path(sys.argv[1]).rglob("*-keypair.json"):
    generated_keypair.unlink()
PY

printf '\nRevision-8 SBF suite summary:\n'
cat "$SUMMARY"
exit "$failed"
