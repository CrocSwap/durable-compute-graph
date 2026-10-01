#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run DCG's ByteSum optimistic-dispute examples in native ProgramTest."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates" / "dcg-program" / "Cargo.toml"
PT2P_FILES = (
    "base-routes.bin",
    "base-geometry.bin",
    "base-payloads.bin",
    "program.bin",
)

SCENARIOS = {
    "liar": {
        "test": "rev8_bytesum_wrong_output_rules_and_settles_sbf",
        "steps": (
            "The executor commits output prefix [4, 5, 6], although this ByteSum case requires [1, 2, 3].",
            "The challenger opens the app-bound leaf. Tag 169 replays it and rules for the challenger with code 800.",
            "Tag 131 settles the challenger win and returns the challenge record; tag 172 closes the refuted document.",
        ),
    },
    "honest": {
        "test": "rev8_bytesum_matching_honest_fastpath_enters_respond_sbf",
        "steps": (
            "The executor commits ByteSum's honest output prefix [1, 2, 3]. The challenger raises a false challenge against it.",
            "Tag 169 does not convict. The executor stages the committed witness with tag 183 and answers with tag 184.",
            "Replay matches the committed output, so the executor wins. Tag 131 returns the challenge bond to the executor.",
        ),
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=("both", *SCENARIOS),
        default="both",
        help="run both outcomes, only the lying executor, or only the false challenge",
    )
    parser.add_argument(
        "--pt2p-root",
        type=Path,
        default=os.environ.get("BASANOS_PT2P_ROOT"),
        help="directory containing the retained PT2P files (or set BASANOS_PT2P_ROOT)",
    )
    args = parser.parse_args()

    if args.pt2p_root is None:
        parser.error("set BASANOS_PT2P_ROOT or pass --pt2p-root to the retained PT2P directory")
    pt2p_root = args.pt2p_root.expanduser().resolve()
    missing = [name for name in PT2P_FILES if not (pt2p_root / name).is_file()]
    if missing:
        parser.error(f"PT2P root {pt2p_root} is missing: {', '.join(missing)}")

    env = os.environ.copy()
    env["BASANOS_PT2P_ROOT"] = str(pt2p_root)
    env["CARGO_TARGET_DIR"] = "/private/tmp/basanos-dcg-hello-dispute-target"
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    env.setdefault("RUST_LOG", "error")
    # These examples intentionally use ProgramTest's native processor.
    env.pop("BASANOS_DCG_V8_SBF", None)
    env.pop("BPF_OUT_DIR", None)

    scenarios = tuple(SCENARIOS) if args.scenario == "both" else (args.scenario,)
    for name in scenarios:
        scenario = SCENARIOS[name]
        print(f"\n=== Hello Dispute: {name} ===", flush=True)
        for step in scenario["steps"]:
            print(f"  {step}", flush=True)
        command = [
            "cargo",
            "test",
            "--quiet",
            "--locked",
            "--profile",
            "fasttest",
            "--manifest-path",
            str(MANIFEST),
            "--features",
            "sbf-real-lifecycle-test",
            "--test",
            "unified_v8_document",
            scenario["test"],
            "--",
            "--test-threads=1",
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            if result.stdout:
                print(result.stdout, end="", flush=True)
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr, flush=True)
            print(f"FAIL: {name} ProgramTest exited {result.returncode}.", flush=True)
            return result.returncode
        print(f"PASS: {name} ruling and settlement assertions completed.", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
