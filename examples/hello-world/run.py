#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the DCG counter example in a local, in-process ProgramTest bank."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "examples" / "hello-world" / "Cargo.toml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("increment", type=int, help="one-byte counter input (0 to 255)")
    args = parser.parse_args()
    if not 0 <= args.increment <= 255:
        parser.error("increment must be between 0 and 255")

    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", "/private/tmp/dcg-hello-world-target")
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    env.setdefault("RUST_LOG", "error")
    command = [
        "cargo",
        "run",
        "--quiet",
        "--locked",
        "--manifest-path",
        str(MANIFEST),
        "--",
        str(args.increment),
    ]
    return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
