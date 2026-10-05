"""Opt-in: the session quickstart (examples/session-app) end to end on a local
validator. Needs `solana-test-validator` and the built image:

    DCG_RUN_LOCAL_VALIDATOR=1 DCG_APP_IMAGE=out/dcg_session_app.so pytest tests/test_session_app_local.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(os.environ.get("DCG_RUN_LOCAL_VALIDATOR") != "1" or not os.environ.get("DCG_APP_IMAGE"),
                    reason="set DCG_RUN_LOCAL_VALIDATOR=1 and DCG_APP_IMAGE to run the session quickstart")
def test_session_quickstart_on_a_local_validator():
    out = subprocess.run([sys.executable, str(ROOT / "examples/session-app/quickstart.py"), os.environ["DCG_APP_IMAGE"]],
                         capture_output=True, text=True, timeout=180,
                         env={**os.environ, "PYTHONPATH": str(ROOT / "python")})
    steps = {s["step"]: s for s in map(json.loads, out.stdout.splitlines())}
    assert out.returncode == 0, out.stdout + out.stderr
    assert steps["advance"]["count"] == 3 and steps["advance"]["rejected"] == 1
    assert steps["runtime"]["version"].startswith("dcg-runtime ")
    assert steps["done"]["ok"]
