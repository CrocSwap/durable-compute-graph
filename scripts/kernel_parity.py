#!/usr/bin/env python3
"""SBF side of the host/SBF kernel parity vectors (stage-2 acceptance).

Runs every case of crates/dcg-kernels/tests/vectors/parity-v1.json as a
consensus-mode Hello Graph run, identity(add(a, b)), through the program's
tag-215 handler and compares the on-chain trace or refusal with the host's.
A kernel refusal surfaces as Custom(0x6200 + 0x100 + code).

Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from dcg import tracing
from dcg.graph_client import ChainError, GraphClient
from dcg.kernels import add_i32, identity_i32

VECTORS = Path(__file__).resolve().parents[1] / "crates/dcg-kernels/tests/vectors/parity-v1.json"
KERNEL_REFUSAL_BASE = 0x6200 + 0x100


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def main() -> int:
    cases = json.loads(VECTORS.read_text())
    client = GraphClient.from_environment()
    admitted = client.admit(tracing.trace(hello), "consensus", window_slots=150, samples=2)
    failures = 0
    for case in cases:
        run = client.init_run(admitted, case["inputs"])
        try:
            sig = client.execute(admitted, run)
            chain = {"trace": client.read_run(run)["trace"]}
        except ChainError as exc:
            match = re.search(r"Custom['\"]?:\s*(\d+)", str(exc))
            code = int(match.group(1)) if match else None
            chain = {"refusal": code - KERNEL_REFUSAL_BASE if code is not None else str(exc)[:120]}
            sig = None
        host = case["host"]
        same = chain.get("trace") == host.get("trace") if "trace" in host else chain.get("refusal") == host["refusal"]
        failures += not same
        print(json.dumps({"name": case["name"], "inputs": case["inputs"], "host": host, "sbf": chain,
                          "match": same, "run": str(run), "signature": sig}))
        try:
            client.close(admitted, run)
        except ChainError:
            pass
    print(json.dumps({"cases": len(cases), "mismatches": failures, "program": str(client.program_id)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
