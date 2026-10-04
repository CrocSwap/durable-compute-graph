#!/usr/bin/env python3
"""Golden vectors for optimistic disputes v2.1, step 1 (tests/golden/dcg/disputes_v21/vectors.json).

The Rust program must reproduce every value here. Regenerate only with a
design change, and say so in the commit.
"""
from __future__ import annotations

import json
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from dcg import tracing  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402
from dcg.disputes_v21 import spec as S  # noqa: E402
from dcg.disputes_v21 import trees  # noqa: E402
from dcg.kernels import add_i32, identity_i32  # noqa: E402

OUT = ROOT / "tests/golden/dcg/disputes_v21/vectors.json"


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def build() -> dict:
    v = {"empty": {k: [trees.empty(k, l).hex() for l in range(4)] for k in trees.NODE_DOMAINS},
         "trees": {}}
    for n in (0, 1, 2, 3, 5, 6, 7, 8, 9, 15, 17):
        leaves = [bytes([i + 1]) * 32 for i in range(n)]
        v["trees"][str(n)] = trees.build("step", leaves).root.hex()
    g = tracing.trace(hello)
    sp = S.derive(g.graph_bytes(), g.plan_bytes())
    values = {0: struct.pack("<i", 20), 1: struct.pack("<i", 22)}
    refs = {e: R.external_ref(e, sp.in_specs[e][8:31], R.value_digest(values[e])) for e in values}
    plan_id, template, executor, nonce = bytes([7]) * 32, bytes([8]) * 32, bytes([9]) * 32, bytes(32)
    run = R.run_id(template, nonce, list(refs.values()), executor)
    honest = R.execute(sp, plan_id, run, values)
    v["hello"] = {
        "inputs": [20, 22], "plan_id": plan_id.hex(), "template_id": template.hex(), "executor": executor.hex(),
        "nonce": nonce.hex(), "external_refs": {str(e): r.hex() for e, r in refs.items()},
        "spec_records": [[t, r.hex()] for t, r in sp.records], "spec_root": sp.root.hex(),
        "run_id": run.hex(), "leaves": [x.hex() for x in honest.leaves],
        "out_entries": [x.hex() for x in honest.out_entries], "step_root": honest.step_tree.root.hex(),
        "out_root": honest.out_tree.root.hex(), "run_root_bytes": honest.root_bytes.hex(),
        "run_root": honest.root.hex(),
    }
    return v


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")
    print(OUT)
