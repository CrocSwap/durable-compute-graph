#!/usr/bin/env python3
"""Golden DLS1, list digest and tag-227 list-claim wire vectors."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

from solders.keypair import Keypair

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from dcg.disputes_v21 import game as G  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402
from dcg.disputes_v21 import spec as S  # noqa: E402
from dcg.disputes_v21 import wire as W  # noqa: E402

TEST_FILE = ROOT / "python/tests/test_disputes_v21_lists.py"
SPEC = importlib.util.spec_from_file_location("list_reference_tests", TEST_FILE)
TESTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TESTS)
OUT = ROOT / "tests/golden/dcg/disputes_v21/lists.json"
PLAN_ID = bytes([8]) * 32
EXECUTOR = bytes(Keypair.from_seed(bytes([0xE1]) * 32).pubkey())
NONCE = bytes(32)


def build() -> dict:
    sp, values = TESTS.mixed_plan()
    refs = {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.input_digest(sp.in_specs[eid], value))
            for eid, value in values.items()}
    template_data = W.template_data(sp, 4, PLAN_ID)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + template_data).digest()
    run_id = R.run_id(template_id, NONCE, [refs[e] for e in sorted(refs)], EXECUTOR)
    committed = R.execute(sp, PLAN_ID, run_id, values)
    executor = G.Executor(committed)
    list_id = 0
    step_ordinal = 6
    element_refs = committed.lists[(step_ordinal, 0)]
    list_record = sp.list_specs[list_id]
    list_opening = sp.opening(sp.list_leaf_index(list_id))
    step_opening = sp.opening(sp.step_leaf_index(step_ordinal))

    edge_bodies = {}
    for element in (0, 6, 12):
        kw = {"index": 0, "element": element, "list_opening": list_opening, "spec_opening": step_opening}
        kind, a, *_ = S.decode_producer(S.decode_list_spec(list_record)[1][element][1])
        if kind == 1:
            kw["producer_opening"] = executor.leaf_opening(a)
        elif kind == 3:
            kw["const_opening"] = sp.opening(sp.const_leaf_index(a))
        edge_bodies[str(element)] = W.claim_body(sp, "STEP_DESCEND", sp.position_of(step_ordinal), "EDGE", kw).hex()

    d = S.decode_step_spec(sp.step_spec(step_ordinal))
    witness = [G.honest_value(committed, sp, prod) for _header, prod, _initial in d["inputs"]]
    step_body = W.claim_body(sp, "STEP_DESCEND", sp.position_of(step_ordinal), "STEP",
                             {"index": 0, "spec_opening": step_opening, "witness": witness}).hex()
    reveal = W.leaf_body(committed.leaves[step_ordinal], {0: element_refs}).hex()
    return {
        "list_id": list_id,
        "record_index": sp.list_leaf_index(list_id),
        "list_spec": list_record.hex(),
        "element_refs": [r.hex() for r in element_refs],
        "list_leaf_hashes": [R.list_leaf(j, r).hex() for j, r in enumerate(element_refs)],
        "list_tree_root": R.list_tree(element_refs).root.hex(),
        "list_digest": R.list_digest(element_refs).hex(),
        "template_data": template_data.hex(),
        "template_id": template_id.hex(),
        "step_ordinal": step_ordinal,
        "step_leaf": committed.leaves[step_ordinal].hex(),
        "staged_leaf_reveal": reveal,
        "edge_claim_bodies": edge_bodies,
        "step_claim_body": step_body,
        "nonce": NONCE.hex(),
        "executor": EXECUTOR.hex(),
        "run_id": run_id.hex(),
        "plan_id": PLAN_ID.hex(),
        "refs": [refs[e].hex() for e in sorted(refs)],
        "spec_records": [[t, r.hex()] for t, r in sp.records],
        "spec_root": sp.root.hex(),
        "leaves": [x.hex() for x in committed.leaves],
        "out_entries": [x.hex() for x in committed.out_entries],
        "total_steps": sp.total_steps,
        "total_outputs": sp.total_outputs,
        "depth": 4,
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")
    print(OUT)
