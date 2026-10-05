#!/usr/bin/env python3
"""Program-oracle transcripts for the DLS1/list-input tag-227 implementation."""
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
from dcg.disputes_v21 import plans as P  # noqa: E402

TEST_FILE = ROOT / "python/tests/test_disputes_v21_lists.py"
MODULE = importlib.util.spec_from_file_location("list_reference_tests", TEST_FILE)
TESTS = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(TESTS)
OUT = ROOT / "tests/golden/dcg/disputes_v21/list_scenarios.json"

PLAN_ID = bytes([8]) * 32
EXECUTOR = bytes(Keypair.from_seed(bytes([0xE1]) * 32).pubkey())
NONCE = bytes(32)


def refs_for(sp, values):
    return {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.input_digest(sp.in_specs[eid], value))
            for eid, value in values.items()}


def setup_for(name, sp, values):
    refs = refs_for(sp, values)
    # Program-test goldens at the 750-slot floor: the staging-time check of
    # live templates (phase_window_for) does not apply.
    template_data = W.template_data(sp, 4, PLAN_ID, slot_ms=None)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + template_data).digest()
    run_id = R.run_id(template_id, NONCE, [refs[e] for e in sorted(refs)], EXECUTOR)
    return {"name": name, "template_data": template_data.hex(), "template_id": template_id.hex(),
            "run_id": run_id.hex(), "nonce": NONCE.hex(), "executor": EXECUTOR.hex(),
            "plan_id": PLAN_ID.hex(), "refs": [refs[e].hex() for e in sorted(refs)],
            "spec_records": [[t, r.hex()] for t, r in sp.records], "spec_root": sp.root.hex(),
            "total_steps": sp.total_steps, "total_outputs": sp.total_outputs}, refs, run_id


def commit_for(sp, setup, run_id, values, **faults):
    return R.execute(sp, PLAN_ID, run_id, values, **faults)


def descend(record, executor, ordinal):
    d = G.Dispute(record, "STEP_DESCEND", 4)
    target = record.spec.position_of(ordinal)
    picks = []
    while d.level > 0:
        d.reveal_nodes(executor.nodes(d))
        depth = min(d.depth, d.level)
        pick = (target >> (d.level - depth)) & ((1 << depth) - 1)
        picks.append(pick)
        d.pick(pick)
    d.reveal_leaf(executor.leaf(d), executor.lists(d))
    return d, picks


def claim_scenario(setup, refs, sp, run_id, honest, committed, name, *, ordinal, claim_name=None, element=None,
                   witness=None, forged=False):
    record = G.RunRecord(PLAN_ID, run_id, sp, committed.root_bytes, refs)
    ex = G.Executor(committed)
    if claim_name is None:
        captured = []
        original = G.Dispute.claim

        def capture(self, claim, **kw):
            captured.append((claim, kw))
            return original(self, claim, **kw)

        G.Dispute.claim = capture
        try:
            d = G.honest_challenge(record, ex, honest, 4)
        finally:
            G.Dispute.claim = original
        if d is None:
            raise AssertionError(f"{name}: expected a challenge")
        claim_name, kw = captured[-1]
    else:
        d, picks = descend(record, ex, ordinal)
        opening = sp.opening(sp.step_leaf_index(ordinal))
        kw = {"index": 0, "spec_opening": opening}
        if claim_name == "EDGE":
            kw.update(TESTS.edge_args(sp, ex, element))
        elif claim_name == "STEP":
            dec = S.decode_step_spec(sp.step_spec(ordinal))
            kw["witness"] = [G.honest_value(honest, sp, prod) for _h, prod, _i in dec["inputs"]]
        ruling = d.claim(claim_name, **kw)
        assert ruling == "E", (name, ruling)
    # The automatic challenger records its own descent; reproduce the unique
    # target path for the Rust driver in either case.
    target = sp.position_of(ordinal)
    picks = []
    level = sp.address_height
    while level:
        depth = min(4, level)
        picks.append((target >> (level - depth)) & ((1 << depth) - 1))
        level -= depth
    actual_ordinal = d.ordinal
    lists = {i: values for (o, i), values in committed.lists.items() if o == actual_ordinal}
    body = W.claim_body(sp, "STEP_DESCEND", d.position, claim_name, kw)
    row = {"name": name, "setup": setup["name"], "commit": name, "ordinal": actual_ordinal,
           "position": d.position, "picks": picks, "claim": claim_name, "index": kw.get("index", 0),
           "claim_body": body.hex(), "staged_leaf_reveal": W.leaf_body(committed.leaves[actual_ordinal], lists).hex(),
           "ruling": d.ruling}
    if forged and claim_name == "EDGE":
        bad = bytearray(body)
        at = 2
        spec_len = struct.unpack_from("<H", bad, at + 1)[0]
        at += 3 + spec_len
        at += 1 + 32 * bad[at]
        at += 1 + 4  # element index and ListSpec spec-tree index
        list_len = struct.unpack_from("<H", bad, at + 1)[0]
        path_at = at + 3 + list_len
        path_len = bad[path_at]
        bad[path_at + 1 + 32 * (path_len - 1)] ^= 1
        row["forged_claim_body"] = bytes(bad).hex()
    return row


def wide_plan(n: int):
    b = P.PlanBuilder()
    external = b.raw_input(0, 8)
    source = P.Step(TESTS.SHA, (P.Input(external, 8),), ((0, 32, False),))
    wide = b.list_input(0, tuple(P.Input(S.producer(1, 0, 0), 32) for _ in range(n)))
    consumer = P.Step(TESTS.SHA, (wide,), ((0, 32, False),))
    b.enumerated([source, consumer])
    b.output(S.producer(1, 1, 0), 32)
    return b.build(), {0: struct.pack("<Q", 0x12345678)}


def max_width_plan():
    """Eight 128-element list inputs: the explicit 1,024-element step cap."""
    b = P.PlanBuilder()
    external = b.raw_input(0, 8)
    lists = tuple(b.list_input(i, tuple(P.Input(external, 8) for _ in range(S.MAX_LIST_ELEMENTS)))
                  for i in range(8))
    b.enumerated([P.Step(TESTS.SHA, lists, ((0, 32, False),))])
    b.output(S.producer(1, 0, 0), 32)
    return b.build(), {0: struct.pack("<Q", 0x12345678)}


def wrong_count(commitment):
    bad = commitment.clone()
    refs = bad.lists[(6, 0)][:-1]
    leaf = R.parse_leaf(bad.leaves[6])
    ins = list(leaf.inputs)
    ins[0] = ins[0][:23] + R.list_digest(refs)
    bad.leaves[6] = R.leaf_preimage(leaf.plan_id, leaf.run_id, leaf.region, leaf.segment, leaf.ordinal, leaf.node,
                                    leaf.kernel_step, ins, list(leaf.outputs), leaf.prior, leaf.next)
    bad.lists[(6, 0)] = refs
    bad.rebuild()
    return bad


def foreign_header(commitment):
    bad = commitment.clone()
    refs = list(bad.lists[(6, 0)])
    refs[7] = struct.pack("<I", 99) + refs[7][4:]
    leaf = R.parse_leaf(bad.leaves[6])
    ins = list(leaf.inputs)
    ins[0] = ins[0][:23] + R.list_digest(refs)
    bad.leaves[6] = R.leaf_preimage(leaf.plan_id, leaf.run_id, leaf.region, leaf.segment, leaf.ordinal, leaf.node,
                                    leaf.kernel_step, ins, list(leaf.outputs), leaf.prior, leaf.next)
    bad.lists[(6, 0)] = refs
    bad.rebuild()
    return bad


def build():
    setups, commits, scenarios = {}, {}, []
    sp, values = TESTS.mixed_plan()
    setup, refs, run_id = setup_for("mixed", sp, values)
    setups["mixed"] = setup
    honest = commit_for(sp, setup, run_id, values)
    commits["mixed-honest"] = {"leaves": [x.hex() if x else None for x in honest.leaves],
                               "out_entries": [x.hex() if x else None for x in honest.out_entries]}
    honest_scenarios = [
        claim_scenario(setup, refs, sp, run_id, honest, honest, "mixed-edge-kind1", ordinal=6,
                       claim_name="EDGE", element=0, forged=True),
        claim_scenario(setup, refs, sp, run_id, honest, honest, "mixed-edge-kind2", ordinal=6,
                       claim_name="EDGE", element=6),
        claim_scenario(setup, refs, sp, run_id, honest, honest, "mixed-edge-kind3", ordinal=6,
                       claim_name="EDGE", element=12),
        claim_scenario(setup, refs, sp, run_id, honest, honest, "mixed-step-honest", ordinal=6,
                       claim_name="STEP"),
    ]
    for row in honest_scenarios:
        row["commit"] = "mixed-honest"
    scenarios.extend(honest_scenarios)
    # Re-run the honest challenge to capture each of the three element lies.
    for kind, j in (("kind1", 0), ("kind2", 6), ("kind3", 12)):
        committed = commit_for(sp, setup, run_id, values,
                               list_fault=lambda o, i, e, value, target=j: (bytes([value[0] ^ 1]) + value[1:]
                                                                            if (o, i, e) == (6, 0, target) else value))
        key = f"mixed-lie-{kind}"
        commits[key] = {"leaves": [x.hex() if x else None for x in committed.leaves],
                        "out_entries": [x.hex() if x else None for x in committed.out_entries]}
        row = claim_scenario(setup, refs, sp, run_id, honest, committed, key, ordinal=6)
        row["commit"] = key
        scenarios.append(row)
    for key, committed in (("mixed-wrong-count", wrong_count(honest)),
                           ("mixed-foreign-header", foreign_header(honest))):
        commits[key] = {"leaves": [x.hex() if x else None for x in committed.leaves],
                        "out_entries": [x.hex() if x else None for x in committed.out_entries]}
        row = claim_scenario(setup, refs, sp, run_id, honest, committed, key, ordinal=6)
        row["commit"] = key
        scenarios.append(row)

    wide, wide_values = wide_plan(100)
    wide_setup, wide_refs, wide_run = setup_for("wide100", wide, wide_values)
    setups["wide100"] = wide_setup
    wide_honest = commit_for(wide, wide_setup, wide_run, wide_values)
    commits["wide100-honest"] = {"leaves": [x.hex() if x else None for x in wide_honest.leaves],
                                 "out_entries": [x.hex() if x else None for x in wide_honest.out_entries]}
    wide_edge = claim_scenario(wide_setup, wide_refs, wide, wide_run, wide_honest, wide_honest,
                               "wide100-edge99", ordinal=1, claim_name="EDGE", element=99)
    wide_edge["commit"] = "wide100-honest"
    wide_step = claim_scenario(wide_setup, wide_refs, wide, wide_run, wide_honest, wide_honest,
                               "wide100-step", ordinal=1, claim_name="STEP")
    wide_step["commit"] = "wide100-honest"
    scenarios.extend([wide_edge, wide_step])

    max_width, max_values = max_width_plan()
    max_setup, max_refs, max_run = setup_for("max-list8x128", max_width, max_values)
    setups["max-list8x128"] = max_setup
    max_honest = commit_for(max_width, max_setup, max_run, max_values)
    commits["max-list8x128-honest"] = {"leaves": [x.hex() if x else None for x in max_honest.leaves],
                                        "out_entries": [x.hex() if x else None for x in max_honest.out_entries]}
    max_step = claim_scenario(max_setup, max_refs, max_width, max_run, max_honest, max_honest,
                              "max-list8x128-step", ordinal=0, claim_name="STEP")
    max_step["commit"] = "max-list8x128-honest"
    scenarios.append(max_step)
    return {"setups": setups, "commits": commits, "scenarios": scenarios}


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(OUT, len(data["scenarios"]), {r: sum(s["ruling"] == r for s in data["scenarios"]) for r in ("C", "E")})
