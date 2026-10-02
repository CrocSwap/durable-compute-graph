"""Optimistic disputes v2.1, step-1 reference: soundness and completeness (offline)."""

from __future__ import annotations

import random
import struct
import unittest

from dcg import tracing
from dcg.disputes_v21 import game as G
from dcg.disputes_v21 import run as R
from dcg.disputes_v21 import spec as S
from dcg.disputes_v21 import trees
from dcg.kernels import add_i32, identity_i32

PLAN_ID = bytes([7]) * 32
TEMPLATE = bytes([8]) * 32
EXECUTOR = bytes([9]) * 32


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def setup(graph, inputs):
    sp = S.derive(graph.graph_bytes(), graph.plan_bytes())
    values = {eid: struct.pack("<i", v) for eid, v in enumerate(inputs)}
    refs = {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.value_digest(values[eid])) for eid in values}
    run = R.run_id(TEMPLATE, bytes(32), list(refs.values()), EXECUTOR)
    honest = R.execute(sp, PLAN_ID, run, values)
    return sp, refs, run, honest


def record_for(sp, refs, run, commitment):
    return G.RunRecord(PLAN_ID, run, sp, commitment.root_bytes, refs)


def play(sp, refs, run, honest, committed, depth=4):
    """The honest challenger against `committed`; an E submission that fails
    verification is E's silence (C wins by timeout)."""
    record = record_for(sp, refs, run, committed)
    try:
        dispute = G.honest_challenge(record, G.Executor(committed), honest, depth)
    except G.Refused:
        return "C", None
    return (dispute.ruling, dispute) if dispute else (None, None)


def random_graph(rng: random.Random):
    n_in = rng.randint(1, 4)
    names = [f"x{i}" for i in range(n_in)]
    regions = {"root": None, "r1": "root", "r2": "r1", "r3": "root", "r4": "r3"}
    unused_inputs = list(names)
    values, consumed, lines = [], set(), []
    n_steps = rng.randint(1, 12)
    for s in range(n_steps):
        must = len(unused_inputs) >= (n_steps - s) * 2 - 1 and unused_inputs
        pool = [v for v in values]
        def take():
            if unused_inputs and (must or not pool or rng.random() < 0.4):
                return unused_inputs.pop(rng.randrange(len(unused_inputs)))
            v = rng.choice(pool)
            consumed.add(v)
            return v
        if rng.random() < 0.6 and (len(unused_inputs) + len(pool)) >= 2:
            a = take()
            b = take()
            call = f"add_i32({a}, {b})" if a != b else f"identity_i32({a})"
        else:
            call = f"identity_i32({take()})"
        region = rng.choice(list(regions))
        path = []
        r = region
        while r != "root":
            path.append(r)
            r = regions[r]
        indent = "    "
        body = ""
        for depth, name in enumerate(reversed(path)):
            body += indent * (depth + 1) + f'with tracing.region("{name}"):\n'
        body += indent * (len(path) + 1) + f"s{s} = {call}\n"
        lines.append(body)
        values.append(f"s{s}")
    # Every external input must be used exactly once.
    while unused_inputs:
        s = len(values)
        lines.append(f"    s{s} = identity_i32({unused_inputs.pop()})\n")
        values.append(f"s{s}")
    outs = [v for v in values if v not in consumed] or [values[-1]]
    src = f"def g({', '.join(names)}):\n" + "".join(lines) + f"    return {', '.join(outs)}\n"
    scope = {"tracing": tracing, "add_i32": add_i32, "identity_i32": identity_i32}
    exec(src, scope)
    graph = tracing.trace(scope["g"])
    if graph.canonical() is None:
        return None, None
    return graph, [rng.randint(-1000, 1000) for _ in range(n_in)]


LIES = ("output_digest", "input_digest", "input_header", "shape_node", "malformed", "empty", "state",
        "out_entry", "internal_node", "two_lies")


def lie(rng, honest: R.Commitment, kind: str) -> R.Commitment:
    c = honest.clone()
    n = len(c.leaves)
    k = rng.randrange(n)
    leaf = R.parse_leaf(c.leaves[k])
    if kind == "output_digest":
        o = leaf.outputs[0]
        new = o[:23] + bytes(32)
        c.leaves[k] = c.leaves[k].replace(o, new)
    elif kind == "input_digest":
        i = leaf.inputs[rng.randrange(len(leaf.inputs))]
        c.leaves[k] = c.leaves[k].replace(i, i[:23] + bytes([1]) * 32)
    elif kind == "input_header":
        i = leaf.inputs[0]
        c.leaves[k] = c.leaves[k].replace(i, i[:17] + struct.pack("<I", 99) + i[21:])
    elif kind == "shape_node":
        raw = bytearray(c.leaves[k])
        raw[64 + 20:64 + 24] = struct.pack("<I", 4242)
        c.leaves[k] = bytes(raw)
    elif kind == "malformed":
        c.leaves[k] = c.leaves[k][:-5]
    elif kind == "empty":
        c.leaves[k] = None
    elif kind == "state":
        c.leaves[k] = c.leaves[k][:-32] + bytes([3]) * 32
    elif kind == "out_entry":
        j = rng.randrange(len(c.out_entries))
        c.out_entries[j] = c.out_entries[j][:23] + bytes([5]) * 32
    elif kind == "internal_node":
        h = c.step_tree.height
        if h == 0:
            c.leaves[k] = None
        else:
            level = rng.randint(1, h)
            pos = rng.randrange(len(c.step_tree.levels[level]))
            if not c.spec.pickable(level, pos):
                pos = 0
            c.node_overrides[(level, pos)] = bytes([6]) * 32
    elif kind == "two_lies":
        c.leaves[k] = None
        c.leaves[rng.randrange(n)] = None
    c.rebuild()
    return c


class DisputesV21Tests(unittest.TestCase):
    def test_tree_shape_and_empty_constants(self):
        self.assertEqual(trees.build("step", []).root, trees.EMPTY_LEAF)
        one = R.leaf_hash(b"x")
        self.assertEqual(trees.build("step", [one]).root, one)
        three = trees.build("step", [one, one, one])
        self.assertEqual(three.height, 2)
        self.assertEqual(three.levels[1][1], trees.node("step", 0, one, trees.EMPTY_LEAF))
        self.assertEqual(trees.empty("step", 2), trees.node("step", 1, trees.empty("step", 1), trees.empty("step", 1)))
        for n in (1, 2, 3, 5, 6, 7, 8, 9, 15, 17):
            t = trees.build("out", [bytes([i]) * 32 for i in range(n)])
            for p in range(n):
                self.assertEqual(trees.root_from_path("out", bytes([p]) * 32, p, t.path(p)), t.root)

    def test_record_lengths(self):
        sp, *_ = setup(tracing.trace(hello), [20, 22])
        lengths = {t: len(r) for t, r in sp.records if t != S.TYPE_STEP}
        self.assertEqual(lengths, {S.TYPE_HEADER: 48, S.TYPE_BLOCK: 104, S.TYPE_IN: 40, S.TYPE_OUT: 56,
                                   S.TYPE_REGION: 32})
        self.assertTrue(all(len(r) <= 960 for r in sp.step_specs))

    def test_hello_honest_has_nothing_to_dispute_and_lies_lose(self):
        sp, refs, run, honest = setup(tracing.trace(hello), [20, 22])
        self.assertEqual(play(sp, refs, run, honest, honest), (None, None))
        rng = random.Random(1)
        for kind in LIES:
            ruling, _ = play(sp, refs, run, honest, lie(rng, honest, kind))
            self.assertEqual(ruling, "C", kind)

    def test_first_divergence_lands_on_the_earliest_lie(self):
        sp, refs, run, honest = setup(tracing.trace(hello), [20, 22])
        c = honest.clone()
        c.leaves[1] = c.leaves[1][:-5]  # malformed at 1
        c.leaves[0] = None  # empty at 0
        c.rebuild()
        ruling, dispute = play(sp, refs, run, honest, c, depth=1)
        self.assertEqual((ruling, dispute.position), ("C", 0))

    def test_every_claim_against_an_honest_leaf_rules_for_the_executor(self):
        rng = random.Random(7)
        checked = 0
        while checked < 40:
            graph, inputs = random_graph(rng)
            if graph is None:
                continue
            sp, refs, run, honest = setup(graph, inputs)
            record = record_for(sp, refs, run, honest)
            ex = G.Executor(honest)
            for k in range(sp.total_steps):
                for claim in ("SHAPE", "EDGE", "STEP"):
                    for i in range(len(R.parse_leaf(honest.leaves[k]).inputs)) if claim == "EDGE" else [0]:
                        d = G.Dispute(record, "STEP_DESCEND", depth=rng.randint(1, 4))
                        while d.level > 0:
                            d.reveal_nodes(ex.nodes(d))
                            d.pick(sorted(d.revealed)[min(k >> (d.level - min(d.depth, d.level)) & ((1 << min(d.depth, d.level)) - 1), len(d.revealed) - 1)])
                        d.reveal_leaf(ex.leaf(d))
                        kk = d.position
                        dec = S.decode_step_spec(sp.step_specs[kk])
                        kind_p, a, *_ = S.decode_producer(dec["inputs"][i][1]) if dec["inputs"] else (0, 0)
                        try:
                            ruling = d.claim(claim, spec_opening=sp.opening(sp.step_leaf_index(kk)), index=i,
                                             producer_opening=ex.leaf_opening(a) if kind_p == 1 else None,
                                             witness=[G._value_for(honest, sp, kk, x)
                                                      for x in range(len(dec["inputs"]))])
                        except G.Refused:
                            continue
                        self.assertEqual(ruling, "E", (claim, kk, i))
            checked += 1

    def test_random_lies_are_always_refuted(self):
        rng = random.Random(2026_10_02)
        trials = wins = 0
        while trials < 400:
            graph, inputs = random_graph(rng)
            if graph is None:
                continue
            sp, refs, run, honest = setup(graph, inputs)
            kind = rng.choice(LIES)
            committed = lie(rng, honest, kind)
            if committed.root == honest.root:
                continue
            ruling, _ = play(sp, refs, run, honest, committed, depth=rng.randint(1, 5))
            trials += 1
            wins += ruling == "C"
            self.assertEqual(ruling, "C", (kind, graph.trace.name))
        self.assertEqual(wins, trials)

    def test_a_reveal_that_does_not_fold_is_refused_and_a_padding_pick_is_refused(self):
        sp, refs, run, honest = setup(tracing.trace(hello), [20, 22])
        d = G.Dispute(record_for(sp, refs, run, honest), "STEP_DESCEND", depth=1)
        good = G.Executor(honest).nodes(d)
        with self.assertRaises(G.Refused):
            d.reveal_nodes({i: bytes(32) for i in good})
        d.reveal_nodes(good)
        with self.assertRaises(G.Refused):
            d.pick(5)


if __name__ == "__main__":
    unittest.main()


class GoldenTests(unittest.TestCase):
    def test_goldens_reproduce(self):
        import importlib.util
        import json
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        spec_ = importlib.util.spec_from_file_location("g", root / "scripts/disputes_v21_goldens.py")
        mod = importlib.util.module_from_spec(spec_)
        spec_.loader.exec_module(mod)
        stored = json.loads((root / "tests/golden/dcg/disputes_v21/vectors.json").read_text())
        self.assertEqual(mod.build(), stored)
