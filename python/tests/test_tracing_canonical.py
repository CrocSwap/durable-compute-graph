"""Canonical v2.0 lowering of traced graphs (offline)."""

from __future__ import annotations

import unittest

from dcg import tracing
from dcg.graph import v2 as wire
from dcg.kernels import add_i32, identity_i32


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def parent_child(a, b):
    s = add_i32(a, b)
    with tracing.region("child"):
        t = identity_i32(s)
    return identity_i32(t)


class CanonicalLoweringTests(unittest.TestCase):
    def test_generic_lowering_reproduces_the_golden_hello_graph(self):
        graph_bytes, _plan = tracing.trace(hello).canonical()
        self.assertEqual(graph_bytes, tracing._golden("minimal_two_level_add_identity", "graphs_v1.tsv"))

    def test_parent_child_flow_is_canonical_with_split_segments(self):
        g = tracing.trace(parent_child)
        self.assertTrue(g.graph_bytes().startswith(b"DCGG") and g.plan_bytes().startswith(b"DCPL"))
        graph = wire.decode_graph(g.graph_bytes())
        plan = wire.decode_plan(g.plan_bytes())
        self.assertEqual(plan.graph_id, wire.graph_id(g.graph_bytes()))
        self.assertEqual([(s.region_id, s.segment_id) for s in plan.steps], [(0, 0), (1, 0), (0, 1)])
        self.assertEqual(len(plan.boundaries), 2)
        self.assertEqual([r.parent_region_id for r in graph.regions], [wire.ROOT_PARENT, 0])

    def test_inexpressible_shapes_fall_back_to_the_fast_encoding(self):
        def reuse(a, b):
            return add_i32(a, a)

        def dead_step(a, b):
            add_i32(a, b)
            return identity_i32(b)

        for fn in (reuse, dead_step):
            g = tracing.trace(fn)
            self.assertIsNone(g.canonical())
            self.assertTrue(g.graph_bytes().startswith(b"DCGGF1"))

    def test_a_region_entered_under_two_parents_is_refused(self):
        def two_parents(a, b):
            with tracing.region("x"):
                s = add_i32(a, b)
            with tracing.region("y"):
                with tracing.region("x"):
                    t = identity_i32(s)
            return t

        with self.assertRaises(tracing.TraceError):
            tracing.trace(two_parents)


if __name__ == "__main__":
    unittest.main()
