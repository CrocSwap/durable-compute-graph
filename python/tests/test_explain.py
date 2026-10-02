"""explain(): composed guarantee and refusals (offline)."""

from __future__ import annotations

import unittest

from dcg import tracing
from dcg.kernels import add_i32, identity_i32
from dcg.tracing import KernelSpec, TraceError, call


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def parent_child(a, b):
    s = add_i32(a, b)
    with tracing.region("child"):
        t = identity_i32(s)
    return identity_i32(t)


def siblings(a, b):
    with tracing.region("left"):
        s = add_i32(a, b)
    with tracing.region("right"):
        t = identity_i32(s)
    return t


def grandchild(a, b):
    with tracing.region("child"):
        with tracing.region("grand"):
            s = add_i32(a, b)
        t = identity_i32(s)
    return identity_i32(t)


def skip_level(a, b):
    with tracing.region("child"):
        with tracing.region("grand"):
            s = add_i32(a, b)
    return identity_i32(s)


def _bind(kernel):
    def uses(a, b):
        return call(kernel, a, b)

    return uses


class ExplainTests(unittest.TestCase):
    def test_hello_names_modes_imports_and_kernels(self):
        text = tracing.trace(hello).explain("optimistic", commitment="root")
        self.assertIn("region child [optimistic, parent root]: steps [0]", text)
        self.assertIn("imports: child step0 -> root step1 (child)", text)
        self.assertIn("add_i32/v1 abi 1 code 1", text)
        self.assertIn("root -> region -> step descent", text)
        self.assertIn("composition: every region resolves in optimistic mode", text)

    def test_relations(self):
        self.assertEqual([f[-1] for f in tracing.trace(parent_child).imports()], ["parent", "child"])
        self.assertEqual([f[-1] for f in tracing.trace(grandchild).imports()], ["child", "child"])
        self.assertEqual([f[-1] for f in tracing.trace(siblings).imports()], ["other"])
        self.assertEqual([f[-1] for f in tracing.trace(skip_level).imports()], ["other"])

    def test_adjacent_imports_are_stated_under_a_root_commitment(self):
        for fn in (hello, parent_child, grandchild):
            self.assertIn("descent", tracing.trace(fn).explain("optimistic", commitment="root"))

    def test_non_adjacent_imports_are_refused_under_a_root_commitment(self):
        for fn in (siblings, skip_level):
            g = tracing.trace(fn)
            with self.assertRaises(TraceError) as ctx:
                g.explain("optimistic", commitment="root")
            self.assertEqual(ctx.exception.code, "IMPORT_UNAUTHENTICATED")
            # The trace commitment replays against posted outputs and still holds.
            self.assertIn("direct replay", g.explain("optimistic"))

    def test_unsupported_modes_and_commitments_are_refused(self):
        g = tracing.trace(hello)
        cases = [(("zk",), {}, "MODE"), (("sampling",), {}, "MODE"), (("optimistic",), {"commitment": "x"}, "COMMITMENT"),
                 (("consensus",), {"commitment": "root"}, "COMMITMENT"),
                 (("sampling",), {"samples": 2, "commitment": "root"}, "COMMITMENT")]
        for args, kw, code in cases:
            with self.assertRaises(TraceError) as ctx:
                g.explain(*args, **kw)
            self.assertEqual(ctx.exception.code, code, (args, kw))

    def test_root_commitment_needs_canonical_bytes(self):
        def reuse(a, b):
            return add_i32(a, a)

        with self.assertRaises(TraceError) as ctx:
            tracing.trace(reuse).explain("optimistic", commitment="root")
        self.assertEqual(ctx.exception.code, "COMMITMENT")
        self.assertIn("admission trusts the step table", tracing.trace(reuse).explain("optimistic"))

    def test_an_unregistered_kernel_is_refused(self):
        mul = KernelSpec(9, "mul_i32", 2)
        newer_add = KernelSpec(1, "add_i32", 2, semantic_version=2)
        for k in (mul, newer_add):
            g = tracing.trace(_bind(k))
            with self.assertRaises(TraceError) as ctx:
                g.explain("consensus")
            self.assertEqual(ctx.exception.code, "CAPABILITY")


if __name__ == "__main__":
    unittest.main()
