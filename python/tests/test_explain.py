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
        text = tracing.trace(hello).explain("optimistic")
        self.assertIn("region child [optimistic, parent root]: steps [0]", text)
        self.assertIn("imports: child step0 -> root step1 (child)", text)
        self.assertIn("add_i32/v1 abi 1 code 1", text)
        self.assertIn("direct replay of one step", text)
        self.assertIn("composition: every region resolves in optimistic mode", text)
        self.assertIn("not a production guarantee", text)

    def test_root_commitment_and_sampling_are_refused_pending_the_redesign(self):
        g = tracing.trace(hello)
        for args, kw in ((("optimistic",), {"commitment": "root"}), (("sampling",), {"samples": 2})):
            with self.assertRaises(TraceError) as ctx:
                g.explain(*args, **kw)
            self.assertEqual(ctx.exception.code, "UNSOUND")

    def test_relations(self):
        self.assertEqual([f[-1] for f in tracing.trace(parent_child).imports()], ["parent", "child"])
        self.assertEqual([f[-1] for f in tracing.trace(grandchild).imports()], ["child", "child"])
        self.assertEqual([f[-1] for f in tracing.trace(siblings).imports()], ["other"])
        self.assertEqual([f[-1] for f in tracing.trace(skip_level).imports()], ["other"])

    def test_non_adjacent_imports_still_explain_under_a_trace_commitment(self):
        for fn in (siblings, skip_level):
            self.assertIn("direct replay", tracing.trace(fn).explain("optimistic"))

    def test_unsupported_modes_and_commitments_are_refused(self):
        g = tracing.trace(hello)
        cases = [(("zk",), {}, "MODE"), (("sampling",), {}, "MODE"), (("optimistic",), {"commitment": "x"}, "COMMITMENT"),
                 (("consensus",), {"commitment": "root"}, "COMMITMENT"),
                 (("sampling",), {"samples": 2, "commitment": "root"}, "COMMITMENT")]
        # Order of checks: mode and commitment shape first, soundness after.
        for args, kw, code in cases:
            with self.assertRaises(TraceError) as ctx:
                g.explain(*args, **kw)
            self.assertEqual(ctx.exception.code, code, (args, kw))

    def test_fast_path_bytes_are_reported_as_trusted(self):
        def reuse(a, b):
            return add_i32(a, a)

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
