"""The v2.1 tracing frontend (alpha E1) builds byte-identical plans to the
hand-built ones the goldens, the Python referee and the program already use,
and refuses what it cannot trace."""

from __future__ import annotations

import struct

import pytest

from dcg import v21
from dcg.disputes_v21 import plans as P
from dcg.disputes_v21 import spec as S
from dcg.disputes_v21 import wire as W
from dcg.tracing import TraceError

SHA = b"dcg-test-sha-v1\x00"
PLAN_ID = bytes([7]) * 32


def same(traced: v21.Traced, hand: S.Spec) -> None:
    sp = traced.plan()
    assert sp.total_steps == hand.total_steps
    assert [sp.step_spec(k) for k in range(sp.total_steps)] == [hand.step_spec(k) for k in range(hand.total_steps)]
    assert W.template_data(sp, 3, PLAN_ID) == W.template_data(hand, 3, PLAN_ID)
    assert sp.in_specs == hand.in_specs


def test_chunked_reduce_matches_the_hand_built_example():
    b = P.PlanBuilder()
    b.chunked_input(0, 4 * 64, 6)
    blk = b.chunked_reduce("sumchunk_i32", 0)
    b.enumerated([P.Step("head_i32", (P.Input(S.producer(6, blk, 0, 0), 8),), ((0, 4, True),))])
    b.output(S.producer(6, blk, 0, 0), 8)

    @v21.trace
    def total(data: v21.Chunked(bytes=256, chunk=64)):
        acc = v21.reduce("sumchunk_i32", data)
        v21.call("head_i32", acc)
        return acc

    same(total, b.build())
    text = total.explain()
    assert "repeated 4 times" in text and "chunked, 256 bytes, chunks of 64 bytes" in text


def test_lists_constants_and_app_kernels_match_the_mixed_plan():
    b = P.PlanBuilder()
    ext = [b.raw_input(i, 16) for i in range(12)]
    b.committed_constant(0, bytes(range(32)))
    steps = [P.Step(SHA, (P.Input(ext[i], 16),), ((0, 32, False),)) for i in range(6)]
    elements = tuple([P.Input(S.producer(1, i, 0), 32) for i in range(6)]
                     + [P.Input(ext[i], 16) for i in range(6, 12)] + [P.Input(S.producer(3, 0), 32)])
    wide = b.list_input(0, elements)
    steps.append(P.Step(SHA, (wide, P.Input(ext[0], 16)), ((0, 32, False),)))
    b.enumerated(steps)
    b.output(S.producer(1, 6, 0), 32)

    @v21.trace(inputs=[v21.Raw(16)] * 12)
    def mixed(*x):
        table = v21.constant(bytes(range(32)))
        hashes = [v21.call(SHA, x[i], out=[(32, False)]) for i in range(6)]
        wide = v21.list(hashes + [*x[6:12]] + [table])
        return v21.call(SHA, wide, x[0], out=[(32, False)])

    same(mixed, b.build())
    assert "dcg-test-sha-v1" in mixed.explain()


def test_scalar_builtins_and_a_reduce_over_a_constant():
    @v21.trace
    def f(a: v21.Scalar, b: v21.Scalar):
        table = v21.constant(struct.pack("<32i", *range(32)), chunk=64)
        s = v21.reduce("sumchunk_i32", table)
        head = v21.call("head_i32", s)
        return v21.call("add_i32", v21.call("add_i32", a, b), head)

    sp = f.plan()
    assert sp.total_steps == 5  # 2 chunk iterations, then head_i32 and two add_i32
    done = f.execute([7, -3])
    assert struct.unpack("<i", done.values[(4, 0)])[0] == 7 - 3 + sum(range(32))
    tdata = f.template(challenge_window=1_500)
    assert len(f.template_id(challenge_window=1_500)) == 32 and tdata


def test_trace_refusals():
    with pytest.raises(TraceError, match="DATA_DEPENDENT_CONTROL"):
        @v21.trace
        def g(a: v21.Scalar):
            if a:
                return a
            return a
        g.plan()
    with pytest.raises(TraceError, match="UNREGISTERED_OP"):
        @v21.trace
        def h(a: v21.Scalar):
            return a + a
        h.plan()
    with pytest.raises(TraceError, match="SHAPE"):
        @v21.trace
        def k(a: v21.Raw(16)):
            return v21.call(SHA, a)
        k.plan()
    with pytest.raises(TraceError, match="TYPE"):
        @v21.trace
        def r(a: v21.Raw(64)):
            return v21.reduce("sumchunk_i32", a)
        r.plan()
