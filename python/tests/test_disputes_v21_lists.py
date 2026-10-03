"""List inputs (wide steps, design v2.1-wide-steps.md option B) in the
Python reference: producer kind 8 names a ListSpec of element producers, the
input's digest is H(count || list-tree root) over the element refs, E reveals
the element refs with the leaf, EDGE(i, j) checks one element against its one
producer, and STEP replays the elements as separate kernel inputs."""

from __future__ import annotations

import hashlib
import struct

import pytest

from dcg.disputes_v21 import game as G
from dcg.disputes_v21 import plans as P
from dcg.disputes_v21 import run as R
from dcg.disputes_v21 import spec as S

PLAN_ID = bytes([8]) * 32
SHA = b"dcg-test-sha-v1\x00"


def mixed_plan():
    """Six SHA steps over externals 0..5, then one SHA step over a 13-element
    list: the six step outputs (kind 1), externals 6..11 (kind 2) and a plain
    constant (kind 3), with external 0 as a second, plain input."""
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
    values = {i: hashlib.sha256(b"in" + bytes([i])).digest()[:16] for i in range(12)}
    return b.build(), values


def wide_plan(n: int):
    """One SHA step over a list of `n` external inputs (8 bytes each)."""
    b = P.PlanBuilder()
    ext = [b.raw_input(i, 8) for i in range(n)]
    wide = b.list_input(0, tuple(P.Input(e, 8) for e in ext))
    b.enumerated([P.Step(SHA, (wide,), ((0, 32, False),))])
    b.output(S.producer(1, 0, 0), 32)
    return b.build(), {i: struct.pack("<Q", i * 7919) for i in range(n)}


def record_for(sp, values, committed):
    refs = {e: R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()}
    return G.RunRecord(PLAN_ID, committed.run_id, sp, committed.root_bytes, refs)


def run(sp, values, **faults):
    run_id = hashlib.sha256(b"list-run").digest()
    honest = R.execute(sp, PLAN_ID, run_id, values)
    committed = R.execute(sp, PLAN_ID, run_id, values, **faults) if faults else honest
    return honest, committed


def descend_to(record, executor, k, depth=4):
    """A dispute descended to leaf k with E's reveal (for claims at a chosen leaf)."""
    d = G.Dispute(record, "STEP_DESCEND", depth)
    target = record.spec.position_of(k)
    while d.level > 0:
        d.reveal_nodes(executor.nodes(d))
        step = min(d.depth, d.level)
        d.pick((target >> (d.level - step)) & ((1 << step) - 1))
    d.reveal_leaf(executor.leaf(d), executor.lists(d))
    return d


def edge_args(sp, executor, j):
    _lid, elements = S.decode_list_spec(sp.list_specs[0])
    ek, ea, *_ = S.decode_producer(elements[j][1])
    extra = {"element": j, "list_opening": sp.opening(sp.list_leaf_index(0))}
    if ek == 1:
        extra["producer_opening"] = executor.leaf_opening(ea)
    elif ek == 3:
        extra["const_opening"] = sp.opening(sp.const_leaf_index(ea))
    return extra


def test_a_spec_without_lists_is_unchanged_and_lists_come_last():
    sp, _ = mixed_plan()
    assert sp.records[-1][0] == S.TYPE_LIST and sp.list_leaf_index(0) == len(sp.records) - 1
    d = S.decode_step_spec(sp.step_spec(6))
    assert struct.unpack_from("<I", d["inputs"][0][0], 7)[0] == S.LAYOUT_LIST
    assert struct.unpack_from("<I", d["inputs"][0][0], 19)[0] == 6 * 32 + 6 * 16 + 32
    b = P.PlanBuilder()
    b.raw_input(0, 4)
    b.enumerated([P.Step(SHA, (P.Input(S.producer(2, 0), 4),), ((0, 32, False),))])
    b.output(S.producer(1, 0, 0), 32)
    plain = b.build()
    assert all(t != S.TYPE_LIST for t, _r in plain.records) and plain.first_list_record == len(plain.records)


def test_honest_run_every_list_claim_rules_for_e():
    sp, values = mixed_plan()
    honest, committed = run(sp, values)
    record = record_for(sp, values, committed)
    ex = G.Executor(committed)
    assert G.honest_challenge(record, ex, honest) is None
    opening = sp.opening(sp.step_leaf_index(6))
    for j in range(13):
        d = descend_to(record, ex, 6)
        assert d.claim("EDGE", spec_opening=opening, index=0, **edge_args(sp, ex, j)) == "E", j
    d = descend_to(record, ex, 6)
    witness = [G.honest_value(honest, sp, p) for _h, p, _i in S.decode_step_spec(sp.step_spec(6))["inputs"]]
    assert d.claim("STEP", spec_opening=opening, witness=witness) == "E"
    d = descend_to(record, ex, 6)
    assert d.claim("SHAPE", spec_opening=opening) == "E"


@pytest.mark.parametrize("j", [0, 5, 6, 11, 12])  # kind 1, kind 1, kind 2, kind 2, kind 3
def test_a_lie_in_one_element_is_convicted_at_that_element(j):
    sp, values = mixed_plan()
    honest, committed = run(sp, values, list_fault=lambda o, i, e, v: bytes([v[0] ^ 1]) + v[1:]
                            if (o, i, e) == (6, 0, j) else v)
    record = record_for(sp, values, committed)
    d = G.honest_challenge(record, G.Executor(committed), honest)
    assert d.ruling == "C" and d.claimed == "EDGE8"
    # The claim named exactly the lying element; its neighbours rule for E.
    ex = G.Executor(committed)
    opening = sp.opening(sp.step_leaf_index(6))
    for other in (j - 1, j + 1):
        if 0 <= other < 13:
            d2 = descend_to(record, ex, 6)
            assert d2.claim("EDGE", spec_opening=opening, index=0, **edge_args(sp, ex, other)) == "E"


def test_a_wrong_output_over_honest_elements_is_convicted_by_step():
    sp, values = mixed_plan()
    honest, committed = run(sp, values, fault=lambda o, outs, nxt: ([bytes([outs[0][0] ^ 1]) + outs[0][1:]], nxt)
                            if o == 6 else (outs, nxt))
    record = record_for(sp, values, committed)
    d = G.honest_challenge(record, G.Executor(committed), honest)
    assert d.ruling == "C" and d.claimed == "STEP"


def test_a_list_with_the_wrong_element_count_is_convicted():
    sp, values = mixed_plan()
    honest, committed = run(sp, values)
    bad = committed.clone()
    refs = bad.lists[(6, 0)][:-1]  # drop the last element, consistently
    leaf = R.parse_leaf(bad.leaves[6])
    ins = list(leaf.inputs)
    ins[0] = ins[0][:23] + R.list_digest(refs)
    bad.leaves[6] = R.leaf_preimage(leaf.plan_id, leaf.run_id, leaf.region, leaf.segment, leaf.ordinal, leaf.node,
                                    leaf.kernel_step, ins, list(leaf.outputs), leaf.prior, leaf.next)
    bad.lists[(6, 0)] = refs
    bad.rebuild()
    record = record_for(sp, values, bad)
    d = G.honest_challenge(record, G.Executor(bad), honest)
    assert d.ruling == "C" and d.claimed == "EDGE8"


def test_reveals_that_do_not_match_the_list_digest_are_refused():
    sp, values = mixed_plan()
    honest, committed = run(sp, values)
    record = record_for(sp, values, committed)
    ex = G.Executor(committed)

    def at_leaf():
        d = G.Dispute(record, "STEP_DESCEND", 4)
        target = sp.position_of(6)
        while d.level > 0:
            d.reveal_nodes(ex.nodes(d))
            step = min(d.depth, d.level)
            d.pick((target >> (d.level - step)) & ((1 << step) - 1))
        return d

    good = ex.lists(at_leaf())
    for lists in ({}, {0: good[0][:-1]}, {0: [good[0][1]] + good[0][1:]}, {0: good[0], 1: good[0]}):
        with pytest.raises(G.ExecutorRefused):
            at_leaf().reveal_leaf(ex.leaf(at_leaf()), lists)
    at_leaf().reveal_leaf(ex.leaf(at_leaf()), good)


def test_forged_list_openings_and_witnesses_are_refused():
    sp, values = mixed_plan()
    honest, committed = run(sp, values)
    record = record_for(sp, values, committed)
    ex = G.Executor(committed)
    opening = sp.opening(sp.step_leaf_index(6))
    args = edge_args(sp, ex, 3)
    with pytest.raises(G.Refused):  # the ConstSpec record offered as the ListSpec
        descend_to(record, ex, 6).claim("EDGE", spec_opening=opening, index=0,
                                         **dict(args, list_opening=sp.opening(sp.const_leaf_index(0))))
    with pytest.raises(G.Refused):
        descend_to(record, ex, 6).claim("EDGE", spec_opening=opening, index=0, **dict(args, element=13))
    witness = [G.honest_value(honest, sp, p) for _h, p, _i in S.decode_step_spec(sp.step_spec(6))["inputs"]]
    with pytest.raises(G.Refused):  # one element value changed
        descend_to(record, ex, 6).claim("STEP", spec_opening=opening,
                                         witness=[witness[0][:4] + [b"x" * 16] + witness[0][5:], witness[1]])
    with pytest.raises(G.Refused):  # the list flattened into one value
        descend_to(record, ex, 6).claim("STEP", spec_opening=opening, witness=[b"".join(witness[0]), witness[1]])


@pytest.mark.parametrize("n", [9, 100, 128])
def test_wide_lists_beyond_the_eight_input_limit(n):
    sp, values = wide_plan(n)
    honest, committed = run(sp, values)
    assert G.honest_challenge(record_for(sp, values, committed), G.Executor(committed), honest) is None
    j = n * 3 // 4
    honest, committed = run(sp, values, list_fault=lambda o, i, e, v: v[::-1] if e == j else v)
    d = G.honest_challenge(record_for(sp, values, committed), G.Executor(committed), honest)
    assert d.ruling == "C" and d.claimed == "EDGE8"


def test_admission_refuses_malformed_lists():
    with pytest.raises(S.SpecError):
        P.PlanBuilder().list_input(0, ())
    b = P.PlanBuilder()
    b.raw_input(0, 8)
    with pytest.raises(S.SpecError):
        b.list_input(0, tuple(P.Input(S.producer(2, 0), 8) for _ in range(129)))
    b = P.PlanBuilder()  # an element producer that is not earlier
    b.raw_input(0, 8)
    wide = b.list_input(0, (P.Input(S.producer(1, 0, 0), 32),))
    b.enumerated([P.Step(SHA, (wide,), ((0, 32, False),))])
    with pytest.raises(S.SpecError):
        b.build()
    b = P.PlanBuilder()  # a list element of kind 5 (chunk reads stay plain inputs)
    b.chunked_input(0, 128, 6)
    wide = b.list_input(0, (P.Input(S.producer(5, 0, 2, 1, 0), 64),))
    b.enumerated([P.Step(SHA, (wide,), ((0, 32, False),))])
    with pytest.raises(S.SpecError):
        b.build()


def test_an_element_ref_with_a_foreign_header_is_convicted():
    """The element's header must be the ListSpec's (node, direction and port
    included), not only its layout fields and digest."""
    sp, values = mixed_plan()
    honest, committed = run(sp, values)
    bad = committed.clone()
    refs = list(bad.lists[(6, 0)])
    refs[7] = struct.pack("<I", 99) + refs[7][4:]  # node 99, same layout, length and digest
    leaf = R.parse_leaf(bad.leaves[6])
    ins = list(leaf.inputs)
    ins[0] = ins[0][:23] + R.list_digest(refs)
    bad.leaves[6] = R.leaf_preimage(leaf.plan_id, leaf.run_id, leaf.region, leaf.segment, leaf.ordinal, leaf.node,
                                    leaf.kernel_step, ins, list(leaf.outputs), leaf.prior, leaf.next)
    bad.lists[(6, 0)] = refs
    bad.rebuild()
    record = record_for(sp, values, bad)
    ex = G.Executor(bad)
    d = descend_to(record, ex, 6)
    assert d.claim("EDGE", spec_opening=sp.opening(sp.step_leaf_index(6)), index=0, **edge_args(sp, ex, 7)) == "C"
    assert G.honest_challenge(record, ex, honest).ruling == "C"
