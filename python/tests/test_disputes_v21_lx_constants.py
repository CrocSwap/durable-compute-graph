"""LX1 constants in openings (design §13) on the toy machine with weights."""

from __future__ import annotations

import dataclasses

import pytest

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21 import trees
from dcg.disputes_v21.lx_toy import ToyMachine, dec, enc

M = ToyMachine(positions_count=9, window=3, weights=True)


class OtherWeights(ToyMachine):
    """An executor that runs with weights other than the template's."""

    WEIGHTS0 = (5, -3, 11, 2, 8, 0, -9, 4)  # chunk 2 read at p = 2, 6


def coord_of(label: str) -> int:
    s = L.Schedule(M)
    return next(c for c in range(s.total) if s.transition(c).label == label)


def at_start(run: L.Execution, p: int, k: int = 1) -> L.Dispute:
    """A dispute narrowed to transition `p{p}.start`, played from `run`."""
    c = L.commit(run, k)
    d = L.Dispute(M, c, 16)
    target = coord_of(f"p{p}.start")
    pair = next(j for j, x in enumerate(L.checkpoint_coordinates(L.Schedule(M), k)) if x > target) - 1
    d.open(pair)
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(run, d))
        uppers = [x for x, _ in d.midpoints] + [d.hi]
        d.pick(next(i for i, x in enumerate(uppers) if x > target))
    assert d.lo == target
    return d


def test_weights_change_the_run_and_the_root_has_an_empty_leaf():
    plain = L.execute(ToyMachine(positions_count=9, window=3))
    weighted = L.execute(M)
    assert plain.states[-1] != weighted.states[-1]
    table = M.constant_table()
    t = table.tree()
    assert t.height == 2 and t.at(0, 1) == trees.EMPTY_LEAVES["lxconst"]
    assert L.constants_root(M) == t.root and L.constants_root(ToyMachine()) == bytes(32)


def test_an_honest_replay_with_constants_rules_for_the_executor():
    run = L.execute(M)
    d = at_start(run, 5)
    proof = L.executor_opening(run, d)
    assert [e.chunk for e in proof.constants] == [M.constant_table().chunk(0, 1), M.constant_table().chunk(2, 2)]
    assert d.submit_opening(proof) == "E"


@pytest.mark.parametrize("k", [1, 4])
@pytest.mark.parametrize("arity", [2, 16])
def test_an_executor_using_other_weights_is_convicted(k, arity):
    """E commits a run computed with weights other than the template's; the
    replay opens the committed weights, so E loses at the first start that
    reads the changed chunk (chunk 2 of constant 0: positions 2 and 6)."""
    truth = L.execute(M)
    liar = L.execute(OtherWeights(positions_count=9, window=3, weights=True))
    liar.machine = M  # its openings are of the template's machine
    d = L.play(M, liar, truth, k, arity)
    assert d.ruling == "C" and d.lo == coord_of("p2.start")


def test_a_lying_challenger_loses_with_constants():
    """Both role orders: an honest executor against a challenger whose own run
    used other weights."""
    truth = L.execute(M)
    liar = L.execute(OtherWeights(positions_count=9, window=3, weights=True))
    d = L.play(M, truth, liar, 4, 16, pair=0)
    assert d.ruling == "E"


def refused(d, proof):
    with pytest.raises(L.LxRefused):
        d.submit_opening(proof)


def test_wrong_missing_extra_or_reordered_constants_are_refused():
    run = L.execute(M)
    d = at_start(run, 5)
    good = L.executor_opening(run, d)
    a, b = good.constants
    table = M.constant_table()
    with_consts = lambda *cs: L.MultiProof(good.values, good.siblings, tuple(cs))  # noqa: E731
    # A wrong chunk: another chunk of the same constant, with its own valid path.
    other = dataclasses.replace(a, chunk=table.chunk(0, 2), chunk_path=tuple(table.chunk_tree(0).path(2)))
    refused(d, with_consts(other, b))
    # A wrong chunk path.
    refused(d, with_consts(dataclasses.replace(a, chunk_path=(bytes(32),) + a.chunk_path[1:]), b))
    # A wrong constant path, and a path one level too long.
    refused(d, with_consts(a, dataclasses.replace(b, const_path=(bytes(32),) + b.const_path[1:])))
    refused(d, with_consts(a, dataclasses.replace(b, const_path=b.const_path + (bytes(32),))))
    # A forged constant: its own chunk tree, not under constants_root.
    forged = dataclasses.replace(a, chunk=enc(99) + a.chunk[8:])
    forged = dataclasses.replace(forged, digest=trees.root_from_path(
        "chunk", L.R.chunk_leaf(1, forged.chunk), 1, list(a.chunk_path)))
    refused(d, with_consts(forged, b))
    # Missing, extra and swapped reads.
    refused(d, with_consts(a))
    refused(d, with_consts(a, b, b))
    refused(d, with_consts(b, a))
    refused(d, with_consts())
    # The executor may retry before its deadline.
    assert d.submit_opening(good) == "E"


def test_a_transition_without_constant_reads_takes_none():
    run = L.execute(M)
    c = L.commit(run, 1)
    d = L.Dispute(M, c, 16)
    target = coord_of("p5.finish")
    pair = 5
    d.open(pair)
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(run, d))
        uppers = [x for x, _ in d.midpoints] + [d.hi]
        d.pick(next(i for i, x in enumerate(uppers) if x > target))
    good = L.executor_opening(run, d)
    assert good.constants == ()
    start = L.executor_opening(run, at_start(run, 5))
    refused(d, L.MultiProof(good.values, good.siblings, start.constants[:1]))
    assert d.submit_opening(good) == "E"


def test_a_planted_referee_that_skips_the_constant_path_check_is_caught(monkeypatch):
    """Mutation check: a referee that does not verify the constant against
    constants_root would accept a forged weight and rule for a lying executor."""
    truth = L.execute(M)
    liar = L.execute(OtherWeights(positions_count=9, window=3, weights=True))
    other = OtherWeights(weights=True).constant_table()
    real = L.trees.root_from_path

    def skip_const(kind, leaf, position, path):
        return L.constants_root(M) if kind == L.CONST_TREE else real(kind, leaf, position, path)

    d = at_start(liar, 2)
    lie = L.prove(M, liar.states[d.lo], [M.H, M.A])
    tc = L.Schedule(M).transition(d.lo)
    forged = tuple(L.ConstOpening(other.chunk(cid, j), tuple(other.chunk_tree(cid).path(j)),
                                  other.digest(cid), ()) for cid, j in tc.constants)
    refused(d, L.MultiProof(lie.values, lie.siblings, forged))
    monkeypatch.setattr(L.trees, "root_from_path", skip_const)
    # Path lengths still bound ids: give the mutant full-length dummy paths.
    forged = tuple(dataclasses.replace(e, const_path=(bytes(32),) * 2) for e in forged)
    assert d.submit_opening(L.MultiProof(lie.values, lie.siblings, forged)) == "E"  # the mutant is fooled
    del truth


# --- data-dependent constant reads (the start's chunk is chosen by h) -------------------

MV = ToyMachine(positions_count=9, window=3, weights=True, by_value=True)


class WrongChunk(ToyMachine):
    """An executor that reads the chunk after the one h selects."""

    def transition(self, p, i):
        t = super().transition(p, i)
        if i == 0:
            return dataclasses.replace(t, constants=lambda r: ((0, (dec(r[self.H]) + 1) % 4), (2, p % 3)))
        return t


def test_by_value_reads_follow_the_verified_state_in_both_role_orders():
    truth = L.execute(MV)
    liar = L.execute(WrongChunk(positions_count=9, window=3, weights=True, by_value=True))
    liar.machine = MV
    d = L.play(MV, liar, truth, 1, 16)
    assert d.ruling == "C" and L.Schedule(MV).transition(d.lo).label.endswith(".start")
    d = L.play(MV, truth, liar, 1, 16, pair=L.first_disputed_pair(L.commit(liar, 1), truth))
    assert d.ruling == "E"


def test_by_value_opening_of_another_chunk_is_refused():
    run = L.execute(MV)
    s = L.Schedule(MV)
    target = next(c for c in range(s.total) if s.transition(c).label == "p5.start")
    d = L.Dispute(MV, L.commit(run, 1), 16)
    d.open(5)
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(run, d))
        uppers = [x for x, _ in d.midpoints] + [d.hi]
        d.pick(next(i for i, x in enumerate(uppers) if x > target))
    good = L.executor_opening(run, d)
    h = dec(run.states[d.lo][MV.H])
    table = MV.constant_table()
    other = (h + 1) % 4
    wrong = dataclasses.replace(good.constants[0], chunk=table.chunk(0, other),
                                chunk_path=tuple(table.chunk_tree(0).path(other)))
    refused(d, L.MultiProof(good.values, good.siblings, (wrong, good.constants[1])))
    assert d.submit_opening(good) == "E"
