"""LX1 (checkpointed state chains, one flattened bisection) on the toy machine."""

from __future__ import annotations

import pytest

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21.lx_toy import ToyMachine, dec, enc

M = ToyMachine(positions_count=9, window=3)


def honest():
    return L.execute(M)


def lie_at(coordinate: int, mutate):
    """An executor that corrupts its state after `coordinate` and continues from it."""
    def fault(c, state):
        return mutate(dict(state)) if c == coordinate else state
    return L.execute(M, fault)


def coord_of(label: str) -> int:
    s = L.Schedule(M)
    for c in range(s.total):
        if s.transition(c).label == label:
            return c
    raise KeyError(label)


def test_schedule_and_states_are_consistent():
    run = honest()
    s = run.schedule
    assert s.total == sum(M.transitions_in(p) for p in range(M.positions()))
    # Scratch is empty at every position boundary.
    for p in range(M.positions() + 1):
        state = run.states[s.position_start(p)]
        assert all(slot not in state for slot in (M.A, M.M, M.S)), p
    assert dec(run.states[-1][M.log0 + M.positions() - 1]) == dec(run.states[-1][M.H])


def test_an_honest_run_has_no_disputed_checkpoint():
    run = honest()
    for k in (1, 4, 16):
        assert L.first_disputed_pair(L.commit(run, k), run) is None


@pytest.mark.parametrize("k", [1, 4, 16])
@pytest.mark.parametrize("arity", [2, 16])
@pytest.mark.parametrize("label,mutate", [
    ("p5.start", lambda st: {**st, M.A: enc(dec(st[M.A]) + 1)}),            # position scratch
    ("p7.max1", lambda st: {**st, M.M: enc(dec(st[M.M]) + 10**6)}),         # phase-1 window
    ("p8.sum2", lambda st: {**st, M.S: enc(dec(st[M.S]) + 5)}),             # phase-2 window
    ("p4.finish", lambda st: {**st, M.log0 + 4: enc(1)}),                   # carried log append
    ("p8.finish", lambda st: {**st, M.A: enc(9)}),                           # scratch not cleared at the end
])
def test_a_lie_is_convicted_at_its_own_transition(k, arity, label, mutate):
    truth, liar = honest(), lie_at(coord_of(label), mutate)
    d = L.play(M, liar, truth, k, arity)
    assert d.ruling == "C"
    assert d.lo == coord_of(label), (d.lo, L.Schedule(M).transition(d.lo).label)


@pytest.mark.parametrize("arity", [2, 16])
def test_a_lying_challenger_loses_to_an_honest_executor(arity):
    run = honest()
    # It disputes a checkpoint pair that agrees, and picks arbitrarily.
    for pick in (lambda d: 0, lambda d: len(d.midpoints), lambda d: len(d.midpoints) // 2):
        d = L.play(M, run, run, 4, arity, pair=1, pick=pick)
        assert d.ruling == "E"


def test_timeouts_rule_against_the_silent_party():
    truth, liar = honest(), lie_at(coord_of("p5.start"), lambda st: {**st, M.A: enc(0)})
    c = L.commit(liar, 4)
    pair = L.first_disputed_pair(c, truth)
    d = L.Dispute(M, c); d.open(pair)
    assert d.timeout() == "C", "E owes the midpoints"
    d = L.Dispute(M, c); d.open(pair)
    d.commit_midpoints(L.executor_midpoints(liar, d))
    assert d.timeout() == "E", "C owes the pick"
    d = L.Dispute(M, c, arity=2); d.open(pair)
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(liar, d))
        d.pick(L.challenger_pick(truth, d))
    assert d.phase == L.PH_OPENING and d.timeout() == "C", "E owes the opening"
    with pytest.raises(L.LxRefused):
        d.timeout()


def test_malformed_submissions_are_refused_without_state_change():
    run = honest()
    c = L.commit(run, 4)
    d = L.Dispute(M, c); d.open(0)
    with pytest.raises(L.LxRefused):
        d.commit_midpoints([b"\x00" * 32])  # wrong count
    with pytest.raises(L.LxRefused):
        d.pick(0)  # not awaiting a pick
    d.commit_midpoints(L.executor_midpoints(run, d))
    with pytest.raises(L.LxRefused):
        d.pick(len(d.midpoints) + 1)  # no such sub-interval
    with pytest.raises(L.LxRefused):
        L.Dispute(M, c).open(len(c.roots))


def test_a_forged_opening_is_refused():
    truth, liar = honest(), lie_at(coord_of("p7.max1"), lambda st: {**st, M.M: enc(10**6)})
    c = L.commit(liar, 4)
    d = L.Dispute(M, c, arity=2); d.open(L.first_disputed_pair(c, truth))
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(liar, d))
        d.pick(L.challenger_pick(truth, d))
    good = L.executor_opening(liar, d)
    # A different value at a read slot does not verify against the lower root.
    slot = next(iter(good.values))
    forged = L.MultiProof({**good.values, slot: enc(123456)}, good.siblings)
    with pytest.raises(L.LxRefused):
        d.submit_opening(forged)
    # Missing slots are refused too.
    with pytest.raises(L.LxRefused):
        d.submit_opening(L.MultiProof({slot: good.values[slot]}, good.siblings))
    # A canonical proof over a subset of the slots is refused as well.
    subset = sorted(good.values)[:-1]
    with pytest.raises(L.LxRefused):
        d.submit_opening(L.prove(M, liar.states[d.lo], subset))
    # Extra siblings beyond the canonical set are refused.
    with pytest.raises(L.LxRefused):
        d.submit_opening(L.MultiProof(good.values, {**good.siblings, (0, 10**6): b"\x00" * 32}))
    assert d.submit_opening(good) == "C"


def test_multiproof_rebuilds_the_root_after_writes():
    run = honest()
    t = L.Schedule(M).transition(coord_of("p6.finish"))
    before, after = run.states[t.coordinate], run.states[t.coordinate + 1]
    proof = L.prove(M, before, sorted(set(t.reads) | set(t.writes)))
    assert L.root_over(M, proof, proof.values) == L.state_root(M, before)
    written = dict(proof.values)
    written.update(t.apply({s: proof.values[s] for s in t.reads}))
    assert L.root_over(M, proof, written) == L.state_root(M, after)


def test_rounds_shrink_logarithmically():
    truth, liar = honest(), lie_at(coord_of("p8.sum2"), lambda st: {**st, M.S: enc(0)})
    d2 = L.play(M, liar, truth, 16, 2)
    d16 = L.play(M, liar, truth, 16, 16)
    assert d16.rounds < d2.rounds
    span = L.Schedule(M).total
    assert d2.rounds <= span.bit_length() + 1


def test_a_lie_that_heals_before_a_checkpoint_is_not_disputable():
    """Only checkpoint states and outputs are claimed. A deviation overwritten
    before the next checkpoint (an uncleared scratch slot that the next
    position's start overwrites) changes nothing committed."""
    truth = honest()
    liar = lie_at(coord_of("p6.finish"), lambda st: {**st, M.A: enc(9)})
    assert L.first_disputed_pair(L.commit(liar, 4), truth) is None
    # With a checkpoint right after it (k=1), the same deviation is committed and convicted.
    d = L.play(M, liar, truth, 1, 16)
    assert d.ruling == "C" and d.lo == coord_of("p6.finish")


# --- review fixes (2026-10-03 LX1 design review) ----------------------------------------

def test_h1_a_lying_initial_root_is_refused_at_commit():
    """A run from a different initial state (another prompt or entropy) differs
    at R_0; COMMIT recomputes R_0 from the admitted inputs and refuses it."""
    other = ToyMachine(positions_count=9, window=3, h0=8)
    c = L.commit(L.execute(other), 4)
    with pytest.raises(L.LxRefused):
        L.admit_commitment(M, c)
    with pytest.raises(L.LxRefused):
        L.Dispute(M, c)


def test_h2_checkpoint_coordinates_are_derived_not_supplied():
    run = honest()
    c = L.commit(run, 4)
    short = L.Commitment(c.k, c.roots[:-1], c.outputs)
    with pytest.raises(L.LxRefused):
        L.admit_commitment(M, short)
    # A run committed at k=4 is judged at k=4's derived coordinates; roots
    # shuffled between checkpoints are disputable at the first mismatch.
    shuffled = L.Commitment(c.k, (c.roots[0], c.roots[2], c.roots[1]) + c.roots[3:], c.outputs)
    pair = L.first_disputed_pair(shuffled, run)
    assert pair == 0
    d = L.Dispute(M, shuffled); d.open(pair)
    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(run, d))
        d.pick(L.challenger_pick(run, d))
    assert d.submit_opening(L.executor_opening(run, d)) == "C"


def test_h3_an_output_lie_with_honest_checkpoints_is_convicted_by_output():
    run = honest()
    honest_c = L.commit(run, 4)
    liar = L.commit(run, 4, outputs={M.H: enc(42)})
    assert L.first_disputed_pair(liar, run) is None and L.output_lie(liar, run)
    proof = L.prove(M, run.states[-1], list(M.output_slots()))
    assert L.Dispute(M, liar).claim_output(proof) == "C"
    assert L.Dispute(M, honest_c).claim_output(proof) == "E"
    # A forged opening of R_T is refused.
    forged = L.MultiProof({M.H: enc(42)}, proof.siblings)
    with pytest.raises(L.LxRefused):
        L.Dispute(M, liar).claim_output(forged)


class EmptyPositionMachine(ToyMachine):
    """A position with no transitions: two checkpoints share a coordinate."""

    def transitions_in(self, p: int) -> int:
        return 0 if p == 4 else super().transitions_in(p)



def test_l1_an_empty_checkpoint_interval_cannot_be_opened():
    m = EmptyPositionMachine(positions_count=9, window=3)
    coords = L.checkpoint_coordinates(L.Schedule(m), 1)
    roots = (L.state_root(m, m.initial_state()),) + tuple(bytes([i]) * 32 for i in range(1, len(coords)))
    c = L.Commitment(1, roots, {m.H: None})
    pair = next(j for j in range(len(coords) - 1) if coords[j] == coords[j + 1])
    with pytest.raises(L.LxRefused):
        L.Dispute(m, c).open(pair)


def test_l2_a_kernel_failure_on_a_verified_opening_rules_for_the_challenger():
    """Only a state the executor committed can hold a malformed value. Here the
    executor's states inside position 5 hold a non-i64 in scratch (its
    checkpoints are honest, since scratch is empty at boundaries). A challenger
    steers to the step that reads it; the replay's kernel fails on the verified
    opening, and the executor loses rather than the referee crashing."""
    truth = honest()
    s = L.Schedule(M)
    start, finish = coord_of("p5.start"), coord_of("p5.finish")
    states = [dict(st) for st in truth.states]
    for c in range(start + 1, finish + 1):
        states[c][M.A] = b"bad"
    liar = L.Execution(M, s, states)
    c = L.commit(liar, 1)
    d = L.Dispute(M, c, arity=2)
    d.open(5)

    def toward(target):
        def pick(dd):
            bounds = [dd.lo] + [m for m, _r in dd.midpoints] + [dd.hi]
            return next(i for i in range(len(bounds) - 1) if bounds[i] <= target < bounds[i + 1])
        return pick

    while d.phase == L.PH_MIDPOINTS:
        d.commit_midpoints(L.executor_midpoints(liar, d))
        d.pick(toward(finish)(d))
    assert d.lo == finish
    assert d.submit_opening(L.executor_opening(liar, d)) == "C"
