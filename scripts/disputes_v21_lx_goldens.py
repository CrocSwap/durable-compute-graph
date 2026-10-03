#!/usr/bin/env python3
"""LX1 golden vectors: slot leaves, state roots and canonical multi-proofs
(siblings in level-then-position order), from the toy machine's real states,
for the Rust mirror (crates/dcg-disputes/tests/lx_goldens.rs)."""
from __future__ import annotations

import json
from pathlib import Path

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21.lx_toy import ToyMachine

OUT = Path(__file__).resolve().parents[1] / "tests/golden/dcg/disputes_v21/lx.json"


def build() -> dict:
    m = ToyMachine(positions_count=9, window=3)
    run = L.execute(m)
    cases = []
    for c in (0, 7, 23, len(run.states) - 1):
        state = run.states[c]
        for slots in ([0], [0, 1, 2], [m.A, m.M, m.S], list(range(m.slot_count))[::3], [m.slot_count - 1]):
            proof = L.prove(m, state, slots)
            cases.append({
                "coordinate": c,
                "height": L.height(m),
                "slots": sorted(proof.values),
                "values": [None if proof.values[s] is None else proof.values[s].hex() for s in sorted(proof.values)],
                "leaves": [L.slot_leaf(s, proof.values[s]).hex() for s in sorted(proof.values)],
                "siblings": [proof.siblings[k].hex() for k in sorted(proof.siblings)],
                "root": L.state_root(m, state).hex(),
            })
    schedules = []
    for positions, window in ((9, 3), (5, 2), (1, 4)):
        tm = ToyMachine(positions_count=positions, window=window)
        sch = L.Schedule(tm)
        schedules.append({
            "positions": positions,
            "starts": sch.starts,
            "checkpoints": {str(k): list(L.checkpoint_coordinates(sch, k)) for k in (1, 2, 3, 4, 7, 16)},
        })
    midpoints = []
    for lo, hi, arity in ((0, 1, 16), (0, 2, 16), (3, 20, 16), (0, 16, 16), (0, 17, 16), (5, 1000, 16),
                          (0, 7, 2), (10, 12_345_678, 16), (0, (1 << 40) + 3, 16), (2, 9, 3)):
        d = L.Dispute.__new__(L.Dispute)
        d.lo, d.hi, d.arity = lo, hi, arity
        midpoints.append({"lo": lo, "hi": hi, "arity": arity, "coordinates": d.midpoint_coordinates()})
    plays = []
    tm = ToyMachine(positions_count=9, window=3)
    honest = L.execute(tm)
    configs = ((4, 16), (1, 2), (4, 3), (16, 16), (2, 4), (3, 5))
    candidates = []
    for c in range(L.Schedule(tm).total):
        for k, arity in configs:
            def f(coord, state, c=c):
                if coord == c:
                    state = dict(state)
                    state[tm.H] = (int.from_bytes(state[tm.H], "little", signed=True) + 1).to_bytes(8, "little", signed=True)
                return state
            if L.first_disputed_pair(L.commit(L.execute(tm, f), k), honest) is not None:
                candidates.append((c, k, arity))
    chosen = []
    for i, cfg in enumerate(configs):  # one fault per (k, arity), spread over the schedule
        mine = [x for x in candidates if x[1:] == cfg]
        if mine:
            chosen.append(mine[len(mine) * (i + 1) // (len(configs) + 1)])
    for c, k, arity in chosen:
        def fault(coord, state, c=c):
            if coord == c:
                state = dict(state)
                state[tm.H] = (int.from_bytes(state[tm.H], "little", signed=True) + 1).to_bytes(8, "little", signed=True)
            return state
        liar = L.execute(tm, fault)
        rounds = []

        def pick(d, rounds=rounds):
            i = L.challenger_pick(honest, d)
            rounds.append({"lo": d.lo, "hi": d.hi, "pick": i})
            return i
        d = L.play(tm, liar, honest, k, arity, pick=pick)
        plays.append({"fault": c, "k": k, "arity": arity, "rounds": rounds, "final": [d.lo, d.hi], "ruling": d.ruling})
    # Terminal replays and OUTPUT claims, for the Rust machine trait (tests/lx_goldens.rs).
    replays, outputs = [], []

    def bump(c):
        def fault(coord, state, c=c):
            if coord == c:
                state = dict(state)
                state[tm.H] = (int.from_bytes(state[tm.H], "little", signed=True) + 1).to_bytes(8, "little", signed=True)
            return state
        return fault

    def opening_record(d, proof, ruling):
        return {
            "coordinate": d.lo,
            "opened": [[s, None if proof.values[s] is None else proof.values[s].hex()] for s in sorted(proof.values)],
            "siblings": [proof.siblings[k].hex() for k in sorted(proof.siblings)],
            "root_lo": d.root_lo.hex(), "root_hi": d.root_hi.hex(), "ruling": ruling,
        }

    for c, k, arity in chosen:
        liar = L.execute(tm, bump(c))
        for executor, challenger in ((liar, honest), (honest, liar)):
            commitment = L.commit(executor, k)
            pair = L.first_disputed_pair(commitment, challenger)
            if pair is None:
                continue
            d = L.Dispute(tm, commitment, arity)
            d.open(pair)
            while d.phase == L.PH_MIDPOINTS:
                d.commit_midpoints(L.executor_midpoints(executor, d))
                d.pick(L.challenger_pick(challenger, d))
            proof = L.executor_opening(executor, d)
            replays.append(opening_record(d, proof, d.submit_opening(proof)))
    for lie in (False, True):
        final = honest.states[-1]
        proof = L.prove(tm, final, list(tm.output_slots()))
        claimed = {s: final.get(s) for s in tm.output_slots()}
        if lie:
            claimed[tm.H] = (12345).to_bytes(8, "little", signed=True)
        d = L.Dispute(tm, L.commit(honest, 4, claimed), 16)
        outputs.append({
            "output_slots": list(tm.output_slots()),
            "opened": [[s, None if proof.values[s] is None else proof.values[s].hex()] for s in sorted(proof.values)],
            "siblings": [proof.siblings[k].hex() for k in sorted(proof.siblings)],
            "root_t": d.commitment.roots[-1].hex(),
            "claimed": [None if claimed[s] is None else claimed[s].hex() for s in tm.output_slots()],
            "ruling": d.claim_output(proof),
        })
    return {"replays": replays, "outputs": outputs,
            "toy": {"positions": tm.positions_count, "window": tm.window, "h0": tm.h0, "height": L.height(tm),
                    "total": L.Schedule(tm).total},
            "plays": plays, "slot_leaf_domain": L.SLOT_LEAF_DOMAIN.hex(), "cases": cases,
            "schedules": schedules, "midpoints": midpoints}


if __name__ == "__main__":
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(OUT, len(data["cases"]))
