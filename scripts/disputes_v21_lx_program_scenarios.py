#!/usr/bin/env python3
"""LX1 program scenarios for the tag 227 ProgramTest
(crates/dcg-program/tests/disputes_v21_lx.rs): the Python toy machine's
commitments, every round's midpoint roots and picks, and the terminal
openings, from played reference disputes. Both role orders: a lying executor
against an honest challenger, and an honest executor against a lying one."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21.lx_toy import ToyMachine

OUT = Path(__file__).resolve().parents[1] / "tests/golden/dcg/disputes_v21/lx_program.json"
P, W, H0 = 9, 3, 7


def h(b: bytes) -> str:
    return b.hex()


def opening(proof: L.MultiProof) -> dict:
    return {
        "opened": [[s, None if proof.values[s] is None else h(proof.values[s])] for s in sorted(proof.values)],
        "siblings": [h(proof.siblings[k]) for k in sorted(proof.siblings)],
        "constants": [{"chunk": h(e.chunk), "chunk_path": [h(x) for x in e.chunk_path], "digest": h(e.digest),
                       "const_path": [h(x) for x in e.const_path]} for e in proof.constants],
    }


def commitment(run: L.Execution, k: int, outputs=None) -> dict:
    c = L.commit(run, k, outputs)
    tm = run.machine
    return {
        "k": k,
        "roots": [h(r) for r in c.roots],
        "checkpoint_root": h(L.checkpoint_tree(c.roots).root),
        "outputs": [None if c.outputs[s] is None else h(c.outputs[s]) for s in tm.output_slots()],
        "outputs_digest": h(L.outputs_digest([c.outputs[s] for s in tm.output_slots()])),
    }


def bump(tm, c):
    def fault(coord, state):
        if coord == c:
            state = dict(state)
            state[tm.H] = struct.pack("<q", struct.unpack("<q", state[tm.H])[0] + 1)
        return state
    return fault


def build() -> dict:
    tm = ToyMachine(positions_count=P, window=W, h0=H0)
    honest = L.execute(tm)
    total = L.Schedule(tm).total
    plays = []
    for k, arity in ((4, 16), (1, 2), (4, 3), (2, 4)):
        faults = [c for c in range(total)
                  if L.first_disputed_pair(L.commit(L.execute(tm, bump(tm, c)), k), honest) is not None]
        for c in (faults[len(faults) // 3], faults[2 * len(faults) // 3]):
            liar = L.execute(tm, bump(tm, c))
            for name, executor, challenger in (("executor-lies", liar, honest), ("challenger-lies", honest, liar)):
                com = L.commit(executor, k)
                pair = L.first_disputed_pair(com, challenger)
                if pair is None:
                    continue
                d = L.Dispute(tm, com, arity)
                d.open(pair)
                rounds = []
                while d.phase == L.PH_MIDPOINTS:
                    mids = L.executor_midpoints(executor, d)
                    d.commit_midpoints(mids)
                    pick = L.challenger_pick(challenger, d)
                    rounds.append({"midpoints": [h(r) for r in mids], "pick": pick})
                    d.pick(pick)
                proof = L.executor_opening(executor, d)
                ruling = d.submit_opening(proof)
                plays.append({
                    "name": f"{name} k={k} a={arity} fault={c}",
                    "arity": arity,
                    "commitment": commitment(executor, k),
                    "pair": pair,
                    "rounds": rounds,
                    "terminal": d.lo,
                    "opening": opening(proof),
                    "ruling": ruling,
                })
    outputs = []
    for lie in (False, True):
        final = honest.states[-1]
        claimed = {s: final.get(s) for s in tm.output_slots()}
        if lie:
            claimed[tm.H] = struct.pack("<q", 12345)
        com = L.commit(honest, 4, claimed)
        d = L.Dispute(tm, com, 16)
        proof = L.prove(tm, final, list(tm.output_slots()))
        outputs.append({
            "commitment": commitment(honest, 4, claimed),
            "opening": opening(proof),
            "ruling": d.claim_output(proof),
        })
    return {
        "weighted": build_weighted(),
        "params": h(struct.pack("<QQq", P, W, H0)),
        "initial_root": h(L.state_root(tm, tm.initial_state())),
        "plays": plays,
        "outputs": outputs,
    }


def build_weighted() -> dict:
    """Constants in openings (design §13): the toy with weights. Lies at
    weighted starts (a bumped scratch value, and an executor that used other
    weights), in both role orders."""
    tm = ToyMachine(positions_count=P, window=W, h0=H0, weights=True)

    class OtherWeights(ToyMachine):
        WEIGHTS0 = (5, -3, 11, 2, 8, 0, -9, 4)

    honest = L.execute(tm)
    other = L.execute(OtherWeights(positions_count=P, window=W, h0=H0, weights=True))
    other.machine = tm
    sch = L.Schedule(tm)
    start5 = next(c for c in range(sch.total) if sch.transition(c).label == "p5.start")

    def bump_a(coord, state):
        if coord == start5:
            state = dict(state)
            state[tm.A] = struct.pack("<q", struct.unpack("<q", state[tm.A])[0] + 1)
        return state

    plays = []
    for lie, liar in (("bumped-start", L.execute(tm, bump_a)), ("other-weights", other)):
        for k, arity in ((1, 16), (4, 2)):
            for name, executor, challenger in (("executor-lies", liar, honest), ("challenger-lies", honest, liar)):
                com = L.commit(executor, k)
                pair = L.first_disputed_pair(com, challenger)
                d = L.Dispute(tm, com, arity)
                d.open(pair)
                rounds = []
                while d.phase == L.PH_MIDPOINTS:
                    mids = L.executor_midpoints(executor, d)
                    d.commit_midpoints(mids)
                    pick = L.challenger_pick(challenger, d)
                    rounds.append({"midpoints": [h(r) for r in mids], "pick": pick})
                    d.pick(pick)
                proof = L.executor_opening(executor, d)
                assert proof.constants, "every weighted play ends at a start"
                ruling = d.submit_opening(proof)
                plays.append({
                    "name": f"weighted {lie} {name} k={k} a={arity}",
                    "arity": arity,
                    "commitment": commitment(executor, k),
                    "pair": pair,
                    "rounds": rounds,
                    "terminal": d.lo,
                    "opening": opening(proof),
                    "ruling": ruling,
                })
    return {
        "params": h(struct.pack("<QQqB", P, W, H0, 1)),
        "constants_root": h(L.constants_root(tm)),
        "initial_root": h(L.state_root(tm, tm.initial_state())),
        "plays": plays,
    }


if __name__ == "__main__":
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(OUT, len(data["plays"]), [p["ruling"] for p in data["plays"]])
