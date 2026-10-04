#!/usr/bin/env python3
"""Generated LX1 dispute scenarios for the tag 227 fuzz campaign
(`lx_fuzz_plays_rule_like_python` in crates/dcg-program/tests/disputes_v21_lx.rs).

Each play is a reference dispute over a randomized toy machine (positions,
window, h0, weights), a randomized template (arity, k bounds, max positions)
and a randomized fault (a slot altered after a coordinate, or an executor that
used other weights), played in a random role order, with the challenger's pair
and picks either honest or arbitrary (any choice the reference accepts). The
expected ruling comes from the Python reference (`dcg.disputes_v21.lx`).
OUTPUT claims (sub 26) are generated the same way. Every play also carries
malformed variants of its opening that the reference refuses.

The output goes outside the repository (default under /private/tmp):

    PYTHONPATH=python python3 scripts/disputes_v21_lx_fuzz.py --seed 1 --count 500
    PYTHONPATH=python python3 scripts/disputes_v21_lx_fuzz.py --seed 1 --only 17

Play `i` of seed `s` depends only on `(s, i)`, so one play regenerates alone
with `--only`. `--extreme` admits h0 and fault values outside the toy's
small range (i64 overflow classes)."""
from __future__ import annotations

import argparse
import copy
import json
import random
import struct
import sys
from pathlib import Path

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21.lx_toy import ToyMachine


def h(b: bytes) -> str:
    return b.hex()


def enc(v: int) -> bytes:
    return struct.pack("<q", v)


def dec(b: bytes) -> int:
    return struct.unpack("<q", b)[0]


def opening_json(proof: L.MultiProof) -> dict:
    return {
        "opened": [[s, None if proof.values[s] is None else h(proof.values[s])] for s in sorted(proof.values)],
        "siblings": [h(proof.siblings[k]) for k in sorted(proof.siblings)],
        "constants": [{"chunk": h(e.chunk), "chunk_path": [h(x) for x in e.chunk_path], "digest": h(e.digest),
                       "const_path": [h(x) for x in e.const_path]} for e in proof.constants],
    }


def proof_from_json(tm, o: dict) -> L.MultiProof | None:
    """The reference's view of a (possibly mutated) JSON opening, as the
    program decodes it: siblings in canonical key order. None when the
    opening cannot even be expressed (the reference refuses it)."""
    values = {}
    for s, v in o["opened"]:
        if s in values:
            return None
        values[s] = None if v is None else bytes.fromhex(v)
    if [s for s, _ in o["opened"]] != sorted(values):
        return None
    need = sorted(L._needed(set(values), L.height(tm)))
    if len(need) != len(o["siblings"]):
        return None
    sib = {k: bytes.fromhex(x) for k, x in zip(need, o["siblings"])}
    consts = tuple(L.ConstOpening(bytes.fromhex(e["chunk"]), tuple(bytes.fromhex(x) for x in e["chunk_path"]),
                                  bytes.fromhex(e["digest"]), tuple(bytes.fromhex(x) for x in e["const_path"]))
                   for e in o["constants"])
    return L.MultiProof(values, sib, consts)


def commitment_json(run: L.Execution, k: int, outputs=None) -> dict:
    c = L.commit(run, k, outputs)
    tm = run.machine
    return {
        "k": k,
        "roots": [h(r) for r in c.roots],
        "checkpoint_root": h(L.checkpoint_tree(c.roots).root),
        "outputs": [None if c.outputs[s] is None else h(c.outputs[s]) for s in tm.output_slots()],
        "outputs_digest": h(L.outputs_digest([c.outputs[s] for s in tm.output_slots()])),
    }


# --- randomized pieces --------------------------------------------------------------------

def rand_machine(rng: random.Random, extreme: bool) -> ToyMachine:
    p = rng.randint(1, 12)
    w = rng.randint(1, 4)
    if extreme and rng.random() < 0.5:
        h0 = rng.choice([1 << 62, -(1 << 62), (1 << 63) - 1, -(1 << 63), rng.randint(-(1 << 63), (1 << 63) - 1)])
    else:
        h0 = rng.choice([rng.randint(-50, 50), rng.randint(-(1 << 31), (1 << 31) - 1)])
    return ToyMachine(positions_count=p, window=w, h0=h0, weights=rng.random() < 0.6)


def rand_value(rng: random.Random, old: bytes | None, extreme: bool) -> bytes | None:
    r = rng.random()
    if old is not None and len(old) == 8 and r < 0.45:
        return enc(dec(old) + rng.choice([1, -1, rng.randint(-1000, 1000) or 7]))
    if r < 0.6:
        return None
    if r < 0.7:
        return bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 4, 7, 9, 16])))
    if extreme and r < 0.85:
        return enc(rng.choice([1 << 62, -(1 << 62), (1 << 63) - 1, -(1 << 63), rng.randint(-(1 << 63), (1 << 63) - 1)]))
    return enc(rng.randint(-(1 << 31), (1 << 31) - 1))


def rand_liar(rng: random.Random, tm: ToyMachine, extreme: bool):
    """A lying execution that the reference can step through, and its label."""
    total = L.Schedule(tm).total
    for _ in range(40):
        if tm.weights and rng.random() < 0.5:
            w0, w2 = list(ToyMachine.WEIGHTS0), list(ToyMachine.WEIGHTS2)
            target = w0 if rng.random() < 0.6 else w2
            j = rng.randrange(len(target))
            target[j] += rng.choice([1, -1, rng.randint(-100, 100) or 3])
            other = type("OtherWeights", (ToyMachine,), {"WEIGHTS0": tuple(w0), "WEIGHTS2": tuple(w2)})
            om = other(positions_count=tm.positions_count, window=tm.window, h0=tm.h0, weights=True)
            try:
                run = L.execute(om)
            except Exception:
                continue
            run.machine = tm
            return run, f"weights{'0' if target is w0 else '2'}[{j}]"
        c = rng.randrange(total)
        slot = rng.randrange(tm.slot_count)
        holder = {}

        def fault(coord, state, c=c, slot=slot):
            if coord == c:
                state = dict(state)
                old = state.get(slot)
                if "v" not in holder:
                    holder["v"] = rand_value(rng, old, extreme)
                v = holder["v"]
                if v is None:
                    state.pop(slot, None)
                else:
                    state[slot] = v
            return state
        try:
            run = L.execute(tm, fault)
        except Exception:
            continue
        return run, f"fault c={c} slot={slot} v={'none' if holder.get('v') is None else h(holder['v'])}"
    return None, None


def rand_template(rng: random.Random, tm: ToyMachine, k: int, arity: int) -> dict:
    k_min = rng.randint(1, k)
    k_max = rng.choice([k, k + rng.randint(0, 20), 1 << rng.randint(4, 20)])
    max_positions = rng.choice([tm.positions_count, tm.positions_count + rng.randint(0, 100), 1 << 16])
    return {"arity": arity, "k_min": k_min, "k_max": max(k_max, k), "max_positions": max_positions}


def params_hex(tm: ToyMachine) -> str:
    base = struct.pack("<QQq", tm.positions_count, tm.window, tm.h0)
    return h(base + (b"\x01" if tm.weights else b""))


def machine_json(tm: ToyMachine) -> dict:
    return {
        "positions": tm.positions_count,
        "window": tm.window,
        "h0": tm.h0,
        "weights": tm.weights,
        "params": params_hex(tm),
        "constants_root": h(L.constants_root(tm)),
        "initial_root": h(L.state_root(tm, tm.initial_state())),
    }


# --- malformed openings ------------------------------------------------------------------

def flip_hex(rng: random.Random, s: str) -> str:
    b = bytearray(bytes.fromhex(s))
    if not b:
        return "00"
    b[rng.randrange(len(b))] ^= rng.randint(1, 255)
    return b.hex()


def mutate(rng: random.Random, tm, o: dict) -> tuple[str, dict] | None:
    o = copy.deepcopy(o)
    opened, sibs, consts = o["opened"], o["siblings"], o["constants"]
    present = [i for i, (_, v) in enumerate(opened) if v is not None]
    kinds = ["value", "clear", "length", "drop-slot", "extra-slot", "reslot", "sibling", "drop-sibling",
             "extra-sibling", "extra-const"]
    if consts:
        kinds += ["chunk", "chunk-path", "digest", "const-path", "drop-const", "swap-const", "no-const",
                  "short-chunk-path", "long-const-path"]
    kind = rng.choice(kinds)
    if kind == "value" and present:
        i = rng.choice(present)
        opened[i][1] = flip_hex(rng, opened[i][1])
    elif kind == "clear":
        i = rng.randrange(len(opened))
        opened[i][1] = None if opened[i][1] is not None else enc(rng.randint(-9, 9)).hex()
    elif kind == "length" and present:
        i = rng.choice(present)
        opened[i][1] = opened[i][1] + "00" if rng.random() < 0.5 else opened[i][1][:-2]
    elif kind == "drop-slot":
        opened.pop(rng.randrange(len(opened)))
    elif kind == "extra-slot":
        taken = {s for s, _ in opened}
        free = [s for s in range(tm.slot_count) if s not in taken]
        if not free:
            return None
        opened.append([rng.choice(free), rng.choice([None, enc(0).hex()])])
        opened.sort(key=lambda e: e[0])
    elif kind == "reslot":
        taken = {s for s, _ in opened}
        free = [s for s in range(tm.slot_count) if s not in taken]
        if not free:
            return None
        opened[rng.randrange(len(opened))][0] = rng.choice(free)
        opened.sort(key=lambda e: e[0])
    elif kind == "sibling" and sibs:
        i = rng.randrange(len(sibs))
        sibs[i] = flip_hex(rng, sibs[i])
    elif kind == "drop-sibling" and sibs:
        sibs.pop(rng.randrange(len(sibs)))
    elif kind == "extra-sibling":
        sibs.insert(rng.randint(0, len(sibs)), h(bytes(rng.randrange(256) for _ in range(32))))
    elif kind == "extra-const":
        consts.append({"chunk": "00" * 8, "chunk_path": [], "digest": "00" * 32, "const_path": []}
                      if not consts else copy.deepcopy(rng.choice(consts)))
    elif kind == "chunk":
        e = rng.choice(consts)
        e["chunk"] = flip_hex(rng, e["chunk"])
    elif kind == "chunk-path":
        e = rng.choice(consts)
        if not e["chunk_path"]:
            return None
        j = rng.randrange(len(e["chunk_path"]))
        e["chunk_path"][j] = flip_hex(rng, e["chunk_path"][j])
    elif kind == "digest":
        e = rng.choice(consts)
        e["digest"] = flip_hex(rng, e["digest"])
    elif kind == "const-path":
        e = rng.choice(consts)
        if not e["const_path"]:
            return None
        j = rng.randrange(len(e["const_path"]))
        e["const_path"][j] = flip_hex(rng, e["const_path"][j])
    elif kind == "drop-const":
        consts.pop(rng.randrange(len(consts)))
    elif kind == "swap-const":
        if len(consts) < 2 or consts[0] == consts[1]:
            return None
        consts[0], consts[1] = consts[1], consts[0]
    elif kind == "no-const":
        consts.clear()
    elif kind == "short-chunk-path":
        e = rng.choice(consts)
        if not e["chunk_path"]:
            return None
        e["chunk_path"].pop()
    elif kind == "long-const-path":
        e = rng.choice(consts)
        e["const_path"].append(h(L.trees.empty(L.CONST_TREE, len(e["const_path"]))))
    else:
        return None
    return kind, o


def refused_by_reference(d: L.Dispute, tm, o: dict, output: bool = False) -> bool:
    proof = proof_from_json(tm, o)
    if proof is None:
        return True
    d = copy.deepcopy(d)
    try:
        if output:
            if proof.constants:
                return True  # an output opening carries no constants section
            d.claim_output(proof)
        else:
            d.submit_opening(proof)
    except L.LxRefused:
        return True
    return False


def mutations(rng: random.Random, d: L.Dispute, tm, o: dict, n: int, output: bool = False) -> list[dict]:
    out = []
    for _ in range(8 * n):
        if len(out) == n:
            break
        m = mutate(rng, tm, o)
        if m is None or m[1] == o:
            continue
        kind, mo = m
        if output and kind in ("extra-const",):
            continue
        if refused_by_reference(d, tm, mo, output):
            out.append({"kind": kind, "opening": mo})
    return out


# --- plays --------------------------------------------------------------------------------

def state_play(rng: random.Random, extreme: bool) -> dict | None:
    tm = rand_machine(rng, extreme)
    try:
        honest = L.execute(tm)
    except Exception:
        return None
    liar, label = rand_liar(rng, tm, extreme)
    if liar is None:
        return None
    k = rng.randint(1, tm.positions_count + 2)
    arity = rng.randint(2, 16)
    order = rng.choice(["executor-lies", "challenger-lies"])
    executor, challenger = (liar, honest) if order == "executor-lies" else (honest, liar)
    com = L.commit(executor, k)
    try:
        L.admit_commitment(tm, com)
    except L.LxRefused:
        return None  # a fault at R_0 is refused at commit, not disputed
    pairs = len(com.roots) - 1
    pair = L.first_disputed_pair(com, challenger)
    honest_pair = pair is not None and rng.random() < 0.75
    if not honest_pair:
        pair = rng.randrange(pairs)
    honest_picks = rng.random() < 0.6
    d = L.Dispute(tm, com, arity)
    d.open(pair)
    rounds = []
    while d.phase == L.PH_MIDPOINTS:
        mids = L.executor_midpoints(executor, d)
        d.commit_midpoints(mids)
        pick = L.challenger_pick(challenger, d) if honest_picks else rng.randrange(len(mids) + 1)
        rounds.append({"midpoints": [h(r) for r in mids], "pick": pick})
        d.pick(pick)
    proof = L.executor_opening(executor, d)
    o = opening_json(proof)
    muts = mutations(rng, d, tm, o, 2)
    ruling = d.submit_opening(proof)
    return {
        "kind": "state",
        "name": f"{order} {label} k={k} a={arity} pair={pair}{'' if honest_pair else '*'}"
                f" picks={'honest' if honest_picks else 'random'}",
        "machine": machine_json(tm),
        "template": rand_template(rng, tm, k, arity),
        "arity": arity,
        "commitment": commitment_json(executor, k),
        "pair": pair,
        "rounds": rounds,
        "terminal": d.lo,
        "opening": o,
        "ruling": ruling,
        "mutations": muts,
        "raw_seed": rng.getrandbits(63),
    }


def output_play(rng: random.Random, extreme: bool) -> dict | None:
    tm = rand_machine(rng, extreme)
    try:
        honest = L.execute(tm)
    except Exception:
        return None
    run = honest
    label = "honest-run"
    if rng.random() < 0.4:
        run, label = rand_liar(rng, tm, extreme)
        if run is None:
            return None
    final = run.states[-1]
    claimed = {s: final.get(s) for s in tm.output_slots()}
    lie = rng.random() < 0.6
    if lie:
        claimed[tm.H] = rand_value(rng, claimed[tm.H], extreme)
    k = rng.randint(1, tm.positions_count + 2)
    com = L.commit(run, k, claimed)
    try:
        L.admit_commitment(tm, com)
    except L.LxRefused:
        return None
    d = L.Dispute(tm, com, 16)
    proof = L.prove(tm, final, list(tm.output_slots()))
    o = opening_json(proof)
    muts = mutations(rng, d, tm, o, 1, output=True)
    ruling = d.claim_output(proof)
    return {
        "kind": "output",
        "name": f"output {label} claim={'lie' if lie else 'true'} k={k}",
        "machine": machine_json(tm),
        "template": rand_template(rng, tm, k, rng.randint(2, 16)),
        "commitment": commitment_json(run, k, claimed),
        "opening": o,
        "ruling": ruling,
        "mutations": muts,
    }


def build(seed: int, count: int, only: int | None, extreme: bool, output_share: float) -> dict:
    plays = []
    indices = [only] if only is not None else range(count)
    for i in indices:
        rng = random.Random(f"lxfuzz:{seed}:{i}:{int(extreme)}")
        p = None
        while p is None:
            p = output_play(rng, extreme) if rng.random() < output_share else state_play(rng, extreme)
        p["seed"], p["index"] = seed, i
        plays.append(p)
    return {"seed": seed, "count": count, "extreme": extreme, "plays": plays}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--only", type=int, help="regenerate only play INDEX of this seed")
    ap.add_argument("--extreme", action="store_true", help="admit h0 and fault values outside the toy's small range")
    ap.add_argument("--output-share", type=float, default=0.1, help="fraction of OUTPUT claims (sub 26)")
    ap.add_argument("--out", type=Path, help="default /private/tmp/dcg-lxfuzz/plays-<seed>.json")
    a = ap.parse_args()
    out = a.out or Path(f"/private/tmp/dcg-lxfuzz/plays-{a.seed}{'-x' if a.extreme else ''}"
                        f"{'' if a.only is None else f'-only{a.only}'}.json")
    repo = Path(__file__).resolve().parents[1]
    if repo in out.resolve().parents:
        sys.exit("write plays outside the repository")
    out.parent.mkdir(parents=True, exist_ok=True)
    data = build(a.seed, a.count, a.only, a.extreme, a.output_share)
    out.write_text(json.dumps(data))
    rulings = [p["ruling"] for p in data["plays"]]
    print(out, len(rulings), "plays;", rulings.count("E"), "E,", rulings.count("C"), "C;",
          sum(len(p["mutations"]) for p in data["plays"]), "malformed openings")


if __name__ == "__main__":
    main()
