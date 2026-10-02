#!/usr/bin/env python3
"""Oracle scenarios for the disputes v2.1 program skeleton.

Writes tests/golden/dcg/disputes_v21/scenarios.json. Each scenario is a
graph, a commitment (honest, or with one planted lie), and the Python honest
challenger's transcript: its picks per round, the claim it makes, and the
Python referee's ruling. A second family replays an adversarial challenger
against an honest commitment (expected ruling: E). The Rust ProgramTest
`disputes_v21_oracle` replays every scenario on the program and must reach
the same ruling.

The template bytes and ids follow the skeleton (`disputes_v21.rs`
create_template and init_run).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from solders.keypair import Keypair  # noqa: E402

from dcg import tracing  # noqa: E402
from dcg.disputes_v21 import game as G  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402
from dcg.disputes_v21 import spec as S  # noqa: E402
from dcg.kernels import add_i32, identity_i32  # noqa: E402

OUT = ROOT / "tests/golden/dcg/disputes_v21/scenarios.json"
TEMPLATE_DOMAIN = b"dcg.template.id.v2.1-skeleton\x00"
PLAN_ID = bytes([7]) * 32
EXECUTOR = bytes(Keypair.from_seed(bytes([0xE1]) * 32).pubkey())
NONCE = bytes(32)
EXECUTOR_BOND, CHALLENGER_BOND, SLASHER = 2_000_000, 1_000_000, 5_000

_t = importlib.util.spec_from_file_location("t", ROOT / "python/tests/test_disputes_v21.py")
T = importlib.util.module_from_spec(_t)
_t.loader.exec_module(T)


def chain(n):
    def f(a):
        v = a
        for _ in range(n):
            v = identity_i32(v)
        return v
    return f


def fanout(a, b):
    with tracing.region("left"):
        s = add_i32(a, b)
    with tracing.region("right"):
        t = identity_i32(s)
    u = add_i32(s, t)
    return identity_i32(u)


def template_data(sp: S.Spec, depth: int) -> bytes:
    data = bytes([depth])
    for x in (sp.total_steps, sp.total_outputs, 1_000, 750, EXECUTOR_BOND, CHALLENGER_BOND):
        data += struct.pack("<Q", x)
    data += struct.pack("<II", 2 + len(sp.in_specs), sp.first_step_record) + sp.root
    data += struct.pack("<H", SLASHER) + PLAN_ID
    return data


class Recorder(G.Executor):
    pass


def transcript(record, executor, honest, depth):
    """The honest challenger's moves, re-derived step by step."""
    picks = []
    orig_pick = G.Dispute.pick

    def pick(self, index):
        picks.append(index)
        return orig_pick(self, index)

    claims = []
    orig_claim = G.Dispute.claim

    def claim(self, name, **kw):
        claims.append((name, kw))
        return orig_claim(self, name, **kw)

    G.Dispute.pick, G.Dispute.claim = pick, claim
    try:
        try:
            d = G.honest_challenge(record, executor, honest, depth)
        except G.Refused:
            return None
    finally:
        G.Dispute.pick, G.Dispute.claim = orig_pick, orig_claim
    if d is None:
        return None
    name, kw = claims[-1]
    producer = None
    if kw.get("producer_opening") is not None:
        # The ordinal of the producer leaf opened, recovered from the spec.
        sp = record.spec
        if d.kind == "OUT_DESCEND":
            producer = S.decode_producer(sp.out_specs[d.position][32:56])[1]
        else:
            dec = S.decode_step_spec(sp.step_specs[d.position])
            producer = S.decode_producer(dec["inputs"][kw.get("index", 0)][1])[1]
    return {"kind": d.kind, "picks": picks, "position": d.position, "claim": name,
            "index": kw.get("index", 0), "producer": producer,
            "witness": [w.hex() for w in (kw.get("witness") or [])], "ruling": d.ruling}


def scenario(graph, inputs, depth, commit_fn, adversarial=None, rng=None):
    sp = S.derive(graph.graph_bytes(), graph.plan_bytes())
    tdata = template_data(sp, depth)
    template_id = hashlib.sha256(TEMPLATE_DOMAIN + tdata).digest()
    values = {eid: struct.pack("<i", v) for eid, v in enumerate(inputs)}
    refs = {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.value_digest(values[eid])) for eid in values}
    run = R.run_id(template_id, NONCE, list(refs.values()), EXECUTOR)
    honest = R.execute(sp, PLAN_ID, run, values)
    committed = commit_fn(honest)
    record = G.RunRecord(PLAN_ID, run, sp, committed.root_bytes, refs)
    if adversarial is None:
        moves = transcript(record, G.Executor(committed), honest, depth)
    else:
        moves = adversarial(record, committed, honest, depth, rng)
    if moves is None:
        return None
    return {"template_data": tdata.hex(), "spec_records": [[t, r.hex()] for t, r in sp.records],
            "refs": [refs[e].hex() for e in sorted(refs)], "leaves": [x.hex() if x else None for x in committed.leaves],
            "out_entries": [x.hex() if x else None for x in committed.out_entries],
            "out_base": 2 + len(sp.in_specs), "step_base": sp.first_step_record,
            "total_steps": sp.total_steps, "total_outputs": sp.total_outputs, "depth": depth, **moves}


def adversarial_step(record, committed, honest, depth, rng):
    """A challenger who descends to a random leaf of an honest commitment and
    makes a random claim there; the referee must rule for E."""
    d = G.Dispute(record, "STEP_DESCEND", depth)
    ex = G.Executor(committed)
    picks = []
    while d.level > 0:
        d.reveal_nodes(ex.nodes(d))
        i = rng.choice(sorted(d.revealed))
        picks.append(i)
        d.pick(i)
    d.reveal_leaf(ex.leaf(d))
    k = d.position
    sp = record.spec
    dec = S.decode_step_spec(sp.step_specs[k])
    name = rng.choice(["SHAPE", "EDGE", "STEP"])
    index = rng.randrange(len(dec["inputs"]))
    kind_p, a, *_ = S.decode_producer(dec["inputs"][index][1])
    witness = [G._value_for(honest, sp, k, x) for x in range(len(dec["inputs"]))]
    ruling = d.claim(name, spec_opening=sp.opening(sp.step_leaf_index(k)), index=index,
                     producer_opening=ex.leaf_opening(a) if kind_p == 1 else None, witness=witness)
    return {"kind": "STEP_DESCEND", "picks": picks, "position": k, "claim": name, "index": index,
            "producer": a if (name == "EDGE" and kind_p == 1) else None,
            "witness": [w.hex() for w in witness] if name == "STEP" else [], "ruling": ruling}


def build() -> list[dict]:
    rng = random.Random(20261002)
    graphs = [(tracing.trace(T.hello), [20, 22]), (tracing.trace(chain(12)), [5]),
              (tracing.trace(chain(37)), [-9]), (tracing.trace(fanout), [3, 4])]
    out = []
    for graph, inputs in graphs:
        for kind in T.LIES:
            if kind == "out_entry" and False:
                continue
            for depth in (1, 4):
                sc = scenario(graph, inputs, depth, lambda h, k=kind: T.lie(rng, h, k))
                if sc:
                    sc["name"] = f"{graph.trace.name}-{kind}-d{depth}"
                    out.append(sc)
        for i in range(3):
            sc = scenario(graph, inputs, rng.randint(1, 4), lambda h: h, adversarial_step, rng)
            sc["name"] = f"{graph.trace.name}-honest-adversary-{i}"
            out.append(sc)
    return out


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    scenarios = build()
    OUT.write_text(json.dumps(scenarios, indent=0, sort_keys=True) + "\n")
    print(OUT, len(scenarios), {r: sum(1 for s in scenarios if s["ruling"] == r) for r in ("C", "E")})
