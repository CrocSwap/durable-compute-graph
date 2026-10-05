#!/usr/bin/env python3
"""Oracle scenarios for chunked kernels on the tag-227 program.

Writes tests/golden/dcg/disputes_v21/chunked_scenarios.json. Each scenario
carries the exact instruction bodies (template, external refs, commit root,
per-round reveals and picks, the leaf, the claim), produced by the Python
challenger and encoded by `dcg.disputes_v21.wire`, and the Python ruling.
The Rust test `disputes_v21_chunked_oracle` sends them to the program and
must reach the same ruling.

Families: consistent faults (output, state, gate, input, prior) convicted by
the honest challenger; structural lies (early stop, extra iteration, empty
iteration 0, chunk edge); and claims against honest runs (every claim at
sampled leaves, and kind 6 claims naming every other iteration), which must
rule for E.
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

from dcg.disputes_v21 import game as G  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402
from dcg.disputes_v21 import spec as S  # noqa: E402
from dcg.disputes_v21 import transcript as X  # noqa: E402
from dcg.disputes_v21 import wire as W  # noqa: E402

OUT = ROOT / "tests/golden/dcg/disputes_v21/chunked_scenarios.json"
PLAN_ID = bytes([7]) * 32
EXECUTOR = bytes(Keypair.from_seed(bytes([0xE1]) * 32).pubkey())
DEPTH = 3
_NONCE = [0]


def next_nonce() -> bytes:
    """Each scenario runs under its own nonce, so all share one test context."""
    _NONCE[0] += 1
    return _NONCE[0].to_bytes(32, "little")

_t = importlib.util.spec_from_file_location("t", ROOT / "python/tests/test_disputes_v21_chunked.py")
T = importlib.util.module_from_spec(_t)
_t.loader.exec_module(T)


def context(sp, values, nonce):
    # Program-test goldens at the 750-slot floor: the staging-time check of
    # live templates (phase_window_for) does not apply.
    tdata = W.template_data(sp, DEPTH, PLAN_ID, slot_ms=None)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
    refs = {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.input_digest(sp.in_specs[eid], v))
            for eid, v in values.items()}
    run = R.run_id(template_id, nonce, list(refs.values()), EXECUTOR)
    return tdata, refs, run


def scenario_against(name, sp, values, nonce, committed, honest, target=None, claim=None, kind="STEP_DESCEND"):
    tdata, refs, run = context(sp, values, nonce)
    assert committed.run_id == run
    record = G.RunRecord(PLAN_ID, run, sp, committed.root_bytes, refs)
    t = X.record(record, committed, honest, DEPTH, target=target, claim=claim, kind=kind)
    return {"name": name, "nonce": nonce.hex(), "template_data": tdata.hex(), "refs": [refs[e].hex() for e in sorted(refs)],
            "root_bytes": committed.root_bytes.hex(), **t}


def execute(sp, values, nonce, **faults):
    tdata, refs, run = context(sp, values, nonce)
    honest = R.execute(sp, PLAN_ID, run, values)
    committed = R.execute(sp, PLAN_ID, run, values, **faults) if faults else honest
    return honest, committed


def app_kernel_plan(split: int):
    """An application kernel (`dcg-test-sha-v1`, SHA-256 over its inputs in
    order: the semantics of Basanos form 22) over 64 KiB of raw external
    input, in `split` inputs. Its STEP witness needs grown staging."""
    from dcg.disputes_v21 import plans as P
    b = P.PlanBuilder()
    size = 65_536 // split
    ins = tuple(P.Input(b.raw_input(e, size), size) for e in range(split))
    b.enumerated([P.Step(b"dcg-test-sha-v1\x00", ins, ((0, 32, False),))])
    b.output(S.producer(1, 0, 0), 32)
    return b.build()


def app_cases(rng):
    for split in (1, 2):
        data = bytes(rng.randrange(256) for _ in range(65_536))
        size = 65_536 // split
        yield f"app-sha-{split}", app_kernel_plan(split), {e: data[e * size:(e + 1) * size] for e in range(split)}


def build() -> list[dict]:
    rng = random.Random(20261002)
    plans = list(T.cases(rng)) + list(T.random_cases(rng, 6)) + list(app_cases(random.Random(65536)))
    # LOG state is in the Python reference only; the program does not run it yet.
    plans = [p for p in plans if not any(S.decode_step_spec(p[1].step_spec(k))["state_scheme"] == 2
                                         for k in range(p[1].total_steps))]
    out = []
    for name, sp, values in plans:
        n0 = next_nonce()
        honest, _ = execute(sp, values, n0)
        # Consistent faults at sampled steps.
        for k in rng.sample(range(sp.total_steps), min(4, sp.total_steps)):
            for mode in ("output", "state", "gate"):
                def fault(o, outs, nxt, k=k, mode=mode):
                    if o != k:
                        return outs, nxt
                    if mode == "output":
                        outs[-1] = bytes([outs[-1][0] ^ 1]) + outs[-1][1:]
                    elif mode == "state" and nxt is not None:
                        exported = S.decode_step_spec(sp.step_spec(o))["state_export"] != 0xFF
                        nxt = bytes([nxt[0] ^ 1]) + nxt[1:]
                        if exported:
                            outs[0] = nxt
                    elif mode == "gate" and len(outs) > 1:
                        outs[1] = struct.pack("<i", 0 if struct.unpack("<i", outs[1])[0] else 1)
                    return outs, nxt
                n = next_nonce()
                h, c = execute(sp, values, n, fault=fault)
                if c.root != h.root:
                    out.append(scenario_against(f"{name}-k{k}-{mode}", sp, values, n, c, h))
            d = S.decode_step_spec(sp.step_spec(k))
            for index in range(len(d["inputs"])):
                n = next_nonce()
                h, c = execute(sp, values, n, input_fault=lambda o, i, v, k=k, index=index:
                               v if (o, i) != (k, index) else bytes([v[0] ^ 1]) + v[1:])
                if c.root != h.root:
                    out.append(scenario_against(f"{name}-k{k}-input{index}", sp, values, n, c, h))
            if d["state_scheme"]:
                n = next_nonce()
                h, c = execute(sp, values, n, prior_fault=lambda o, p, k=k:
                               p if o != k else (bytes(len(p)) if any(p) else b"\x01" + p[1:]))
                if c.root != h.root:
                    out.append(scenario_against(f"{name}-k{k}-prior", sp, values, n, c, h))
        # Structural lies, each under a fresh run.
        rep = next((bi for bi, b in enumerate(sp.blocks) if b.kind == 2), None)
        lies = []
        if rep is not None:
            blk, last = sp.blocks[rep], honest.last_running[rep]
            if last >= 1:
                def early(c, rep=rep, last=last, blk=blk):
                    for e in range(blk.body_len):
                        c.leaves[sp.ordinal_of(rep, last, e)] = None
                lies.append(("early-stop", early))
            if last + 1 < blk.k:
                def extra(c, rep=rep, last=last):
                    c.leaves[sp.ordinal_of(rep, last + 1, 0)] = c.leaves[sp.ordinal_of(rep, last, 0)]
                lies.append(("extra-iteration", extra))

            def empty0(c, rep=rep):
                c.leaves[sp.ordinal_of(rep, 0, 0)] = None
            lies.append(("empty-iteration-0", empty0))
        else:
            def empty_step(c):
                c.leaves[0] = None
            lies.append(("empty-step", empty_step))
        if sp.out_specs:
            def out_entry(c):
                c.out_entries[0] = c.out_entries[0][:23] + bytes(32)
            lies.append(("out-entry", out_entry))
        for lie, edit in lies:
            n = next_nonce()
            h, _ = execute(sp, values, n)
            c = h.clone()
            edit(c)
            c.rebuild()
            out.append(scenario_against(f"{name}-{lie}", sp, values, n, c, h))
        # Claims against an honest run must rule for E: every claim at
        # sampled leaves, and OUT claims naming every iteration. Each claim
        # runs under its own run, so its openings are rebuilt for it.
        def honest_run():
            n = next_nonce()
            h, _ = execute(sp, values, n)
            _tdata, refs, run = context(sp, values, n)
            return n, h, G.RunRecord(PLAN_ID, run, sp, h.root_bytes, refs), G.Executor(h)

        for k in rng.sample(range(sp.total_steps), min(3, sp.total_steps)):
            _n, h0, rec0, ex0 = honest_run()
            for i in range(len(T.honest_claims(rec0, ex0, h0, k))):
                n, h, record, ex = honest_run()
                cname, kw = T.honest_claims(record, ex, h, k)[i]
                try:
                    out.append(scenario_against(f"{name}-honest-k{k}-{cname}{kw.get('index', '')}", sp, values, n,
                                                h, h, target=sp.position_of(k), claim=(cname, kw)))
                except G.Refused:
                    pass
        # Constant reads opened with another constant's ConstSpec: the
        # referee must refuse the claim (the dispute stays open).
        if len(sp.const_specs) >= 2:
            for k in range(sp.total_steps):
                d = S.decode_step_spec(sp.step_spec(k))
                for i, (_h, prod, _init) in enumerate(d["inputs"]):
                    pk, a, src, _c, dd = S.decode_producer(prod)
                    if pk not in (3, 5) or (pk == 5 and src != 3):
                        continue
                    other = next(c for c in sorted(sp.const_specs) if c != a)
                    n, h, record, ex = honest_run()
                    claims = [c for c in T.honest_claims(record, ex, h, k) if c[0] == "EDGE" and c[1]["index"] == i]
                    t = X.record(record, h, h, DEPTH, target=sp.position_of(k), claim=claims[0])
                    forged = dict(claims[0][1], const_opening=sp.opening(sp.const_leaf_index(other)))
                    try:  # the Python referee refuses the forged opening
                        probe = X.record(record, h, h, DEPTH, target=sp.position_of(k), claim=("EDGE", forged))
                        raise AssertionError(f"forged constant opening accepted: {probe['ruling']}")
                    except G.Refused:
                        pass
                    body = bytearray(W.claim_body(sp, "STEP_DESCEND", sp.position_of(k), "EDGE", claims[0][1]))
                    head = W.claim_body(sp, "STEP_DESCEND", sp.position_of(k), "SHAPE", claims[0][1])
                    rest = (struct.pack("<I", sp.const_leaf_index(other)) + W.spec_opening(forged["const_opening"])
                            + (W.chunk_opening(forged["chunk_opening"]) if pk == 5 else b""))
                    body = bytes(body[:len(head)]) + rest
                    tdata, refs, _run = context(sp, values, n)
                    out.append({"name": f"{name}-forged-const-k{k}.{i}", "nonce": n.hex(), "template_data": tdata.hex(),
                                "refs": [refs[e].hex() for e in sorted(refs)], "root_bytes": h.root_bytes.hex(),
                                **t, "claim": body.hex(), "claim_name": "EDGE", "ruling": "refused"})
        # Kind 6 reads (step inputs and graph outputs) claimed at every
        # iteration up to K + 1. Past the block, the challenger supplies the
        # next block's real leaves: the bound must still rule for E.
        targets = [("OUT", j, 0, raw[32:56]) for j, raw in enumerate(sp.out_specs)]
        for k in range(sp.total_steps):
            for i, (_h, prod, _init) in enumerate(S.decode_step_spec(sp.step_spec(k))["inputs"]):
                targets.append(("EDGE", k, i, prod))
        for cname, at, index, prod in targets:
            pk, a, _b, c, _d = S.decode_producer(prod)
            if pk != 6:
                continue
            block = sp.blocks[a]
            for t in range(block.k + 2):
                o = block.base + t * block.body_len + c
                if o >= sp.total_steps:
                    continue
                n, h, record, ex = honest_run()
                kw = {"t": t, "producer_opening": ex.leaf_opening(o)}
                if t != block.k - 1:
                    g = block.base + t * block.body_len + block.gate_entry
                    if g < sp.total_steps:
                        kw["gate_opening"] = ex.leaf_opening(g)
                        gate = h.values.get((g, block.gate_port))
                        kw["gate_value"] = gate if gate is not None and len(gate) == 4 else None
                if cname == "OUT":
                    kw["spec_opening"] = sp.opening(sp.out_leaf_index(at))
                    target, kind = at, "OUT_DESCEND"
                else:
                    kw.update(spec_opening=sp.opening(sp.step_leaf_index(at)), index=index)
                    target, kind = sp.position_of(at), "STEP_DESCEND"
                try:
                    out.append(scenario_against(f"{name}-kind6-{cname}{at}.{index}-t{t}", sp, values, n, h, h,
                                                target=target, claim=(cname, kw), kind=kind))
                except G.Refused:
                    pass
    for s in out:
        assert s["ruling"] in ("C", "E", "refused")
    return out


if __name__ == "__main__":
    scenarios = build()
    OUT.write_text(json.dumps(scenarios, indent=0, sort_keys=True) + "\n")
    print(OUT, len(scenarios), {r: sum(1 for s in scenarios if s["ruling"] == r) for r in ("C", "E")},
          sorted({s["claim_name"] for s in scenarios}))
