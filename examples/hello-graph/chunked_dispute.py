"""A chunked kernel disputed on chain (tag 227, disputes v2.1).

A chunked sum over a 4-chunk input (256 bytes, 64-byte chunks), then a step
that reads its result (kind 6), committed by an executor that corrupts the
running state at chunk 2 and carries on consistently. The Python challenger
finds the first divergence; every move is sent to the program, which must
rule for the challenger. A control run commits honestly and is challenged
with a STEP claim at the same chunk-step: the program must rule for the
executor.

    export DCG_PAYER_KEYPAIR=... DCG_PROGRAM_ID=... DCG_RPC_URL=https://testnet.fogo.io
    PYTHONPATH=python python/.venv/bin/python examples/hello-graph/chunked_dispute.py
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import struct
import sys

from solders.keypair import Keypair

from dcg.disputes_v21 import client as CL
from dcg.disputes_v21 import game as G
from dcg.disputes_v21 import plans as P
from dcg.disputes_v21 import run as R
from dcg.disputes_v21 import spec as S
from dcg.disputes_v21 import transcript as X
from dcg.disputes_v21 import wire as W
from dcg.graph_client import GraphClient

PLAN_ID = bytes([7]) * 32
DEPTH = 3
LIED_STEP = 2  # the chunk-step whose running state the executor corrupts


def plan():
    b = P.PlanBuilder()
    b.chunked_input(0, 4 * 64, 6)
    blk = b.chunked_reduce("sumchunk_i32", 0)
    b.enumerated([P.Step("head_i32", (P.Input(S.producer(6, blk, 0, 0), 8),), ((0, 4, True),))])
    b.output(S.producer(6, blk, 0, 0), 8)
    return b.build()


def main() -> int:
    gc = GraphClient.from_environment()
    cl = CL.DisputeClient(gc)
    # The run's payer may not be its executor (the remainder deterrent).
    executor, challenger = Keypair(), Keypair()
    cl.fund(executor.pubkey(), 200_000_000)
    cl.fund(challenger.pubkey(), 200_000_000)
    sp = plan()
    rng = random.Random(int.from_bytes(os.urandom(4), "little"))
    words = [rng.randint(-1000, 1000) for _ in range(64)]
    values = {0: struct.pack("<64i", *words)}
    tdata = W.template_data(sp, DEPTH, PLAN_ID)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
    template = cl.create_template(tdata, gc.payer)
    refs = {e: R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()}
    results = []
    for case in ("lie", "honest"):
        nonce = os.urandom(32)
        run_id = R.run_id(template_id, nonce, list(refs.values()), bytes(executor.pubkey()))
        honest = R.execute(sp, PLAN_ID, run_id, values)

        def fault(o, outs, nxt):
            if o != LIED_STEP:
                return outs, nxt
            nxt = bytes([nxt[0] ^ 1]) + nxt[1:]
            outs[0] = nxt  # the export stays consistent: only replay can tell
            return outs, nxt

        committed = R.execute(sp, PLAN_ID, run_id, values, fault=fault) if case == "lie" else honest
        record = G.RunRecord(PLAN_ID, run_id, sp, committed.root_bytes, refs)
        if case == "lie":
            t = X.record(record, committed, honest, DEPTH)
        else:
            t = X.record(record, committed, honest, DEPTH, target=sp.position_of(LIED_STEP),
                         claim=step_claim(sp, honest, LIED_STEP))
        run = cl.init_run(template, template_id, nonce, executor.pubkey(), list(refs.values()), gc.payer)
        cl.commit(run, template, committed.root_bytes, executor)
        out = cl.play(run, template, t, executor, challenger)
        out.update(case=case, claim=t["claim_name"], oracle=t["ruling"], rounds=len(t["rounds"]),
                   claim_bytes=len(t["claim"]) // 2, run=str(run), run_status=cl.run_status(run),
                   sum=sum(words))
        print(json.dumps(out), flush=True)
        results.append(out["ruling"] == out["oracle"] == ("C" if case == "lie" else "E"))
    print(json.dumps({"transactions": cl.sent, "all_agree": all(results)}))
    return 0 if all(results) else 1


def step_claim(sp, honest, k):
    """A STEP claim at chunk-step k with honest witnesses (the control)."""
    d = S.decode_step_spec(sp.step_spec(k))
    witness = [G.honest_value(honest, sp, prod) for _h, prod, _i in d["inputs"]]
    pk, a, *_ = S.decode_producer(d["state_predecessor"])
    state = honest.states[a] if pk == 1 else bytes(d["state_size"])
    return "STEP", {"spec_opening": sp.opening(sp.step_leaf_index(k)), "witness": witness, "state_witness": state}


if __name__ == "__main__":
    sys.exit(main())
