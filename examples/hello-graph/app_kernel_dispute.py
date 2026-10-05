"""An application kernel disputed on chain (tag 227; alpha R4 smoke).

One step runs the example application kernel `dcg-test-sha-v1` (SHA-256 of
its input, resolved from the image's `dcg-alpha/1` manifest) over a 256-byte
input. The lying executor commits a corrupted digest; the challenger's STEP
claim replays the kernel on chain and must win. A control run commits
honestly and is challenged with the same STEP claim: the executor must win.
This is the program path the kernel kit shares (`kernel_kit::step_kernel_call`).

    export DCG_PAYER_KEYPAIR=... DCG_PROGRAM_ID=... DCG_RPC_URL=https://testnet.fogo.io
    PYTHONPATH=python python/.venv/bin/python examples/hello-graph/traced_dispute.py [--settle]

With --settle (alpha E4), a third, unchallenged run is added, and every run
is then settled with `settle_and_reclaim` (rulings advanced, pot paid,
disputes, caches and runs closed, the honest run finalized after its
window), and the template is retired and closed.
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
from dcg import v21
from dcg.graph_client import GraphClient

PLAN_ID = bytes([7]) * 32
DEPTH = 3
LIED_STEP = 0  # the step whose output the executor corrupts


@v21.trace
def checksum(data: v21.Raw(bytes=256)):
    """SHA-256 of a 256-byte input by the application kernel."""
    return v21.call("dcg-test-sha-v1", data, out=[(32, False)])


def plan():
    print(checksum.explain(), file=sys.stderr)
    return checksum.plan()


def main() -> int:
    gc = GraphClient.from_environment()
    cl = CL.DisputeClient(gc)
    # The run's payer may not be its executor (the remainder deterrent).
    executor, challenger = Keypair(), Keypair()
    cl.fund(executor.pubkey(), 200_000_000)
    cl.fund(challenger.pubkey(), 200_000_000)
    sp = plan()
    rng = random.Random(int.from_bytes(os.urandom(4), "little"))
    values = {0: rng.randbytes(256)}
    tdata = W.template_data(sp, DEPTH, PLAN_ID)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
    template = cl.create_template(tdata, gc.payer)
    refs = {e: R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()}
    settle = "--settle" in sys.argv
    balance0 = gc.rpc("getBalance", [str(gc.payer.pubkey()), {"commitment": "confirmed"}])["value"]
    results, runs = [], []
    for case in ("lie", "honest") + (("unchallenged",) if settle else ()):
        nonce = os.urandom(32)
        run_id = R.run_id(template_id, nonce, list(refs.values()), bytes(executor.pubkey()))
        honest = R.execute(sp, PLAN_ID, run_id, values)

        def fault(o, outs, nxt):
            if o == LIED_STEP:
                outs[0] = bytes([outs[0][0] ^ 1]) + outs[0][1:]
            return outs, nxt

        committed = R.execute(sp, PLAN_ID, run_id, values, fault=fault) if case == "lie" else honest
        record = G.RunRecord(PLAN_ID, run_id, sp, committed.root_bytes, refs)
        if case == "lie":
            t = X.record(record, committed, honest, DEPTH, target=sp.position_of(LIED_STEP),
                         claim=step_claim(sp, honest, LIED_STEP))
        else:
            t = X.record(record, committed, honest, DEPTH, target=sp.position_of(LIED_STEP),
                         claim=step_claim(sp, honest, LIED_STEP))
        run = cl.init_run(template, template_id, nonce, executor.pubkey(), list(refs.values()), gc.payer)
        cl.commit(run, template, committed.root_bytes, executor)
        runs.append(run)
        if case == "unchallenged":
            results.append(True)
            continue
        out = cl.play(run, template, t, executor, challenger)
        out.update(case=case, claim=t["claim_name"], oracle=t["ruling"], rounds=len(t["rounds"]),
                   claim_bytes=len(t["claim"]) // 2, run=str(run), run_status=cl.run_status(run),
                   )
        print(json.dumps(out), flush=True)
        results.append(out["ruling"] == out["oracle"] == ("C" if case == "lie" else "E"))
    if settle:
        # E4: settle every run and reclaim its rent (the challenge window is
        # the template's, so the unchallenged run waits for it).
        # The template's address is fixed by its plan, so earlier runs of
        # this example may still hold it open: settle those too.
        for run in runs + [r for r in cl.runs_of(template) if r not in runs]:
            out = cl.settle_and_reclaim(run, wait=80.0)
            print(json.dumps({"run": str(run), **out}), flush=True)
            results.append(out["state"] == "closed")
        if gc.account(template)[134] == 0:
            cl.retire_template(template, gc.payer)
        cl.close_template(template, gc.payer)
        balance1 = gc.rpc("getBalance", [str(gc.payer.pubkey()), {"commitment": "confirmed"}])["value"]
        print(json.dumps({"template_closed": gc.account(template) is None,
                          "payer_net_lamports": balance1 - balance0}), flush=True)
        results.append(gc.account(template) is None)
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
