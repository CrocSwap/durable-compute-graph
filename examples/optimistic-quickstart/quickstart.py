"""Optimistic mode in one file: trace a graph, run it twice, and watch the
watchtower convict the run that lies (docs/optimistic-quickstart.md).

What it does:
1. traces `checksum` below into a v2.1 plan and creates a template for it;
2. commits two runs of the plan: an honest one, and one whose executor
   corrupts the running state at one step and carries on consistently;
3. runs the executor service (which answers disputes) and a watchtower
   (which checks every run and challenges a wrong one), in this process;
4. waits until the lie is convicted and both runs are settled and closed,
   then closes the template and prints what the payer spent.

On a local chain (`dcg dev` in another terminal, then source its env file):

    PYTHONPATH=python python examples/optimistic-quickstart/quickstart.py

On the shared testnet program, set DCG_RPC_URL, DCG_PROGRAM_ID and
DCG_PAYER_KEYPAIR yourself (docs/optimistic-quickstart.md). The services'
own logs go to `services.log` in the run directory it prints.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import time

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg import v21
from dcg.disputes_v21 import client as CL
from dcg.disputes_v21 import run as R
from dcg.disputes_v21 import wire as W
from dcg.graph_client import GraphClient
from dcg.services.executor import ExecutorService, Plan
from dcg.services.watchtower import Watched, Watchtower

PLAN_ID = bytes([7]) * 32  # your application's name for this plan
DEPTH = 3  # reveal depth: tree levels the executor opens per round (1..4)
LIED_STEP = 2  # the step whose state the lying executor corrupts


# 1. The graph. Edit this: any straight-line function of kernels traces.
@v21.trace
def checksum(data: v21.Chunked(bytes=256, chunk=64)):
    """A running sum over 4 chunks of 64 bytes, then a step that reads it."""
    acc = v21.reduce("sumchunk_i32", data)
    v21.call("head_i32", acc)
    return acc


def sample_inputs(traced, rng: random.Random) -> dict[int, bytes]:
    """Random inputs for every input the traced function declares, so the
    graph can change without editing this: an i32 for `v21.Scalar`, and i32
    words in -1000..1000 for byte inputs (random bytes if not whole words)."""
    values = {}
    for eid, decl in enumerate(traced._declarations()):
        if decl is v21.Scalar:
            values[eid] = struct.pack("<i", rng.randint(-1000, 1000))
        elif decl.bytes % 4 == 0:
            values[eid] = struct.pack(f"<{decl.bytes // 4}i", *[rng.randint(-1000, 1000) for _ in range(decl.bytes // 4)])
        else:
            values[eid] = bytes(rng.randrange(256) for _ in range(decl.bytes))
    return values


def lying_execute(sp, plan_id, run_id, values):
    """The executor's computation, with a lie at LIED_STEP."""
    def fault(o, outs, nxt):
        if o != LIED_STEP:
            return outs, nxt
        nxt = bytes([nxt[0] ^ 1]) + nxt[1:]
        outs[0] = nxt  # consistent from here on: only replaying the step can tell
        return outs, nxt
    return R.execute(sp, plan_id, run_id, values, fault=fault)


class Events(io.TextIOBase):
    """Keeps the services' JSON logs and prints the interesting ones."""

    def __init__(self, path: str, names: dict[str, str]):
        self.f, self.names, self.buf = open(path, "a"), names, ""

    def write(self, s: str) -> int:
        self.f.write(s)
        self.f.flush()
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.show(e)
        return len(s)

    def show(self, e: dict) -> None:
        name = self.names.get(e.get("run", ""), "")
        ev = e.get("event")
        text = {
            "run_ok": f"watchtower: the {name} run matches its inputs",
            "open": f"watchtower: the {name} run does not match; dispute opened",
            "pick": "watchtower: descending toward the first wrong step",
            "claim": f"watchtower: claim sent ({e.get('claim')})",
            "executor_timeout": "watchtower: the executor missed a deadline",
            "settled_elsewhere": "watchtower: its dispute was already settled (the executor's service settles too; either may go first)",
            "error": f"error: {e.get('error')}",
        }.get(ev)
        if ev == "settle" and e.get("ruling"):
            text = f"ruled: {'challenger wins' if e['ruling'] == 'C' else e['ruling']}; watchtower settles ({e.get('state')})"
        if ev == "settle" and e.get("run") and e.get("state") == "closed":
            text = f"executor: the {self.names.get(e['run'], '')} run is settled and closed"
        if text:
            print(f"  {text}", file=sys.__stdout__, flush=True)


def balance(gc: GraphClient, key) -> int:
    return gc.rpc("getBalance", [str(key), {"commitment": "confirmed"}])["value"]


def main() -> int:
    gc = GraphClient.from_environment()
    local = any(h in gc.rpc_url for h in ("127.0.0.1", "localhost"))
    run_dir = tempfile.mkdtemp(prefix="dcg-quickstart-", dir="/private/tmp" if sys.platform == "darwin" else None)
    os.chmod(run_dir, 0o700)
    print(f"chain {gc.rpc_url}, program {gc.program_id}; run directory {run_dir}")

    # 2. The plan and its template. Testnet windows leave room for a service
    #    far from its RPC node (docs/services.md).
    sp = checksum.plan()
    print(checksum.explain())
    windows = {} if local else {"challenge_window": 3_000, "phase_window": 1_500}
    tdata = W.template_data(sp, DEPTH, PLAN_ID, slot_ms=50.0 if local else 40.0, **windows)
    template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
    cl = CL.DisputeClient(gc)
    payer0 = balance(gc, gc.payer.pubkey())
    template = cl.create_template(tdata, gc.payer)
    print(f"template {template}")

    # 3. The parties. The executor posts a bond per run, the challenger one
    #    per dispute; both are funded by the payer here.
    executor, challenger = Keypair(), Keypair()
    for k in (executor, challenger):
        cl.fund(k.pubkey(), 100_000_000)
    published: dict[str, dict[int, bytes]] = {}  # the application's input store
    names: dict[str, str] = {}
    lies: set[str] = set()

    def execute(sp_, plan_id, run_id, values):
        return (lying_execute if run_id.hex() in lies else R.execute)(sp_, plan_id, run_id, values)

    def inputs(run, eid, ref):
        return published.get(str(run), {}).get(eid)

    events = Events(os.path.join(run_dir, "services.log"), names)
    with contextlib.redirect_stdout(events):
        gce, gcw = GraphClient(gc.rpc_url, gc.program_id, gc.payer), GraphClient(gc.rpc_url, gc.program_id, challenger)
        service = ExecutorService(CL.DisputeClient(gce), executor,
                                  os.path.join(run_dir, "executor.json"), {str(template): Plan(sp, PLAN_ID, DEPTH)},
                                  execute=execute)
        tower = Watchtower(CL.DisputeClient(gcw), challenger,
                           os.path.join(run_dir, "watchtower.json"),
                           [Watched(template, sp, PLAN_ID, inputs, DEPTH)])

    # 4. Two runs: inputs, run id, commitment, then the commit on chain.
    rng = random.Random()
    for case in ("honest", "lying"):
        values = sample_inputs(checksum, rng)
        refs = [R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()]
        nonce = os.urandom(32)
        run_id = R.run_id(template_id, nonce, refs, bytes(executor.pubkey()))
        if case == "lying":
            lies.add(run_id.hex())
        committed = execute(sp, PLAN_ID, run_id, values)
        run = cl.init_run(template, template_id, nonce, executor.pubkey(), refs, gc.payer)
        published[str(run)] = values
        names[str(run)] = case
        with contextlib.redirect_stdout(events):
            service.add_run(run, template, run_id, values)  # journaled before the commit
        cl.commit(run, template, committed.root_bytes, executor)
        print(f"committed the {case} run {run}")

    # 5. Tick both services until every run is settled and closed. The honest
    #    run finalizes only after its challenge window.
    print("waiting for the watchtower and the executor (2-3 minutes locally, about 5 on testnet)...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < 900:
        with contextlib.redirect_stdout(events):
            service.tick()
            tower.tick()
        runs_done = all(e["done"] for e in service.journal.data["runs"].values())
        disputes_done = all(d.get("done") for d in tower.journal.data["disputes"].values())
        if runs_done and disputes_done and tower.journal.data["disputes"]:
            break
        time.sleep(1.0)
    else:
        print("timed out; see services.log")
        return 1

    # 6. The outcome, read from each run's receipt on chain.
    status = {CL.RUN_FINAL: "FINAL (accepted)", CL.RUN_REFUTED: "REFUTED (the executor's bond was slashed)"}
    for run, case in names.items():
        print(f"the {case} run: {status.get(cl.run_status(Pubkey.from_string(run)), '?')}")

    # What each party gained or lost (the payer funded both with 100,000,000).
    for name, k in (("executor", executor), ("challenger", challenger)):
        print(f"{name}: {balance(gc, k.pubkey()) - 100_000_000:+,} lamports (bonds and rent, less its fees)")

    # 7. Close the template and count the cost.
    cl.retire_template(template, gc.payer)
    cl.close_template(template, gc.payer)
    returns = []
    for k in (executor, challenger):  # return what is left to the payer
        left = balance(gc, k.pubkey())
        if left > 5_000:
            returns.append(GraphClient(gc.rpc_url, gc.program_id, k))
            CL.DisputeClient(returns[-1]).fund(gc.payer.pubkey(), left - 5_000)
    spent = payer0 - balance(gc, gc.payer.pubkey())
    txs = sum(len(c.signatures) for c in (gc, gce, gcw, *returns))
    receipts = 2 * gc.rpc("getMinimumBalanceForRentExemption", [CL.RECEIPT_BYTES])
    print(f"done in {time.monotonic() - t0:.0f} s, {txs} transactions. The payer spent {spent:,} lamports: {receipts:,} stay in the two "
          f"run receipts (each run's permanent record), the rest is fees. Every other account was closed and its "
          f"rent returned; the slashed bond went to the challenger and the payer.")
    print(f"template {template} closed: {gc.account(template) is None}")
    if "--keep" not in sys.argv:
        shutil.rmtree(run_dir, ignore_errors=True)
    else:
        print(f"kept the journals and services.log in {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
