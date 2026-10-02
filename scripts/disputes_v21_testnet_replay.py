#!/usr/bin/env python3
"""Replay a sample of the chunked oracle scenarios on a live cluster.

Samples up to `--per` scenarios for every (claim, ruling) pair in
tests/golden/dcg/disputes_v21/chunked_scenarios.json, preferring staged and
multi-round ones, and sends each with `dcg.disputes_v21.client`. The
scenarios' executor is the keypair seeded with 0xE1 (as in the oracle test);
it and a fresh challenger are funded from the payer. Prints one JSON line
per scenario and a summary; exits 1 on any disagreement.

    export DCG_PAYER_KEYPAIR=... DCG_PROGRAM_ID=... DCG_RPC_URL=...
    PYTHONPATH=python python/.venv/bin/python scripts/disputes_v21_testnet_replay.py --per 2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from solders.keypair import Keypair  # noqa: E402

from dcg.disputes_v21 import client as CL  # noqa: E402
from dcg.disputes_v21 import wire as W  # noqa: E402
from dcg.graph_client import GraphClient  # noqa: E402

SCENARIOS = ROOT / "tests/golden/dcg/disputes_v21/chunked_scenarios.json"


def sample(scenarios: list[dict], per: int) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for s in scenarios:
        groups.setdefault((s["claim_name"], s["ruling"]), []).append(s)
    out = []
    for key in sorted(groups):
        # Prefer staged claims, then more descent rounds, then early stops.
        ranked = sorted(groups[key], key=lambda s: (-(len(s["claim"]) // 2 > CL.DIRECT_LIMIT), -len(s["rounds"]),
                                                    "early-stop" not in s["name"], s["name"]))
        out += ranked[:per]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per", type=int, default=2)
    args = ap.parse_args()
    gc = GraphClient.from_environment()
    cl = CL.DisputeClient(gc)
    executor, challenger = Keypair.from_seed(bytes([0xE1]) * 32), Keypair()
    chosen = sample(json.loads(SCENARIOS.read_text()), args.per)
    cl.fund(executor.pubkey(), 50_000_000 * len(chosen))
    cl.fund(challenger.pubkey(), 50_000_000 * len(chosen))
    agree = skipped = 0
    t0 = time.monotonic()
    for s in chosen:
        tdata = bytes.fromhex(s["template_data"])
        template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
        template = cl.create_template(tdata, gc.payer)
        refs = [bytes.fromhex(r) for r in s["refs"]]
        flat = b"".join(sorted(refs, key=lambda r: int.from_bytes(r[:4], "little")))
        run_id = hashlib.sha256(b"dcg.run.id.v2.1\x00" + template_id + bytes.fromhex(s["nonce"])
                                + len(refs).to_bytes(4, "little") + flat + bytes(executor.pubkey())).digest()
        if gc.account(cl.pda(b"dcg21run", run_id)) is not None:
            # A recorded run id is fixed by its leaves; one already on this
            # cluster (an earlier, interrupted replay) cannot be replayed.
            print(json.dumps({"name": s["name"], "skipped": "run exists on this cluster"}), flush=True)
            skipped += 1
            continue
        run = cl.init_run(template, template_id, bytes.fromhex(s["nonce"]), executor.pubkey(), refs, gc.payer)
        cl.commit(run, template, bytes.fromhex(s["root_bytes"]), executor)
        out = cl.play(run, template, s, executor, challenger)
        ok = out["ruling"] == s["ruling"]
        agree += ok
        print(json.dumps({"name": s["name"], "claim": s["claim_name"], "oracle": s["ruling"], **out,
                          "rounds": len(s["rounds"]), "claim_bytes": len(s["claim"]) // 2, "agree": ok}), flush=True)
    print(json.dumps({"scenarios": len(chosen), "agree": agree, "skipped": skipped, "transactions": cl.sent,
                      "wall_s": round(time.monotonic() - t0, 1)}))
    return 0 if agree + skipped == len(chosen) else 1


if __name__ == "__main__":
    sys.exit(main())
