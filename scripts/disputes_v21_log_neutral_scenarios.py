#!/usr/bin/env python3
"""LOG-state claims are neutral on chain (review 10-03, F3).

The program judges SMALL state only; until LOG is implemented there, a STATE
or STEP claim on a LOG-state step is ruled moot (the challenger's bond
returns, nobody is convicted). These scenarios use the Python reference's
LOG plan (`kv_plan`) and record the program's expected ruling, "moot",
instead of the Python referee's LOG ruling. Replayed by the chunked oracle
test with CHUNKED_SCENARIOS=tests/golden/dcg/disputes_v21/log_neutral_scenarios.json.
"""
from __future__ import annotations

import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_s = importlib.util.spec_from_file_location("chunked", ROOT / "scripts/disputes_v21_chunked_scenarios.py")
C = importlib.util.module_from_spec(_s)
_s.loader.exec_module(C)
OUT = ROOT / "tests/golden/dcg/disputes_v21/log_neutral_scenarios.json"


def _scenario(name, sp, values, k, fault=None):
    """One claim at LOG step k. STEP bodies are re-encoded with an empty state
    witness: the program rules neutral after the spec opening and reads no
    further (the wire format has no LOG witness encoding yet)."""
    T, W = C.T, C.W
    n = C.next_nonce()
    h, committed = C.execute(sp, values, n, **({"fault": fault} if fault else {}))
    _tdata, refs, run = C.context(sp, values, n)
    record = C.G.RunRecord(C.PLAN_ID, run, sp, committed.root_bytes, refs)
    claims = dict(T.honest_claims(record, C.G.Executor(committed), committed, k))
    s = C.scenario_against(f"log-k{k}-{name}", sp, values, n, committed, h, target=sp.position_of(k),
                           claim=("STATE", claims["STATE"]))
    if name.endswith("STEP"):
        kw = dict(claims["STEP"], state_witness=b"")
        s["claim"] = W.claim_body(sp, "STEP_DESCEND", sp.position_of(k), "STEP", kw).hex()
        s["claim_name"] = "STEP"
    s["ruling"] = "moot"
    return s


def build() -> list[dict]:
    T = C.T
    sp = T.kv_plan(4)
    values = {0: T.words(list(range(1, 4 * 16 + 1)))}
    out = []
    for k in range(sp.total_steps):
        out.append(_scenario("honest-STATE", sp, values, k))
        out.append(_scenario("honest-STEP", sp, values, k))
    # A LOG lie at step 2 (a wrong output): the STEP claim there is neutral too.
    lie = lambda o, outs, nxt: ([bytes([outs[0][0] ^ 1]) + outs[0][1:]] + outs[1:], nxt) if o == 2 else (outs, nxt)
    out.append(_scenario("output-lie-STEP", sp, values, 2, fault=lie))
    return out


if __name__ == "__main__":
    scenarios = build()
    OUT.write_text(json.dumps(scenarios, indent=0, sort_keys=True) + "\n")
    print(OUT, len(scenarios), sorted({s["claim_name"] for s in scenarios}))
