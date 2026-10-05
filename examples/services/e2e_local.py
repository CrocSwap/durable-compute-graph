"""The executor service and the watchtower as separate processes on a local
validator (alpha E3, design executor-watchtower-v1 §6).

    PYTHONPATH=python python examples/services/e2e_local.py ALPHA_IMAGE.so

The driver starts `solana-test-validator` with the alpha image (8 ticks per
slot, about 50 ms, close to testnet's 40 ms), creates a template for the
traced chunked-checksum plan, and starts two processes:

- **executor**: the application's executor. It creates and commits one run
  per scenario (honest, or lying as the scenario says), publishes each run's
  inputs to a shared directory (the watchtower's input source), and runs
  the executor service until its runs are closed. In the `silent` scenario
  it never answers that run's disputes.
- **watchtower**: watches the template, checks every run, and challenges.

Each prints one JSON line per action. The driver checks the outcome per
scenario: an honest run finalizes unchallenged; every lie is ruled for the
challenger; every run ends closed. Nothing leaves this machine.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / "hello-graph"))

from dcg.disputes_v21 import client as CL  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402
from dcg.disputes_v21 import wire as W  # noqa: E402
from dcg.graph_client import GraphClient  # noqa: E402

SCENARIOS = {
    "honest": {},
    "state-lie": {"fault": "state", "step": 2},
    "input-lie": {"input_fault": True, "step": 4},
    "silent": {"fault": "state", "step": 1, "silent": True},
}
DEPTH = 3
PLAN_ID = bytes([7]) * 32


def plan():
    import io
    from contextlib import redirect_stderr

    import traced_dispute as T
    with redirect_stderr(io.StringIO()):
        return T.checksum.plan()


def faulty_execute(scenario: dict):
    def execute(sp, plan_id, run_id, values):
        kw = {}
        if scenario.get("fault") == "state":
            def fault(o, outs, nxt, k=scenario["step"]):
                if o != k:
                    return outs, nxt
                nxt = bytes([nxt[0] ^ 1]) + nxt[1:]
                outs[0] = nxt
                return outs, nxt
            kw["fault"] = fault
        if scenario.get("input_fault"):
            kw["input_fault"] = lambda o, i, v, k=scenario["step"]: (bytes([v[0] ^ 1]) + v[1:]) if o == k and i == 0 else v
        return R.execute(sp, plan_id, run_id, values, **kw)
    return execute


def key(path: Path) -> Keypair:
    return Keypair.from_bytes(bytes(json.loads(path.read_text())))


def client(cfg: dict, payer: Keypair) -> CL.DisputeClient:
    gc = GraphClient(cfg["rpc"], Pubkey.from_string(cfg["program"]), payer, timeout=30)
    return CL.DisputeClient(gc)


# --- the executor process ----------------------------------------------------------------------
def role_executor(cfg: dict) -> int:
    from dcg.services.executor import ExecutorService, Plan, log

    run_dir = Path(cfg["dir"])
    executor, payer = key(run_dir / "executor.json"), key(run_dir / "payer.json")
    cl = client(cfg, payer)
    sp = plan()
    template = Pubkey.from_string(cfg["template"])
    template_id = bytes.fromhex(cfg["template_id"])
    by_run: dict[str, dict] = {}

    def execute(sp_, plan_id, run_id, values):
        return faulty_execute(by_run[run_id.hex()])(sp_, plan_id, run_id, values)

    service = ExecutorService(cl, executor, str(run_dir / "executor-journal.json"), {str(template): Plan(sp, PLAN_ID, DEPTH)},
                              execute=execute)
    rng = random.Random(7)
    silent: set[str] = set()
    for name, scenario in SCENARIOS.items():
        values = {0: struct.pack("<64i", *[rng.randint(-1000, 1000) for _ in range(64)])}
        refs = [R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()]
        nonce = os.urandom(32)
        run_id = R.run_id(template_id, nonce, refs, bytes(executor.pubkey()))
        by_run[run_id.hex()] = scenario
        committed = execute(sp, PLAN_ID, run_id, values)
        run = cl.init_run(template, template_id, nonce, executor.pubkey(), refs, payer)
        # The application publishes the inputs (the watchtower's input source).
        (run_dir / "inputs" / str(run)).mkdir(parents=True, exist_ok=True)
        for e, v in values.items():
            (run_dir / "inputs" / str(run) / f"{e}.bin").write_bytes(v)
        cl.commit(run, template, committed.root_bytes, executor)
        log(event="committed", scenario=name, run=str(run))
        if scenario.get("silent"):
            silent.add(str(run))
        else:
            service.add_run(run, template, run_id, values)
    (run_dir / "runs.json").write_text(json.dumps({name: None for name in SCENARIOS}))
    deadline = time.monotonic() + cfg["seconds"]
    while time.monotonic() < deadline:
        service.tick()
        if all(e["done"] for e in service.journal.data["runs"].values()):
            log(event="executor_done")
            return 0
        time.sleep(1.0)
    log(event="executor_timeout_overall")
    return 1


# --- the watchtower process --------------------------------------------------------------------
def role_watchtower(cfg: dict) -> int:
    from dcg.services.watchtower import Watched, Watchtower, log

    run_dir = Path(cfg["dir"])
    challenger = key(run_dir / "challenger.json")
    cl = client(cfg, challenger)
    sp = plan()

    def inputs(run: Pubkey, eid: int, ref: bytes) -> bytes | None:
        path = run_dir / "inputs" / str(run) / f"{eid}.bin"
        return path.read_bytes() if path.exists() else None

    tower = Watchtower(cl, challenger, str(run_dir / "watchtower-journal.json"),
                       [Watched(Pubkey.from_string(cfg["template"]), sp, PLAN_ID, inputs, DEPTH)])
    deadline = time.monotonic() + cfg["seconds"]
    while time.monotonic() < deadline:
        tower.tick()
        runs = tower.journal.data["runs"]
        disputes = tower.journal.data["disputes"]
        if (len(runs) >= len(SCENARIOS) and all(r["state"] in ("ok", "closed") for r in runs.values())
                and all(d.get("done") for d in disputes.values())):
            log(event="watchtower_done")
            return 0
        time.sleep(1.0)
    log(event="watchtower_timeout_overall")
    return 1


# --- the driver ----------------------------------------------------------------------------------
def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_key(path: Path, k: Keypair) -> None:
    path.write_text(json.dumps(list(bytes(k))))
    os.chmod(path, 0o600)


def driver(image: Path, seconds: int) -> int:
    run_dir = Path(tempfile.mkdtemp(prefix="dcg-e3-", dir="/private/tmp" if sys.platform == "darwin" else None))
    program = Keypair().pubkey()
    rpc_port, faucet_port, base = _port(), _port(), random.randrange(30_000, 60_000, 100)
    rpc = f"http://127.0.0.1:{rpc_port}"
    validator = subprocess.Popen(
        [shutil.which("solana-test-validator") or "solana-test-validator", "--reset", "--ledger", str(run_dir / "ledger"),
         "--upgradeable-program", str(program), str(image), "none", "--ticks-per-slot", "8",
         "--rpc-port", str(rpc_port), "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
         "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
        stdout=(run_dir / "validator.log").open("wb"), stderr=subprocess.STDOUT)
    procs = []
    try:
        admin = Keypair()
        gc = GraphClient(rpc, program, admin, timeout=30)
        t0 = time.monotonic()
        while True:
            try:
                gc.slot()
                break
            except Exception:
                if validator.poll() is not None or time.monotonic() - t0 > 60:
                    raise RuntimeError(f"validator did not start; see {run_dir / 'validator.log'}")
                time.sleep(0.25)
        keys = {name: Keypair() for name in ("executor", "challenger", "payer")}
        for name, k in keys.items():
            write_key(run_dir / f"{name}.json", k)
        for k in [admin, *keys.values()]:
            gc.rpc("requestAirdrop", [str(k.pubkey()), 50_000_000_000])
        time.sleep(2)
        cl = CL.DisputeClient(gc)
        sp = plan()
        tdata = W.template_data(sp, DEPTH, PLAN_ID, slot_ms=50.0)
        import hashlib
        template = cl.create_template(tdata, admin)
        cfg = {"rpc": rpc, "program": str(program), "dir": str(run_dir), "template": str(template),
               "template_id": hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest().hex(), "seconds": seconds}
        (run_dir / "config.json").write_text(json.dumps(cfg))
        env = {**os.environ}
        for role in ("watchtower", "executor"):
            procs.append(subprocess.Popen([sys.executable, str(HERE), "--role", role, "--config", str(run_dir / "config.json")],
                                          stdout=(run_dir / f"{role}.log").open("w"), stderr=subprocess.STDOUT, env=env))
        codes = [p.wait(timeout=seconds + 60) for p in procs]
        return report(run_dir, codes, time.monotonic() - t0)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        validator.terminate()
        validator.wait(timeout=20)


def report(run_dir: Path, codes: list[int], seconds: float) -> int:
    lines = {}
    for role in ("executor", "watchtower"):
        lines[role] = []
        for line in (run_dir / f"{role}.log").read_text().splitlines():
            try:
                lines[role].append(json.loads(line))
            except json.JSONDecodeError:
                lines[role].append({"event": "text", "line": line})
    runs = {e["run"]: e["scenario"] for e in lines["executor"] if e.get("event") == "committed"}
    outcome = {name: {"run": run} for run, name in runs.items()}
    for e in lines["watchtower"]:
        name = runs.get(e.get("run"))
        if e.get("event") == "run_ok" and name:
            outcome[name]["watchtower"] = "ok"
        if e.get("event") == "open" and name:
            outcome[name]["watchtower"] = "challenged"
            outcome[name]["dispute"] = e["dispute"]
        if e.get("event") in ("settle", "executor_timeout") and e.get("ruling"):
            for o in outcome.values():
                if o.get("dispute") == e.get("dispute"):
                    o["ruling"] = e["ruling"]
        if e.get("event") == "settled_elsewhere" and e.get("outcome") == "refuted":
            for o in outcome.values():
                if o.get("dispute") == e.get("dispute"):
                    o["ruling"] = "C"
        if e.get("event") == "executor_timeout":
            for o in outcome.values():
                if o.get("dispute") == e.get("dispute"):
                    o["timeout"] = True
                    if e.get("state") == "closed":
                        o["ruling"] = "C"
    errors = [e for role in lines for e in lines[role] if e.get("event") in ("error", "text")]
    ok = (all(c == 0 for c in codes)
          and outcome["honest"].get("watchtower") == "ok"
          and all(outcome[n].get("watchtower") == "challenged" and outcome[n].get("ruling") == "C"
                  for n in ("state-lie", "input-lie", "silent")))
    print(json.dumps({"ok": ok, "exit_codes": codes, "seconds": round(seconds, 1), "outcome": outcome,
                      "errors": errors[:10], "dir": str(run_dir)}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--role")
    ap.add_argument("--config")
    ap.add_argument("--seconds", type=int, default=300)
    a = ap.parse_args()
    if a.role:
        cfg = json.loads(Path(a.config).read_text())
        raise SystemExit(role_executor(cfg) if a.role == "executor" else role_watchtower(cfg))
    raise SystemExit(driver(Path(a.image), a.seconds))
