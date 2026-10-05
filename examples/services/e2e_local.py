"""The executor service and the watchtower as separate processes on a local
validator (alpha E3, design executor-watchtower-v1 §6).

    PYTHONPATH=python python examples/services/e2e_local.py ALPHA_IMAGE.so [options]

The driver starts `solana-test-validator` with the alpha image (8 ticks per
slot, about 50 ms, close to testnet's 40 ms), creates one template per plan
(the traced chunked checksum, and a plan with a 13-element list input), and
starts the processes:

- **executor**: the application's executor. It creates and commits one run
  per scenario (honest, or lying as the scenario says), publishes each run's
  inputs to a shared directory (the watchtower's input source), and runs the
  executor service until its runs are closed. In the `silent` scenario it
  never answers that run's disputes.
- **watchtower** (one or more): watches the templates, checks every run, and
  challenges.

Options:
- `--restart-watchtower`: kill the first watchtower after its first pick and
  restart it; it must rebuild its disputes from chain.
- `--watchtowers N`: N watchtowers with their own keys.
- Adversaries (review 10-05):
  - `--precreate`: the watchtower creates the executor's staging buffer of
    every dispute it opens (H1). The honest executor must still stage and
    reveal.
  - `--plant-buffer`: the lying executor of `state-lie` writes a fake LVR1
    body into its own buffer before revealing its plain leaf (H6). The
    watchtower must still claim.
  - `--drop-pick-confirm`: the watchtower's first pick lands but its
    confirmation is "lost" (an exception after the send) (H5). The
    watchtower must recover from chain.

The driver checks: the honest run finalizes unchallenged; every lie ends
ruled for a challenger; every run ends closed; no process logs an error.
Nothing leaves this machine.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
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
from contextlib import redirect_stderr
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
    "honest": {"plan": "checksum"},
    "state-lie": {"plan": "checksum", "fault": "state", "step": 2},
    "input-lie": {"plan": "checksum", "input_fault": True, "step": 4},
    "silent": {"plan": "checksum", "fault": "state", "step": 1, "silent": True},
    # A lie in a list element: the dispute ends at a list leaf, which the
    # executor must stage (LVR1) and the watchtower must read back.
    "list-lie": {"plan": "list", "list_fault": [6, 0, 0]},
}
LIES = [n for n in SCENARIOS if n != "honest"]
PLAN_IDS = {"checksum": bytes([7]) * 32, "list": bytes([8]) * 32}
DEPTHS = {"checksum": 3, "list": 4}


def plans() -> dict:
    """Plan name -> (spec, values function of an rng)."""
    import traced_dispute as T

    with redirect_stderr(io.StringIO()):
        checksum = T.checksum.plan()
    spec = importlib.util.spec_from_file_location("list_reference_tests",
                                                  HERE.parents[2] / "python/tests/test_disputes_v21_lists.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    mixed, mixed_values = tests.mixed_plan()
    return {
        "checksum": (checksum, lambda rng: {0: struct.pack("<64i", *[rng.randint(-1000, 1000) for _ in range(64)])}),
        "list": (mixed, lambda rng: dict(mixed_values)),
    }


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
        if scenario.get("list_fault"):
            o_, i_, e_ = scenario["list_fault"]
            kw["list_fault"] = lambda o, i, e, v: (bytes([v[0] ^ 1]) + v[1:]) if (o, i, e) == (o_, i_, e_) else v
        return R.execute(sp, plan_id, run_id, values, **kw)
    return execute


def key(path: Path) -> Keypair:
    return Keypair.from_bytes(bytes(json.loads(path.read_text())))


def client(cfg: dict, payer: Keypair) -> CL.DisputeClient:
    return CL.DisputeClient(GraphClient(cfg["rpc"], Pubkey.from_string(cfg["program"]), payer, timeout=30))


# --- the executor process ----------------------------------------------------------------------
def role_executor(cfg: dict) -> int:
    from dcg.services.executor import ExecutorService, Plan, log

    run_dir = Path(cfg["dir"])
    executor, payer = key(run_dir / "executor.json"), key(run_dir / "payer.json")
    cl = client(cfg, payer)
    specs = plans()
    by_run: dict[str, dict] = {}

    def execute(sp_, plan_id, run_id, values):
        return faulty_execute(by_run[run_id.hex()])(sp_, plan_id, run_id, values)

    service = ExecutorService(cl, executor, str(run_dir / "executor-journal.json"),
                              {t["template"]: Plan(specs[name][0], PLAN_IDS[name], DEPTHS[name])
                               for name, t in cfg["templates"].items()},
                              execute=execute)
    if cfg.get("plant_buffer"):
        # Adversary (review H6): before revealing a plain leaf in state-lie,
        # write a fake LVR1 body (a list for input 0) into our own buffer.
        answer = service._answer

        def planting(state, entry, d):
            if d.phase == 3 and by_run.get(entry["run_id"], {}).get("fault") == "state":
                fake = b"LVR1" + b"\x01" + struct.pack("<H", 1) + b"\x00" + bytes([1, 0, 1]) + bytes(55)
                cl.stage_body(state.address, state.template, d.address, CL.ROLE_EXECUTOR, fake, executor, executor)
                log(event="planted_buffer", dispute=str(d.address))
            return answer(state, entry, d)

        service._answer = planting
    rng = random.Random(7)
    for name, scenario in SCENARIOS.items():
        t = cfg["templates"][scenario["plan"]]
        sp, values_fn = specs[scenario["plan"]]
        template, template_id = Pubkey.from_string(t["template"]), bytes.fromhex(t["template_id"])
        values = values_fn(rng)
        refs = [R.external_ref(e, sp.in_specs[e][8:31], R.input_digest(sp.in_specs[e], v)) for e, v in values.items()]
        nonce = os.urandom(32)
        run_id = R.run_id(template_id, nonce, refs, bytes(executor.pubkey()))
        by_run[run_id.hex()] = scenario
        committed = execute(sp, PLAN_IDS[scenario["plan"]], run_id, values)
        run = cl.init_run(template, template_id, nonce, executor.pubkey(), refs, payer)
        # The application publishes the inputs (the watchtower's input source).
        (run_dir / "inputs" / str(run)).mkdir(parents=True, exist_ok=True)
        for e, v in values.items():
            (run_dir / "inputs" / str(run) / f"{e}.bin").write_bytes(v)
        if not scenario.get("silent"):
            service.add_run(run, template, run_id, values)  # write ahead of the commit
        cl.commit(run, template, committed.root_bytes, executor)
        log(event="committed", scenario=name, run=str(run))
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
def role_watchtower(cfg: dict, name: str = "challenger") -> int:
    from solders.instruction import AccountMeta

    from dcg.services.watchtower import Watched, Watchtower, log

    run_dir = Path(cfg["dir"])
    challenger = key(run_dir / f"{name}.json")
    cl = client(cfg, challenger)
    specs = plans()

    def inputs(run: Pubkey, eid: int, ref: bytes) -> bytes | None:
        path = run_dir / "inputs" / str(run) / f"{eid}.bin"
        return path.read_bytes() if path.exists() else None

    watched = [Watched(Pubkey.from_string(t["template"]), specs[p][0], PLAN_IDS[p], inputs, DEPTHS[p])
               for p, t in cfg["templates"].items()]
    tower = Watchtower(cl, challenger, str(run_dir / f"{name}-journal.json"), watched)
    if cfg.get("precreate") and name == "challenger":
        # Adversary (review H1): create the executor's buffer right after
        # each open, before the executor stages.
        opened = tower._open

        def open_and_precreate(run, template, dispute, nonce, kind):
            opened(run, template, dispute, nonce, kind)
            buffer = cl.pda(b"dcg21stg", bytes(dispute), bytes([CL.ROLE_EXECUTOR]))
            cl._send("stage_create", bytes([CL.ROLE_EXECUTOR]) + struct.pack("<I", 0),
                     [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, False),
                      AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                      AccountMeta(buffer, False, True), AccountMeta(CL.SYSTEM, False, False)], [challenger])
            log(event="precreated_executor_buffer", dispute=str(dispute))

        tower._open = open_and_precreate
    if cfg.get("drop_pick_confirm") and name == "challenger":
        # Adversary (review H5): the first pick lands, its confirmation "is lost".
        send, dropped = cl._send, {"done": False}

        def lossy(sub, *a, **kw):
            out = send(sub, *a, **kw)
            if sub == "pick" and not dropped["done"]:
                dropped["done"] = True
                log(event="dropped_confirmation", sub=sub)
                raise CL.ChainError("simulated: the pick was not confirmed in time")
            return out

        cl._send = lossy
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


def driver(image: Path | None, seconds: int, towers: int, restart: bool, adversary: dict,
           network: dict | None = None) -> int:
    """`network` (testnet mode): {"rpc", "program", "payer_key", "dir"}; no
    local validator, party keys funded by transfer from the payer."""
    if network:
        run_dir = Path(network["dir"])
        run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(run_dir, 0o700)
        program, rpc, validator = Pubkey.from_string(network["program"]), network["rpc"], None
        slot_ms = 40.0
    else:
        run_dir = Path(tempfile.mkdtemp(prefix="dcg-e3-", dir="/private/tmp" if sys.platform == "darwin" else None))
        program = Keypair().pubkey()
        rpc_port, faucet_port, base = _port(), _port(), random.randrange(30_000, 60_000, 100)
        rpc = f"http://127.0.0.1:{rpc_port}"
        validator = subprocess.Popen(
            [shutil.which("solana-test-validator") or "solana-test-validator", "--reset", "--ledger",
             str(run_dir / "ledger"), "--upgradeable-program", str(program), str(image), "none", "--ticks-per-slot", "8",
             "--rpc-port", str(rpc_port), "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
             "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
            stdout=(run_dir / "validator.log").open("wb"), stderr=subprocess.STDOUT)
        slot_ms = 50.0
    procs = []
    templates = {}
    # Testnet: windows sized for a service ~350 ms per RPC call away from the
    # node (measured 10-05): 3,000-slot challenge (~2 min), 1,500-slot phase
    # (~1 min). Local: the program's minimums.
    windows = {"challenge_window": 3_000, "phase_window": 1_500} if network else {}
    try:
        admin = key(Path(network["payer_key"])) if network else Keypair()
        gc = GraphClient(rpc, program, admin, timeout=30)
        t0 = time.monotonic()
        while True:
            try:
                gc.slot()
                break
            except Exception:
                if validator is None or validator.poll() is not None or time.monotonic() - t0 > 60:
                    raise RuntimeError(f"validator did not start; see {run_dir / 'validator.log'}")
                time.sleep(0.25)
        names = ["challenger"] + [f"challenger{i}" for i in range(2, towers + 1)]
        keys = {name: Keypair() for name in ("executor", "payer", *names)}
        for name, k in keys.items():
            write_key(run_dir / f"{name}.json", k)
        cl = CL.DisputeClient(gc)
        if network:
            for k in keys.values():
                cl.fund(k.pubkey(), 500_000_000)  # 0.5 FOGO each, testnet
        else:
            for k in [admin, *keys.values()]:
                gc.rpc("requestAirdrop", [str(k.pubkey()), 50_000_000_000])
            time.sleep(2)
        for p, (sp, _values) in plans().items():
            tdata = W.template_data(sp, DEPTHS[p], PLAN_IDS[p], slot_ms=slot_ms, **windows)
            templates[p] = {"template": str(cl.create_template(tdata, admin)),
                            "template_id": hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest().hex()}
        cfg = {"rpc": rpc, "program": str(program), "dir": str(run_dir), "templates": templates,
               "seconds": seconds, **adversary}
        (run_dir / "config.json").write_text(json.dumps(cfg))

        def start(role: str, name: str = "", mode: str = "w") -> subprocess.Popen:
            args = [sys.executable, str(HERE), "--role", role, "--config", str(run_dir / "config.json")]
            if name:
                args += ["--name", name]
            return subprocess.Popen(args, stdout=(run_dir / f"{name or role}.log").open(mode),
                                    stderr=subprocess.STDOUT)

        towers_p = {n: start("watchtower", n) for n in names}
        executor_p = start("executor")
        restarted = False
        while restart and not restarted and time.monotonic() - t0 < seconds:
            if '"event": "pick"' in (run_dir / "challenger.log").read_text():
                towers_p["challenger"].kill()
                towers_p["challenger"].wait()
                towers_p["challenger"] = start("watchtower", "challenger", mode="a")
                restarted = True
            time.sleep(0.2)
        procs.extend([*towers_p.values(), executor_p])
        codes = [p.wait(timeout=seconds + 60) for p in procs]
        return report(run_dir, codes, time.monotonic() - t0, names, restarted if restart else None, adversary)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        if network:
            # Retire and close the templates (their runs are closed by now).
            cl = CL.DisputeClient(GraphClient(rpc, program, admin, timeout=30))
            for t in templates.values():
                try:
                    template = Pubkey.from_string(t["template"])
                    if cl.gc.account(template)[134] == 0:
                        cl.retire_template(template, admin)
                    cl.close_template(template, admin)
                    print(json.dumps({"event": "template_closed", "template": t["template"]}), flush=True)
                except Exception as exc:
                    print(json.dumps({"event": "template_left", "template": t["template"], "error": str(exc)[:200]}))
        if validator is not None:
            validator.terminate()
            validator.wait(timeout=20)


def report(run_dir: Path, codes: list[int], seconds: float, names: list[str], restarted: bool | None,
           adversary: dict) -> int:
    lines = {}
    for role in ("executor", *names):
        lines[role] = []
        for line in (run_dir / f"{role}.log").read_text().splitlines():
            try:
                lines[role].append(json.loads(line))
            except json.JSONDecodeError:
                lines[role].append({"event": "text", "line": line})
    runs = {e["run"]: e["scenario"] for e in lines["executor"] if e.get("event") == "committed"}
    outcome = {name: {"run": run, "disputes": {}} for run, name in runs.items()}
    by_dispute = {}
    events = [e for n in names for e in lines[n]]
    for e in events:
        name = runs.get(e.get("run"))
        if e.get("event") == "run_ok" and name:
            outcome[name]["watchtower"] = "ok"
        if e.get("event") == "open" and name:
            outcome[name]["watchtower"] = "challenged"
            outcome[name]["disputes"][e["dispute"]] = None
            by_dispute[e["dispute"]] = name
    for e in events:
        d = e.get("dispute")
        if d not in by_dispute:
            continue
        disputes = outcome[by_dispute[d]]["disputes"]
        if e.get("event") == "settle" and e.get("ruling"):
            disputes[d] = e["ruling"]
        if e.get("event") == "settled_elsewhere":
            disputes[d] = disputes[d] or ("C" if e.get("outcome") == "refuted" else e.get("outcome"))
        if e.get("event") == "executor_timeout":
            outcome[by_dispute[d]]["timeout"] = True
            if e.get("state") == "closed":
                disputes[d] = disputes[d] or "C"
    # The simulated lost confirmation is logged by the watchtower as a failed
    # send; it is the injected fault, not a defect.
    errors = [e for role in lines for e in lines[role] if e.get("event") in ("error", "text")
              and "simulated:" not in str(e.get("error", ""))]
    seen = {
        "precreate": any(e.get("event") == "precreated_executor_buffer" for e in events),
        "plant_buffer": any(e.get("event") == "planted_buffer" for e in lines["executor"]),
        "drop_pick_confirm": any(e.get("event") == "dropped_confirmation" for e in events),
    }
    wanted = [k for k, v in adversary.items() if v]
    ok = (all(c == 0 for c in codes) and not errors
          and outcome["honest"].get("watchtower") == "ok"
          and all(outcome[n].get("watchtower") == "challenged" and "C" in outcome[n]["disputes"].values()
                  and all(r in ("C", "moot", "refuted", "closed") for r in outcome[n]["disputes"].values())
                  for n in LIES)
          and all(seen[k] for k in wanted)
          and restarted is not False)
    print(json.dumps({"ok": ok, "restarted": restarted, "adversary": {k: seen[k] for k in wanted},
                      "watchtowers": len(names), "exit_codes": codes, "seconds": round(seconds, 1),
                      "outcome": {n: {"watchtower": o.get("watchtower"), "rulings": list(o["disputes"].values()),
                                      **({"timeout": True} if o.get("timeout") else {})} for n, o in outcome.items()},
                      "errors": errors[:10], "dir": str(run_dir)}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--role")
    ap.add_argument("--config")
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--name", default="challenger")
    ap.add_argument("--watchtowers", type=int, default=1)
    ap.add_argument("--restart-watchtower", action="store_true")
    ap.add_argument("--precreate", action="store_true")
    ap.add_argument("--plant-buffer", action="store_true")
    ap.add_argument("--drop-pick-confirm", action="store_true")
    ap.add_argument("--rpc", help="testnet mode: an RPC URL (no local validator)")
    ap.add_argument("--program", help="testnet mode: the deployed alpha program")
    ap.add_argument("--payer-key", help="testnet mode: the funding and template payer key")
    ap.add_argument("--run-dir", help="testnet mode: where keys, journals and logs go (mode 700)")
    a = ap.parse_args()
    if a.role:
        cfg = json.loads(Path(a.config).read_text())
        raise SystemExit(role_executor(cfg) if a.role == "executor" else role_watchtower(cfg, a.name))
    network = ({"rpc": a.rpc, "program": a.program, "payer_key": a.payer_key, "dir": a.run_dir}
               if a.rpc else None)
    raise SystemExit(driver(Path(a.image) if a.image else None, a.seconds, a.watchtowers, a.restart_watchtower,
                            {"precreate": a.precreate, "plant_buffer": a.plant_buffer,
                             "drop_pick_confirm": a.drop_pick_confirm}, network))
