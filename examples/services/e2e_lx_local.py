"""The executor service answering LX1 disputes, on a local validator (alpha
E3; the LX watchtower is not in v1, owner 10-05, so this driver plays a
scripted challenger that reads the executor's moves from chain).

    PYTHONPATH=python python examples/services/e2e_lx_local.py ALPHA_IMAGE.so

The toy LX1 machine (`dcg-lx-toy-v1`, in the alpha image) runs in two cases:

- `executor-lies`: the executor commits a faulty execution; the challenger
  bisects from its honest execution; the executor service answers every
  round and opens the terminal transition; the program rules C.
- `challenger-lies`: the executor commits honestly; a challenger disputes a
  checkpoint pair anyway and always picks the last sub-interval; the
  executor service's opening stands; the program rules E.

The executor service runs in its own process. Nothing leaves this machine.
"""

from __future__ import annotations

import argparse
import hashlib
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

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.disputes_v21 import client as CL
from dcg.disputes_v21 import lx as L
from dcg.disputes_v21 import lx_client as LC
from dcg.disputes_v21.lx_toy import ToyMachine
from dcg.graph_client import GraphClient

HERE = Path(__file__).resolve()
P, WINDOW, H0, K, ARITY = 9, 3, 7, 4, 4
# --weighted: the toy with constant weights (design §13), so the terminal
# opening carries constants (review M6); the lie is at a weighted start.
# --staged-open: the challenger always prestages its open body, so the
# dispute address is named in transactions before the dispute exists
# (review N1: the executor must still find the dispute after it opens).
STAGED_OPEN = "--staged-open" in sys.argv
WEIGHTED = "--weighted" in sys.argv or os.environ.get("DCG_LX_WEIGHTED") == "1"
PARAMS = struct.pack("<QQqB", P, WINDOW, H0, 1) if WEIGHTED else struct.pack("<QQq", P, WINDOW, H0)


def machine():
    return ToyMachine(positions_count=P, window=WINDOW, h0=H0, weights=WEIGHTED)


TEMPLATE = LC.LxTemplate(kernel=b"dcg-lx-toy-v1\x00\x00\x00", semantic=1, abi=1, arity=ARITY, k_min=1, k_max=16,
                         max_positions=1 << 16,
                         constants_root=L.constants_root(machine()) if WEIGHTED else bytes(32))
D_REVEALED, D_REVEALED_N = 144, 128
D_LX_ROOT_HI = 144 + 32 * 32 + 8 + 8


def bump(tm, c):
    def fault(coord, state):
        if coord == c:
            state = dict(state)
            state[tm.H] = struct.pack("<q", struct.unpack("<q", state[tm.H])[0] + 1)
        return state
    return fault


def key(path: Path) -> Keypair:
    return Keypair.from_bytes(bytes(json.loads(path.read_text())))


def lx_client(cfg: dict, payer: Keypair) -> LC.LxClient:
    return LC.LxClient(GraphClient(cfg["rpc"], Pubkey.from_string(cfg["program"]), payer, timeout=30))


def execution(case: str):
    tm = machine()
    if case == "executor-lies" and WEIGHTED:
        sch = L.Schedule(tm)
        start5 = next(c for c in range(sch.total) if sch.transition(c).label == "p5.start")

        def bump_a(coord, state):
            if coord == start5:
                state = dict(state)
                state[tm.A] = struct.pack("<q", struct.unpack("<q", state[tm.A])[0] + 1)
            return state
        return L.execute(tm, bump_a)
    if case == "executor-lies":
        total = L.Schedule(tm).total
        fault = next(c for c in range(total // 2, total)
                     if L.first_disputed_pair(L.commit(L.execute(tm, bump(tm, c)), K), L.execute(tm)) is not None)
        return L.execute(tm, bump(tm, fault))
    return L.execute(tm)


# --- the executor process ----------------------------------------------------------------------
def role_executor(cfg: dict) -> int:
    from dcg.services.executor import ExecutionAnswerer, ExecutorService, Plan, log

    run_dir = Path(cfg["dir"])
    executor, payer = key(run_dir / "executor.json"), key(run_dir / "payer.json")
    cl = lx_client(cfg, payer)
    template = Pubkey.from_string(cfg["template"])
    answerers: dict[str, ExecutionAnswerer] = {}
    service = ExecutorService(cl, executor, str(run_dir / "executor-journal.json"),
                              {str(template): Plan(None, bytes(32), lx=lambda run: answerers[str(run)])})
    runs = {}
    for case, payer_name in (("executor-lies", "payer"), ("challenger-lies", "payer2")):
        run_exec = execution(case)
        params = PARAMS
        # An LX1 run's input id is its parameters' digest (LX1 review H1), so
        # its run id is fixed: each case uses its own payer, hence its own run.
        case_payer = key(run_dir / f"{payer_name}.json")
        run, run_id = cl.init_lx_run(template, TEMPLATE.template_id(), params, executor.pubkey(), case_payer)
        com = L.commit(run_exec, K)
        answerers[str(run)] = ExecutionAnswerer(run_exec, params, ARITY)
        service.add_run(run, template, run_id, {})  # write ahead of the commit
        cl.lx_commit(run, template, run_id, com.roots, L.outputs_digest([com.outputs[s] for s in run_exec.machine.output_slots()]),
                     params, P, K, executor)
        runs[case] = str(run)
        log(event="committed", case=case, run=str(run))
    (run_dir / "runs.json").write_text(json.dumps(runs))
    deadline = time.monotonic() + cfg["seconds"]
    while time.monotonic() < deadline:
        service.tick()
        if all(e["done"] for e in service.journal.data["runs"].values()):
            log(event="executor_done")
            return 0
        time.sleep(1.0)
    log(event="executor_timeout_overall")
    return 1


# --- the scripted challenger (in the driver) -----------------------------------------------------
def challenge(cfg: dict, case: str, run: Pubkey, log) -> str:
    run_dir = Path(cfg["dir"])
    challenger = key(run_dir / "challenger.json")
    cl = lx_client(cfg, challenger)
    template = Pubkey.from_string(cfg["template"])
    honest = execution("challenger-lies")  # the honest execution
    tm = honest.machine
    committed = execution(case)
    com = L.commit(committed, K)
    levels = LC.checkpoint_levels(com.roots)
    coordinates = L.checkpoint_coordinates(L.Schedule(tm), K)
    pair = L.first_disputed_pair(com, honest)
    if pair is None:
        pair = 0  # a lying challenger disputes an honest pair
    nonce = os.urandom(32)
    dispute = cl.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), nonce)
    body = (bytes([LC.KIND_LX_STATE]) + struct.pack("<I", pair) + com.roots[pair] + com.roots[pair + 1]
            + LC.tree_path(levels, pair) + LC.tree_path(levels, pair + 1) + PARAMS)
    metas = [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, True),
             AccountMeta(template, False, False), AccountMeta(dispute, False, True), AccountMeta(CL.SYSTEM, False, False)]
    if len(body) > LC.INLINE_OPEN_MAX or STAGED_OPEN:
        secret = os.urandom(32)
        buffer = cl.lx_prestage(run, template, dispute, nonce, body[1:], challenger, secret)
        cl._send("open", nonce + bytes([LC.KIND_LX_STATE, CL.FROM_STAGING]) + secret,
                 metas + [AccountMeta(buffer, False, True)], [challenger])
    else:
        cl._send("open", nonce + body, metas, [challenger])
    log(event="lx_open", case=case, pair=pair, dispute=str(dispute))
    party = [AccountMeta(challenger.pubkey(), True, False), AccountMeta(run, False, True),
             AccountMeta(template, False, False), AccountMeta(dispute, False, True)]
    deadline = time.monotonic() + cfg["seconds"]
    picked_at = None
    while time.monotonic() < deadline:
        d = cl.gc.account(dispute)
        if d is None:
            return "closed"
        if d[CL.D_RULING] != CL.RULING_OPEN:
            return CL.RULINGS[d[CL.D_RULING]]
        lo, hi = struct.unpack_from("<Q", d, 16)[0], struct.unpack_from("<Q", d, 144 + 32 * 32 + 8)[0]
        if d[CL.D_PHASE] == 2 and picked_at != (lo, hi):  # PICK
            m = struct.unpack_from("<H", d, D_REVEALED_N)[0]
            mids = LC.midpoint_coordinates(lo, hi, ARITY)
            uppers = [d[D_REVEALED + 32 * i:D_REVEALED + 32 * (i + 1)] for i in range(m)] + [d[D_LX_ROOT_HI:D_LX_ROOT_HI + 32]]
            coords = mids + [hi]
            if case == "challenger-lies":
                pick = len(uppers) - 1
            else:
                pick = next((i for i, (c, r) in enumerate(zip(coords, uppers)) if r != honest.root_at(c)), len(uppers) - 1)
            cl._send("lx_pick", bytes([pick]), party, [challenger])
            picked_at = (lo, hi)
            log(event="lx_pick", case=case, interval=[lo, hi], pick=pick)
        time.sleep(0.5)
    return "timeout"


# --- the driver ----------------------------------------------------------------------------------
def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def driver(image: Path, seconds: int) -> int:
    def log(**f):
        print(json.dumps({"t": round(time.time(), 1), **f}), flush=True)

    run_dir = Path(tempfile.mkdtemp(prefix="dcg-e3lx-", dir="/private/tmp" if sys.platform == "darwin" else None))
    program = Keypair().pubkey()
    rpc_port, faucet_port, base = _port(), _port(), random.randrange(30_000, 60_000, 100)
    rpc = f"http://127.0.0.1:{rpc_port}"
    validator = subprocess.Popen(
        [shutil.which("solana-test-validator") or "solana-test-validator", "--reset", "--ledger", str(run_dir / "ledger"),
         "--upgradeable-program", str(program), str(image), "none", "--ticks-per-slot", "8",
         "--rpc-port", str(rpc_port), "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
         "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
        stdout=(run_dir / "validator.log").open("wb"), stderr=subprocess.STDOUT)
    proc = None
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
                    raise RuntimeError("validator did not start")
                time.sleep(0.25)
        for name in ("executor", "challenger", "payer", "payer2"):
            k = Keypair()
            (run_dir / f"{name}.json").write_text(json.dumps(list(bytes(k))))
            os.chmod(run_dir / f"{name}.json", 0o600)
            gc.rpc("requestAirdrop", [str(k.pubkey()), 50_000_000_000])
        gc.rpc("requestAirdrop", [str(admin.pubkey()), 50_000_000_000])
        time.sleep(2)
        template = LC.LxClient(gc).create_template(TEMPLATE.data(), admin)
        cfg = {"rpc": rpc, "program": str(program), "dir": str(run_dir), "template": str(template), "seconds": seconds}
        (run_dir / "config.json").write_text(json.dumps(cfg))
        proc = subprocess.Popen([sys.executable, str(HERE), "--role", "executor", "--config", str(run_dir / "config.json")]
                                + (["--weighted"] if WEIGHTED else []),
                                stdout=(run_dir / "executor.log").open("w"), stderr=subprocess.STDOUT)
        while not (run_dir / "runs.json").exists():
            if proc.poll() is not None:
                raise RuntimeError(f"executor exited: {(run_dir / 'executor.log').read_text()[-2000:]}")
            time.sleep(0.5)
        runs = json.loads((run_dir / "runs.json").read_text())
        rulings = {case: challenge(cfg, case, Pubkey.from_string(run), log) for case, run in runs.items()}
        code = proc.wait(timeout=seconds + 60)
        errors = [line for line in (run_dir / "executor.log").read_text().splitlines() if '"error"' in line]
        ok = rulings == {"executor-lies": "C", "challenger-lies": "E"} and code == 0 and not errors
        print(json.dumps({"ok": ok, "weighted": WEIGHTED, "rulings": rulings, "executor_exit": code, "errors": errors[:3],
                          "seconds": round(time.monotonic() - t0, 1), "dir": str(run_dir)}, indent=1))
        return 0 if ok else 1
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        validator.terminate()
        validator.wait(timeout=20)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--role")
    ap.add_argument("--config")
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--weighted", action="store_true")
    ap.add_argument("--staged-open", action="store_true")
    a = ap.parse_args()
    if a.role:
        raise SystemExit(role_executor(json.loads(Path(a.config).read_text())))
    raise SystemExit(driver(Path(a.image), a.seconds))
