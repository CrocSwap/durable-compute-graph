"""A local validator with a DCG program loaded (alpha E6, `dcg dev`).

    with LocalValidator(image) as dev:
        print(dev.rpc_url, dev.program_id)

Starts `solana-test-validator` with:
- the image as an upgradeable program at a fresh address;
- 8 ticks per slot (about 50 ms, close to Fogo testnet's 40 ms);
- free ports, away from the defaults, so several can run at once;
- a short ledger path (macOS limits socket paths to 104 bytes, and the
  validator's admin socket lives in the ledger).

The validator is stopped when the context exits, even after an error.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json"}), timeout=10) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def write_key(path: Path, key: Keypair) -> None:
    path.write_text(json.dumps(list(bytes(key))))
    os.chmod(path, 0o600)


class LocalValidator:
    def __init__(self, image: str | os.PathLike[str], *, run_dir: str | os.PathLike[str] | None = None,
                 ticks_per_slot: int = 8, fund_lamports: int = 100_000_000_000, startup_s: float = 60.0):
        self.image = Path(image).resolve()
        if not self.image.is_file():
            raise FileNotFoundError(f"no program image at {self.image}")
        if shutil.which("solana-test-validator") is None:
            raise FileNotFoundError("solana-test-validator is not on PATH (install the Solana or Agave CLI)")
        base_dir = "/private/tmp" if sys.platform == "darwin" else None
        self.run_dir = Path(run_dir) if run_dir else Path(tempfile.mkdtemp(prefix="dcg-dev-", dir=base_dir))
        self.run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        self.ticks_per_slot, self.fund_lamports, self.startup_s = ticks_per_slot, fund_lamports, startup_s
        self.program_id: Pubkey | None = None
        self.payer_path = self.run_dir / "payer.json"
        self.rpc_url = ""
        self.process: subprocess.Popen | None = None

    def start(self) -> LocalValidator:
        program = Keypair()
        write_key(self.run_dir / "program.json", program)
        self.program_id = program.pubkey()
        rpc_port, faucet_port, base = _port(), _port(), random.randrange(30_000, 60_000, 100)
        self.rpc_url = f"http://127.0.0.1:{rpc_port}"
        self.process = subprocess.Popen(
            ["solana-test-validator", "--reset", "--ledger", str(self.run_dir / "ledger"),
             "--upgradeable-program", str(self.program_id), str(self.image), "none",
             "--ticks-per-slot", str(self.ticks_per_slot), "--rpc-port", str(rpc_port),
             "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
             "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
            stdout=(self.run_dir / "validator.log").open("wb"), stderr=subprocess.STDOUT)
        t0 = time.monotonic()
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(f"the validator exited; see {self.run_dir / 'validator.log'}")
            try:
                _rpc(self.rpc_url, "getHealth", [])
                if _rpc(self.rpc_url, "getAccountInfo", [str(self.program_id), {"encoding": "base64"}])["value"]:
                    break
            except Exception:
                pass
            if time.monotonic() - t0 > self.startup_s:
                raise RuntimeError(f"the validator did not start in {self.startup_s:.0f} s; see {self.run_dir / 'validator.log'}")
            time.sleep(0.25)
        payer = Keypair()
        write_key(self.payer_path, payer)
        sig = _rpc(self.rpc_url, "requestAirdrop", [str(payer.pubkey()), self.fund_lamports])
        while True:
            status = _rpc(self.rpc_url, "getSignatureStatuses", [[sig]])["value"][0]
            if status and status.get("confirmationStatus") in ("confirmed", "finalized"):
                break
            if time.monotonic() - t0 > self.startup_s:
                raise RuntimeError("the faucet did not fund the payer")
            time.sleep(0.2)
        return self

    def env(self) -> dict[str, str]:
        """The environment the DCG examples and clients read."""
        return {"DCG_RPC_URL": self.rpc_url, "DCG_PROGRAM_ID": str(self.program_id),
                "DCG_PAYER_KEYPAIR": str(self.payer_path)}

    def write_env(self, path: str | os.PathLike[str] | None = None) -> Path:
        path = Path(path) if path else self.run_dir / "dcg-dev.env"
        path.write_text("".join(f"export {k}={v}\n" for k, v in self.env().items()))
        os.chmod(path, 0o600)
        return path

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def __enter__(self) -> LocalValidator:
        try:
            return self.start()
        except BaseException:
            self.stop()
            raise

    def __exit__(self, *exc) -> None:
        self.stop()
