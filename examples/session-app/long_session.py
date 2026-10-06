"""A long session through the sequencer (alpha plan C5; docs/session-tutorial.md).

    ./build.sh out
    PYTHONPATH=../../python python long_session.py out/dcg_session_app.so [--steps 2000] [--drop-at 100]

It starts `solana-test-validator` with the tally program, opens a rejectable
session with a ring input stream (so it never fills), and runs `--steps`
inputs, 8 per transaction: each transaction writes 8 inputs and advances
the session over them (`Session.write_and_advance`), so all of it applies or
none does. The first new transaction sent at or after send number `--drop-at` is
dropped on purpose:
the endpoint reports it sent, but it never reaches the validator. The
sequencer must notice that it did not land and resend it.

At the end it reads the state, checks it against the Python mirror, reads
the session's info, closes every account, and prints the costs. One JSON line
per stage. Nothing leaves this machine.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from solders.keypair import Keypair
from solders.transaction import Transaction

from dcg.sequencer import Commitment, RpcConfig, RpcUnavailable, SolanaRpcEndpoint
from dcg.sequencer.types import SendReceipt
from dcg.session import KernelRef, Session, SessionSigners, SequencedInstructionTransport

sys.path.insert(0, str(Path(__file__).parent))
from mirror import TALLY  # noqa: E402
from quickstart import TALLY_SESSION, _port, _port_base, say  # noqa: E402


class DroppingEndpoint(SolanaRpcEndpoint):
    """An RPC endpoint that silently drops one send, as a congested network
    would, and counts sends so the resend can be seen."""

    def __init__(self, *args, drop_at: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.sends, self.drop_at = 0, drop_at
        self.dropped: str | None = None  # the dropped transaction's signature
        self.resent_same = 0  # later sends of the very same bytes
        self.dropped_bytes: bytes | None = None
        self.dropped_at = 0
        self.seen: set[str] = set()

    async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt:
        self.sends += 1
        signature = str(Transaction.from_bytes(raw_bytes).signatures[0])
        first = signature not in self.seen
        self.seen.add(signature)
        # Drop the first send of a new transaction, not a rebroadcast of one
        # that may already have landed.
        if self.dropped is None and first and self.sends >= self.drop_at:
            self.dropped, self.dropped_bytes, self.dropped_at = signature, raw_bytes, self.sends
            return SendReceipt(signature)  # "sent", but nothing reaches the validator
        if raw_bytes == self.dropped_bytes:
            self.resent_same += 1
        return await super().send_raw_transaction(raw_bytes)


def compute_units(rpc_url: str, address: str, n: int = 20) -> list[int]:
    """Compute units of the last `n` transactions that touched `address`."""
    import json
    import urllib.request

    def call(method, params):
        req = urllib.request.Request(rpc_url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                                          "params": params}).encode(),
                                     {"Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]

    sigs = call("getSignaturesForAddress", [address, {"limit": n, "commitment": "confirmed"}])
    out = []
    for s in sigs:
        tx = call("getTransaction", [s["signature"], {"commitment": "confirmed", "maxSupportedTransactionVersion": 0}])
        if tx and tx["meta"] and tx["meta"].get("computeUnitsConsumed") is not None and not tx["meta"]["err"]:
            out.append(tx["meta"]["computeUnitsConsumed"])
    return out


async def balance(endpoint, key) -> int:
    info = await endpoint.get_account_info(str(key), Commitment.CONFIRMED)
    return 0 if info is None else info.lamports


async def start_validator(image: Path, run_dir: Path):
    program_id = Keypair().pubkey()
    rpc_port, faucet_port, base = _port(), _port(), _port_base()
    validator = subprocess.Popen(
        [shutil.which("solana-test-validator") or "solana-test-validator", "--reset", "--ledger", str(run_dir / "ledger"),
         "--upgradeable-program", str(program_id), str(image), "none",
         # 8 ticks per slot: about 50 ms slots, close to Fogo's 40 ms.
         "--ticks-per-slot", "8",
         "--rpc-port", str(rpc_port), "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
         "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
        stdout=(run_dir / "validator.log").open("wb"), stderr=subprocess.STDOUT)
    return validator, program_id, f"http://127.0.0.1:{rpc_port}"


async def main(image: Path, steps: int, drop_at: int) -> int:
    run_dir = Path(tempfile.mkdtemp(prefix="dcg-long-", dir="/private/tmp" if sys.platform == "darwin" else None))
    validator, program_id, rpc_url = await start_validator(image, run_dir)
    endpoint = DroppingEndpoint("local", rpc_url, drop_at=drop_at, config=RpcConfig(
        timeout_seconds=4, requests_per_second=200, max_in_flight=1, commitment=Commitment.CONFIRMED))
    try:
        t0 = time.monotonic()
        while True:
            if validator.poll() is not None or time.monotonic() - t0 > 60:
                raise RuntimeError(f"the local validator did not start; see {run_dir / 'validator.log'}")
            try:
                await endpoint.get_health()
                break
            except RpcUnavailable:
                await asyncio.sleep(0.25)
        say("validator", rpc=rpc_url, program=str(program_id))

        payer, authority = Keypair(), Keypair()
        airdrop = await endpoint.request_airdrop(str(payer.pubkey()), 5_000_000_000)
        while (status := await endpoint.signature_status(airdrop)) is None or status.commitment not in {
                Commitment.CONFIRMED, Commitment.FINALIZED}:
            await asyncio.sleep(0.1)
        async def funds() -> int:  # rent goes back to the authority, fees come from the payer
            return await balance(endpoint, payer.pubkey()) + await balance(endpoint, authority.pubkey())

        balance0 = await funds()

        signers = SessionSigners(payer=payer, authority=authority)
        transport = SequencedInstructionTransport(endpoint=endpoint, signers=signers,
                                                  journal_dir=run_dir / "transactions")
        # A ring stream reuses its slots, so the session can run any number of
        # steps; the writer stays at most 64 inputs ahead of the cursor.
        session = Session(kernel=KernelRef.from_manifest(TALLY_SESSION), transport=transport, signers=signers,
                          program_id=program_id, session_id=1, journal_path=run_dir / "accounts.json",
                          max_steps=8, ring=True, input_capacity=128)
        await session.open()
        opened = await funds()
        ops_open = transport._operation
        say("open", session=str(session.addresses.session), rent_lamports=balance0 - opened)

        rng = random.Random(7)
        inputs = [rng.randrange(256) for _ in range(steps)]
        t1 = time.monotonic()
        for start in range(0, steps, 8):
            batch = inputs[start:start + 8]
            await session.write_and_advance(batch)
            done = start + len(batch)
            if done % 400 == 0 or done == steps:
                say("progress", steps=done, transactions=transport._operation, seconds=round(time.monotonic() - t1, 1))
        run_seconds = time.monotonic() - t1

        state = await session.read_state()
        count, total = struct.unpack("<QQ", state)
        info = await session.info()
        predicted = TALLY.initial_state(TALLY.state_spans)
        for value in inputs:
            predicted = TALLY.transition(bytes([value]), predicted).state
        zeros = inputs.count(0)
        say("result", count=count, sum=total, cursor=info.cursor, rejected=info.rejected_count,
            mirror_agrees=predicted == state, expected_rejections=zeros)

        dropped_status = await endpoint.signature_status(endpoint.dropped) if endpoint.dropped else None
        say("dropped send", send_number=endpoint.dropped_at, signature=endpoint.dropped,
            resent_same_bytes=endpoint.resent_same,
            landed=dropped_status is not None and dropped_status.error is None,
            note="the session still advanced every step, so the sequencer recovered it")

        cus = sorted(compute_units(rpc_url, str(session.addresses.session)))
        say("compute", transactions_sampled=len(cus), median_units_per_8_step_transaction=cus[len(cus) // 2] if cus else None,
            max_units=max(cus) if cus else None)

        receipt = await session.close()
        fees = balance0 - await funds()
        say("close", rent_returned_lamports=receipt.rent_lamports, accounts_closed=len(receipt.accounts_closed),
            net_cost_lamports=fees)
        ok = (predicted == state and info.cursor == steps and count == steps - zeros
              and info.rejected_count == zeros and endpoint.dropped is not None)
        txs = transport._operation
        say("done", ok=ok, steps=steps, transactions=txs, session_transactions=txs - ops_open,
            sends_including_rebroadcasts=endpoint.sends,
            steps_per_second=round(steps / run_seconds, 1),
            fee_lamports_per_transaction=round(fees / max(txs, 1)),
            seconds=round(time.monotonic() - t0, 1), run_dir=str(run_dir))
        return 0 if ok else 1
    finally:
        validator.terminate()
        validator.wait(timeout=20)
        await endpoint.aclose()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=Path)
    ap.add_argument("--steps", type=int, default=2000)
    ap.add_argument("--drop-at", type=int, default=100)
    a = ap.parse_args()
    raise SystemExit(asyncio.run(main(a.image, a.steps, a.drop_at)))
