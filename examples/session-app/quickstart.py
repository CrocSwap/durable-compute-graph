"""Session quickstart (alpha plan C1): run the tally app on a local validator
and drive one session from Python.

    cargo build-sbf --sbf-out-dir out             # builds out/dcg_session_app.so
    PYTHONPATH=../../python python quickstart.py out/dcg_session_app.so

Steps: start `solana-test-validator` with the program loaded at a fresh
address, read its DCG runtime version from chain, open a rejectable stateful
v3 session (the kernel declares REJECTS_INPUT), write four inputs (one of
them the rejected 0), advance, read the state and the session's info, check
the result against the Python mirror, and close the session and its accounts.
Prints one JSON line per step. Nothing leaves this machine.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from solders.keypair import Keypair

from dcg.runtime import program_runtime_version
from dcg.sequencer import Commitment, RpcConfig, RpcUnavailable, SolanaRpcEndpoint
from dcg.session import KernelRef, Session, SessionSigners, SequencedInstructionTransport

sys.path.insert(0, str(Path(__file__).parent))
from mirror import TALLY  # noqa: E402

#: The session's view of the kernel: the same identity and limits the Rust
#: `KernelDecl` declares, plus how this session lays out its inputs and state.
TALLY_SESSION = {
    "id": "dcg-tally-v1",
    "semantic_version": 1,
    "abi_version": 1,
    "mode": {"id": 0x434F4E53, "version": 3},  # MODE_CONSENSUS_V3
    "schema": {"id": 0x54414C53, "version": 1},  # STATE_SCHEMA "TALS"
    "input_width": 1,
    "state_spans": [16],
    "input_codec": "u8",
    "state_codec": "bytes",
    "rejects_input": True,
}
INPUTS = [5, 0, 7, 3]


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_base() -> int:
    """A base for the validator's dynamic port range, away from the defaults
    so a second local validator can run alongside."""
    import random

    return random.Random().randrange(30_000, 60_000, 100)


def say(step: str, **fields) -> None:
    print(json.dumps({"step": step, **fields}), flush=True)


async def main(image: Path) -> int:
    # A short path: the validator's admin socket lives in the ledger, and
    # macOS limits socket paths to 104 bytes.
    run_dir = Path(tempfile.mkdtemp(prefix="dcg-app-", dir="/private/tmp" if sys.platform == "darwin" else None))
    program_id = Keypair().pubkey()
    rpc_port, faucet_port, base = _port(), _port(), _port_base()
    rpc_url = f"http://127.0.0.1:{rpc_port}"
    log = (run_dir / "validator.log").open("wb")
    validator = subprocess.Popen(
        [shutil.which("solana-test-validator") or "solana-test-validator", "--reset", "--ledger", str(run_dir / "ledger"),
         "--upgradeable-program", str(program_id), str(image), "none",
         "--rpc-port", str(rpc_port), "--faucet-port", str(faucet_port), "--gossip-port", str(_port()),
         "--dynamic-port-range", f"{base}-{base + 25}", "--quiet"],
        stdout=log, stderr=subprocess.STDOUT)
    endpoint = SolanaRpcEndpoint("local", rpc_url, config=RpcConfig(
        timeout_seconds=4, requests_per_second=50, max_in_flight=1, commitment=Commitment.CONFIRMED))
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
        say("validator", rpc=rpc_url, program=str(program_id), seconds=round(time.monotonic() - t0, 1))

        # C0: which DCG runtime does the deployed program embed?
        say("runtime", version=str(program_runtime_version(rpc_url, program_id)))

        payer, authority = Keypair(), Keypair()
        airdrop = await endpoint.request_airdrop(str(payer.pubkey()), 5_000_000_000)
        while (status := await endpoint.signature_status(airdrop)) is None or status.commitment not in {
                Commitment.CONFIRMED, Commitment.FINALIZED}:
            await asyncio.sleep(0.1)

        signers = SessionSigners(payer=payer, authority=authority)
        transport = SequencedInstructionTransport(endpoint=endpoint, signers=signers,
                                                  journal_dir=run_dir / "transactions")
        session = Session(kernel=KernelRef.from_manifest(TALLY_SESSION), transport=transport, signers=signers,
                          program_id=program_id, session_id=1, journal_path=run_dir / "accounts.json",
                          max_steps=len(INPUTS))
        await session.open()
        say("open", session=str(session.addresses.session))

        for value in INPUTS:
            await session.write_input(value)
        await session.advance(len(INPUTS))
        state = await session.read_state()
        count, total = struct.unpack("<QQ", state)
        info = await session.info()
        say("advance", inputs=INPUTS, count=count, sum=total, cursor=info.cursor,
            rejected=info.rejected_count, last_reject=[info.last_reject_sequence, info.last_reject_code])

        # The mirror predicts the same state from the same inputs.
        predicted = TALLY.initial_state(TALLY.state_spans)
        for value in INPUTS:
            predicted = TALLY.transition(bytes([value]), predicted).state
        agree = predicted == state
        say("mirror", agrees=agree)

        receipt = await session.close()
        say("close", receipt=str(receipt))
        ok = agree and (count, total) == (3, 15) and info.rejected_count == 1
        say("done", ok=ok, seconds=round(time.monotonic() - t0, 1), run_dir=str(run_dir))
        return 0 if ok else 1
    finally:
        validator.terminate()
        validator.wait(timeout=20)
        await endpoint.aclose()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(Path(sys.argv[1]))))
