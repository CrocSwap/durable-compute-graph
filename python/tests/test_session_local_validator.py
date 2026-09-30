"""Opt-in end-to-end check of Python-built stateful instructions on local SBF."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg.sequencer import Commitment, RpcConfig, SolanaRpcEndpoint, RpcUnavailable
from dcg.session import (
    COUNTER_MANIFEST,
    DEFAULT_PROGRAM_ID,
    CounterState,
    KernelRef,
    Session,
    SessionSigners,
    SequencedInstructionTransport,
    WritableAccountRefused,
)
from dcg.session.instructions import advance as encode_advance


ENABLED = os.environ.get("DCG_RUN_LOCAL_VALIDATOR") == "1"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class StatefulSessionLocalValidatorTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(ENABLED, "set DCG_RUN_LOCAL_VALIDATOR=1 and DCG_SBF_IMAGE to run the local SBF canary")
    async def test_python_session_counter_refusal_and_journaled_reclaim(self):
        image = Path(os.environ["DCG_SBF_IMAGE"]).resolve()
        self.assertTrue(image.is_file(), "DCG_SBF_IMAGE must point to the built dcg_program.so")
        validator = shutil.which("solana-test-validator")
        self.assertIsNotNone(validator, "solana-test-validator is required")

        rpc_port = _free_port()
        faucet_port = _free_port()
        rpc_url = f"http://127.0.0.1:{rpc_port}"
        run_dir = Path(tempfile.mkdtemp(prefix="dcg-python-session-", dir="/private/tmp"))
        log_path = run_dir / "validator.log"
        output = log_path.open("wb")
        process = subprocess.Popen(
            [
                validator,
                "--reset",
                "--ledger",
                str(run_dir / "ledger"),
                "--bpf-program",
                str(DEFAULT_PROGRAM_ID),
                str(image),
                "--rpc-port",
                str(rpc_port),
                "--faucet-port",
                str(faucet_port),
                "--quiet",
            ],
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        endpoint = SolanaRpcEndpoint(
            "dcg-session-local",
            rpc_url,
            config=RpcConfig(
                timeout_seconds=4,
                requests_per_second=20,
                max_in_flight=1,
                commitment=Commitment.CONFIRMED,
            ),
        )
        try:
            deadline = time.monotonic() + 45
            genesis = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                    self.fail(f"local validator exited {process.returncode}:\n{tail}")
                try:
                    await endpoint.get_health()
                    genesis = await endpoint.get_genesis_hash()
                    break
                except RpcUnavailable:
                    await asyncio.sleep(0.2)
            self.assertIsNotNone(genesis, "local validator did not become healthy")
            program = await endpoint.get_account_info(str(DEFAULT_PROGRAM_ID), Commitment.CONFIRMED)
            self.assertIsNotNone(program, "local validator did not load the DCG SBF program")
            self.assertTrue(program.executable)

            payer = Keypair()
            authority = Keypair()
            airdrop = await endpoint.request_airdrop(str(payer.pubkey()), 5_000_000_000)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                status = await endpoint.signature_status(airdrop)
                if status is not None and status.commitment in {Commitment.CONFIRMED, Commitment.FINALIZED}:
                    break
                await asyncio.sleep(0.1)
            else:
                self.fail("local validator faucet did not fund the session payer")

            signers = SessionSigners(payer=payer, authority=authority)
            transport = SequencedInstructionTransport(
                endpoint=endpoint,
                signers=signers,
                journal_dir=run_dir / "transactions",
            )
            session = Session(
                kernel=KernelRef.from_manifest(COUNTER_MANIFEST),
                transport=transport,
                signers=signers,
                program_id=DEFAULT_PROGRAM_ID,
                session_id=0xDCC01,
                journal_path=run_dir / "accounts.json",
            )
            await session.open()
            await session.write_input(7)

            malformed = encode_advance(
                program_id=DEFAULT_PROGRAM_ID,
                addresses=session.addresses,
                authority=authority.pubkey(),
                cursor=0,
                steps=1,
                wire_version=1,
                input_stream_writable=False,
            )
            with self.assertRaises(WritableAccountRefused) as refusal:
                await session._send(
                    malformed,
                    expected=((session.addresses.session, True), (session.addresses.stream, True))
                    + tuple((address, True) for address in session.addresses.states),
                )
            self.assertIn("input_stream", str(refusal.exception))
            self.assertIn("must be writable", str(refusal.exception))

            await session.advance(1)
            state = await session.read_state()
            self.assertEqual(state, CounterState(value=7, total=7))
            close_receipt = await session.close()
            self.assertGreater(close_receipt.rent_lamports, 0)
            self.assertEqual(len(close_receipt.accounts_closed), 4)
            self.assertEqual({record.lifecycle for record in session.inventory.accounts}, {"closed"})
            for account in close_receipt.accounts_closed:
                self.assertIsNone(await endpoint.get_account_info(account, Commitment.CONFIRMED))
            print(
                "DCG_SESSION_LOCAL_VALIDATOR_RESULT "
                f"input=7 value={state.value} total={state.total} "
                f"accounts_closed={len(close_receipt.accounts_closed)} "
                f"rent_refunded_lamports={close_receipt.rent_lamports}"
            )
        finally:
            await endpoint.aclose()
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, 10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 10)
            output.close()
            trash = Path("/private/tmp/trash-dcg-python-session")
            trash.mkdir(parents=True, exist_ok=True)
            if run_dir.exists():
                shutil.move(str(run_dir), str(trash / run_dir.name))


if __name__ == "__main__":
    unittest.main()
