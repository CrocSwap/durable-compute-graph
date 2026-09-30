"""Opt-in test-validator canary; see docs/sequencer.md for its scope and command."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey

from dcg.sequencer import (
    Backoff,
    Commitment,
    EndpointLimits,
    JournalStore,
    KeypairFileSigner,
    PostconditionResult,
    RetryPolicy,
    RpcConfig,
    RpcUnavailable,
    Sequencer,
    SequencerConfig,
    SolanaRpcEndpoint,
    TransactionPlan,
    TransactionStep,
)


PROGRAM_ID = Pubkey.from_bytes(bytes([0xD8]) * 32)
SYSTEM_PROGRAM = Pubkey.default()
CASE_ID = 1
TEST_STAKE_LAMPORTS = 2_000_000
_LOCAL_RUN_ENABLED = os.environ.get("DCG_RUN_LOCAL_VALIDATOR") == "1"


def _instruction(data: bytes, accounts: list[AccountMeta]) -> Instruction:
    return Instruction(PROGRAM_ID, data, accounts)


def _entries() -> bytes:
    inputs = (b"\x01\x02\x03", b"\x07", b"\x0a\x0b", b"\x04\x05\x06")
    encoded = bytearray()
    for value in inputs:
        encoded.append(len(value))
        encoded.extend(value)
        encoded.extend(bytes(8 - len(value)))
        encoded.extend(sum(value).to_bytes(8, "little"))
    return bytes(encoded)


def _build_plan(signer: KeypairFileSigner, endpoint_id: str, genesis_hash: str):
    payer = Pubkey.from_string(signer.public_key)
    template, _template_bump = Pubkey.find_program_address(
        [b"dcg-test-template", bytes(payer), bytes([CASE_ID])], PROGRAM_ID
    )
    document, _document_bump = Pubkey.find_program_address(
        [b"dcg-test-document", bytes(template), bytes([CASE_ID])], PROGRAM_ID
    )
    bond, _bond_bump = Pubkey.find_program_address(
        [b"dcg-test-bond", bytes(document), bytes([CASE_ID])], PROGRAM_ID
    )
    refund, _refund_bump = Pubkey.find_program_address(
        [b"dcg-test-refund", bytes(payer), bytes([CASE_ID])], PROGRAM_ID
    )

    register_data = (
        bytes([240, CASE_ID])
        + b"dcg-test-sum-v1\0"
        + (1).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + (0x4F50_5449).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
    )
    register = _instruction(
        register_data,
        [
            AccountMeta(payer, True, True),
            AccountMeta(template, False, True),
            AccountMeta(SYSTEM_PROGRAM, False, False),
        ],
    )
    admit = _instruction(
        bytes([241, CASE_ID]),
        [AccountMeta(payer, True, False), AccountMeta(template, False, True)],
    )
    init = _instruction(
        bytes([242, CASE_ID]) + TEST_STAKE_LAMPORTS.to_bytes(8, "little") + _entries(),
        [
            AccountMeta(payer, True, True),
            AccountMeta(template, False, False),
            AccountMeta(document, False, True),
            AccountMeta(bond, False, True),
            AccountMeta(SYSTEM_PROGRAM, False, False),
        ],
    )

    def document_step(tag: int):
        return _instruction(
            bytes([tag, CASE_ID]),
            [
                AccountMeta(payer, True, False),
                AccountMeta(template, False, False),
                AccountMeta(document, False, True),
            ],
        )

    land = document_step(243)
    finalize = document_step(244)
    resolve = document_step(245)
    close = _instruction(
        bytes([250, CASE_ID]),
        [
            AccountMeta(payer, True, True),
            AccountMeta(refund, False, True),
            AccountMeta(template, False, True),
            AccountMeta(document, False, True),
            AccountMeta(bond, False, True),
        ],
    )

    def account_state(address: Pubkey, test, label: str):
        async def check(endpoint):
            info = await endpoint.get_account_info(str(address), Commitment.CONFIRMED)
            if info is None or len(info.data) <= test[0] or info.data[test[0] : test[0] + len(test[1])] != test[1]:
                return PostconditionResult(False, None)
            return PostconditionResult(True, hashlib.sha256(label.encode() + info.data).hexdigest())

        return check

    def template_status(expected: int):
        async def check(endpoint):
            info = await endpoint.get_account_info(str(template), Commitment.CONFIRMED)
            if info is None or len(info.data) <= 6 or info.data[6] != expected:
                return PostconditionResult(False, None)
            return PostconditionResult(True, hashlib.sha256(info.data).hexdigest())

        return check

    async def closed_state(endpoint):
        info = await endpoint.get_account_info(str(document), Commitment.CONFIRMED)
        refund_info = await endpoint.get_account_info(str(refund), Commitment.CONFIRMED)
        if info is not None or refund_info is None or refund_info.lamports <= 0:
            return PostconditionResult(False, None)
        return PostconditionResult(True, hashlib.sha256(str(refund_info.lamports).encode()).hexdigest())

    instructions = [
        ("register", register, template_status(1), ()),
        ("admit", admit, template_status(2), ("register",)),
        ("init", init, account_state(document, (6, b"\x01"), "init"), ("admit",)),
        ("land", land, account_state(document, (6, b"\x02"), "land"), ("init",)),
        ("finalize", finalize, account_state(document, (6, b"\x03"), "finalize"), ("land",)),
        ("resolve", resolve, account_state(document, (6, b"\x04"), "resolve"), ("finalize",)),
        ("close", close, closed_state, ("resolve",)),
    ]
    steps = []
    for name, instruction, postcondition, dependencies in instructions:
        instruction_digest = hashlib.sha256(bytes(instruction)).hexdigest()

        def build_message(lease, ix=instruction):
            message = Message.new_with_blockhash(
                [ix], payer, Hash.from_string(lease.blockhash)
            )
            return bytes(message)

        steps.append(
            TransactionStep(
                step_id=name,
                dependencies=dependencies,
                endpoint_id=endpoint_id,
                compute_class=f"test-lifecycle-tag-{instruction.data[0]}",
                compute_unit_limit=180_000,
                intent_digest=instruction_digest,
                recovery_policy_digest=f"postcondition:{name}:v1",
                build_message=build_message,
                postcondition=postcondition,
                write_locks=("test-lifecycle-document",),
                retry_policy=RetryPolicy.NEVER,
            )
        )
    plan = TransactionPlan(
        genesis_hash=genesis_hash,
        program_id=str(PROGRAM_ID),
        destination_accounts=tuple(map(str, (template, document, bond, refund))),
        signer_public_key=signer.public_key,
        steps=tuple(steps),
    )
    return plan, (template, document, bond, refund)


class _CrashAfterAcceptedSend:
    """Wait after the first RPC acknowledgement so the parent can SIGKILL us."""

    def __init__(self, endpoint: SolanaRpcEndpoint, marker: Path):
        self._endpoint = endpoint
        self._marker = marker
        self.endpoint_id = endpoint.endpoint_id

    def __getattr__(self, name):
        return getattr(self._endpoint, name)

    async def send_raw_transaction(self, raw_bytes):
        receipt = await self._endpoint.send_raw_transaction(raw_bytes)
        self._marker.write_text(receipt.signature, encoding="ascii")
        await asyncio.Event().wait()


async def _child_entry() -> None:
    rpc_url = os.environ["DCG_LOCAL_VALIDATOR_RPC_URL"]
    keypair_file = Path(os.environ["DCG_LOCAL_VALIDATOR_KEYPAIR"])
    journal = JournalStore(Path(os.environ["DCG_LOCAL_VALIDATOR_JOURNAL"]))
    marker = Path(os.environ["DCG_LOCAL_VALIDATOR_CRASH_MARKER"])
    signer = KeypairFileSigner.from_file(keypair_file)
    endpoint = SolanaRpcEndpoint(
        "local-validator",
        rpc_url,
        config=RpcConfig(
            timeout_seconds=5,
            requests_per_second=200,
            max_in_flight=4,
            status_batch_window_seconds=0.002,
            commitment=Commitment.CONFIRMED,
        ),
    )
    try:
        genesis = await endpoint.get_genesis_hash()
        plan, _accounts = _build_plan(signer, endpoint.endpoint_id, genesis)
        sequencer = Sequencer(
            endpoints={endpoint.endpoint_id: _CrashAfterAcceptedSend(endpoint, marker)},
            signer=signer,
            config=SequencerConfig(
                endpoint_limits={endpoint.endpoint_id: EndpointLimits(200, 1)},
                max_batch_size=1,
                blockhash_lifetime_seconds=30,
                per_step_time_cap_seconds=90,
                confirmation_poll_seconds=0.25,
                backoff=Backoff(0.1, 1),
            ),
        )
        await sequencer.submit(plan, journal)
    finally:
        await endpoint.aclose()


class LocalValidatorTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(_LOCAL_RUN_ENABLED, "set DCG_RUN_LOCAL_VALIDATOR=1 to run the SBF local-validator canary")
    async def test_bytesum_honest_document_survives_sequencer_kill_and_resume(self):
        image = Path(os.environ["DCG_SBF_IMAGE"]).resolve()
        if not image.is_file():
            self.fail("DCG_SBF_IMAGE must point to the built dcg_program.so")
        validator = shutil.which("solana-test-validator")
        if validator is None:
            self.fail("solana-test-validator is required for the opt-in integration test")

        def free_port() -> int:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        rpc_port = free_port()
        faucet_port = free_port()
        rpc_url = f"http://127.0.0.1:{rpc_port}"
        task_dir = Path(tempfile.mkdtemp(prefix="dcg-sequencer-2-", dir="/private/tmp"))
        ledger = task_dir / "ledger"
        validator_log = task_dir / "validator.log"
        keypair_file = task_dir / "payer.json"
        journal_path = task_dir / "sequencer.jsonl"
        marker = task_dir / "accepted.marker"
        child_log = task_dir / "sequencer-child.log"
        payer = Keypair()
        keypair_file.write_text(json.dumps(list(bytes(payer))), encoding="ascii")
        keypair_file.chmod(0o600)
        validator_cmd = [
            validator,
            "--reset",
            "--ledger",
            str(ledger),
            "--bpf-program",
            str(PROGRAM_ID),
            str(image),
            "--rpc-port",
            str(rpc_port),
            "--faucet-port",
            str(faucet_port),
            "--quiet",
        ]
        start = time.monotonic()
        validator_output = validator_log.open("wb")
        process = subprocess.Popen(validator_cmd, stdout=validator_output, stderr=subprocess.STDOUT)
        child = None
        endpoint = SolanaRpcEndpoint(
            "local-validator",
            rpc_url,
            config=RpcConfig(
                timeout_seconds=3,
                requests_per_second=200,
                max_in_flight=4,
                status_batch_window_seconds=0.002,
                commitment=Commitment.CONFIRMED,
            ),
        )
        try:
            deadline = time.monotonic() + 45
            genesis = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail(f"solana-test-validator exited {process.returncode}; inspect {validator_log}")
                try:
                    await endpoint.get_health()
                    genesis = await endpoint.get_genesis_hash()
                    break
                except RpcUnavailable:
                    await asyncio.sleep(0.2)
            self.assertIsNotNone(genesis, "local validator did not become healthy")
            program = await endpoint.get_account_info(str(PROGRAM_ID), Commitment.FINALIZED)
            self.assertIsNotNone(program, "test-validator did not load the DCG SBF image")
            self.assertTrue(program.executable)

            airdrop = await endpoint.request_airdrop(str(payer.pubkey()), 10_000_000_000)
            airdrop_deadline = time.monotonic() + 30
            while time.monotonic() < airdrop_deadline:
                observation = await endpoint.signature_status(airdrop)
                if observation is not None and observation.commitment in {Commitment.CONFIRMED, Commitment.FINALIZED}:
                    break
                await asyncio.sleep(0.1)
            else:
                self.fail("local faucet airdrop did not confirm")

            child_env = os.environ.copy()
            child_env.update(
                {
                    "DCG_LOCAL_VALIDATOR_RPC_URL": rpc_url,
                    "DCG_LOCAL_VALIDATOR_KEYPAIR": str(keypair_file),
                    "DCG_LOCAL_VALIDATOR_JOURNAL": str(journal_path),
                    "DCG_LOCAL_VALIDATOR_CRASH_MARKER": str(marker),
                }
            )
            tests_dir = str(Path(__file__).resolve().parent)
            python_dir = str(Path(__file__).resolve().parents[1])
            child_env["PYTHONPATH"] = os.pathsep.join(
                part for part in (tests_dir, python_dir, child_env.get("PYTHONPATH", "")) if part
            )
            child_output = child_log.open("wb")
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve())],
                env={**child_env, "DCG_LOCAL_VALIDATOR_CHILD": "1"},
                stdout=child_output,
                stderr=subprocess.STDOUT,
            )
            child_deadline = time.monotonic() + 45
            while time.monotonic() < child_deadline and not marker.exists():
                if child.poll() is not None:
                    child_output.close()
                    tail = child_log.read_text(encoding="utf-8", errors="replace")[-6000:]
                    self.fail(
                        f"sequencer child exited {child.returncode} before the crash marker; "
                        f"diagnostic tail:\n{tail}"
                    )
                await asyncio.sleep(0.05)
            self.assertTrue(marker.exists(), "sequencer did not reach its first accepted send")
            child.kill()
            await asyncio.to_thread(child.wait, 10)
            child_output.close()
            child = None

            journal = JournalStore(journal_path)
            events_before_resume = journal.events()
            register_attempts_before = sum(
                event.name == "send_attempt_started" and event.data.get("step_id") == "register"
                for event in events_before_resume
            )
            register_acks_before = sum(
                event.name == "send_acknowledged" and event.data.get("step_id") == "register"
                for event in events_before_resume
            )
            self.assertEqual(register_attempts_before, 1)
            self.assertEqual(register_acks_before, 0, "the kill must leave the first packet fate ambiguous")

            signer = KeypairFileSigner.from_file(keypair_file)
            plan, (_template, document, _bond, _refund) = _build_plan(signer, endpoint.endpoint_id, genesis)
            sequencer = Sequencer(
                endpoints={endpoint.endpoint_id: endpoint},
                signer=signer,
                config=SequencerConfig(
                    endpoint_limits={endpoint.endpoint_id: EndpointLimits(200, 1)},
                    max_batch_size=1,
                    blockhash_lifetime_seconds=30,
                    per_step_time_cap_seconds=90,
                    confirmation_poll_seconds=0.25,
                    backoff=Backoff(0.1, 1),
                ),
            )
            result = await sequencer.resume(plan, journal)
            elapsed = time.monotonic() - start
            events = journal.events()
            attempts = sum(event.name == "send_attempt_started" for event in events)
            transactions = len(result.outcomes)
            retries = attempts - transactions
            self.assertEqual(transactions, 7)
            self.assertEqual((await endpoint.get_account_info(str(document), Commitment.FINALIZED)), None)
            self.assertEqual(result.outcomes["resolve"].confirmed_by, "signature")
            self.assertEqual(result.outcomes["register"].confirmed_by, "signature")
            print(
                "DCG_LOCAL_VALIDATOR_RESULT "
                f"transactions={transactions} wall_seconds={elapsed:.3f} retries={retries} "
                "recovered_ambiguous_fates=1"
            )
            (task_dir / "result.json").write_text(
                json.dumps(
                    {
                        "transactions": transactions,
                        "wall_seconds": elapsed,
                        "send_attempts": attempts,
                        "retries": retries,
                        "recovered_ambiguous_fates": 1,
                        "scope": "test-only ByteSum lifecycle, not revision-8",
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                await asyncio.to_thread(child.wait, 10)
            if "child_output" in locals() and not child_output.closed:
                child_output.close()
            keypair_file.unlink(missing_ok=True)
            await endpoint.aclose()
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, 10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 10)
            validator_output.close()
            trash = Path("/private/tmp/trash-dcg-sequencer-2")
            trash.mkdir(parents=True, exist_ok=True)
            if task_dir.exists():
                shutil.move(str(task_dir), str(trash / task_dir.name))


if __name__ == "__main__" and os.environ.get("DCG_LOCAL_VALIDATOR_CHILD") == "1":
    asyncio.run(_child_entry())
