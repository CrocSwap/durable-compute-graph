from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import httpx
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from dcg.sequencer import (
    Backoff,
    BlockhashExpired,
    BlockhashLease,
    Commitment,
    EndpointLimits,
    JournalStore,
    KeypairFileSigner,
    PlanError,
    PostconditionResult,
    ProgramRefused,
    RateLimited,
    RpcConfigurationError,
    RpcConfig,
    RpcUnavailable,
    Sequencer,
    SequencerConfig,
    SignatureObservation,
    SimulationResult,
    SolanaRpcEndpoint,
    TransactionPlan,
    TransactionStep,
)


GENESIS = "11111111111111111111111111111111"
BLOCKHASH = "SysvarRent111111111111111111111111111111111"


class RpcAdapterTests(unittest.IsolatedAsyncioTestCase):
    def endpoint(self, handler, *, config: RpcConfig | None = None):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        endpoint = SolanaRpcEndpoint(
            "local",
            "http://rpc.invalid",
            config=config or RpcConfig(requests_per_second=100_000, status_batch_window_seconds=0.002),
            client=client,
        )
        self.addAsyncCleanup(endpoint.aclose)
        self.addAsyncCleanup(client.aclose)
        return endpoint

    async def test_rpc_methods_and_status_coalescing(self):
        calls: list[dict] = []
        signatures = ["sig-a", "sig-b"]
        account_bytes = b"account-state\x00"

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            calls.append(payload)
            method = payload["method"]
            if method == "getGenesisHash":
                result = GENESIS
            elif method == "getLatestBlockhash":
                self.assertEqual(payload["params"], [{"commitment": "confirmed"}])
                result = {"context": {"slot": 44}, "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": 99}}
            elif method == "getSignatureStatuses":
                requested = payload["params"][0]
                result = {
                    "context": {"slot": 45},
                    "value": [
                        {"slot": i + 1, "confirmations": None, "confirmationStatus": "finalized", "err": None}
                        for i, _signature in enumerate(requested)
                    ],
                }
            elif method == "sendTransaction":
                self.assertEqual(payload["params"][1]["encoding"], "base64")
                self.assertEqual(base64.b64decode(payload["params"][0]), b"signed-packet")
                self.assertEqual(payload["params"][1]["preflightCommitment"], "confirmed")
                result = "send-signature"
            elif method == "getAccountInfo":
                self.assertIn(payload["params"][1]["commitment"], {"confirmed", "finalized"})
                result = {
                    "context": {"slot": 46},
                    "value": {
                        "owner": "Owner111111111111111111111111111111111",
                        "lamports": 1234,
                        "executable": False,
                        "rentEpoch": 7,
                        "data": [base64.b64encode(account_bytes).decode(), "base64"],
                    },
                }
            elif method == "getHealth":
                result = "ok"
            elif method == "requestAirdrop":
                result = "airdrop-signature"
            elif method == "simulateTransaction":
                self.assertEqual(base64.b64decode(payload["params"][0]), b"simulation-packet")
                result = {"context": {"slot": 47}, "value": {"err": None, "logs": ["ok"], "unitsConsumed": 17}}
            else:
                self.fail(f"unexpected RPC method {method}")
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

        endpoint = self.endpoint(handler)
        lease = await endpoint.latest_blockhash(GENESIS, 5)
        self.assertEqual(lease.blockhash, BLOCKHASH)
        self.assertEqual(lease.context_slot, 44)
        self.assertEqual(lease.last_valid_block_height, 99)

        first, second = await asyncio.gather(
            endpoint.signature_status(signatures[0]), endpoint.signature_status(signatures[1])
        )
        self.assertIsInstance(first, SignatureObservation)
        self.assertIsInstance(second, SignatureObservation)
        self.assertEqual(first.commitment, Commitment.FINALIZED)
        status_requests = [call for call in calls if call["method"] == "getSignatureStatuses"]
        self.assertEqual(len(status_requests), 1)
        self.assertEqual(status_requests[0]["params"][0], signatures)

        receipt = await endpoint.send_raw_transaction(b"signed-packet")
        self.assertEqual(receipt.signature, "send-signature")
        account_address = "Account111111111111111111111111111111111"
        finalized_account = await endpoint.get_account_info(account_address, Commitment.FINALIZED)
        confirmed_account = await endpoint.get_account_info(account_address, Commitment.CONFIRMED)
        self.assertEqual(finalized_account.data, account_bytes)
        self.assertEqual(confirmed_account.context_slot, 46)
        self.assertEqual(await endpoint.request_airdrop(account_address, 1_000), "airdrop-signature")
        with self.assertRaises(ValueError):
            await endpoint.get_account_info(account_address, Commitment.PROCESSED)
        self.assertEqual(await endpoint.get_health(), "ok")
        simulation = await endpoint.simulate_transaction(b"simulation-packet")
        self.assertEqual(simulation, SimulationResult(None, ("ok",), 17, None))

        called = {call["method"] for call in calls}
        self.assertEqual(
            called,
            {
                "getGenesisHash",
                "getLatestBlockhash",
                "getSignatureStatuses",
                "sendTransaction",
                "getAccountInfo",
                "getHealth",
                "requestAirdrop",
                "simulateTransaction",
            },
        )

    async def test_status_batch_splits_at_configured_limit(self):
        batches: list[list[str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            requested = payload["params"][0]
            batches.append(requested)
            result = {"context": {"slot": 1}, "value": [None] * len(requested)}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

        endpoint = self.endpoint(handler, config=RpcConfig(requests_per_second=100_000, status_batch_size=3))
        statuses = await endpoint.signature_statuses([f"sig-{i}" for i in range(7)])
        self.assertEqual(len(batches), 3)
        self.assertEqual([len(batch) for batch in batches], [3, 3, 1])
        self.assertEqual(len(statuses), 7)
        self.assertTrue(all(status is None for status in statuses.values()))

    async def test_429_retry_after_and_outage_map_to_round_one_classes(self):
        def limited_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"retry-after": "0.75"})

        endpoint = self.endpoint(limited_handler)
        with self.assertRaises(RateLimited) as limited:
            await endpoint.get_health()
        self.assertAlmostEqual(limited.exception.retry_after, 0.75)

        def outage_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        endpoint = self.endpoint(outage_handler)
        with self.assertRaises(RpcUnavailable):
            await endpoint.get_health()

        def auth_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        endpoint = self.endpoint(auth_handler)
        with self.assertRaises(RpcConfigurationError):
            await endpoint.get_health()

        def timeout_handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("private test timeout")

        endpoint = self.endpoint(timeout_handler)
        with self.assertRaisesRegex(RpcUnavailable, "timed out"):
            await endpoint.get_health()

    async def test_json_rpc_refusal_and_expired_blockhash_are_classified(self):
        def response_with_error(code: int, message: str):
            def handler(request: httpx.Request) -> httpx.Response:
                payload = json.loads(request.content)
                return httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": payload["id"], "error": {"code": code, "message": message}},
                )

            return handler

        endpoint = self.endpoint(response_with_error(-32002, "InstructionError: custom program error: 0x2"))
        with self.assertRaises(ProgramRefused):
            await endpoint.send_raw_transaction(b"packet")
        endpoint = self.endpoint(response_with_error(-32002, "BlockhashNotFound"))
        with self.assertRaises(BlockhashExpired):
            await endpoint.send_raw_transaction(b"packet")

    async def test_wrong_genesis_is_rejected_before_blockhash_use(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            calls.append(payload["method"])
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": GENESIS})

        endpoint = self.endpoint(handler)
        with self.assertRaises(PlanError):
            await endpoint.latest_blockhash("wrong-genesis", 3)
        self.assertEqual(calls, ["getGenesisHash"])


class KeypairFileSignerTests(unittest.IsolatedAsyncioTestCase):
    async def test_signs_one_signer_legacy_message_and_keeps_key_material_out_of_logs_and_journal(self):
        keypair = Keypair()
        secret = bytes(keypair)
        secret_json = json.dumps(list(secret), separators=(",", ":")).encode()
        pubkey_bytes = bytes(keypair.pubkey())
        message = bytes([1, 0, 0, 1]) + pubkey_bytes + bytes(Hash.default()) + bytes([0])

        class Endpoint:
            endpoint_id = "rpc"

            def __init__(self):
                self.signature: str | None = None
                self.sent = False

            async def latest_blockhash(self, genesis_hash, lifetime_seconds):
                return BlockhashLease("blockhash", genesis_hash, 1_800_000_000.0, lifetime_seconds=lifetime_seconds)

            async def send_raw_transaction(self, raw_bytes):
                self.assert_packet(raw_bytes)
                self.sent = True
                from dcg.sequencer import SendReceipt

                return SendReceipt(self.signature)

            def assert_packet(self, raw_bytes):
                self.last_packet = raw_bytes

            async def signature_status(self, signature):
                if self.signature is None or not self.sent:
                    return None
                return SignatureObservation(signature, Commitment.FINALIZED, slot=12)

        endpoint = Endpoint()
        with tempfile.TemporaryDirectory(prefix="dcg-keypair-signer-") as directory:
            keyfile = Path(directory) / "keypair.json"
            keyfile.write_bytes(secret_json)
            signer = KeypairFileSigner.from_file(keyfile)
            self.assertEqual(signer.public_key, str(keypair.pubkey()))

            signed = await signer.sign(
                message, BlockhashLease("blockhash", GENESIS, 1_800_000_000.0)
            )
            endpoint.signature = signed.signature
            signature = Signature.from_string(signed.signature)
            self.assertTrue(signature.verify(Pubkey.from_bytes(pubkey_bytes), message))
            self.assertEqual(signed.raw_bytes, b"\x01" + bytes(signature) + message)

            step = TransactionStep(
                step_id="signed-step",
                dependencies=(),
                endpoint_id="rpc",
                compute_class="test",
                compute_unit_limit=100_000,
                intent_digest="intent-test",
                recovery_policy_digest="recovery-test",
                build_message=lambda _lease: message,
                postcondition=lambda _endpoint: asyncio.sleep(0, result=PostconditionResult(False)),
            )
            plan = TransactionPlan(GENESIS, "Program111", ("Destination111",), signer.public_key, (step,))
            journal = JournalStore(Path(directory) / "run.jsonl")
            sequencer = Sequencer(
                endpoints={"rpc": endpoint},
                signer=signer,
                config=SequencerConfig(
                    endpoint_limits={"rpc": EndpointLimits(sends_per_second=100_000, max_in_flight=1)},
                    per_step_time_cap_seconds=1,
                    confirmation_poll_seconds=0,
                    backoff=Backoff(initial_seconds=0, maximum_seconds=0),
                ),
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                await sequencer.submit(plan, journal)
            journal_bytes = journal.path.read_bytes()
            captured = (stdout.getvalue() + stderr.getvalue()).encode()
            self.assertNotIn(secret_json, journal_bytes)
            self.assertNotIn(base64.b64encode(secret), journal_bytes)
            self.assertNotIn(secret_json, captured)
            self.assertNotIn(base64.b64encode(secret), captured)

    async def test_rejects_wrong_fee_payer_and_multisigner_messages(self):
        signer = KeypairFileSigner(Keypair())
        lease = BlockhashLease("blockhash", GENESIS, 1_800_000_000.0)
        wrong_payer = Keypair()
        message = bytes([1, 0, 0, 1]) + bytes(wrong_payer.pubkey()) + bytes(Hash.default()) + bytes([0])
        with self.assertRaisesRegex(ValueError, "fee payer"):
            await signer.sign(message, lease)
        multisigner = (
            bytes([2, 0, 0, 2])
            + bytes(signer._keypair.pubkey())
            + bytes(wrong_payer.pubkey())
            + bytes(Hash.default())
            + bytes([0])
        )
        with self.assertRaisesRegex(ValueError, "one required signer"):
            await signer.sign(multisigner, lease)


if __name__ == "__main__":
    unittest.main()
