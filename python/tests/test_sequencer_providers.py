from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest

from solders.keypair import Keypair

from dcg.sequencer.pool import EndpointRoute
from dcg.sequencer.providers import (
    ProviderProtocolError,
    RpcSendProvider,
    SendDisposition,
    TpuHelperDied,
    TpuHelperConfigurationError,
    TpuQuicConfig,
    TpuQuicSendProvider,
    _SubprocessTpuHelper,
)
from dcg.sequencer.types import FailureClass, RateLimited, RpcUnavailable, SendReceipt


def signed_wire_packet() -> tuple[bytes, str]:
    """Generate a disposable signature; no private material is retained."""

    signer = Keypair()
    signature = signer.sign_message(b"offline DCG TPU provider test")
    return b"\x01" + bytes(signature) + b"offline-message", str(signature)


class FakeEndpoint:
    def __init__(self, endpoint_id: str, *, errors: list[BaseException] | None = None):
        self.endpoint_id = endpoint_id
        self.errors = list(errors or [])
        self.sent: list[bytes] = []

    async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt:
        self.sent.append(raw_bytes)
        if self.errors:
            raise self.errors.pop(0)
        return SendReceipt(str_from_packet(raw_bytes))


def str_from_packet(raw_bytes: bytes) -> str:
    from solders.signature import Signature

    return str(Signature.from_bytes(raw_bytes[1:65]))


class MemoryHelper:
    def __init__(self, *, dead: bool = False):
        self.dead = dead
        self.sent: list[tuple[bytes, str]] = []
        self.closed = False

    async def send_raw(self, raw_bytes: bytes, expected_signature: str) -> None:
        if self.dead:
            # Model a helper dying after its pipe may have accepted this frame.
            self.sent.append((raw_bytes, expected_signature))
            raise TpuHelperDied("fake sidecar exited", returncode=7)
        self.sent.append((raw_bytes, expected_signature))

    async def close(self) -> None:
        self.closed = True


class SequencerProviderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.packet, self.signature = signed_wire_packet()
        self.route = EndpointRoute("rpc-a", "bulk")

    async def test_rpc_retry_reuses_exact_signed_bytes(self) -> None:
        endpoint = FakeEndpoint("rpc-a", errors=[RateLimited("429", retry_after=0)])
        provider = RpcSendProvider({"rpc-a": endpoint})
        with self.assertRaises(RateLimited):
            await provider.send_raw(self.packet, self.signature, self.route)
        receipt = await provider.send_raw(self.packet, self.signature, self.route)
        self.assertEqual(receipt.disposition, SendDisposition.RPC_ACCEPTED)
        self.assertEqual(endpoint.sent, [self.packet, self.packet])
        self.assertIs(endpoint.sent[0], self.packet)
        self.assertIs(endpoint.sent[1], self.packet)

    async def test_rpc_provider_rejects_signature_mismatch(self) -> None:
        endpoint = FakeEndpoint("rpc-a")
        provider = RpcSendProvider({"rpc-a": endpoint})
        other_signature = str(Keypair().sign_message(b"different packet"))
        with self.assertRaises(ValueError):
            await provider.send_raw(self.packet, other_signature, self.route)
        self.assertEqual(endpoint.sent, [])

    async def test_rpc_provider_rejects_mismatched_rpc_response(self) -> None:
        class BadEndpoint(FakeEndpoint):
            async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt:
                self.sent.append(raw_bytes)
                return SendReceipt(str(Keypair().sign_message(b"wrong response")))

        endpoint = BadEndpoint("rpc-a")
        provider = RpcSendProvider({"rpc-a": endpoint})
        with self.assertRaises(ProviderProtocolError):
            await provider.send_raw(self.packet, self.signature, self.route)

    async def test_helper_death_restarts_but_never_replays_without_caller_retry(self) -> None:
        dead = MemoryHelper(dead=True)
        survivor = MemoryHelper()
        helpers = iter((dead, survivor))
        spawn_count = 0

        def factory() -> MemoryHelper:
            nonlocal spawn_count
            spawn_count += 1
            return next(helpers)

        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="unused-in-test", rpc_url="http://127.0.0.1:8899"),
            helper_factory=factory,
        )
        try:
            with self.assertRaises(TpuHelperDied) as error:
                await provider.send_raw(self.packet, self.signature, self.route)
            self.assertEqual(error.exception.returncode, 7)
            self.assertIs(error.exception.failure_class, FailureClass.AMBIGUOUS)
            self.assertEqual(spawn_count, 1, "failed call must not be hidden by an automatic replay")
            self.assertEqual(dead.sent, [(self.packet, self.signature)])
            self.assertIs(dead.sent[0][0], self.packet)

            receipt = await provider.send_raw(self.packet, self.signature, self.route)
            self.assertEqual(receipt.disposition, SendDisposition.HELPER_PIPE_WRITTEN)
            self.assertEqual(spawn_count, 2)
            self.assertEqual(survivor.sent, [(self.packet, self.signature)])
            self.assertIs(survivor.sent[0][0], self.packet)
        finally:
            await provider.close()

    async def test_provider_error_and_retry_keep_packet_bytes_identical(self) -> None:
        class FailOnceHelper(MemoryHelper):
            async def send_raw(self, raw_bytes: bytes, expected_signature: str) -> None:
                if not self.sent:
                    raise TpuHelperDied("write failed after caller handed packet", returncode=9)
                await super().send_raw(raw_bytes, expected_signature)

        failing = FailOnceHelper()
        survivor = MemoryHelper()
        helpers = iter((failing, survivor))
        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="unused-in-test", rpc_url="https://rpc.invalid"),
            helper_factory=lambda: next(helpers),
        )
        try:
            with self.assertRaises(TpuHelperDied):
                await provider.send_raw(self.packet, self.signature, self.route)
            retry = await provider.send_raw(self.packet, self.signature, self.route)
            self.assertEqual(retry.signature, self.signature)
            # The replacement received precisely the caller's journal bytes.
            self.assertEqual(retry.disposition, SendDisposition.HELPER_PIPE_WRITTEN)
            self.assertEqual(survivor.sent, [(self.packet, self.signature)])
            self.assertIs(survivor.sent[0][0], self.packet)
        finally:
            await provider.close()

    async def test_tpu_configuration_requires_explicit_executable(self) -> None:
        provider = TpuQuicSendProvider(
            TpuQuicConfig(helper_binary="definitely-missing", rpc_url="http://127.0.0.1:8899")
        )
        try:
            with self.assertRaises(TpuHelperConfigurationError):
                await provider.send_raw(self.packet, self.signature, self.route)
        finally:
            await provider.close()

    async def test_tpu_configuration_rejects_unexecutable_helper(self) -> None:
        with tempfile.NamedTemporaryFile() as helper_file:
            os.chmod(helper_file.name, 0o600)
            provider = TpuQuicSendProvider(
                TpuQuicConfig(helper_binary=helper_file.name, rpc_url="http://127.0.0.1:8899")
            )
            try:
                with self.assertRaises(TpuHelperConfigurationError):
                    await provider.send_raw(self.packet, self.signature, self.route)
            finally:
                await provider.close()

    async def test_tpu_helper_died_is_not_an_rpc_unavailable_error(self) -> None:
        error = TpuHelperDied("helper exited", returncode=7)
        self.assertIs(error.failure_class, FailureClass.AMBIGUOUS)
        self.assertNotIsInstance(error, RpcUnavailable)


class SubprocessTpuHelperTests(unittest.IsolatedAsyncioTestCase):
    async def start_helper(self, script: str):
        failures: list[tuple[str | None, str]] = []
        failure_seen = asyncio.Event()
        exited = asyncio.Event()

        async def on_failure(signature: str | None, reason: str) -> None:
            failures.append((signature, reason))
            failure_seen.set()

        async def on_exit(_helper: _SubprocessTpuHelper) -> None:
            exited.set()

        helper = _SubprocessTpuHelper(
            [sys.executable, "-u", "-c", script],
            on_failure,
            on_exit,
            startup_timeout_seconds=1.0,
            pipe_drain_timeout_seconds=0.25,
        )
        await helper.start()
        return helper, failures, failure_seen, exited

    async def test_subprocess_protocol_frames_little_endian_length_and_payload(self) -> None:
        script = (
            "import struct,sys\n"
            "print('READY', flush=True)\n"
            "header=sys.stdin.buffer.read(4)\n"
            "length=struct.unpack('<I', header)[0]\n"
            "body=sys.stdin.buffer.read(length)\n"
            "print(f'ERR - frame:{length}:{body.hex()}', flush=True)\n"
            "sys.stdin.buffer.read()\n"
        )
        helper, failures, failure_seen, _exited = await self.start_helper(script)
        payload = b"signed transaction bytes"
        try:
            await helper.send_raw(payload, "unused-signature")
            await asyncio.wait_for(failure_seen.wait(), timeout=1.0)
            self.assertEqual(failures, [(None, f"frame:{len(payload)}:{payload.hex()}")])
        finally:
            await helper.close()

    async def test_startup_failure_reports_exit_and_stderr_tail(self) -> None:
        script = "import sys\nsys.stderr.write('startup exploded\\n')\nsys.stderr.flush()\nsys.exit(7)\n"
        failures: list[tuple[str | None, str]] = []

        async def on_failure(signature: str | None, reason: str) -> None:
            failures.append((signature, reason))

        async def on_exit(_helper: _SubprocessTpuHelper) -> None:
            pass

        helper = _SubprocessTpuHelper(
            [sys.executable, "-u", "-c", script],
            on_failure,
            on_exit,
            startup_timeout_seconds=1.0,
            pipe_drain_timeout_seconds=0.25,
        )
        with self.assertRaises(TpuHelperDied) as caught:
            await helper.start()
        self.assertEqual(caught.exception.returncode, 7)
        self.assertIn("startup exploded", caught.exception.stderr_tail)
        self.assertIn("startup exploded", str(caught.exception))
        self.assertEqual(failures, [(None, "helper-exited rc=7")])

    async def test_death_mid_stream_records_failure_and_retires_helper(self) -> None:
        script = (
            "import struct,sys\n"
            "print('READY', flush=True)\n"
            "header=sys.stdin.buffer.read(4)\n"
            "if len(header)==4: sys.stdin.buffer.read(struct.unpack('<I',header)[0])\n"
            "sys.stderr.write('fatal mid-stream\\n')\n"
            "sys.stderr.flush()\n"
            "sys.exit(9)\n"
        )
        helper, failures, _failure_seen, exited = await self.start_helper(script)
        try:
            await helper.send_raw(b"accepted then died", "unused-signature")
            await asyncio.wait_for(exited.wait(), timeout=1.0)
            self.assertIn((None, "helper-exited rc=9"), failures)
            with self.assertRaises(TpuHelperDied) as caught:
                await helper.send_raw(b"next frame", "unused-signature")
            error = caught.exception
            self.assertEqual(error.returncode, 9)
            self.assertIn("fatal mid-stream", error.stderr_tail)
            self.assertIn("fatal mid-stream", str(error))
        finally:
            await helper.close()


if __name__ == "__main__":
    unittest.main()
