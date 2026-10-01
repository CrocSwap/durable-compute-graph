from __future__ import annotations

import unittest

from solders.keypair import Keypair

from dcg.sequencer.pool import EndpointRoute
from dcg.sequencer.providers import (
    ProviderProtocolError,
    RpcSendProvider,
    SendDisposition,
    TpuHelperDied,
    TpuQuicConfig,
    TpuQuicSendProvider,
)
from dcg.sequencer.types import FailureClass, RateLimited, SendReceipt


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
            with self.assertRaises(FileNotFoundError):
                await provider.send_raw(self.packet, self.signature, self.route)
        finally:
            await provider.close()


if __name__ == "__main__":
    unittest.main()
