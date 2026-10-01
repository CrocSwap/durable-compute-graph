"""Send-only RPC and Rust TPU/QUIC providers for signed transaction bytes.

Integration contract
--------------------
Package C selects an :class:`EndpointRoute` from ``pool.py`` after signing and
durably journaling a packet, then calls ``provider.send_raw(packet.raw_bytes,
packet.signature, route)``. The provider receives no signer, message builder,
blockhash policy, or authority to create a new transaction. On a retry, Package
C must pass the exact bytes retained by its journal. An ambiguous helper death
is returned to the sequencer; it does not cause this module to replay the
packet. A later caller retry will lazily start a fresh helper and submit only
the bytes it supplies. TPU ``ERR`` records arrive asynchronously, so Package C
must consume ``drain_failures`` or install ``failure_handler`` and reconcile
those signatures through its journal. Before using TPU, Package C also checks
the configured RPC observer's genesis and binds the helper URL to that checked
cluster identity.

The TPU sidecar is an explicit runtime dependency. Build the checked-in
``rust/tpu-sender`` crate with Cargo and pass its executable path in
:class:`TpuQuicConfig`. The helper accepts little-endian length-prefixed signed
wire packets on stdin and is send-only; RPC still owns signature/account
observation. Tests inject an in-memory helper factory and never start a process.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import struct
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Awaitable, Callable, Mapping, Protocol, Sequence

import httpx
from solders.signature import Signature

from .pool import EndpointRoute
from .types import (
    FailureClass,
    RpcEndpoint,
    RpcError,
    RpcUnavailable,
    SendReceipt,
    SequencerError,
)


class SendDisposition(str, Enum):
    """What a provider can attest about the transport handoff."""

    RPC_ACCEPTED = "rpc-accepted"
    HELPER_PIPE_WRITTEN = "helper-pipe-written"


@dataclass(frozen=True)
class ProviderReceipt:
    signature: str
    provider_id: str
    endpoint_id: str
    disposition: SendDisposition
    accepted_at_unix: float


class SendProvider(Protocol):
    """Send already-signed bytes without owning confirmation or rebuilding."""

    @property
    def provider_id(self) -> str: ...

    async def send_raw(
        self, raw_bytes: bytes, expected_signature: str, route: EndpointRoute
    ) -> ProviderReceipt: ...


class ProviderProtocolError(SequencerError):
    """A provider response does not match the signed packet it was given."""


class TpuHelperDied(RpcUnavailable):
    """The sidecar died during handoff; the signed packet's fate is ambiguous."""

    failure_class = FailureClass.AMBIGUOUS

    def __init__(self, message: str, *, returncode: int | None = None):
        self.returncode = returncode
        suffix = f" (exit code {returncode})" if returncode is not None else ""
        super().__init__(message + suffix)


@dataclass(frozen=True)
class TpuSendFailure:
    """Asynchronous helper ERR line, attributable to an already journaled signature."""

    signature: str | None
    reason: str
    provider_id: str


@dataclass(frozen=True)
class TpuQuicConfig:
    helper_binary: str | os.PathLike[str]
    rpc_url: str
    ws_url: str | None = None
    bind_address: str | None = None
    fanout_slots: int = 8
    connections: int = 1
    rate: float | None = None
    send_timeout_ms: int | None = None
    reconnect_min_interval_seconds: int | None = None
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not str(self.helper_binary):
            raise ValueError("helper_binary must name the packaged TPU helper executable")
        if not self.rpc_url.startswith(("http://", "https://")):
            raise ValueError("rpc_url must use HTTP or HTTPS")
        if self.ws_url is not None and not self.ws_url.startswith(("ws://", "wss://")):
            raise ValueError("ws_url must use WS or WSS")
        if self.fanout_slots <= 0 or self.connections <= 0:
            raise ValueError("fanout_slots and connections must be positive")
        if self.rate is not None and (self.rate <= 0 or not float(self.rate) < float("inf")):
            raise ValueError("rate must be finite and positive")
        if self.send_timeout_ms is not None and self.send_timeout_ms <= 0:
            raise ValueError("send_timeout_ms must be positive")
        if self.reconnect_min_interval_seconds is not None and self.reconnect_min_interval_seconds < 0:
            raise ValueError("reconnect_min_interval_seconds cannot be negative")


class TpuSendHelper(Protocol):
    async def send_raw(self, raw_bytes: bytes, expected_signature: str) -> None: ...

    async def close(self) -> None: ...


HelperFactory = Callable[[], TpuSendHelper | Awaitable[TpuSendHelper]]
FailureHandler = Callable[[TpuSendFailure], Awaitable[None] | None]


class RpcSendProvider:
    """RPC ``sendTransaction`` adapter; status and account reads stay separate."""

    def __init__(self, endpoints: Mapping[str, RpcEndpoint], *, provider_id: str = "rpc"):
        if not provider_id:
            raise ValueError("provider_id must be non-empty")
        if not endpoints:
            raise ValueError("RPC send provider requires at least one endpoint")
        for endpoint_id, endpoint in endpoints.items():
            if endpoint.endpoint_id != endpoint_id:
                raise ValueError(f"RPC mapping key {endpoint_id!r} differs from endpoint identity")
        self._endpoints = dict(endpoints)
        self._provider_id = provider_id

    @property
    def provider_id(self) -> str:
        return self._provider_id

    async def send_raw(
        self, raw_bytes: bytes, expected_signature: str, route: EndpointRoute
    ) -> ProviderReceipt:
        packet = _validate_packet(raw_bytes, expected_signature)
        if route.is_probe:
            raise ValueError("health-probe routes cannot submit transactions")
        try:
            endpoint = self._endpoints[route.endpoint_id]
        except KeyError as exc:
            raise ValueError(f"RPC provider has no endpoint {route.endpoint_id!r}") from exc
        try:
            result: SendReceipt = await endpoint.send_raw_transaction(packet)
        except RpcError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise RpcUnavailable(f"RPC send failed at {route.endpoint_id}: {exc}") from exc
        if result.signature != expected_signature:
            raise ProviderProtocolError(
                f"RPC send returned {result.signature!r} for packet {expected_signature!r}"
            )
        return ProviderReceipt(
            signature=expected_signature,
            provider_id=self.provider_id,
            endpoint_id=route.endpoint_id,
            disposition=SendDisposition.RPC_ACCEPTED,
            accepted_at_unix=time.time(),
        )


class TpuQuicSendProvider:
    """Persistent Rust TPU helper wrapper with journal-authorized restart retries."""

    def __init__(
        self,
        config: TpuQuicConfig,
        *,
        provider_id: str = "tpu-quic",
        helper_factory: HelperFactory | None = None,
        failure_handler: FailureHandler | None = None,
        max_retained_failures: int = 256,
    ):
        if not provider_id:
            raise ValueError("provider_id must be non-empty")
        if max_retained_failures <= 0:
            raise ValueError("max_retained_failures must be positive")
        self.config = config
        self._provider_id = provider_id
        self._helper_factory = helper_factory
        self._failure_handler = failure_handler
        self._failures: deque[TpuSendFailure] = deque(maxlen=max_retained_failures)
        self._helper: TpuSendHelper | None = None
        self._helper_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._closed = False

    @property
    def provider_id(self) -> str:
        return self._provider_id

    async def send_raw(
        self, raw_bytes: bytes, expected_signature: str, route: EndpointRoute
    ) -> ProviderReceipt:
        packet = _validate_packet(raw_bytes, expected_signature)
        if route.is_probe:
            raise ValueError("health-probe routes cannot submit transactions")
        if self._closed:
            raise TpuHelperDied("TPU provider is closed")
        helper = await self._get_helper()
        try:
            # A failed helper call is an ambiguous fate. Do not resend here: only
            # the sequencer's journal and retry policy can authorize that action.
            async with self._send_lock:
                await helper.send_raw(packet, expected_signature)
        except TpuHelperDied:
            await self._retire_helper(helper)
            raise
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            await self._retire_helper(helper)
            raise TpuHelperDied(f"TPU helper pipe failed: {exc}") from exc
        return ProviderReceipt(
            signature=expected_signature,
            provider_id=self.provider_id,
            endpoint_id=route.endpoint_id,
            disposition=SendDisposition.HELPER_PIPE_WRITTEN,
            accepted_at_unix=time.time(),
        )

    def drain_failures(self) -> tuple[TpuSendFailure, ...]:
        """Drain bounded asynchronous ERR records emitted by the sidecar."""

        failures = tuple(self._failures)
        self._failures.clear()
        return failures

    async def close(self) -> None:
        self._closed = True
        async with self._helper_lock:
            helper = self._helper
            self._helper = None
        if helper is not None:
            await helper.close()

    async def _get_helper(self) -> TpuSendHelper:
        async with self._helper_lock:
            if self._closed:
                raise TpuHelperDied("TPU provider is closed")
            if self._helper is None:
                helper = await self._new_helper()
                self._helper = helper
            return self._helper

    async def _new_helper(self) -> TpuSendHelper:
        if self._helper_factory is not None:
            helper = self._helper_factory()
            if inspect.isawaitable(helper):
                helper = await helper
            return helper
        helper = _SubprocessTpuHelper(self._command(), self._on_helper_failure)
        await helper.start()
        return helper

    async def _retire_helper(self, helper: TpuSendHelper) -> None:
        async with self._helper_lock:
            if self._helper is helper:
                self._helper = None
        try:
            await helper.close()
        except Exception:
            # Preserve the send failure. close() is best-effort cleanup.
            pass

    def _command(self) -> tuple[str, ...]:
        binary = Path(self.config.helper_binary).expanduser()
        if not binary.is_file():
            raise FileNotFoundError(
                f"DCG TPU helper not found at {binary}; build rust/tpu-sender with Cargo "
                "and configure helper_binary to the resulting executable"
            )
        if not os.access(binary, os.X_OK):
            raise PermissionError(f"DCG TPU helper is not executable: {binary}")
        command = [str(binary), "--rpc", self.config.rpc_url]
        if self.config.ws_url is not None:
            command += ["--ws", self.config.ws_url]
        command += ["--fanout-slots", str(self.config.fanout_slots)]
        command += ["--connections", str(self.config.connections)]
        if self.config.bind_address is not None:
            command += ["--bind", self.config.bind_address]
        if self.config.rate is not None:
            command += ["--rate", str(self.config.rate)]
        if self.config.send_timeout_ms is not None:
            command += ["--send-timeout-ms", str(self.config.send_timeout_ms)]
        if self.config.reconnect_min_interval_seconds is not None:
            command += [
                "--reconnect-min-interval-secs",
                str(self.config.reconnect_min_interval_seconds),
            ]
        command.extend(self.config.extra_args)
        return tuple(command)

    async def _on_helper_failure(self, signature: str | None, reason: str) -> None:
        failure = TpuSendFailure(signature, reason, self.provider_id)
        self._failures.append(failure)
        if self._failure_handler is not None:
            result = self._failure_handler(failure)
            if inspect.isawaitable(result):
                await result


class _SubprocessTpuHelper:
    """The checked-in Rust helper's bounded stdin/stdout framing adapter."""

    def __init__(
        self,
        command: Sequence[str],
        on_failure: Callable[[str | None, str], Awaitable[None]],
    ):
        self._command = tuple(command)
        self._on_failure = on_failure
        self._process: asyncio.subprocess.Process | None = None
        self._write_lock = asyncio.Lock()
        self._reader_tasks: tuple[asyncio.Task[None], ...] = ()
        self._stderr_tail: deque[str] = deque(maxlen=20)

    async def start(self) -> None:
        if self._process is not None:
            return
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._reader_tasks = (
            asyncio.create_task(self._read_stdout(self._process.stdout)),
            asyncio.create_task(self._read_stderr(self._process.stderr)),
        )

    async def send_raw(self, raw_bytes: bytes, expected_signature: str) -> None:
        process = self._process
        if process is None or process.stdin is None or process.returncode is not None:
            raise self._death("TPU helper exited before send")
        frame = struct.pack("<I", len(raw_bytes)) + raw_bytes
        async with self._write_lock:
            if process.returncode is not None or process.stdin.is_closing():
                raise self._death("TPU helper stdin is closed")
            try:
                process.stdin.write(frame)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionError, OSError, RuntimeError) as exc:
                raise self._death(f"TPU helper pipe failed: {exc}") from exc

    async def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.is_closing():
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except TimeoutError:
                process.kill()
                await process.wait()
        if self._reader_tasks:
            for task in self._reader_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self._reader_tasks, return_exceptions=True)

    async def _read_stdout(self, stream: asyncio.StreamReader) -> None:
        while line := await stream.readline():
            text = line.decode("utf-8", "replace").strip()
            if not text.startswith("ERR "):
                continue
            _, _, rest = text.partition(" ")
            signature, _, reason = rest.partition(" ")
            try:
                await self._on_failure(
                    None if signature == "-" else signature,
                    reason or "send-failed",
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # The bounded local failure queue is updated before invoking a
                # caller hook; a bad diagnostics hook must not stop pipe drains.
                continue

    async def _read_stderr(self, stream: asyncio.StreamReader) -> None:
        while line := await stream.readline():
            text = line.decode("utf-8", "replace").rstrip()
            if text:
                self._stderr_tail.append(text)

    def _death(self, message: str) -> TpuHelperDied:
        process = self._process
        return TpuHelperDied(
            message,
            returncode=None if process is None else process.returncode,
        )


def _validate_packet(raw_bytes: bytes, expected_signature: str) -> bytes:
    if not isinstance(raw_bytes, bytes):
        raise TypeError("raw_bytes must be immutable bytes")
    if not 1 <= len(raw_bytes) <= 1232:
        raise ValueError("signed transaction bytes must be between 1 and 1232 bytes")
    count, offset = _decode_shortvec(raw_bytes)
    if count < 1 or len(raw_bytes) < offset + 64 * count:
        raise ValueError("signed transaction has a malformed signature header")
    try:
        wanted = Signature.from_string(expected_signature)
        actual = Signature.from_bytes(raw_bytes[offset : offset + 64])
    except (ValueError, TypeError) as exc:
        raise ValueError("expected_signature or packet signature is invalid") from exc
    if actual != wanted:
        raise ValueError("expected_signature does not match the packet's first signature")
    return raw_bytes


def _decode_shortvec(data: bytes) -> tuple[int, int]:
    value = 0
    for index in range(3):
        if index >= len(data):
            raise ValueError("truncated transaction signature count")
        byte = data[index]
        value |= (byte & 0x7F) << (7 * index)
        if byte & 0x80 == 0:
            return value, index + 1
    raise ValueError("transaction signature count is too long")
