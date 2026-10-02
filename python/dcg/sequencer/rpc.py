"""Paced asynchronous Solana JSON-RPC adapter for the sequencer."""

from __future__ import annotations

import asyncio
import base64
import itertools
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Sequence

import httpx

from .types import (
    AccountInfo,
    BlockhashExpired,
    BlockhashLease,
    Commitment,
    PlanError,
    ProgramRefused,
    RateLimited,
    RpcConfigurationError,
    RpcUnavailable,
    SendReceipt,
    SignatureObservation,
    SimulationResult,
)


@dataclass(frozen=True)
class RpcConfig:
    timeout_seconds: float = 10.0
    requests_per_second: float = 20.0
    max_in_flight: int = 8
    status_batch_window_seconds: float = 0.002
    status_batch_size: int = 256
    outage_cooldown_seconds: float = 0.25
    max_cooldown_seconds: float = 8.0
    commitment: Commitment = Commitment.CONFIRMED
    # Skip RPC preflight simulation. Program errors then surface through the
    # signature status instead of the send call; saves a full simulation per send.
    skip_preflight: bool = False


class SolanaRpcEndpoint:
    """Production HTTP JSON-RPC implementation of ``RpcEndpoint``.

    All methods share one request pacer, concurrency bound, 429 cooldown and
    outage backoff. Concurrent single-signature polls are coalesced into
    Solana's ``getSignatureStatuses([signatures])`` request form.
    """

    def __init__(
        self,
        endpoint_id: str,
        url: str,
        *,
        config: RpcConfig = RpcConfig(),
        client: httpx.AsyncClient | None = None,
    ):
        if not endpoint_id or not url.startswith(("http://", "https://")):
            raise ValueError("endpoint id and an HTTP(S) RPC URL are required")
        if config.timeout_seconds <= 0 or config.requests_per_second <= 0 or config.max_in_flight <= 0:
            raise ValueError("RPC timeout, request rate, and in-flight limit must be positive")
        if (
            config.status_batch_window_seconds < 0
            or config.status_batch_size <= 0
            or config.status_batch_size > 256
        ):
            raise ValueError("status batch window and size are invalid")
        if not isinstance(config.commitment, Commitment):
            raise ValueError("RPC commitment must be a Commitment value")
        if config.outage_cooldown_seconds < 0 or config.max_cooldown_seconds < 0:
            raise ValueError("RPC cooldowns cannot be negative")
        self._endpoint_id = endpoint_id
        self._url = url
        self.config = config
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout_seconds),
            limits=httpx.Limits(
                max_connections=config.max_in_flight,
                max_keepalive_connections=config.max_in_flight,
            ),
            headers={"content-type": "application/json"},
        )
        self._owns_client = client is None
        self._request_slots = asyncio.Semaphore(config.max_in_flight)
        self._pace_lock = asyncio.Lock()
        self._next_request_at = 0.0
        self._cooldown_until = 0.0
        self._outage_count = 0
        self._ids = itertools.count(1)
        self._genesis_hash: str | None = None
        self._status_lock = asyncio.Lock()
        self._pending_statuses: list[tuple[str, asyncio.Future[SignatureObservation | None]]] = []
        self._status_flush_task: asyncio.Task[None] | None = None

    @property
    def endpoint_id(self) -> str:
        return self._endpoint_id

    async def __aenter__(self) -> SolanaRpcEndpoint:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        task = self._status_flush_task
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)
        if self._owns_client:
            await self._client.aclose()

    async def get_genesis_hash(self) -> str:
        result = await self._call("getGenesisHash", [])
        if not isinstance(result, str) or not result:
            raise RpcUnavailable("RPC returned an invalid genesis hash")
        self._genesis_hash = result
        return result

    async def latest_blockhash(self, genesis_hash: str, lifetime_seconds: float) -> BlockhashLease:
        if lifetime_seconds <= 0:
            raise ValueError("blockhash lease lifetime must be positive")
        actual_genesis = self._genesis_hash or await self.get_genesis_hash()
        if actual_genesis != genesis_hash:
            raise PlanError("RPC endpoint genesis hash differs from the plan")
        result = await self._call(
            "getLatestBlockhash", [{"commitment": self.config.commitment.value}]
        )
        try:
            context = result["context"]
            value = result["value"]
            blockhash = value["blockhash"]
            last_valid = value["lastValidBlockHeight"]
            slot = context["slot"]
        except (KeyError, TypeError) as exc:
            raise RpcUnavailable("RPC returned an invalid latest blockhash result") from exc
        if not isinstance(blockhash, str) or not blockhash or not isinstance(last_valid, int):
            raise RpcUnavailable("RPC returned invalid blockhash lease fields")
        return BlockhashLease(
            blockhash=blockhash,
            genesis_hash=actual_genesis,
            fetched_at_unix=time.time(),
            last_valid_block_height=last_valid,
            context_slot=slot if isinstance(slot, int) else None,
            lifetime_seconds=lifetime_seconds,
        )

    async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt:
        encoded = base64.b64encode(raw_bytes).decode("ascii")
        result = await self._call(
            "sendTransaction",
            [
                encoded,
                {
                    "encoding": "base64",
                    "skipPreflight": self.config.skip_preflight,
                    "preflightCommitment": self.config.commitment.value,
                    "maxRetries": 0,
                },
            ],
        )
        if not isinstance(result, str) or not result:
            raise RpcUnavailable("RPC returned an invalid sendTransaction signature")
        return SendReceipt(result)

    async def signature_status(self, signature: str) -> SignatureObservation | None:
        return await self._batched_signature_status(signature)

    async def signature_statuses(
        self, signatures: Sequence[str]
    ) -> dict[str, SignatureObservation | None]:
        """Read a group of statuses with one getSignatureStatuses RPC call per 256 signatures."""

        if any(not isinstance(signature, str) or not signature for signature in signatures):
            raise ValueError("signature status requests require non-empty signatures")
        output: dict[str, SignatureObservation | None] = {}
        for start in range(0, len(signatures), self.config.status_batch_size):
            group = list(signatures[start : start + self.config.status_batch_size])
            if not group:
                continue
            result = await self._call("getSignatureStatuses", [group, {"searchTransactionHistory": True}])
            try:
                values = result["value"]
            except (KeyError, TypeError) as exc:
                raise RpcUnavailable("RPC returned an invalid signature status result") from exc
            if not isinstance(values, list) or len(values) != len(group):
                raise RpcUnavailable("RPC returned the wrong number of signature statuses")
            for signature, value in zip(group, values, strict=True):
                output[signature] = self._parse_status(signature, value)
        return output

    async def _batched_signature_status(self, signature: str) -> SignatureObservation | None:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[SignatureObservation | None] = loop.create_future()
        async with self._status_lock:
            self._pending_statuses.append((signature, future))
            if self._status_flush_task is None:
                self._status_flush_task = loop.create_task(self._flush_statuses())
        return await future

    async def _flush_statuses(self) -> None:
        await asyncio.sleep(self.config.status_batch_window_seconds)
        async with self._status_lock:
            pending = self._pending_statuses
            self._pending_statuses = []
            self._status_flush_task = None
        if not pending:
            return
        try:
            results = await self.signature_statuses([signature for signature, _ in pending])
        except Exception as exc:
            for _signature, future in pending:
                if not future.done():
                    future.set_exception(exc)
        else:
            for signature, future in pending:
                if not future.done():
                    future.set_result(results[signature])

    async def get_account_info(self, address: str, commitment: Commitment) -> AccountInfo | None:
        if commitment not in {Commitment.CONFIRMED, Commitment.FINALIZED}:
            raise ValueError("getAccountInfo commitment must be confirmed or finalized")
        result = await self._call(
            "getAccountInfo", [address, {"encoding": "base64", "commitment": commitment.value}]
        )
        try:
            context_slot = result["context"].get("slot")
            value = result["value"]
        except (KeyError, TypeError) as exc:
            raise RpcUnavailable("RPC returned an invalid getAccountInfo result") from exc
        if value is None:
            return None
        return self._parse_account_info(value, context_slot)

    async def get_multiple_accounts(
        self, addresses: Sequence[str], commitment: Commitment
    ) -> tuple[AccountInfo | None, ...]:
        """Read up to 100 accounts in one Solana ``getMultipleAccounts`` call."""

        if commitment not in {Commitment.CONFIRMED, Commitment.FINALIZED}:
            raise ValueError("getMultipleAccounts commitment must be confirmed or finalized")
        if len(addresses) > 100 or any(not isinstance(address, str) or not address for address in addresses):
            raise ValueError("getMultipleAccounts needs at most 100 non-empty addresses")
        result = await self._call(
            "getMultipleAccounts",
            [list(addresses), {"encoding": "base64", "commitment": commitment.value}],
        )
        try:
            context_slot = result["context"].get("slot")
            values = result["value"]
        except (KeyError, TypeError) as exc:
            raise RpcUnavailable("RPC returned an invalid getMultipleAccounts result") from exc
        if not isinstance(values, list) or len(values) != len(addresses):
            raise RpcUnavailable("RPC returned the wrong number of getMultipleAccounts values")
        slot = context_slot if isinstance(context_slot, int) else None
        return tuple(None if value is None else self._parse_account_info(value, slot) for value in values)

    async def get_program_accounts(
        self,
        program_id: str,
        *,
        filters: Sequence[dict[str, object]],
        commitment: Commitment,
    ) -> tuple[tuple[str, AccountInfo], ...]:
        """Read program-owned accounts matching the supplied Solana filters."""

        if commitment not in {Commitment.CONFIRMED, Commitment.FINALIZED}:
            raise ValueError("getProgramAccounts commitment must be confirmed or finalized")
        result = await self._call(
            "getProgramAccounts",
            [
                program_id,
                {
                    "encoding": "base64",
                    "commitment": commitment.value,
                    "withContext": True,
                    "filters": list(filters),
                },
            ],
        )
        try:
            context_slot = result["context"].get("slot")
            values = result["value"]
        except (KeyError, TypeError) as exc:
            raise RpcUnavailable("RPC returned an invalid getProgramAccounts result") from exc
        if not isinstance(values, list):
            raise RpcUnavailable("RPC returned malformed getProgramAccounts values")
        slot = context_slot if isinstance(context_slot, int) else None
        parsed: list[tuple[str, AccountInfo]] = []
        try:
            for item in values:
                address = item["pubkey"]
                if not isinstance(address, str) or not address:
                    raise ValueError
                parsed.append((address, self._parse_account_info(item["account"], slot)))
        except (KeyError, TypeError, ValueError) as exc:
            raise RpcUnavailable("RPC returned malformed getProgramAccounts entries") from exc
        return tuple(parsed)

    @staticmethod
    def _parse_account_info(value: object, context_slot: int | None) -> AccountInfo:
        try:
            data_value = value["data"]
            if not isinstance(data_value, list) or len(data_value) != 2 or data_value[1] != "base64":
                raise ValueError
            data = base64.b64decode(data_value[0], validate=True)
            owner = value["owner"]
            lamports = value["lamports"]
            executable = value["executable"]
            rent_epoch = value.get("rentEpoch")
        except (KeyError, TypeError, ValueError) as exc:
            raise RpcUnavailable("RPC returned malformed account info") from exc
        if (
            not isinstance(owner, str)
            or not isinstance(lamports, int)
            or isinstance(lamports, bool)
            or lamports < 0
            or not isinstance(executable, bool)
            or (rent_epoch is not None and not isinstance(rent_epoch, int))
        ):
            raise RpcUnavailable("RPC returned malformed account info fields")
        return AccountInfo(
            owner=owner,
            lamports=lamports,
            executable=executable,
            rent_epoch=rent_epoch,
            data=data,
            context_slot=context_slot,
        )

    async def get_health(self) -> str:
        result = await self._call("getHealth", [])
        if not isinstance(result, str) or not result:
            raise RpcUnavailable("RPC returned an invalid health result")
        if result != "ok":
            raise RpcUnavailable("RPC endpoint reports unhealthy")
        return result

    async def request_airdrop(self, address: str, lamports: int) -> str:
        """Request faucet funds on a development cluster such as test-validator."""

        if lamports <= 0:
            raise ValueError("airdrop amount must be positive")
        result = await self._call(
            "requestAirdrop", [address, lamports, {"commitment": self.config.commitment.value}]
        )
        if not isinstance(result, str) or not result:
            raise RpcUnavailable("RPC returned an invalid requestAirdrop signature")
        return result

    async def simulate_transaction(
        self,
        raw_transaction: bytes,
        *,
        commitment: Commitment = Commitment.CONFIRMED,
        sig_verify: bool = False,
        replace_recent_blockhash: bool = False,
    ) -> SimulationResult:
        result = await self._call(
            "simulateTransaction",
            [
                base64.b64encode(raw_transaction).decode("ascii"),
                {
                    "encoding": "base64",
                    "commitment": commitment.value,
                    "sigVerify": sig_verify,
                    "replaceRecentBlockhash": replace_recent_blockhash,
                },
            ],
        )
        try:
            value = result["value"]
        except (KeyError, TypeError) as exc:
            raise RpcUnavailable("RPC returned an invalid simulateTransaction result") from exc
        if not isinstance(value, dict):
            raise RpcUnavailable("RPC returned an invalid simulateTransaction value")
        logs = value.get("logs") or ()
        if not isinstance(logs, (tuple, list)) or any(not isinstance(line, str) for line in logs):
            raise RpcUnavailable("RPC returned malformed simulation logs")
        units = value.get("unitsConsumed")
        if units is not None and not isinstance(units, int):
            raise RpcUnavailable("RPC returned malformed simulation compute units")
        return SimulationResult(
            error=value.get("err"),
            logs=tuple(logs),
            units_consumed=units,
            return_data=value.get("returnData"),
        )

    async def _call(self, method: str, params: list[Any]) -> Any:
        request_id = next(self._ids)
        try:
            async with self._request_slots:
                await self._pace()
                response = await self._client.post(
                    self._url,
                    json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                )
        except httpx.TimeoutException as exc:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} timed out") from exc
        except httpx.TransportError as exc:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} transport failed") from exc

        if response.status_code == 429:
            delay = _retry_after(response.headers.get("retry-after"))
            await self._record_rate_limit(delay)
            raise RateLimited(f"RPC {method} returned HTTP 429", retry_after=delay)
        if response.status_code in {408, 425} or response.status_code >= 500:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise RpcConfigurationError(f"RPC {method} returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} returned a mismatched JSON-RPC envelope")
        self._outage_count = 0
        if "error" in payload:
            try:
                self._raise_rpc_error(method, payload["error"])
            except RateLimited as exc:
                await self._record_rate_limit(exc.retry_after)
                raise
            except RpcUnavailable:
                await self._record_outage()
                raise
        if "result" not in payload:
            await self._record_outage()
            raise RpcUnavailable(f"RPC {method} response has no result")
        return payload["result"]

    async def _pace(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._pace_lock:
            now = loop.time()
            start_at = max(now, self._next_request_at, self._cooldown_until)
            self._next_request_at = start_at + (1.0 / self.config.requests_per_second)
            delay = start_at - now
        if delay > 0:
            await asyncio.sleep(delay)

    async def _record_rate_limit(self, retry_after: float | None) -> None:
        loop = asyncio.get_running_loop()
        delay = retry_after if retry_after is not None else self.config.outage_cooldown_seconds
        async with self._pace_lock:
            self._cooldown_until = max(self._cooldown_until, loop.time() + max(0.0, delay))

    async def _record_outage(self) -> None:
        loop = asyncio.get_running_loop()
        self._outage_count += 1
        delay = min(
            self.config.max_cooldown_seconds,
            self.config.outage_cooldown_seconds * (2 ** min(self._outage_count - 1, 12)),
        )
        async with self._pace_lock:
            self._cooldown_until = max(self._cooldown_until, loop.time() + delay)

    def _raise_rpc_error(self, method: str, error: Any) -> None:
        if not isinstance(error, dict):
            raise RpcUnavailable(f"RPC {method} returned an invalid error object")
        code = error.get("code")
        message = error.get("message")
        safe_message = message if isinstance(message, str) else "JSON-RPC error"
        lowered = safe_message.lower()
        if "blockhashnotfound" in lowered or "blockhash not found" in lowered:
            raise BlockhashExpired(safe_message)
        if "too many requests" in lowered or "rate limit" in lowered:
            raise RateLimited(safe_message)
        if "instructionerror" in lowered or "custom program error" in lowered or "error processing instruction" in lowered:
            raise ProgramRefused(safe_message)
        if code in {-32005, -32004} or "node is unhealthy" in lowered or "node unhealthy" in lowered:
            raise RpcUnavailable(safe_message)
        # Unknown RPC errors are treated as transient. In particular, they do
        # not authorize a second signed identity; the sequencer reconciles the
        # original signature and account state before any rebuild.
        raise RpcUnavailable(safe_message)

    @staticmethod
    def _parse_status(signature: str, value: Any) -> SignatureObservation | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise RpcUnavailable("RPC returned a malformed signature status")
        commitment = value.get("confirmationStatus")
        if commitment is None:
            confirmations = value.get("confirmations")
            commitment = "finalized" if confirmations is None else ("confirmed" if confirmations else "processed")
        try:
            status_commitment = Commitment(commitment)
        except ValueError as exc:
            raise RpcUnavailable("RPC returned an unknown signature commitment") from exc
        error = value.get("err")
        if error is not None:
            error = json.dumps(error, sort_keys=True, separators=(",", ":"))
        slot = value.get("slot")
        if slot is not None and not isinstance(slot, int):
            raise RpcUnavailable("RPC returned a malformed signature slot")
        return SignatureObservation(
            signature=signature,
            commitment=status_commitment,
            error=error,
            slot=slot,
            transaction_metadata_available=False,
        )


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None
