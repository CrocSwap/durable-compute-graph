"""Ordered pipelined lanes: send a chain of dependent transactions without a
round trip per step, and heal any step that lands out of order.

Measured on Fogo testnet (2026-10-01, Doom on DCG, 29 dependent transactions
per frame): per-step confirm waits gave 0.025 frames/s; this lane gave about
0.44 frames/s with every frame landing in order. Four levers:

1. **Tight compute requests.** The leader's cost tracker charges each
   transaction's *requested* limit against a per-writable-account block cap
   (2.5M cost units on Fogo). Blanket 1.4M requests allow one step per block
   and let a small later step jump ahead of a large earlier one.
2. **Strictly decreasing priority.** When conflicting transactions sit in the
   leader's buffer together, higher priority runs first, so earlier steps win.
3. **One ordered connection.** HTTP/1.1 pipelining writes every request in
   order on one socket before reading any response, to the lowest-latency node.
4. **Simulate-and-skip repair.** Applications must make each step refuse when
   it is not the next step (cursor/sequence guards). After a lane, any failed
   or missing step is replayed in order: a step whose simulation passes is sent
   and awaited; one whose simulation is refused has already landed.

The lane does not journal packets; exactly-once comes from the application's
on-chain guards, which is why those guards are a precondition.
"""

from __future__ import annotations

import base64
import json
import socket
import time
import urllib.request
from dataclasses import dataclass
from typing import Awaitable, Callable, Sequence
from urllib.parse import urlparse

from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction
from solders.message import Message
from solders.pubkey import Pubkey


@dataclass(frozen=True)
class LaneStep:
    step_id: str
    instructions: tuple[Instruction, ...]
    compute_unit_limit: int


@dataclass
class LaneResult:
    landed: int
    failed_first: int | None
    repaired: int
    skipped: int
    send_seconds: float
    landed_seconds: float
    slots: list[int | None]


Sign = Callable[[bytes], Awaitable[tuple[str, bytes]]]


class OrderedLane:
    def __init__(self, url: str, payer: Pubkey, sign: Sign, *, priority_step: int = 1000,
                 user_agent: str = "dcg-ordered-lane"):
        self.url, self.payer, self.sign = url, payer, sign
        self.priority_step = priority_step
        self.user_agent = user_agent

    def rpc(self, method: str, params: list):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json",
                                                      "User-Agent": self.user_agent})
        out = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    def blockhash(self, commitment: str = "confirmed") -> str:
        return self.rpc("getLatestBlockhash", [{"commitment": commitment}])["value"]["blockhash"]

    async def _build(self, step: LaneStep, blockhash: str, price: int) -> tuple[str, bytes]:
        message = Message.new_with_blockhash(
            [set_compute_unit_price(price), set_compute_unit_limit(step.compute_unit_limit), *step.instructions],
            self.payer, Hash.from_string(blockhash))
        return await self.sign(bytes(message))

    def _send_ordered(self, wires: Sequence[bytes]) -> None:
        u = urlparse(self.url)
        sock = socket.create_connection((u.hostname, u.port or 80), timeout=10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            for i, raw in enumerate(wires):
                body = json.dumps({"jsonrpc": "2.0", "id": i, "method": "sendTransaction",
                                   "params": [base64.b64encode(raw).decode(),
                                              {"encoding": "base64", "skipPreflight": True, "maxRetries": 0}]}).encode()
                sock.sendall((f"POST / HTTP/1.1\r\nHost: {u.hostname}\r\nContent-Type: application/json\r\n"
                              f"Content-Length: {len(body)}\r\nUser-Agent: {self.user_agent}\r\n\r\n").encode() + body)
            got = b""
            while got.count(b"HTTP/1.1 ") < len(wires):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                got += chunk
        finally:
            sock.close()

    async def run(self, steps: Sequence[LaneStep], *, wait_seconds: float = 20.0, repair: bool = True) -> LaneResult:
        blockhash = self.blockhash()
        n = len(steps)
        built = [await self._build(step, blockhash, self.priority_step * (n - i)) for i, step in enumerate(steps)]
        t0 = time.monotonic()
        self._send_ordered([raw for _sig, raw in built])
        sent = time.monotonic() - t0
        sigs = [sig for sig, _raw in built]
        statuses: list = [None] * n
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            statuses = self.rpc("getSignatureStatuses", [sigs])["value"]
            if all(v is not None for v in statuses) or any(v and v.get("err") for v in statuses):
                break
            time.sleep(0.1)
        landed_s = time.monotonic() - t0
        bad = [i for i, v in enumerate(statuses) if v is None or v.get("err")]
        base = min((v["slot"] for v in statuses if v), default=0)
        result = LaneResult(n - len(bad), bad[0] if bad else None, 0, 0, sent, landed_s,
                            [v["slot"] - base if v else None for v in statuses])
        if bad and repair:
            time.sleep(1.0)
            result.repaired, result.skipped = await self.repair(steps, bad[0])
        return result

    async def repair(self, steps: Sequence[LaneStep], start: int = 0) -> tuple[int, int]:
        sent = skipped = 0
        for step in list(steps)[start:]:
            sig, raw = await self._build(step, self.blockhash("processed"), 0)
            sim = self.rpc("simulateTransaction", [base64.b64encode(raw).decode(),
                                                   {"encoding": "base64", "commitment": "processed"}])["value"]
            if sim.get("err"):
                skipped += 1
                continue
            self.rpc("sendTransaction", [base64.b64encode(raw).decode(),
                                         {"encoding": "base64", "skipPreflight": True, "maxRetries": 0}])
            end = time.monotonic() + 15
            while time.monotonic() < end:
                status = self.rpc("getSignatureStatuses", [[sig]])["value"][0]
                if status is not None:
                    if status.get("err"):
                        raise RuntimeError(f"lane repair step {step.step_id} failed: {status['err']}")
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"lane repair step {step.step_id} did not land")
            sent += 1
        return sent, skipped
