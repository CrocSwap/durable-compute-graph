"""Ordered pipelined lanes: send a chain of dependent transactions without a
round trip per step, and heal any step that lands out of order.

Measured on Fogo testnet (2026-10-01, Doom on DCG, 29 dependent transactions
per frame): per-step confirm waits gave 0.025 frames/s; this lane gave about
0.44 frames/s with every frame landing in order. Four levers:

1. **Tight, non-decreasing compute requests.** The leader's cost tracker
   charges each transaction's *requested* limit against a per-writable-account
   block cap (2.5M cost units on Fogo). Blanket 1.4M requests allow one step
   per block; a later step requesting less than an earlier one can fit a block
   the earlier one could not and land first, so requests are raised to the
   running maximum along the lane.
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


def _read_responses(sock, count: int) -> list[bytes]:
    """Read ``count`` pipelined HTTP/1.1 responses, each body by Content-Length."""
    buf, bodies = b"", []
    while len(bodies) < count:
        head_end = buf.find(b"\r\n\r\n")
        if head_end >= 0:
            head = buf[:head_end].decode("latin-1").lower()
            length = next((int(line.split(":", 1)[1]) for line in head.split("\r\n")
                           if line.startswith("content-length:")), 0)
            if len(buf) >= head_end + 4 + length:
                bodies.append(buf[head_end + 4:head_end + 4 + length])
                buf = buf[head_end + 4 + length:]
                continue
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bodies


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
    first_error: object = None


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

    def _send_ordered(self, wires: Sequence[bytes]) -> list[str]:
        u = urlparse(self.url)
        secure = u.scheme == "https"
        sock = socket.create_connection((u.hostname, u.port or (443 if secure else 80)), timeout=10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if secure:
            import ssl
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        try:
            for i, raw in enumerate(wires):
                body = json.dumps({"jsonrpc": "2.0", "id": i, "method": "sendTransaction",
                                   "params": [base64.b64encode(raw).decode(),
                                              {"encoding": "base64", "skipPreflight": True, "maxRetries": 0}]}).encode()
                sock.sendall((f"POST / HTTP/1.1\r\nHost: {u.hostname}\r\nContent-Type: application/json\r\n"
                              f"Content-Length: {len(body)}\r\nUser-Agent: {self.user_agent}\r\n\r\n").encode() + body)
            bodies = _read_responses(sock, len(wires))
        finally:
            sock.close()
        return [body[:300].decode(errors="replace") for body in bodies if b'"error"' in body]

    async def run(self, steps: Sequence[LaneStep], *, wait_seconds: float = 20.0, repair: bool = True,
                  monotonic_limits: bool = True, blockhash: str | None = None,
                  watch_last: bool = False, poll_seconds: float = 0.1,
                  resend_after_seconds: float = 0.5, max_resends: int = 3, salt: int = 0) -> LaneResult:
        """Send ``steps`` in order and wait for them.

        ``watch_last`` polls only the final step: valid when the application's
        guards make the final step impossible unless every earlier step landed
        (e.g. a commit that checks a cursor). Any failure or timeout falls back
        to reading every status, then to repair."""
        blockhash = blockhash or self.blockhash()
        n = len(steps)
        if monotonic_limits:
            # A step requesting less compute than its predecessor can fit a
            # block the predecessor could not and land first; non-decreasing
            # requests along the lane rule that out (measured on Fogo 10-01).
            ceiling, raised = 0, []
            for step in steps:
                ceiling = max(ceiling, step.compute_unit_limit)
                raised.append(LaneStep(step.step_id, step.instructions, ceiling))
            steps = raised
        # ``salt`` makes repeated steps unique when a blockhash is reused: an
        # identical (message, blockhash) pair would dedupe as already processed.
        built = [await self._build(step, blockhash, self.priority_step * (n - i) + salt) for i, step in enumerate(steps)]
        t0 = time.monotonic()
        send_errors = self._send_ordered([raw for _sig, raw in built])
        sent = time.monotonic() - t0
        if send_errors and len(send_errors) == n:
            raise RuntimeError(f"every lane send was rejected; first: {send_errors[0]}")
        sigs = [sig for sig, _raw in built]
        statuses: list = [None] * n
        deadline = time.monotonic() + wait_seconds
        if watch_last:
            # Leaders can drop transactions outright (maxRetries 0 means the RPC
            # never re-sends). If the final step is not visible soon, re-send the
            # identical bytes in order: landed steps dedupe by signature and the
            # dropped ones get another chance, still in order.
            resend_at = time.monotonic() + resend_after_seconds
            resends = 0
            while time.monotonic() < deadline:
                last = self.rpc("getSignatureStatuses", [sigs[-1:]])["value"][0]
                if last is not None:
                    if not last.get("err"):
                        statuses = [{"slot": last["slot"], "err": None}] * (n - 1) + [last]
                        deadline = 0
                    break
                if resends < max_resends and time.monotonic() >= resend_at:
                    self._send_ordered([raw for _sig, raw in built])
                    resends += 1
                    resend_at = time.monotonic() + resend_after_seconds
                time.sleep(poll_seconds)
        while time.monotonic() < deadline:
            statuses = self.rpc("getSignatureStatuses", [sigs])["value"]
            if all(v is not None for v in statuses) or any(v and v.get("err") for v in statuses):
                break
            time.sleep(poll_seconds)
        landed_s = time.monotonic() - t0
        bad = [i for i, v in enumerate(statuses) if v is None or v.get("err")]
        base = min((v["slot"] for v in statuses if v), default=0)
        result = LaneResult(n - len(bad), bad[0] if bad else None, 0, 0, sent, landed_s,
                            [v["slot"] - base if v else None for v in statuses],
                            (statuses[bad[0]] or {}).get("err", "missing") if bad else None)
        if bad and repair:
            time.sleep(1.0)
            # Walk from the start: a step's simulation also fails while an
            # earlier step is still missing, so starting at the first failure
            # can skip work that never landed.
            result.repaired, result.skipped = await self.repair(steps, 0)
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
