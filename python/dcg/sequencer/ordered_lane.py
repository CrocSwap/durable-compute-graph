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

Also here (transport v1.1):
- a step with ``lookup_tables`` is built as a version-0 message, so a step too
  large for a 1,232-byte legacy packet can still go through a lane (the
  ``sign`` callback then receives version-0 message bytes; ``keypair_signer``
  handles both);
- ``run_batch`` sends independent steps (no ordering), re-sends the missing
  ones, and rebuilds them on a fresh blockhash before the old one expires;
- ``size_compute`` sets a step's compute request from a simulation.
"""

from __future__ import annotations

import base64
import json
import math
import socket
import time
import urllib.request
from dataclasses import dataclass, replace
from typing import Awaitable, Callable, Sequence
from urllib.parse import urlparse

from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction
from solders.message import Message, MessageV0, from_bytes_versioned, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

# A Fogo blockhash stays valid for about 150 slots of 40 ms (about 6 s); rebuild
# before that so a re-send is never wasted on an expired message.
BLOCKHASH_MAX_AGE_SECONDS = 4.0
MAX_COMPUTE_UNITS = 1_400_000


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
    # AddressLookupTableAccount values; non-empty builds a version-0 message.
    lookup_tables: tuple = ()


@dataclass
class LaneHandle:
    steps: list
    built: list
    started: float
    send_seconds: float


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
    signatures: list[str] | None = None
    statuses: list | None = None


@dataclass
class BatchResult:
    landed: list[str]
    failed: dict[str, object]
    missing: list[str]
    sends: int
    rebuilds: int
    seconds: float


Sign = Callable[[bytes], Awaitable[tuple[str, bytes]]]


def keypair_signer(*keypairs) -> Sign:
    """A ``sign`` callback for legacy and version-0 message bytes."""

    async def sign(message: bytes) -> tuple[str, bytes]:
        tx = VersionedTransaction(from_bytes_versioned(message), list(keypairs))
        return str(tx.signatures[0]), bytes(tx)

    return sign


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
        ixs = [set_compute_unit_price(price), set_compute_unit_limit(step.compute_unit_limit), *step.instructions]
        if step.lookup_tables:
            message = MessageV0.try_compile(self.payer, ixs, list(step.lookup_tables), Hash.from_string(blockhash))
            return await self.sign(to_bytes_versioned(message))
        return await self.sign(bytes(Message.new_with_blockhash(ixs, self.payer, Hash.from_string(blockhash))))

    async def size_compute(self, step: LaneStep, *, margin: float = 1.15, extra: int = 2_000,
                           floor: int = 5_000) -> LaneStep:
        """``step`` with its compute request set from a simulation:
        ``ceil(consumed * margin) + extra``, at least ``floor`` and at most
        1.4M. Fogo charges the *requested* limit against the per-account block
        cap, so tight requests let more steps share a block. Valid only for a
        step that can run now (independent, or the next step of a lane)."""
        probe = replace(step, compute_unit_limit=MAX_COMPUTE_UNITS)
        _sig, raw = await self._build(probe, self.blockhash("processed"), 0)
        sim = self.rpc("simulateTransaction", [base64.b64encode(raw).decode(),
                                               {"encoding": "base64", "commitment": "processed",
                                                "replaceRecentBlockhash": True}])["value"]
        if sim.get("err"):
            raise RuntimeError(f"cannot size {step.step_id}: simulation refused: {sim['err']}")
        used = int(sim.get("unitsConsumed") or 0)
        limit = min(MAX_COMPUTE_UNITS, max(floor, math.ceil(used * margin) + extra))
        return replace(step, compute_unit_limit=limit)

    async def run_batch(self, steps: Sequence[LaneStep], *, price: int = 1000, max_seconds: float = 60.0,
                        poll_seconds: float = 0.2, resend_after_seconds: float = 0.6,
                        blockhash_max_age: float = BLOCKHASH_MAX_AGE_SECONDS) -> BatchResult:
        """Send independent steps (any landing order is valid) until each has
        landed or failed.

        Missing steps are re-sent with their identical bytes (a landed copy
        dedupes by signature) and rebuilt on a fresh blockhash once theirs is
        ``blockhash_max_age`` old. A rebuilt step has a new signature, so the
        application must refuse a duplicate (as attestations of one output
        index do). A step that lands with an error is reported, not retried."""
        t0 = time.monotonic()
        by_id = {step.step_id: step for step in steps}
        if len(by_id) != len(steps):
            raise ValueError("batch step ids must be unique")
        sigs: dict[str, list[str]] = {sid: [] for sid in by_id}
        raw: dict[str, bytes] = {}
        landed: list[str] = []
        failed: dict[str, object] = {}
        sends = rebuilds = 0
        built_at = 0.0

        async def build(ids: list[str]) -> None:
            nonlocal built_at
            blockhash = self.blockhash()
            built_at = time.monotonic()
            for sid in ids:
                sig, raw[sid] = await self._build(by_id[sid], blockhash, price)
                sigs[sid].append(sig)

        pending = list(by_id)
        await build(pending)
        while pending and time.monotonic() - t0 < max_seconds:
            self._send_ordered([raw[sid] for sid in pending])
            sends += 1
            resend_at = time.monotonic() + resend_after_seconds
            while time.monotonic() < resend_at:
                time.sleep(poll_seconds)
                flat = [(sid, sig) for sid in pending for sig in sigs[sid]]
                values = []
                for i in range(0, len(flat), 256):
                    values += self.rpc("getSignatureStatuses", [[sig for _sid, sig in flat[i:i + 256]]])["value"]
                # Success wins: a rebuilt copy of a landed step is refused as a
                # duplicate, and that refusal must not mark the step failed.
                seen = [(sid, v) for (sid, _sig), v in zip(flat, values) if v is not None]
                for sid, v in seen:
                    if not v.get("err") and sid not in landed:
                        landed.append(sid)
                for sid, v in seen:
                    if v.get("err") and sid not in landed and sid not in failed:
                        failed[sid] = v["err"]
                pending = [sid for sid in pending if sid not in failed and sid not in landed]
                if not pending:
                    break
            if pending and time.monotonic() - built_at >= blockhash_max_age:
                await build(pending)
                rebuilds += 1
        return BatchResult(landed, failed, pending, sends, rebuilds, time.monotonic() - t0)

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

    async def send(self, steps: Sequence[LaneStep], *, monotonic_limits: bool = True,
                   blockhash: str | None = None, salt: int = 0, epoch: int | None = None,
                   epoch_ceiling: int = 100_000) -> "LaneHandle":
        """Build, sign and send ``steps`` in order without waiting."""
        blockhash = blockhash or self.blockhash()
        n = len(steps)
        if monotonic_limits:
            # A step requesting less compute than its predecessor can fit a
            # block the predecessor could not and land first; non-decreasing
            # requests along the lane rule that out (measured on Fogo 10-01).
            ceiling, raised = 0, []
            for step in steps:
                ceiling = max(ceiling, step.compute_unit_limit)
                raised.append(replace(step, compute_unit_limit=ceiling))
            steps = raised
        # ``salt`` makes repeated steps unique when a blockhash is reused: an
        # identical (message, blockhash) pair would dedupe as already processed.
        # ``epoch`` (an increasing lane number) makes priority decrease across
        # lanes too, so a later lane never outranks an earlier one still in
        # flight; it also makes every transaction unique.
        offset = salt if epoch is None else self.priority_step * n * (epoch_ceiling - epoch)
        built = [await self._build(step, blockhash, self.priority_step * (n - i) + offset)
                 for i, step in enumerate(steps)]
        t0 = time.monotonic()
        send_errors = self._send_ordered([raw for _sig, raw in built])
        if send_errors and len(send_errors) == n:
            raise RuntimeError(f"every lane send was rejected; first: {send_errors[0]}")
        return LaneHandle(list(steps), built, t0, time.monotonic() - t0)

    async def wait(self, handle: "LaneHandle", *, wait_seconds: float = 20.0, repair: bool = True,
                   watch_last: bool = False, poll_seconds: float = 0.1,
                   resend_after_seconds: float = 0.5, max_resends: int = 3) -> LaneResult:
        """Wait for a sent lane.

        ``watch_last`` polls only the final step: valid when the application's
        guards make the final step impossible unless every earlier step landed
        (e.g. a commit that checks a cursor). Any failure or timeout falls back
        to reading every status, then to repair."""
        steps, built, t0 = handle.steps, handle.built, handle.started
        n = len(built)
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
        result = LaneResult(n - len(bad), bad[0] if bad else None, 0, 0, handle.send_seconds, landed_s,
                            [v["slot"] - base if v else None for v in statuses],
                            (statuses[bad[0]] or {}).get("err", "missing") if bad else None,
                            sigs, statuses)
        if bad and repair:
            time.sleep(1.0)
            # Walk from the start: a step's simulation also fails while an
            # earlier step is still missing, so starting at the first failure
            # can skip work that never landed.
            result.repaired, result.skipped = await self.repair(steps, 0)
        return result

    async def run(self, steps: Sequence[LaneStep], *, wait_seconds: float = 20.0, repair: bool = True,
                  monotonic_limits: bool = True, blockhash: str | None = None,
                  watch_last: bool = False, poll_seconds: float = 0.1,
                  resend_after_seconds: float = 0.5, max_resends: int = 3, salt: int = 0) -> LaneResult:
        """Send ``steps`` in order and wait for them (``send`` then ``wait``)."""
        handle = await self.send(steps, monotonic_limits=monotonic_limits, blockhash=blockhash, salt=salt)
        return await self.wait(handle, wait_seconds=wait_seconds, repair=repair, watch_last=watch_last,
                               poll_seconds=poll_seconds, resend_after_seconds=resend_after_seconds,
                               max_resends=max_resends)

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
