"""OrderedLane against a local JSON-RPC stub (offline)."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from dcg.sequencer.ordered_lane import LaneStep, OrderedLane

PROGRAM = Pubkey.from_string("FCzAE7H9q8Q4Ki5YQUikHQmCTbYJbjDjTupGj187BZox")
BLOCKHASH = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"


class Chain:
    """A cursor-guarded program: step k succeeds only when the cursor is k."""

    def __init__(self, reject_sends: bool = False, drop: set[int] | None = None):
        self.cursor = 0
        self.arrivals: list[int] = []
        self.status: dict[str, dict] = {}
        self.reject_sends = reject_sends
        self.drop = drop or set()
        self.lock = threading.Lock()

    @staticmethod
    def step_of(raw: bytes) -> tuple[str, int, int]:
        tx = Transaction.from_bytes(raw)
        ix = tx.message.instructions[-1]
        return str(tx.signatures[0]), bytes(ix.data)[0], len(tx.message.instructions)

    def apply(self, raw: bytes, *, simulate: bool) -> dict | None:
        sig, k, _n = self.step_of(raw)
        with self.lock:
            ok = k == self.cursor
            if simulate:
                return {"err": None if ok else {"InstructionError": [2, {"Custom": 2325}]}}
            self.arrivals.append(k)
            if k in self.drop:
                self.drop.discard(k)
                return None
            if ok:
                self.cursor += 1
            self.status[sig] = {"slot": 100 + len(self.arrivals), "err": None if ok else {"Custom": 2325},
                                "confirmationStatus": "processed"}
            return None


def make_handler(chain: Chain):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, params = req["method"], req["params"]
            if method == "getLatestBlockhash":
                result = {"value": {"blockhash": BLOCKHASH}}
            elif method == "sendTransaction":
                if chain.reject_sends:
                    body = json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                       "error": {"code": -32002, "message": "rejected"}}).encode()
                    self._reply(body)
                    return
                raw = base64.b64decode(params[0])
                chain.apply(raw, simulate=False)
                result = Chain.step_of(raw)[0]
            elif method == "simulateTransaction":
                result = {"value": chain.apply(base64.b64decode(params[0]), simulate=True)}
            elif method == "getSignatureStatuses":
                result = {"value": [chain.status.get(sig) for sig in params[0]]}
            else:
                result = None
            self._reply(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}).encode())

        def _reply(self, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


class OrderedLaneTests(unittest.TestCase):
    def setUp(self):
        self.payer = Keypair()

    def serve(self, chain: Chain) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(chain))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def lane(self, url: str) -> OrderedLane:
        async def sign(message: bytes):
            msg = Message.from_bytes(message)
            tx = Transaction([self.payer], msg, msg.recent_blockhash)
            return str(tx.signatures[0]), bytes(tx)

        return OrderedLane(url, self.payer.pubkey(), sign)

    def steps(self, n: int, limits=(80_000,)) -> list[LaneStep]:
        return [LaneStep(f"s{k}", (Instruction(PROGRAM, bytes([k]), [AccountMeta(self.payer.pubkey(), True, True)]),),
                         limits[k % len(limits)]) for k in range(n)]

    def test_steps_arrive_in_order_and_all_land(self):
        chain = Chain()
        result = asyncio.run(self.lane(self.serve(chain)).run(self.steps(12)))
        self.assertEqual(chain.arrivals, list(range(12)))
        self.assertEqual(result.landed, 12)
        self.assertIsNone(result.failed_first)
        self.assertEqual(chain.cursor, 12)

    def test_priority_strictly_decreases_and_limits_are_per_step(self):
        chain = Chain()
        lane = self.lane(self.serve(chain))
        steps = self.steps(4, limits=(80_000, 420_000))
        built = [asyncio.run(lane._build(step, BLOCKHASH, 1000 * (4 - i))) for i, step in enumerate(steps)]
        prices, limits = [], []
        for _sig, raw in built:
            ixs = Transaction.from_bytes(raw).message.instructions
            prices.append(int.from_bytes(bytes(ixs[0].data)[1:9], "little"))
            limits.append(int.from_bytes(bytes(ixs[1].data)[1:5], "little"))
        self.assertEqual(prices, sorted(prices, reverse=True))
        self.assertEqual(limits, [80_000, 420_000, 80_000, 420_000])

    def test_dropped_step_is_repaired_in_order(self):
        chain = Chain(drop={3})
        result = asyncio.run(self.lane(self.serve(chain)).run(self.steps(8)))
        self.assertEqual(result.failed_first, 3)
        # Steps 4.. were refused out of order; repair resends 3..7 in order.
        self.assertEqual(result.repaired, 5)
        self.assertEqual(chain.cursor, 8)

    def test_repair_skips_steps_already_landed(self):
        chain = Chain()
        lane = self.lane(self.serve(chain))
        steps = self.steps(5)
        asyncio.run(lane.run(steps[:3]))
        sent, skipped = asyncio.run(lane.repair(steps))
        self.assertEqual((sent, skipped), (2, 3))
        self.assertEqual(chain.cursor, 5)

    def test_every_send_rejected_is_surfaced(self):
        chain = Chain(reject_sends=True)
        with self.assertRaisesRegex(RuntimeError, "every lane send was rejected"):
            asyncio.run(self.lane(self.serve(chain)).run(self.steps(3)))


if __name__ == "__main__":
    unittest.main()
