"""OrderedLane against a local JSON-RPC stub (offline)."""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction, VersionedTransaction
from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.hash import Hash

from dcg.sequencer import LaneJournal, LaneStep, OrderedLane, keypair_signer

PROGRAM = Pubkey.from_string("FCzAE7H9q8Q4Ki5YQUikHQmCTbYJbjDjTupGj187BZox")
BLOCKHASH = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"


class Chain:
    """A cursor-guarded program: step k succeeds only when the cursor is k."""

    def __init__(self, reject_sends: bool = False, drop: set[int] | None = None, independent: bool = False,
                 drop_times: dict[int, int] | None = None):
        self.cursor = 0
        # independent: step k succeeds once, in any order; a second copy is refused.
        self.independent = independent
        self.done: set[int] = set()
        self.drop_times = dict(drop_times or {})
        self.blockhashes = 0
        self.versions: list[object] = []
        self.arrivals: list[int] = []
        self.status: dict[str, dict] = {}
        self.reject_sends = reject_sends
        self.drop = drop or set()
        self.lock = threading.Lock()

    @staticmethod
    def step_of(raw: bytes) -> tuple[str, int, int]:
        tx = VersionedTransaction.from_bytes(raw)
        ix = tx.message.instructions[-1]
        return str(tx.signatures[0]), bytes(ix.data)[0], len(tx.message.instructions)

    def apply(self, raw: bytes, *, simulate: bool) -> dict | None:
        sig, k, _n = self.step_of(raw)
        with self.lock:
            if sig in self.status:
                return None  # the same signature dedupes
            ok = (k not in self.done) if self.independent else k == self.cursor
            if simulate:
                return {"err": None if ok else {"InstructionError": [2, {"Custom": 2325}]},
                        "unitsConsumed": 1_000 * (k + 1)}
            self.arrivals.append(k)
            self.versions.append(VersionedTransaction.from_bytes(raw).version())
            if k in self.drop:
                self.drop.discard(k)
                return None
            if self.drop_times.get(k, 0) > 0:
                self.drop_times[k] -= 1
                return None
            if ok:
                self.cursor += 1
                self.done.add(k)
            self.status[sig] = {"slot": 100 + len(self.arrivals), "err": None if ok else {"Custom": 2325},
                                "confirmationStatus": "processed"}
            return None


def make_handler(chain: Chain, seen: list | None = None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, params = req["method"], req["params"]
            if method == "getLatestBlockhash":
                chain.blockhashes += 1
                result = {"value": {"blockhash": str(Hash.new_unique()) if chain.independent else BLOCKHASH}}
            elif method == "sendTransaction":
                if seen is not None:
                    seen.append(Chain.step_of(base64.b64decode(params[0]))[1])
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

    def serve(self, chain: Chain, seen: list | None = None) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(chain, seen))
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


    def test_lookup_table_steps_are_version_0_and_land_in_order(self):
        chain = Chain()
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer))
        extra = Pubkey.new_unique()
        table = AddressLookupTableAccount(Pubkey.new_unique(), [extra])
        steps = [LaneStep(f"s{k}", (Instruction(PROGRAM, bytes([k]), [AccountMeta(self.payer.pubkey(), True, True),
                                                                        AccountMeta(extra, False, True)]),),
                          80_000, (table,) if k % 2 else ()) for k in range(6)]
        result = asyncio.run(lane.run(steps))
        self.assertEqual((result.landed, chain.cursor), (6, 6))
        self.assertEqual([str(v) for v in chain.versions],
                         ["Legacy.Legacy", "0", "Legacy.Legacy", "0", "Legacy.Legacy", "0"])

    def test_size_compute_uses_the_simulation(self):
        chain = Chain(independent=True)
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer))
        sized = asyncio.run(lane.size_compute(self.steps(10)[9]))  # stub consumes 10,000
        self.assertEqual(sized.compute_unit_limit, 13_500)
        chain.done.add(9)
        with self.assertRaisesRegex(RuntimeError, "simulation refused"):
            asyncio.run(lane.size_compute(self.steps(10)[9]))

    def test_batch_lands_every_independent_step_despite_drops(self):
        chain = Chain(independent=True, drop_times={1: 1, 4: 2})
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer))
        result = asyncio.run(lane.run_batch(self.steps(6), resend_after_seconds=0.1, poll_seconds=0.02,
                                            max_seconds=10))
        self.assertEqual(sorted(result.landed), [f"s{k}" for k in range(6)])
        self.assertEqual((result.failed, result.missing), ({}, []))
        self.assertGreaterEqual(result.sends, 3)
        self.assertEqual(chain.done, set(range(6)))

    def test_batch_rebuilds_on_a_fresh_blockhash_and_a_duplicate_is_not_a_failure(self):
        chain = Chain(independent=True, drop_times={2: 3})
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer))
        result = asyncio.run(lane.run_batch(self.steps(4), resend_after_seconds=0.05, poll_seconds=0.02,
                                            blockhash_max_age=0.0, max_seconds=10))
        self.assertGreaterEqual(result.rebuilds, 1)
        self.assertGreaterEqual(chain.blockhashes, 2)
        self.assertEqual(sorted(result.landed), ["s0", "s1", "s2", "s3"])
        self.assertEqual(result.failed, {})

    def test_batch_reports_a_refused_step_without_retrying_it(self):
        chain = Chain(independent=True)
        chain.done.add(3)  # already attested: the program refuses step 3
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer))
        result = asyncio.run(lane.run_batch(self.steps(5), resend_after_seconds=0.1, poll_seconds=0.02))
        self.assertEqual(list(result.failed), ["s3"])
        self.assertEqual(sorted(result.landed), ["s0", "s1", "s2", "s4"])
        self.assertEqual(chain.arrivals.count(3), 1)


    def test_extra_nodes_receive_the_same_ordered_packets(self):
        chain, primary, extra = Chain(), [], []
        lane = OrderedLane(self.serve(chain, primary), self.payer.pubkey(), keypair_signer(self.payer),
                           extra_urls=(self.serve(chain, extra),))
        result = asyncio.run(lane.run(self.steps(6)))
        self.assertEqual((result.landed, chain.cursor), (6, 6))
        self.assertEqual(primary, list(range(6)))
        self.assertEqual(extra, list(range(6)))

    def test_a_dead_extra_node_does_not_stop_the_lane(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = f"http://127.0.0.1:{probe.getsockname()[1]}"
        chain = Chain()
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer), extra_urls=(dead,))
        self.assertEqual(asyncio.run(lane.run(self.steps(4))).landed, 4)

    def journal(self) -> LaneJournal:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return LaneJournal(f"{tmp.name}/lane.jsonl")

    def test_journal_records_and_closes_each_lane(self):
        chain, journal = Chain(), self.journal()
        lane = OrderedLane(self.serve(chain), self.payer.pubkey(), keypair_signer(self.payer), journal=journal)
        asyncio.run(lane.run(self.steps(3)))
        asyncio.run(lane.run([LaneStep(f"t{k}", s.instructions, s.compute_unit_limit)
                              for k, s in enumerate(self.steps(5)[3:], start=3)]))
        self.assertEqual([(r["event"], r["lane"]) for r in journal.rows()],
                         [("sent", 1), ("closed", 1), ("sent", 2), ("closed", 2)])
        self.assertIsNone(journal.open_lane())
        self.assertIsNone(asyncio.run(lane.resume(self.steps(3))))

    def test_resume_after_a_crash_polls_the_original_packets(self):
        chain, journal = Chain(), self.journal()
        url = self.serve(chain)
        steps = self.steps(5)
        asyncio.run(OrderedLane(url, self.payer.pubkey(), keypair_signer(self.payer), journal=journal).send(steps))
        # crash: the process never waited. A new process resumes from the journal.
        original = journal.open_lane()["signatures"]
        result = asyncio.run(OrderedLane(url, self.payer.pubkey(), keypair_signer(self.payer),
                                         journal=journal).resume(steps))
        self.assertEqual((result.landed, result.repaired, chain.cursor), (5, 0, 5))
        self.assertEqual(result.signatures, original)
        self.assertEqual(len(chain.status), 5, "no packet beyond the journaled ones was signed")
        self.assertIsNone(journal.open_lane())

    def test_resume_repairs_steps_lost_before_the_crash(self):
        chain, journal = Chain(drop={2}), self.journal()
        url = self.serve(chain)
        steps = self.steps(6)
        asyncio.run(OrderedLane(url, self.payer.pubkey(), keypair_signer(self.payer), journal=journal).send(steps))
        result = asyncio.run(OrderedLane(url, self.payer.pubkey(), keypair_signer(self.payer),
                                         journal=journal).resume(steps))
        self.assertEqual(chain.cursor, 6)
        self.assertIsNone(journal.open_lane())
        with self.assertRaisesRegex(ValueError, "not the given steps"):
            journal.record_sent(9, ["x"], [("sig", b"raw")])
            asyncio.run(OrderedLane(url, self.payer.pubkey(), keypair_signer(self.payer),
                                    journal=journal).resume(steps))


if __name__ == "__main__":
    unittest.main()
