"""Client for the DCG v2 graph lifecycle (tags 209-219) on a live cluster.

Small synchronous JSON-RPC client: each instruction is one transaction that is
signed, sent, re-sent every two seconds, and confirmed within a deadline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import time
import urllib.request

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from dcg.tracing import Graph, PLAN_DOMAIN, GRAPH_DOMAIN, TABLE_DOMAIN

SYSTEM = Pubkey.from_string("11111111111111111111111111111111")
SLOT_HASHES = Pubkey.from_string("SysvarS1otHashes111111111111111111111111111")
TEMPLATE_DOMAIN = b"dcg.template.id.v2\x00"
RUN_DOMAIN = b"dcg.run.id.v2\x00"
MODES = {"consensus": 1, "optimistic": 2, "sampling": 3}
STATUS = {0: "open", 1: "committed", 2: "final", 3: "challenger_won"}
RUN_HEADER = 32 + 32 * 4
CHUNK = 900


class ChainError(RuntimeError):
    pass


class GraphClient:
    def __init__(self, rpc_url: str, program_id: Pubkey, payer: Keypair, timeout: float = 30.0):
        self.rpc_url, self.program_id, self.payer, self.timeout = rpc_url, program_id, payer, timeout
        self.signatures: list[str] = []

    @classmethod
    def from_environment(cls) -> "GraphClient":
        with open(os.environ["DCG_PAYER_KEYPAIR"]) as f:
            payer = Keypair.from_bytes(bytes(json.load(f)))
        return cls(os.environ.get("DCG_RPC_URL", "http://127.0.0.1:8899"),
                   Pubkey.from_string(os.environ["DCG_PROGRAM_ID"]), payer)

    # --- rpc ------------------------------------------------------------------
    def rpc(self, method: str, params: list):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.rpc_url, body, {"Content-Type": "application/json", "User-Agent": "dcg-graph-client/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read())
        if "error" in out:
            raise ChainError(f"{method}: {out['error']}")
        return out["result"]

    def slot(self) -> int:
        return self.rpc("getSlot", [{"commitment": "confirmed"}])

    def account(self, key: Pubkey) -> bytes | None:
        value = self.rpc("getAccountInfo", [str(key), {"encoding": "base64", "commitment": "confirmed"}])["value"]
        return None if value is None else base64.b64decode(value["data"][0])

    def send(self, data: bytes, metas: list[AccountMeta], signers: list[Keypair] | None = None, cu: int = 400_000) -> str:
        signers = [self.payer] + [s for s in (signers or []) if s.pubkey() != self.payer.pubkey()]
        budget = Instruction(Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
                             bytes([2]) + struct.pack("<I", cu), [])
        ix = Instruction(self.program_id, data, metas)
        blockhash = Hash.from_string(self.rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
        tx = Transaction(signers, Message.new_with_blockhash([budget, ix], self.payer.pubkey(), blockhash), blockhash)
        wire = base64.b64encode(bytes(tx)).decode()
        sig = str(tx.signatures[0])
        try:
            self.rpc("sendTransaction", [wire, {"encoding": "base64", "preflightCommitment": "confirmed"}])
        except ChainError as exc:
            raise ChainError(f"tag {data[0]} refused in preflight: {exc}") from None
        deadline = time.monotonic() + self.timeout
        last = time.monotonic()
        while time.monotonic() < deadline:
            status = self.rpc("getSignatureStatuses", [[sig]])["value"][0]
            if status and status.get("confirmationStatus") in ("confirmed", "finalized"):
                if status.get("err"):
                    raise ChainError(f"tag {data[0]} failed on chain: {status['err']}")
                self.signatures.append(sig)
                return sig
            if time.monotonic() - last > 2:
                self.rpc("sendTransaction", [wire, {"encoding": "base64", "skipPreflight": True}])
                last = time.monotonic()
            time.sleep(0.4)
        raise ChainError(f"tag {data[0]} not confirmed within {self.timeout}s ({sig})")

    def pda(self, *seeds: bytes) -> Pubkey:
        return Pubkey.find_program_address(list(seeds), self.program_id)[0]

    # --- lifecycle ------------------------------------------------------------
    def upload_blob(self, kind: int, body: bytes, domain: bytes) -> Pubkey:
        blob_id = hashlib.sha256(domain + body).digest()
        blob = self.pda(b"dcg2blob", bytes([kind]), blob_id)
        existing = self.account(blob)
        if existing is not None and existing[5] == 1:
            return blob
        if existing is None:
            self.send(bytes([210, kind]) + struct.pack("<I", len(body)) + blob_id,
                      [AccountMeta(self.payer.pubkey(), True, True), AccountMeta(blob, False, True),
                       AccountMeta(SYSTEM, False, False)])
        for offset in range(0, len(body), CHUNK):
            self.send(bytes([211]) + struct.pack("<I", offset) + body[offset:offset + CHUNK],
                      [AccountMeta(self.payer.pubkey(), True, False), AccountMeta(blob, False, True)])
        self.send(bytes([212]), [AccountMeta(self.payer.pubkey(), True, False), AccountMeta(blob, False, True)])
        return blob

    def admit(self, graph: Graph, mode: str, window_slots: int = 150, samples: int = 0,
              manifest_root: bytes | None = None, bond: int | None = None) -> dict:
        """``bond``: executor bond in lamports, posted at commit, paid to a
        winning challenger or auditor and refunded at finalize. ``None`` admits
        a template without a bond field (the pre-bond identity)."""
        if manifest_root is None:
            # A canonical DCPL binds its kernel-manifest root (bytes 104..136),
            # and admission checks the declared root against it.
            plan = graph.plan_bytes()
            manifest_root = plan[104:136] if plan.startswith(b"DCPL") else b"\0" * 32
        policy = b"POL" + bytes([MODES[mode], samples]) + struct.pack("<Q", window_slots)
        blobs = {
            "graph": self.upload_blob(1, graph.graph_bytes(), GRAPH_DOMAIN),
            "plan": self.upload_blob(2, graph.plan_bytes(), PLAN_DOMAIN),
            # The template identity omits mode/window (fixed in the next image);
            # a trailing policy suffix, ignored by the on-chain parser, keeps
            # templates of different modes distinct.
            "table": self.upload_blob(3, table := graph.step_table() + policy, TABLE_DOMAIN),
        }
        ids = {**graph.ids(), "table": hashlib.sha256(TABLE_DOMAIN + table).digest()}
        image_id = hashlib.sha256(b"dcg.app.image.v2\x00" + bytes(self.program_id)).digest()
        template_id = hashlib.sha256(TEMPLATE_DOMAIN + ids["graph"] + ids["plan"] + image_id + manifest_root
                                     + ids["table"] + policy[3:]
                                     + (b"" if bond is None else struct.pack("<Q", bond))).digest()
        template = self.pda(b"dcg2tmpl", template_id)
        if self.account(template) is None:
            self.send(bytes([213, MODES[mode], samples]) + struct.pack("<Q", window_slots) + manifest_root
                      + (b"" if bond is None else struct.pack("<Q", bond)),
                      [AccountMeta(self.payer.pubkey(), True, True), AccountMeta(template, False, True),
                       AccountMeta(blobs["graph"], False, False), AccountMeta(blobs["plan"], False, False),
                       AccountMeta(blobs["table"], False, False), AccountMeta(SYSTEM, False, False)])
        return {"template": template, "template_id": template_id, "table": blobs["table"], "bond": bond or 0, **blobs}

    def init_run(self, admitted: dict, inputs: list[int]) -> Pubkey:
        nonce = secrets.token_bytes(32)
        cells = b"".join(struct.pack("<i", v) for v in inputs)
        run_id = hashlib.sha256(RUN_DOMAIN + admitted["template_id"] + nonce + cells).digest()
        run = self.pda(b"dcg2run", run_id)
        self.send(bytes([214]) + nonce + cells,
                  [AccountMeta(self.payer.pubkey(), True, True), AccountMeta(run, False, True),
                   AccountMeta(admitted["template"], False, False), AccountMeta(admitted["table"], False, False),
                   AccountMeta(SYSTEM, False, False)])
        return run

    def _run_metas(self, admitted: dict, run: Pubkey, signer: Keypair | None = None, table: bool = True):
        who = (signer or self.payer).pubkey()
        # The signer is writable: it posts or receives a bond.
        metas = [AccountMeta(who, True, True), AccountMeta(run, False, True),
                 AccountMeta(admitted["template"], False, False)]
        if table:
            metas.append(AccountMeta(admitted["table"], False, False))
        return metas

    def execute(self, admitted, run):
        return self.send(bytes([215]), self._run_metas(admitted, run))

    def commit(self, admitted, run, trace_values: list[int], executor: Keypair | None = None):
        return self.send(bytes([216]) + b"".join(struct.pack("<i", v) for v in trace_values),
                         self._run_metas(admitted, run, executor, table=False) + [AccountMeta(SYSTEM, False, False)],
                         [executor] if executor else None)

    def challenge(self, admitted, run, step: int, challenger: Keypair | None = None):
        return self.send(bytes([217]) + struct.pack("<H", step), self._run_metas(admitted, run, challenger),
                         [challenger] if challenger else None)

    def finalize(self, admitted, run):
        metas = self._run_metas(admitted, run, table=False)
        if admitted.get("bond"):
            d = self.account(run)
            metas.append(AccountMeta(Pubkey.from_bytes(d[128:160]), False, True))
        return self.send(bytes([218]), metas)

    def audit(self, admitted, run):
        return self.send(bytes([219]), self._run_metas(admitted, run) + [AccountMeta(SLOT_HASHES, False, False)])

    def close(self, admitted, run):
        return self.send(bytes([209]), [AccountMeta(self.payer.pubkey(), True, True), AccountMeta(run, False, True),
                                        AccountMeta(admitted["template"], False, False)])

    def read_run(self, run: Pubkey) -> dict:
        d = self.account(run)
        if d is None:
            return {"status": "closed"}
        n_in, n_steps, bad = struct.unpack_from("<HHH", d, 6)
        cells = list(struct.unpack_from(f"<{n_in + n_steps}i", d, RUN_HEADER))
        return {"status": STATUS[d[4]], "audited": bool(d[5]), "inputs": cells[:n_in], "trace": cells[n_in:],
                "bad_step": None if bad == 0xFFFF else bad,
                "commit_slot": struct.unpack_from("<Q", d, 16)[0], "deadline": struct.unpack_from("<Q", d, 24)[0]}

    def wait_past(self, slot: int, cap: float = 80.0):
        end = time.monotonic() + cap
        while self.slot() <= slot:
            if time.monotonic() > end:
                raise ChainError(f"slot {slot} not reached within {cap}s")
            time.sleep(0.5)
