"""A live-cluster client for the tag-227 disputes v2.1 program.

It sends recorded transcripts (`transcript.record`): the template, the run,
the executor's commitment, and then each dispute move as one transaction.
Bodies too large for one transaction go through the dispute's staging
buffers, as the program's oracle test does.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer

from dcg.graph_client import ChainError, GraphClient

from . import wire as W
from .errors import explain

TAG = 227
SUB = {"create_template": 1, "init_run": 2, "commit": 3, "open": 4, "reveal_nodes": 5, "pick": 6,
       "reveal_leaf": 7, "claim": 8, "finalize": 10, "advance": 11, "pay_pot": 13, "stage_create": 14,
       "stage_write": 15, "stage_grow": 17, "close_dispute": 18, "close_run": 19, "close_cache": 20,
       "close_template": 21, "retire_template": 22, "timeout": 9, "moot": 12}
RUN_OPEN, RUN_COMMITTED, RUN_FINAL, RUN_REFUTED = 0, 1, 2, 3
SUB_CACHE_ANSWER = 16
# Run, dispute and cache layouts (disputes_v21.rs).
R_STATUS, R_TEMPLATE, R_PAYER, R_EXECUTOR, R_DEADLINE, R_OPEN = 4, 8, 40, 72, 144, 152
R_SEQ, R_PREFIX, R_BEST, R_PAID, R_CLOSED = 160, 168, 176, 184, 188
D_PHASE, D_RULING, D_DEADLINE, D_CHALLENGER, D_RUN, D_SEQ = 4, 6, 24, 32, 64, 136
PH_RULED, RULING_OPEN, RULING_CHALLENGER = 5, 0, 2
CACHE_BYTES = 56 + 32 * 32
CACHE_BYTES_V2 = CACHE_BYTES + 32
RECEIPT_BYTES = 136 + 176  # a closed run: its first 136 bytes, then its root
KIND = {"STEP_DESCEND": 1, "OUT_DESCEND": 2}
ROLE_EXECUTOR, ROLE_CHALLENGER, FROM_STAGING = 1, 2, 0xFF
DIRECT_LIMIT = 700
LIST_HEAP_FRAME = 256 * 1024
# A staged write carries two signatures and five accounts; 600 bytes of
# body keeps it under the 1,232-byte transaction limit.
STAGE_PIECE = 600
CREATE_STAGE = 10_240 - 48  # one CPI creation; larger buffers are grown
STAGE_HEADER = 48
SYSTEM = Pubkey.from_string("11111111111111111111111111111111")
RULINGS = {0: "open", 1: "E", 2: "C", 3: "moot"}


def _list_step_heap_frame(leaf: bytes) -> int | None:
    """Request the expanded SVM heap for a staged list-input leaf."""
    return LIST_HEAP_FRAME if leaf.startswith(b"LVR1") else None


def program_tx_keys(tx: dict, program_id: Pubkey) -> list[str]:
    """The account keys of a `getTransaction` (json) result that invokes
    `program_id`, including lookup-table accounts; [] for any other
    transaction (so unrelated transactions naming an account are skipped)."""
    keys = list(tx["transaction"]["message"]["accountKeys"])
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    keys += list(loaded.get("writable", [])) + list(loaded.get("readonly", []))
    program = str(program_id)
    if not any(keys[ix["programIdIndex"]] == program for ix in tx["transaction"]["message"]["instructions"]):
        return []
    return keys


class DisputeClient:
    def __init__(self, gc: GraphClient):
        self.gc = gc
        self.sent = 0

    def _send(self, sub: str, body: bytes, metas: list[AccountMeta], signers: list[Keypair],
              *, heap_frame: int | None = None) -> str:
        self.sent += 1
        try:
            return self.gc.send(bytes([TAG, SUB[sub]]) + body, metas, signers, cu=1_400_000, heap_frame=heap_frame)
        except ChainError as exc:
            named = explain(exc)
            if named is None:
                raise
            raise ChainError(f"{sub}: {exc}\n  {named}") from None

    def _send_many(self, items: list[tuple[str, bytes, list[AccountMeta], list[Keypair]]], cap: float = 60.0) -> None:
        """Send order-independent instructions together (staged writes),
        then confirm them all, resending any not yet confirmed."""
        import base64

        from solders.hash import Hash
        from solders.instruction import Instruction
        from solders.message import Message
        from solders.transaction import Transaction

        gc = self.gc
        budget = Instruction(Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
                             bytes([2]) + struct.pack("<I", 200_000), [])
        blockhash = Hash.from_string(gc.rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
        pending = {}
        for sub, body, metas, signers in items:
            signers = [gc.payer] + [k for k in signers if k.pubkey() != gc.payer.pubkey()]
            ix = Instruction(gc.program_id, bytes([TAG, SUB[sub]]) + body, metas)
            tx = Transaction(signers, Message.new_with_blockhash([budget, ix], gc.payer.pubkey(), blockhash), blockhash)
            pending[str(tx.signatures[0])] = base64.b64encode(bytes(tx)).decode()
        self.sent += len(pending)
        deadline = time.monotonic() + cap
        while pending and time.monotonic() < deadline:
            for wire in pending.values():
                gc.rpc("sendTransaction", [wire, {"encoding": "base64", "skipPreflight": True}])
            time.sleep(1.5)
            sigs = list(pending)
            for at in range(0, len(sigs), 200):
                batch = sigs[at:at + 200]
                for sig, st in zip(batch, gc.rpc("getSignatureStatuses", [batch])["value"]):
                    if st and st.get("confirmationStatus") in ("confirmed", "finalized"):
                        if st.get("err"):
                            named = explain(st["err"])
                            raise RuntimeError(f"staged write {sig} failed: {st['err']}" + (f"\n  {named}" if named else ""))
                        pending.pop(sig)
        if pending:
            raise RuntimeError(f"{len(pending)} staged writes not confirmed within {cap}s")

    def pda(self, *seeds: bytes) -> Pubkey:
        return self.gc.pda(*seeds)

    def fund(self, to: Pubkey, lamports: int) -> None:
        """Transfer from the payer (GraphClient.send targets one program id,
        so the system program is swapped in for this one transaction)."""
        ix = transfer(TransferParams(from_pubkey=self.gc.payer.pubkey(), to_pubkey=to, lamports=lamports))
        saved = self.gc.program_id
        try:
            self.gc.program_id = ix.program_id
            self.gc.send(bytes(ix.data), list(ix.accounts), [], cu=10_000)
        finally:
            self.gc.program_id = saved
        self.sent += 1

    # --- setup ----------------------------------------------------------------------
    def create_template(self, tdata: bytes, admitter: Keypair) -> Pubkey:
        template_id = hashlib.sha256(W.TEMPLATE_DOMAIN + tdata).digest()
        template = self.pda(b"dcg21tmpl", template_id, bytes(admitter.pubkey()))
        if self.gc.account(template) is None:
            self._send("create_template", tdata, [AccountMeta(admitter.pubkey(), True, True),
                                                  AccountMeta(template, False, True),
                                                  AccountMeta(SYSTEM, False, False)], [admitter])
        return template

    def init_run(self, template: Pubkey, template_id: bytes, nonce: bytes, executor: Pubkey, refs: list[bytes],
                 payer: Keypair) -> Pubkey:
        refs = sorted(refs, key=lambda r: struct.unpack_from("<I", r)[0])
        flat = b"".join(refs)
        run_id = hashlib.sha256(b"dcg.run.id.v2.1\x00" + template_id + nonce + struct.pack("<I", len(refs)) + flat
                                + bytes(executor)).digest()
        run = self.pda(b"dcg21run", run_id, bytes(payer.pubkey()))
        body = nonce + bytes(executor) + struct.pack("<I", len(refs)) + flat
        self._send("init_run", body, [AccountMeta(payer.pubkey(), True, True), AccountMeta(run, False, True),
                                      AccountMeta(template, False, True), AccountMeta(SYSTEM, False, False)], [payer])
        return run

    def commit(self, run: Pubkey, template: Pubkey, root_bytes: bytes, executor: Keypair) -> None:
        self._send("commit", root_bytes, [AccountMeta(executor.pubkey(), True, True), AccountMeta(run, False, True),
                                          AccountMeta(template, False, False), AccountMeta(SYSTEM, False, False)],
                   [executor])

    # --- a dispute ------------------------------------------------------------------
    def play(self, run: Pubkey, template: Pubkey, transcript: dict, executor: Keypair, challenger: Keypair,
             dispute_nonce: bytes = bytes([1]) * 32) -> dict:
        """Send one recorded dispute; returns the ruling and timings."""
        t0, sent0 = time.monotonic(), self.sent
        dispute = self.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), dispute_nonce)
        self._send("open", dispute_nonce + bytes([KIND[transcript["kind"]]]),
                   [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                    AccountMeta(SYSTEM, False, False)], [challenger])

        def party(who: Keypair) -> list[AccountMeta]:
            return [AccountMeta(who.pubkey(), True, False), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True)]

        for rnd in transcript["rounds"]:
            self._send("reveal_nodes", bytes.fromhex(rnd["reveal"]), party(executor), [executor])
            self._send("pick", bytes([rnd["pick"]]), party(challenger), [challenger])

        def buffer(role: int) -> Pubkey:
            return self.pda(b"dcg21stg", bytes(dispute), bytes([role]))

        def stage(role: int, body: bytes, writer: Keypair) -> None:
            created = CREATE_STAGE if role == ROLE_EXECUTOR else min(len(body), CREATE_STAGE)
            grow_metas = [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, False),
                          AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                          AccountMeta(buffer(role), False, True), AccountMeta(SYSTEM, False, False)]
            self._send("stage_create", bytes([role]) + struct.pack("<I", created), grow_metas, [challenger])
            size = created
            while size < len(body):
                add = min(len(body) - size, 10_240)
                self._send("stage_grow", struct.pack("<I", add), grow_metas, [challenger])
                size += add
            write_metas = [AccountMeta(writer.pubkey(), True, False), AccountMeta(run, False, False),
                           AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                           AccountMeta(buffer(role), False, True)]
            self._send_many([("stage_write", struct.pack("<I", at) + body[at:at + STAGE_PIECE], write_metas, [writer])
                             for at in range(0, len(body), STAGE_PIECE)])

        leaf = bytes.fromhex(transcript["leaf"])
        heap_frame = _list_step_heap_frame(leaf)
        metas = party(executor)
        list_leaf = leaf.startswith(b"LVR1")
        if list_leaf or len(leaf) > DIRECT_LIMIT:
            stage(ROLE_EXECUTOR, leaf, executor)
            leaf, metas = bytes([FROM_STAGING]), metas + [AccountMeta(buffer(ROLE_EXECUTOR), False, False)]
        self._send("reveal_leaf", leaf, metas, [executor], heap_frame=heap_frame)
        claim = bytes.fromhex(transcript["claim"])
        metas = [AccountMeta(challenger.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                 AccountMeta(executor.pubkey(), False, True), AccountMeta(challenger.pubkey(), False, True)]
        if len(claim) > DIRECT_LIMIT:
            stage(ROLE_CHALLENGER, claim, challenger)
            claim, metas = bytes([FROM_STAGING]), metas + [AccountMeta(buffer(ROLE_CHALLENGER), False, False)]
        if list_leaf:
            metas.append(AccountMeta(buffer(ROLE_EXECUTOR), False, False))
        self._send("claim", claim, metas, [challenger], heap_frame=heap_frame)
        ruling = RULINGS[self.gc.account(dispute)[6]]
        return {"ruling": ruling, "transactions": self.sent - sent0, "wall_s": round(time.monotonic() - t0, 1),
                "dispute": str(dispute)}

    def stage_body(self, run: Pubkey, template: Pubkey, dispute: Pubkey, role: int, body: bytes, writer: Keypair,
                   funder: Keypair) -> Pubkey:
        """Create (or resume) a dispute's staging buffer for `role`, grow it to
        fit, and write `body` into it; `funder` pays any rent it adds. Returns
        the buffer. Resumable: a buffer that already exists (left by an
        interrupted attempt, or created by the other party, which the program
        allows) is checked and reused, and every piece is rewritten (writes
        are idempotent; only the role's own party may write)."""
        buffer = self.pda(b"dcg21stg", bytes(dispute), bytes([role]))
        grow = [AccountMeta(funder.pubkey(), True, True), AccountMeta(run, False, False),
                AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                AccountMeta(buffer, False, True), AccountMeta(SYSTEM, False, False)]
        existing = self.gc.account(buffer)
        if existing is None:
            created = CREATE_STAGE if role == ROLE_EXECUTOR else min(len(body), CREATE_STAGE)
            try:
                self._send("stage_create", bytes([role]) + struct.pack("<I", created), grow, [funder])
            except ChainError:
                existing = self.gc.account(buffer)  # it may have landed late, or been created meanwhile
                if existing is None:
                    raise
            existing = existing if existing is not None else self.gc.account(buffer)
        if existing is None or existing[:4] != b"D21S" or existing[4] != role or existing[8:40] != bytes(dispute):
            raise RuntimeError(f"staging buffer {buffer} is not this dispute's role-{role} buffer")
        size = len(existing) - STAGE_HEADER
        while size < len(body):
            add = min(len(body) - size, 10_240)
            self._send("stage_grow", struct.pack("<I", add), grow, [funder])
            size += add
        write = [AccountMeta(writer.pubkey(), True, False), AccountMeta(run, False, False),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                 AccountMeta(buffer, False, True)]
        self._send_many([("stage_write", struct.pack("<I", at) + body[at:at + STAGE_PIECE], write, [writer])
                         for at in range(0, len(body), STAGE_PIECE)])
        return buffer

    # The LX client's name for it.
    _stage = stage_body

    def run_status(self, run: Pubkey) -> int:
        """A live run's or a receipt's status byte (both keep it at byte 4)."""
        data = self.gc.account(run)
        if data is None or data[:4] not in (b"D21R", b"D21P"):
            raise ValueError(f"{run} is not a v2.1 run or receipt")
        return data[4]

    # --- settlement and rent reclaim ------------------------------------------------
    def _caller(self) -> AccountMeta:
        return AccountMeta(self.gc.payer.pubkey(), True, False)

    def advance(self, run: Pubkey, template: Pubkey, dispute: Pubkey) -> None:
        self._send("advance", b"", [self._caller(), AccountMeta(run, False, True), AccountMeta(template, False, False),
                                    AccountMeta(dispute, False, False)], [])

    def finalize(self, run: Pubkey, template: Pubkey, executor: Pubkey) -> None:
        self._send("finalize", b"", [self._caller(), AccountMeta(run, False, True), AccountMeta(template, False, False),
                                     AccountMeta(executor, False, True)], [])

    def pay_pot(self, run: Pubkey, template: Pubkey, dispute: Pubkey, challenger: Pubkey, payer: Pubkey) -> None:
        self._send("pay_pot", b"", [self._caller(), AccountMeta(run, False, True), AccountMeta(template, False, False),
                                    AccountMeta(dispute, False, False), AccountMeta(challenger, False, True),
                                    AccountMeta(payer, False, True)], [])

    def close_dispute(self, run: Pubkey, template: Pubkey, dispute: Pubkey, challenger: Pubkey,
                      executor: Pubkey) -> None:
        """Close a ruled dispute the ruled prefix has passed, with its staging
        buffers: buffer rent to its creator, dispute rent to the challenger."""
        buffers = [self.pda(b"dcg21stg", bytes(dispute), bytes([role])) for role in (ROLE_EXECUTOR, ROLE_CHALLENGER)]
        self._send("close_dispute", b"", [self._caller(), AccountMeta(run, False, True),
                                          AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                                          AccountMeta(challenger, False, True), AccountMeta(executor, False, True)]
                   + [AccountMeta(b, False, True) for b in buffers], [])

    def close_run(self, run: Pubkey, template: Pubkey, payer: Pubkey) -> None:
        """Shrink a settled run whose disputes are all closed to its receipt
        (anyone; the freed rent goes to `payer`, the run's payer). For an
        expired uncommitted run this cancels it, with rent still going to
        `payer`."""
        self._send("close_run", b"", [self._caller(), AccountMeta(run, False, True), AccountMeta(template, False, True),
                                      AccountMeta(payer, False, True)], [])

    def retire_template(self, template: Pubkey, payer: Keypair) -> None:
        """Stop future run creation; only the recorded template payer may retire it."""
        self._send("retire_template", b"", [AccountMeta(payer.pubkey(), True, True),
                                               AccountMeta(template, False, True)], [payer])

    def close_template(self, template: Pubkey, payer: Keypair) -> None:
        """Close a zero-run template and return all its lamports to its recorded payer."""
        self._send("close_template", b"", [AccountMeta(payer.pubkey(), True, True),
                                              AccountMeta(template, False, True)], [payer])

    def close_cache(self, run: Pubkey, cache: Pubkey, executor: Pubkey) -> None:
        self._send("close_cache", b"", [self._caller(), AccountMeta(run, False, False), AccountMeta(cache, False, True),
                                        AccountMeta(executor, False, True)], [])

    def settle_dispute(self, run: Pubkey, template: Pubkey, dispute: Pubkey, challenger: Pubkey,
                       executor: Pubkey, payer: Pubkey) -> None:
        """After a ruling on a run's only open dispute: advance the ruled
        prefix, pay the pot if the challenger won, and close the dispute."""
        self.advance(run, template, dispute)
        if self.run_status(run) == RUN_REFUTED:
            self.pay_pot(run, template, dispute, challenger, payer)
        self.close_dispute(run, template, dispute, challenger, executor)

    # --- the whole lifecycle -------------------------------------------------------------

    def accounts_touching(self, run: Pubkey) -> list[Pubkey]:
        """Every account named by a tag-227 transaction that touched the run,
        from the run's signature history (``getProgramAccounts`` is often
        disabled on public RPC nodes). Disputes and reveal caches are always
        written in a transaction that names their run. Includes accounts
        loaded through address lookup tables."""
        sigs, before = [], None
        while True:
            opts = {"limit": 1000, "commitment": "confirmed", **({"before": before} if before else {})}
            page = self.gc.rpc("getSignaturesForAddress", [str(run), opts])
            # A failed transaction created nothing.
            sigs += [p["signature"] for p in page if p.get("err") is None]
            if len(page) < 1000:
                break
            before = page[-1]["signature"]
        from concurrent.futures import ThreadPoolExecutor

        def fetch(sig: str):
            return self.gc.rpc("getTransaction", [sig, {"encoding": "json", "commitment": "confirmed",
                                                        "maxSupportedTransactionVersion": 0}])

        keys: dict[str, None] = {}
        with ThreadPoolExecutor(max_workers=8) as pool:
            for tx in pool.map(fetch, sigs):
                if tx is None:
                    raise ChainError("a transaction of the run's history is not yet readable; retry")
                keys.update(dict.fromkeys(program_tx_keys(tx, self.gc.program_id)))
        return [Pubkey.from_string(k) for k in keys]

    def runs_of(self, template: Pubkey) -> list[Pubkey]:
        """The live runs (not receipts) of a template, from its signature
        history: every run's creation names its template."""
        return [k for k, d in self._program_accounts(self.accounts_touching(template))
                if d[:4] == b"D21R" and d[R_TEMPLATE:R_TEMPLATE + 32] == bytes(template)]

    def _program_accounts(self, keys: list[Pubkey]) -> list[tuple[Pubkey, bytes]]:
        out = []
        for at in range(0, len(keys), 100):
            batch = keys[at:at + 100]
            values = self.gc.rpc("getMultipleAccounts", [[str(k) for k in batch],
                                                         {"encoding": "base64", "commitment": "confirmed"}])["value"]
            for key, v in zip(batch, values):
                if v is not None and v["owner"] == str(self.gc.program_id):
                    out.append((key, base64.b64decode(v["data"][0])))
        return out

    def disputes_of(self, run: Pubkey, candidates: list[Pubkey]) -> list[tuple[Pubkey, bytes]]:
        """The live disputes of a run among the candidate accounts, by sequence."""
        out = [(k, d) for k, d in self._program_accounts(candidates)
               if d[:4] == b"D21D" and d[D_RUN:D_RUN + 32] == bytes(run)]
        return sorted(out, key=lambda kd: struct.unpack_from("<Q", kd[1], D_SEQ)[0])

    def caches_of(self, run: Pubkey, candidates: list[Pubkey]) -> list[tuple[Pubkey, bytes]]:
        """The live reveal caches of a run among the candidates. A cache does
        not record its run, so each is matched by re-deriving its address."""
        return [(k, d) for k, d in self._program_accounts(candidates)
                if d[:4] == b"D21C" and len(d) in (CACHE_BYTES, CACHE_BYTES_V2)
                and self.pda(b"dcg21rc", bytes(run), d[4:5], d[8:12], d[16:24]) == k]

    def _settle_once(self, run: Pubkey, timeouts: bool, candidates: list[Pubkey]) -> str | None:
        """Send the next lifecycle step a run allows, and name it. Returns
        None when nothing is left, or ``wait: ...`` when the next step needs
        a deadline to pass."""
        r = self.gc.account(run)
        if r is None:
            return None
        u64 = lambda d, at: struct.unpack_from("<Q", d, at)[0]  # noqa: E731
        u32 = lambda d, at: struct.unpack_from("<I", d, at)[0]  # noqa: E731
        receipt = r[:4] == b"D21P"
        executor = Pubkey.from_bytes(r[R_EXECUTOR:R_EXECUTOR + 32])
        if receipt:
            for cache, k in self.caches_of(run, candidates):
                payee = Pubkey.from_bytes(k[CACHE_BYTES:]) if len(k) == CACHE_BYTES_V2 else executor
                self.close_cache(run, cache, payee)
                return f"close_cache {cache}"
            return None
        template = Pubkey.from_bytes(r[R_TEMPLATE:R_TEMPLATE + 32])
        payer = Pubkey.from_bytes(r[R_PAYER:R_PAYER + 32])
        status, now = r[R_STATUS], self.gc.slot()
        deadline = u64(r, R_DEADLINE)
        if status == RUN_OPEN:
            if now <= deadline:
                return f"wait: uncommitted until slot {deadline}"
            self.close_run(run, template, payer)
            return "close_run (cancelled: never committed)"
        disputes = self.disputes_of(run, candidates)
        best, prefix, paid = u64(r, R_BEST), u64(r, R_PREFIX), r[R_PAID]
        for dispute, d in disputes:
            if d[D_RULING] != RULING_OPEN:
                continue
            challenger = Pubkey.from_bytes(d[D_CHALLENGER:D_CHALLENGER + 32])
            if status == RUN_REFUTED and u64(d, D_SEQ) > best:
                self._send("moot", b"", [self._caller(), AccountMeta(run, False, True),
                                         AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                                         AccountMeta(challenger, False, True)], [])
                return f"moot {dispute}"
            if timeouts and now > u64(d, D_DEADLINE):
                self._send("timeout", b"", [self._caller(), AccountMeta(run, False, True),
                                            AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                                            AccountMeta(executor, False, True), AccountMeta(challenger, False, True)], [])
                return f"timeout {dispute}"
        for dispute, d in disputes:
            if u64(d, D_SEQ) == prefix and d[D_RULING] != RULING_OPEN:
                self.advance(run, template, dispute)
                return f"advance past {dispute}"
        if status == RUN_REFUTED and not paid and prefix > best:
            dispute, d = next((dd for dd in disputes if u64(dd[1], D_SEQ) == best))
            self.pay_pot(run, template, dispute, Pubkey.from_bytes(d[D_CHALLENGER:D_CHALLENGER + 32]), payer)
            return f"pay_pot {dispute}"
        for dispute, d in disputes:
            seq = u64(d, D_SEQ)
            if d[D_RULING] != RULING_OPEN and seq < prefix and not (status == RUN_REFUTED and seq == best and not paid):
                self.close_dispute(run, template, dispute, Pubkey.from_bytes(d[D_CHALLENGER:D_CHALLENGER + 32]),
                                   executor)
                return f"close_dispute {dispute}"
        open_disputes = u32(r, R_OPEN)
        if status == RUN_COMMITTED and open_disputes == 0:
            if now <= deadline:
                return f"wait: challenge window open until slot {deadline}"
            self.finalize(run, template, executor)
            return "finalize"
        settled = status == RUN_FINAL or (status == RUN_REFUTED and paid)
        if settled and open_disputes == 0:
            for cache, k in self.caches_of(run, candidates):
                payee = Pubkey.from_bytes(k[CACHE_BYTES:]) if len(k) == CACHE_BYTES_V2 else executor
                self.close_cache(run, cache, payee)
                return f"close_cache {cache}"
            if u32(r, R_CLOSED) == u64(r, R_SEQ):
                self.close_run(run, template, payer)
                return "close_run (shrunk to its receipt)"
        if open_disputes:
            soonest = min(u64(d, D_DEADLINE) for _k, d in disputes if d[D_RULING] == RULING_OPEN)
            return f"wait: {open_disputes} open dispute(s), next phase deadline slot {soonest}"
        return None

    def settle_and_reclaim(self, run: Pubkey, *, timeouts: bool = True, wait: float = 0.0,
                           max_steps: int = 256, candidates: list[Pubkey] | None = None) -> dict:
        """Take a run as far through its lifecycle as the chain allows, and
        reclaim every rent it can (alpha plan E4).

        In order: time out disputes whose phase deadline passed (unless
        ``timeouts=False``); rule moot the disputes opened after a refuted
        run's lowest challenger win; advance the ruled prefix; pay the pot;
        close ruled disputes with their staging buffers; finalize after the
        challenge window; close the run's reveal caches; shrink the run to
        its receipt (or cancel an expired uncommitted run). Anyone may send
        each step; rent goes where the program sends it, not to the caller.

        ``candidates``: the run's known accounts (disputes, caches); by
        default they are found from the run's signature history.

        With ``wait`` > 0, sleeps and retries while the next step is behind
        a deadline, for at most ``wait`` seconds. Returns the steps taken and
        the run's state: ``closed`` (a receipt with nothing left),
        ``waiting`` (with the reason) or ``stuck``.
        """
        steps: list[str] = []
        give_up = time.monotonic() + wait
        # Callers that already track the run's accounts (the services) pass
        # them, so a settle does not rescan the run's whole history.
        candidates = self.accounts_touching(run) if candidates is None else candidates
        refused = 0
        while len(steps) < max_steps:
            try:
                step = self._settle_once(run, timeouts, candidates)
            except ChainError as exc:
                # Anyone may settle: another party's step may land between our
                # read and our send (for example RulingOutOfOrder after its
                # advance). Re-read and continue; give up after three in a row.
                refused += 1
                if refused >= 3:
                    return {"state": "stuck", "reason": str(exc).splitlines()[-1].strip(), "steps": steps}
                time.sleep(1.0)
                continue
            refused = 0
            if step is None:
                data = self.gc.account(run)
                state = "closed" if data is None or data[:4] == b"D21P" else "stuck"
                return {"state": state, "steps": steps}
            if step.startswith("wait: "):
                if time.monotonic() >= give_up:
                    return {"state": "waiting", "reason": step[6:], "steps": steps}
                time.sleep(2.0)
                continue
            steps.append(step)
        return {"state": "stuck", "reason": f"more than {max_steps} steps", "steps": steps}
