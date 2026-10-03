"""A live-cluster client for the tag-227 disputes v2.1 program.

It sends recorded transcripts (`transcript.record`): the template, the run,
the executor's commitment, and then each dispute move as one transaction.
Bodies too large for one transaction go through the dispute's staging
buffers, as the program's oracle test does.
"""

from __future__ import annotations

import hashlib
import struct
import time

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer

from dcg.graph_client import GraphClient

from . import wire as W

TAG = 227
SUB = {"create_template": 1, "init_run": 2, "commit": 3, "open": 4, "reveal_nodes": 5, "pick": 6,
       "reveal_leaf": 7, "claim": 8, "finalize": 10, "advance": 11, "pay_pot": 13, "stage_create": 14,
       "stage_write": 15, "stage_grow": 17, "close_dispute": 18, "close_run": 19, "close_cache": 20,
       "close_template": 21, "retire_template": 22}
RUN_COMMITTED, RUN_FINAL, RUN_REFUTED = 1, 2, 3
RECEIPT_BYTES = 136 + 176  # a closed run: its first 136 bytes, then its root
KIND = {"STEP_DESCEND": 1, "OUT_DESCEND": 2}
ROLE_EXECUTOR, ROLE_CHALLENGER, FROM_STAGING = 1, 2, 0xFF
DIRECT_LIMIT = 700
LIST_HEAP_FRAME = 256 * 1024
# A staged write carries two signatures and five accounts; 600 bytes of
# body keeps it under the 1,232-byte transaction limit.
STAGE_PIECE = 600
CREATE_STAGE = 10_240 - 48  # one CPI creation; larger buffers are grown
SYSTEM = Pubkey.from_string("11111111111111111111111111111111")
RULINGS = {0: "open", 1: "E", 2: "C", 3: "moot"}


def _list_step_heap_frame(leaf: bytes) -> int | None:
    """Request the expanded SVM heap for a staged list-input leaf."""
    return LIST_HEAP_FRAME if leaf.startswith(b"LVR1") else None


class DisputeClient:
    def __init__(self, gc: GraphClient):
        self.gc = gc
        self.sent = 0

    def _send(self, sub: str, body: bytes, metas: list[AccountMeta], signers: list[Keypair],
              *, heap_frame: int | None = None) -> str:
        self.sent += 1
        return self.gc.send(bytes([TAG, SUB[sub]]) + body, metas, signers, cu=1_400_000, heap_frame=heap_frame)

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
                            raise RuntimeError(f"staged write {sig} failed: {st['err']}")
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
