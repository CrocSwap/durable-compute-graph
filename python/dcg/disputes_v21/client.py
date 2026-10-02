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
       "reveal_leaf": 7, "claim": 8, "stage_create": 14, "stage_write": 15}
KIND = {"STEP_DESCEND": 1, "OUT_DESCEND": 2}
ROLE_EXECUTOR, ROLE_CHALLENGER, FROM_STAGING = 1, 2, 0xFF
DIRECT_LIMIT = 700
# A staged write carries two signatures and five accounts; 600 bytes of
# body keeps it under the 1,232-byte transaction limit.
STAGE_PIECE = 600
SYSTEM = Pubkey.from_string("11111111111111111111111111111111")
RULINGS = {0: "open", 1: "E", 2: "C", 3: "moot"}


class DisputeClient:
    def __init__(self, gc: GraphClient):
        self.gc = gc
        self.sent = 0

    def _send(self, sub: str, body: bytes, metas: list[AccountMeta], signers: list[Keypair]) -> str:
        self.sent += 1
        return self.gc.send(bytes([TAG, SUB[sub]]) + body, metas, signers, cu=1_400_000)

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
        template = self.pda(b"dcg21tmpl", template_id)
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
        run = self.pda(b"dcg21run", run_id)
        body = nonce + bytes(executor) + struct.pack("<I", len(refs)) + flat
        self._send("init_run", body, [AccountMeta(payer.pubkey(), True, True), AccountMeta(run, False, True),
                                      AccountMeta(template, False, False), AccountMeta(SYSTEM, False, False)], [payer])
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
            return [AccountMeta(who.pubkey(), True, False), AccountMeta(run, False, False),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True)]

        for rnd in transcript["rounds"]:
            self._send("reveal_nodes", bytes.fromhex(rnd["reveal"]), party(executor), [executor])
            self._send("pick", bytes([rnd["pick"]]), party(challenger), [challenger])

        def buffer(role: int) -> Pubkey:
            return self.pda(b"dcg21stg", bytes(dispute), bytes([role]))

        def stage(role: int, body: bytes, writer: Keypair) -> None:
            self._send("stage_create", bytes([role]) + struct.pack("<I", len(body)),
                       [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, False),
                        AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                        AccountMeta(buffer(role), False, True), AccountMeta(SYSTEM, False, False)], [challenger])
            for at in range(0, len(body), STAGE_PIECE):
                self._send("stage_write", struct.pack("<I", at) + body[at:at + STAGE_PIECE],
                           [AccountMeta(writer.pubkey(), True, False), AccountMeta(run, False, False),
                            AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                            AccountMeta(buffer(role), False, True)], [writer])

        leaf = bytes.fromhex(transcript["leaf"])
        metas = party(executor)
        if len(leaf) > DIRECT_LIMIT:
            stage(ROLE_EXECUTOR, leaf, executor)
            leaf, metas = bytes([FROM_STAGING]), metas + [AccountMeta(buffer(ROLE_EXECUTOR), False, False)]
        self._send("reveal_leaf", leaf, metas, [executor])
        claim = bytes.fromhex(transcript["claim"])
        metas = [AccountMeta(challenger.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                 AccountMeta(executor.pubkey(), False, True), AccountMeta(challenger.pubkey(), False, True)]
        if len(claim) > DIRECT_LIMIT:
            stage(ROLE_CHALLENGER, claim, challenger)
            claim, metas = bytes([FROM_STAGING]), metas + [AccountMeta(buffer(ROLE_CHALLENGER), False, False)]
        self._send("claim", claim, metas, [challenger])
        ruling = RULINGS[self.gc.account(dispute)[6]]
        return {"ruling": ruling, "transactions": self.sent - sent0, "wall_s": round(time.monotonic() - t0, 1),
                "dispute": str(dispute)}

    def run_status(self, run: Pubkey) -> int:
        return self.gc.account(run)[4]
