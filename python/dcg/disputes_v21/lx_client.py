"""A live-cluster client for LX1 checkpointed disputes on tag 227 (design
`docs/design/v2.1-lazy-expansion.md` §8): the LX1 template, the commitment,
and a dispute played live between two parties that answer from their own
executions (roots at coordinates, the terminal opening), as the program's
ProgramTest (`crates/dcg-program/tests/disputes_v21_lx.rs`) sends them.

Parties are callables, so an application plugs in its executor service:
`roots(coordinates) -> [32-byte root]` and `opening(coordinate) -> bytes`
(the staged replay opening: state multi-proof, then constant reads).
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from . import lx as L
from . import wire as W
from .client import CREATE_STAGE, ROLE_CHALLENGER, ROLE_EXECUTOR, RULINGS, STAGE_PIECE, SUB, SYSTEM, DisputeClient

SUB.update({"lx_midpoints": 23, "lx_pick": 24, "lx_opening": 25, "lx_output": 26})
KIND_LX_STATE, KIND_LX_OUTPUT = 3, 4
LX_TAIL_MAGIC = b"DLX1"
PARAMS_DOMAIN = b"dcg.lx.params.v1\x00"
RUN_ROOT_BYTES = 176
LX_HEAP_FRAME = 256 * 1024


@dataclass(frozen=True)
class LxTemplate:
    kernel: bytes  # 16 bytes
    semantic: int
    abi: int
    arity: int
    k_min: int
    k_max: int
    max_positions: int
    constants_root: bytes = bytes(32)
    challenge_window: int = 1_000
    phase_window: int = 750
    executor_bond: int = 2_000_000
    challenger_bond: int = 1_000_000
    slasher_bps: int = 5_000

    def data(self) -> bytes:
        """The v2.1 template skeleton (depth 1, one step, no outputs, the
        constants root in the spec-root field, no blocks), then the LX tail."""
        if len(self.kernel) != 16 or len(self.constants_root) != 32:
            raise ValueError("kernel id or constants root")
        data = bytes([1])
        for x in (1, 0, self.challenge_window, self.phase_window, self.executor_bond, self.challenger_bond):
            data += struct.pack("<Q", x)
        data += struct.pack("<II", 0, 0) + self.constants_root + struct.pack("<H", self.slasher_bps) + bytes(32)
        data += LX_TAIL_MAGIC + self.kernel + struct.pack("<HH", self.semantic, self.abi)
        data += bytes([self.arity, 0, 0, 0]) + struct.pack("<IIQ", self.k_min, self.k_max, self.max_positions)
        return data

    def template_id(self) -> bytes:
        return hashlib.sha256(W.TEMPLATE_DOMAIN + self.data()).digest()


def checkpoint_levels(roots: Sequence[bytes]) -> list[list[bytes]]:
    return L.checkpoint_tree(list(roots)).levels


def tree_path(levels: list[list[bytes]], i: int) -> bytes:
    out = b""
    for level in levels[:-1]:
        out += level[i ^ 1]
        i >>= 1
    return out


def midpoint_coordinates(lo: int, hi: int, arity: int) -> list[int]:
    """`lx.Dispute.midpoint_coordinates`: fixed by the interval."""
    span = hi - lo
    parts = min(arity, span)
    return sorted({lo + (span * i) // parts for i in range(1, parts)})


class LxClient(DisputeClient):
    """LX1 moves on top of the v2.1 client's setup, staging and closes."""

    def run_id(self, template_id: bytes, params: bytes, executor: Pubkey, nonce: bytes | None = None) -> bytes:
        nonce = hashlib.sha256(PARAMS_DOMAIN + params).digest() if nonce is None else nonce
        return hashlib.sha256(b"dcg.run.id.v2.1\x00" + template_id + nonce + struct.pack("<I", 0) + bytes(executor)).digest()

    def init_lx_run(self, template: Pubkey, template_id: bytes, params: bytes, executor: Pubkey,
                    payer: Keypair) -> tuple[Pubkey, bytes]:
        """An LX1 run: its input id is the digest of the machine parameters
        (the payer admits them, LX1 review H1)."""
        nonce = hashlib.sha256(PARAMS_DOMAIN + params).digest()
        run = self.init_run(template, template_id, nonce, executor, [], payer)
        return run, self.run_id(template_id, params, executor, nonce)

    def lx_commit(self, run: Pubkey, template: Pubkey, run_id: bytes, roots: Sequence[bytes], outputs_digest: bytes,
                  params: bytes, positions: int, k: int, executor: Keypair) -> list[list[bytes]]:
        levels = checkpoint_levels(roots)
        root = bytearray(RUN_ROOT_BYTES)
        root[0:32] = run_id
        root[32:64] = levels[-1][0]
        root[64:96] = outputs_digest
        root[96:128] = hashlib.sha256(PARAMS_DOMAIN + params).digest()
        root[128:136] = struct.pack("<Q", positions)
        root[136:140] = struct.pack("<I", k)
        self.commit(run, template, bytes(root) + tree_path(levels, 0) + params, executor)
        return levels

    def _stage(self, run: Pubkey, template: Pubkey, dispute: Pubkey, role: int, body: bytes, writer: Keypair,
               funder: Keypair) -> Pubkey:
        buffer = self.pda(b"dcg21stg", bytes(dispute), bytes([role]))
        created = CREATE_STAGE if role == ROLE_EXECUTOR else min(len(body), CREATE_STAGE)
        grow = [AccountMeta(funder.pubkey(), True, True), AccountMeta(run, False, False),
                AccountMeta(template, False, False), AccountMeta(dispute, False, False),
                AccountMeta(buffer, False, True), AccountMeta(SYSTEM, False, False)]
        self._send("stage_create", bytes([role]) + struct.pack("<I", created), grow, [funder])
        size = created
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

    def lx_play(self, run: Pubkey, template: Pubkey, *, coordinates: Sequence[int], roots: Sequence[bytes],
                levels: list[list[bytes]], pair: int, params: bytes, arity: int,
                executor: Keypair, challenger: Keypair,
                executor_roots: Callable[[list[int]], list[bytes]],
                challenger_roots: Callable[[list[int]], list[bytes]],
                executor_opening: Callable[[int], bytes],
                dispute_nonce: bytes = bytes([1]) * 32, log: Callable[[str], None] = print) -> dict:
        """C opens checkpoint pair `pair` of E's commitment; the parties bisect
        it from their executions; E opens the terminal transition. Returns the
        ruling, the terminal coordinate and the transaction count."""
        t0, sent0 = time.monotonic(), self.sent
        dispute = self.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), dispute_nonce)
        body = (bytes([KIND_LX_STATE]) + struct.pack("<I", pair) + roots[pair] + roots[pair + 1]
                + tree_path(levels, pair) + tree_path(levels, pair + 1) + params)
        self._send("open", dispute_nonce + body,
                   [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                    AccountMeta(SYSTEM, False, False)], [challenger])

        def party(who: Keypair) -> list[AccountMeta]:
            return [AccountMeta(who.pubkey(), True, False), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True)]

        lo, hi = coordinates[pair], coordinates[pair + 1]
        root_hi = roots[pair + 1]
        rounds = 0
        while hi - lo > 1:
            mids = midpoint_coordinates(lo, hi, arity)
            theirs = executor_roots(mids)
            self._send("lx_midpoints", b"".join(theirs), party(executor), [executor])
            # C names the first sub-interval whose upper root it disputes.
            uppers = theirs + [root_hi]
            mine = challenger_roots(mids + [hi])
            pick = next((i for i, (r, m) in enumerate(zip(uppers, mine)) if r != m), len(uppers) - 1)
            self._send("lx_pick", bytes([pick]), party(challenger), [challenger])
            bounds = [lo] + mids + [hi]
            root_hi = uppers[pick]
            lo, hi = bounds[pick], bounds[pick + 1]
            rounds += 1
            log(f"  round {rounds}: [{lo}, {hi})")
        terminal = struct.unpack_from("<Q", self.gc.account(dispute), 16)[0]
        if terminal != lo:
            raise RuntimeError(f"the program's terminal {terminal} is not the bisection's {lo}")
        opening = executor_opening(lo)
        buffer = self._stage(run, template, dispute, ROLE_EXECUTOR, opening, executor, challenger)
        self._send("lx_opening", params,
                   [AccountMeta(executor.pubkey(), True, True), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                    AccountMeta(challenger.pubkey(), False, True), AccountMeta(buffer, False, False)],
                   [executor], heap_frame=LX_HEAP_FRAME)
        ruling = RULINGS[self.gc.account(dispute)[6]]
        return {"ruling": ruling, "terminal": lo, "rounds": rounds, "opening_bytes": len(opening),
                "transactions": self.sent - sent0, "wall_s": round(time.monotonic() - t0, 1), "dispute": str(dispute)}

    def lx_output_claim(self, run: Pubkey, template: Pubkey, *, roots: Sequence[bytes], levels: list[list[bytes]],
                        output_opening: bytes, params: bytes, executor: Pubkey, challenger: Keypair,
                        dispute_nonce: bytes = bytes([3]) * 32) -> dict:
        """C claims the committed outputs are wrong by opening the output slots
        against the final root (one transaction after staging)."""
        dispute = self.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), dispute_nonce)
        self._send("open", dispute_nonce + bytes([KIND_LX_OUTPUT]),
                   [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                    AccountMeta(SYSTEM, False, False)], [challenger])
        staged = roots[-1] + tree_path(levels, len(roots) - 1) + output_opening
        buffer = self._stage(run, template, dispute, ROLE_CHALLENGER, staged, challenger, challenger)
        self._send("lx_output", params,
                   [AccountMeta(challenger.pubkey(), True, True), AccountMeta(run, False, True),
                    AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                    AccountMeta(executor, False, True), AccountMeta(buffer, False, False)], [challenger])
        return {"ruling": RULINGS[self.gc.account(dispute)[6]], "dispute": str(dispute)}
