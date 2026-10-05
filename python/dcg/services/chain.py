"""Reading v2.1 runs and disputes for the services (layouts from
`disputes_v21.rs`), and finding new accounts by signature history."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from solders.pubkey import Pubkey

from ..disputes_v21 import client as CL

# Dispute layout.
D_KIND, D_DEPTH, D_LEVEL, D_POSITION, D_CURRENT, D_REVEALED_N = 5, 7, 8, 16, 96, 128
D_REVEALED = 144
D_LEAF_LEN = D_REVEALED + 32 * 32
D_LEAF_PRESENT = D_LEAF_LEN + 2
D_LEAF = D_LEAF_LEN + 8
D_LX_HI = D_LEAF
PH_NODES, PH_PICK, PH_LEAF, PH_CLAIM = 1, 2, 3, 4
KIND_NAMES = {1: "STEP_DESCEND", 2: "OUT_DESCEND", 3: "LX_STATE", 4: "LX_OUTPUT"}
# Run layout additions (client.py has the rest).
R_RUN_ID, R_NEXT, R_ROOT = 104, 156, 192
RUN_ROOT_BYTES = 176
STAGE_HEADER = 48


def _u32(d: bytes, at: int) -> int:
    return struct.unpack_from("<I", d, at)[0]


def _u64(d: bytes, at: int) -> int:
    return struct.unpack_from("<Q", d, at)[0]


@dataclass(frozen=True)
class DisputeState:
    address: Pubkey
    kind: int
    phase: int
    ruling: int
    depth: int
    level: int
    position: int
    deadline: int
    challenger: Pubkey
    run: Pubkey
    seq: int
    raw: bytes

    @classmethod
    def parse(cls, address: Pubkey, d: bytes) -> DisputeState:
        return cls(address, d[D_KIND], d[CL.D_PHASE], d[CL.D_RULING], d[D_DEPTH], _u32(d, D_LEVEL),
                   _u64(d, D_POSITION), _u64(d, CL.D_DEADLINE), Pubkey.from_bytes(d[CL.D_CHALLENGER:CL.D_CHALLENGER + 32]),
                   Pubkey.from_bytes(d[CL.D_RUN:CL.D_RUN + 32]), _u64(d, CL.D_SEQ), bytes(d))

    @property
    def kind_name(self) -> str:
        return KIND_NAMES.get(self.kind, f"kind {self.kind}")

    def revealed(self, pickable) -> dict[int, bytes]:
        """The current round's reveal by descendant index (pickable ones)."""
        d = min(self.depth, self.level)
        base, first = self.level - d, self.position << d
        return {i: self.raw[D_REVEALED + 32 * i:D_REVEALED + 32 * (i + 1)]
                for i in range(1 << d) if pickable(base, first + i)}

    def leaf(self) -> bytes | None:
        """The revealed leaf preimage (None for an absent leaf)."""
        if self.raw[D_LEAF_PRESENT] != 1:
            return None
        n = struct.unpack_from("<H", self.raw, D_LEAF_LEN)[0]
        return self.raw[D_LEAF:D_LEAF + n]

    @property
    def lx_hi(self) -> int:
        return _u64(self.raw, D_LX_HI)


@dataclass(frozen=True)
class RunState:
    address: Pubkey
    status: int
    template: Pubkey
    payer: Pubkey
    executor: Pubkey
    run_id: bytes
    deadline: int
    open: int
    root: bytes
    refs: dict[int, bytes]

    @classmethod
    def parse(cls, address: Pubkey, d: bytes) -> RunState | None:
        if d[:4] != b"D21R":
            return None
        n = _u32(d, R_NEXT)
        refs_at = R_ROOT + RUN_ROOT_BYTES
        refs = {_u32(d, refs_at + 52 * i): bytes(d[refs_at + 52 * i:refs_at + 52 * (i + 1)]) for i in range(n)}
        return cls(address, d[CL.R_STATUS], Pubkey.from_bytes(d[CL.R_TEMPLATE:CL.R_TEMPLATE + 32]),
                   Pubkey.from_bytes(d[CL.R_PAYER:CL.R_PAYER + 32]), Pubkey.from_bytes(d[CL.R_EXECUTOR:CL.R_EXECUTOR + 32]),
                   bytes(d[R_RUN_ID:R_RUN_ID + 32]), _u64(d, CL.R_DEADLINE), _u32(d, CL.R_OPEN),
                   bytes(d[R_ROOT:R_ROOT + RUN_ROOT_BYTES]), refs)


def staged_lists(buffer_data: bytes | None) -> dict[int, list[bytes]] | None:
    """The element refs of a staged LVR1 leaf body in an executor buffer, or
    None if the buffer holds no LVR1 body."""
    if buffer_data is None or len(buffer_data) < STAGE_HEADER:
        return None
    n = _u32(buffer_data, 40)
    body = buffer_data[STAGE_HEADER:STAGE_HEADER + n]
    if body[:4] != b"LVR1":
        return None
    leaf_len = struct.unpack_from("<H", body, 5)[0]
    at = 7 + leaf_len
    count, at = body[at], at + 1
    out = {}
    for _ in range(count):
        index, k = body[at], body[at + 1]
        at += 2
        out[index] = [bytes(body[at + 55 * j:at + 55 * (j + 1)]) for j in range(k)]
        at += 55 * k
    return out


class Discovery:
    """New accounts named by transactions touching an address, since the last
    signature seen (in signature order, oldest first)."""

    def __init__(self, cl: CL.DisputeClient, cursors: dict[str, str] | None = None):
        self.cl = cl
        self.cursors = cursors if cursors is not None else {}

    def new_keys(self, address: Pubkey) -> list[Pubkey]:
        last = self.cursors.get(str(address))
        sigs, before = [], None
        while True:
            opts = {"limit": 1000, "commitment": "confirmed"}
            if last:
                opts["until"] = last
            if before:
                opts["before"] = before
            page = self.cl.gc.rpc("getSignaturesForAddress", [str(address), opts])
            sigs += page
            if len(page) < 1000:
                break
            before = page[-1]["signature"]
        if not sigs:
            return []
        self.cursors[str(address)] = sigs[0]["signature"]
        keys: dict[str, None] = {}
        for sig in reversed([s["signature"] for s in sigs if s.get("err") is None]):
            tx = self.cl.gc.rpc("getTransaction", [sig, {"encoding": "json", "commitment": "confirmed",
                                                         "maxSupportedTransactionVersion": 0}])
            if tx is not None:
                keys.update(dict.fromkeys(tx["transaction"]["message"]["accountKeys"]))
        return [Pubkey.from_string(k) for k in keys]


def dispute_moves(cl: CL.DisputeClient, dispute: Pubkey) -> list[tuple[int, bytes]]:
    """The successful tag-227 moves on a dispute, oldest first, as
    (sub-tag, body), read from its transaction history. A watchtower rebuilds
    its replica from these after a restart, so recovery does not depend on
    its journal having been saved."""
    import base64

    from solders.transaction import VersionedTransaction

    sigs, before = [], None
    while True:
        opts = {"limit": 1000, "commitment": "confirmed", **({"before": before} if before else {})}
        page = cl.gc.rpc("getSignaturesForAddress", [str(dispute), opts])
        sigs += [p["signature"] for p in page if p.get("err") is None]
        if len(page) < 1000:
            break
        before = page[-1]["signature"]
    moves = []
    for sig in reversed(sigs):
        tx = cl.gc.rpc("getTransaction", [sig, {"encoding": "base64", "commitment": "confirmed",
                                                "maxSupportedTransactionVersion": 0}])
        if tx is None:
            continue
        message = VersionedTransaction.from_bytes(base64.b64decode(tx["transaction"][0])).message
        keys = message.account_keys
        for ix in message.instructions:
            data = bytes(ix.data)
            if keys[ix.program_id_index] == cl.gc.program_id and len(data) >= 2 and data[0] == CL.TAG:
                moves.append((data[1], data[2:]))
    return moves
