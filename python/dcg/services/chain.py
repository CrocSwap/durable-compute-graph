"""Reading v2.1 runs and disputes for the services (layouts from
`disputes_v21.rs`), and finding new accounts by signature history."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

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


def staged_lists(buffer_data: bytes | None, expected_leaf: bytes | None = None) -> dict[int, list[bytes]] | None:
    """The element refs of a staged LVR1 leaf body in an executor buffer, or
    None if the buffer holds no LVR1 body, or (with `expected_leaf`) one
    whose leaf is not the revealed leaf (review H6: a buffer the executor
    wrote but did not reveal from proves nothing)."""
    if buffer_data is None or len(buffer_data) < STAGE_HEADER:
        return None
    n = _u32(buffer_data, 40)
    body = buffer_data[STAGE_HEADER:STAGE_HEADER + n]
    if body[:4] != b"LVR1":
        return None
    leaf_len = struct.unpack_from("<H", body, 5)[0]
    if expected_leaf is not None and (body[4] != 1 or body[7:7 + leaf_len] != expected_leaf):
        return None
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
    """Accounts named by tag-227 transactions touching an address, found
    incrementally from its signature history (oldest first).

    - The cursor advances only past transactions that were read; a
      transaction the RPC cannot return yet is retried on the next call.
    - Lookup-table accounts are included; transactions that do not invoke
      the program are ignored (anyone may name an address in a transaction).
    - Each call reads at most `max_transactions` new transactions, so a burst
      of transactions cannot stall deadline-bound work; the rest follow on
      later calls.
    - `known(address)` is every account seen so far for that address.
    """

    def __init__(self, cl: CL.DisputeClient, state: dict | None = None, max_transactions: int = 64):
        self.cl = cl
        self.state = state if state is not None else {}
        self.state.setdefault("cursors", {})
        self.state.setdefault("keys", {})
        self.max_transactions = max_transactions

    def known(self, address: Pubkey) -> list[Pubkey]:
        return [Pubkey.from_string(k) for k in self.state["keys"].get(str(address), [])]

    def new_keys(self, address: Pubkey) -> list[Pubkey]:
        last = self.state["cursors"].get(str(address))
        pending, before = [], None
        while True:
            opts = {"limit": 1000, "commitment": "confirmed"}
            if last:
                opts["until"] = last
            if before:
                opts["before"] = before
            page = self.cl.gc.rpc("getSignaturesForAddress", [str(address), opts])
            pending += page
            if len(page) < 1000:
                break
            before = page[-1]["signature"]
        pending.reverse()  # oldest first
        # Every key of every newly read transaction is returned, even one
        # seen before: an address may be named before its account exists
        # (review N1); callers drop what they already track.
        found: dict[str, None] = {}
        seen = self.state["keys"].setdefault(str(address), [])
        batch = [e for e in pending[:self.max_transactions]]
        txs = self._fetch([e["signature"] for e in batch if e.get("err") is None])
        for entry in batch:
            if entry.get("err") is None:
                tx = txs.get(entry["signature"])
                if tx is None:
                    break  # not readable yet: stop here and retry from this signature
                for k in CL.program_tx_keys(tx, self.cl.gc.program_id):
                    found[k] = None
            self.state["cursors"][str(address)] = entry["signature"]
        seen.extend(k for k in found if k not in seen)
        return [Pubkey.from_string(k) for k in found]

    def _fetch(self, sigs: list[str]) -> dict[str, dict | None]:
        """`getTransaction` for each signature, in parallel."""
        from concurrent.futures import ThreadPoolExecutor

        def one(sig: str):
            return self.cl.gc.rpc("getTransaction", [sig, {"encoding": "json", "commitment": "confirmed",
                                                           "maxSupportedTransactionVersion": 0}])
        with ThreadPoolExecutor(max_workers=16) as pool:
            return dict(zip(sigs, pool.map(one, sigs)))

    def search_newest(self, address: Pubkey, found: Callable[[list[Pubkey]], bool], page: int = 64,
                      max_pages: int = 4) -> list[Pubkey]:
        """Read the address's history newest first until `found(keys so far)`
        is true (review R1: an account the chain says exists must not wait
        behind a backlog of unrelated transactions). At most `max_pages`
        pages per call (review H-1: one tick must not scan an unbounded
        history); a search that has not finished resumes where it stopped on
        the next call, and restarts from the newest once it reaches the end
        or succeeds. Does not move the forward cursor."""
        keys: dict[str, None] = {}
        resume = self.state.setdefault("search", {})
        before = resume.get(str(address))
        pages = 0
        while True:
            opts = {"limit": page, "commitment": "confirmed", **({"before": before} if before else {})}
            sigs = self.cl.gc.rpc("getSignaturesForAddress", [str(address), opts])
            if not sigs:
                resume.pop(str(address), None)
                break
            txs = self._fetch([s["signature"] for s in sigs if s.get("err") is None])
            for tx in txs.values():
                if tx is not None:
                    keys.update(dict.fromkeys(CL.program_tx_keys(tx, self.cl.gc.program_id)))
            result = [Pubkey.from_string(k) for k in keys]
            pages += 1
            if found(result) or len(sigs) < page:
                resume.pop(str(address), None)
                break
            before = sigs[-1]["signature"]
            if pages >= max_pages:
                resume[str(address)] = before  # continue from here next call
                break
        seen = self.state["keys"].setdefault(str(address), [])
        seen.extend(k for k in keys if k not in seen)
        return [Pubkey.from_string(k) for k in keys]


def dispute_moves(cl: CL.DisputeClient, dispute: Pubkey) -> list[tuple[int, bytes]]:
    """The successful descent moves on one dispute, oldest first, as
    (sub-tag, body), read from its transaction history: reveal_nodes (5),
    pick (6), and a cache answer (16) returned as a reveal_nodes body read
    from the cache account (slots in order, pickable ones only are used by
    the caller). Only instructions whose dispute account (index 3) is this
    dispute count, so batched transactions do not mix disputes. A watchtower
    rebuilds its replica from these after a restart."""
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
    from concurrent.futures import ThreadPoolExecutor

    def fetch(sig: str):
        return cl.gc.rpc("getTransaction", [sig, {"encoding": "base64", "commitment": "confirmed",
                                                  "maxSupportedTransactionVersion": 0}])
    with ThreadPoolExecutor(max_workers=16) as pool:
        fetched = dict(zip(sigs, pool.map(fetch, sigs)))
    moves = []
    for sig in reversed(sigs):
        tx = fetched[sig]
        if tx is None:
            raise RuntimeError(f"transaction {sig} of dispute {dispute} is not readable yet")
        message = VersionedTransaction.from_bytes(base64.b64decode(tx["transaction"][0])).message
        loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
        keys = list(message.account_keys) + [Pubkey.from_string(k) for k in
                                            loaded.get("writable", []) + loaded.get("readonly", [])]
        for ix in message.instructions:
            data = bytes(ix.data)
            accounts = list(ix.accounts)
            if (keys[ix.program_id_index] != cl.gc.program_id or len(data) < 2 or data[0] != CL.TAG
                    or len(accounts) < 4 or keys[accounts[3]] != dispute):
                continue
            if data[1] == CL.SUB_CACHE_ANSWER:
                cache = cl.gc.account(keys[accounts[4]]) if len(accounts) > 4 else None
                if cache is None:
                    raise RuntimeError(f"the cache answering dispute {dispute} is gone; cannot rebuild")
                moves.append((CL.SUB["reveal_nodes"], b"SLOTS" + bytes(cache[56:56 + 32 * 32])))
            else:
                moves.append((data[1], data[2:]))
    return moves
