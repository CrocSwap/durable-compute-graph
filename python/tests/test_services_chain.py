"""Discovery and dispute-history reading for the E3 services, against a fake
RPC (review 10-05: H2 cursor only past what was read, H3 lookup-table
accounts and non-program transactions, H4 bounded reads, M2 cache answers
and batched moves on other disputes)."""

from __future__ import annotations

import base64

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from dcg.disputes_v21 import client as CL
from dcg.services.chain import Discovery, dispute_moves

PROGRAM = Pubkey.new_unique()


class FakeGC:
    def __init__(self, sigs, txs, accounts=None):
        self.program_id = PROGRAM
        self.sigs = sigs  # newest first: [{"signature": s, "err": None}]
        self.txs = txs  # signature -> tx (or None: not readable yet)
        self.accounts = accounts or {}
        self.reads = 0

    def rpc(self, method, params):
        if method == "getSignaturesForAddress":
            opts = params[1]
            out = list(self.sigs)
            if "until" in opts:
                out = out[:[s["signature"] for s in out].index(opts["until"])]
            if "before" in opts:
                out = out[[s["signature"] for s in out].index(opts["before"]) + 1:]
            return out[:opts["limit"]]
        if method == "getTransaction":
            self.reads += 1
            return self.txs.get(params[0])
        raise AssertionError(method)

    def account(self, key):
        return self.accounts.get(key)


def json_tx(keys, program_index, loaded=()):
    return {"transaction": {"message": {"accountKeys": [str(k) for k in keys],
                                        "instructions": [{"programIdIndex": program_index}]}},
            "meta": {"loadedAddresses": {"writable": [str(k) for k in loaded], "readonly": []}}}


def strip(keys):
    """Drop the program id itself (it is one of every program transaction's keys)."""
    return [k for k in keys if k != PROGRAM]


def client(gc):
    cl = CL.DisputeClient.__new__(CL.DisputeClient)
    cl.gc = gc
    return cl


def test_discovery_reads_only_program_transactions_and_lookup_accounts():
    a, b, hidden, other = (Pubkey.new_unique() for _ in range(4))
    txs = {"s1": json_tx([a, PROGRAM], 1, loaded=[hidden]), "s2": json_tx([b, other], 1)}
    gc = FakeGC([{"signature": "s2", "err": None}, {"signature": "s1", "err": None}], txs)
    d = Discovery(client(gc))
    keys = d.new_keys(Pubkey.new_unique())
    assert hidden in keys and a in keys and b not in keys  # s2 does not invoke the program


def test_discovery_never_skips_an_unreadable_transaction():
    a, b = Pubkey.new_unique(), Pubkey.new_unique()
    txs = {"s1": json_tx([a, PROGRAM], 1), "s2": None}
    gc = FakeGC([{"signature": "s2", "err": None}, {"signature": "s1", "err": None}], txs)
    d = Discovery(client(gc))
    addr = Pubkey.new_unique()
    assert strip(d.new_keys(addr)) == [a]
    assert d.state["cursors"][str(addr)] == "s1"  # stopped before s2
    gc.txs["s2"] = json_tx([b, PROGRAM], 1)  # readable now
    assert strip(d.new_keys(addr)) == [b]
    assert set(strip(d.known(addr))) == {a, b}


def test_discovery_reads_a_bounded_number_per_call():
    keys = [Pubkey.new_unique() for _ in range(10)]
    sigs = [{"signature": f"s{i}", "err": None} for i in reversed(range(10))]
    gc = FakeGC(sigs, {f"s{i}": json_tx([keys[i], PROGRAM], 1) for i in range(10)})
    d = Discovery(client(gc), max_transactions=4)
    addr = Pubkey.new_unique()
    assert strip(d.new_keys(addr)) == keys[:4]
    assert gc.reads == 4
    assert strip(d.new_keys(addr)) == keys[4:8]
    assert strip(d.new_keys(addr)) == keys[8:]


def b64_tx(instructions, payer):
    msg = Message.new_with_blockhash(instructions, payer.pubkey(), Hash.default())
    tx = Transaction.new_unsigned(msg)
    return {"transaction": [base64.b64encode(bytes(tx)).decode(), "base64"], "meta": {"loadedAddresses": {}}}


def test_dispute_moves_reads_cache_answers_and_ignores_other_disputes():
    payer = Keypair()
    run, tmpl, dispute, other, cache = (Pubkey.new_unique() for _ in range(5))

    def ix(sub, body, d, extra=()):
        metas = [AccountMeta(payer.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(tmpl, False, False), AccountMeta(d, False, True)] + [AccountMeta(k, False, False) for k in extra]
        return Instruction(PROGRAM, bytes([CL.TAG, sub]) + body, metas)

    slots = bytes(range(32)) * 32
    txs = {
        "s1": b64_tx([ix(CL.SUB_CACHE_ANSWER, b"", dispute, [cache])], payer),
        "s2": b64_tx([ix(CL.SUB["pick"], b"\x03", other), ix(CL.SUB["pick"], b"\x01", dispute)], payer),
    }
    cache_data = b"D21C" + bytes(52) + slots
    gc = FakeGC([{"signature": "s2", "err": None}, {"signature": "s1", "err": None}], txs, {cache: cache_data})
    moves = dispute_moves(client(gc), dispute)
    assert moves == [(CL.SUB["reveal_nodes"], b"SLOTS" + slots), (CL.SUB["pick"], b"\x01")]


def test_discovery_returns_an_address_again_once_it_appears_later():
    """Review N1: a dispute address named (by a prestage, or deliberately)
    before its account exists must be returned again when a later
    transaction names it, so the service can adopt it then."""
    dispute = Pubkey.new_unique()
    txs = {"s1": json_tx([dispute, PROGRAM], 1)}
    gc = FakeGC([{"signature": "s1", "err": None}], txs)
    d = Discovery(client(gc))
    addr = Pubkey.new_unique()
    assert dispute in d.new_keys(addr)  # named early; the caller finds no account yet
    gc.sigs.insert(0, {"signature": "s2", "err": None})
    gc.txs["s2"] = json_tx([dispute, PROGRAM], 1)  # the open
    assert dispute in d.new_keys(addr)


def test_search_newest_finds_past_a_backlog():
    """Review R1: an account the chain counts is found newest first, past
    any backlog the bounded cursor has not reached."""
    keys = [Pubkey.new_unique() for _ in range(300)]
    sigs = [{"signature": f"s{i}", "err": None} for i in reversed(range(300))]
    gc = FakeGC(sigs, {f"s{i}": json_tx([keys[i], PROGRAM], 1) for i in range(300)})
    d = Discovery(client(gc), max_transactions=4)
    addr = Pubkey.new_unique()
    target = keys[299]  # the newest
    got = d.search_newest(addr, lambda ks: target in ks, page=64)
    assert target in got and gc.reads <= 64
