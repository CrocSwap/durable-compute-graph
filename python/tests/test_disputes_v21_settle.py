"""settle_and_reclaim's choice of the next lifecycle step (alpha E4), on a
fake chain. The common paths (advance, pot, dispute and run closes, finalize)
ran on the alpha testnet program (Basanos out/runs/dcg-e4-settle-2026-10-05);
these cover the moot and timeout branches and the waits."""

from __future__ import annotations

import struct

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from dcg import v21
from dcg.disputes_v21 import client as CL

PROGRAM = Pubkey.new_unique()


def run_bytes(status, *, deadline=100, open_=0, seq=0, prefix=0, best=2**64 - 1, paid=0, closed=0, template=None):
    r = bytearray(CL.R_CLOSED + 4 + 176)
    r[:4], r[CL.R_STATUS] = b"D21R", status
    r[CL.R_TEMPLATE:CL.R_TEMPLATE + 32] = bytes(template or Pubkey.new_unique())
    struct.pack_into("<Q", r, CL.R_DEADLINE, deadline)
    struct.pack_into("<I", r, CL.R_OPEN, open_)
    struct.pack_into("<QQQ", r, CL.R_SEQ, seq, prefix, best)
    r[CL.R_PAID] = paid
    struct.pack_into("<I", r, CL.R_CLOSED, closed)
    return bytes(r)


def dispute_bytes(run, seq, *, ruling=0, phase=1, deadline=100):
    d = bytearray(CL.D_SEQ + 8)
    d[:4], d[CL.D_PHASE], d[CL.D_RULING] = b"D21D", phase, ruling
    struct.pack_into("<Q", d, CL.D_DEADLINE, deadline)
    d[CL.D_CHALLENGER:CL.D_CHALLENGER + 32] = bytes(Pubkey.new_unique())
    d[CL.D_RUN:CL.D_RUN + 32] = bytes(run)
    struct.pack_into("<Q", d, CL.D_SEQ, seq)
    return bytes(d)


class FakeChain:
    def __init__(self, accounts, slot):
        self.accounts, self.now, self.sent = accounts, slot, []
        self.program_id, self.payer = PROGRAM, Keypair()

    def account(self, key):
        return self.accounts.get(key)

    def slot(self):
        return self.now

    def pda(self, *seeds):
        return Pubkey.find_program_address(list(seeds), PROGRAM)[0]

    def rpc(self, method, params):
        assert method == "getMultipleAccounts"
        import base64
        return {"value": [None if k not in self.accounts else
                          {"owner": str(PROGRAM), "data": [base64.b64encode(self.accounts[k]).decode()]}
                          for k in map(Pubkey.from_string, params[0])]}

    def send(self, data, metas, signers, cu, heap_frame=None):
        self.sent.append(next(k for k, v in CL.SUB.items() if v == data[1]))
        return "sig"


def step(accounts, slot, run):
    gc = FakeChain(accounts, slot)
    out = CL.DisputeClient(gc)._settle_once(run, True, list(accounts))
    return out, gc.sent


def test_moot_before_timeout_on_a_refuted_run():
    run, d0, d1 = (Pubkey.new_unique() for _ in range(3))
    accounts = {run: run_bytes(CL.RUN_REFUTED, open_=1, seq=2, prefix=0, best=0),
                d0: dispute_bytes(run, 0, ruling=CL.RULING_CHALLENGER, phase=CL.PH_RULED),
                d1: dispute_bytes(run, 1, deadline=10)}
    out, sent = step(accounts, 50, run)
    assert sent == ["moot"] and out == f"moot {d1}"


def test_timeout_after_the_phase_deadline_and_wait_before_it():
    run, d0 = Pubkey.new_unique(), Pubkey.new_unique()
    accounts = {run: run_bytes(CL.RUN_COMMITTED, open_=1, seq=1), d0: dispute_bytes(run, 0, deadline=60)}
    out, sent = step(accounts, 50, run)
    assert sent == [] and out.startswith("wait: 1 open dispute(s), next phase deadline slot 60")
    out, sent = step(accounts, 61, run)
    assert sent == ["timeout"]


def test_finalize_waits_for_the_window_and_cancels_an_expired_uncommitted_run():
    run = Pubkey.new_unique()
    assert step({run: run_bytes(CL.RUN_COMMITTED, deadline=100)}, 100, run) == (
        "wait: challenge window open until slot 100", [])
    assert step({run: run_bytes(CL.RUN_COMMITTED, deadline=100)}, 101, run)[1] == ["finalize"]
    assert step({run: run_bytes(CL.RUN_OPEN, deadline=100)}, 101, run)[1] == ["close_run"]


def test_pot_before_closing_the_best_dispute():
    run, d0 = Pubkey.new_unique(), Pubkey.new_unique()
    accounts = {run: run_bytes(CL.RUN_REFUTED, seq=1, prefix=1, best=0),
                d0: dispute_bytes(run, 0, ruling=CL.RULING_CHALLENGER, phase=CL.PH_RULED)}
    assert step(accounts, 1, run)[1] == ["pay_pot"]
    accounts[run] = run_bytes(CL.RUN_REFUTED, seq=1, prefix=1, best=0, paid=1)
    assert step(accounts, 1, run)[1] == ["close_dispute"]
    del accounts[d0]
    accounts[run] = run_bytes(CL.RUN_REFUTED, seq=1, prefix=1, best=0, paid=1, closed=1)
    assert step(accounts, 1, run)[1] == ["close_run"]


def test_phase_window_is_sized_from_the_largest_witness():
    import pytest

    from dcg.disputes_v21 import wire as W

    sp = _big.plan()
    # The chunk, the running accumulator input and the state (an upper bound).
    assert W.largest_step_witness(sp) == 65_536 + 4 + 4
    need = W.phase_window_for(W.largest_step_witness(sp))
    assert need == 2_288  # (10 s + 51 s upload) x 1.5 at 40 ms slots
    with pytest.raises(ValueError, match="too short"):
        W.template_data(sp, 3, bytes(32))
    W.template_data(sp, 3, bytes(32), phase_window=need)
    W.template_data(sp, 3, bytes(32), slot_ms=None)  # the check can be skipped
    assert W.phase_window_for(0) == W.MIN_PHASE_WINDOW


@v21.trace
def _big(data: v21.Chunked(bytes=2 * 65_536, chunk=65_536)):
    return v21.reduce("sumchunk_i32", data)
