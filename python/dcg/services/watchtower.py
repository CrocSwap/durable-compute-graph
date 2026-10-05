"""The watchtower (alpha E3, design executor-watchtower-v1 §4): check every
committed run of the watched templates and challenge a wrong commitment
from its first divergence (STEP and OUT descents; LX runs are not checked in
v1, owner 10-05).

    tower = Watchtower(client, challenger_key, "watchtower.json", watched)
    while True:
        tower.tick()                                  # at most every W/4

Each watched template names its plan and an input source: the application
supplies each run's external inputs, and the watchtower checks them against
the run's refs (owner 10-05: inputs come from the application until they
are posted on chain). A run whose inputs are not available is reported, not
checked.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from ..disputes_v21 import client as CL
from ..disputes_v21 import game as G
from ..disputes_v21 import run as R
from ..disputes_v21 import spec as S
from .chain import PH_CLAIM, PH_PICK, Discovery, DisputeState, RunState, dispute_moves, staged_lists
from .challenger import Challenger, dispute_kind
from .journal import Journal

#: (run, external id, its 52-byte ref) -> the input bytes, or None if unknown.
InputSource = Callable[[Pubkey, int, bytes], "bytes | None"]


@dataclass
class Watched:
    template: Pubkey
    spec: S.Spec
    plan_id: bytes
    inputs: InputSource
    depth: int = 4
    #: Template kinds the watchtower does not check (LX1 in v1).
    lx: bool = False


@dataclass
class Budget:
    max_open_disputes: int = 4


def log(**fields) -> None:
    print(json.dumps({"t": round(time.time(), 1), **fields}, default=str), flush=True)


@dataclass
class _Live:
    challenger: Challenger
    fed_rounds: int = 0
    claimed: bool = False
    extra: dict = field(default_factory=dict)


class Watchtower:
    def __init__(self, cl: CL.DisputeClient, challenger: Keypair, journal: str, watched: list[Watched],
                 budget: Budget = Budget()):
        self.cl, self.key, self.budget = cl, challenger, budget
        self.watched = {str(w.template): w for w in watched}
        self.journal = Journal(journal)
        for k in ("runs", "disputes", "cursors"):
            self.journal.data.setdefault(k, {})
        self.discovery = Discovery(cl, self.journal.data["cursors"])
        self._live: dict[str, _Live] = {}

    # --- the loop -------------------------------------------------------------------------
    def tick(self) -> list[str]:
        actions: list[str] = []
        for t_s, w in self.watched.items():
            try:
                self._discover(w)
            except Exception as exc:
                log(event="error", template=t_s, error=f"{type(exc).__name__}: {exc}")
        for run_s, entry in self.journal.data["runs"].items():
            if entry["state"] in ("ok", "closed", "skipped", "disputed", "missed"):
                continue
            try:
                actions += self._check(Pubkey.from_string(run_s), entry)
            except Exception as exc:
                log(event="error", run=run_s, error=f"{type(exc).__name__}: {exc}")
        for d_s, entry in self.journal.data["disputes"].items():
            if entry.get("done"):
                continue
            try:
                act = self._play(Pubkey.from_string(d_s), entry)
                if act:
                    actions.append(act)
            except Exception as exc:
                # A move refused because the dispute was ruled meanwhile (moot
                # after another challenger's win, or a timeout) is a race,
                # not a fault; the next tick settles it.
                raw = self.cl.gc.account(Pubkey.from_string(d_s))
                if raw is not None and DisputeState.parse(Pubkey.from_string(d_s), raw).ruling != CL.RULING_OPEN:
                    log(event="raced", dispute=d_s, note="ruled before our move landed")
                else:
                    log(event="error", dispute=d_s, error=f"{type(exc).__name__}: {exc}")
        self.journal.save()
        return actions

    def _discover(self, w: Watched) -> None:
        for key in self.discovery.new_keys(w.template):
            if str(key) in self.journal.data["runs"]:
                continue
            raw = self.cl.gc.account(key)
            if raw and raw[:4] == b"D21R" and raw[CL.R_TEMPLATE:CL.R_TEMPLATE + 32] == bytes(w.template):
                self.journal.data["runs"][str(key)] = {"template": str(w.template), "state": "seen"}
                log(event="run_seen", run=str(key), template=str(w.template))

    def _check(self, run: Pubkey, entry: dict) -> list[str]:
        raw = self.cl.gc.account(run)
        if raw is None or raw[:4] != b"D21R":
            entry["state"] = "closed"
            return []
        state = RunState.parse(run, raw)
        if state.status == CL.RUN_OPEN:
            return []  # not committed yet
        w = self.watched[entry["template"]]
        if state.status != CL.RUN_COMMITTED or self.cl.gc.slot() > state.deadline:
            entry["state"] = "closed" if state.status != CL.RUN_COMMITTED else "missed"
            if entry["state"] == "missed":
                log(event="missed", run=str(run), reason="the challenge window closed before a check")
            return []
        if w.lx:
            entry["state"] = "skipped"
            log(event="skipped", run=str(run), reason="LX1 runs are not checked in v1")
            return []
        values = {}
        for eid, ref in sorted(state.refs.items()):
            value = w.inputs(run, eid, ref)
            if value is None or R.external_ref(eid, w.spec.in_specs[eid][8:31], R.input_digest(w.spec.in_specs[eid], value)) != ref:
                log(event="inputs_unavailable", run=str(run), external_id=eid)
                return []  # retried next tick, until the window closes
            values[eid] = value
        honest = R.execute(w.spec, w.plan_id, state.run_id, values)
        record = G.RunRecord(w.plan_id, state.run_id, w.spec, state.root, state.refs)
        kind = dispute_kind(record, honest)
        if kind is None:
            entry["state"] = "ok"
            log(event="run_ok", run=str(run))
            return []
        open_now = sum(1 for d in self.journal.data["disputes"].values() if not d.get("done"))
        if open_now >= self.budget.max_open_disputes:
            log(event="over_budget", run=str(run))
            return []
        nonce = os.urandom(32)
        dispute = self.cl.pda(b"dcg21dsp", bytes(run), bytes(self.key.pubkey()), nonce)
        # Write ahead: a crash after the open lands must not open a second
        # dispute on restart (the journal names this one first).
        entry["state"] = "disputed"
        self.journal.data["disputes"][str(dispute)] = {"run": str(run), "kind": kind, "nonce": nonce.hex(),
                                                        "done": False}
        self.journal.save()
        self._open(run, state.template, dispute, nonce, kind)
        self.journal.data["disputes"][str(dispute)]["opened"] = True
        self.journal.save()
        self._live[str(dispute)] = _Live(Challenger(record, honest, kind, w.depth))
        log(event="open", run=str(run), dispute=str(dispute), kind=kind)
        return [f"open {dispute}"]

    def _open(self, run: Pubkey, template: Pubkey, dispute: Pubkey, nonce: bytes, kind: str) -> None:
        self.cl._send("open", nonce + bytes([CL.KIND[kind]]),
                      [AccountMeta(self.key.pubkey(), True, True), AccountMeta(run, False, True),
                       AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                       AccountMeta(CL.SYSTEM, False, False)], [self.key])

    # --- playing a dispute ------------------------------------------------------------------
    def _replica(self, d_s: str, entry: dict) -> _Live:
        """The in-memory challenger, rebuilt from the journal after a restart."""
        if d_s not in self._live:
            run = Pubkey.from_string(entry["run"])
            state = RunState.parse(run, self.cl.gc.account(run))
            w = self.watched[self.journal.data["runs"][entry["run"]]["template"]]
            values = {eid: w.inputs(run, eid, ref) for eid, ref in state.refs.items()}
            honest = R.execute(w.spec, w.plan_id, state.run_id, values)
            record = G.RunRecord(w.plan_id, state.run_id, w.spec, state.root, state.refs)
            live = _Live(Challenger(record, honest, entry["kind"], w.depth))
            # Replay the dispute's own moves from chain: each reveal and the
            # pick that followed it (a reveal still awaiting its pick is
            # handled by the PICK phase below).
            c, pending = live.challenger, None
            for sub, body in dispute_moves(self.cl, Pubkey.from_string(d_s)):
                if sub == CL.SUB["reveal_nodes"]:
                    r = c.replica
                    d = min(r.depth, r.level)
                    base, first = r.level - d, r.position << d
                    slots = [i for i in range(1 << d) if r._pickable(base, first + i)]
                    pending = {i: body[32 * n:32 * (n + 1)] for n, i in enumerate(slots)}
                elif sub == CL.SUB["pick"] and pending is not None:
                    c.on_nodes(pending)
                    c.pick(body[0])
                    pending = None
            log(event="replica_rebuilt", dispute=d_s, level=c.replica.level, position=c.replica.position)
            self._live[d_s] = live
        return self._live[d_s]

    def _play(self, dispute: Pubkey, entry: dict) -> str | None:
        raw = self.cl.gc.account(dispute)
        run = Pubkey.from_string(entry["run"])
        if raw is None and not entry.get("opened"):
            # Written ahead but the open never landed: open it now, while the
            # run can still be disputed (else give up on this entry).
            run_raw = self.cl.gc.account(run)
            state = RunState.parse(run, run_raw) if run_raw else None
            if state and state.status == CL.RUN_COMMITTED and self.cl.gc.slot() <= state.deadline:
                self._open(run, state.template, dispute, bytes.fromhex(entry["nonce"]), entry["kind"])
                entry["opened"] = True
                self.journal.save()
                log(event="open_retried", dispute=str(dispute))
                return f"open {dispute}"
            entry["done"] = True
            return None
        if raw is not None and not entry.get("opened"):
            entry["opened"] = True
        if raw is None:
            # Closed by someone else's settlement: the run's receipt says how
            # it ended (refuted means a challenger won).
            status = self.cl.run_status(run) if self.cl.gc.account(run) is not None else None
            entry["done"] = True
            self.journal.data["runs"][entry["run"]]["state"] = "closed"
            log(event="settled_elsewhere", dispute=str(dispute), run=str(run),
                outcome={CL.RUN_REFUTED: "refuted", CL.RUN_FINAL: "final"}.get(status, "closed"))
            return None
        d = DisputeState.parse(dispute, raw)
        if d.ruling != CL.RULING_OPEN:
            out = self.cl.settle_and_reclaim(run, wait=0.0)
            log(event="settle", dispute=str(dispute), ruling=CL.RULINGS[d.ruling], **out)
            if out["state"] == "closed" or self.cl.gc.account(dispute) is None:
                entry["done"] = True
                self.journal.data["runs"][entry["run"]]["state"] = "closed"
            return f"settle {run}" if out["steps"] else None
        if self.cl.gc.slot() > d.deadline and d.phase not in (PH_PICK, PH_CLAIM):
            # The executor missed its deadline: the timeout rules for us.
            out = self.cl.settle_and_reclaim(run, wait=0.0)
            log(event="executor_timeout", dispute=str(dispute), **out)
            return f"timeout {dispute}" if out["steps"] else None
        live = self._replica(str(dispute), entry)
        c = live.challenger
        template = Pubkey.from_bytes(self.cl.gc.account(run)[CL.R_TEMPLATE:CL.R_TEMPLATE + 32])
        party = [AccountMeta(self.key.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, True)]
        if d.phase == PH_PICK and c.replica.level == d.level and c.replica.position == d.position:
            nodes = d.revealed(c.replica._pickable)
            pick = c.on_nodes(nodes)
            self.cl._send("pick", bytes([pick]), party, [self.key])
            c.pick(pick)
            self.journal.save()
            log(event="pick", dispute=str(dispute), level=d.level, pick=pick)
            return f"pick {dispute}"
        if d.phase == PH_CLAIM and not live.claimed:
            buffer_e = self.cl.pda(b"dcg21stg", bytes(dispute), bytes([CL.ROLE_EXECUTOR]))
            lists = staged_lists(self.cl.gc.account(buffer_e))
            name, _kw, body, ruling = c.on_leaf(d.leaf(), lists)
            if ruling != "C":
                log(event="claim_withheld", dispute=str(dispute), claim=name, local_ruling=ruling)
                live.claimed = True
                return None
            executor = Pubkey.from_bytes(self.cl.gc.account(run)[CL.R_EXECUTOR:CL.R_EXECUTOR + 32])
            metas = [AccountMeta(self.key.pubkey(), True, False), AccountMeta(run, False, True),
                     AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                     AccountMeta(executor, False, True), AccountMeta(self.key.pubkey(), False, True)]
            if len(body) > CL.DIRECT_LIMIT:
                buffer_c = self.cl.stage_body(run, template, dispute, CL.ROLE_CHALLENGER, body, self.key, self.key)
                body, metas = bytes([CL.FROM_STAGING]), metas + [AccountMeta(buffer_c, False, False)]
            heap = None
            if lists is not None:
                metas.append(AccountMeta(buffer_e, False, False))
                heap = CL.LIST_HEAP_FRAME
            self.cl._send("claim", body, metas, [self.key], heap_frame=heap)
            live.claimed = True
            self.journal.save()
            log(event="claim", dispute=str(dispute), claim=name)
            return f"claim {dispute}"
        return None
