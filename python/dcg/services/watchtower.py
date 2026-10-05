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
checked. The plan is checked against the template on chain at start-up.
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
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

# Template account layout (disputes_v21.rs `template`).
T_DEPTH, T_STEPS, T_OUTPUTS, T_SPEC_ROOT, T_PLAN_ID = 4, 8, 16, 64, 136


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


class ConfigError(ValueError):
    """A watched plan does not match its template on chain."""


class Watchtower:
    def __init__(self, cl: CL.DisputeClient, challenger: Keypair, journal: str, watched: list[Watched],
                 budget: Budget = Budget(), tick_budget_s: float = 10.0):
        self.cl, self.key, self.budget, self.tick_budget_s = cl, challenger, budget, tick_budget_s
        self.watched = {str(w.template): w for w in watched}
        self.journal = Journal(journal)
        for k in ("runs", "disputes", "discovery"):
            self.journal.data.setdefault(k, {})
        self.discovery = Discovery(cl, self.journal.data["discovery"])
        self._live: dict[str, Challenger] = {}
        # A move sent whose landing is not yet known (review N2): the pick
        # (level, position, index), or the built claim (to resend as is).
        self._sent_pick: dict[str, tuple[int, int, int]] = {}
        self._claims: dict[str, tuple] = {}
        for w in watched:
            self._check_config(w)

    def _check_config(self, w: Watched) -> None:
        """The plan must be the one the template commits to: a wrong plan
        makes H wrong, and the watchtower would challenge honest runs."""
        t = self.cl.gc.account(w.template)
        if t is None or t[:4] != b"D21T":
            raise ConfigError(f"{w.template} is not a v2.1 template")
        if w.lx:
            return
        got = (t[T_DEPTH], struct.unpack_from("<Q", t, T_STEPS)[0], struct.unpack_from("<Q", t, T_OUTPUTS)[0],
               bytes(t[T_SPEC_ROOT:T_SPEC_ROOT + 32]), bytes(t[T_PLAN_ID:T_PLAN_ID + 32]))
        want = (w.depth, w.spec.total_steps, w.spec.total_outputs, w.spec.root, w.plan_id)
        if got != want:
            raise ConfigError(f"the plan for template {w.template} does not match the template on chain")

    # --- the loop -------------------------------------------------------------------------
    def tick(self) -> list[str]:
        """One pass. Own disputes come first (soonest deadline first), then
        checks of committed runs, then bounded discovery of new runs."""
        t0 = time.monotonic()
        actions: list[str] = []
        disputes = []
        for d_s, entry in self.journal.data["disputes"].items():
            if entry.get("done"):
                continue
            raw = self._safe(lambda d_s=d_s: self.cl.gc.account(Pubkey.from_string(d_s)))
            deadline = struct.unpack_from("<Q", raw, CL.D_DEADLINE)[0] if raw else 0
            disputes.append((deadline, d_s, entry))
        for _deadline, d_s, entry in sorted(disputes, key=lambda x: x[0]):
            try:
                act = self._play(Pubkey.from_string(d_s), entry)
                if act:
                    actions.append(act)
            except Exception as exc:
                self._report(d_s, exc)
            self.journal.save()
        for run_s, entry in self.journal.data["runs"].items():
            if entry["state"] in ("ok", "closed", "skipped", "disputed", "missed"):
                continue
            try:
                actions += self._check(Pubkey.from_string(run_s), entry)
            except Exception as exc:
                log(event="error", run=run_s, error=f"{type(exc).__name__}: {exc}")
        for t_s, w in self.watched.items():
            try:
                self._discover(w)
            except Exception as exc:
                log(event="error", template=t_s, error=f"{type(exc).__name__}: {exc}")
        self.journal.save()
        elapsed = time.monotonic() - t0
        if elapsed > self.tick_budget_s:
            log(event="slow_tick", seconds=round(elapsed, 1), budget=self.tick_budget_s)
        return actions

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:
            return None

    def _report(self, d_s: str, exc: Exception) -> None:
        """A move refused because the dispute was ruled meanwhile (moot after
        another challenger's win, or a timeout) is a race, not a fault."""
        raw = self._safe(lambda: self.cl.gc.account(Pubkey.from_string(d_s)))
        if raw is not None and raw[CL.D_RULING] != CL.RULING_OPEN:
            log(event="raced", dispute=d_s, note="ruled before our move landed")
        else:
            log(event="error", dispute=d_s, error=f"{type(exc).__name__}: {exc}")
            if d_s not in self._sent_pick and d_s not in self._claims:
                self._live.pop(d_s, None)  # rebuild from chain on the next tick

    def _discover(self, w: Watched) -> None:
        self._adopt(w, self.discovery.new_keys(w.template))
        # The template counts its live runs: if it has more than we know,
        # search its history newest first until they are found (review R1).
        t = self.cl.gc.account(w.template)
        active = struct.unpack_from("<I", t, len(t) - 4)[0] if t is not None and len(t) >= 4 else 0
        if active > self._known_live(w):
            self.discovery.search_newest(w.template, lambda ks: self._adopt(w, ks) >= active)

    def _adopt(self, w: Watched, keys: list[Pubkey]) -> int:
        for key in keys:
            if str(key) in self.journal.data["runs"]:
                continue
            raw = self.cl.gc.account(key)
            if raw and raw[:4] == b"D21R" and raw[CL.R_TEMPLATE:CL.R_TEMPLATE + 32] == bytes(w.template):
                self.journal.data["runs"][str(key)] = {"template": str(w.template), "state": "seen"}
                log(event="run_seen", run=str(key), template=str(w.template))
        return self._known_live(w)

    def _known_live(self, w: Watched) -> int:
        n = 0
        for run_s, entry in self.journal.data["runs"].items():
            if entry["template"] == str(w.template) and entry["state"] != "closed":
                raw = self.cl.gc.account(Pubkey.from_string(run_s))
                n += raw is not None and raw[:4] == b"D21R"
        return n

    def _run_accounts(self, run: Pubkey, dispute: Pubkey) -> list[Pubkey]:
        """The run's known accounts for settlement (review M-b): its
        disputes and caches from bounded discovery, not a full rescan."""
        self.discovery.new_keys(run)
        known = self.discovery.known(run)
        return known + ([dispute] if dispute not in known else [])

    def _inputs(self, w: Watched, run: Pubkey, state: RunState) -> dict[int, bytes] | None:
        values = {}
        for eid, ref in sorted(state.refs.items()):
            value = w.inputs(run, eid, ref)
            if value is None or R.external_ref(eid, w.spec.in_specs[eid][8:31],
                                               R.input_digest(w.spec.in_specs[eid], value)) != ref:
                log(event="inputs_unavailable", run=str(run), external_id=eid)
                return None
            values[eid] = value
        return values

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
        values = self._inputs(w, run, state)
        if values is None:
            return []  # retried next tick, until the window closes
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
        # Write ahead, with the checked inputs: a crash after the open lands
        # must neither open a second dispute nor depend on the input source.
        entry["state"] = "disputed"
        self.journal.data["disputes"][str(dispute)] = {
            "run": str(run), "kind": kind, "nonce": nonce.hex(), "done": False, "opened": False,
            "inputs": {str(k): v.hex() for k, v in values.items()}}
        self.journal.save()
        self._open(run, state.template, dispute, nonce, kind)
        self.journal.data["disputes"][str(dispute)]["opened"] = True
        self.journal.save()
        self._live[str(dispute)] = Challenger(record, honest, kind, w.depth)
        log(event="open", run=str(run), dispute=str(dispute), kind=kind)
        return [f"open {dispute}"]

    def _open(self, run: Pubkey, template: Pubkey, dispute: Pubkey, nonce: bytes, kind: str) -> None:
        self.cl._send("open", nonce + bytes([CL.KIND[kind]]),
                      [AccountMeta(self.key.pubkey(), True, True), AccountMeta(run, False, True),
                       AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                       AccountMeta(CL.SYSTEM, False, False)], [self.key])

    # --- playing a dispute ------------------------------------------------------------------
    def _replica(self, d_s: str, entry: dict) -> Challenger:
        """The in-memory challenger, rebuilt from the dispute's own moves on
        chain (not from the journal) whenever it is missing."""
        if d_s not in self._live:
            run = Pubkey.from_string(entry["run"])
            state = RunState.parse(run, self.cl.gc.account(run))
            w = self.watched[self.journal.data["runs"][entry["run"]]["template"]]
            values = {int(k): bytes.fromhex(v) for k, v in entry["inputs"].items()}
            honest = R.execute(w.spec, w.plan_id, state.run_id, values)
            record = G.RunRecord(w.plan_id, state.run_id, w.spec, state.root, state.refs)
            c, pending = Challenger(record, honest, entry["kind"], w.depth), None
            for sub, body in dispute_moves(self.cl, Pubkey.from_string(d_s)):
                if sub == CL.SUB["reveal_nodes"]:
                    r = c.replica
                    d = min(r.depth, r.level)
                    base, first = r.level - d, r.position << d
                    slots = [i for i in range(1 << d) if r._pickable(base, first + i)]
                    if body.startswith(b"SLOTS"):  # a cache answer: slot-indexed nodes
                        raw = body[5:]
                        pending = {i: raw[32 * i:32 * (i + 1)] for i in slots}
                    else:
                        pending = {i: body[32 * n:32 * (n + 1)] for n, i in enumerate(slots)}
                elif sub == CL.SUB["pick"] and pending is not None:
                    c.on_nodes(pending)
                    c.pick(body[0])
                    pending = None
            log(event="replica_rebuilt", dispute=d_s, level=c.replica.level, position=c.replica.position)
            self._live[d_s] = c
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
                log(event="open_retried", dispute=str(dispute))
                return f"open {dispute}"
            entry["done"] = True
            return None
        if raw is not None:
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
            out = self.cl.settle_and_reclaim(run, wait=0.0, candidates=self._run_accounts(run, dispute))
            log(event="settle", dispute=str(dispute), ruling=CL.RULINGS[d.ruling], **out)
            if out["state"] == "closed" or self.cl.gc.account(dispute) is None:
                entry["done"] = True
                self.journal.data["runs"][entry["run"]]["state"] = "closed"
            return f"settle {run}" if out["steps"] else None
        if self.cl.gc.slot() > d.deadline and d.phase not in (PH_PICK, PH_CLAIM):
            # The executor missed its deadline: the timeout rules for us.
            out = self.cl.settle_and_reclaim(run, wait=0.0, candidates=self._run_accounts(run, dispute))
            log(event="executor_timeout", dispute=str(dispute), **out)
            return f"timeout {dispute}" if out["steps"] else None
        if d.phase not in (PH_PICK, PH_CLAIM):
            return None  # the executor's move
        d_s = str(dispute)
        c = self._replica(d_s, entry)
        template = Pubkey.from_bytes(self.cl.gc.account(run)[CL.R_TEMPLATE:CL.R_TEMPLATE + 32])
        party = [AccountMeta(self.key.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, True)]
        # A pick sent last time whose landing was not confirmed (review N2):
        # apply it if the chain moved on, resend it if the chain did not.
        if d_s in self._sent_pick:
            lvl, pos, pk = self._sent_pick[d_s]
            step = min(c.replica.depth, lvl)
            if (d.level, d.position) == (lvl - step, (pos << step) + pk):
                c.pick(pk)
                del self._sent_pick[d_s]
            elif (d.level, d.position) == (lvl, pos) and d.phase == PH_PICK:
                self.cl._send("pick", bytes([pk]), party, [self.key])
                c.pick(pk)
                del self._sent_pick[d_s]
                log(event="pick_resent", dispute=d_s, level=lvl, pick=pk)
                return f"pick {dispute}"
            else:
                del self._sent_pick[d_s]
                self._live.pop(d_s, None)
                c = self._replica(d_s, entry)
        # Otherwise the replica must stand where the chain stands; rebuild
        # from the dispute's moves only when it does not.
        if (c.replica.level, c.replica.position) != (d.level, d.position) and d_s not in self._claims:
            self._live.pop(d_s, None)
            c = self._replica(d_s, entry)
            if (c.replica.level, c.replica.position) != (d.level, d.position):
                raise RuntimeError("the rebuilt replica does not match the dispute on chain")
        if d.phase == PH_PICK:
            nodes = d.revealed(c.replica._pickable)
            pick = c.on_nodes(nodes)
            self._sent_pick[d_s] = (d.level, d.position, pick)
            self.cl._send("pick", bytes([pick]), party, [self.key])
            c.pick(pick)
            del self._sent_pick[d_s]
            log(event="pick", dispute=d_s, level=d.level, pick=pick)
            return f"pick {dispute}"
        # CLAIM.
        if entry.get("done_claim"):
            return None  # withheld: the program would rule against it
        if d_s not in self._claims:
            leaf = d.leaf()
            lists = None
            parsed = R.parse_leaf(leaf) if (leaf is not None and c.kind == "STEP_DESCEND") else None
            has_lists = parsed is not None and any(struct.unpack_from("<I", ref, 7)[0] == S.LAYOUT_LIST
                                                   for ref in parsed.inputs)
            buffer_e = self.cl.pda(b"dcg21stg", bytes(dispute), bytes([CL.ROLE_EXECUTOR]))
            if has_lists:
                # Only a list leaf's element refs are read from the executor's
                # buffer, and only if the buffer's leaf is the revealed one.
                lists = staged_lists(self.cl.gc.account(buffer_e), expected_leaf=leaf)
            name, _kw, body, ruling = c.on_leaf(leaf, lists)
            # Send a claim the program upholds, or one it rules moot (the
            # bond returns, review M-a); withhold one it would rule for E.
            if ruling not in ("C", "moot"):
                log(event="claim_withheld", dispute=d_s, claim=name, local_ruling=ruling)
                entry["done_claim"] = True
                return None
            self._claims[d_s] = (name, body, buffer_e if has_lists else None)
        name, body, list_buffer = self._claims[d_s]
        executor = Pubkey.from_bytes(self.cl.gc.account(run)[CL.R_EXECUTOR:CL.R_EXECUTOR + 32])
        metas = [AccountMeta(self.key.pubkey(), True, False), AccountMeta(run, False, True),
                 AccountMeta(template, False, False), AccountMeta(dispute, False, True),
                 AccountMeta(executor, False, True), AccountMeta(self.key.pubkey(), False, True)]
        if len(body) > CL.DIRECT_LIMIT:
            buffer_c = self.cl.stage_body(run, template, dispute, CL.ROLE_CHALLENGER, body, self.key, self.key)
            body, metas = bytes([CL.FROM_STAGING]), metas + [AccountMeta(buffer_c, False, False)]
        heap = None
        if list_buffer is not None:
            metas.append(AccountMeta(list_buffer, False, False))
            heap = CL.LIST_HEAP_FRAME
        self.cl._send("claim", body, metas, [self.key], heap_frame=heap)
        log(event="claim", dispute=d_s, claim=name)
        return f"claim {dispute}"
