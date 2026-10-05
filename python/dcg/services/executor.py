"""The executor service (alpha E3, design executor-watchtower-v1 §3): answer
every dispute on the runs it committed before each phase deadline, then
settle and reclaim.

    service = ExecutorService(client, executor_key, "executor.json", plans)
    service.add_run(run, template, run_id, values)   # after committing it
    while True:
        service.tick()                                # at most every W/4

A plan is registered per template: its spec, plan id and descent depth, and
for LX1 templates an `LxAnswerer`. The service answers from the commitment
`execute` produces (the honest `run.execute` by default) and refuses a run
whose recomputed root is not the one on chain.
"""

from __future__ import annotations

import json
import struct
import sys
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from ..disputes_v21 import client as CL
from ..disputes_v21 import game as G
from ..disputes_v21 import lx_client as LX
from ..disputes_v21 import run as R
from ..disputes_v21 import spec as S
from ..disputes_v21 import wire as W
from .chain import PH_CLAIM, PH_LEAF, PH_NODES, PH_PICK, Discovery, DisputeState, RunState
from .journal import Journal


class LxAnswerer(Protocol):
    """The executor's LX1 machine for one run."""

    arity: int
    params: bytes

    def roots(self, coordinates: list[int]) -> list[bytes]: ...

    def opening(self, coordinate: int) -> bytes: ...


@dataclass
class Plan:
    spec: S.Spec | None
    plan_id: bytes
    depth: int = 4
    #: For LX1 templates: run -> the executor's machine for that run.
    lx: Callable[[Pubkey], LxAnswerer] | None = None


def log(**fields) -> None:
    print(json.dumps({"t": round(time.time(), 1), **fields}, default=str), flush=True)


class ExecutorService:
    def __init__(self, cl: CL.DisputeClient, executor: Keypair, journal: str, plans: dict[str, Plan], *,
                 execute: Callable[..., R.Commitment] = R.execute, tick_budget_s: float = 10.0):
        self.cl, self.executor, self.plans, self.execute = cl, executor, plans, execute
        self.tick_budget_s = tick_budget_s
        self.journal = Journal(journal)
        self.journal.data.setdefault("runs", {})
        self.journal.data.setdefault("discovery", {})
        self.discovery = Discovery(cl, self.journal.data["discovery"])
        self._commitments: dict[str, R.Commitment] = {}

    # --- runs ----------------------------------------------------------------------------
    def add_run(self, run: Pubkey, template: Pubkey, run_id: bytes, values: dict[int, bytes]) -> None:
        """Journal a run. Call it before committing (write ahead): the
        service ignores a run until its commit lands, and a run whose commit
        never lands is cancelled after its deadline."""
        self.journal.data["runs"][str(run)] = {"template": str(template), "run_id": run_id.hex(),
                                               "values": {str(k): v.hex() for k, v in values.items()},
                                               "disputes": [], "done": False}
        self.journal.save()

    def _commitment(self, run: str, entry: dict, chain_root: bytes) -> R.Commitment:
        if run not in self._commitments:
            plan = self.plans[entry["template"]]
            values = {int(k): bytes.fromhex(v) for k, v in entry["values"].items()}
            c = self.execute(plan.spec, plan.plan_id, bytes.fromhex(entry["run_id"]), values)
            if c.root_bytes != chain_root:
                raise RuntimeError(f"run {run}: the recomputed commitment is not the committed root")
            self._commitments[run] = c
        return self._commitments[run]

    # --- the loop -------------------------------------------------------------------------
    def tick(self) -> list[str]:
        """One pass. Deadline-bound answers come first, soonest deadline
        first across all runs; then bounded discovery of new disputes; then
        settlement where a step is possible. Returns the actions taken."""
        t0 = time.monotonic()
        actions: list[str] = []
        live: list[tuple[Pubkey, dict, RunState]] = []
        for run_s, entry in self.journal.data["runs"].items():
            if entry["done"]:
                continue
            run = Pubkey.from_string(run_s)
            try:
                data = self.cl.gc.account(run)
                if data is None or data[:4] == b"D21P":
                    entry["done"] = True
                    log(event="run_closed", run=run_s)
                    continue
                live.append((run, entry, RunState.parse(run, data)))
            except Exception as exc:
                log(event="error", run=run_s, error=f"{type(exc).__name__}: {exc}")
        # 1. Answers, soonest deadline first.
        due = []
        for run, entry, state in live:
            if state.status == CL.RUN_OPEN:
                continue
            for d_s in entry["disputes"]:
                try:
                    raw = self.cl.gc.account(Pubkey.from_string(d_s))
                    if raw is not None:
                        d = DisputeState.parse(Pubkey.from_string(d_s), raw)
                        if d.ruling == CL.RULING_OPEN:
                            due.append((d.deadline, d_s, run, entry, state, d))
                except Exception as exc:
                    log(event="error", dispute=d_s, error=f"{type(exc).__name__}: {exc}")
        now = self.cl.gc.slot()
        challenger_late: set[str] = set()
        for _deadline, d_s, run, entry, state, d in sorted(due, key=lambda x: x[0]):
            try:
                act = self._answer(state, entry, d)
                if act:
                    actions.append(act)
                elif d.phase in (PH_PICK, PH_CLAIM) and now > d.deadline:
                    challenger_late.add(str(run))
            except Exception as exc:  # one dispute's trouble must not stop the others
                log(event="error", dispute=d_s, error=f"{type(exc).__name__}: {exc}")
        self.journal.save()
        # 2. Bounded discovery of new disputes; if the run counts more open
        # disputes than we know, search its history newest first until they
        # are found (review R1).
        for run, entry, state in live:
            if state.status == CL.RUN_OPEN:
                continue
            try:
                self._adopt(run, entry, self.discovery.new_keys(run))
                if state.open > self._known_open(entry):
                    keys = self.discovery.search_newest(
                        run, lambda ks: self._adopt(run, entry, ks) >= state.open)
                    self._adopt(run, entry, keys)
            except Exception as exc:
                log(event="error", run=str(run), error=f"discovery: {type(exc).__name__}: {exc}")
        self.journal.save()
        # 3. Settlement, only where a step is possible.
        for run, entry, state in live:
            settleable = (
                str(run) in challenger_late
                or state.status in (CL.RUN_FINAL, CL.RUN_REFUTED)
                or (state.status == CL.RUN_COMMITTED and state.open == 0 and now > state.deadline)
                or (state.status == CL.RUN_OPEN and now > state.deadline)
                or any(self._ruled(d_s) for d_s in entry["disputes"])
            )
            if not settleable:
                continue
            try:
                out = self.cl.settle_and_reclaim(run, wait=0.0, candidates=self.discovery.known(run))
                if out["steps"]:
                    log(event="settle", run=str(run), **out)
                    actions += out["steps"]
                if out["state"] == "closed":
                    entry["done"] = True
            except Exception as exc:
                log(event="error", run=str(run), error=f"settle: {type(exc).__name__}: {exc}")
        self.journal.save()
        elapsed = time.monotonic() - t0
        if elapsed > self.tick_budget_s:
            log(event="slow_tick", seconds=round(elapsed, 1), budget=self.tick_budget_s)
        return actions

    def _adopt(self, run: Pubkey, entry: dict, keys: list[Pubkey]) -> int:
        """Add the run's disputes among `keys`; returns how many open
        disputes of the run are now known."""
        for key in keys:
            if str(key) in entry["disputes"]:
                continue
            raw = self.cl.gc.account(key)
            if raw and raw[:4] == b"D21D" and raw[CL.D_RUN:CL.D_RUN + 32] == bytes(run):
                entry["disputes"].append(str(key))
                log(event="dispute_seen", run=str(run), dispute=str(key))
        return self._known_open(entry)

    def _known_open(self, entry: dict) -> int:
        n = 0
        for d_s in entry["disputes"]:
            raw = self.cl.gc.account(Pubkey.from_string(d_s))
            n += raw is not None and raw[CL.D_RULING] == CL.RULING_OPEN
        return n

    def _ruled(self, d_s: str) -> bool:
        raw = self.cl.gc.account(Pubkey.from_string(d_s))
        return raw is not None and raw[CL.D_RULING] != CL.RULING_OPEN

    def _party(self, state: RunState, d: DisputeState) -> list[AccountMeta]:
        return [AccountMeta(self.executor.pubkey(), True, False), AccountMeta(state.address, False, True),
                AccountMeta(state.template, False, False), AccountMeta(d.address, False, True)]

    def _answer(self, state: RunState, entry: dict, d: DisputeState) -> str | None:
        plan = self.plans[entry["template"]]
        late = self.cl.gc.slot() > d.deadline
        if d.kind in (1, 2):
            if d.phase not in (PH_NODES, PH_LEAF):
                return None
            c = self._commitment(str(state.address), entry, state.root)
            record = G.RunRecord(plan.plan_id, state.run_id, plan.spec, state.root, state.refs)
            replica = G.Dispute(record, d.kind_name, d.depth)
            replica.level, replica.position = d.level, d.position
            ex = G.Executor(c)
            if d.phase == PH_NODES:
                nodes = ex.nodes(replica)
                self.cl._send("reveal_nodes", b"".join(nodes[i] for i in sorted(nodes)), self._party(state, d),
                              [self.executor])
                log(event="reveal_nodes", dispute=str(d.address), level=d.level, late=late)
                return f"reveal_nodes {d.address}"
            lists = ex.lists(replica)
            body = W.leaf_body(ex.leaf(replica), lists if lists else None)
            metas = self._party(state, d)
            if body.startswith(b"LVR1") or len(body) > CL.DIRECT_LIMIT:
                buffer = self.cl.stage_body(state.address, state.template, d.address, CL.ROLE_EXECUTOR, body,
                                            self.executor, self.executor)
                body, metas = bytes([CL.FROM_STAGING]), metas + [AccountMeta(buffer, False, False)]
            self.cl._send("reveal_leaf", body, metas, [self.executor], heap_frame=CL._list_step_heap_frame(
                W.leaf_body(ex.leaf(replica), lists if lists else None)))
            log(event="reveal_leaf", dispute=str(d.address), late=late)
            return f"reveal_leaf {d.address}"
        if d.kind == LX.KIND_LX_STATE and plan.lx is not None:
            machine = plan.lx(state.address)
            verify = getattr(machine, "verify", None)
            if verify is not None and not verify(state.root):
                raise RuntimeError(f"run {state.address}: the LX answerer does not reproduce the committed checkpoints")
            lo, hi = d.position, d.lx_hi
            if d.phase == PH_NODES:
                roots = machine.roots(LX.midpoint_coordinates(lo, hi, machine.arity))
                self.cl._send("lx_midpoints", b"".join(roots), self._party(state, d), [self.executor])
                log(event="lx_midpoints", dispute=str(d.address), interval=[lo, hi], late=late)
                return f"lx_midpoints {d.address}"
            if d.phase == PH_LEAF:
                buffer = self.cl.stage_body(state.address, state.template, d.address, CL.ROLE_EXECUTOR,
                                            machine.opening(lo), self.executor, self.executor)
                self.cl._send("lx_opening", machine.params,
                              [AccountMeta(self.executor.pubkey(), True, True), AccountMeta(state.address, False, True),
                               AccountMeta(state.template, False, False), AccountMeta(d.address, False, True),
                               AccountMeta(d.challenger, False, True), AccountMeta(buffer, False, False)],
                              [self.executor], heap_frame=LX.LX_HEAP_FRAME)
                log(event="lx_opening", dispute=str(d.address), terminal=lo, late=late)
                return f"lx_opening {d.address}"
        return None


def run_forever(service: ExecutorService, period: float) -> None:
    while True:
        service.tick()
        time.sleep(period)


if __name__ == "__main__":
    print("The executor service is configured in Python (plans and keys); see "
          "examples/services/ and docs/design/executor-watchtower-v1.md.", file=sys.stderr)
    raise SystemExit(2)


class ExecutionAnswerer:
    """An `LxAnswerer` over an `lx.Execution` (the executor's own run)."""

    def __init__(self, execution, params: bytes, arity: int):
        self.execution, self.params, self.arity = execution, params, arity

    def roots(self, coordinates: list[int]) -> list[bytes]:
        return [self.execution.root_at(c) for c in coordinates]

    def opening(self, coordinate: int) -> bytes:
        return LX.executor_opening_bytes(self.execution, coordinate)

    def verify(self, run_root: bytes) -> bool:
        """Whether this execution's checkpoints are the committed ones (the
        run root's checkpoint root at bytes 32..64, k at 136..140)."""
        from ..disputes_v21 import lx as L

        if getattr(self, "_verified", None) != run_root:
            k = struct.unpack_from("<I", run_root, 136)[0]
            if L.checkpoint_tree(L.commit(self.execution, k).roots).root != run_root[32:64]:
                return False
            self._verified = run_root  # checked once per run root
        return True
