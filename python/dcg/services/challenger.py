"""The watchtower's challenger logic, independent of the chain: a replica of
one dispute fed with the executor's moves as observed, the first-divergence
pick, and the claim built over the committed view (design §4, §5)."""

from __future__ import annotations

from ..disputes_v21 import game as G
from ..disputes_v21 import run as R
from ..disputes_v21 import wire as W
from .view import CommittedView


def dispute_kind(record: G.RunRecord, honest: R.Commitment) -> str | None:
    """Which descent the first-divergence challenger opens, or None when the
    committed root equals H's."""
    if record.step_root != honest.step_tree.root:
        return "STEP_DESCEND"
    if record.out_root != honest.out_tree.root:
        return "OUT_DESCEND"
    return None


class Challenger:
    """One dispute as the watchtower plays it. Feed it the executor's reveals
    (`on_nodes`, `on_leaf`) as read from chain; ask it for the pick and the
    claim. It never sees the executor's commitment."""

    def __init__(self, record: G.RunRecord, honest: R.Commitment, kind: str, depth: int):
        self.record, self.honest, self.kind = record, honest, kind
        self.replica = G.Dispute(record, kind, depth)
        self.view = CommittedView(honest, record.step_root)

    def on_nodes(self, nodes: dict[int, bytes]) -> int:
        """Record a reveal (it must fold to the current node) and return the
        first child that differs from H."""
        r = self.replica
        d = min(r.depth, r.level)
        if self.kind == "STEP_DESCEND":
            self.view.record_round(r.level, r.position, d, nodes)
        r.reveal_nodes(nodes)
        tree = self.honest.step_tree if self.kind == "STEP_DESCEND" else self.honest.out_tree
        base, first = r.level - d, r.position << d
        diff = [i for i in sorted(r.revealed) if r.revealed[i] != tree.at(base, first + i)]
        if not diff:
            raise AssertionError("no differing child under a differing node")
        return diff[0]

    def pick(self, index: int) -> None:
        self.replica.pick(index)

    def on_leaf(self, leaf: bytes | None, lists: dict[int, list[bytes]] | None) -> tuple[str, dict, bytes, str]:
        """Record the leaf reveal; return the claim's name, arguments, wire
        body, and the local referee's ruling (which must be "C")."""
        r = self.replica
        r.reveal_leaf(leaf, lists)
        name, kw = G.honest_claim(self.record, self.view, self.honest, r)
        body = W.claim_body(self.record.spec, self.kind, r.position, name, kw)
        # As the program rules it (onchain: LOG-state STEP/STATE claims are
        # moot there), so a claim the program would not uphold is withheld.
        ruling = G.Dispute.claim(_copy(r), name, **kw, onchain=True)
        return name, kw, body, ruling


def _copy(d: G.Dispute) -> G.Dispute:
    import copy

    return copy.copy(d)


def play_offline(record: G.RunRecord, committed: R.Commitment, honest: R.Commitment, depth: int) -> dict | None:
    """The watchtower against an executor answering from `committed`, in one
    process: the challenger sees only the executor's moves."""
    kind = dispute_kind(record, honest)
    if kind is None:
        return None
    executor = G.Executor(committed)
    c = Challenger(record, honest, kind, depth)
    while c.replica.level > 0:
        c.pick(c.on_nodes(executor.nodes(c.replica)))
    name, _kw, body, ruling = c.on_leaf(executor.leaf(c.replica), executor.lists(c.replica))
    return {"kind": kind, "claim_name": name, "claim": body.hex(), "ruling": ruling}
