"""A dispute played out offline and recorded as program instruction bodies.

The Python referee plays both parties (the executor answering from its
commitment, the challenger either honest or making a given claim), and each
move is recorded in the program's wire format (`wire.py`). The recording can
be replayed on a test validator or a live cluster; the referee's ruling is
the expected outcome.
"""

from __future__ import annotations

from . import game as G
from . import run as R
from . import wire as W


def _honest_claim(record: G.RunRecord, executor: G.Executor, honest: R.Commitment, depth: int):
    """The honest challenger's dispute kind and claim, captured as it is made."""
    captured = {}
    orig = G.Dispute.claim

    def spy(self, name, **kw):
        captured["v"] = (name, kw)
        return orig(self, name, **kw)

    G.Dispute.claim = spy
    try:
        d = G.honest_challenge(record, executor, honest, depth)
    finally:
        G.Dispute.claim = orig
    if d is None:
        raise ValueError("the commitment equals the honest one; there is nothing to dispute")
    return d.kind, captured["v"]


def record(record: G.RunRecord, committed: R.Commitment, honest: R.Commitment, depth: int, *,
           target: int | None = None, claim: tuple[str, dict] | None = None, kind: str = "STEP_DESCEND") -> dict:
    """Play one dispute. Without `target`, the honest challenger descends to
    the first divergence and makes its claim; with `target` (a step-tree
    position or out index), it descends there and makes `claim`."""
    executor = G.Executor(committed)
    if target is None:
        kind, (name, kw) = _honest_claim(record, executor, honest, depth)
    else:
        name, kw = claim
    sp = record.spec
    dispute = G.Dispute(record, kind, depth)
    htree = honest.step_tree if kind == "STEP_DESCEND" else honest.out_tree
    rounds = []
    while dispute.level > 0:
        nodes = executor.nodes(dispute)
        reveal = b"".join(nodes[i] for i in sorted(nodes))
        dispute.reveal_nodes(nodes)
        step = min(dispute.depth, dispute.level)
        base, first = dispute.level - step, dispute.position << step
        if target is None:
            pick = next(i for i in sorted(dispute.revealed) if dispute.revealed[i] != htree.at(base, first + i))
        else:
            pick = (target >> (dispute.level - step)) & ((1 << step) - 1)
        dispute.pick(pick)
        rounds.append({"reveal": reveal.hex(), "pick": pick})
    leaf = executor.leaf(dispute)
    dispute.reveal_leaf(leaf)
    body = W.claim_body(sp, kind, dispute.position, name, kw)
    ruling = dispute.claim(name, **kw)
    return {"kind": kind, "rounds": rounds, "leaf": W.leaf_body(leaf).hex(), "claim": body.hex(),
            "claim_name": name, "ruling": ruling}
