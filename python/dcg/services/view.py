"""The watchtower's committed view of a step tree (design
executor-watchtower-v1 §5).

The executor never publishes its tree. Under first divergence the challenger
can still open any step leaf left of the disputed one: that leaf equals H's,
and each sibling on its path is either revealed on chain during the descent,
folded from revealed descendants of one round, or a subtree wholly left of
the divergence, which equals H's. `CommittedView` supplies `leaf_opening`
in place of `game.Executor`, and checks every opening against the committed
step root before it is used.
"""

from __future__ import annotations

from ..disputes_v21 import run as R
from ..disputes_v21 import trees


class OpeningUnavailable(RuntimeError):
    """An opening the view cannot build from H and the descent's reveals."""


class CommittedView:
    def __init__(self, honest: R.Commitment, step_root: bytes, kind: str = "step"):
        self.honest = honest
        self.step_root = step_root
        self.kind = kind
        self.known: dict[tuple[int, int], bytes] = {}

    def record_round(self, level: int, position: int, depth: int, revealed: dict[int, bytes]) -> None:
        """One round of a STEP descent: the node (level, position) and its
        revealed descendants `depth` levels below (pickable ones only; the
        rest are the empty subtree). Intermediate nodes are folded."""
        base, first = level - depth, position << depth
        row = [revealed.get(i, trees.empty(self.kind, base)) for i in range(1 << depth)]
        for i, h in enumerate(row):
            self.known[(base, first + i)] = h
        for lvl in range(base, level):
            row = [trees.node(self.kind, lvl, row[i], row[i + 1]) for i in range(0, len(row), 2)]
            for i, h in enumerate(row):
                self.known[(lvl + 1, (first >> (lvl + 1 - base)) + i)] = h

    def _node(self, level: int, index: int) -> bytes:
        return self.known.get((level, index)) or self.honest.step_tree.at(level, index)

    def leaf_opening(self, ordinal: int):
        sp = self.honest.spec
        position = sp.position_of(ordinal)
        leaf = self.honest.leaves[ordinal]
        path, at = [], position
        for level in range(self.honest.step_tree.height):
            path.append(self._node(level, at ^ 1))
            at >>= 1
        if trees.root_from_path(self.kind, R.leaf_hash(leaf), position, path) != self.step_root:
            raise OpeningUnavailable(f"step {ordinal} does not open under the committed root from H and the reveals")
        return leaf, path
