"""v2.1 trees (design `optimistic-descent-v2.1.md` §6.1).

Capacity is a power of two. Unused positions hold the tree type's empty leaf,
and an all-empty subtree at level l is the constant EMPTY_t[l]. A node at
level l is SHA256(domain || l:u16 || left || right); leaves are level 0. There
is no duplicate-last rule.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from functools import lru_cache


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


NODE_DOMAINS = {
    "step": b"dcg.trace.node.v2.1\x00",
    "out": b"dcg.out.node.v2.1\x00",
    "chunk": b"dcg.chunk.node.v2.1\x00",
    "log": b"dcg.log.node.v2.1\x00",
    "spec": b"dcg.spec.node.v2.1\x00",
    "lazy": b"dcg.lazy.node.v1\x00",
    "lxstate": b"dcg.lx.state.node.v1\x00",
    "lxcheckpoint": b"dcg.lx.checkpoint.node.v1\x00",
    "list": b"dcg.list.node.v2.1\x00",
}
EMPTY_LEAVES = {
    "step": _h(b"dcg.leaf.empty.v2.1\x00"),
    "out": _h(b"dcg.out.empty.v2.1\x00"),
    "chunk": _h(b"dcg.chunk.empty.v2.1\x00"),
    "log": _h(b"dcg.log.empty.v2.1\x00"),
    "spec": _h(b"dcg.spec.empty.v2.1\x00"),
    "lazy": _h(b"dcg.lazy.empty.v1\x00"),
    "lxstate": _h(b"dcg.lx.slot.empty.v1\x00"),
    "lxcheckpoint": _h(b"dcg.lx.checkpoint.empty.v1\x00"),
    "list": _h(b"dcg.list.empty.v2.1\x00"),
}
EMPTY_LEAF = EMPTY_LEAVES["step"]
EMPTY_OUT = EMPTY_LEAVES["out"]


def node(kind: str, level: int, left: bytes, right: bytes) -> bytes:
    return _h(NODE_DOMAINS[kind], struct.pack("<H", level), left, right)


@lru_cache(maxsize=None)
def empty(kind: str, level: int) -> bytes:
    if level == 0:
        return EMPTY_LEAVES[kind]
    below = empty(kind, level - 1)
    return node(kind, level - 1, below, below)


def height_for(n: int) -> int:
    """H = ceil(log2(max(n, 1)))."""
    return max(n - 1, 0).bit_length()


@dataclass
class Tree:
    """A full v2.1 tree: levels[0] are the 2^H leaves, levels[H] = [root]."""

    kind: str
    levels: list[list[bytes]]

    @property
    def height(self) -> int:
        return len(self.levels) - 1

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def at(self, level: int, position: int) -> bytes:
        return self.levels[level][position]

    def path(self, position: int) -> list[bytes]:
        """Sibling hashes from the leaf level upwards."""
        out = []
        for level in range(self.height):
            out.append(self.levels[level][position ^ 1])
            position >>= 1
        return out


def build(kind: str, leaves: list[bytes], height: int | None = None) -> Tree:
    h = height_for(len(leaves)) if height is None else height
    if len(leaves) > (1 << h):
        raise ValueError("more leaves than capacity")
    level = list(leaves) + [EMPTY_LEAVES[kind]] * ((1 << h) - len(leaves))
    levels = [level]
    for l in range(h):
        level = [node(kind, l, level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return Tree(kind, levels)


def root_from_path(kind: str, leaf: bytes, position: int, path: list[bytes]) -> bytes:
    acc = leaf
    for level, sibling in enumerate(path):
        acc = node(kind, level, sibling, acc) if position & 1 else node(kind, level, acc, sibling)
        position >>= 1
    return acc


def fold_reveal(kind: str, level: int, position: int, depth: int, revealed: dict[int, bytes],
                pickable) -> bytes | None:
    """Fold a reveal of the descendants `depth` levels below node (level,
    position). `revealed` maps descendant index (0..2^depth) to hash and must
    contain exactly the pickable descendants; the rest are filled with
    EMPTY[level - depth]. `pickable(level, position)` is structural (§7.1).
    Returns the folded hash, or None if the reveal lists a wrong set."""
    base_level = level - depth
    first = position << depth
    expected = {i for i in range(1 << depth) if pickable(base_level, first + i)}
    if set(revealed) != expected:
        return None
    row = [revealed.get(i, empty(kind, base_level)) for i in range(1 << depth)]
    for l in range(base_level, level):
        row = [node(kind, l, row[i], row[i + 1]) for i in range(0, len(row), 2)]
    return row[0]
