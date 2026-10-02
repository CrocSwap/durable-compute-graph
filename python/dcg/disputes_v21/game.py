"""Referee, executor answers and the honest challenger (design §7, §8), step-1 scope.

The referee mirrors what the program will check, from public data (the spec,
the run record) and the committed run root only. A ruling is "C" or "E". A
party's own malformed submission raises `Refused` and changes nothing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import run as R
from . import spec as S
from . import trees


class Refused(ValueError):
    """A party's own fresh submission failed verification; it may retry."""


@dataclass
class RunRecord:
    """The on-chain facts a referee reads: ids, the committed root, external refs."""

    plan_id: bytes
    run_id: bytes
    spec: S.Spec
    root_bytes: bytes
    external_refs: dict[int, bytes]  # external id -> 52-byte ref

    @property
    def step_root(self) -> bytes:
        return self.root_bytes[104:136]

    @property
    def out_root(self) -> bytes:
        return self.root_bytes[144:176]


@dataclass
class Dispute:
    record: RunRecord
    kind: str  # "STEP_DESCEND" | "OUT_DESCEND"
    depth: int = 4
    level: int = 0
    position: int = 0
    current: bytes = b""
    revealed: dict[int, bytes] = field(default_factory=dict)
    leaf: bytes | None = None
    leaf_revealed: bool = False
    ruling: str | None = None
    rounds: int = 0

    def __post_init__(self):
        sp = self.record.spec
        if self.kind == "STEP_DESCEND":
            self.level, self.current = sp.address_height, self.record.step_root
        else:
            self.level, self.current = trees.height_for(sp.total_outputs), self.record.out_root

    # --- structure ---------------------------------------------------------------------
    def _tree_kind(self) -> str:
        return "step" if self.kind == "STEP_DESCEND" else "out"

    def _pickable(self, level: int, position: int) -> bool:
        sp = self.record.spec
        limit = sp.total_steps if self.kind == "STEP_DESCEND" else sp.total_outputs
        return (position << level) < limit

    # --- descent -----------------------------------------------------------------------
    def reveal_nodes(self, hashes: dict[int, bytes]) -> None:
        if self.ruling or self.level == 0:
            raise Refused("not awaiting nodes")
        d = min(self.depth, self.level)
        folded = trees.fold_reveal(self._tree_kind(), self.level, self.position, d, hashes, self._pickable)
        if folded != self.current:
            raise Refused("reveal does not fold to the current node")
        self.revealed = dict(hashes)
        self.rounds += 1

    def pick(self, index: int) -> None:
        if index not in self.revealed:
            raise Refused("not a revealed pickable position")
        d = min(self.depth, self.level)
        self.level -= d
        self.position = (self.position << d) + index
        self.current = self.revealed[index]
        self.revealed = {}

    def reveal_leaf(self, preimage: bytes | None) -> None:
        if self.level != 0 or self.leaf_revealed:
            raise Refused("not awaiting a leaf")
        if self.kind == "STEP_DESCEND":
            h = R.leaf_hash(preimage)
        else:
            h = R.out_leaf(self.position, preimage)
        if h != self.current:
            raise Refused("leaf does not match the committed hash")
        self.leaf, self.leaf_revealed = preimage, True

    def timeout(self, silent: str) -> str:
        self.ruling = "C" if silent == "E" else "E"
        return self.ruling

    # --- openings ------------------------------------------------------------------------
    def _spec_record(self, leaf_index: int, opening) -> bytes:
        type_code, record, path = opening
        if trees.root_from_path("spec", S.spec_leaf(type_code, record), leaf_index, path) != self.record.spec.root:
            raise Refused("spec opening does not verify")
        return record

    def _step_opening(self, ordinal: int, opening) -> bytes | None:
        """A leaf of E's committed step tree at `ordinal` (present flag, preimage, path)."""
        preimage, path = opening
        if trees.root_from_path("step", R.leaf_hash(preimage), ordinal, path) != self.record.step_root:
            raise Refused("leaf opening does not verify")
        return preimage

    # --- claims ----------------------------------------------------------------------------
    def _rule(self, who: str) -> str:
        self.ruling = who
        return who

    def claim(self, name: str, *, spec_opening=None, index: int = 0, producer_opening=None,
              witness: list[bytes] | None = None) -> str:
        if not self.leaf_revealed or self.ruling:
            raise Refused("no leaf to claim against")
        if self.kind == "OUT_DESCEND":
            return self._claim_out(spec_opening, producer_opening)
        k = self.position
        sp = self.record.spec
        record = self._spec_record(sp.step_leaf_index(k), spec_opening)
        d = S.decode_step_spec(record)
        leaf = R.parse_leaf(self.leaf) if self.leaf is not None else None
        # Malformed or empty bytes under E's own commitment rule for C (an
        # enumerated block has no gated steps, so empty is a violation too).
        if leaf is None:
            return self._rule("C")
        if name == "SHAPE":
            return self._rule("C" if self._shape_wrong(leaf, d, k) else "E")
        if name == "EDGE":
            if index >= len(d["inputs"]) or index >= len(leaf.inputs):
                raise Refused("no such input")
            got = leaf.inputs[index]
            kind, a, b, _c, _d = S.decode_producer(d["inputs"][index][1])
            if kind == 2:
                ref = self.record.external_refs[a]
                return self._rule("C" if got[7:55] != ref[4:52] else "E")
            if kind == 1:
                if producer_opening is None:
                    raise Refused("EDGE needs the producer leaf")
                p = R.parse_leaf(self._step_opening(a, producer_opening) or b"")
                if p is None:
                    return self._rule("C")
                port = next((o for o in p.outputs if struct.unpack_from("<H", o, 5)[0] == b), None)
                if port is None:
                    return self._rule("C")
                return self._rule("C" if got[7:55] != port[7:55] else "E")
            raise Refused("producer kind not in step-1 scope")
        if name == "STEP":
            if witness is None or len(witness) != len(leaf.inputs):
                raise Refused("witness has the wrong input count")
            for value, ref in zip(witness, leaf.inputs):
                if R.value_digest(value) != ref[23:55]:
                    raise Refused("witness value does not match its committed digest")
            outs = R.replay(d["kernel_id"], witness)
            if outs is None:
                return self._rule("C")  # a refused step cannot carry committed outputs
            if len(outs) != len(leaf.outputs):
                return self._rule("C")
            wrong = any(R.value_digest(v) != ref[23:55] for v, ref in zip(outs, leaf.outputs))
            return self._rule("C" if wrong else "E")
        raise Refused(f"unknown claim {name}")

    def _shape_wrong(self, leaf: R.Leaf, d: dict, k: int) -> bool:
        expected_in = [h for h, _p, _i in d["inputs"]]
        return (leaf.plan_id != self.record.plan_id or leaf.run_id != self.record.run_id
                or leaf.region != d["region"] or leaf.coord_region != d["region"]
                or leaf.segment != d["segment"] or leaf.ordinal != k or leaf.node != d["node"]
                or leaf.kernel_step != d["kernel_step"]
                or len(leaf.inputs) != len(expected_in) or len(leaf.outputs) != len(d["outputs"])
                or any(r[:23] != h for r, h in zip(leaf.inputs, expected_in))
                or any(r[:23] != h for r, h in zip(leaf.outputs, d["outputs"]))
                or leaf.prior != bytes(32) or leaf.next != bytes(32))

    def _claim_out(self, spec_opening, producer_opening) -> str:
        j = self.position
        record = self._spec_record(self.record.spec.out_leaf_index(j), spec_opening)
        header, prod = record[8:31], record[32:56]
        entry = self.leaf
        if entry is None or len(entry) != 55 or entry[:23] != header:
            return self._rule("C")
        _kind, a, b, _c, _d = S.decode_producer(prod)
        if producer_opening is None:
            raise Refused("OUT needs the producer leaf")
        p = R.parse_leaf(self._step_opening(a, producer_opening) or b"")
        if p is None:
            return self._rule("C")
        port = next((o for o in p.outputs if struct.unpack_from("<H", o, 5)[0] == b), None)
        if port is None:
            return self._rule("C")
        return self._rule("C" if entry[23:55] != port[23:55] else "E")


# --- the parties ------------------------------------------------------------------------------

class Executor:
    """Answers from its own commitment, honest or not."""

    def __init__(self, commitment: R.Commitment):
        self.c = commitment

    def nodes(self, dispute: Dispute) -> dict[int, bytes]:
        d = min(dispute.depth, dispute.level)
        tree = self.c.step_tree if dispute.kind == "STEP_DESCEND" else self.c.out_tree
        base, first = dispute.level - d, dispute.position << d
        return {i: tree.at(base, first + i) for i in range(1 << d) if dispute._pickable(base, first + i)}

    def leaf(self, dispute: Dispute) -> bytes | None:
        if dispute.kind == "STEP_DESCEND":
            return self.c.leaves[dispute.position]
        return self.c.out_entries[dispute.position]

    def leaf_opening(self, ordinal: int):
        return self.c.leaves[ordinal], self.c.step_tree.path(ordinal)


def spec_opening(spec: S.Spec, leaf_index: int):
    return spec.opening(leaf_index)


def honest_challenge(record: RunRecord, executor: Executor, honest: R.Commitment, depth: int = 4) -> Dispute | None:
    """Play the first-divergence strategy against `executor`. Returns the
    finished dispute, or None when the commitment equals H's."""
    if record.step_root != honest.step_tree.root:
        kind, htree = "STEP_DESCEND", honest.step_tree
    elif record.out_root != honest.out_tree.root:
        kind, htree = "OUT_DESCEND", honest.out_tree
    else:
        return None
    dispute = Dispute(record, kind, depth)
    while dispute.level > 0:
        dispute.reveal_nodes(executor.nodes(dispute))
        d = min(dispute.depth, dispute.level)
        base, first = dispute.level - d, dispute.position << d
        diff = [i for i in sorted(dispute.revealed) if dispute.revealed[i] != htree.at(base, first + i)]
        if not diff:
            raise AssertionError("no differing child under a differing node")
        dispute.pick(diff[0])
    dispute.reveal_leaf(executor.leaf(dispute))
    sp = record.spec
    j = dispute.position
    if kind == "OUT_DESCEND":
        _k, a, _b, _c, _d = S.decode_producer(sp.out_specs[j][32:56])
        dispute.claim("OUT", spec_opening=spec_opening(sp, sp.out_leaf_index(j)),
                      producer_opening=executor.leaf_opening(a))
        return dispute
    k = j
    opening = spec_opening(sp, sp.step_leaf_index(k))
    leaf = R.parse_leaf(dispute.leaf) if dispute.leaf is not None else None
    if leaf is None or dispute._shape_wrong(leaf, S.decode_step_spec(sp.step_specs[k]), k):
        dispute.claim("SHAPE", spec_opening=opening)
        return dispute
    mine = R.parse_leaf(honest.leaves[k])
    for i, (got, want) in enumerate(zip(leaf.inputs, mine.inputs)):
        if got != want:
            kind_p, a, _b, _c, _d = S.decode_producer(S.decode_step_spec(sp.step_specs[k])["inputs"][i][1])
            dispute.claim("EDGE", spec_opening=opening, index=i,
                          producer_opening=executor.leaf_opening(a) if kind_p == 1 else None)
            return dispute
    witness = [_value_for(honest, sp, k, i) for i in range(len(leaf.inputs))]
    dispute.claim("STEP", spec_opening=opening, witness=witness)
    return dispute


def _value_for(honest: R.Commitment, sp: S.Spec, k: int, i: int) -> bytes:
    kind, a, b, _c, _d = S.decode_producer(S.decode_step_spec(sp.step_specs[k])["inputs"][i][1])
    if kind == 2:
        return honest.values[("ext", a)]
    return honest.values[(a, b)]
