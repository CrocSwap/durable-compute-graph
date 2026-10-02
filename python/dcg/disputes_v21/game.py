"""Referee, executor answers and the honest challenger (design §7, §8).

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


class ExecutorRefused(Refused):
    """E's reveal or opening failed verification (E may retry; if it cannot,
    C wins at E's deadline)."""


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
    claimed: str | None = None  # the claim made (EDGE carries its producer kind)

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
        if self.kind == "STEP_DESCEND":
            return sp.pickable(level, position)
        return (position << level) < sp.total_outputs

    @property
    def ordinal(self) -> int:
        """The step ordinal at the current leaf position (STEP_DESCEND)."""
        k = self.record.spec.ordinal_at(self.position)
        if k is None:
            raise Refused("not a step position")
        return k

    # --- descent -----------------------------------------------------------------------
    def reveal_nodes(self, hashes: dict[int, bytes]) -> None:
        if self.ruling or self.level == 0:
            raise Refused("not awaiting nodes")
        d = min(self.depth, self.level)
        folded = trees.fold_reveal(self._tree_kind(), self.level, self.position, d, hashes, self._pickable)
        if folded != self.current:
            raise ExecutorRefused("reveal does not fold to the current node")
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
            raise ExecutorRefused("leaf does not match the committed hash")
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
        position = self.record.spec.position_of(ordinal)
        if trees.root_from_path("step", R.leaf_hash(preimage), position, path) != self.record.step_root:
            raise ExecutorRefused("leaf opening does not verify")
        return preimage

    # --- claims ----------------------------------------------------------------------------
    def _rule(self, who: str) -> str:
        self.ruling = who
        return who

    def claim(self, name: str, *, spec_opening=None, index: int = 0, producer_opening=None,
              witness: list[bytes] | None = None, state_witness: bytes | None = None, t: int | None = None,
              gate_opening=None, gate_value: bytes | None = None, chunk_opening=None, const_opening=None) -> str:
        if not self.leaf_revealed or self.ruling:
            raise Refused("no leaf to claim against")
        self.claimed = name if name != "EDGE" else f"EDGE{self._edge_kind(index)}"
        if self.kind == "OUT_DESCEND":
            return self._claim_out(spec_opening, producer_opening, t, gate_opening, gate_value)
        sp = self.record.spec
        k = self.ordinal
        bi, block, it, _e = sp.locate(k)
        stored = self._spec_record(sp.step_leaf_index(k), spec_opening)
        expected = stored if block.kind == 1 else S.generate(stored, block, it)
        d = S.decode_step_spec(expected)
        if self.leaf is None:
            # Empty is a violation unless the step is gated (iteration >= 1).
            if not sp.gated(k):
                return self._rule("C")
            if name != "GATE":
                raise Refused("an empty gated leaf is contested by GATE")
            return self._rule(self._gate_says(bi, block, it, present=False, opening=gate_opening, value=gate_value))
        leaf = R.parse_leaf(self.leaf)
        if leaf is None:  # malformed bytes under E's own commitment
            return self._rule("C")
        if name == "GATE":
            if not sp.gated(k):
                return self._rule("E")
            return self._rule(self._gate_says(bi, block, it, present=True, opening=gate_opening, value=gate_value))
        if name == "SHAPE":
            return self._rule("C" if self._shape_wrong(leaf, d, k) else "E")
        if name == "EDGE":
            return self._rule(self._edge(leaf, d, index, producer_opening, t, gate_opening, gate_value,
                                         chunk_opening, const_opening))
        if name == "STATE":
            return self._rule(self._state(leaf, d, producer_opening))
        if name == "STEP":
            return self._rule(self._step(leaf, d, witness, state_witness))
        raise Refused(f"unknown claim {name}")

    def _edge_kind(self, index: int) -> int:
        """The producer kind of input `index` at the current leaf (diagnostics only)."""
        try:
            d = S.decode_step_spec(self.record.spec.step_spec(self.ordinal))
            return S.decode_producer(d["inputs"][index][1])[0]
        except (Refused, IndexError, S.SpecError):
            return 0

    # --- claim rules (§7.3) --------------------------------------------------------------
    def _port(self, leaf: R.Leaf, port: int) -> bytes | None:
        return next((o for o in leaf.outputs if struct.unpack_from("<H", o, 5)[0] == port), None)

    def _gate_value(self, gate_leaf: R.Leaf, port: int, value: bytes | None) -> int | None:
        """The gate port's i32, checked against its digest; None if the port is missing."""
        ref = self._port(gate_leaf, port)
        if ref is None:
            return None
        if value is None or len(value) != 4 or R.value_digest(value) != ref[23:55]:
            raise Refused("gate value does not match its digest")
        return struct.unpack("<i", value)[0]

    def _gate_says(self, bi: int, block, it: int, *, present: bool, opening, value) -> str:
        sp = self.record.spec
        g = sp.ordinal_of(bi, it - 1, block.gate_entry)
        if opening is None:
            raise Refused("GATE needs the previous iteration's gate leaf")
        raw = self._step_opening(g, opening)
        if raw is None:
            expected = False
        else:
            gate_leaf = R.parse_leaf(raw)
            if gate_leaf is None:
                return "C"
            v = self._gate_value(gate_leaf, block.gate_port, value)
            if v is None:
                return "C"
            expected = v != 0
        return "C" if present != expected else "E"

    def _last_running_port(self, a: int, port: int, entry: int, t: int | None, opening, gate_opening,
                           gate_value) -> bytes | None:
        """Kind 6 (§3.4, R3-S1): the port ref at C's named iteration t, if t is
        the last running iteration by honest-earlier leaves; else None (E wins)."""
        sp = self.record.spec
        if t is None or a >= len(sp.blocks):
            raise Refused("kind 6 needs an iteration and a block")
        block = sp.blocks[a]
        if not 0 <= t < block.k:
            return None
        raw = self._step_opening(sp.ordinal_of(a, t, entry), opening)
        leaf = R.parse_leaf(raw) if raw is not None else None
        if leaf is None:
            return None
        if t != block.k - 1:
            if gate_opening is None:
                raise Refused("kind 6 needs the gate leaf at t")
            graw = self._step_opening(sp.ordinal_of(a, t, block.gate_entry), gate_opening)
            gate_leaf = R.parse_leaf(graw) if graw is not None else None
            if gate_leaf is None or self._gate_value(gate_leaf, block.gate_port, gate_value) != 0:
                return None
        return self._port(leaf, port)

    def _const(self, constant_id: int, opening) -> bytes:
        """The ConstSpec for `constant_id`, from a spec opening at its leaf."""
        if opening is None:
            raise Refused("a constant read needs its ConstSpec opening")
        record = self._spec_record(self.record.spec.const_leaf_index(constant_id), opening)
        if len(record) != 104 or record[:4] != b"DCN1" or struct.unpack_from("<I", record, 4)[0] != constant_id:
            raise Refused("not that constant's ConstSpec")
        return record

    def _edge(self, leaf: R.Leaf, d: dict, index: int, producer_opening, t, gate_opening, gate_value,
              chunk_opening, const_opening=None) -> str:
        if index >= len(d["inputs"]) or index >= len(leaf.inputs):
            raise Refused("no such input")
        got = leaf.inputs[index]
        header = d["inputs"][index][0]
        kind, a, b, c, dd = S.decode_producer(d["inputs"][index][1])
        if kind == 2:
            ref = self.record.external_refs.get(a)
            if ref is None:  # the run never posted that input
                return "C"
            return "C" if got[7:55] != ref[4:52] else "E"
        if kind == 1:
            if producer_opening is None:
                raise Refused("EDGE needs the producer leaf")
            raw = self._step_opening(a, producer_opening)
            p = R.parse_leaf(raw) if raw is not None else None
            if p is None:
                return "C"
            port = self._port(p, b)
            if port is None:
                return "C"
            return "C" if got[7:55] != port[7:55] else "E"
        if kind == 3:
            record = self._const(a, const_opening)
            return "C" if got[7:23] != record[8 + 7:8 + 23] or got[23:55] != record[40:72] else "E"
        if kind == 5:
            if b == 3:
                root = self._const(a, const_opening)[40:72]
            else:
                ref = self.record.external_refs.get(a)
                if ref is None:
                    return "C"
                root = ref[20:52]
            if chunk_opening is None:
                raise Refused("EDGE kind 5 needs the chunk opening")
            chunk, path = chunk_opening
            if trees.root_from_path("chunk", R.chunk_leaf(dd, chunk), dd, path) != root:
                raise Refused("chunk opening does not verify")
            return "C" if got[23:55] != R.value_digest(chunk) or got[7:23] != header[7:23] else "E"
        if kind == 6:
            port = self._last_running_port(a, b, c, t, producer_opening, gate_opening, gate_value)
            if port is None:
                return "E"
            return "C" if got[7:55] != port[7:55] else "E"
        if kind == 7:
            return "C" if got[23:55] != R.value_digest(struct.pack("<I", a)) else "E"
        raise Refused("producer kind not supported")

    def _state(self, leaf: R.Leaf, d: dict, producer_opening) -> str:
        if not d["state_scheme"]:
            return "E"
        kind, a, _b, _c, _d = S.decode_producer(d["state_predecessor"])
        if kind == 1:
            if producer_opening is None:
                raise Refused("STATE needs the predecessor leaf")
            raw = self._step_opening(a, producer_opening)
            p = R.parse_leaf(raw) if raw is not None else None
            if p is None:
                return "C"
            return "C" if leaf.prior != p.next else "E"
        if kind == 2:
            ref = self.record.external_refs.get(a)
            if ref is None:
                return "C"
            return "C" if leaf.prior != ref[20:52] else "E"
        return "C" if leaf.prior != R.small_state_digest(bytes(d["state_size"])) else "E"

    def _step(self, leaf: R.Leaf, d: dict, witness: list[bytes] | None, state_witness: bytes | None) -> str:
        if witness is None or len(witness) != len(leaf.inputs):
            raise Refused("witness has the wrong input count")
        for value, ref in zip(witness, leaf.inputs):
            if R.value_digest(value) != ref[23:55]:
                raise Refused("witness value does not match its committed digest")
        prior = None
        if d["state_scheme"]:
            if state_witness is None or R.small_state_digest(state_witness) != leaf.prior:
                raise Refused("state witness does not match the prior digest")
            prior = state_witness
        result = R.replay_step(d["kernel_id"], witness, prior)
        if result is None:
            return "C"  # a refused step cannot carry committed outputs
        outs, nxt = result
        if len(outs) != len(leaf.outputs):
            return "C"
        wrong = any(R.value_digest(v) != ref[23:55] for v, ref in zip(outs, leaf.outputs))
        if nxt is not None and R.small_state_digest(nxt) != leaf.next:
            wrong = True
        return "C" if wrong else "E"

    def _shape_wrong(self, leaf: R.Leaf, d: dict, k: int) -> bool:
        expected_in = [h for h, _p, _i in d["inputs"]]
        stateful = bool(d["state_scheme"])
        zero = bytes(32)
        wrong = (leaf.plan_id != self.record.plan_id or leaf.run_id != self.record.run_id
                 or leaf.region != d["region"] or leaf.coord_region != d["region"]
                 or leaf.segment != d["segment"] or leaf.ordinal != k or leaf.node != d["node"]
                 or leaf.kernel_step != d["kernel_step"]
                 or len(leaf.inputs) != len(expected_in) or len(leaf.outputs) != len(d["outputs"])
                 or any(r[:23] != h for r, h in zip(leaf.inputs, expected_in))
                 or any(r[:23] != h for r, h in zip(leaf.outputs, d["outputs"]))
                 or (leaf.prior == zero) == stateful or (leaf.next == zero) == stateful)
        if not wrong and stateful and d["state_export"] != 0xFF:
            export = self._port(leaf, d["state_export"])
            wrong = export is None or export[23:55] != leaf.next
        return wrong

    def _claim_out(self, spec_opening, producer_opening, t, gate_opening, gate_value) -> str:
        j = self.position
        record = self._spec_record(self.record.spec.out_leaf_index(j), spec_opening)
        header, prod = record[8:31], record[32:56]
        entry = self.leaf
        if entry is None or len(entry) != 55 or entry[:23] != header:
            return self._rule("C")
        kind, a, b, c, _d = S.decode_producer(prod)
        if kind == 6:
            port = self._last_running_port(a, b, c, t, producer_opening, gate_opening, gate_value)
            if port is None:
                return self._rule("E")
            return self._rule("C" if entry[23:55] != port[23:55] else "E")
        if producer_opening is None:
            raise Refused("OUT needs the producer leaf")
        raw = self._step_opening(a, producer_opening)
        p = R.parse_leaf(raw) if raw is not None else None
        if p is None:
            return self._rule("C")
        port = self._port(p, b)
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
            return self.c.leaves[dispute.ordinal]
        return self.c.out_entries[dispute.position]

    def leaf_opening(self, ordinal: int):
        return self.c.leaves[ordinal], self.c.step_tree.path(self.c.spec.position_of(ordinal))


def spec_opening(spec: S.Spec, leaf_index: int):
    return spec.opening(leaf_index)


def _value_for(honest: R.Commitment, sp: S.Spec, k: int, i: int) -> bytes:
    _h, prod, _init = S.decode_step_spec(sp.step_spec(k))["inputs"][i]
    return honest_value(honest, sp, prod)


def honest_value(honest: R.Commitment, sp: S.Spec, prod: bytes) -> bytes:
    """H's value for a resolved producer."""
    kind, a, b, c, d = S.decode_producer(prod)
    if kind == 1:
        return honest.values[(a, b)]
    if kind == 2:
        return honest.values[("ext", a)]
    if kind == 3:
        return honest.values[("const", a)]
    if kind == 5:
        if b == 3:
            return R.chunks(honest.values[("const", a)], 1 << R.const_chunk_log2(sp.const_specs[a]))[d]
        return R.chunks(honest.values[("ext", a)], 1 << sp.in_specs[a][32])[d]
    if kind == 6:
        t = honest.last_running[a]
        return honest.values[(sp.ordinal_of(a, t, c), b)]
    if kind == 7:
        return struct.pack("<I", a)
    raise ValueError(f"producer kind {kind}")


def chunk_args(sp: S.Spec, honest: R.Commitment, a: int, source: int, index: int) -> dict:
    """The chunk opening (and, for a constant, its ConstSpec opening) of a kind 5 read."""
    if source == 3:
        value, log2 = honest.values[("const", a)], R.const_chunk_log2(sp.const_specs[a])
        extra = {"const_opening": sp.opening(sp.const_leaf_index(a))}
    else:
        value, log2 = honest.values[("ext", a)], sp.in_specs[a][32]
        extra = {}
    extra["chunk_opening"] = (R.chunks(value, 1 << log2)[index], R.chunk_tree(value, 1 << log2).path(index))
    return extra


def _kind6_args(record: RunRecord, executor: Executor, honest: R.Commitment, a: int, c: int) -> dict:
    sp = record.spec
    block = sp.blocks[a]
    t = honest.last_running[a]
    args = {"t": t, "producer_opening": executor.leaf_opening(sp.ordinal_of(a, t, c))}
    if t != block.k - 1:
        g = sp.ordinal_of(a, t, block.gate_entry)
        args["gate_opening"] = executor.leaf_opening(g)
        args["gate_value"] = honest.values[(g, block.gate_port)]
    return args


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
    if kind == "OUT_DESCEND":
        j = dispute.position
        pk, a, _b, c, _d = S.decode_producer(sp.out_specs[j][32:56])
        extra = (_kind6_args(record, executor, honest, a, c) if pk == 6
                 else {"producer_opening": executor.leaf_opening(a)})
        dispute.claim("OUT", spec_opening=spec_opening(sp, sp.out_leaf_index(j)), **extra)
        return dispute
    k = dispute.ordinal
    bi, block, it, _e = sp.locate(k)
    opening = spec_opening(sp, sp.step_leaf_index(k))
    mine_raw = honest.leaves[k]
    if dispute.leaf is None or mine_raw is None:
        if not sp.gated(k):
            dispute.claim("SHAPE", spec_opening=opening)
            return dispute
        g = sp.ordinal_of(bi, it - 1, block.gate_entry)
        dispute.claim("GATE", spec_opening=opening, gate_opening=executor.leaf_opening(g),
                      gate_value=honest.values.get((g, block.gate_port)))
        return dispute
    d = S.decode_step_spec(sp.step_spec(k))
    leaf = R.parse_leaf(dispute.leaf)
    if leaf is None or dispute._shape_wrong(leaf, d, k):
        dispute.claim("SHAPE", spec_opening=opening)
        return dispute
    mine = R.parse_leaf(mine_raw)
    for i, (got, want) in enumerate(zip(leaf.inputs, mine.inputs)):
        if got != want:
            pk, a, _b, c, dd = S.decode_producer(d["inputs"][i][1])
            extra: dict = {}
            if pk == 1:
                extra["producer_opening"] = executor.leaf_opening(a)
            elif pk == 5:
                extra.update(chunk_args(sp, honest, a, _b, dd))
            elif pk == 3:
                extra["const_opening"] = sp.opening(sp.const_leaf_index(a))
            elif pk == 6:
                extra = _kind6_args(record, executor, honest, a, c)
            dispute.claim("EDGE", spec_opening=opening, index=i, **extra)
            return dispute
    if leaf.prior != mine.prior:
        pk, a, *_ = S.decode_producer(d["state_predecessor"])
        dispute.claim("STATE", spec_opening=opening,
                      producer_opening=executor.leaf_opening(a) if pk == 1 else None)
        return dispute
    witness = [honest_value(honest, sp, prod) for _h, prod, _i in d["inputs"]]
    state_witness = None
    if d["state_scheme"]:
        pk, a, *_ = S.decode_producer(d["state_predecessor"])
        state_witness = (honest.states[a] if pk == 1 else honest.values[("ext", a)] if pk == 2
                         else bytes(d["state_size"]))
    dispute.claim("STEP", spec_opening=opening, witness=witness, state_witness=state_witness)
    return dispute
