"""LX1: checkpointed state chains with one flattened bisection (Python reference).

Design: docs/design/v2.1-lazy-expansion.md. A run commits state roots every
`k` positions. A dispute bisects the flattened schedule of finest
transitions between two adjacent checkpoints; each round the executor
commits the `a-1` midpoint roots and the challenger picks the first
sub-interval whose upper root it disputes. At one transition, the terminal
replay opens the read and written slots of the agreed lower root
(multi-proof), applies the transition, and compares the rebuilt root with
the committed upper root.

DCG provides only this mechanism and a toy machine (`lx_toy.py`); an
application's machine (slot layout, schedule, kernels) is registered by the
application.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol, Sequence

from . import run as R
from . import trees

SLOT_LEAF_DOMAIN = b"dcg.lx.slot.leaf.v1\x00"
EMPTY_SLOT = hashlib.sha256(b"dcg.lx.slot.empty.v1\x00").digest()
TREE = "lxstate"


class LxRefused(ValueError):
    """A malformed submission; the sender may retry until its deadline."""


def slot_leaf(slot: int, value: bytes | None) -> bytes:
    """The leaf of one slot: its index and value, or the empty leaf."""
    if value is None:
        return EMPTY_SLOT
    return hashlib.sha256(SLOT_LEAF_DOMAIN + struct.pack("<II", slot, len(value)) + value).digest()


# --- the machine ------------------------------------------------------------------------

@dataclass(frozen=True)
class Transition:
    """One finest transition: the slots it reads, the slots it writes (a
    written slot set to None is cleared), and the integer kernel.

    `constants` are the template constant chunks it reads (design §13), as
    `(constant_id, chunk_index)` in order; a transition that reads any is
    applied as `apply(values, chunks)` with the chunk bytes in that order."""

    coordinate: int
    label: str
    reads: tuple[int, ...]
    writes: tuple[int, ...]
    apply: Callable[..., Mapping[int, bytes | None]]
    constants: tuple[tuple[int, int], ...] = ()


def apply_transition(t: Transition, values: Mapping[int, bytes | None],
                     chunks: Sequence[bytes]) -> Mapping[int, bytes | None]:
    return t.apply(values, list(chunks)) if t.constants else t.apply(values)


# --- template constants (design §13) ----------------------------------------------------

CONST_LEAF_DOMAIN = b"dcg.lx.const.leaf.v1\x00"
CONST_TREE = "lxconst"


def const_leaf(constant_id: int, digest: bytes) -> bytes:
    """The constants tree's leaf at position `constant_id`: the id and the
    constant's chunk-tree root."""
    return hashlib.sha256(CONST_LEAF_DOMAIN + struct.pack("<I", constant_id) + digest).digest()


@dataclass(frozen=True)
class ConstantTable:
    """An LX1 template's committed constants: values by dense id, each split
    into `2^chunk_log2`-byte chunks (v2.1 §4.2 chunk trees). The template
    commits `root`; the values are available off chain."""

    values: Mapping[int, bytes]
    chunk_log2: Mapping[int, int]

    def chunk_tree(self, cid: int) -> trees.Tree:
        return R.chunk_tree(self.values[cid], 1 << self.chunk_log2[cid])

    def digest(self, cid: int) -> bytes:
        return self.chunk_tree(cid).root

    def tree(self) -> trees.Tree:
        n = max(self.values) + 1
        return trees.build(CONST_TREE, [const_leaf(i, self.digest(i)) if i in self.values
                                        else trees.EMPTY_LEAVES[CONST_TREE] for i in range(n)])

    @property
    def root(self) -> bytes:
        return self.tree().root

    def chunk(self, cid: int, index: int) -> bytes:
        return R.chunks(self.values[cid], 1 << self.chunk_log2[cid])[index]


def constants_root(machine: "Machine") -> bytes:
    """The root an LX1 template commits for its machine's constants (zero for
    a machine without any)."""
    table = constant_table(machine)
    return table.root if table is not None else bytes(32)


def constant_table(machine: "Machine") -> ConstantTable | None:
    get = getattr(machine, "constant_table", None)
    return get() if get is not None else None


@dataclass(frozen=True)
class ConstOpening:
    """One declared constant read in an opening: the chunk, its path to the
    constant's chunk root, and that root with its path to `constants_root`."""

    chunk: bytes
    chunk_path: tuple[bytes, ...]
    digest: bytes
    const_path: tuple[bytes, ...]


def open_constants(machine: "Machine", t: Transition) -> tuple[ConstOpening, ...]:
    table = constant_table(machine)
    if not t.constants:
        return ()
    ctree = table.tree()
    return tuple(ConstOpening(table.chunk(cid, j), tuple(table.chunk_tree(cid).path(j)),
                              table.digest(cid), tuple(ctree.path(cid)))
                 for cid, j in t.constants)


MAX_CHUNK_PATH = 48
MAX_CONST_PATH = 32


def check_constants(t: Transition, opened: Sequence[ConstOpening], root: bytes) -> list[bytes]:
    """What the replay checks before applying (design §13): one entry per
    declared read, in order, each chunk verifying against its constant's
    digest and that digest against the template's `constants_root`. The ids
    and indices come from the machine, never from the opening."""
    if len(opened) != len(t.constants):
        raise LxRefused("the opening does not cover the transition's constant reads")
    chunks = []
    for (cid, index), e in zip(t.constants, opened):
        if (len(e.chunk_path) > MAX_CHUNK_PATH or len(e.const_path) > MAX_CONST_PATH
                or index >> len(e.chunk_path) or cid >> len(e.const_path)):
            raise LxRefused("a constant path is too short or too long")
        if trees.root_from_path("chunk", R.chunk_leaf(index, e.chunk), index, list(e.chunk_path)) != e.digest:
            raise LxRefused("a chunk does not verify against its constant")
        if trees.root_from_path(CONST_TREE, const_leaf(cid, e.digest), cid, list(e.const_path)) != root:
            raise LxRefused("a constant does not verify against constants_root")
        chunks.append(e.chunk)
    return chunks


class Machine(Protocol):
    """An application's state machine, as registered by its template."""

    slot_count: int

    def positions(self) -> int: ...

    def transitions_in(self, position: int) -> int:
        """The number of finest transitions in a position (a closed-form rule)."""

    def transition(self, position: int, index: int) -> Transition: ...

    def initial_state(self) -> dict[int, bytes]:
        """The state before position 0, a pure function of the admitted inputs
        (review H1): R_0 is recomputed, never taken from the executor."""

    def output_slots(self) -> tuple[int, ...]:
        """Carried slots holding the run's outputs in the final state (review H3)."""

    # Optional (design §13): `constant_table() -> ConstantTable`, the template
    # constants that transitions declare in `Transition.constants`.


def height(machine: Machine) -> int:
    return trees.height_for(machine.slot_count)


def state_tree(machine: Machine, state: Mapping[int, bytes]) -> trees.Tree:
    leaves = [slot_leaf(i, state.get(i)) for i in range(machine.slot_count)]
    return trees.build(TREE, leaves, height(machine))


def state_root(machine: Machine, state: Mapping[int, bytes]) -> bytes:
    return state_tree(machine, state).root


class Schedule:
    """Global coordinates: transitions numbered across positions in order."""

    def __init__(self, machine: Machine):
        self.machine = machine
        self.starts = [0]
        for p in range(machine.positions()):
            self.starts.append(self.starts[-1] + machine.transitions_in(p))

    @property
    def total(self) -> int:
        return self.starts[-1]

    def position_start(self, position: int) -> int:
        return self.starts[position]

    def locate(self, coordinate: int) -> tuple[int, int]:
        if not 0 <= coordinate < self.total:
            raise LxRefused("coordinate outside the schedule")
        lo, hi = 0, len(self.starts) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self.starts[mid] <= coordinate:
                lo = mid
            else:
                hi = mid
        return lo, coordinate - self.starts[lo]

    def transition(self, coordinate: int) -> Transition:
        p, i = self.locate(coordinate)
        t = self.machine.transition(p, i)
        if t.coordinate != coordinate:
            raise ValueError("machine numbered a transition inconsistently")
        return t


def step(machine: Machine, state: dict[int, bytes], t: Transition) -> dict[int, bytes]:
    """Apply one transition to a full state (an executor's or challenger's)."""
    out = dict(state)
    table = constant_table(machine)
    chunks = [table.chunk(cid, j) for cid, j in t.constants]
    for slot, value in apply_transition(t, {s: state.get(s) for s in t.reads}, chunks).items():
        if slot not in t.writes:
            raise ValueError(f"{t.label} wrote undeclared slot {slot}")
        if value is None:
            out.pop(slot, None)
        else:
            out[slot] = value
    return out


# --- execution and commitment --------------------------------------------------------------

Fault = Callable[[int, dict[int, bytes]], dict[int, bytes]]


@dataclass
class Execution:
    """A party's full execution: the state after every coordinate (the reference
    keeps them all; a real executor keeps snapshots and recomputes)."""

    machine: Machine
    schedule: Schedule
    states: list[dict[int, bytes]]  # states[c] is the state before coordinate c

    def root_at(self, coordinate: int) -> bytes:
        return state_root(self.machine, self.states[coordinate])


def execute(machine: Machine, fault: Fault | None = None) -> Execution:
    """Run the machine. `fault(coordinate, state_after)` may return an altered
    state after a coordinate: a lying executor continues from it."""
    schedule = Schedule(machine)
    state = dict(machine.initial_state())
    states = [state]
    for c in range(schedule.total):
        state = step(machine, state, schedule.transition(c))
        if fault is not None:
            state = fault(c, state)
        states.append(state)
    return Execution(machine, schedule, states)


@dataclass(frozen=True)
class Commitment:
    """What a run commits: checkpoint roots every k positions, the final root,
    and the claimed outputs. The checkpoint coordinates are derived from `k` and
    the schedule (review H2); the executor supplies only the roots and outputs."""

    k: int
    roots: tuple[bytes, ...]
    outputs: Mapping[int, bytes | None]  # output slot -> claimed value


def checkpoint_coordinates(schedule: Schedule, k: int) -> tuple[int, ...]:
    if k < 1:
        raise ValueError("k must be at least 1")
    positions = schedule.machine.positions()
    marks = sorted({min(p, positions) for p in range(0, positions + k, k)} | {positions})
    return tuple(schedule.position_start(p) for p in marks)


def commit(run: Execution, k: int, outputs: Mapping[int, bytes | None] | None = None) -> Commitment:
    coords = checkpoint_coordinates(run.schedule, k)
    final = run.states[-1]
    claimed = {s: final.get(s) for s in run.machine.output_slots()} if outputs is None else dict(outputs)
    return Commitment(k, tuple(run.root_at(c) for c in coords), claimed)


def admit_commitment(machine: Machine, commitment: Commitment) -> tuple[int, ...]:
    """What COMMIT checks: the root array has the derived length, R_0 is the
    root of the admitted initial state, and the outputs name exactly the output
    slots. Returns the derived coordinates. On chain, R_0 is checked with a few
    paths over the input subtree (design §3), not by rebuilding the tree."""
    coords = checkpoint_coordinates(Schedule(machine), commitment.k)
    if len(commitment.roots) != len(coords):
        raise LxRefused("the checkpoint array does not have the derived length")
    if commitment.roots[0] != state_root(machine, machine.initial_state()):
        raise LxRefused("R_0 is not the admitted initial state's root")
    if set(commitment.outputs) != set(machine.output_slots()):
        raise LxRefused("outputs do not name exactly the output slots")
    return coords


# --- program commitments (tag 227 LX1, design §8) -------------------------------------

OUTPUTS_DOMAIN = b"dcg.lx.outputs.v1\x00"


def outputs_digest(values: Sequence[bytes | None]) -> bytes:
    """Chained digest of the claimed outputs in output-slot order (mirrors
    `dcg_disputes::lx::outputs_digest`)."""
    acc = bytes(32)
    for v in values:
        if v is None:
            acc = hashlib.sha256(OUTPUTS_DOMAIN + acc + b"\x00").digest()
        else:
            acc = hashlib.sha256(OUTPUTS_DOMAIN + acc + b"\x01" + len(v).to_bytes(4, "little") + v).digest()
    return acc


def checkpoint_tree(roots: Sequence[bytes]) -> trees.Tree:
    """The run commits one root over its checkpoint roots; a dispute opens the
    two it names with paths."""
    return trees.build("lxcheckpoint", list(roots))


# --- multi-proofs ----------------------------------------------------------------------------

@dataclass(frozen=True)
class MultiProof:
    """Opened slot values (None = empty) and the sibling nodes needed to rebuild
    the root over exactly those slots."""

    values: Mapping[int, bytes | None]
    siblings: Mapping[tuple[int, int], bytes]  # (level, position) -> hash
    constants: tuple[ConstOpening, ...] = ()  # the transition's constant reads (§13)


def _needed(slots: set[int], h: int) -> set[tuple[int, int]]:
    """Sibling nodes not derivable from the opened slots."""
    need, known = set(), set(slots)
    for level in range(h):
        parents = set()
        for pos in known:
            sib = pos ^ 1
            if sib not in known:
                need.add((level, sib))
            parents.add(pos >> 1)
        known = parents
    return need


def prove(machine: Machine, state: Mapping[int, bytes], slots: Sequence[int]) -> MultiProof:
    tree = state_tree(machine, state)
    s = set(slots)
    return MultiProof({i: state.get(i) for i in s},
                      {(l, p): tree.at(l, p) for l, p in _needed(s, tree.height)})


def root_over(machine: Machine, proof: MultiProof, values: Mapping[int, bytes | None]) -> bytes:
    """Rebuild the root from `values` at the proof's slots and the proof's siblings."""
    h = height(machine)
    if set(values) != set(proof.values):
        raise LxRefused("values do not cover the proof's slots")
    if set(proof.siblings) != _needed(set(values), h):
        raise LxRefused("the proof's sibling set is not the canonical one")
    nodes = {(0, i): slot_leaf(i, v) for i, v in values.items()}
    nodes.update(proof.siblings)
    frontier = set(values)
    for level in range(h):
        parents = set()
        for pos in frontier:
            left, right = nodes[(level, pos & ~1)], nodes[(level, pos | 1)]
            nodes[(level + 1, pos >> 1)] = trees.node(TREE, level, left, right)
            parents.add(pos >> 1)
        frontier = parents
    return nodes[(h, 0)]


# --- the dispute -----------------------------------------------------------------------------

PH_MIDPOINTS, PH_PICK, PH_OPENING, PH_RULED = "midpoints", "pick", "opening", "ruled"


@dataclass
class Dispute:
    """One LX1 dispute between checkpoints `pair` and `pair + 1` of a commitment."""

    machine: Machine
    commitment: Commitment
    arity: int = 16
    lo: int = 0
    hi: int = 0
    root_lo: bytes = b""
    root_hi: bytes = b""
    midpoints: list[tuple[int, bytes]] = field(default_factory=list)
    phase: str = PH_MIDPOINTS
    ruling: str | None = None  # "E", "C"
    rounds: int = 0

    def __post_init__(self):
        if self.arity < 2:
            raise ValueError("arity must be at least 2")
        self.schedule = Schedule(self.machine)
        self.coordinates = admit_commitment(self.machine, self.commitment)

    # Opening: C names a checkpoint pair (agreed lower, disputed upper).
    def open(self, pair: int) -> None:
        c = self.commitment
        if not 0 <= pair < len(self.coordinates) - 1:
            raise LxRefused("no such checkpoint pair")
        lo, hi = self.coordinates[pair], self.coordinates[pair + 1]
        if hi <= lo:
            raise LxRefused("an empty checkpoint interval cannot be disputed")  # review L1
        self.lo, self.hi = lo, hi
        self.root_lo, self.root_hi = c.roots[pair], c.roots[pair + 1]
        self.phase = PH_MIDPOINTS if self.hi - self.lo > 1 else PH_OPENING

    def claim_output(self, proof: MultiProof) -> str:
        """OUTPUT (review H3): C opens the output slots against the committed
        final root R_T; C wins if any opened value differs from the claimed
        output. One transaction, no bisection."""
        if self.phase != PH_MIDPOINTS or self.lo or self.hi:
            raise LxRefused("OUTPUT is a claim of its own, made before any interval opens")
        slots = set(self.machine.output_slots())
        if set(proof.values) != slots:
            raise LxRefused("the opening does not cover the output slots")
        if root_over(self.machine, proof, proof.values) != self.commitment.roots[-1]:
            raise LxRefused("the opening does not verify against R_T")
        lie = any(proof.values[s] != self.commitment.outputs.get(s) for s in slots)
        return self._rule("C" if lie else "E")

    def midpoint_coordinates(self) -> list[int]:
        """Fixed by the interval: a-1 evenly spaced interior points (fewer when
        the interval is short). The executor does not choose them."""
        span = self.hi - self.lo
        parts = min(self.arity, span)
        return sorted({self.lo + (span * i) // parts for i in range(1, parts)})

    def commit_midpoints(self, roots: Sequence[bytes]) -> None:
        if self.phase != PH_MIDPOINTS:
            raise LxRefused("not awaiting midpoints")
        coords = self.midpoint_coordinates()
        if len(roots) != len(coords) or any(len(r) != 32 for r in roots):
            raise LxRefused("wrong midpoint list")
        self.midpoints = list(zip(coords, roots))
        self.phase = PH_PICK

    def pick(self, index: int) -> None:
        """C names sub-interval `index`: 0 is [lo, m1], the last is [m_last, hi]."""
        if self.phase != PH_PICK:
            raise LxRefused("not awaiting a pick")
        bounds = [(self.lo, self.root_lo)] + self.midpoints + [(self.hi, self.root_hi)]
        if not 0 <= index < len(bounds) - 1:
            raise LxRefused("no such sub-interval")
        (self.lo, self.root_lo), (self.hi, self.root_hi) = bounds[index], bounds[index + 1]
        self.midpoints = []
        self.rounds += 1
        self.phase = PH_MIDPOINTS if self.hi - self.lo > 1 else PH_OPENING

    def submit_opening(self, proof: MultiProof) -> str:
        """E opens the agreed lower state at the transition's slots; the program
        replays it and rules."""
        if self.phase != PH_OPENING:
            raise LxRefused("not awaiting an opening")
        t = self.schedule.transition(self.lo)
        slots = set(t.reads) | set(t.writes)
        chunks = check_constants(t, proof.constants, constants_root(self.machine))
        if not slots:
            # A transition that touches no slot is the identity (LX1 program
            # review M1): the roots must already agree.
            if proof.values or proof.siblings:
                raise LxRefused("an identity transition takes an empty opening")
            return self._rule("E" if self.root_lo == self.root_hi else "C")
        if set(proof.values) != slots:
            raise LxRefused("the opening does not cover the transition's slots")
        if root_over(self.machine, proof, proof.values) != self.root_lo:
            raise LxRefused("the opening does not verify against the lower root")
        written = dict(proof.values)
        try:
            updates = apply_transition(t, {s: proof.values[s] for s in t.reads}, chunks)
        except Exception:
            # A kernel failure on a verified opening rules for C (review L2):
            # the committed lower state cannot lead to any committed upper root.
            return self._rule("C")
        for slot, value in updates.items():
            if slot not in t.writes:
                raise ValueError(f"{t.label} wrote undeclared slot {slot}")
            written[slot] = value
        rebuilt = root_over(self.machine, proof, written)
        return self._rule("E" if rebuilt == self.root_hi else "C")

    def timeout(self) -> str:
        """The party that owes the phase loses: E owes midpoints and the opening."""
        if self.phase == PH_RULED:
            raise LxRefused("already ruled")
        return self._rule("C" if self.phase in (PH_MIDPOINTS, PH_OPENING) else "E")

    def _rule(self, who: str) -> str:
        self.ruling, self.phase = who, PH_RULED
        return who


# --- honest parties --------------------------------------------------------------------------

def first_disputed_pair(commitment: Commitment, mine: Execution) -> int | None:
    """The first checkpoint whose committed root differs from my execution's.
    R_0 is checked at admission, so a differing R_0 never reaches a dispute."""
    coords = checkpoint_coordinates(mine.schedule, commitment.k)
    for j, (c, r) in enumerate(zip(coords, commitment.roots)):
        if r != mine.root_at(c):
            return j - 1 if j > 0 else None
    return None


def output_lie(commitment: Commitment, mine: Execution) -> bool:
    """Every checkpoint agrees but a claimed output differs: dispute with OUTPUT."""
    final = mine.states[-1]
    return any(commitment.outputs.get(s) != final.get(s) for s in mine.machine.output_slots())


def executor_midpoints(run: Execution, dispute: Dispute) -> list[bytes]:
    return [run.root_at(c) for c in dispute.midpoint_coordinates()]


def challenger_pick(mine: Execution, dispute: Dispute) -> int:
    """The first sub-interval whose upper root differs from mine."""
    uppers = [r for _c, r in dispute.midpoints] + [dispute.root_hi]
    coords = [c for c, _r in dispute.midpoints] + [dispute.hi]
    for i, (c, r) in enumerate(zip(coords, uppers)):
        if r != mine.root_at(c):
            return i
    return len(uppers) - 1  # nothing differs: an honest challenger would not be here


def executor_opening(run: Execution, dispute: Dispute) -> MultiProof:
    t = dispute.schedule.transition(dispute.lo)
    proof = prove(run.machine, run.states[dispute.lo], sorted(set(t.reads) | set(t.writes)))
    return MultiProof(proof.values, proof.siblings, open_constants(run.machine, t))


def play(machine: Machine, executor: Execution, challenger: Execution, k: int,
         arity: int = 16, pair: int | None = None,
         pick: Callable[[Dispute], int] | None = None) -> Dispute:
    """Play one dispute to a ruling: E answers from `executor`, C from
    `challenger` (or the given `pick` strategy)."""
    commitment = commit(executor, k)
    if pair is None:
        pair = first_disputed_pair(commitment, challenger)
        if pair is None:
            raise ValueError("no disputed checkpoint")
    d = Dispute(machine, commitment, arity)
    d.open(pair)
    while d.phase == PH_MIDPOINTS:
        d.commit_midpoints(executor_midpoints(executor, d))
        d.pick(pick(d) if pick else challenger_pick(challenger, d))
    d.submit_opening(executor_opening(executor, d))
    return d
