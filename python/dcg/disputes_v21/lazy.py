"""Lazy, second-level decompositions for ordinary v2.1 STEP claims.

This module is the protocol-generic Python reference. Application arithmetic is
registered by the application; DCG only commits indexed sub-step records,
binds their endpoints to the already committed parent leaf, and arbitrates one
sub-step after first-divergence descent.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from . import run as R
from . import trees

SUBSTEP_LEAF_DOMAIN = b"dcg.lazy.substep.leaf.v1\x00"
SUBTRACE_DOMAIN = b"dcg.lazy.subtrace.v1\x00"
ACCUMULATOR_DOMAIN = b"dcg.lazy.accumulator.v1\x00"
VALUES_DOMAIN = b"dcg.lazy.values.v1\x00"


class LazyRefused(ValueError):
    """A malformed party submission; the sender may retry before its deadline."""


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def values_digest(values: Sequence[bytes]) -> bytes:
    return _h(VALUES_DOMAIN, struct.pack("<H", len(values)),
              *(struct.pack("<I", len(v)) + v for v in values))


def accumulator_digest(raw: bytes) -> bytes:
    return _h(ACCUMULATOR_DOMAIN, struct.pack("<I", len(raw)), raw)


def refs_digest(values: Sequence[bytes]) -> bytes:
    """Digest an ordered set of already domain-separated value digests."""
    return _h(VALUES_DOMAIN, struct.pack("<H", len(values)),
              *(struct.pack("<I", len(v)) + v for v in values))


@dataclass(frozen=True)
class AccumulatorScheme:
    """A fixed-width, explicitly identified SMALL accumulator image."""

    scheme_id: int
    version: int
    byte_length: int

    def __post_init__(self) -> None:
        if not (0 < self.scheme_id < 1 << 16 and 0 < self.version < 1 << 16):
            raise ValueError("accumulator scheme identity must be nonzero u16")
        if not (0 <= self.byte_length <= 4096):
            raise ValueError("lazy accumulator must fit SMALL state (4096 bytes)")


@dataclass(frozen=True)
class ParentStep:
    """The immutable ordinary STEP statement, plus its available input bytes."""

    leaf_hash: bytes
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    decomposition_id: int
    decomposition_version: int
    shape: Mapping[str, int]
    inputs: tuple[bytes, ...]
    outputs: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if len(self.leaf_hash) != 32 or len(self.kernel_id) != 16:
            raise ValueError("parent leaf hash or kernel id width")
        if self.decomposition_id <= 0 or self.decomposition_version <= 0:
            raise ValueError("lazy parent must declare a decomposition")
        if len(self.inputs) > 8 or len(self.outputs) > 8:
            raise ValueError("ordinary StepSpec has at most eight inputs and outputs")


@dataclass(frozen=True)
class SubstepWitness:
    """The private values needed to replay one committed sub-step."""

    inputs: tuple[bytes, ...]
    prior_accumulator: bytes
    outputs: tuple[bytes, ...]
    next_accumulator: bytes


@dataclass(frozen=True)
class SubstepRecord:
    """Small leaf preimage: identities and value/state digests, never payloads."""

    index: int
    phase: int
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    input_digests: tuple[bytes, ...]
    prior_digest: bytes
    output_digests: tuple[bytes, ...]
    next_digest: bytes

    def encode(self) -> bytes:
        if (self.index < 0 or self.index >= 1 << 32 or not 0 <= self.phase < 1 << 16
                or len(self.kernel_id) != 16 or len(self.input_digests) > 8
                or len(self.output_digests) > 8
                or any(len(v) != 32 for v in self.input_digests + self.output_digests)
                or len(self.prior_digest) != 32 or len(self.next_digest) != 32):
            raise LazyRefused("sub-step record field width")
        return (b"LSS1" + struct.pack("<IH", self.index, self.phase) + self.kernel_id
                + struct.pack("<HHBB2x", self.semantic_version, self.abi_version,
                              len(self.input_digests), len(self.output_digests))
                + self.prior_digest + b"".join(self.input_digests)
                + b"".join(self.output_digests) + self.next_digest)

    @classmethod
    def decode(cls, raw: bytes) -> "SubstepRecord | None":
        try:
            if len(raw) < 4 + 6 + 16 + 6 + 32 + 32 or raw[:4] != b"LSS1":
                return None
            index, phase = struct.unpack_from("<IH", raw, 4)
            kernel_id = raw[10:26]
            sem, abi, n_in, n_out = struct.unpack_from("<HHBB", raw, 26)
            if n_in > 8 or n_out > 8 or raw[32:34] != b"\x00\x00":
                return None
            expected = 34 + 32 + 32 * (n_in + n_out) + 32
            if len(raw) != expected:
                return None
            prior = raw[34:66]
            at = 66
            ins = tuple(raw[at + 32 * i:at + 32 * (i + 1)] for i in range(n_in))
            at += n_in * 32
            outs = tuple(raw[at + 32 * i:at + 32 * (i + 1)] for i in range(n_out))
            at += n_out * 32
            nxt = raw[at:at + 32]
            return cls(index, phase, kernel_id, sem, abi, ins, prior, outs, nxt)
        except (ValueError, struct.error):
            return None


@dataclass(frozen=True)
class SubtraceHeader:
    """Descriptor hashed with the root and checked against the parent StepSpec."""

    parent_leaf_hash: bytes
    kernel_id: bytes
    semantic_version: int
    abi_version: int
    decomposition_id: int
    decomposition_version: int
    accumulator: AccumulatorScheme
    step_count: int
    shape_digest: bytes
    parent_inputs_digest: bytes
    first_inputs_digest: bytes
    initial_accumulator_digest: bytes
    terminal_outputs_digest: bytes

    def encode(self) -> bytes:
        fixed = (self.parent_leaf_hash, self.shape_digest, self.parent_inputs_digest,
                 self.first_inputs_digest,
                 self.initial_accumulator_digest, self.terminal_outputs_digest)
        if (any(len(v) != 32 for v in fixed) or len(self.kernel_id) != 16
                or not 1 <= self.step_count < 1 << 32):
            raise LazyRefused("subtrace header field width")
        return (b"LSH1" + self.parent_leaf_hash + self.kernel_id
                + struct.pack("<HHIHHHII", self.semantic_version, self.abi_version,
                              self.decomposition_id, self.decomposition_version,
                              self.accumulator.scheme_id, self.accumulator.version,
                              self.accumulator.byte_length, self.step_count)
                + self.shape_digest + self.parent_inputs_digest + self.first_inputs_digest
                + self.initial_accumulator_digest + self.terminal_outputs_digest)

    @property
    def digest(self) -> bytes:
        return _h(SUBTRACE_DOMAIN, self.encode())


class Decomposition(Protocol):
    """Application-supplied deterministic sub-step schedule and arithmetic."""

    kernel_id: bytes
    semantic_version: int
    abi_version: int
    decomposition_id: int
    decomposition_version: int

    def count(self, parent: ParentStep) -> int: ...
    def accumulator_scheme(self, parent: ParentStep) -> AccumulatorScheme: ...
    def phase(self, parent: ParentStep, index: int) -> int: ...
    def initial_accumulator(self, parent: ParentStep) -> bytes: ...
    def inputs(self, parent: ParentStep, index: int,
               prior_witnesses: Sequence[SubstepWitness]) -> tuple[bytes, ...]: ...
    def replay(self, parent: ParentStep, index: int, inputs: tuple[bytes, ...],
               prior_accumulator: bytes) -> tuple[tuple[bytes, ...], bytes]: ...


class DecompositionRegistry:
    """Exact StepSpec dispatch: kernel/version and decomposition/version."""

    def __init__(self) -> None:
        self._items: dict[tuple[bytes, int, int, int, int], Decomposition] = {}

    def register(self, implementation: Decomposition) -> None:
        key = (bytes(implementation.kernel_id), implementation.semantic_version,
               implementation.abi_version, implementation.decomposition_id,
               implementation.decomposition_version)
        if len(key[0]) != 16 or any(v <= 0 for v in key[1:]):
            raise ValueError("invalid lazy decomposition identity")
        if key in self._items:
            raise ValueError("duplicate lazy decomposition identity")
        self._items[key] = implementation

    def resolve(self, parent: ParentStep) -> Decomposition:
        key = (parent.kernel_id, parent.semantic_version, parent.abi_version,
               parent.decomposition_id, parent.decomposition_version)
        try:
            return self._items[key]
        except KeyError as exc:
            raise LazyRefused("unregistered StepSpec decomposition") from exc


REGISTRY = DecompositionRegistry()


def _shape_digest(parent: ParentStep) -> bytes:
    # Shape keys and values have one canonical little-endian representation.
    rows = []
    for key, value in sorted(parent.shape.items()):
        raw = key.encode("ascii")
        if len(raw) > 255 or not -(1 << 63) <= int(value) < 1 << 63:
            raise LazyRefused("shape field width")
        rows.append(bytes([len(raw)]) + raw + struct.pack("<q", int(value)))
    return _h(b"dcg.lazy.shape.v1\x00", b"".join(rows))


def _record(handler: Decomposition, parent: ParentStep, index: int,
            witness: SubstepWitness) -> SubstepRecord:
    return SubstepRecord(index, handler.phase(parent, index), handler.kernel_id,
                         handler.semantic_version, handler.abi_version,
                         tuple(R.value_digest(v) for v in witness.inputs),
                         accumulator_digest(witness.prior_accumulator),
                         tuple(R.value_digest(v) for v in witness.outputs),
                         accumulator_digest(witness.next_accumulator))


@dataclass
class SubtraceCommitment:
    """On-demand commitment and local openings for one parent STEP."""

    header: SubtraceHeader
    records: tuple[bytes, ...]
    witnesses: tuple[SubstepWitness, ...]
    tree: trees.Tree

    @property
    def root(self) -> bytes:
        return self.tree.root

    @property
    def commitment(self) -> bytes:
        return _h(SUBTRACE_DOMAIN + b"commit\x00", self.header.encode(), self.root)

    def opening(self, index: int) -> tuple[bytes, list[bytes]]:
        return self.records[index], self.tree.path(index)

    @classmethod
    def from_witnesses(cls, parent: ParentStep, handler: Decomposition,
                       witnesses: Sequence[SubstepWitness], *,
                       header_override: SubtraceHeader | None = None) -> "SubtraceCommitment":
        expected_count = handler.count(parent)
        if expected_count <= 0 or len(witnesses) != expected_count:
            raise LazyRefused("subtrace has the wrong declared sub-step count")
        records = tuple(_record(handler, parent, i, witness) for i, witness in enumerate(witnesses))
        raw = tuple(record.encode() for record in records)
        acc = handler.accumulator_scheme(parent)
        first = witnesses[0]
        last = witnesses[-1]
        header = SubtraceHeader(parent.leaf_hash, parent.kernel_id, parent.semantic_version,
                                parent.abi_version, parent.decomposition_id,
                                parent.decomposition_version, acc, expected_count,
                                _shape_digest(parent),
                                refs_digest(tuple(R.value_digest(v) for v in parent.inputs)),
                                refs_digest(tuple(R.value_digest(v) for v in first.inputs)),
                                accumulator_digest(handler.initial_accumulator(parent)),
                                refs_digest(tuple(R.value_digest(v) for v in parent.outputs)))
        return cls(header_override or header, raw, tuple(witnesses),
                   trees.build("lazy", [_h(SUBSTEP_LEAF_DOMAIN, value) for value in raw]))

    @classmethod
    def from_raw(cls, header: SubtraceHeader, records: Sequence[bytes],
                 witnesses: Sequence[SubstepWitness]) -> "SubtraceCommitment":
        """Commit even malformed record bytes, as an executor can; the game rules them."""
        if not records:
            raise LazyRefused("empty subtrace")
        raw = tuple(bytes(v) for v in records)
        return cls(header, raw, tuple(witnesses),
                   trees.build("lazy", [_h(SUBSTEP_LEAF_DOMAIN, value) for value in raw]))


def honest_subtrace(parent: ParentStep, handler: Decomposition) -> SubtraceCommitment:
    """Execute the declared schedule and build the reference second-level root."""
    n = handler.count(parent)
    if n <= 0 or n >= 1 << 32:
        raise LazyRefused("decomposition count outside u32")
    scheme = handler.accumulator_scheme(parent)
    acc = handler.initial_accumulator(parent)
    if len(acc) != scheme.byte_length:
        raise LazyRefused("initial accumulator length differs from declared scheme")
    witnesses: list[SubstepWitness] = []
    for index in range(n):
        ins = handler.inputs(parent, index, witnesses)
        outs, nxt = handler.replay(parent, index, ins, acc)
        if len(nxt) != scheme.byte_length:
            raise LazyRefused("next accumulator length differs from declared scheme")
        witnesses.append(SubstepWitness(ins, acc, outs, nxt))
        acc = nxt
    return SubtraceCommitment.from_witnesses(parent, handler, witnesses)


def _header_binding(parent: ParentStep, handler: Decomposition,
                    subtrace: SubtraceCommitment) -> str | None:
    h = subtrace.header
    n = handler.count(parent)
    scheme = handler.accumulator_scheme(parent)
    initial = handler.initial_accumulator(parent)
    first_inputs = handler.inputs(parent, 0, ())
    checks = (
        h.parent_leaf_hash == parent.leaf_hash,
        h.kernel_id == parent.kernel_id == handler.kernel_id,
        h.semantic_version == parent.semantic_version == handler.semantic_version,
        h.abi_version == parent.abi_version == handler.abi_version,
        h.decomposition_id == parent.decomposition_id == handler.decomposition_id,
        h.decomposition_version == parent.decomposition_version == handler.decomposition_version,
        h.accumulator == scheme,
        h.step_count == n == len(subtrace.records),
        h.shape_digest == _shape_digest(parent),
        h.parent_inputs_digest == refs_digest(tuple(R.value_digest(v) for v in parent.inputs)),
        h.first_inputs_digest == refs_digest(tuple(R.value_digest(v) for v in first_inputs)),
        h.initial_accumulator_digest == accumulator_digest(initial),
        h.terminal_outputs_digest == refs_digest(tuple(R.value_digest(v) for v in parent.outputs)),
    )
    if not all(checks):
        return "C"
    # The root submission carries authenticated first and last leaf openings.
    # This makes the claimed boundaries auditable before descent, while all
    # interior arithmetic remains lazy.
    if len(subtrace.records) != n:
        return "C"
    first_raw, last_raw = subtrace.records[0], subtrace.records[-1]
    if (trees.root_from_path("lazy", _h(SUBSTEP_LEAF_DOMAIN, first_raw), 0,
                             subtrace.tree.path(0)) != subtrace.root
            or trees.root_from_path("lazy", _h(SUBSTEP_LEAF_DOMAIN, last_raw), n - 1,
                                    subtrace.tree.path(n - 1)) != subtrace.root):
        return "C"
    first_record, last_record = (SubstepRecord.decode(first_raw),
                                 SubstepRecord.decode(last_raw))
    if first_record is None or last_record is None:
        return "C"
    if (refs_digest(first_record.input_digests) != h.first_inputs_digest
            or first_record.prior_digest != h.initial_accumulator_digest
            or refs_digest(last_record.output_digests) != h.terminal_outputs_digest):
        return "C"
    return None


def _step_proof(parent: ParentStep, handler: Decomposition, index: int,
                record_raw: bytes, witness: SubstepWitness,
                prior_record: SubstepRecord | None, *, public: bool = True) -> str:
    record = SubstepRecord.decode(record_raw)
    if record is None:
        return "C"
    if record.index != index or record.phase != handler.phase(parent, index) \
            or record.kernel_id != handler.kernel_id \
            or record.semantic_version != handler.semantic_version \
            or record.abi_version != handler.abi_version:
        return "C"  # SHAPE
    try:
        expected_inputs = handler.inputs(parent, index, ()) if index == 0 else None
        # For later steps, the input producer proof belongs to earlier subtrace
        # leaves. The reference handler recomputes that source from the honest
        # execution; on chain this is an EDGE opening against the named leaf.
        if expected_inputs is None:
            prefix = honest_subtrace(parent, handler)
            expected_inputs = handler.inputs(parent, index, prefix.witnesses[:index])
        if tuple(R.value_digest(v) for v in expected_inputs) != record.input_digests:
            return "C"  # EDGE
        expected_prior = (accumulator_digest(handler.initial_accumulator(parent)) if index == 0 else
                          (prior_record.next_digest if prior_record is not None else None))
        if expected_prior is None or expected_prior != record.prior_digest:
            return "C"  # STATE
        if tuple(R.value_digest(v) for v in witness.inputs) != record.input_digests:
            raise LazyRefused("sub-step witness input digest mismatch")
        if accumulator_digest(witness.prior_accumulator) != record.prior_digest:
            raise LazyRefused("sub-step witness prior accumulator mismatch")
        if accumulator_digest(witness.prior_accumulator) != expected_prior:
            return "C"  # STATE
        outs, nxt = handler.replay(parent, index, witness.inputs, witness.prior_accumulator)
        if (tuple(R.value_digest(v) for v in outs) != record.output_digests
                or accumulator_digest(nxt) != record.next_digest
                or tuple(R.value_digest(v) for v in witness.outputs) != record.output_digests
                or accumulator_digest(witness.next_accumulator) != record.next_digest):
            return "C"  # STEP
        if index == handler.count(parent) - 1 and witness.outputs != parent.outputs:
            return "C"  # final STEP-to-parent output binding
        return "E"
    except LazyRefused:
        raise


class LazyDispute:
    """Second-level first-divergence descent for one already-open parent STEP."""

    def __init__(self, parent: ParentStep, handler: Decomposition,
                 executor: SubtraceCommitment, honest: SubtraceCommitment, depth: int = 4):
        self.parent, self.handler = parent, handler
        self.executor, self.honest, self.depth = executor, honest, depth
        if depth < 1 or depth > 5:
            raise LazyRefused("reveal depth must be in 1..5")
        self.level = executor.tree.height
        self.position = 0
        self.revealed: dict[int, bytes] = {}
        self.leaf: bytes | None = None
        self.ruling: str | None = None
        self.claimed: str | None = None

    def _pickable(self, level: int, position: int) -> bool:
        return (position << level) < self.handler.count(self.parent)

    def reveal_nodes(self, hashes: dict[int, bytes]) -> None:
        if self.ruling or self.level == 0:
            raise LazyRefused("not awaiting subtrace nodes")
        d = min(self.depth, self.level)
        folded = trees.fold_reveal("lazy", self.level, self.position, d, hashes, self._pickable)
        if folded != self.executor.tree.at(self.level, self.position):
            raise LazyRefused("subtrace reveal does not fold")
        self.revealed = dict(hashes)

    def pick(self, child: int) -> None:
        if child not in self.revealed:
            raise LazyRefused("pick is not one of the revealed children")
        d = min(self.depth, self.level)
        self.level -= d
        self.position = (self.position << d) + child
        self.revealed.clear()

    def reveal_leaf(self, raw: bytes) -> None:
        if self.level != 0 or self.leaf is not None:
            raise LazyRefused("not awaiting a sub-step leaf")
        if trees.root_from_path("lazy", _h(SUBSTEP_LEAF_DOMAIN, raw), self.position,
                                self.executor.tree.path(self.position)) != self.executor.root:
            raise LazyRefused("sub-step leaf does not verify")
        self.leaf = bytes(raw)

    def claim(self, name: str, witness: SubstepWitness | None = None) -> str:
        if self.leaf is None or self.ruling is not None:
            raise LazyRefused("no sub-step leaf to claim")
        if name not in ("EDGE", "STATE", "STEP", "SHAPE", "BINDING"):
            raise LazyRefused("unknown lazy claim")
        self.claimed = name
        binding = _header_binding(self.parent, self.handler, self.executor)
        if binding:
            self.ruling = binding
            return binding
        expected = self.honest.records[self.position]
        if self.leaf == expected:
            self.ruling = "E"
            return "E"
        if name == "BINDING":
            # Header-to-parent boundaries are public and checked before a
            # sub-step. A boundary value hidden in a leaf is checked at 0/n-1.
            h = self.executor.header
            self.ruling = "C" if h.terminal_outputs_digest != values_digest(self.parent.outputs) else "E"
            return self.ruling
        if name == "SHAPE":
            self.ruling = "C" if SubstepRecord.decode(self.leaf) is None else "E"
            return self.ruling
        if witness is None:
            raise LazyRefused("sub-step claim needs a witness")
        prior = (SubstepRecord.decode(self.honest.records[self.position - 1])
                 if self.position else None)
        # The source leaf is earlier and authenticated by the same subtrace root.
        self.ruling = _step_proof(self.parent, self.handler, self.position,
                                  self.leaf, witness, prior)
        return self.ruling

    def timeout(self, silent: str) -> str:
        if self.ruling is not None or silent not in ("E", "C"):
            raise LazyRefused("invalid timeout")
        self.ruling = "C" if silent == "E" else "E"
        return self.ruling


def _subtree_nodes(commitment: SubtraceCommitment, dispute: LazyDispute) -> dict[int, bytes]:
    d = min(dispute.depth, dispute.level)
    base, first = dispute.level - d, dispute.position << d
    return {i: commitment.tree.at(base, first + i)
            for i in range(1 << d) if dispute._pickable(base, first + i)}


def honest_lazy_challenge(parent: ParentStep, handler: Decomposition,
                          executor: SubtraceCommitment, honest: SubtraceCommitment,
                          depth: int = 4) -> LazyDispute | None:
    """Use the same leftmost-differing-child strategy as the outer STEP tree."""
    if _header_binding(parent, handler, executor):
        d = LazyDispute(parent, handler, executor, honest, depth)
        d.ruling = "C"
        d.claimed = "BINDING"
        return d
    if executor.root == honest.root:
        return None
    dispute = LazyDispute(parent, handler, executor, honest, depth)
    while dispute.level:
        dispute.reveal_nodes(_subtree_nodes(executor, dispute))
        d = min(dispute.depth, dispute.level)
        base, first = dispute.level - d, dispute.position << d
        correct = {i: honest.tree.at(base, first + i) for i in dispute.revealed}
        differing = [i for i in sorted(dispute.revealed) if dispute.revealed[i] != correct[i]]
        if not differing:
            raise AssertionError("no differing sub-step under a differing root")
        dispute.pick(differing[0])
    raw = executor.records[dispute.position]
    dispute.reveal_leaf(raw)
    expected = SubstepRecord.decode(honest.records[dispute.position])
    actual = SubstepRecord.decode(raw)
    if actual is None:
        dispute.claim("SHAPE")
        return dispute
    if actual.input_digests != expected.input_digests:
        # use the honest witness only as an input-opening oracle; the referee
        # compares the committed edge to the declared producer/source.
        dispute.claim("EDGE", executor.witnesses[dispute.position])
    elif actual.prior_digest != expected.prior_digest:
        dispute.claim("STATE", executor.witnesses[dispute.position])
    else:
        dispute.claim("STEP", executor.witnesses[dispute.position])
    return dispute


# Each phase is a separate permissionless transaction in the proposed program.
PHASE_PARTY = {
    "AWAIT_SUBTRACE_ROOT": "E",
    "AWAIT_SUBTRACE_NODES": "E",
    "AWAIT_SUBTRACE_PICK": "C",
    "AWAIT_SUBSTEP_LEAF": "E",
    "AWAIT_SUBSTEP_CLAIM": "C",
    "AWAIT_SUBSTEP_OPENING": "E",
    "AWAIT_SUBSTEP_WITNESS": "C",
}


@dataclass
class LazyPhaseDeadline:
    phase: str
    deadline: int
    ruling: str | None = None

    def timeout(self, now: int) -> str:
        if self.phase not in PHASE_PARTY or now <= self.deadline or self.ruling is not None:
            raise LazyRefused("timeout is valid only after this phase deadline")
        silent = PHASE_PARTY[self.phase]
        self.ruling = "C" if silent == "E" else "E"
        return self.ruling
