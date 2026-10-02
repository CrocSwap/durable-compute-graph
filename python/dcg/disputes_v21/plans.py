"""Build multi-block dispute specs: enumerated blocks and repeated blocks
with gates, producer kinds 1 to 7, SMALL state and chunked external inputs
(design §3, §4.2, §4.3, §5). This is the chunked-kernel slice.

A *chunked kernel* is `chunked_reduce`: a repeated block of one stateful step
per chunk of a chunked input, its running partial in SMALL state, exported on
port 0, with the block's gate on port 1. Later steps and graph outputs read
the result through kind 6 (the last running iteration).

The builder writes body entries directly instead of lowering a body DCGG, so
`parameter_digest` and `port_shapes_digest` are zero here, as for traced
kernels without parameters.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from dcg.graph import v2 as wire

from . import reductions
from . import spec as S
from . import trees

ROOT_MODE_ID, SCHEME_ID, SCHEME_VERSION = 1330664521, 2, 1
ROOT_REGION = wire.RegionV1(0, wire.ROOT_PARENT, ROOT_MODE_ID, 1, SCHEME_ID, SCHEME_VERSION, 1, 1, b"", b"", b"")


def scalar_header(node: int, direction: int, port: int) -> bytes:
    return S.port_header(node, direction, port, S.LAYOUT_SCALAR, 1, SCHEME_ID, SCHEME_VERSION, 4)


def raw_header(node: int, direction: int, port: int, length: int) -> bytes:
    return S.port_header(node, direction, port, S.LAYOUT_RAW, 1, SCHEME_ID, SCHEME_VERSION, length)


@dataclass(frozen=True)
class Input:
    producer: bytes  # 24
    length: int  # bytes the consumer reads
    scalar: bool = False  # i32 scalar layout, else raw bytes
    initial: bytes = S.NO_PRODUCER  # kind 4 only


@dataclass(frozen=True)
class Step:
    kernel: str | bytes  # a registered name, or an exact 16-byte application kernel id
    inputs: tuple[Input, ...]
    # (port, length, scalar) per output, in port order
    outputs: tuple[tuple[int, int, bool], ...]
    state_bytes: int = 0
    state_predecessor: bytes = S.NO_PRODUCER  # kind 1/4, or the initial producer when first
    state_initial: bytes = S.NO_PRODUCER  # kind 2, or kind 0 for EMPTY_STATE
    state_export: int = 0xFF
    log: tuple[int, int] | None = None  # (entry_bytes, capacity): LOG state instead of SMALL


@dataclass
class PlanBuilder:
    inputs: dict[int, tuple[int, int]] = field(default_factory=dict)  # eid -> (length, chunk_log2)
    constants: dict[int, tuple[bytes, int]] = field(default_factory=dict)  # id -> (value, chunk_log2)
    blocks: list[tuple] = field(default_factory=list)  # ("enum", [Step]) | ("rep", [Step], K, gate)
    outputs: list[tuple[bytes, int, bool]] = field(default_factory=list)  # (producer, length, scalar)
    node_base: int = 1

    # --- declarations --------------------------------------------------------------
    def scalar_input(self, eid: int) -> bytes:
        self.inputs[eid] = (4, 0)
        return S.producer(2, eid)

    def raw_input(self, eid: int, length: int) -> bytes:
        """A plain external input of `length` raw bytes (layout 5)."""
        self.inputs[eid] = (length, -1)
        return S.producer(2, eid)

    def chunked_input(self, eid: int, length: int, chunk_log2: int) -> int:
        if not 6 <= chunk_log2 <= 16:
            raise S.SpecError("chunk_log2 must be 6..16")
        if length % (1 << chunk_log2):
            raise S.SpecError("this slice reads whole chunks only")
        self.inputs[eid] = (length, chunk_log2)
        return eid

    def committed_constant(self, cid: int, value: bytes, chunk_log2: int = 0) -> int:
        """A committed (non-resident) constant (design §4.2, §5.1). Chunked
        (`chunk_log2` 6..16): its ConstSpec carries the chunk-tree root and
        steps read whole chunks by kind 5 with source 3. Plain (0): raw
        bytes with the plain value digest, read whole by kind 3. The locator
        is the SHA-256 of the bytes."""
        if not value or (chunk_log2 and (not 6 <= chunk_log2 <= 16 or len(value) % (1 << chunk_log2))):
            raise S.SpecError("a chunked constant is whole chunks of 2^6..2^16 bytes")
        self.constants[cid] = (value, chunk_log2)
        return cid

    def chunked_reduce_const(self, kernel: str, cid: int, extra: tuple["Input", ...] = ()) -> int:
        """A chunked kernel whose iteration i reads chunk i of constant `cid`."""
        value, chunk_log2 = self.constants[cid]
        chunk_bytes = 1 << chunk_log2
        kern = reductions.REGISTRY[kernel]
        step = Step(kernel=kernel, inputs=(Input(S.producer(5, cid, 3, 1, 0), chunk_bytes),) + extra,
                    outputs=((0, kern.state_bytes, False), (1, 4, True)), state_bytes=kern.state_bytes,
                    state_predecessor=S.producer(4, 0, 0, 1), state_export=0)
        return self.repeated([step], len(value) // chunk_bytes, (0, 1))

    def enumerated(self, steps: list[Step]) -> int:
        self.blocks.append(("enum", steps))
        return len(self.blocks) - 1

    def repeated(self, body: list[Step], k: int, gate: tuple[int, int]) -> int:
        self.blocks.append(("rep", body, k, gate))
        return len(self.blocks) - 1

    def output(self, producer: bytes, length: int, scalar: bool = False) -> None:
        self.outputs.append((producer, length, scalar))

    def chunked_reduce(self, kernel: str, eid: int, extra: tuple[Input, ...] = ()) -> int:
        """One chunked kernel: iteration i reads chunk i of input `eid` (kind 5)."""
        length, chunk_log2 = self.inputs[eid]
        chunk_bytes = 1 << chunk_log2
        k = length // chunk_bytes
        kern = reductions.REGISTRY[kernel]
        step = Step(
            kernel=kernel,
            inputs=(Input(S.producer(5, eid, 2, 1, 0), chunk_bytes),) + extra,
            outputs=((0, kern.state_bytes, False), (1, 4, True)),
            state_bytes=kern.state_bytes,
            state_predecessor=S.producer(4, 0, 0, 1),  # entry 0, lag 1
            state_initial=S.NO_PRODUCER,  # EMPTY_STATE
            state_export=0,
        )
        return self.repeated([step], k, (0, 1))

    # --- derivation ------------------------------------------------------------------
    def build(self) -> S.Spec:
        shapes, bases, base = [], [], 0
        for blk in self.blocks:
            if blk[0] == "enum":
                shapes.append((1, len(blk[1]), 0))
                bases.append(base)
                base += len(blk[1])
            else:
                shapes.append((2, len(blk[1]), blk[2]))
                bases.append(base)
                base += len(blk[1]) * blk[2]
        total_steps = base
        placement, height = S.place_blocks(shapes)
        in_ids = sorted(self.inputs)
        in_records = []
        for eid in in_ids:
            length, chunk_log2 = self.inputs[eid]
            if chunk_log2 > 0:
                header = S.port_header(0, 0, 0, S.LAYOUT_CHUNKED, chunk_log2, SCHEME_ID, SCHEME_VERSION, length)
            elif chunk_log2 < 0:
                header = raw_header(0, 0, 0, length)
            else:
                header = scalar_header(0, 0, 0)
            in_records.append(S.in_spec(eid, header, max(chunk_log2, 0)))
        const_ids = sorted(self.constants)
        const_records = []
        for cid in const_ids:
            value, chunk_log2 = self.constants[cid]
            from . import run as R
            if chunk_log2:
                header = S.port_header(0, 0, 0, S.LAYOUT_CHUNKED, chunk_log2, SCHEME_ID, SCHEME_VERSION, len(value))
                digest = R.chunked_digest(value, 1 << chunk_log2)
            else:
                header = raw_header(0, 0, 0, len(value))
                digest = R.value_digest(value)
            const_records.append(S.const_spec(cid, header, 2, 1, digest, hashlib.sha256(value).digest()))
        first_out = 1 + len(self.blocks) + len(const_records) + len(in_records)
        regions = [ROOT_REGION]
        first_block_record = first_out + len(self.outputs) + len(regions)
        node = self.node_base
        blocks, block_records, out_records = [], [], []
        record_at = first_block_record
        for bi, blk in enumerate(self.blocks):
            steps = blk[1]
            magic = b"DSS1" if blk[0] == "enum" else b"DSB1"
            records = []
            for e, st in enumerate(steps):
                records.append(self._step_record(st, magic, node, bi))
                node += 1
            addr_base, addr_height = placement[bi]
            if blk[0] == "enum":
                b = S.Block(1, bases[bi], len(steps), 0, 0, 0, 0, record_at, len(steps), addr_base, addr_height)
            else:
                _tag, body, k, (g, q) = blk
                b = S.Block(2, bases[bi], k * len(body), k, len(body), g, q, record_at, len(body), addr_base,
                            addr_height)
            blocks.append(b)
            block_records.append(records)
            record_at += len(records)
        for prod, length, scalar in self.outputs:
            header = scalar_header(0, 1, 0) if scalar else raw_header(0, 1, 0, length)
            out_records.append(S.out_spec(header, prod))
        spec_records = [(S.TYPE_HEADER, S.spec_header(len(blocks), len(const_records), len(in_records), len(out_records), 0,
                                                       len(regions), total_steps, len(out_records)))]
        spec_records += [(S.TYPE_BLOCK, b.record()) for b in blocks]
        spec_records += [(S.TYPE_CONST, r) for r in const_records]
        spec_records += [(S.TYPE_IN, r) for r in in_records]
        spec_records += [(S.TYPE_OUT, r) for r in out_records]
        spec_records += [(S.TYPE_REGION, S.region_spec(r)) for r in regions]
        for b, records in zip(blocks, block_records):
            code = S.TYPE_STEP if b.kind == 1 else S.TYPE_BODY
            spec_records += [(code, r) for r in records]
        sp = S.Spec(spec_records, blocks, block_records, dict(zip(in_ids, in_records)), out_records, total_steps,
                    len(out_records), height, first_out, dict(zip(const_ids, const_records)),
                    {cid: self.constants[cid][0] for cid in const_ids})
        self._check(sp)
        return sp

    def _step_record(self, st: Step, magic: bytes, node: int, block: int) -> bytes:
        inputs = []
        for port, inp in enumerate(st.inputs):
            header = scalar_header(node, 0, port) if inp.scalar else raw_header(node, 0, port, inp.length)
            inputs.append(S.StepInput(header, inp.producer, inp.initial))
        outputs = tuple(scalar_header(node, 1, port) if scalar else raw_header(node, 1, port, length)
                        for port, length, scalar in st.outputs)
        return S.StepSpec(
            region_id=0, dcpl_segment_id=block, node_id=node, kernel_step=1,
            kernel_id=(st.kernel if isinstance(st.kernel, bytes) else
                       reductions.kernel_id(st.kernel) if st.kernel in reductions.REGISTRY
                       or st.kernel in reductions.LOG_REGISTRY else
                       (st.kernel + "/v1").encode().ljust(16, b"\x00")),
            semantic_version=1, abi_version=1, decomposition_id=0, decomposition_version=0, max_cu=400_000,
            parameter_digest=bytes(32), port_shapes_digest=bytes(32), inputs=tuple(inputs), outputs=outputs,
            state_scheme=2 if st.log else 1 if st.state_bytes else 0, state_export_port=st.state_export,
            state_unit=st.log[0] if st.log else 0, state_size=st.log[1] if st.log else st.state_bytes,
            state_predecessor=st.state_predecessor, state_initial=st.state_initial,
            magic=magic).encode()

    # --- admission checks (§3.3, a subset: the ones this slice can violate) -------------
    def _check(self, sp: S.Spec) -> None:
        for k in range(sp.total_steps):
            bi, b, i, _e = sp.locate(k)
            d = S.decode_step_spec(sp.step_spec(k))
            for header, prod, _init in d["inputs"]:
                kind, a, pb, _c, dd = S.decode_producer(prod)
                if kind == 1 and a >= k:
                    raise S.SpecError("a producer is not earlier")
                if kind == 1 and b.kind == 2 and not (a < b.base or b.base <= a < k):
                    raise S.SpecError("kind 1 inside a body must precede the block")
                if kind == 6 and a >= bi:
                    raise S.SpecError("kind 6 must name an earlier block")
                if kind == 5:
                    length, chunk_log2 = self.inputs[a] if pb == 2 else (len(self.constants[a][0]), self.constants[a][1])
                    if dd >= length >> chunk_log2:
                        raise S.SpecError("chunk index out of range")
                    if struct.unpack_from("<I", header, 19)[0] != 1 << chunk_log2:
                        raise S.SpecError("chunk consumer reads a different length")
                if kind == 2 and a not in self.inputs:
                    raise S.SpecError("unknown external input")
        if sp.address_height > 40:
            raise S.SpecError("step tree too tall")
        _ = trees  # tree shapes are fixed by place_blocks
