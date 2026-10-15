"""Mode results v1 (design ``docs/design/mode-results-v1.md``): the Python
mirror of ``dcg_program::result``.

A finished computation in any mode reads into the same 256-byte result
reference: its mode, the program and account it was read from, a commitment to
its values and how that opens, and a body that says what was computed and what
its security rests on. This module has the canonical encoding and digest, the
seal over a session's final state, the openings, and readers over account
bytes for v2.1 runs and sealed sessions. The program is normative; the goldens
in ``tests/golden/dcg/result/`` pin both implementations to the same bytes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from solders.pubkey import Pubkey

from dcg.disputes_v21 import lx as _lx
from dcg.disputes_v21 import trees as _trees
from dcg.disputes_v21.run import out_leaf

RESULT_BYTES = 256
RESULT_MAGIC = b"DRR1"
RESULT_VERSION = 1
RESULT_DIGEST_DOMAIN = b"dcg.result.v1\x00"

MODE_CONSENSUS = 1
MODE_OPTIMISTIC = 2

SCHEME_OUT_TREE_V21 = 1
SCHEME_LX_OUTPUTS_V1 = 2
SCHEME_STATE_SEAL_V1 = 3

SEAL_INIT_DOMAIN = b"dcg/state-seal-init/1"
SEAL_CHUNK_DOMAIN = b"dcg/state-seal-chunk/1"
SEAL_DOMAIN = b"dcg/state-seal/1"
SEAL_CHUNK_BYTES = 65_536

VALUE_DOMAIN = b"dcg.value.v2\x00"
_BODY = 112


class ResultError(ValueError):
    """Bytes that are not a result, or a result that is not the one required.
    ``kind`` names the reason, matching ``dcg_program::result::ResultError``."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class OptimisticBody:
    template_id: bytes
    run_id: bytes
    root_aux: bytes  # generic root: spec_root; LX1: params_digest
    challenge_window: int
    phase_window: int
    executor_bond: int
    challenger_bond: int
    steps: int  # generic root: total_steps; LX1: positions


@dataclass(frozen=True)
class ConsensusBody:
    kernel_id: bytes  # 16 bytes
    semantic_version: int
    abi_version: int
    state_schema: tuple[int, int]
    resource_schema: tuple[int, int]
    features: int
    halt_reason: int
    halt_cursor: int
    input_root: bytes
    stream_root: bytes
    resource_commitment: bytes


@dataclass(frozen=True)
class ResultRef:
    scheme: int
    host: bytes
    source: bytes
    root: bytes
    count: int
    body: OptimisticBody | ConsensusBody = field(repr=False)

    @property
    def mode(self) -> int:
        return MODE_CONSENSUS if isinstance(self.body, ConsensusBody) else MODE_OPTIMISTIC

    def encode(self) -> bytes:
        head = (RESULT_MAGIC + struct.pack("<HBB", RESULT_VERSION, self.mode, self.scheme)
                + bytes(self.host) + bytes(self.source) + self.root + struct.pack("<Q", self.count))
        b = self.body
        if isinstance(b, OptimisticBody):
            body = (b.template_id + b.run_id + b.root_aux
                    + struct.pack("<QQQQQ", b.challenge_window, b.phase_window, b.executor_bond,
                                  b.challenger_bond, b.steps) + bytes(8))
        else:
            body = (b.kernel_id + struct.pack("<HHIHIHB", b.semantic_version, b.abi_version, b.state_schema[0],
                                              b.state_schema[1], b.resource_schema[0], b.resource_schema[1],
                                              b.features)
                    + bytes(3) + struct.pack("<II", b.halt_reason, b.halt_cursor) + bytes(4)
                    + b.input_root + b.stream_root + b.resource_commitment)
        out = head + body
        assert len(out) == RESULT_BYTES
        return out

    @classmethod
    def decode(cls, raw: bytes) -> ResultRef:
        raw = bytes(raw)
        if len(raw) != RESULT_BYTES or raw[:4] != RESULT_MAGIC or struct.unpack_from("<H", raw, 4)[0] != RESULT_VERSION:
            raise ResultError("Layout")
        mode, scheme = raw[6], raw[7]
        b = raw[_BODY:]
        count = struct.unpack_from("<Q", raw, 104)[0]
        if mode == MODE_OPTIMISTIC and scheme in (SCHEME_OUT_TREE_V21, SCHEME_LX_OUTPUTS_V1):
            if any(b[136:144]) or (scheme == SCHEME_LX_OUTPUTS_V1 and count != 0):
                raise ResultError("Layout")
            body: OptimisticBody | ConsensusBody = OptimisticBody(
                b[0:32], b[32:64], b[64:96], *struct.unpack_from("<QQQQQ", b, 96))
        elif mode == MODE_CONSENSUS and scheme == SCHEME_STATE_SEAL_V1:
            if any(b[33:36]) or any(b[44:48]):
                raise ResultError("Layout")
            sv, av, sid, sver, rid, rver, features = struct.unpack_from("<HHIHIHB", b, 16)
            reason, cursor = struct.unpack_from("<II", b, 36)
            body = ConsensusBody(b[0:16], sv, av, (sid, sver), (rid, rver), features, reason, cursor,
                                 b[48:80], b[80:112], b[112:144])
        else:
            raise ResultError("Layout")
        return cls(scheme, raw[8:40], raw[40:72], raw[72:104], count, body)

    def digest(self) -> bytes:
        return hashlib.sha256(RESULT_DIGEST_DOMAIN + self.encode()).digest()

    # --- openings ------------------------------------------------------------------------------

    def open_output(self, index: int, value_ref: bytes, path: list[bytes]) -> None:
        """``OUT_TREE_V21``: the 55-byte value reference is output ``index`` under the root."""
        if (self.scheme != SCHEME_OUT_TREE_V21 or index >= self.count or len(value_ref) != 55
                or len(path) != tree_height(self.count)):
            raise ResultError("Opening")
        acc, pos = out_leaf(index, value_ref), index
        for level, sibling in enumerate(path):
            acc = _trees.node("out", level, sibling, acc) if pos & 1 else _trees.node("out", level, acc, sibling)
            pos >>= 1
        if acc != self.root:
            raise ResultError("Opening")

    def open_lx_outputs(self, outputs: list[bytes | None]) -> None:
        if self.scheme != SCHEME_LX_OUTPUTS_V1 or _lx.outputs_digest(outputs) != self.root:
            raise ResultError("Opening")

    def open_state(self, state: bytes) -> None:
        if (not isinstance(self.body, ConsensusBody) or self.scheme != SCHEME_STATE_SEAL_V1
                or len(state) != self.count or seal_digest(self.body, state) != self.root):
            raise ResultError("Opening")


def tree_height(count: int) -> int:
    return (max(count, 1) - 1).bit_length()


def plain_value_matches(value_ref: bytes, value: bytes) -> bool:
    return (struct.unpack_from("<I", value_ref, 19)[0] == len(value)
            and hashlib.sha256(VALUE_DOMAIN + value).digest() == value_ref[23:55])


def seal_digest(c: ConsensusBody, state: bytes) -> bytes:
    """The seal over a session's final state (design §3.2)."""
    tail = (c.input_root + c.kernel_id + struct.pack("<IH", *c.state_schema)
            + struct.pack("<II", c.halt_cursor, len(state)))
    acc = hashlib.sha256(SEAL_INIT_DOMAIN + tail).digest()
    for offset in range(0, len(state), SEAL_CHUNK_BYTES):
        acc = hashlib.sha256(SEAL_CHUNK_DOMAIN + acc + struct.pack("<I", offset)
                             + state[offset:offset + SEAL_CHUNK_BYTES]).digest()
    return hashlib.sha256(SEAL_DOMAIN + acc + tail).digest()


# --- readers ------------------------------------------------------------------------------------

def _u32(d: bytes, at: int) -> int:
    return struct.unpack_from("<I", d, at)[0]


def _u64(d: bytes, at: int) -> int:
    return struct.unpack_from("<Q", d, at)[0]


def read_run_result(host: Pubkey, run: tuple[Pubkey, Pubkey, bytes],
                    template: tuple[Pubkey, Pubkey, bytes]) -> ResultRef:
    """A FINAL v2.1 run's result from (key, owner, data) of the run (live or
    receipt) and its template (``docs/spec/run-read-layout-v21.md``)."""
    (run_key, run_owner, r), (template_key, template_owner, t) = run, template
    r, t = bytes(r), bytes(t)
    if run_owner != host or template_owner != host:
        raise ResultError("Owner")
    if r[:4] == b"D21R":
        if len(r) < 368 or r[5] not in (0, 1):
            raise ResultError("Layout")
        trailer = 4 if r[5] == 0 else 36
        if len(r) != 368 + 52 * _u32(r, 156) + trailer:
            raise ResultError("Layout")
        root_at = 192
    elif r[:4] == b"D21P" and len(r) == 312:
        root_at = 136
    else:
        raise ResultError("Layout")
    run_id = r[104:136]
    if Pubkey.find_program_address([b"dcg21run", run_id, r[40:72]], host)[0] != run_key:
        raise ResultError("Address")
    if r[8:40] != bytes(template_key) or len(t) < 168 or t[:4] != b"D21T":
        raise ResultError("Template")
    if r[4] != 2:
        raise ResultError("NotFinal")
    root = r[root_at:root_at + 176]
    lx = t[5] == 1
    if (root[0:32] if lx else root[32:64]) != run_id:
        raise ResultError("Layout")
    if lx:
        scheme, value_root, count, aux, steps = SCHEME_LX_OUTPUTS_V1, root[64:96], 0, root[96:128], _u64(root, 128)
    else:
        scheme, value_root, count, aux, steps = SCHEME_OUT_TREE_V21, root[144:176], _u64(root, 136), root[64:96], _u64(root, 96)
    body = OptimisticBody(t[96:128], run_id, aux, _u64(t, 24), _u64(t, 32), _u64(t, 40), _u64(t, 48), steps)
    return ResultRef(scheme, bytes(host), bytes(run_key), value_root, count, body)


def read_session_result(host: Pubkey, key: Pubkey, owner: Pubkey, raw: bytes) -> ResultRef:
    """A sealed session's result from its record bytes. Checks the owner, the
    record form, the address, a kernel halt and the seal; the program checks
    the rest of the record when it writes it."""
    raw = bytes(raw)
    if owner != host:
        raise ResultError("Owner")
    if (len(raw) != 1280 or raw[:4] != b"DSS3" or struct.unpack_from("<H", raw, 4)[0] != 3
            or struct.unpack_from("<IH", raw, 106) != (0x434F_4E53, 3) or raw[1278] & ~3 or raw[1279]):
        raise ResultError("Layout")
    sealed, trimmed = raw[1278] & 1, raw[1278] & 2
    # The program's record rules for the flags (decode_session).
    if (sealed or trimmed) and raw[6] != 2:
        raise ResultError("Layout")
    if sealed and (raw[1164] != 0 or _u32(raw, 1254) == 0 or _u32(raw, 188) != _u32(raw, 1258)):
        raise ResultError("Layout")
    authority, sid, bump = raw[22:54], raw[14:22], raw[1262]
    try:
        derived = Pubkey.create_program_address([b"dcg-session-v3", authority, sid, bytes([bump])], host)
    except Exception as e:  # off-curve failures surface as errors
        raise ResultError("Address") from e
    if derived != key or raw[228:260] != bytes(key):
        raise ResultError("Address")
    if raw[6] != 2:
        raise ResultError("NotHalted")
    if _u32(raw, 1254) == 0:
        raise ResultError("NoKernelVerdict")
    if not sealed:
        raise ResultError("NotSealed")
    if trimmed:
        raise ResultError("Trimmed")
    sv, av = struct.unpack_from("<HH", raw, 102)
    body = ConsensusBody(
        kernel_id=raw[86:102], semantic_version=sv, abi_version=av,
        state_schema=struct.unpack_from("<IH", raw, 1183), resource_schema=struct.unpack_from("<IH", raw, 1124),
        features=raw[1273], halt_reason=_u32(raw, 1254), halt_cursor=_u32(raw, 1258),
        input_root=raw[156:188], stream_root=raw[124:156], resource_commitment=raw[1132:1164],
    )
    return ResultRef(SCHEME_STATE_SEAL_V1, bytes(host), bytes(key), raw[192:224], _u32(raw, 224), body)
