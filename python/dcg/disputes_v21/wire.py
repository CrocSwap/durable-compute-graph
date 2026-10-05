"""Instruction bodies for the tag-227 program (the skeleton's wire format).

The Python referee and challenger produce moves as values; these encoders
turn them into the exact bytes the program reads (see `disputes_v21.rs`,
`claim`). Scenario generators use them so that Python is the reference for
the encoding as well as the rulings.
"""

from __future__ import annotations

import struct

from . import spec as S
from . import trees

TEMPLATE_DOMAIN = b"dcg.template.id.v2.1-skeleton\x00"
ROLE_EXECUTOR, ROLE_CHALLENGER = 1, 2
FROM_STAGING = 0xFF
MAX_STAGE = 128 * 1024
MAX_STAGE_GROW = 10_240


#: The program's floor on a phase window, in slots (admission, §5.3).
MIN_PHASE_WINDOW = 750
#: Staged-witness upload rate on Fogo testnet: 64 KiB in about 51 s
#: (measured 2026-10-03). Slots there are about 40 ms (measured 2026-10-05).
TESTNET_UPLOAD_BYTES_PER_S = 1_285
TESTNET_SLOT_MS = 40.0


def largest_step_witness(sp: S.Spec) -> int:
    """The most bytes a STEP claim on this plan stages as its witness: the
    step's declared input lengths (one chunk for a chunked input) plus its
    state. Openings and proofs add a few hundred bytes, covered by the
    fixed allowance in `phase_window_for`."""
    most = 0
    for k in range(sp.total_steps):
        d = S.decode_step_spec(sp.step_spec(k))
        size = sum(struct.unpack_from("<I", header, 19)[0] for header, _prod, _ in d["inputs"]) + d["state_size"]
        most = max(most, size)
    return most


def phase_window_for(witness_bytes: int, *, slot_ms: float = TESTNET_SLOT_MS,
                     bytes_per_s: float = TESTNET_UPLOAD_BYTES_PER_S, fixed_s: float = 10.0,
                     margin: float = 1.5) -> int:
    """Slots a phase needs so a party can stage `witness_bytes` and send its
    move in time: (fixed allowance + upload time) times a margin, and never
    below the program's floor (alpha plan E4)."""
    seconds = (fixed_s + witness_bytes / bytes_per_s) * margin
    return max(MIN_PHASE_WINDOW, int(-(-seconds * 1000 // slot_ms)))


def template_data(sp: S.Spec, depth: int, plan_id: bytes, *, challenge_window: int = 1_000, phase_window: int = 750,
                  executor_bond: int = 2_000_000, challenger_bond: int = 1_000_000, slasher_bps: int = 5_000,
                  with_blocks: bool = True, slot_ms: float | None = TESTNET_SLOT_MS) -> bytes:
    """A tag-227 template. Refuses a phase window too short to stage the
    plan's largest STEP witness at `slot_ms` (see `phase_window_for`);
    ``slot_ms=None`` skips that check."""
    if slot_ms is not None:
        needed = phase_window_for(largest_step_witness(sp), slot_ms=slot_ms)
        if phase_window < needed:
            raise ValueError(f"phase_window {phase_window} slots is too short to stage this plan's largest STEP "
                             f"witness ({largest_step_witness(sp)} bytes); use at least {needed} "
                             f"(phase_window_for, at {slot_ms} ms per slot)")
    data = bytes([depth])
    for x in (sp.total_steps, sp.total_outputs, challenge_window, phase_window, executor_bond, challenger_bond):
        data += struct.pack("<Q", x)
    data += struct.pack("<II", sp.first_out_record, sp.first_step_record) + sp.root
    data += struct.pack("<H", slasher_bps) + plan_id
    # Canonical form (program, owner 10-05): a lone block equal to the default
    # block (one enumerated block over every step) is written as no blocks,
    # so one template has one id.
    default = S.block_spec(1, 0, sp.total_steps, 0, 0, 0, 0, sp.first_step_record, sp.total_steps, 0,
                           trees.height_for(sp.total_steps))
    if with_blocks and not (len(sp.blocks) == 1 and sp.blocks[0].record() == default):
        data += bytes([len(sp.blocks)]) + b"".join(b.record() for b in sp.blocks)
    # Spec openings identify ListSpecs by their authenticated record type/id;
    # there is no separate caller-supplied first-list boundary in a template.
    return data


def path_bytes(path: list[bytes]) -> bytes:
    return bytes([len(path)]) + b"".join(path)


def spec_opening(opening) -> bytes:
    type_code, record, path = opening
    return bytes([type_code]) + struct.pack("<H", len(record)) + record + path_bytes(path)


def step_opening(opening) -> bytes:
    preimage, path = opening
    body = preimage or b""
    return bytes([preimage is not None]) + struct.pack("<H", len(body)) + body + path_bytes(path)


def chunk_opening(opening) -> bytes:
    chunk, path = opening
    return struct.pack("<H", len(chunk)) + chunk + path_bytes(path)


def const_opening(sp: S.Spec, producer: bytes, opening) -> bytes:
    """`leaf_index:u32` and the spec opening of the producer's ConstSpec."""
    cid = S.decode_producer(producer)[1]
    return struct.pack("<I", sp.const_leaf_index(cid)) + spec_opening(opening)


def gate_value(value: bytes | None) -> bytes:
    v = value or b""
    return bytes([len(v)]) + v


def last_running(kw: dict) -> bytes:
    out = struct.pack("<I", kw["t"]) + step_opening(kw["producer_opening"])
    if kw.get("gate_opening") is not None:
        out += step_opening(kw["gate_opening"]) + gate_value(kw.get("gate_value"))
    return out


CLAIM_CODES = {"SHAPE": 1, "EDGE": 2, "STEP": 3, "OUT": 4, "GATE": 5, "STATE": 6}


def claim_body(sp: S.Spec, kind: str, position: int, name: str, kw: dict) -> bytes:
    """The claim instruction body for a dispute at `position` (a step-tree
    position for STEP_DESCEND, an out index for OUT_DESCEND)."""
    body = bytes([CLAIM_CODES[name], kw.get("index", 0)]) + spec_opening(kw["spec_opening"])
    if name == "OUT":
        pk = S.decode_producer(sp.out_specs[position][32:56])[0]
        return body + (last_running(kw) if pk == 6 else step_opening(kw["producer_opening"]))
    k = sp.ordinal_at(position)
    d = S.decode_step_spec(sp.step_spec(k))
    if name == "SHAPE":
        return body
    if name == "GATE":
        return body + step_opening(kw["gate_opening"]) + gate_value(kw.get("gate_value"))
    if name == "EDGE":
        producer = d["inputs"][kw["index"]][1]
        pk, list_id, *_ = S.decode_producer(producer)
        if pk == S.PRODUCER_LIST:
            ek = S.decode_producer(S.decode_list_spec(sp.list_specs[list_id])[1][kw["element"]][1])[0]
            out = bytes([kw["element"]]) + struct.pack("<I", sp.list_leaf_index(list_id))
            out += spec_opening(kw["list_opening"])
            if ek == 1:
                out += step_opening(kw["producer_opening"])
            elif ek == 3:
                out += const_opening(sp, S.decode_list_spec(sp.list_specs[list_id])[1][kw["element"]][1],
                                     kw["const_opening"])
            return body + out
        if pk == 1:
            return body + step_opening(kw["producer_opening"])
        if pk == 3:
            return body + const_opening(sp, d["inputs"][kw["index"]][1], kw["const_opening"])
        if pk == 5:
            pre = (const_opening(sp, d["inputs"][kw["index"]][1], kw["const_opening"])
                   if kw.get("const_opening") is not None else b"")
            return body + pre + chunk_opening(kw["chunk_opening"])
        if pk == 6:
            return body + last_running(kw)
        return body
    if name == "STATE":
        pk = S.decode_producer(d["state_predecessor"])[0]
        return body + (step_opening(kw["producer_opening"]) if pk == 1 else b"")
    if name == "STEP":
        if len(kw["witness"]) != len(d["inputs"]):
            raise ValueError("STEP witness count must match the step inputs")
        out = bytes([len(kw["witness"])])
        for (_header, producer, _initial), value in zip(d["inputs"], kw["witness"]):
            values = value if S.decode_producer(producer)[0] == S.PRODUCER_LIST else [value]
            for v in values:
                out += struct.pack("<I", len(v)) + v
        if d["state_scheme"]:
            out += struct.pack("<I", len(kw["state_witness"])) + kw["state_witness"]
        return body + out
    raise ValueError(name)


def leaf_body(preimage: bytes | None, lists: dict[int, list[bytes]] | None = None) -> bytes:
    """Encode E's leaf reveal. List refs use a staged-only LVR1 envelope so
    claims can reread and reauthenticate them without enlarging disputes."""
    if lists is None:
        return bytes([preimage is not None]) + (preimage or b"")
    if preimage is None and lists:
        raise ValueError("an absent leaf cannot reveal list refs")
    leaf = preimage or b""
    out = b"LVR1" + bytes([preimage is not None]) + struct.pack("<H", len(leaf)) + leaf
    out += bytes([len(lists)])
    for input_index, refs in sorted(lists.items()):
        if not 0 <= input_index < 8 or not 1 <= len(refs) <= S.MAX_LIST_ELEMENTS:
            raise ValueError("invalid list reveal")
        if any(len(ref) != 55 for ref in refs):
            raise ValueError("each list ref is 55 bytes")
        out += bytes([input_index, len(refs)]) + b"".join(refs)
    return out


def stage_create_body(role: int, size: int = 0) -> bytes:
    """Tag-227 SUB_STAGE_CREATE body. E's first allocation is fixed at 10 KiB;
    C supplies its requested capacity in bytes."""
    if role not in (ROLE_EXECUTOR, ROLE_CHALLENGER):
        raise ValueError("unknown staging role")
    if role == ROLE_EXECUTOR:
        size = 0
    elif not 1 <= size <= 10_192:
        raise ValueError("challenger stage size must be 1..10192")
    return bytes([role]) + struct.pack("<I", size)


def stage_grow_body(add: int) -> bytes:
    if not 1 <= add <= MAX_STAGE_GROW:
        raise ValueError("stage growth must be 1..10240 bytes")
    return struct.pack("<I", add)


def stage_write_bodies(payload: bytes, chunk_bytes: int = 900) -> list[bytes]:
    """Return offset-prefixed SUB_STAGE_WRITE bodies for one staged payload."""
    if not 1 <= chunk_bytes <= 1_200 or len(payload) > MAX_STAGE:
        raise ValueError("invalid staging payload or transaction chunk size")
    return [struct.pack("<I", offset) + payload[offset:offset + chunk_bytes]
            for offset in range(0, len(payload), chunk_bytes)]
