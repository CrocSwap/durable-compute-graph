"""Instruction bodies for the tag-227 program (the skeleton's wire format).

The Python referee and challenger produce moves as values; these encoders
turn them into the exact bytes the program reads (see `disputes_v21.rs`,
`claim`). Scenario generators use them so that Python is the reference for
the encoding as well as the rulings.
"""

from __future__ import annotations

import struct

from . import spec as S

TEMPLATE_DOMAIN = b"dcg.template.id.v2.1-skeleton\x00"


def template_data(sp: S.Spec, depth: int, plan_id: bytes, *, challenge_window: int = 1_000, phase_window: int = 750,
                  executor_bond: int = 2_000_000, challenger_bond: int = 1_000_000, slasher_bps: int = 5_000,
                  with_blocks: bool = True) -> bytes:
    data = bytes([depth])
    for x in (sp.total_steps, sp.total_outputs, challenge_window, phase_window, executor_bond, challenger_bond):
        data += struct.pack("<Q", x)
    data += struct.pack("<II", sp.first_out_record, sp.first_step_record) + sp.root
    data += struct.pack("<H", slasher_bps) + plan_id
    if with_blocks:
        data += bytes([len(sp.blocks)]) + b"".join(b.record() for b in sp.blocks)
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
        pk = S.decode_producer(d["inputs"][kw["index"]][1])[0]
        if pk == 1:
            return body + step_opening(kw["producer_opening"])
        if pk == 5:
            return body + chunk_opening(kw["chunk_opening"])
        if pk == 6:
            return body + last_running(kw)
        return body
    if name == "STATE":
        pk = S.decode_producer(d["state_predecessor"])[0]
        return body + (step_opening(kw["producer_opening"]) if pk == 1 else b"")
    if name == "STEP":
        out = bytes([len(kw["witness"])]) + b"".join(struct.pack("<I", len(v)) + v for v in kw["witness"])
        if d["state_scheme"]:
            out += struct.pack("<I", len(kw["state_witness"])) + kw["state_witness"]
        return body + out
    raise ValueError(name)


def leaf_body(preimage: bytes | None) -> bytes:
    return bytes([preimage is not None]) + (preimage or b"")
