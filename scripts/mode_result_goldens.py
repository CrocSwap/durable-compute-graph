#!/usr/bin/env python3
"""Mode results v1 golden vectors (design docs/design/mode-results-v1.md): the
256-byte ResultRef and its digest for each mode and scheme, a seal over a
multi-chunk state, and an out-tree opening, for the Rust mirror
(crates/dcg-program/tests/result_goldens.rs)."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from dcg import result as R
from dcg.disputes_v21 import lx, trees
from dcg.disputes_v21.run import out_leaf

OUT = Path(__file__).resolve().parents[1] / "tests/golden/dcg/result/vectors.json"
STATE_LEN = 150_000  # three seal chunks, the last one short


def state() -> bytes:
    return bytes((i * 31 + 7) % 251 for i in range(STATE_LEN))


def value_ref(i: int) -> tuple[bytes, bytes]:
    value = struct.pack("<I", 1000 + i)
    header = struct.pack("<IBHIHIHI", 40 + i, 1, 0, 1, 1, 1, 1, len(value))
    return value, header + hashlib.sha256(R.VALUE_DOMAIN + value).digest()


def build() -> dict:
    consensus = R.ConsensusBody(
        kernel_id=b"dcg-tickrej-v1\x00\x00", semantic_version=1, abi_version=3, state_schema=(0x5354, 1),
        resource_schema=(0, 0), features=0x07, halt_reason=0xBEEF, halt_cursor=10,
        input_root=bytes(range(32)), stream_root=bytes([0x33] * 32), resource_commitment=bytes(32))
    s = state()
    seal = R.seal_digest(consensus, s)
    c_ref = R.ResultRef(R.SCHEME_STATE_SEAL_V1, bytes([0xDA] * 32), bytes([0x11] * 32), seal, len(s), consensus)

    refs = [value_ref(i) for i in range(5)]
    tree = trees.build("out", [out_leaf(j, r) for j, (_, r) in enumerate(refs)])
    opt = R.OptimisticBody(template_id=bytes([0x21] * 32), run_id=bytes([0x22] * 32), root_aux=bytes([0x23] * 32),
                           challenge_window=1_500, phase_window=750, executor_bond=2_000_000,
                           challenger_bond=1_000_000, steps=40)
    o_ref = R.ResultRef(R.SCHEME_OUT_TREE_V21, bytes([0xDA] * 32), bytes([0x12] * 32), tree.root, len(refs), opt)
    lx_outputs = [b"\x01\x02", None, b"", b"lx"]
    lx_body = R.OptimisticBody(bytes([0x31] * 32), bytes([0x32] * 32), bytes([0x33] * 32), 900, 750, 5, 6, 12)
    l_ref = R.ResultRef(R.SCHEME_LX_OUTPUTS_V1, bytes([0xDA] * 32), bytes([0x13] * 32),
                        lx.outputs_digest(lx_outputs), 0, lx_body)
    for ref in (c_ref, o_ref, l_ref):
        assert R.ResultRef.decode(ref.encode()) == ref
    c_ref.open_state(s)
    o_ref.open_output(3, refs[3][1], tree.path(3))
    l_ref.open_lx_outputs(lx_outputs)
    return {
        "refs": [{"name": n, "encoded": r.encode().hex(), "digest": r.digest().hex()}
                 for n, r in (("consensus", c_ref), ("optimistic", o_ref), ("lx", l_ref))],
        "seal": {"state_len": STATE_LEN, "state_rule": "(i * 31 + 7) % 251", "seal": seal.hex()},
        "out_tree": {"values": [v.hex() for v, _ in refs], "refs": [r.hex() for _, r in refs],
                     "index": 3, "path": [p.hex() for p in tree.path(3)], "root": tree.root.hex()},
        "lx_outputs": [None if v is None else v.hex() for v in lx_outputs],
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"wrote {OUT}")
