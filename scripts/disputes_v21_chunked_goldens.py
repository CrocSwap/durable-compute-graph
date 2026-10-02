#!/usr/bin/env python3
"""Golden vectors for v2.1 chunked kernels (tests/golden/dcg/disputes_v21/chunked.json).

Pins, per plan: spec records, blocks, the address map (positions, ordinals,
pickability at every level), generated StepSpecs, honest leaves and roots.
Also pins the reduction kernels' replay. The Rust crate and program must
reproduce every value. Regenerate only with a design change.
"""
from __future__ import annotations

import importlib.util
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from dcg.disputes_v21 import reductions as K  # noqa: E402
from dcg.disputes_v21 import run as R  # noqa: E402

OUT = ROOT / "tests/golden/dcg/disputes_v21/chunked.json"
_t = importlib.util.spec_from_file_location("t", ROOT / "python/tests/test_disputes_v21_chunked.py")
T = importlib.util.module_from_spec(_t)
_t.loader.exec_module(T)


def plan_vector(name, sp, values):
    refs, run, honest, _ = T.setup(sp, values)
    H = sp.address_height
    return {
        "name": name,
        "values": {str(e): v.hex() for e, v in values.items()},
        "external_refs": {str(e): r.hex() for e, r in refs.items()},
        "run_id": run.hex(),
        "spec_records": [[t, r.hex()] for t, r in sp.records],
        "spec_root": sp.root.hex(),
        "blocks": [[b.kind, b.base, b.step_count, b.k, b.body_len, b.gate_entry, b.gate_port, b.first_record,
                    b.record_count, b.address_base, b.address_height] for b in sp.blocks],
        "total_steps": sp.total_steps, "address_height": H,
        "positions": [sp.position_of(k) for k in range(sp.total_steps)],
        "ordinal_at": [-1 if sp.ordinal_at(p) is None else sp.ordinal_at(p) for p in range(1 << H)],
        "pickable": ["".join("1" if sp.pickable(l, p) else "0" for p in range(1 << (H - l))) for l in range(H + 1)],
        "step_specs": [sp.step_spec(k).hex() for k in range(sp.total_steps)],
        "step_leaf_index": [sp.step_leaf_index(k) for k in range(sp.total_steps)],
        "leaves": [None if x is None else x.hex() for x in honest.leaves],
        "out_entries": [x.hex() for x in honest.out_entries],
        "step_root": honest.step_tree.root.hex(), "out_root": honest.out_tree.root.hex(),
        "run_root_bytes": honest.root_bytes.hex(),
        "last_running": {str(b): t for b, t in honest.last_running.items()},
        "states": {str(k): v.hex() for k, v in honest.states.items()},
    }


def kernel_vectors(rng):
    out = []
    for _ in range(40):
        name = rng.choice(["sumchunk_i32", "argmax_i32c", "scan_i32c", "head_i32"])
        n = rng.choice([1, 4, 16])
        chunk = struct.pack(f"<{n}i", *[rng.randint(-9, 9) for _ in range(n)])
        it = struct.pack("<I", rng.randint(0, 5))
        k = K.REGISTRY[name]
        inputs = {"sumchunk_i32": [chunk], "argmax_i32c": [chunk, it], "head_i32": [chunk],
                  "scan_i32c": [chunk, it, chunk[4 * rng.randrange(n):][:4]]}[name]
        prior = bytes(k.state_bytes) if rng.random() < 0.5 else bytes(rng.randrange(256) for _ in range(k.state_bytes))
        result = R.replay_step(K.kernel_id(name), inputs, prior if k.state_bytes else None)
        out.append({"kernel": K.kernel_id(name).hex(), "inputs": [x.hex() for x in inputs],
                    "prior": prior.hex() if k.state_bytes else None,
                    "outputs": None if result is None else [x.hex() for x in result[0]],
                    "next": None if result is None or result[1] is None else result[1].hex()})
    # Refusals: i64 overflow, a ragged chunk, a wrong arity.
    big = struct.pack("<q", (1 << 63) - 1)
    for name, inputs, prior in (("sumchunk_i32", [struct.pack("<i", 1)], big),
                                ("sumchunk_i32", [b"\x01\x02\x03"], bytes(8)),
                                ("argmax_i32c", [struct.pack("<i", 1)], bytes(12))):
        result = R.replay_step(K.kernel_id(name), inputs, prior)
        assert result is None
        out.append({"kernel": K.kernel_id(name).hex(), "inputs": [x.hex() for x in inputs], "prior": prior.hex(),
                    "outputs": None, "next": None})
    return out


def rowdot_vectors():
    rng = random.Random(64)
    out = []
    # (row, width, magnitude): two in range, an i64 overflow, a row past 63.
    for i, n, m in ((0, 16, 1 << 20), (63, 4, 1 << 31), (5, 16, 1 << 31), (64, 16, 9)):
        if i == 5:  # all maximal: 16 products of about 2^62 overflow i64
            w = x = struct.pack(f"<{n}i", *[(1 << 31) - 1] * n)
        else:
            w = struct.pack(f"<{n}i", *[rng.randint(-m, m - 1) for _ in range(n)])
            x = struct.pack(f"<{n}i", *[rng.randint(-m, m - 1) for _ in range(n)])
        prior = bytes(rng.randrange(256) for _ in range(512))
        inputs = [w, x, struct.pack("<I", i)]
        result = R.replay_step(K.kernel_id("rowdot_i32c"), inputs, prior)
        out.append({"kernel": K.kernel_id("rowdot_i32c").hex(), "inputs": [v.hex() for v in inputs],
                    "prior": prior.hex(), "outputs": None if result is None else [v.hex() for v in result[0]],
                    "next": None if result is None else result[1].hex()})
    return out


def build() -> dict:
    rng = random.Random(20261002)
    data = [rng.randint(-1000, 1000) for _ in range(16 * 4)]
    w = T.words
    plans = [
        ("sum-then-scan", T.sum_then_scan_plan(4), {0: w(data), 1: struct.pack("<i", data[3])}),
        ("argmax", T.argmax_plan(3), {0: w(data[:48])}),
        ("scan-early-stop", T.scan_plan(4), {0: w(data), 1: struct.pack("<i", data[16 + 2])}),
        ("two-reductions", T.two_reductions_plan(3), {0: w(data[:48])}),
        ("unexported-state", T.unexported_state_plan(3), {0: w(data[:48])}),
        ("matvec-const", T.matvec_plan(4, seed=3), {0: w(data[:16])}),
    ]
    return {"plans": [plan_vector(*p) for p in plans], "kernels": kernel_vectors(rng) + rowdot_vectors(),
            "chunk_leaf": [{"index": i, "chunk": c.hex(), "leaf": R.chunk_leaf(i, c).hex()}
                           for i, c in enumerate([b"", b"\x01" * 64, bytes(range(128))])]}


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")
    print(OUT)
