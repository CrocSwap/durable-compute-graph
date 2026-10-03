#!/usr/bin/env python3
"""LX1 golden vectors: slot leaves, state roots and canonical multi-proofs
(siblings in level-then-position order), from the toy machine's real states,
for the Rust mirror (crates/dcg-disputes/tests/lx_goldens.rs)."""
from __future__ import annotations

import json
from pathlib import Path

from dcg.disputes_v21 import lx as L
from dcg.disputes_v21.lx_toy import ToyMachine

OUT = Path(__file__).resolve().parents[1] / "tests/golden/dcg/disputes_v21/lx.json"


def build() -> dict:
    m = ToyMachine(positions_count=9, window=3)
    run = L.execute(m)
    cases = []
    for c in (0, 7, 23, len(run.states) - 1):
        state = run.states[c]
        for slots in ([0], [0, 1, 2], [m.A, m.M, m.S], list(range(m.slot_count))[::3], [m.slot_count - 1]):
            proof = L.prove(m, state, slots)
            cases.append({
                "coordinate": c,
                "height": L.height(m),
                "slots": sorted(proof.values),
                "values": [None if proof.values[s] is None else proof.values[s].hex() for s in sorted(proof.values)],
                "leaves": [L.slot_leaf(s, proof.values[s]).hex() for s in sorted(proof.values)],
                "siblings": [proof.siblings[k].hex() for k in sorted(proof.siblings)],
                "root": L.state_root(m, state).hex(),
            })
    return {"slot_leaf_domain": L.SLOT_LEAF_DOMAIN.hex(), "cases": cases}


if __name__ == "__main__":
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(OUT, len(data["cases"]))
