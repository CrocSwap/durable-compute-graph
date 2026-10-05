"""The watchtower's challenger (E3) makes byte-identical claims to the
offline first-divergence game, using only the executor's revealed moves and
H: every honest-challenger dispute of the chunked and list scenario
generators is replayed both ways."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from dcg.disputes_v21 import transcript as X
from dcg.services.challenger import play_offline

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_watchtower_claims_match_the_offline_game_chunked(monkeypatch):
    script = "disputes_v21_chunked_scenarios"
    compared = []
    original = X.record

    def checked(record, committed, honest, depth, *, target=None, claim=None, kind="STEP_DESCEND"):
        out = original(record, committed, honest, depth, target=target, claim=claim, kind=kind)
        if target is None:
            ours = play_offline(record, committed, honest, depth)
            assert ours is not None
            assert (ours["kind"], ours["claim_name"], ours["claim"], ours["ruling"]) == (
                out["kind"], out["claim_name"], out["claim"], out["ruling"]), out["claim_name"]
            compared.append(out["claim_name"])
        return out

    monkeypatch.setattr(X, "record", checked)
    module = _load(script)
    module.build()
    assert compared, "no honest-challenger disputes were generated"
    print(script, len(compared), sorted(set(compared)))


def _reference(record, committed, honest, depth):
    """The offline game's claim: honest_challenge with the executor's own tree."""
    from dcg.disputes_v21 import game as G
    from dcg.disputes_v21 import wire as W

    captured = {}
    original = G.Dispute.claim

    def spy(self, name, **kw):
        captured.update(name=name, kw=kw, position=self.position, kind=self.kind)
        captured["ruling"] = original(self, name, **kw)
        return captured["ruling"]

    G.Dispute.claim = spy
    try:
        G.honest_challenge(record, G.Executor(committed), honest, depth)
    finally:
        G.Dispute.claim = original
    body = W.claim_body(record.spec, captured["kind"], captured["position"], captured["name"], captured["kw"])
    return captured["kind"], captured["name"], body.hex(), captured["ruling"]


def test_watchtower_claims_match_the_offline_game_lists():
    from dcg.disputes_v21 import game as G

    m = _load("disputes_v21_list_scenarios")
    sp, values = m.TESTS.mixed_plan()
    setup, refs, run_id = m.setup_for("mixed", sp, values)
    honest = m.commit_for(sp, setup, run_id, values)
    lies = [m.commit_for(sp, setup, run_id, values,
                         list_fault=lambda o, i, e, value, target=j: (bytes([value[0] ^ 1]) + value[1:]
                                                                      if (o, i, e) == (6, 0, target) else value))
            for j in (0, 6, 12)]
    lies += [m.wrong_count(honest), m.foreign_header(honest)]
    for committed in lies:
        record = G.RunRecord(m.PLAN_ID, run_id, sp, committed.root_bytes, refs)
        ours = play_offline(record, committed, honest, 4)
        assert (ours["kind"], ours["claim_name"], ours["claim"], ours["ruling"]) == _reference(record, committed, honest, 4)
        assert ours["ruling"] == "C"
