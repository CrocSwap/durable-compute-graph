"""Mode results v1: the Python mirror reproduces the Rust bytes (goldens), and
its readers reproduce the program's results from real account bytes captured
by the Rust flow tests (``tests/golden/dcg/result/{session,run}.json``)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from solders.pubkey import Pubkey

from dcg import result as R

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests/golden/dcg/result"


def load(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text())


def key(h: str) -> Pubkey:
    return Pubkey.from_bytes(bytes.fromhex(h))


def test_the_golden_vectors_regenerate_identically():
    spec = importlib.util.spec_from_file_location("mode_result_goldens", ROOT / "scripts/mode_result_goldens.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.build() == load("vectors")


def test_references_round_trip_and_refuse_what_encode_would_not_write():
    for entry in load("vectors")["refs"]:
        raw = bytes.fromhex(entry["encoded"])
        ref = R.ResultRef.decode(raw)
        assert ref.encode() == raw and ref.digest().hex() == entry["digest"]
        for at in (0, 4, 6, 7):
            bad = bytearray(raw)
            bad[at] ^= 0x40
            with pytest.raises(R.ResultError):
                R.ResultRef.decode(bytes(bad))
    consensus = bytearray(bytes.fromhex(load("vectors")["refs"][0]["encoded"]))
    consensus[112 + 34] = 1
    with pytest.raises(R.ResultError, match="Layout"):
        R.ResultRef.decode(bytes(consensus))


def test_a_sealed_session_record_reads_as_the_programs_result():
    f = load("session")
    host, k, owner, record = key(f["host"]), key(f["key"]), key(f["owner"]), bytes.fromhex(f["record"])
    ref = R.read_session_result(host, k, owner, record)
    assert ref.encode().hex() == f["result"]
    state = bytes.fromhex(f["state"])
    ref.open_state(state)
    with pytest.raises(R.ResultError, match="Opening"):
        ref.open_state(bytes([state[0] ^ 1]) + state[1:])
    with pytest.raises(R.ResultError, match="Owner"):
        R.read_session_result(host, k, Pubkey.default(), record)
    with pytest.raises(R.ResultError, match="Address"):
        R.read_session_result(host, Pubkey.default(), owner, record)
    unsealed = bytearray(record)
    unsealed[1278] = 0
    with pytest.raises(R.ResultError, match="NotSealed"):
        R.read_session_result(host, k, owner, bytes(unsealed))
    # A sealed flag on a record the program would not write (no kernel
    # reason) is refused as Rust's decode refuses it.
    authority_halt = bytearray(record)
    authority_halt[1254:1258] = bytes(4)
    with pytest.raises(R.ResultError, match="Layout"):
        R.read_session_result(host, k, owner, bytes(authority_halt))
    trimmed = bytearray(record)
    trimmed[1278] |= 2
    with pytest.raises(R.ResultError, match="Trimmed"):
        R.read_session_result(host, k, owner, bytes(trimmed))


def test_a_final_run_reads_the_same_live_and_as_its_receipt_and_an_output_opens():
    f = load("run")
    host, run, template = key(f["host"]), key(f["run"]), key(f["template"])
    t = (template, host, bytes.fromhex(f["template_data"]))
    live = R.read_run_result(host, (run, host, bytes.fromhex(f["live"])), t)
    receipt = R.read_run_result(host, (run, host, bytes.fromhex(f["receipt"])), t)
    assert live.encode().hex() == f["result"] == receipt.encode().hex()
    path = [bytes.fromhex(p) for p in f["output0_path"]]
    output0 = bytes.fromhex(f["output0"])
    live.open_output(0, output0, path)
    with pytest.raises(R.ResultError, match="Opening"):
        live.open_output(0, bytes([output0[0] ^ 1]) + output0[1:], path)
    committed = bytearray.fromhex(f["live"])
    committed[4] = 1
    with pytest.raises(R.ResultError, match="NotFinal"):
        R.read_run_result(host, (run, host, bytes(committed)), t)
    with pytest.raises(R.ResultError, match="Template"):
        R.read_run_result(host, (run, host, bytes.fromhex(f["live"])), (Pubkey.default(), host, t[2]))
    with pytest.raises(R.ResultError, match="Address"):
        R.read_run_result(host, (Pubkey.default(), host, bytes.fromhex(f["live"])), t)
    # A refuted receipt (status 3) is never a result.
    refuted = bytearray.fromhex(f["receipt"])
    refuted[4] = 3
    with pytest.raises(R.ResultError, match="NotFinal"):
        R.read_run_result(host, (run, host, bytes(refuted)), t)


def test_a_final_lx_run_reads_as_the_programs_result_and_its_outputs_open():
    f = load("lx_run")
    host, run, template = key(f["host"]), key(f["run"]), key(f["template"])
    t = (template, host, bytes.fromhex(f["template_data"]))
    live = R.read_run_result(host, (run, host, bytes.fromhex(f["live"])), t)
    receipt = R.read_run_result(host, (run, host, bytes.fromhex(f["receipt"])), t)
    assert live.encode().hex() == f["result"] == receipt.encode().hex()
    assert live.scheme == R.SCHEME_LX_OUTPUTS_V1 and live.count == 0
    outputs = [None if o is None else bytes.fromhex(o) for o in f["outputs"]]
    live.open_lx_outputs(outputs)
    with pytest.raises(R.ResultError, match="Opening"):
        live.open_lx_outputs(outputs[:-1] + [b"x"])
    with pytest.raises(R.ResultError, match="Opening"):
        live.open_output(0, bytes(55), [])
