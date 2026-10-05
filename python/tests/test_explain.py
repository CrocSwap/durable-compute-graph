"""`explain()` (alpha E8): a template described from its account bytes, its
plan checked against it, windows flagged; a session's guarantee and bounds."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from solders.pubkey import Pubkey

from dcg import explain
from dcg.kernel_kit import MODE_CONSENSUS_V3, KernelDecl
from dcg.session import KernelRef
from dcg.session.layout import SessionInfo

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "hello-graph"))
import traced_dispute as T  # noqa: E402

SPEC = T.checksum.plan()


def account(spec, *, depth=3, challenge=1_000, phase=750, plan_id=T.PLAN_ID, tracked_runs=2) -> bytes:
    d = bytearray(explain.T_LX + 44 + 40)
    d[:4] = b"D21T"
    d[explain.T_DEPTH] = depth
    struct.pack_into("<QQQQQQ", d, explain.T_STEPS, spec.total_steps, spec.total_outputs, challenge, phase,
                     2_000_000, 1_000_000)
    d[explain.T_SPEC_ROOT:explain.T_SPEC_ROOT + 32] = spec.root
    struct.pack_into("<H", d, explain.T_SLASHER, 5_000)
    d[explain.T_PLAN_ID:explain.T_PLAN_ID + 32] = plan_id
    d[explain.T_FIXED] = len(spec.blocks)
    d[len(d) - 40:len(d) - 36] = b"D21O"
    struct.pack_into("<I", d, len(d) - 4, tracked_runs)
    return bytes(d)


def test_template_with_its_plan():
    e = explain.template(None, Pubkey.new_unique(), spec=SPEC, data=account(SPEC), watcher_tick_s=5)
    text = str(e)
    assert "the given plan matches" in text and "sumchunk_i32" in text and "2 live run(s)" in text
    assert "largest STEP witness" in text and not e.warnings


def test_tight_windows_and_wrong_plans_are_flagged():
    e = explain.template(None, Pubkey.new_unique(), spec=SPEC, data=account(SPEC))  # remote watcher (33 s)
    assert any("challenge window" in w for w in e.warnings) and any("phase window" in w for w in e.warnings)
    e = explain.template(None, Pubkey.new_unique(), spec=SPEC, data=account(SPEC, plan_id=bytes(32)),
                         plan_id=T.PLAN_ID)
    assert any("does NOT match" in w for w in e.warnings)
    e = explain.template(None, Pubkey.new_unique(), data=account(SPEC))
    assert any("no plan given" in w for w in e.warnings)
    long = account(SPEC, challenge=3_000, phase=2_000)  # 120 s and 80 s: over twice a 33 s tick
    assert not explain.template(None, Pubkey.new_unique(), spec=SPEC, data=long).warnings


def test_session_text_states_the_guarantee_and_bounds():
    kernel = KernelRef.from_manifest({"id": "dcg-tally-v1", "semantic_version": 1, "abi_version": 1,
                                      "mode": {"id": 0x434F4E53, "version": 3}, "schema": {"id": 1, "version": 1},
                                      "input_width": 1, "state_spans": [16], "rejects_input": True})
    decl = KernelDecl(name="dcg-tally-v1", max_input_bytes=1, max_output_bytes=16, max_state_bytes=16,
                      max_compute_units=50_000, max_operations=8, modes=(MODE_CONSENSUS_V3,), rejects_input=True)
    info = SessionInfo(status="active", capacity=8, cursor=4, frontier=4, features=2, rejected_count=1,
                       halt_reason=0, halt_cursor=0, last_reject_sequence=1, last_reject_code=1)
    text = explain.session_text(info, kernel, decl, "dcg-runtime 0.1.0 (stateful-v3, v21)", max_steps=4)
    assert "consensus" in text and "may reject inputs" in text and "50,000 CU" in text and "200,000 CU" in text
    assert "rejected inputs: 1" in text
