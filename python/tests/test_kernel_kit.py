"""Kernel kit (alpha plan E2/C3): mirrors agree with their Rust kernels, and
the check catches the mirror bugs it exists for (review finding F2's kind).

The conformance tests need the example server: ``cargo build -p
dcg-kernel-conform`` (or set ``DCG_KERNEL_CONFORM_BIN``); they skip without it.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import os
import struct
import sys
from pathlib import Path

import pytest

from dcg import kernel_kit as kit
from dcg.disputes_v21 import appkernels
from dcg.disputes_v21.run import replay_step

ROOT = Path(__file__).resolve().parents[2]


def _mirrors():
    path = ROOT / "examples" / "kernel-kit" / "counter_mirrors.py"
    spec = importlib.util.spec_from_file_location("counter_mirrors", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["counter_mirrors"] = module
    spec.loader.exec_module(module)
    return module


CM = _mirrors()


def _server() -> Path | None:
    env = os.environ.get("DCG_KERNEL_CONFORM_BIN")
    candidates = [Path(env)] if env else []
    target = os.environ.get("CARGO_TARGET_DIR")
    candidates += [Path(target) / "debug" / "dcg-kernel-conform"] if target else []
    candidates += [ROOT / "target" / "debug" / "dcg-kernel-conform"]
    return next((p for p in candidates if p.is_file()), None)


SERVER = _server()
needs_server = pytest.mark.skipif(SERVER is None, reason="cargo build -p dcg-kernel-conform first")


@pytest.fixture(scope="module")
def rust():
    with kit.RustKernels(SERVER) as r:
        yield r


# --- offline ------------------------------------------------------------------------------------


def test_registry_is_the_kit_registry_and_replays():
    assert appkernels.REGISTRY is kit.STEP_REGISTRY
    key = (kit.kernel_id("dcg-test-sha-v1"), 1, 1)
    assert key in appkernels.REGISTRY
    assert replay_step(key[0], [b"hi"], None) == ([hashlib.sha256(b"hi").digest()], None)
    assert replay_step(key[0], [b""], None) is None  # a refusal
    assert replay_step(key[0], [b"hi"], None, semantic_version=2) is None


def test_declarations_check_names_and_duplicates():
    assert kit.kernel_id("abc") == b"abc" + bytes(13)
    for bad in ("", "x" * 17, "a\x00b"):
        with pytest.raises(ValueError):
            kit.kernel_id(bad)
    with pytest.raises(ValueError):
        kit.step_kernel("dcg-test-sha-v1", max_input_bytes=1, max_output_bytes=1, max_compute_units=1)(lambda i: b"")
    with pytest.raises(ValueError):
        kit.KernelRefused("NoSuchKind")


def test_step_cases_reach_every_edge():
    decl = appkernels.sha256_concat.decl
    totals = {sum(map(len, c)) for c in kit.step_cases(decl)}
    assert {0, 1, 65_535, 65_536, 65_537} <= totals
    assert [] in kit.step_cases(decl) and [b""] in kit.step_cases(decl)


def test_judge_matches_runtime_rules():
    d = CM.REJECT_COUNTER.decl
    s = bytes(16)
    ok = lambda o, rej=True: kit.judge(d, o, s, rej)  # noqa: E731
    assert ok(kit.Outcome(b"x" * 16, s))
    assert not ok(kit.Outcome(b"x" * 17, s))  # more output than the buffer
    assert ok(kit.Outcome(b"", s, "reject", 7))
    assert not ok(kit.Outcome(b"", s, "reject", 7), rej=False)  # plain session
    assert not kit.judge(CM.UNDECLARED_REJECT.decl, kit.Outcome(b"", s, "reject", 7), s, True)
    assert not ok(kit.Outcome(b"", s, "reject", 0))
    assert not ok(kit.Outcome(b"", b"\x01" + s[1:], "reject", 7))  # dirty
    assert not ok(kit.Outcome(b"\x00", s, "reject", 7))  # output on reject
    assert not ok(kit.Outcome(b"", b"\x01" + s[1:], "halt_before", 1))
    assert not ok(kit.Outcome(b"", s, "halt_after", 0))
    # Above the snapshot cap the runtime does not check that state is unchanged.
    big = dataclasses.replace(d, max_state_bytes=kit.SNAPSHOT_CHECK_BYTES + 1)
    prior = bytes(kit.SNAPSHOT_CHECK_BYTES + 1)
    assert kit.judge(big, kit.Outcome(b"", b"\x01" + prior[1:], "reject", 7), prior, True)


# --- against the Rust kernels -------------------------------------------------------------------


@needs_server
def test_examples_conform(rust):
    reports = [kit.check_step(rust, appkernels.sha256_concat)]
    reports += [kit.check_stateful(rust, m, seed=s) for m in (CM.COUNTER, CM.REJECT_COUNTER,
                                                                CM.UNDECLARED_REJECT, CM.LANE_COUNTER)
                for s in (0, 1)]
    for r in reports:
        assert r.ok, r.summary()
    rej = next(r for r in reports if r.kernel.startswith("dcg-rejctr"))
    # The cases reached every disposition and refusals.
    assert {"continue", "reject", "halt_before", "halt_after", "refused"} <= set(rej.reached)


@needs_server
def test_cli(capsys):
    path = str(ROOT / "examples" / "kernel-kit" / "counter_mirrors.py")
    assert kit.main(["check", "--bin", str(SERVER), "dcg.disputes_v21.appkernels", path]) == 0
    assert "dcg-rejctr-v1 v1/1 (stateful)" in capsys.readouterr().out


def _step_mutant(fn, **limits):
    decl = dataclasses.replace(appkernels.sha256_concat.decl, **limits)
    return kit.StepMirror(decl, fn)


@needs_server
def test_catches_an_off_by_one_limit(rust):
    """The F2 kind: a mirror whose own limit is one byte short."""

    def short(inputs):
        if not inputs or not 0 < sum(map(len, inputs)) < 65_536:
            raise kit.KernelRefused("InvalidInput")
        return hashlib.sha256(b"".join(inputs)).digest()

    r = kit.check_step(rust, _step_mutant(short))
    assert not r.ok and any("65536" in d or "inputs [65536" in d for d in r.disagreements), r.summary()


@needs_server
def test_catches_a_declared_limit_mismatch(rust):
    r = kit.check_step(rust, _step_mutant(appkernels.sha256_concat.fn, max_input_bytes=65_535))
    assert not r.ok and r.disagreements[0].startswith("manifest"), r.summary()


@needs_server
def test_catches_wrong_semantics(rust):
    r = kit.check_step(rust, _step_mutant(lambda inputs: hashlib.sha256(b"|".join(inputs)).digest()))
    assert not r.ok


class WrappingCounter(CM.Counter):
    """Wraps on overflow where the kernel refuses."""

    def transition(self, command, state):
        if len(command) != 1:
            raise kit.KernelRefused("InvalidInput")
        value, total = struct.unpack("<QQ", state)
        value = (value + command[0]) & CM.MASK
        total = (total + value) & CM.MASK
        nxt = struct.pack("<QQ", value, total)
        return kit.Outcome(nxt, nxt)


class CleanDirtyReject(CM.RejectCounter):
    """Models the dirty reject as clean, so it predicts acceptance."""

    def transition(self, command, state):
        if command[:1] == bytes([CM.REJECT_DIRTY]):
            return kit.Outcome(b"", state, "reject", CM.REJECT_CODE)
        return super().transition(command, state)


class UndeclaredCapability(CM.RejectCounter):
    decl = dataclasses.replace(CM.RejectCounter.decl, rejects_input=False)


@needs_server
@pytest.mark.parametrize("mutant", [WrappingCounter(), CleanDirtyReject(), UndeclaredCapability()])
def test_catches_stateful_mutants(rust, mutant):
    assert not kit.check_stateful(rust, mutant).ok
