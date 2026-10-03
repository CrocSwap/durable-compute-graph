"""Kernel ids resolve exactly as the program resolves them (review 10-03, F2 and F9)."""

import struct

from dcg.disputes_v21 import appkernels, reductions
from dcg.disputes_v21 import run as R


def pad(raw: bytes) -> bytes:
    return raw + bytes(16 - len(raw))


def test_builtin_and_reduction_ids_must_be_exact():
    one = struct.pack("<i", 7)
    assert R.replay(pad(b"identity_i32/v1"), [one]) == [one]
    for bad in (b"identity_i32", b"identity_i32/v2", b"identity_i32/v1x"):
        assert R.replay(pad(bad), [one]) is None, bad
    assert R.replay(b"identi\x00ty_i32/v1", [one]) is None, "interior NUL"
    assert R.replay(pad(b"\xff\xfe"), [one]) is None, "invalid UTF-8 is unknown, not a crash"
    assert reductions.lookup(pad(b"sumchunk_i32/v1")) is not None
    for bad in (b"sumchunk_i32", b"sumchunk_i32/v7", b"sumchunk_i32/v1x", b"head_i32/v1\x00\x00x"):
        assert reductions.lookup(pad(bad)) is None, bad


def test_application_kernels_resolve_by_id_and_versions():
    sha = b"dcg-test-sha-v1\x00"
    assert R.replay_step(sha, [b"abc"], None, 1, 1) is not None
    assert R.replay_step(sha, [b"abc"], None, 2, 1) is None, "another semantic version is unknown"
    assert R.replay_step(sha, [b"abc"], None, 1, 2) is None, "another ABI version is unknown"
    assert (sha, 1, 1) in appkernels.REGISTRY
