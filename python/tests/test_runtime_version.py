"""The DCG runtime marker (alpha plan C0): its Rust definition, and reading it
from an image or from a deployed program's ProgramData."""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest
from solders.pubkey import Pubkey

from dcg import runtime
from dcg.session import KernelRef

ROOT = Path(__file__).resolve().parents[2]


def test_the_rust_marker_matches_the_reader():
    lib = (ROOT / "crates" / "dcg-program" / "src" / "lib.rs").read_text()
    assert 'concat!("\\0dcg-runtime/1 ", env!("CARGO_PKG_VERSION"), " stateful-v3 v21\\0")' in lib
    version = re.search(r'^version = "([^"]+)"', (ROOT / "crates/dcg-program/Cargo.toml").read_text(), re.M)[1]
    image = b"\x7fELF..." + b"\x00dcg-runtime/1 " + version.encode() + b" stateful-v3 v21\x00" + b"..."
    got = runtime.runtime_version(image)
    assert got.version == version and got.surfaces == ("stateful-v3", "v21")
    # The entry points read the marker so it stays in every image.
    assert lib.count("touch_runtime_marker(); let Some(tag)") == 2
    assert "crate::touch_runtime_marker();" in (ROOT / "crates/dcg-program/src/stateful_v3.rs").read_text()


def test_absent_and_conflicting_markers():
    assert runtime.runtime_version(b"no marker here") is None
    two = b"\x00dcg-runtime/1 0.1.0 a\x00" + b"\x00dcg-runtime/1 0.2.0 a\x00"
    with pytest.raises(ValueError, match="more than one"):
        runtime.runtime_version(two)


def test_reads_programdata_of_an_upgradeable_program():
    program, programdata = Pubkey.new_unique(), Pubkey.new_unique()
    image = b"\x00dcg-runtime/1 0.1.0 stateful-v3 v21\x00"
    accounts = {
        str(program): (runtime.UPGRADEABLE_LOADER, (2).to_bytes(4, "little") + bytes(programdata)),
        str(programdata): (runtime.UPGRADEABLE_LOADER, bytes(runtime.PROGRAMDATA_HEADER) + image),
    }

    def rpc(method, params):
        owner, data = accounts[params[0]]
        return {"value": {"owner": owner, "data": [base64.b64encode(data).decode()]}}

    assert str(runtime.program_runtime_version("unused", program, rpc=rpc)) == "dcg-runtime 0.1.0 (stateful-v3, v21)"


def test_session_manifest_pads_a_short_kernel_name():
    ref = KernelRef.from_manifest({"id": "dcg-tally-v1", "semantic_version": 1, "abi_version": 1,
                                   "mode": {"id": 1, "version": 3}, "schema": {"id": 1, "version": 1},
                                   "input_width": 1, "state_spans": [16]})
    assert ref.id == b"dcg-tally-v1" + bytes(4)
