"""`dcg` developer commands (alpha E6): argument handling, `verify` against a
fake RPC, and (opt-in) `LocalValidator` on a real local validator."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from solders.pubkey import Pubkey

from dcg import cli, runtime


def test_build_needs_a_target(capsys):
    with pytest.raises(SystemExit):
        cli.main(["build", "out"])
    with pytest.raises(SystemExit):
        cli.main(["dev", "--image", "a.so", "--crate", "x"])


def _fake_chain(monkeypatch, image: bytes, headroom: bytes):
    program, programdata = Pubkey.new_unique(), Pubkey.new_unique()
    accounts = {
        str(program): (runtime.UPGRADEABLE_LOADER, (2).to_bytes(4, "little") + bytes(programdata)),
        str(programdata): (runtime.UPGRADEABLE_LOADER, bytes(runtime.PROGRAMDATA_HEADER) + image + headroom),
    }

    def rpc_at(_url):
        def rpc(method, params):
            owner, data = accounts[params[0]]
            return {"value": {"owner": owner, "data": [base64.b64encode(data).decode()]}}
        return rpc

    monkeypatch.setattr(runtime, "_rpc_at", rpc_at)
    return program


def _receipt(tmp_path: Path, image: bytes, **extra) -> Path:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps({"bytes": len(image), "sha256": hashlib.sha256(image).hexdigest(), **extra}))
    return path


def test_verify_accepts_the_receipt_image_and_refuses_others(monkeypatch, tmp_path, capsys):
    image = b"\x7fELF" + b"\x00dcg-runtime/1 0.1.0 stateful-v3 v21\x00" + bytes(100)
    program = _fake_chain(monkeypatch, image, bytes(64))
    good = _receipt(tmp_path, image, runtime="dcg-runtime 0.1.0 (stateful-v3, v21)")
    assert cli.main(["verify", "--rpc", "x", "--program", str(program), "--receipt", str(good)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    other = _receipt(tmp_path, image[:-1] + b"\x01")
    assert cli.main(["verify", "--rpc", "x", "--program", str(program), "--receipt", str(other)]) == 1
    wrong_runtime = _receipt(tmp_path, image, runtime="dcg-runtime 0.2.0 (stateful-v3, v21)")
    assert cli.main(["verify", "--rpc", "x", "--program", str(program), "--receipt", str(wrong_runtime)]) == 1
    program = _fake_chain(monkeypatch, image, b"\x00\x01")  # bytes after the image
    assert cli.main(["verify", "--rpc", "x", "--program", str(program), "--receipt", str(good)]) == 1


@pytest.mark.skipif(os.environ.get("DCG_RUN_LOCAL_VALIDATOR") != "1" or not os.environ.get("DCG_ALPHA_IMAGE"),
                    reason="set DCG_RUN_LOCAL_VALIDATOR=1 and DCG_ALPHA_IMAGE to run the local validator")
def test_local_validator_loads_the_program_and_funds_a_payer(tmp_path):
    from dcg.devnet import LocalValidator, _rpc

    with LocalValidator(os.environ["DCG_ALPHA_IMAGE"]) as dev:
        assert _rpc(dev.rpc_url, "getAccountInfo", [str(dev.program_id), {"encoding": "base64"}])["value"]["executable"]
        env = dev.env()
        payer = json.loads(Path(env["DCG_PAYER_KEYPAIR"]).read_text())
        assert len(payer) == 64 and oct(os.stat(env["DCG_PAYER_KEYPAIR"]).st_mode)[-3:] == "600"
        assert dev.write_env().read_text().count("export DCG_") == 3
    assert dev.process.poll() is not None  # stopped on exit
