"""Which DCG runtime a program embeds (alpha plan C0).

Every image that links DCG's entry points carries a NUL-delimited marker,
``dcg-runtime/1 <version> <surfaces>`` (``RUNTIME_MARKER`` in
``crates/dcg-program/src/lib.rs``). It is read from a built ``.so``, or from a
deployed program's ProgramData account with one ``getAccountInfo`` per
account; no transaction is sent.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from dataclasses import dataclass
from typing import Callable

from solders.pubkey import Pubkey

PREFIX = b"\x00dcg-runtime/1 "
#: The upgradeable loader's ProgramData header: tag(4) slot(8) option(1) authority(32).
PROGRAMDATA_HEADER = 45
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"


@dataclass(frozen=True)
class RuntimeVersion:
    version: str
    surfaces: tuple[str, ...]

    def __str__(self) -> str:
        return f"dcg-runtime {self.version} ({', '.join(self.surfaces)})"


def runtime_version(image: bytes) -> RuntimeVersion | None:
    """The marker in an image's bytes, or None for an image without one (built
    before the marker existed, or not linking DCG). Two different markers in
    one image are refused."""
    found = set()
    at = image.find(PREFIX)
    while at != -1:
        end = image.find(b"\x00", at + 1)
        if end == -1:
            break
        found.add(image[at + len(PREFIX):end].decode("ascii", "replace"))
        at = image.find(PREFIX, end)
    if not found:
        return None
    if len(found) > 1:
        raise ValueError(f"the image carries more than one DCG runtime marker: {sorted(found)}")
    version, *surfaces = found.pop().split(" ")
    return RuntimeVersion(version, tuple(surfaces))


def _rpc_at(url: str) -> Callable[[str, list], object]:
    def rpc(method: str, params: list):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    return rpc


def program_runtime_version(rpc_url: str, program_id: Pubkey | str,
                            rpc: Callable[[str, list], object] | None = None) -> RuntimeVersion | None:
    """The marker of a deployed upgradeable program, read from its
    ProgramData account."""
    rpc = rpc or _rpc_at(rpc_url)

    def data(key: str) -> tuple[str, bytes]:
        value = rpc("getAccountInfo", [key, {"encoding": "base64", "commitment": "confirmed"}])["value"]
        if value is None:
            raise ValueError(f"{key} does not exist")
        return value["owner"], base64.b64decode(value["data"][0])

    owner, program = data(str(program_id))
    if owner != UPGRADEABLE_LOADER or program[:4] != (2).to_bytes(4, "little"):
        raise ValueError(f"{program_id} is not an upgradeable program")
    _owner, programdata = data(str(Pubkey.from_bytes(program[4:36])))
    return runtime_version(programdata[PROGRAMDATA_HEADER:])


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        with open(sys.argv[1], "rb") as f:
            print(runtime_version(f.read()))
    elif len(sys.argv) == 3:
        print(program_runtime_version(sys.argv[1], sys.argv[2]))
    else:
        print("usage: python -m dcg.runtime IMAGE.so | RPC_URL PROGRAM_ID", file=sys.stderr)
        raise SystemExit(2)
