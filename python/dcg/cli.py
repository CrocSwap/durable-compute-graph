"""`dcg`: developer commands (alpha plan E6).

    dcg dev   [--image SO | --crate DIR [--features F]] [--dir D] [--seconds N]
    dcg build (--alpha | --crate DIR [--features F]) OUT
    dcg verify --rpc URL --program ID --receipt OUT/receipt.json

- `dev` starts a local validator with a DCG program loaded (the alpha image
  by default, built on first use), funds a payer, and writes an env file
  (DCG_RPC_URL, DCG_PROGRAM_ID, DCG_PAYER_KEYPAIR) that the examples and
  clients read. It runs in the foreground until Ctrl-C (or `--seconds`).
- `build` builds an SBF image twice in separate target directories, refuses
  unless the two are byte-identical, and writes a receipt: commit, tree
  state, features, platform tools, size, sha256 and the DCG runtime version.
- `verify` checks a deployed program against a receipt: the ProgramData
  payload must be the receipt's image (sha256 over its length) followed only
  by zeros, and must carry the same runtime version.

Also `python -m dcg ...`. The SBF toolchain is pinned (platform tools
v1.51); `cargo build-sbf` and `solana-test-validator` must be on PATH.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLATFORM_TOOLS = "v1.51"
ALPHA = {"crate": REPO / "crates" / "dcg-program", "features": "alpha-image"}


def _git(path: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else ""


def sbf_build(crate: Path, features: str | None, out_dir: Path, target_dir: Path) -> Path:
    """One `cargo build-sbf` of `crate` into `out_dir`; returns the image."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["cargo", "build-sbf", "--tools-version", PLATFORM_TOOLS, "--manifest-path", str(crate / "Cargo.toml"),
           "--sbf-out-dir", str(out_dir)]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "--locked"]
    log = out_dir / "build.log"
    with log.open("wb") as f:
        code = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                              env={**os.environ, "CARGO_TARGET_DIR": str(target_dir)}).returncode
    if code != 0:
        raise SystemExit(f"cargo build-sbf failed ({code}); see {log}")
    images = sorted(out_dir.glob("*.so"))
    if len(images) != 1:
        raise SystemExit(f"expected one .so in {out_dir}, found {[p.name for p in images]}")
    return images[0]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_build(a) -> int:
    from .runtime import runtime_version

    crate, features = (ALPHA["crate"], ALPHA["features"]) if a.alpha else (Path(a.crate).resolve(), a.features)
    out = Path(a.out).resolve()
    dirty = _git(crate, "status", "--porcelain", "--", ".")
    if dirty and not a.allow_dirty:
        print(f"{crate} has uncommitted changes; commit them (or pass --allow-dirty for a non-reproducible build)",
              file=sys.stderr)
        return 2
    images = []
    for name in ("a", "b"):
        with tempfile.TemporaryDirectory(prefix=f"dcg-build-{name}-") as target:
            images.append(sbf_build(crate, features, out / name, Path(target)))
    shas = [_sha(p) for p in images]
    if shas[0] != shas[1]:
        print(f"the two builds differ: {shas[0]} vs {shas[1]}", file=sys.stderr)
        return 1
    final = out / images[0].name
    shutil.copyfile(images[0], final)
    version = runtime_version(final.read_bytes())
    receipt = {
        "schema": "dcg/build-receipt/1",
        "image": final.name,
        "crate": str(crate.relative_to(REPO)) if crate.is_relative_to(REPO) else str(crate),
        "features": features or "",
        "commit": _git(crate, "rev-parse", "HEAD"),
        "tree_clean": not dirty,
        "platform_tools": PLATFORM_TOOLS,
        "bytes": final.stat().st_size,
        "sha256": shas[0],
        "runtime": str(version) if version else None,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=1) + "\n")
    print(json.dumps({"image": str(final), "sha256": shas[0], "bytes": receipt["bytes"], "two_builds_equal": True,
                      "runtime": receipt["runtime"]}))
    return 0


def cmd_verify(a) -> int:
    from solders.pubkey import Pubkey

    from .runtime import PROGRAMDATA_HEADER, UPGRADEABLE_LOADER, _rpc_at, runtime_version

    receipt = json.loads(Path(a.receipt).read_text())
    rpc = _rpc_at(a.rpc)

    def data(key: str) -> tuple[str, bytes]:
        value = rpc("getAccountInfo", [key, {"encoding": "base64", "commitment": a.commitment}])["value"]
        if value is None:
            raise SystemExit(f"{key} does not exist")
        return value["owner"], base64.b64decode(value["data"][0])

    owner, program = data(a.program)
    if owner != UPGRADEABLE_LOADER or program[:4] != (2).to_bytes(4, "little"):
        raise SystemExit(f"{a.program} is not an upgradeable program")
    _owner, programdata = data(str(Pubkey.from_bytes(program[4:36])))
    payload = programdata[PROGRAMDATA_HEADER:]
    n = receipt["bytes"]
    result = {
        "program": a.program,
        "image_sha256_matches": hashlib.sha256(payload[:n]).hexdigest() == receipt["sha256"],
        "rest_is_zero": not any(payload[n:]),
        "headroom_bytes": len(payload) - n,
        "runtime": str(runtime_version(payload[:n])) if runtime_version(payload[:n]) else None,
    }
    # Receipts from before the runtime marker (dcg/alpha-image-build/1) carry
    # no runtime version; the image hash already pins it.
    result["runtime_matches"] = (result["runtime"] == receipt["runtime"]) if "runtime" in receipt else None
    result["ok"] = (result["image_sha256_matches"] and result["rest_is_zero"]
                    and result["runtime_matches"] is not False)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


def _dev_image(a) -> Path:
    """The image `dcg dev` loads: --image, or a single build of --crate or
    of the alpha image (cached by commit under target/dcg-dev)."""
    if a.image:
        return Path(a.image).resolve()
    crate, features = (Path(a.crate).resolve(), a.features) if a.crate else (ALPHA["crate"], ALPHA["features"])
    commit = _git(crate, "rev-parse", "HEAD")[:12] or "nogit"
    dirty = bool(_git(crate, "status", "--porcelain", "--", "."))
    cache = REPO / "target" / "dcg-dev" / f"{crate.name}-{features or 'default'}-{commit}"
    images = sorted(cache.glob("*.so"))
    if images and not dirty:
        return images[0]
    print(f"building {crate.name} ({features or 'default features'}) for dcg dev ...", file=sys.stderr, flush=True)
    return sbf_build(crate, features, cache, REPO / "target" / "dcg-dev" / "cargo")


def cmd_dev(a) -> int:
    from .devnet import LocalValidator

    image = _dev_image(a)
    dev = LocalValidator(image, run_dir=a.dir, ticks_per_slot=a.ticks_per_slot)
    try:
        return _serve(a, dev, image)
    finally:
        # An automatically created run directory (ledger, keys) is removed on
        # exit unless --keep; one named with --dir is always kept.
        if not a.dir and not a.keep:
            shutil.rmtree(dev.run_dir, ignore_errors=True)


def _serve(a, dev, image: Path) -> int:
    from .runtime import runtime_version

    with dev:
        env_file = dev.write_env(a.env_file)
        version = runtime_version(image.read_bytes())
        print(json.dumps({"rpc": dev.rpc_url, "program": str(dev.program_id), "payer": str(dev.payer_path),
                          "image": str(image), "runtime": str(version) if version else None,
                          "env_file": str(env_file), "dir": str(dev.run_dir)}), flush=True)
        print(f"# source {env_file}   (Ctrl-C stops the validator)", file=sys.stderr, flush=True)
        stop = {"now": False}
        signal.signal(signal.SIGTERM, lambda *_: stop.update(now=True))
        deadline = time.monotonic() + a.seconds if a.seconds else None
        try:
            while not stop["now"] and (deadline is None or time.monotonic() < deadline):
                if dev.process.poll() is not None:
                    print(f"the validator exited; see {dev.run_dir / 'validator.log'}", file=sys.stderr)
                    return 1
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dcg", description="DCG developer commands (alpha plan E6)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    dev = sub.add_parser("dev", help="a local validator with a DCG program, a funded payer and an env file")
    src = dev.add_mutually_exclusive_group()
    src.add_argument("--image", help="a built program image (.so)")
    src.add_argument("--crate", help="an application crate to build and load (default: the alpha image)")
    dev.add_argument("--features", help="cargo features for --crate")
    dev.add_argument("--dir", help="run directory (default: a new short temporary directory)")
    dev.add_argument("--env-file", help="where to write the env file (default: DIR/dcg-dev.env)")
    dev.add_argument("--ticks-per-slot", type=int, default=8)
    dev.add_argument("--seconds", type=float, default=0, help="stop after this long (default: until Ctrl-C)")
    dev.add_argument("--keep", action="store_true", help="keep the automatically created run directory on exit")
    dev.set_defaults(fn=cmd_dev)

    build = sub.add_parser("build", help="a reproducible SBF image (two builds compared) with a receipt")
    what = build.add_mutually_exclusive_group(required=True)
    what.add_argument("--alpha", action="store_true", help="the DCG alpha shared-program image")
    what.add_argument("--crate", help="an application crate directory")
    build.add_argument("--features", help="cargo features for --crate")
    build.add_argument("--allow-dirty", action="store_true", help="build with uncommitted changes (not reproducible)")
    build.add_argument("out", help="output directory")
    build.set_defaults(fn=cmd_build)

    verify = sub.add_parser("verify", help="check a deployed program against a build receipt")
    verify.add_argument("--rpc", required=True)
    verify.add_argument("--program", required=True)
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--commitment", default="finalized")
    verify.set_defaults(fn=cmd_verify)

    ex = sub.add_parser("explain", help="what a template guarantees and costs (alpha E8)")
    ex.add_argument("what", choices=["template"])
    ex.add_argument("--rpc", required=True)
    ex.add_argument("--template", required=True)
    ex.add_argument("--plan", help="FILE.py:NAME, a Spec or a traced function, to check against the template")
    ex.add_argument("--slot-ms", type=float, default=40.0)
    ex.add_argument("--watcher-tick", type=float, default=None,
                    help="a watcher's slowest tick in seconds (default: the remote testnet measurement)")
    ex.add_argument("--json", action="store_true")
    ex.set_defaults(fn=cmd_explain)

    a = ap.parse_args(argv)
    return a.fn(a)


def _load_plan(ref: str):
    """FILE.py:NAME -> a Spec (calling `.plan()` on a traced function)."""
    import importlib.util
    import io
    from contextlib import redirect_stderr

    path, _, name = ref.rpartition(":")
    sys.path.insert(0, str(Path(path).resolve().parent))
    spec = importlib.util.spec_from_file_location(Path(path).stem, path)
    module = importlib.util.module_from_spec(spec)
    with redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
        obj = getattr(module, name)
        return obj.plan() if hasattr(obj, "plan") else obj() if callable(obj) else obj


def cmd_explain(a) -> int:
    from . import explain

    spec = _load_plan(a.plan) if a.plan else None
    kw = {"spec": spec, "slot_ms": a.slot_ms}
    if a.watcher_tick is not None:
        kw["watcher_tick_s"] = a.watcher_tick
    e = explain.template(a.rpc, a.template, **kw)
    if a.json:
        print(json.dumps({"title": e.title, "sections": e.sections, "warnings": e.warnings}, indent=1))
    else:
        print(e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
