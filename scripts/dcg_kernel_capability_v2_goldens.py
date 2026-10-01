#!/usr/bin/env python3
"""Generate or verify DCKC/DCTV v1 capability and test-vector goldens."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from dcg.graph import v2 as wire  # noqa: E402
from dcg.graph import kernel_capability_v2 as vectors  # noqa: E402
from dcg_graph_plan_v2_goldens import first_slice  # noqa: E402

OUT = ROOT / "tests" / "golden" / "dcg" / "kernel_capability_v2"


def vector_id(label: bytes) -> bytes:
    return hashlib.sha256(b"dcg.kernel.vector.id.v1\x00" + label).digest()[:16]


def equation_source_id(kernel: wire.KernelCapabilityV1) -> bytes:
    return hashlib.sha256(
        b"dcg.kernel.vector.equation.v1\x00"
        + kernel.kernel_id
        + kernel.semantic_version.to_bytes(2, "little")
        + kernel.abi_version.to_bytes(2, "little")
    ).digest()


def first_slice_vectors(manifest: wire.KernelManifestV1, manifest_root: bytes) -> tuple[vectors.KernelTestVectorV1, ...]:
    add, identity = manifest.kernels
    cases = (
        vectors.KernelTestVectorV1(
            vector_id(b"add_i32 inputs 2,3 -> 5"),
            add.kernel_id,
            add.semantic_version,
            add.abi_version,
            manifest_root,
            1,
            equation_source_id(add),
            bytes(16),
            0,
            bytes(32),
            b"",
            (vectors.PortValueV1(0, (2).to_bytes(4, "little", signed=True)),
             vectors.PortValueV1(1, (3).to_bytes(4, "little", signed=True))),
            b"",
            (vectors.PortValueV1(0, (5).to_bytes(4, "little", signed=True)),),
        ),
        vectors.KernelTestVectorV1(
            vector_id(b"identity_i32 input 5 -> 5"),
            identity.kernel_id,
            identity.semantic_version,
            identity.abi_version,
            manifest_root,
            1,
            equation_source_id(identity),
            bytes(16),
            0,
            bytes(32),
            b"",
            (vectors.PortValueV1(0, (5).to_bytes(4, "little", signed=True)),),
            b"",
            (vectors.PortValueV1(0, (5).to_bytes(4, "little", signed=True)),),
        ),
    )
    return tuple(sorted(cases, key=lambda item: item.vector_id))


def _tsv(fieldnames: tuple[str, ...], rows: list[dict[str, str]]) -> bytes:
    from io import StringIO

    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("ascii")


def _refusal_rows(canonical: bytes) -> bytes:
    cases: list[tuple[str, str, bytes]] = []
    cases.append(("vector_bad_magic", "MAGIC", b"XXXX" + canonical[4:]))
    version = bytearray(canonical)
    version[4:6] = (2).to_bytes(2, "little")
    cases.append(("vector_unknown_version", "VERSION", bytes(version)))
    flags = bytearray(canonical)
    flags[6:8] = (1).to_bytes(2, "little")
    cases.append(("vector_nonzero_flags", "FLAGS", bytes(flags)))
    body_length = bytearray(canonical)
    body_length[8:12] = (len(canonical) - 16 + 1).to_bytes(4, "little")
    cases.append(("vector_wrong_body_length", "BODY_LENGTH", bytes(body_length)))
    trailing = bytearray(canonical + b"\x00")
    trailing[8:12] = (len(trailing) - 16).to_bytes(4, "little")
    cases.append(("vector_trailing_bytes", "TRAILING_BYTES", bytes(trailing)))
    return _tsv(
        ("name", "expected_code", "malformed_bytes_base64"),
        [
            {"name": name, "expected_code": code, "malformed_bytes_base64": base64.b64encode(data).decode("ascii")}
            for name, code, data in cases
        ],
    )


def outputs() -> dict[Path, bytes]:
    _graph, manifest, _plan = first_slice()
    manifest_bytes = wire.encode_kernel_manifest(manifest)
    root = wire.kernel_manifest_root(manifest_bytes)
    vector_set = first_slice_vectors(manifest, root)
    vector_bytes = vectors.encode_test_vectors(vector_set)
    return {
        OUT / "kernel_manifests_v1.tsv": _tsv(
            ("name", "bytes_base64", "sha256"),
            [{"name": "minimal_add_identity_capabilities",
              "bytes_base64": base64.b64encode(manifest_bytes).decode("ascii"),
              "sha256": root.hex()}],
        ),
        OUT / "vectors_v1.tsv": _tsv(
            ("name", "bytes_base64", "sha256"),
            [{"name": "minimal_add_identity_equations",
              "bytes_base64": base64.b64encode(vector_bytes).decode("ascii"),
              "sha256": hashlib.sha256(vector_bytes).hexdigest()}],
        ),
        OUT / "refusals_v1.tsv": _refusal_rows(vector_bytes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write the generated TSV files")
    args = parser.parse_args()
    generated = outputs()
    mismatches: list[str] = []
    for path, expected in generated.items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
        elif not path.exists() or path.read_bytes() != expected:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        print("golden mismatch: " + ", ".join(mismatches), file=sys.stderr)
        return 1
    action = "wrote" if args.write else "verified"
    print(f"{action} {len(generated)} DCG kernel capability v2 golden files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
