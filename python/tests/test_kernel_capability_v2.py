from __future__ import annotations

import base64
import csv
import hashlib
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path

from dcg.graph import kernel_capability_v2 as vectors
from dcg.graph import v2 as wire

ROOT = Path(__file__).resolve().parents[2]
GOLDENS = ROOT / "tests" / "golden" / "dcg" / "kernel_capability_v2"
GRAPH_GOLDENS = ROOT / "tests" / "golden" / "dcg" / "graph_plan_v2"
GENERATOR = ROOT / "scripts" / "dcg_kernel_capability_v2_goldens.py"


def rows(path: Path):
    csv.field_size_limit(16 * 1024 * 1024)
    with path.open(encoding="ascii", newline="") as stream:
        yield from csv.DictReader(stream, delimiter="\t")


class KernelCapabilityV2GoldenTests(unittest.TestCase):
    def test_generator_reproduces_all_golden_files(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "python")
        completed = subprocess.run(
            [sys.executable, str(GENERATOR)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("verified 3 DCG kernel capability v2 golden files", completed.stdout)

    def test_manifest_roundtrip_root_and_graph_plan_identity(self):
        manifest_rows = tuple(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        self.assertEqual(len(manifest_rows), 1)
        row = manifest_rows[0]
        encoded = base64.b64decode(row["bytes_base64"], validate=True)
        manifest = wire.decode_kernel_manifest(encoded)
        self.assertEqual(wire.encode_kernel_manifest(manifest), encoded)
        self.assertEqual(wire.kernel_manifest_root(encoded).hex(), row["sha256"])
        self.assertEqual(len(manifest.kernels), 2)

        graph_row = next(rows(GRAPH_GOLDENS / "kernel_manifests_v1.tsv"))
        self.assertEqual(encoded, base64.b64decode(graph_row["bytes_base64"], validate=True))
        self.assertEqual(row["sha256"], graph_row["sha256"])

    def test_normative_vectors_roundtrip_and_expected_bytes(self):
        row = next(rows(GOLDENS / "vectors_v1.tsv"))
        encoded = base64.b64decode(row["bytes_base64"], validate=True)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), row["sha256"])
        decoded = vectors.decode_test_vectors(encoded)
        self.assertEqual(vectors.encode_test_vectors(decoded), encoded)
        self.assertEqual(len(decoded), 2)
        self.assertEqual({item.source_kind for item in decoded}, {1})
        self.assertEqual(
            {value.value for item in decoded for value in (item.expected_outputs or ())},
            {(5).to_bytes(4, "little", signed=True)},
        )
        manifest_row = next(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        manifest_bytes = base64.b64decode(manifest_row["bytes_base64"], validate=True)
        manifest_root = wire.kernel_manifest_root(manifest_bytes)
        self.assertTrue(all(item.manifest_root == manifest_root for item in decoded))

    def test_malformed_golden_vectors_refuse_with_expected_code(self):
        for row in rows(GOLDENS / "refusals_v1.tsv"):
            malformed = base64.b64decode(row["malformed_bytes_base64"], validate=True)
            with self.subTest(vector=row["name"]):
                with self.assertRaises(vectors.VectorError) as raised:
                    vectors.decode_test_vectors(malformed)
                self.assertEqual(raised.exception.code, row["expected_code"])

    def test_refusal_outcome_roundtrip_and_canonical_port_order(self):
        row = next(rows(GOLDENS / "vectors_v1.tsv"))
        encoded = base64.b64decode(row["bytes_base64"], validate=True)
        decoded = vectors.decode_test_vectors(encoded)
        vector = next(item for item in decoded if len(item.inputs) == 2)
        manifest_row = next(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        manifest = wire.decode_kernel_manifest(
            base64.b64decode(manifest_row["bytes_base64"], validate=True)
        )
        refusal_code = manifest.kernels[0].error_mappings[0].stable_error_code
        refusal = replace(vector, expected_outputs=None, stable_error_code=refusal_code)
        refusal_bytes = vectors.encode_test_vectors((refusal,))
        self.assertEqual(vectors.decode_test_vectors(refusal_bytes), (refusal,))
        unsorted = replace(vector, inputs=tuple(reversed(vector.inputs)))
        with self.assertRaises(vectors.VectorError) as raised:
            vectors.encode_test_vectors((unsorted,))
        self.assertEqual(raised.exception.code, "ORDER")

    def test_zero_replay_opening_is_refused(self):
        row = next(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        manifest = wire.decode_kernel_manifest(base64.b64decode(row["bytes_base64"], validate=True))
        kernel = manifest.kernels[0]
        mode = kernel.modes[0]
        replay = replace(mode.replay, max_opening_bytes=0)
        changed_mode = replace(mode, replay=replay)
        changed_kernel = replace(kernel, modes=(changed_mode,))
        changed_manifest = replace(manifest, kernels=(changed_kernel,) + manifest.kernels[1:])
        with self.assertRaises(wire.GraphError) as raised:
            wire.encode_kernel_manifest(changed_manifest)
        self.assertEqual(raised.exception.code, "OPENING_LIMIT")

    def test_read_only_sharing_is_refused_on_output_ports(self):
        row = next(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        manifest = wire.decode_kernel_manifest(base64.b64decode(row["bytes_base64"], validate=True))
        kernel = manifest.kernels[0]
        output = next(index for index, port in enumerate(kernel.ports) if port.direction == 1)
        ports = list(kernel.ports)
        ports[output] = replace(ports[output], alias_rule=1)
        changed_kernel = replace(kernel, ports=tuple(ports))
        changed_manifest = replace(manifest, kernels=(changed_kernel,) + manifest.kernels[1:])
        with self.assertRaises(wire.GraphError) as raised:
            wire.encode_kernel_manifest(changed_manifest)
        self.assertEqual(raised.exception.code, "ALIAS_RULE")

    def test_exact_in_place_alias_remains_open_and_refused(self):
        row = next(rows(GOLDENS / "kernel_manifests_v1.tsv"))
        manifest = wire.decode_kernel_manifest(base64.b64decode(row["bytes_base64"], validate=True))
        kernel = manifest.kernels[0]
        first_port = replace(kernel.ports[0], alias_rule=2)
        aliased_kernel = replace(kernel, ports=(first_port,) + kernel.ports[1:])
        aliased_manifest = replace(manifest, kernels=(aliased_kernel,) + manifest.kernels[1:])
        with self.assertRaises(wire.GraphError) as raised:
            wire.encode_kernel_manifest(aliased_manifest)
        self.assertEqual(raised.exception.code, "ALIAS_RULE_OPEN")


if __name__ == "__main__":
    unittest.main()
