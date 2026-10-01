from __future__ import annotations

import base64
import csv
import hashlib
import os
import subprocess
import sys
import unittest
from pathlib import Path

from dcg.graph import v2


ROOT = Path(__file__).resolve().parents[2]
GOLDENS = ROOT / "tests" / "golden" / "dcg" / "graph_plan_v2"
GENERATOR = ROOT / "scripts" / "dcg_graph_plan_v2_goldens.py"


def rows(path: Path):
    csv.field_size_limit(16 * 1024 * 1024)
    with path.open(encoding="ascii", newline="") as stream:
        yield from csv.DictReader(stream, delimiter="\t")


class GraphPlanV2GoldenTests(unittest.TestCase):
    def test_generator_reproduces_tsv_files_byte_for_byte(self):
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
        self.assertIn("verified 5 DCG graph/plan v2 golden files", completed.stdout)

    def test_graph_vectors_decode_reencode_and_match_identity(self):
        for row in rows(GOLDENS / "graphs_v1.tsv"):
            with self.subTest(vector=row["name"]):
                encoded = base64.b64decode(row["bytes_base64"], validate=True)
                graph = v2.decode_graph(encoded)
                self.assertEqual(v2.encode_graph(graph), encoded)
                self.assertEqual(v2.graph_id(encoded).hex(), row["sha256"])

    def test_plan_vectors_decode_reencode_and_match_identity(self):
        for row in rows(GOLDENS / "plans_v1.tsv"):
            with self.subTest(vector=row["name"]):
                encoded = base64.b64decode(row["bytes_base64"], validate=True)
                plan = v2.decode_plan(encoded)
                self.assertEqual(v2.encode_plan(plan), encoded)
                self.assertEqual(v2.plan_id(encoded).hex(), row["sha256"])

    def test_manifest_vectors_decode_reencode_and_match_root(self):
        for row in rows(GOLDENS / "kernel_manifests_v1.tsv"):
            with self.subTest(vector=row["name"]):
                encoded = base64.b64decode(row["bytes_base64"], validate=True)
                manifest = v2.decode_kernel_manifest(encoded)
                self.assertEqual(v2.encode_kernel_manifest(manifest), encoded)
                self.assertEqual(v2.kernel_manifest_root(encoded).hex(), row["sha256"])

    def test_all_domain_separated_hash_preimages_match(self):
        seen = set()
        for row in rows(GOLDENS / "hashes_v1.tsv"):
            preimage = base64.b64decode(row["preimage_base64"], validate=True)
            with self.subTest(vector=row["name"]):
                self.assertEqual(hashlib.sha256(preimage).hexdigest(), row["sha256"])
                self.assertIn(b"\x00", preimage[:40])
            seen.add(row["name"])
        self.assertEqual(
            seen,
            {
                "graph_id",
                "plan_id",
                "template_id",
                "kernel_manifest_root",
                "run_id",
                "step_leaf",
                "merkle_node_level_0",
                "region_root",
            },
        )

    def test_malformed_vectors_refuse_with_expected_code(self):
        for row in rows(GOLDENS / "refusals_v1.tsv"):
            encoded = base64.b64decode(row["malformed_bytes_base64"], validate=True)
            with self.subTest(vector=row["name"]):
                if row["codec"] == "graph":
                    decoder = v2.decode_graph
                elif row["codec"] == "plan":
                    decoder = v2.decode_plan
                elif row["codec"] == "manifest":
                    decoder = v2.decode_kernel_manifest
                else:
                    self.fail(f"unknown codec in vector {row['name']}")
                with self.assertRaises(v2.GraphError if row["codec"] != "plan" else v2.PlanError) as raised:
                    decoder(encoded)
                self.assertEqual(raised.exception.code, row["expected_code"])

    def test_run_identity_requires_sorted_unique_input_ids(self):
        refs = (
            v2.ExternalInputRefV1(0, 1, 1, 2, 1, 4, b"a" * 32),
            v2.ExternalInputRefV1(1, 1, 1, 2, 1, 4, b"b" * 32),
        )
        actual = v2.run_id(b"t" * 32, b"n" * 32, refs)
        self.assertEqual(len(actual), 32)
        with self.assertRaisesRegex(v2.GraphError, "ORDER"):
            v2.run_id(b"t" * 32, b"n" * 32, tuple(reversed(refs)))
        with self.assertRaisesRegex(v2.GraphError, "DUPLICATE"):
            v2.run_id(b"t" * 32, b"n" * 32, (refs[0], refs[0]))

    def test_odd_merkle_level_duplicates_last_child(self):
        leaves = (b"a" * 32, b"b" * 32, b"c" * 32)
        expected_last = hashlib.sha256(
            b"dcg.region.node.v2\x00" + b"\x00\x00" + leaves[2] + leaves[2]
        ).digest()
        expected_root = hashlib.sha256(
            b"dcg.region.node.v2\x00" + b"\x01\x00" + hashlib.sha256(
                b"dcg.region.node.v2\x00" + b"\x00\x00" + leaves[0] + leaves[1]
            ).digest() + expected_last
        ).digest()
        self.assertEqual(v2.merkle_root(leaves), expected_root)


if __name__ == "__main__":
    unittest.main()
