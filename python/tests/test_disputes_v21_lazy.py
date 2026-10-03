"""Lazy second-level STEP disputes: protocol mechanics only."""

from __future__ import annotations

from dataclasses import replace
import struct
import unittest

from dcg.disputes_v21 import lazy
from dcg.disputes_v21.lazy_toy import DOT, parent_step, register


class LazyDisputesV21Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        register()

    def setUp(self):
        self.parent = parent_step([(3, 9), (-7, 4), (8, 6), (11, -2), (5, 13), (2, 22)], chunk_pairs=2)
        self.honest = lazy.honest_subtrace(self.parent, DOT)

    def test_honest_subtrace_and_every_local_claim_rule_for_executor(self):
        self.assertIsNone(lazy.honest_lazy_challenge(self.parent, DOT, self.honest, self.honest))
        for index, raw in enumerate(self.honest.records):
            for claim in ("EDGE", "STATE", "STEP"):
                dispute = lazy.LazyDispute(self.parent, DOT, self.honest, self.honest)
                dispute.position = index
                dispute.level = 0
                dispute.leaf = raw
                self.assertEqual(dispute.claim(claim, self.honest.witnesses[index]), "E",
                                 (index, claim))

    def test_wrong_parent_output_is_convicted_at_first_wrong_substep(self):
        true = struct.unpack("<q", self.parent.outputs[0])[0]
        parent = parent_step([(3, 9), (-7, 4), (8, 6), (11, -2), (5, 13), (2, 22)],
                             chunk_pairs=2, output=true + 1)
        honest = lazy.honest_subtrace(parent, DOT)
        false_output = parent.outputs[0]
        witnesses = list(honest.witnesses)
        witnesses[-1] = replace(witnesses[-1], outputs=(false_output,))
        executor = lazy.SubtraceCommitment.from_witnesses(parent, DOT, witnesses)
        dispute = lazy.honest_lazy_challenge(parent, DOT, executor, honest, depth=1)
        self.assertEqual((dispute.ruling, dispute.position, dispute.claimed),
                         ("C", len(honest.records) - 1, "STEP"))

    def test_wrong_accumulator_is_caught_as_state_at_first_bad_substep(self):
        witnesses = list(self.honest.witnesses)
        i = 1
        wrong_prior = struct.pack("<q", struct.unpack("<q", witnesses[i].prior_accumulator)[0] + 1)
        witnesses[i] = replace(witnesses[i], prior_accumulator=wrong_prior)
        executor = lazy.SubtraceCommitment.from_witnesses(self.parent, DOT, witnesses)
        dispute = lazy.honest_lazy_challenge(self.parent, DOT, executor, self.honest, depth=2)
        self.assertEqual((dispute.ruling, dispute.position, dispute.claimed), ("C", i, "STATE"))

    def test_parent_boundary_binding_lie_is_caught(self):
        for wrong_header in (
            replace(self.honest.header, parent_inputs_digest=bytes([0xA5]) * 32),
            replace(self.honest.header, terminal_outputs_digest=bytes([0xA5]) * 32),
        ):
            with self.subTest(header=wrong_header):
                executor = lazy.SubtraceCommitment.from_raw(wrong_header, self.honest.records,
                                                             self.honest.witnesses)
                dispute = lazy.honest_lazy_challenge(self.parent, DOT, executor, self.honest)
                self.assertEqual((dispute.ruling, dispute.claimed), ("C", "BINDING"))

    def test_malformed_subtrace_leaf_is_convicted(self):
        records = list(self.honest.records)
        index = 1
        records[index] = b"not an LSS1 record"
        executor = lazy.SubtraceCommitment.from_raw(self.honest.header, records,
                                                     self.honest.witnesses)
        dispute = lazy.honest_lazy_challenge(self.parent, DOT, executor, self.honest, depth=1)
        self.assertEqual((dispute.ruling, dispute.position, dispute.claimed),
                         ("C", index, "SHAPE"))

    def test_input_edge_lie_is_convicted(self):
        witnesses = list(self.honest.witnesses)
        index = 1
        raw = bytearray(witnesses[index].inputs[0])
        raw[0] ^= 0x40
        witnesses[index] = replace(witnesses[index], inputs=(bytes(raw),))
        executor = lazy.SubtraceCommitment.from_witnesses(self.parent, DOT, witnesses)
        dispute = lazy.honest_lazy_challenge(self.parent, DOT, executor, self.honest, depth=2)
        self.assertEqual((dispute.ruling, dispute.position, dispute.claimed), ("C", index, "EDGE"))

    def test_timeout_at_every_new_phase_rules_for_the_non_silent_party(self):
        for phase, silent in lazy.PHASE_PARTY.items():
            with self.subTest(phase=phase):
                deadline = lazy.LazyPhaseDeadline(phase, deadline=100)
                with self.assertRaises(lazy.LazyRefused):
                    deadline.timeout(100)
                self.assertEqual(deadline.timeout(101), "C" if silent == "E" else "E")

    def test_subtrace_merkle_proofs_reject_bad_child_hashes(self):
        dispute = lazy.LazyDispute(self.parent, DOT, self.honest, self.honest, depth=1)
        nodes = lazy._subtree_nodes(self.honest, dispute)
        with self.assertRaises(lazy.LazyRefused):
            dispute.reveal_nodes({i: bytes(32) for i in nodes})


if __name__ == "__main__":
    unittest.main()
