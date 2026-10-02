"""Optimistic disputes v2.1, chunked kernels: repeated blocks, gates, SMALL
state, chunked inputs and producer kinds 4 to 7 (offline reference)."""

from __future__ import annotations

import random
import struct
import unittest

from dcg.disputes_v21 import game as G
from dcg.disputes_v21 import plans as P
from dcg.disputes_v21 import run as R
from dcg.disputes_v21 import spec as S

PLAN_ID = bytes([7]) * 32
TEMPLATE = bytes([8]) * 32
EXECUTOR = bytes([9]) * 32


def words(values: list[int]) -> bytes:
    return struct.pack(f"<{len(values)}i", *values)


def sum_plan(n_chunks: int, chunk_log2: int = 6):
    """sum over a chunked input, then head_i32 of the result (kind 6), and
    both as graph outputs (kind 6 and kind 1)."""
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << chunk_log2, chunk_log2)
    blk = b.chunked_reduce("sumchunk_i32", 0)
    b.enumerated([P.Step("head_i32", (P.Input(S.producer(6, blk, 0, 0), 8),), ((0, 4, True),))])
    b.output(S.producer(6, blk, 0, 0), 8)
    b.output(S.producer(1, n_chunks, 0), 4, scalar=True)
    return b.build()


def argmax_plan(n_chunks: int, chunk_log2: int = 6):
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << chunk_log2, chunk_log2)
    blk = b.chunked_reduce("argmax_i32c", 0, extra=(P.Input(S.producer(7), 4, scalar=True),))
    b.output(S.producer(6, blk, 0, 0), 12)
    return b.build()


def scan_plan(n_chunks: int, chunk_log2: int = 6):
    """First match of a scalar needle; the gate stops the block once found."""
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << chunk_log2, chunk_log2)
    needle = b.scalar_input(1)
    blk = b.chunked_reduce("scan_i32c", 0, extra=(P.Input(S.producer(7), 4, scalar=True),
                                                  P.Input(needle, 4, scalar=True)))
    b.output(S.producer(6, blk, 0, 0), 8)
    return b.build()


def two_reductions_plan(n_chunks: int):
    """Two chunked kernels over the same input, combined by add_i32."""
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << 6, 6)
    s = b.chunked_reduce("sumchunk_i32", 0)
    a = b.chunked_reduce("argmax_i32c", 0, extra=(P.Input(S.producer(7), 4, scalar=True),))
    base = n_chunks * 2
    b.enumerated([
        P.Step("head_i32", (P.Input(S.producer(6, s, 0, 0), 8),), ((0, 4, True),)),
        P.Step("head_i32", (P.Input(S.producer(6, a, 0, 0), 12),), ((0, 4, True),)),
        P.Step("add_i32", (P.Input(S.producer(1, base, 0), 4, True), P.Input(S.producer(1, base + 1, 0), 4, True)),
               ((0, 4, True),)),
    ])
    b.output(S.producer(1, base + 2, 0), 4, scalar=True)
    return b.build()


def sum_then_scan_plan(n_chunks: int):
    """A sum block followed by a scan block whose gate is already zero in
    iteration 0 (the needle is in chunk 0), then a read of the sum (kind 6).
    Both export 8 raw bytes, so a kind 6 claim naming t = K of the sum block
    would land on the scan's iteration 0 unless t is bounded."""
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << 6, 6)
    needle = b.scalar_input(1)
    s = b.chunked_reduce("sumchunk_i32", 0)
    b.chunked_reduce("scan_i32c", 0, extra=(P.Input(S.producer(7), 4, scalar=True), P.Input(needle, 4, scalar=True)))
    b.enumerated([P.Step("head_i32", (P.Input(S.producer(6, s, 0, 0), 8),), ((0, 4, True),))])
    b.output(S.producer(6, s, 0, 0), 8)
    return b.build()


def unexported_state_plan(n_chunks: int):
    """A stateful chunk step without a state export: its next state is
    checked only by STEP (and by the next iteration's STATE)."""
    b = P.PlanBuilder()
    b.chunked_input(0, n_chunks << 6, 6)
    step = P.Step("sumchunk_i32", (P.Input(S.producer(5, 0, 2, 1, 0), 64),), ((0, 8, False), (1, 4, True)),
                  state_bytes=8, state_predecessor=S.producer(4, 0, 0, 1))
    b.repeated([step], n_chunks, (0, 1))
    return b.build()


def setup(sp: S.Spec, values: dict[int, bytes], fault=None, **faults):
    refs = {eid: R.external_ref(eid, sp.in_specs[eid][8:31], R.input_digest(sp.in_specs[eid], v))
            for eid, v in values.items()}
    run = R.run_id(TEMPLATE, bytes(32), list(refs.values()), EXECUTOR)
    honest = R.execute(sp, PLAN_ID, run, values)
    faulty = fault is not None or faults
    committed = R.execute(sp, PLAN_ID, run, values, fault=fault, **faults) if faulty else honest
    return refs, run, honest, committed


def play(sp, refs, run, honest, committed, depth=4):
    record = G.RunRecord(PLAN_ID, run, sp, committed.root_bytes, refs)
    try:
        dispute = G.honest_challenge(record, G.Executor(committed), honest, depth)
    except G.ExecutorRefused:
        return "C", None  # E cannot answer: C wins at E's deadline
    return (dispute.ruling, dispute) if dispute else (None, None)


def descend_to(record, executor, ordinal, depth):
    """A dispute walked to `ordinal`'s leaf (any challenger may descend anywhere)."""
    sp = record.spec
    d = G.Dispute(record, "STEP_DESCEND", depth)
    target = sp.position_of(ordinal)
    while d.level > 0:
        d.reveal_nodes(executor.nodes(d))
        step = min(d.depth, d.level)
        d.pick((target >> (d.level - step)) & ((1 << step) - 1))
    d.reveal_leaf(executor.leaf(d))
    return d


def honest_claims(record, executor, honest, k):
    """Every claim C could make at leaf k, with honest openings."""
    sp = record.spec
    bi, block, it, _e = sp.locate(k)
    opening = sp.opening(sp.step_leaf_index(k))
    d = S.decode_step_spec(sp.step_spec(k))
    out = [("SHAPE", {"spec_opening": opening})]
    if sp.gated(k):
        g = sp.ordinal_of(bi, it - 1, block.gate_entry)
        out.append(("GATE", {"spec_opening": opening, "gate_opening": executor.leaf_opening(g),
                             "gate_value": honest.values.get((g, block.gate_port))}))
    if honest.leaves[k] is None:
        return out
    for i, (_h, prod, _init) in enumerate(d["inputs"]):
        pk, a, _b, c, dd = S.decode_producer(prod)
        extra = {}
        if pk == 1:
            extra["producer_opening"] = executor.leaf_opening(a)
        elif pk == 5:
            data = honest.values[("ext", a)]
            cb = 1 << sp.in_specs[a][32]
            extra["chunk_opening"] = (R.chunks(data, cb)[dd], R.chunk_tree(data, cb).path(dd))
        elif pk == 6:
            extra = G._kind6_args(record, executor, honest, a, c)
        out.append(("EDGE", {"spec_opening": opening, "index": i, **extra}))
    if d["state_scheme"]:
        pk, a, *_ = S.decode_producer(d["state_predecessor"])
        out.append(("STATE", {"spec_opening": opening,
                              "producer_opening": executor.leaf_opening(a) if pk == 1 else None}))
    witness = [G.honest_value(honest, sp, prod) for _h, prod, _i in d["inputs"]]
    state = None
    if d["state_scheme"]:
        pk, a, *_ = S.decode_producer(d["state_predecessor"])
        state = honest.states[a] if pk == 1 else bytes(d["state_size"])
    out.append(("STEP", {"spec_opening": opening, "witness": witness, "state_witness": state}))
    return out


def cases(rng):
    data = [rng.randint(-1000, 1000) for _ in range(16 * 6)]
    yield "sum", sum_plan(6), {0: words(data)}
    yield "argmax", argmax_plan(6), {0: words(data)}
    hit = data[16 * 2 + 5]
    yield "scan-early-stop", scan_plan(6), {0: words(data), 1: struct.pack("<i", hit)}
    yield "scan-no-hit", scan_plan(6), {0: words(data), 1: struct.pack("<i", 5000)}
    yield "two-reductions", two_reductions_plan(6), {0: words(data)}
    yield "sum-then-scan", sum_then_scan_plan(6), {0: words(data), 1: struct.pack("<i", data[3])}
    yield "unexported-state", unexported_state_plan(6), {0: words(data)}


class Honest(unittest.TestCase):
    def test_results_match_direct_computation(self):
        rng = random.Random(1)
        data = [rng.randint(-1000, 1000) for _ in range(16 * 6)]
        sp = sum_plan(6)
        _refs, _run, honest, _ = setup(sp, {0: words(data)})
        self.assertEqual(struct.unpack("<q", honest.states[5])[0], sum(data))
        sp = argmax_plan(6)
        _refs, _run, honest, _ = setup(sp, {0: words(data)})
        seen, best, index = struct.unpack("<IiI", honest.states[5])
        self.assertEqual((best, index), (max(data), data.index(max(data))))
        sp = scan_plan(6)
        needle = data[16 * 2 + 5]
        _refs, _run, honest, _ = setup(sp, {0: words(data), 1: struct.pack("<i", needle)})
        found, index = struct.unpack("<II", honest.states[max(honest.states)])
        self.assertEqual((found, index), (1, data.index(needle)))
        self.assertEqual(honest.last_running[0], data.index(needle) // 16)
        # Iterations after the hit are gated off (empty leaves).
        self.assertTrue(all(x is None for x in honest.leaves[honest.last_running[0] + 1:]))

    def test_honest_commitment_is_not_disputed(self):
        rng = random.Random(2)
        for name, sp, values in cases(rng):
            refs, run, honest, committed = setup(sp, values)
            self.assertEqual(play(sp, refs, run, honest, committed), (None, None), name)


def random_cases(rng, n):
    """Random chunked plans: kernel, chunk size, chunk count and data."""
    for c in range(n):
        log2 = rng.choice([6, 7, 8])
        k = rng.randint(1, 9)
        data = [rng.randint(-50, 50) for _ in range((k << log2) // 4)]
        which = rng.choice(["sum", "argmax", "scan", "two"])
        if which == "sum":
            yield f"r{c}-sum", sum_plan(k, log2), {0: words(data)}
        elif which == "argmax":
            yield f"r{c}-argmax", argmax_plan(k, log2), {0: words(data)}
        elif which == "scan":
            needle = rng.choice(data + [999])
            yield f"r{c}-scan", scan_plan(k, log2), {0: words(data), 1: struct.pack("<i", needle)}
        else:
            data = data[: (k << 6) // 4]
            yield f"r{c}-two", two_reductions_plan(k), {0: words(data)}


class Soundness(unittest.TestCase):
    """Every consistent fault (corrupt one step, continue from it) is convicted."""

    won_by: set = set()

    @classmethod
    def tearDownClass(cls):
        # Every claim type this slice adds must have convicted something.
        missing = ({"STEP", "SHAPE", "GATE", "STATE", "OUT", "EDGE1", "EDGE2", "EDGE5", "EDGE6", "EDGE7"}
                   - cls.won_by)
        assert not missing, f"claims never exercised: {missing} (won by {cls.won_by})"

    def test_every_step_fault_is_convicted(self):
        rng = random.Random(3)
        convicted = 0
        for name, sp, values in list(cases(rng)) + list(random_cases(rng, 40)):
            for k in range(sp.total_steps):
                for mode in ("output", "state", "gate"):
                    def fault(o, outs, nxt, k=k, mode=mode):
                        if o != k:
                            return outs, nxt
                        if mode == "output":
                            outs[-1] = bytes([outs[-1][0] ^ 1]) + outs[-1][1:]
                        elif mode == "state" and nxt is not None:
                            exported = S.decode_step_spec(sp.step_spec(o))["state_export"] != 0xFF
                            nxt = bytes([nxt[0] ^ 1]) + nxt[1:]
                            if exported:
                                outs[0] = nxt  # keep the export consistent: a STEP lie
                        elif mode == "gate" and len(outs) > 1:
                            on = struct.unpack("<i", outs[1])[0]
                            outs[1] = struct.pack("<i", 0 if on else 1)
                        return outs, nxt
                    refs, run, honest, committed = setup(sp, values, fault)
                    if committed.root == honest.root:
                        continue  # the fault did not apply at a gated-off step
                    for depth in (1, 4):
                        ruling, d = play(sp, refs, run, honest, committed, depth)
                        self.assertEqual(ruling, "C", (name, k, mode, depth))
                        if d is not None:
                            Soundness.won_by.add(d.claimed)
                        convicted += 1
        self.assertGreater(convicted, 100)

    def test_wrong_inputs_and_priors_are_convicted(self):
        """An executor that feeds a step a wrong input (another chunk, another
        iteration index, a stale result) or a wrong prior state, then
        continues consistently from it."""
        rng = random.Random(6)
        convicted = 0
        for name, sp, values in list(cases(rng)) + list(random_cases(rng, 25)):
            for k in range(sp.total_steps):
                d = S.decode_step_spec(sp.step_spec(k))
                for index in range(len(d["inputs"])):
                    def input_fault(o, i, v, k=k, index=index):
                        return v if (o, i) != (k, index) else bytes([v[0] ^ 1]) + v[1:]
                    refs, run, honest, committed = setup(sp, values, input_fault=input_fault)
                    if committed.root == honest.root:
                        continue
                    ruling, dispute = play(sp, refs, run, honest, committed, rng.choice([1, 2, 4, 5]))
                    self.assertEqual(ruling, "C", (name, k, index))
                    Soundness.won_by.add(dispute.claimed)
                    convicted += 1
                if d["state_scheme"]:
                    def prior_fault(o, prior, k=k):
                        return prior if o != k else bytes(len(prior)) if any(prior) else b"\x01" + prior[1:]
                    refs, run, honest, committed = setup(sp, values, prior_fault=prior_fault)
                    if committed.root == honest.root:
                        continue
                    ruling, dispute = play(sp, refs, run, honest, committed, rng.choice([1, 2, 4, 5]))
                    self.assertEqual(ruling, "C", (name, k, "prior"))
                    Soundness.won_by.add(dispute.claimed)
                    convicted += 1
        self.assertGreater(convicted, 200)

    def test_structural_lies_are_convicted(self):
        rng = random.Random(4)
        for name, sp, values in cases(rng):
            refs, run, honest, _ = setup(sp, values)
            lies = []
            rep = next(bi for bi, b in enumerate(sp.blocks) if b.kind == 2)
            blk = sp.blocks[rep]
            last = honest.last_running[rep]
            if last >= 1:  # stop early: drop the last running iteration
                c = honest.clone()
                for e in range(blk.body_len):
                    c.leaves[sp.ordinal_of(rep, last, e)] = None
                lies.append(("early-stop", c))
            if last + 1 < blk.k:  # run past the gate: a fabricated extra iteration
                c = honest.clone()
                c.leaves[sp.ordinal_of(rep, last + 1, 0)] = c.leaves[sp.ordinal_of(rep, last, 0)]
                lies.append(("extra-iteration", c))
            c = honest.clone()  # iteration 0 empty
            c.leaves[sp.ordinal_of(rep, 0, 0)] = None
            lies.append(("empty-iteration-0", c))
            c = honest.clone()  # malformed leaf
            c.leaves[sp.ordinal_of(rep, 0, 0)] = b"\x01\x02"
            lies.append(("malformed", c))
            if honest.out_entries:  # an out entry that is not the last running iteration's
                c = honest.clone()
                c.out_entries[0] = c.out_entries[0][:23] + bytes(32)
                lies.append(("out-entry", c))
            k = sp.ordinal_of(rep, 0, 0)  # a wrong chunk digest (EDGE kind 5)
            leaf = R.parse_leaf(honest.leaves[k])
            c = honest.clone()
            ins = list(leaf.inputs)
            ins[0] = ins[0][:23] + R.value_digest(b"not the chunk")
            c.leaves[k] = R.leaf_preimage(PLAN_ID, run, leaf.region, leaf.segment, k, leaf.node, leaf.kernel_step,
                                          ins, list(leaf.outputs), leaf.prior, leaf.next)
            lies.append(("chunk-edge", c))
            for lie, committed in lies:
                committed.rebuild()
                for depth in (1, 3, 5):
                    ruling, d = play(sp, refs, run, honest, committed, depth)
                    self.assertEqual(ruling, "C", (name, lie, depth))
                    if d is not None:
                        Soundness.won_by.add(d.claimed)


class Completeness(unittest.TestCase):
    """Against an honest commitment every claim at every leaf rules for E."""

    def test_every_claim_against_an_honest_run_rules_for_e(self):
        rng = random.Random(5)
        checked = 0
        for name, sp, values in list(cases(rng)) + list(random_cases(rng, 15)):
            refs, run, honest, _ = setup(sp, values)
            record = G.RunRecord(PLAN_ID, run, sp, honest.root_bytes, refs)
            executor = G.Executor(honest)
            for k in range(sp.total_steps):
                for claim, kwargs in honest_claims(record, executor, honest, k):
                    d = descend_to(record, executor, k, 4)
                    try:
                        ruling = d.claim(claim, **kwargs)
                    except G.Refused:
                        continue  # e.g. EDGE against an empty gated leaf
                    self.assertEqual(ruling, "E", (name, k, claim, kwargs.get("index")))
                    checked += 1
        self.assertGreater(checked, 150)


class DishonestChallenger(unittest.TestCase):
    """A challenger naming a wrong iteration for a kind 6 read, or using
    SHAPE against a state export, must lose against an honest executor."""

    def test_kind6_at_any_other_iteration_rules_for_e(self):
        rng = random.Random(7)
        tried = 0
        for name, sp, values in list(cases(rng)) + list(random_cases(rng, 15)):
            refs, run, honest, _ = setup(sp, values)
            record = G.RunRecord(PLAN_ID, run, sp, honest.root_bytes, refs)
            ex = G.Executor(honest)
            targets = []  # (ordinal or out index, input index, producer)
            for k in range(sp.total_steps):
                for i, (_h, prod, _init) in enumerate(S.decode_step_spec(sp.step_spec(k))["inputs"]):
                    if S.decode_producer(prod)[0] == 6:
                        targets.append(("step", k, i, prod))
            for j, raw in enumerate(sp.out_specs):
                if S.decode_producer(raw[32:56])[0] == 6:
                    targets.append(("out", j, 0, raw[32:56]))
            for where, at, index, prod in targets:
                _pk, a, _b, c, _d = S.decode_producer(prod)
                block = sp.blocks[a]
                for t in range(block.k + 2):
                    o = sp.ordinal_of(a, t, c)
                    if o >= sp.total_steps or honest.leaves[o] is None:
                        continue
                    args = {"t": t, "producer_opening": ex.leaf_opening(sp.ordinal_of(a, t, c))}
                    if t != block.k - 1:
                        g = sp.ordinal_of(a, t, block.gate_entry)
                        if g < sp.total_steps:
                            args["gate_opening"] = ex.leaf_opening(g)
                            args["gate_value"] = honest.values.get((g, block.gate_port))
                    try:
                        if where == "step":
                            d = descend_to(record, ex, at, 3)
                            ruling = d.claim("EDGE", spec_opening=sp.opening(sp.step_leaf_index(at)), index=index,
                                             **args)
                        else:
                            d = G.Dispute(record, "OUT_DESCEND", 3)
                            while d.level > 0:
                                d.reveal_nodes(ex.nodes(d))
                                step = min(d.depth, d.level)
                                d.pick((at >> (d.level - step)) & ((1 << step) - 1))
                            d.reveal_leaf(ex.leaf(d))
                            ruling = d.claim("OUT", spec_opening=sp.opening(sp.out_leaf_index(at)), **args)
                    except G.Refused:
                        ruling = "E"  # a refused claim cannot win
                    self.assertEqual(ruling, "E", (name, where, at, t))
                    tried += 1
        self.assertGreater(tried, 30)

    def test_shape_rules_on_a_state_export_that_is_not_the_next_state(self):
        rng = random.Random(8)
        _name, sp, values = next(cases(rng))
        refs, run, honest, _ = setup(sp, values)
        k = 0
        leaf = R.parse_leaf(honest.leaves[k])
        outs = list(leaf.outputs)
        outs[0] = outs[0][:23] + R.value_digest(b"other")  # export port 0 no longer equals next
        lie = honest.clone()
        lie.leaves[k] = R.leaf_preimage(PLAN_ID, run, leaf.region, leaf.segment, k, leaf.node, leaf.kernel_step,
                                        list(leaf.inputs), outs, leaf.prior, leaf.next)
        lie.rebuild()
        record = G.RunRecord(PLAN_ID, run, sp, lie.root_bytes, refs)
        d = descend_to(record, G.Executor(lie), k, 4)
        self.assertEqual(d.claim("SHAPE", spec_opening=sp.opening(sp.step_leaf_index(k))), "C")
        d = descend_to(G.RunRecord(PLAN_ID, run, sp, honest.root_bytes, refs), G.Executor(honest), k, 4)
        self.assertEqual(d.claim("SHAPE", spec_opening=sp.opening(sp.step_leaf_index(k))), "E")


class AddressMap(unittest.TestCase):
    def test_positions_round_trip_and_padding_is_not_pickable(self):
        sp = two_reductions_plan(6)
        positions = {sp.position_of(k) for k in range(sp.total_steps)}
        self.assertEqual(len(positions), sp.total_steps)
        for p in range(1 << sp.address_height):
            k = sp.ordinal_at(p)
            self.assertEqual(k is not None, p in positions)
            self.assertEqual(sp.pickable(0, p), p in positions)
            if k is not None:
                self.assertEqual(sp.position_of(k), p)
        for level in range(1, sp.address_height + 1):
            for p in range(1 << (sp.address_height - level)):
                lo, hi = p << level, (p + 1) << level
                self.assertEqual(sp.pickable(level, p), any(lo <= q < hi for q in positions))


if __name__ == "__main__":
    unittest.main()
