"""Client transaction details needed by v2.1 list claims and template closes."""

from __future__ import annotations

import base64

from solders.hash import Hash
from solders.instruction import AccountMeta
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from dcg.disputes_v21.client import DisputeClient, LIST_HEAP_FRAME, _list_step_heap_frame
from dcg.graph_client import GraphClient


def test_list_reveal_and_claim_request_the_256_kib_heap_frame():
    sent = []
    gc = GraphClient("unused", Pubkey.new_unique(), Keypair(), timeout=1)

    def rpc(method, params):
        if method == "getLatestBlockhash":
            return {"value": {"blockhash": str(Hash.default())}}
        if method == "sendTransaction":
            sent.append(params[0])
            return "sent"
        if method == "getSignatureStatuses":
            return {"value": [{"confirmationStatus": "confirmed", "err": None}]}
        raise AssertionError(f"unexpected RPC method {method}")

    gc.rpc = rpc
    client = DisputeClient(gc)
    heap_frame = _list_step_heap_frame(b"LVR1list reveal")
    assert heap_frame == LIST_HEAP_FRAME == 256 * 1024
    assert _list_step_heap_frame(b"ordinary leaf") is None
    client._send("reveal_leaf", b"LVR1list reveal", [], [], heap_frame=heap_frame)
    client._send("claim", b"list claim", [], [], heap_frame=heap_frame)

    assert len(sent) == 2
    for wire, sub, body in zip(sent, (7, 8), (b"LVR1list reveal", b"list claim")):
        tx = Transaction.from_bytes(base64.b64decode(wire))
        assert [bytes(ix.data) for ix in tx.message.instructions] == [
            bytes([2]) + (1_400_000).to_bytes(4, "little"),
            bytes([1]) + LIST_HEAP_FRAME.to_bytes(4, "little"),
            bytes([227, sub]) + body,
        ]


def test_close_run_marks_the_tracked_template_writable():
    class RecordingClient:
        payer = Keypair()

        def send(self, data, metas, signers, cu, heap_frame=None):
            self.call = (data, metas, signers, cu, heap_frame)
            return "sig"

    gc = RecordingClient()
    client = DisputeClient(gc)
    run, template, payer = (Pubkey.new_unique() for _ in range(3))
    client.close_run(run, template, payer)

    data, metas, _signers, _cu, _heap_frame = gc.call
    assert data == bytes([227, 19])
    assert metas[1].pubkey == run
    assert metas[2].pubkey == template and metas[2].is_writable
    assert metas[3].pubkey == payer and metas[3].is_writable


def test_close_cache_does_not_write_run():
    class RecordingClient:
        payer = Keypair()

        def send(self, data, metas, signers, cu, heap_frame=None):
            self.call = (data, metas)
            return "sig"

    gc = RecordingClient()
    client = DisputeClient(gc)
    client.close_cache(Pubkey.new_unique(), Pubkey.new_unique(), Pubkey.new_unique())
    data, metas = gc.call
    assert data == bytes([227, 20])
    assert not metas[1].is_writable


def test_client_plays_a_recorded_list_dispute_through_staging():
    import importlib.util
    from pathlib import Path
    from dcg.disputes_v21 import game as G, transcript as T

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("list_scenarios", root / "scripts/disputes_v21_list_scenarios.py")
    scenarios = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenarios)
    sp, values = scenarios.TESTS.mixed_plan()
    setup, refs, run_id = scenarios.setup_for("mixed", sp, values)
    honest = scenarios.commit_for(sp, setup, run_id, values)
    committed = scenarios.commit_for(sp, setup, run_id, values,
        list_fault=lambda o, i, e, value: bytes([value[0] ^ 1]) + value[1:]
        if (o, i, e) == (6, 0, 0) else value)
    record = G.RunRecord(scenarios.PLAN_ID, run_id, sp, committed.root_bytes, refs)
    transcript = T.record(record, committed, honest, 4)
    assert transcript["ruling"] == "C"
    assert bytes.fromhex(transcript["leaf"]).startswith(b"LVR1")

    class RecordingClient:
        program_id = Pubkey.new_unique()
        payer = Keypair()

        def __init__(self):
            self.calls = []

        def pda(self, *seeds):
            return Pubkey.find_program_address(list(seeds), self.program_id)[0]

        def send(self, data, metas, signers, cu, heap_frame=None):
            self.calls.append((data[1], data[2:], metas, heap_frame))
            return "sig"

        def account(self, _key):
            return bytes(6) + bytes([2])

    gc = RecordingClient()
    client = DisputeClient(gc)
    client._send_many = lambda items: gc.calls.extend((15, body, metas, None) for _, body, metas, _ in items)
    executor, challenger = Keypair(), Keypair()
    run, template = Pubkey.new_unique(), Pubkey.new_unique()
    result = client.play(run, template, transcript, executor, challenger)
    assert result["ruling"] == "C"
    dispute = client.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), bytes([1]) * 32)
    executor_buffer = client.pda(b"dcg21stg", bytes(dispute), bytes([1]))
    reveal = next(call for call in gc.calls if call[0] == 7)
    claim = next(call for call in gc.calls if call[0] == 8)
    assert reveal[1] == b"\xff" and reveal[3] == LIST_HEAP_FRAME
    assert executor_buffer in [meta.pubkey for meta in reveal[2]]
    assert executor_buffer == claim[2][-1].pubkey and claim[3] == LIST_HEAP_FRAME
    assert any(call[0] == 14 for call in gc.calls)
    for sub, _body, metas, _ in gc.calls:
        if sub in (14, 15, 17):
            assert not metas[1].is_writable, f"stage sub {sub} needlessly writes run"
    writes = [(int.from_bytes(body[:4], "little"), body[4:]) for sub, body, metas, _ in gc.calls
              if sub == 15 and metas[-1].pubkey == executor_buffer]
    assert writes
    staged = bytearray(len(bytes.fromhex(transcript["leaf"])))
    for offset, piece in writes:
        staged[offset:offset + len(piece)] = piece
    assert bytes(staged) == bytes.fromhex(transcript["leaf"])
    challenger_buffer = client.pda(b"dcg21stg", bytes(dispute), bytes([2]))
    assert claim[1] == b"\xff" and claim[2][-2].pubkey == challenger_buffer
    claim_bytes = bytearray(len(bytes.fromhex(transcript["claim"])))
    for sub, body, metas, _ in gc.calls:
        if sub == 15 and metas[-1].pubkey == challenger_buffer:
            offset = int.from_bytes(body[:4], "little")
            claim_bytes[offset:offset + len(body) - 4] = body[4:]
    assert bytes(claim_bytes) == bytes.fromhex(transcript["claim"])


def test_template_address_is_scoped_to_its_payer():
    class RecordingClient:
        program_id = Pubkey.new_unique()

        def pda(self, *seeds):
            return Pubkey.find_program_address(list(seeds), self.program_id)[0]

        def account(self, _key):
            return None

        def send(self, data, metas, signers, cu, heap_frame=None):
            return "sig"

    client = DisputeClient(RecordingClient())
    data = bytes(range(123))
    assert client.create_template(data, Keypair()) != client.create_template(data, Keypair())


def test_short_list_reveal_is_staged_and_claim_reads_executor_buffer():
    class RecordingClient:
        program_id = Pubkey.new_unique()
        payer = Keypair()

        def __init__(self):
            self.calls = []

        def pda(self, *seeds):
            return Pubkey.find_program_address(list(seeds), self.program_id)[0]

        def send(self, data, metas, signers, cu, heap_frame=None):
            self.calls.append((data[1], data[2:], metas))
            return "sig"

        def account(self, _key):
            return bytes(6) + bytes([2])

    gc = RecordingClient()
    client = DisputeClient(gc)
    client._send_many = lambda items: gc.calls.extend((15, body, metas) for _, body, metas, _ in items)
    run, template = Pubkey.new_unique(), Pubkey.new_unique()
    executor, challenger = Keypair(), Keypair()
    transcript = {"kind": "STEP_DESCEND", "rounds": [], "leaf": (b"LVR1" + bytes(96)).hex(),
                  "claim": bytes(50).hex()}
    client.play(run, template, transcript, executor, challenger)
    dispute = client.pda(b"dcg21dsp", bytes(run), bytes(challenger.pubkey()), bytes([1]) * 32)
    executor_buffer = client.pda(b"dcg21stg", bytes(dispute), bytes([1]))
    reveal = next(call for call in gc.calls if call[0] == 7)
    claim = next(call for call in gc.calls if call[0] == 8)
    assert reveal[1] == b"\xff"
    assert executor_buffer in [meta.pubkey for meta in reveal[2]]
    assert executor_buffer == claim[2][-1].pubkey
