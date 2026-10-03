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
