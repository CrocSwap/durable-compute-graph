from __future__ import annotations

import base64
import json
import unittest

import httpx

from dcg.sequencer import Commitment, RpcConfig, SolanaRpcEndpoint


class RpcAccountReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_multiple_and_filtered_program_account_reads_parse_solana_responses(self):
        requests = []
        owner = "Program1111111111111111111111111111111111"
        first = "11111111111111111111111111111111"
        second = "SysvarRent111111111111111111111111111111111"
        child = "Vote111111111111111111111111111111111111111"

        def account(data: bytes, lamports: int):
            return {
                "data": [base64.b64encode(data).decode("ascii"), "base64"],
                "owner": owner,
                "lamports": lamports,
                "executable": False,
                "rentEpoch": 7,
            }

        def respond(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            requests.append(payload)
            if payload["method"] == "getMultipleAccounts":
                result = {"context": {"slot": 42}, "value": [account(b"one", 11), None]}
            elif payload["method"] == "getProgramAccounts":
                result = {
                    "context": {"slot": 43},
                    "value": [{"pubkey": child, "account": account(b"child", 22)}],
                }
            else:
                raise AssertionError(payload["method"])
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        rpc = SolanaRpcEndpoint(
            "rpc-test",
            "http://127.0.0.1:8899",
            config=RpcConfig(requests_per_second=1000, max_in_flight=1),
            client=client,
        )
        try:
            values = await rpc.get_multiple_accounts((first, second), Commitment.CONFIRMED)
            children = await rpc.get_program_accounts(
                owner,
                filters=({"memcmp": {"offset": 8, "bytes": first}},),
                commitment=Commitment.CONFIRMED,
            )
        finally:
            await rpc.aclose()
            await client.aclose()

        self.assertEqual(values[0].data, b"one")
        self.assertEqual(values[0].lamports, 11)
        self.assertEqual(values[0].context_slot, 42)
        self.assertIsNone(values[1])
        self.assertEqual(children[0][0], child)
        self.assertEqual(children[0][1].data, b"child")
        self.assertEqual(children[0][1].context_slot, 43)
        self.assertEqual(requests[0]["method"], "getMultipleAccounts")
        self.assertEqual(requests[1]["method"], "getProgramAccounts")
        self.assertEqual(requests[1]["params"][1]["filters"], [{"memcmp": {"offset": 8, "bytes": first}}])


if __name__ == "__main__":
    unittest.main()
