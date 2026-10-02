"""Upload a large immutable byte image into a keypair account owned by DCG (tag 208).

usage: upload_raw_account.py <file> <account-keypair> [--max-seconds N] [--rate TPS] [--probe]
Resumable: every pass reads the account back and re-sends only differing chunks.
Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.system_program import CreateAccountParams, create_account
from solders.transaction import Transaction

from dcg.graph_client import GraphClient

CHUNK = 880


def load(path: str) -> Keypair:
    with open(path) as f:
        return Keypair.from_bytes(bytes(json.load(f)))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("account")
    p.add_argument("--max-seconds", type=float, default=50)
    p.add_argument("--rate", type=float, default=60)
    p.add_argument("--probe", action="store_true", help="create the account and write only chunk 0")
    args = p.parse_args()
    data = open(args.file, "rb").read()
    client = GraphClient.from_environment()
    if not os.path.exists(args.account):
        kp = Keypair()
        with open(args.account, "w") as f:
            json.dump(list(bytes(kp)), f)
        os.chmod(args.account, 0o600)
    account = load(args.account)
    started = time.monotonic()
    live = client.account(account.pubkey())
    if live is None:
        lamports = client.rpc("getMinimumBalanceForRentExemption", [len(data)])
        ix = create_account(CreateAccountParams(from_pubkey=client.payer.pubkey(), to_pubkey=account.pubkey(),
                                                lamports=lamports, space=len(data), owner=client.program_id))
        for _ in range(60):
            if _ % 6 == 0:
                bh = Hash.from_string(client.rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
                tx = Transaction([client.payer, account], Message.new_with_blockhash([ix], client.payer.pubkey(), bh), bh)
                client.rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                               {"encoding": "base64", "skipPreflight": True}])
            time.sleep(0.5)
            live = client.account(account.pubkey())
            if live is not None:
                break
        if live is None:
            print("account creation not confirmed", file=sys.stderr)
            return 1
        print(f"created {account.pubkey()} ({len(data)} bytes, {lamports} lamports)")
    chunks = list(range(0, len(data), CHUNK))
    if args.probe:
        chunks = chunks[:1]
    pass_no = 0
    while time.monotonic() - started < args.max_seconds:
        live = client.account(account.pubkey())
        missing = [o for o in chunks if live[o:o + CHUNK] != data[o:o + CHUNK]]
        print(f"pass {pass_no}: {len(missing)}/{len(chunks)} chunks differ  t={time.monotonic() - started:.1f}s", flush=True)
        if not missing:
            print(f"DONE {account.pubkey()}")
            return 0
        bh = Hash.from_string(client.rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
        bh_at = time.monotonic()

        def send(offset: int):
            ix = Instruction(client.program_id, bytes([208]) + struct.pack("<I", offset) + data[offset:offset + CHUNK],
                             [AccountMeta(account.pubkey(), True, True)])
            tx = Transaction([client.payer, account], Message.new_with_blockhash([ix], client.payer.pubkey(), bh), bh)
            try:
                client.rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                               {"encoding": "base64", "skipPreflight": True}])
            except Exception as exc:  # noqa: BLE001
                return str(exc)[:120]
            return None

        errors = 0
        with ThreadPoolExecutor(8) as pool:
            for i, offset in enumerate(missing):
                if time.monotonic() - started > args.max_seconds or time.monotonic() - bh_at > 20:
                    break
                pool.submit(send, offset)
                time.sleep(1 / args.rate)
        time.sleep(4)
        pass_no += 1
    print("time budget reached; rerun to resume")
    return 2


if __name__ == "__main__":
    sys.exit(main())
