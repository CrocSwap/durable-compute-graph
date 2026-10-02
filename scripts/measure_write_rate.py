#!/usr/bin/env python3
"""Measure staged-write landing throughput on Fogo (optimistic disputes v2.1, open item O1).

A dispute's staging buffer is one account written in 900-byte chunks. This
writes 900-byte chunks repeatedly into one unsealed 10 KiB graph-v2 blob (tag
211) on the shared testnet graph program, cycling offsets, and reports landed
writes per second and bytes per second for three sending modes:

- sequential: send one, wait for confirmation, send the next;
- lane: OrderedLane windows (pipelined, in order);
- batch: OrderedLane.run_batch (unordered, re-sends missing).

Usage: measure_write_rate.py MODE [--writes N] [--window W] [--cap S]
Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL. Testnet only.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from dcg.sequencer import LaneStep, OrderedLane, keypair_signer  # noqa: E402
from solders.instruction import AccountMeta, Instruction  # noqa: E402
from solders.keypair import Keypair  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402

TESTNET_GENESIS = "9GGSFo95raqzZxWqKM5tGYvJp5iv4Dm565S4r8h5PEu9"
BLOB_BYTES = 10_240 - 76  # a CPI create is capped at 10,240 bytes including the header
CHUNK = 900
SYSTEM = Pubkey.from_string("11111111111111111111111111111111")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("sequential", "lane", "batch"))
    ap.add_argument("--writes", type=int, default=1165)
    ap.add_argument("--window", type=int, default=48)
    ap.add_argument("--cu", type=int, default=20_000)
    ap.add_argument("--cap", type=float, default=80.0)
    a = ap.parse_args()
    payer = Keypair.from_bytes(bytes(json.loads(Path(os.environ["DCG_PAYER_KEYPAIR"]).read_text())))
    program = Pubkey.from_string(os.environ["DCG_PROGRAM_ID"])
    url = os.environ["DCG_RPC_URL"]
    lane = OrderedLane(url, payer.pubkey(), keypair_signer(payer), user_agent="dcg-write-rate")
    if lane.rpc("getGenesisHash", []) != TESTNET_GENESIS:
        raise SystemExit("refusing: not Fogo testnet")

    # One unsealed blob per payer and run tag, created once.
    tag = os.environ.get("RATE_TAG", "o1-2026-10-02")
    blob_id = hashlib.sha256(b"dcg.steptable.id.v2\x00" + tag.encode()).digest()  # never sealed
    blob = Pubkey.find_program_address([b"dcg2blob", bytes([3]), blob_id], program)[0]
    if lane.rpc("getAccountInfo", [str(blob), {"encoding": "base64"}])["value"] is None:
        create = Instruction(program, bytes([210, 3]) + struct.pack("<I", BLOB_BYTES) + blob_id,
                             [AccountMeta(payer.pubkey(), True, True), AccountMeta(blob, False, True),
                              AccountMeta(SYSTEM, False, False)])
        r = asyncio.run(lane.run([LaneStep("create", (create,), 60_000)], repair=False, wait_seconds=20))
        if r.landed != 1:
            raise SystemExit(f"blob create failed: {r.first_error}")

    def write(i: int) -> LaneStep:
        offset = (i * CHUNK) % (BLOB_BYTES - CHUNK)
        body = bytes([i % 251]) * CHUNK
        ix = Instruction(program, bytes([211]) + struct.pack("<I", offset) + body,
                         [AccountMeta(payer.pubkey(), True, False), AccountMeta(blob, False, True)])
        return LaneStep(f"w{i}", (ix,), a.cu)

    steps = [write(i) for i in range(a.writes)]
    t0 = time.monotonic()
    landed = sends = 0
    if a.mode == "sequential":
        for s in steps:
            if time.monotonic() - t0 > a.cap:
                break
            r = asyncio.run(lane.run([s], repair=False, wait_seconds=10, salt=sends))
            sends += 1
            landed += r.landed
    elif a.mode == "lane":
        at = 0
        while at < len(steps) and time.monotonic() - t0 < a.cap:
            window = steps[at:at + a.window]
            r = asyncio.run(lane.run(window, repair=False, monotonic_limits=False, wait_seconds=10, salt=at))
            sends += 1
            landed += r.landed
            at += len(window)
    else:
        r = asyncio.run(lane.run_batch(steps, max_seconds=a.cap, resend_after_seconds=0.6))
        sends, landed = r.sends, len(r.landed)
    wall = time.monotonic() - t0
    out = {"mode": a.mode, "writes_attempted": len(steps), "landed": landed, "wall_s": round(wall, 2),
           "writes_per_s": round(landed / wall, 2), "bytes_per_s": round(landed * CHUNK / wall),
           "sends": sends, "window": a.window if a.mode == "lane" else None, "cu_request": a.cu,
           "packet_bytes": None, "rpc": url, "blob": str(blob)}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
