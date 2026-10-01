"""Drive one counter session as a single-lane DCG stream on a real cluster.

Opens a counter session with the fixed-plan session client, then streams
alternating write_input / advance steps through ``Sequencer.open_stream``.
Every step shares the session's write locks, so the whole run is one lane.
A small ``max_pending_steps`` forces journal pruning early, which is the case
that used to deadlock (package C review, C1).

Environment: the same DCG_* variables as run_session.py, plus
DCG_STREAM_STEPS (default 64 input/advance pairs) and DCG_STREAM_PENDING
(default 4).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path

from solders.hash import Hash
from solders.message import Message

from dcg.sequencer import (
    Commitment,
    PostconditionResult,
    RetryPolicy,
    Sequencer,
    TransactionStep,
)
from dcg.sequencer.stream_journal import StreamIdentity, StreamIntent, StreamLimits
from dcg.session import KernelRef, Session
from dcg.session.instructions import advance as encode_advance
from dcg.session.instructions import write_input as encode_write_input
from dcg.session.manifest import COUNTER_MANIFEST


def _fingerprint(info) -> str:
    if info is None:
        return "absent"
    return hashlib.sha256(bytes(info.data)).hexdigest()


async def main() -> int:
    pairs = int(os.environ.get("DCG_STREAM_STEPS", "64"))
    pending = int(os.environ.get("DCG_STREAM_PENDING", "4"))
    session = Session.from_environment(
        KernelRef.from_manifest(COUNTER_MANIFEST), input_capacity=max(2, pairs), max_steps=1
    )
    await session.open()
    transport = session.transport
    endpoint = transport.endpoint
    signers = session.signers.for_roles({"payer", "authority", "writer"})
    program_id = session.program_id
    addresses = session.addresses
    genesis = await endpoint.get_genesis_hash()

    sequencer = Sequencer(
        endpoints={endpoint.endpoint_id: endpoint},
        signer=signers,
        config=transport._sequencer_config,
    )

    built: dict[str, object] = {}
    before: dict[str, dict[str, str]] = {}
    intents: list[StreamIntent] = []
    for index in range(pairs):
        for kind in ("write", "advance"):
            if kind == "write":
                instruction = encode_write_input(
                    program_id=program_id,
                    addresses=addresses,
                    writer=session.signers.writer.pubkey(),
                    sequence=index,
                    value=bytes([1]),
                    wire_version=session.wire_version,
                )
                watched = (addresses.stream,)
            else:
                instruction = encode_advance(
                    program_id=program_id,
                    addresses=addresses,
                    authority=session.signers.authority.pubkey(),
                    cursor=index,
                    steps=1,
                    wire_version=session.wire_version,
                )
                watched = (addresses.session, *addresses.states)
            step_id = f"{len(intents):05d}-{kind}"
            built[step_id] = (instruction, watched)
            locks = tuple(sorted(str(meta.pubkey) for _role, meta in instruction.account_roles if meta.is_writable))
            intents.append(
                StreamIntent(
                    step_id=step_id,
                    dependencies=(),
                    route_group=endpoint.endpoint_id,
                    compute_class=f"dcg-stateful-tag-{instruction.tag}",
                    compute_unit_limit=200_000,
                    intent_digest=hashlib.sha256(instruction.data + step_id.encode()).hexdigest(),
                    recovery_policy_digest="stream-counter:account-delta-v1",
                    intent_data={"index": index, "kind": kind},
                    write_locks=locks,
                )
            )

    payer = session.signers.payer.pubkey()

    def factory(intent: StreamIntent) -> TransactionStep:
        instruction, watched = built[intent.step_id]

        def message(lease):
            return bytes(
                Message.new_with_blockhash([instruction.instruction], payer, Hash.from_string(lease.blockhash))
            )

        async def postcondition(pooled):
            snapshot = {}
            for address in watched:
                snapshot[str(address)] = _fingerprint(
                    await pooled.get_account_info(str(address), Commitment.CONFIRMED)
                )
            prior = before.setdefault(intent.step_id, snapshot)
            changed = snapshot != prior
            digest = hashlib.sha256(repr(sorted(snapshot.items())).encode()).hexdigest()
            return PostconditionResult(changed, digest if changed else None)

        return TransactionStep(
            step_id=intent.step_id,
            dependencies=intent.dependencies,
            endpoint_id=endpoint.endpoint_id,
            route_group=intent.route_group,
            route_affinity=intent.route_affinity,
            compute_class=intent.compute_class,
            compute_unit_limit=intent.compute_unit_limit,
            intent_digest=intent.intent_digest,
            recovery_policy_digest=intent.recovery_policy_digest,
            build_message=message,
            postcondition=postcondition,
            max_packet_bytes=intent.max_packet_bytes,
            write_locks=intent.write_locks,
            retry_policy=RetryPolicy.SAME_BYTES,
        )

    destinations = sorted(
        {str(meta.pubkey) for instruction, _ in built.values() for _role, meta in instruction.account_roles}
    )
    identity = StreamIdentity(
        run_id=f"stream-counter-{secrets.token_hex(4)}",
        genesis_hash=genesis,
        program_id=str(program_id),
        destination_accounts=tuple(destinations),
        signer_public_keys=signers.public_keys,
        route_policy_digest=sequencer.route_policy_digest,
        commitment_policy="confirmed",
    )
    journal = Path(os.environ.get("DCG_STREAM_JOURNAL", f"/private/tmp/dcg-stream-{identity.run_id}"))
    started = time.monotonic()
    stream = await sequencer.open_stream(
        identity,
        str(journal),
        factory,
        limits=StreamLimits(max_pending_steps=pending),
    )
    try:
        for intent in intents:
            await stream.append(intent)
        await stream.close_input(wait_for_pending=False)
        try:
            result = await asyncio.wait_for(stream.wait(), timeout=float(os.environ.get("DCG_STREAM_WAIT", "600")))
        except Exception:
            for step_id, exc in stream._failures.items():
                print(f"FAILED {step_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
            raise
    finally:
        await stream.close()
    elapsed = time.monotonic() - started
    session.cursor = pairs
    session._write_cursor = pairs
    state = await session.read_state()
    print(f"steps={len(intents)} pending_limit={pending} elapsed={elapsed:.1f}s "
          f"rate={len(intents) / elapsed:.2f} tx/s result={type(result).__name__}")
    print(f"counter: {state}")
    receipt = await session.close()
    print(f"close: {receipt}")
    await session.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
