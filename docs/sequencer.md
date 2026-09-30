# Python transaction sequencer

`dcg.sequencer` is a pure-Python transport core for DCG applications. It sends
application-built transaction messages through an injected signer and RPC
adapter. It does not construct DCG instructions, decide fees or rent, choose
retry safety, interpret program errors, or define application state.

The package currently provides the sequencing and journal API only. A chain
SDK or application supplies the `Signer` and `RpcEndpoint` implementations;
the offline tests use an in-memory fake and make no network calls.

## Offline tests

From the repository root, run the standard-library test suite with Python 3.12:

```sh
PYTHONPATH=python UV_PROJECT_ENVIRONMENT=/private/tmp/dcg-sequencer-venv \
UV_CACHE_DIR=/private/tmp/dcg-sequencer-uv-cache \
uv run --locked --no-sync --project python --python 3.12 \
python -m unittest discover -s python/tests -v
```

There are no live-network tests in this round.

## First use

Inside an async function, the builder receives the endpoint's blockhash lease
and returns the unsigned message bytes. It must encode the caller's compute
budget in the transaction message. The postcondition reads application-owned accounts and returns a
stable digest when it can identify the committed state.

```python
from pathlib import Path

from dcg.sequencer import (
    Backoff,
    EndpointLimits,
    JournalStore,
    PostconditionResult,
    Sequencer,
    SequencerConfig,
    TransactionPlan,
    TransactionStep,
)

# rpc implements RpcEndpoint; signer implements Signer. Keep their secrets in
# the signer implementation and choose the endpoint's genesis hash explicitly.
step = TransactionStep(
    step_id="write-range-0",
    dependencies=(),
    endpoint_id="fogo-testnet-rpc-a",
    compute_class="template-range-write",
    compute_unit_limit=180_000,
    intent_digest="sha256-of-the-stable-instruction-and-account-intent",
    recovery_policy_digest="sha256-of-postcondition-and-rebuild-policy-v1",
    build_message=lambda lease: build_wire_message(lease.blockhash),
    postcondition=lambda endpoint: read_range_postcondition(endpoint),
    write_locks=("template-range-0",),
)
plan = TransactionPlan(
    genesis_hash="the-configured-genesis-hash",
    program_id="the-target-program-id",
    destination_accounts=("template-account",),
    signer_public_key=signer.public_key,
    steps=(step,),
)
sequencer = Sequencer(
    endpoints={"fogo-testnet-rpc-a": rpc},
    signer=signer,
    config=SequencerConfig(
        endpoint_limits={"fogo-testnet-rpc-a": EndpointLimits(sends_per_second=8, max_in_flight=4)},
        backoff=Backoff(initial_seconds=0.25, maximum_seconds=4),
    ),
)
journal = JournalStore(Path("out/sequencer/run.jsonl"))
result = await sequencer.submit(plan, journal)

# On restart, construct the same plan and signer identity, then use the same
# journal path. The sequence validates the full plan before resuming a packet.
# result = await sequencer.resume(plan, journal)
```

`submit` requires an empty journal. `resume` requires an existing run. Both
return a `RunResult` with one `StepOutcome` per confirmed step. A returned
signature status can prove confirmation even when `getTransaction` metadata is
missing; fee and consumed-CU fields stay `None` when unavailable.

## Plan, batching, and pacing

Each `TransactionStep` declares its dependencies, endpoint, stable intent and
recovery-policy digests, compute class and limit, packet limit, write locks,
retry policy, message builder, and postcondition. The recovery-policy digest
binds postcondition and rebuild-authorization semantics across restarts. Plan
validation rejects unknown/cyclic
dependencies, missing endpoint limits, invalid budgets, duplicate step IDs,
and signer or plan identity mismatches before signing.

The sequencer fires up to `max_batch_size` ready independent steps together.
Declared dependencies gate the next wave. Steps sharing a declared write lock
are placed in separate waves. A batch means concurrent RPC sends; it is not an
atomic transaction and send order does not imply landing order. Endpoint
`sends_per_second` spaces sends, and `max_in_flight` bounds active transactions
from preparation through confirmation. These limits are local configured
caps, not measured network capacity.

The caller sets a compute class and a transaction-level CU limit for every
step. The core records these values and checks packet size, but it does not
inspect instructions or add a compute-budget instruction. Applications must
provide the appropriate per-class value and encode it in their message. The
transport does not assume a remaining-CU syscall exists; dynamic CU discovery
is not part of this API.

## Signing and packet size

The signer exposes only a public key, signature count and signature size, and
returns a signature plus exact signed bytes. The sequencer estimates the
serialized packet size before invoking the signer. The default cap is 1,232
bytes; a step may choose a smaller cap. It checks the returned bytes again
after signing as a consistency guard.

After signing, the exact raw transaction bytes and signature are appended to
the journal and fsynced before a send attempt is handed to the RPC adapter.
Every resend uses those stored bytes. The journal API never accepts a signer
secret, and the sequencer does not print or log credentials. Signatures,
public keys, transaction bytes, destination identities and state digests are
not private keys, but journals should still be stored with suitable local
access controls.

## Journal format v1

The journal is UTF-8 JSON Lines. Each row has `schema_version: 1`, a monotonic
sequence number, a run ID, an event name, an ISO-8601 timestamp and an event
data object. Appends are serialized, flushed, and `fsync`ed before returning;
new parent-directory entries are also synced. An incomplete final JSON row is
discarded on recovery. A malformed complete row, sequence gap, unsupported
version, plan mismatch, or signer mismatch stops resume.

The first `run_started` row binds genesis hash, program ID, destination
accounts, signer public key and signature shape, plan digest, and each step's
dependencies, compute budget, endpoint, packet limit, write locks, intent
digest, recovery-policy digest and retry policy. The digest intentionally does
not serialize Python callables; the application-supplied `intent_digest` must
bind the transaction's stable instruction and account intent, while
`recovery_policy_digest` binds postcondition and fresh-sign authorization
semantics.

| Event | Durable facts |
|---|---|
| `step_signed` | Generation, signature, base64 exact packet bytes, public signer identity, compute class/limit and blockhash lease/context. |
| `send_attempt_started` | The attempt was durably recorded before endpoint handoff. A crash at this point is treated as an ambiguous send and reconciled by signature/state. |
| `send_acknowledged` / `send_error` | Provider response signature or classified transport error; neither alone proves chain execution. |
| `status_observed` | Signature commitment, finalized error if any, slot and nullable fee/compute metadata. |
| `postcondition_observed` | Application state result and optional digest; `satisfied: null` means unknown. |
| `step_rebuild_authorized` | Adapter approval to create a new signature after old-identity reconciliation. |
| `step_confirmed` / `step_terminal_failure` | Confirmation source and nullable chain metadata, or finalized program refusal. |
| `step_ambiguous` / `step_time_cap` | Safe stop reason; the run can be resumed with the same plan and journal. |

The journal is append-only JSONL rather than a transactional database. The
implementation repairs an incomplete tail, but it does not encrypt entries or
provide multi-process journal locking. Use one sequencer process per run.
Fsync confirms the operating system accepted the bytes; it does not establish
storage-device power-loss behavior.

## Confirmation, ambiguity, and failures

| Class | Examples | Sequencer behavior |
|---|---|---|
| Resumable transport | RPC outage, rate limit/429, expired blockhash, per-step time cap | Bounded exponential backoff; honor `Retry-After`; preserve the current signature and exact bytes. An expired sent packet must be reconciled before a replacement signature. |
| Confirmed terminal | Finalized program error/refusal, invalid plan, packet too large | Persist finalized refusal where applicable and stop that dependency branch. No automatic new identity. |
| Ambiguous fate | Status unavailable or null and app state does not prove success | Preserve the signed identity and stop safely when its lease expires. A later `resume` repeats status and postcondition checks. |

`RetryPolicy.SAME_BYTES` (the default) can rebroadcast the same signed bytes
while the lease is live. `NEVER` sends once and only observes. The explicit
`RECONCILE` policy additionally requires `authorize_rebuild(evidence)`. A new
signature is allowed only after the old lease has expired, status has been
queried, and the application postcondition has been checked. The adapter must
decide whether its idempotency and observed pre/post state make rebuilding
safe. A timeout, null status, `BlockhashNotFound` text, or height alone is not
treated as proof that a prior packet cannot land.

When status is missing, the sequencer asks the app-supplied account
postcondition. A satisfied postcondition can confirm a step without transaction
metadata. Unknown fee or CU metadata remains `null`; it is never converted to
zero. A finalized program error is terminal even if an application might later
choose to construct a different plan.

Every step has a time cap. The designed default is 90 seconds; on timeout the
sequencer journals the cap event and leaves the last signed identity available
for resume. This bounds one step, not the overall plan.

## Defaults and limits

- **Designed:** maximum packet size defaults to 1,232 bytes.
- **Designed:** blockhash lease soft lifetime defaults to 6 seconds. The
  Basanos transport census (2026-09-30) reports about 150 slots / 6 seconds at
  observed 40 ms Fogo slots in one run (measured there); this value is not a network guarantee.
  A provider returns lease-specific expiry metadata and may request a shorter
  lifetime. Other networks should configure their own bound.
- **Designed:** every step requires caller-provided compute class and CU limit;
  no generic CU values are asserted.
- **Open:** production provider behavior, real signer implementations, live
  network limits and power-loss behavior have not been exercised in this
  package round.

## First Basanos migration

Migrate `scripts/rev8_template.py` first. Its setup/write/seal phases and
resumable upload cursors exercise independent writes, dependency boundaries,
packet checks, exact-byte resend and account-state reconciliation without
moving template policy into DCG. The Basanos adapter would construct each
revision-8 instruction and its account metas, set the instruction-class CU
limit, expose destination/write-lock identities, and implement range/cursor
postconditions from the template accounts. It would wrap the existing Basanos
RPC transport and signer behind `RpcEndpoint` and `Signer`, pass the v8
program/template identities into `TransactionPlan`, and leave cursor policy,
template bytes, account allocation, rent, fees, and the decision to authorize a
fresh signature in the Basanos adapter. This round does not migrate that
sender.
