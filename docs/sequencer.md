# Python transaction sequencer

`dcg.sequencer` is a pure-Python transport core for DCG applications. It sends
application-built transaction messages through an injected signer and RPC
adapter. It does not construct DCG instructions, decide fees or rent, choose
retry safety, interpret program errors, or define application state.

The stateful application layer is [`dcg.session`](python-session.md). It uses
this sequencer while owning stateful PDA derivation, instruction encoding,
typed state reads, known stateful refusal messages and a local account
inventory for cleanup. These responsibilities stay outside the generic
sequencer core.

The package includes a production HTTP JSON-RPC endpoint and a keypair-file
signer, alongside the injectable `RpcEndpoint` and `Signer` protocols. Offline
tests use an in-memory fake or an HTTPX mock transport and make no network
calls.

## Which API to use (alpha)

The sequencer is consensus mode's transport. Four layers, from simplest to
fastest:

| Layer | Use it for | Exactly once from | Measured |
|---|---|---|---|
| `dcg.session.Session` | a session from Python: open, write, advance, read, close | the program's cursor guards, plus a journal per transaction | 16 steps/s on a local validator: 8 steps per transaction, one transaction confirmed at a time (`examples/session-app/long_session.py`, 2026-10-05) |
| `Sequencer` with a `TransactionPlan` | a fixed list of dependent transactions you build yourself | the journal (`JournalStore`) and your postconditions | as `Session`: one confirmation round trip per transaction |
| `SequencerStream` | an open-ended stream, with backpressure, batched confirmation and restart from the journal | the stream journal | see "Streaming plans" |
| `OrderedLane` | a chain of dependent transactions sent without waiting for each one; out-of-order landings are repaired | the application's on-chain guards (each step must refuse when it is not next) | Doom on DCG, Fogo testnet from Tokyo: 3.81 frames/s, 8 game steps per frame, 3 lanes, 1,000 frames with no repairs (Basanos M1384, 2026-10-05) |

Start with `Session` ([`session-tutorial.md`](session-tutorial.md)). Move to
`OrderedLane` when the round trip per transaction is the bottleneck.

**Batching.** `Session.write_and_advance(values)` writes up to `max_steps`
(at most 8) inputs and advances over them in one transaction: all of it
applies, or none does. The transport's `send_many` puts any list of session
instructions in one transaction; keep the packet under 1,232 bytes.

**What the sequencer guarantees:**
- **Signed bytes are journaled before they are sent.** A rebroadcast reuses
  the same bytes while their blockhash is valid. A new signature is made only
  after the old one's blockhash has expired, its status has been queried, and
  the application's postcondition has been checked (details below).
- **A dropped transaction is resent.** In the measured long sessions, one
  send was dropped on purpose. In a 400-step run a rebroadcast of the same
  bytes landed. In the 16,000-step run (2,008 transactions) the dropped
  signature never landed; after its blockhash expired, the sequencer checked
  the session's state and signed the step again. Every step applied once.
- **Unclear outcomes stop safely.** If a transaction's fate cannot be
  established, the sequencer stops that step instead of guessing. Resuming
  with the same plan and journal checks again and finishes the work.
- **Refusals are final and named.** A program refusal is not retried; the
  session layer raises it as a named error (`dcg.session.errors`).

**Exactly once needs the program too.** The sequencer never knowingly sends
a step twice under two signatures. But the guarantee that a step applies at
most once comes from the program: a session's cursor guards refuse a
duplicate. Keep such guards in any program you drive with the sequencer.

**What it does not guarantee:**
- **Landing order across lanes or parallel sends.** That comes from the
  program's guards. `OrderedLane` repairs out-of-order landings only because
  the steps refuse when they are not next.
- **Fees or priority.** The application chooses compute limits and prices
  (`OrderedLane` documents the levers that worked for Doom).
- **Liveness of the network.** A step that cannot land before its time cap
  is reported, not forced.

**Throughput guidance.**
- One confirmed transaction at a time costs one confirmation round trip:
  about 0.5 s on a local validator with 50 ms slots, more on a remote
  testnet node. Batch steps into transactions first; 8 tally steps used about
  64,000 compute units.
- A long session through `Session` on a local validator ran 16,000 steps
  in 2,008 transactions in 1,113 s (14.5 steps/s;
  [`session-tutorial.md`](session-tutorial.md)).
- For more, pipeline with `OrderedLane`, and run close to the RPC node.
  Doom's 3.81 frames/s ran from a host near the Fogo testnet nodes.

## Production adapters

The runtime dependencies are pinned in `pyproject.toml` and `uv.lock`:

- `httpx==0.28.1` provides async HTTP, connection reuse, and explicit request
  timeouts for JSON-RPC.
- `solders==0.29.0` parses Solana keypair bytes and signs canonical legacy and
  v0 messages. This avoids implementing Ed25519 or transaction signature
  framing in the client.

`SolanaRpcEndpoint` implements `sendTransaction`, `getLatestBlockhash`,
`getSignatureStatuses`, `getAccountInfo`, `getHealth`, and
`simulateTransaction`. It checks `getGenesisHash` before issuing its first
blockhash lease and rejects a mismatch with the plan. Account reads accept
`confirmed` or `finalized`; simulations accept the requested commitment.
Metadata not returned by `getSignatureStatuses` remains `None`.

`Sequencer` puts every blockhash, status, account and send request through an
`EndpointPool`. Each node has independent send and total-request rates, an
in-flight cap, a weight and a route group. A single confirmation pump coalesces
signature watches across fixed-plan steps, stream lanes and send providers;
status batches are capped at 256 by default. The pool is the authoritative
limiter, so configure `SolanaRpcEndpoint`'s own limiter high enough that it
does not impose a lower competing cap. HTTP 429 and JSON-RPC rate-limit errors become
`RateLimited` and honor `Retry-After`; timeouts, transport failures, and 5xx
responses become `RpcUnavailable`; explicit blockhash errors become
`BlockhashExpired`; and explicit instruction/program errors become
`ProgramRefused`. Other HTTP 4xx responses become terminal
`RpcConfigurationError`. Unknown JSON-RPC errors remain resumable so they do
not authorize a fresh signature.

`KeypairFileSigner.from_file(path)` reads a standard Solana 64-byte JSON
keypair into memory and supports one required transaction signer. It validates
that the message fee payer matches the keypair before signing. A regression
test checks that private key bytes do not appear in captured output or the
journal. Hardware or remote signers can implement the `Signer` protocol,
keeping signing custody outside the sequencer. `MultiSigner` combines multiple
injected `MessageSigner` implementations in the required-signer order encoded
by the Solana message. It checks that this order matches the supplied signer
set and that each signer returns a 64-byte signature. The first signer remains
the plan's primary signer; fixed-plan identity and digest also bind the full
ordered signer list when a plan uses multiple signers. Every returned
signature is verified against its required message key before the transaction
is assembled. The sequencer never opens or discovers additional key material.

```python
from dcg.sequencer import KeypairFileSigner, RpcConfig, SolanaRpcEndpoint

signer = KeypairFileSigner.from_file("/secure/path/id.json")
rpc = SolanaRpcEndpoint(
    "fogo-rpc-a",
    "https://rpc.example.invalid",
    config=RpcConfig(timeout_seconds=8, requests_per_second=12, max_in_flight=6),
)
```

Close the endpoint with `await rpc.aclose()` or an async context manager when
the run ends.

## Offline tests

From the repository root, install the pinned dependencies once, then run the
offline test suite with Python 3.12:

```sh
UV_PROJECT_ENVIRONMENT=/private/tmp/dcg-sequencer-venv \
UV_CACHE_DIR=/private/tmp/dcg-sequencer-uv-cache \
uv sync --locked --project python --python 3.12

UV_PROJECT_ENVIRONMENT=/private/tmp/dcg-sequencer-venv \
UV_CACHE_DIR=/private/tmp/dcg-sequencer-uv-cache \
uv run --locked --no-sync --project python --python 3.12 \
python -m unittest discover -s python/tests -v
```

The default suite is offline. The opt-in local-validator test is skipped unless
`DCG_RUN_LOCAL_VALIDATOR=1` is set. The 100k-step streaming persistence test is
also opt-in; set `DCG_RUN_STREAM_100K=1` when invoking `unittest` to include it.

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
    KeypairFileSigner,
    SolanaRpcEndpoint,
    TransactionPlan,
    TransactionStep,
)

# The endpoint checks its actual genesis hash against the plan before it gets
# the first blockhash. Keep key material inside the signer.
signer = KeypairFileSigner.from_file("/secure/path/id.json")
rpc = SolanaRpcEndpoint("fogo-testnet-rpc-a", "https://rpc.example.invalid")
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

For fixed plans, the sequencer fires up to `max_batch_size` ready independent
steps together. Declared dependencies gate the next wave. Steps sharing a
declared write lock are placed in separate waves. A batch means concurrent
sends; it is not an atomic transaction and send order does not imply landing
order. Each signed send attempt is journaled and fsynced first; the sequencer
then acquires a `RequestKind.SEND` pool lease immediately before handing the
exact packet bytes to its provider. RPC and TPU/QUIC use the same lease rule.
The lease selects the observer endpoint recorded for the attempt, including
when a shared TPU helper carries the packet.

The default health policy cools a node after three consecutive transport
failures or immediately after any rate limit/429. Its base cooldown is one
second, doubling up to 60 seconds, followed by a probe before normal traffic
resumes. These values, each node's rates and in-flight cap, pool acquisition
deadline, and health thresholds are configurable through `SequencerConfig`
and `EndpointLimits`. They are operator caps, not measured network capacity.

```python
from dcg.sequencer import EndpointLimits, SequencerConfig

config = SequencerConfig(
    endpoint_limits={
        "rpc-a": EndpointLimits(
            sends_per_second=8,
            requests_per_second=40,
            max_in_flight=4,
            weight=2,
            route_group="cluster-a",
        ),
        "rpc-b": EndpointLimits(
            sends_per_second=4,
            requests_per_second=20,
            max_in_flight=2,
            route_group="cluster-a",
        ),
    },
)
```

RPC is the default send provider. A configured provider can instead submit
signed bytes through TPU/QUIC; status and application state observations
still use the checked RPC endpoints. Provider handoff acknowledgments do not
prove landing. A helper failure leaves the signature ambiguous and the
journaled bytes authoritative.

In streaming mode, asynchronous TPU `ERR` records are matched to their
acknowledged signature and recorded as `late_provider_failure`; a provider's
existing failure callback is preserved and chained. Errors without a matching
active stream attempt are kept in a bounded 256-entry
`sequencer.unmatched_provider_failures` queue for application handling.
Fixed-plan v1 has no late-provider event, so its journal shape is unchanged;
its asynchronous failures remain available in that queue and the provider's
own bounded `drain_failures()` queue.

## Streaming plans

`Sequencer.open_stream()` adds open-ended scheduling while retaining
`TransactionPlan` and `submit`/`resume` for finite work. The stream identity
binds the run, genesis, program, destination accounts, signer set, route-policy
digest and commitment policy. Each append is a durable `StreamIntent` with a
monotonic sequence, stable digest, dependencies, route group, compute and
packet limits, and write locks. A callback builds the transaction step from
that intent; it cannot change the durable intent fields.

```python
from dcg.sequencer import (
    StreamIdentity,
    StreamIntent,
    StreamLimits,
)

identity = StreamIdentity(
    run_id="render-session-17",
    genesis_hash=genesis_hash,
    program_id=program_id,
    destination_accounts=(session_account, workspace_account),
    signer_public_keys=(signer.public_key,),
    route_policy_digest=sequencer.route_policy_digest,
    commitment_policy="confirmed",
)
stream = await sequencer.open_stream(
    identity,
    "out/sequencer/render-session-17",
    build_step_from_intent,
    limits=StreamLimits(
        max_pending_steps=128,
        max_journal_bytes=1_000_000_000,
    ),
)
await stream.append(StreamIntent(
    step_id="advance-0",
    dependencies=(),
    route_group="cluster-a",
    route_affinity="session-lane",
    compute_class="advance",
    compute_unit_limit=180_000,
    intent_digest="sha256-of-stable-advance-intent",
    recovery_policy_digest="sha256-of-postcondition-and-recovery-policy",
    intent_data={"cursor": 1},
    write_locks=(session_account,),
))
await stream.checkpoint()
await stream.close_input(wait_for_pending=True)
result = await stream.wait()
```

The stream queue is bounded and `append` applies backpressure at its configured
pending-step limit. The configured journal quota defaults to 1 GB; exact signed
packets and every attempt stay in the journal until safe terminal handling.
Call `checkpoint()` at an application-selected terminal prefix. Package B
compacts the stream into the latest checkpoint and deletes the older checkpoint
and covered segments after the new manifest pointer commits. The effective
checkpoint retention is therefore one, including with the default
`SequencerConfig.stream_checkpoint_retention=2`; that setting is currently
validated but does not change Package B's compaction policy. Keeping only the
latest checkpoint is safe because it contains the state needed to resume, and
the prior files are removed only after the new pointer commits. Quota exhaustion
stops new appends rather than evicting unresolved signed work.

The default `LatencyMode.CONFIRMED` releases dependents only after the
configured stable commitment. `LatencyMode.PROCESSED` can release bounded
optimistic descendants after a parent reaches `processed`: the default limit
is two dependency steps or two seconds per unresolved branch. Optimistic
outcomes carry `optimistic=True` and appear in `RunResult.optimistic_steps`;
they are not confirmed outcomes. The journal labels each observation as
`optimistic`, `stable`, or `unresolved`; `SequencerStream.optimistic_steps`
lists pending steps whose latest observation remains optimistic. Processed mode
requires an app-supplied `reconcile_dropped` callback. If a processed signature
disappears, the journal records the drop and branch invalidation. The callback
reads app-owned state, and the scheduler checks every already-signed descendant's signature and
postcondition through its callback, and then raises `ReconciliationRequired`.
It does not automatically replay or replace signed bytes. Package B's
`reconciliation_required` method also accepts unsigned descendants, so each
invalidated pending intent is journaled even when it never received a packet.
After application reconciliation, the adapter can journal a `continue`,
`rebuild`, or `abandon` decision with its evidence digest. An abandoned
descendant is released from the pending bound only after a terminal
`abandoned` summary references that decision; this outcome has no stable
commitment. For signed work, abandonment remains the application's decision
and requires evidence that the packet can no longer land.

The stream shares one batched confirmation pump across lanes and configured
send providers. Steps with overlapping write locks serialize; independent
lanes can run concurrently subject to pool admission. Checkpoint and stream
journal formats are versioned separately from fixed-plan v1. The fixed-plan
v1 manifest, digest and event shape remain unchanged for single-signer plans.

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

In streaming mode, abandonment is also an application-adapter decision. Before
it records an `abandon` reconciliation decision and terminal summary for a
signed step, the adapter must have evidence that the packet can no longer land.
A timeout, missing status, provider error, or block-height observation alone
does not establish that. The journal records the adapter's evidence digest and
decision; it cannot independently prove the packet's fate. Unsigned descendants
can be abandoned after the adapter has reconciled their dependencies and
application state.

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
- **Designed:** endpoint cooldown starts at one second, doubles to a 60-second
  cap, and requires three consecutive transport failures or any rate limit;
  after cooldown the next bounded request is a probe.
- **Designed:** stream quota defaults to 1 GB, and processed optimism is
  bounded to two steps or two seconds. Package B currently retains only the
  latest compacted checkpoint; see Streaming plans.
- **Open:** external-cluster behavior, live network limits, TPU helper runtime
  packaging, and storage-device power-loss behavior have not been exercised
  in this package round.

## Run against a local validator

Build the standalone DCG SBF image with the repository's pinned platform-tools
v1.51 wrapper, then run the opt-in integration test:

```sh
export DCG_SBF_SDK=/private/tmp/basanos-sbf-sdk-v151-20260920
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-sequencer-2-sbf-staging
export CARGO_TARGET_DIR=/private/tmp/dcg-sequencer-2-target

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-sequencer-2-sbf

DCG_RUN_LOCAL_VALIDATOR=1 \
DCG_SBF_IMAGE=/private/tmp/dcg-sequencer-2-sbf/dcg_program.so \
uv run --locked --no-sync --project python --python 3.12 \
  python -m unittest discover -s python/tests -p 'test_local_validator.py' -v
```

`test_local_validator.py` starts `solana-test-validator` under `/private/tmp`,
funds a temporary payer, then submits seven dependent transactions through the
sequencer, JSON-RPC adapter, and keypair-file signer. It kills a child
sequencer after the validator accepts the first packet but before its send
acknowledgment is journaled, then resumes from that journal and verifies the
final account state. It prints the transaction count, elapsed wall time,
retries, and recovered ambiguous fates. The ledger and journal are moved into
`/private/tmp/trash-dcg-sequencer-2` after the run; the temporary payer
keypair file is deleted during teardown.

Each local step uses `RetryPolicy.NEVER`. The kill exercise therefore measures
status/account reconciliation after an ambiguous send, not same-byte
rebroadcast frequency; same-byte retry behavior remains covered by the offline
sequencer tests.

The checked-in local fixture uses private test-only tags 240–250 for the
crate's four-entry ByteSum honest lifecycle. It validates the local RPC,
signer, journal-recovery, and SBF-loading path only. It does **not** run the
round-5 revision-8 sequence, PT2P/PT2S setup, registry/admission, or a protocol
lifecycle. Those Basanos-specific fixture builders are not part of this
standalone package, so revision-8 local-validator coverage remains open.

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

For `rev8_template.py`, the next adapter work is to map its existing
instruction builders to stable step intents, carry its per-tag CU limits and
write hazards into `TransactionStep`, and implement its account/cursor
postconditions from the template's current on-chain bytes. It also needs a
multisigner implementation for setup instructions that require the authority
and newly allocated account keypairs in one transaction. Compare its old
receipts against the sequencer journal on local-validator runs before replacing
the sender; keep cursor, rent, funding, fee, and fresh-sign authorization
decisions in the Basanos adapter.
