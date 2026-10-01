# Typed Python stateful session client

`dcg.session` is an application-facing layer over the durable transaction
sequencer. It derives the stateful PDAs, encodes the selected wire operations,
submits each transaction through the existing signer/RPC/journal boundary,
and interprets account bytes as typed results.

## API

- `KernelRef.from_manifest(mapping)` validates the 16-byte kernel ID, semantic
  and ABI versions, mode, state schema, command width and state-span lengths.
- `Session.from_environment(kernel)` reads `DCG_RPC_URL`, `DCG_PROGRAM_ID`,
  `DCG_PAYER_KEYPAIR`, `DCG_AUTHORITY_KEYPAIR`, optional
  `DCG_WRITER_KEYPAIR`, and local journal paths.
- `open()` derives and creates the session, input stream and state spans.
- `write_input(value)` encodes one typed input at the next stream cursor.
- `advance(n)` advances only after enough inputs are journaled to the client.
- `read_state()` returns a `CounterState` for the checked-in counter codec, or
  bytes for a byte-state manifest.
- `close()` reconciles chain state, halts and retires the session, retires and
  closes its children, then closes the session and returns a `CloseReceipt`.

The caller supplies separate fee-payer, authority and optional writer
keypairs. Only keys required by each transaction message sign it. The private
key material remains inside `SessionSigners`; the sequencer journal stores
public identities and signed transaction bytes under its existing policy.

## Wire and account layouts

`dcg.session.layout` owns the PDA seed sets by stateful wire version. V1 uses
`dcg-session-v1`, `dcg-input-v1`, `dcg-state-v1` and `dcg-view-v1`; v2 uses the
corresponding `-v2` seeds. A future version adds one layout entry rather than
adding seed branches throughout the client.

The `examples/hello-world` counter is currently wired to stateful v1 and the
v1 `CounterKernel`. The Python encoder preserves those exact instruction data
bytes for compatibility. The client also encodes the shared v2 open, create,
input, advance, halt and close forms, including bounded state growth and
initialization. The separate v2 scaled workload has another manifest and is
not the counter example's end-to-end target.

The instruction golden test fixes the five data byte strings emitted by the
existing Rust example. PDA vectors were independently produced with Solana's
Rust `find-program-derived-address` CLI for v1 and v2. The refusal table is
checked against the Rust constants in `stateful.rs` and `stateful_v2.rs`.

## Readable refusals

Known custom codes become named exceptions with a short explanation and a
recommended next step. In particular, `Custom(2304)` is mapped to the session
account refusal; when an instruction marks a required mutable role read-only,
the exception also names that account role and says to mark it writable. The
v2 code band `2321–2336` is mapped separately from v1 `2301–2314`.

## Account inventory and cleanup

`Inventory` is the account list used by session cleanup and is also available
for other DCG account kinds. Each record stores its kind, role, PDA seeds,
derived address, parent, lifecycle (`planned`, `live`, `retired`, or `closed`),
payer, rent lamports, and optional expected data size. The file is atomically
replaced with mode `0600`. `planned` is a pre-create recovery marker; `live`,
`retired`, and `closed` are the account lifecycle states. Existing v1 session
journals are upgraded only when the new seed-derived plan matches their
recorded address, role, and parent.

The chain is the source of truth. `await inventory.reconcile(rpc)` derives each
address from its saved seeds, reads all expected accounts with
`getMultipleAccounts`, and reports missing accounts, untracked children,
owner/size/header problems, and lifecycle mismatches in a
`ReconciliationReport`. Parent-bearing account kinds use filtered
`getProgramAccounts` reads to find children omitted from the local file. Pass
`rebuild=True` to add recognized on-chain children whose headers contain their
parent and enough seed material. The report exposes `missing`, `unexpected`,
`wrong_state`, `chain_children`, `rebuilt`, and `discovery_complete` fields.
Operators should stop cleanup if discovery is incomplete or the report has
unresolved drift.

To inspect or recover a session inventory:

```python
report = await session.inventory.reconcile(session.transport.endpoint, rebuild=True)
if not report.ok:
    print(report)
```

Call `inventory.retire(address)` only when an account is no longer intended for
use. Retirement is local cleanup intent; for a session, `Session.close()` first
halts the on-chain session before retiring it. `inventory.close(address, rpc,
close_action)` refuses live or planned accounts, re-reads the account from
chain, checks its owner, size, header state and seed-derived address, verifies
that no on-chain child names it as parent, invokes the kind-specific close
instruction, and records `closed` only after a further batched read confirms
the account is gone. The program handler remains the final atomic guard against
a child appearing between the client read and the close transaction.

Rebuild can recover role, seeds, parent, current size, and current lamports
only for registered header codecs. It cannot recover the original payer from
Solana account state, so a rebuilt record leaves `payer` unset. Account kinds
whose headers omit their parent cannot be discovered from child scans and need
an explicit application-level inventory entry. Register a codec for each
parent-bearing kind before relying on dependency checks for it.

The inventory is local recovery metadata, not an ownership proof or an
independent crash-safe transaction journal. The sequencer retains the exact
transaction journal for each operation. After a create lands but the local
write is interrupted, run reconciliation with rebuild enabled before cleanup;
the client does not trust the saved lifecycle over account reads.

### Basanos cleanup migration

Basanos cleanup scripts should adopt `Inventory` when they move to the packaged
DCG Python client. At account creation, record the exact seed tuple, kind/role,
parent, payer, and expected data length. Before cleanup, run reconciliation
against the same configured RPC and preserve its drift report with the run
receipt. Rebuild only account kinds with checked parent-header codecs. Replace
direct close calls with the sequence “retire, recheck, close” and a
kind-specific close action. Keep Basanos-specific account discovery and
ownership policies in the cleanup caller; the generic inventory owns seed
derivation, drift reporting, and close gating. Migration can proceed script by
script after the DCG package/API version is pinned.

## Verification scope

Offline tests cover the instruction goldens, v1/v2 PDA vectors, the Rust
refusal-code constants, writable-role diagnostics, inventory seed derivation,
mocked RPC drift cases (missing, extra, wrong owner and wrong size), rebuild,
dependency refusal, and rejection of a live-account close. The opt-in
`test_session_local_validator.py` runs the built `sbf-lifecycle-test` image on
a local validator, exercises the counter, submits an intentionally read-only
advance account and checks the named refusal, then verifies journaled account
reclaim. It is separate from the original native ProgramTest `run.py` path.

The test image uses a test-only static kernel. This is mechanics evidence for
the local SBF handler and client integration, not a deployed program result,
kernel-quality claim or network measurement.
