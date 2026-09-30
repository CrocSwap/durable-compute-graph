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
- `close()` halts, closes its journaled children and session, and returns a
  `CloseReceipt` with refunded lamports.

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

`Session` keeps a small mode-0600 JSON inventory containing each derived
account's role, parent and lifecycle (`planned`, `created` or `closed`). It
writes the plan before account creation, then marks each account created after
the sequencer confirms the transaction. Before cleanup, the client checks each
journaled address and parent against the session's independent derivations.
`close()` only submits close operations for inventory entries marked created;
it never searches for or closes unrelated accounts.

The inventory is local cleanup groundwork, not an on-chain ownership proof or
a crash-recovery protocol. The sequencer keeps the exact transaction journal
for each operation. If a process stops after an on-chain create but before the
inventory update, cleanup fails closed until that account is reconciled.

## Verification scope

Offline tests cover the instruction goldens, v1/v2 PDA vectors, the Rust
refusal-code constants, writable-role diagnostics and rejection of an
inventory address outside the derived session. The opt-in
`test_session_local_validator.py` runs the built `sbf-lifecycle-test` image on
a local validator, exercises the counter, submits an intentionally read-only
advance account and checks the named refusal, then verifies journaled account
reclaim. It is separate from the original native ProgramTest `run.py` path.

The test image uses a test-only static kernel. This is mechanics evidence for
the local SBF handler and client integration, not a deployed program result,
kernel-quality claim or network measurement.
