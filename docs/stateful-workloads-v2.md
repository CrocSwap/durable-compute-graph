# Stateful workloads v2 (local prototype)

Status: designed and implemented as a separate stateful wire version. The
v1 adapter and its wire bytes remain available. The v2 SBF run is a mechanics
demonstration; it does not include Doom code and does not change revision-8
instructions, records, or goldens.

V2 keeps the stateful tag range 230–239 and selects semantics from the wire
version byte. Its session and child accounts use separate `DSS2`, `DSB2`,
`DSE2`, and `DVW2` headers and versioned PDA seeds. The default revision-8
entrypoint still does not dispatch these app-owned tags. The test app uses the
processor composition helper and links one static workload kernel.

## V2 additions

| Tag | V2 operations | Contract |
|---:|---|---|
| 230 | OPEN_SESSION | Commits the resource key, schema, and digest with the existing session and kernel identity. |
| 231 | CREATE_STREAM, GROW_STREAM | Keeps one session and absolute cursor while increasing capacity by at most 512 slots per growth instruction. The session and stream header retain the same stream root. |
| 232 | CREATE_STATE, GROW_STATE, INITIALIZE_STATE | Creates up to eight contiguous spans, grows each account by at most 8,192 bytes per instruction, then authenticates and initializes state. GROW and INITIALIZE are subtypes under tag 232. |
| 233 | CREATE_VIEW, CREATE_SCRATCH, GROW_VIEW | Supports up to 16 ABI-bound outputs and scratch sized for their concatenation. GROW is a subtype under tag 233. |
| 234 | WRITE_INPUT | Keeps the existing indexed/append policies and write-once slots. The writable window remains bounded to 64 commands from the current cursor. |
| 235 | ADVANCE | Keeps the existing cursor, gap, and atomicity checks; one instruction advances at most eight steps. |
| 236 | BEGIN_PHASE, RUN_PHASE, COMMIT_PHASE, ABORT_PHASE | Stages a declared output set in bounded chunks, verifies the exact phase cursor and state cursor, and publishes all outputs in one final transaction. |
| 237 | HALT_SESSION | Halts only at the current cursor and outside an active publication phase. |
| 238 | CLOSE_ACCOUNT | Closes child/session accounts after halt and returns lamports to the authority recorded by the session. |
| 239 | ANCHOR | Retains explicit input-chain and state anchoring; ordinary consensus advances remain hash-free. |

The 10,000,000-byte aggregate state bound remains. An individual account may
grow to the SVM account-data limit; each realloc step is capped at 8,192 bytes
and receives its rent top-up from a signed payer. V2 stream capacity is bounded
by account size, and each stream growth adds at most 512 slots. A publication
phase declares a fixed compute limit chosen by the compiled kernel; the
adapter rejects a declaration above the existing 1,400,000-CU runtime bound.
The concatenated output set must fit its scratch account, which is capped at
4,000,000 bytes. The test kernel declares 1,000,000 CU and stages at most
65,536 output bytes per phase. These are designed limits, not measured cost
estimates.

`OPEN_SESSION` records an optional read-only resource key, schema, and
commitment. `CREATE_STATE` binds that resource account into the state setup.
After all state accounts have grown, `INITIALIZE_STATE` passes resource spans
and the committed digest to `StatefulKernel::initial_state_spans_with_resources`.
The compiled kernel must validate resource bytes against the commitment before
using them; the adapter authenticates the account key and passes the declared
schema/digest, but does not prescribe an application resource codec.

`StateSpanMut::data_address()` returns the first application byte after the
128-byte account header. `bind_invocation_state` runs before initial-state and
transition callbacks, and `unbind_invocation_state` runs after them, including
when a callback refuses. The address is callback-local: it is not encoded in
session/state data. A view callback receives authenticated state slices whose
data begins after the same header; `AccountSpan.data.as_ptr()` is its
read-only context address. Application code must rebind and clear any engine
context around each engine call, including render calls.

The processor helper `process_with_kernel_or_else` routes tags 230–239 to the
selected v1/v2 static kernel and routes tag 240 by wire version to v3's
resource-copy handler. Other tags go to the app's existing handler. It defines
no Solana entrypoint. An application can therefore keep one entrypoint and
compose DCG handling with its existing dispatch.

## Resumable view publication

Tag 236 uses operation subtypes 0–3 for begin, run, commit, and abort. Begin
binds the phase to the current state cursor, sums declared output lengths, and
stores the phase compute declaration. Each run must name the exact next byte
cursor, the same declaration, and unchanged state. It writes at most the
kernel's fixed phase byte limit into scratch in role order. A run refuses if
the state cursor or any state span version changes during publication. Abort
clears the in-session phase record. Commit requires every output byte to have
been staged against the same state cursor, then copies the complete ordered
scratch contents to all outputs in one Solana transaction. Until commit, the
output accounts remain untouched.

The default `render_view_phase` copies the requested range from canonical
state. A workload may override it with a renderer, but must keep each callback
bounded by the declared bytes and compute units. The scaled test uses the
default copy callback. It demonstrates multi-transaction staging and atomic
publication, not the cost or quality of an application renderer.

## Scaled SBF demonstration

`tests/stateful_v2_sbf_workload.rs` runs the feature-built SBF ELF in ProgramTest.
Its static kernel creates two state spans: a 16-byte counter and a contiguous
1,113,792-byte payload. It binds a test resource into the second span, then
publishes a 1,048,768-byte snapshot and eight 8,128-byte strips. The 1,001-step
workload crosses stream capacities 64, 576, and 1,024 while preserving the
same session, absolute cursor, and stream root. One extra transition occurs
after an intentionally suspended publication to check state-version refusal;
the successful output set is then published at cursor 1,002.

The test covers these exact instructions and refusal paths:

- 230 open; 231 create and grow stream from 64 to 576 and 576 to 1,024.
- 232 wrong-resource refusal, large state creation, 135 bounded state growth
  instructions, then authenticated initialization.
- 233 creation of nine outputs and scratch, followed by 263 bounded growth
  instructions for the snapshot and scratch.
- 234 1,002 successful input writes, one deliberate duplicate write refusal.
- 235 126 advances across 1,001 steps, a gap refusal with state/session/stream
  bytes checked unchanged, and a successful transition during a suspended
  publication.
- 236 stale phase-cursor refusal, state-version-changed refusal with scratch
  checked unchanged, abort, a fresh 17-chunk run, and one atomic commit. The
  test checks that outputs stay byte-for-byte untouched until commit.
- 237 halt; 238 live-close refusal, then close/refund every child and session.
- 239 is not exercised by this v2 workload test.

The test reads the resource in `initial_state_spans_with_resources`, verifies
its key/schema/hash/content, and checks the resulting state and all nine views.
Its invocation-local kernel stores the engine pointer only in that kernel
instance while a callback is active; it compares the pointer against the
actual state span address and clears it after callbacks. No pointer is
serialized. This is a binding mechanics check, not a Doom engine integration.

The per-instruction SBF compute measurements and exact reproduction command
are in [`experiments/stateful-sbf-workload-v2-2026-09-30.md`](experiments/stateful-sbf-workload-v2-2026-09-30.md).

## Doom adapter work remaining

The generic mechanics are available for an adapter, but no Doom code was
added. The Doom app still needs to pin its kernel semantic/ABI versions and
state schema; encode/import its 9,734,160-byte context and companion state
spans; implement the indexed four-byte tic command and exact halt policy; and
compare every resulting state boundary with the retained SIM/2 oracle. The
adapter must bind the actual context-span address, with the account header
excluded, around each engine transition and render call, and clear the pointer
before returning.

At session creation, the Doom adapter must bind and validate its WAD key,
schema, and content digest in `initial_state_spans_with_resources`. It must
compose `process_with_kernel_or_else` into Doom's existing single SVM
dispatcher. For rendering, it must assign the snapshot/eight-strip ABIs,
implement the Doom renderer in deterministic resumable chunks, choose the
phase byte and CU declarations, and measure every phase on the final SBF
image. This run shows only that v2 can stage and atomically publish those byte
counts using the default copy renderer; it does not establish that Doom's
render work fits any phase declaration. The v2 input-chain `ANCHOR` tag is
available, but was not exercised in this workload test.

V2 currently initializes all state spans in one `INITIALIZE_STATE`
instruction. The test resource callback only writes its small resource prefix
into otherwise zeroed state, so the measured initialization cost does not
cover importing Doom's 9.7 MB context. Measure the complete WAD-to-context
initialization against the runtime ceiling before calling the adapter usable;
if it does not fit, add a deterministic resumable initialization stage with
the same stale-state protections before integrating Doom.
