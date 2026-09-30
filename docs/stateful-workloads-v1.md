# Stateful workloads v1 (local prototype)

Status: designed and implemented as a versioned DCG adapter; the SBF
demonstration is test-only and does not change revision-8 instructions or
records. The test application links a small counter kernel. It contains no Doom
code, runtime loading, or kernel CPI.

The adapter follows the owner decisions in
dcg-stateful-workloads-2026-09-25.md: one session-owned input layer with
indexed and append policies, per-kernel consensus mode, schema-bound state
spans, output views declared from a kernel ABI, and close-with-refund for every
created account. Each instruction carries wire version 1; account headers use
versioned magic values DSS1, DSB1, DSE1, and DVW1.

## Versioned instruction surface

The app adapter reserves tags 230–239, outside revision 8. The default
revision-8 entrypoint does not dispatch them. The test image enables these tags
with sbf-real-lifecycle-test.

| Tag | Operation | Main checks |
|---:|---|---|
| 230 | OPEN_SESSION | Exact kernel semantic/ABI and consensus-mode identity; policy and stream geometry; finite compute, state, and operation limits; authority and PDA |
| 231 | CREATE_STREAM | One session-owned stream with fixed slot capacity and command width |
| 232 | CREATE_STATE | One to eight contiguous schema-bound state spans; total bytes within the kernel limit |
| 233 | CREATE_VIEW | Static output ABI id, source range and length, or a scratch span |
| 234 | WRITE_INPUT | Policy writer, in-range sequence, bounded lead, canonical command width, write-once slot |
| 235 | ADVANCE | Signed sequencer, expected cursor, bounded step count, complete input slots, ordered state spans |
| 236 | PUBLISH_VIEWS | Exact committed state cursor; distinct output and scratch accounts; all declared outputs in one transaction |
| 237 | HALT_SESSION | Recorded authority and current cursor |
| 238 | CLOSE_ACCOUNT | Session halted; refund destination is the recorded authority |
| 239 | ANCHOR | Explicit input-chain and state anchor at the current cursor |

The instruction tags are an application adapter example, not revision-9
consensus bytes. A workload image selects its own static kernel and tag map.

## Input stream

DSS1 binds the session id, authority, input writer, kernel id and versions,
consensus mode, policy, command width, capacity, maximum steps per transaction,
and an initial 32-byte stream root. It also stores each created child key so
ADVANCE, publication, and close validate bindings without deriving PDAs or
hashing stream/state on the normal consensus path. DSB1 is a separate account with the same
session and geometry. Each fixed 16-byte slot contains sequence:u32,
written:u8, three reserved zero bytes, and up to eight command bytes with a
zero tail.

For indexed policy, the recorded authority writes any unconsumed index inside
the capacity and at most half the capacity ahead of the cursor. This permits
out-of-order deposits and temporary gaps. A slot is write-once. ADVANCE only
accepts a consecutive sequence beginning at its expected cursor, so it refuses
if a gap remains.

For append policy, the recorded writer supplies exactly the current frontier as
its sequence. This policy cannot create gaps. Both policies use the same slot
layout, cursor, advance implementation, and close path.

Each advance names its expected cursor and a positive step count no greater
than the session's declared maximum. The end cursor must fit both the stream
capacity and the deposited frontier. The kernel manifest bounds input,
output, state, operations, and compute. The adapter checks
max_compute_units × requested_steps with checked multiplication against the
1.4M-CU transaction ceiling before running the kernel. The per-kernel compute
number is a designed ceiling; the SBF test reports measurements separately.

The input stream_root is the session's committed policy/root identity. The
running input_root starts empty. Ordinary deposits and consensus advances do
not hash. An explicit ANCHOR folds consumed (sequence, command) pairs from the
previous anchor cursor and hashes the current state spans. Default consensus
execution is hash-free, and callers pay for roots only when they request an
anchor.

## Engine-state spans

DSE1 stores no process address or runtime pointer. Each program-owned state
account binds the session, StateSchema id and version, span index and count,
canonical byte offset and length, total state length, and before/after cursor.
Span ranges must be nonempty, ordered, contiguous, non-overlapping, and cover
the full canonical state byte string. The adapter supports up to eight spans
and bounds their aggregate at 10,000,000 bytes. A kernel can implement
initial_state_spans and transition_spans to read or mutate these spans in
place without flattening a large state into a temporary buffer.

Every advance first authenticates all accounts, checks the state schema and
the prior cursor on every span, and validates all requested input slots. It
then runs each transition and records the prior and resulting cursors in all
state headers. Solana transaction atomicity covers writes across the session,
stream, and state accounts: a kernel refusal or malformed later step rolls the
whole instruction back.

## Views and scratch

An output view is a DVW1 account with the output-view flag, a statically
declared 32-byte ABI id, a canonical state offset and byte length, and the
source cursor/version of its last publication. StatefulKernel::view_abis
binds allowed ids, roles, and maximum lengths to the compiled app image. A
view must select a range within the committed state schema. It is not a state
input and is not added to a revision-8 record or Merkle root.

Scratch is a separate non-view role. PUBLISH_VIEWS validates two independent
output spans and the scratch span from one state cursor, stages both outputs in
scratch, then writes the output accounts in the same transaction. It rejects
aliases or a stale requested cursor before publication. Transaction atomicity
prevents one output from persisting without the other.

## Halt, close and rent

The authority halts an active session at its current cursor. Anyone may then
close a child account, but the only accepted refund destination is the
authority recorded in DSS1. Each close drains the account's lamports, resizes
it to zero, assigns it to the system program, and decrements the session's
created-child count. Stream, every state span, both views, and scratch use this
same path. The session record can close only after it is halted and every child
is closed. A close while active or a wrong refund destination is refused
atomically.

## SBF demonstration

The test kernel stores {value:u64, running_total:u64} in two independent
8-byte state accounts. Each one-byte input adds to value; the new value is
added to running_total. Its two views expose those fields from one cursor.
This is a mechanics kernel and makes no capability claim about Doom or another
large workload.

tests/stateful_sbf_workload.rs uses ProgramTest with the feature-built SBF
ELF. It exercises tags 230–239: open, stream and split-state creation, three
view/scratch declarations, indexed and append deposits, bounded advances,
views, explicit anchor, halt, child close, and session close. Its negative
controls cover over-limit resources, stale cursor, duplicate input slot,
wrong append sequence/writer, wrong view cursor, close while active, wrong
refund authority, and writable-account aliasing. The test prints consumed CU
for each sent instruction and checks state, output, rent refund, and refusal
atomicity.

The separate tests/unified_v8_document.rs target is now retained in this
repository behind sbf-real-lifecycle-test. It contains the round-5 patch for
CU logging and the focused timeout/settlement/close test. Set the retained
compiler-v1 artifact environment documented in the getting-started guide to
reproduce the K=80 and K=10,240 real revision-8 handler cases. The v8 driver
and its fixture inputs do not alter the v8 golden bytes.

## Doom adapter work remaining

The next adapter must bind Doom's exact kernel semantic and ABI versions,
state-schema bytes, stream command decoder, and resource ceilings in a
Doom-owned static app image. It must export/import the 9,734,160-byte context
through contiguous authenticated spans without persisting runtime pointers,
then compare every state boundary with the retained SIM/2 oracle. Add Doom's
indexed 4-byte commands, exact halt policy, state-specific view ABIs, snapshot
and eight strip outputs, and account alias/refusal controls. The generic
counter pass establishes only these DCG account and transaction mechanics.

The SBF measurements and reproducible image identity are recorded in
[`experiments/stateful-sbf-workload-2026-09-30.md`](experiments/stateful-sbf-workload-2026-09-30.md).
