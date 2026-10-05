# Declared input rejection and ring-buffer streams (design v1)

**Status: designed (2026-10-05), not implemented.** Owner decisions of
2026-10-05 on the sessions review
([`experiments/sessions-v3-review-2026-10-05.md`](../experiments/sessions-v3-review-2026-10-05.md)):
H4 is fixed by a reject outcome that only kernels declaring the capability may
use, rolled up to a flag on the session or template that users can see in
advance; M2 is fixed by a ring-buffer stream. Both change the session input
stream, so they ship together under one versioned feature set. Every handler
change here touches how inputs are consumed, so the implementation gets a
rule-10 review and the session fuzzer is extended before merge.

## 1. Problem

- **H4.** `ADVANCE` treats any kernel error as a refusal and rolls back. Inputs
  are write-once, so a well-formed input that the kernel will not apply sits at
  the cursor forever: the session can only halt and close. The Doom lanes
  session hit this at tic 5,310 (a USE command).
- **M2.** A stream holds absolute slots `0..capacity`, grows only when
  `cursor == capacity`, and stops at `MAX_STREAM_CAPACITY` (655,352 inputs,
  about 10 MiB of rent). That is about 5.2 h of Doom at one input per tic
  (estimated), short of the week-long public demo.

## 2. Declared rejection

### 2.1 Kernel capability

`KernelManifest` gains `capabilities: KernelCapabilities`, a `u32` bit set;
bit 0 is `REJECTS_INPUT`. Every existing manifest is `KernelCapabilities::NONE`
(a mechanical change to each manifest literal in DCG and the apps). Unknown
bits are refused by `ApplicationManifest::validate`. The capability is part of
the kernel's promised behaviour, so it is covered by the kernel's semantic
version: turning it on is a semantic-version bump, and it is included in
`admission_identity_digest` so an admitted document cannot silently gain it.

The off-chain `DCKC` manifest (spec `kernel-capability-v2.md`) is frozen at
format 1 with `flags = 0`. It gets the same bit in a format-2 record only when a
DCKC consumer needs it; until then the static Rust manifest is the source of
truth. (Recorded so nobody reinterprets format 1's flags in place.)

### 2.2 Transition outcome

`TransitionDisposition` gains `Reject { code: u32 }` (`code != 0`). Contract:

- the kernel leaves state unchanged (as for `HaltBefore`: checked by the
  adapter's snapshot when aggregate state is at most 8 KiB, a kernel obligation
  above that);
- the kernel writes no output;
- the input is **consumed**: the cursor moves past it.

`ADVANCE` handling, per command in order:

| Disposition | Session not rejectable | Session rejectable |
|---|---|---|
| `Continue`, `HaltBefore`, `HaltAfter` | unchanged | unchanged |
| `Reject` | refused (`REFUSAL_KERNEL` 2334): a kernel that did not declare the capability must not reject | input consumed, state unchanged, chain entry marks rejection, `rejected_count += 1`, `last_reject = (sequence, code)`; the loop continues with the next command |
| kernel error | refused, rolled back (unchanged) | refused, rolled back (unchanged) |

So a declaring kernel converts "I will not apply this well-formed input" into a
committed, visible outcome; genuine faults still refuse. A session whose
kernel never rejects behaves byte for byte as today.

### 2.3 Input chain

Today each consumed input extends `input_root` with
`sha256("dcg/input-chain/2" || root || sequence:u32 || command)`. A session
with the reject feature uses a distinct domain and a disposition byte for
every entry:

`sha256("dcg/input-chain/3" || root || sequence:u32 || disposition:u8 || command)`,
`disposition` = 0 applied, 1 rejected (followed by `code:u32` for 1).

Sessions without the feature keep `/2`, so their chains and goldens are
unchanged. Replays (host replay, anchors, the fuzzer's host model) must use the
domain the session declares.

### 2.4 Rollup: the session and template flag

The owner's requirement is that a user knows **before using** a session or
template whether "rejected" is a possible outcome.

- **Sessions.** `OPEN_SESSION` carries a `features` byte (§4). Bit 1
  `REJECTABLE` must equal the bound kernel's `REJECTS_INPUT` capability:
  opening a rejectable kernel without the bit, or the bit with a non-declaring
  kernel, refuses (`REFUSAL_RESOURCE` 2326). The flag is stored in the session
  record and never changes. The session read layout exposes `features`,
  `rejected_count` and `last_reject`; the Python client's session view and the
  docs' "explain" output show "rejectable: yes/no".
- **v2.1 LX templates.** The `DLX1` tail names its one kernel. Tail byte 25
  (reserved, zero today) becomes `flags`, bit 0 `REJECTABLE`; `create_template`
  requires it to equal the named kernel's capability. The template id hashes
  the creation data, so the id commits to the flag.
- **v2.1 block templates.** The program does not see the step kernels at
  creation (they are opened from the spec root during a dispute), so the
  template **declares** the flag in a creation-data flags field (zero today)
  and the program **enforces** it at replay: a step whose kernel rejects in a
  template without the flag rules against the party that committed the
  rejection. Off-chain admission tools check the spec root's kernels against
  the flag before anyone uses the template.
- **What "rejected" means in a v2.1 run.** A rejecting step's output is a
  canonical rejection record (`"DRJ1" || code:u32`), committed like any other
  output and covered by `outputs_digest`. Consumers that read outputs (TCR1)
  learn from the template flag whether they must handle that record. **Open
  (Q2):** no current v2.1 kernel declares the capability, so the first
  implementation can refuse rejectable v2.1 templates at creation and ship the
  session half only.

## 3. Ring-buffer stream

### 3.1 Layout

A ring stream keeps the `DSB3` header and 16-byte slots; slot `i` holds
sequence `s` with `i = s mod capacity`. Each slot already records its own
sequence (bytes 0..4) and presence (byte 4), so the change is in addressing and
reuse, not in the slot format.

### 3.2 Rules

- **Capacity** is fixed at creation and is at least `2 × MAX_STREAM_WINDOW`
  (128). `GROW_STREAM` refuses on a ring stream. Rent is fixed for life.
- **Write** (`WRITE_INPUT`, sequence `s`): the existing window checks stay
  (`cursor <= s < cursor + 64`, policy rules, frontier). The target slot must be
  empty, or hold a consumed sequence `t < cursor` with `t ≡ s (mod capacity)`;
  it is then overwritten. A slot holding `s` already is a duplicate (2327).
  Because `s - cursor < 64 <= capacity / 2`, a live (unconsumed) input is never
  overwritten.
- **Read** (`ADVANCE`): slot `s mod capacity` must hold exactly `s`, present;
  otherwise `REFUSAL_INPUT_GAP` as today.
- **Lifetime.** Sequences stay `u32`; at `cursor == u32::MAX - 64` the stream
  refuses new writes (`REFUSAL_BACKPRESSURE`), about 3.9 years at 35 inputs per
  second (estimated). No wraparound of sequence numbers.
- **History.** Consumed inputs are overwritten after one lap, so the stream is
  no longer the archive of all inputs. The archive is the input chain
  (`input_root`), anchors, and the sequencer's journal; anyone needing every
  input must record them as they land. The Doom replay tooling already keeps
  its own input log; verify it does before the public demo.

### 3.3 Clients

The Python session client, journal (`session/journal.py` slot offsets) and
`OrderedLane` repair address slots as `128 + 16 × (s mod capacity)` for a ring
stream; the sequencer stops calling `GROW_STREAM` for ring streams. The Basanos
Doom drivers (`stunts/doom-dcg`) drop `grow_stream` when they open a ring
session.

## 4. Versioning

`OPEN_SESSION` (v3 payload) gains a trailing `features: u8`:

| Bit | Feature | Effect |
|---:|---|---|
| 0 | `RING_STREAM` | stream addressed as §3 |
| 1 | `REJECTABLE` | must equal the kernel capability; enables §2 and chain domain `/3` |

The existing payload length (no byte) means `features = 0`: today's linear
stream and no rejection, bytes and goldens unchanged. Unknown bits refuse. The
session record stores `features`, `rejected_count:u32`, `last_reject_sequence:u32`
and `last_reject_code:u32` in currently reserved bytes of the 1,280-byte
`DSS3` record (offsets fixed at implementation and recorded in
`stateful-workloads-v3.md`).

**Open (Q1):** a features byte inside wire v3 (v3 is testnet-only; cheapest)
versus a wire v4 with new discriminators (cleanest for mainnet). Recommended:
the features byte now, and a mainnet release folds v3-with-features into the
version it freezes.

## 5. Tests and review

- Native and SBF ProgramTest: a declaring test kernel rejecting at each step
  position of an 8-step `ADVANCE`; a non-declaring kernel returning `Reject`
  (refused); a rejecting kernel that changed state (refused under 8 KiB);
  open-time mismatch both ways; chain `/2` versus `/3` goldens.
- Ring: write/read across several laps, the overwrite boundary
  (`t < cursor` versus `t >= cursor`), duplicates after a lap, `GROW_STREAM`
  refused, capacity below 128 refused, the `u32` ceiling, and lanes capturing
  across a lap.
- The session fuzzer (`stateful_v3_fuzz.rs`) gains a rejecting kernel and ring
  streams, with the closability and liveness oracles (a rejected input must
  never wedge the session) and a host model of the `/3` chain.
- Rule-10 review of the implementation before merge: who profits by writing an
  input that will be rejected (a griefing writer under the APPEND policy now
  costs the authority one consumed slot, not the session); whether a
  non-authority writer can force a rejection loop; whether a lap can overwrite
  anything a lane or view still needs.

## 6. Estimates (designed)

Session half (capability, outcome, flag, chain `/3`, ring stream, clients,
tests): about 1–1.5 days on the host plus the review. v2.1 template flag (LX
tail check and refusing rejectable templates): half a day. v2.1 rejection
records in block templates: separate work, after Q2.

## 7. Open questions for the owner

1. **Q1 Versioning:** a `features` byte in wire v3 (recommended) or wire v4.
2. **Q2 v2.1 scope:** ship the template flag with rejectable v2.1 templates
   refused for now (recommended), or design the rejection record path now.
3. **Q3 Stream history:** accept that a ring stream keeps only the last lap of
   inputs, with the input chain and app journals as the archive.
