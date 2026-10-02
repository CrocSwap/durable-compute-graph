# App-bound replay v1

Status: **designed protocol entry** for revision 8. The mechanism uses the
revision-8 DCM2 v7 and DCR1 v6 formats. It adds no dynamic program loading.
Application code and replay kernels are statically linked, and their semantic
identity must be versioned as specified below.

## 1. Admission

An application manifest used for admission MUST pass `ApplicationManifest::validate`.
Until a later app-bound replay version defines multi-input routes, each legacy
form binding MUST declare at most one input route. That declaration selects
the plan read ordinal that becomes the application's input span; the selected
ordinal MUST exist at every admitted instance of the bound form. Other reads
are outside this kernel's replay input binding. Their producer leaves can be
challenged separately, but that does not check how this consumer used those
reads. Applications must not treat those producer challenges as verification
of the consumer's complete input use; a future multi-input version must bind
every read on which replay depends.

A binding with no input spans at an instance that has plan reads is refused
unless its replay explicitly opts in with `accepts_empty_input_spans()`. That
opt-in means replay accepts no opened plan input at that coordinate; the
application is responsible for ensuring its result does not depend on those
unbound reads. The default `replay_input_spans` adapter calls `replay(&[], …)`
when the opt-in is present. Every route length MUST be a multiple of the bound
kernel's input alignment. Under a full-scan manifest
(`AdmissionScan::Full`, §1.1), every class whose form is bound by the manifest
MUST be checked against the sealed plan at tag 160.
Admission rejects with code 799 if any instance cannot be opened by the tag-184
adapter, including when:

- the consumer's route count is unsupported or its selected ordinal is outside
  the instance's plan reads;
- the route is a document input, crosses a position or segment, or names a
  producer that is not earlier in the same segment;
- no application binding exists for the producer;
- the producer's write does not match the read's region, effective offset,
  byte length, and declared output width; or
- the maximum honest opening exceeds the staging cap.

For a form binding `b`, the maximum ARW1 size is
`ARW1_HEADER + Σ(SPAN_HEADER + input_span.max_bytes) + claimed_output_bytes`.
For a route-free form, that is the complete opening. For one supported route,
the maximum complete opening is:

```text
consumer_ARW1
+ 14                         RWP1 header
+ producer_ARW1
+ 32 × segment_path_height
```

The result MUST be at most 900 bytes. The producer's ARW1 may have zero input
spans; this is a valid zero-span ARW1, not an empty byte string. A producer
preimage in RWP1 opens its committed output leaf and route bytes. The producer
is separately challenged at its own coordinate to test its computation.

Each kernel's declared compute units MUST be at most the transaction ceiling
minus the measured worst-case tag-184 adapter cost and the declared safety
margin. With the current measured cost of 45,573 CU, a 25,000-CU designed
margin, and a 1,400,000-CU transaction ceiling, the cap is 1,329,427 CU. The
fixture and image are recorded in `docs/experiments/dcg-seam-fix-2026-09-30.md`.
These numbers constrain the manifest; they do not prove every app kernel's
actual worst-case runtime.

### 1.1 Full and attested admission

The manifest's `admission_scan` selects how tag 160 treats a class whose form
it binds:

- `Full`: the per-instance check above. Its cost grows with positions times
  bound classes. Measured on the K=10,240 fixture: about 271,000 tag-160
  transactions covered roughly 1,600 of an estimated 3,300 bound classes, so a
  single transaction cannot finish it and the parked DEA2 v4 cursor
  (`fast/admission-cursor`) is the only on-chain route.
- `Attested`: a bound class is admitted on its binding and registry checks
  alone. The sealed template is trusted to be openable, and parties who rely
  on it verify that off chain by running the same per-instance check.
  Measured: the K=10,240 fixture admits in about 1,800 tag-160 transactions.

A DEA2 that admitted at least one bound class without the scan sets flag
bit 2 (`attested`). An attested manifest's identity digest also commits the
choice (`dcg/application-admission-attested/1`), so documents record which
admission they relied on; a full-scan manifest's digest is unchanged.

**What attestation gives up.** If an attested template does contain a
coordinate the adapter cannot open, a challenge at that coordinate is ruled
neutrally (as for a changed identity, §2): the challenger's bond is refunded
and the executor is not convicted. A lie at such a coordinate therefore
stands. This is the risk accepted by trusting the template.

## 2. App identity

Admission state DEA2 v3 uses flag bit 0 for complete, bit 1 for app-bound and
bit 2 for attested (§1.1).
If any admitted class uses an app form, UnifiedInit writes a 64-byte DCM2 v7
extension after the option table:

```text
"ARI1" | admission_identity_digest[32] | zero[28]
```

The identity digest commits the application id and version plus the static
form-to-kernel bindings, selected modes, input span declarations, and route
declarations. An application or kernel implementation change MUST increment
the application version or the kernel semantic version. A program upgrade
that changes replay behavior without changing those versions is outside this
identity guarantee and is invalid application versioning.

At a fix-point with registry code 0, a saved ARI1 identity whose manifest
digest differs from the current manifest is ruled with winner byte 0 and cause
5 (`APP_IDENTITY_CHANGED`), even when the current image no longer binds the
challenged form. A saved identity with no current manifest is also ruled
neutrally. When DCM2 has no saved identity, neutrality applies only if the
current manifest binds the challenged coordinate. Registry-code convictions
keep their ordinary rulings. Neutral identity rulings do not set DCM2's
refuted flag or counter. Tag 131 refunds the challenger's challenge bond and
changes only the open-challenge count.

At timeout, identity neutrality applies only to a live DCR1 v6 app RESPOND
record, after the handler verifies that the record is in a timeout-eligible
phase, and follows the same saved-identity rules as a fix-point. A phase-3
ruling cannot be changed by tag 132 after an app upgrade. The challenger
receives no conviction or protocol bond pot, and the executor receives no
challenge-bond transfer when a live app RESPOND record is ruled neutral. This
rule records no computational finding under a replay identity different from
the one admitted.

The DCM2 ARI1 admission digest commits the whole static form table. A table
change can therefore still neutralize a dispute at a selected app coordinate
when the changed row is unrelated to that form. This version retains that
manifest-wide commitment because DCM2 has one admission-identity field; a
per-form commitment would require a separately versioned storage layout.

## 3. Leaf commitment and first divergence

The leaf domain is `app-replay-leaf/2`; `/1` MUST NOT be reused. The leaf
commits the descriptor, coordinate, app/kernel/mode identity, and canonical
ARW1 bytes. If ARW1 carries an RWP1 suffix, `/2` hashes the ARW1 prefix and
strips the complete suffix. RWP1 has this exact encoding:

```text
"RWP1" | route_ordinal:u16 | producer_local:u32 | path_height:u8 |
reserved_zero:u8 | producer_ARW1_length:u16 | producer_ARW1 |
producer_leaf_path[path_height][32]
```

The route proof authenticates a same-position, same-segment producer leaf
against the saved segment root and checks that the exact routed byte slice
equals the consumer's ARW1 input. It does not assert that the producer computed
those bytes correctly.

Clients MUST descend to the first divergent leaf. If a consumer correctly
computed its output from a fabricated producer output, a challenge against the
consumer is won by the executor. The challenger must instead challenge the
producer; its app replay then tests whether the committed producer output is
correct. A malformed or invalid challenger fast-path RWP1 does not rule against
the executor and sends an otherwise admitted app-bound fix-point to RESPOND.

## 4. DCR1 app opening state

Revision-8 DCR1 v5 remains the compatibility format. An app-bound fix-point
that enters RESPOND switches to DCR1 v6, still 8,192 bytes, and is non-terminal
until tag 184, timeout, or a neutral identity rule. The relevant bytes are:

| Bytes | Meaning while in app RESPOND |
| --- | --- |
| `170..172` | staged witness total `u16` |
| `172..174` | staged prefix length `u16` |
| `7040..7104` | DEV2 report; status 0 means admitted but pending |
| `7104..7168` | saved 64-byte ARI1 ruling identity |
| `7168..8068` | witness staging buffer, maximum 900 bytes |
| `8068..8100` | saved segment root for the challenged consumer |

Revision-8 challenge open writes its canonical PDA bump at byte `146`, marker
`1` at byte `147`, and the canonical DRU1 response bump at both staged byte
`181` and stable byte `219`, for both DCR1 v5 and v6 records. Tag 164 refreshes
byte `219` from byte `181` when it consumes position roots. A tag 132 timeout
ruling in POSITION_REVEAL or SELECT also copies the staged bump to byte `219`
so tag 131 can settle without a preceding tag 164. These bytes were reserved
in the earlier layout.
Readers use the stored bumps for fixed-cost address checks. A fresh revision-8
program address requires marker `1`; a marker-0 record from an older image is
refused. Revision-7 builds leave these reserved bytes zero. The DCR1 record
size and instruction encodings are unchanged. The address inputs are still the
descriptor, challenger, and nonce read from DCR1 itself because these challenge
account lists have no independent identity anchor; stored bumps limit search
cost but do not close that provenance gap.

While staging counters occupy `170..174`, DEV2 retains the fix-point entry
index and form. Any terminal ruling restores the ordinary `t:u32 | form:u16`
words at `170..176` after clearing the staging region.

### Tag 183 — StageAppWitnessV1

Data is exactly `tag:u8 | total:u16 | offset:u16 | chunk[]`. Accounts are
DCR1 writable and executor signer. The total MUST be in `1..=900`, the chunk
MUST be nonempty, and its end MUST not exceed total. Offset 0 starts or restarts
staging and clears the prior buffer. Every other offset MUST equal the current
staged prefix length and use the original total. Staging is permitted through
the exact deadline slot; it is refused after the deadline.

### Tag 184 — RespondAppWitnessV1

Data is exactly the tag. Accounts are DCR1 writable, executor signer, DCM2,
PT2S, base routes, base geometry, DRP2, and the PT1S index. The complete staged
preimage MUST match the challenged `/2` leaf and pass the route proof. A
matching opening whose kernel replay succeeds rules for the executor (winner
1, code 0). An authenticated opening with invalid committed input or incorrect
output rules for the challenger (winner 2, code 799 or 800). A missing,
partial, or non-matching opening is refused without ending RESPOND; timeout
then rules for the challenger. Tag 184 can rule only once.

## 5. Fix-point behavior

The route-tree fold and saved segment root are computed only for a selected
app binding. On the default revision-8 compatibility path with no selected app
binding, the original DCR1 v5 byte layout and fix-point tree fold remain in
force. App-bound paths leave DEV2 status 0 while awaiting the executor.
Revision 8 does not dispatch tag 182; its default result remains
`InvalidInstructionData`.

## 6. Compatibility boundary

This entry does not change the DCM2 v7 base encoding, the default app-empty
document length, or revision-8 golden bytes. The optional DCM2 ARI1 extension
appears only on app-bound documents. DCR1 v5 app-empty behavior is unchanged.
The new leaf domain `/2` applies only to app-bound replay leaves; all leaf
builders and verifiers for that path MUST use it consistently.
