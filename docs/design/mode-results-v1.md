# Mode results v1: one result reference for every mode (2026-10-14)

**Status: designed, in progress on branch `result-records` (owner
2026-10-14: build it now; workloads are expected to compose modes soon).**
Numbers are *designed* unless marked.

## 1. Purpose

DCG has two modes today: consensus (stateful sessions, every step on chain)
and optimistic (v2.1 runs and disputes). More are planned: sampling,
Freivalds for integer matrix products, ZK (`dcg-modes-and-compiler`, Basanos
`docs/design/dcg-modes-and-compiler-2026-09-30.md`). Workloads will chain
them: a consensus checker that consumes an optimistic run's output, an
optimistic run whose input is a finished session's state, a Freivalds-checked
matrix product feeding either.

Rather than a reader for every pair of modes, every mode produces the same
thing when it finishes, a **result reference** (`ResultRef`), and every
consumer reads results one way. A new mode is then one producer and its
openings; nothing that consumes results changes.

The composition rules are those of the 09-30 design, unchanged:
- one mode per sweep;
- a consumer imports only final values;
- no rollback of anything already final;
- values cross boundaries as canonical bytes, and a change of commitment
  scheme is an explicit, committed translation.

## 2. The result reference

A fixed 256-byte canonical encoding. All integers little-endian.

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | magic `DRR1` | |
| 4 | 2 | version = 1 | |
| 6 | 1 | mode | 1 consensus, 2 optimistic; 3 sampling, 4 Freivalds, 5 ZK reserved |
| 7 | 1 | scheme | how `root` opens (§4) |
| 8 | 32 | host | the program that holds the source account |
| 40 | 32 | source | the account the result was read from |
| 72 | 32 | root | the commitment to the result's values |
| 104 | 8 | count | values under `root` (outputs, or state bytes) |
| 112 | 144 | body | mode-specific (§3) |

`result_digest = SHA256("dcg.result.v1\0" || ResultRef)`. The digest is what
another mode commits to when it takes a result as an input (for example as an
optimistic run's external reference). Unused body bytes are zero, and a
reader refuses nonzero padding.

The reference is what was read at one moment from accounts the host owns. It
is only as trustworthy as the host program's image and upgrade authority
(`dcg verify`), which is part of every result's security basis.

## 3. Producers

### 3.1 Optimistic (mode 2): v2.1 runs

Read from the run (`D21R`, or its receipt `D21P`) and its template (`D21T`),
following `docs/spec/run-read-layout-v21.md`:

- the run is owned by `host`, at `["dcg21run", run_id, payer]`, with the
  exact length of its form;
- the template account is the run's template (offset 8), owned by `host`;
- status is `FINAL` (2). `COMMITTED`, `OPEN` and `REFUTED` are refused.

| Body offset | Size | Field |
|---:|---:|---|
| 0 | 32 | template_id (template offset 96) |
| 32 | 32 | run_id |
| 64 | 32 | generic root: spec_root; LX1: params_digest |
| 96 | 8 | challenge_window (slots) |
| 104 | 8 | phase_window (slots) |
| 112 | 8 | executor_bond (lamports) |
| 120 | 8 | challenger_bond (lamports) |
| 128 | 8 | generic: total_steps; LX1: positions |
| 136 | 8 | zero |

- **Generic root:** scheme `OUT_TREE_V21` (1), `root` = `out_tree_root`,
  `count` = `total_outputs`.
- **LX1 root** (template kind byte 5 = 1): scheme `LX_OUTPUTS_V1` (2),
  `root` = `outputs_digest`, `count` = 0 (the digest commits the slots).

The template must still exist: the receipt names the template only by
address. A consumer that needs a run's result after its template closes
copies the `ResultRef` first (§6).

### 3.2 Consensus (mode 1): sealed sessions

A session's state anchor chains every earlier anchor, so it cannot be
recomputed from the final state alone. v1 adds a **seal**: one more
chunked hash, over the final state of a session its kernel halted, with its
own domains and no link to earlier anchors.

- `SEAL` reuses the anchor instructions (239 begin, chunk, finish, abort) on a
  session with status `HALTED` and a nonzero halt reason, at the halt cursor.
  The phase is `PHASE_STATE_SEAL`, so a seal and an anchor never mix.
- Only the recorded authority signs, as for anchors: the authority can
  withhold a result but not forge one, the same as with verdicts.
- Domains: `dcg/state-seal-init/1`, `dcg/state-seal-chunk/1`, `dcg/state-seal/1`.
  ```
  acc0 = SHA256("dcg/state-seal-init/1" || input_root || kernel_id[16]
                || schema_id:u32 || schema_version:u16 || cursor:u32 || total:u32)
  acc  = SHA256("dcg/state-seal-chunk/1" || acc || offset:u32 || state[offset .. offset+n])
         for each 65,536-byte chunk in order (the last may be shorter)
  seal = SHA256("dcg/state-seal/1" || acc || input_root || kernel_id[16]
                || schema_id:u32 || schema_version:u16 || cursor:u32 || total:u32)
  ```
- Finishing writes `seal` into the record's `state_anchor`, the halt cursor
  into `anchor_cursor`, and sets bit 0 (sealed) of byte 1278. A sealed session
  cannot be sealed again. Decoding refuses a sealed flag on a session that is
  not halted by its kernel at `anchor_cursor`.
- **The seal covers the whole final state or nothing** (independent review
  2026-10-14, findings 1 to 4):
  - while a seal is in progress no child of the session closes, so an abort
    always ends it and the seal covers the accounts it began with;
  - closing a state span or the resource copy after the halt sets bit 1
    (trimmed) of byte 1278. A trimmed session takes no seal, and its record
    reads as no result (`Trimmed`), since it no longer describes the whole
    final state;
  - finishing checks that the hashed total still equals the record's state
    bytes.

The reader requires the same as `read_verdict` (owner, layout, address,
kernel halt) plus the seal. Scheme `STATE_SEAL_V1` (3), `root` = seal,
`count` = state bytes.

| Body offset | Size | Field |
|---:|---:|---|
| 0 | 16 | kernel_id |
| 16 | 2 | semantic_version |
| 18 | 2 | abi_version |
| 20 | 4 | state schema id |
| 24 | 2 | state schema version |
| 26 | 4 | resource schema id |
| 30 | 2 | resource schema version |
| 32 | 1 | features |
| 33 | 3 | zero |
| 36 | 4 | halt_reason |
| 40 | 4 | halt_cursor |
| 44 | 4 | zero |
| 48 | 32 | input_root |
| 80 | 32 | stream_root |
| 112 | 32 | resource_commitment |

The session record closes with the session, so a consumer that needs the
result afterwards copies the `ResultRef` (§6).

### 3.3 Later modes

A new mode defines its body, its schemes and its terminal condition, and
writes nothing new into existing modes. Sketches, to be fixed with each mode:
- **Sampling:** body carries the sample count, the randomness source and its
  value, and the trace length; final only when every opening is answered and
  the audit window has closed.
- **Freivalds:** body carries the field prime(s), the accumulator range, the
  randomness, and the accumulator and output roots; final when every modular
  check and every exact requantization check has passed.
- **ZK:** body carries the proof system, the verifier key digest and the public
  inputs digest.

## 4. Openings

An opening checks values against a result's `root` under its scheme:

- **`OUT_TREE_V21`:** one output `j < count`, given its 55-byte value reference,
  the value's bytes and the sibling path of height `ceil(log2 max(count, 1))`.
  The value must hash to the reference's digest (`dcg.value.v2`), and
  `out_leaf(j, ref)` must fold to `root`. Opening one output costs one hash per
  level.
- **`LX_OUTPUTS_V1`:** every output slot in order, rehashed with
  `lx::outputs_digest`. No single-output opening.
- **`STATE_SEAL_V1`:** the whole final state, rehashed as in §3.2 with the body's
  kernel, schema, cursor and input root. Fine on a client; on chain, practical
  only for small states (one hash per 64 KiB chunk plus the bytes).

Merkle openings of parts of a session's state are a later scheme, not v1.

On chain cost, *measured* on SBF (2026-10-15; table in
`docs/stateful-workloads-v3.md`, seal section): reading a session result is
about 5,300 CU and a run result 2,400-3,900 CU; opening an 80,000-byte state
is 41,898 CU (about 34,000 per 64 KiB, *estimated*); opening one output of a
one-output run is 285 CU.

## 5. What a consumer checks

`ResultRef::require(&ResultRequirements)` refuses unless every stated
requirement holds:
- the mode;
- the computation: the template id and, for LX1, the parameters digest
  (`root_aux`, which the template does not fix) for optimistic; the kernel,
  its versions and state schema for consensus;
- the instance, where pinned: the run id (which binds the executor, nonce and
  external inputs), or the session address with its input chain and stream
  roots (a session address can be reused after the session closes);
- for consensus, the halt reason and the resource schema and commitment,
  where stated;
- for optimistic, the least challenge and phase windows and executor and
  challenger bonds, where stated, since an optimistic result's security rests
  on them.

`ResultRef::basis()` reports the security basis as typed assumptions, never
one scalar: host program trust for every result, then chain execution
(consensus), or the challenge window, bonds and an honest challenger
(optimistic). A composed output's basis is the union over its ancestry, and
its finality is the latest finality in it (09-30 design §4).

## 6. Keeping a result

Both sources can disappear: a session closes completely (and its result stops
reading as soon as a state span or its resource copy closes), and a run's
receipt stays but its template may close. A consumer that needs a result later copies
the 256-byte `ResultRef` into its own account when it first reads it (the
pattern of the verdict registry in `tests/stateful_v3_verdict.rs`). The copy
is then in the consumer's trusted base. A DCG-run result registry is a later
option, not v1.

## 7. Implementation (v1)

- `dcg_program::result`: `ResultRef` (encode, decode, digest), `read_run_result`,
  `read_session_result` (and `_bytes` forms for clients), `require`, `basis`,
  and the three openings. CPI-free, usable on chain and on a client.
- `stateful_v3`: the seal (§3.2). This is the one handler change, so it gets
  native and SBF tests and an independent review before it merges (rule 10).
- Python mirror `dcg.result`: encoding, digest, the readers over account bytes,
  and the openings, with shared golden vectors (`tests/golden/dcg/result/`).
- Tests on real flows: a finalized and a refuted v2.1 run, live and as a
  receipt, generic and LX1; a sealed session; then malformed and cheating
  cases (wrong owner, address, template, status, padding; a seal on an
  authority halt; a forged opening path; a changed value).

Example: `examples/composed-app` is a consensus session whose only inputs
are verified outputs of FINAL v2.1 runs of one template (native and SBF).

## 8. Open questions

1. Should anyone be able to seal a halted session, not only its authority? The
   state is frozen, so sealing is deterministic; v1 keeps the authority, as for
   anchors.
2. Should the v2.1 receipt carry the template id, so results stay readable
   after the template closes? That is a program change to the receipt form
   (a new magic under run-read v1's versioning rule).
3. Merkle openings for part of a session's state (a tree seal), for large
   states consumed on chain.
