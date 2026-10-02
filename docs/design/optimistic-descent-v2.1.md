# Optimistic disputes v2.1: first-divergence disputes for graph runs (draft)

Status: **draft design, 2026-10-02.** Nothing here is implemented. It
replaces the root-committed descent of v2.0 (tags 220–226), which the
2026-10-02 review found unsound (Basanos
`out/runs/review-dcg-graph-v2-2026-10-02.md`, B2–B8, S4, S6–S10). Numbers
are *estimated* unless marked *measured*.

## 1. Goal

One general mechanism by which DCG settles a disagreement about a graph run
of any size. The executor commits one root. A challenger who knows the
honest execution forces, in a logarithmic number of rounds, a ruling on one
small fact that the program checks locally. Applications, Basanos first,
supply kernels and economics hooks rather than building their own dispute
game.

**Required properties** (each is tested; see section 11):

- **P-sound.** If the committed root differs from the honest execution's in
  any way, an honest challenger who opens before the challenge deadline and
  answers every phase in time wins, whatever the executor does. This covers
  wrong outputs, and also wrong internal values that happen to leave the
  outputs right.
- **P-complete.** An honest executor who answers every phase in time never
  loses, whatever challengers do.
- **P-local.** Every check reads a bounded number of fixed-size records and
  logarithmic Merkle paths. Nothing decodes the whole graph or plan, and
  every witness fits a staging buffer of declared, bounded size.
- **P-rounds.** A dispute takes at most `ceil(log2(n) / d) + 2` rounds, for
  `n` steps and a reveal fan-out of `2^d`. That is 7 rounds for 1M steps at
  `d = 4`.
- **P-live.** Any number of challengers, up to a committed limit, can
  dispute concurrently; none can stop another from opening or finishing.
  Every record reaches a terminal state within a bounded time after the
  challenge deadline, and all rent and bonds are released.
- **P-bound.** A finalized run's outputs are bound on chain to the committed
  root (review S8).

Non-goals:
- the sampling mode (section 9 says what it needs);
- kernels whose single step exceeds one transaction's compute (they use the
  existing `kernel_step` decomposition; see O3);
- multiple executors per run (section 10).

## 2. What went wrong in v2.0, and the change

v2.0 committed a tree of regions (`RegionRootV1`). A dispute walked down that
tree, and inputs were checked against the regions next to the step. That fails
in three ways:

- **Waypoints.** A region lists only its own steps' boundary values. A value
  that crosses two region levels has no committed waypoint, so its
  consistency cannot be checked (B4, and B7's sibling and grandparent
  inputs).
- **Bounds.** Nothing binds a leaf's position, or a region's outputs, to the
  plan (B2). The expected shape is learned by decoding the whole graph (B7).
- **Rounds.** A downward walk cannot find the first wrong value. That value
  can lie up or across the region tree, and inside one region an honest
  challenger may need one round per step of a dependency chain.

The change: **commit one Merkle tree over every step leaf, in topological
order, and find the first divergent leaf by descending that tree.** If every
leaf before it is honest, everything the divergent leaf depends on is
honest. Each of its fields can then be checked locally against the spec or
an earlier leaf.

Regions no longer carry any soundness weight. They remain in each leaf's
coordinate and in the spec, which records each region's mode for later
composition (section 10).

## 3. Commitments

### 3.1 Order

Steps are ordered by plan ordinal. Admission requires that every step's
producers have smaller ordinals: the plan's ordinal order must be a
topological order. The spec derivation checks this (section 5). DCGG and
DCPL bytes do not change.

### 3.2 Step leaf

The v2.0 step-leaf preimage (graph-plan-v2 §5) is unchanged:
- plan id, run id, region and coordinate;
- input and output `ValueRefV1` lists, sorted by port key;
- prior and next state digests, which must be all zero for stateless kernels.

A leaf with 8 inputs and 2 outputs is 710 bytes (*estimated* from the
encoding).

### 3.3 Run root

```
RunRootV21 =
  plan_id[32] run_id[32] spec_root[32]
  step_count:u64  step_tree_root[32]     ; leaves: step leaf digests, ordinal order
  out_count:u32   out_tree_root[32]      ; leaves: ValueRefV1 of graph outputs, spec order
run_root = SHA256("dcg.run.root.v2.1\0" || RunRootV21)
```

- `step_tree_root` is the root of an **ordered tree whose shape the spec
  fixes**, over the `n = step_count` leaf digests in ordinal order.
  - The default shape is a balanced binary tree. It uses the node rule of
    graph-plan-v2 §5 under domain `dcg.trace.node.v2.1\0`, and duplicates the
    last node of an odd layer.
  - A template may instead declare a chunked shape: fixed-size chunk roots,
    with the run root over the chunk roots. Basanos's per-position roots
    under an MMR are such a shape.
  - With a chunked shape, an executor can land chunk roots as it goes and
    seal the top at `COMMIT`.
  - First-divergence (section 4) needs only that the leaf order is the
    ordinal order and that the shape is fixed in advance.
- `out_tree_root` is formed the same way over
  `SHA256("dcg.run.out.v2.1\0" || index:u32 || ValueRefV1)`.
- Both counts come from the spec. Because the counts are fixed, every padding
  position is known in advance and its value is defined by the duplication
  rule.

### 3.4 What the executor posts

`COMMIT` (section 7) posts:
- the `RunRootV21` bytes (180 bytes);
- every graph output entry with its out-tree path;
- each graph output's value bytes.

The program checks each entry against `out_tree_root`, and each value against
its digest. It stores the run root and the output values in the run. This
binds the result (S8). Outputs too large for one transaction are staged
first (section 6.4).

## 4. Why first-divergence works

Let H be the honest execution. The challenger computes H's leaves and H's
step tree, so it knows the honest hash of every node.

**Descent.** The dispute keeps a current node of the executor's step tree,
starting at the root.
1. Each round, the executor reveals the `2^d` node hashes `d` levels below
   the current node.
2. The program checks that they hash up to the current node, and that the
   positions covering only padding obey the duplication rule.
3. The challenger names the **leftmost** revealed node whose hash differs
   from H's. That node becomes the current node.
4. At the leaf level, the executor reveals the leaf bytes. The program checks
   them against the leaf hash.

**Invariant.** Every leaf left of the current node equals H's leaf.
- A node is skipped only when its hash equals H's.
- By collision resistance, every leaf under a skipped node then equals H's.
- A node covering only padding is never the leftmost difference. It is a
  copy of a node to its left, so if it differs, that earlier node differs
  too.

**Existence.** The step-tree root differs from H's exactly when some leaf
differs. In that case each level has a differing child, and the leftmost one
is always available.

**Base case.** The descent ends at leaf `k`. Leaf `k` differs from H's leaf
`k`, and every leaf before it equals H's. One of the following holds, and
each is a local check (section 6.2):
- **Wrong shape.** The plan or run id, coordinate, port keys, counts or zero
  state digests differ from the spec or the run. This is SHAPE.
- **Wrong input from an earlier step.** An input digest differs from H's.
  Its producer is leaf `p < k`, by the order rule. Leaf `p` is H's leaf, so
  its committed output digest is H's, and the input and producer disagree.
  This is EDGE: open leaf `p` from the tree and compare.
- **Wrong external input.** An input digest differs from the run's committed
  external input digest. This is EDGE against the run record.
- **Wrong output.** The shape and every input equal H's, so an output digest
  differs from what the kernel produces. The challenger knows every input
  value, because they are H's. This is STEP: stage the input values, replay
  the kernel, and compare.

**Outputs.** If the step-tree root equals H's but a posted graph output
differs from H's, then output `j`'s producer leaf is H's. Its output digest
differs from the posted entry. This is OUT: open the producer leaf and
compare.

**Completeness.** If the executor's commitment is H's:
- every reveal it makes verifies;
- the challenger finds no differing node, so it can only make claims that
  compare equal values, or replay to equal digests;
- every claim therefore rules for the executor.

The executor needs only to answer each phase before its deadline.

**Data availability.** The game supplies it. The executor either reveals
the committed node hashes and leaves on demand, or loses by silence. The
challenger needs no off-chain copy of the commitment, only H.

## 5. Dispute spec (`DCDS`)

The program must know each step's expected shape and each input's producer
without decoding the graph (B7). The spec is that knowledge, as one Merkle
tree. Its root is committed in the template.

| Record | Key | Body |
|---|---|---|
| `StepSpec` | ordinal | region, segment, node, kernel_step, kernel id, semantic version and ABI; per input (at most 8), its port key and producer; per output, its port key |
| `OutSpec` | output index j | port key; producer `(ordinal, output port)` |
| `InSpec` | external id | port key `(layout, scheme, byte_length)` |
| `RegionSpec` | region id | parent id, mode, scheme and layout ids and versions |

- A port key is `(node, direction, port, layout, scheme, byte_length)`.
- A producer is `(kind:u8, a:u64, b:u32)`. Kind 1 means step ordinal `a`,
  output port `b`. Kind 2 means external input `a`.
- The spec-tree leaves are, in order: every `StepSpec` by ordinal, every
  `OutSpec` by index, every `InSpec` by external id, then every `RegionSpec`
  by id.
- A spec header records the four counts. It is hashed into `spec_root`, so
  every record's position is computable.
- A leaf hashes as `SHA256("dcg.spec.leaf.v2.1\0" || type:u8 || record)`.
- The derivation is a pure function of the canonical DCGG and DCPL. It
  refuses a plan whose ordinals are not a topological order. A Python
  reference produces it, Rust mirrors it, and golden vectors pin it.

Admission computes `spec_root` from the verified graph and plan, and binds
it into the template. For graphs too large to decode in one transaction, the
derivation runs segment by segment under an admission cursor (open item O1).

## 6. The game

A dispute is between the run's executor E and one challenger C. Each dispute
has its own record (section 8) and runs independently of the others.

### 6.1 Phases

```
OPEN (C posts bond; chooses DESCEND or OUT(j))
  DESCEND:  AWAIT_NODES  -> E reveals 2^d hashes under the current node
            AWAIT_PICK   -> C names the leftmost differing one   (repeat)
            AWAIT_LEAF   -> E reveals the leaf bytes at index k
            AWAIT_CLAIM  -> C names SHAPE, EDGE(input i) or STEP
            AWAIT_OPENING-> E opens what the claim needs (EDGE: leaf p)
            AWAIT_WITNESS-> C stages input values (STEP only); program replays
  OUT(j):   AWAIT_OPENING-> E opens output j's producer leaf; program compares
  -> RULED
```

- Every action checks `now <= phase_deadline`. Every timeout checks
  `now > phase_deadline`. The two are exclusive (B5).
- A silent party loses.
- A submission that fails verification is refused and changes nothing. The
  party may retry until its deadline.
- Spec records are public template data. Whichever party's submit needs
  them supplies them, with their spec paths.

### 6.2 Claims at leaf k

| Claim | What is opened | Rules for C when |
|---|---|---|
| SHAPE | `StepSpec(k)` | the leaf's plan id, run id, coordinate, port keys, input or output counts, or zero state digests differ from the spec and the run |
| EDGE(i), producer is step p | `StepSpec(k)`; leaf `p` with its step-tree path (E opens it) | leaf k's input i digest differs from leaf p's output digest at the spec's port, or p ≥ k |
| EDGE(i), producer is external | `StepSpec(k)` | leaf k's input i digest differs from the run's external input digest |
| STEP | `StepSpec(k)`; C stages input values | every staged value hashes to its leaf input digest, and the replayed output digests differ from the leaf's |

If the opened facts agree, the claim rules for E. A STEP whose witness never
verifies times out, which rules for E. The OUT(j) claim works like EDGE,
with `OutSpec(j)` and the producer leaf.

### 6.3 Sizes

**Descent.**
- A node round with `d = 4` reveals 16 hashes, 512 bytes.
- For `n = 1M`, the descent takes `ceil(20 / 4) = 5` node rounds, then one
  leaf round.

**Openings.**
- A leaf opening is at most about 710 bytes.
- An EDGE opening is one leaf plus a 20-level path: 710 + 640 bytes. It is
  staged over two transactions.
- A spec record with its path is under 1 KB.

All sizes are *estimated* from the encodings.

**Witnesses.** A STEP witness is the input values: 32 bytes for eight i32
inputs, and larger for tensor layouts (O2).

### 6.4 Staging

Each dispute record has a staging area. Its size is the template's declared
`max_opening`, which admission computes from the spec. It is the largest of:
- one leaf plus the deepest path;
- one spec record plus its path;
- the largest input set of any step.

The party whose turn it is writes into the staging area over one or more
transactions, then submits. This generalizes Basanos's DRU1 (tags 115–118
and 125): it grows in 10,240-byte steps and takes writes of 900 bytes. The submit hashes the staged bytes and checks
them. Small items are written and submitted in one transaction.

Admission refuses a template whose `max_opening` exceeds the program
ceiling (*designed*: 1 MiB, the Basanos DRU1 response cap; a measured form-30
body is about 582 KB). So every claim stays refutable within bounded
storage. This replaces v2.0's one-transaction replay, which measured 1,545
bytes on a three-step graph (B7).

## 7. Instructions

| Instruction | Who |
|---|---|
| `COMMIT(run root, outputs, values)` (staged when large) | the run's named executor |
| `OPEN_DISPUTE(nonce, kind)`, with bond | anyone, while `now <= challenge_deadline` |
| `STAGE(offset, bytes)` | the party whose turn it is |
| `REVEAL_NODES`, `PICK(index)`, `REVEAL_LEAF`, `CLAIM(kind, i)`, `SUBMIT_OPENING`, `SUBMIT_WITNESS` | E, C, E, C, E, C |
| `TIMEOUT` | anyone, after a phase deadline |
| `SETTLE_DISPUTE`, `FINALIZE_RUN` | anyone |
| `CLOSE_DISPUTE`, `CLOSE_RUN` | anyone; rent goes to the recorded payers |

These get new tags; tags 220–226 are not reused. The v2.0 handlers stay
under `graph-v2-experimental` until they are removed, so old runs remain
readable.

The trace-committed path (216–219) keeps working for small graphs. A
template's `commitment_kind` fixes which path its runs use (B7, S6).

## 8. Concurrency, deadlines and records (B5, S4, S6)

- **One record per dispute**, at PDA `["dcg2dsp", run, challenger, nonce]`.
  - The run keeps `open_disputes:u32` and `next_sequence:u64`.
  - Each open takes the next sequence (dispute-economics-v2 §1).
  - The template commits a `challenge_limit` per run, from 1 to 1,024.
- **Opening** is allowed while `now <= challenge_deadline`. A dispute opened
  in time runs to its end after the deadline.
- **Refutation.** The first ruling for a challenger marks the run `REFUTED`.
  Any other open disputes become moot: they settle with their bonds
  refunded.
- **Finalization** requires `now > challenge_deadline`, `open_disputes == 0`
  and no refutation.
- **Bounded delay.**
  - A dispute has at most `2 × ceil(log2(n)/d) + 5` phases, each at most
    `phase_window` slots.
  - So finalization comes at most
    `challenge_window + (2 × ceil(log2(n)/d) + 5) × phase_window` slots after
    commit (*designed*).
  - A puppet challenger can add at most that delay, and cannot block anyone.
- **Windows** are bounded at admission. `phase_window` has a wall-time
  minimum (*designed*: 750 slots, about 30 s at 40 ms), so an honest party
  can answer under congestion.
- **Named executor** (S6). `init_run` names the executor key, or the zero key
  for anyone. Only that key may commit.
- **Records close.** A settled dispute closes, with its rent going to its
  challenger. A finalized or refuted run closes after all its disputes have
  closed (S4).
- **Pre-funded addresses** are topped up, not refused (S1).
- **Every `u64` addition is checked** (S3).

## 9. Economics (hooks, not policy)

DCG enforces conservation and authenticated facts. The application's policy
chooses the split, following dispute-economics-v2 and the 09-26 decision that
dispute economics are application hooks. The default standard policy:

- E posts `executor_bond` at commit, and C posts `challenger_bond` at open.
- On a ruling for C:
  - C's bond returns to C;
  - the earliest-opened winning challenger receives `bond_slasher_bps` of the
    executor bond;
  - the remainder goes to the run's payer or the incinerator, as the template
    commits.

  So a self-challenge always forfeits the remainder (S7).
- On a ruling for E: C's bond goes to E.
- A moot dispute (opened before a refutation by someone else) gets its bond
  refunded.

The sampling mode reuses the STEP check as its audit primitive. Its draws
must come from a fixed slot, the SlotHashes entry at `commit_slot + k`, not
the newest one (B6). With first-divergence, a failed sample is a ready-made
leaf `k` for the claims of 6.2. Sampling is specified separately.

## 10. Identities, versions and what changes

**Template ID v2.1** is `SHA256("dcg.template.id.v2.1\0" || graph_id ||
plan_id || app_image_id || kernel_manifest_root || spec_root ||
commitment_kind:u8 || reveal_depth:u8 || challenge_window:u64 ||
phase_window:u64 || bond_policy_digest[32] || max_opening:u32 ||
challenge_limit:u32)`. Every field is mandatory, so there are no optional
trailing bytes (S10).

**Run ID** follows graph-plan-v2 §5: template id, nonce, and the 52-byte
external input refs, sorted. The named executor key is appended.

**Unchanged:**
- DCGG and DCPL bytes;
- `ValueRefV1`;
- the step-leaf preimage;
- the value digest;
- the v2.0 Merkle node rule, under a new domain.

**New:**
- `RunRootV21`;
- the `DCDS` spec and `spec_root`;
- the template and run identities.

**Retired from disputes:** `RegionRootV1` and `ChildRootV1`. They stay in the
frozen v2.0 codec, and a later hierarchical commitment can reuse them (see
below).

**Regions and modes.** Leaves keep their region coordinate, and the spec
keeps each region's mode. v2.1 still admits one mode per template. Later
composition fits on top:
- a consensus region's steps could be executed on chain at commit;
- a sampled region's leaves are what the sampler draws from;
- a ZK region could replace its leaves with one proof leaf, whose STEP check
  is proof verification.

**What a flat tree gives up.** A flat tree is a single commitment by a single
executor. Running regions on different executors, or committing regions
incrementally, would need region subtrees. They would be a hierarchical
variant whose descent first picks a region and then a leaf, with a leaf
order still topological across regions. That is a later, additive version.

## 11. Test plan

- **Goldens.** `DCDS` records, `spec_root`, `RunRootV21`, output entries and
  trace roots for the Hello, parent-child, sibling, grandparent, fan-out and
  long-chain shapes. Python and Rust must agree.
- **Property tests** (native ProgramTest, with Python as the oracle):
  - **Random lies.** Each random small graph gets one lie: a wrong output
    digest, a wrong input digest, a wrong coordinate or key, a nonzero state
    digest, a wrong graph output, a malformed internal tree node, or a
    padding violation. The first-divergence challenger wins every time.
  - **Honest commitments.** No sequence of challenger moves wins.
  - **Rounds.** The round count matches `ceil(log2(n)/d) + 2`.
- **Adversarial cases from the review:**
  - B2: honest leaves with a wrong posted output (OUT);
  - B3: an unopenable input digest (first divergence lands on an earlier leaf
    or on EDGE);
  - B4: does not exist any more (producers come from the spec);
  - B5: a puppet challenger (an independent dispute finishes, and the run
    waits);
  - B7: the three-step `add(add,add)` (staged), and a 1M-step chain (rounds
    and sizes);
  - B8: a root commitment needs a verified template and
    `commitment_kind = ROOT`;
  - self-challenge (the remainder is lost);
  - deadline boundaries `==` and `+1` in every phase;
  - a pre-funded dispute PDA;
  - bond conservation across every ruling.
- **Testnet.** Hello and parent-child again; a wide fan-out graph; a long
  chain; and a forged-input case.

## 12. Open items

- **O1. Large-graph admission.** Deriving `spec_root` for a graph too big to
  decode in one transaction needs a cursor. The other option is an off-chain
  derivation with its own challenge game. The Basanos admission cursor is the
  precedent.
- **O2. Chunked values (required for Basanos).** Large inputs are committed
  by a Merkle root over fixed-size chunks; model weights are the main case.
  The value digest of such a layout is that root, under a declared
  `scheme_id`. A STEP witness carries only the chunks the kernel reads, each
  with its path. Replay refuses if it reaches a chunk the witness lacks, so
  the challenger must supply every chunk the honest kernel reads.
  Data-dependent reads, such as embedding rows chosen by token, are covered:
  the challenger knows the honest inputs and so knows which chunks are read.
  Basanos's weight proofs (tags 122, 123 and 127) are this mechanism, written
  for one application.
- **O3. Steps over one transaction's compute** (required for Basanos).
  Forms 16, 17 and 19 exceeded 1.4M CU when replayed whole, and form 30's
  output is 257 KiB. Such steps either split into `kernel_step` sub-steps,
  each its own leaf with prior and next state digests, or replay in chunks
  under a DCG-owned replay cursor. The tag-124 interface v2 proposes the
  cursor; it is designed, not measured. The leaf-split route needs no new
  dispute machinery, so it is preferred where a kernel can expose
  intermediate state.
- **O4. Reveal fan-out `d`.** It trades reveal size (`32 × 2^d` bytes)
  against rounds. `d = 4` is a starting point; it is fixed per template.
- **O5. Off-chain publication of the commitment** is an application choice.
  The game does not depend on it.

## 13. Mapping Basanos revision 8 onto this design

Source: a read of Basanos `docs/spec/dcg-unified-v8.md`, `dcg-unified-v1.md`
and `dcg-closure-v2-generic-dispute-2026-09-23.md`, and DCG
`docs/spec/referee-laws.md`, `docs/design/tag124-replay-interface-v2.md` and
`closure_v2_response.rs`. Revision 8's dispute path has not run on testnet;
the 10-01 run measured the happy path only.

| Revision 8 | This design |
|---|---|
| One root per position landed in DPR2, an MMR prefix root, segment roots under each position, op leaves under segments | A chunked step-tree shape (3.3): leaves are op entries in (position, segment, local) order, which is topological because positions run in order. Landing per position is incremental commit. |
| Tag 166: open directly at a known bad leaf. Tags 167, 163, 164, 168 and 169: reveal segment roots, then descend 16 descendants per round | First-divergence descent (section 4) with `d = 4`, the same reveal width. Revision 8 lets the challenger pick *any* leaf it believes bad. Picking the first divergent one is what guarantees every input check is against an honest producer. |
| Tag 120: target leaf against the commitment. Tag 121: prior-state reads proved to the producer leaf and position root | SHAPE and EDGE (6.2). The producer is found from `StepSpec`, not from the caller. |
| Tags 122, 123 and 127: model descriptor, weight rows and artifact blocks by proof | Chunked values (O2): weights are an external input whose digest is a chunk root, and a STEP witness carries the rows read. |
| Tag 128 output stream and tag 124 chunked replay | STEP with chunked replay or `kernel_step` sub-leaves (O3). |
| DRU1 staging, tags 115–118 and 125, 1 MiB | Staging (6.4), same cap. |
| Family summaries, tags 170, 171 and 179–181 | Ordinary steps: a summary is a kernel over family outputs, so it needs no separate dispute branch. |
| Output attestation, tag 177, one cell per transaction | Graph outputs posted at `COMMIT` with out-tree paths (3.4). At 10,210 outputs, posting may stay incremental, as tag 177 is; `FINALIZE_RUN` requires all of them. |
| DCR1 per (descriptor, challenger, nonce); no sequence or cap; the first *settled* winner takes the executor bond (order-dependent) | One record per dispute (8). The sequence and earliest-*opened* winner (dispute-economics-v2) remove the order dependence, and `challenge_limit` caps storage. |
| Self-challenge through a second key can recover the pot under a 100% slasher share | The remainder always goes to the payer or the incinerator (9). |
| Custom settlement (tag 187) retries indefinitely | Out of scope here: dispute-economics-v2's finite fallback applies unchanged. |

What carries over:
- The narrowing, authentication and staging ideas carry over almost one for
  one. Basanos already has a hierarchical commitment, read authentication by
  producer proof, 16-wide descent and DRU1 staging.
- First-divergence makes the challenger's choice of leaf principled.
- `DCDS` replaces PT2S's role of telling the referee each leaf's operation
  and reads.
- The Basanos-specific parts stay application code: the A16 kernels and the
  forms catalog (3, 4, 40–47), the meaning of the model root, and the weight
  layout. They enter through the existing `ApplicationDisputeHooks` replay
  and `ArtifactWitnessVerifier`, which become STEP's kernel replay and O2's
  chunk verifier.

What Basanos would need from DCG to move onto this:
1. Chunked step-tree shapes.
2. Chunked values (O2).
3. Chunked replay or sub-step leaves (O3).
4. Large-graph admission (O1). A Basanos document has about 10^5 to 10^6 op
   entries.

The Basanos admission cursor for O1, DRU1 and the tag-124 cursor design
already exist as Basanos-specific versions of these.
