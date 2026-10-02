# Optimistic disputes v2.1: first-divergence disputes for graph runs (draft, revision 2)

Status: **draft design, 2026-10-02, revision 2.** Nothing here is implemented.

It replaces the root-committed descent of v2.0 (tags 220–226). Two reviews
shaped it, both in `out/runs/` of the Basanos repository:
- `review-dcg-graph-v2-2026-10-02.md` found v2.0 unsound. Its items are cited
  here as v2.0-B*n* and v2.0-S*n*.
- `review-dcg-disputes-v2.1-design-2026-10-02.md` reviewed revision 1 of this
  design. Its items are cited as R1-B*n*, R1-S*n*, R1-M*n* and R1-N*n*.

Section 17 maps every reviewed item to the section that handles it. Numbers
are *estimated* unless marked *measured*.

The owner decided on 2026-10-02 to design this now, before more code relies on
the v2.0 formats. The same decision folds in what Basanos needs to move onto
it: large and variable-length runs, state, template constants and late
outputs.

## 1. Goal and properties

One general mechanism by which DCG settles a disagreement about a run of any
size. The executor commits one root. A challenger who knows the honest
execution forces, in a logarithmic number of rounds, a ruling on one small
fact that the program checks locally. Applications supply kernels, constants
and economics hooks rather than building their own dispute game.

**Properties** (each is tested; see section 15):

- **P-sound.** Suppose the committed root differs in any byte from the root
  of the honest execution H. Then an honest challenger who opens before the
  challenge deadline and submits in time wins, whatever the executor does.
  The challenger needs the run's external input bytes, which section 4.4
  makes available.
- **P-complete.** An honest executor who submits in time never loses a
  dispute, whatever challengers do.
- **P-local.** Every check reads a bounded number of fixed-size records and
  logarithmic paths. Nothing decodes a whole graph or plan. Every witness
  fits a staging buffer of a size declared at admission, and every check fits
  a declared compute budget.
- **P-rounds.** For a step tree of height `h` and reveal depth `d`, a dispute
  takes at most `ceil(h/d) + 3` submissions by each party.
- **P-live.**
  - Nobody can stop another challenger from opening or from finishing.
  - Every record reaches a terminal state, and all rent and bonds are
    released, within a bounded time after the challenge deadline.
- **P-bound.**
  - A final run's outputs are bound to the committed root: anyone may post
    an output value with its proof, at any time.
  - A *refuted* run has no result. That is not the honest result: an
    executor can always choose to be refuted. The payer needs a re-run path,
    which section 10 gives.

## 2. What changes, in brief

- **First-divergence.**
  - The executor commits one ordered step tree, in topological order, of
    fixed shape.
  - The challenger descends to the leftmost child whose hash differs from
    H's. That lands on the first divergent leaf, and every earlier leaf is
    then honest.
  - That leaf is refuted locally, by one of the claims in section 7: SHAPE,
    EDGE, GATE, STATE or STEP.
  - Regions carry no soundness weight. v2.0 failed because it relied on them
    (v2.0-B2, B4 and B7).
- **Generated structure.**
  - A plan is a sequence of *segments*. Each segment is either enumerated
    (an explicit step list, for traced graphs) or repeated (a body of steps
    unrolled up to a template bound `K`).
  - Each iteration of a repeated segment is gated by a value computed
    earlier, and an absent iteration is a constant empty subtree. Size is
    therefore fixed by the template and never depends on data.
  - The dispute spec of a repeated segment is generated from its body at
    dispute time. It is never enumerated (R1-M1, R1-M2, R1-S7).
- **State.**
  - Steps may carry state along explicit state chains, and a STATE claim
    checks each link (R1-B5).
  - Large state is chunked. An append-only log covers key and value caches
    and family accumulators (R1-M5).
- **Template constants.** Large immutable inputs, such as model weights,
  are bound in the template identity. They are not chosen per run (R1-M3).
- **Outputs.** The output tree's root is committed at `COMMIT`. Values are
  posted later with proofs, and `OUT_DESCEND` finds a divergent output
  (R1-M4).

The frozen v2.0 bytes that do not change are listed in section 12.

## 3. Structure: plans of segments

### 3.1 Steps, values and producers

A **step** runs one kernel invocation:
- inputs: at most 8 *values*;
- parameters: one node parameter block;
- state: optionally, one prior state;
- results: its output values and, if stateful, a next state.

Each value has exactly one **producer**:

| Kind | Producer | Bound by |
|---|---|---|
| 1 | an output port of an earlier step | the step tree |
| 2 | an external input of the run | the run ID (section 12) |
| 3 | a template constant | the template ID (section 12) |

A step with state names its **state predecessor**: the earlier step whose
next state is its prior state. Alternatively, it names a state *initial
value*, which is a producer of kind 2 or 3.

### 3.2 Enumerated segments

An enumerated segment lists its steps explicitly. A traced graph lowers to
one enumerated segment, from its canonical DCGG and DCPL. The frozen profile
limits it to 16,384 steps, and its spec is derived at admission (section
5.3).

### 3.3 Repeated segments

A repeated segment has three parts:
- a **body**, a list of at most 16,384 step templates;
- a **bound** `K`, the number of iterations, at most 2^32 − 1;
- a **gate**, which decides whether each iteration runs.

**Step templates.** A step template is a step spec in which producers may be
*relative*:
- `(kind 4, body entry e, port b, lag l)` means "output port `b` of body
  entry `e` in iteration `i − l`", with `l ≥ 1`, or `l = 0` when `e` is
  earlier in the body;
- `(kind 5, external or constant id, chunk = i × stride + offset)` means "a
  chunk of a chunked input, indexed by the iteration". It covers inputs such
  as prompt tokens by position.

State predecessors may be relative in the same way. "The key and value cache
of the previous iteration" is the state at lag 1.

**Gate.** Iteration `i ≥ 1` runs if and only if the gate value is nonzero.
The gate value is one designated i32 output of a designated body entry in
iteration `i − 1`. Iteration 0 always runs.
- Once an iteration is gated off, every later iteration is off.
- In an iteration that runs, every step runs.
- In an iteration that is off, every step leaf is the constant `EMPTY_LEAF`.

A stop rule is a body kernel whose output is "continue". The run's
effective length is data, not structure, so D9's "no graph loops" holds: the
unrolled DAG has a fixed size `K × |body|`, and gating only masks it.

**Admission checks.** Admission checks a repeated segment's body once:
- every relative producer points backwards in the order (iteration, body
  index);
- every chunk index fits its declared chunked value for every `i < K`;
- the per-iteration subtree has a fixed shape.

These checks make the unrolled order topological without enumerating it.

**Ceilings.** A template's total step capacity `Σ segments` is at most
2^40. The frozen 16,384 limit applies to each enumerated segment and to each
body. Raising a ceiling this way is a profile change (section 12).

## 4. Values, state and availability

### 4.1 Plain values

A plain value's digest is the frozen value digest:
`SHA256("dcg.value.v2\0" || bytes)`. Its `ValueRefV1` header gives its
layout, scheme, versions and length.

### 4.2 Chunked values (required)

A value whose layout declares `chunked(chunk_bytes)` has a different digest.
It is the root of a tree over its chunks:
- each chunk leaf is `SHA256("dcg.chunk.leaf.v2.1\0" || index:u64 || chunk)`;
- the tree has the shape of section 6.2, so it is padded with
  `EMPTY_CHUNK`;
- the last chunk may be short, and the declared `byte_length` fixes its
  length.

A kernel that reads a chunked value receives *chunk openings*: the chunk
with its path. A STEP witness carries only the chunks the honest kernel
reads. Replay refuses if it reaches a chunk the witness lacks. This holds
for data-dependent reads too, such as embedding rows chosen by token: the
honest challenger knows H, so it knows which chunks are read.

### 4.3 State

A state scheme is declared per node and committed in the spec:

| Scheme | State digest | Prior state supplied to replay |
|---|---|---|
| `SMALL` (at most 4 KiB) | value digest of the state bytes | the bytes |
| `LOG(entry_bytes)`, append-only | `SHA256("dcg.log.v2.1\0" || length:u64 || mmr_root)` over entries | the chunk openings it reads, plus the log's peaks for appending |
| `CHUNKED(chunk_bytes)`, random access | chunked-value digest of the state image | the chunk openings it reads and writes |

Replay computes the next state digest from the prior digest, the openings
and the kernel's writes:
- a `LOG` appends;
- a `CHUNKED` state recomputes the root along each written path.

Basanos's key and value cache, and its family summaries, are `LOG` state
(R1-M5). Range reads are chunk openings against the prior log.

### 4.4 Availability

P-sound requires the challenger to compute H. It therefore needs:
- the run's external input bytes;
- the template constants;
- the published plan.

Admission requires each template constant to be stored on chain in sealed
blobs. `init_run` requires each external input either to be posted to the
run's input account in full, or, for a chunked input, its chunks to be
posted to a run-owned chunk account before the challenge window opens. A
run whose inputs are not fully posted cannot be committed (R1-S3). The
executor's commitment needs no publication: the game reveals it on demand.

## 5. Dispute spec (`DCDS`)

### 5.1 Records

All integers are little-endian. All reserved bytes are zero.

**Port header.** The expected `ValueRefV1` header, minus the digest, is 23
bytes: `node_id:u32 direction:u8 port_id:u16 layout_id:u32
layout_version:u16 scheme_id:u32 scheme_version:u16 byte_length:u32`.
- A port's `scheme_id` and `scheme_version` are those of the **producer's**
  region.
- An external input's scheme is the root region's.
- A constant's scheme is declared with the constant.

The spec fixes the header exactly, so SHAPE, EDGE and OUT compare all 23
bytes (R1-B4).

**Producer.** A producer is 24 bytes:

```
kind:u8 reserved:u8[3] a:u64 b:u32 lag_or_stride:u32 offset:u32
```

- Kind 1: `a` = ordinal, `b` = port.
- Kind 2: `a` = external id.
- Kind 3: `a` = constant id.
- Kind 4: `a` = body entry, `b` = port, `lag_or_stride` = lag.
- Kind 5: `a` = chunked input id, `b` = 2 (external) or 3 (constant),
  `lag_or_stride` = stride, `offset` = offset.
- Unused fields are zero.

**`StepSpec`.** At most 8 inputs and 8 outputs:

| Bytes | Field |
|---|---|
| `0..4` | magic `DSS1` |
| `4..8` | region_id:u32 |
| `8..12` | segment_id:u32 |
| `12..16` | node_id:u32 |
| `16..20` | kernel_step:u32 |
| `20..36` | kernel_id:[16] |
| `36..38` | semantic_version:u16 |
| `38..40` | abi_version:u16 |
| `40..44` | decomposition_id:u32 |
| `44..46` | decomposition_version:u16 |
| `46..48` | reserved |
| `48..56` | max_cu:u64 |
| `56..88` | parameter_digest:[32] (`SHA256("dcg.params.v2.1\0" || layout_id:u32 || layout_version:u16 || length:u32 || bytes)`; zero for an empty block) |
| `88..120` | port_shapes_digest:[32] (SHA-256 of the node's canonical DCGG port records, so replay knows scalar type, rank and dimensions) |
| `120` | state_scheme:u8 (0 none, 1 SMALL, 2 LOG, 3 CHUNKED) |
| `121..124` | reserved |
| `124..128` | state_parameter:u32 (entry or chunk bytes) |
| `128..152` | state_predecessor: producer (kind 1 or 4 for a previous step; kind 2 or 3 for an initial value) |
| `152` | input_count:u8 |
| `153` | output_count:u8 |
| `154..160` | reserved |
| `160..` | inputs: `input_count` × (port header 23 + producer 24 + reserved 1) |
| then | outputs: `output_count` × (port header 23 + reserved 1) |

**Other records.**
- **`OutSpec(j)`.** `j` is the rank in `external_id` order (R1-N8). The
  record is a port header plus a producer of kind 1 or 4, plus, in a
  repeated segment, the iteration it reads.
- **`InSpec(id)` and `ConstSpec(id)`.** A port header plus a chunk size
  (zero for a plain value). `ConstSpec` adds the constant's digest.
- **`SegmentSpec`.**
  - Its kind: enumerated or repeated.
  - The ordinal base, the step count (for a repeated segment, `K ×
    body_len`) and `K`.
  - The gate's body entry and port.
  - The digest of its body table or enumerated records.
- **`RegionSpec`.** Region id, parent, mode, and scheme and layout ids and
  versions.

### 5.2 Spec root

The spec is a tree over its records in this order:
1. the header;
2. the `SegmentSpec` records;
3. the `ConstSpec`, `InSpec`, `OutSpec` and `RegionSpec` records;
4. per segment, its body table (repeated) or its `StepSpec` records
   (enumerated).

It has the shape of section 6.2. The header holds the count of each record
type, so every record's position can be computed. Its layout:

```
magic "DCS1"
version:u16
reserved:u16
segment, const, in, out and region counts: u32 each
total_steps:u64
tree_shape:u8 (section 6.2)
reveal_depth:u8
reserved:u16
```

Each leaf is `SHA256("dcg.spec.leaf.v2.1\0" || type:u8 || record)`.
`spec_root` is the tree's root.

**Repeated segments.** `StepSpec(k)` for ordinal `k` in a repeated segment
is computed at dispute time:
1. Write `k = base + i × body_len + e`.
2. Open body entry `e` of the segment's body table.
3. Resolve its relative producers for iteration `i`:
   - kind 4 with lag `l` becomes kind 1 at ordinal `base + (i − l) ×
     body_len + e'`, or, when `i < l`, the declared initial producer;
   - kind 5 becomes a chunk index.

The spec for 10^6 Basanos op entries is therefore its body table plus a few
records, not 10^6 records.

### 5.3 Derivation and admission

The derivation is a pure function. Its inputs are:
- for enumerated segments, the canonical DCGG and DCPL;
- for repeated segments, a canonical *body plan* (a DCPL whose steps are the
  body, plus the relative-producer table).

It refuses each of the following:
- a non-topological order;
- an output port listed by more than one step;
- more than 8 inputs or outputs on a step;
- a relative producer that points forward;
- a chunk index out of range;
- a state chain that forks;
- a node with `kernel_step > 1` unless its decomposition is declared and the
  state chain links its sub-steps.

**Admission.** An admission cursor computes `spec_root` over several
transactions. It keeps a scratch account holding:
- the producer index for enumerated segments, mapping
  `(node, port) → ordinal`;
- a streaming Merkle frontier.

Enumerated segments are bounded by 16,384 steps, so the work is bounded
(*estimated*: under 30 transactions at 16,384 steps). A Basanos template's
cost is its body.

The alternative R1-S7 proposed was to index the sealed DCGG and DCPL and
derive specs at dispute time. That is rejected. Repeated segments need a
committed body table anyway, and the frozen DCPL cannot express repetition.
A single derived root also keeps the referee independent of shard layout.

## 6. Commitments

### 6.1 Step leaf

The frozen v2.0 step-leaf preimage (graph-plan-v2 §5) is unchanged:
- plan id and run id;
- region and coordinate, with `ordinal:u64`, so 2^40 fits;
- input and output `ValueRefV1` lists, sorted by port key;
- `prior_state_digest` and `next_state_digest`.

For a stateless step, both state digests are zero. A leaf with 8 inputs and
8 outputs is 1,040 bytes (*estimated* from the encoding).

`EMPTY_LEAF = SHA256("dcg.leaf.empty.v2.1\0")` is the leaf of a gated-off
step.

### 6.2 Tree shape (replaces duplicate-last for v2.1 trees)

Every v2.1 tree has the same shape: the step tree, the out tree, the chunk
trees, log MMR peaks bagged into a fixed tree, and the spec tree. Its rules:

- **Leaves.** A tree over `n` leaves has `2^ceil(log2 n)` leaf positions.
  Positions `≥ n` hold the empty constant of that tree type. There is no
  duplication rule, so R1-B8 does not arise.
- **Nodes.** A node is `SHA256(domain || level:u16 || left || right)`, with
  a per-tree domain:
  - `dcg.trace.node.v2.1\0` for the step tree;
  - `dcg.out.node.v2.1\0` for the out tree (R1-N4);
  - `dcg.chunk.node.v2.1\0` for chunk trees;
  - `dcg.spec.node.v2.1\0` for the spec tree.
- **Empty subtrees.** An all-empty subtree at level `l` has the constant
  `EMPTY[l]`, defined by `EMPTY[l+1] = node(l, EMPTY[l], EMPTY[l])`.
- **Two-level shape** (`tree_shape = 1`). The step tree is a top tree whose
  leaves are per-segment subtrees, and each segment's subtree is in turn:
  - enumerated: a tree over its steps;
  - repeated: a top tree over `K` iteration subtrees, each a tree over
    `body_len` leaves.

  An executor can land iteration roots as it goes, as Basanos lands
  position roots, and seal the top at `COMMIT`.
- **Off iterations.** An iteration that is gated off has the subtree
  `EMPTY[h_body]`. An executor who stops at iteration `s` commits empties
  for every later iteration without hashing them.

The shape is a pure function of the spec header and segment records. The
tree's height `h` is fixed per template.

### 6.3 Run root

```
RunRootV21 =                                   ; 180 bytes
  plan_id[32] run_id[32] spec_root[32]
  total_steps:u64
  step_tree_root[32]
  out_count:u32
  out_tree_root[32]
  effective_iterations:u32                     ; repeated segments: last running iteration + 1, else 0
  reserved:u32
run_root = SHA256("dcg.run.root.v2.1\0" || RunRootV21)
```

The run root fixes `effective_iterations`. The gate claim (7.3) refutes a
wrong value.

### 6.4 `COMMIT` checks (R1-S1)

`COMMIT` refuses unless all of the following hold:
- `plan_id`, `run_id` and `spec_root` equal the run's and the template's;
- `total_steps` and `out_count` equal the spec's, and the descent uses the
  spec's counts, never the posted ones;
- `effective_iterations` is at most `K`;
- the run's inputs are fully posted (4.4).

Output values are **not** required at commit. Anyone may post output `j`
with its out-tree path and value bytes at any time, even after the run is
final. The program checks:
- the path against `out_tree_root`;
- the entry's header against `OutSpec(j)`;
- the value against its digest.

Consumers read outputs only through such posts, so they are bound (P-bound).
An out-tree position of a gated-off output holds `EMPTY_OUT`.

## 7. Why first-divergence works

Let H be the honest execution. Its step tree, out tree and
`effective_iterations` are all computable from the plan, the constants and
the inputs (4.4).

### 7.1 Descent

The dispute keeps a current node of the executor's tree, starting at the
root.

1. **Reveal.** Each round, the executor reveals the hashes `d'` levels below
   the current node, where `d' = min(d, remaining height)` and `d ≤ 5`
   (R1-N7). It lists only positions whose leaf range intersects `[0, n)`.
   The program fills every all-empty position with `EMPTY[l]`, folds level
   by level, and checks the result against the current node.
2. **Pick.** The challenger picks one revealed position. The pick is refused
   if the position is all-empty (R1-B8), so the descent never reaches an
   index `≥ n`.
3. **Leaf.** At the leaf level, the executor reveals the leaf bytes, or the
   empty marker for an `EMPTY_LEAF`. The program checks them against the
   leaf hash and stores them.

**Invariant.** The challenger always picks the leftmost position whose hash
differs from H's. Every leaf to the left of the current node is then equal
to H's. A position is skipped only when its hash equals H's, and by
collision resistance every leaf under it then equals H's. Empty positions
equal H's empties by construction.

The scratch model of R1 confirmed this on 3,000 random trees (*measured*,
offline model, not DCG code).

**Existence.** The root differs from H's exactly when some leaf differs, and
then the leftmost differing child exists at every level.

### 7.2 Base case: leaf k is the first divergent leaf

Every leaf before `k` equals H's. Leaf `k`, as revealed, differs from H's
leaf `k`. The challenger claims one of the following (7.3), each a local
check:

| Divergence in leaf `k` | Claim | Why the check wins |
|---|---|---|
| bytes that do not parse, wrong plan or run id, wrong coordinate, a header byte, a count, nonzero state digests on a stateless step, or empty versus present on a non-gated step | SHAPE | compared against `StepSpec(k)` and the run |
| leaf present or empty, but the gate says otherwise | GATE | the gate value comes from an earlier leaf, which is honest |
| an input digest | EDGE(i) | the producer is an earlier leaf (honest), an external input (run) or a constant (template) |
| the prior state digest | STATE | the predecessor is an earlier leaf (honest), or an initial value |
| outputs or the next state digest | STEP | every input, the prior state and the parameters equal H's, so the challenger can witness them, and replay produces H's outputs |

The rows are exhaustive. A leaf is fully determined by the spec, the run,
its producers' outputs, its predecessor's state and the kernel.

**Outputs.**
- If the step tree equals H's but the out tree differs, the challenger
  descends the out tree the same way (`OUT_DESCEND`). It lands on the first
  differing entry `j`, whose producer leaf is honest.
- If the step tree equals H's but `effective_iterations` differs, a GATE
  claim on the first iteration where the commitment and H disagree wins.
  That iteration's gate producer is honest.

The challenger should start with `OUT_DESCEND` only when `step_tree_root`
equals H's (R1-N5).

### 7.3 Claims

| Claim | Opened (by whom) | Rules for C when |
|---|---|---|
| SHAPE | `StepSpec(k)` (either party; for a repeated segment, the body entry and segment record) | the leaf's bytes fail to parse, or any byte differs from the expected leaf except digests: ids, coordinate, every 23-byte port header, counts, the zero state of a stateless step, and the empty marker of a step that is not gated |
| EDGE(i) | `StepSpec(k)`; for kind 1 or 4, producer leaf `p` with its path (E, or C from the cached descent, R1-N6) | the 55-byte input ref differs in any field from the producer's output ref, the external ref (52 bytes plus node fields) or the constant's digest; or the producer leaf lacks the port; or it is empty |
| GATE | `SegmentSpec`; the gate producer leaf for iteration `i − 1` | leaf `k` is present but the gate value is zero, or leaf `k` is empty but the gate value is nonzero; for `effective_iterations`, the posted value disagrees with the gates |
| STATE | `StepSpec(k)`; the predecessor leaf, or the initial value's ref | `prior_state_digest` differs from the predecessor's `next_state_digest`, or from the initial digest |
| STEP | `StepSpec(k)`; C's witness: input values or chunk openings, parameter bytes, port records, prior state material | the witness verifies against leaf `k`'s digests, `parameter_digest` and `port_shapes_digest`, and the replayed outputs or next state differ from leaf `k`'s |
| OUT(j) | `OutSpec(j)`; the producer leaf | the full out entry differs from the producer's output ref, or the producer lacks the port |

**Normative rule for malformed data (R1-B3).** Bytes that hash to the
executor's own commitment are accepted as they are and stored. If they are
malformed, missing a port or the wrong length, the claim rules for the
challenger. A party's own fresh submission that fails verification (a
witness, a reveal that does not fold, a pick of an all-empty position) is
refused, and that party may retry until its deadline.

**Completeness.** If the commitment is H's:
- every reveal and opening verifies;
- every comparison is between equal fields;
- every replay reproduces the committed digests;
- `OUT_DESCEND` and GATE find nothing that differs.

Every claim rules for the executor.

## 8. The game

### 8.1 Phases

```
OPEN(kind = STEP_DESCEND | OUT_DESCEND), C posts bond and pre-funds its staging
  AWAIT_NODES   E reveals (8.3 run cache may answer at once)
  AWAIT_PICK    C picks                                   repeat to leaf level
  AWAIT_LEAF    E reveals leaf k (or entry j)
  AWAIT_CLAIM   C names SHAPE | EDGE(i) | GATE | STATE | STEP | OUT
  AWAIT_OPENING E opens what the claim needs (skipped when public or cached)
  AWAIT_WITNESS C submits its pre-staged witness (STEP only)
  RULED
```

- Every action checks `now <= phase_deadline`, and every timeout checks
  `now > phase_deadline`.
- A silent party loses.
- Spec records are public. Either party may supply them.

### 8.2 Staging (R1-B7, R1-S5)

Each party owns its own staging buffers. For each one:
- the party funds its rent and gets it back when the dispute closes;
- the party may write to it at any time, not only during its own phase;
- the buffer is written in 900-byte writes and grows in 10,240-byte
  increments (DRU1-style).

Only the final submit is timed.
- C can stage a witness as soon as the leaf is revealed.
- E can stage a leaf opening as soon as a pick is made.

Admission sets `max_opening` to the largest of:
- one leaf plus its path;
- one spec record plus its path;
- the largest witness: inputs or openings, parameters, port records and
  state material.

Admission refuses a template whose `max_opening` is over 1 MiB, the DRU1 cap.
For reference, a measured Basanos form-30 body is about 582 KB.

### 8.3 Windows and load (R1-B7)

**Phase windows.**
- A phase's window is `phase_window + ceil(bytes_due / write_rate) ×
  write_slots`, where `bytes_due` is the most that phase may require
  staging.
- `write_rate` and `write_slots` are template parameters. They must be at
  least the floors measured on testnet before the constants are fixed (open
  item O1).

**Run-level reveal cache.** The run keeps a cache of revealed tree nodes.
- When E reveals the hashes under a node once, every dispute reaches that
  node with its answer already present.
- So an honest executor answers at most one reveal per distinct node,
  however many disputes share a path.
- Leaves and openings are cached the same way.

**Load extension.** When more than `c` disputes (a template parameter) are
waiting on E at once, each additional waiting dispute extends E's deadlines
in all of them by `extend_slots`. The extension is capped by the bounded
finalization delay (section 10).

### 8.4 Sizes (*estimated*)

| Case | Size |
|---|---|
| Node reveal at `d = 4` | 512 bytes |
| Tree height, Basanos-size template (K = 10,240, about 64 entries per iteration) | about 20 levels |
| Descent rounds at `d = 4` (or 4 at `d = 5`) | 5 |
| Leaf, at most | 1,040 bytes |
| EDGE opening (leaf plus a 20-level path) | 1.7 KB |
| STEP witness for a Basanos A16 op | up to the 582 KB already measured for form 30 |

## 9. Instructions

| Instruction | Who |
|---|---|
| `COMMIT(run root)`; `LAND_SUBTREE(segment, iteration, root)` for incremental landing | the run's named executor |
| `POST_OUTPUT(j, path, value)` | anyone, any time after commit |
| `OPEN_DISPUTE(nonce, kind)`, with bond and staging pre-fund | anyone, while `now <= challenge_deadline` and the run is not `REFUTED` |
| `STAGE_CREATE`, `STAGE_WRITE(offset, bytes)` | either party, own buffer |
| `REVEAL_NODES`, `PICK`, `REVEAL_LEAF`, `CLAIM`, `SUBMIT_OPENING`, `SUBMIT_WITNESS` | E, C, E, C, E, C |
| `TIMEOUT`, `ADVANCE_RULED_PREFIX`, `SETTLE`, `FINALIZE_RUN`, `CANCEL_RUN` | anyone (`CANCEL_RUN`: the payer, after the commit deadline with no commit) |
| `CLOSE_DISPUTE`, `CLOSE_STAGING`, `CLOSE_RUN`, `CLOSE_CACHE` | anyone; rent goes to the recorded payers |

These are new tags. Tags 220–226 are not reused. The v2.0 handlers stay
under `graph-v2-experimental` until they are removed. The trace-committed
path (209–218) stays for small graphs, and a template's `commitment_kind`
fixes which path its runs use (v2.0-B7, v2.0-S6).

Every record is accepted only at its derived PDA:
- run, template and blob, as already fixed in `b78e742`;
- dispute, staging and cache records, newly.

Blob PDAs are seeded with their writer, so an unsealed blob cannot squat an
id (v2.0-S2, R1-S6).

## 10. Concurrency, records, finality and economics

### 10.1 Disputes and their order

**No cap (R1-B1).**
- Each dispute is its own PDA, `["dcg2dsp", run, challenger, nonce]`, paid
  for by its challenger.
- The run keeps `next_sequence:u64` and `open_disputes:u32`. Each open takes
  the next sequence.
- No table means no slot can be filled.

**Ruled prefix (R1-B2).**
- The run keeps `ruled_prefix:u64`, the smallest sequence not yet ruled.
- It also keeps `best_win:u64`, the lowest-sequence challenger win.
- `ADVANCE_RULED_PREFIX` moves the prefix over ruled disputes in sequence
  order. It is permissionless.

**Refutation.** The first challenger ruling sets the run to `REFUTED`.
- Disputes with a *lower* sequence than `best_win` continue to their
  ruling.
- Disputes with a *higher* sequence become moot (NEUTRAL), and their bonds
  are refunded.
- No dispute may open on a refuted run.
- The pot goes to `best_win` once `ruled_prefix > best_win`, as in
  dispute-economics-v2 §2.

### 10.2 Bounds, finality and liveness

**Bounded delay.**
- Every open happens before the challenge deadline.
- Each dispute lasts at most `(ceil(h/d) + 3) × 2` phases.
- With the load extension capped, finality is at most `challenge_window +
  D_max` after commit, where `D_max` is computed at admission from the
  windows and the cap.

**Windows.** `challenge_window` and `phase_window` have a minimum and a
maximum at admission (v2.0-S3, R1-S6), and every `u64` addition is checked.

**Finalization.** A run finalizes when:
- `now > challenge_deadline`;
- `open_disputes == 0`;
- and the run is not refuted.

**Liveness.**
- `init_run` names the executor key (v2.0-S6).
- With the zero key ("anyone"), the bond and the rent follow the actual
  committer (R1-S9).
- The payer may `CANCEL_RUN` a run with no commit after its commit deadline
  (R1-S6).

**Re-run (R1-S10).**
- A refuted run has no result.
- The payer may open a new run with the same inputs and a different
  executor.
- The application decides what happens to its requester, through a hook.
  For Basanos, that is the document's disposition.

**Records close.**
- A dispute closes after settlement. Its rent goes to its challenger, and
  each staging buffer's rent goes to its owner.
- The run and its reveal cache close after every dispute has closed
  (v2.0-S4).

### 10.3 Economics

These are application hooks, with DCG enforcing conservation.

**Bonds.** E posts `executor_bond` at commit, and C posts `challenger_bond`
at open.

**Standard policy.**
- A challenger win returns C's bond.
- `best_win` receives `bond_slasher_bps` of the executor bond.
- The remainder goes to the template's committed destination: the payer or
  the incinerator.
- An executor win takes C's bond.
- A moot dispute is refunded.

**Admission rules.** Admission requires:
- `bond_slasher_bps < 10,000`;
- a nonzero remainder;
- a remainder destination that is not the executor.

**What deters a cheating executor.**
- The deterrent is the remainder. A cheating executor can always front-run
  with its own challenger and recover the slasher share (R1-S4).
- The payer is the guaranteed watcher: it loses the result if it does not
  watch.
- An application that wants third-party watchers sets the slasher share,
  and the bonds, high enough to pay them.

## 11. Composition and finality across regions (R1-S8)

**Finality across regions.** graph-plan-v2 §3 makes cross-region imports
wait for source-region finality. In a v2.1 run, all regions finalize
together with the run, so every import is final exactly when its source is.
This is a recorded change to the frozen profile under its §9 change control.
It is not silent.

**Regions and modes.** Regions remain in leaf coordinates and in the spec.
v2.1 admits one mode per template. Later composition can come per region,
on the same tree:
- a consensus region's steps executed on chain at commit;
- sampled regions;
- ZK regions with proof leaves.

## 12. Identities, versions and what changes

**Template ID v2.1.**
- It is `SHA256("dcg.template.id.v2.1\0" || …)` over every one of these
  fields, all mandatory, with no optional trailing bytes (v2.0-S10):
  - `graph_id` and `plan_id` (zero when the template has only repeated
    segments);
  - `body_plan_ids_root`, `app_image_id`, `kernel_manifest_root`,
    `spec_root` and `constants_root`;
  - `commitment_kind:u8`, `reveal_depth:u8` and `tree_shape:u8`;
  - `challenge_window`, `phase_window`, `write_rate`, `write_slots`, `c`
    and `extend_slots`;
  - `commit_deadline_slots`;
  - `bond_policy_digest` and `max_opening`.
- `constants_root` is the tree root over `ConstSpec` digests.

**Run ID v2.1.** It is `SHA256("dcg.run.id.v2.1\0" || template_id ||
nonce || count:u32 || external refs (52 bytes each, sorted) || executor[32])`
(R1-S9). `init_run` checks the refs against `InSpec`: exact ids, headers
and lengths (R1-S3).

**Unchanged frozen bytes:**
- DCGG and DCPL;
- `ValueRefV1`;
- the step-leaf preimage;
- the value digest;
- the 52-byte external ref.

**New:**
- `DCDS` and its records;
- body plans with relative producers;
- `RunRootV21`;
- the v2.1 tree shape with empty constants;
- chunked values and state schemes;
- the template and run identities.

**Retired from disputes:** `RegionRootV1`, `ChildRootV1`, and duplicate-last
padding for v2.1 trees.

**Profile changes, recorded under graph-plan-v2 §9:**
- repeated segments: a total capacity of 2^40, with 16,384 per body;
- one replay opening raised from 4 KiB to staged openings of up to 1 MiB;
- cross-region finality (section 11);
- stateful nodes admitted under the declared schemes.

## 13. Basanos revision 8 on v2.1

Sources:
- the scout read of `dcg-unified-v8.md`, `dcg-unified-v1.md` and the closure
  notes;
- R1's checks of v8 §1.x and §8.3.7.

Revision 8's dispute path has not run on testnet. The 10-01 run measured
the happy path only.

| Revision 8 | v2.1 |
|---|---|
| One K = 10,240 template for every document; prompt length variable; stop rule | One repeated segment with `K = 10,240`. The body is one position's op entries. Prompt tokens come from a chunked external input (kind 5, stride 1). The body's stop kernel is the gate. Variable length is data, not structure (R1-M2). |
| Op entries by (position, segment, local) | Ordinal = `base + position × body_len + entry`, which is topological. Revision 8 segments become sub-blocks of the body. |
| Per-position roots landed in DPR2, with an MMR prefix | `LAND_SUBTREE` per iteration into the fixed two-level shape. The MMR is replaced, which closes R1-M5's shape problem. |
| Tags 166, 167, 163, 164, 168 and 169 (direct open, segment reveal, 16-wide descent) | First-divergence descent with `d = 4`, the same width. The leaf choice is now forced to the first divergence. |
| Tags 120 and 121 (target leaf; reads proved to the producer leaf) | SHAPE and EDGE, with producers from `StepSpec`. |
| Prior-state and key/value cache reads | `LOG` state carried along the iteration (lag 1). Reads are chunk openings, and STATE checks the links. |
| Tags 122, 123 and 127 (model descriptor, weight rows, artifact blocks) | The weights are template constants (kind 3, chunked) inside `constants_root`, sealed with the template as revision 8 seals them (R1-M3). The STEP witness carries the rows read. |
| Tags 128 and 124 (output stream, chunked replay) | STEP with chunk openings. A form over one transaction's compute (16, 17, 19) is split by its declared decomposition into sub-step leaves linked by a `SMALL` or `CHUNKED` state chain. |
| DRU1 (115–118, 125), 1 MiB | Per-party staging (8.2), with the same cap and write size. |
| Family summaries (170, 171, 179–181) | Ordinary body steps over `LOG` state, placed after the ops they read (the derivation checks this; §8.3.7 interleaving). |
| Output attestation (177) after finalize | `POST_OUTPUT` at any time against the committed `out_tree_root` (R1-M4). |
| DCR1 per (descriptor, challenger, nonce), first-settled winner | Ruled prefix and `best_win` (10.1). |
| Self-challenge through a second key | The remainder deterrent (10.3). |
| Custom settlement retry (187) | dispute-economics-v2's finite fallback, unchanged. |

**Application-supplied, through existing hooks:**
- A16 kernels and the form catalog, as STEP replay via
  `ApplicationDisputeHooks`;
- the weight layout and the meaning of the model root, as the chunk
  verifier via `ArtifactWitnessVerifier`.

**What a Basanos migration still needs (implementation, not design):**
1. A body plan for one position.
2. Each form's decomposition and state scheme.
3. Measured `write_rate` (O1).
4. The CU of each form's replay plus hashing within `max_cu` (O2).

## 14. Implementation order

1. **Core.** Python reference for:
   - the v2.1 tree shape;
   - `DCDS`, for enumerated segments;
   - `RunRootV21`;
   - the descent;
   - SHAPE, EDGE, STEP and OUT, stateless.

   Goldens for all of them.
2. **Native program.** Commit, dispute records, staging, cache, ruled
   prefix, economics. Property tests (section 15).
3. **Repeated segments and gates.** GATE and generated specs.
4. **State.** The three schemes and STATE.
5. **Chunked values and constants.**
6. **Testnet:**
   - write-rate measurement (O1);
   - Hello, fan-out and long-chain runs;
   - a gated repeated segment.
7. **Basanos body plan,** on a K = 35 document first.

## 15. Test plan

- **Goldens** (Python and Rust must agree):
  - tree shape for `n = 1, 2, 3, 5, 6, 7, 2^k ± 1`, including `EMPTY[l]`;
  - every `DCDS` record and the spec header;
  - generated `StepSpec` for repeated segments;
  - `RunRootV21`;
  - chunked values, `LOG` and `CHUNKED` state digests.
- **Property tests** (native ProgramTest, with Python as the oracle):
  - **Random lies.** Random graphs and segments each get one lie in any field
    of any leaf: header bytes, a digest, a count, state, the gate, the empty
    marker, an out entry, `effective_iterations`, an internal node, or an
    unparseable leaf. The first-divergence challenger wins every time.
  - **Honest commitments.** No challenger move wins.
  - **Rounds.** The round count matches `ceil(h/d) + 3`.
- **Adversarial:**
  - each R1 blocker:
    - B1: puppets cannot block an open;
    - B2: an earlier honest dispute is paid despite a faster puppet;
    - B3: malformed executor bytes rule for C;
    - B4: each header field is caught;
    - B5: state lies are caught;
    - B6: a STEP witness with wrong parameters is refused;
    - B7: concurrent disputes and the extension;
    - B8: padding picks are refused;
  - each v2.0 blocker that still applies;
  - deadlines at `==` and `+1`;
  - pre-funded PDAs;
  - conservation across every ruling and moot path.
- **Testnet:** section 14, step 6.

## 16. Open items

- **O1.** `write_rate`, `write_slots` and staged-write landing throughput on
  Fogo. These must be measured before the window constants are fixed.
- **O2.** CU for replay plus witness hashing per kernel. SHA-256 over 1 MiB
  is roughly 0.5M CU (*estimated*, R1-S11). Admission refuses a step whose
  declared `max_cu` exceeds the budget, and such steps must be decomposed.
- **O3.** The sampling mode on top of STEP. The fixed-slot draw is still
  open to grinding by that slot's leader, and Fogo's validator set is small
  (R1-N10).
- **O4.** Reveal depth `d`, up to 5. `d = 4` is the default.
- **O5.** Hierarchical (multi-executor) commitments. They would be an
  additive version over the same leaves and spec.

## 17. Review traceability

| Item | Where |
|---|---|
| v2.0-B1 forged records; v2.0-S2 squatting | 9 (derived PDAs; writer-seeded blobs) |
| v2.0-B2 unbound outputs and positions | 6.2–6.4, 7 |
| v2.0-B3 preimage before consistency | 7.3 (digest comparisons; malformed-data rule) |
| v2.0-B4 any-child authentication | removed; producers come from the spec (5) |
| v2.0-B5 one slot, deadlines | 8.1, 10.1 |
| v2.0-B6 sampling grind | O3 |
| v2.0-B7 size, decode, siblings | 5.2, 5.3, 8.2; there are no region waypoints |
| v2.0-B8 unverified templates | 9 (`commitment_kind`; spec root required) |
| v2.0-S1 dust; S3 windows; S4 records; S5 stranded | 9, 10.2 |
| v2.0-S6 executor; S7 self-challenge; S8 result binding | 10.2, 10.3, 6.4 |
| v2.0-S9 replay checks; S10 identities; S11 capacity | 5.1 (`StepSpec`), 12, 3.3 and 8.2 |
| R1-B1 to R1-B8 | 10.1, 10.1, 7.3, 5.1, 4.3 and 7.3, 5.1, 8.2 and 8.3, 6.2 and 7.1 |
| R1-M1 to R1-M5 | 3.3 and 5.2, 3.3, 3.1 and 13, 6.4, 4.3 and 6.2 |
| R1-S1 to R1-S11 | 6.4, 5.1 and 5.2, 4.4 and 12, 10.3, 8.2, 9 and 10.2, 5.3, 11, 12, 10.2, O2 |
| R1-N1 to R1-N10 | 6.3 (180 bytes, recounted with the new fields), 3.3, 7.3, 6.2, 7.2, 7.3, 7.1, 5.1, 1 and 10.2, O3 |
