# Optimistic disputes v2.1: first-divergence disputes for graph runs (draft, revision 3.1)

Status: **draft design, 2026-10-02, revision 3.1** (revision 3 plus the focused check's fixes, `review-dcg-disputes-v2.1-rev3-focused-2026-10-02.md`, cited R3-*). Tag 227 implements selected slices of this design, described below; it is not a complete implementation. It replaces the root-committed descent of v2.0 (tags 220–226).

Review history (reports in Basanos `out/runs/`):
- `review-dcg-graph-v2-2026-10-02.md` found v2.0 unsound. Cited here as
  v2.0-B*n* and v2.0-S*n*.
- `review-dcg-disputes-v2.1-design-2026-10-02.md` reviewed revision 1. Cited
  as R1-*.
- `review-dcg-disputes-v2.1-rev2-2026-10-02.md` reviewed revision 2. Cited as
  R2-*.

Section 18 maps every item to its section. Numbers are *estimated* unless
marked *measured*.

The owner decided on 2026-10-02 to design this before more code relies on
the v2.0 formats, and to fold in what Basanos needs: large and
variable-length runs, state, template constants and late outputs.

## 1. Goal and properties

A general mechanism by which DCG settles a disagreement about a run of any
size:
- The executor commits one root.
- A challenger who knows the honest execution H forces, in a logarithmic
  number of rounds, a ruling on one small fact that the program checks
  locally.

Applications supply kernels, constants and economics hooks. They do not
build their own dispute game.

**Properties** (each tested; see section 16):

- **P-sound.** If the committed run root differs in any byte from H's, an
  honest challenger wins whatever the executor does. The challenger must
  open before the challenge deadline and submit in time. It relies on the
  availability conditions of section 4.4.
- **P-complete.** An honest executor who submits in time never loses a
  dispute, whatever challengers do. Section 10.2 makes "in time" bounded per
  open: every extra concurrent open extends the executor's deadlines (R2-B5).
- **P-local.** Every check reads a bounded number of fixed-size records and
  logarithmic paths. Nothing decodes a whole graph or plan. Every witness
  fits a staging buffer of a size declared at admission. Every check fits a
  declared compute budget.
- **P-rounds.** For a step tree of height `h` and reveal depth `d`, a dispute
  takes at most `ceil(h/d) + 3` submissions by each party.
- **P-live.** No one can stop another challenger from opening or finishing.
  Every record reaches a terminal state, and all rent and bonds are released.
  Finality comes within `challenge_window + D(N)` slots of the commit, where
  `N` is the number of disputes opened. `D` is linear in `N` and fixed at
  admission. Every open is paid for by a bond.
- **P-bound.** A final run's outputs are bound to its root. Anyone may post
  an output with its proof once the run is final. A refuted run has no
  result. It does not have the honest result either, because an executor can
  always choose to be refuted. The payer has a re-run path (section 10.2).

## 2. Changes in brief

- **First divergence.**
  - The executor commits one step tree in topological order. Its shape is
    fixed by the template.
  - The challenger descends to the leftmost pickable child whose hash
    differs from H's. It lands on the first divergent leaf, and every earlier
    leaf is then honest.
  - That leaf is refuted by one local claim: SHAPE, EDGE, GATE, STATE or
    STEP.
  - Regions carry no soundness weight.
- **Generated structure.**
  - A plan is a list of *blocks*. Each block is either enumerated (an
    explicit step list) or repeated (a body unrolled up to a bound `K` and
    gated per iteration).
  - Absent iterations are empty subtrees. The address map is fixed by the
    template.
  - Specs for repeated blocks are generated at dispute time. They are never
    enumerated.
- **State.** Explicit state chains, with a STATE claim. There are three
  schemes: SMALL, LOG and CHUNKED. LOG and CHUNKED are fixed-capacity trees,
  so no MMR is needed. A step may export its state as a value for other
  steps to read.
- **Constants.** Large immutable inputs are bound in the template ID. They
  may be resident on chain, or committed and held off chain (R2-B6).
- **Outputs.** The output tree root is committed at `COMMIT`. Values are
  posted with proofs after finality. `OUT_DESCEND` refutes a divergent
  output.

Unchanged frozen bytes are listed in section 12.

## 3. Structure: plans of blocks

DCPL already uses "segment" for a per-region step run, and the leaf
coordinate's `segment_id` keeps that meaning. This design calls its
top-level units **blocks** (R2-S11.7).

### 3.1 Steps, values and producers

A **step** runs one kernel invocation:
- on at most 8 input *values*;
- with one node parameter block;
- optionally with one prior state;
- producing at most 8 output values and, if stateful, a next state.

Each value has exactly one producer:

| Kind | Producer | Bound by |
|---|---|---|
| 1 | an output port of an earlier step (absolute ordinal) | the step tree |
| 2 | an external input of the run | the run ID |
| 3 | a template constant | the template ID |
| 4 | an output port of a body entry at a relative iteration (repeated blocks) | the step tree |
| 5 | one chunk of a chunked external input or constant, indexed by the iteration | the run or template ID |
| 6 | an output port of a body entry in the **last running iteration** of an earlier repeated block | the step tree and gates |
| 7 | the iteration index `i`, as a `u32` value (repeated blocks; R2-N5) | the spec |

A stateful step names a **state predecessor**. That is either a kind 1 or
kind 4 producer whose next state is its prior state, or an **initial value**
of kind 2 or kind 3.

### 3.2 Enumerated blocks

An enumerated block is an explicit list of at most 16,384 steps, the frozen
profile ceiling. A traced graph lowers to one enumerated block, taken from
its canonical DCGG and DCPL.

### 3.3 Repeated blocks

A repeated block has:
- a **body** of at most 16,384 step templates;
- a **bound** `K`, from 1 to 2^32 − 1;
- a **gate**: body entry `g`, output port `q`.

The gate port must be a scalar `i32` (scalar code 5), rank 0 and
`byte_length = 4` (R2-S1).

**Iterations.**
- Iteration 0 always runs.
- Iteration `i ≥ 1` runs only if iteration `i − 1` runs and its gate value
  (the little-endian `i32` of entry `g`, port `q`) is nonzero.
- Gating is therefore monotone: once an iteration is off, every later one is
  off.
- In a running iteration every step runs. In an off iteration every step's
  leaf is `EMPTY_LEAF`.

The unrolled DAG has fixed size `K × body_len`. Gating only masks it, so D9
("no graph loops") holds.

**Relative producers.**
- **Kind 4** `(e', port, lag l)` reads entry `e'`'s port in iteration
  `i − l`, where `l ≥ 1`, or `l = 0` when `e' < e`.
- When `i < l`, the input takes its **initial** producer instead (5.1). That
  is kind 2, 3 or 7, or kind 1 with an ordinal before the block (R2-S2).

**Admission checks** (R2-S3). All are linear in the body, so none needs
enumeration:
- Every relative producer points backwards in `(iteration, body index)`.
- Every kind 1 producer named inside a body has `ordinal < block base`.
- **No absolute reference into a repeated block from outside it** (R2-B4).
  A kind 1 producer or predecessor naming an ordinal inside repeated block
  `B` is refused unless the consumer is in `B`'s own body. Reads of a
  repeated block from later blocks use kind 6.
- Every kind 5 chunk index `i × stride + offset`, at `i = K − 1`, computed
  in `u64`, stays inside the chunked value. It must also avoid the short
  last chunk unless the consumer header is the short length (R2-S4).
- **Headers agree.** For every producer, the consumer's expected 23-byte
  header agrees with the producer's header in bytes 7..23.
- **No forks.** Each `(e', state output)` is named as a state predecessor by
  at most one body entry, with one lag.
- **Capacity.** The bound is on leaf *positions*, not steps (R3-S6):
  - the step tree's height `H` is at most 40;
  - the sum of the blocks' aligned address ranges, alignment included, is at
    most 2^40, computed in `u64`;
  - there are at most 64 blocks, and no empty block (`step_count ≥ 1`);
  - each `BlockSpec`'s stored `address_base` and `address_height` must equal
    the derived ones, and the `base_ordinal`s must be contiguous.
- **Chunk headers** (R3-B3). A kind 5 consumer is compared against a
  *derived chunk header*, not against the whole value's header:
  - layout 5 ("raw bytes", version 1, registered);
  - the value's scheme;
  - `byte_length = chunk_bytes`.

  The chunk index range must avoid the short last chunk.

### 3.4 Kind 6: last running iteration

Kind 6 `(block B, entry e', port b)` names entry `e'`'s port in the last
iteration `t` of `B` that runs. The consumer must come after `B`. Its honest
value is always defined, because iteration 0 always runs. Section 7.3 gives
its claim rule.

## 4. Values, state and availability

### 4.1 Plain values

The digest is the frozen `SHA256("dcg.value.v2\0" || bytes)`.

### 4.2 Chunked values (R2-S4, R2-S5)

**Registration.**
- A new registered layout, `layout_id = 3` (chunked), is a profile change.
- `layout_version = v` fixes `chunk_bytes = 2^v`, for `6 ≤ v ≤ 16`.
- The port header's `byte_length` is the whole value's length.
- The last chunk is short when `byte_length` is not a multiple of
  `chunk_bytes`.

**Digest.** The value digest is the root of a v2.1 tree (section 6) over
`ceil(byte_length / chunk_bytes)` chunk leaves, each
`SHA256("dcg.chunk.leaf.v2.1\0" || index:u64 || chunk bytes)`. The empty
leaf is `EMPTY_CHUNK`.

**Kind 5 inputs.** A kind 5 input is one chunk read as a plain value. Its
input digest is the plain value digest of the chunk bytes. Its header is the derived chunk header of 3.3: layout 5, the value's
scheme, and `byte_length = chunk_bytes`.

**Chunk openings.** A kernel reading a chunked input receives chunk
openings, each a chunk plus its path. The STEP witness carries exactly the
chunks the honest kernel reads, including data-dependent reads (C knows H).
Replay refuses on a missing chunk.

### 4.3 State (R2-S6)

| Scheme | Declared in `StepSpec` | Digest | Replay is given |
|---|---|---|---|
| SMALL | `state_bytes ≤ 4,096` | plain value digest of the bytes | the bytes |
| LOG | `entry_bytes`, `capacity` (entries) | `SHA256("dcg.log.v2.1\0" || length:u64 || root)`, where `root` is the v2.1 tree over `capacity` entry leaves `SHA256("dcg.log.entry.v2.1\0" || index:u64 || entry)` with empty slots `EMPTY_LOG` | the entries it reads with their paths, and for each appended slot its (empty) path |
| CHUNKED | `chunk_bytes`, `state_bytes` (fixed image length) | the chunked-value digest of the image | the chunks it reads or writes, with their paths |

- **Fixed capacity.** LOG and CHUNKED trees have fixed capacity. An append
  or a write recomputes the root along each touched path, so no peaks and no
  MMR are needed (R2-N6).
- **Empty initial state.** Each scheme's empty state is defined:
  - SMALL: `state_bytes` zero bytes;
  - LOG: length 0, all slots `EMPTY_LOG`;
  - CHUNKED: an all-zero image.

  `EMPTY_STATE(spec)` is its digest. An initial value of kind 2 or 3 must
  have the scheme's layout and size, which admission checks.
- **Chains.** Every stateful step has nonzero prior and next digests. The
  first step of a chain takes its prior from the initial producer, or from
  `EMPTY_STATE`. A decomposition's sub-steps form one chain in the same way.
  The last sub-step's next state may be exported (below) or simply end.
- **State export** (non-chain reads). A stateful step may declare one output
  port as its *state export*. It has the state's layout:
  - layout 3 for CHUNKED;
  - layout 4 (registered, "log") for LOG;
  - the SMALL layout for SMALL.

  Its digest must equal `next_state_digest`, and SHAPE checks this. Other
  steps then read the state as an ordinary chunked input with chunk
  openings. This is how Basanos family consumers read family logs.

### 4.3a Chunked kernels (added 2026-10-02)

A kernel too large to replay in one transaction is written as a **chunked
kernel**. It has no new protocol objects: it is a repeated block (3.3) whose
body is one stateful step, with this shape:

- **iteration `i` reads chunk `i`** of a chunked input (kind 5, stride 1);
- it may also read `i` itself (kind 7) and plain inputs (kind 1 before the block, kind 2);
- **its running partial is SMALL state**, chained by a kind 4 state predecessor with lag 1, starting from `EMPTY_STATE`;
- it **exports the state on port 0** and **drives the gate on port 1**, which allows an early stop;
- later steps and graph outputs read the result through kind 6.

A dispute then replays one chunk-step: one chunk, one prior state.

**Reductions this covers.** Every wide operation in a transformer layer is
a reduction followed by cheap per-element work. Each reduction keeps a fixed-width
integer partial:
- sums, such as a dot product or a matrix-vector row (a running `i64`);
- max, and argmax with the lowest index on ties;
- softmax, as a running max with a rescaled running sum;
- the sum of squares for a norm.

The integer rescale rule for softmax belongs to the application's kernel.
DCG ships only generic integer reductions (`sumchunk_i32`, `argmax_i32c`,
`scan_i32c`), as test and example kernels.

**Sizing target (measured on the Basanos K=10,240 fixture, 2026-10-02).** The widest compiler-v1 operations read up to 36 producer inputs and about 67 KB per operation:
- form 22, class 237 reads 35 chunks of 256 to 1,024 bytes plus one of 32 KB;
- form 22, class 238 reads one 64 KB input.

About 1,591 form-22 classes exist; 831 of them read more than one input.

Attention reads up to `K = 10,240` positions per head. A chunk-step must fit
one transaction: its chunk (at most `2^16` bytes), its prior state (at most
4,096 bytes), hashing both, and replaying the kernel over them, all within
`max_cu`.

The single-route app adapter of revision 8 (one input, an opening of at most
900 bytes) cannot carry these operations. Probe: Basanos
`out/runs/attested-admission-2026-10-02/route-rule-probe.md`.

**Correction (2026-10-02, later the same day).** That does not make them
chunked kernels. Compiler v1 already sizes every operation instance to
replay in one transaction. Revision 8's native dispute path measured 28 of
its 29 forms through the full response path in one transaction each, the
largest being form 40 at 1,195,036 CU (Basanos evidence M1364). Form 4,
over 40 weight rows, executes in 1,093,802 CU (M1311).

Their wide inputs are carried by staged witnesses, not by splitting the
compute: form 4 took 439 transactions per dispute, mostly weight rows. Form
22 is SHA-256 over up to 64 KB of reads (about 32k CU of hashing); its cost
is the witness size alone.

Under v2.1, a compiler-v1 instance is therefore an ordinary step. It needs:
- an application kernel for STEP replay;
- witnesses staged beyond 10 KiB;
- committed constants with chunk openings, for weight rows (step 5).

Chunked kernels are for operations whose *compute* exceeds one transaction:
a larger model shape, a future compiler, or other applications.

**Status.** There is a Python reference: `plans.py`, `reductions.py`, and `test_disputes_v21_chunked.py` (*measured*):
- every consistent output, state, gate, input and prior fault in 72 chunked plans is convicted;
- every structural lie is convicted: early stop, extra iteration, empty iteration 0, malformed leaf, out entry, chunk edge;
- every claim against honest runs rules for E, including kind 6 claims naming every other iteration;
- 12 planted referee bugs are each caught.

Not yet built:
- the native crate and the program handlers;
- chunked inputs read whole with chunk openings (only kind 5 is in this slice);
- constants, LOG and CHUNKED state, and `OutBlockSpec`.

### 4.4 Availability (R2-B6, R2-S10)

P-sound requires C to compute H inside the challenge window. Admission and
init enforce these preconditions:

1. **External inputs.**
   - The run does not count as `INPUTS_COMPLETE` until every external input
     has been posted on chain and verified against its digest:
     - a plain input is posted in full;
     - a chunked input is posted chunk by chunk, with a cursor that
       recomputes the root.
   - The commit deadline starts at `INPUTS_COMPLETE`, not at `init_run`.
2. **Constants.** Each constant is one of two kinds:
   - **resident**: stored in sealed blobs, checked against its digest at
     admission;
   - **committed**: only its digest is in `constants_root`, and the
     template names a content-addressed availability source. The source is a
     `source_kind:u8` plus a 32-byte locator.

   For a committed constant, P-sound rests on that source. Section 1 states
   that, and Basanos 27B weights are of this kind.
3. **Time.** The template declares `honest_compute_slots`, an upper bound on
   the time to compute H. Admission requires `challenge_window ≥
   honest_compute_slots + phase_window`.

The executor's own commitment needs no publication. The game reveals it on
demand.

## 5. Dispute spec (`DCDS`)

### 5.1 Records

All integers are little-endian, and all reserved bytes are zero. Each record
below gives its byte length.

**Port header (23 bytes).**
`node_id:u32 direction:u8 port_id:u16 layout_id:u32 layout_version:u16
scheme_id:u32 scheme_version:u16 byte_length:u32`.
- `scheme` is the producer's region scheme. For external inputs it is the
  root region's. For constants it is declared with the constant.

**Producer (24 bytes).**
`kind:u8 reserved:u8[3] a:u64 b:u32 c:u32 d:u32`:

| Kind | a | b | c | d |
|---|---|---|---|---|
| 1 | ordinal | port | 0 | 0 |
| 2 | external id | 0 | 0 | 0 |
| 3 | constant id | 0 | 0 | 0 |
| 4 | body entry | port | lag | 0 |
| 5 | input or constant id | 2 or 3 | stride | offset |
| 6 | block index | port | body entry | 0 |
| 7 | 0 | 0 | 0 | 0 |

**`StepSpec` (at most 1,024 bytes).**

| Bytes | Field |
|---|---|
| `0..4` | magic `DSS1` |
| `4..8` | region_id:u32 |
| `8..12` | dcpl_segment_id:u32 |
| `12..16` | node_id:u32 |
| `16..20` | kernel_step:u32 |
| `20..36` | kernel_id:[16] |
| `36..38` | semantic_version:u16 |
| `38..40` | abi_version:u16 |
| `40..44` | decomposition_id:u32 |
| `44..46` | decomposition_version:u16 |
| `46..48` | reserved |
| `48..56` | max_cu:u64 |
| `56..88` | parameter_digest:[32] = `SHA256("dcg.params.v2.1\0" || layout_id:u32 || layout_version:u16 || length:u32 || bytes)`, or all zero for an empty block |
| `88..120` | port_shapes_digest:[32] (below) |
| `120` | state_scheme:u8: 0 none, 1 SMALL, 2 LOG, 3 CHUNKED |
| `121` | state_export_port:u8 (`0xFF` for none) |
| `122..124` | reserved |
| `124..128` | state_unit:u32 (`entry_bytes` or `chunk_bytes`; 0 for SMALL) |
| `128..136` | state_size:u64 (`state_bytes`, or `capacity` for LOG) |
| `136..160` | state_predecessor: producer |
| `160..184` | state_initial: producer (kind 2, 3, or 0 for `EMPTY_STATE`) |
| `184` | input_count:u8 |
| `185` | output_count:u8 |
| `186..192` | reserved |
| `192..` | inputs: `input_count` × 72 bytes = port header 23 + producer 24 + initial producer 24 + reserved 1 |
| then | outputs: `output_count` × 24 bytes = port header 23 + reserved 1 |

The largest record (8 in, 8 out) is 192 + 576 + 192 = 960 bytes.

`port_shapes_digest` is `SHA256("dcg.ports.v2.1\0" || records)`. `records`
are the node's DCGG port records, each without its `u32` length prefix,
ordered by `(direction, port_id)`. The source graph is:
- for enumerated blocks, the template's DCGG;
- for repeated blocks, the block's body DCGG (R2-S11.4).

**Body entry.** A body entry is a `StepSpec` with magic `DSB1`, in which
producers may be of kinds 4, 5, 6 and 7. Its `ordinal` is implicit.

**`BlockSpec` (104 bytes).**
`magic "DBK1" kind:u8 (1 enumerated, 2 repeated) reserved:u8[3]
base_ordinal:u64 step_count:u64 K:u32 body_len:u32 gate_entry:u32
gate_port:u16 reserved:u16 first_record:u64 record_count:u64
address_base:u64 address_height:u8 reserved:u8[7] body_graph_id:[32]`.
- For an enumerated block, `step_count = record_count` and
  `K = body_len = 0`.
- For a repeated block, `step_count = K × body_len` and
  `record_count = body_len`.
- `first_record` is the spec-tree leaf index of the block's first `StepSpec`
  or body entry (R2-S11.3).
- `address_base` and `address_height` place the block in the address map
  (6.2).

**`InSpec` (40 bytes).**
`magic "DIN1" external_id:u32 header:[23] reserved:u8 chunk_log2:u8
reserved:u8[7]`. For a chunked input, `chunk_log2` must equal the header's
`layout_version`; otherwise it is 0 (R3-S9).

**`ConstSpec` (104 bytes).**
`magic "DCN1" constant_id:u32 header:[23] residency:u8 (1 resident,
2 committed) source_kind:u8 reserved:u8[7] digest:[32] locator:[32]`.

**`OutSpec` (56 bytes).**
`magic "DOU1" reserved:u32 header:[23] reserved:u8 producer:[24]`.
- The producer is kind 1 or kind 6.
- `j` is the rank in DCGG `external_id` order.

**`OutBlockSpec` (56 bytes)** (R2-S11.8, S11.9). This is for outputs
produced in every iteration of a repeated block.
`magic "DOB1" block:u32 entry:u32 port:u16 reserved:u16 header:[23]
reserved:u8 first_out_index:u64 reserved:u8[8]`.
- It generates `K` out entries `first_out_index + i`, each with kind 1
  producer `base + i × body_len + entry`.
- When iteration `i` is off, its out entry is `EMPTY_OUT`.

**Out index space** (R3-S7):
- The `OutSpec` records take indices `0..out_count`, by `external_id` rank.
- The `OutBlockSpec` records follow in block order, each taking `K`
  consecutive indices from its `first_out_index`.
- Admission checks that the ranges are disjoint and tile
  `[0, total_outputs)`.

**`RegionSpec` (32 bytes).**
`magic "DRG1" region_id:u32 parent:u32 mode_id:u32 mode_version:u16
scheme_id:u32 scheme_version:u16 layout_id:u32 layout_version:u16
reserved:u16`.

**Spec header (48 bytes).**
`magic "DCS1" version:u16 reserved:u16 block_count:u32 const_count:u32
in_count:u32 out_count:u32 out_block_count:u32 region_count:u32
total_steps:u64 total_outputs:u64`.
- `total_outputs` counts generated outputs too.
- The counts are of stored records only.

### 5.2 Spec tree and generation

The spec tree's leaves, in order:
1. the header;
2. `BlockSpec` × `block_count`;
3. `ConstSpec`, `InSpec`, `OutSpec`, `OutBlockSpec` and `RegionSpec`, each
   by id or index;
4. then per block, in order, its `StepSpec` records (enumerated) or body
   entries (repeated).

Body tables live only here (R2-S11.2). Each leaf is
`SHA256("dcg.spec.leaf.v2.1\0" || type:u8 || record)`, with these type codes:

| Code | Record |
|---|---|
| 1 | header |
| 2 | `BlockSpec` |
| 3 | `ConstSpec` |
| 4 | `InSpec` |
| 5 | `OutSpec` |
| 6 | `OutBlockSpec` |
| 7 | `RegionSpec` |
| 8 | `StepSpec` |
| 9 | body entry |

The tree has the shape of section 6. Its root is `spec_root`.

**Generating `StepSpec(k)`.** For ordinal `k` in repeated block `B`:
1. Write `k = base + i × body_len + e`.
2. Open body entry `e` at leaf `first_record + e`.
3. Resolve each producer:
   - kind 4 with lag `l` becomes kind 1 at `base + (i − l) × body_len + e'`
     if `i ≥ l`. Otherwise it becomes the entry's initial producer;
   - kind 5 becomes the chunk at `i × stride + offset`;
   - kind 7 becomes the value `i`;
   - kind 6 is unchanged; 7.3 handles it.
4. Resolve state predecessors in the same way.

### 5.3 Derivation and admission

The derivation is a pure function of:
- the canonical DCGG and DCPL (enumerated blocks);
- the canonical body plans and their DCGGs (repeated blocks);
- the constant and input declarations.

It refuses:
- a non-topological order;
- an output port produced by more than one step;
- more than 8 inputs or outputs on a step;
- any failure of the 3.3 checks;
- a state chain that forks;
- `kernel_step > 1` without a declared decomposition chain;
- a `max_cu` above the program's replay budget (O2).

An admission cursor computes `spec_root` over several transactions. It keeps
a scratch producer index and a streaming tree frontier. Enumerated blocks
cost at most 16,384 steps each (*estimated*: under 30 transactions). Repeated
blocks cost their body.

R1-S7's alternative was to derive the spec at dispute time from indexed DCGG
and DCPL. It is rejected: repeated blocks need a committed body table anyway,
and the frozen DCPL cannot express repetition.

## 6. Tree shape and addressing (replaces duplicate-last for v2.1)

### 6.1 Trees

Every v2.1 tree has the same shape: the step tree, out tree, chunk trees,
LOG and CHUNKED trees, and the spec tree.

- A tree of **capacity** `2^H` has leaf positions `0..2^H`.
- A node at level `l` (leaves are level 0) is
  `SHA256(domain || l:u16 || left || right)`.
- An empty subtree at level `l` has the constant `EMPTY_t[l]`:
  - `EMPTY_t[0]` is the tree type's empty leaf;
  - `EMPTY_t[l+1] = node(l, EMPTY_t[l], EMPTY_t[l])`.
- A tree of capacity 1 has its root equal to its single leaf.
- A tree over `n` leaves uses `H = ceil(log2 max(n, 1))`, with positions
  `≥ n` empty.

The domains and empty leaves, all `SHA256` of the ASCII string with a
trailing zero byte (R2-S1, R2-S11.5):

| Tree | Node domain | Empty leaf |
|---|---|---|
| step | `dcg.trace.node.v2.1` | `EMPTY_LEAF = SHA256("dcg.leaf.empty.v2.1\0")` |
| out | `dcg.out.node.v2.1` | `EMPTY_OUT = SHA256("dcg.out.empty.v2.1\0")` |
| chunk | `dcg.chunk.node.v2.1` | `EMPTY_CHUNK = SHA256("dcg.chunk.empty.v2.1\0")` |
| log | `dcg.log.node.v2.1` | `EMPTY_LOG = SHA256("dcg.log.empty.v2.1\0")` |
| spec | `dcg.spec.node.v2.1` | `EMPTY_SPEC = SHA256("dcg.spec.empty.v2.1\0")` |

An out-tree leaf is `SHA256("dcg.out.leaf.v2.1\0" || index:u64 ||
ValueRefV1[55])`.

### 6.2 The step tree's address map (R2-B2)

Each block occupies an aligned range of leaf positions:

- **Enumerated block.** It occupies `2^a` positions, `a =
  ceil(log2 step_count)`. Ordinal `base + r` sits at position
  `address_base + r`.
- **Repeated block.** It occupies `2^(hk + hb)` positions, `hb =
  ceil(log2 body_len)` and `hk = ceil(log2 K)`. Ordinal `base + i ×
  body_len + e` sits at position `address_base + (i << hb) + e`.
- **Placement.** Blocks are placed in block order. Each block's
  `address_base` is the smallest multiple of its own size at or after the
  previous block's end. Its size is `2^address_height`.
- **The whole tree.** It has capacity `2^H`, the smallest power of two
  covering the last block's end. Levels count from the global leaf layer.
- **Step positions.** A leaf position is a *step position* if it is the
  address of some ordinal `< total_steps`. Every other position is
  *padding*, which is always `EMPTY_LEAF`.

The map is a pure function of the `BlockSpec` records. Two blocks never
share an internal node below their alignment level. An iteration of a
repeated block is an aligned subtree of height `hb`.

**Landing.** The executor may land iteration roots as it goes, using
`LAND_SUBTREE`. Landed roots are **informational only** (R2-S7):
- they are write-once per `(block, iteration)`;
- they are never used by the descent;
- they are never inserted into the reveal cache.

`COMMIT` posts only the root.

### 6.3 Run root (R2-B3)

```
RunRootV21 =                                   ; 176 bytes
  plan_id[32] run_id[32] spec_root[32]
  total_steps:u64
  step_tree_root[32]
  total_outputs:u64
  out_tree_root[32]
run_root = SHA256("dcg.run.root.v2.1\0" || RunRootV21)
```

`effective_iterations` is removed. The stop position, if wanted, is a graph
output, written by the stop kernel as an output of the body and read by
kind 6. OUT and `OUT_DESCEND` then cover it.

### 6.4 `COMMIT` checks

`COMMIT` requires all of:
- `now <= commit_deadline`, where the deadline starts at `INPUTS_COMPLETE`
  (R2-N2);
- the ids equal the run's and the template's;
- `total_steps` and `total_outputs` equal the spec's.

The descent uses the spec's address map, never posted counts.

**Posting outputs** (R2-S9). `POST_OUTPUT(j, path, value)` is allowed only
once the run is `FINAL`. It checks:
- the path against `out_tree_root`;
- the entry's header against the generated or stored `OutSpec(j)`;
- the value against its digest.

When the run closes, it leaves a **run receipt** PDA,
`["dcg2rcpt", run_id]`. The receipt holds the run root, the final status,
`out_tree_root`, and the template. Outputs can still be posted against it
after the run closes.

## 7. Why first divergence works

### 7.1 Descent (R2-B2)

The dispute holds a current node, starting at the root, and the node's level
`l`.

1. **Reveal.** E reveals the hashes of the current node's descendants `d'`
   levels down, `d' = min(d, l)`, `d ≤ 5`, listed in position order. It
   lists only **pickable** positions. A position is pickable if and only if
   its subtree contains at least one step position (6.2). That depends only
   on the address map, never on a hash. The program:
   - fills every non-pickable position with `EMPTY_LEAF[level]`;
   - folds level by level;
   - checks the result against the current node.
2. **Pick.** C picks one pickable position. A non-pickable pick is refused.
3. **Leaf.** At level 0, E reveals the leaf. The reveal is either
   `present:u8 = 1` followed by the leaf preimage, or `present = 0` for
   `EMPTY_LEAF`. The program checks the reveal against the leaf hash and
   stores it.

**Invariant.** C always picks the leftmost pickable position whose hash
differs from H's.
- Every step position left of the current node then holds H's leaf.
- A skipped pickable node equals H's, so every leaf under it is H's, by
  collision resistance.
- A non-pickable node holds only padding. Padding is a constant in every
  commitment, because the program fills it.

Gated-off iterations are step positions, so they are always pickable. An
early stop (E commits `EMPTY_LEAF` where H runs) is therefore always
reachable. R2's model of the actual empty-constant, two-level shape showed
the structural rule landing on the first divergence in 1,500 of 1,500
trials. A hash-based rule missed it in 472 (*measured*, offline model only).

**Existence.** The root differs from H's exactly when some step position
differs. In that case, a differing pickable child exists at every level.

### 7.2 Base case

Every step position before `k` holds H's leaf. Leaf `k` differs.

| What differs in leaf `k` | Claim | Why it wins |
|---|---|---|
| does not parse; ids, coordinate, a header's bytes 0..23, counts, state digests zero or nonzero against the scheme, a state export that does not match; empty in iteration 0 or in an enumerated block | SHAPE | compared with `StepSpec(k)` and the run |
| present or empty against the gate | GATE | `BlockSpec`; gate leaf `(B, i−1, g)` with its 4-byte gate value | leaf `k` is present and the gate leaf is empty or its value is zero; or leaf `k` is empty and the gate leaf is present with a nonzero value |
| an input's bytes 7..55 | EDGE(i) | the producer is earlier (honest), or is the run or the template |
| prior state digest | STATE | the predecessor is earlier (honest), or is the initial value |
| outputs or next state | STEP | inputs, prior state and parameters equal H's, so C can witness them |

The rows are exhaustive: a present leaf is fully determined by its spec,
its run, its producers, its predecessor and its kernel.

**Outputs.** If the step tree equals H's but the out tree differs,
`OUT_DESCEND` descends the out tree the same way. Its pickable positions are
exactly those `< total_outputs`, and the program fills every other position
with `EMPTY_OUT[level]` (R3-F2). It lands on the first differing entry `j`. Its producer leaf is
in the honest step tree.

### 7.3 Claims

| Claim | Opened | Rules for C when |
|---|---|---|
| SHAPE | `StepSpec(k)`, generated or stored | parse failure; any byte other than digests differs from the expected leaf; state digest presence wrong for the scheme; a state export digest differs from `next_state_digest`; empty where the step is not gated |
| EDGE(i), kind 1 or 4 | `StepSpec(k)`; producer leaf `p` with its path (E opens it, or C opens it from the cached descent) | input bytes 7..55 differ from `p`'s output bytes 7..55 at the named port; `p` lacks the port; `p` is empty (R2-B1) |
| EDGE(i), kind 2 | `StepSpec(k)` | input bytes 7..55 differ from the run's external ref bytes 4..52 |
| EDGE(i), kind 3 | `StepSpec(k)`, `ConstSpec` | input bytes 7..23 differ from the `ConstSpec` header bytes 7..23, or the digest differs from the constant's |
| EDGE(i), kind 5 | `StepSpec(k)`; the chunk at its index, with its path against the input's or constant's chunk root | the input digest differs from the chunk's plain value digest, or the header differs |
| EDGE(i), kind 7 | `StepSpec(k)` | the input digest differs from the value digest of `i` as a `u32` |
| EDGE(i), kind 6 (`B, e', b`) | C names `t:u32`. Opened: leaf `(B, t, e')` and, unless `t = K − 1`, the gate leaf `(B, t, g)` with its 4-byte gate value | C wins if and only if `t < K`, leaf `(B, t, e')` is present, the gate at `t` is zero or `t = K − 1`, and the input bytes 7..55 differ from port `b`'s bytes 7..55. Otherwise E wins (R3-S1). |
| GATE | `BlockSpec`; gate leaf `(B, i−1, g)` | leaf `k` is present and the gate leaf is empty or its value is zero; or leaf `k` is empty and the gate leaf is present with a nonzero value (R2-S1) |
| STATE | `StepSpec(k)`; the predecessor leaf, or the initial value's ref | `prior_state_digest` differs from the predecessor's `next_state_digest`, the initial digest, or `EMPTY_STATE`; or the predecessor is empty |
| STEP | `StepSpec(k)`; C's witness (inputs or chunk openings, parameter bytes, port records, state material) | the witness verifies against leaf `k`'s digests, `parameter_digest` and `port_shapes_digest`, and the replay's outputs or next state differ |
| OUT(j) | `OutSpec(j)` or `OutBlockSpec`; the producer leaf (for a kind 6 producer, as in EDGE kind 6, with C naming `t`) | the entry is not `EMPTY_OUT` and the producer is empty or lacks the port; or the entry is `EMPTY_OUT` and the producer is present; or entry bytes 0..23 differ from the spec header; or entry bytes 23..55 differ from the producer port's digest (R3-S8, R3-B2) |

**Gate values** (R3-S2). A leaf holds the gate port's digest, not its value.
Whoever supplies a gate opening also supplies the 4 bytes. The program checks
`SHA256("dcg.value.v2\0" || bytes)` against the leaf's digest before reading
the little-endian `i32`.

**Why kind 6 is sound.** The honest `t` exists. Leaf `(B, t, e')` is before
`k`, so it is honest. Its gate leaf is honest. Every leaf of `B` is before `k`, so it is honest. "Present at `t`, and
gate zero at `t`" therefore fixes the honest `t`, and no third opening is
needed. So C can always establish the honest last
iteration with honest leaves, and E cannot establish a different one.

**Malformed-data rule (R1-B3).** Bytes that hash to E's own commitment are
stored as they are. If they are malformed, missing a port or empty where
present is required, the claim rules for C. A party's own fresh submission
that fails verification is refused, and that party may retry until its
deadline.

**Completeness.** If E's commitment is H's:
- every reveal and opening verifies;
- every compared field is equal, including bytes 7..55 of every edge (R2-B1);
- gates agree;
- kind 6 establishes only H's `t`;
- every replay reproduces the committed digests.

Every claim therefore rules for E. Admission's header-agreement and
no-outside-reference checks (3.3) rule out spec-level contradictions
(R2-B4, R2-S3).

## 8. The game

### 8.1 Phases

```
OPEN(kind = STEP_DESCEND | OUT_DESCEND); C posts its bond and pre-funds both staging buffers
  AWAIT_NODES → AWAIT_PICK   (repeat to level 0; cached nodes skip AWAIT_NODES)
  AWAIT_LEAF                  E reveals the leaf (present flag + preimage) or out entry
  AWAIT_CLAIM                 C names SHAPE | EDGE(i[, t]) | GATE | STATE | STEP | OUT
  AWAIT_OPENING               E opens what the claim needs (skipped if public or cached)
  AWAIT_WITNESS               C submits its pre-staged witness (STEP only)
  RULED
```

- Actions check `now <= deadline`, and timeouts check `now > deadline`.
- A silent party loses.
- Spec records are public, so either party may supply them.

### 8.2 Staging (R2-B5)

- Each party has its own staging buffer for each dispute.
- **The challenger funds both buffers at open, at different sizes**
  (R3-S4):
  - E's buffer is funded to the rent of E's largest opening, a few KB, so
    E never pays to grow it;
  - C's buffer is sized for the largest witness, up to 1 MiB.

  Both rents are refunded to C at close. So griefing locks C's capital, not
  E's. In section 9, `STAGE_CREATE` for E's buffer happens inside
  `OPEN_DISPUTE`.
- Each party may write to its buffer in 900-byte writes and grow it in
  10,240-byte increments. E's writes and growth stop when the dispute enters
  `AWAIT_CLAIM`; this freezes any leaf data, including revealed list refs,
  that a later claim reads. C can continue writing its own claim through
  submission. Only the submit is timed.
- Admission sets `max_opening` to the largest of:
  - one leaf (up to 1,040 bytes) plus a path;
  - one spec record (up to 1,024 bytes) plus a path;
  - one reveal (up to 1,024 bytes at `d = 5`);
  - the largest witness.

  It refuses anything over 1 MiB.
- Leaves and `d = 5` reveals exceed a legacy packet, so they are staged
  (R2-N1).

**Measured staging throughput (O1, 2026-10-02, testnet).** 1 MiB written
into one account as 900-byte writes:

| From | Unordered | Ordered (128 per window) |
|---|---|---|
| Mac | 170–211 writes/s | 65 writes/s |
| Tokyo box | 722–771 writes/s | 312 writes/s |

### 8.3 Windows and load (R2-B5)

**Phase windows.** A phase's window is `phase_window + ceil(bytes_due /
write_rate) × write_slots`.
- Admission requires `write_rate × (1 / write_slots)` to be at most the
  floor measured from an ordinary host: **100 writes/s** (O1).
- `phase_window` is at least 750 slots, about 30 s.

**Reveal cache.**
- An entry is inserted only from a reveal or opening that verified against
  an already authenticated parent. It is keyed by that parent's position and
  hash.
- A cached answer satisfies every dispute at that node.
- With collision resistance, a node has one fold-valid child set, so one
  dispute cannot poison another (R2-S7).

**Load extension, uncapped** (R3-B1).
- The run keeps `extension_total:u64`. E's effective deadline in any dispute
  is the stored base deadline plus `extension_total`, so an extension writes
  only the run account, not N dispute accounts.
- Each time a dispute starts waiting on E while `waiting_E ≥ c`,
  `extension_total` grows by `extend_slots`. Extensions are counted per
  *wait*, not per open.
- Admission requires `extend_slots ≥ answer_slots`, the measured time for
  E to land its largest answer. A kind 6 opening is the largest: three
  leaves, three paths and a gate value, about 3.2 KB plus `3 × 32 × h` bytes
  (R3-S3). Each additional waiting dispute therefore buys E the time to
  answer it.
- Every open costs a bond and pre-funds E's buffer, so the delay is paid
  for.
- **Contention** (R3-S5). Picks and answers both write the run account.
  `answer_slots` must be measured with an attacker spamming picks before the
  constants are fixed. Otherwise `waiting_E` and `extension_total` move to a
  per-run counter account that only E's answers and the extension write.

## 9. Instructions

| Instruction | Who |
|---|---|
| `POST_INPUT(chunk…)`, `INPUTS_COMPLETE` | the payer, or anyone, before commit |
| `COMMIT(run root)` | the named executor, while `now <= commit_deadline` |
| `LAND_SUBTREE(block, iteration, root)` (informational) | the named executor |
| `POST_OUTPUT(j, path, value)` | anyone, after `FINAL`, also against the receipt |
| `OPEN_DISPUTE(nonce, kind)`, with bond and both staging pre-funds | anyone, while `now <= challenge_deadline` and the run is not `REFUTED` |
| `STAGE_CREATE`, `STAGE_WRITE` | each party, on its own buffer |
| `REVEAL_NODES`, `PICK`, `REVEAL_LEAF`, `CLAIM`, `SUBMIT_OPENING`, `SUBMIT_WITNESS` | E, C, E, C, E, C |
| `TIMEOUT`, `ADVANCE_RULED_PREFIX`, `SETTLE`, `FINALIZE_RUN` | anyone |
| `CANCEL_RUN` | anyone, while `now > commit_deadline` with no commit; rent goes to the run payer |
| `CLOSE_DISPUTE` (only after `ruled_prefix > sequence`, R2-S8), `CLOSE_STAGING`, `CLOSE_RUN` (leaves the receipt), `CLOSE_CACHE` | anyone; rent goes to the recorded payers |
| `RETIRE_TEMPLATE` | the recorded template payer; blocks future `INIT_RUN` calls |
| `CLOSE_TEMPLATE` | the recorded template payer, when the active-run count is zero |

**Rent reclaim (tag 227 subs 18–22).** Dispute, run and cache reclaim is
measured by the v2.1 skeleton suite, natively and on SBF; nine planted guard
bugs are each caught. Template-close coverage and its planted guard bugs are
recorded below with their implementation results.
- **`CLOSE_DISPUTE` (18), anyone.** Allowed for a ruled or moot dispute once
  the ruled prefix has passed it; the run's lowest challenger win must also
  wait until the pot is paid. It closes the dispute's two staging buffers in
  the same instruction (so there is no separate `CLOSE_STAGING`). Each
  buffer's rent goes to the party that created it, recorded in byte 5 of its
  header; growth funders are not recorded and are refunded through the
  creator. The dispute's rent goes to the challenger. The run counts closed
  disputes in a former pad field.
- **`CLOSE_RUN` (19).** A settled run (final, or refuted with the pot paid)
  whose disputes are all closed shrinks to its receipt, and anyone may send
  it. **The receipt stays at the run's own address**
  (`["dcg21run", run_id]`, magic `D21P`, 312 bytes: the run's first 136
  bytes, then its root) instead of a separate `["dcg2rcpt", run_id]`
  account. Keeping the address occupied keeps the run id single-use, so the
  same run cannot be initialized and committed a second time. The freed
  rent goes to the run's payer. An uncommitted run may be cancelled by anyone
  after the commit deadline; the full run balance still goes to its payer.
  **Who profits by calling this first?** The caller receives no rent. It can
  free one template run slot and unblock the payer's template closure.
- **`CLOSE_CACHE` (20), anyone.** Allowed once the run is settled with no
  open dispute, or is a receipt or cancelled. New caches record the
  executor that paid their rent (32 bytes after the revealed nodes, 1,112
  bytes in all); `cache_answer` accepts both sizes. A cache from before this
  change closes only while its run or receipt can name the executor.
- **`RETIRE_TEMPLATE` (22), the recorded template payer.** This one-way
  transition sets the retired bit in the template's previously reserved pad
  and makes `INIT_RUN` refuse. The payer can stop new runs while existing
  runs settle or expire.
- **`CLOSE_TEMPLATE` (21), the recorded template payer.** New templates
  append a 40-byte extension after the fixed block area: `D21O`, the
  creating admitter's key (the account funding template rent), and
  `active_runs:u32`. The retired flag uses a previously reserved byte. The
  template ID remains the hash of the exact template wire bytes, while new
  template addresses derive from `["dcg21tmpl", template_id, payer]`.
  The instruction's account order is unchanged. New creates refuse the old
  ignored trailing four-byte word; previously created accounts at the old PDA
  remain readable. The original size remains usable with read-only template
  metas; those accounts lack reliable provenance and are not closeable. The
  earlier tracked accounts at the old PDA retain their recorded payer and
  close lifecycle.
  `INIT_RUN` increments the count. `CLOSE_RUN` decrements it only when an
  uncommitted run is cancelled or a settled run becomes a receipt. Thus the
  count remains nonzero for every live run, including a run whose disputes
  have ended but whose run account has not yet been closed. Receipts and
  caches do not read the template. No separate dispute count is needed:
  `CLOSE_RUN` already requires every dispute to be terminal, past the ruled
  prefix and closed (and any winning pot paid). New-template `INIT_RUN` and
  `CLOSE_RUN` mark their existing template account slot writable to update
  the count; the account positions are unchanged. Template closure requires
  the recorded payer's signature, a writable template account and a zero
  count, then drains the account to that payer. A zero-count template may be
  retired and closed immediately. Empty, system-owned, pre-funded template
  PDAs are adopted, and all lamports held at close go to the recorded payer,
  including the pre-fund (a pre-funded escrow is a gift, not a lock). A
  front-run creator becomes the recorded payer only on its own template
  address, because creation is keyed by payer as well as content.

  **Who profits by calling this first?** For CREATE, a caller can create and
  fund only the PDA derived from its own key. It becomes that account's payer
  and may later recover its rent, but gains no control of another payer's
  template. The intended admitter can create the same content at its own
  address and initialize runs there. For RETIRE, only the recorded payer can
  stop future runs from its template; a squatter can retire its own separate
  template only. The executor, challenger, and bystanders gain no rent or
  retirement authority on the admitter's account. Concurrent initialization,
  retirement, and closure on one template serialize through its writable
  account. Legacy templates retain their old address derivation and read path.

  **Template-close validation (measured, 2026-10-03).** The original close
  implementation passed 18 tests natively and 18 against the v1.51 SBF image.
  After the independent-review rework, the 21-test v2.1 skeleton suite passed
  natively and against the v1.51 SBF image. It covers cancellation, retired
  templates, final receipts, refuted receipts, claim and timeout rulings,
  moot disputes, legacy read-only template accounts, pre-funded template
  adoption, front-run creation, and exact lamport conservation. The earlier
  native guard-mutation run caught each of these failures:
  removing the active-run check fails
  `an_uncommitted_run_cancels_for_its_payer_after_the_commit_deadline`,
  removing the recorded-payer check fails
  `an_honest_run_closes_every_account_and_returns_all_rent`, and skipping the
  run-close decrement makes that same test fail at template closure. The
  mutations were restored before their final native and SBF runs. Current
  rework artifacts are under Basanos
  `out/runs/dcg-v21-lists-r2-2026-10-03/`; the SBF image SHA-256 is
  `651e937e56abd33467b328d44f7b2a7b5d4986134fabbfd96208c49b9fba9ecd`.

**Independent review fixes (2026-10-03).** From the first independent review
of tag 227 at bc4e391:
- **F1, moot beats timeout.** On a refuted run, any ruling of a dispute
  opened after the lowest challenger win (by claim or timeout) is moot: the
  challenger's bond returns and the executor gains nothing. Before, the
  executor could time out a later dispute whose challenger had stopped
  playing and take its bond.
- **F2, STEP kernels.** A manifest kernel replays a STEP claim only if it
  advertises `MODE_STEP_V21` (`"STEP"` v1, `kernel.rs`). The Python registry
  is keyed by (id, semantic version, ABI version), as the program resolves
  it. Applications must mirror each kernel's limits exactly and check at plan
  time that every step fits them (Basanos form 4 does).
- **F3, LOG state.** The program judges SMALL state only. STATE and STEP
  claims on a LOG-state step are ruled moot (neutral) until LOG is
  implemented on chain. `tests/golden/dcg/disputes_v21/log_neutral_scenarios.json`
  (from `scripts/disputes_v21_log_neutral_scenarios.py`) checks this.
  Superseded for new runs by follow-up A below.
- **F4, flooding.** Templates need nonzero executor and challenger bonds. The
  load extension (§8.3) is built: a phase the executor owes gets the phase
  window times the run's open disputes, capped at the maximum window.
  Superseded for new runs by follow-up B below.
- **F5, run address and cancel.** The run PDA is `["dcg21run", run_id,
  payer]`, so a cancelled run cannot be re-initialized at the same address by
  someone else. `init_run` sets a commit deadline (the init slot plus the
  challenge window); a later commit is refused, and the payer may cancel only
  after it. The run id itself is unchanged.
- **F9, kernel ids.** Built-in and reduction kernels resolve only from the
  exact `name/v1` id, NUL-padded with nothing after the padding, in the
  program and in Python. Invalid UTF-8 is an unknown kernel in Python, not a
  crash.
- **Re-review (2026-10-03, keep 0862470), conditions and follow-ups:**
  - Until the program implements LOG, **template admitters must refuse
    LOG-state templates**. On such a template, a challenger can steer any
    dispute to a LOG step and get a free moot (no dispute cost, delayed
    finality), and a lie at a LOG step cannot be convicted. The program
    cannot enforce this, because it trusts the spec root.
- **Follow-up A (queued):** narrow F3 to keep judging the STATE
    predecessor check for producer kinds 1 and 2, which does not depend on
    the scheme.
  - **Follow-up B (queued):** the load extension counts every open dispute,
    including the executor's own puppets waiting on their challenger, so an
    executor can stretch its own deadlines up to `MAX_WINDOW` per phase (a
    probe: 20 puppets, 15,750-slot deadlines, about 0.36 SOL locked and all
    returned). Implement §8.3's additive extension, counted only while
    disputes wait on the executor. There is no false finality: finalize
    needs zero open disputes.
  - Upgrading an existing program in place strands runs created before
    0862470 (the run address changed). Drain them first, or deploy at
    fresh addresses, as testnet already does.
  - The commit deadline reuses the challenge window; the design's own
    commit deadline (after the inputs are complete) is not built.
  - Consumers identify a run by its address. The run id is not unique
    across payers.
  - Follow-ups A and B change endings and get their own independent review
    (Basanos project rule 10).

**Follow-ups A and B (implementation candidate, 2026-10-03; independent
review pending).** For LOG state, a present, well-formed leaf's STATE claim
judges predecessor kinds 1 and 2 using the authenticated predecessor leaf or
the run's external ref. An initial/other predecessor STATE claim and every
LOG STEP claim remain neutral. Empty or malformed executor leaves still lose.
The bounded skeleton encodes `waiting_E:u32` and `extension_total:u64` after
the run's external refs. It uses `c=1` and `extend_slots=phase_window` (the
only timing parameter its current template admits). OPEN and PICK enter an
executor wait; REVEAL_NODES, CACHE_ANSWER, and REVEAL_LEAF leave it. An entry
when another executor wait exists adds one phase window to the run total.
An executor phase times out only after its stored base deadline plus that
total; a challenger phase times out after its unextended stored deadline.
Ruling or mooting an executor wait decrements `waiting_E`. Arithmetic is
checked; overflow refuses the instruction. The changed run account size
requires fresh testnet runs for this skeleton.

**Who profits by calling first?** OPEN is funded by its challenger; opening
while another dispute waits on E extends E's deadline, but a puppet already
waiting on C buys no extension. PICK can buy that extension only by ending
its challenger's own wait and starting E's next wait. REVEAL_NODES,
CACHE_ANSWER, and REVEAL_LEAF end an E wait, so a caller cannot bank future
extension by answering first. CLAIM can now convict a false LOG predecessor
of kind 1 or 2; the honest challenger receives its bond and, if earliest,
the slasher share, while the payer receives the remainder. TIMEOUT respects
the same effective deadline for E and the unchanged deadline for C. MOOT,
CLOSE_DISPUTE, CLOSE_RUN, and CLOSE_TEMPLATE pay their recorded recipients;
the permissionless caller, including a bystander, receives no rent or bond
merely by calling first. For all these calls, the executor's only timing gain
is the extension earned by genuine outstanding executor waits.
- **Not changed:** F6 (buffers an executor created before bc4e391 refund the
  challenger; testnet only), F7 (receipt offsets differ from a live run;
  status stays at byte 4, and the Python client now checks the magic), F8 (a
  close needs a payee account that can hold the payment), F10 (staging bytes
  share the program id; buffers start with `D21S`, which no other handler
  accepts, but other handlers were not audited), F11 (a cheating executor can
  recover the slasher share through a puppet dispute; the payer's remainder is
  the deterrent).

- These are new tags. Tags 220–226 are not reused, and the v2.0 handlers
  stay under `graph-v2-experimental` until they are removed.
- The trace-committed path (209–218) remains for small graphs. A template's
  `commitment_kind` chooses the path.
- Every record is accepted only at its derived PDA. Blob PDAs are seeded by
  their writer.

## 10. Concurrency, finality and economics

### 10.1 Order

**No cap on disputes.** Each dispute is its own PDA,
`["dcg2dsp", run, challenger, nonce]`, paid for by its challenger. The run
keeps:
- `next_sequence:u64`;
- `open_disputes:u32`;
- `waiting_E:u32`;
- `ruled_prefix:u64`;
- `best_win:u64`.

**Ruled prefix.** `ADVANCE_RULED_PREFIX` moves `ruled_prefix` over ruled
disputes in sequence order. A dispute cannot close before the prefix passes
it (R2-S8).

**Refutation.**
- The first challenger ruling sets the run to `REFUTED`.
- Disputes with a lower sequence than `best_win` continue.
- Disputes with a higher sequence become moot. Their bonds are refunded,
  and a ruling made before mootness still stands for its own bond (R2-N3).
- No new opens are allowed on a refuted run.
- The pot is paid to `best_win` once `ruled_prefix > best_win`.

### 10.2 Bounds and liveness

**Bounded delay.** Every open happens before the challenge deadline. A
dispute has at most `2 × (ceil(h/d) + 3)` phases. Finality is at most
`challenge_window + D(N)`, where:
- `D(N) = (2 × (ceil(h/d) + 3)) × max_phase_slots + W × extend_slots`;
- `W ≤ N × (ceil(h/d) + 3)` is the number of waits on E, with `N` the number
  of opens (R3-B1).

**Windows.** Each window has a minimum and a maximum at admission.

**Finalization.** A run finalizes when `now > challenge_deadline`,
`open_disputes == 0`, and the run is not refuted.

**Executor.** `init_run` names the executor. With the zero key (anyone may
commit), the bond and the rent follow whoever commits.

**Re-run.** A refuted run has no result. The payer may start a new run with
the same inputs and a different executor. The application's hook decides the
requester's disposition (for Basanos, the document's).

### 10.3 Economics (hooks; DCG enforces conservation)

**Bonds.** E bonds at commit. C bonds at open, and also pre-funds both
staging buffers.

**Standard policy.**
- C's own bond:
  - returned to C on a challenger win;
  - taken by E on an executor win;
  - refunded on a moot dispute.
- The executor bond:
  - `best_win` receives `bond_slasher_bps` of it;
  - the remainder goes to the committed destination, the payer or the
    incinerator.

**Admission requires:**
- `bond_slasher_bps < 10,000`;
- a nonzero remainder;
- a remainder destination that is not the executor.

**Deterrence.** The remainder is the deterrent. The payer is the guaranteed
watcher.

**dispute-economics-v2 §1.** It is amended to match (R2-S12). v2.1 runs
replace its `challenge_limit` and outcome table with the ruled prefix.

## 11. Regions, modes and cross-region finality

A v2.1 run finalizes as one unit. Cross-region imports (graph-plan-v2 §3)
are therefore final exactly when their source is. This is a recorded profile
change.

Regions stay in leaf coordinates and the spec, for later per-region modes:
- consensus regions run at commit;
- sampled regions;
- ZK proof leaves.

## 12. Identities, versions and what changes

**Template ID v2.1.**
- It is `SHA256("dcg.template.id.v2.1\0" || …)` over these fields, in this
  order:
  - `graph_id` and `plan_id` (zero if no enumerated block);
  - `body_plans_root`, `app_image_id`, `kernel_manifest_root`, `spec_root`
    and `constants_root`;
  - `commitment_kind:u8`, `reveal_depth:u8`;
  - `challenge_window`, `phase_window` (minimum and maximum),
    `max_phase_slots`, `write_rate`, `write_slots`, `c`, `extend_slots`,
    `commit_deadline_slots` and `honest_compute_slots`;
  - `bond_policy_digest`;
  - `max_opening`.
- Every field is mandatory.

**Run ID v2.1.** It is `SHA256("dcg.run.id.v2.1\0" || template_id ||
nonce || count:u32 || external refs (52 bytes each, sorted) ||
executor[32])`. `init_run` checks the refs against `InSpec`.

A variable-length prompt is a fixed-length input of `K` padded tokens plus a
separate length input (R2-S4).

**Unchanged frozen bytes:**
- DCGG and DCPL;
- `ValueRefV1`;
- the step-leaf preimage;
- the value digest;
- the 52-byte external ref.

**New:**
- `DCDS` records and the spec tree;
- body plans and producer kinds 4–7;
- `RunRootV21`;
- the v2.1 tree and address map;
- chunked layout 3 and log layout 4;
- state schemes and state export;
- template and run identities;
- the run receipt.

**Retired from disputes:** `RegionRootV1`, `ChildRootV1`, and duplicate-last
padding.

**Profile changes (graph-plan-v2 §9):**
- capacity 2^40, with 16,384 per body and per enumerated block;
- staged openings up to 1 MiB (was 4 KiB);
- layouts 3 and 4;
- stateful nodes;
- cross-region finality.

## 13. Basanos revision 8 on v2.1

Revision 8's dispute path has never run on testnet. The 10-01 run measured
the happy path only.

| Revision 8 | v2.1 |
|---|---|
| One K = 10,240 template; variable prompt; stop rule | One repeated block, `K = 10,240`, whose body is one position. Prompt: a `K`-token padded input read by kind 5, plus a length input. The stop kernel is the gate. The stop position, if needed, is an output. |
| Op entries `(position, segment, local)` | Ordinal `base + position × body_len + entry`; address `(position << hb) + entry`. |
| DPR2 position roots with an MMR prefix | `LAND_SUBTREE` (informational) into the fixed address map. The DPR2 MMR is gone. |
| Tags 166–169 (direct open, segment reveal, 16-wide descent) | First-divergence descent, `d = 4`. |
| Tags 120/121 (target leaf, reads by producer proof) | SHAPE and EDGE, with producers from the spec. |
| KV cache and prior-state reads | LOG state carried at lag 1. Attention reads are LOG entry openings. |
| Tags 122/123/127 (weights by proof) | Committed constants with a named availability source, for 27B (R2-B6). Resident constants for small models. The STEP witness carries the rows read. |
| Tags 128/124 (output stream, chunked replay) | STEP over a declared decomposition chain. |
| DRU1 staging | Per-party staging, with the same cap. |
| Family summaries | Body steps over LOG state. Consumers read the state export. |
| Output attestation (177) | `POST_OUTPUT` after finality, against the run or its receipt. |
| First-settled winner; self-challenge | Ruled prefix and `best_win`; the remainder deterrent. |
| Custom settlement retry (187) | dispute-economics-v2's finite fallback. |

**Still needed before Basanos can migrate:**
1. **Attention witness growth.** The body is fixed, so every step must fit
   `max_opening` and `max_cu` at the worst position, `i = K − 1`. An
   attention op reading the whole KV log grows with `i`. R2 estimates about
   40 MB per layer at position 10,240 for a 4B-class model, not checked
   against revision 8's attention forms.

   The fix is a fixed decomposition into sub-steps, sized for the worst
   position: each sub-step reads a bounded window of the log, accumulates
   into SMALL state, and early positions run zero-length windows. That
   multiplies `body_len` and CU. Revision 8's own attention forms must be
   checked for how they bound a single op's read, before choosing the
   decomposition.
2. **Typed decisions.** A decision document (`L = 1 + option_count`, with
   options carried by the document) is a different template: an enumerated
   or short repeated block, whose options are an external input.
3. **Per-form work.** Decompositions and state schemes for each form, and
   CU measurements (O2).
4. **Admission cursor.** It must be measured on the Basanos body.

## 14. Implementation order

**Status, 2026-10-02.** Step 1 is done offline, in `python/dcg/disputes_v21/`:
- the trees, `DCDS` for one enumerated block, `RunRootV21`, the referee and the
  honest challenger;
- `python/tests/test_disputes_v21.py`, with these results (*measured*):
  - 400 random lies across 10 kinds were all refuted;
  - every claim against every leaf of 40 honest random graphs ruled for E;
  - two reintroduced bugs (the R2-B1 EDGE bytes, and SHAPE ignoring state
    digests) were each caught;
- goldens in `tests/golden/dcg/disputes_v21/vectors.json`, from
  `scripts/disputes_v21_goldens.py`.

Not in step 1:
- producer kinds 3 to 7;
- parameters, so STEP does not check `parameter_digest` or
  `port_shapes_digest` (the traced kernels have none);
- state;
- repeated blocks.

1. **Core.** Pin the record bytes first: header, `BlockSpec`, `StepSpec`,
   `OutSpec`, `InSpec`, the trees and empty constants. Then build the Python
   reference, scoped to **one enumerated block**, with these stateless
   pieces:
   - the address map;
   - the step tree and out tree;
   - `DCDS`;
   - `RunRootV21`;
   - descent with structural picks and the honest-challenger strategy;
   - SHAPE, EDGE (kinds 1, 2, 3), STEP and OUT;
   - a random-lie fuzzer;
   - goldens.
2. **Native program:**
   - commit;
   - dispute records;
   - per-party staging pre-funded by C;
   - reveal cache;
   - ruled prefix;
   - uncapped extension;
   - economics;
   - receipts;
   - ProgramTest against the Python oracle.
3. **Repeated blocks:** gates, kinds 4, 5, 6 and 7, generated specs, and the
   multi-block address map.
   *Python reference done 2026-10-02 for the chunked-kernel slice (4.3a),
   together with SMALL state from step 4 and kind 5 chunk inputs from step 5.*
4. **State:** SMALL, LOG and CHUNKED, STATE, and state export.
   *2026-10-02: SMALL done through the program; LOG in the Python reference
   (`logsum_i32l`, a read-all-then-append KV-cache shape; STEP verifies the
   read entries and the empty append slot against the prior root). CHUNKED
   state not started.*
5. **Chunked values:** constants, residency and the availability source.
6. **Testnet:** Hello, fan-out, long chain, a gated block, and concurrent
   disputes.
7. **Basanos:** a body plan for one position, on a K = 35 document.

## 15. Open items

- **O1. Staged writes** (*measured* 2026-10-02, 8.2). The 100 writes/s floor
  is set from the slower host. `answer_cost` for the load-extension check
  still needs measuring, once handlers exist.
- **O2. Replay and witness-hashing compute per kernel.** SHA-256 over 1 MiB
  is roughly 0.5M CU (*estimated*). `max_cu` is a DCKC property backed by
  test vectors (R2-N4). Admission refuses oversize steps.
- **O3. Sampling on top of STEP.** A fixed-slot draw can still be ground by
  the leader of that slot.
- **O4.** `d` up to 5. The default is 4.
- **O5.** Hierarchical, multi-executor commitments, as a later additive
  version.
- **O6. Availability sources for committed constants.** Which
  `source_kind`s to support (for example a content-addressed HTTP mirror, or
  Arweave). An owner decision.

## 16. Test plan

**Goldens** (Python and Rust must agree):
- trees of capacity 1, 2, 4, 8 and 16, with `n = 0, 1, 2, 3, 5, 6, 7` and
  `2^k ± 1`;
- every `EMPTY_t[l]`;
- the address map for one enumerated block, one repeated block (`K` not a
  power of two, `body_len` not a power of two), and mixed blocks;
- every record type;
- generated `StepSpec`;
- `RunRootV21`;
- chunked, LOG and CHUNKED digests;
- the state export.

**Property tests** (ProgramTest, with Python as the oracle):
- **Random lies.** One lie per run, in any field: header bytes, a digest, a
  count, state, the gate, an early stop, a late stop, empty against present,
  an out entry, `EMPTY_OUT` misuse, a kind 6 value, an internal node, or an
  unparseable leaf. The first-divergence challenger wins.
- **Honest runs.** No challenger move wins. Every EDGE against every input
  of an honest leaf rules for E (R2-B1).
- **Rounds.** The round count matches the formula.

**Adversarial:**
- every R1 and R2 blocker;
- deadlines at `==` and `+1`;
- pre-funded PDAs;
- conservation on every path;
- a closed-dispute prefix stall (S8);
- posts before `FINAL` and after `CLOSE_RUN`.

**Testnet:** section 14, step 6.

## 17. Concerns not yet resolved

- The "honest executor never loses" bound (8.3) depends on a measured
  `answer_cost`. Until the handlers exist, `c` is a placeholder.
- Committed, non-resident constants make P-sound conditional on an off-chain
  source (O6). This is inherent at 27B scale. Revision 8 has the same
  dependency.

## 18. Review traceability

| Item | Where |
|---|---|
| v2.0-B1 forged records; S2 squatting | 9 |
| v2.0-B2 to B5, B7, B8 | 6, 7, 8.1, 10.1, 5, 9 |
| v2.0-B6 sampling | O3 |
| v2.0-S1 to S11 | 9, 10.2, 8.2, 6.4, 5.1, 12, 3.3 |
| R1-B1 to R1-B8 | 10.1, 10.1, 7.3, 5.1 and 7.3, 4.3 and 7.3, 5.1, 8.2 and 8.3, 6 and 7.1 |
| R1-M1 to R1-M5 | 3.3 and 5.2, 3.3, 3.1 and 4.4, 6.4, 4.3 and 6.2 |
| R1-S1 to R1-S11; R1-N1 to R1-N10 | as in revision 2, superseded where R2 below applies |
| R2-B1 EDGE bytes | 7.3 |
| R2-B2 structural picks, address map | 6.2, 7.1 |
| R2-B3 `effective_iterations` | 6.3 (removed) |
| R2-B4 outside reads of off iterations | 3.3 (refused), 3.4 and 7.3 (kind 6) |
| R2-B5 load and P-complete | 1, 8.2, 8.3, 10.2 |
| R2-B6 constant residency | 4.4, 13, O6 |
| R2-S1 gate and empty rules, constants | 3.3, 6.1, 7.3 |
| R2-S2 initial producers | 5.1 (`StepSpec` inputs and state_initial) |
| R2-S3 admission checks | 3.3 |
| R2-S4 kind 5 | 4.2, 7.3, 12 |
| R2-S5 chunked layout | 4.2 |
| R2-S6 state boundaries and export | 4.3 |
| R2-S7 landing and cache | 6.2, 8.3 |
| R2-S8 prefix stall | 9, 10.1 |
| R2-S9 output posting | 6.4 |
| R2-S10 availability | 4.4 |
| R2-S11 byte layouts | 5.1, 5.2, 6.1 |
| R2-S12 economics-v2 §1 | 10.3, plus the amendment in that file |
| R2-N1 to R2-N6 | 8.2, 6.4 and 9, 10.1, O2, 3.1 (kind 7), 4.3 |
| R3-F1 record lengths; R3-F2 out padding; R3-F3 `total_outputs` width | 5.1, 7.2, 6.3 |
| R3-B1 extension arithmetic; R3-B2 OUT kind 6; R3-B3 chunk headers | 8.3 and 10.2; 7.3; 3.3 and 4.2 |
| R3-S1 to R3-S9 | 7.3, 7.3, 8.3, 8.2, 8.3, 3.3, 5.1, 7.3, 5.1 |
