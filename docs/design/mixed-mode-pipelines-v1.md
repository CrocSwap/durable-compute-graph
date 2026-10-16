# Mixed modes in one template: pipelines of single-mode stages (2026-10-15)

**Status: designed and accepted, not started (owner 2026-10-15: design
mixed regions now; mode results §8 answered the same day, folded into slice
1; 2026-10-16: every §11 recommendation accepted).** Numbers are *estimated* unless marked *measured*. Builds on
`mode-results-v1.md` (merged to main 2026-10-15) and on the v2.1 design
(`optimistic-descent-v2.1.md`, §11 reserved per-region modes). Follows the
composition rules of Basanos `docs/design/dcg-graph-sweeps-modes-2026-09-30.md`
and `dcg-modes-and-compiler-2026-09-30.md` §4, and seam (b) of
`dcg-consensus-mixed-mode-2026-09-23.md` §2.3 (a consensus reader waits for
finality; results are never conditional).

## 1. What mixing inside one template buys

Today an application can already compose modes: `examples/composed-app` is a
consensus session that imports verified outputs of finished optimistic runs.
That composition is written by the application, and its README lists what it
leaves to trust:
- the session's authority picks which runs enter;
- anyone can make a run of the trusted template, so "a FINAL run of template
  T" is not "the run of this job";
- an optimistic run cannot take a chain value (another result, a session's
  state) as an input except as an external ref its initializer asserts.

A template whose parts run in different modes closes those gaps. The program,
not the application, binds each part to the parts it consumes, for one job
instance. Concretely it buys:
1. **One identity per job.** One template id names every part and how they are
   wired; one pipeline run id names the instance.
2. **Program-checked hand-offs.** A later part's inputs are checked against an
   earlier part's final result by the program, at the moment they enter.
3. **Chain-bound inputs for optimistic work.** An optimistic part can take an
   input that the program verified against a final result (of this job or of
   another), instead of an input its initializer merely asserts.
4. **A smaller dispute surface.** Cheap, consensus-sensitive steps (for
   example tokenization, retrieval ranking, a verdict program) can run on
   chain and are then never disputed.
5. **Earlier finality for the parts that allow it.** A consensus part's
   outputs are final when it finishes, before the optimistic part's window
   closes; an optimistic part's outputs are final at its own window, before
   later parts finish.

What it does not buy: a v2.1 run still finalizes as one unit (v2.1 §11), so
putting consensus steps inside an optimistic part does not make that part
final sooner. Every boundary from an optimistic part to a later part costs
one challenge window of latency (§5).

## 2. The model: a pipeline of stages

A **pipeline template** is an ordered list of **stages**. Each stage:
- runs in exactly one mode (one mode per sweep);
- is a run of an ordinary single-mode template of that mode (a v2.1 template
  for consensus or optimistic stages; later modes bring their own);
- consumes only **final** values: the pipeline's external inputs, its own
  template constants, and outputs of earlier stages that are already final;
- ends in a `ResultRef` (mode results v1), which is the only thing a later
  stage reads.

Stages form a DAG in list order: a stage may import only from stages before
it. Independent stages may run concurrently. A "region" of a graph in the
user-facing sense is a stage: the planner (§7) cuts the developer's graph
into stages where the declared mode changes.

The rules, as in the 09-30 design:
- one mode per stage;
- a stage imports only final values, so nothing is ever rolled back;
- values cross stage boundaries as canonical bytes (`ValueRefV1` plus bytes),
  opened against the source stage's result;
- each output's finality is the latest finality in its ancestry, and its
  security basis is the union of its ancestry's bases, kept typed.

### 2.1 Why stages and not mixed blocks inside one tree

Two designs that keep everything in one run were considered and rejected.

- **Proven blocks inside an optimistic run.** Consensus blocks would be
  executed on chain before `COMMIT`, and `COMMIT` would check a path from each
  proven block root into the committed step tree. Descent would then never
  enter a proven block, because it equals the honest one by construction. But
  a block executed before commit may consume only final values (externals,
  constants, other proven blocks), since an optimistic step's output is a
  claim until the run is final. Such a block is exactly a consensus stage
  placed before the optimistic stage. The only saving is one output opening
  per crossing edge (about 285 CU each, *measured* for one output of a
  one-output run). It is not worth a second commit path and a second set of
  dispute cases.
- **Consensus steps that consume unfinal optimistic values (conditional
  execution).** The result would be correct only if its inputs survive their
  window, so a refutation would have to roll back everything downstream. The
  2026-09-23 note (seam b) rejected this for sessions; the same holds here.

Several verifiers over **one** commitment (for example Freivalds or sampling
checks over an optimistic run's committed trace) are a different thing: they
are a property of a single stage's mode, designed with those modes. The stage
model does not prevent them. §12 evaluates the general form, per-kernel modes
chosen by the executor, which is sound in one tree, and defers it.

## 3. The three pieces

The design is three additive pieces. Each is useful alone and ships alone,
in this order.

### 3.1 Imported inputs for v2.1 runs

An external input of a v2.1 template may be declared **imported**: its value
must be an output of a final result, checked by the program before the run
can commit. This is the "optimistic run reads a result" direction, and it is
what pipelines use to bind stages. Implemented 2026-10-16 behind feature
`pipelines-v1`; this section describes what was built.

**Import table in the template** (not in the spec tree). The program's v2.1
template id is `SHA256(TEMPLATE_DOMAIN || create data)`, so a table appended
to the create data is bound by the id without touching the spec tree or its
header: `"DIM0" count:u8 zero(3)` then `count` (1 to 16) `ImportSpec`
records, external ids strictly increasing. The template account stores it
after the tracking extension (`"D21I" count zero(3)` + 16 record slots; the
account grows by 1,672 bytes). LX1 templates take no imports in slice 1.

**`ImportSpec`** (104 bytes): `magic "DIM1" external_id:u32 source:u8
scheme:u8 zero(6) out_index:u64 requirements_digest[32] host[32] zero(16)`.
- `source` is 2 (any final result the requirements accept); 1, a pipeline
  stage, is reserved for slice 3 and refused.
- `scheme` is `OUT_TREE_V21` (output `out_index` becomes the input) or
  `STATE_TREE_V1` (a tree-sealed session's whole state becomes one chunked
  input; `out_index` 0). Importing one chunk of a state is deferred: a chunk of
  up to 64 KiB does not fit in a transaction, and staging it is later work.
- `host` is the program the source account must belong to. Trusting a host is
  part of the result's security basis (mode results §2), so the template
  fixes it.
- `requirements_digest` is `SHA256("dcg.requirements.v1\0" || DRQ1)`. `DRQ1`
  is the canonical encoding of `ResultRequirements`: `magic "DRQ1" version:u16
  present:u16`, then each present field at its fixed width in a fixed order
  (`result.rs`), so a typical requirement is 50 to 80 bytes. The template
  stores only the digest; `IMPORT` carries the bytes.

**Run account version 2.** A run of a template with imports must use
version-1 init (sub 28, a remainder destination); it becomes version 2:
remainder_to and then a 4-byte pending-import bitmap (bit `i`: import `i` of
the table outstanding) after the executor-wait trailer. Init refuses a run
whose refs lack an imported external id. `COMMIT` refuses while any bit is
set. `docs/spec/run-read-layout-v21.md` gives the form, and `read_run_result`
reads it.

**`IMPORT`** (tag 227 sub 29; anyone may send it, before the commit deadline):
`[caller(s), run(w), template, source, source template (optional)]`,
`external_id:u32 drq_len:u16 DRQ1`, then for an out-tree import the output's
`ValueRefV1` (55) with `path_len:u8` and the path. The program:
1. finds the import, checks `DRQ1` against its digest;
2. reads the source's result: a v2.1 run of `host` (live with its template,
   or a receipt; a `D21Q` needs no template), or a sealed session of `host`;
3. requires its scheme to be the import's and `ResultRef::require` to pass;
4. checks the run's external ref for the input: for an output, that the ref's
   bytes are the value ref's bytes 7..55 and the value ref opens at
   `out_index`; for a state, that the ref is a chunked value (layout 3) with
   the seal's chunk size as layout version, the state's length and the seal as
   its digest (no path and no posting);
5. clears the input's bit. When the last bit clears, the commit deadline
   starts afresh (`now + challenge_window`): the `INPUTS_COMPLETE` rule of
   v2.1 §4.4, for imports.

If an import can never verify (the asserted ref is false, the source is
refuted or trimmed), the payer cancels after the deadline, as for a missed
commit.

Disputes do not change. An imported input is an external input (EDGE kind 2,
or kind 5 chunks of a chunked input), and its ref was checked against a final
result before commit. As for any external input, a challenger needs the value's
bytes: an output's from wherever the source run's outputs are published, a
state's from the session's state accounts while they are open (or a copy taken
at seal).

**Requirements must name the computation** (review 2026-10-16 M2): `IMPORT`
refuses a run import whose requirements name neither a template id nor a run
id, a state import whose requirements name no kernel, and a stated mode that is
not the scheme's (optimistic for outputs, consensus for states). A template
with weaker requirements is created but its runs never import (fail closed);
the Python builder refuses them. Binding one instance (a session's input root
or address, a run id) is the template author's choice.

Transaction size: `DRQ1` plus the value ref and a path of `h` levels must fit
in one transaction, so out trees up to about 2^18 outputs (*estimated*).

Cost: one source read (2,400 to 3,900 CU for a run, about 5,300 for a
session, *measured*) plus one opening (285 CU plus about 150 CU per tree
level, *estimated*) per import, one transaction each.

Tests: `disputes_v21_skeleton.rs` (a run imports a FINAL run's output, from
the live run and from its `D21Q` after its template closed; refusals for
requirements, value, path, source, an input imported twice, a missing ref, a
version-0 init, a non-canonical table); `stateful_v3_result.rs` (a run imports
a tree-sealed session's state; refusals for a linear seal, a trimmed session,
another kernel, another length or chunk size); goldens for `DRQ1` and the
table (`vectors.json`, Python `dcg.disputes_v21.imports`).

### 3.2 Consensus runs of v2.1 templates

A v2.1 template may declare mode **consensus** (template field `mode:u8`,
bound in the template id; 2 is optimistic, the existing behaviour). A
consensus run has no executor bond, no commit and no challenge window.
Instead anyone executes its steps on chain, in ordinal order:

**`EXECUTE(ordinal k)`** with the step's inputs staged in a buffer (the STEP
witness format, reused). The program:
1. generates `StepSpec(k)` exactly as a dispute does (v2.1 §5.2);
2. checks every input affirmatively, as the corresponding EDGE claim would
   rule for E: an earlier step's output against that step's stored leaf hash
   (the caller supplies the leaf preimage), an external input against the run's
   ref, a constant against its `ConstSpec`, a chunk against its chunk root,
   `i` as a value;
3. checks the prior state against the predecessor's next-state digest or the
   initial value (the STATE rule), and the gate against the previous
   iteration's gate leaf (the GATE rule);
4. replays the kernel (`reductions::replay`, as the STEP claim does);
5. builds the leaf preimage itself and stores its hash at the step's
   position.

**`EXECUTE_SKIP(block, i)`** marks iterations `i..K` of a repeated block empty
once the gate leaf of `i − 1` is zero (or empty), so a stopped loop costs one
instruction.

Positions only increase, so the program folds the step tree with a frontier
of at most 40 hashes; it keeps one 32-byte leaf hash per step in a leaf table
for later input checks. After the last step, **`FOLD_OUTPUTS`** computes the
out tree from the `OutSpec` and `OutBlockSpec` records (each entry's producer
leaf supplied and checked against the leaf table), over as many transactions
as needed. The run is then `FINAL` and holds the same `RunRootV21` that an
honest optimistic executor would commit for the same template body and
inputs. So the Python tracer is the oracle for both modes, and a stage can
move between consensus and optimistic without changing its outputs or their
openings.

Execution is permissionless because it is deterministic: liveness needs one
honest sender, as in the permissionless `ANCHOR` of the 2026-09-23 note. The template declares an `execute_window`;
a run not finished by then can be cancelled by its payer and re-run.

Its result is a `ResultRef` with mode 1 (consensus) and scheme
`OUT_TREE_V21`, a new `(mode, scheme)` pair (§4). Outputs open exactly as an
optimistic run's do.

Cost: each step costs its replay plus about 0.5 CU per byte of producer leaf
preimages hashed (leaves are at most 1,040 bytes) plus the generation of its
spec. This is about 5,000 to 15,000 CU per step on top of the kernel, and at
least one transaction per step (*estimated*). Consensus stages therefore suit
small graphs (hundreds to low thousands of steps with small kernels), not
model inference. The leaf table costs rent of 32 bytes per step until the run
closes; closing leaves the run receipt, as today.

### 3.3 Pipelines

**Pipeline template `DPT1`** (new account, authority-created like v2.1
templates). It holds:
- `stage_count:u32` and, per stage, `mode:u8` and the stage's v2.1
  `template_id` (the template account itself is named by address at use);
- the **wiring**: for every imported external input of every stage, its source
  `(stage, out_index)` (source 1) or its requirements (source 2), and for
  every plain external input, the pipeline input that feeds it;
- the pipeline's own output list: `(stage, out_index)` pairs.

`pipeline_id = SHA256("dcg.pipeline.id.v1\0" || that encoding)`. Admission
checks that every source stage is earlier, that headers agree on every wire,
and that each stage's `ImportSpec` records name the same `(stage, out_index)`
as the wiring.

**Pipeline run record `DPR1`**, at `["dcgpipe", pipeline_run_id, payer]`, with
`pipeline_run_id = SHA256("dcg.pipeline.run.v1\0" || pipeline_id || nonce ||
count:u32 || pipeline external refs (52 bytes each, sorted))`. Per stage it
holds the status, the attempt number, the stage run's address and run id,
and, once the stage is final, its 256-byte `ResultRef`.

Instructions (new subs; anyone may send except where noted):
- **`INIT_STAGE(s)`** (the payer): requires every source stage of `s` to be
  `FINAL` in the record. Creates the stage run through the ordinary v2.1 init
  with `nonce = SHA256("dcg.pipeline.stage.v1\0" || pipeline_run_id || s:u32 ||
  attempt:u32)`, plain refs taken from the pipeline's refs by the wiring, and
  imported refs as asserted by the payer. Records the stage run id.
- **`IMPORT`** (§3.1) for a stage run reads the source stage's stored
  `ResultRef` from the record, never the source run, and requires that the
  record's run id for that stage is the one the result came from. So a stage's
  inputs are the outputs of this job's earlier stages, not any run of the same
  template.
- **`STAGE_FINAL(s)`**: reads the stage run with `read_run_result`, requires its
  run id to be the record's, and copies the `ResultRef` into the record.
  Because the record keeps the copy, later imports do not need the source run
  or its template to stay open (this answers mode results §8 Q2 within a
  pipeline).
- **`STAGE_RESET(s)`** (the payer): if the stage run is refuted or cancelled,
  increments the attempt so the stage can be re-run with a new executor (the
  v2.1 §10.2 re-run path). Later stages never started, because they need the
  stage final.
- **`CLOSE_PIPELINE`** (the payer, once every stage is final or the payer
  abandons it): returns the record's rent.

**Reading a pipeline output.** `read_pipeline_result(record, stage)` returns
`(pipeline_id, stage, ResultRef)`. A consumer that requires `pipeline_id`
gets, by that one field, every ancestor stage's template, mode, windows and
bonds, so it does not have to require each ancestor separately.

All stages live in the program that holds the record in v1. Stages hosted in
another program (for example a v3 session in an app program, sealed as in
mode results §3.2) are a later extension through the `host` field of the
`ResultRef`; they need a decision about which hosts a pipeline may trust.

### 3.4 Folded into slice 1 (owner 2026-10-15)

The owner's answers to mode results §8 (2026-10-15) put three more changes
into slice 1, so the shared image changes once.

**A. Run receipts carry the template's fields (mode results §8 Q2).** A run
closes into a new receipt form `D21Q`, 380 bytes: bytes 0..312 as in `D21P`
(magic replaced), then `template_id` (32, the template's offset 96), the
template kind byte (1, offset 5), 3 zero bytes, and the template's
challenge window, phase window, executor bond and challenger bond (8 each,
offsets 24..56), which the result's body also needs. `read_run_result` reads a
`D21Q` without the template account (its `template` argument is an `Option`),
so a result stays readable after its template closes. `init_run` funds the
`D21Q`'s rent for a run shorter than it; a run short of that rent at close (one
created by an older image) closes into a `D21P`, which keeps its form and still
needs the template. The run read layout gains the form as run-read v2
(`docs/spec/run-read-layout-v21.md`); the live run's version 2 (imports) is in
the same document. Implemented 2026-10-16 behind feature `pipelines-v1`.

**B. Anyone may seal a halted session (mode results §8 Q1).**
- `SEAL` begin needs only the payer's signature; the authority slot is not
  checked. Chunk and finish in the seal phase take any signer, so anyone may
  continue and finish a seal someone else began; the hash is fixed by the
  frozen state, so who sends the chunks does not matter.
- Only the authority may abort a seal in progress. Once sealed, a session is
  never sealed again.
- A payer who begins on a session with no anchor account yet pays that
  account's rent; it goes to the authority when the anchor closes, like every
  child's rent.
- A seal still needs a kernel halt and the halt cursor. An anchor on a live
  session still needs the authority.
- **Found while implementing (2026-10-16): anyone could deny a session's
  result.** Closing a halted session's children needs no signature (the rent
  goes to the authority), so anyone could close one state span right after a
  kernel halt. That trims the session, and a trimmed session takes no seal.
  With `pipelines-v1`, until a kernel-halted session is sealed, closing a state
  span or the resource copy needs the authority's signature. Anyone may seal,
  so the rent can always be released; once sealed or trimmed, anyone closes as
  before; an authority halt (no result) is unaffected.
- A stranger's begun seal blocks closes until it ends. The authority ends it
  with an abort and a signed close in one transaction, which leaves no gap for
  another begin; or anyone finishes it.
- **Independent review 2026-10-16, fixed:**
  - *H1, a stranger could fix the seal form.* The first to seal chose linear or
    tree and the chunk size, for good, and could do it in one transaction
    before the authority could abort; a consumer expecting another form could
    then never import. Now the kernel declares the form strangers use
    (`StatefulKernel::open_seal_log2`, default 0: linear); the authority may
    begin either form.
  - *H2, anyone could trim a sealed session.* The close rule held only until
    the seal, so a griefer could close a span right after it and end the result
    before any consumer imported. Now a kernel-halted session's state spans and
    resource copy close only with the authority's signature until the
    authority has trimmed it, sealed or not. The rent goes to the authority in
    any case, so no one else gains by closing; the authority decides when a
    result ends.

Implemented 2026-10-16 behind feature `pipelines-v1`; tests in
`tests/stateful_v3_result.rs`, and the session fuzzer models open seals and
signed closes (campaign seed 1050, 300 sequences, 37 seals begun, clean).

**C. Tree seals (mode results §8 Q3).** A second seal scheme,
`STATE_TREE_V1` (scheme 4), lets a consumer open part of a large state and
lets an optimistic run take a session's state as a chunked input.
- The sealer chooses `chunk_log2 = v`, `6 ≤ v ≤ 16`, at begin.
- The tree is exactly a v2.1 chunked value (v2.1 §4.2, layout 3) over the
  state bytes: leaves `SHA256("dcg.chunk.leaf.v2.1\0" || index:u64 || chunk)`,
  nodes in the chunk tree's domain, `EMPTY_CHUNK` padding. The program folds it
  with a frontier as the chunks arrive, in the same 65,536-byte instructions
  as the linear seal.
- The record's `state_anchor` holds that chunked-value digest; byte 1278 bit 2
  marks a tree seal and byte 1279 (zero today, refused if nonzero) holds `v`.
  The `ResultRef` has `root` = the chunked-value digest, `count` = state bytes,
  and the body's byte 33 holds `v` (34..36 stay zero). Its other body fields (kernel,
  schemas, halt reason and cursor, input chain and stream roots) are as for
  the linear seal, so the requirements bind the computation as before.
- Openings: one chunk with its path (about 0.5 CU per byte plus about 150 CU
  per level, *estimated*), or the whole state.
- Because the root is a chunked-value digest, an imported whole state needs
  no posting: the run's ref names the digest and length, `IMPORT` checks them
  against the root, and kind 5 inputs and chunk openings then work unchanged
  in disputes. The bytes stay available to a challenger on chain while the
  session's state accounts are open; a template importing a state should set
  its windows so the payer can keep them open, or the challenger relies on its
  own copy taken at seal (stated in the result's basis).
- The linear seal stays for small states read whole on chain.

Implemented 2026-10-16 behind feature `pipelines-v1`: op `ANCHOR_OP_TREE_SEAL`
(0xF9) plus the log2 byte. Each 64 KiB chunk instruction hashes its chunks
into one aligned subtree (of height `16 − log2`, or the whole tree if smaller)
and pushes it onto a frontier of at most 17 subtree roots kept in the anchor
account, which grows to 704 bytes for it (bytes 116..120 the subtrees folded,
120 the log2, 121 a tree flag; the payer funds the growth). Finish folds the
frontier into the root. Abort and finish clear the frontier, so a linear seal
can follow an aborted tree seal. Checked: Rust and Python agree on goldens
(`vectors.json`, a 150,000-byte state at 1 KiB chunks) and on the program's
record (`tree_session.json`); the streaming fold equals the level-by-level
tree for chunk sizes 2^6 to 2^16 and lengths 0 to 131,073; through the program,
80,000 bytes at 2^6 and 2^16 in two transactions, chunks opening across the
span boundary; the session fuzzer models tree seals (seed 1051, 400 sequences,
60 seals begun, clean). Compute, *measured* on SBF (2026-10-16, 80,000-byte
state): a full 64 KiB chunk instruction costs 533,329 CU at 2^6 chunks and
46,431 CU at 2^16, the last (short) chunk 132,591 and 21,073 CU, and finish
13,682 and 10,269 CU. The worst case is within the 1.4M transaction limit with
a margin of about 2.6; clients set a compute limit above the 200,000 default.

## 4. Additions to mode results

- `(MODE_CONSENSUS, SCHEME_OUT_TREE_V21)`: a consensus v2.1 run. The body is
  the optimistic body layout with windows and bonds zero and `total_steps` in
  place, and `basis()` reports chain execution and host trust only. v1 readers
  refuse the pair today, so the addition is versioned by the pair, not by a
  new magic.
- `DRQ1`: the canonical encoding of `ResultRequirements`, with its digest, and
  Python mirror and goldens.
- A `pipeline_id` and stage requirement for `read_pipeline_result`.
- Scheme `STATE_TREE_V1` (4) with its chunk openings, and the `D21Q` receipt
  in `read_run_result` (§3.4).

## 5. Finality, basis and `explain()`

A pipeline output's finality time is the longest path through its ancestry:
- an optimistic stage adds its honest compute time, the commit, and its
  challenge window (plus `D(N)` if disputed);
- a consensus stage adds its execution time (its transaction count over the
  landing rate; Basanos measured about 12 s per landing through Fogo
  mainnet direct nodes, more under load);
- `INIT_STAGE`, imports and `STAGE_FINAL` add a few transactions per
  boundary.

So a consensus stage *before* an optimistic stage costs no window, and a stage
*after* an optimistic stage waits a full window. The planner should cut a new
stage only where the mode changes or where an earlier final result is worth
the wait.

`explain()` reports, per pipeline output, the stage path, the finality bound,
and the basis as the union over the path: host program trust, chain execution
for consensus stages, and each optimistic stage's window, bonds and
honest-challenger assumption.

## 6. Liveness and economics

- Each optimistic stage keeps its own bonds, hooks and remainder destination
  (v2.1 §10.3). A pipeline adds no economics; the app's hook sees each
  stage's terminal outcome.
- The payer of the pipeline pays every stage's rent and is the guaranteed
  watcher of every optimistic stage, as for a single run.
- Consensus execution and cranks (`IMPORT`, `STAGE_FINAL`, `FOLD_OUTPUTS`) are
  permissionless; whoever sends them pays fees.
- A refuted stage blocks only its descendants, until it is re-run.

## 7. Python and the planner

- `dcg` gains a pipeline builder: the developer marks regions of a graph with a
  mode; the planner cuts stages at mode changes in topological order, refuses a
  region whose inputs come from a later stage, emits one v2.1 template per stage
  plus the `DPT1` wiring, and computes `pipeline_id`.
- The tracer runs the whole pipeline off chain and produces every stage's run
  root, so consensus and optimistic stages share one oracle.
- The client drives a pipeline run: init each stage when its sources are
  final, send imports, execute consensus stages, crank `STAGE_FINAL`.
- `explain()` as in §5.

## 8. What changes, and versions

New, all additive to existing accounts and records:
- spec leaf type 10 (`ImportSpec`), `DRQ1`, run account version 2;
- the template `mode` field, bound by a new template id domain
  `dcg.template.id.v2.2\0` (§11 decision 6); existing templates keep their
  v2.1 ids and are optimistic;
- `EXECUTE`, `EXECUTE_SKIP`, `FOLD_OUTPUTS`, the leaf table;
- `DPT1`, `DPR1` and their instructions;
- the `(consensus, OUT_TREE_V21)` result pair.

Unchanged: the dispute game, every claim, `RunRootV21`, the step and out
trees, `ValueRefV1`, the value digest, the receipt.

The shared image changes, so the shared testnet program needs an upgrade with
a week's notice. Mainnet `2Hxny…` and TCR1 are untouched unless their owners
choose to adopt it.

## 9. Implementation order and estimates

| Slice | Content | Estimate |
|---|---|---|
| 1 | `DRQ1`; `ImportSpec`; run version 2; `IMPORT` with `source = 2`; `D21Q` receipts; permissionless seals; tree seals and state imports (§3.4); Python mirror; native and SBF tests; fuzzer seal ops for B and C; rule-10 review | 3–4 weeks |
| 2 | consensus v2.1 runs: template mode, `EXECUTE`, `EXECUTE_SKIP`, `FOLD_OUTPUTS`, the result pair; equality with the optimistic run root on the same template body; review | 2–3 weeks |
| 3 | pipelines: `DPT1`, `DPR1`, stage instructions, `read_pipeline_result`; Python builder, client, `explain()`; review | 2–2.5 weeks |
| 4 | an example pipeline (consensus tokenize → optimistic body → consensus verdict) native and SBF, then the shared-image upgrade | about 1 week |

Total about 8 to 10.5 engineer-weeks, low confidence (*estimated*). Slice 1
alone already lets an optimistic run take a verified chain input, including
a large session state; slice 2
alone lets a whole template run in consensus.

## 10. Tests (rule 10 for each slice)

- Goldens: `DRQ1`, `ImportSpec`, `pipeline_id`, `pipeline_run_id`, stage nonces,
  run version 2 lengths (Python and Rust agree).
- Imports: a false asserted ref never verifies; a committed, refuted, wrong
  template, short window or foreign host source is refused; an import from a
  run of the right template but another pipeline instance is refused; the
  commit deadline starts only after the last import.
- Consensus runs: the folded run root equals the tracer's and an honest
  optimistic commit's; every input kind; a wrong producer preimage, a skipped
  step, an out-of-order step, a skip with a nonzero gate are refused; a gated
  loop stops in one instruction.
- Pipelines: a stage cannot start before its sources are final; a stage result
  cannot be copied from a run that is not the record's; a refuted stage
  re-runs and its descendants see only the new attempt; closing returns rent;
  who profits calling first, for every crank.
- Slice 1 additions: a `D21Q` reads the same as the live run and needs no
  template; a seal begun by a stranger is finished by another stranger and by
  the authority, and equals the authority's own; a stranger cannot abort; a
  sealed session refuses a new seal; a tree seal's root equals the Python
  chunked-value digest for `v = 6` and `v = 16` and a state that is not a
  multiple of the chunk; a state imported whole into an optimistic run is
  disputed through kind 5 and rules as the oracle.
- Fuzz: a pipeline-level sequence fuzzer in the style of the session fuzzer,
  with the tracer as the reference model.

## 11. Owner decisions

Decided 2026-10-15: mode results §8 Q1 (anyone seals; §3.4 B), Q2 (receipts
carry the template id; §3.4 A) and Q3 (tree seals; §3.4 C), all in slice 1.

Decided 2026-10-16 (owner accepted every recommendation):
1. "Mixed regions" means pipelines of single-mode stages (§2); proven blocks
   inside one tree are rejected (§2.1).
2. Slice 1 is built first.
3. Consensus stages are consensus v2.1 runs with permissionless execution
   (§3.2), not v3 sessions; sessions may join later as stages from other
   hosts.
4. Each slice is built behind a feature on the test image and trialled with a
   workload (qushta or Basanos) before the shared-image upgrade.
5. Per-kernel modes chosen by the executor are deferred (§12); slice 2
   reserves their fields in the step spec and leaf.
6. Template ids take the `mode` field through a **new id domain**,
   `dcg.template.id.v2.2\0`, over the v2.1 fields plus `mode` (and the reserved
   per-kernel mode fields). Existing templates keep their v2.1 ids and read as
   optimistic; readers accept both domains (option A, slice 2).

Open: the go to start building slice 1.

## 12. Per-kernel modes chosen by the executor (evaluated 2026-10-16, deferred)

**Proposal (owner 2026-10-16).** Each kernel in a template lists the modes it
accepts. On each run the executor picks, for each step, one mode from its
kernel's list. The owner's motivation is mostly a cost trade-off for the
executor, not steps that are too large.

**Mechanics (designed).**
- The step spec carries the kernel's allowed-mode set and the step leaf the
  chosen mode. Both are frozen bytes today, so this is a new protocol version
  (step leaf and spec v2).
- SHAPE rules for C when the chosen mode is not allowed.
- STEP dispatches on the leaf's mode: optimistic replays C's witness (today);
  consensus rules for E if and only if the program recorded the step as
  executed on chain before `COMMIT`; Freivalds runs a randomized check with
  randomness drawn after the claim; ZK needs E's proof.

**Soundness.** It is sound in one tree. A proven step shows only that its
outputs follow from its own claimed inputs. If it is the first divergent leaf,
its inputs or prior state differ from H's, and EDGE, STATE or SHAPE refute it
against earlier leaves, which are honest by the descent invariant (v2.1 §7.1).
This corrects §2.1, which considered only template-fixed consensus blocks.

**Every step must still fit replay.** v2.1 admission requires every step to fit
its declared compute and the 1 MiB staging limit. Large work is decomposed
(lazy decomposition, LX1 checkpoints) until each leaf a dispute can reach is
small. Under per-kernel modes, a kernel that allows optimistic must still fit
replay, because the executor can always choose it. Only a kernel without
optimistic could skip the rule, and decomposition already covers large steps.
So no mode makes a step checkable that is not checkable today.

**The executor's choice buys little with today's modes.**
- An honest executor never loses a dispute, so proving a step at commit buys
  it no protection. It pays compute now to avoid answering a dispute it would
  win.
- A run finalizes as one unit at its window (v2.1 §11), so proving some steps
  does not shorten finality. A run with every step proven could finalize at
  once, but that is a consensus run (slice 2).
- The guarantee a consumer gets is the weakest allowed mode, since the executor
  may always pick it. The allowed list is therefore a security parameter of the
  template.
- What proving does buy is a smaller dispute surface, which helps the payer
  more than the executor.

**Freivalds for a 4B decode token** (all *estimated* unless marked).
- About 98 to 99% of a decode token's arithmetic is matrix-vector products
  (about one multiply-add per weight, 3.5 to 4 billion per token), so that
  much is eligible by operation count. Requantization of every output cell
  still needs an exact check in another mode.
- **As a dispute resolver it is worse than first divergence.** Checking
  `y = W·x` needs `rᵀW`, which for one token touches all of `W`: for the 4B
  `up_proj` (2,560 × 9,216) about 23.6M multiply-adds, about 175M CU at the
  *measured* 7.42 CU per multiply-add of the exact matmul path (Basanos
  `docs/experiments/matmul-kernel-cu-2026-09-03.md`), at least 126 full
  instructions. First divergence replays one small window instead, at most
  1.4M CU.
- **As a check of every token, without a window,** the compute amortizes
  (one `rᵀW` per matrix per run, about 3×10^10 CU, then a dot product per
  token per matrix), but the data does not: the program must read every
  token's inputs and accumulators for every matrix, about 2 million values,
  roughly 5 to 15 MB, per token. Requantization adds about 10^8 CU per token.
  Against an honest optimistic run, which costs nothing on chain, it is never
  a saving.
- **Finality.** The window is sized to the worst case: the executor publishes
  only its commitment and a challenger recomputes from the inputs
  (`challenge_window ≥ honest_compute_slots + phase_window`). Freivalds speeds
  up checking only a trace the executor chose to publish, and a published trace
  already allows a parallel, teacher-forced re-check. The program cannot
  enforce off-chain availability, and on-chain posting is the data cost above.
  Honest finality shrinks through faster honest recomputation (faster exact
  kernels, better hardware), not through Freivalds.
- **Privacy.** Worse than optimistic. An honest optimistic run puts only its
  commitment and inputs on chain, and a dispute reveals one window's witness;
  Freivalds needs the operands and accumulators of every checked matrix. Neither
  hides the weights, which optimistic challengers must already have. Only ZK
  offers privacy, at the cost of proving 4B off chain.
- Where it could still help: a watcher's off-chain tool to locate a divergent
  layer quickly before disputing optimistically; matrix-matrix work such as
  batch prefill, which still carries the data cost.

**Decision (owner 2026-10-16): deferred.** No practical upside now. Slice 2
reserves the mode fields in the step spec and leaf when it changes the
template format, at almost no cost. Per-step dispatch is built together with
the first mode whose cost on the executor's side differs enough for the choice
to matter (for example a ZK proof posted once in place of an interactive
dispute, or a bond released early).
