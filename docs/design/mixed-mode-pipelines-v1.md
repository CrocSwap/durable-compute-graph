# Mixed modes in one template: pipelines of single-mode stages (2026-10-15)

**Status: designed, not started (owner 2026-10-15: design mixed regions
now).** Numbers are *estimated* unless marked *measured*. Builds on
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
model does not prevent them.

## 3. The three pieces

The design is three additive pieces. Each is useful alone and ships alone,
in this order.

### 3.1 Imported inputs for v2.1 runs

An external input of a v2.1 template may be declared **imported**: its value
must be an output of a final result, checked by the program before the run
can commit. This is the "optimistic run reads a result" direction, and it is
what pipelines use to bind stages.

**Spec record `ImportSpec`** (new spec-tree leaf type 10, 104 bytes):
`magic "DIM1" external_id:u32 source:u8 (1 a pipeline stage, 2 any result)
scheme:u8 reserved:u8[2] stage:u32 reserved:u32 out_index:u64
requirements_digest:[32] reserved:u8[40]`.
- `scheme` is `OUT_TREE_V21` in v1 (one output becomes one external input).
  Whole-state imports from a sealed session need the state posted as a
  chunked input and wait for tree seals (§8 of mode results, and §9 Q3 here).
- `requirements_digest` is `SHA256("dcg.requirements.v1\0" || DRQ1)`, where
  `DRQ1` is a new canonical, fixed-length encoding of `ResultRequirements`
  (every field present, with a presence bitmap). For `source = 1` it is zero;
  the pipeline supplies the requirements (§3.3).
- The external id's `InSpec` header must equal the source output's
  `OutSpec` header bytes 0..23 (checked when the import verifies, since the
  source template is known only then for `source = 2`).

**Run account version 2.** A run of a template with imports is created with
`R_VERSION = 2` and an import bitmap after the refs. Its live length grows by
`ceil(n_import / 8)` bytes, padded to 4. `docs/spec/run-read-layout-v21.md`
gains the form under its versioning rule, and `read_run_result` accepts it.

**`IMPORT(external_id, path)`** (new sub, anyone may send, before commit):
1. reads the source result: a `FINAL` run through `read_run_result`, or a
   pipeline record's stored stage result (§3.3);
2. checks it against the import's requirements with `ResultRef::require`;
3. opens output `out_index` with the 55-byte ref recorded in the run (the run
   id already binds it) and `path`;
4. sets the input's bit.

The commit deadline starts when the last import bit is set. This is the
`INPUTS_COMPLETE` rule of v2.1 §4.4, implemented for imports only (plain and
chunked input posting stays a roadmap item). If an import can never verify
(the asserted ref is false, or the source is refuted), the payer cancels
after the existing deadline, as for a missed commit.

Disputes do not change. An imported input is an external input (EDGE kind 2),
and its ref was checked against a final result before commit.

Cost: one source read (2,400 to 3,900 CU, *measured*) plus one opening (285 CU
plus about 150 CU per tree level, *estimated*) per import, one transaction
each.

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

## 4. Additions to mode results

- `(MODE_CONSENSUS, SCHEME_OUT_TREE_V21)`: a consensus v2.1 run. The body is
  the optimistic body layout with windows and bonds zero and `total_steps` in
  place, and `basis()` reports chain execution and host trust only. v1 readers
  refuse the pair today, so the addition is versioned by the pair, not by a
  new magic.
- `DRQ1`: the canonical encoding of `ResultRequirements`, with its digest, and
  Python mirror and goldens.
- A `pipeline_id` and stage requirement for `read_pipeline_result`.

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
- the template `mode` field (v2.1 template id gains it; existing templates are
  optimistic and keep their ids under a version rule decided at implementation);
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
| 1 | `DRQ1`; `ImportSpec`; run version 2; `IMPORT` with `source = 2`; Python mirror; native and SBF tests; rule-10 review | 1.5–2 weeks |
| 2 | consensus v2.1 runs: template mode, `EXECUTE`, `EXECUTE_SKIP`, `FOLD_OUTPUTS`, the result pair; equality with the optimistic run root on the same template body; review | 2–3 weeks |
| 3 | pipelines: `DPT1`, `DPR1`, stage instructions, `read_pipeline_result`; Python builder, client, `explain()`; review | 2–2.5 weeks |
| 4 | an example pipeline (consensus tokenize → optimistic body → consensus verdict) native and SBF, then the shared-image upgrade | about 1 week |

Total about 6.5 to 8.5 engineer-weeks, low confidence (*estimated*). Slice 1
alone already lets an optimistic run take a verified chain input; slice 2
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
- Fuzz: a pipeline-level sequence fuzzer in the style of the session fuzzer,
  with the tracer as the reference model.

## 11. Owner decisions

1. Adopt the stage model (pipelines of single-mode stages) as the meaning of
   "mixed regions", rejecting proven blocks inside one tree (§2.1).
   Recommended.
2. Build slice 1 first; it is useful without pipelines. Recommended.
3. Consensus stages as consensus v2.1 runs with permissionless execution
   (§3.2), rather than v3 sessions. Recommended: the graph and kernels stay
   the same across modes, and sessions remain the streaming consensus form.
   Sessions as stages come later through foreign hosts.
4. Build behind a feature on the test image first and trial it with a
   workload (qushta or Basanos) before the shared-image upgrade. Recommended.
5. How existing v2.1 template ids absorb the `mode` field: a new template id
   domain for mode-carrying templates (old ids unchanged), or mode only in a
   new template version. Decide at slice 2.
