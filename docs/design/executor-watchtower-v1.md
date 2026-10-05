# Executor and watchtower services (alpha E3), design v1

Status: accepted, 2026-10-05. Owner answers (§7): Q1 (c), an application-supplied input source now and on-chain input posting before any mainnet use; Q2 (a), the watchtower handles descents only in v1.

## 1. Why

Today a v2.1 dispute happens only when a script plays both sides from a
recorded transcript (`DisputeClient.play`). Optimistic mode is safe only if:
- an honest executor always answers its disputes before each phase deadline;
- someone always checks committed runs and challenges a wrong one inside the
  challenge window.

E3 builds the two long-running services that do this:
- the **executor service**, for the party that commits runs;
- the **watchtower**, for anyone who wants runs checked.

## 2. What already exists

- `game.py`: the referee, the executor's answers (`Executor.nodes`, `.leaf`,
  `.lists`) and the first-divergence challenger (`honest_challenge`). All of
  it runs offline, with both parties in one process.
- `run.execute`: H, the honest commitment of a plan over its inputs.
- `client.py`: every instruction; `settle_and_reclaim` (E4); discovery of a
  run's accounts from its signature history; named errors (E5).
- `lx_client.py`: the LX1 dispute moves, again played from one process.

The services reuse these. What is new is that each party runs alone and
reacts to what it reads on chain.

## 3. Executor service

**Input.** A journal of the runs it committed. Each entry records:
- template, run address and run id;
- plan id and spec;
- external input values;
- the committed root.

On restart the service recomputes the commitment with `run.execute` and
refuses to answer if it does not reproduce the committed root.

**Each tick, for each run:**

1. Find new accounts touching the run, from signatures since the last one
   seen (`getSignaturesForAddress` with `until`).
2. For each open dispute, read its phase, level, position and depth:
   - **NODES** (the executor owes a reveal): send `reveal_nodes` with
     `Executor.nodes`.
   - **LEAF:** send `reveal_leaf` with the leaf and its list refs, staged
     when large or a list leaf.
   - **LX disputes (kinds 3 and 4):** the midpoints and opening moves from
     `lx_client`.
3. Once the run can settle, call `settle_and_reclaim`.

**Timing.**
- A tick runs at least every quarter of the template's phase window
  (750 slots is 30 s on testnet; *measured*, 40 ms slots).
- A move whose deadline is nearer than its expected send time is logged as
  late, and the service still tries.
- Staged uploads go at the measured rate of 64 KiB in about 51 s, which
  `phase_window_for` (E4) already prices into the template.

## 4. Watchtower

**Input:**
- the templates to watch;
- for each template, its plan (templates are trusted subjectively and
  verified off chain, owner 10-02);
- an **input source** for each run's external inputs (see §7, Q1);
- a budget: the most open disputes, and the most lamports at stake.

**Each tick:**

1. Find the templates' runs (`runs_of`, incrementally).
2. For each newly committed run inside its window:
   - get the inputs and check them against the run's external refs;
   - compute H and compare it with the committed root;
   - if the roots are equal, do nothing more for this run;
   - if they differ, open a STEP or OUT descent with a fresh nonce, paying
     the challenger bond.
3. Play each open dispute of its own:
   - **PICK:** read the revealed nodes on chain, store them as this round's
     reveal, and pick the first child that differs from H.
   - **CLAIM:** build the claim with the game's first-divergence logic over
     a *committed view* (§5), staging it when large.
   - A missed executor deadline is handled by `settle_and_reclaim`, which
     sends the timeout.
4. After the ruling, call `settle_and_reclaim`: advance, pay the pot,
   close, and get the bond and rent back.

**Several watchtowers on one run** each open their own dispute. The
program's moot rule returns the bonds of disputes opened after the lowest
challenger win.

## 5. The committed view: opening the executor's leaves without its data

Claims need openings of leaves in the *executor's* tree: a producer leaf for
EDGE, STATE and OUT, and the leaf path for some claims. The executor never
publishes its tree; the design (§4.4, the EDGE row) says the challenger opens
these "from the cached descent". Under first divergence this always works:

- Every leaf left of the disputed step equals H's leaf, so the challenger
  has its preimage.
- For a path sibling, the challenger uses, in order:
  1. a node revealed on chain during this descent;
  2. a node folded from revealed descendants within a round;
  3. H's node. This is only reached for a subtree wholly left of the
     divergence, where it equals the executor's node.

`CommittedView(honest, reveals)` implements `leaf` and `leaf_opening` in
place of `game.Executor`, so `honest_challenge`'s claim logic is reused
unchanged. Every opening it builds is checked locally with `root_from_path`
against the committed root before it is sent. A mismatch means a bug or a
gap in this argument, and the dispute is logged and left to time out rather
than sent wrong.

The watchtower records each round's reveal as it plays, reading
`D_REVEALED` during the PICK phase, because the dispute account keeps only
the current round.

## 6. Operation

- **Journals.** Each service keeps a journal (mode 0600, atomic replace) of
  its runs, disputes, the reveals seen per round, and the moves sent with
  their signatures. Every action re-reads the chain first, so a resend after
  a crash is harmless; the program refuses a move in the wrong phase.
- **Keys.** The executor key signs the executor's moves; the watchtower key
  signs the challenger's and pays bonds. Both are separate from the fee
  payer. No key is printed.
- **Errors.** Refusals carry their tag-227 name (E5).
- **Commands:**
  - `python -m dcg.services.executor --journal J --rpc URL`
  - `python -m dcg.services.watchtower --config C --rpc URL`

  Both run in the foreground and log one JSON line per action.
- **Tests.** The two services run as separate processes against a local
  validator with the alpha image. Scenarios:
  - an honest run (the watchtower stays silent and the run finalizes);
  - each lie family from the chunked and list scenarios (the watchtower
    wins);
  - the executor offline (the watchtower wins by timeout);
  - the watchtower offline (the executor finalizes);
  - two watchtowers on one run;
  - a restart in the middle of a dispute.

  Then the same on the alpha testnet program, with each on-chain step under
  the 90 s cap.

## 7. Owner questions

**Q1. Where does the watchtower get a run's inputs?** The alpha program
commits each external input only as a digest. The on-chain input posting of
design §4.4 (`INPUTS_COMPLETE`) is designed but not built. Options:

- **(a) An application-supplied input source (recommended for the alpha).**
  The watchtower calls a configured source and checks each input against its
  ref. The guarantee then reads: a run is checked if its inputs are
  available to a watchtower. The `explain()` and guarantees pages say so.
- **(b) Build on-chain input posting now.** This is a program change with a
  rule-10 review and more rent per run, but checking then needs nothing off
  chain.
- **(c) Both:** (a) now, (b) on the roadmap before any mainnet use.

**Q2. LX1 scope in v1.**
- The executor service must answer LX disputes, or LX runs lose by timeout,
  so it is in v1.
- The LX watchtower must recompute the whole run, Basanos's K=10,240
  executor, to find a divergence. That is heavy, and the CUDA work comes
  later.

Options:
- **(a) v1 watches STEP/OUT descents only;** the LX watchtower follows.
  Recommended.
- **(b) Both in v1.**

## 8. Not in v1

- Choosing which runs are worth checking by value at stake: v1 checks every
  run of the configured templates.
- Multi-node sends and priority fees: these are C2's sequencer work.
- Watching sessions (consensus mode): it has no disputes; the program checks
  every step itself.
