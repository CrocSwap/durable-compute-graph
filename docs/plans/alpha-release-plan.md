# DCG alpha release plan

**Status: owner decisions recorded 2026-10-03 (below).** Durations are
**estimates**. Nothing here is measured yet unless it says so.

## What the alpha is

The alpha is the first release that people outside the project can use on
Fogo testnet. DCG runs computations too big for one transaction, in two
modes, and the chain stays the source of truth in both:

- **Consensus mode:** the computation runs entirely on chain, split across
  as many transactions as it needs. DCG keeps durable state between
  transactions, applies each step exactly once and in order, and sequences
  the transactions. Doom runs this way. Nobody has to be trusted or watched;
  the cost is throughput and fees.
- **Optimistic mode (v2.1):** an executor runs the computation off chain and
  commits to every step. Anyone can dispute the first wrong step, and the
  chain judges only that step. It suits work far too large to run on chain,
  such as model inference. It needs an honest watcher and a challenge window.

Each mode is first-class in the alpha. The long-term design mixes them per
region of a graph (`docs/design/`, the modes and compiler design).

The alpha comes with a clear statement of what is guaranteed in each mode
and what is not.

It is not a mainnet release. It also does not depend on Basanos moving its
documents to v2.1. Basanos's own mainnet switchover runs separately and in
parallel; it is useful evidence, but it does not gate the alpha.

## Proposed surface (owner decision)

| In the alpha | Out of the alpha |
|---|---|
| **Consensus mode, stateful sessions (v3):** sessions, stateful kernels, cursor and phase discipline, views and their phased publication, resources, closes | **The v2.0 trace path (tags 208–226):** superseded by v2.1. It stays behind its feature flag and is not documented for users. |
| **The sequencer** (`dcg.sequencer`): ordered lanes, batching, resend and journal, multi-node sends | **Sampling, Freivalds and ZK modes:** not started |
| **v2.1 optimistic disputes (tag 227):** templates, runs, first-divergence descent, the claims, chunked kernels, committed constants, list inputs, application kernels by manifest, rent reclaim | **The revision-8 document lifecycle as a user API:** it stays in DCG core because Basanos runs on it in production, but it is Basanos-shaped (positions, PT2P), and outside users get v2.1 instead (owner decision) |
| **The Python tracing frontend, client and sequencer** | **LOG-state templates:** refused until LOG is on chain (re-review condition) |
| **LX1 checkpointed state chains** (`docs/design/v2.1-lazy-expansion.md`): a v2.1 commitment kind for long, repeated computations. A run commits a state root every `k` positions; a dispute bisects one flattened schedule and replays one finest transition against a multi-proof. Applications register their machine as code (`LxMachine`). | |
| **`explain()` for v2.1 templates** | **TypeScript:** a thin layer after the alpha |

## Readiness work

**R1. Finish hardening v2.1.**
- List inputs and template closes land: in progress, and template closes get their own review.
- Follow-ups A and B from the 10-03 re-review: narrow the LOG neutrality; implement the design's additive load extension, counted only while disputes wait on the executor.
- The run-level dispute fuzzer: several disputes per run, random interleavings, invariants checked after every step.

**R1b. Finish LX1 (owner, 2026-10-03: in the alpha).**
- Done: the Python reference; the pure Rust core in `dcg-disputes` (state tree, multi-proof fold, coordinates, `pick_interval`, the machine trait, terminal replay, the OUTPUT claim), checked against played Python disputes.
- Next, on the host: the tag 227 LX subcodes (open, midpoints, pick, opening, output) and timeouts; the every-ending matrix; the toy machine as the DCG example; then the independent review (rule 10).
- Basanos's 4B model as an LX1 machine is the first real application and its testnet requalification; it lives in Basanos.
- Alpha bar: LX1 handlers are covered by R2's review and the fuzzer, by `explain()` (E8), and by a newcomer walkthrough (E7) using the toy machine.

**R2. Review the whole surface.** Only tag 227 has had an independent review.
*Status 10-05:* stateful sessions v3 + lanes reviewed (4 high fixed and
re-reviewed: authority on creators, pre-funded addresses, partial-primary
close; `docs/experiments/sessions-v3-review-2026-10-05.md`) and fuzzed
(13,500 sequences, ~1.07M transactions, native and SBF, no failure; F1 fixed;
`docs/experiments/sessions-v3-fuzz-2026-10-05.md`). Signable as a mechanics
claim for accepting kernels, excluding L3 (anyone may close a halted
session's children). H4 and M2 are fixed by session features (merged 10-05,
5624a82): declared input rejection and ring-buffer streams
(`docs/design/session-reject-and-ring-v1.md`; rule-10 reviewed, fix-then-merge;
fuzzed 1,500 native + 300 SBF sequences with ring laps and rejections, clean).
Still to do there: client support for v3 features (no DCG Python client speaks
v3; Doom adopts them with its repin). **Admission, the template lifecycle, the
closes and routing reviewed 10-05** (two independent reviews, fixes, two
re-reviews; merged 69fe0a1): staging growth refunded by recorded payer,
admission floors and canonical template ids, built-ins bound at version (1, 1),
LX staged length, and a named `alpha-image` (only tag 227 routes; image
`e63816cb…`, 344,096 bytes, reproducible). Known alpha limits: kernels resolve
against the live image (no kernel change while runs are live); template promises
under the trusted spec root. F10 answered: no handler trusts an account by owner
and magic alone where it matters. **R2 is complete.**
- Stateful sessions (v3) get the same treatment tag 227 had, including a run-level fuzzer of their own: random interleavings of steps, resends, failed and duplicated transactions, view publications and closes, with invariants (each step applied once and in order, state digests match a host replay, lamports conserved) checked after every step.
- Admission, the template lifecycle, and every other handler the shared program exposes each get an independent adversarial review (Basanos project rule 10).
- That includes the staging-buffer question from finding F10: does any handler accept an account by owner and magic alone?

**R3. Put the reviewed image on the shared testnet program.** **Done 2026-10-05** (owner: a fresh address): `J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9` runs the alpha image `e63816cb…` (DCG 69fe0a1; reproducible build; routing and a chunked-kernel dispute measured on chain; `docs/hello-graph.md`). The older test image `FCzAE7…` (`7b04f8d5`) remains for v2.0 and internal replays.
- Upgrade it to the reviewed image and record the image hash.
- Publish an upgrade policy: runs created before an upgrade that changes addresses must drain first.
- Set fee, rent and abuse limits.

**R4. Make the repo stand alone.** Move out or delete the Basanos-specific leftovers:
- features: `legacy-basanos-fixtures`, `a16-kernel-probe`, `decision-kernel-probe`, `legacy-hclosure-handlers`, `pt2p-seal-profile`, `weight-witness-probe`, `v7-cu-probe`;
- old fixtures and docs that name Basanos internals.

DCG keeps no model code (owner decision, 09-26).

**R5. Release terms.**
- The license (GPL-3 today, "for now").
- Formats may change before beta, and breaking changes are announced in a changelog with migration notes.
- A security contact.
- What is guaranteed, and what is not: no mainnet use, and testnet tokens only.

## Developer ergonomics work

**E1. v2.1 lowering in the tracing frontend (highest priority).**
- Write a Python function with loops, constants and wide reads, and get a v2.1 plan: repeated blocks, gates, constants, chunked and list inputs.
- Today a v2.1 plan is assembled by hand from packed producer tuples, which only the authors can do.

**E2. A kernel kit.**
- One way to declare an application kernel.
- A conformance harness that runs the Rust kernel and its Python mirror on generated inputs, including every edge limit and refusal, and fails on any disagreement. It would have caught review finding F2.
- A template for an application image that embeds custom kernels, with its build command.

**E3. Executor and watchtower services.**
- An executor service that answers its runs' disputes on time: reveals, leaves, openings and staged witnesses.
- A watchtower that checks runs it cares about, and challenges a wrong commitment from the first divergence.
- Without both, users can only replay scripted disputes.

**E4. The lifecycle in the client.**
- `settle_and_reclaim(run)`: advance, pay the pot, close disputes with their buffers, finalize after the window, shrink the run to its receipt, close caches.
- Phase windows sized from the largest witness a template needs, so a template cannot be set too short. A 64 KiB upload takes about 51 s on testnet (*measured* 10-03), longer than the 750-slot minimum.
- *Status (2026-10-05):* built. `DisputeClient.settle_and_reclaim(run)` takes a run as far as the chain allows (timeouts, moot, advance, pot, dispute closes with buffers, finalize, caches, receipt or cancel), finding disputes and caches from the run's transaction history; `runs_of(template)` finds a template's live runs. `wire.template_data` refuses a phase window shorter than `phase_window_for(largest_step_witness(plan))` (testnet: 40 ms slots, *measured* 10-05). On the alpha testnet program, `traced_dispute.py --settle` settled a refuted, an upheld and an unchallenged run and closed the template (31 transactions, 72 s, payer net −0.0002 FOGO: fees only; *measured* 10-05, Basanos `out/runs/dcg-e4-settle-2026-10-05`), and settled four older runs left by earlier examples.

**E5. Named errors.** A table in the client that maps every tag-227 error code to its name and meaning: `0x660d` becomes "phase deadline passed". *Status (2026-10-05):* built: `dcg.disputes_v21.errors` (48 codes, each with a meaning and a usual fix; a test keeps it equal to the codes the program source raises); the dispute client appends the name to every refusal.

**E6. Developer commands.**
- `dcg dev`: a local validator, the program deployed, a funded payer.
- `dcg build`: a reproducible program image with its receipt.
- Today these take a pinned SDK path, wrapper environment variables and the Basanos runbook's deploy tools.

**E7. Docs.**
- Getting started for v2.1, replacing today's v2.0-era guide.
- A dispute walkthrough (a lie, the descent, the ruling, settlement, rent back).
- "Your first custom kernel", using E2.
- A guarantees page built on `explain()`.

**E8. `explain()` for both modes:** for v2.1 templates, the kernels and their STEP mode, the dispute path, windows, bonds and open limits; for sessions, the consensus guarantee, the kernel, and the per-step compute and transaction bounds.

### Consensus mode

**C0. The embedding contract.**
- A documented way to embed the stateful runtime in an application program: a template app program, its build, and its deploy.
- A runtime version marker readable on chain or from the image, so apps and users can check which DCG runtime a program embeds, and SECURITY advisories can say which versions are affected.

**C1. A session quickstart.** Write a stateful kernel (`StatefulKernel`: initial state, transition, optional views), register it in an application image, open a session from Python, drive it to completion with the sequencer, and read the result. The existing `python-session.md` and `sequencer.md` become its basis.

**C2. The sequencer as a product.**
- A documented, stable Python API: lanes, batching, resend and recovery from the journal, multi-node sends, and pacing.
- What it guarantees, and what it does not.
- Measured throughput guidance per workload shape (Doom's numbers are the first data point).

**C3. Stateful kernel kit.** The E2 conformance harness extended to stateful kernels: the Rust transition and its host reference agree on generated inputs, including state at its size limits and every refusal.

**C4. Lanes (throughput); an alpha gate.** Lanes (`docs/design/stateful-session-lanes-v1.md`, owner decisions recorded) let independent parts of a session advance in parallel. They are consensus mode's main throughput lever.
- **The alpha's hook (owner, 2026-10-03; program clarified 2026-10-05):** Doom runs on DCG at 3.0 frames per second on testnet, on **Doom's own program** built on the reviewed DCG runtime (the consensus runtime is a library embedded in each application's program, owner decision 2026-10-03; the shared program does not route sessions).
- Lanes are on the critical path, together with whatever else that target needs: CoW views, inputs-in-step and TPU sends (DCG roadmap, the 10-01 owner goal).
- Today's measured floor is about 0.32 s of serial execution plus about 0.25 s of visibility per frame. Reaching 3.0 frames per second means parallel render work per frame, not only faster sends.

**C5. A tutorial:** "a multi-transaction state machine", from an empty repo to a session running on the shared program, with costs (transactions, compute, rent) shown at each step.

## Order of work (estimated)

| Phase | Work | Estimate |
|---|---|---|
| 1 | R1 (hardening), R1b (LX1 in the program), E5 (named errors), E4 (lifecycle in the client) | about 1–2 weeks |
| 2 | E1 (v2.1 lowering), E2 and C3 (kernel kits), E8 (`explain()`), C1 and C2 (session quickstart, sequencer API), R4 (repo boundary) | about 2 weeks |
| 3 | E3 (executor and watchtower), R2 (reviews, including the sessions fuzzer) | about 1–2 weeks, partly parallel with phase 2 |
| 4 | R3 (shared program upgrade), E6 (`dcg dev`, `dcg build`), E7 and C5 (docs and tutorials), R5 (terms) | about 1 week |
| L | C4: lanes in the program and sequencer, their review, and Doom at 3.0 frames/s on testnet | about 2–4 weeks, in parallel from phase 1 |

**Estimated total: about 5–7 weeks** at the current pace if lanes (track L) keep pace. Track L is the riskiest item: the 3.0 frames/s target depends on chain visibility as well as our design, and it is the alpha's hook, so it starts now, in parallel.

## Exit criteria

The alpha ships when all of these hold:

1. **Independent reviews:** every handler in the alpha surface has one, and every finding is fixed or written up as a known limit.
2. **Fuzzer:** it runs clean, natively and on SBF, over the agreed number of interleavings.
3. **Public program:** the shared testnet program runs the reviewed image, and the hash is published.
4. **A newcomer test in each mode,** with no help from the authors. Starting from the docs, someone who did not build DCG:
   - **Optimistic:** traces a v2.1 graph, runs it on the shared program, watches the watchtower convict a planted lie, and gets their rent back.
   - **Consensus:** writes a stateful kernel, runs a session of a few thousand transactions to completion with the sequencer (including a resend after a dropped transaction), reads the result, and closes the session.
5. **A custom kernel** passes the kernel kit's conformance harness and wins an honest dispute on testnet.
6. **Release terms** are published.
7. **Doom on DCG runs at 3.0 frames per second** on testnet, on Doom's own program built on the reviewed DCG runtime (*measured*, sustained over a session of at least 1,000 frames), with lanes reviewed (owner 2026-10-05: Doom stays on its own program).

## Owner decisions (2026-10-03)

1. **Surface:** consensus mode (sessions and the sequencer) and optimistic
   mode (v2.1) are both first-class. The v2.0 trace path is out. The
   revision-8 lifecycle question (internal, or moved to Basanos) is being
   explained separately.
2. **License:** GPL-3 for now; re-releasing under another license may be
   considered later.
3. **Lanes are in the alpha.** Doom runs on DCG at 3.0 frames per second in
   the alpha; that is the hook (exit criterion 7).
4. **Security contact:** security@crocodilelabs.io, with `SECURITY.md` and a
   disclosure window. Breaking changes follow `SECURITY.md`'s companion
   policy: a changelog, GitHub releases, and at least one week's notice
   before the shared program is upgraded.
5. **Consensus mode is embedded:** DCG's stateful runtime is a library. An
   app compiles it, with its own kernels, into its own program, as Doom does
   today. The app owns its session accounts and its upgrade key. The alpha
   makes this easy with the kernel kit (C3), `dcg build`, a template app
   program, and a runtime version check, so an app can tell which DCG
   runtime it embeds and whether a security fix applies to it. A hosted
   option (sessions on a shared DCG program, with app kernels in their own
   programs, called once per step) is post-alpha.
6. **LX1 is in the alpha** (evening): "We're finishing it, so let's package
   it." It carries the full alpha bar: independent review, fuzzer coverage,
   `explain()` and a newcomer walkthrough.
7. **Parallel work stays narrow** (evening): worker rounds have cost more
   than host work in cold builds, full suites, ramp-up, review rounds and
   integration. Only long-running work runs in parallel, such as fuzzer
   campaigns, long test sweeps and testnet waits, and only when it merges
   back cleanly: built on the real-flow test harness and a stable base, with
   no large hand-written fixtures. Design, program changes and fix rounds are
   done serially on the host.
